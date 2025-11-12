#!/usr/bin/env python3
"""
DHCP Snooping应用 - 基础演示版
功能：识别并拦截来自非信任端口的DHCP响应
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, dhcp
import struct
import time
from ryu.lib.packet import arp


class SimpleDhcpSnooping(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDhcpSnooping, self).__init__(*args, **kwargs)
        # 定义信任端口：连接合法DHCP服务器的端口（端口1连接h1）
        self.trusted_ports = {1}  # 端口1是信任端口

        # 🔥 新增：IP-MAC绑定表
        self.binding_table = {}  # MAC地址 -> {ip, port, switch_id, timestamp,source}

        # 🔥 新增：预先注册静态设备
        self.pre_register_static_devices()

        self.logger.info("🚀 DHCP Snooping应用启动！信任端口: %s", self.trusted_ports)
        self.logger.info("📋 初始化IP-MAC绑定表")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """交换机连接时的初始化处理"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 安装默认流表：将所有未知数据包发送到控制器
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("🔌 交换机 %s 已连接控制器，初始化成功！", datapath.id)

    def add_flow(self, datapath, priority, match, actions):
        """添加流表项的工具函数"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """处理从交换机发送到控制器的所有数据包"""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # 🔥 新增：简单的计数器，每处理30个包打印一次绑定表
        if not hasattr(self, "packet_count"):
            self.packet_count = 0
        self.packet_count += 1

        if self.packet_count % 30 == 0:
            self.logger.info(
                "--------------📊 处理了 %d 个数据包，当前绑定表状态:------------",
                self.packet_count,
            )
            self.print_binding_table()  # 首先记录所有报文的基本信息（包括ARP）

        if eth:
            time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.logger.info(
                "⏰ %s：📦 控制器从交换机收到数据包 - 端口: %s, 源MAC: %s, 目的MAC: %s, 以太网类型: 0x%04x",
                time_string,
                in_port,
                eth.src,
                eth.dst,
                eth.ethertype,
            )

        # 检查是否是ARP报文并优先处理
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("  🔗 检测到ARP报文，操作码: %d", arp_pkt.opcode)
            self.handle_arp_packet(datapath, in_port, arp_pkt, msg.data)
            return  # DAI处理完成后返回

        # 检查IPv4报文
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.logger.info(
                "  🌐 IPv4报文 - 协议: %d, 源IP: %s, 目的IP: %s",
                ipv4_pkt.proto,
                ipv4_pkt.src,
                ipv4_pkt.dst,
            )

        # 检查UDP报文
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.logger.info(
                "      📨 UDP报文 - 源端口: %d, 目的端口: %d",
                udp_pkt.src_port,
                udp_pkt.dst_port,
            )

        # 检查是否是DHCP报文
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if dhcp_pkt:
            dhcp_type = self.get_dhcp_message_type(dhcp_pkt)
            self.logger.info(
                "          🔍 检测到DHCP报文 - 类型: %s, 端口: %s", dhcp_type, in_port
            )
            self.handle_dhcp_packet(datapath, in_port, dhcp_type, msg)
            return

        # 检查其他协议（移除了ARP检查，因为已经处理过了）
        if eth and eth.ethertype == 0x86DD:  # IPv6协议
            self.logger.info("  🌐 检测到IPv6报文，端口: %s", in_port)

        # 其他报文正常转发
        self.flood_packet(datapath, in_port, msg.data, msg.buffer_id)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def packet_in_handler(self, ev):
    #     """处理所有进入控制器的数据包"""
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     in_port = msg.match['in_port']

    #     pkt = packet.Packet(msg.data)

    #     # 记录收到的数据包基本信息
    #     eth_pkt = pkt.get_protocol(ethernet.ethernet)
    #     if eth_pkt:
    #         self.logger.info("📦 收到数据包 - 端口: %s, 源MAC: %s, 目的MAC: %s",
    #                        in_port, eth_pkt.src, eth_pkt.dst)

    #     # 检查是否是DHCP报文
    #     dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
    #     if dhcp_pkt:
    #         dhcp_type = self.get_dhcp_message_type(dhcp_pkt)
    #         self.logger.info("🔍 检测到DHCP报文 - 类型: %s, 端口: %s", dhcp_type, in_port)

    #         # 处理DHCP报文
    #         self.handle_dhcp_packet(datapath, in_port, dhcp_type, msg)
    #     else:
    #         # 非DHCP报文，正常转发
    #         self.flood_packet(datapath, in_port, msg.data, msg.buffer_id)

    def handle_dhcp_packet(self, datapath, in_port, dhcp_type, msg):
        """处理DHCP报文的核心逻辑"""
        # DHCP响应报文（OFFER/ACK）需要检查信任状态
        if dhcp_type in ["DHCPOFFER", "DHCPACK"]:
            if in_port in self.trusted_ports:
                self.logger.info("              ✅ 允许信任端口 %s 的DHCP响应", in_port)

                # 🔥 新增：如果是DHCP ACK，更新绑定表
                if dhcp_type == "DHCPACK":
                    self.update_binding_table(datapath, in_port, msg)
                # 将数据以广播形式发出
                self.flood_packet(datapath, in_port, msg.data, msg.buffer_id)

            else:
                self.logger.warning(
                    "               🚫 拦截！非信任端口 %s 的DHCP响应", in_port
                )
                # 丢弃报文，不进行任何操作
        else:
            # DHCP请求报文（DISCOVER/REQUEST）允许通过
            self.logger.info("             ✅ 转发DHCP客户端请求")
            self.flood_packet(datapath, in_port, msg.data, msg.buffer_id)

    def get_dhcp_message_type(self, dhcp_pkt):
        """获取DHCP报文类型"""
        self.logger.info(
            "          🔧 开始解析DHCP选项，选项数量: %d",
            len(dhcp_pkt.options.option_list),
        )

        for i, option in enumerate(dhcp_pkt.options.option_list):
            # self.logger.info("          🔧 选项[%d]: tag=%s, value=%s, value类型=%s",
            #             i, option.tag, option.value, type(option.value))

            if option.tag == 53:  # DHCP Message Type选项
                # self.logger.info("          ✅ 找到DHCP报文类型选项，原始值: %s", option.value)

                message_types = {
                    1: "DHCPDISCOVER",
                    2: "DHCPOFFER",
                    3: "DHCPREQUEST",
                    5: "DHCPACK",
                    6: "DHCPNAK",
                    7: "DHCPRELEASE",
                    8: "DHCPINFORM",
                }

                # 处理可能的类型转换问题
                if isinstance(option.value, bytes):
                    value_int = int.from_bytes(option.value, byteorder="big")
                    # self.logger.info("          🔧 字节值转换: %s -> %d", option.value, value_int)
                else:
                    value_int = int(option.value)

                result = message_types.get(value_int, "UNKNOWN")
                # self.logger.info("          🔧 类型映射结果: %d -> %s", value_int, result)
                return result

        self.logger.warning("           ⚠️ 未找到DHCP报文类型选项(tag=53)")
        return "UNKNOWN"

    # def get_dhcp_message_type(self, dhcp_pkt):
    #     """获取DHCP报文类型"""
    #     for option in dhcp_pkt.options.option_list:
    #         if option.tag == 53:  # DHCP Message Type选项
    #             message_types = {
    #                 1: "DHCPDISCOVER",
    #                 2: "DHCPOFFER",
    #                 3: "DHCPREQUEST",
    #                 5: "DHCPACK",
    #                 6: "DHCPNAK",
    #                 7: "DHCPRELEASE",
    #                 8: "DHCPINFORM"
    #             }
    #             return message_types.get(option.value, "UNKNOWN")
    #     return "UNKNOWN"

    def flood_packet(self, datapath, in_port, data, buffer_id=None):
        """广播数据包（除了入端口）"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 广播到所有端口（除了来源端口）
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
        else:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data,
            )
        datapath.send_msg(out)

    # 🔥 新增：绑定表（IP-MAC）更新函数
    def update_binding_table(self, datapath, in_port, msg):
        """从DHCP ACK报文中提取信息并更新绑定表"""
        try:
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

            if not eth_pkt or not dhcp_pkt:
                return

            # 提取客户端MAC地址（从以太网头）
            client_mac = eth_pkt.dst  # DHCP ACK的目的MAC是客户端MAC

            # 从DHCP ACK中提取分配的IP地址
            assigned_ip = self.extract_assigned_ip(dhcp_pkt)
            if not assigned_ip:
                return
            # 更新绑定表（DHCP来源优先级最高）
            self.binding_table[client_mac] = {
                "ip": assigned_ip,
                "port": in_port,
                "switch_id": datapath.id,
                "timestamp": time.time(),
                "source": "dhcp",
                "lease_time": self.extract_lease_time(dhcp_pkt),
            }

            self.logger.info(
                "📋 DHCP绑定表更新: %s -> %s (端口%d, 交换机%d)",
                client_mac,
                assigned_ip,
                in_port,
                datapath.id,
            )

        except Exception as e:
            self.logger.error("❌ 更新绑定表时出错: %s", e)

    # 🔥 新增：从DHCP报文中提取分配的IP地址
    def extract_assigned_ip(self, dhcp_pkt):
        """从DHCP ACK报文中提取yiaddr字段（分配的IP地址）"""
        if hasattr(dhcp_pkt, "yiaddr") and dhcp_pkt.yiaddr:
            return dhcp_pkt.yiaddr
        return None

    def extract_lease_time(self, dhcp_pkt):
        """从DHCP选项中提取租约时间"""
        for option in dhcp_pkt.options.option_list:
            if option.tag == 51:  # IP Address Lease Time
                return (
                    option.value if isinstance(option.value, int) else 3600
                )  # 默认1小时
        return 3600  # 默认租约时间

    # 🔥 新增：绑定表查询函数
    def get_binding_info(self, mac_address):
        """查询指定MAC地址的绑定信息"""
        return self.binding_table.get(mac_address)

    def print_binding_table(self):
        """打印当前绑定表状态"""
        self.logger.info("------------📊 当前IP-MAC绑定表状态:-----------")
        if not self.binding_table:
            self.logger.info("   绑定表为空")
            return

        for mac, info in self.binding_table.items():
            # self.logger.info(self.binding_table)
            self.logger.info(
                "   MAC: %s -> IP: %s, 端口: %d, 来源: %s",
                mac,
                info["ip"],
                info["port"],
                info["source"],
            )
        self.logger.info("----------------------------------------------------------")

    # 🔥 新增：定期清理过期绑定项（可选）
    def cleanup_expired_bindings(self):
        """清理过期的绑定表项"""
        current_time = time.time()
        expired_macs = []

        for mac, info in self.binding_table.items():
            if current_time - info["timestamp"] > info["lease_time"]:
                expired_macs.append(mac)

        for mac in expired_macs:
            del self.binding_table[mac]
            self.logger.info("🗑️ 清理过期绑定: %s", mac)

    def handle_arp_packet(self, datapath, in_port, arp_pkt, packet_data):
        """智能DAI：允许合法通信，拦截明确欺骗"""

        # 信任端口完全豁免
        if in_port in self.trusted_ports:
            if arp_pkt.opcode == 1:
                self.logger.info("  ✅ 来自DAI信任端口豁免，允许广播ARP请求")
            elif arp_pkt.opcode == 2:
                self.logger.info("  ✅ 来自DAI信任端口豁免，允许广播ARP响应")
            self.flood_packet(datapath, in_port, packet_data)
            return

        # src_mac = arp_pkt.src_mac
        src_mac = self.normalize_mac(arp_pkt.src_mac)
        src_ip = arp_pkt.src_ip
        opcode = arp_pkt.opcode

        # 如果是ARP请求，总是允许（支持网络发现）
        if opcode == 1:  # ARP请求
            self.logger.info(
                "  ✅ DAI检测为ARP请求: %s 请求查询目标%s的IP, 端口=%d, 直接广播",
                src_mac,
                arp_pkt.dst_ip,
                in_port,
            )
            self.flood_packet(datapath, in_port, packet_data)
            return
        if opcode == 2:  # ARP响应
            self.logger.info(
                "  🔍 DAI检测为ARP响应: 源MAC=%s -> （我的IP是）源IP=%s, 端口%d, 🔍验证中...",
                src_mac,
                src_ip,
                in_port,
            )
            # 调用验证函数
            is_valid, reason = self.validate_arp(src_mac, src_ip, in_port)

            if is_valid:
                self.logger.info("  ✅ DAI验证通过: %s", reason)
                self.flood_packet(datapath, in_port, packet_data)
            else:
                self.logger.warning(
                    "   🚫 DAI拦截: %s", reason
                )  # 拦截ARP欺骗，不进行任何操作

        # 其他类型的ARP报文（如RARP）正常转发
        else:
            self.logger.info("  ✅ DAI允许其他ARP操作: 操作码%d", opcode)
            self.flood_packet(datapath, in_port, packet_data)

    # def validate_arp(self, mac, ip, port):
    #     """
    #     验证ARP响应的合法性
    #     返回: (is_valid, reason)
    #     - is_valid: True=允许通过, False=拦截
    #     - reason: 验证结果的描述
    #     """
    #     # 检查MAC地址是否在绑定表中
    #     if mac not in self.binding_table:
    #         # 新设备，学习并允许通过
    #         self.binding_table[mac] = {
    #             "ip": ip,
    #             "port": port,
    #             "source": "dynamic",  # 动态学习
    #             "timestamp": time.time(),
    #         }
    #         self.logger.info("  📋 DAI学习新设备: %s -> %s (动态学习)", mac, ip)
    #         return True, "新设备学习"

    #     # 获取绑定表中的记录
    #     binding_info = self.binding_table[mac]

    #     # 检查IP地址是否匹配
    #     if binding_info["ip"] != ip:
    #         # IP不匹配，可能是ARP欺骗
    #         reason = f"IP不匹配! 声称 {ip}, 绑定表记录 {binding_info['ip']}"

    #         # 根据来源决定处理策略
    #         if binding_info["source"] == "dhcp":
    #             # DHCP分配的IP，严格拦截
    #             self.logger.warning("   🚫 DAI验证失败: %s", reason)
    #             return False, reason
    #         elif binding_info["source"] == "static":
    #             # 静态配置，记录警告但允许（可能是合法变更）
    #             self.logger.warning("   ⚠️ DAI警告: %s", reason)
    #             # 更新绑定表
    #             binding_info["ip"] = ip
    #             binding_info["timestamp"] = time.time()
    #             return True, "静态IP变更（已更新）"
    #         else:
    #             # 动态学习的设备，更新信息
    #             self.logger.info("  ℹ️ DAI更新: %s", reason)
    #             binding_info["ip"] = ip
    #             binding_info["timestamp"] = time.time()
    #             return True, "动态学习更新"

    #     # IP匹配，验证通过
    #     return True, "IP-MAC映射一致"

    def validate_arp(self, mac, ip, port):
        """增强版ARP验证：正确处理静态设备"""
        # 标准化MAC地址格式
        mac_str = self.normalize_mac(mac)

        self.logger.info("  🔍 DAI验证: MAC=%s, IP=%s, 端口=%d", mac_str, ip, port)

        # 检查MAC是否在绑定表中
        if mac_str not in self.binding_table:
            # 新设备学习（动态来源）
            return self._learn_new_device(mac_str, ip, port)

        binding_info = self.binding_table[mac_str]
        self.logger.info(
            "   🔍 绑定表记录: %s -> %s (来源: %s)",
            mac_str,
            binding_info["ip"],
            binding_info.get("source", "unknown"),
        )

        # 根据设备来源采取不同验证策略
        if binding_info.get("source") == "static":
            # 静态设备：严格验证，必须匹配预注册IP
            if ip != binding_info["ip"]:
                reason = f"静态设备IP欺骗! 声称 {ip}, 配置为 {binding_info['ip']}"
                self.logger.warning("   🚫 %s", reason)
                return False, reason
            return True, "静态IP验证通过"

        elif binding_info.get("source") == "dhcp":
            # DHCP设备：严格验证，必须匹配分配IP
            if ip != binding_info["ip"]:
                reason = f"DHCP设备IP欺骗! 声称 {ip}, 分配为 {binding_info['ip']}"
                self.logger.warning("   🚫 %s", reason)
                return False, reason
            return True, "DHCP IP验证通过"

        else:  # dynamic来源或其他
            # 动态学习设备：必须匹配首次学习值
            first_ip = binding_info.get("first_claim_ip", ip)
            if ip != first_ip:
                reason = f"动态设备IP欺骗! 声称 {ip}, 首次学习为 {first_ip}"
                self.logger.warning("   🚫 %s", reason)
                return False, reason
            return True, "动态IP验证通过"


    def _learn_new_device(self, mac, ip, port):
        """学习新设备（动态来源）"""
        self.binding_table[mac] = {
            "ip": ip,
            "port": port,
            "switch_id": 1,  # 假设交换机ID为1
            "timestamp": time.time(),
            "source": "dynamic",
            "first_claim_ip": ip,  # 记录首次声明的IP
        }
        self.logger.info("📋 DAI学习新设备: %s -> %s (动态学习)", mac, ip)
        return True, "新设备学习阶段"


    def normalize_mac(self, mac):
        """标准化MAC地址格式"""
        if isinstance(mac, bytes):
            # 字节格式转换为字符串
            return ":".join("%02x" % b for b in mac).lower()
        elif isinstance(mac, str):
            # 确保小写和标准格式
            return mac.lower().replace("-", ":")
        else:
            return str(mac).lower()



    def pre_register_static_devices(self):
        """
        预先注册静态配置的设备到绑定表
        在单一交换机拓扑中，端口分配通常是：
        - h1: 端口1, MAC: 00:00:00:00:00:01
        - h2: 端口2, MAC: 00:00:00:00:00:02
        - h3: 端口3, MAC: 00:00:00:00:00:03 (DHCP客户端，不预注册)
        - h4: 端口4, MAC: 00:00:00:00:00:04
        """
        # 静态设备配置：MAC地址、IP地址、端口号
        static_devices = [
            {
                "mac": "00:00:00:00:00:01",
                "ip": "10.0.0.100",
                "port": 1,
                "description": "h1 (DHCP服务器)",
            },
            {
                "mac": "00:00:00:00:00:02",
                "ip": "10.0.0.200",
                "port": 2,
                "description": "h2 (非法DHCP服务器)",
            },
            {
                "mac": "00:00:00:00:00:04",
                "ip": "10.0.0.4",
                "port": 4,
                "description": "h4 (静态客户端)",
            },
        ]

        for device in static_devices:
            self.binding_table[device["mac"]] = {
                "ip": device["ip"],
                "port": device["port"],
                "switch_id": 1,  # 假设交换机ID为1
                "timestamp": time.time(),
                "source": "static",  # 关键：标记为静态来源
                "description": device["description"],
                "lease_time": 0,  # 静态设备无租约时间
            }
            self.logger.info(
                "📋 预注册静态设备: %s -> %s (%s)",
                device["mac"],
                device["ip"],
                device["description"],
            )


if __name__ == "__main__":
    print("这是一个Ryu应用，请使用: ryu-manager simple_dhcp_snooping.py 运行")
