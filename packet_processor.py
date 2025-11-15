"""报文处理类 - 策略模式"""

from ryu.lib.packet import packet, ethernet, ipv4, udp, dhcp, arp
import time
from config import Config


class PacketProcessor:
    def __init__(self, logger, binding_table_manager):
        self.logger = logger
        self.config = Config()
        self.binding_table = binding_table_manager
        self.packet_count = 0

    def process_packet(self, msg, datapath):
        """处理入口报文"""
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        # 统计和日志
        self._update_packet_count()

        # 记录基本信息
        self._log_basic_info(pkt, in_port)

        # 按协议类型处理
        if self._process_arp(pkt, datapath, in_port, msg.data):
            return
        if self._process_dhcp(pkt, datapath, in_port, msg):
            return

        # 其他报文正常转发
        self._flood_packet(datapath, in_port, msg.data, msg.buffer_id)

    def _process_arp(self, pkt, datapath, in_port, data):
        """处理ARP报文"""
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return False

        self.logger.info("  🔗 检测到ARP报文，操作码: %d", arp_pkt.opcode)
        self._handle_arp_packet(datapath, in_port, arp_pkt, data)
        return True

    def _process_dhcp(self, pkt, datapath, in_port, msg):
        """处理DHCP报文（支持标准和自定义报文）"""
        # 尝试标准解析
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        # 使用增强的报文类型识别
        dhcp_type = self._get_dhcp_message_type(dhcp_pkt, msg.data)

        if dhcp_type != "UNKNOWN":
            self.logger.info(
                "  🔍 检测到DHCP报文 - 类型: %s, 端口: %s", dhcp_type, in_port
            )

            # 🔥 新增：在进行任何处理前先检查速率
            if not self._check_dhcp_rate(datapath.id, in_port, dhcp_type):
                self.logger.warning(
                    "  🚫 DHCP速率超限! 端口%d 可能正在进行饿死攻击，丢弃报文", in_port
                )
                return True  # 已处理，丢弃报文

            # 速率检查通过，继续正常处理
            self._handle_dhcp_packet(datapath, in_port, dhcp_type, msg)
            return True
        else:
            # 检查是否具有DHCP特征但无法识别类型
            if self._has_dhcp_characteristics(pkt, msg.data):
                self.logger.warning(
                    "  ⚠️  收到疑似DHCP报文但无法识别类型，端口: %s", in_port
                )
            return False

    def _handle_arp_packet(self, datapath, in_port, arp_pkt, packet_data):
        """处理ARP报文核心逻辑"""

        # 信任端口豁免
        if in_port in self.config.get_trusted_ports():
            self.logger.info("  ✅ 信任端口豁免")
            self._flood_packet(datapath, in_port, packet_data)
            return

        src_mac = self.binding_table.normalize_mac(arp_pkt.src_mac)
        src_ip = arp_pkt.src_ip

        if arp_pkt.opcode == 1:  # ARP请求
            self.logger.info("  ✅ 允许ARP请求")
            self._flood_packet(datapath, in_port, packet_data)
            return

        if arp_pkt.opcode == 2:  # ARP响应
            self.logger.info("  🔍 ARP响应验证: %s -> %s", src_mac, src_ip)
            is_valid, reason = self.binding_table.validate_arp(src_mac, src_ip, in_port)

            if is_valid:
                self.logger.info("  ✅ ARP验证通过: %s", reason)
                self._flood_packet(datapath, in_port, packet_data)
            else:
                self.logger.warning("  🚫 ARP拦截: %s", reason)

    def _handle_dhcp_packet(self, datapath, in_port, dhcp_type, msg):
        """处理DHCP报文核心逻辑"""
        if dhcp_type in ["DHCPOFFER", "DHCPACK"]:
            if in_port in self.config.get_trusted_ports():
                self.logger.info("  ✅ 允许信任端口DHCP响应")
                if dhcp_type == "DHCPACK":
                    self._update_dhcp_binding(datapath, in_port, msg)
                self._flood_packet(datapath, in_port, msg.data, msg.buffer_id)
            else:
                self.logger.warning("  🚫 拦截非信任端口DHCP响应")
        else:
            self.logger.info("  ✅ 转发DHCP客户端请求")
            self._flood_packet(datapath, in_port, msg.data, msg.buffer_id)

    def _update_packet_count(self):
        """更新报文计数"""
        self.packet_count += 1
        if self.packet_count % self.config.LOG_INTERVAL == 0:
            self.logger.info("📊 已处理 %d 个数据包", self.packet_count)
            self.binding_table.print_table()

    def _log_basic_info(self, pkt, in_port):
        """记录报文基本信息"""
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            time_str = time.strftime("%Y-%m-%d %H:%M:%S")
            self.logger.info(
                "⏰ %s：📦 端口: %s, 源MAC: %s, 目的MAC: %s",
                time_str,
                in_port,
                eth.src,
                eth.dst,
            )

    def _get_dhcp_message_type(self, dhcp_pkt, raw_data=None):
        """
        增强版DHCP报文类型识别
        支持标准DHCP报文和自定义简化报文
        """
        # 首先尝试标准解析
        if (
            dhcp_pkt
            and hasattr(dhcp_pkt, "options")
            and hasattr(dhcp_pkt.options, "option_list")
        ):
            message_types = {
                1: "DHCPDISCOVER",
                2: "DHCPOFFER",
                3: "DHCPREQUEST",
                5: "DHCPACK",
                6: "DHCPNAK",
                7: "DHCPRELEASE",
                8: "DHCPINFORM",
            }

            for option in dhcp_pkt.options.option_list:
                if option.tag == 53:  # DHCP Message Type
                    if isinstance(option.value, bytes):
                        value = int.from_bytes(option.value, byteorder="big")
                    else:
                        value = int(option.value)
                    return message_types.get(value, "UNKNOWN")

        # 如果标准解析失败，尝试从原始数据中识别
        if raw_data:
            return self._detect_dhcp_type_from_raw(raw_data)

        return "UNKNOWN"

    def _update_dhcp_binding(self, datapath, in_port, msg):
        """更新DHCP绑定信息"""
        try:
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

            if eth_pkt and dhcp_pkt and hasattr(dhcp_pkt, "yiaddr"):
                client_mac = eth_pkt.dst
                assigned_ip = dhcp_pkt.yiaddr

                self.binding_table.add_entry(
                    client_mac,
                    assigned_ip,
                    in_port,
                    "dhcp",
                    lease_time=self.config.DEFAULT_LEASE_TIME,
                )
        except Exception as e:
            self.logger.error("❌ 更新DHCP绑定时出错: %s", e)

    def _flood_packet(self, datapath, in_port, data, buffer_id=None):
        """广播数据包"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def _check_dhcp_rate(self, switch_id, in_port, dhcp_type):
        """
        修正版：合理的DHCP请求速率检查
        解决过早触发和统计不合理的问题
        """
        # 🔥 信任端口豁免（端口1是合法DHCP服务器）
        if in_port in self.config.TRUSTED_PORTS:
            return True  # 信任端口不受速率限制

        # 🔥 只对DHCP Discover进行速率限制（饿死攻击使用Discover）
        if dhcp_type != "DHCPDISCOVER":
            return True  # 其他类型的DHCP报文不受速率限制

        # 生成端口唯一标识
        port_id = (switch_id, in_port)
        current_time = time.time()

        # 初始化该端口的记录
        if port_id not in self.config.DHCP_REQUEST_COUNT:
            self.config.DHCP_REQUEST_COUNT[port_id] = {
                "count": 0,
                "start_time": current_time,
                "last_alert": 0,
                "timestamps": [],  # 🔥 新增：记录时间戳用于滑动窗口
            }

        port_stats = self.config.DHCP_REQUEST_COUNT[port_id]
        port_stats["count"] += 1
        port_stats["timestamps"].append(current_time)  # 🔥 记录时间戳

        # 🔥 清理过旧的时间戳（滑动窗口）
        window_start = current_time - self.config.WINDOW_SIZE
        port_stats["timestamps"] = [
            ts for ts in port_stats["timestamps"] if ts >= window_start
        ]

        # 更新计数为滑动窗口内的实际数量
        actual_count = len(port_stats["timestamps"])

        # 🔥 关键修复：只有达到最小样本量才开始检查速率
        if actual_count < self.config.MIN_SAMPLE_SIZE:
            self.logger.debug(
                "📊 端口 %d: 样本不足 (%d < %d)，跳过速率检查",
                in_port,
                actual_count,
                self.config.MIN_SAMPLE_SIZE,
            )
            return True  # 样本不足，不进行检查

        # 计算时间窗口
        if actual_count > 1:
            elapsed_time = port_stats["timestamps"][-1] - port_stats["timestamps"][0]
        else:
            elapsed_time = 0.001  # 防止除零

        # 🔥 确保有合理的时间窗口
        if elapsed_time < 0.5:  # 至少需要0.5秒才有意义
            self.logger.debug(
                "📊 端口 %d: 时间窗口过短 (%.3fs)，等待更多数据", in_port, elapsed_time
            )
            return True

        # 计算实际速率
        current_rate = actual_count / elapsed_time

        # 调试信息
        self.logger.debug(
            "📊 端口 %d: 计数=%d, 时间=%.3fs, 速率=%.2f 请求/秒",
            in_port,
            actual_count,
            elapsed_time,
            current_rate,
        )

        # 检查是否超限
        if current_rate >= self.config.DHCP_RATE_LIMIT:
            # 限制告警频率，避免日志刷屏
            if current_time - port_stats["last_alert"] > 30:
                self.logger.warning(
                    "⚠️ 检测到疑似DHCP饿死攻击! 端口: %d, 速率: %.2f 请求/秒 (样本: %d个报文/%.3fs)",
                    in_port,
                    current_rate,
                    actual_count,
                    elapsed_time,
                )
                port_stats["last_alert"] = current_time
            return False

        return True

    def _is_custom_dhcp_packet(self, pkt, in_port):
        """
        自定义DHCP报文识别规则
        基于报文特征而非严格的标准格式
        """
        # 检查以太网帧
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            return False, None

        # 特征1：目标MAC是广播地址
        if eth_pkt.dst.lower() != "ff:ff:ff:ff:ff:ff":
            return False, None

        # 特征2：源MAC是本地管理的MAC（02:开头）
        if not eth_pkt.src.lower().startswith("02:"):
            return False, None

        # 检查IP报文
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return False, None

        # 特征3：源IP是0.0.0.0或目标IP是广播地址
        if ip_pkt.src != "0.0.0.0" and ip_pkt.dst != "255.255.255.255":
            return False, None

        # 检查UDP报文
        udp_pkt = pkt.get_protocol(udp.udp)
        if not udp_pkt:
            return False, None

        # 特征4：端口是DHCP标准端口（客户端68 -> 服务器67）
        if not (udp_pkt.src_port == 68 and udp_pkt.dst_port == 67):
            return False, None

        # 如果满足以上所有特征，认为是DHCP Discover报文
        self.logger.info(
            "  🔍 自定义规则识别为DHCP Discover报文，源MAC: %s", eth_pkt.src
        )
        return True, "DHCPDISCOVER"

    def _detect_dhcp_type_from_raw(self, raw_data):
        """
        从原始数据中识别DHCP报文类型
        基于常见特征和模式匹配
        """
        try:
            # 检查数据长度
            if len(raw_data) < 240:  # 最小DHCP报文长度
                return "UNKNOWN"

            # 检查Magic Cookie (偏移量: 以太网14 + IP20 + UDP8 + BOOTP头236 = 278字节)
            if len(raw_data) > 282:
                magic_cookie = raw_data[278:282]
                if magic_cookie == b"\x63\x82\x53\x63":  # 标准Magic Cookie
                    # 检查选项53 (DHCP消息类型)
                    # 选项53通常紧跟在Magic Cookie后面
                    if len(raw_data) > 284:
                        option_tag = raw_data[282]
                        option_length = raw_data[283] if len(raw_data) > 283 else 0

                        if (
                            option_tag == 53
                            and option_length == 1
                            and len(raw_data) > 284
                        ):
                            message_type = raw_data[284]
                            message_types = {
                                1: "DHCPDISCOVER",
                                2: "DHCPOFFER",
                                3: "DHCPREQUEST",
                                5: "DHCPACK",
                                6: "DHCPNAK",
                                7: "DHCPRELEASE",
                                8: "DHCPINFORM",
                            }
                            return message_types.get(message_type, "UNKNOWN")

            # 基于报文特征进行启发式识别
            if self._is_likely_dhcp_discover(raw_data):
                return "DHCPDISCOVER"
            elif self._is_likely_dhcp_offer(raw_data):
                return "DHCPOFFER"
            elif self._is_likely_dhcp_request(raw_data):
                return "DHCPREQUEST"
            elif self._is_likely_dhcp_ack(raw_data):
                return "DHCPACK"

        except Exception as e:
            self.logger.debug("原始数据解析失败: %s", e)

        return "UNKNOWN"

    def _is_likely_dhcp_discover(self, raw_data):
        """启发式判断是否为DHCP Discover报文"""
        # 特征1: 源IP为0.0.0.0
        if len(raw_data) >= 30:
            src_ip = raw_data[26:30]
            if src_ip != b"\x00\x00\x00\x00":  # 0.0.0.0
                return False

        # 特征2: 目标IP为255.255.255.255
        if len(raw_data) >= 34:
            dst_ip = raw_data[30:34]
            if dst_ip != b"\xff\xff\xff\xff":  # 255.255.255.255
                return False

        # 特征3: 目标MAC为广播地址
        if len(raw_data) >= 12:
            dst_mac = raw_data[0:6]
            if dst_mac != b"\xff\xff\xff\xff\xff\xff":  # 广播MAC
                return False

        # 特征4: UDP目标端口为67
        if len(raw_data) >= 36:
            udp_dst_port = raw_data[34:36]
            if udp_dst_port != b"\x00\x43":  # 端口67
                return False

    def _is_likely_dhcp_offer(self, raw_data):
        """启发式判断是否为DHCP Offer报文"""
        # 特征1: 源IP是DHCP服务器IP
        # 特征2: 目标IP可能是广播地址或特定IP
        # 特征3: 包含yiaddr字段（分配的IP）
        # 简化实现：暂时只检查端口
        if len(raw_data) >= 36:
            udp_src_port = raw_data[34:36]
            return udp_src_port == b"\x00\x43"  # 源端口67
        return False

    def _is_likely_dhcp_request(self, raw_data):
        """启发式判断是否为DHCP Request报文"""
        # 类似于Discover但可能有不同特征
        return self._is_likely_dhcp_discover(raw_data)

    def _is_likely_dhcp_ack(self, raw_data):
        """启发式判断是否为DHCP ACK报文"""
        # 类似于Offer但确认分配
        return self._is_likely_dhcp_offer(raw_data)

    def _has_dhcp_characteristics(self, pkt, raw_data):
        """检查是否具有DHCP报文特征"""
        # 检查以太网类型
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt or eth_pkt.ethertype != 0x0800:
            return False

        # 检查IP协议
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt or ip_pkt.proto != 17:  # UDP
            return False

        # 检查UDP端口
        udp_pkt = pkt.get_protocol(udp.udp)
        if not udp_pkt or udp_pkt.dst_port != 67:  # DHCP服务器端口
            return False

        return True
