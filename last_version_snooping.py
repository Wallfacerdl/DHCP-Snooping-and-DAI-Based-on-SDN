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


class SimpleDhcpSnooping(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDhcpSnooping, self).__init__(*args, **kwargs)
        # 定义信任端口：连接合法DHCP服务器的端口（端口1连接h1）
        self.trusted_ports = {1}  # 端口1是信任端口
        self.logger.info("🚀 DHCP Snooping应用启动！信任端口: %s", self.trusted_ports)

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

        pkt = packet.Packet(msg.data)  # 解析收到的以太网帧（数据为二进制格式）

        # 打印更详细的报文信息
        eth = pkt.get_protocol(ethernet.ethernet)  # ethernet报文:表示以太网帧头
        if eth:
            # 加入时间信息
            time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.logger.info(
                "⏰ %s：📦 控制器从交换机收到数据包 - 端口: %s, 源MAC: %s, 目的MAC: %s, 以太网类型: 0x%04x",
                time_string,
                in_port,
                eth.src,
                eth.dst,
                eth.ethertype,
            )

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

            # 处理DHCP报文
            self.handle_dhcp_packet(datapath, in_port, dhcp_type, msg)
            return

        # 如果不是DHCP报文，检查是否是其他需要关注的协议
        if eth and eth.ethertype == 0x0806:  # ARP协议
            self.logger.info("  🔗 检测到ARP报文，端口: %s", in_port)
        elif eth and eth.ethertype == 0x86DD:  # IPv6协议
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


if __name__ == "__main__":
    print("这是一个Ryu应用，请使用: ryu-manager simple_dhcp_snooping.py 运行")
