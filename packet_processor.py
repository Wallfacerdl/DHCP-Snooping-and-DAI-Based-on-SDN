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
        """处理DHCP报文"""
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if not dhcp_pkt:
            return False

        dhcp_type = self._get_dhcp_message_type(dhcp_pkt)
        self.logger.info("  🔍 检测到DHCP报文 - 类型: %s, 端口: %s", dhcp_type, in_port)
        self._handle_dhcp_packet(datapath, in_port, dhcp_type, msg)
        return True

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

    def _get_dhcp_message_type(self, dhcp_pkt):
        """获取DHCP报文类型"""
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
