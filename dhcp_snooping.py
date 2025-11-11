"""主应用文件：实现DHCP Snooping功能"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, dhcp

class DHCPSnooping(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DHCPSnooping, self).__init__(*args, **kwargs)
        # 初始化绑定表
        self.mac_to_port = {} # 用于存储MAC地址到端口的映射
        self.dhcp_binding_table = {}  # 用于存储DHCP绑定信息

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 安装默认流表项：将无法匹配的数据包发送到控制器
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match,
                                   instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # 处理接收到的数据包
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 学习MAC地址和端口的映射
        self.mac_to_port[eth.src] = in_port

        # 处理DHCP报文
        if eth.ethertype == 0x0800:  # IP报文
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt and ip_pkt.proto == 17:  # UDP
                udp_pkt = pkt.get_protocol(dhcp.dhcp)
                if udp_pkt:
                    self.handle_dhcp(datapath, in_port, eth, ip_pkt, udp_pkt, msg.data)

        # 如果不是DHCP报文，或者处理完DHCP后，可以继续处理其他报文
        # 这里我们可以添加其他逻辑，比如ARP处理等

    def handle_dhcp(self, datapath, in_port, eth, ip_pkt, dhcp_pkt, data):
        # 这里实现DHCP Snooping逻辑
        # 1. 判断报文类型（Discover, Offer, Request, ACK等）
        # 2. 判断端口是否信任端口（假设某个端口是信任端口，比如连接合法DHCP服务器的端口）
        # 3. 如果是从非信任端口收到的DHCP响应报文（如Offer、ACK），则丢弃
        # 4. 如果是DHCP请求报文，则允许通过，并记录绑定信息（当收到ACK时记录）
        # 5. 其他逻辑

        # 示例：打印DHCP报文类型
        self.logger.info("DHCP packet: %s", dhcp_pkt)
        
        # 示例：假设端口1是信任端口，其他端口是非信任端口
        trusted_port = 1
        if in_port != trusted_port:
            # 如果是从非信任端口收到的DHCP响应报文，则丢弃
            if dhcp_pkt.op == 2:  # 2表示响应报文（Offer/ACK等）
                self.logger.info("Drop DHCP response from untrusted port %s", in_port)
                return  # 直接返回，不处理这个报文，相当于丢弃

        # 如果不是要丢弃的报文，则正常转发（这里简单广播，实际应根据情况转发）
        # 注意：这里只是示例，实际处理应该更复杂，比如DHCP请求报文应该只发送到信任端口等
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)