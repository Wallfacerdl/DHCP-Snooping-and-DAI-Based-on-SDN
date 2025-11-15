"""DHCP Snooping主应用类"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from config import Config
from binding_table import BindingTableManager
from packet_processor import PacketProcessor


class SimpleDhcpSnooping(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDhcpSnooping, self).__init__(*args, **kwargs)

        # 初始化组件
        
        self.config = Config()
        self.binding_table = BindingTableManager(self.logger)
        self.packet_processor = PacketProcessor(self.logger, self.binding_table)

        # 注册观察者
        self.binding_table.add_observer(self)

        self.logger.info(
            "🚀 DHCP Snooping应用启动！信任端口: %s", self.config.TRUSTED_PORTS
        )

    def on_binding_table_change(self, event_type, data):
        """绑定表变化回调（观察者模式）"""
        if event_type == "ADD":
            self.logger.info("🔔 绑定表更新通知: %s -> %s", data["mac"], data["ip"])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """交换机连接处理"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 安装默认流表
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self._add_flow(datapath, 0, match, actions)

        self.logger.info("🔌 交换机 %s 已连接", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """报文入口处理"""
        self.packet_processor.process_packet(ev.msg, ev.msg.datapath)

    def _add_flow(self, datapath, priority, match, actions):
        """添加流表项"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)
