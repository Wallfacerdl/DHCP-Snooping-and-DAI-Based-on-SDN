from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, HANDLER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(CONFIG_DISPATCHER, [ofproto_v1_3.OFP_VERSION])
    def _config_DISPATCHER(self, ev, **_kwargs):
        # 处理流表默认规则
        pass

    @set_ev_cls(HANDLER, [ofproto_v1_3.OFP_VERSION])
    def _handler(self, ev):
        # 处理数据包
        pass

def main():
    app = SimpleSwitch13()
    app.run()

if __name__ == '__main__':
    main()