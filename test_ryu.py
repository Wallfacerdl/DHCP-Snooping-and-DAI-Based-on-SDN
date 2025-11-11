from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3


class TestApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TestApp, self).__init__(*args, **kwargs)
        print("Ryu 应用初始化成功！")


if __name__ == "__main__":
    print("直接运行测试...")
    app = TestApp()
