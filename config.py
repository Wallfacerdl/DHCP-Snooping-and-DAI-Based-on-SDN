"""配置管理类 - 单例模式"""


class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._init_config()
        return cls._instance

    def _init_config(self):
        """初始化配置参数"""
        self.TRUSTED_PORTS = {1}
        self.SWITCH_ID = 1
        self.LOG_INTERVAL = 30  # 日志打印间隔
        self.DEFAULT_LEASE_TIME = 3600  # 默认租约时间

        # 🔥 新增：DHCP饿死攻击防护相关变量
        self.DHCP_REQUEST_COUNT = {}  # 记录每个端口的DHCP请求计数
        self.DHCP_RATE_LIMIT = 10  # 速率限制：10个包/秒
        self.WINDOW_SIZE = 5  # 统计时间窗口：5秒
        self.MIN_SAMPLE_SIZE = 5  # 🔥 新增：最小样本量（需要5个报文才开始检查）

        # 预注册的静态设备
        self.STATIC_DEVICES = [
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

    def get_trusted_ports(self):
        return self.TRUSTED_PORTS

    def get_static_devices(self):
        return self.STATIC_DEVICES
