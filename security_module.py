"""
防范DHCP攻击的安全模块
包括：
1. DHCP Snooping：防止伪造的DHCP服务器发送恶意的IP地址
2. DHCP Rate Limiting：限制DHCP请求的速率，防止洪水攻击

"""


def check_dhcp_rate_limit(self, src_mac, in_port):
    """检查DHCP请求速率限制"""
    current_time = time.time()
    if src_mac not in self.rate_limit_table:
        self.rate_limit_table[src_mac] = []

    # 清理过期记录
    self.rate_limit_table[src_mac] = [
        t
        for t in self.rate_limit_table[src_mac]
        if current_time - t < 60  # 60秒时间窗口
    ]

    # 检查是否超过阈值（例如：每秒10个请求）
    if len(self.rate_limit_table[src_mac]) > 10:
        return False  # 超过限制

    self.rate_limit_table[src_mac].append(current_time)
    return True


def validate_ip_source(self, pkt, in_port, datapath_id):
    """验证IP报文的源地址合法性"""
    ip_pkt = pkt.get_protocol(ipv4.ipv4)
    if ip_pkt:
        src_mac = pkt.get_protocol(ethernet.ethernet).src
        # 检查IP-MAC-端口绑定是否匹配
        if src_mac in self.dhcp_binding_table:
            binding = self.dhcp_binding_table[src_mac]
            if (
                ip_pkt.src != binding["ip"]
                or in_port != binding["port"]
                or datapath_id != binding["switch"]
            ):
                return False  # 非法源IP
    return True
