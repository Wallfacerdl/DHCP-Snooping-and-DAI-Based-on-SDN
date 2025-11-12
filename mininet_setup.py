#!/usr/bin/env python3
"""
Mininet 自动化配置脚本 (集成Config版本)
功能：自动搭建单交换机四主机拓扑，并根据Config配置完成主机设置。
注意：运行此脚本前，请确保已在另一个终端手动启动Ryu控制器。
"""

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
import time

# 从Config类导入配置（假设Config类在config.py中）
try:
    from config import Config
    config = Config()
    STATIC_DEVICES = config.get_static_devices()
    TRUSTED_PORTS = config.get_trusted_ports()
except ImportError:
    # 备用配置（如果无法导入Config类）
    info("⚠️  无法导入Config类，使用备用配置\n")
    STATIC_DEVICES = [
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
    TRUSTED_PORTS = {1}


def run_auto_setup():
    """自动执行Mininet网络创建和主机配置"""
    info("*** 创建单交换机拓扑（4台主机）并连接至远程控制器\n")
    # 创建拓扑。controller指向您手动启动Ryu的IP和端口（默认127.0.0.1:6633）
    topo = SingleSwitchTopo(k=4)
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633),
        autoSetMacs=True,  # 自动设置MAC地址
        autoStaticArp=False,  # 禁用自动ARP，依赖控制器学习
    )

    info("*** 启动网络\n")
    net.start()

    # 获取主机对象
    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
    hosts = {"h1": h1, "h2": h2, "h3": h3, "h4": h4}

    info("*** 开始配置各主机网络（基于Config设置）\n")

    # 配置静态设备（从Config读取）
    for device in STATIC_DEVICES:
        port = device["port"]
        host_name = f"h{port}"
        host = hosts[host_name]
        ip = device["ip"]
        description = device["description"]
        
        info(f"*** 配置{host_name}: {description}\n")
        host.cmd(f"ifconfig {host_name}-eth0 0")
        host.cmd(f"ifconfig {host_name}-eth0 {ip}/24")
        
        # 如果是DHCP服务器，启动dnsmasq
        if "DHCP服务器" in description:
            if port == 1:  # 合法DHCP服务器
                host.cmd("dnsmasq -i h1-eth0 -F 10.0.0.10,10.0.0.50 --dhcp-option=option:router,10.0.0.1 --log-dhcp &")
            elif port == 2:  # 非法DHCP服务器
                host.cmd("dnsmasq -i h2-eth0 -F 10.0.0.150,10.0.0.250 --dhcp-option=option:router,10.0.0.2 --log-dhcp &")
        
        info(f"   {host_name} 配置完成, IP: {ip}\n")

    # 配置h3为DHCP客户端（不在静态设备列表中）
    info("*** 配置h3为DHCP客户端\n")
    h3.cmd("ifconfig h3-eth0 0")
    # 清除可能的旧dhclient进程，然后获取IP
    h3.cmd("dhclient -r h3-eth0; killall -q dhclient; sleep 1")
    h3.cmd("dhclient -v h3-eth0 &")  # 后台执行，避免阻塞
    info("   h3 (DHCP客户端) 正在获取IP...\n")
    time.sleep(3)  # 等待DHCP过程完成

    info("*** 等待网络稳定...\n")
    time.sleep(2)

    info("*** 最终各主机IP配置检查:\n")
    for host_name, host in hosts.items():
        result = host.cmd(f"ifconfig {host_name}-eth0 | grep 'inet '")
        info("   %s: %s\n" % (host_name, result.strip() if result else "未检测到IP"))

    info("*** 网络配置全部完成！您现在可以开始测试。\n")
    info("*** 启动Mininet CLI...\n")
    info("*** 可用测试命令示例:\n")
    info("   1. 基础连通性: h4 ping -c 3 h1\n")
    info("   2. 全网连通性: pingall\n")
    info("   3. 进入h3查看获取的IP: h3 ifconfig h3-eth0\n")
    info("   4. DAI测试: 在h4上尝试ARP欺骗攻击并观察Ryu控制器日志,请将h4_attack文本文件中的内容复制到命令行中\n")

    # 将控制权交给用户
    CLI(net)

    info("*** 停止并清理网络\n")
    net.stop()


if __name__ == "__main__":
    # 设置Mininet日志级别，显示详细信息
    setLogLevel("info")
    # 运行设置函数
    run_auto_setup()