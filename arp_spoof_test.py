#!/usr/bin/env python3
"""
简化的ARP欺骗测试脚本
在Mininet主机中运行此脚本来测试DAI功能
"""

import socket
import struct
import sys


def send_arp_spoof(target_ip, spoofed_ip, interface):
    """发送ARP欺骗包"""
    try:
        # 创建原始套接字
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))

        # 获取本机MAC地址（简化版，实际应该从接口获取）
        # 这里我们使用硬编码的MAC，实际使用时需要修改
        local_mac = b"\x00\x00\x00\x00\x00\x04"  # h4的MAC

        # 目标MAC（广播）
        target_mac = b"\xff\xff\xff\xff\xff\xff"

        # 构造ARP响应包
        arp_packet = (
            target_mac  # 目标MAC
            + local_mac  # 源MAC
            + b"\x08\x06"  # 以太网类型: ARP
            + b"\x00\x01"  # 硬件类型: 以太网
            + b"\x08\x00"  # 协议类型: IP
            + b"\x06"  # 硬件地址长度
            + b"\x04"  # 协议地址长度
            + b"\x00\x02"  # 操作码: 响应
            + local_mac  # 发送方MAC
            + socket.inet_aton(spoofed_ip)  # 发送方IP（欺骗的IP）
            + target_mac  # 目标MAC
            + socket.inet_aton(target_ip)  # 目标IP
        )

        s.send(arp_packet)
        s.close()
        print(f"✅ ARP欺骗包已发送: 声称 {spoofed_ip} 的MAC是 {local_mac.hex()}")

    except Exception as e:
        print(f"❌ 发送ARP欺骗包失败: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("用法: python3 arp_spoof_test.py <目标IP> <欺骗的IP> <接口>")
        print("示例: python3 arp_spoof_test.py 10.0.0.100 10.0.0.13 h4-eth0")
        sys.exit(1)

    target_ip = sys.argv[1]
    spoofed_ip = sys.argv[2]
    interface = sys.argv[3]

    send_arp_spoof(target_ip, spoofed_ip, interface)
