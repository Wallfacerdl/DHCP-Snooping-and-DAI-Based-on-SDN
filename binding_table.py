"""绑定表管理类 - 观察者模式"""

import time
from config import Config


class BindingTableManager:
    def __init__(self, logger):
        self.logger = logger
        self.config = Config()
        self.table = {}
        self.observers = []  # 观察者列表
        self._pre_register_static_devices()

    def add_observer(self, observer):
        """添加观察者"""
        self.observers.append(observer)

    def _notify_observers(self, event_type, data):
        """通知所有观察者"""
        for observer in self.observers:
            observer.on_binding_table_change(event_type, data)

    def _pre_register_static_devices(self):
        """预注册静态设备"""
        for device in self.config.get_static_devices():
            self.add_entry(
                device["mac"],
                device["ip"],
                device["port"],
                "static",
                description=device["description"],
            )

    def add_entry(self, mac, ip, port, source_type, **kwargs):
        """添加绑定表条目"""
        normalized_mac = self.normalize_mac(mac)

        self.table[normalized_mac] = {
            "ip": ip,
            "port": port,
            "switch_id": self.config.SWITCH_ID,
            "timestamp": time.time(),
            "source": source_type,
            **kwargs,
        }

        # 通知观察者
        self._notify_observers(
            "ADD", {"mac": normalized_mac, "ip": ip, "source": source_type}
        )

        self.logger.info(
            "📋 绑定表添加: %s -> %s (%s)", normalized_mac, ip, source_type
        )

    def get_entry(self, mac):
        """获取绑定表条目"""
        normalized_mac = self.normalize_mac(mac)
        return self.table.get(normalized_mac)

    def validate_arp(self, mac, ip, port):
        """验证ARP响应合法性"""
        normalized_mac = self.normalize_mac(mac)
        entry = self.get_entry(normalized_mac)

        if not entry:
            # 新设备学习
            self.add_entry(normalized_mac, ip, port, "dynamic", first_claim_ip=ip)
            return True, "新设备学习阶段"

        # 根据来源类型验证
        if entry["source"] == "static":
            return self._validate_static_device(entry, ip, normalized_mac)
        elif entry["source"] == "dhcp":
            return self._validate_dhcp_device(entry, ip, normalized_mac)
        else:  # dynamic
            return self._validate_dynamic_device(entry, ip, normalized_mac)

    def _validate_static_device(self, entry, claimed_ip, mac):
        """验证静态设备"""
        if claimed_ip != entry["ip"]:
            reason = f"静态设备IP欺骗! 声称 {claimed_ip}, 配置为 {entry['ip']}"
            return False, reason
        return True, "静态IP验证通过"

    def _validate_dhcp_device(self, entry, claimed_ip, mac):
        """验证DHCP设备"""
        if claimed_ip != entry["ip"]:
            reason = f"DHCP设备IP欺骗! 声称 {claimed_ip}, 分配为 {entry['ip']}"
            return False, reason
        return True, "DHCP IP验证通过"

    def _validate_dynamic_device(self, entry, claimed_ip, mac):
        """验证动态设备"""
        first_ip = entry.get("first_claim_ip", claimed_ip)
        if claimed_ip != first_ip:
            reason = f"动态设备IP欺骗! 声称 {claimed_ip}, 首次学习为 {first_ip}"
            return False, reason
        return True, "动态IP验证通过"

    def normalize_mac(self, mac):
        """标准化MAC地址格式"""
        if isinstance(mac, bytes):
            return ":".join("%02x" % b for b in mac).lower()
        elif isinstance(mac, str):
            return mac.lower().replace("-", ":")
        return str(mac).lower()

    def print_table(self):
        """打印绑定表状态"""
        self.logger.info("------------📊 绑定表状态 -----------")
        for mac, info in self.table.items():
            self.logger.info("   %s -> %s (来源: %s)", mac, info["ip"], info["source"])
