# 🛡️ SDN网络安全管理项目

一个基于**Ryu控制器**和**Mininet**的软件定义网络（SDN）安全项目，实现了**DHCP Snooping**和**动态ARP检测（DAI）** 功能，有效防护局域网内的ARP欺骗攻击和非法DHCP服务器。

## **📋 目录**

- 项目简介
- 核心功能
- 系统架构
- 环境要求
- 快速开始
- 详细使用指南
- 测试与验证
- 项目结构
- 故障排除
- 后续开发

## **🚀 项目简介**

本项目演示了在SDN环境中如何通过中央控制器实现二层网络安全策略：

- **DHCP Snooping**：区分信任与非信任端口，只允许合法DHCP服务器响应
- **动态ARP检测（DAI）**：验证ARP响应的合法性，防止IP-MAC映射被篡改
- **实时监控**：对网络中的ARP和DHCP报文进行深度检测与控制

## **✨ 核心功能**

### **✅ 已实现功能**

- **非法DHCP服务器屏蔽**：自动拦截非信任端口的DHCP响应报文
- **ARP欺骗攻击防护**：实时检测并拦截伪造的ARP请求/响应
- **IP-MAC绑定表管理**：动态学习并维护合法的IP-MAC映射关系
- **信任端口机制**：支持配置信任端口（如连接合法DHCP服务器的端口）
- **详细日志系统**：完整的操作日志，便于监控和调试

### **🔮 后续开发计划**

- 加入容器化技术
- IPv6协议支持
- Web可视化管理界面

## **🏗 系统架构**

```markdown
+----------------+     +----------------+     +----------------+
|   Ryu控制器    |     |  OpenFlow交换机  |     |   Mininet网络   |
|                |     |                |     |                |
| • DHCP Snooping|←---→| • 流表管理     |←---→| • h1:合法DHCP  |
| • DAI防护引擎  |     | • 报文转发     |     | • h2:非法DHCP  |
| • 绑定表管理   |     | • 端口状态监控 |     | • h3:DHCP客户端|
+----------------+     +----------------+     | • h4:静态客户端|
                                               +----------------+

```

## **⚙️ 环境要求**

- **操作系统**：Ubuntu 22.04 LTS 或更高版本
- **Python**：3.9.25
- **必要软件**：
    - Mininet
    - Ryu
    - Open vSwitch

## **🚀 快速开始**

### **1. 环境准备**

**（1）Open vSwitch (OVS)/MiniNet 安装**

[Linux上如何实现软件定义网络（SDN）？_sdn创建自定义拓扑-CSDN博客](https://blog.csdn.net/gongwanzhang/article/details/151781659)

**（2）SDN控制器——ryu安装**

**github主页：**

[https://github.com/faucetsdn/ryu](https://github.com/faucetsdn/ryu)

```bash
# 确保Python环境正确（如果您使用Conda）
# 以管理员模式下运行（因为我conda安装在root目录下）
sudo -s
# 创建3.9版本的Python
conda create -n ryu-env python=3.9
# 激活库
conda activate ryu-env

# 更新setuptools（不然会报错）
pip uninstall setuptools
pip install setuptools==67.6.1

# 将下载好的ryu库安装到环境中
cd /home/Downloads/ryu
pip install .

#检查是否安装成功
ryu-manager --version
```

### **2. 启动系统(依旧在conda** ryu-env**环境下）**

**终端1：启动Ryu控制器**

```bash
# 启动Ryu控制器（自动记录带时间戳的日志）
./start_sdn.sh

```

**终端2：启动Mininet并配置网络**

```bash
# 运行Mininet自动化配置脚本sudo python mininet_setup.py
sudo ./mininet_setup.py
```

## **📖 详细使用指南**

### **网络配置流程**

当Mininet启动后，自动化脚本会执行以下配置：

1. **清理环境**：确保无旧网络配置残留
2. **创建拓扑**：单交换机4主机拓扑（h1-h4）
3. **配置主机**（基于Config类设置，可自行设置或默认）：
    - **h1**：合法DHCP服务器（10.0.0.100，信任端口）
    - **h2**：非法DHCP服务器（10.0.0.200，非信任端口）
    - **h3**：DHCP客户端（自动获取IP）
    - **h4**：静态IP客户端（10.0.0.4）
4. **启动服务**：在h1和h2上启动dnsmasq服务
5. 结束时输出日志

### **配置管理系统**

项目使用Config单例类统一管理所有配置：

```python
# config.py - 配置管理类class Config:
    def _init_config(self):
        self.TRUSTED_PORTS = {1}
        self.STATIC_DEVICES = [
            {
                "mac": "00:00:00:00:00:01",
                "ip": "10.0.0.100",
                "port": 1,
                "description": "h1 (DHCP服务器)",
            },
# ...更多设备配置
        ]

```

## **🧪 测试与验证**

### **自动化测试流程**

项目包含完整的自动化测试脚本，执行以下测试序列：

1. **基础连通性测试**：验证网络基础功能
2. **DHCP功能测试**：确保h3能正确从h1获取IP
3. **DAI防护测试**：自动执行ARP欺骗攻击并验证防护效果

### **手动测试命令**

在Mininet CLI中可执行以下测试：

### **基础功能测试**

```bash
# 测试全网连通性
pingall

# 测试h4到h1的连通性
h4 ping -c 3 h1

# 查看各主机IP配置
h1 ifconfig h1-eth0
h2 ifconfig h2-eth0
h3 ifconfig h3-eth0
h4 ifconfig h4-eth0

```

### **DAI功能测试（来自文件h4_attack.txt)**

```
# 在h4上执行ARP欺骗攻击（测试DAI功能）
h4 python3 -c "
import socket
import struct

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('h4-eth0', 0))

arp_response = (
    b'\xff\xff\xff\xff\xff\xff' +
    b'\x00\x00\x00\x00\x00\x04' +
    b'\x08\x06' +
    b'\x00\x01\x08\x00\x06\x04\x00\x02' +
    b'\x00\x00\x00\x00\x00\x04' +
    b'\x0a\x00\x00\x0d' +
    b'\x00\x00\x00\x00\x00\x00' +
    b'\x00\x00\x00\x00'
)

s.send(arp_response)
s.close()
print('ARP欺骗包已发送: h4声称拥有h3的IP(10.0.0.13)')
"

```

### **预期测试结果**

**DAI防护成功时，Ryu控制器应输出：**

```markdown
🚫 DAI拦截: ARP欺骗! 00:00:00:00:00:04 声称IP 10.0.0.13, 绑定表记录为 10.0.0.4

```

**同时应验证：**

- h1的ARP表未被污染（h3的IP仍指向h3的MAC）
- h3与h1之间的正常通信不受影响

## **📁 项目结构**

```markdown
sdn-security-project/
├── README.md                 # 项目说明文档
├── dhcp_snooping.py          # Ryu控制器主程序
├── mininet_setup.py          # Mininet自动化配置脚本
├── start_sdn.sh              # 控制器启动脚本（带日志记录）
├── config.py                 # 配置管理类（单例模式）
├── packet_processor.py       # 包处理过程
└── logs                      # 日志文件

```

## **🔧 故障排除**

### **常见问题及解决方案**

1. **控制器无法启动**
    
    ```bash
    # 检查Ryu安装
    pip list | grep ryu
    
    # 检查Python环境
    python3 --version
    
    ```
    
2. **Mininet主机无法通信**
    
    ```bash
    # 检查Open vSwitch状态sudo service openvswitch-switch status
    
    # 检查控制器连接
    ovs-vsctl show
    
    ```
    
3. **DAI功能不生效**
    - 确认控制器已正确学习绑定表
    - 检查Config类中的信任端口配置
    - 验证ARP欺骗包格式是否正确
4. **日志文件问题**
    
    ```bash
    # 查看最新日志文件ls -lt ryu_controller_*.log
    
    # 实时监控日志tail -f ryu_controller_20231112_143022.log
    
    ```
    

### **调试技巧**

1. **增加日志详细程度**
    
    ```bash
    # 修改start_sdn.sh中的日志级别
    ryu-manager --ofp-tcp-listen-port=6633 --verbose dhcp_snooping.py
    
    ```
    
2. **检查绑定表状态**
    
    ```bash
    # 在Mininet中查看各主机ARP表
    h1 arp -a
    h2 arp -a
    
    ```
    
3. **验证网络连通性**
    
    ```bash
    # 使用pingall测试全网连通性
    mininet> pingall
    
    ```
    

## **🚀 后续开发**

### **短期计划**

- [ ]  实现Web管理界面

### **长期规划**

- [ ]  开发REST API接口
- [ ]  创建Docker容器化部署

## **📧 联系方式**

如有问题或建议，请通过以下方式联系：

- 邮箱：wallfacerdl@gmail.com
- 项目地址：https://github.com/Wallfacerdl/SDN-project-ryu-for-dhcp_snooping

## **🙏 致谢**

感谢以下开源项目：

- Ryu SDN Framework
- Mininet
- Open vSwitch

---

**⭐ 如果这个项目对您有帮助，请给它一个Star！**