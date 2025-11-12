#!/bin/bash
# DHCP Snooping应用启动脚本 - 自动记录带时间戳的日志

echo "🚀 启动DHCP Snooping控制器..."

# 生成带时间戳的日志文件名
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="ryu_controller_${TIMESTAMP}.log"

echo "📋 配置信息:"
echo "   - 控制器端口: 6633"
echo "   - 日志级别: verbose"
echo "   - OpenFlow版本: 1.3"
echo "   - 日志文件: $LOG_FILE"

# 激活conda环境（如果需要）
# source /root/miniconda3/etc/profile.d/conda.sh
# sudo -s
# conda activate ryu-env

# 清除Mininet旧配置
echo "🧹 清理Mininet旧配置..."
sudo mn -c

# 启动Ryu控制器并将输出同时显示在终端和保存到日志文件
echo "⏳ 启动Ryu控制器..."
echo "💡 日志同时显示在终端并保存到: $LOG_FILE"
echo "💡 按 Ctrl+C 停止控制器"

# 使用tee命令同时输出到终端和文件
ryu-manager --ofp-tcp-listen-port=6633 --verbose dhcp_snooping.py 2>&1 | tee "$LOG_FILE"

echo "✅ 控制器已停止"
echo "📁 日志已保存到: $LOG_FILE"