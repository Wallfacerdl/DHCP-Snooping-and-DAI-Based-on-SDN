"""测试文件"""

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.ofproto import ofproto_v1_3

    print("✅ Ryu框架导入成功")

    # 测试您的模块导入（创建空文件先）
    try:
        import dhcp_binding

        print("✅ 自定义模块导入成功")
    except ImportError as e:
        print("⚠️ 自定义模块导入问题:", e)

except ImportError as e:
    print("❌ Ryu框架导入失败:", e)

print("项目结构验证完成")
