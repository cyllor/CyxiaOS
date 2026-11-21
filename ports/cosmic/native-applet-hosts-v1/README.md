# 新增 applet 的原生宿主契约

新增程序的真实客体诊断显示：原面板稳态已有 60/64 个 FD，启动下一个子进程
会临时创建六个管道 FD。这个 transient peak 不能靠仅扩大 Unix 池解决。

本层从已验的完整 session 和 panel 导出源码，分别只把本地原生 launch-pad
适配的 `MAX_FDS` 从 64 改为 128。Cargo.lock、Cargo 功能、原版默认配置与
其余源码保持；JSON 绑定前后完整树、模式、配方和补丁。原 SPAWN 请求的
64 字节布局不变，适配读取内核实际 RLIMIT 并校验所有继承 FD。

`tools/build_cosmic_applet_host_v1.py` 重新解析并编译完整锁定依赖图。
panel 显式链接已验的真实 Mesa 修复对象，链接图必须证明旧 Wayland 对象
未被选入。消费者独立核验源码、全部依赖、编译器、SDK、原始链接与发布。

两个宿主必须一起安装，catalog 内的 `usr/share/cyxia/cosmic-applets-v1.json`
绑定资源 profile、源码策略及两个实际 ELF 的 SHA-256。OS 构建和重放入口
独立验这个契约。旧 profile 的 64-FD 和旧对象身份编码保持；新 profile 的
512 个 OFD 槽使用九位槽号和独立的代际退役上限，避免高槽位身份碰撞。
