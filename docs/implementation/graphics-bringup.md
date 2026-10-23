# D1 Rust 显示与输入驱动切片

2026-10-15 的 D1 设备接入记录；2026-10-18 更新运行期说明。本文中的最初验收数字属于 D1，当时尚未实现桌面。后续真实 Xorg、Openbox、PCManFM、LXPanel 和终端集成见 [X11 桌面验收](x11-desktop-integration.md)，不应再把本页的历史范围当作当前系统总状态。

## 已实现

- `contracts::VirtioMmioResource` 与有界 DTB 枚举：32 个槽位、禁用节点跳过、拒绝地址重叠、容量溢出、未支持的总线地址转换和 IRQ 编码。
- `cyxia-driver-virtio`：Rust/no_std、无外部依赖，现代 MMIO Version 2，仅协商 VERSION_1；split ring，单个控制命令链，输入队列预投递 8 个独立事件缓冲。
- VirtIO GPU 2D 资源创建、固定 backing、transfer、scanout、flush；携带 fence 并核对回复身份。显示 1024×768 的 8 色测试图，帧由 ARM 客体生成。
- VirtIO keyboard/mouse 原始事件诊断：按下、释放、相对位移。用于 D1 的图形构建明确输出测试输入编码，不是通用输入服务，也不用于生产用户输入日志。
- 独立 `graphics` 编译特性；默认串口构建不运行图形设备初始化。AArch64 启动页表新增 virt 板的 VirtIO Device/XN 窗口，仅访问 DTB 发现且位于该窗口的资源。

采用 ECC Rust ownership/Result/类型边界规范；底层 MMIO/DMA 的 unsafe 限制在驱动和板级适配，通用 DTB 解析禁止 unsafe。C++ 技能不作为改写 Rust 内核的理由。

## 运行与验证

```sh
python3 tools/graphics.py
python3 tools/verify_graphics.py --profile dev
python3 tools/verify_graphics.py --profile release
```

第一个命令构建后显示 QEMU Cocoa 测试窗口，Ctrl+C 关闭它；这是设备诊断入口，不叫“启动桌面”。无窗口自动验证保留原始串口、QEMU 参数、QMP 输入、PPM 截图和结果 JSON。宿主只做输入注入和像素比较，不绘制客体帧。

开发版和优化版均通过以下五项：GPU 与两个输入设备启动；逐像素核对全部 786432 像素；键盘按下/释放及鼠标位移；串口 Shell 可继续响应；未配置图形设备时可回到 Shell。

证据：[开发版](../../artifacts/graphics-dev/result.json)、[优化版](../../artifacts/graphics-release/result.json)。验证工具只在实际执行成功后写 PASS，异常保留 FAIL 和原因。

新增 10 个驱动逻辑用例覆盖错误版本/特性、请求背压、长度/ID/索引损坏、重复输入 ID、16 位 ring 索引回绕、超时隔离和旧 fence。DTB 新增 5 个用例；工作区共 102 个 Rust 测试、29 个 Python 测试通过。主机和 AArch64 graphics 构建 Clippy 无警告；[M1 完整回归](../../artifacts/m1-after-graphics/summary.json) 22 项通过。后续 [POSIX](../../artifacts/posix-after-graphics/summary.json)、[Shell/FS](../../artifacts/shell-after-graphics/summary.json) 和 [AI 资源](../../artifacts/resources-after-graphics/summary.json) 客体回归也通过（本次分别记录 44、96、54 条检查，POSIX 轮询次数随调度变化）。

## 内存与失败路径

静态分配一个 3 MiB 帧和三个 20 KiB 队列池，位于链接器保留的内核池；新增显示节奏策略另有一个 64 KiB CPU 暂存槽。这些资源标为 BOOTSTRAP/MECHANISM，不冒充 AI 正常内存准入。页固定到 VM 生命周期结束；后续 [重复更新接口](desktop-memory-display.md) 只在上一 fence 完成后借用 framebuffer 修改，提交时归还 CPU 借用并同步缓存。底层地址验证及 ELF 检查保证不越出当前内核保留区。

平台提供 DMA 地址转换、缓存 clean/invalidate 和屏障。队列失败后设 FAILED 并禁止重用，静态 DMA 存储继续保留，不在未知设备状态下回收。当前没有热重启/热插拔或运行期回收，GPU 错误退回串口诊断；故障案例的队列逻辑以主机模拟验证，尚未对实体设备或真实 GPU 停顿开展故障注入。

## 明确限制与后续

- 只有初始化保留同步控制命令。运行期 SVC24 与 Xorg DDX 已使用异步提交/轮询，调用线程等待完整 fence、其他任务继续调度；每个 GPU 阶段的超时为 250 ms。新增 [本地显示节奏模型](display-ai-pacing.md) 只控制提交前有界等待，尚不提供通用显示服务公平性或动态 framebuffer 准入。
- 后续输入已有全局有界 FIFO、SYN_DROPPED 重同步、key-state 快照及 Xorg 键盘/相对鼠标路径；焦点和键位转换由实际图形服务处理。LED/status 队列、设备 capability 查询、绝对坐标轴范围和实体硬件仍未完整实现。
- 当前平台仍限现代 MMIO / 小端 AArch64 / QEMU virt / Cortex-A53 / 1 CPU；D1 使用 256 MiB，后续轻量桌面配置使用 512 MiB。legacy、PCI、实体 ARM、多核与第二 ISA 未验证。
- 已移植若干真实静态上游桌面程序，但不等于完整 LXDE、Qt、动态运行库或“大多数 Linux 程序”兼容；具体边界与新验收以对应桌面文档为准。

协议依据：[VirtIO 1.2 CS01](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html)。源码中的固定队列/画面配置是 bring-up 限制，不是通用硬件规格。
