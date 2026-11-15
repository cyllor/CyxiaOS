# V0.17 开发状态

更新：2026-11-15；分支 `CyxiaOS-V0.17`；版本 `0.17.0-dev`。
分支承接 V0.16 `208cd29db8f79533b893ca040f5faa1ebfd5cd23` 和本地 R15/R16 实现，
保留原有 ARM 兼容功能。主平台与验收边界见 [V0.17 设计](../../CyxiaOS-v0.17-platform-design.md)。

本轮已调整总设计、详细设计、实施计划、README、VERSION 和构建 CLI 默认目标。
已有 x86 平台支持与 kernel 目录重构一并纳入新分支；`.qwen/tmp` 本地日志不属于源码提交。

| 项目 | 状态 |
| --- | --- |
| x86 单 BSP、256 MiB、分页/异常/定时器/用户态 | V0.17 dev/release 实际 TCG 平台自测与独立复核通过 |
| kernel 分层 | 已实施，保留共享逻辑模块接口 |
| 正式四核/1 GiB 启动 | 高半区内核、每核上下文、LAPIC/HPET、真实 PCI 设备已运行 |
| 文件持久化 | Shell 创建/写入/读取、块设备 FLUSH 和重启恢复已通过 |
| NativeOs 用户态 | 实际 C 文件 API、寄存器抢占、五种隔离故障、Rust FP/TLS/堆、双进程 IPC 已通过 |
| 调度与计量 | 三个 AP 已执行独立普通进程，并捕获到同时处于 CPL3；CPU0 排空整批后处理共享服务。HPET 时间未冒充 CPU 计费，独立执行计量后端仍待接入 |
| COSMIC x86 依赖 | musl、Rust std、Wayland、xkbcommon、Mesa 客体通过；Smithay 独立客户端、12 场景显示/键盘/清理及资源回收通过 |
| 完整 COSMIC 会话 | 未实现，尚无 cosmic-comp 客体运行声明 |
| KVM、64 核宿主、实体 PC | 未实测 |
| x86 A01–A16 | NOT_RUN；没有迁移历史 PASS |
| A03 | 用户已取消推进；历史要求和失败保留，不再阻塞正式 OS/COSMIC |

当前目标是完整 CyxiaOS 和已有 COSMIC / Smithay / Wayland 桌面线。最新直接运行证据：

- **[最终系统与桌面集成](v17-os-cosmic-20261115.md)**：同一正式镜像的 Smithay/EGL、完整已接通基础回归及同盘重启全部通过；构建与捕获绑定实际源码、SDK、编译产物和验证器。

- [正式 Shell 与磁盘写入](../../artifacts/v017-x86-runtime-20261114-r3/os-dev-05-socket-run/summary.json)：真正的 UART socket 输入、mkdir/write/cat、两次 FLUSH。
- [同盘重启恢复](../../artifacts/v017-x86-runtime-20261114-r3/os-dev-05-reboot-run/summary.json)：读取上次提交的实际内容。
- [正式 NativeOs](../../artifacts/v017-x86-runtime-20261114-r3/os-native-01-run/summary.json)：C/Rust 独立用户空间、实际抢占、异常回收、FP/TLS、堆、并发 IPC；进程退出后页额度归还。四核实际 CR0/EFER 同时验证缓存、浮点异常与完整 FP 保存模式。
- [Linux64 与真实显示](../../artifacts/v017-x86-runtime-20261114-r3/os-linux-04-run/summary.json)：musl、xkbcommon、Wayland 和 Rust std 全部通过，真实 VirtIO 显示核对 786432 个像素；[同盘重启](../../artifacts/v017-x86-runtime-20261114-r3/os-linux-04-reboot-run/summary.json)恢复通过。
- [普通进程多核与 Mesa](../../artifacts/v017-x86-runtime-20261114-r3/os-parallel-01-run/summary.json)：保留上述全部基线，并用 QMP 暂停后的实际寄存器证明 AP1/2/3 同时处于 CPL3；Mesa EGL 1.5/GLES 3.1 softpipe 完成离屏绘制、compute 与内存压力恢复，进程退出归还额度。
- [审查修复后的客体回归](../../artifacts/v017-x86-runtime-20261114-r3/os-parallel-02-run/summary.json)：上述全部回归再次通过；新增真实捕获未映射、只读写入和 PROT_NONE 页故障，验证 `si_code`、硬件 ERR/TRAPNO/CR2 和信号返回后继续执行；负数/零大小 `epoll_create` 正确拒绝。

复现入口为 `tools/os_x86.py build/run` 和 `tools/os_smoke.py`。
上述最新配置构建时增加 `--graphics --ported --feature large-memory --feature mesa-probe`，
捕获时使用 `--scenario parallel --egl`；所需真实 x86 SDK/ELF 必须先构建。
工具绑定编译源码、编译器、用户 ELF/资源文件与独立 Cargo 缓存，保留失败捕获与真实串口记录。
以上结果不代表 Linux64 完整兼容、网络服务或完整桌面已完成。

本轮首次真实启动停在 IF=0 的 HLT，已改为原子的定时器设置与 STI/HLT。另一失败是测试器将
QMP ringbuf-write 误作客体输入；改用真实 serial socket 后才取得文件命令通过证据，原失败保留。
审查另修复用户信号恢复污染 MXCSR 能力掩码、AP 缓存禁用状态及 FFXSR/原生浮点异常设置。
Linux64 调试修正 x86 的 2048 字节最小备用信号栈，以及 musl clone 汇编采用的非 ARM 栈对齐。
新增 UART 接收错误处理会排空坏字节并丢弃整条命令；RTC、UART、进程派发所有权有独立回归。
独立审查修正 Linux64 页故障信号信息丢失、负数 epoll 参数及 LAPIC 伪中断误报用户故障。
对应 POSIX 184 项、架构 24 项组件测试通过；另修复 TLB 撤销确认使用晚读取代次的问题。
内核构建仍有未使用代码警告。

## 早期平台与 A03 历史记录

R16 验证为 939 项 Rust、806 项工具和 14 项专项测试通过；另有 1 项历史输入测试跳过，
26 个历史宿主测试方法失败未关闭。详见 [R16](v16-kernel-layout-20261114-r16.md)。
这些结果只归属原快照；它们不是 V0.17 原生验收。

本轮修复了普通场景仅凭后续模型回复就结束的问题，并用同一发布计数器互斥 root 回复和
C0 留存写入，拒绝写入中的记录。独立验证器继续检查原生采集身份、完整整数 MLP/Plan、
ApplyID 与实际所有权链。详见 [A03 完成门禁修复](v17-a03-applied-completion-20261114.md)。

未训练初始模型在历史 quiet 场景仍选择双核，完整采集还曾触发发布预算超限。
当时真实数据、客体训练、独立验证及 Active 切换未闭环；这些 A03 工作现已取消。
历史失败未被修改或升级为当前平台通过。
