# 桌面运行基础：匿名内存、FP/TLS 与用户态绘制

更新：2026-10-18。Rust/no_std 实现，ARM 寄存器交接使用独立汇编。**当前已有真实 X.Org/Openbox/GTK 控件图形集成，TWM 路径也已验证；完整 LXDE 桌面尚未完成。** 当前运行证据见 [X11 集成记录](x11-desktop-integration.md)。源码准备及依赖见 [桌面移植清单](desktop-port-inventory.md)。

## 实际实现

默认 256 MiB 配置中，每个原生 EL0 进程拥有独立匿名地址窗口 `0x200000..0xa00000`，4 KiB 页、每槽最多 2048 页、512 个活动分配及 grant 记录。启动时在 RAM 中为八个槽保留共 64 MiB，避开内核映像上限及固件保留范围，并登记到 BootInfo。这是当前 virt 板的 BOOTSTRAP 物理池，不是全 RAM 分配器；内存模型还会保留余量，可成功申请量小于窗口容量。

GTK 启动曾在仍有 1687 页额度时因 128 个分配元数据槽耗尽而失败，因此将匿名堆记录扩至 512；页额度没有扩大。`BoundedGrantLedger<RECORDS>` 将元数据容量显式参数化，匿名堆使用 512，其他小服务仍通过 `GrantLedger` 别名使用 128。大表随进程监督器静态保留，清理时逐项撤销，不在 64 KiB 内核栈上构造整张 512 项表。即使页数仍有余量，512 个记录全部占用后仍会明确返回 ENOMEM。

内核/引导保留区截止 `0x44000000`，即当前 RAM 基址 `0x40000000` 起的 64 MiB；ELF 从 `0x40200000` 装载。内嵌程序和只读资产目录总上限默认 48 MiB，`large-memory` 配置为 52 MiB。另为静态 ELF 映像预留八槽共 128 MiB 的 BOOTSTRAP 物理池，每槽 4096 页；PT_LOAD 和 256 KiB / 64 页用户栈共同计入该额度。栈位于 `0x03000000` 起的独立用户映射，前一页未映射。两个用户物理池都从内核上限之外寻找合法 RAM，检查固件及其他预留区重叠。此预算仍在单核、256 MiB QEMU 基线上运行。

完整桌面使用显式 `large-memory` 配置：512 MiB RAM，匿名窗口 `0x04000000..0x05000000`，每槽 4096 页 / 16 MiB，八槽物理池共 128 MiB；映像池仍为 128 MiB，内核区仍为 64 MiB。匿名池位于 `0x44000000..0x4c000000`，映像池位于 `0x4c000000..0x54000000`，其余 192 MiB 尚未交给通用分配器。单次匿名申请仍限 2048 页，避免超出既有模型训练范围。两种配置由 ELF 内保留的版本化 `CYXIA_BOOT_PROFILE` 声明，启动和验收工具据此选择 QEMU RAM 与期望额度；默认配置没有被暗中扩大。

大池曾让 `PageBatch` 按值返回的临时副本叠加到 64 KiB 内核栈上，真实 X.Org 启动时触发 guard fault。当前 `Heap` 在静态元数据中保留输出缓冲，`Vm::allocate_into/unmap_into` 原地填写；失败清空输出且不改变映射。监督器将较大的 spawn/ELF 装载路径隔离为独立栈帧。反汇编量化的 mmap 相关链由约 65,440 字节降到约 33,168 字节，仍保留原 64 KiB 带保护页内核栈；该量化针对本轮优化候选，不代表全部路径的形式化栈上界。基线与大池主机用例覆盖全池分配、释放和输出复用失败原子性。

正常申请由本地整数模型 `8194` 决定，再由核心 grant ledger 检查真实容量并原子记账。模型使用 16 页为单位的保守量化；合成教师训练范围 free=0..256、request=1..128，留出集 6580 项中 6580 项与教师一致。该数据仅描述策略拟合，不代表桌面性能或生产负载学习。模型拒绝返回 ENOMEM，内核不会跳过模型。固定映像页准入、CPU 选择及预算模型继续使用各自身份。

映射前清零并仅设置用户 RW/NX 权限。返回 EL1、禁用 TTBR0 并完成 TLB 同步后才能撤销，清零后归还 grant。退出、异常和 kill 共用清理路径。跨页用户缓冲区先校验完整范围，再分段复制；文件和 IPC 读写也能使用匿名内存。零字节 I/O 不触碰用户指针，但仍检查文件描述符或通信句柄。

ARM 交接保存和恢复 Q0—Q31 的全部 128 位、FPCR、FPSR、TPIDR_EL0。新进程上下文全部清零，防止进程槽复用暴露旧状态。内核和中断 Rust 仍为 soft-float；反汇编检查只允许两个具名交接函数内的 FP 状态加载/保存，其他函数的 FP/SIMD、未知指令均拒绝。静态 ELF 装载器提供 PT_TLS、映射后的程序头及 Linux auxv，真实 musl 自行建立初始 TLS 块和 errno；此路径已有客体探针验证。已有真实单核最多 8 线程上下文的 musl pthread/clone/futex 子集验证；尚不支持动态 TLS、完整 pthread 或 SVE/SME。

显示驱动保留 GPU 所有权。写固定 framebuffer 前确认上一事务完成，更新后进行缓存同步及带 fence 的传输、刷新；失败时隔离设备，并继续保留 DMA backing。EL0 通过复制接口提交矩形，没有获得 DMA 指针或内核内存的映射权限。

## 私有调用与边界

下表是 CyxiaOS 原生 ABI，**不等价于 POSIX mmap/munmap 或 Linux syscall**。调用号放 x8，参数 x0—x2，返回值或负 errno 放 x0。

独立的 Linux AArch64 personality 另有已验证的私有匿名 mmap、PROT_NONE/RW 与 mprotect 子集，复用同一本地 AI 准入和 grant 回收机制。munmap 仍要求完整原分配；未实现通用文件映射、共享映射及任意部分拆分。不能把原生调用号直接传给 Linux personality。

| 调用 | 参数与结果 | 当前限制 |
|---|---|---|
| 22 | x0 页数，x1/x2 必须为 0；返回用户地址 | 1..2048 页；受模型和容量约束；仅匿名 RW/NX |
| 23 | x0 原始地址、x1 原始页数，x2 必须为 0；成功返回 0 | 完整释放单个原始分配；不支持部分、组合、文件映射或 mprotect |
| 24 | x0 低/高 32 位为 x/y；x1 低/高 32 位为 width/height；x2 为 u32 像素数组地址 | 1024×768，B8G8R8X8，单次最多 1024 像素；完整越界拒绝；缺少设备为 ENODEV |

绘制提交为 MECHANISM，当前会在事务未完成时挂起调用进程，监督器轮询 transfer/flush fence 后唤醒。每阶段 250 ms 上限；错误隔离设备并保持 DMA backing，不提前复用。仍需 CPU 复制与整帧缓存同步，**1/4 ms AI 派发预算不等于系统调用或交互响应硬截止**。当前没有通用图形权限服务或 AI 呈现队列。

`heap_free=2048`（默认）或 `4096`（大池）表示该进程槽匿名池页额度，`image_free=4096` 表示静态 ELF/栈池额度，`free_pages=64` 指八槽的固定映像共享准入池，均不是全系统空闲 RAM。每进程占用 8 页底座，最多准入 7 个活动进程；特征 `free.min(32)` 保持模型 8193 的既有训练域，剩余 8 页时拒绝第八个进程。静态 ET_EXEC、线程子集、显式原生 spawn 及有界持久检查点已实现；动态链接、通用 fork/execve 和大文件写入仍未实现。

## 手动运行

串口 Shell：

```text
posix spawn heap
posix spawn heapfault
posix spawn heapexec
posix spawn fpu
posix list
```

`heapfault` 预期因释放后访问而 Fault/139；`heapexec` 预期因执行 RW/NX 页而 Fault/139。`heap` 与 `fpu` 应为 Exited/0，所有结束路径均应回收动态页。

查看真实客体两次矩形更新：

```sh
python3 tools/graphics.py --paint
```

八色诊断背景上的左上区域先显示 RGB 123456、随后变为 A1B2C3；Ctrl+C 关闭 VM。这是绘制链路验收，不是窗口管理器或桌面替代品。宿主没有绘制或修补截图。

256 MiB 基线中，64 MiB 内核保留区之后的 192 MiB 分别为 64 MiB 匿名池和 128 MiB 映像池，没有额外物理池余量。平台分配器检查固件保留和内存边界；出现占用冲突或 RAM 不足时应明确拒绝，不能重叠映射。

## 验证范围与剩余工作

`tools/verify_desktop_runtime.py` 检查并发 FP/TLS、槽复用清零、匿名内存隔离、撤销后访问保护、NX 保护及异常后恢复。并发要求实际看到两个活动 PID；heap 程序在相同 VA 写入 PID 相关字节并在交替调度后检查。FP 组记录每个进程 AI 选择和 IRQ 数，要求组内发生 IRQ，不宣称每个进程都被 IRQ 抢占。

`tools/verify_graphics_updates.py` 检查两次真实 EL0 绘制后的全部 786432 像素，矩形外像素必须保持原样；同时检查错误参数、回收和无 GPU 路径。DMA 超时/错误隔离有主机模拟测试，尚未在实体硬件注入 GPU 停顿。

Openbox 集成期间的 [内存/FP/TLS 回归](../../artifacts/desktop-runtime-openbox/summary.json)、[静态 musl 及映像回收回归](../../artifacts/ported-openbox/summary.json)、[事件/目录/信号/socket 回归](../../artifacts/desktop-abi-release-r1/summary.json) 均记录为 PASS。它们覆盖该轮 `e0d9486c9d83860a0b25c3875951cf9fa6583ad48f3a6c10281db952d74e1afb` 内核，包括 8 MiB 匿名额度和 64 页静态 ELF 栈；后续构建必须使用其自身报告，不能沿用这些 PASS。

以下是较早的内存/显示阶段历史证据，保留供追溯，**不是当前内核或完整桌面的验收标记**。该阶段开发版 graphics ELF SHA-256 为 `440868d76c343f19f937f9a7864f8acc99cd54218e3c89caed3458a9e73df5f8`；优化版为 `5574bcec966d842326199da1f65d8e203b8f1a3d9c046bb19980581d49d55a6c`。

| 检查 | 结果与证据 |
|---|---|
| Rust 工作区 | 136 项通过；[日志](../../artifacts/m1-desktop-runtime/host-tests.log)，host/default/selftest/graphics Clippy 无警告 |
| Python 工具 | 57 项通过；[日志](../../artifacts/desktop-host-python-final.log)，包含源码获取、像素验收及 FP 反汇编大小写拒绝用例 |
| M1 基础 | [22 项通过](../../artifacts/m1-desktop-runtime/summary.json)，包含 dev/release 自检、压力和默认 production 启动；该报告对应其所录旧构建哈希 |
| 内存/FP/TLS | [开发版 8 项](../../artifacts/desktop-runtime-concurrent-dev-r2/summary.json)、[优化版 8 项](../../artifacts/desktop-runtime-concurrent-release/summary.json)，每轮 9 个进程；并发 FP 的两进程 IRQ 次数分别 42/42、45/41 |
| 重复矩形更新 | [开发版 6 项](../../artifacts/graphics-runtime-dev/result.json)、[优化版 6 项](../../artifacts/graphics-runtime-release/result.json)，全画面逐像素核对 |
| GPU/键鼠回归 | [优化版 5 项](../../artifacts/graphics-runtime-input/result.json) |
| POSIX 与原生 IPC | [POSIX 44 条](../../artifacts/posix-runtime-final/summary.json)、[多进程/IPC 5 组](../../artifacts/native-runtime-final/summary.json)，最终优化版 ELF |
| Shell/FS 与 AI 资源 | [96 条](../../artifacts/shell-desktop-runtime/summary.json)、[54 条](../../artifacts/resources-desktop-runtime/summary.json)，此前同内核逻辑的默认 production ELF，哈希见报告 |

曾出现 FP 用例循环过短、完全没有观察到 IRQ 的验收失败，证据保留在 `artifacts/desktop-runtime-concurrent-dev`。后来延长 EL0 计算区间，保留“必须观察到 IRQ”的断言，新构建才通过；没有重跑旧构建直到碰巧通过。零字节用户复制和大写 FPCR/FPSR 静态扫描遗漏也已修复并复验。模型生成器的 `--check` 确认可复现。

当前已经补齐静态 musl 装载、命名 Unix socket、poll/eventfd、部分信号与目录接口、真实 X11 输入及异步显示；X.Org 和 Openbox 已在该基础上运行。GTK 控件已通过独立显示/点击/输入/关闭客体验收；七进程容量也已验证。PCManFM 的创建/重命名和 LXPanel 任务栏已通过独立客体操作；原生 spawn/GLib 后端及持久检查点也有独立证据。菜单、终端/PTY 与图形保存正在做同一最终映像的联合验收。LXSession、VTE/LXTerminal 及完整 LXDE 依赖闭包仍单独记录，不由其他组件通过推定完成。动态库装载和更完整 ABI 用于扩大应用兼容。此前宿主空间不足已解除，后续构建继续保留来源、许可证和实际失败证据；完整依赖构建峰值仍待测量。
