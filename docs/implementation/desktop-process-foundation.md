# 桌面 D2 基础：原生多进程与本地通信

日期：2026-10-16。范围：自研内核上的 Rust/no_std 原生多进程/IPC 切片，QEMU virt-10.2、Cortex-A53、单核、256 MiB。本文保留该阶段的私有 ABI、布局和测试证据。后续已增加静态 musl/Linux AArch64 ABI 子集、Unix socket、事件及目录接口，真实 X.Org/Openbox 已运行；当前状态见 [X11 集成记录](x11-desktop-integration.md)。**本页历史结果不代表完整 LXDE 验收。** 桌面选型以 [GUI 设计](../../CyxiaOS-gui-design.md)为准。

## 已实现的运行链路

`Shell 请求 → 本地模型内存准入 → 独立页表/静态 ELF → 本地模型进程选择及时间预算 → EL0 → IRQ/SVC → 等待、唤醒或回收`。

- 4 个静态进程槽，各自独立 Arena、TTBR0 页表、寄存器上下文、FD、cwd 和 umask。每进程 8 个用户页，保持原有 RX/RW/XN 和保护页布局。PID 单调递增，不复用；退出槽可重用，旧通信句柄不会变为新连接。
- 用户池实际预留 32 页（128 KiB），另有每槽 12 KiB 页表和管理元数据。内存模型 8193 接受 32/24/16 页剩余量上的 8 页请求，拒绝仅剩 8 页时的请求，因此当前最多同时运行 **3 个**进程。可用页指授予容量；整个静态池始终占据引导预留 RAM。它与原来的 32 页 EL1 池分开，仍非全 RAM 分配器。
- 每次进入用户态切换到对应根页表，完整刷新 TLB；返回 EL1 禁用低地址遍历并刷新，再允许撤销/清零/回收。单核正确性优先，尚未加入 ASID 优化或 SMP；后续已补充 [FP/SIMD 与 TLS 寄存器交接](desktop-memory-display.md)。
- 原 `posix run ...` C 验证程序保留 500 ms 测试寿命上限；新增原生 Rust 服务没有该无条件上限。`Waiting` 进程仍占有自己的内存，不可误当空槽重用。
- 本地 IPC 为 4 对静态双向字节流，每方向 256 字节。写满返回 `EAGAIN`，允许短读写；对端退出后先排空已发送数据再返回 EOF，继续发送返回 `EPIPE`。按当前进程身份验证端点，用户不能伪造发送者 PID。
- 原生等待支持可读/可写条件，以及最长单次 60 秒的睡眠。检查、注册和唤醒均由 CPU0 唯一前台所有者执行；关闭对端会唤醒等待者。等待进程不参与正常可运行队列排序。此私有 IPC 等待没有信号取消或 POSIX poll/select 语义；Linux personality 的 socket/poll 是后续独立接口。
- 成对启动中第二次准入失败，会关闭并回收第一次启动的进程。单个异常、终止或退出仅关闭所属 FD/端点并撤销自己的映射。

## AI 决策边界

正常 EL0 进程选择复用本地整数 CPU 模型 **12289**：特征为就绪等待时间、固定相同优先级、根据最近 IRQ/系统调用结果估计的工作量。等待时间限幅至训练域；同分先选等待更久者，再按槽序确定。就绪等待超过 100 ms 的防饥饿选择单独记为 `SAFETY_GUARD`，不能计作模型决策。

选中后，模型 **12290** 根据是否 CPU 密集和其他可运行 EL0/EL1 数量选择 1/4 ms 预算，竞争数量限幅至模型训练域 8。IRQ 取回执行权、每次最多 32 次用户返回、IPC 字节顺序/唤醒/权限检查属于机制或安全约束。模型不改写字节，不重排已提交流内容。

`posix list` 显示每个槽的模型编号、AI 选择/保护选择次数、抢占次数、IPC 字节数和等待/唤醒次数。它是易失统计，未新增完整审计流水或在线 CPU 学习。现有权重来自原资源模型的合成训练；本轮复用并验证实际决策链路，未宣称桌面负载优化收益。EL1 与 EL0 仍由主循环分层推进，尚未形成全系统统一调度器。

## 手动检查

通过现有 `Start-CyxiaOS.command` 或 `python3 tools/shell.py` 启动串口 Shell：

```text
posix spawn idle
posix spawn spin
posix list
posix kill 2
posix pair
posix list
posix kill 1
```

PID 以实际启动输出为准。`posix spawn idle` 保持低频睡眠并检查私有内存；`spin` 持续运行，须手动终止；`fault` 延迟后故意访问内核地址，验证隔离。`posix pair` 启动两个 Rust EL0 验证程序，使用相同虚拟地址保存不同 PID 校验值，双向各交换 16 KiB，检查短读写/背压、坏指针、权限和隔离，然后退出。它们是运行时验证程序，不是桌面进程。

`posix status` 显示最后一次成功启动的进程；`posix list` 显示槽内状态。无参数 `posix kill` 终止该最后启动进程；指定 PID 只终止对应活动进程。终态信息随槽重用被覆盖，不提供父子关系、僵尸进程或 waitpid。

## 原生接口与源码

原有 1–15 号 C 接口不变。新增接口均是 **CyxiaOS 私有 ABI**，不宣称对应 POSIX socket、nanosleep 或 Linux syscall：

| 号 | x0/x1/x2 输入 | 结果 |
|---|---|---|
| 16 | 端点/源地址/长度 | 已发送字节数或负 errno |
| 17 | 端点/目标地址/长度 | 已接收字节数、EOF 或负 errno |
| 18 | 保留 | 主动让出本次派发，返回 0 |
| 19 | 保留 | 单调毫秒 |
| 20 | 端点/兴趣（1 可读，2 可写）/保留 | 就绪返回 0，否则等待至可进展；关闭也视为可进展 |
| 21 | 毫秒数/保留/保留 | 0–60000，等待后返回 0；0 立即返回 |

端点配对仅由受信任监督器创建，并通过原生启动寄存器传递；不提供命名空间、本地 socket 路径、连接认证或 FD 传递。预留环属于引导元数据，普通数据推进在已授予的进程执行预算内完成，没有独立的 IPC 流量模型。

- [可移植 IPC](../../crates/posix/src/ipc.rs)：无 unsafe、无硬件依赖。
- [进程监督器](../../kernel/src/user.rs)：进程生命周期、页表绑定、等待和系统调用集成。
- [AI 选择接口](../../crates/ai-runtime/src/lib.rs)：模型排序、时间预算及保护来源。
- [Rust 用户程序](../../user/rust/services.rs)：由现有 Rust 工具链交叉编译，静态嵌入；未下载额外依赖。
- [QEMU 验证器](../../tools/verify_native_services.py)：只发命令和核验客体输出，不在宿主执行被测进程或 IPC。

## 验证与桌面剩余工作

运行 `python3 tools/verify_native_services.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --output artifacts/native-services-dev`；release 映像另验。证据路径：

- `artifacts/native-services-dev/summary.json`、`artifacts/native-services-release/summary.json`：双向完整数据、第三进程抢占、故障隔离、等待对端退出、部分启动回滚及三轮槽/端点重用。
- `artifacts/m1-after-native/summary.json`：原基础内核、格式、主机测试、Clippy、依赖边界和 dev/release 启动。
- `artifacts/posix-after-native-dev/summary.json`、`artifacts/posix-after-native-release/summary.json`：C 接口、权限和生命周期回归。
- `artifacts/graphics-after-native/result.json`：既有色条/原始输入及无设备回退回归。

该阶段结果：108 项 Rust 测试、29 项 Python 测试、22 项 M1 检查通过；原生多进程 dev/release 各 5 组验证通过，C POSIX dev/release 回归通过，Shell 96 步、资源管理 54 步、图形 5 组检查通过。各映像哈希以对应 JSON 为准；覆盖率该轮未测量。

后续容量更新（2026-10-18）：源码现有 8 个槽，底座池 64 页；模型 8193 保守截断输入到原训练范围，最多准入 7 个进程并保留 8 页。`artifacts/desktop-capacity-native-r3/summary.json` 验证七进程并发、第八次拒绝、新 PID 槽复用、部分启动回滚及第七槽私有堆回收；`artifacts/desktop-capacity-high-slot-elf/summary.json` 验证高槽真实 musl ELF 映像 backing。上文 4 槽/32 页/3 进程是原阶段快照。

后续已补充 [匿名内存、静态 musl/TLS 和 EL0 矩形更新](desktop-memory-display.md)，以及静态 ET_EXEC 装载、Linux AArch64 syscall 子集、命名 Unix socket、poll/eventfd 和真实 X.Org/Openbox。本文描述的原生 IPC 仍是私有字节流，不能与另行实现的 socket API 混用。完整桌面继续缺少通用进程启动/等待、实际会话容量、动态库/线程、PTY、大文件写入和持久存储；D2/D3 的完整退出条件按 GUI 设计及各自客体证据判定。
