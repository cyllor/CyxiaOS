# CyxiaOS 通用操作系统容量设计

2026-11-21 · V0.17 · 设计提案

以 x86_64、1 GiB RAM、4 vCPU 的 COSMIC 桌面为验收配置，覆盖一个本地会话、现有桌面组件和轻量应用。日常回归继续使用 1 GiB 镜像。表中的现行值记录引入启动定额前的 `cosmic-app-library-v1` 容量，启动定额落地情况见第 6 节。

## 1. 限额模型

每类资源分别记录系统硬容量、工作负载组额度、进程额度和关键服务保留量。系统硬容量由物理池、静态表及设备能力决定。组额度约束一个应用及其子进程的总量。进程额度约束 FD 编号、线程和各虚拟地址窗口。保留量包含在系统硬容量内，由内核识别的系统服务使用。组身份由启动方授予并由子进程继承，同 UID 的普通应用也受组额度约束。

警戒水位触发诊断、延后后台启动或回收可重建缓存。硬限额在提交资源前执行。设计借鉴 Linux cgroup v2 的组级内存、任务、CPU 和 I/O 控制，Linux 进程软硬限额与文件对象上限，以及 FreeBSD 按进程、用户和登录类计费的机制。[Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) · [Linux getrlimit(2)](https://man7.org/linux/man-pages/man2/getrlimit.2.html) · [Linux 文件系统限额](https://docs.kernel.org/admin-guide/sysctl/fs.html#file-max-file-nr) · [FreeBSD rctl(8)](https://man.freebsd.org/cgi/man.cgi?query=rctl&sektion=8)

## 2. 1 GiB 物理内存预算

容量设计所用的基线 release 镜像 QMP 内存为 1,073,741,824 B，客体发现 RAM 1,073,201,152 B。ELF 装载区间为 `[0x0010_0000, 0x14bd_1000)`，约 330.82 MiB，已经包含内嵌应用目录、静态元数据和设备缓冲。启动代码按固件内存图在其后取得以下四块独立预留。[基线镜像 manifest](../../artifacts/v017-os-kernel-heap-algorithm-1g-v1/build-manifest.json) · [基线启动串口](../../artifacts/v017-kernel-heap-algorithm-1g-v1/native/serial.raw) · [启动预留顺序](../../kernel/src/runtime/os.rs)

| 启动预留 | 页数（4 KiB） | 物理预算 | 设计约束 |
| --- | ---: | ---: | --- |
| 用户根页表 | 5,120 | 20 MiB | 40 槽 × 128 页，单槽 512 KiB |
| 匿名页池 | 65,536 | 256 MiB | 按成功提交的物理页计费 |
| ELF 与初始栈池 | 65,536 | 256 MiB | 当前每次装载需要一个连续物理段 |
| 共享页池 | 4,096 | 16 MiB | 同一 backing 页计一次，映射引用另计 |
| **合计** | **140,288** | **548 MiB** | 四池按独立地址区间核验 |

最后一池结束于 `0x36fd_1000`，到 1 GiB 地址上界约 144.18 MiB。实际余量按固件 RAM 区间扣除固件、引导、内核及四池区间后计算，并检查最大的连续段。设计采用 **96 MiB 系统余量目标**，其中内核与元数据扩展 32 MiB、回收优先的文件缓存 32 MiB、设备与工作缓冲 16 MiB、回收与关键服务恢复 16 MiB。静态区间已含的对象与缓冲只计一次。按当前镜像地址计算，扣除该目标后最多约 48.18 MiB 可供其他增长。启动验收以完整内存图的区间核算为准。[固件内存图与预留器](../../crates/platform-pc/src/boot.rs)

**进程地址空间**沿用 `full-os-v3`。ELF 窗口 64 MiB，初始栈 2 MiB，ELF backing 与初始栈合计受 16,384 页结构上限约束。匿名窗口 64 MiB，单进程最多 1,024 项分配记录，单次申请最多 2,048 页（8 MiB），线程新增栈也占匿名预算。共享窗口 16 MiB，每进程最多 32 个共享映射，单个共享对象最多 2,048 页（8 MiB）。五个现行窗口覆盖 74 个 2 MiB 页表叶跨度，再计祖先表，沿用 128 页 arena 的重复映射回归。硬容量同时受可用 VA、物理页和元数据约束。[用户 VA 合同](../../crates/contracts/src/user_layout.rs) · [ELF backing](../../kernel/src/desktop/memory/exec_memory.rs) · [匿名分配](../../kernel/src/desktop/memory/user_heap.rs) · [共享映射](../../crates/posix/src/shared_memory.rs) · [页表容量回归](../../tests/host/page_space_reuse_cases.rs)

### 会话与新增应用预算

- 保持 ELF、匿名、共享池的物理容量。建议分别为关键服务恢复保留 **40 MiB 连续 ELF backing、16 MiB 匿名页、2 MiB 共享页**。40 MiB 覆盖已观测的最大单组件 8,826 页（34.48 MiB，含初始栈），用于一次关键组件重启。启用回收前验证实际最大可分配连续段。
- 普通进程匿名警戒水位 48 MiB，compositor 等经实测的重载进程 60 MiB。系统匿名池和共享池达到 80% 时告警并延后后台新申请，降至 75% 时解除压力状态。前台申请继续按组、进程及关键服务保留额度检查。ELF 池优先检查连续段能否承接关键组件，同时记录总页水位。
- 以额外同时运行两个轻量应用为第一阶段容量场景。每个应用组按 **ELF 8 MiB、匿名 8 MiB、共享 1 MiB、2 进程、8 线程**计预算，组件实测超出时重新核算其组额度。该场景要求桌面本身的 ELF、匿名、共享用量分别不超过 **200 / 224 / 12 MiB**。当前桌面 ELF 样本峰值 **226.55 MiB**，距目标约 **26.55 MiB**。优先减少 ELF 装载的驻留页，例如按镜像身份复用不可写页，或经测量缩减常驻组件。移出内嵌目录可降低内核驻留区间，同时需要独立核算 ELF 页池收益。

## 3. CPU、进程和对象参数

| 资源 | 现行硬容量 | 1 GiB 设计值 |
| --- | --- | --- |
| CPU 与派发 | 4 CPU，CPU0 服务，3 AP 同时运行独立进程，每根同时由一个 AP 持有 | 维持 4/3，按关键服务、前台、后台组使用相对权重 200/100/25。有空闲预算时允许借用，单组的多个进程共同消耗该组份额 |
| 派发时段 | COSMIC AP wall-time grant 为 8 或 32 ms | 保留现行 grant 与抢占规则。分别计 AP 执行和 CPU0 队列等待，输入、完成和资源回收优先于后台新任务准入 |
| 进程 | 40 槽，8 页标准请求下现有策略可准入 39 个 | 保持 39，普通组累计最多 35，4 个留给关键服务。按 ELF、匿名和 IPC 余量做联合准入 |
| 线程 | 每进程 16（含主线程），40 槽的结构上界为 640 | 每进程保持 16，建议全局 256 个活线程，其中保留 16 个。按线程计费，独立于 PID 数 |
| 子进程退出记录 | 全局 40 槽，记录在回收前持续占用 | 保持 40，普通请求预留 4 个记录给关键服务，成功收割后释放 |
| FD 与 OFD | 每进程 128 FD，系统 512 个打开文件描述（OFD） | 每进程维持 128，96 告警。系统建议 **640 OFD**，其中 32 个保留，有效 FD 编号为 0–127 |
| epoll | 每 owner 16，系统 64，每实例 128 个 watch | 每 owner 和每实例维持，系统建议 **96 实例**，其中 8 个保留。watch 与实例分开计数 |
| inotify | 每 owner 8，系统 32，每实例 64 watch / 64 排队事件 | 维持硬容量，记录溢出次数，用 `IN_Q_OVERFLOW` 提示调用者重扫 |
| `eventfd` / `timerfd` | 计入 FD 和 OFD，重复 FD 可共享同一对象 | 沿用两级总额度，另报活对象和到期队列水位。基础应用按合计 16 个的需求估算 |
| 匿名管道 / PTY | 40 对管道，每对 4 KiB。4 对 PTY | 建议 **64 对管道**，其中 4 对保留，维持 4 KiB `PIPE_BUF` 与 4 对 PTY |
| Unix 域流套接字 | 128 端点、64 连接，每方向 4 KiB，监听 backlog 最大 8 | 建议 **192 端点 / 96 连接**，其中保留 16 / 8，保持缓冲大小与 backlog。分别核算监听、排队和已连接状态 |
| `SCM_RIGHTS` | 16 条消息、64 个引用，每次最多 8 个 FD | 维持硬容量。队列暂存和在途引用均计费，接收失败及销毁时归还对应额度 |
| 共享对象 | 48 对象，4,096 页物理池，每进程 32 个映射 | 建议 **64 元数据对象**，其中 4 个保留，物理页和 VA 窗口维持 |

全局候选值按近几轮的实测高水位留余量。相同观测负载下，OFD 405/640、epoll 56/96、Unix 端点 106/192、连接 52/96、管道 30/64、共享对象 36/64 均低于 70%。达到 80% 时报告对应池和占用最大的组，降到 75% 解除。增加对象表前测量 `size_of` 与 ELF 装载区间差额，验证句柄索引、位图宽度、策略模型输入域和每轮扫描开销。现有 `getrlimit` / `prlimit64` 返回部分固定值并接受无变化的请求。后续可由同一内核限额账本提供软硬值，经授权在硬限额内调整软值。[CPU 及准入策略](../../crates/ai-runtime/src/lib.rs) · [线程与子进程](../../kernel/src/desktop/user/threads.rs) · [退出记录](../../kernel/src/desktop/user/spawn.rs) · [FD 与监视器](../../crates/posix/src/limits.rs) · [Unix 连接](../../crates/posix/src/unix.rs) · [当前 Linux ABI](../../kernel/src/desktop/user/linux.rs)

## 4. 文件系统、设备和服务容量

| 资源 | 现行配置 | 建议值与核算方式 |
| --- | --- | --- |
| 只读启动目录 | 256 MiB 内容预算，256 个文件条目 | 保持上限。记录实际 ROM 字节与内核驻留差额，随应用目录增长逐步迁移大文件到独立只读存储 |
| 可写 RAMFS | 128 节点、8 KiB 单文件、256 KiB 保留载荷。路径缓冲 96 B | 保持，用于运行时文件和轻量配置。节点和字节分别限额，已 unlink 但仍被打开的数据持续计费 |
| 现有持久化 | A/B checkpoint 槽各 768 × 512 B，最小盘空间 768 KiB。单槽 payload 383.5 KiB | 保持现有恢复格式，按一个在途 checkpoint 计费。通用可写卷独立维护 |
| 通用可写卷（随文件系统启用） | 当前配置提供 RAMFS checkpoint | 初始按 **4 GiB 卷、32,768 inode** 设计。每用户默认 512 MiB、4,096 inode，单文件的系统级上限 1 GiB，仍受用户与卷剩余量约束。预留 16 MiB 日志与总容量 10% 的恢复空间，分别核算元数据、数据块和 inode |
| 块设备 I/O（随异步块层启用） | CPU0 轮询，checkpoint 有界分批 | 每设备至多 32 个在途请求，其中 4 个保留给刷盘和恢复。回写缓存包含在 32 MiB 文件缓存，脏页预算 8 MiB |
| 显示 | 单输出 1,024 × 768 × 4 B，扫描输出 3 MiB，单次提交最多 16,384 像素（64 KiB） | 保持单输出和提交上限。图形缓冲按 stride × height × buffer count 计费，模式或输出数变更时预检扫描输出和共享页。一个 1,920 × 1,080 的三缓冲约 23.73 MiB，需单独核算显存或 backing |
| 输入与日志 | 键盘与指针各一 VirtIO 输入设备，串口队列 128 KiB | 保持队列和输入优先服务，在压力下合并可合并的移动及限频诊断，分别统计按键、按钮和移动丢弃。记录日志积压与丢弃计数 |
| IP 网络（随协议栈启用） | 常规镜像无 NIC，用户 socket 支持 Unix 域流 | 初始按 1 NIC、收发各 128 描述符、64 个 IP socket 设计。每 socket 默认收发各 16 KiB、最高各 64 KiB，系统缓冲上限 4 MiB，描述符和 DMA 页另计入设备预算 |

存储卷大小、网络队列和缓存是能力启用后的预算参数。本阶段在同一个 1 GiB 客体内验证。当前边界见 [启动目录构建](../../kernel/build/os.rs) · [RAMFS](../../crates/ai-fs/src/lib.rs) · [checkpoint 格式](../../crates/driver-virtio/src/snapshot.rs) · [GPU 扫描输出](../../crates/driver-virtio/src/gpu.rs) · [实际 VM 设备](../../tools/os_x86.py)。

## 5. 实测水位与扩展顺序

取 1 GiB / 4 vCPU 下启动、日历、工作区和平铺，以及上一轮 App Library 的采样最大值。每行独立取值，连续采样覆盖范围与内核记录的匿名高水位不同。ELF 用量是同一份进程快照内活进程 `image_pages` 的总和，已含初始栈。[工作区客体串口](../../artifacts/v017-kernel-heap-algorithm-1g-v1/panel/serial.raw) · [App Library 客体串口](../../artifacts/v017-kernel-dispatch-1g-v1/app-library/serial.raw) · [回归汇总](../../artifacts/v017-kernel-heap-algorithm-1g-v1/verification.json)

| 资源 | 实测 | 现行容量与水位 |
| --- | ---: | ---: |
| ELF backing（同时驻留） | 57,996 页 / 226.55 MiB | 65,536 页 / 88.5% |
| 全局匿名 backing（内核高水位） | 51,388 页 / 200.73 MiB | 65,536 页 / 78.4% |
| 单进程匿名 backing | 14,950 页 / 58.40 MiB | 16,384 页 / 91.2% |
| 进程 / 同时存活线程 / 单进程线程峰值 | 13 / 59 / 11 | 39 / 640 结构上界 / 16 |
| OFD / 单进程 FD | 405 / 92 | 512 / 128（79.1% / 71.9%） |
| epoll 实例 / watches | 56 / 280 | 64 实例（87.5%）/ 每实例 128 watch |
| Unix 端点 / 连接 | 106 / 52 | 128 / 64（82.8% / 81.3%） |
| 管道不可用槽 | 30 | 40（75.0%） |
| 共享对象 / backing 页 | 36 / 2,082 | 48 / 4,096（75.0% / 50.8%） |

先降低 ELF 驻留并监测最大连续段，同时验证 §3 的对象候选值。完整 COSMIC 会话的旧组件清单估算最多 33 个常驻进程，进程名额还有空间。新增应用按真实启动顺序记录 ELF、匿名页、线程和 IPC 增量，再核算整组及重启所需余量。轻量应用组的初始对象预算为每进程 32 FD，以及每组 32 OFD、4 epoll、2 inotify、12 个 Unix 端点、6 个连接、4 对管道和 4 个共享对象。以 OFD 为例，`405 + 2 × 32 + 32 = 501`，在建议的 640 对象内。

扩展对象池时，候选硬容量取 `max(ceil(实测峰值 / 0.70), 基线占用 + 新组预算 + 关键服务保留量)` 后按实现粒度取整，并验证其静态成本和处理时延。物理页先满足内存账本，再据剩余空间调整分组额度。[完整会话容量盘点](../superpowers/specs/2026-11-17-cosmic-session-process-capacity.md)

增加 CPU 或物理 RAM 时，把发现的拓扑、内存区间和每核与每槽成本作为输入。每增加一个进程槽，按 `512 KiB 页表预留 + 新进程槽带来的 ELF 静态区间增量` 计费，同时核算新增进程的实际 backing 和对象。当前 PC 生产路径的物理上界为 1 GiB，ACPI 和中断表支持 4 CPU。扩大硬件配置需先扩展内存发现、直接映射及 AP 初始化合同，再独立建立证据。资源组和每进程的 ABI 限额可独立于板级容量演进。[PC 物理上界](../../crates/platform-pc/src/boot.rs) · [CPU 拓扑上界](../../crates/platform-pc/src/acpi.rs) · [中断表上界](../../crates/arch-x86_64/src/interrupts.rs)

## 6. 启动时计算有效容量

当前 x86_64 实现从固件内存图、已上线 CPU 和实际设备确定生效容量。COSMIC 启动优先试算完整额度，在内存图副本上依次尝试 100%、90% 至 0% 的区间份额。份额表示各资源从下限到上限的取值比例。四个物理池均检查真实连续区间，区间全部可预留并且系统余量至少 96 MiB 后才发布。页表、匿名、ELF 和共享池的缩减下限分别为 24 槽、224 MiB、240 MiB 和 12 MiB。各根页表仍使用 128 页。最低容量无法满足时，串口报告实际可用字节、最低池预算与系统余量要求。[内存图试算](../../crates/platform-pc/src/boot.rs) · [OS 初始化](../../kernel/src/runtime/os.rs)

同一份额用于选取进程、全局和每进程线程、FD、OFD、epoll、inotify、管道、Unix 域端点与连接以及共享对象的有效额度。`getrlimit(RLIMIT_NOFILE)` 返回进程生效值。静态对象表继续按构建上限分配。CPU0 根据上线 AP 位图派发，支持 1–4 vCPU。单核使用现有同步路径。`SYSTEM_CAPACITY` 报告页池预留后的 RAM、CPU 和设备容量，`ai system` 与 `ai objects` 报告生效的对象池与页池水位。应用组隔离、关键组专用保留量和 §3 的候选对象扩容属于后续设计。[内核准入配置](../../kernel/src/desktop/user/capacity.rs) · [x86 CPU 上线规则](../../kernel/src/arch/x86_64/runtime.rs) · [文件表额度](../../crates/posix/src/open_description.rs)

默认回归使用 1 GiB、4 vCPU。对当前源码生成的同一个镜像，可通过启动参数检查内存和拓扑变化。

```sh
python3 tools/os_x86.py run --build artifacts/v017-os-build --ram-mib 960 --cpus 2
```

真实客体上，默认配置保留 548 MiB 四池，1 GiB 的 1 vCPU 和 2 vCPU 配置均运行用户程序。960 MiB、2 vCPU 选择 70% 份额，预留 528.5 MiB，系统保留约 99.54 MiB，并启用 35 个进程槽、217 个全局线程额度和每进程 118 个 FD。896 MiB 的验证客体在预留池发布前报告最低预算无法满足。[容量启动回归记录](../../artifacts/v017-dynamic-capacity-1g-v1/boot-capacity.json)

1 GiB、4 vCPU 的原生回归、工作区、平铺和应用库通过。日历两轮打开和关闭分别为 11.828、7.657、8.760、7.652 秒。同一纯色背景指针探测中，旧镜像和容量调整镜像的最慢样本分别为 4.268 和 3.062 秒，均超过 500 ms 门槛。[工作区与日历回归](../../artifacts/v017-dynamic-capacity-1g-v1/workspace-v3/workspace-result.json) · [应用库回归](../../artifacts/v017-dynamic-capacity-1g-v1/app-library/application-library-result.json) · [旧镜像指针测量](../../artifacts/v017-dynamic-capacity-1g-v1/pointer-baseline/pointer-measurements.json) · [容量镜像指针测量](../../artifacts/v017-dynamic-capacity-1g-v1/pointer-candidate/pointer-measurements.json)

## 7. 准入与验收

1. **记账与失败原子性。** 内核先检查进程、组、系统和保留额度，再一并提交所需对象。预留中的对象与在途引用参加计数。任一分配失败时归还此前取得的资源。保持已有 ABI 错误语义，并在新接口上区分进程 FD 耗尽（`EMFILE`）、全局文件对象耗尽（`ENFILE`）、线程或进程额度耗尽（`EAGAIN`）、物理页或 VA 耗尽（`ENOMEM`）以及卷空间耗尽（`ENOSPC`）。页表撤销与 TLB 同步完成后归还 backing。
2. **容量边界。** 对进程、线程、FD、OFD、epoll、Unix、共享对象和存储，分别验证上限前一单位、最后一单位、超限请求及回收后重试。组合验证 FD 传递、子进程收割、权限校验和组件反复启动。采样 `used`、`reserved`、`capacity`、`peak`、拒绝原因，页池额外记录 `largest_free_run`。
3. **1 GiB 客体回归。** 使用同源、同应用目录的 4 vCPU QEMU TCG 运行冷启动、日历两次开关、工作区、平铺、App Library 和指针压力。维持既有启动首帧 ≤45 s、对应交互 ≤15 s、指针采样 ≤500 ms 的回归门槛。容量场景加入两个轻量应用和一个关键组件重启，核对系统余量、进程存活、峰值和退出后对象池恢复。[启动回归门槛](v17-cosmic-startup-ready-idle-20261121.md) · [现有桌面验收](v17-cosmic-workspace-applets-20261121.md) · [指针与日历实测](../../artifacts/v017-kernel-heap-algorithm-1g-v1/verification.json)
