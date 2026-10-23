# POSIX 兼容第一阶段：EL0 与文件接口子集

正式目标与后续验收以 [POSIX 需求与架构设计](../../CyxiaOS-posix-design.md) 为准；本文保留第一阶段原生 C shim 的接口、内存布局和验收记录，不替代完整需求或后续兼容层状态。

2026-10-15 第一阶段交付是 **可重新编译 C 程序的 POSIX 文件接口子集**，以及实际 ARM 用户态隔离、系统调用、静态 ELF 装载和中断恢复基础。该阶段不支持 Linux ABI，不是完整 POSIX 实现或认证。

2026-10-16 实施更新：独立 Linux AArch64 personality 已执行指定静态 musl、X.Org/Openbox 和探针，加入目录 FD、getdents64、openat/fstatat、匿名映射、socket/poll/eventfd 与部分信号。当前范围及限制见 [X11 集成记录](x11-desktop-integration.md)；本页原生 shim 的 15 个调用和固定小映像布局不能当作整个系统的现状。

## 操作

2026-10-20 后续兼容层新增 [CLOCK_MONOTONIC timerfd](timerfd.md)：真实周期
计数、共享 OFD、阻塞读取及 level/oneshot epoll 已有 ARM 客体证据。
它属于 Linux personality 的明确子集，不扩大本页原生 POSIX shim 的声明。

启动 `Start-CyxiaOS.command` 或 `python3 tools/shell.py`，输入：

```text
posix run demo
posix status
cat /posix-result
posix run preempt
posix status
posix run spin
posix status
```

- `demo`：C 程序调用公开头文件中的接口，验证文件创建、共享/独立偏移、局部覆盖、空洞、追加、删除后继续访问、错误码、坏指针、目录操作、文件上限，成功时输出 `POSIX EL0 C program: PASS`，退出码 0。文件 `/posix-result` 内容为 `hello from EL0`。它使用 `/posix` 和 `/posix-result` 作为测试路径；已有同名对象会影响测试。
- `preempt`：运行不主动系统调用的循环，验证中断前后的寄存器内容，成功时输出 `EL0 REGISTERS PASS`。状态显示实际抢占次数。
- `fault` / `kernel` / `readonly` / `execdata` / `guard`：分别触发空地址、内核页访问、只读页写入、数据页执行、未映射保护页访问。预期终态 `Fault`、代码 139；这是本实现的故障状态码，尚无 POSIX 信号投递。
- `spin`：不退出的程序，内核通过 IRQ 收回执行权，500 ms 总存活上限使其进入 `Timeout`、代码 124；不是 POSIX 默认进程时限。
- `posix kill`：操作员终止当前用户进程；代码 137 是本实现状态，不是 `kill()`/信号 API。
- `posix status`：PID、状态、返回码、系统调用次数、抢占次数、AI 派发次数、CPU 模型版本、最近派发预算、异常 ESR/FAR、用户池空闲页数。

2026-10-16 更新：监督器已支持多个独立 EL0 地址空间，当前已扩为 8 槽、64 页底座，内存策略最多准入 7 个进程；`posix run` 仍是固定 C 测试入口，新增 `posix spawn/pair/list/kill PID` 及 Rust 验证程序详见 [D2 多进程基础](desktop-process-foundation.md)。EL1 协作任务和 Shell 继续推进；每个进程独立关闭 FD、撤销映射、清空页并回收授予。状态按槽保留至复用，不提供父子关系或 `waitpid()`。

## 已提供的接口与边界

`user/include` 是 CyxiaOS 的公开 C 头文件；`user/src/libc.c` 将 C 返回值/`errno` 转换为自有系统调用 ABI。

| 接口 | 已实现行为 |
|---|---|
| `open` | 最小可用 FD；`O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/O_EXCL/O_TRUNC/O_APPEND`；独立 open 描述与偏移；单 UID 的 owner 权限检查 |
| `close` | 关闭 FD，最后一个引用关闭时释放描述与 inode pin；进程结束自动关闭 |
| `read/write` | 按偏移传输、EOF、短读/短写、零填充文件空洞、覆盖不截掉尾部；追加按本次写入时 EOF 定位 |
| `lseek` | `SEEK_SET/CUR/END`、负位置/溢出错误；允许越过 EOF，直到后续写入才扩展 |
| `dup/dup2` | 共享同一个 open 描述/偏移；`dup2` 验证源之后才替换目标 |
| `unlink` | 名称消失；已打开 inode 保留到最后引用关闭；重建同名文件不会混淆旧句柄 |
| `mkdir/rmdir/chdir/getcwd` | 有界目录操作、逐组件解析、权限检查；最终 `.` 不被错误折叠删除 |
| `umask` | 创建时屏蔽权限，初始 `0022` |
| `getpid/_exit` | 当前唯一 PID、低 8 位正常退出状态、资源回收 |

截至 2026-10-18，限制包括 16 个 FD/进程、64 个 RAMFS 节点、可写文件最多 4096 字节、UTF-8 路径最多 95 字节及单用户环境。只读引导资产另行提供程序配置和字体。尚不支持用户/组切换、ACL、完整时间戳/stat、符号链接、硬链接、目录 rename 或完整终端规范。Linux personality 的 pipe2 已通过真实 musl 探针；普通文件 rename/renameat2 和有界单核线程均已通过真实 musl 客体验收（`thread-abi-r2` 与 `thread-runtime-r2`），不代表完整 pthread 兼容。第一阶段未提供的目录 FD、socket、fcntl、mmap 及信号已有后续子集实现，但没有因此扩充本页 C shim 的公开接口。未知系统调用返回 `ENOSYS`；不支持的 open 标志返回 `EINVAL`。这些边界不构成整套 POSIX 合规声明。

初始 FD 0 是明确的空输入流（读取 EOF），FD 1/2 是保留的非阻塞控制台输出；不是交互式 TTY，输出可短写或返回 `EAGAIN`。应用需要按返回值重试。保留控制台的单次驱动推进属于机制行为，不计作设备 AI 竞争仲裁。

文件系统与 Shell 共用。内核系统调用处理串行执行，不存在本轮 CPU 内的检查/提交交错；Shell 是受信任操作员，可修改文件，因此不把它算作不可信多租户。Shell 自身也不是 POSIX shell。

## 用户态与内存

实际使用 AArch64 EL0t，SVC 进入 EL1，异常向量保存通用寄存器/PC/PSTATE/SP。中断或 SVC 把上下文交还内核循环；只有内核验证的上下文可重新进入。用户不能设置 EL1 返回状态或屏蔽内核 IRQ。

| 用户虚拟地址 | 权限与用途 |
|---|---|
| `0x100000–0x103fff` | 16 KiB 代码/只读常量，EL0 RX，EL1 execute-never |
| `0x104000–0x105fff` | 8 KiB 数据/BSS，RW，execute-never |
| `0x106000–0x106fff` | 未映射保护页 |
| `0x107000–0x108fff` | 8 KiB 栈，RW，execute-never |

每次启动清零并装载固定静态 ELF，传入 `argc/argv`。加载器检查 ELF64、小端、AArch64、ET_EXEC、两个 PT_LOAD、范围/整数溢出、文件长度、对齐、入口和 RX/RW 权限；拒绝动态解释器、W+X、任意地址映射。没有运行时任意 ELF 文件选择或动态链接器。用户代码需按此布局重新编译。

TTBR0 只包含上述用户页；内核高地址映射保留 EL1 权限。退出用户执行时禁用低地址页表遍历并执行 TLBI/DSB，再清除页表、释放授予及清零。未导出 DMA 映射、未启用多核。系统调用通过安全切片进行 copy-in/copy-out；原始用户地址只作整数验证，不直接解引用。内核代码地址、只读目标、保护页、范围跨界和地址溢出返回 `EFAULT`，不触发内核访问异常。

当前原生小映像的物理池独立静态预留 64 页（256 KiB），8 个槽各有 8 页 Arena 和额外 12 KiB 页表。模型准入最多 7 个活动进程并保留 8 页；未授予页不向 EL0 映射。原有 `mem status` 的 32 页 EL1 池与用户池独立。后续另有每槽 8 MiB 匿名窗口及 16 MiB 静态 ELF/栈池，见 [内存实施记录](desktop-memory-display.md)；这些都是有界池，尚非全 RAM 分配器，也没有共享映射或换页。

## AI 决策及约束

- 启动准入：复用本地内存模型 8193，以私有用户池可用页/8 页请求推理；受信任入口验证后提交并兑现 grant。当前固定映像和小型静态池使这一准入场景很窄，不声称已优化全机内存。
- 用户 CPU 派发：新整数模型 12290，以最近是否因 IRQ 返回、其他可运行 EL0/EL1 任务数（限幅至训练域 8）选择 1 或 4 ms 的真实单调时间预算。`posix status` 显示模型与执行计数；CPU 密集程序无竞争时可得到 4 ms，有 EL1 竞争时缩短。
- 1 ms 定时 IRQ 使不合作代码可被收回；每次派发最多处理 32 次用户返回，以及 C 验证程序专有的 500 ms 存活上限，均为明确的安全约束，不伪装成 AI 最优策略。截止检查在 IRQ/返回点进行，不保证硬实时期限。
- 用户文件读写仍通过原有 AI-FS 的准入、缓存和学习逻辑。拒绝文件增长映射为 `ENOSPC`，拒绝用户启动容量为 `ENOMEM`，模型不得伪造成功或改变读回字节。
- 模型由固定种子合成目标训练，训练脚本保留旧模型权重并增加 USER_QUANTUM；不证明真实业务性能提升，不新增在线 CPU/内存学习。用户状态和启动/终态日志与原有 EL1 `ai audit` 分开；没有持久化审计。

## 源码与构建

- `crates/posix`：无 unsafe 的可移植 FD、路径、用户缓冲区、ELF 校验。
- `crates/ai-fs`：稳定 inode/pin、延迟释放、权限元数据、位置读写，保留 AI 策略。
- `crates/arch-aarch64/src/user.rs` / `user.S`：EL0 进入与返回；`mmu.rs`：用户页权限编码。
- `kernel/src/user.rs`：平台集成、授予/回收、系统调用处理及派发；共享 FS 通过唯一前台所有者借用。
- `user/src/demo.c`：实际测试程序，可编辑后重新构建；`libc.c`/`start.S`：最小运行时；`user/include`：兼容头文件。

production 构建额外使用已安装的 Clang（`--target=aarch64-none-elf`）与 Rust 工具链自带 LLD，不下载库。可用 `CYXIA_CC` 指定 Clang。C 代码禁止 FP/SIMD、PIC 和栈保护依赖，纯静态链接。构建产物 `posix-demo.elf` 在 Cargo 的 kernel build OUT_DIR，并嵌入内核；启动脚本会自动重建。可编译自己的简单 C 程序替换 demo，但不能直接用宿主系统头文件/库链接。

自有 ABI：`svc #0`，x8 系统调用号，x0–x2 参数，x0 成功值或负 errno。1–15 依次为 open、close、read、write、lseek、dup、dup2、unlink、mkdir、rmdir、chdir、getcwd、getpid、umask、_exit；C 封装转为 -1/errno（getcwd 为 NULL）。新增 16–21 是私有 IPC/让出/单调时间/等待/睡眠调用，见 D2 说明；不增加上述 POSIX 符合性计数。此 ABI 不承诺与 Linux syscall 编号或二进制布局一致。

## 验证与后续

```sh
cargo test --locked
python3 tools/train_resource_models.py --check
python3 tools/verify_m1.py --output artifacts/posix-m1-regression
python3 tools/verify_posix.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/posix-release
python3 tools/verify_shell.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/posix-shell-regression
python3 tools/verify_resources.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/posix-resource-regression
```

另构建 dev production 并运行 `verify_posix.py`。整体验收包括 C 语义断言、故障类检查、寄存器保存、抢占、AI 预算随竞争变化、超时/终止回收，以及故障后新程序仍可运行。单元测试覆盖 FD 耗尽前不截断文件、坏 dup2 源不关闭目标、AI 拒绝原子性、ELF 截断/溢出、用户指针及稳定 inode。独立审核发现并修复 `rmdir("/empty/.")` 错删目录的问题。

原阶段验收（2026-10-15，历史映像，非本次更新后的哈希）：

| 检查 | 结果与证据 |
|---|---|
| Rust / Python | 87 / 29 项全部通过；`artifacts/posix-m1-regression/host-tests.log`、`python-tests.log` |
| M1 回归 | 22 项全部通过；`artifacts/posix-m1-regression/summary.json` |
| POSIX ARM production | 开发版、优化版全部通过，各实际启动 10 次用户程序（包含故障、超时及操作员终止）；`artifacts/posix-dev/summary.json`、`artifacts/posix-release/summary.json` |
| 原 Shell / AI-FS | 96 步通过；`artifacts/posix-shell-regression/summary.json` |
| 原 AI 资源管理 | 54 步通过；`artifacts/posix-resource-regression/summary.json` |
| 模型 / 独立审核 | 训练参数可复现；目录路径缺陷修复后复核无剩余发现 |

优化版内核加载范围 1081344 字节，开发版 1118208 字节。优化版 ELF SHA-256：`b5c6c37dbf364310a6b4fd145ede66064fd4f17ad06f2f08bfbf95d427f32eb7`。优化版扫描 29017 条内核指令、开发版扫描 30435 条，未发现 FP/SIMD。以上证据来自 QEMU 单核 ARM，不代表实体硬件或完整 POSIX 认证。

后续更新：多个固定 ELF 独立地址空间和私有 IPC 已在 D2 基础切片验证。下一阶段仍需通用受控 ELF 启动入口、父子进程和 wait/exec、匿名用户内存映射；然后补充信号/管道/终端、线程/同步以及更完整 libc。M2 全部目标和完整 POSIX 尚未完成。

语义核对依据为 The Open Group 的 [open](https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html)、[read](https://pubs.opengroup.org/onlinepubs/9799919799/functions/read.html)、[dup/dup2](https://pubs.opengroup.org/onlinepubs/9799919799/functions/dup.html)。ARM 权限编码依据 [Arm Memory Management](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/LearnTheArchitecture-MemoryManagement-101811_0100_00_en.pdf)。以本页列明的有限支持范围解释这些参考，不能据此声明全面符合标准。
