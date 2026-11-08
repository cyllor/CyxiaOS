# CyxiaOS V0.16：审核修复开发基线

本文记录初始审核提交 `abd8fa01d0dab42c43ecd4c1a4cf29e24ba9906f` 的九项修复及当时验证范围。
后续实现恢复与新源码的独立验证见 [恢复说明](v16-reintegration-summary.md) 和
[恢复验证记录](v16-reintegration-verification.json)；本文及原审核记录的 PASS/APPROVED 不转移到后续源码。
2026-11-08 新源码的独立运行目录为 A01/A02/A09 三项 PASS，其余十三项 A 验收待完成；见 [逐项进度](v16-a01-a16-progress-20261108.md)。本轮功能测试通过，严格特性 Clippy 仍有既有失败；原生子项与完整验收分别记账。

## 版本与来源

| 项目 | 值 |
|---|---|
| 开发分支 | `CyxiaOS-V0.16` |
| 软件版本 | `0.16.0-dev` |
| 版本性质 | 开发源码，`development-source-only` |
| 基线 | V0.15 `32057802e6e7d9239d04f1e7e3fed4f82f90db7e` |
| 基线树 | `db337d179974761aae837e373b1d708d198aac2e` |
| 设计规范 | v1.3，Rust / AArch64 |
| 审核依据 | 同一 V0.15 提交的全量审核与 Superpowers 独立复核；确认 1 项 P1、8 项 P2 |
| 原生验收 | `NOT_RUN`；不继承历史提交的 PASS |

V0.16 将这九项确认问题落实为源码修复和回归测试。完整来源及审核报告摘要校验值见 [v16-source-baseline.json](v16-source-baseline.json)，本轮实际命令、结果、限制与源码绑定见 [v16-verification.json](v16-verification.json)。[V0.15 的历史清单](v15-source-baseline.json)保持其原始归属。

架构继续采用 16 个同等地位的 AI 域、18 类动作和动态数量的专用控制核。控制面与业务执行面分离，业务热路径异步消费经过验证的策略，不同步等待模型；正式集群成员原生运行 CyxiaOS。

## 九项审核问题的修复

| 编号 | 原等级 | 修复与实际行为 | 回归入口 |
|---|---|---|---|
| R01 | P1 | 重连关闭历史改为可续传游标；ACK/CLOSE 整对检查队列余量，一次等待一个契约的匹配 CLOSE_REPLY，再推进下一条。保留协议帧余量，防止本地及慢速对端的保留队列溢出。 | `user/prototype-cluster/tests/support/reconnect_checks.rs`、`resend_checks.rs` |
| R02 | P2 | 已开始且状态为 Unknown 的执行不会因迟到 Pending/Busy/Again 回退。在写入各视图前规范化这一非法回退，保持原截止时间、实际执行记录和未决义务；后续 Registry 错误不能抹去已经发生的 APPLY。 | `tests/host/test_control_remediation.py` |
| R03 | P2 | 分离发起方向的条款、哈希、预留和任务身份，以及接收方向的执行身份/截止时间；按接收契约 ID 查找执行条款，回复及恢复不覆盖另一方向。 | `user/prototype-cluster/tests/driver_host.rs` |
| R04 | P2 | 超限清理独立处理整个自建进程组，即使组长先退出仍升级信号；返回前有界确认成员已停止并回收组长。Linux 区分存活与僵尸，其他平台采用保守的组存在性检查，不能确认时明确失败。 | `tests/host/test_v016_tools_bounds.py` |
| R05 | P2 | PTY 验证的函数和 CLI 均在读取 ELF/启动客体前拒绝非正次数，不能通过空循环产生 PASS；正次数仍逐次记录完成结果。 | `tests/host/test_v016_tools_bounds.py` |
| R06 | P2 | 原生 STORE 顺序读取保留下一条记录的游标，避免每个键从日志开头扫描。EOF 使用试探游标，后续追加仍可见；随机访问、分片缓存、初始化和错误关闭语义保留。 | `crates/prototype/tests/native_unified_store.rs` |
| R07 | P2 | RNG 在读取完成队列前采样截止时间，避免设备已经完成而后采样时间跨过截止点导致错误失效；原始提交时间和 DMA 所有权规则不变。 | `crates/driver-virtio/src/rng/batched.rs` 内回归 |
| R08 | P2 | 普通任务目标批次通过既有非阻塞所有者门读取完整的实时端点目录，覆盖第三个及后续普通 IPC 端点、关闭和重新打开的代次。首次查询 Busy 时保留该域的 object 游标和 due 时间，同时轮转全局 family 游标，允许其他所有者获得调度机会；已持有准备工作的重试语义保留。 | `tests/host/test_control_remediation.py` |
| R09 | P2 | 回放扫描使用带类型的 exact 目标批次查询，Busy/NotReady 不再变成“枚举结束”；不可读时保留游标，成功返回空目标才结束该域。保留四步扫描预算和原有排除规则。 | `tests/host/test_control_remediation.py` |

本轮没有修改持久日志格式、协议帧格式、队列容量或规范版本。修复不要求通过清空磁盘、更换成员身份或取消未决义务来恢复服务。

### 集群恢复与双向执行

重连测试覆盖 15/16/32 条已收终态结果、两种节点调度顺序、7 字节和 4096 字节传输片段、服务对象重建，以及连续重连。测试要求收到全部预期关闭回复后保持 READY；仅观察到 READY 不足以通过。另有 1/97/207 字节 HELLO 分片、队列填满和部分输出消费的回归。

双向测试通过普通应用提交，并使用实际 Authority 检查 reserve/grant/start/release 次数、完成值和关闭状态。模拟的时钟、套接字队列、存储代理及任务执行仍是主机测试边界；这些结果不等于原生 TCP、冷启动或断电恢复验收。

### 控制面状态与目标枚举

R02 回归绑定实际 poll、网络回执处理、Registry、历史和 TlsEgress，验证 Unknown 前后所有视图一致、APPLY 只执行一次、截止时间不延长，以及终态回执正常收敛。保留早期 Pending、截止点和错误服务代次对照。集成测试另外验证 Registry 拒绝不会丢失实际执行起点、重复 APPLY 或阻止候选终态优先提示退休。本次采用回执规范化这一较小修正，保留已有实际执行事实的记录顺序，不把修复描述为任意 Registry 异常下所有视图的事务性提交。

R08 回归使用实际 Ipc 生命周期和批次解析器，验证新端点、恢复端点排除、关闭、复用后的新代次、批次上界及 Busy 重试。所有者门是非阻塞借用，不在端点业务热路径加入模型等待。

R09 回归只执行实际目标查询语句及 ReadSnapshot/目标投影组件，验证真实读者门竞争下的 Busy 和扫描位置保持；它不构造完整回放冻结过程。该修复关闭已确认的“暂不可读被吞成枚举结束”路径，不声称已经证明原生冻结完成、跨所有者多轮扫描目录的原子快照或所有并发时序。

### 日志恢复的成本证据

相同的生产 STORE 模块在合法 Engine 历史上执行读取。新回归同时检查内容、返回码、EOF 和明确的线性块读取上界。

| 合法记录数 | V0.15 块读取 | V0.16 块读取 | 单游标参考 |
|---:|---:|---:|---:|
| 36 | 1,415，触发回归失败 | 73 | 74 |
| 68 | 本轮未重复测量 | 138 | 139 |
| 132 | 本轮未重复测量 | 268 | 269 |

这些数字是内存块设备上的 4 KiB 读取调用计数，不是物理磁盘启动时间。测试还覆盖 9,000 字节分片、随机读取、EOF 后追加、换卷初始化、CRC 损坏及追加失败。两文件卷边界的正确性经过源码复核；新增回归的 EOF/追加场景主要位于第一个文件。

## 验证与 CI

本次先记录修复前失败，再执行修复后验证，并完成集群、控制面、工具/驱动、存储四组独立复核。复核与集成测试进一步收紧进程清理的返回时序、观察失败路径和 PID 所有权，补充了跨域公平重试及 Registry 拒绝后的执行义务测试。已有 vendored ring 生命周期警告和部分测试辅助代码的 unused/dead-code 警告保留，不能将输出描述为无警告。

最终整合运行的结果如下。各套件可能包含重叠用例，不能将计数相加作为独立用例总数。

| 验证范围 | 本轮结果 |
|---|---|
| Rust 工作区，排除裸机内核测试目标 | 1,203 通过，0 失败 |
| prototype + `cluster-engine` | 612 通过，0 失败，包含五项 STORE 回归 |
| TLS 特性 | 34 通过，0 失败 |
| 集群应用完整主机套件 | 88 通过，含 62 项 driver_host 测试 |
| Virtio 驱动 | 79 通过，包含在工作区覆盖中 |
| Python 工具套件 | 232 通过 |
| 控制面新增回归 | 3 项通过；候选执行义务另有 2 项测试，含 19 个场景及变异检查 |
| 构建/PTY 新增边界回归 | 6 项通过；既有构建模块 13 项，含 1 项既有 opt-in 跳过 |
| 完整 Python 主机矩阵 | 837 项；1 失败、22 异常、2 跳过 |
| 工程入口总状态 | **FAIL**，保留环境受限项的真实结果 |

主机矩阵剩余项分别为：20 个测试缺少固定 Wayland 包，1 个类初始化缺少 `cosmic-comp-epoch` 源码，1 个 NBD 测试遭遇 Unix socket `EPERM`，1 个 runner 测试因同一权限问题得到与预期 QMP 超时不同的错误；2 个跳过来自历史原生捕获缺失。固定工具链的格式化/Clippy 与输入准备检查也未通过。第一次整合运行暴露的两处控制面问题经过修正和针对性验证后，在这次完整运行中均已消除。

常用复查命令如下；实际工具版本、计数和失败原因以本轮 [验证记录](v16-verification.json) 为准：

```sh
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline --workspace --exclude cyxia-kernel
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline -p cyxia-prototype --features cluster-engine
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline -p cyxia-cluster-transport --features tls
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline --manifest-path user/prototype-cluster/Cargo.toml
RUSTUP_TOOLCHAIN=1.95.0 python3 -B -m unittest discover -s tests/host -p test_control_remediation.py
RUSTUP_TOOLCHAIN=1.95.0 python3 -B -m unittest discover -s tests/host -p test_v016_tools_bounds.py
RUSTUP_TOOLCHAIN=1.95.0 python3 -B tools/prototype.py test --output artifacts/v016-checks
```

工程四路、A01–A16 组件六路及独立 A02 原生流程均接入 `CyxiaOS-V0.16`。Rust 工程路显式增加 `cluster-engine`，防止 feature-gated 存储/引擎回归被默认测试遗漏。新源码工作流校验 V0.15 父提交、规范/目录哈希、修复测试入口和本轮源码绑定，再从触发提交执行 `git archive`，记录 commit、tree、文件数和 ZIP SHA256，并保留失败日志。历史 V0.15 工作流及清单保留。

## 仍需完成的验证和维护

受版本管理的验收目录保持原始状态：A 类 16 项、T 类 20 项、E 类 15 项以及 18 类动作的原生证据尚未由本次工作替换。创建开发分支不会打开完整原型发布门禁。

本地固定 Rust 1.95.0 缺少 AArch64 目标以及 rustfmt/clippy 组件；缺少 QEMU、Clang、部分 COSMIC 固定源码和 Wayland 测试包，且部分 Unix socket 操作受环境限制。现有 stable 的 rustfmt 1.10.0 仅用于修改代码的格式处理。使用 stable Rust 1.99.1 的补充 AArch64 检查停在缺少已构建的每节点 EL0 集群服务，未完成统一内核编译；它不能替代固定版本构建或原生验收。

下一阶段应在具备固定工具链、每节点身份、完整测试输入和指定 QEMU 的环境中，针对 V0.16 的精确提交重跑工程、组件和原生矩阵。优先验证重连历史、普通双向契约、Unknown 回执、动态端点、回放目标竞争、日志恢复及设备完成时序。

前次审核单独列出的依赖升级债务保留。本轮没有改动 Cargo.lock 或 vendored ring，也没有把锁文件版本匹配直接等同于项目可利用漏洞。完整 COSMIC、通用 Linux ABI、全部 v1.3 功能与物理实时性仍按原有范围逐项验收。
