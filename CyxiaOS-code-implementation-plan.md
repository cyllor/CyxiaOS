# CyxiaOS 全系统代码实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. 当前采用本会话内顺序执行；ECC plan 默认不委派规划。本文为路线图，首批可执行任务见 M1 计划。

**Goal:** 分阶段实现不基于 Linux、由客体本地 AI 大脑决策与学习的 CyxiaOS，先交付单核 ARM 可启动基础，再形成可验证的全系统资源决策闭环。

**Architecture:** 通用机制、平台契约、架构适配、设备驱动和本地模型分别实现。各资源域向 AI 提交请求和可信观测，执行经校验的动作/有效计划，结果进入审计和学习；硬约束和已承诺操作的正确性由内核维护。

**Tech Stack:** 建议冻结 Rust 1.95.0 `no_std`、少量 AArch64 汇编、`aarch64-unknown-none-softfloat`、QEMU 10.2.2 `virt-10.2` / Cortex-A53 / TCG / 1 CPU / 256 MiB、Python 标准库测试驱动。模型首版为自研整数运行时，无云模型依赖。

**Spec:** [总体设计 v0.12](CyxiaOS-design.md)、[详细设计 v0.12](CyxiaOS-detailed-design.md)、[全系统 AI 决策契约](CyxiaOS-ai-decision-contract.md)、[学习设计](CyxiaOS-learning-prototype-design.md)。

POSIX 正式规格：[POSIX 兼容需求与架构](CyxiaOS-posix-design.md)，含 PX-R01—12、S1—S6 及 PX-T01—12。POSIX 专项以源码兼容为目标；新增 Linux 应用目标由独立兼容专项承接，认证另行决定。

## Global Constraints

- 所有管理模块的正常资源策略必须来自 AI_DIRECT 或有效 AI_PLAN；BOOTSTRAP、SAFETY_GUARD、RECOVERY、OPERATOR、MECHANISM 单独统计。
- 第一个运行目标只有一个 ARM CPU；通用接口仍使用 CpuId、所有权和代际，不能把全局单例写死在调度算法里。
- 基础页 4 KiB；TTBR0/TTBR1 使用 39 位地址范围；首版不启用 FP/Advanced SIMD，不支持交换、压缩或按需调页。
- 普通任务最多 64 槽，控制器独立槽；启用学习时 4 个普通服务槽使测试应用上限为 60。
- 控制器 4 MiB、审计 1 MiB、学习另预留 8 MiB；未来各域模型另做总账准入。
- CPU 时间片 0.5/1/2 ms；单控制窗口 250 μs；固定 10 ms 周期共享保留 1 ms；最小窗口间隔 500 μs。
- 学习/验证共同后台额度建议 2 ms/100 ms，分片目标不超过 250 μs；完整整数算法与发布 ABI 在对应阶段冻结。
- 物理页 OWNED → REVOKING → DIRTY_FREE → CLEAN_FREE → OWNED；清零和撤销未完成不能给新所有者。
- BudgetLimit、PlanAllowance、ResourceGrant 分型；计划失效不撤销已提交资源授予的履约义务。
- 现有 HTML 不可当作内核或正式模型实现；已有 v0.7 审核不证明 v0.10 完整通过。
- POSIX 可观察语义是硬约束，AI 优化不得改变数据、权限、FD/同步和返回契约；研究 ABI 与实验 POSIX ABI 必须隔离配置。
- 保留现有文档、原型和历史审核快照；不引入 Linux 内核、宿主模型代算或联网推理。

## Review Focus

1. 迟到/重复动作、对象与计数代际耗尽：不得复活旧请求或绕回身份；M1 契约测试、M3 动作测试。
2. 已授予内存与计划失效交错：不得重复扣账、超配或丢失已承诺资源；M1 授予账本与 M5 映射整合测试。
3. 模型、服务和 I/O 相互等待：控制器、时钟与必要回收必须有独立前进路径；M3/M4 故障测试、M9 联合压力。
4. 设备/日志持续中断及消费者停读：不得用长日志打印掩盖停机；M1 中断测试、M3 V18—V20。
5. 文件/网络物理副作用部分完成：不能把额度回滚当数据回滚；M6 持久化测试、M8/M9 幂等和部分失败测试。

当前执行状态（2026-10-15）：用户已确认并完成 M1，见 [M1 实现结果](docs/implementation/m1-status.md)。以下环境盘点和规划门槛保留为原始计划记录；随后按用户要求提前交付 [Shell 与 AI 文件系统切片](docs/implementation/shell-ai-fs.md)：EL1 Shell、RAMFS、文件域模型与显式学习发布。又按用户要求增加 [AI 内存/任务/设备切片](docs/implementation/ai-resource-management.md)，包含真实有界页池、协作式 EL1 任务及 UART/Timer 队列。其余 M2—M9 范围尚未完成，尤其不等同于完整 M6 或全系统 AI 调度。

## 1. 当前事实与规划范围

2026-10-15 只读检查：项目路径 `/Users/robin/CyxiaOS`；已有设计与两个 HTML 原型，没有 Cargo 工程、内核源码或 Git 仓库。Rust 1.95.0、Cargo 1.95.0、QEMU 10.2.2 已安装；当前 Rust 只安装主机目标 `aarch64-apple-darwin`。`~/.cargo/bin` 不在本次 shell 的 PATH 内，可用绝对路径调用；不因此认定 Rust 缺失。不修改全局 shell 配置。

`rustc --print target-list` 包含裸机 softfloat 目标，但尚未安装；LLVM 工具组件也未安装。计划执行时再补齐。QEMU 列表确认 `virt` 是 `virt-10.2` 别名，采用版本化名称减少配置漂移。尚未验证 QEMU 10.2.2 的完整串口背压契约，不能沿用旧文档对 9.2.0 源码的核查结论。

本次 `/ecc plan` 只生成计划。尚未安装工具、建立仓库、写内核代码、执行内核测试或改变审核状态。首批实施范围为 **M1（对应 P0/P1）**；后续 M2—M9 为依赖与验收路线，进入时另细化可执行计划。不是用“整个 OS 一次写完”的任务替代分阶段交付。

## 2. 可复用约定与缺失项

| 类别 | 已有依据 | 实施决定 |
|---|---|---|
| 命名/分层 | 详细设计 §3：contracts、kernel-core、arch、platform、drivers、brain | Rust crate 采用 cyxia-*，目录采用职责名称；这是新约定，现无 Rust 代码可镜像 |
| 错误处理 | 详细设计 ABI、代际与页生命周期规定结构化原因 | Result + 有限错误枚举；不得吞错或把失败标为 AI 通过 |
| 日志 | 详细设计 §12：来源、代际、完整性及丢失计数 | 有界记录和非阻塞输出，版本化帧；启动标记可独立检查 |
| 数据访问 | 能力、独立地址空间和受限设备接口 | 不借用宿主文件/网络完成客体系统服务 |
| 测试 | 详细设计 V00—V23、A/S/X 检查，学习 L01—L10、全域 C01—C08 | 纯逻辑主机测试 + 客体 QEMU 集成测试；无现成测试框架可复用 |

## 3. 代码布局路线

首批只创建 M1 列出的文件，其余是未来路径，不提前堆砌空实现。

| 路径 | 职责 / 阶段 |
|---|---|
| `crates/contracts/` | 逻辑身份、平台接口、决策来源和资源授予类型；M1 |
| `crates/kernel-core/` | 页管理、计量、后续任务/能力/IPC/动作提交；M1—M3 |
| `crates/arch-aarch64/` | 汇编入口、异常、页表、屏障、时钟；M1—M2 |
| `crates/platform-virt/` | DTB 转换与虚拟板资源；M1 |
| `crates/driver-pl011/`, `crates/driver-gicv2/` | UART 和中断设备；M1 |
| `kernel/` | 最终组合、链接脚本、启动及受限自检入口；M1 |
| `user/` | 测试应用、诊断及后续进程服务；M2 起 |
| `brain/runtime/`, `brain/model/` | 客体整数推理、模型格式/权重和版本；M3 |
| `brain/learning/`, `brain/validation/`, `brain/publisher/` | 隔离训练、验证和发布；M4 |
| `services/process/`, `services/memory/` | 动态任务和内存 AI 请求/计划执行；M5 |
| `services/fs/`, `services/device/`, `services/net/` | 受 AI 资源决策约束的服务；M6—M8 |
| `brain/coordinator/` | 低频跨域目标/联合提案；M9 |
| `tools/`、`tests/qemu/`、`tests/fixtures/` | 构建/运行/证据与故障场景；从 M1 演进 |

## 4. 里程碑与退出条件

| 里程碑 | 依赖 | 代码交付与可证明行为 | 复杂度 |
|---|---|---|---|
| M1：AI 契约与可启动内核 | 当前设计、工具链补齐 | 契约主机测试；QEMU EL1 启动、高地址映射、受限串口、页管理、时钟中断；明确 AI 尚未在线 | 高 |
| M2：隔离任务与恢复执行 | M1 | 静态 ELF/启动包、EL0、上下文、能力、IPC、确定性恢复；V00/V02/V03/V04/V12/V13/V17/V21 | 高 |
| M3：本地 AI CPU 决策 | M2；整数参考/训练可在 M2 时准备 | 真正训练得到的 24→32→16→4 模型；客体推理、一次提交、预算/公平/恢复；V01/V05—V11/V14—V22 | 很高 |
| M4：本地学习与受控发布 | M3；冻结学习算法、票据与事务 | 独立服务增量参数更新、保留集、观察回退；L01—L09；最终测试集不参与选权重 | 很高 |
| M5：AI 内存与进程合同 | M3/M4；专项规格 | 动态进程/线程模型、资源请求和 AI 准入、授予兑现、可回收缓存；C01—C07、V23 | 很高 |
| M6：AI 文件和存储 | M5；块驱动与文件系统专项规格 | 文件/目录/权限/读写、AI I/O 计划、写屏障、持久化与恢复测试；L10 仅在模型持久化链满足后执行 | 很高 |
| M7：AI 设备策略 | M3，按设备类别依赖 M5/M6 | 设备注册、驱动匹配、请求队列、DMA 生命周期、授权性能/恢复提案；不把热插拔或驱动生态默认标完成 | 高 |
| M8：AI 网络策略 | M5/M7；协议与网卡专项规格 | 流请求、能力、协议栈、AI 带宽/队列计划、有界缓冲及离线恢复；C01—C07 | 很高 |
| M9：联合控制、多核及移植分支 | 相关单域验收 | 跨域有界准备/提交/取消、振荡对照；S01—S09 验证多核，X01—X02 验证第二架构；分别报告，不捆绑虚假完成 | 很高 |

M7 的通用设备策略可以独立推进；M6 所需基础块驱动、M8 所需网卡驱动必须先于对应服务实现，不因编号顺序推迟依赖。多核和移植在 CPU P4 验收后可独立展开，无需等待 M9 的全部联合优化。文件系统类型、真实板卡、网络协议最小集合、设备电源能力都需要专项规格，现阶段不伪造最终选型。

### M1 的直接工作清单

- [x] 按 [M1 详细计划](CyxiaOS-code-m1-plan.md) 完成任务 T1—T10。
- [x] 保留原型；为真实内核建立独立构建与测试入口。
- [x] 生成编译器/QEMU/映像哈希/启动配置/测试结果清单。
- [x] 确认日志标为 BOOTSTRAP/MECHANISM，而非 AI_ACTIVE。
- [x] 根据实际结果更新 M1 实现状态。
- [ ] 在后续阶段细化 M2。

### 后续阶段统一动作

每个阶段开始前都需：将相关设计的不确定项收敛为可检验接口 → 明确文件和状态机 → 写失败测试 → 最小实现 → 主机/客体验证 → 审查证据 → 提交阶段快照。不能拿 UI 的“Pass”或模型文字解释替代客体行为。

## 5. 验证分层与证据

1. 主机纯逻辑：版本/代际、资源总账、计划失效、解析器拒绝、模型整数边界、事件状态机；覆盖行为，不只镜像代码。
2. ARM 客体：EL1/EL0 权限、定时抢占、陷阱返回、页表、启动恢复、实际客体模型运行。每条结果有显式成功/失败标记与退出码。
3. 故障/压力：模型超时、缓冲满、消费者停读、计数耗尽、I/O 部分失败、学习预算不足；业务进度须由独立计数证明。
4. 基线对照：相同内核、隔离、计量、模型版本和负载；分别报告算法效果、控制成本、公平保护和恢复占比。
5. 实体设备与多核另验：QEMU 墙钟性能不代表实体 ARM 的时延、DMA/缓存和功耗。

证据存入 `artifacts/<run-id>/`（执行时创建，Git 忽略大文件）；包含环境清单、命令参数、ELF SHA-256、QMP/串口原始记录、结果 JSON、丢失计数和未通过项。源码和小型黄金数据进入 Git，日志不写入秘密或用户文件内容。

## 6. 风险与处理

| 风险 | 当前情况 | 处理 |
|---|---|---|
| 新需求超出历史审核 | v0.9 尚未全域终审 | 每阶段先验证涉及的契约；独立检查不冒充全部归零 |
| 工具环境不完整 | 裸机 target / LLVM 组件缺失，PATH 缺 Rust shim | 执行时局部配置、安装精确目标并记录版本，不改全局默认环境 |
| QEMU 后端契约漂移 | 已装 10.2.2，旧审阅针对 9.2.0 | T1 核查指定版本源与启动约定；无法核实则不开放相应完成声明 |
| ELF/DTB/MMU 相互覆盖 | 裸机入口与高地址链接易错 | 固定布局、ELF 离线检查、范围/保留区测试；先证据后 EL0 |
| AI 成为“装饰层” | HTML 其他域仍为手动规则 | 各域 C01 来源审计；真实训练权重与回放证明，测试替身不算 AI |
| 模型开销大于收益 | 仅有计算量估算 | 实测并可失败退出；不得降低隔离或偷用宿主推理 |
| 规模扩展过快 | 全 OS、学习、设备同时展开容易断层 | 首批 M1，逐阶段退出；不承诺未经验证的总工期 |

## 7. 来源与方案选择

- 单核 ARM、本地 AI、全新内核、学习、解耦/跨平台/多核为用户要求。Rust、AArch64、Cortex-A53、具体 QEMU 版本与当前阶段划分是本计划建议；确认计划后按此落地。
- Rust 官方文档说明这组目标适用于裸机，softfloat 目标不默认使用 FP/SIMD；目标可通过 rustup 安装，链接布局仍需自定义。[Rust 裸机 AArch64 目标](https://doc.rust-lang.org/rustc/platform-support/aarch64-unknown-none.html)
- QEMU virt 文档区分 Linux 与裸机启动，设备布局应使用 DTB；版本化机器类型用于固定行为。[QEMU virt](https://www.qemu.org/docs/master/system/arm/virt.html)
- 串口采用有界 ringbuf + QMP 异步读取，并核对实际版本源码，不以 stdout 打印代替背压验证。[QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html)

## 8. 本轮完成与执行门槛

本轮完成的是规划与只读环境核查。计划按 ECC 2.2.3 的 `commands/plan.md` 流程生成；该指令要求先确认计划再写实现。等待用户确认后，在当前会话执行 M1，不默认派发子代理，也不擅自开始所有后续阶段。

计划自查：现有实现约定缺失已明确；前提、来源、风险、阶段依赖和测试证据均列出。每个未实现域保留可见状态，不承诺不存在待解决设计问题。

## POSIX 第一阶段实现进展

已增加独立 EL0 地址映射、静态 C ELF、SVC/IRQ 上下文返回、用户指针验证、FD 与 POSIX 文件接口子集；本地模型控制准入和派发预算。仍无多进程、完整 exec/fork/wait、IPC、信号或全套 libc，不将 M2 全部标记完成。见 [实现范围与验证](docs/implementation/posix-compatibility.md)。

## POSIX 正式需求的后续实施门槛

S1 现有 15 接口/单 ELF 切片的证据见 [实现说明](docs/implementation/posix-compatibility.md)，不将 S2—S6 或整个 M2 标为完成。以下按专项矩阵追踪：

- [ ] S2 / M2、M5：多地址空间、通用受控装载、fork/exec/wait、用户堆/映射和 ABI 配置绑定；PX-T02/03/05/06。
- [ ] S3 / M6、M7：VFS 元数据/路径、信号/管道/终端/等待 I/O；PX-T04/07/08。
- [ ] S4 / M5、M9：pthread/TLS、同步/时间与对应 SMP 共享状态；PX-T09/11。
- [ ] S5 / M6—M8：SDK、C 库、真实应用移植及所选网络选项；PX-T12。
- [ ] S6：Shell/工具与所声明兼容配置的全部必需项/已选选项证据；PX-T01—12，不用“支持若干函数”替代整体结论。

各阶段同步资源总账和 AI 来源契约；每次学习/模型切换均保留兼容性回归门槛 PX-T10。通用应用运行配置必须移除未经授权的测试寿命上限；新的软件/硬件能力单独验收。

## 轻量桌面与 Linux 应用实施分支（规划）

采用 [LXDE/X11 桌面设计](CyxiaOS-gui-design.md)与 [Linux 应用兼容设计](CyxiaOS-linux-compatibility-design.md)。本分支替代 LVGL G0—G5 路线，不修改前文历史交付记录。二进制范围在 L0 冻结，当前假设直接运行 ARM64 Linux 用户态程序；未实现或验收。

- [ ] D0/L0：冻结桌面/运行库/应用清单、源码与包哈希、许可、ABI、依赖、资源总账和二进制/源码兼容范围。
- [ ] D1：VirtIO GPU/Input 和独立图形启动配置；串口回归及 DMA 故障恢复。
- [ ] L1：通用多进程、映射/ELF/TLS/FP 上下文与 Linux ABI，真实静态 Linux ELF。
- [ ] L2：动态运行库、线程/信号、事件/Unix socket、VFS/PTY，真实动态 Linux CLI。
- [ ] D2/L3：原生 X.Org 后端和多客户端；接入 Linux X11 客户端并验证 AI 资源计量。
- [ ] D3/L4/D4：Openbox、LXPanel、PCManFM、LXSession、终端；GTK/Qt 应用按固定工作流验收。
- [ ] D5/L5：扩充软件矩阵、Wayland/Xwayland、网络/音频/加速和受限学习；大型应用逐项关闭依赖差距。

D1 可独立推进；原生桌面移植与 Linux 二进制兼容可分步验收，最终都依赖真实进程和资源机制。现有 256 MiB 内核配置保留，另行评估桌面集成内存；旧 24 MiB LVGL 预算不适用。第一实施动作应为依赖与 ABI 清单冻结，不直接下载整套发行版后宣称兼容。

D1 实施进展：Rust 现代 VirtIO MMIO、GPU 2D 彩条和原始键鼠事件已在指定 QEMU 的 dev/release 验证；缺设备回退 Shell。仍无桌面/完整输入服务/运行期 AI 图形调度，D1 不整体勾选。详见 [切片证据与限制](docs/implementation/graphics-bringup.md)。

D2 基础进展（2026-10-16）：新增最多 3 个同时活动的固定 ELF 独立 EL0 进程、本地模型选择/预算、私有双向 IPC、等待/唤醒和独立故障回收；原生 Rust 服务不继承 C 测试 500 ms 寿命限制。详见 [实现和证据](docs/implementation/desktop-process-foundation.md)。通用映射/装载、C 运行库、本地 socket、X.Org 和 LXDE 尚缺，D2/L1/S2 均不整体勾选。


桌面增量（2026-10-18）：第一版组合已包括真实 X.Org/Openbox、PCManFM、LXPanel、原生 PTY 终端/shell 和图形保存，单核 ARM 512 MiB；默认 256 MiB 内核继续保留。同一候选 `f432d168…` 的菜单启动、任务栏、文件重命名、终端写读/缩放/中断/退出、两次 flush 后保存成功和新 VM 恢复均已通过，证据见 [第一版轻量桌面](docs/implementation/lightweight-desktop.md)。八槽最多准入七进程；桌面常驻四进程，终端与 shell 增至六，保存窗口短时为七；实际资源路径经过本地模型及 grant ledger。大池每槽 16 MiB 匿名额度、512 条映射记录；内嵌目录上限 52 MiB，内核物理保留区仍为 64 MiB。RAMFS 仍为 64 节点/每文件 4 KiB，有 UTF-8 名称、普通文件原子重命名和显式持久检查点。

- [x] 第一版轻量桌面：真实上游窗口/面板/文件组件、静态菜单启动、原生终端与文件保存重启恢复。
- [ ] 完整 LXDE 服务集合：LXSession、动态 menu-cache、VTE/LXTerminal；当前启动器/静态菜单/原生终端不冒充这些组件。
- [ ] L4/D4：动态链接、通用 Linux 原二进制与 GTK/Qt 广泛应用兼容，按独立固定工作流验收。
