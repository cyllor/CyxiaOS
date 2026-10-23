> 范围提示（2026-10-18）：本文主要记录早期 EL1 资源切片。当前 EL0、桌面、存储、显示和学习的逐域状态及验证见 [全系统 AI 强化落地清单](system-ai-status.md)，客体使用 `ai system`。

# AI 内存、进程与设备管理

日期：2026-10-15。新增 `cyxia-ai-runtime`，运行于真实 QEMU ARM 客体；通用管理逻辑不依赖 ARM、MMIO、宿主模型或网络。用户请求的三个资源域已形成基础闭环：请求 → 观测 → 本地模型 → 校验 → 执行 → 状态/审计反馈。

> 后续进展：EL0/POSIX 第一阶段现已另行实现，见 [POSIX 兼容说明](posix-compatibility.md)。本文的 `proc`/32 页池仍指原协作式 EL1 服务。

## 当前能做什么

| 资源域 | 实际实现 | 当前边界 |
|---|---|---|
| 内存 | 32×4 KiB 页池；AI 准入；沿用资源授予账本；所有者校验；跨页读写；清零；任务退出回收 | 独立静态 RAM 区域；不是管理全部 256 MiB 的用户虚拟内存服务，无换页/压缩/动态 MMU 映射 |
| 进程/任务 | 最多 8 个协作式 EL1 内核任务；创建、暂停、恢复、等待 I/O、完成、失败、终止、回收；AI 选择任务和 32/256 工作单位额度 | 实际运行内建 compute/memory/uart 工作负载；没有独立 EL0 地址空间、可执行文件装载或抢占式上下文切换 |
| 设备 | 从已验证的启动平台信息注册 PL011 UART 与 ARM 定时器；16 槽异步队列；AI 竞争仲裁；部分完成、限次重试、期限、取消、完成唤醒 | UART 使用现有 CRC 帧传输；Timer 返回真实硬件计数；不宣称磁盘、网络、USB、热插拔或 DMA 支持 |

`Runtime` 只有一个提交所有者，CPU0 前台调用；计时中断继续运行。内核工作负载以有界、可恢复的 Rust 状态保存进度，实际执行运算、页字节读写和设备操作，不能把这种任务形态描述为已有隔离的用户进程。

## 启动与测试命令

双击 `Start-CyxiaOS.command`，或在项目目录运行 `python3 tools/shell.py`。旧的已启动虚拟机不会自动加载新代码；新窗口使用新内核。

### 内存

```text
mem status
mem alloc 2
mem list
mem poke 1 4096 173
mem peek 1 4096
mem free 1
mem status
```

上例假设这是本次启动的首个分配；以后以 `mem alloc` 返回的 ID 为准。`alloc` 页数范围 1–8，`poke` 字节值范围 0–255，偏移以字节计。模型可在尚有空闲页时返回 `AiDenied`，以保留后续请求余量；物理容量、所有者与边界限制始终由机制执行。分配和释放都会清零，旧 ID 不复用。手工内存命令属于操作员 owner=1，不能利用猜测 ID 访问任务页。

### 任务

```text
proc spawn compute 1000000 1 1
proc spawn memory 9000 2 3
proc spawn uart 2 1 1
ps
proc pause 2
proc resume 2
proc kill 2
proc reap 2
mem status
```

`proc spawn 类型 工作量 [优先级] [页数]`：工作量 1–1000000、优先级 0–3、页数 1–8；后两项默认 1。PID 从 2 开始递增，以实际返回值为准。

- `compute` 实际计算并通过所拥有的页保存、读取工作字节；`memory` 跨所拥有的页写入/读取并产生校验和。
- `uart` 每个工作单位提交一条 `[CyxiaOS AI task UART]` 消息并等待完成，随后再次进入就绪态。
- `ps` 显示 Ready/Waiting/Exited/Failed/Killed、暂停状态、进度、校验和、执行次数、最近工作额度、当前占用页和错误原因。
- 暂停不会撤销已提交的设备副作用：在途请求可完成，但暂停任务不会继续发起新工作。kill 取消后续设备工作并回收页，不能撤回已经发送的字节。
- 自然完成/失败/kill 会立即释放页；终态记录保留到 `reap`。队列或任务槽满时显式拒绝，不覆盖已有对象。

### 设备

```text
 dev list
 dev read timer
 dev write Hello-from-AI-device-manager
 dev batch 4
 dev requests
 ai audit
 dev reap 1
 dev disable uart
 dev enable uart
```

前导空格可省略。`dev batch N` 同时提交 1–8 个 Timer 请求，优先级按 0–3 循环，用于直接观察竞争仲裁；失败时整批不提交。`dev requests` 显示请求 ID、所有者、已知接受字节数、状态、结果、重试次数和不确定性。使用实际 ID 执行 `dev cancel ID` 或 `dev reap ID`；操作员不能取消或回收任务拥有的请求。

`disable/enable` 只控制普通请求通道，**不会关闭内核的控制台或计时中断**。有在途请求时返回 Busy；未启用通道返回 Offline。设备硬件在本轮不动态卸载。

每轮至多一次非阻塞驱动尝试。零进度 Again 最多尝试 8 次，提交后达到 64 ms 则失败。部分成功只续写剩余部分；无法确定写入进度的失败直接终止，`uncertain=true`，不重试可能已发送的字节。UART 以 CRC 帧为逻辑提交单位：帧开始前 Again 可安全重试且不制造序号间隙；部分帧失败为终态，宿主显式检测传输丢失/损坏，不伪造完整输出。完成表示驱动接受，不保证外部接收方消费。

## AI 策略与来源

参数由 `tools/train_resource_models.py` 从固定种子合成样本拟合，结果见 `resource-model-training.json` 和 `crates/ai-runtime/src/weights.rs`。这是明确目标的策略蒸馏，不是手写参数冒充训练，也不是生产工作负载上更优的证明。

- Memory 模型 8193：容量与请求页数决定准入。通过后由受信任服务调用 `AuthorizedGrantRequest::validated_ai`，立即提交/兑现；模型不能伪造所有者、直接取得页地址或修改账本。
- CPU 模型 12289：就绪等待、优先级、剩余工作决定排序，另一个固定分类器决定 32 或 256 个工作单位。执行前校验修订号、PID、状态和额度；消费修订号防重放。
- Device 模型 16385：有多个待处理请求时，根据等待、优先级、重试次数排序。只有实际竞争模型选择计为 AI_DIRECT；只有一个请求时的协议推进为 MECHANISM，不虚增 AI 决策比例。
- 等待超过 32 ms 的就绪任务进入最老等待保护；过期设备请求进入失败清理。两者标为 SAFETY_GUARD，不伪装成 AI 优化。

内核采用真实单调硬件计数换算毫秒，不能用可能跳过周期的 IRQ 次数冒充经过时间。处理错过的周期不无限补跑。工作单位不是微秒或抢占时间片；当前没有硬实时期限保证。

```text
ai resources
ai audit
```

`ai resources` 区分内存准入、CPU 模型派发、保护、设备竞争选择、非竞争推进和失败计数。`ai audit` 保留最近 64 条带序号、资源域、来源、模型、对象、数量、事件和请求终态的记录，包括提交、取消、完成、失败、回收、任务结束与页归还；覆盖数量显式显示。审计不是持久化日志，ID 耗尽在新动作前拒绝。

三个新域本轮使用固定发布参数，**尚无在线训练和自动发布**；原文件域的 `ai train/apply/rollback` 保持独立，不能把文件域学习算成全域学习。也尚无跨域协调大模型。

## 预算、隔离与扩展

- 管理服务静态对象小于 256 KiB，其中真实页数据占 128 KiB。文件系统/Shell 原有部分另计小于 128 KiB；组合 Shell 对象小于 384 KiB，内核栈另计 64 KiB。编译期与主机测试约束这些上限。
- 每轮最多扫描 8 个任务和 16 个请求，运行至多 256 个工作单位并尝试一次设备 I/O。没有运行时堆分配、模型锁内推理或后台无限重试。
- 通用管理只依赖 contracts/kernel-core；设备通过 `DeviceIo` 注入；依赖检查禁止引入平台驱动。原有页池/MMU 机制保留，新增页服务是静态区域上的授予兑现实现。
- 工作负载不能取得裸页引用；所有字节访问经所有者/范围检查。因为当前没有对任务导出 CPU/DMA 映射，独占服务完成访问后才形成撤销完成收据。未来引入 EL0/DMA 必须扩展实际撤销/TLB/同步协议，不能沿用本轮收据条件。
- 当前仍为单核，`Runtime` 的 Rust 独占访问是提交串行化基础。跨平台的算法层可复用，但没有据此宣称已有其他架构或 SMP 支持。

## 验证

```sh
python3 tools/train_resource_models.py --check
cargo test --locked
python3 tools/verify_m1.py --output artifacts/resources-m1-regression
python3 tools/build.py --profile release --production
python3 tools/verify_resources.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/resources-release
python3 tools/verify_shell.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/resources-shell-regression
```

独立审核的三项重要发现已修复并复核：真实 UART Again 被错误转为永久失败、无竞争处理被误计为 AI、取消/任务退出缺少请求终态记录。新增测试覆盖上述接入缺口，以及内存所有权/清零/容量、CPU 提案重放、任务暂停/恢复/退出、I/O 部分完成与取消、竞争模型排序、审计身份耗尽。实际最终结果以 artifacts 下 JSON 报告为准。

### 本轮最终结果（2026-10-15）

- Rust 75 项测试、Python 29 项测试全部通过；模型参数可复现检查通过。
- M1 基础回归 22 项全部通过，包含格式、主机与 ARM clippy、依赖边界、开发/优化版启动、自测、日志压力和 production 启动。报告：`artifacts/resources-m1-regression/summary.json`。压力用例主动制造传输损失，验收的是损失可检测及内核持续推进，不能解释为压力下零丢失。
- ARM production 开发版与优化版各 54 步资源管理交互通过，报告：`artifacts/resources-dev/summary.json`、`artifacts/resources-release/summary.json`。验证真实页读写与清零、任务计算及退出回收、暂停/恢复/终止、Timer 计数读取、UART 输出、离线失败、设备竞争决策及内存 AI 拒绝。
- 原有 Shell/文件系统 96 步回归通过，包括训练、发布、回滚与重启清空 RAM 文件，报告：`artifacts/resources-shell-regression/summary.json`。
- 优化版 ELF SHA-256：`61a181d041067cb53342fa44581f97b51710032226eb8f2ce01c5a7bd2081b1a`；内核加载范围 937984 字节；扫描 23215 条反汇编指令，未发现 FP/SIMD。开发版加载范围 958464 字节。
- 独立复核确认上述重要问题均已解决，当前已声明实现范围内没有新增重要或严重发现；这不表示完整操作系统或真实硬件已获验证。
