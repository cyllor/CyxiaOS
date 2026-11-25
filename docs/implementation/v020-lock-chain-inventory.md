# V0.20 控制面锁链清单与 G1 冻结待决项（inventory / plan，非冻结）

基线：`docs/design/baselines/v0.19.9-implementation-spec.txt` §3.2「锁与上下文」。
代码基线：`CyxiaOS-V0.20` @ `d07bd42`（本清单只读盘点 + 计量接线，未提交）。

**性质声明（务必先读）：** 本文件是**锁/同步位点的实际清单**与 **G1 冻结必须裁决的事项列表**，
**不是** G1 锁链冻结本身，**不声称**冻结已完成。基线 L1556–1558 要求 G1 冻结
「锁链调用图与最大深度、最坏指令/路径计量方案」，并明确「不以设计 5μs 当实测保证」。
本清单给出的深度/路径是**静态阅读观察**，不是实测、不是冻结上界。生产 `policy_lock`
对象、DAIF 屏蔽/恢复强制点、try_lock 机制、冻结调用图仍是 G1 的交付物。

---

## 1. 基线要求（引用行号）

| 行号 | 要求 |
|---|---|
| L1530–1532 | 锁序：注册表→核心/资源账本→policy_lock→任务→CPU ID 升序运行队列→地址空间→页元数据→端点/设备队列。短临界区用 try_lock(acquire/release)，**不在 IRQ-off 或持其他锁时等待**；失败逆序释放并恢复 IRQ/抢占。 |
| L1534 | policy_lock 只复制有界字段/交换根，不分配、IPC、等待或设备操作。 |
| L1536 | 硬 IRQ 只确认中断并向预分配完成队列发事件，**不取跨模块锁**、不分配普通内存、不发阻塞 IPC。 |
| L1542 | policy_lock 单次持锁有效工作 ≤45μs，且屏蔽本地 IRQ→恢复整个区间 ≤50μs；超限诊断、封闭新优化，不强行释放引用。中断入口/完成路径/核心静默确认禁取该锁。 |
| L1546–1548 | 一次连续 IRQ-off 区：全部获取尝试+锁序检查+释放+屏障+恢复 IRQ 开销合计 ≤5μs；持锁有效工作合计 ≤45μs；DAIF 屏蔽→恢复实测总 ≤50μs。单锁/多锁**共用一个区间预算**。 |
| L1550 | 失败逆序释放、恢复 IRQ，最多 4 个独立尝试区间后让出并在外层绝对截止内重试。 |
| L1552 | 持有者异常/超界不强行解锁，封闭新准入，无法证明账本一致则 fail-stop。 |
| L1554 | 每次连续 IRQ-off 区最多 8 把实际锁（含不同 CPU 运行队列每把锁），不把锁序层级当可叠加额度。 |
| L1556–1558 | **G1 须冻结锁链调用图与最大深度、最坏指令/路径计量方案**；STATIC_EL1 及 S13 实测最深合法链/竞争失败链，不以设计 5μs 当实测保证。 |
| L5031 / L7340 | 45+5≤50μs 仍为强制计量；`lock_work_max_us = 45`（固定原型配置）。 |

计量脚手架 `crates/kernel-core/src/control_plane/policy_lock_v0199.rs` 已按上述常量落地
（`WORK_BUDGET_NS=45_000`、`IRQ_OFF_BUDGET_NS=50_000`、`ACQUISITION_BUDGET_NS=5_000`、
`MAX_LOCKS_PER_IRQ_OFF=8`、`MAX_TRY_INTERVALS=4`、8 秩 `LockRank`/`LOCK_ORDER`），
提供 caller-supplied 单调 ns 的 `CriticalSectionMeter`（begin/end/record_acquire）与粘性
fail-closed `Fault`（无 reset API）。**它是计量/强制脚手架，不是锁实现，也不是冻结。**

---

## 2. 位点分类（关键：feature 门控决定哪些位点在哪个 profile 生效）

盘点发现控制面锁/同步位点分三类，**生效 profile 不同**，G1 冻结必须先澄清目标 profile：

- **A 类｜kernel-core `control_plane`（宿主 + 原生恒编译）**：纯引擎，`#![forbid(unsafe_code)]`
  （`crates/kernel-core/src/control_plane/mod.rs:10`），**自身无原子锁**，串行化完全由调用方
  （受信 EL1 owner）保证。含 manager、registered_gate、policy_lock 脚手架、dispatch Gate、svc_bridge。
- **B 类｜`kernel/src/runtime` 粗粒度 AtomicBool 域门（`unified-runtime` 门控，遗留 profile）**：
  任务点名的「GATE AtomicBool / locked() 闭包 / control_pool with()」都在这里。
  `kernel/src/composition/aarch64.rs:86–156` 将 control_pool/domain_control/domain_tasks/
  domain_services/service_windows/a02_capture 全部置于 `#[cfg(feature = "unified-runtime")]`。
  `unified-runtime`（`kernel/Cargo.toml`）拉 cluster-transport/peer-billing/legacy-cluster，是
  **保留的历史 profile**；**默认 `smp-selftest` / `v0199-local-native` 原生构建不编译这些域门**。
- **C 类｜arch DAIF/IRQ 强制点（aarch64 恒编译）**：EL0 进出与异常入口的 DAIF 屏蔽/恢复，
  以及硬 IRQ 处理。这是当前**唯一真实存在的 IRQ-off 区间**。

> 结论先行：V0.20 原生方向（fixed-CPU0 / smp-selftest / v0199-* 夹具）实际依赖的是
> **A 类引擎 + per-CPU dispatch Gate + C 类 DAIF 过渡**；B 类粗粒度域门属于遗留 unified-runtime。
> G1 冻结必须明确：是为遗留域门补锁序/IRQ-off，还是将其退役并把冻结绑定到 A/C 类原生路径。

---

## 3. 逐位点清单（file:line + 机制 + 阻塞性 + 基线秩映射 + IRQ-off）

基线 8 秩（升序，`policy_lock_v0199.rs::LOCK_ORDER`）：
`0 Registry 注册表 · 1 CoreResourceLedger 核心/资源账本 · 2 PolicyLock · 3 Task 任务 ·
4 RunQueue CPU ID 升序运行队列 · 5 AddressSpace 地址空间 · 6 PageMeta 页元数据 ·
7 EndpointDeviceQueue 端点/设备队列`。
**下表秩映射为「建议映射」，非已冻结绑定**；当前代码并未给这些粗粒度门赋秩（见 §5 偏差）。

### A 类｜kernel-core control_plane（恒编译，自身无锁，调用方串行）

| 位点 | file:line | 机制 / 阻塞性 | 建议基线秩 | IRQ-off? |
|---|---|---|---|---|
| `Manager::review_brains`（只读复核） | `crates/kernel-core/src/control_plane/manager.rs:94` | `&self` 纯读，无锁；调用方串行 | 读路径，不取锁 | 否 |
| `Manager::review_brains_metered`（计量接线①） | `crates/kernel-core/src/control_plane/manager.rs:146` | begin(EffectiveWork,now)→review→end(done_ns)；超限粘性 fault | 同上（计量） | 否（脚手架不屏蔽 IRQ） |
| `Manager::actor`（SEC-S04 唯一发布者鉴权） | `crates/kernel-core/src/control_plane/manager.rs:177` | 纯鉴权 `can_publish*`，无锁 | 准入检查，不取锁 | 否 |
| `Manager::submit`（策略准入/actor 路径） | `crates/kernel-core/src/control_plane/manager.rs:220` | `&mut self`；check_time→actor→decode→bank.accept | 1 ownership + 2 policy bank | 否 |
| `Manager::publish`（drain 发布临界区） | `crates/kernel-core/src/control_plane/manager.rs:318` | `&mut self`；ownership.publish 交换分区 + sync 重配 bank；有界、无分配/IPC/等待 | 1 ownership + 2 policy bank | 否 |
| `Manager::publish_metered`（计量接线②，本次新增） | `crates/kernel-core/src/control_plane/manager.rs:349` | begin(EffectiveWork,now)→publish→end(done_ns)；超限粘性 fault；**计量非事务**（Clock 不回滚已生效发布） | 同上（计量） | 否 |
| `RegisteredDecisionGate`（结构） | `crates/kernel-core/src/control_plane/registered_gate_v3.rs:171` | **无原子/无 static/无 unsafe**（全文件 grep 证实）；`&mut self` 独占，串行化完全靠调用方 | 2 PolicyLock（决策发布） | 否 |
| `RegisteredDecisionGate::publish_once` | `crates/kernel-core/src/control_plane/registered_gate_v3.rs:585` | 校验冻结 plan→begin_publish→native_accept 回调；回调可能副作用 | 2 | 否 |
| `publish_trial_one` / `publish_rejected_fallback_one` / `publish_assisted_once` | `registered_gate_v3.rs:802 / 1273 / 1323` | 同上，各纵向切片 | 2 | 否 |
| `SvcV3Bridge.gate`（SVC 0x50/0x41 桥） | `crates/kernel-core/src/control_plane/svc_bridge_v3.rs:43–44` | 持 `&'a mut RegisteredDecisionGate`；串行化靠调用方 | 2 | 否 |
| `dispatch::Gate`（per-CPU 线性化派发栅栏） | `crates/kernel-core/src/control_plane/dispatch.rs:32` | 单 `AtomicU64` CAS；`try_enter`(:97)/`open`(:67)/`close`(:85) **单 CAS、不旋不队列**；`Permit` drop(:128) release | 3 Task / 4 RunQueue（per-CPU 执行准入） | 否（CAS 本身不屏蔽 IRQ） |
| `policy_lock_v0199` 计量脚手架 | `crates/kernel-core/src/control_plane/policy_lock_v0199.rs`（全模块） | caller-supplied ns 计量 + 锁序/8 锁/粘性 fault；**非锁实现** | 秩注册表契约 | 否 |

**A 类要点：** manager 与 registered_gate 都是**无内部锁的纯引擎**，基线要求的「持锁临界区 +
IRQ-off 区间」在生产侧**尚未落到这些对象上**——谁在原生路径串行化它们、在哪个 DAIF 区间内，
是 G1 必须裁决的（当前 advice-e2e 夹具靠「单 CPU0 同步 turn loop」这一外部约定，见
`kernel/src/arch/aarch64/v0199_advice_e2e.rs:42–54` 的 UNSAFE BOUNDARY 登记，`production_wiring=false`）。

### B 类｜unified-runtime 粗粒度域门（遗留 profile；默认原生构建不编译）

| 位点 | file:line | 机制 / 阻塞性 | 建议基线秩 | IRQ-off? |
|---|---|---|---|---|
| `control_pool` GATE | `kernel/src/runtime/control/control_pool.rs:23` | AtomicBool；`with()`(:159) `compare_exchange(Acquire)`→Busy；`Guard` drop(:61) release | 1 CoreResourceLedger（+6 PageMeta：FrameMeta 登记） | **否** |
| `control_pool::with`（池门入口） | `control_pool.rs:159` | 非阻塞 try-lock；门内做 FrameMeta 登记+子分配+证据发布 | 1 / 6 | 否 |
| `control_pool::allocate/pin/span/write/read/inspect` | `control_pool.rs:226 / 320 / 237 / 258 / 284 / 299` | 各自 `with(...)`；allocate 额外 CPU0 检查 | 1 / 6 | 否 |
| `domain_control` CLAIMED（控制 owner 门） | `kernel/src/runtime/control/domain_control.rs:423` | AtomicBool；`with()`(:470) CAS→Busy；`Guard` drop(:463) release；先 `cpu::slot()>=4`→Auth | 0 Registry（持 `registry: Registry`） | **否** |
| `domain_control::accept`（发布验收） | `domain_control.rs:2816` | `with(|s|...)` 内调 `reserve_scheduler_publication`(:2907)/`reserve_spawn_publication`(:2930) → **嵌套任务门** | 0 → 3 | 否 |
| `domain_tasks` LOCK（任务 owner 门） | `kernel/src/runtime/tasks/domain_tasks.rs:145` | `owner_gate::Gate`；`acquire_guard()`(:559)→`try_acquire`；`locked()`(:571)/`locked_with_guard()`(:574) | 3 Task | **否** |
| `owner_gate::Gate::try_acquire` | `kernel/src/runtime/tasks/domain_tasks/owner_gate.rs:64` | CAS held + 有界 per-CPU 偏好/交接（waiting/preferred/until/turn_until）；失败即返回，**不等待** | 3 | 否 |
| `owner_gate::Permit::release` / `protect_service_until` | `owner_gate.rs:156 / 137` | release 设偏好；CPU0 服务授予可保护当前 epoch ≤2.5 span | 3 | 否 |
| `reserve_baseline/scheduler/spawn_publication` | `kernel/src/runtime/tasks/domain_tasks/publication.rs:26 / 144 / 250`（acquire_guard :35/:154/:258） | 各自取任务门后跑 `*_locked` 纯投影 | 3 | 否 |
| `domain_services` LOCK | `kernel/src/runtime/services/domain_services.rs:39` | AtomicBool；`with()`(:195) CAS→Busy；`read()`(:263) 走只读 `READ_VIEW.inspect`（**不取锁**）；`current()`(:904) 经 read | 7 EndpointDeviceQueue | **否** |
| `service_windows` GATE | `kernel/src/runtime/services/service_windows.rs:104` | AtomicBool；`lock()`(:120)/`with()`(:125) CAS→Busy；`init()`(:135) 门内调 pool | 7（服务元数据） | **否** |
| `core_replay` QUEUE_GATE | `kernel/src/runtime/control/domain_control/core_replay.rs:161` | AtomicBool；`queue()`(:168) CAS→Busy；`prepare()`(:203) 门内调 pool | 7（预分配完成/工作队列） | **否** |
| `learning_driver` GATE | `kernel/src/runtime/control/domain_control/learning_driver.rs:305` | AtomicBool；`guard()`(:313)/`with()`(:318) CAS→Busy；`init()` 门内 `pool::pin`(:363) | 无干净对应（域控制元数据，建议 1，待冻结裁决） | **否** |
| `a02_capture` LOCK / WAITERS | `kernel/src/diagnostics/a02_capture.rs:43–44` | **唯一等待锁**：`locked()`(:46) CAS 失败→`WFE` 自旋，release 后 `SEV`；**违反「不等待」** | 诊断捕获（非生产客体路径锁） | 在 EL0 边界 DAIF 屏蔽区内被调（见 §4） |

**B 类要点：** 除 `a02_capture` 外全部是**非阻塞 CAS try-lock（竞争返回 Busy）**，因此**构造上无死锁**
（不等待），但**并未实现基线的升序取锁纪律，也未在临界区屏蔽 IRQ**。`a02_capture` 是唯一 WFE 等待锁，
且在 EL0 进出 DAIF 屏蔽区内被调用（`smp.rs:1523/1525/1549/1551`），与 L1532「不在 IRQ-off 时等待」直接冲突，
须由冻结裁决（改为非阻塞，或作为 opt-in 诊断机制显式豁免）。

### C 类｜arch DAIF/IRQ 强制点（aarch64 恒编译；当前唯一真实 IRQ-off 区间）

| 位点 | file:line | 作用 |
|---|---|---|
| 异常入口屏蔽 | `crates/arch-aarch64/src/entry.S:5` | `msr daifset, #15`（异常进入即屏蔽 D/A/I/F） |
| EL0 进入 Rust 侧屏蔽/恢复 | `crates/arch-aarch64/src/user.rs:91 / 119`（`enter_inner`:87） | `mrs daif`+`daifset #15` 保护 ACTIVE/TTBR0 半安装对；返回前 `msr daif` 恢复 |
| EL0 进入汇编屏蔽/恢复 | `crates/arch-aarch64/src/user.S:18–20 / 92 / 153` | 保存 DAIF→`daifset #15`；返回路径再屏蔽；`cyxia_user_return` 末恢复 |
| per-CPU ACTIVE/INTEGER_ONLY | `crates/arch-aarch64/src/user.rs:70 / 72` | `AtomicPtr`/`AtomicBool`，在 DAIF 屏蔽区内安装/清空 |
| smp EL0 切片 DAIF 区间 | `kernel/src/arch/aarch64/smp.rs:1491 / 1554`（`enter_service_inner`） | `daifset #2`（屏蔽 IRQ）→arm timer→a02_capture→`user::enter`→返回→`msr daif` 恢复；**区间包住整个 EL0 执行** |
| 使能 IRQ | `crates/arch-aarch64/src/timer.rs:136` | `msr daifclr, #2`（`enable_irqs`） |
| 硬 IRQ 处理 | `kernel/src/platform/virt/interrupts.rs:34`（`handle`） | 仅 GIC ack/re-arm timer/原子计数；**不取任何跨模块锁**（符合 L1536） |
| 异常分发 | `kernel/src/arch/aarch64/exceptions.rs:19`（`exception_dispatch`） | smp-selftest→`smp::exception`；硬 IRQ 走 `interrupts::handle` |
| per-CPU 派发门实例 | `kernel/src/arch/aarch64/smp.rs:155`（`GATES: [Gate; C]`） | 用 A 类 `dispatch::Gate`；`try_enter`(:746) 单 CAS |

**C 类要点：** 现有 DAIF 屏蔽**只围绕 EL0 进出/异常入口/TTBR0 安装**，**不围绕任何控制面临界区**。
`smp.rs:1491–1554` 的 IRQ-off 区间包住的是**整个 EL0 执行**（含 `user::enter`），不是基线意义的
「短临界区 ≤50μs」——基线 L1542 的 50μs 约束针对普通客体路径临界区，且明确「致命停机不声称 IRQ-off 受 50μs 约束」。
**当前没有任何控制面锁临界区被 DAIF 区间包裹**，即基线的 ≤45/≤5/≤50μs 计量模型在生产锁路径上尚未实现。

---

## 4. 观察到的嵌套链与最坏深度（静态阅读，非冻结/实测上界）

以下为**静态追踪到的真实嵌套**（持 A 门期间取 B 门），均附 file:line。
**注意：这些深度-2 链全部位于 B 类（`unified-runtime` 遗留 profile）**；默认 `smp-selftest` 原生路径
不编译这些域门，其 per-CPU `dispatch::Gate` permit 在 EL0 进入期间持有、**未观察到再嵌套其他控制面门**（深度 1）。

1. **domain_control CLAIMED → domain_tasks LOCK**（深度 2）
   `domain_control.rs:2816 accept` 的 `with(|s|...)` 内 → `:2907 reserve_scheduler_publication` /
   `:2930 reserve_spawn_publication` → `publication.rs:154/:258 acquire_guard` → `owner_gate.rs:64 try_acquire`。
   建议秩 0→3，**升序，符合 L1530**。
2. **service_windows GATE → domain_control CLAIMED**（深度 2）
   `service_windows.rs:219 with` → `:232 registration_slot` → `:194 domain_control::service_target_retired`
   （另 `:233 register_service_boundary`、`:435 observe_service_window`）→ `domain_control.rs:470 with`。
   建议秩 7→0，**降序**（见 §5）。
3. **service_windows GATE → control_pool GATE**（深度 2）
   `service_windows.rs:135 init` 持 `lock()` → `:142 pool::allocate` / `:146 pool::pin` / `:148 pool::span` →
   `control_pool.rs:159 with`。建议秩 7→1，**降序**。
4. **core_replay QUEUE_GATE → control_pool GATE**（深度 2）
   `core_replay.rs:203 prepare` CAS(:207) → `:212 pool::allocate` / `:216 pool::pin` / `:218 pool::span` →
   `control_pool.rs:159 with`。建议秩 7→1，**降序**。（`prepare` 随后 `:224 super::with` 是**顺序**取 CLAIMED，非嵌套。）
5. **learning_driver GATE → control_pool GATE**（深度 2）
   `learning_driver.rs:345 init` 持 `guard()`(:351) → `:363 pool::pin` / `:365 pool::span` → `control_pool.rs:159 with`。
6. **domain_control CLAIMED → control_pool GATE**（深度 2，模型 pin/release）
   `domain_control.rs:580 pin_job_model` 的 `with` → `:596 s.models.pin` → `model_bank.rs:221 ModelBank::pin`
   → `:228 memory.pin` → `:344 NativeMemory::pin` → `:345 control_pool::span` / `:346 pin_readonly` → `control_pool.rs:159 with`。
   `release_job_model`(:602→:603 `s.models.release` → `model_bank.rs:349` → `:350 control_pool::unpin`) 同链。
   建议秩 0→1，**升序，符合 L1530**。（`NativeMemory` 的 `inspect` 闭包为纯 `Sha256::digest`，`model_bank.rs:340`，不再取门。）

**最坏观察深度 = 2（同时持 2 把门）。** control_pool 既被低秩 CLAIMED 升序取（链 6，合规），也被高秩域门降序取（链 3/4/5，偏差）。
未发现深度 ≥3 的控制面链：
- 任务门路径（`reserve_*` → `*_locked`）全是已持锁 State 上的纯投影，**不再取 control_pool**
  （`kernel/src/runtime/tasks` 全目录 grep `control_pool`/`pool::` 无命中）。
- control_pool `with()` 的闭包均为纯 ledger 操作 + FrameMeta 登记，**不再取其他门**（control_pool 恒为叶）。
- domain_services `current()` 经只读 `read()`/`READ_VIEW.inspect`（`domain_services.rs:263`），**不取 LOCK**。

**必须声明的上界局限：** 以上是静态阅读观察，**不是冻结上界也不是实测**。
`domain_control` 的 `Family` 回调（`current/observe/apply/reconcile`，`domain_control.rs:276`）是
**函数指针**，其具体实现由注册方决定；本清单只追踪了已注册的 `domain_services::register_control`
（`domain_services.rs:1285`）等少数族。**G1 必须枚举所有注册族及其回调、所有 `native_accept` 回调
（`registered_gate_v3.rs:585`）的实际原生实现，才能证明最大深度上界**（基线 L1554 的 8 锁/区间、
L1556 的最大深度）。当前不能排除某回调在持门期间再取门而加深链。

---

## 5. 与基线的结构性偏差（冻结必须裁决，而非已证合规）

1. **粗粒度门 ≠ 8 秩细粒度锁序。** 当前实现用少量域级 AtomicBool 门（CLAIMED/LOCK/GATE/QUEUE_GATE），
   并未给它们赋基线 8 秩。§3 的秩映射是**建议**，非绑定。
2. **资源账本门（control_pool）被当作叶锁。** 基线把「核心/资源账本」放在秩 1（近根，注册表之后），
   但观察到的链 3/4/5 都在**更高秩域门之下**最后取 control_pool。在建议映射下这是**降序取锁**，
   与 L1530 升序纪律不符。因全为非阻塞 CAS，表现为 **Busy 重试而非死锁**，但**升序契约未被证明满足**。
3. **service_windows → domain_control 全降序**（链 2，建议秩 7→0）：服务端点门之下取注册表门。
   是否可接受取决于冻结赋予的权威秩；当前**未证明**满足 L1530。
4. **控制面临界区无 DAIF 屏蔽。** B 类门与 A 类引擎的临界区都不屏蔽本地 IRQ（§3/C 类）。
   基线 ≤45/≤5/≤50μs 的 IRQ-off 计量模型在生产锁路径**尚未实现**；现有 DAIF 区间只包 EL0 进出。
   硬 IRQ 不取跨模块锁（`interrupts.rs:34`），故无 IRQ 死锁，但持有者**可被本地 IRQ 抢占**。
5. **a02_capture 是唯一等待锁**（WFE/SEV，`a02_capture.rs:46`），且在 EL0 DAIF 屏蔽区内被调
   （`smp.rs:1523/1525`），与 L1532「不在 IRQ-off 时等待」冲突；须改非阻塞或显式豁免（opt-in 诊断）。
6. **owner_gate 的有界交接/偏好**（`owner_gate.rs` waiting/preferred/turn_until/protected_until）比基线
   「简单 try_lock」复杂；其公平/让出语义与 L1550「最多 4 个独立尝试区间后让出」的对应关系须由冻结澄清。
7. **A 类引擎无内部锁**：manager/registered_gate 的串行化与 IRQ-off 区间完全依赖外部调用方约定
   （当前 advice-e2e 夹具为单 CPU0 同步 loop，`production_wiring=false`）。生产 in-vector SVC 接线未建立。

---

## 6. G1 冻结必须裁决/交付的事项（精确列表）

依据 L1556–1558，G1 冻结须产出并冻结以下各项（当前**均未完成**）：

1. **目标 profile 与锁链调用图**：明确冻结绑定到遗留 unified-runtime 域门，还是退役它们并把冻结绑定到
   A 类引擎 + per-CPU dispatch Gate + C 类 DAIF 的原生 fixed-CPU0 路径；产出**完整锁链调用图**
   （含所有 `Family` 回调、`native_accept` 回调的实际原生实现）。
2. **try_lock 机制**：确定生产 try_lock(acquire/release) 的实现与失败语义（当前为 CAS→Busy）；
   裁决 owner_gate 有界交接、a02_capture WFE 等待锁的去留（改非阻塞或豁免）；落实 L1550 的
   「≤4 独立尝试区间后让出 + 外层绝对截止重试」重试环（脚手架 `MAX_TRY_INTERVALS=4` 仅钉扎常量，未实现环）。
3. **DAIF 强制点**：确定每个生产临界区的 DAIF 屏蔽/恢复位置（当前控制面锁路径**无** DAIF 屏蔽）；
   保证硬 IRQ/完成路径/核心静默确认不取 policy_lock（L1536/L1542）；把 ≤45/≤5/≤50μs 计量区间
   真正落到生产锁路径，而非仅 EL0 进出。
4. **最大深度上界**：在完整调用图上证明同时持锁数上界（观察值 2，**未冻结**），并满足 L1554
   「每连续 IRQ-off 区 ≤8 把实际锁」；枚举函数指针回调以排除更深链。
5. **最坏路径计量方案**：按 L1556–1558 / L5031 冻结「最坏获取/检查/释放/屏障/恢复开销 ≤5μs、
   有效工作 ≤45μs、DAIF 总 ≤50μs」的**实测**方案（STATIC_EL1 及 S13 实测最深合法链/竞争失败链）；
   **不得以设计 5μs 当实测保证**。脚手架 `CriticalSectionMeter` 是 caller-supplied ns 观测，
   不读硬件计数器，须由冻结接入真实单调时钟/PMU 并定义测量点。
6. **秩绑定与锁序证明**：给每个真实锁对象赋权威基线秩，证明所有嵌套升序（或重构 §5 的降序链 2/3/4/5），
   落实 run-queue CPU ID 升序子序（`runqueue_cpu_order_violation`）；把 `record_acquire` 的 held-set
   契约接到真实持锁集合。
7. **fail-closed / fail-stop 语义**：落实 L1552「持有者异常/超界不强行解锁、封闭新准入、无法证明账本一致则
   fail-stop」；脚手架已实现粘性 fault + 封闭准入（无 reset），冻结须定义恢复/重建路径与账本一致性证明。
8. **生产 policy_lock 对象**：当前**不存在**生产 policy_lock 锁对象（脚手架是计量器，不是锁）；
   冻结须交付该对象及其「只复制有界字段/交换根，不分配/IPC/等待/设备操作」（L1534）的实现与验证。

---

## 7. 已就位 vs 仍缺（诚实边界）

**已就位（本次 + 前序）：**
- 计量脚手架 `policy_lock_v0199.rs`：45/50/5μs 常量、8 锁/8 秩、粘性 fail-closed、caller-supplied ns；
  12 项宿主测试（`cargo test -p cyxia-kernel-core control_plane::policy_lock_v0199` 全绿）。
- 计量接线①`review_brains_metered`（`manager.rs:146`，前序）+ 计量接线②`publish_metered`
  （`manager.rs:349`，**本次新增**，drain 发布真实临界区）；happy path 与未计量完全一致，
  超限粘性 fault 不改结果，Clock 保留开区间；manager 共 7 项计量宿主测试全绿。
- 硬 IRQ 不取跨模块锁（`interrupts.rs:34`）；EL0 进出 DAIF 过渡（C 类）已存在。

**仍缺（G1 冻结交付物，本清单不声称完成）：**
- 生产 policy_lock 对象、DAIF 强制点、try_lock 重试环、冻结锁链调用图、最大深度上界证明、
  最坏路径**实测**计量方案、秩绑定与升序证明、§5 各偏差的裁决。
- 本清单的深度/路径为静态观察；**未实测、未冻结**。介质统一等下游仍须先等 G1 冻结。

**验证（本次实际运行，均通过）：**
- `cargo test -p cyxia-kernel-core control_plane::policy_lock_v0199` → 12 passed / 0 failed。
- `cargo test -p cyxia-kernel-core` → lib 342 passed + 全部集成测试，0 failed。
- `cargo build -p cyxia-kernel --target aarch64-unknown-none-softfloat --features smp-selftest` → Finished。
- `rustfmt --edition 2024` 已作用于 `manager.rs`（仅新增方法/测试/导入，未触碰无关既有代码）。