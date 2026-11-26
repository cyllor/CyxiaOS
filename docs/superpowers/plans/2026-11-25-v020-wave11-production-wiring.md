# V0.20 第十一波：新特性接入生产路径 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把不依赖 G1 介质的 V0.20 特性（FrameMeta 静态页登记、RecoveryProof v2 内存态、policy_lock 计量、SEC-N 真实网卡 + TCP 到 local-echo）真正接入 `v020-production` 启动路径；依赖介质的特性接到默认关闭的 `v020-production-media-staging` 后面。

**Architecture:** 在 `kernel/src/arch/aarch64/production/` 下新建子模块，每个特性一个文件，由 `production.rs::run` 和 in-vector 分发调用。每个特性把结果写进证据页 128..160 字（第十一波段），由 `tools/verify_v020_production.py` 按字校验。SEC-N 的 0x43 broker 从夹具中抽成对 `Port` 泛型的共享模块，夹具和生产共用。

**Tech Stack:** Rust no_std（EL1 `aarch64-unknown-none-softfloat`，EL0 guest `aarch64-unknown-none`）、smoltcp（net-transport `smoltcp` 特性）、QEMU 10.2.2 virt、Python 3 验证器（unittest）。

**Spec:** [docs/superpowers/specs/2026-11-25-v020-wave11-production-wiring-design.md](../specs/2026-11-25-v020-wave11-production-wiring-design.md)

**集成后的证据约定。** 以下表格记录初始计划。当前实现用字 133 记录 `RECOVERY_REQUIRED` 下的发布拒绝，字 140 记录 EL0 直接确认的 Admission 收据，字 152–155 分别记录恢复写者交接数、服务 Arena 页数、实际计量超限次数及最长实测耗时。字 144–151 仅用于介质暂存。完成标记跟踪 `media_staging_enabled` 与 `staging_ok`。TCG 泳道核对计量完整性，硬件预算另需取证。 [第十一波实现和复验](../../releases/v0.20.md#2026-11-25-第十一波生产路径接线)

## Global Constraints

- EL1 闭包保持软浮点，不得引入 `tls` / rustls / ring / NEON；`sec-n-native` 只含 smoltcp。
- 以下配置的构建结果行为不变：默认（无特性）、`smp-selftest`、`v0199-advice-e2e-selftest`、`v0199-sec-n-selftest`、`v0199-format-selftest`、`v0199-epoch-disk-selftest`、`legacy-coreset`。
- G-A 构建（`v020-production`）不得读写任何 v1 盘上布局。
- 证据如实标注：`production_skeleton=true`、`full_authority=false`、`real_models=false`、`staged_boot_epoch=true`、`tls_echo_turn_verified=false`、`recovery_pair_facts_staged=true`；不得出现「G4」「验收通过」等措辞。
- 同一条生产连接只用 `net-transport::admission::Admission` 计额度；生产代码不得引用 `kernel-core::security::network::RateLimiter`。
- 新增的 `static mut` 和原子量，都要在所属模块头部按 production.rs:36-60 的格式登记 unsafe 边界。production.rs:38 的原声明如果被新增的 DMA 或副核写入打破，必须改写为准确的描述。
- 单文件 ≤ 800 行（production.rs 已有 1839 行，只允许加入极少量调用点）；函数 < 50 行。
- QEMU 固定为 `virt-10.2,gic-version=2`、`cortex-a53`、`-smp 4`、`-m 256M`。
- 计数以实测为准：第十波基线 workspace 2067 项、源码守卫 43 项，均不得减少。
- 计量时间源：CNTVCT 按 CNTFRQ 换算为 ns；预算用 `policy_lock_v0199::WORK_BUDGET_NS = 45_000`。

## Review Focus

1. QEMU 不带网卡时，生产启动必须 fail-closed：`real_net_device=0`，串口输出 `V020_W11_NET_ABSENT`，建议链照常完成，G-A 泳道验证器判 FAIL。→ Task 7 `net_absent_is_fail_closed`、`rejects_missing_net_device`。
2. 对端在握手中途断开或一直不发数据时，broker 不能卡住：握手 turn 预算耗尽后回收连接，CPU0 回到 turn loop。→ Task 7 `peer_silent_exhausts_handshake_budget`，由 Task 5 实现。
3. 进入 RECOVERY_REQUIRED 或 Unknown 后再发起 0x41，必须被拒绝，`published_count` 不变。→ Task 3 `publish_rejected_after_unknown`。
4. 计量出现超预算时，被计量的调用结果照常返回，但超预算计数非零，验证器必须判 FAIL。→ Task 4 `overrun_settles_but_preserves_result`、Task 7 `rejects_policy_lock_overrun`。
5. 静态页区间重叠或超出 FrameMeta 窗口时，整个登记失败并粘性 fail-closed，不得部分发布。→ Task 2 `overlap_rejects_whole_registration`。

---

## 证据页第十一波段（Task 1 定义常量，各任务共用）

| 字 | 名称 | G-A 期望值 |
|---|---|---|
| 128 | `W11_MAGIC` = `0x4359_5052_4431_3131`（"CYXPRD11"） | 常量 |
| 129 | frame_meta_production_statics | 1 |
| 130 | FrameMeta permanent 行数 | = 静态页总页数，> 0 |
| 131 | recovery_accumulators | 4 |
| 132 | 已记录 DegradedEvent 总数 | ≥ 1 |
| 133 | recovery_required_publish_rejected | 1 |
| 134 | recovery_pair_facts_staged | 1 |
| 135 | policy_lock_metered | 1 |
| 136 | 已结算临界区数 | ≥ 2 |
| 137 | 超预算次数 | 0 |
| 138 | real_net_device | 1 |
| 139 | tcp_to_local_echo | 1 |
| 140 | Admission 已发放租约数 | ≥ 1 |
| 141 | 经 0x43 转给 local-echo 的字节数 | > 0 |
| 142 | tls_echo_turn_verified | 0 |
| 143 | staged_boot_epoch | 1 |
| 144 | media_staging_enabled | G-A 为 0；staging 泳道为 1 |
| 145..159 | staging 段（Task 6） | G-A 全为 0 |
| 160..511 | 保留 | 全为 0 |

G-A 的串口完成标记必须恰好出现一行：
`V020_W11_PRODUCTION frame_meta=1 recovery=1 metered=1 net=1 tcp_echo=1 tls_echo=0 media_staging=0`

---

### Task 1: 特性门控、模块骨架与证据段常量

**Files:**
- Modify: `kernel/Cargo.toml:66`；新增 `v020-production-media-staging`
- Modify: `kernel/src/composition/aarch64.rs:224-240`
- Modify: `kernel/src/arch/aarch64/production.rs`（只加 `mod` 声明和证据调用）
- Create: `kernel/src/arch/aarch64/production/evidence.rs`
- Modify: `tools/test_v19_native_security_source.py`

**Interfaces:**
- Produces: `evidence` 模块，含 `pub const W11_BASE: usize = 128`、`pub const W11_MAGIC: u64`，上表每个字各一个 `W11_*` 常量，以及 `pub fn put(word: usize, value: u64)`。`put` 只接受 128..160，越界调用 `fatal`。
- Produces: 特性 `v020-production = ["smp-selftest", "dep:sha2", "sec-n-native"]`、`v020-production-media-staging = ["v020-production", "prototype-memory"]`。

- [ ] **Step 1: 写失败的守卫测试** `test_v020_wave11_feature_gating`，断言：
  - `v020-production` 含 `"sec-n-native"`；
  - `v020-production-media-staging` 存在且含 `"v020-production"`；
  - `virtio_platform` 的 cfg 列表含 `feature = "v020-production"`；
  - `mod net_device` 附近不再有 `allow(dead_code)` 和 "not yet wired by default"。
- [ ] **Step 2: 运行** `python3 tools/test_v19_native_security_source.py`，确认新测试 FAIL。
- [ ] **Step 3: 实现**：
  - 修改 Cargo 特性；
  - 把 `virtio_platform` 的 cfg 扩展到 `v020-production`；
  - 删除 `allow(dead_code)`，注释改为如实描述 production/net.rs 的调用关系；
  - 在 run() 中写入 `W11_MAGIC` 和 `staged_boot_epoch=1`。
- [ ] **Step 4: 构建矩阵**：对 F ∈ {空, smp-selftest, v020-production, v020-production-media-staging, v0199-sec-n-selftest, v0199-advice-e2e-selftest} 逐个运行 `cargo build -p cyxia-kernel --release --target aarch64-unknown-none-softfloat --features <F>`，不得有错误。`net_device` 的未使用警告由 Task 5 消除，这一步允许暂时存在。
- [ ] **Step 5: 提交** `feat(v020-w11): production feature gating, W11 evidence segment`

### Task 2: FrameMeta 登记生产静态页

**Files:**
- Create: `kernel/src/arch/aarch64/production/frames.rs`
- Modify: `production.rs`（run() 开头一处调用）
- Test: `crates/kernel-core/src/frame_meta_v0199.rs` 内 `#[cfg(test)]`

**Interfaces:**
- Consumes: `Ledger::initialize_static(rows, base, &[StaticRegion])`（frame_meta_v0199.rs:281）、`Ledger::inventory()`（:437）。
- Produces: `pub(super) fn register_production_statics() -> Result<Inventory, Error>`。在任何 EL0 进入之前调用一次。失败时写字 129=0，run() 直接 `fatal`，不进入建议链。

- [ ] **Step 1: 写失败的测试**：
  - `overlap_rejects_whole_registration`：两段重叠区间 → `Err(Error::Conflict)`，并且没有任何行被发布；
  - `statics_register_as_permanent_unowned`：三段不重叠区间 → `inventory().permanent` 等于页数之和，`reserve()` 不会返回这些页。

  已有测试覆盖的部分只补断言。
- [ ] **Step 2: 运行** `cargo test -p cyxia-kernel-core frame_meta`，确认 FAIL。
- [ ] **Step 3: 实现**：
  - 登记的区间为 ROOTS、MIDDLES、LEAVES、DATA_PAGES、USER_STACKS、PIE backing/tables、EXEC_TARGET；PA 换算用 control_pool.rs:95-112 的 checked 写法；
  - 页表类登记为 `Metadata`，其余登记为 `Control`；
  - `base` 取最低 PA，窗口超过 `COUNT` 行时返回 `Error::Range`；
  - rows 放在模块内的 static backing，并登记 unsafe 边界。
- [ ] **Step 4: 运行** 测试 PASS；`v020-production` 构建通过。
- [ ] **Step 5: 提交** `feat(v020-w11): register production statics in FrameMeta`

### Task 3: RecoveryProof v2 内存态与 0x41 阻断

**Files:**
- Create: `kernel/src/arch/aarch64/production/recovery.rs`
- Modify: `production.rs`（run() 初始化；advice_dispatch 0x41 分支前检查，约 :1035）
- Modify: `kernel/src/arch/aarch64/exceptions.rs`（EL0 同步故障路径加一处 `record_fault`，只在 `v020-production` 下编译）
- Test: `crates/kernel-core/src/security/recovery_proof_v2.rs` 内 `#[cfg(test)]`

**Interfaces:**
- Consumes: `RecoveryAuthority::{new, record_degraded, observe_unknown, state}`（:732–833）。
- Produces:
  - `pub(super) fn init(boot_epoch: u64) -> Result<(), Error>`：
    - facts 中 `first_valid`、`second_valid`、`same_fs_uuid`、`identical_initial_pair`、`relation_provable` 为 true，其余为 false；
    - `protection_generation = 1`，`reopen_authority = SUPER`；
    - 写入字 131=4、134=1。
  - `pub(crate) fn record_fault(cpu: u32, esr: u64, far: u64)`：
    - 构造 `DegradedEvent { kind: OtherCritical, event_id: 每个 CPU 内单调递增, event_digest: sha256(esr‖far‖cpu), object_id: 0, object_generation: 1, failure_code: (esr >> 26) as u32 }`；
    - 只写本 CPU 自己的累加器。
  - `pub(super) fn publish_allowed() -> bool`：仅当 `state() == Verified` 时返回 true。
- 并发：每个累加器只由所属 CPU 写，gate 只由 CPU0 写。这条边界登记在 recovery.rs 头部，并据此改写 production.rs:38。

- [ ] **Step 1: 写失败的测试** `publish_rejected_after_unknown`，断言：
  - `new` 之后 `state()` 为 Verified；
  - `observe_unknown()` 之后为 Unknown；
  - 之后再 `observe_pair(&clean)`，状态不会回到 Verified；
  - `record_degraded(2, ev)` 只改变 cpu2 的 proof，其余三个 CPU 的编码逐字节不变。
- [ ] **Step 2: 运行** `cargo test -p cyxia-kernel-core recovery_proof_v2`，确认 FAIL。
- [ ] **Step 3: 实现**：
  - 0x41 分支在 `!publish_allowed()` 时返回 `E_AUTH`，不调用 bridge；
  - 正向建议链结算后，run() 调用 `observe_unknown()`，复用现有负向探测入口再驱动一次 0x41，断言返回 `E_AUTH` 且 `published_count` 仍为 1，然后写字 133=1；
  - run() 结尾把各累加器的事件数之和写入字 132。smp 业务夹具的权限故障探测会产生这些事件。
- [ ] **Step 4: 运行** 测试 PASS；构建通过。
- [ ] **Step 5: 提交** `feat(v020-w11): RecoveryProof v2 accumulators gate production 0x41`

### Task 4: policy_lock 计量接入 in-vector 注册与发布

**Files:**
- Create: `kernel/src/arch/aarch64/production/meter.rs`
- Modify: `production.rs:1000`、`:1035`（包住 `register_assisted_one` 和 `publish_assisted_one`）
- Test: `crates/kernel-core/src/control_plane/policy_lock_v0199.rs` 内 `#[cfg(test)]`

**Interfaces:**
- Consumes: `CriticalSectionMeter::{new, begin(SectionKind::EffectiveWork, now_ns), end(now_ns)}`。
- Produces: `pub(super) fn metered<T>(f: impl FnOnce() -> T) -> T`。
  - 调用前后各读一次 CNTVCT 换算为 ns，无论 `f` 成功与否都要结算；
  - 结算出错或超预算时，字 137 加一；正常结算时，字 136 加一；
  - `f` 的返回值原样透传；
  - run() 结束时写字 135=1。
- 只做计量；IRQ-off 强制和生产 policy_lock 对象归 G1，本任务不做。

- [ ] **Step 1: 写失败的测试** `overrun_settles_but_preserves_result`，断言：
  - begin(0)→end(45_001) 的结算是超预算类；
  - begin(0)→end(45_000) 不算超预算；
  - end 时间早于 begin 时返回 `Error::Clock`，之后的计量粘性失败。
- [ ] **Step 2: 运行** `cargo test -p cyxia-kernel-core policy_lock`，确认 FAIL。
- [ ] **Step 3: 实现** meter.rs，并包住两处调用点。
- [ ] **Step 4: 运行** 测试 PASS；构建通过。
- [ ] **Step 5: 提交** `feat(v020-w11): meter production register/publish critical sections`

### Task 5: SEC-N 真实网卡 + TCP 到 local-echo

**Files:**
- Create: `kernel/src/arch/aarch64/sec_n_broker.rs`（从 `v0199_sec_n_fixture.rs:398-650` 抽出 shared page 辅助函数、`allowed`、`broker`、`run_until_park`，改成对 `P: Port` 泛型）
- Modify: `v0199_sec_n_fixture.rs`（改为调用 sec_n_broker；`LoopbackPort` 保留，行为逐位不变）
- Create: `kernel/src/arch/aarch64/production/net.rs`
- Modify: `production.rs`（建议链之后调用一次 `net::serve`）；`composition/aarch64.rs`（`sec_n_broker` 的 cfg 为 `any(v0199-sec-n-selftest, v020-production)`）

**Interfaces:**
- Consumes: `net_device::init(&BootInfo) -> Result<NetDevice, Error>`；`cyxia_net_transport::device::{VirtioPort, Port}`；`tcp::Tcp::{new, listen, poll, state}`。Admission 留在 EL0 local-echo 内。
- Produces:
  - `pub(crate) fn broker<P: Port>(port: &mut P)`；
  - `pub(crate) fn run_until_park<P: Port>(layout: &Layout, port: &mut P, budget: u64) -> u64`；
  - `pub(super) fn serve(info: &BootInfo) -> NetOutcome`，其中 `NetOutcome { device: bool, tcp_established: bool, leases: u64, relayed_bytes: u64 }`。
- 网络参数：guest 用静态 IP 10.0.2.15/24，监听 TCP 7。
- 运行方式：轮询模式，IRQ 保持屏蔽，在 CPU0 上有界循环，上限 `NET_POLL_TURNS = 20_000`，私有定时器兜底。
- `leases` 读 local-echo 通过共享页回报的 Admission 计数，沿用夹具的 shared page 字段。
- 没有网卡时：`device=false`，串口打印 `V020_W11_NET_ABSENT`，不 fatal，不影响建议链证据。

- [ ] **Step 1: 写失败的守卫测试** `test_v020_wave11_sec_n_production_pins`，断言：
  - production/net.rs 调用了 `net_device::init`；
  - production/net.rs 不含 `LoopbackPort` 和 `RateLimiter`；
  - 夹具引用 sec_n_broker。
- [ ] **Step 2: 运行**，确认 FAIL。
- [ ] **Step 3: 抽出 sec_n_broker**，夹具改为调用它。运行 `python3 tools/verify_v0199_sec_n.py`，必须 PASS，且布尔标志与 artifacts/v020-wave9-sec-n-recheck/summary.json 一致，以此证明这是纯重构。
- [ ] **Step 4: 实现** production/net.rs，在 run() 中调用，写入字 138–142。
- [ ] **Step 5: 运行** 守卫 PASS；`v020-production` 构建通过，并且没有 dead_code 警告。
- [ ] **Step 6: 提交** `feat(v020-w11): real virtio-net + TCP to local-echo in production boot`

### Task 6: 介质 staging（默认关闭）

**Files:**
- Create: `kernel/src/arch/aarch64/production/media_staging.rs`（整个文件受 `v020-production-media-staging` 门控；按需拆分子文件，每个 ≤ 800 行）
- Modify: `production.rs` 的 0x40 分支：staging 下转交 media_staging，非 staging 仍返回 `EAGAIN`

**Interfaces:**
- Consumes: `file_format_v1` 格式化器、`file_mount_v1::validate`、`file_media_unified_v1::{validate_unified_system_map, unified_superblock_pair}`、`BootEpochAuthority::{open, allocate, confirmed_epoch}`、`file_admission_flow_v1::run_admission_flow`。
- Produces: `pub(super) fn stage(info: &BootInfo) -> StagingOutcome`，写入以下字：

  | 字 | 含义 |
  |---|---|
  | 144 | 1（staging 已启用） |
  | 145 | formatted |
  | 146 | mount_validated |
  | 147 | unified_map_validated |
  | 148 | `confirmed_epoch`，0 表示未确认 |
  | 149 | admission_flow_ok |
  | 150 | snapshot_0x40_fail_closed |
  | 151 | golden_vector_pending=1 |

- 磁盘：每次运行新建一块全零的 virtio-blk scratch 盘，用完即丢，做法同 verify_v0199_format.py。
- 串口输出 `V020_W11_MEDIA_STAGING golden_vector_pending=1`。只证明能启动、fail-closed 路径正确，不声称持久性或格式正确。

- [ ] **Step 1: 写失败的守卫测试** `test_v020_wave11_media_staging_is_opt_in`，断言：
  - media_staging 受 cfg 门控；
  - 非 staging 下 0x40 仍返回 `EAGAIN`；
  - `v020-production` 不蕴含 staging 特性。
- [ ] **Step 2: 运行**，确认 FAIL。
- [ ] **Step 3: 实现** media_staging。
- [ ] **Step 4: 运行** 守卫 PASS；两个 production 特性集都构建通过。
- [ ] **Step 5: 提交** `feat(v020-w11): opt-in media staging (golden-vector-pending)`

### Task 7: 验证器、CI 泳道

**Files:**
- Modify: `tools/verify_v020_production.py`
  - QEMU 参数：`-nic none` 改为 `-nic user,model=virtio-net-device,hostfwd=tcp:127.0.0.1:<空闲端口>-:7`；
  - 新增宿主对端：连上端口后发送一份固定的 512B ClientHello 样本，最多等待 5 s；
  - 新增 `--media-staging` 模式，额外挂载 scratch 盘。
- Create: `tools/test_verify_v020_production.py`
- Modify: `.github/workflows/v020-production.yml`（新增 staging 作业）

**Interfaces:**
- Produces:
  - `Production.validate` 新增对字 128..160 的校验，尾部全零检查改为从字 160 开始；
  - metadata 新增 `real_net_device`、`tcp_to_local_echo`、`tls_echo_turn_verified=False`、`frame_meta_production_statics`、`recovery_accumulators`、`recovery_pair_facts_staged=True`、`policy_lock_metered`、`media_staging_enabled`；
  - staging 模式另加 `golden_vector_pending=True`。

- [ ] **Step 1: 写失败的单测**（用合成的证据页和串口字节）：
  - `accepts_complete_w11_page`；
  - `rejects_missing_net_device`（字 138=0）；
  - `rejects_policy_lock_overrun`（字 137=1）；
  - `rejects_tls_claim`（字 142=1）；
  - `rejects_staging_words_in_ga_lane`（字 145≠0）；
  - `net_absent_is_fail_closed`（串口出现 `V020_W11_NET_ABSENT` 时判 FAIL）；
  - `peer_silent_exhausts_handshake_budget`（字 139=1 但字 141=0 时判 FAIL，并给出明确的错误信息）；
  - `staging_requires_golden_vector_pending`。
- [ ] **Step 2: 运行** `python3 -m unittest tools/test_verify_v020_production.py`，确认 FAIL。
- [ ] **Step 3: 实现** 验证器和 workflow 的修改。
- [ ] **Step 4: 运行** 单测 PASS；`python3 tools/verify_v020_production.py --output artifacts/v020-wave11-production` 连续 3 次 PASS；`--media-staging --output artifacts/v020-wave11-media-staging` 1 次 PASS。
- [ ] **Step 5: 提交** `test(v020-w11): verifier, CI lanes for production and media staging`

### Task 8: 中央验证、文档同步与波次落地

**Files:**
- Modify: `docs/design/v0.20-native-local-system.md` §6：新增第十一波段，并把第十波段里的「进行中」改为已提交的事实
- Modify: `docs/releases/` 下的 V0.20 发布记录（新增第十一波节）
- Modify: `production.rs:1-35` 模块头的 HONEST SCOPE

- [ ] **Step 1: 全量复验，记录实测数字**：
  - `cargo test --workspace 2>&1 | tee artifacts/v020-wave11-workspace.log`，逐段求和，总数 ≥ 2067 且 0 失败；
  - 源码守卫全部 OK，数量 ≥ 43 加本波新增；
  - `cargo fmt --check` 通过；双 profile clippy `-D warnings` 通过；
  - Global Constraints 中列出的每个配置都能构建；
  - 默认启动回归 `artifacts/v020-wave11-default-boot.json` PASS。
- [ ] **Step 2: 写文档**：每条结果都带范围标签和标志。未闭合清单至少包括：TLS 回显、真实模型、真实执行器、持久 BootEpoch（在 staging）、G1 字节冻结、生产挂载仍是 v2、全负载 PMU、127 个 ID 仍 NOT_RUN、G4/G5 仍 NOT_RUN。
- [ ] **Step 3: 合并为一个波次提交**（本波的本地提交都没有推送过）：执行 `git reset --soft c7bd8e0` 后提交，提交信息为 `Land V0.20 wave 11: production wiring for FrameMeta statics, RecoveryProof v2, policy_lock metering, SEC-N real NIC; media staging opt-in`，正文写明实测计数和范围标签。
