# CyxiaOS 1.3 原生控制隔离与双节点接入实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 按 1.3 功能契约实现持续运行的隔离 AI 控制服务和两个原生 CyxiaOS 节点的协作，并以实际执行、故障注入和独立判定器提供证据。

**Architecture:** 保留现有桌面及旧自检，建立版本化的原型机制与原生运行配置。EL1 只提供能力、所有权、派发、设备与持久化机制；模型、学习与发布代理属于控制 EL0，文件、网络/TLS、集群与纯计算任务属于业务 EL0。主机只构建、离线训练、模拟设备、注入故障和判定证据。

**Tech Stack:** Rust 1.95.0 `no_std`、AArch64 汇编、QEMU 10.2.2、Python 标准库验收工具；密码和 TCP/TLS 使用锁定的原生依赖。

**Spec:** `CyxiaOS_Minimal_Prototype_Design_Final.docx`，设计配置 1.3，SHA256 `e427ff5b75c5a7b5f3ae96ddb13905985b142132493b3af98544a9895865675a`。

## Global Constraints

- 用户于 2026-10-24 明确选择“沿用 Rust 接入功能，并明确记录对 1.3 语言要求的偏离”。唯一已批准偏离是 §1.2 的 C11 语言要求；不得因此声称逐条无偏离符合原规范。
- QEMU `virt-10.2,gic-version=2,secure=off,virtualization=off`、cortex-a53、4 vCPU、1 GiB RAM。验证 Guest vCPU 所有权，不证明宿主物理核独占。
- 每节点独立 512 MiB 磁盘，4 KiB 块，16 MiB redo；不同身份、MAC、IP、可写磁盘。失败关闭新授权，不清空历史以恢复服务。
- CACP 为独立 EL0 服务，正常优化由本地模型决定；业务热路径、完成和恢复不等待推理。
- C/B/T/Q 互斥且覆盖登记核心。DRAIN 和无 ACK 故障保留最后 C/B，suspect/draining 是独立标志；只有静默/可靠停止证明允许 T/Q。
- 64 业务线程、16 任务组、32 单向普通 IPC 端点；每核 100 ms 中硬承诺至多 90 ms。普通/控制/恢复完成队列各 64 槽，预占完成 credit。
- MLP 64→32→16→1，2576 个 int8 权重、49 个 int32 偏置，2772 字节；Q8.8 激活、有界整数推理、最多32候选、稳定择优。
- PolicyEnvelope 144 字节、PlanHeader 64 字节；受理期限100ms，持续参数到期为快照+10000ms，核心转换200ms。发布意图不等于实际执行。
- 16 域18动作族同等接入；完整完成须覆盖51个 A/T/E 编号、各动作族实际行为及文件格式故障。未运行为 NOT_RUN，禁止以主机测试填原生 PASS。
- 32 未释放远程合同、128 未确认结果槽、每 ClusterID 各4096合同/任务墓碑；纯计算 `hash_buffer/vector_sum`，无远程设备副作用。
- 旧81项清单保持历史身份，新1.3清单独立建立。当前工作区原有暂存修改不撤回、不混入本次提交。

## Review Focus

1. 无静默ACK、迟到ACK和已变化代际不能转移核心或释放页；任务2、5验证。
2. malformed/截断模型或报文、溢出与重复键必须拒绝且不部分修改状态；任务1、3、6验证。
3. 接受、PUBLISH、APPLIED、DONE、DURABLE与ACK必须分开；任务4–7验证实际边界。
4. 磁盘成功响应丢失、节点重启、网络分区不能产生第二次执行或丢失唯一结果；任务4、6、8验证。
5. 训练和模型故障不能吃掉恢复预算或让业务等待模型；任务3、5、7验证。

## Execution decisions

现有 `integrate/ai-control-20261024` 有用户未提交的集成工作。继续在该项目分支以新增模块隔离版本变更；不新建会遗漏工作区修改的旧HEAD worktree，不自动提交用户原有暂存区。并行任务只拥有互不重叠的文件，Cargo 清单和整机编译由协调者串行管理。

旧自检的合成遥测与 `production_isolation=false` 标签保持真实。新运行路径必须真正替换测试编排，不能通过改标签或验收脚本期望值制造完成。

## Task 1: 1.3 规格身份与验收目录

**Files:** Create `docs/implementation/v13-acceptance-map.md`, `docs/implementation/v13-requirements.json`, `tools/check_v13_evidence.py`, `tests/host/test_v13_evidence.py`.

**Interfaces:** 目录绑定本文档散列、Rust偏离和完整A/T/E集合；验证入口 `validate(document, root, source_manifest) -> dict` 返回目录完整性与原生证据完成度，不能将其解释为运行真实性证明。

- [ ] 以删减E用例、旧规范散列、旧81项、主机结果冒充原生、相同磁盘/身份、文件篡改和 NOT_RUN 发布写失败测试。
- [x] 保存编号原文及条款，新目录初始均 NOT_RUN；旧局部结果单独列为基线。
- [ ] 实现散列、来源、执行层次、每节点身份、配置及原始轨迹绑定检查；功能验收和语言偏离分别报告。
- [x] 运行普通与 `python -O` 的主机验证；`--release` 必须拒绝未完成目录。

## Task 2: 1.3 核心所有权与资源准入机制

**Files:** Create `crates/prototype/src/cores.rs`, `crates/prototype/tests/cores.rs`; coordinator creates crate/workspace declarations.

**Interfaces:** `Cores::new(online,control)`, `snapshot()`, `begin(target, expected_core_gen, expected_ledger_gen, now_ms) -> Ticket`, `ack_quiescent(ticket,cpu)`, `publish(ticket,now_ms)`, `suspect(cpu)`, `confirm_stopped(cpu)`, `expire(now_ms)`; exact signatures may include typed `Result` and bounded reservation records. Snapshot exposes C/B/T/Q, suspect/draining and generations. `permits(cpu,plane)` excludes suspect/draining. Resource admission records thread id, generation, budget_milli, allowed_mask, assigned_cpu; capacity checked per core, never only aggregate.

- [x] Tests first: 1→2→1, DRAIN keeps source ownership, no-ACK timeout keeps owner/suspect, stale ACK rejected, late success cannot revive canceled ticket, at least one healthy C/B and C overlap, generation exhaustion, two600milli threads restricted to one CPU rejected, no quota reset on migration.
- [x] Implement bounded safe no_std state machine with private proof construction; never accept an arbitrary externally supplied boolean as real stop proof. Native adapter is sole producer of validated acknowledgments.
- [x] Host tests and AArch64 compilation; no native PASS until task5 supplies actual stop/dispatch evidence. References A02/A04/A06/A09/A11, E02/E03/E07/E08/E13.

## Task 3: 1.3 integer model and immutable package

**Files:** Create `crates/prototype/src/model.rs`, `crates/prototype/tests/model.rs`, `tools/train_v13_model.py`, versioned model/schema under `ports/prototype/`.

**Interfaces:** `Model::parse(&[u8]) -> Result<Model,Error>` accepts exactly2772 bytes; `score(&[i16;64]) -> i16`; `select(&[[i16;64]]) -> Result<usize,Error>` accepts1..32 candidates, stable first-max. Package integer bytes are read-only and little endian for biases; input validation rejects malformed lengths before inference. Feature/schema identity supplied by versioned service ABI, not inferred from floats.

- [x] Tests first with independently hand-calculated multi-layer vectors, negative half rounding, saturation, malformed length, max-weight accumulation and tie order.
- [x] Implement exact §5 integer kernel without allocator/unsafe; reject zero or33 candidates.
- [ ] Train frozen package from replayed actual executions, split groups, record all hashes; synthetic initial engineering vectors remain marked synthetic until replaced by real replay data.
- [x] Compare independent host reference with actual EL0 inference and preserve input/output/timing. Completed for synthetic engineering vectors only; the trained package and full A05/A08/A16/E14 remain pending.

## Task 4: Native devices and persistent progress

**Files:** Create `crates/driver-virtio/src/net.rs`, tests there; create bounded journal modules under `crates/prototype/src/storage/`, native adapters in new kernel profile, offline format/check/fault tools under `tools/prototype/`.

**Interfaces:** `Net::initialize(Transport, &'static mut QueueMemory, &'static mut QueueMemory, &impl Platform)`, bounded `send`, `poll_tx`, `poll_rx`, `mac`; one queue owner with pinned DMA until completion. API returning Busy never overwrites in-flight DMA. Journal backend performs BEGIN+REDO/FLUSH/COMMIT/FLUSH before durable acknowledgment and preserves complete transaction keys through checkpoint.

- [x] Test net framing/used-length/descriptor ids, RX rearm, concurrent TX busy, feature rejection, queue poisoning without premature reuse; reuse existing MMIO/Platform contracts.
- [x] Implement modern VirtIO-net device1, queues0/1, no offloads; optional MRG_RXBUF negotiation still uses one bounded RX buffer and requires num_buffers=1. Actual two-QEMU Ethernet delivery is verified independently of cluster protocol. This implementation choice avoids QEMU 10.2.2 omitting num_buffers without MRG; it does not relax the header check.
- [x] Implement 4KiB codecs/formatter, redo/checkpoint/recovery, dedicated-volume BootEpoch and native VirtIO-block adapter; independent boot-image decoder.
- [ ] Extend to general filesystem service, identity/contracts, reserved completion space and full golden/fault matrix.
- [x] Host sparse-disk model discards unflushed writes at commit/checkpoint boundaries and selected format cuts; rejects SHA/CRC/chain corruption.
- [ ] Native power-loss model and full filesystem matrix, including identity/contracts; references A10/A11/E04/E15.

## Task 5: Continuous native control and business execution

**Files:** New explicit prototype kernel configuration and `kernel/src/prototype/` modules; native EL0 program under `user/prototype-control/`; `tools/prototype.py` build/run-single entrypoints.

**Interfaces:** Per-CPU protected context, async snapshot/request/reply mailbox, execution receipts keyed by boot/controller/decision/plan/action/target generations; task2 owns core publication. Stateful `poll(now)` does bounded work and returns to scheduling; no synchronous response wait in business, IRQ or lock scope.

- [ ] Native negative tests fail until secondary dispatch, protected mappings, forged receipt rejection and timer-contained controller faults exist.
- [ ] Boot four cores/1GiB from DTB, reserve control/progress pools, run control workers only C and business only B; EL0 service samples real scheduling/queue counters.
- [ ] Replace the closed test sequence with persistent sampling/decision/validation/drain/publish/reconcile loop; prove 1→2→1 from distinct actual load windows.
- [ ] Keep recovery/completion runnable during model stall, enforce unchanged budgets, pin pages until IPI/TLB/DMA completion. References A01–A09/A15, E01–E08/E13/E14.

## Task 6: Native transport and two-node protocol

**Files:** New business EL0 network/cluster service, `crates/prototype/src/cluster/`, pinned TCP/TLS dependencies, `tools/prototype.py run-pair` and fault injector.

**Interfaces:** 96-byte RPC header, bounded65536-byte payload over mutually authenticated TLS1.3; all session and BootEpoch checks use current authenticated peer. Membership STANDALONE/CONFIRMED/BOUND/LEAVING and connection READY/ISOLATED follow §§10–12. Native Store/Executor/DrainBackend connect to task4/5, never host proxies.

- [ ] Pin vetted transport/crypto sources and run standard vectors natively; disable0-RTT/resumption, provision distinct test identities, fail closed on unavailable CSPRNG.
- [ ] Implement bilateral proofs, READY/reconnect, QUOTE/PREPARE/COMMIT/ACTIVATE, bounded per-thread reservations and historical result/ACK/CLOSE.
- [ ] Run native `hash_buffer/vector_sum`, persist before success, preserve DONE body until durable receiver ACK, never rerun ambiguous STARTED after restart.
- [ ] Test all T01–T20/E09–E12, including real link loss, protocol replay, process/node crash, quota competition, tombstone exhaustion, final-gate races and formal leave.

## Task 7: Full-domain execution and model governance

**Files:** 16 domain executors and schema, native control learning/validation/publisher roles, grouped replay harness.

**Interfaces:** PolicyEnvelope144B/PlanHeader64B with bounded payloads, exact generation/freshness/idempotence rules. Each of18 families has at least two legal choices and distinguishable real workloads; APPLIED comes only from registered executor.

- [ ] Implement the §8 actions, cross-domain resource ledger, reserved completion credits and deterministic SAFE_EXEC revalidation.
- [ ] Last-layer-only clip/update/project/quantize learning, independent complete-MLP validation, Shadow and D15 limited Canary; model generation never rolls backward.
- [ ] Enforce61ms mandatory/70ms total control budget per100ms, raw full CPU accounting, five frozen paired seeds,1s warmup/10s observation including negative outcomes.
- [ ] Run A05/A08/A15/A16/E13/E14 and each action family; do not replace actual device/IRQ/process/file effects with logs.

## Task 8: Combined native acceptance and delivery

**Files:** `tools/prototype.py test/report`, versioned receipts and implementation documentation.

- [ ] Bind compiler/linker/QEMU/DTB/source/images/model/Schema/dependencies/commands and every node identity to each run.
- [ ] Run combined core-migration/resource-grant, AI-failure/memory-pressure/writeback, confirm/powercut, commit/lost-response, task-start/restart scenarios.
- [ ] Run all A/T/E,18-family and filesystem fault suites; independently review raw events, counters, durable images and verifier behavior.
- [ ] Verify build/run-single/run-pair/test/report return nonzero on failure; report remaining NOT_RUN/FAIL and language deviation explicitly. Only all functional gates passing permits the functional completion claim.

## Baseline, not completion

2026-10-24: existing Rust `ai-control-selftest` native run PASS at `artifacts/v13-implementation-baseline-20261024/control-normal/summary.json`: four guest CPUs,8 model inferences,1→2→1,one controller recovery,20 permission probes. It uses256MiB and synthetic telemetry and explicitly reports production isolation/cluster/full16-domain=false; it does not close any complete1.3 A/T/E gate.
