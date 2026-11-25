# CyxiaOS V0.20 集群残余删除就绪审计与分阶段删除计划（ledger #26 / PR #26 P1）

状态：**READ-ONLY 审计 + 本文件；未改动任何源码**。基线 `d07bd42`（CyxiaOS-V0.20，waves 6-7 已落地）。本文件是实现层就绪台账，不是正式设计基线变更，不是 V0.20 发行物，不授予任何 G0/G1/G4 合格声明。

上游要求（`docs/implementation/v020-six-workstreams-integration.md` 去分布式 #26 行，P1）：历史 `kernel/src/runtime/cluster`、`kernel-core/src/cluster`、`prototype/src/cluster`、可选 Cargo features 与 D16 历史兼容解码仍在；**需确认所有目标可达性及新介质无旧集群对象后分批删除**。本文件给出逐项可达性分类、删除前置判定与分阶段计划。

## 1. 删除前置判定（结论先行）

**问：门控死代码能否在不触碰 v2 介质的情况下删除？——能，但有源码层前置。**

证据：
- 默认构建（`v0199-local-native` / workspace 默认 features）根本不编译 `kernel-core::cluster`（`crates/kernel-core/src/lib.rs:3-4` `#[cfg(feature = "legacy-cluster")]`）与 `prototype::cluster::{wire,engine}`（`crates/prototype/src/cluster/mod.rs:1-6`）。默认 `cargo test -p cyxia-kernel-core` 442/0、`-p cyxia-prototype` 754/0（本次实测，见 §6）。
- 门控集群代码与 v2 介质格式**零耦合**：`kernel-core/src/cluster/*` 只使用其内部 `cluster/storage.rs` 的 legacy Store 契约（如 `boot.rs:7`、`contracts.rs:10`），不引用 prototype 的 `CLUSTER_*` 常量；`prototype/src/cluster/{wire,engine}.rs` 对 `crate::storage` / `crate::journal` / `local_volume` / `CLUSTER_*` 的引用数为 0（本次 grep 实测）。v2 介质由 `prototype/src/{storage,journal,local_volume}.rs` 独立写入。
- 因此删除这些门控模块**不可能改变任何 v2 介质字节**；`CLUSTER_*` 磁盘身份（§3.F）与门控代码删除是两条独立轨道。

**阻止"现在立即全删"的因素（全部是源码/治理层，不是介质层）：**
1. **源码守卫钉扎精确字符串**：`tools/test_v19_native_security_source.py` 的 wave 结构 pin 直接断言门控语句原文存在（§4）。删除门控代码必须在**同一提交**内改写这些 pin，否则 V0.20 CI（`.github/workflows/v20-native-hardening.yml:80`）红。
2. **kernel 的 `unified-runtime` 仍引用 `cyxia-prototype/legacy-cluster`**（`kernel/Cargo.toml:88`）并 optional 依赖 `cyxia-cluster-transport` / `cyxia-peer-billing`。删 prototype/kernel-core 的 feature 前必须先退役或重接 `unified-runtime`（kernel/Cargo.toml 属并发任务 T9 范围，本任务不触碰）。
3. **`local_volume.rs:6-9` 的 `cluster-engine` 分支**：`MAX_EFFECT` 在 engine 编译时取 `cluster::engine::MAX_EFFECT`（`engine.rs:111` = 33_200，与默认分支常量相同）。删 engine 需把该 cfg 双分支收敛为单常量，且该双分支原文被守卫钉扎（§4 pin 3）。
4. **验证车道**：`tools/prototype.py:115-118` 的 `cluster-engine` / `tls` 车道与 `tests/host/test_prototype_validation_lanes.py:16-28` 对车道存在的断言。
5. **默认宿主测试经 `#[path]` 直接包含 "cluster 路径下" 的现役文件**（§3.C）：`kernel-core/tests/native_store.rs:58`、`prototype/tests/domain_store_identity.rs:1` 无门控包含 `kernel/src/runtime/cluster/unified_store.rs` 与 `unified_store/identity.rs`；`prototype/tests/domain_network_quote_stop.rs:1`、`domain_network_placement.rs:4` 无门控包含 `user/prototype-cluster/src/abi.rs`。**这些文件是现役本地机制，不是死代码**，删除/搬迁前必须先给它们中性新家。
6. **旧分支 CI 仍消费 `user/prototype-cluster/tools/provision.py`**（v13-*、native-replay-current 等，均 branch-scoped 到 V0.13/V0.18/V0.19 等旧分支，不在 CyxiaOS-V0.20 触发；`workflow_dispatch` 仍可用）。退役这些工作流或保留旧分支快照是治理决定，不是技术阻断。

**阻止"完全删除"（含介质身份与 ABI 命名）的因素：**
- **G1 介质统一未冻结**：生产挂载仍是 V0.18 v2/4240 格式，`CLUSTER_INODES=[226,227]`、`CLUSTER_START=4242`、`.cyxia-cluster-a/b` 是磁盘可见身份（§3.F）。在 G1 冻结 v1/4118 + v4 收据并提供新镜像/离线迁移之前，**任何 CLUSTER_* 改名都不得发生**（storage.rs/local_volume.rs 的 "Do not rename" 注释是硬约束）。
- **默认学习回放依赖 D16 变体**（§3.D、§5）：`OfferCpu(0)` stop-quote 基线、stability 守卫、features 编码、RegisteredSet pack/unpack 全部在默认路径。变体本身不可门控、不可删。
- **120 字节位置化 custody key ABI**：`legacy_remote_scope` 字段名已是源码层改名（wave 6），字段本身是 wire ABI 的一部分（§3.G），删字段=ABI 变更，须走 G1 版本化冻结。

## 2. 可达性总览（默认构建视角）

| 残余区 | 默认编译？ | 默认运行可达？ | 分类 |
| --- | --- | --- | --- |
| kernel-core/src/cluster（13 文件）+ tests/cluster.rs | 否（legacy-cluster） | 否 | (a) 门控死代码 |
| prototype/src/cluster/{wire,engine} + 门控测试 | 否（legacy-cluster / cluster-engine） | 否 | (a) 门控死代码 |
| kernel/src/runtime/cluster 多数文件 | 否（unified-runtime） | 否 | (a) 门控死代码 |
| kernel/src/runtime/cluster/unified_store.rs + identity.rs | 是（宿主测试 #[path]） | 宿主测试 | (c) 现役本地机制，cluster 路径命名 |
| domains/types.rs D16/CoreSet 变体 + permitted_v0199_local | 是 | 是（学习回放/授权门） | (c) 承重 |
| policy_wire.rs D16 解码臂 | 否（legacy-d16-decode，wave 6 已门控） | 否 | (a) 已门控 |
| storage.rs CLUSTER_* / local_volume NAMES / journal 格式化 | 是 | 是（v2 介质） | (b) 磁盘身份，等 G1 |
| task_admission legacy_remote_scope | 是 | 是（custody ABI） | (c) 承重 ABI |
| user/prototype-cluster（独立 workspace，46 文件） | 否（非成员） | 仅旧分支 CI / 显式构建 | (a)  crate 级可删，但 3 个 src 文件被 #[path] 共享 |
| crates/cluster-transport（exclude） | 否 | 仅 unified-runtime/tcp-v13-selftest/旧 CI | (a/c) facade + legacy wire |
| crates/peer-billing（exclude） | 否 | 仅 unified-runtime | (a) 待 unified-runtime 退役 |
| net-transport LEGACY_CLUSTER_ALPN | 是（常量） | legacy TLS 诊断 | (c) wire 身份（T1/T2 范围） |

## 3. 逐项残余清单（file:line + 分类）

分类：**(a)** 门控死代码，源码层可删（不触介质）；**(b)** 磁盘可见介质身份，必须等 G1 介质统一；**(c)** 承重遗留诊断/现役机制/命名残余，不可直接删。

### A. kernel-core/src/cluster — (a)
- `crates/kernel-core/src/lib.rs:3-4` — `#[cfg(feature = "legacy-cluster")] pub mod cluster;`（唯一入口）。
- 13 文件：`admission.rs auth.rs boot.rs codec.rs contracts.rs endpoint.rs health.rs membership.rs mod.rs replication.rs storage.rs tasks.rs wire.rs`。内部 `Scope.cluster: ObjectId`（`mod.rs:73`）、membership/codec/replication 的 cluster 字段均为 legacy 双节点契约自有类型，与 v2 介质无关。
- `crates/kernel-core/Cargo.toml` — `legacy-cluster = []` + `[[test]] name="cluster" required-features=["legacy-cluster"]`。
- `crates/kernel-core/tests/cluster.rs`（约 2100 行）— 仅 feature 开启时编译；`CLUSTER_SCENARIO PASS` 证据串在 :2122。
- 删除影响：仅 legacy 诊断能力；默认构建零变化。

### B. prototype/src/cluster — (a)
- `crates/prototype/src/lib.rs:17` — `pub mod cluster;` 无门控，但子模块全门控，默认是空模块。
- `crates/prototype/src/cluster/mod.rs:1-6` — engine  behind `cluster-engine`，wire behind `legacy-cluster`，`cluster-engine = ["legacy-cluster"]`（Cargo.toml）。
- `engine.rs:111` `MAX_EFFECT = 33_200`；`engine.rs:229` `CX-CLUSTER-v1` hash 域（legacy 身份派生，仅 engine 内部）。
- `crates/prototype/Cargo.toml` — `legacy-cluster`/`cluster-engine`/`legacy-d16-decode` features + `[[test]] cluster_wire required-features`。
- 门控测试：`tests/cluster_wire.rs`（required-features）、`tests/cluster_engine.rs:1`、`tests/native_unified_store.rs:4`（`#![cfg(feature = "cluster-engine")]`）。
- **耦合点**：`crates/prototype/src/local_volume.rs:6-9` — `#[cfg(feature = "cluster-engine")] pub use crate::cluster::engine::MAX_EFFECT;` / `#[cfg(not(...))] pub const MAX_EFFECT: usize = 33_200;`。删 engine 时收敛为单常量（数值已相同），并同步守卫 pin。

### C. kernel/src/runtime/cluster（12 文件）— 多数 (a)，两个例外 (c)
入口：`kernel/src/composition/aarch64.rs:152,174-181`（全部 `#[cfg(feature = "unified-runtime")]`）。
- (a) `unified.rs`（1232 行，:25 #[path] 包含 user/prototype-cluster/src/abi.rs；:27-31 包含下列三个子模块）、`unified_discovery.rs`、`unified_runtime_loop.rs`、`unified_session_exit.rs`、`unified_task.rs`（608 行）+ `unified_task/custody.rs`（:62/:70 custody key 位置编解码）、`peer_replay.rs`（:12-17 包含 ledger/owner + user/prototype-cluster/src/replay_work.rs）、`peer_replay/{ledger.rs,owner.rs,attempt.rs}`。
- **(c) 例外 1**：`unified_store.rs`（156 行）— 名为 cluster，实为 **CPU0 append-only 期刊 broker**（本地机制，使用 `local_volume::{Volume,MAX_EFFECT}`）。被 `kernel-core/tests/native_store.rs:58` **无门控** #[path] 包含（默认宿主测试），也被 `prototype/tests/native_unified_store.rs:94`（cluster-engine 门控）包含。kernel 内仅 unified-runtime 使用（`unified.rs:602,1044`）。**删除/搬迁前必须先迁移默认宿主测试的包含路径。**
- **(c) 例外 2**：`unified_store/identity.rs`（25 行，CXID1/CXID2 85 字节身份记录准入）— 被 `prototype/tests/domain_store_identity.rs:1` **无门控**包含（默认宿主测试）。这是新介质身份记录的准入规则，属现役契约。
- 构建钩子：`kernel/build/aarch64.rs:262`（unified-runtime 分支）、:499（rerun-if-changed 清单含 `runtime/cluster/unified.rs`）、:515-540 附近 `CYXIA_CLUSTER_SERVICE_ELF` / `CYXIA_CLUSTER_IDENTITY` / `CYXIA_CLUSTER_UNIX_SECONDS` 环境变量硬依赖（unified-runtime 构建必须先有 user/prototype-cluster 产物与 provisioned 身份）。

### D. prototype/src/domains/types.rs — (c) 承重，**不可再门控**（详见 §5）
- `types.rs:145-150` — `Action::{ControlSet(u64), OfferCpu(u16), Placement(u16)}` 变体。
- `types.rs:157-165` — `permitted_v0199_local`：原生 V0.19.9 本地授权门，拒绝上述三变体进入新 prepare/apply/publish。调用点：`kernel/src/runtime/control/domain_control.rs:2571,2658`（默认原生控制路径）。**这是安全边界本身，不是残余。**
- `types.rs:176-180`（domain()：OfferCpu/Placement→16）、kind()/one_shot()/validate()/order() 各臂 — 被默认代码消费（§5 表）。

### E. policy_wire.rs D16 解码 — (a) 已门控（wave 6 完成，本任务未再改动）
- `crates/prototype/src/policy_wire.rs:175-178` — `(16,1)/(16,2)` 解码臂已在 `#[cfg(feature = "legacy-d16-decode")]` 后；默认 `_ => Err(Error::Unsupported)`。
- `policy_wire.rs:151` `(1,2) => ControlSet` **有意不门控**：域 1 是本地域，解码可达但授权门（D）拒绝执行；legacy-coreset 夹具依赖。
- `crates/prototype/src/policy.rs:606,627-628` — `unpack_registered_action` 的 (1,2)/(16,1)/(16,2) 臂是**内存 canonical pack/unpack**（RegisteredSet 紧凑存储），不是 wire 解码，默认承重，不可门控。
- 门控测试：`tests/domain_policy.rs:650-669`、`tests/native_control.rs:306,386,407,448`、`src/policy/canonical_plan_tests.rs:435-436`。

### F. 介质身份 — (b) 必须等 G1
- `crates/prototype/src/storage.rs:30` `CLUSTER_INODES=[226,227]`、:38 `CLUSTER_START=DATA_START+2`（DATA_START=4240，v2）、:42 `CLUSTER_FILE_BLOCKS=2048`；三处均带 "Legacy media identity … Do not rename" 注释。
- `crates/prototype/src/local_volume.rs:22` `NAMES=[".cyxia-cluster-a",".cyxia-cluster-b"]`（格式化时写入系统根目录项）、:23-24 `FILE_BLOCKS/START` 别名。
- 写入/校验消费点：`journal.rs:817`（格式化 inode 种类）、:872-873（目录项写入）、:895（CLUSTER_START 区域清零）；`domains/filesystem/validation.rs:6,123,135-136`（挂载校验）。
- 宿主/工具消费点：`tests/host/test_v2_filesystem.py:69`、`tools/check_v2_filesystem.py:27`、`tools/check_v13_filesystem.py:11`、`tools/check_v13_disk.py:160`、`tools/test_check_v13_boot_disk.py:74,112,140-184`、`tests/host/test_unified_disk.py:42`、`prototype/tests/domain_storage.rs:485,506`、`prototype/tests/journal.rs:3`（`CLUSTER_START as DATA_START`）。
- **判定**：这些名字/数值是 v2 磁盘格式身份。G1 冻结 v1/4118 + v4 收据、产出新镜像与离线迁移之前不得改名；改名必须与介质版本切换同一变更，不允许在 v2 上原地重命名。

### G. task_admission legacy_remote_scope — (c) 承重 ABI（改名已完成）
- `crates/kernel-core/src/control_plane/task_admission.rs:48-54` — `CustodyKey.legacy_remote_scope: [u8;32]`，注释明确：120 字节位置化 custody key 的 bytes 8..40，字段名纯源码层，wire 位置编解码不依赖名字。
- `task_admission.rs:193` — `reserve_with_custody` 要求该字段非零（key 有效性的一部分）。
- 位置编解码消费点：`kernel/src/runtime/cluster/unified_task/custody.rs:62,70`；`user/prototype-cluster/src/abi.rs:32`（注释）、`tests/driver_host.rs:318`、`tests/kernel_custody.rs:13`；宿主测试 `kernel-core/tests/task_admission.rs:7,32`。
- **判定**：字段删除=120B ABI 变更，须 G1 版本化冻结；当前命名已是可接受终态（守卫 pin 禁止回退为 `pub cluster:`）。

### H. user/prototype-cluster（46 文件，独立 workspace）— (a) crate 级，但有共享文件
- 非根 workspace 成员（自带 `[workspace]`/Cargo.lock）；依赖 `cyxia-cluster-transport(tls)` + `cyxia-prototype(cluster-engine)`；`[patch.crates-io] ring = vendor/ring`（中性路径，已搬迁）。vendor 目录已不存在于此 crate。
- **被外部 #[path] 共享的 3 个文件**：`src/abi.rs`（默认 prototype 测试 ×2 + unified.rs）、`src/replay_work.rs`（peer_replay.rs:17）、`src/application.rs`（`kernel/src/runtime/network/domain_network/requests.rs:11`，unified-runtime 门控）。删 crate 前必须先给这三份内容中性新家。
- `tools/provision.py` / `provision_billing.py` / `build.sh` — 旧分支 CI（v13-a-acceptance:106、v13-a01-stress:96、v13-boot-provenance:118、v13-a01-reboots:102、v14-native-a02:71、native-replay-current:92）与 `tools/build_unified.py:165-170` 消费。
- `tools/v16_a12_local.py:29-31` 钉扎其 3 个 src 文件的 SHA-256（历史验收工具）。

### I. crates/cluster-transport（exclude，T1/T2 范围，本任务仅登记）
- `src/lib.rs:10-17` — facade：re-export `cyxia_net_transport::{device,discovery,tcp,local_echo_tcp}`；本地仅剩 `wire.rs`（cluster RPC 帧，`wire.rs:67` `cluster_id:[u8;32]`）与 `tls.rs`（re-export net-transport tls）。
- 守卫依赖：`test_v19_native_security_source.py` 要求 facade 存在且 `pub use cyxia_net_transport`、`tls.rs` 含 `cyxia_net_transport::tls::*`（§4 pin 6/7）。
- 消费点：kernel optional dep（unified-runtime/tcp-v13-selftest）、user/prototype-cluster、`tools/prototype.py:117-118` tls 车道、`v19-advisory-smoke.yml:53`（V0.19 分支）、`tools/test_decode_discovery.py:17`、`tools/test_discovery_capture.py:30`、`tests/host/test_network_piece_trace.py:85,128`。
- Cargo.lock:124 条目（kernel optional dep 引入）。

### J. crates/peer-billing（exclude）— (a) 待 unified-runtime 退役
- 计费信封 crate（ed25519 签名 CPU 证据）；kernel aarch64 optional dep（`kernel/Cargo.toml` unified-runtime）。
- `tests/ledger.rs:1`、`tests/native_attempt.rs:23,25` #[path] 包含 `kernel/src/runtime/cluster/peer_replay/{ledger,attempt}.rs`。
- Cargo.lock:214 条目；`v18-x86.yml:41` 在 V0.18 分支 `-p cyxia-peer-billing`（该分支 workspace 未 exclude 时有效；V0.20 不触发）。
- `tools/test_v0199_local_link_graph.py:19` 断言默认链接图**不含** cluster-transport/peer-billing（删除后此守卫自然满足）。

### K. kernel 门控胶水 — (a/c)
- `kernel/src/main.rs:3-14` — compile_error：默认 profile 禁止 unified-runtime/tcp-v13-selftest/prototype-runtime（**保留，这是隔离边界**）。
- `kernel/src/composition/aarch64.rs:83-84`（tcp-v13-selftest → `runtime/network/cluster_transport.rs`）、:152-181（unified-runtime 各 mod）。
- `kernel/src/runtime/network/cluster_transport.rs`（295 行）— tcp-v13-selftest 专用 TCP bring-up 诊断，名字 legacy，机制是本地 TCP（无成员准入）。
- `kernel/Cargo.toml:88` unified-runtime 定义、tcp-v13-selftest、prototype-runtime；`kernel/build/aarch64.rs` unified-runtime 构建块（含 user/prototype-runtime、prototype-learning、prototype-governance 镜像构建）。
- smp.rs / prototype_storage.rs / virtio_platform.rs 中大量 `#[cfg(feature = "unified-runtime")]` 分支 — 随 feature 退役一并清除（T9 范围协同）。

### L. net-transport LEGACY_CLUSTER_ALPN — (c) wire 身份（T1/T2 范围）
- `crates/net-transport/src/tls.rs:47` `LEGACY_CLUSTER_ALPN = b"cyxia-cluster/1"`、:51 `ApplicationProtocol::LegacyCluster`、:57,:269。
- 守卫 pin：`test_local_echo_tls_is_protocol_isolated_from_cluster_rpc` 要求 net-transport tls.rs 同时含 `cyxia-echo/1` 与 `cyxia-cluster/1`。ALPN 是协商身份，删除=协议变更，须与 legacy TLS 诊断退役一起决定。
- 其余 net-transport 文件中的 "cluster" 均为禁止性注释（native_tcp.rs:4、service.rs:106、local_echo_tcp.rs:2-4、lib.rs:4-11），不是代码残余。

### M. 默认测试/工具的 legacy 命名 — (c)
- `crates/prototype/tests/cluster_volume.rs` — 无门控，测试的是 **local_volume**（现役机制），仅文件名 legacy。可更名（需同步源码清单门），不可删。
- `crates/control-model/src/reward_v2.rs:5` — 仅注释。
- `crates/kernel-core/src/control_plane/service_image.rs:1` — "private native cluster service" 注释；模块默认编译、默认宿主测试（tests/{service_image,image_abi}.rs）消费，运行期仅 unified.rs 使用。ELF 计划解析器本身是通用机制（新路径另有 pie_image_v0199）。注释更名安全但非必须；模块删除属后续阶段。
- `crates/kernel-core/src/control_plane/advisory.rs:75-76` — D16 无评审路径注释；`Controller<D>` 强制 D≤15（:81-83）是承重边界。
- `tools/cluster_native_journal.py` + `tests/host/test_native_cluster_journal.py` — v2 CXE1 期刊的宿主离线解码/向量（"host-only, never native admission evidence"）。属 (b/c)：读的是 v2 介质记录，G1 前保留为离线 v2 读取器。

### N. 历史文档与锁文件
- `docs/implementation/cluster-safety-core.md`、`docs/implementation/unified-native-control-cluster.md`、`docs/superpowers/plans/2026-10-24-unified-control-cluster.md` — 历史设计记录，保留（删除代码不删历史）。
- 根 `Cargo.lock:124,164,172,214` — cluster-transport/peer-billing 条目；依赖边移除后 `cargo generate-lockfile` 精确重生成（#26 已要求锁文件准确）。
- `user/prototype-cluster/Cargo.lock` — 随 crate 删除。

## 4. 源码守卫义务（删除提交必须同步改写）

`tools/test_v19_native_security_source.py`（V0.20 CI 每次运行，本次实测 37/37 OK）中与集群直接相关的精确字符串 pin：

| # | 测试方法 | 钉扎内容 | 删除阶段影响 |
| --- | --- | --- | --- |
| 1 | `test_v020_wave_structural_pins_kernel_core_cluster_isolation` | kernel-core lib.rs 门控原文 + `legacy-cluster = []` + cluster test required-features | Phase 1 删 kernel-core/cluster 时改写为"模块不存在"断言 |
| 2 | `test_v020_wave_structural_pins_prototype_wire_isolation` | prototype cluster/mod.rs wire 门控 + features + cluster_wire required-features | Phase 1 同上 |
| 3 | `test_v020_wave_structural_pins_local_volume_relocation` | local_volume.rs MAX_EFFECT 双 cfg 分支原文 | Phase 1 收敛单常量后改写 |
| 4 | `test_v020_wave6_structural_pins_legacy_d16_decode_gate` | policy_wire.rs 两个 cfg 解码臂原文 + `legacy-d16-decode = []` | Phase 5 若删 compat 解码时改写 |
| 5 | `test_v020_wave6_structural_pins_task_admission_legacy_scope_rename` | `pub legacy_remote_scope: [u8; 32],` + 非零校验 + 禁止 `pub cluster:` | Phase 5 ABI 变更时改写 |
| 6 | `test_v020_wave6_structural_pins_net_transport_adapter_relocation` | cluster-transport facade re-export 原文 | Phase 3 删 facade 时改写（T1/T2 协同） |
| 7 | `test_local_echo_tls_is_protocol_isolated_from_cluster_rpc` | 读取 cluster-transport/src/tls.rs；net-transport 含 `cyxia-cluster/1` | Phase 3 / ALPN 决定时改写 |
| 8 | `test_v019_freestanding_ring_uses_existing_native_crypto_patch` | `ring = { path = "vendor/ring" }` | **不受删除影响**（中性路径已就位，删 user/prototype-cluster 不触 TLS crypto） |

另有：`tests/host/test_prototype_validation_lanes.py:16-28`（cluster-engine 车道存在性）、`tools/test_v0199_local_link_graph.py:19`（默认链接图排除断言，删除后仍满足）、`tools/v16_a12_local.py:29-31`（历史 SHA-256 pin，随历史工具退役）。**源码清单门要求更名/搬迁先 staged**（wave 经验），并发编辑触发竞态需新目录重试。

## 5. types.rs D16 门控决定（任务 4）：**不门控**

判定依据（全部默认路径消费点，本次 HEAD 实测）：

| 变体 | 默认消费点 | 后果若门控 |
| --- | --- | --- |
| `OfferCpu` | `learning/baseline.rs:8,16,23-26` — **stop-quote 特例**：`(16,1)+[0;4]` 解码为 `OfferCpu(0)`，不经 legacy-d16-decode；`learning/reward.rs:590`、`reward/bounded.rs:1212` stopped_offer；`domains/stability.rs:114,167-168,457-458` D16 守卫；`domains/platform/placement.rs:48` QuoteExecutor；`policy.rs:346-348` opening_offer、:627 unpack；`features.rs:177` | 默认学习回放（wave-5 已确认）与 stability/quote 机制编译失败 |
| `Placement` | `policy.rs:360`（(16,2) 候选集必须含 Placement(2) 的不变量）、:628 unpack；`features.rs:110,175` | 默认候选集校验/特征编码编译失败 |
| `ControlSet` | `policy_wire.rs:151` 域 1 解码（有意不门控）；`policy.rs:352,606`；`features.rs:122,156`；`learning/reward.rs:582,875` | 本地域 1 契约与 legacy-coreset 夹具编译失败 |
| `permitted_v0199_local` | `kernel/src/runtime/control/domain_control.rs:2571,2658` | 原生授权门消失 = 安全回归 |

结论：types.rs 的 D16/CoreSet 变体是**默认学习回放与授权契约的承重件**，不是 compat 解码残余。真正的 wire compat 解码残余已在 `policy_wire.rs:175-178` 由 `legacy-d16-decode` 门控（wave 6 完成，守卫 pin 4 保护）。**本任务对 types.rs 零改动**；变体的最终退役只能发生在 G1 Action v2 冻结、stop-quote 基线改用非 D16 表示之后（Phase 5，设计决定）。

## 6. 分阶段删除计划

顺序约束：Phase 1-3 为源码层，互不触介质，可在 G1 之前推进；Phase 4 严格 G1 之后；Phase 5 严格 G1 ABI 冻结之后。每阶段独立提交，守卫与源码同提交更新，验证 = workspace 默认测试 + 源码守卫 + 两架构构建（CI 口径见 `.github/workflows/v20-native-hardening.yml`）。

### Phase 0 — 审计与就绪台账（本任务，已完成）
- 产出本文件；确认门控代码与 v2 介质零耦合；确认 types.rs 不可再门控。无源码改动。

### Phase 1 — 门控安全核心与 wire/engine 删除（源码层，不触介质）
范围：`kernel-core/src/cluster/`（13 文件）+ `kernel-core/tests/cluster.rs` + kernel-core `legacy-cluster` feature；`prototype/src/cluster/`（3 文件）+ prototype `legacy-cluster`/`cluster-engine` features + `tests/{cluster_wire,cluster_engine,native_unified_store}.rs`；`local_volume.rs:6-9` 收敛为单 `MAX_EFFECT = 33_200`。
前置：
1. kernel `unified-runtime` 退役或重接（解除对 `cyxia-prototype/legacy-cluster` 的引用；kernel/Cargo.toml 与 T9 协同）；若 unified-runtime 暂留，则本阶段只能删 kernel-core 侧，prototype feature 保留为空壳直至 Phase 2。
2. 守卫 pin 1/2/3 同提交改写；`tools/prototype.py` cluster-engine 车道与 `test_prototype_validation_lanes.py` 同步。
3. `cargo generate-lockfile`（如依赖边变化）。
验证：默认 workspace 测试、守卫、AArch64/x86 构建；可选 `--features legacy-cluster` 车道在本阶段后不复存在（CI 旧分支工作流不受影响，branch-scoped）。

### Phase 2 — kernel runtime/cluster 退役与现役文件搬迁
范围：`kernel/src/runtime/cluster/{unified,unified_discovery,unified_runtime_loop,unified_session_exit,unified_task,peer_replay}.rs` 及子目录中纯 legacy 部分；kernel `unified-runtime`/`tcp-v13-selftest`/`prototype-runtime` features 与 `build/aarch64.rs` 对应构建块（CYXIA_CLUSTER_* 环境变量）、`runtime/network/cluster_transport.rs`、composition 门控 mod。
前置（**搬迁先于删除**）：
1. `unified_store.rs` + `unified_store/identity.rs` 迁至中性路径（建议 `kernel/src/runtime/files/` 或 `control/`），同步 `kernel-core/tests/native_store.rs:58`、`prototype/tests/domain_store_identity.rs:1`、`prototype/tests/native_unified_store.rs:94` 的 #[path]；搬迁先 staged（源码清单门）。
2. `user/prototype-cluster/src/abi.rs` 的共享常量迁至中性 crate（默认 prototype 测试 ×2 依赖）；`replay_work.rs`/`application.rs` 随 unified-runtime 退役失去消费者后方可删。
3. 守卫与 `tools/v16_a12_*`、`tools/build_unified.py`、旧分支 CI 工作流退役决定同步。
验证：默认宿主测试（含 native_store/domain_store_identity）+ 两架构构建 + 守卫。

### Phase 3 — 排除 crate 与 user crate 删除
范围：`crates/peer-billing/`、`crates/cluster-transport/`（T1/T2 net-transport 收敛完成后）、`user/prototype-cluster/`（46 文件）；kernel optional 依赖边移除；根 Cargo.lock 精确重生成；workspace `exclude` 列表清空。
前置：Phase 2 完成；ALPN `cyxia-cluster/1` 退役决定（守卫 pin 7）；facade 守卫 pin 6 改写；`tools/prototype.py` tls 车道、`tools/test_decode_discovery.py`、`test_discovery_capture.py`、`test_network_piece_trace.py` 同步；`vendor/ring` 不动（pin 8 已中性）。
验证：`tools/test_v0199_local_link_graph.py` 默认链接图断言 + workspace 测试 + 守卫 + 两架构构建。

### Phase 4 — 介质身份更名（**严格 G1 之后**）
范围：`storage.rs` CLUSTER_INODES/CLUSTER_START/CLUSTER_FILE_BLOCKS、`local_volume.rs` NAMES、journal 格式化/校验、Python v2 检查器与宿主测试（§3.F 全清单）。
前置：G1 冻结 v1/4118 超级块 + v4 收据索引；新镜像/离线迁移工具与断电恢复证据（#25/#28 P0 门）；**新介质确认无旧集群对象**（#26 原文要求）——迁移后介质不再含 `.cyxia-cluster-a/b` 目录项与 226/227 保留 inode 语义。
规则：不允许在 v2 上原地改名；更名与介质版本切换同一变更；旧 v2 离线读取器（tools/cluster_native_journal.py 等）保留或显式退役。

### Phase 5 — ABI 与 D16 变体退役（**严格 G1 ABI 冻结之后**）
范围：custody key `legacy_remote_scope` 字段（120B→新 ABI）；`Action::{OfferCpu,Placement,ControlSet}` 变体与 `legacy-d16-decode` compat 解码。
前置：G1 Action v2 / SVC ABI v3 冻结；stop-quote 基线改用非 D16 表示的设计决定（learning/baseline.rs、stability.rs、reward、features、policy unpack 全链改造）；`permitted_v0199_local` 授权门随变体删除而失去对象，需以新 schema 的域边界（advisory D≤15）承接；守卫 pin 4/5 改写。
规则：在此之前，types.rs 变体与 `legacy_remote_scope` 命名是**可接受终态**，不做进一步门控。

## 7. 本次验证证据（实测）

基线 `d07bd42`，工作树审计开始时干净；`. "$HOME/.cargo/env"` 后执行：
- `cargo test --locked --offline -p cyxia-kernel-core`：**442 passed / 0 failed**（默认 features；legacy-cluster 测试目标按 required-features 排除）。尾部 `test result: ok. 4 passed; 0 failed`（time.rs）+ Doc-tests 0。
- `cargo test --locked --offline -p cyxia-prototype`：**754 passed / 0 failed**（默认 features；cluster-engine/legacy-cluster/legacy-d16-decode 测试排除）。尾部含 2 个 compile-fail doc-tests PASS。
- `python3 -B -m unittest tools.test_v19_native_security_source`：**Ran 37 tests — OK**。
- 门控代码与 v2 介质零耦合：grep 实测（§1）。
- 本任务未修改 types.rs（§5 判定），未修改任何其它源码；新增文件仅本台账。

## 8. 与并发任务的边界

- T1/T2（net-transport）：`LEGACY_CLUSTER_ALPN`、cluster-transport facade 的收敛归其范围；本台账仅登记依赖。
- T9（kernel/Cargo.toml）：unified-runtime/tcp-v13-selftest/prototype-runtime feature 退役归其范围；Phase 1/2 的前置 1 需与其协同。
- 本任务所有权：`domains/types.rs`（判定为零改动）+ 本文件。未触碰其它路径。
