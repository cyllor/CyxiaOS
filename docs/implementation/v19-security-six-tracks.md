# CyxiaOS V0.19 — 六大安全专项代码实施与证据边界

状态：**WIP / 未通过 G2–G4 原生验收**。本文件对应《CyxiaOS V0.19 六大安全方向并行细化设计》（2026-11-23），不更改现有 syscall ABI、PolicyEnvelope、PlanHeader、磁盘格式或 D01–D15 动作集合。原有分布式 D16/集群运行时代码仍须在独立的单机化变更中移除。

## 源代码

| 专项 | 新增确定性机制 | 源码 | 单域主机测试 |
| --- | --- | --- | --- |
| SEC-P 进程安全 | 受限包/调用者与业务核准入、spawn 去重、退出/引用/TLB/DMA 栅栏 | `crates/kernel-core/src/security/process.rs` | `sec_p01`–`sec_p08` |
| SEC-F 文件安全 | 路径字节边界、能力/代际/受保护系统对象、redo 提交阶段与 UNKNOWN 收据 | `.../security/file.rs` | `sec_f01`–`sec_f08` |
| SEC-M 内存安全 | 帧归属、W^X/别名、清零门、TLB ACK 与 DMA pin/reference 退役 | `.../security/memory.rs` | `sec_m01`–`sec_m08` |
| SEC-N 网络安全 | 本机只读 Echo 帧边界、限流/握手额度、TLS 版本与受限授权契约 | `.../security/network.rs` | `sec_n01`–`sec_n08` |
| SEC-D 设备安全 | 有界描述符租约、完成/复位证据、UNKNOWN 资源留存、IRQ 路由合法性 | `.../security/device.rs` | `sec_d01`–`sec_d08` |
| SEC-S 系统调用安全 | 已有调用号白名单、稳定复制、svc_submitv 输入前检、角色检查、幂等终态 | `.../security/syscall.rs` | `sec_s01`–`sec_s08` |

共 48 个单域 **主机契约** 测试函数，以及 12 个 `j01`–`j12` 跨模块**主机模型**测试。测试名称不意味着满足同名 SEC/J 的原生设备/负载/故障注入验收：例如 SEC-N01 的真实 TLS 签名、SEC-N07 的密钥泄漏观测、SEC-F05 的掉电 FLUSH 和 SEC-D05 的真实设备复位均须在受保护客体中独立证明。

### 当前实际接线

- `control_plane::manager::actor` 的唯一发布者检查调用 `security::syscall::can_publish`，保留既有控制核权限检查。
- 其余五域的纯机制对象**尚未**全部连接至内核 syscall/EL0、地址空间装载、VirtIO/TLS/文件持久化执行器。
- `VerifiedTls`、`ReliableReset`、`CompletionProof` 和 `SharedGrant` 的内部构造器只表示预期的可信调用边界；不能由此宣称已有实际 TLS/IRQ/TLB/设备停止的硬件证据。
- `SpawnLedger`、`DurableReceipts` 和 `ReceiptTable` 的有界历史空间不会自动回收；生产接线前必须冻结墓碑保留/重放水位与资源背压策略，禁止静默淘汰 UNKNOWN。
- 既有 `cyxia-prototype` 域机制、V0.18 不可变日志快照和原生执行器保持原状；没有使用本补丁更改磁盘记录或宣称 fsync 已经过新 SEC-F 审核。
- V0.18 独立内存安全增量 `fd526faff0517d06baca99073a0536f99f7cb13c` 仍须拿到源码、比对、合入并复测，不能用此模块充当那个补丁。

## 验收关口（原设计 G0–G4）

| 门槛 | 状态 | 现有证据与缺口 |
| --- | --- | --- |
| G0 基线与 ABI 冻结 | **PARTIAL** | V0.19 分支和新模块未扩 ABI；原有历史设计与新设计 v2 协议仍需逐项冻结对账 |
| G1 对象/权限/收据契约 | **PARTIAL** | 六域安全数据结构已加入源码；DEC-01–05 和实际角色/能力绑定需冻结 |
| G2 六域原生代码 | **NOT_RUN** | 主机机制代码已写入；EL1/EL0 全域接线、故障注入、可信 TLS 与 DMA 证据未完成 |
| G3 十二项跨域交错 | **NOT_RUN** | 仅 J01–J12 主机模型测试代码；真实 CPU/IPI/TLB/DMA/断电并发尚未执行 |
| G4 全系统安全验收 | **NOT_RUN** | 原 A/E/H 强制用例、48 SEC 和 12 J 的原生 PASS 及三 AI 模式证据缺失 |

本提交环境无可执行的 Rust 工具链或 QEMU；任何测试命令都 **未被本提交者执行**，GitHub Actions 后续的报告也不能自动替代客体故障验收。

## 主机检查命令（执行后须留记录）

```sh
cargo test --locked --offline -p cyxia-kernel-core --lib security::
cargo test --locked --offline -p cyxia-kernel-core --test control_plane
cargo test --locked --offline -p cyxia-prototype --test immutable_snapshots
```

对每个 SEC/J 原生用例，必须另记录源码/模型/Schema/RuleProfile/镜像 hash、客体平台和 AI 模式、种子与故障时刻、原始对象/代际、权限拒绝、前后账本、真实完成/保留证据及独立判定器版本。缺任一完整链路不得置 PASS。网络仅取得只读回声权限；AI 从不取得安全拒绝、资源授予、页表、设备停止或文件持久化的裁决权。

## 下一项可合并条件

- 在单机版原生内核中用受保护的任务/能力/文件/帧/设备/网络注册表构造上述证据，不接受业务或 AI 伪造的字段；
- 给实际事务/队列/进程/映射加线性化点、必要停止/FLUSH/ACK 栅栏，并保持固定容量； 
- 完成 ABI/磁盘/对象格式冻结、编译和静态/单元测试，再跑原生负向及 J01–J12 矩阵；
- 按 `AI_DISABLED`、`SHADOW`、`ASSISTED` 分别保存可核验结果；任何强制项 FAIL 或 NOT_RUN 时不可宣布“六大安全专项实施完成”。

## G2 接线增量：可信入口（AArch64 原生运行时）

- `kernel/src/runtime/tasks/domain_tasks/abi.rs` 的批量只读请求在读取到**内核私有稳定副本**后、分配 vector ID 与执行服务 preflight 之前，调用 `security::syscall::validate_readonly_batch` 校验批次长度、flags、合法 opcode 与 tag 唯一性。对象/能力代际等由既有 `ServiceBatch::preflight/resolve` 逐项裁决，避免错误的全批回滚。
- `kernel/src/runtime/tasks/domain_tasks/memory.rs` 的用户复制准备阶段已使用 `security::syscall::user_copy_span` 做可溢出地址范围拒绝；页实际归属、访问权限和缺页处理仍由原生 pager 校验。
- 旧本机业务接口 19/20（跨节点放置、结果查询）现在在内核 syscall 入口**直接返回 Unsupported**，不会接收远端任务、授予资源或触碰用户缓冲区。其余 `unified-runtime` 集群代码仍在，故不能声称已移除整个分布式系统。
- 这是代码接线，不是运行保证；必须由目标 AArch64 构建、用户态伪造调用、非法/旧能力与链路断开注入证明真实拒绝。安全引擎、权限记录和审计上限未被扩容。

## G2 增量：SEC-P/SEC-M 原生强制入口（本次）

- SEC-P 在 AArch64 的 `Creator::authorize` 和 `Creator::build` 中复用 `security::process::authorize_business_core`，由原生 `CpuLayout`（已排除 draining）核验健康业务核心及配置代际；请求不能凭模型建议把新任务放入 C/T/Q 核。真正的调度承诺、资源账户与 rollback 仍由原 `SpawnAdmission` 和 scheduler 完成，不建立并行账本。
- SEC-M 在原生 `Pages::map` 和 `Pages::revoke` 前验证 frame 不属于启动期页表/代码保留前缀或物理池外；拒绝时不发布新 PTE，也不释放仍受账本监管的页。真实 owner、清零、全局 TLBI/DSB/ISB 仍来自既有 `Memory` 与架构层。
- 两处增加了纯单元负向测试，验证错误 CPU、draining、quarantine、错误代际以及保护帧/越界帧的拒绝。**测试通过不构成“所有 DMA/TLB ACK 已实施”或真实 SMP 故障注入通过**。

### G2 隔离核拒绝追加

- `cyxia_prototype::domains::tasks::Scheduler::quarantine_mask()` 新增常数时间可信读取，不遍历线程表。
- AArch64 `Creator::authorize/build` 调用受保护 `security::process::authorize_business_core` 时，除了健康业务核和代际，现还同时传入真实调度器隔离位图；已被隔离 CPU 不能作为新任务创建目标。
- 本地 CI 新增原 `domain_tasks` 主机调度/生命周期回归；完整 ARM 运行时仍需独立构建与故障注入。

### G2 增量：SEC-F 与 SEC-D 原生入口（本轮）

- `kernel/src/runtime/files/domain_file_abi.rs::validate_shape` 在已稳定复制的 EL0 文件 ABI 帧上调用 `security::file::validate_absolute_path`；非法路径与组件在 inode 分配、日志或文件系统操作前拒绝。仅对包含路径的既有操作生效，不修改 ABI 或磁盘格式。
- `crates/driver-virtio/src/block/batched.rs` 的块设备完成已验证时保留原 token 的代际与完成占用，直到调用者 `acknowledge` 且 `queue.release` 成功才释放。本驱动复用原有 `pending` 槽，无新增缓冲或完成池；超时不会将已完成但未 ACK 的 DMA 误当成未完成并释放。
- 新增 `native_sec_d06_completion_keeps_exact_token_until_valid_ack`，检查过早 ACK、失效代际、重复 ACK、延期 ACK 和真正可静默性；新增路径输入负向单元测试及源码接线回归。
- 这些是实际原生入口的代码改动，但 *不等于* 真实掉电/恶意设备/DMA/TLS 故障验收。需在 AArch64 目标构建和 QEMU 注入下继续 G2/G3/G4。

### G2 下一步：文件系统内部路径与设备部分完成超时（本轮）

- `crates/prototype/src/domains/filesystem.rs` 的内部 `FileSystem::path` 也拒绝空组件、重复斜杠、尾部斜杠、`.`/`..`，且遵守 512/63 字节界限；这补足了已有 EL0 文件服务输入检查以外的直接内部调用边界，不新增磁盘格式或权限位。
- `crates/prototype/tests/journal.rs` 增加 SEC-F01 原生文件系统模型的无副作用非法路径测试；CI 还运行整个 journal 断电/两次 FLUSH/重启测试文件，保留现有不可变快照回归。
- `crates/driver-virtio/src/block/batched.rs` 增加真实 split-ring 模拟的部分完成、另一个请求超过 250ms 超时测试：仅已证实完成的 token 可单独 ACK，未知在途描述符及 DMA 缓冲维持占用，队列失效并拒新 I/O。
- 以上均属于主机可复现机制与模拟故障验证，**不是**在 AArch64 QEMU 中证明物理 DMA 停止，也不是完整 SEC-F05/SEC-D05 的原生验收。

### G2 单机网络/TLS 协议隔离增量（本次）

- 新增独立 `crates/net-transport`：将原来集群包中的同一份 rustls TLS 1.3 双向 Ed25519 钉扎、X25519、密钥清除及无恢复票据实现**迁到无集群依赖的基础库**。旧 `cyxia-cluster-transport::tls` 只做兼容 re-export，保持旧 ABI/ALPN 和既有历史测试可用，避免两套不一致的 TLS 安全实现。
- `Pairing::new_local_echo` 使用独立的 `cyxia-echo/1` ALPN；旧 `Pairing::new` 仍保留历史 `cyxia-cluster/1`。只有实际钉扎 TLS 握手完成且会话协议为单机 Echo 时，`Session::accept_local_echo` 才允许解析已解密应用字节；在握手前或旧集群会话中拒绝。 进一步要求 Rustls 回报的**实际协商 ALPN** 与 Echo 标识一致，不能仅以配置文件、服务名称或已认证身份推断 ALPN。
- `crates/net-transport/src/echo.rs` 仅支持固定 16 字节小端头和 `READONLY_ECHO=1`、最大 4096 字节正文。精确长度/版本/操作码检查；任务、远程放置、资源授权、文件修改以及 Plan 发布操作没有任何解码入口。
- CI 新增从独立包执行的完整 TLS 测试、legacy TLS 兼容测试，及相应源代码守卫。此增量**不是**原生 EL0 Echo 服务或可认证设备 TCP/TLS 运行验收；单机网络实体执行、16/4 连接额度、来源限流、实际证书配置和 QEMU 故障交错仍需 G2/G3 证明。

### AArch64 目标编译门（开发 CI，不是原生验收）

增加 `cyxia-net-transport` 开启 TLS 特性的 `aarch64-unknown-none-softfloat` 交叉编译检查，用于发现 ARM 裸机目标中的 rustls/ring/Crypto 兼容性问题。此检查不实例化网络设备、不驱动 TLS 会话、没有实际 QEMU 数据包/证书/断线证据；结果必须以对应 GitHub Actions 记录为准。G2/G3/G4 状态不因编译成功而升级。

交叉编译初次尝试在 `ring` 的 freestanding C 构建中缺少 `assert.h` 而失败，不能标记 ARM PASS。下一次按发布模式编译，并对裸机 C 加 `-DNDEBUG`（只禁用标准 C 调试断言，不改变 TLS 证书、身份、ALPN 或 Rust 协议验证的代码路径）；必须重新检查 CI 编译日志，且依旧不代表设备实际通信验收。

检查了仓库中同版本 ring 的 `include/ring-core/check.h`，其明确提供 `RING_CORE_NOSTDLIBINC`（在没有 `assert.h` 时使用受控的 `__builtin_trap` 调试检查）。因此 AArch64 cross-C 代码改用正式裸机宏，而不通过手写空头文件或跳过密码学验证来求得构建通过。此前 `-DNDEBUG` 不能解决无头文件问题的失败记录仍保留。

实测第二次目标编译通过了裸机 C 头文件阶段，但触发了 `ring` 的 `_AARCH64_HAS_NEON` 静态断言。检查原生 `user/prototype-cluster/.cargo/config.toml` 与 `tools/build.sh` 后，确认**原设计的 EL0 TLS 服务使用 `aarch64-unknown-none`（含必要 FP/SIMD），只有 EL1 内核使用 `aarch64-unknown-none-softfloat`**。下一次 CI 因此按原有 EL0 TLS 目标/编译标志验证，而非给内核软浮点 ABI 擅自加 NEON。此时目标编译仍不得声称 QEMU PASS。

### G2 固定 CPU1 / 双 AI 建议前置架构

六专项后续接线必须复用 V0.19 固定角色：CPU1 是唯一 AI 控制核（CPU0 仅为确定性 EL1 机制 broker），两个逻辑隔离的建议邮箱无执行权、不参与资源栅栏的签发。业务内核/IRQ/TLB/DMA/文件事务安全拒绝不能由运营或安全 AI 消除。模型建议不触发 CoreSet 伸缩/跨核接管。双 EL0 推理进程实际隔离、并行调度以及 AArch64 QEMU 证明仍缺失，G2/G3/G4 状态不因契约测试通过而升级。

### G2 SEC-N 活动连接/来源额度加固（固定控制核之后）

- `cyxia-kernel-core::security::network::RateLimiter` 按受保护网络端点来源记录活动会话占用；以前泛化的 `close_active()` 改成 `close_active_from(ip)`，拒绝错误来源、重复关闭，防止攻击连接错误归还另一来源的活动 credit。
- 即便 16 个活动额度已满，已结束或拒绝的握手仍精确释放其对应待认证 credit，不得因返回 Capacity 将 4 个 pending credit 永久占住。真实未授予会话必须由原生 TLS 适配器关闭。
- 32 个来源槽的空闲驱逐新增 `active == 0` 条件；只靠令牌回满/静默不能驱逐仍有活动连接的来源，避免下次重入偷偷重置 burst。
- 新增满额、跨来源关闭/重复关闭、活跃来源驱逐共 3 个单元负向测试，以及源代码回归检查。这里的来源身份必须来自受保护的 TCP endpoint，而非模型或应用字节；当前仍是主机机制级，原生 TCP 端点接线和 QEMU 网络洪泛故障验收尚未完成。

### SEC-N G2 协议层：真实 TLS 会话代际与连接额度联动（本次）

- 新增 `crates/net-transport/src/admission.rs`：32 个来源、4 个待认证、16 个活动连接的固定容量无堆 admission ledger。每次握手获取不对外解码的 `PendingTicket{slot,generation}`，过期/重复回执不能回收另一握手；限流参数和来源 IPv4 仅允许由可信原生 TCP 适配器提供。
- 真实 Rustls `Session` 使用当前 EL0 服务生命周期内单调的会话序列，`local_echo_proof()` 只有在双向钉扎 TLS 已完成且实际协商 ALPN 为 `cyxia-echo/1` 时产生。`Admission::authenticate` 持有该 *精确会话* 的证明，防止同 IP 或同一认证公钥的不同连接替用旧 active ticket、同一会话占用两个活动槽。
- `Admission::reply(active, &session, output)` **只消费 session.plaintext()**（Rustls 真实解密数据），不接受任意声称已解密的字节缓存；解析仍限 16 字节 header / 4096 字节正文 / 只读 opcode，返回值仅为有界回复数据，不是文件、内存、设备、计划发布权。
- 断链/服务重启调用 `begin_drain` 或 `begin_restart` 时保留原 token 和 credit。只有可信本机适配器在**实际** TCP/TLS 输出、VirtIO 描述符、DMA pin 与完成对账后才能调用 `finish_drain`。该函数本身不是硬件证明，测试用例模拟这一外部前提；重启不会自动清空信用账本或重置源限流。
- 新增票据代际、pending/来源容量、服务重启与 TLS 真握手后 Echo、来源重放及 17 号活动连接拒绝的主机负向测试。**仍缺实际 AArch64 EL0 单机网络服务使用此 ledger 的构造/消亡适配，以及 SEC-N07 密钥/遥测实测与 SEC-N08 QEMU 网络丢包/断链故障注入。** G2/G3/G4 原生证据不升级。

生产级接线门槛：`security::network::RateLimiter` 是此前独立的主机契约模型，`net-transport::admission::Admission` 是本轮与真实 TLS Session 绑定的建议迁移实现。**不可在同一条生产连接上同时使用两套额度计账**；必须在原生网络服务迁移时指定唯一权威账本、对齐旧连接代际，并以真实 TX/DMA 完成证据管理 `finish_drain`。在完成该单点接线前，不得声称 SEC-N G2 原生完成。

### G2 五项受保护机制额外负向约束（本轮）

- SEC-P：在 AArch64 四核 V0.19 原生业务核入口，CPU0（EL1 机制 broker）和 CPU1（唯一 AI 控制核）即使被损坏的业务核掩码错误标成健康，仍不可承接普通业务任务。其他平台适配需冻结对应专用核角色映射。
- SEC-F：系统对象访问不能仅凭一般文件上含有 `SYSTEM_STORE` 位。必须同时匹配可信系统对象注册表提供的 inode 身份和代际；**不推断 DEC-01 尚未冻结的固定保留 inode 编码**。
- SEC-M：没有有效 owner 的用户帧不能靠伪造共享授权映射进入 EL0，即使其 zeroed/W^X 标志形式上满足条件。
- SEC-D：描述符链总占用对每一在途、已发布及 UNKNOWN 租约累计，不能只看请求槽位数；未经完成证据的 UNKNOWN 仍占有真实描述符信用，预算求和使用 checked arithmetic。
- SEC-S：固定控制发布者必须同时通过受保护角色身份、**CPU1**、精确 `0b0010` 控制掩码及现有控制执行权限检查；旧泛化迁移测试管理器只保留历史回归行为。
- SEC-N：来源记录经合法静默驱逐也要推进全局可信单调时钟，不能在服务时间回退后凭重建来源记录获得新的 burst。

这些是六专项契约与既有原生入口的局部加固，**不改 syscall ABI/文件格式/模型动作位**，不证明未接线的实际 DMA、TLB、系统卷、启动/宕机故障流程。G2/G3/G4 仍须原生硬件/模拟器证据。

### 固定 CPU1 的旧 SEC-P/SEC-D 模型假设清理

- 将未接原生驱动的 `SEC-P::VerifiedSpawn` 主机账本测试迁到 CPU2 业务核，并明确拒绝 CPU0/CPU1，即使损坏的业务掩码或健康掩码宣称其可用；J01 的 DRAIN/任务退出模型同步使用 CPU2。
- `SEC-D::validate_irq_route` 明确拒绝将普通 VirtIO SPI 路由至固定控制 CPU1，即使错误的 `healthy_business` 位图包含 CPU1；CPU0 作为 EL1 机制 broker 的设备中断属于独立的受保护设备所有者，不由这个普通业务路由门签发。
- 执行边界仍是原生受保护 CPU owner/设备路由适配；这些 host check 不替代 QEMU GIC/IRQ 实际交错验收。

### SEC-N 新增：TLS 回声实际发送与排空门（本轮）

- 在 `crates/net-transport/src/admission.rs` 将 `dispatch_echo` 绑定已授权的活动票据与实际 Rustls Session。仅从该 Session 的已认证明文解析只读 Echo，回复写入**同一个 TLS 会话**的加密发送队列；写入前的拒绝/背压不吞掉原明文。
- 新增一位有界 `tls_egress_pending` 账本。一次回复成功被 TLS 接纳后，直到 `confirm_tls_output_drained` 验证该会话没有待编码明文或尚未交出的 TLS 密文，才允许清除此债务。重新发送期间拒绝第二次调度或重复退账；`finish_drain` 不得绕开这项 TLS 排空债务。
- 此处只判定 **TLS 内部输出缓冲已排空**，并不证明 TCP 对端 ACK、VirtIO TX 使用环、DMA pin 或 NIC 完成。这些仍必须由受保护原生网络/设备适配器对账；当前尚未完成实际原生服务接线，不能将 G2/G3/G4 记为通过。
- 新增实际双向 TLS 会话的回声收发、非法写操作码、回复待发送与延迟排空测试；同时运行主机/源代码回归与 AArch64 EL0 TLS 交叉编译。

### SEC-N 字节流边界与原生 smoltcp 适配（本轮）

- `crates/net-transport/src/echo.rs::next_frame_len` 从 TLS 字节流只提取第一条完整只读 Echo，未完成报待更多数据，非法版本/opcode/超过 4096 字节长度立即拒绝；`parse_request` 仍严格拒绝尾字节，不扩大对外协议。
- `tls::Session::pump` 在既有 16 KiB 受保护明文缓冲区中追加后续已认证记录，不覆盖此前未处理的明文。一个 TCP/TLS 记录含多条 Echo 时先处理首条，消费准确长度后保留剩余；分片不能死锁、尾字节不误吞。
- 新增 `net-transport::native_tcp::turn`：每调用至多 1 次本机 TCP/VirtIO service、1 次 TLS 接收、1 次只读 Echo 分发和 2 次密文队列写入；所有写入按实际接收长度消费，不等待模型，不引入队列或额外堆缓冲。TCP 已入队不构成远端 ACK 或 DMA 完成证明。
- `cluster-transport::local_echo_tcp` 仅重用当前原生 `smoltcp::Tcp` 驱动为 `NativeSocket`；不调用成员发现、集群 wire、远程任务或联合调度。这是可复用的 transport 代码接线，**原生单机 EL0 Echo 服务尚未部署到启动配置**。
- 新增真实 TLS 片段、两帧合并以及模拟部分本机 TCP 收发的端到端测试；同一旧集群 transport 依赖保留兼容测试，未来须将 TCP 机制单独迁出集群包。

### SEC-D 真实 VirtIO Net TX 代际回执（本轮）

- 在 `driver-virtio::net::BatchedNet` 新增可选的 `poll_tx_receipt` / `acknowledge_tx`；收到经过驱动解析校验的 used-ring 完成后，原 token+generation+策略版本保持占用，必须匹配完整回执才能释放真实描述符；重复/伪造代际或在持回执期间重 poll 都拒绝。
- 原 `poll_tx` 保持同一可信驱动调用回合内立即确认的兼容实现，避免破坏现有 smoltcp 进度，新的安全适配器可按真实 TX 回执延迟 ACK。新增主机模拟 used-ring 单测，明确区分 **设备链已完成、TCP 已入队、TLS 输出排空、远端 ACK** 四层，不推断彼此。
- 本轮验证仍是主机测试和 AArch64 TLS 库编译，未执行 EL0 单机 Echo 部署、QEMU NIC/DMA 断电/断线注入、SEC-N08/SEC-D05 的原生设备验收，G2/G3/G4 状态不升级。

### SEC-N ↔ SEC-D 单机网络退出安全栅栏（本轮）

- `driver-virtio::net::Net` 与 `BatchedNet` 提供**只读** `tx_quiescent`：单链路仅当真实 used-ring 完成清除其唯一 TX pending，批量队列仅当所有 TX descriptor 完成并由原始 token+generation ACK 释放且无保留回执才返回真；设备 poison/fault/UNKNOWN 返回假。
- `cluster-transport::device::VirtioPort` 将这份受保护设备状态传到现有 `smoltcp::Tcp`，而 `Tcp::terminal_tx_quiescent` 还要求 TCP 状态为 CLOSED、内核 TCP 发送队列为 0；未知端口默认假，拒绝靠普通 socket reset 模拟可靠设备完成。
- `net-transport::native_tcp::finish_session` 是对外正常退役入口，同时检查本机 TCP 与 VirtIO TX 静默、实际相同 TLS 会话代际、待编码明文及 TLS 密文排空，再调用受限内部 `Admission::finish_drain` 归还活动连接额度。不接受模型建议、仅超时、端口宣称 Closed 或无关 TLS 会话作为资源结束证明。
- 新增主机负向测试：TCP 未终止、TCP 已终止但 NIC 仍在途、不同 TLS 会话、重复信用释放，以及已有 TLS 回复尚未加密/发送时拒绝正常关闭；VirtIO 实测 used-ring + 匹配 ACK 前后 `tx_quiescent` 值不同。
- **限制**：这是只有可信本机驱动执行后的正常退役门，仍未能证明 TCP 对端收到了消息；若 TLS 已 abort 且设备卡死，信用应保持隔离，必须由平台可靠设备复位/完成对账另行提供释放证明。单机 EL0 Echo 服务部署与原生 QEMU NIC/DMA 故障矩阵仍属 NOT_RUN。

### G2 原生单机 EL0 Echo 可执行程序候选（本轮）

- 新增 `user/local-echo` 独立的 Rust `#![no_std]` AArch64 EL0 服务项目。它依赖 `cyxia-net-transport` TLS/Echo 和受保护的本机 Cyxia SVC 共享页，但**不依赖** `cyxia-cluster-transport`、集群任务引擎或成员发现服务。自身只读 broker allowlist 限定为随机数、时钟、状态轮询、TCP 密文读写、关闭与 yield；WRITE 固定采用受限的原生 TLS 密文通路，不允许文件写、远程任务、存储或策略修改操作。
- 服务入口从外部 provisioned 本机证书、私钥和对端公钥 pin 构造原生 Rustls TLS 1.3；当前只作为被动 Echo 服务端。证书身份需匹配受保护内核共享页，`Admission` 的 32/4/16 信用、握手票据/实际 TLS 会话代际及 `native_tcp::turn` 均在客体中实际运行。本地 TLS 会话异常后进入 fail-closed，**不**以连接断开冒充 DMA 已停止。
- 为不扩大应用权限，guest 使用独立的 `user/local-echo/src/abi.rs` **只读共享页字段视图**与旧内核 `SVC #0x43` 二进制布局兼容；其保留填充不导出旧集群任务或存储类型。新增 `tests/native_shared_layout.rs` 以**仅限测试**的 `cyxia-prototype` 依赖将所有实际访问字段偏移与原受保护 ABI 对账，运行时 guest 不引入集群引擎。真正的最小权限仍需内核执行上下文按凭据/能力实施操作白名单，不能只依靠用户态检查。
- 构建新增 `cyxia-local-echo` 工作区成员、独立 linker 和外部凭据提供门。CI 运行无客户身份的 broker allowlist 单元测试，并用临时测试证书仅作 `aarch64-unknown-none` 交叉类型检查，不生成部署镜像，也绝不发布测试私钥作为生产证书。
- **尚未完成**：从旧 `unified-runtime` 内核启动链独立部署新 Echo guest，按本机网络配置关闭集群发现/远程任务分发；为此 guest 提供来自 EL1 的真实端口来源、TCP/VirtIO TX 静默证明及服务重启信用留存。guest 在缺少这些证明时保守停止，不默许重连，因此 G2/G3/G4 原生验收仍是 NOT_RUN。

- 新增 CI-only `cargo build --release` 的 AArch64 ELF 实际链接/LOAD 段检查。使用 runner 临时测试证书及无效 peer pin，只用于揭示 freestanding 目标与 guest linker/BSS 越界错误。**这个测试 ELF 绝不上传、部署或当成可信发行产物**；源码打包仍通过 `git archive` 不包含 `target/`。
