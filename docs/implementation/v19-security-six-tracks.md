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
