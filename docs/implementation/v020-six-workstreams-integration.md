# CyxiaOS V0.20 × V0.19.9 六工作流集成验收台账（WIP）

状态：**INTEGRATED INTO DRAFT PR #20 ONLY；G0 BLOCKED / G1 NOT_READY / G4-QEMU NOT_RUN / G5-ARCH NOT_RUN**。本文件记录实现证据与残余阻断，不是正式设计基线变更，不是正式 V0.20 发行物。

上游版本：`CyxiaOS-V0.20`，此版已新增 V0.19.9 正文与 V0.19.10 不可变快照候选设计（`docs/design/v0.19.10-immutable-snapshots.md`），后者尚未正式冻结。原始修复起点为 `02a5fc2be7c3ea40ce446d921f81ffab5507cd1a`。六项均在独立 `work/v020-gap-*` 分支以相同 PR #20 开发源为基线，通过对应**主机组件+两架构构建**后再合并到 `fix/v020-v0199-contract-gaps`。目标 `CyxiaOS-V0.20` **没有被本次集成合并修改**。

## 六项并行集成

| 工作流/PR | 已有可审计代码 | 精确分支 CI 证据 | 尚未完成的原生门 |
| --- | --- | --- | --- |
| [CPU0 #21](https://github.com/cyllor/CyxiaOS/pull/21) | `control_plane/cpu0_v0199.rs` 的 C=CPU0/B=CPU1-3 快照与单核计费；`cores::Ownership::new_v0199_cpu0`；`manager::new_v0199_cpu0`；`security::syscall::can_publish_cpu0_v0199` | [run 45347214723](https://github.com/cyllor/CyxiaOS/actions/runs/45347214723) 4/4 PASS，组件/编译 | **P0** 真正 AArch64 控制任务、EL0 时间片、IRQ/TLB/DMA 及内核原本 CPU1/CPU0 broker 路径仍须迁移、启动测量；目前旧 `prototype_runtime` 仍以 CPU1 控制运行 |
| [八 EL0 角色 #22](https://github.com/cyllor/CyxiaOS/pull/22) | `control_plane/role_manifest_v0199.rs` 为 6/7/2/8/9/3/10/11 角色核验、身份/代际、互不共享 TTBR 根/私有 RW 区、最小能力、统一 ≤70ms/100ms/8MiB 预算 | [run 45348231859](https://github.com/cyllor/CyxiaOS/actions/runs/45348231859) 4/4 PASS | **P0** 八个真实、独立可重启原生 EL0 地址空间、任务加载、可信端点/IPC、栈、预算与 fault/restart 测试尚未接线；`NativeRoleManifest` 是准入契约，不是运行实例 |
| [SVC #23](https://github.com/cyllor/CyxiaOS/pull/23) | `control_plane/svc_bridge_v3.rs` 的 ABI v3 `0x50` role2 决定登记和 `0x41` role8 唯一发布（仅 RULE_ONLY）；受保护身份、独立 endpoint cap、严格内核 copyin 及重放拒绝逻辑与主机测试 | [run 45348338721](https://github.com/cyllor/CyxiaOS/actions/runs/45348338721) 4/4 PASS | **P0** 真正 AArch64 EL0 SVC trap 与 `x8,x0..x5` ABI、cap table、EL1 可信 copyin/out、同序 v3 sidecar、原生执行器及 `ApplyReport` 还未切换，不能称为已运行 SVC |
| [AI 证据 #24](https://github.com/cyllor/CyxiaOS/pull/24) | `control_plane/advice_ledger_v0199.rs` 的 64×≤512B 有界建议槽、真实 SHA-256、AdviceKey 不回绕、role6→role2→role11 受保护提交/处置/消费、模型不可宣称 APPLIED | [run 45347477565](https://github.com/cyllor/CyxiaOS/actions/runs/45347477565) 4/4 PASS | **P0** 实际双脑 EL0 模型输入/产出、独立裁决 v3+AdviceDisposition 496B 登记、唯一发布及真实 APPLIED/反馈成本区间缺少完整 E2E |
| [文件与介质 #25](https://github.com/cyllor/CyxiaOS/pull/25) | `security/file_service_v4.rs` 的 FileServiceRequest v4/Reply v3 15 op 长度、版本、能力选择器和 UNKNOWN 拒绝；`security/file_media_v0199.rs` 严格超级块 v1 4096B + 收据 v4 192B CRC32C 只读校验 | [run 45348079942](https://github.com/cyllor/CyxiaOS/actions/runs/45348079942) 4/4 PASS | **P0** 当前持久盘是 v2/4240，规范 v1/4118 + v4 收据索引/ACL/BootEpoch/SecurityState；需要新镜像/离线迁移、真实 FILE_AUTH、redo/FLUSH、快照保留期及断电恢复证明 |
| [去分布式 #26](https://github.com/cyllor/CyxiaOS/pull/26) | 默认内核 `v0199-local-native`；`kernel/src/main.rs` 禁止默认构建旧 `unified-runtime`/远端 TCP/CPU1 原型控制；旧 peer/cluster crates 排出 workspace，锁文件准确重生成；保留本地原生 net/TLS | [run 45348177711](https://github.com/cyllor/CyxiaOS/actions/runs/45348177711) 4/4 PASS | **P1** 历史 `kernel/src/runtime/cluster`、`kernel-core/src/cluster`、`prototype/src/cluster`、可选 Cargo features 与 D16 历史兼容解码仍在；需确认所有目标可达性及新介质无旧集群对象后分批删除 |

## 不可颠倒的 G0 / G1 / G4 判定顺序

1. **G0** 先冻实际真实 CPU0 控制核、三 B 核与 8 个互不越权的 EL0 角色，在 4-vCPU AArch64 QEMU 内读回 TTBR/IRQ/定时器/CPU 亲和证据。CPU0 单核 70ms/100ms 是全部控制角色总额，不允许 CPU1 再运行第二个 C。
2. **G1** 再按 V0.19.9 的版本化机器 Schema 逐对象锁定：Feature v3、Action v2、Decision v3、RuleProfile v2、Advice/Disposition v1、Plan/Policy v2、SVC ABI v3、FileService v4/v3、Receipt+Index v4 和 SecurityState v2。每个冻结证据包含 CRC/hash、正负黄金向量、版本拒绝与所有跨层数据拷贝。
3. **G2/G3** 六方向 SEC-P/F/M/N/D/S 原生执行（84 个单域 ID）及 J01–J13 原生交错；与全部业务平权的 D01–D15 真实建议→决定→发布→APPLIED→反馈证据逐一匹配。
4. **G4-QEMU** ARM/x86 各自真实完整启动、长期压力、文件断电/复位、EL0 故障、未知设备完成与 127 项稳定 ID 适用判定；两个架构不能用交叉编译代替。
5. **G5-ARCH** 只有在真实锁定实体 A53 等平台测量/勘误复核后可标为 PASS；目前没有这类证明。

## 本次真实可声明与不可声明

- 可声明：六组源码分支分别经主机安全契约、AArch64 交叉构建、x86 构建、归档/散列 CI 验证并整合到仍为 Draft 的 PR #20；`RULE_ONLY` 的只读/有界控制链和历史代码隔离继续受保护。
- 不可声明：原生控制 CPU 已从 CPU1 实际切到 CPU0；8 个原生 EL0 进程已启动；0x50/0x41 真实 SVC trap 已替换；FileService v4 和 v1 卷已可写；分布式源码完全删除；127 ID 或 ARM/x86 真机通过。任何没有逐项证据的格子均为 **NOT_RUN/NOT_READY**。
- 对单机默认 profile 的遗留 `prototype-runtime`、`unified-runtime` 和 `tcp-v13-selftest` 施加编译硬拒绝；需要旧机制诊断必须明确 `--no-default-features`，其结果不授予 V0.19.9 合格认证。
