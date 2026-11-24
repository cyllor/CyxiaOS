# V0.20 → V0.19.9 源码缺口修复台账（进行中）
 
基线：`CyxiaOS-V0.20` @ `02a5fc2be7c3ea40ce446d921f81ffab5507cd1a`（PR #19 后）。依据用户提供的 173 页《CyxiaOS V0.19.9 现行实现规范与分级验收》。本次修复分支：`fix/v020-v0199-contract-gaps`；**不是发布分支或完整验收结果**。
 
## 已落地的源代码改动（需要持续验收）
 
| 编号 | 工作项 | 实现变更 | 证据类型 |
|---|---|---|---|
| F01 | 安全大脑决策越权 | `control_plane/fixed.rs`：废止 Safety+Action 建议通道、单独存放 Finding、不可参与运营参数选择；仅风险建议申请重新确定性复核 | 单元测试+主机契约 |
| F02 | SecurityFinding v2 192B | `control_plane/security_finding.rs`：严格 LE 编解码输入格式、单独的可信快照域/模型/代际关联、期限≤100ms、风险等级与 hint 校验，拒绝非法保留位与旧版本 | 组件级；原生 role7 IPC 尚未接线 |
| F03 | 控制预算拆分 | `learning/governance.rs` 及 ARM `prototype_runtime/learning.rs`：61.5ms 必需 + 8.5ms 可选、总70ms/100ms；增加异常计费/临界预算测试 | 组件/构建；全负载 ARM QEMU 整窗未验收 |
| F04 | 旧跨节点/动态核心原生拒绝 | `domains/types.rs` 添加本地动作准入门；ARM `domain_control.rs` 在 CHECK 及 PUBLISH 两次拒绝 `ControlSet`/`OfferCpu`/`Placement` | 本地动作门单元测试；旧历史解码保留供迁移/审计 |
| F05 | RuleProfile v2 基础契约 | `control_plane/rule_profile_v2.rs`：≤64KiB、LE、递增 rule_id、1–15 域、敏感域拒 choice_policy1、谓词/静态档序/回退秩严格校验及只读候选求交 | 仅无分配组件；独立控制器/决策登记尚未接线 |
| F06 | 敏感域 AI 采纳与建议时效 | `control_plane/advisory.rs`：D06/D11/D12/D14 在普通路径只选确定性基线；建议期限不得超过快照+100ms | 主机逻辑测试；原生 PUBLISH 侧仍待联调 |
| F07 | 运营 AdviceEnvelope v1 | `control_plane/advice_envelope_v1.rs`：152B LE 封包、当前快照/模型/候选 hash、建议索引与实际候选值绑定；`fixed.rs` 接入独立运营 mailbox | 组件测试；受保护 EL0/EL1 真实 IPC 未接线 |
| F08 | RuleProfile v2 普通裁决入口 | `fixed.rs::review_with_rule_profile` 只在受信模式与同代规则下采纳允许集合内运营建议；无合法候选 fail-closed；`RuleProfile` 的 trial 规则无真实许可不进入普通审查 | 规则/模式单元测试；不是独立决定登记或执行 |
| F09 | DecisionRecord v3 | `control_plane/decision_record_v3.rs`：256B LE 解析、模式/来源/处置/理由/允许位图/候选索引约束、敏感域 AI_DENY | G1 只读规范组件；缺 role2 冻结登记与真实 AdviceDisposition |
| F10 | Plan/Policy v2 | `control_plane/plan_wire_v2.rs`：64B+144B v2 小端、长短/域/目标/代际/模式/重复检查，交叉匹配 DecisionRecord v3 | 不产生发布授权；没有实际 SHA-256、受保护 sidecar 登记、发布者身份、原生 PREPARE/PUBLISH/执行回执 |

 
## 完成定义与保留阻断
 
**P0：固定 CPU 编号冲突。** V0.19.9 唯一控制 C=CPU0、业务 B=CPU1–3；V0.20 仍是 C=CPU1、CPU0 EL1 broker、业务 CPU2–3。不得简单替换常量，必须重接异常/定时器、CPU0 EL0 控制调度、业务核亲和、IRQ/DMA 等并通过真正原生启动与 A01–A04、A15/E14。当前原生布局不符合规范，G0 **BLOCKED**。
 
**P0：核心版本化封包。** 旧原生 `policy_wire.rs` 仍在处理 PlanHeader/PolicyEnvelope v1；本工作分支新增 V0.19.9 v2/v3 只读解析/绑定组件，但**尚未将原生发布执行切换到 v2、也没有 EL1 DecisionRecord v3 冻结登记/唯一代理 PUBLISH/RuleProfile v2 最终硬门核验**。旧 v1 不得被称为 v2。G1 **NOT_READY**。
 
**P0：任务与存储 ABI。** Syscall x8/x0–x5 ABI v3、ET_DYN/PIE 安全装载、FileService v4/Reply v3、磁盘超级块 v1(80B)/data_start=4118、Receipt/Index v4 与安全状态持久对象尚未一致迁移。禁止尝试用旧格式数据直接改变版本号。当前数据磁盘不可视为符合规范。
 
**P1：同等十五域和学习。** 旧 `FAMILIES=18`、FeatureSchema/ActionSchema/RewardSchema/LearningConfig 旧代际、15 领域原生动作/反馈链仍未移除 D16 并整体完成；主机旧兼容测试不能代替新的 A05/A08/127 项验收。
 
**P1：旧分布式依赖。** `Cargo.toml` members、`kernel` unified-runtime 的 cluster-transport/peer-billing 及历史 cluster 协议仍在；仅禁止新增相关原生策略行动，不是全面去分布式。必须保留本机网络/TLS。
 
**P1：原生全系统验证。** 已知 x86 SMP 机制夹具曾失败；ARM 机制夹具通过不代表运行整个 CACP、六大安全硬件路径或 G4。G2/G3/G4-QEMU 及 G5-ARCH 均缺符合 V0.19.9 的完整证据。
 
## 必须在原生验收前完成的检查
 
针对每个提交记录精确 source commit/tree、Rust/LLVM/QEMU hashes、全部活动 Schema 的单独规范字节 hash，逐项导出安全/发布/执行/崩溃结果（PASS/FAIL/NOT_RUN）、AI_DISABLED/SHADOW/ASSISTED 模式、100ms 时间窗实际单核 CPU 区间与独立设备/磁盘事实。完整门槛是 **84 SEC 单域 + 13 J + 30 A/E/H = 127 稳定 ID**，不能由旧 48+12 单元测试相加冒称原生通过。实体 A53 (G5-ARCH) 必须在 G4-QEMU 之后另行验收。
 
此台账为代码修复进度/风险说明，不构成生产发布声明；不应把 Draft PR 合入为“设计符合性已完成”。
