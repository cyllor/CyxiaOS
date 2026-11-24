# V0.20 八个正式控制角色运行专项审核（开发证据）
基线：`418ab0b84a12b0d0aa9eb48516cccd84a0eaf9f1`；正式依据：`docs/design/baselines/v0.19.9-implementation-spec.txt` §2.0、2.1、2.1.1、2.2.2、2.3、4.1、5.3、10、13.7、安§0.7。**G0 BLOCKED；G1 NOT_READY；不得标记正式八服务运行 PASS。**

## 真实镜像与运行路径盘点
| 角色 | 已有相关实现（不是生产启动证据） | 尚缺正式运行条件 |
|---|---|---|
| role6 运营 AI | user/prototype-control/main.rs（synthetic fixture）、user/prototype-runtime/main.rs（旧固定地址/历史调用）及 Advice v1 ledger | 静态 PIE ABI3 运营包、15 域授权视图、真实建议 IPC、CPU0 2ms/域实测 |
| role7 安全大脑 | security_finding.rs 有界受保护账本、FindingDisposition v2 | 独立安全模型 ELF/配置/输入编码，脱敏 0x40、Finding IPC、role11 独立复核 |
| role2 确定性控制器 | registered_gate_v3.rs、rule_profile_v2.rs、svc_bridge_v3.rs；旧 prototype-runtime 不是新正式控制器 | 独立原始证据、ABI3 登记、恢复后规则模式、实际决策预算 |
| role8 唯一发布代理 | 已登记计划的 exact-byte gate 和 ApplyReport 组件 | 独立 native publisher ELF、实际 0x41/cap、原子发布/真实回执 |
| role9 独立验证者 | user/prototype-learning/main.rs 同一旧学习/验证算术程序 | 单独地址空间/候选输入、验证资格和有界验证回执 |
| role3 模型管理者 | user/prototype-governance/main.rs 旧治理命令生产者 | 正式模型晋升/回退/D15 许可独立包、当前离线许可及真实版本账 |
| role10 受限学习器 | user/prototype-learning/main.rs、kernel/src/runtime/control/prototype_runtime/learning.rs（C1-only 历史路径） | CPU0 独立 ABI3 包、脱敏反馈、独立候选区、共享可选预算 |
| role11 监督与审计恢复者 | service_restart.rs、advice/finding ledger、旧治理路径 | 独立监督包、真实审计读/ACK、停止证明与持久 epoch、EL1 接管 |

历史 governance.rs 明确曾在 CPU1 C owner 执行；当前 `kernel/src/main.rs` 禁止默认 v0199-local-native 激活旧 unified/prototype runtime。因此不能将旧治理/学习镜像或相同 smp_user.S 程序重新命名为正式八服务。当前角色夹具实际建立 8 个 TTBR0 与数据/栈页，仍执行相同测试代码，生产 ABI3 程序包启动闭包尚未实现。

## 本轮独立审核工作流
- role-launch-package：可信角色镜像、ABI3、32KiB 栈、镜像及 RELATIVE sidecar 摘要；精确 PT_PHDR 文件映射。真实只读启动包和独占 staged launch 仍需连接。
- role-authorization：实际 holder/endpoint/CPU0 及 CONTROL_AUX role/op 资格；运营、安全、控制器视图分离。实际 cap type/label、视图字段和 ControlRPC 事务仍须查权威表。
- role-budget：固定 CPU0 六类预算 30/8/7.5/8/8/8.5ms 合计70ms；独立恢复、每角色上限、D01–D15 运营槽/裁决共享额度、每窗最多4个安全槽。生产计时器/调度器和全部角色 CPU 消耗尚需实际接线。
- role-fault-runtime：扩展 native fixture，以每角色真实 ESR/FAR 40 个故障用例、独占静态两页清零与同根重新进入 8 次，以及其他角色/业务核继续运行作为机制证据。禁止当作真实重建 TTBR、完整 32KiB 栈、真实 cap/TLB/DMA/持久代际、正式服务重启或功耗证据。

## 验收停止线
已有 #62 的原生 SVC/copy 夹具 run 45391808897 PASS（在其精确提交上），不等于 19 个正式系统调用调度。每个新角色必须独立提供真实包 SHA、可信启动清单、页表/栈/物理账本、当前角色和实际 cap、有效期、执行区间及真实重启回执；AI 未就绪不阻塞 SAFE_EXEC 和业务。G0 生产八服务、G1 完整 ABI/介质、G4 127 项、G5 实体硬件仍未通过。所有预算/计时只认实际独立观察，不以模型输出或测试标记代替。
