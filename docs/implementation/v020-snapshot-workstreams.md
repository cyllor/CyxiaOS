# V0.20 不可变快照并行开发台账（候选，未冻结）
基线：CyxiaOS-V0.20@cb779dfbf206da013fcde406a4090a67b53ba18c。依据 docs/design/v0.19.10-immutable-snapshots.md。G1 NOT_READY；新版原生端到端 NOT_RUN。以下分支是独立开发增量，不是已合入主线或通过验收的证据。

| 工作流 | 分支 | 本批边界 |
|---|---|---|
| S1 保留与 GC | work/v020-snapshot-retention-floor | 所有删除入口共享周期层保护下限，保留期、引用、GC 原门保持；回归覆盖手动/自动删除与重挂载。 |
| S2 介质预检 | work/v020-snapshot-media-preflight | 严格只读识别 v1/v2 双超级块；拒绝混合格式/身份/不连续；不是迁移器、挂载器。 |
| S3 恢复保护 | work/v020-snapshot-restore-guard | 恢复业务根时不得导入旧 FileStreamIndex v4 / SecurityState v2；仅检查两类系统对象投影；未接真实事务。 |
| S4 验证 | work/v020-snapshot-native-test-plan | 独立宿主测试工作流，日志绑定提交；不得宣称原生。 |
| S5 统一介质/ABI | 后续阻断任务 | 确认新卷版本、固定对象位置、快照目录/槽、ACL/收据、位图事务闭包；旧卷只读导出与历史保护完整迁移；不能静默格式化。 |
| S6 原生文件服务 | 依赖 S5 | 独立 0x50 端点、真实 EL1 copyin、主体/能力/代际、唯一文件所有者、原生 redo/FLUSH、实际调度与 IRQ。解除 unified-runtime 依赖，不启用旧 CPU1 控制或集群路径。 |
| S7 安全大脑 | 依赖 S5/S6 | role7 SecurityFinding v2 仅触发独立规则复核；冻结/保护点创建来自受保护执行链，AI_DISABLED 继续周期保护，SHADOW 无副作用。 |
| S8 原生验收 | 依赖 S5–S7 | 固定四核 CPU0/CPU1–3 的真实单机 ARM QEMU，x86 适用验证；原生创建、覆盖/删除、历史读取、恢复、独立开门、断电、配额、GC。 |

## 原生验收必须保存的证据
- exact source tree、编译器/QEMU/模型/Schema hash、单机镜像、EL0 程序身份、启动与调度记录。
- 真实文件服务提交序号、捕获边界、历史根摘要、恢复新 epoch、旧句柄拒绝、控制/保护代际及独立开门证明。
- 每个写/FLUSH 故障边界，未知请求状态，全部活动/历史根可达性与块所有权；关闭后用独立只读检查器核对磁盘。
- 不以宿主 BlockDevice 模拟断电冒充 QEMU 掉电，不放宽 CPU 预算或隔离条件；历史 V0.18 原生 FAIL 保留。
- 既有 127 稳定 ID 不改；新增断言在 G1 冻结后映射，不私自宣布通过。
