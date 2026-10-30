# Active CpuWeight 发布重试与累计计费

基线：`5ab75ab`。本文把当前已入库实现的必要约束保存在跟踪文件中，替代旧计划对 checkout 外 brief 的依赖；它不是新的原生验收声明。

## 原 Job 的生命周期

`domain_control::accept` 在读出原 Job 后，使用本次实际 CPU 起点和该 Job 的 `publication_debit` 创建 `PublicationBudget`。只有精确匹配原生 D1/D13 注册契约的 CpuWeight 候选集合，才在 Registry 提交前尝试取得 Task owner 借用。

仅借用获取返回 Busy 时允许保留尚未提交的原 Job。保留 CPU、sequence、controller、snapshot、输出、原始开始时刻和 deadline；将此次实际 publication CPU 加入原 debit，下一次使用同一累计预算。其他合法性、依赖、selection、模型或 Registry 结果不转化为这种重试。

真实原生注册匹配检查 callback/resolver 函数身份，并拒绝 custom dependency binder；不匹配时使用原普通执行路径。借用不授予模型、baseline、恢复或资源权限，原合法性、普通 selection、ADMISSION 和 commit 检查继续执行。

## 计费与结果交付

- 模型工作上限 2 ms、累计 publication 上限 500 µs、原始 wall deadline 50 ms。重试、最终完成和 abort 保留已花费 CPU，不能通过换起点或刷新 deadline 获取新额度。
- 借用仅在本次同步提交路径内存活；Executor 和未移入 Executor 的借用均在 Root/work 结果交付前释放。最终 cap 采样包含实际 release 成本。
- Registry 已完成结果保持原回执语义，即使最终 release 使累计计费超限也不伪造一个不同的 Registry 结果；优化停止状态与实际超限诊断另行保留。
- 交付 Busy 只重试交付，不重新提交策略。Pending/UNKNOWN 仍保留原执行义务。

## 验证入口与限制

主机回归包括 `test_active_accept_retry.py`、`test_scheduler_publication_contract.py`、`test_active_scheduler_publication.py`、`test_carried_publication_budget.py`、`test_native_publication_clock.py`、`test_native_submission_provenance.py`。夹具执行真实生产函数并替代明确的硬件/owner 边界，负向变异必须因预期行为断言失败，不能以编译错误替代。

主机通过之后仍须在冻结源码、新构建镜像及已核验补丁 QEMU 上验证原生 CPU、续期连续覆盖、原始记录、累计成本与有效配对。当前 catalogue 的未完成状态不因本文或主机结果改变。
