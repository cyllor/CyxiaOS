# 完整原型：多 Agent 并行执行清单

> **For agentic workers:** Use superpowers:executing-plans for the existing acceptance plan and superpowers:dispatching-parallel-agents for the independent workstreams below. Checkboxes record verified outcomes.

**Goal:** 完成当前 Active CpuWeight 发布的有界重试接线，并继续关闭完整原型验收缺口。

**Architecture:** 沿用已审查的显式累计 publication debit、单次 Task 只读借用和普通 selection/ADMISSION。按文件分配写入所有权，主 Agent 统一集成、提交和验证。开发与主机测试并行；原生计时运行单独执行。

**Tech Stack:** Rust no_std / AArch64、Python 回归、固定 QEMU 10.2.2。

**Spec:** `2026-10-25-prototype-v13-acceptance.md`；配置 1.3 DOCX SHA-256 `01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0`。当前实现设计与证据见 `.superpowers/sdd/2026-10-25-prototype-v13-acceptance/active-task-publication-brief.md`。

## 共同约束

- 原 deadline 50 ms、publication CPU 500 µs、work CPU 2 ms；保留角色、模型、代际、依赖和普通 selection 校验。
- 仅获取借用时的 Busy 可保留尚未提交的原 Job；Registry 已完成结果保持原回执语义。
- Guard 在同步提交路径内持有，在结果交付前释放；累计成本覆盖重试、最终完成和 abort。
- Agent 不提交、不推送、不修改分配范围外的文件。主 Agent 按明确路径统一提交。
- 编译源在构建与原生运行期间冻结。QEMU 运行期间所有 Agent 停止构建、测试和重型解析。
- 原生与主机结果分别记录；全部 69 项 catalogue、文件系统矩阵和有效配对标签齐备后才完成目标。

## 并行任务与文件所有权

| 线路 | 所有者 | 文件 / 产出 | 完成条件 |
| --- | --- | --- | --- |
| A：提交重试与预算接线（关键路径） | `active_accept_retry` | `kernel/src/domain_control.rs`、`domain_control/replay.rs`、`domain_control/governance.rs`；可新增 acceptance helper 与专用测试 | 实际 accept/root_return 的 RED→GREEN；同 Job/输出/序号/快照重试、预算累计、abort/交付、Guard 释放、发布后超限回执均验证 |
| B：原生注册契约识别 | `native_scheduler_contract` | `kernel/src/domain_tasks.rs`、`domain_tasks/publication.rs`、独立契约测试 | 仅原生 D1/D13 回调、resolver 且无 custom binder 才选用借用；其他配置在获取 Guard 前回退 |
| C：后续验收缺口审计 | `review_v012_checkpoint` | 只读源码、69 项 catalogue 与文件系统矩阵；输出可独立实施的下一批任务 | 列出已有 runner/验证器、真实未闭环项、精确文件归属及优先顺序；集成后切换为独立审查 |
| D：回归适配与统一集成 | 主 Agent | 既有 Native/clock/progress/rejection 测试适配、文档、检查和构建 | 合并接口、负向变异、全套 9 项检查、双镜像、源码一致性和独立审查通过 |

## A / B 接口

- `Job.publication_debit: policy::CpuTime`：同 CPU 的先前预提交实际 CPU，初始为零。
- `Executor.publication_debit: policy::CpuTime`：与 Registry `PublicationBudget` 一致；现有三个非普通构造点显式零 debit。
- `domain_tasks::scheduler_publication_matches(consumer: &domain_control::Family, prerequisite: Option<&domain_control::Family>, resolver: Option<fn(ObjectKey) -> Result<[Option<domain_control::Prerequisite>; 2], Error>>, has_custom_binder: bool) -> bool`。
- B 采用项目已有的 `fn_addr_eq` 注册身份比较惯例，检查被替换的原生 callback/resolver，D13 缺失或不匹配时返回 false；A 在获取 TaskGuard 前调用。
- `reserve_scheduler_publication(action)` / `SchedulerPublication`、`ActivePublication`、`PublicationBudget` / `submit_job_debited` 已存在，继续复用。

## 执行关卡

- [x] A、B 各自完成真实失败回归、最小实现、定向检查和负向变异。
- [ ] D 完成既有回归适配，C 独立审查集成差异；修复实质问题。
- [ ] 全套检查、双镜像和源码映射通过；所有写入 Agent 与重型进程停止。
- [ ] 单独运行新的 600 秒原生配置，读取已产出的小型证据。
- [ ] 停机后验证 CRC/原始记录/累计成本/候选连续性，更新验收状态。
- [ ] 根据 C 的缺口审计开启下一批互不重叠任务，继续原总目标。

加速来自并行开发、独立审计和一次性集成；原生计时验证仍保持独占。
