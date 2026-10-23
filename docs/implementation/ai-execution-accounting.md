# EL0 AI 执行反馈统计

本轮修正了“选择候选就记为已执行”的边界：进程和线程可能在下一次进入用户态之前被待处理信号终止，或触发测试时限。现在只有实际调用用户上下文入口的派发才增加执行计数；模型提案与取消另计。原 `posix status` 的 AI 派发字段沿用名称，语义收紧为真实执行。

`ai system` 输出 `AI_DOMAIN name=... key=value`。这些累计值来自 CPU0 前台实际入口，独立于可复用的进程槽；退出、重新启动和槽复用不清零。固定表为 11×160=1760 字节，编译期限制不超过一页，无运行时堆分配；计数饱和不回绕。读取发生在单核前台，不是 SMP 原子快照。

| 域 | 实际统计范围 | 模型 / 单位 |
|---|---|---|
| `cpu_process` | 已选进程提案及真实派发 | 12289 / 派发 |
| `cpu_thread` | 每进程线程候选提案及真实派发 | 12289 / 派发 |
| `cpu_quantum` | 1/4 ms 预算提案、实际进入与返回 | 12290 / 派发 |
| `process` | 原生启动所需的 8 页基础资源授予 | 8193 / 页 |
| `thread` | `clone` 增加的上下文；不重复计算进程首线程 | 8193 / 上下文信用 |
| `anonymous` | 匿名页分配入口 | 8194 / 页 |
| `elf` | 静态 ELF 及初始栈装载入口 | 8195 / 页 |
| `spawn_receipt` | 子进程退出回执准入与消费、孤儿回收 | 8193 / 回执信用 |
| `unix`、`pipe`、`pty` | 相应内核适配器的资源准入 | 8193 / 适配器定义的信用 |

未编入的域保留零值，零值不代表实现或通过验收。原生 `posix pair` 的 LocalIpc 是操作员测试机制，单独标注，不能用它充当普通 POSIX IPC 的 AI 决策证据。线程与回执信用模型复用保守容量准入，不等于按生产工作负载训练的专用策略。

`unix`、`pipe`、`pty` 当前接入准入提案和请求结果，没有接入资源 `granted/released` 计数；这些字段的零值不能用来证明无资源占用或已完成回收，端点生命周期仍需相应真实探针验证。

资源入口的 `requests` 只覆盖表列服务调用，不覆盖在更早的 syscall 参数解析层已拒绝的调用。一个请求恰好以 `committed`、`denied`、`capacity`、`invalid`、`failed` 之一结束：

- `proposals`：确实调用了模型入口；`approved`：模型明确允许。
- `denied`：模型明确否决。模型本身错误不会算作否决。
- `capacity`：模型调用前触发容量或硬限额；`invalid`：调用前的参数、权限或不支持的请求。
- `failed`：模型运行错误、模型允许后的执行失败或其他后端失败；`last_errno` 保留最近请求的实际结果，不修改 syscall 的 errno。
- `committed`：该服务调用整体成功。`granted` / `grant_units` 是机制实际保留的资源，`released` / `release_units` 是已完成撤销和回收的资源。装载失败可能产生一次授予与回收而没有成功请求，不能把授予当作装载成功。
- `ai` / `guard` 分别统计已执行的 AI 动作与公平保护派发，不将保护重复计入 AI。

CPU 统计的 `proposals` 是候选选择或时间片提案；未实际执行而被替代、终止的提案进入 `cancelled`。`cpu_thread` 的提案可比执行次数多，因为比较进程之前要先为每个进程选择可运行线程。`cpu_quantum.enters` / `returns` 统计每次真实上下文进入和返回，一次派发可有多次 syscall 返回。`elapsed_ms` 是派发的单调墙钟时间，包含同步 syscall 工作，不是精确 EL0 CPU 时间。

静止且没有活动进程时可检验：

- `cpu_process.committed == cpu_quantum.committed`。
- CPU 各域 `committed == ai + guard`，且所有提案均为已执行或已取消。
- `cpu_quantum.enters == returns >= committed`。
- 进程、额外线程、匿名页、ELF 页和 spawn 回执全部关闭后 `grant_units == release_units`。
- 重复运行同一程序复用槽后，累计计数仍单调增加。

主机测试入口是 `cargo test -p cyxia-ai-runtime accounting`；真实客体应结合 `thread-probe`、`spawn-probe`、匿名内存原生服务和 `ai system` 前后快照检查上述关系。编译检查需包含桌面 profile 与未启用 ported 的基础 profile。

客体验证入口：`python3 tools/verify_ai_accounting.py --elf <固定ELF> --output <报告目录>`。

2026-10-18 最终 r2 候选 `1a0f5534cdb50ab2e8e291ad0fd6890899f35e55ce536c6756ffc8c8e42aae81` 完成三组独立客体验收：

- `artifacts/ai-system-r2/accounting/summary.json`：真实 500 ms 超时产生 1 次取消而没有额外执行（进程/线程选择各 96 提案、95 执行）；两轮 pthread 共 94 次成功、2 次硬限额拒绝；25 次子进程回执成功、1 次模型拒绝；进程 232 页、匿名 3360 页、ELF 2132 页及 94 个额外线程上下文、25 个子进程回执均完成等量回收。
- `artifacts/ai-system-r2/threads/summary.json`：原始真实 musl pthread 探针连续三轮通过，覆盖 TLS、同步、信号、futex、上限复用与线程组退出。
- `artifacts/ai-system-r2/terminal/summary.json`：使用校验真实记录数 footer 的严格窗口解析器，真实 LXPanel → Terminal → PTY → 独立 EL0 shell 路径通过读写、窗口缩放、100×29 PTY 尺寸回读、Ctrl+C、SIGHUP 与全部资源回收。

历史 r1 候选 `db844d8c4a06b66b02b34f2637c54668143d2e65cfeb382f24b7a66c06b4aaf2` 的对应报告保留在 `artifacts/ai-system-r1/{accounting,threads,terminal}/summary.json`，仅作该身份的历史证据。r2 的增量是 IPC 模型错误入口计数与窗口检查器的记录数校验；上述最终结果均重新验证 r2，不能外推至后续未测试映像。

这些是有界执行反馈累计值，不是完整事件审计。当前没有每次 EL0 动作的 request/decision/snapshot ID、版本、期限与持久化日志，也没有 CPU/内存在线训练与发布。现有模型继续读取等待时间、最近 IRQ/syscall 行为及实际空闲容量；本轮没有把统计计数冒充新的训练或全系统协调模型。
