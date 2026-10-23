# 有界显示提交策略

2026-10-18。该切片把普通 EL0 显示提交接入客体本地整数模型，覆盖的是提交节奏。像素内容、X11 请求语义、焦点、菜单、键鼠事件和 GPU fence 协议仍由确定性机制执行。

模型 `24577 / 0x6001`、版本 1 位于 [display_policy.rs](../../crates/ai-runtime/src/display_policy.rs)。[训练工具](../../tools/train_display_model.py) 从明确的合成策略蒸馏整数权重：根据上一笔实际 transfer+flush 完成耗时，以及距上次等待以来完成的矩形数，选择提交前等待 0 或 1 ms。四个有界输入为常数、截断到 16 ms 的 fence 耗时、截断到 8 的完成数和保留的零值。推理只做四项整数乘加，无动态分配，不读像素或输入内容，不持有设备队列借用。完成回执更新下一次推理的观测值；权重不会在线修改。

[训练报告](display-model-training.json) 记录 153 个特征组合上的合成训练，以及 4096 个原始观测的策略一致性验证。后者映射到训练过的有界特征，不能表述为未见桌面工作负载上的性能提升或在线学习效果。

`graphics::begin_blit` 的单个 CPU 暂存槽最多保留 16384 像素 / 64 KiB；此槽是 BOOTSTRAP 固定内存，不计为 AI 分配。合法、设备存在且空闲的请求推理一次，获得带 owner、单调 ID、时间、观测、score、来源的单次计划。忙时不会再次推理或覆盖已有数据。`Queued → Submitted → Completed/Failed` 分别对应计划准入、真实硬件接收、完整 transfer+flush fence 成功或实际失败。请求提交后，即使原进程退出，内核仍继续处理 fence；不会因新的策略决定撤销已有 DMA 或提前复用其 backing。

等待输出上限为 1 ms，并有独立的开销上界检查：每八个完成矩形最多允许一次计划等待。当前 1024×768 全屏、每次 16384 像素的 DDX 路径共 48 个 tile，任意连续 48 次提交的计划额外等待不超过 6 ms。**这不是实际整帧时延上限**：缓存同步、GPU、进程调度和前台轮询还会产生耗时。暂存还增加每矩形一次 CPU 复制，完整上述帧累计额外复制 3 MiB。`planned_wait_ms` 与 `actual_queue_ms` / `max_queue_ms` 分开计数，后者包括暂存复制和轮询延迟。安全上界若修正模型输出，该次实际来源记 `SAFETY_GUARD`，不混入 `ai_admitted`；`admitted = ai_admitted + guard_admitted`。

Linux 私有 DDX ABI 与原生 SVC24 不变；调用者仍等待真实提交完成。策略等待在内核中保留完整矩形，不向 Xorg 返回新的策略性 EAGAIN，因此不会触发 DDX 从整帧起点反复重试的活锁。设备实际繁忙仍按原来的背压机制返回 EAGAIN。

`ai system` 的 `AI_DOMAIN name=display` 提供模型、版本、phase、proposal/admit/submit/complete/fail、busy、策略输入错误、时钟拒绝、保护来源和等待数据；`AI_DISPLAY_RECEIPT` 给出最近一次提交的因果字段与 outcome。它是有界聚合及最近回执视图，尚不是完整持久审计日志。设备缺失、协议错误和隔离不能被写成 AI 成功。静态 DMA 池保持原有保留与隔离语义。

主机状态机测试覆盖反馈改变真实模型结果、每 48-tile 窗口的计划成本上界、忙与非法调用保留原计划、完成前不得宣布成功、真实失败与成功分离、时钟溢出及保护来源。运行：

```sh
python3 tools/train_display_model.py --check
cargo test -p cyxia-ai-runtime display_policy
```

最终候选 `ai-system-r2`（SHA-256 `1a0f5534cdb50ab2e8e291ad0fd6890899f35e55ce536c6756ffc8c8e42aae81`）的 [精确像素回归](../../artifacts/ai-system-r2/graphics/result.json)、[LXPanel 物理控件回归](../../artifacts/ai-system-r2/panel/summary.json) 和 [全域客体核验](../../artifacts/ai-system-r2/system/summary.json) 均 PASS。前者检查全部 786432 像素、两次矩形更新、非法参数及无 GPU 路径；面板验证真实任务按钮最小化/恢复、显示桌面隐藏/恢复及受测进程内存、线程资源回收。窗口观察核对客体报告总数，串口混入日志导致不完整 JSON 时整次重试，不以漏掉的记录判断窗口消失。正常退出和桌面终止回收已测，但未通过专门故障注入强制命中“owner 恰在 DMA 在途时死亡”，不将这些普通退出用例冒充该强断言。

该次四程序桌面采样中，194 次推理/准入/提交/完成均一致，21 次选择 1 ms 计划等待，实际累计排队 25 ms、最大单次 2 ms；停止桌面后的累计 199 次全部完成，计划等待 22 ms、实际累计排队 26 ms、最大单次 2 ms。实际排队包含前台调度与复制成本，说明计划 1 ms 不能被解读为真实等待至多 1 ms。停止桌面后的最大观测 fence 完成耗时为 152 ms，也包含前台轮询和串口检查期间的延迟，不能解释为纯 GPU 执行时间。所有计数可由原始串口与 summary 复核；这是一次并行 QEMU 回归的观测，不是性能基准或优于基线的证明。

尚未提供跨多个显示服务的公平性、动态 framebuffer 准入、多显示器、vblank 保证或线上模型更新。
