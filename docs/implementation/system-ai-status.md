# CyxiaOS 全系统 AI 强化落地清单

日期：2026-10-18。适用范围：真实 AArch64 单核内核与首版轻量桌面，256 MiB 基础配置 / 512 MiB 桌面配置。本文描述已经存在的代码路径与本轮验收边界，不以架构目标替代实现证据。

当前系统是**本地整数模型参与各资源域决策，确定性内核校验并执行**。已有资源反馈；文件缓存具有受限本地参数学习。尚未实现统一跨域协调模型、全域在线学习、网络策略或多核调度，不能称为“所有系统资源已经完全由 AI 统一决策”。

## 统一检查入口

2026-10-22 锚定缩放增量：[缩放与抓取清理验收](smithay-resize-native.md) 使用未改变的本地模型。最终合成器请求 3981 页（3917 页映像与 64 页栈），经实际模型 8195 批准；独立检查确认 4016 页仍获准、4017/4039 页仍被拒绝。三次启动共 108 次 AI 显示准入及真实完成，CPU/显示无 guard 替代，资源全部归还。配置事务、几何锚点、关闭后的指针释放处理属于确定性执行机制，未增加自主布局、学习或资源容量。

2026-10-22 交互增量：[鼠标移动与缩放验收](smithay-interactive-native.md) 继续使用同一本地模型。最终合成器请求 3980 页（3916 页映像与 64 页栈），由实际模型 8195 批准，模型输入与前一阶段相同。三次启动共 108 次 AI 显示准入及真实完成，CPU/显示均无 guard 替代，资源全部归还。输入序号、事件所有权、抓取和位移计算仍为确定性机制；未新增窗口布局模型、学习模型或容量扩展。

2026-10-22 双窗口增量：[并发合成与焦点验收](smithay-multi-native.md) 继续使用同一本地模型。合成器请求 3977 页（3913 页映像和 64 页栈），经实际模型 8195 批准；构建模型输入与上阶段逐字节相同。三次启动共 90 次 AI 显示准入及真实完成，CPU/显示均无 guard 替代，资源全部归还。点击命中、窗口堆叠和协议顺序仍是确定性机制；本轮没有新增自主窗口策略或学习模型。

2026-10-22 xdg-shell 增量：[窗口生命周期验收](smithay-xdg-native.md) 继续走同一资源模型。初版请求 4039 页被模型 8195 拒绝，即使低于物理容量也没有启动；fat LTO 将请求降到 3976 页后获准。构建预检直接调用同一模型函数。三次运行共 54 次显示准入和真实完成，全部资源归还；本轮未改变权重、额度或学习能力。

2026-10-22 增量：真实 Smithay Wayland 表面已接入上述资源域，见 [原生显示/输入验收](smithay-wayland-native.md)。三次独立运行中，每次六帧共完成 18 次本地显示模型准入、提交与 GPU fence，无 guard 代替、拒绝或失败；匿名/共享页、ELF、跨进程 FD 与进程资源均完整归还。输入事件保持确定顺序，不能由模型改写。此证据没有引入新的学习模型，也不代表统一跨域 AI 协调已经完成。

在 CyxiaOS 串口 shell 输入：

```text
ai system
ai status
ai resources
ai audit
storage status
```

`ai system` 排队一个只读请求，在 CPU0 前台边界读取真实服务计数，输出版本化 `AI_SYSTEM schema=1`、逐域 `AI_DOMAIN`、学习状态和 `AI_GAPS`，以 `AI_SYSTEM_END` 结束。该命令不会推理、训练、分配资源或改写文件。内核不生成覆盖百分比；没有决策机会的域允许计数为零。

`ai resources` / `ai audit` 专指早期 EL1 cooperative runtime。原来容易被理解为全系统状态的文字已经改正。完整命令在串口 shell；桌面的 `cyxia-sh` 目前没有导出这个管理接口。

## 各子系统的实际链路

| 子系统 | 本地策略和实际效果 | 机制与当前限制 |
|---|---|---|
| 进程 | 8193 准入基本页；8195 准入真实 ELF 页；12289 选择可运行进程 | 授权启动、退出、kill、地址空间隔离保持确定性；尚无服务恢复模型 |
| 线程 | 8193 准入上下文额度；12289 对可运行线程排序 | futex、信号、TLS、唤醒和 clear_tid 是机制；每进程最多 8 线程 |
| CPU | 12289 排序；12290 决定 EL0 1/4 ms 时间片；真实 IRQ/syscall/等待反馈进入后续决策 | 超龄保护单列；EL1/EL0/存储等域之间的前台循环仍固定，无全域协调器 |
| 内存 | 8193 元数据/基本页准入，8194 匿名页准入，8195 ELF 页准入；模型批准后才兑现真实 grant | 按进程静态私有池；无全 RAM 动态重分配、交换或任意回收应用匿名页 |
| 文件系统 | 本地写入准入；超过 4 个缓存候选时模型排序；POSIX read_at/write_at 同样走该路径 | 指定文件、字节、偏移、权限和删除语义不由模型改写；≤4 候选无竞争选择记 MECHANISM |
| 持久存储 | **本轮新增 20481**：可信 runnable work 决定每 8 ms 最多新提交 1/4 个块操作；8194 准入快照暂存页 | 真实 begin 成功才扣额度；已在途完成先推进，恢复 BOOTSTRAP，payload→flush→header→flush 顺序固定；仍需显式 Save/checkpoint |
| UART / Timer | 16385 对竞争请求排序，有真实完成/重试/超时反馈 | 单请求为 MECHANISM，过期保护单列；不代表已覆盖所有设备类别 |
| Unix sockets / pipe / PTY | 8193 用实际空闲槽数量做逻辑占用准入；**本轮加入批准、后续失败、真实池提交统计** | 复用元数据准入模型，固定 backing 为 BOOTSTRAP；FIFO、line discipline、信号、已授予对象传输为机制；无带宽模型 |
| 显示 / 桌面 | 进程、线程、heap 已使用上述模型；**本轮新增 24577**：根据真实上一 fence 延迟和完成数选择 0/1 ms 提交等待 | 单槽 64 KiB 暂存，最多每 8 个完成矩形增加 1 ms 计划等待；busy 不推理；进程死亡后仍完成已接收提交 |
| 用户输入 / 权限 | 输入有序传输，权限、所有权、W^X 等硬边界由内核执行 | 这是正确的确定性职责，不将焦点、按键、权限更改包装为 AI 决策 |
| 学习 | 文件缓存收集真实读取样本，48 训练 / 16 留出 + 16 canary；候选非下降门控后显式 apply，支持 rollback | 只覆盖缓存模型；参数、样本不随文件快照持久化；未证明实际缓存收益，无自动性能回退 |
| 网络 / SMP / 跨 ISA | 未完成 | 不能用 AF_UNIX 或设计文档代替 TCP/IP、多核或第二平台客体验收 |

模型为客体内执行的固定整数推理。CPU、内存、设备的参数来自可复现合成 teacher 蒸馏；新增存储/显示也是明确的合成目标。这证明了策略到执行的接通，不证明优于传统策略或已具备通用智能。

## 本轮修正的具体问题

1. **模型选择不等于实际执行。** 原计数在测试寿命到期或待处理终止信号之前递增。现在进程、线程和时间片执行只在真实 `enter` 边界记账；未进入的选择归入取消。累计计数在进程槽复用后保留。模型入口错误也保留提案记录；多池请求不会继承上一次求值的批准状态。
2. **模型批准不等于资源提交。** 真实 grant 和 release 分开计量，整体操作失败后的回滚不会计为成功。Unix 原先在 socket/bind/connect 之前就输出成功式日志；现在以池操作实际结果为准。这里的 committed 指池资源提交，不等同于随后 FD 安装或整个 syscall 成功。
3. **存储旧 CPU 模型输出未实际控制工作。** 原路径只比较推理耗时，仍固定推进一个 sector。现在移除该误导性预算，使用能够限制新块请求的模型额度。同步 snapshot/CRC 成本仍是独立有界机制，不冒充模型 CPU 时间预算。
4. **显示有模型控制的提交节奏。** 模型不能访问像素和输入内容；单槽保证不覆盖未完成数据。transfer+flush 完成后才报告应用成功。策略等待与实际排队/设备延迟分开计量。
5. **学习及无竞争缓存来源可见。** 分开显示准入、缓存推理、无竞争机制、样本不足、候选验证拒绝、发布与回滚，避免把所有文件读取都计作 AI 选择。

## 计量口径

- `requests / proposals / approved / committed` 含义不同；模型提案和批准不自动算执行。
- 准入域按请求计数；一次 Unix 多池申请可能包含多次模型求值，因此 proposals 不是原始矩阵运算次数。
- `denied` 是模型否决；`capacity`、`invalid`、`failed` 分别保留硬容量、前置无效请求和执行失败。
- `grant_units / release_units` 在内存域是页，在上下文/退出回执域是明确逻辑单位；不得跨域相加称总内存。
- CPU 的 `committed` 是实际进入过上下文的 dispatch，`enters / returns` 是真实边界次数；一个 dispatch 可以进入多次。`elapsed_ms` 含同步 syscall 工作，不是纯 EL0 CPU 时间。
- 显示 `admitted = ai_admitted + guard_admitted`；安全覆盖动作只归 SAFETY_GUARD。计划等待上限不是实际帧延迟上限；实际排队、fence 延迟及额外整帧最多 3 MiB CPU copy 成本单独披露。
- 计数在一次启动内累计并饱和；EL1 审计仍是 64 条覆盖环，其他域主要是聚合/最近回执。尚不具备全域 request/decision/snapshot/epoch/期限关联和持久日志。
- `ai system` 是可观测入口，不是新的资源总账或跨域 AI 大脑。

## 验证入口

冻结候选：`artifacts/ai-system-r2/cyxia-kernel.elf`，feature 为 `graphics,lxpanel,large-memory,spawn-test`。SHA-256：`1a0f5534cdb50ab2e8e291ad0fd6890899f35e55ce536c6756ffc8c8e42aae81`。

最终 [联合验收报告](../../artifacts/ai-system-r2/summary.json) 为 **PASS**：同一 SHA 的 10 组 ARM/QEMU 门禁通过；266 项主机 Rust 测试、123 项 large-memory 配置测试、95 项 Python 检查通过，主机及 ARM 基础/桌面配置 Clippy 无警告。模型参数可复现检查通过。通过范围仅限本文列出的实现，不包含后续系统级能力。

```sh
python3 tools/verify_ai_system.py --elf artifacts/ai-system-r2/cyxia-kernel.elf --output artifacts/ai-system-r2/system
python3 tools/verify_ai_accounting.py --elf artifacts/ai-system-r2/cyxia-kernel.elf --output artifacts/ai-system-r2/accounting
python3 tools/verify_storage.py --elf artifacts/ai-system-r2/cyxia-kernel.elf --output artifacts/ai-system-r2/storage
python3 tools/verify_graphics_updates.py --elf artifacts/ai-system-r2/cyxia-kernel.elf --output artifacts/ai-system-r2/graphics
```

联合检查真实四进程桌面、模型拒绝、缓存竞争、累计执行计数、资源归还和精确文件内容；另回归线程、存储压力下双 flush/重启恢复、显示精确像素/正常退出以及 LXPanel 控件。模型训练脚本支持 `--check`；主机单测检查额度耗尽/期限、来源分类、失败不产生成功回执等边界。

## 验证工具本轮修正

真实菜单回归暴露两个证据问题：在应用选择器实际映射前就发 Escape；以及串口其他记录插入窗口 JSON 后，旧工具静默丢弃损坏行，误判窗口已关闭。失败证据保留于 `artifacts/ai-system-r1/menu`，不列入最终通过集合。

现在 guest inspector 报告真实输出的窗口数；工具要求完整结束标志、声明数、完整记录数和有效 JSON 数完全一致，否则在原超时内重做完整观察。窗口记录不能静默省略。菜单测试等待真实 `Choose Application` 出现和消失，并先证明旧目录窗口消失，再以新 spawn 的父 PID/子 PID 和新映射窗口证明根菜单动作；XID 允许合法复用。最终 r2 桌面相关门禁使用这套严格采集逻辑。

## 尚待实现的系统级能力

2026-10-18 COSMIC 基础移植的 [r3 联合报告](../../artifacts/cosmic-bootstrap-r3/summary.json) 继续验证既有本地模型路径：新 Rust/Wayland 程序的页、线程和 IPC 请求仍走现有准入，真实四进程桌面的 `ai system`、拒绝和资源回收回归通过。新增 epoll、信号栈、熵和键位解释属于有界机制；未新增跨域 AI 协调器或训练能力。当前 COSMIC 合成器尚未运行，不能据此声称 AI 已调度完整 COSMIC 会话。

1. 跨域观测、联合资源合同和模型协调器；当前各域额度不能动态移动所有物理 RAM 或整体 CPU 分额。
2. 可替换模型的身份、版本、有效期、超时、撤销与明确 RECOVERY，覆盖完整 POSIX 和已承诺 I/O 回归。
3. CPU/内存/设备的候选学习、真实收益与稳定性验证、预算内发布回滚；文件模型持久化。
4. 网络栈和对应准入/带宽策略，设备扩展、多核放置、第二 ISA 验收。
5. 完整跨域事件因果日志，以及固定工作负载下的推理成本、吞吐、尾延迟和能耗评估。

详见 [AI 决策契约](../../CyxiaOS-ai-decision-contract.md)、[执行计量](ai-execution-accounting.md)、[显示节奏](display-ai-pacing.md)、[持久存储](persistent-storage.md)。
