# 性能审核复核与 1 GiB 热路径优化

在 `099d4b0` 的 1 GiB 启动优化和容量夹具修复之后，本轮复核用户提供的
双轴审核。实际修改两个内核文件与抢占检查的错误诊断，保持相同的 129 个
输入文件、1 GiB、4 vCPU、CPU 授予、W^X、AP 完成和页表回收契约。

## 审核判断复核

| 意见 | 核对及处理 |
| --- | --- |
| `MAX_PROCESSES=16` 幻影容量 | 确认。硬编码位于 `test_page_map_batch.py` 生成模块，而非 cases 文件。`099d4b0` 已提取真实 `usermem.rs` 的 8/40 feature gate，增加首槽、末合法槽及越界覆盖；16 槽位与 off-by-one 负例均在两档失败。 |
| preemption deadline 后丢弃证据 | 确认。原 `break` 丢掉刚读取的本 PID 非零计数。现在仍拒绝超时结果，同时在 `TimeoutError` 中保留 PID 与计数；`finally` 继续回收探针。先观察到诊断回归失败，再修复通过，未放宽 5 秒判据。 |
| retire/synchronize 致密 | 属可读性判断，未发现新的错误或性能证据。保留所有权事务和失败前缀的集中结构。 |

## 已落实的内核优化

`prepare_threads` 原先对全部 parked 槽位执行两次 4 KiB Context swap，再调用
通常立即返回的 `wake`。现在直接按原顺序向活动槽位转移 pending signal，
跳过 inactive 或无 wait 的线程，只有阻塞线程使用原 selected-context
唤醒机制。真正选中另一线程时仍执行一次选择 swap。复杂的 Linux 重启、
信号、OFD identity 和 wait 唤醒实现保持原样。

提取生产准备函数的夹具明确观察每次 `core::mem::swap`，并转发给真实 swap。
8/16 线程容量直接来自生产声明；4 KiB Context、pending、wake 和策略输入是
显式宿主夹具。旧实现对空槽/全 ready 的一轮分别做 14/30 次 swap，三个回归
在两档均失败；现在为 0。阻塞唤醒的顺序、上下文归属及最后一个 parked 线程
的实际选择均通过，共八项。此计数不是实际总线字节数或客体 CPU 计费。

旧 release ELF 的 `arm_deadline` 可见两次宽整数除法 helper 调用，分别来自
HPET 换算和定时器计数。本轮将算术与硬件访问分开：

- 整纳秒 HPET 周期使用 checked `u64` 乘法；分数纳秒周期保留原精确的
  `u128` 乘除与截断，溢出仍失败，不舍弃精度或改变时间源。
- 定时器用 checked `u64` 乘积并向上取整、限制到 `[1, u32::MAX]`。
  乘积若超出 `u64::MAX`，它必定已大于 `u32::MAX × 10^9`，因此结果可
  直接判为上限，无需宽除法。该路径对所有输入与原定义完全相同。
- 独立宽整数 oracle 覆盖整/分数周期、溢出、零、向上取整和饱和边界，
  以及 100,000 组全宽与 100,000 组短期限样本，共四项。

没有缓存时钟结果、跳过定时器重装或改变实际 HPET/LAPIC 访问与 IRQ 状态。
重复 deadline 是否可省需要同时证明对应 CPU 的已装载/取消/到期状态，
不能只比较时间值。

## 其余性能建议的边界

- **syscall 往返税**：实际 AP→CPU0 完整收集、服务、重新派发路径仍存在。
  当前没有 `AT_SYSINFO_EHDR`/vDSO 实现；共享时钟页需要独立的时间插值、
  精度、auxv/ELF ABI、映射与生命周期方案。本轮没有重新采集审核引用的
  约 60% syscall 占比，不能据此给各项分配启动收益。
- **1 ms backstop**：无 runnable 时确实继续定期执行全服务循环；有 runnable
  的无条件休眠已在 `099d4b0` 消除。空闲退避需要统筹设备完成、polling 输入
  与最近的用户定时期限，本轮保留原回退期限。
- **epoll**：`observe_backend` 确实遍历使用中的 epoll 和 armed watches，
  拓扑缓存没有免掉采样。按 source 建索引需要同时维护 close/dup/复用与嵌套
  edge 的失效，不属于已落实的变化。
- **输入日志**：源码只对 `event.kind == 1 || event.kind == 2` 写该条串口
  日志；absolute motion 的 kind 3 不走这条日志。因而“每个输入事件均约
  百次 IO”的概括过宽。该成本对键和相对运动存在，启动测量没有输入事件。
- **匿名页与统计**：full-os 的释放清零和下次 `alloc_zeroed`、堆的
  `largest_free_run` 扫描均可在源码确认。减少清零需要验证所有回收/复用契约；
  惰性统计需要区分原有公开快照的时点，本轮未更改它们。
- **RTC**：1024 次/1 ms 预算的重试仅在 Busy 时触发，成功读取直接返回且不
  访问 HPET。缓存秒值还需定义时钟跳变与失效行为，本轮保持真实读取。

## 1 GiB 实测与回归

同一最终镜像两轮在 **24.203 / 22.186 秒**观察到时钟；`099d4b0` 的两轮为
26.212 / 26.210 秒。使用更早的、同输入 1 GiB 对照 54.590 / 54.497 秒，
取较慢的新轮次对较快的旧轮次，累计观察耗时减少 **55.6%**，继续满足原先
冻结的 27.295 秒目标。计时仍从发送 `cosmic-session` 命令开始，非完整 OS
就绪时间；启动到控制台与总线建立另存于每轮原始结果。

镜像 `artifacts/v017-os-audit-hotpaths-1g-v1`，boot SHA-256：

`7b254a5fb182b0a6a26f1781ee2d01cb12392978cc83a410938a5e298eec1c3d`

新时钟换算的 native 检查直接读取 QMP 实际内存及 HPET capabilities，得到
1 GiB、周期 `10,000,000 fs`，确实适用整纳秒快速路径。硬件查询原始响应
保存在 `qmp.json`；wrapper 初次在 `SystemExit` 后未写独立收据，已从带摘要
的实际 QMP 对话恢复该收据，并将后续写出移到 `finally`。客体验收不受影响。

线程准备八项、算术四项、抢占证据四项回归通过；此前的 idle/AP 完成、
两档页表夹具各 61 项保持通过。完整 POSIX cosmic-session 295 项及 ARM
graphics 兼容编译通过。宿主测试/政策/IRQ 夹具的范围与真实客体证据分开记录。

最终 full-os 和非 ported legacy 的 1 GiB 镜像均通过 `OS_NATIVE_PASS`，
包括真实定时抢占、寄存器、FP/TLS、堆重用、IPC 与持久化；full-os 另验证
匿名页撤销后的真实访问 fault 和 NX fault。日历两次打开/关闭全部在原
15 秒期限内，45 秒首帧门槛保持；核心进程及原时钟存活，无异常退出。
两次关闭后共享状态相同。随后明确结束七个用户进程，匿名帧、共享对象/
页/映射/引用、grant 与 OFD 引用全部归零。

数据仍是单台宿主、约两秒截图间隔的墙钟观察；不会把组合变更的波动单独
归因给某个 helper。完整 OS、COSMIC session、语义首帧验收标志仍为 false。

主要重现命令：

```sh
python3 -m unittest discover -s tests/host -p test_thread_prepare.py -v
python3 -m unittest discover -s tests/host -p test_x86_clock_math.py -v
python3 -m unittest discover -s tools -p test_os_smoke_preemption.py -v
python3 -m unittest discover -s tests/host -p test_page_map_batch.py -v
RUST_MIN_STACK=16777216 cargo test --locked --offline -p cyxia-posix --features cosmic-session
python3 tools/os_cosmic_startup_profile.py \
  --build artifacts/v017-os-audit-hotpaths-1g-v1 \
  --output artifacts/v017-startup-audit-hotpaths-1g-new --no-status
```

负例、原始源码、测试日志、时序与聚合证据位于
`artifacts/debug/cosmic-audit-hotpaths-20261121/`。宿主测试的大栈只用于原有
POSIX 大夹具，不改变客体栈或资源额度。全部编译和客体运行串行执行。
