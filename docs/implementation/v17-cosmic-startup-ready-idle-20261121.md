# COSMIC 1 GiB 启动调度优化

本轮在持久页表提交 `e43b8e3` 之上，消除仍有可运行用户线程时的无条件
休眠，并修复 AP 完成通知与进入休眠之间的竞态。用户随后要求移除 2 GiB
配置，因此最终性能结论和回归统一使用 1 GiB 镜像。

## 实现边界

- CPU0 前台循环继续执行原有控制台、资源、存储、图形、用户及 AI 服务。
  进入休眠前，在 IF 清除的范围内检查活动进程的当前线程及全部 parked
  线程；有可运行线程则立即继续，没有则保留原 1 ms 定时回退。
- 新增 `idle_until_while`，将非消费式状态检查放在 CLI 与 STI/HLT 之间。
  `idle_until` 保留原行为。已过期期限和定时器设置错误仍恢复中断。
- AP 完成阶段在同一边界复查未收集 ticket 的完成状态。检查不转移所有权，
  真正的回收仍由 `try_collect` 完成。已收集 ticket 从待查集合移除；
  共享的 `dispatch::drain` 不改成会反复看到已完成 ticket 的空转循环。
- COSMIC 仍等待所有 AP 实际完成原授予时间片，再执行前台服务；legacy
  的 stop-on-first 规则保持。未调整 CPU 时间片、资源额度、ELF、初始化顺序、
  输入队列、组件及 Mesa 行为。持久根页表、PTE 撤销、alias 与 W^X 边界保持。

## 1 GiB 同输入测量

固定 QEMU TCG、4 vCPU、1024×768 VirtIO scanout、1 GiB RAM、release 配置，
使用 `artifacts/v017-native-pointer-motion-catalog-v1` 的同一 129 个输入文件。
旧版从独立的 `e43b8e3` 工作树构建，未覆盖当前源码；它也使用原生 1 GiB
构建器且未启用已删除的 2 GiB feature。两版输入摘要、features、编译器及
编译参数相同。QMP 实际内存均为 `1073741824` 字节，未热插内存。

第一轮旧版时钟为 54.590 秒。在构建 1 GiB 候选版之前，将本配置的目标固定为
27.295 秒。测量不做周期状态查询；每约两秒取实际 scanout，连续两帧达到
相同字形判据后记录第一帧时间，并在结束时检查七个核心进程的状态。
计时起点为发送 `posix exec cosmic-session`；启动到控制台和总线建立的
时间另行记录在原始结果中。

| 轮次 | 旧版背景 | 新版背景 | 旧版时钟 | 新版时钟 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 20.216 s | 8.081 s | 54.590 s | 26.212 s |
| 2 | 22.193 s | 8.068 s | 54.497 s | 26.210 s |

取较慢的新轮次对较快的旧轮次，时钟观察耗时减少 **51.9%**，两轮均达到
预先固定的 27.295 秒目标。七个核心进程存活，各只创建一次根页表，随后复用。

候选镜像为 `artifacts/v017-os-startup-ready-wake-1g-v1`，boot SHA-256：

`243015c4ace36dff8f61cff004416579eef361de3602ee82b0f38468efe407da`

这些数据是单台宿主的墙钟观察，不是 CPU 计费或延迟分布；两秒截图粒度
及宿主波动限制了归因精度。此前 2 GiB 上两个实现变体的原始测量保留供审计，
不用于最终 1 GiB 达标结论，也不能据其约两秒差值单独量化 AP 竞态修复的收益。
完整 OS、COSMIC session 和机器语义首帧验收标志仍为 false。

## 回归与清理

- 原 idle 实现执行 1000 次 ready 循环会发生 1000 次不必要的休眠；相同
  生产函数回归在修复后不设置定时器、不进入 HLT。另覆盖无任务、CLI
  边界到达、过期期限及错误恢复，共四项；原生、ported legacy 和 ported
  full-os 的选中/parked 线程状态另各一项，容量直接提取生产的 8/16 配置。
- 原 AP 完成阶段在最后一次 poll 后收到完成仍等到回退期限。新增回归在
  legacy 与 session 两种配置均通过，原完整时间片、唯一收集、空批次及
  缺少完成时保留 backing 的超时用例保持，共十项。
- 生产页表/alias/撤销宿主夹具在 legacy/session 两档各 61 项通过，PC 平台
  与 x86 架构 73 项通过。审核指出的夹具 `MAX_PROCESSES=16` 确认属实；
  现改为提取生产 `usermem.rs` 的 8/40 feature gate，覆盖首槽、末合法槽、
  第一个越界槽、下一槽及 `usize::MAX`。合法槽用非零未对齐的 pool 到达
  实际 arena 校验器，非法槽必须在实际 owner guard 返回；没有替换 guard
  或声称该边界夹具成功分配了客体物理页。独立的 16 槽位及 `>=` 改为 `>`
  负例在两档均失败，证明能捕获幻影额度与越界放行。
  删除 2 GiB 后仍检查 1 GiB 最后一页可映射、越界页拒绝、phase 元数据边界，
  以及 loader 对 2 GiB 内存拒绝而非截断。宿主夹具不是硬件 MMU 验证。
- 页表夹具首次因缺少 `arch::space` 导出而编译失败；补齐实际生产模块路径
  后通过，没有复制窗口常量或跳过边界断言。初次失败日志保留。
- AArch64 `graphics` 兼容编译通过，保留原有 11 条警告；未声称新的 ARM
  客体验收或在 ARM 上启用 x86 的 full-os 配置。

- 最终 1 GiB full-os 与非 ported legacy 镜像分别通过 `OS_NATIVE_PASS`，
  覆盖寄存器、真实定时抢占、FP/TLS、堆零填充/重用、IPC 和持久化。full-os
  额外发生实际匿名页撤销后访问 fault（vector 14/error 4）与 NX fault
  （error 0x15），地址均为 `0x0c000000`。
- 日历两次打开/关闭为 6.584 / 4.398 / 7.139 / 6.042 秒，均在原 15 秒内。
  原时钟及核心进程存活，无异常退出；45 秒首帧门槛保持。两次关闭后的共享
  状态均为 12 对象 / 105 页 / 20 映射。检查原进程存活后明确结束七个用户
  进程，匿名帧、共享对象/页/映射/引用、grant 及 OFD 引用全部归零。

已删除 `ram-2g` 的两个 Cargo feature、上 GiB 启动自检、2 GiB loader
准入、三个专用 Python 工具，并将启动 profiler 绑定到标准 `os_x86` 与实际
1 GiB QMP 断言。共清理 42 项已生成的镜像、磁盘和对应 Cargo 缓存，保留
小型 manifest、测量、源码快照及日志；旧 2 GiB 配置文档已标记为历史记录。

## 重现入口

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-time-applet-v1 \
  --sysroot artifacts/v017-native-pointer-motion-catalog-v1 \
  --output artifacts/v017-os-startup-ready-wake-1g-new
python3 tools/os_cosmic_startup_profile.py \
  --build artifacts/v017-os-startup-ready-wake-1g-new \
  --output artifacts/v017-startup-ready-wake-1g-new --no-status
python3 -m unittest discover -s tests/host -p test_os_ready_idle.py -v
python3 -m unittest discover -s tests/host -p test_cosmic_parallel_phase.py -v
python3 -m unittest discover -s tests/host -p test_page_map_batch.py -v
cargo test --locked --offline -p cyxia-arch-x86_64 -p cyxia-platform-pc
```

完整来源、测试日志、预算/变体账本、清理清单、负例及聚合验证器位于
`artifacts/debug/cosmic-startup-half-20261120/`；最终聚合入口为 `verify_1g.py`。
每次构建和客体运行均串行持有原生会话锁，测量期间不并发编译或运行其他 QEMU。
