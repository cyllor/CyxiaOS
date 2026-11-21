# COSMIC 日历交互的调度与账本热路径

基线为 `1e1e26a`。在 1 GiB、4 vCPU、原三组件 catalog 和每进程 128 个页表页
的配置下，先移除 `collect_children()` 的无用 4 KiB 上下文交换，再将 grant
账本快照改为常数时间。日历继续使用原 15 秒门槛。

## 复现与最小反馈循环

原症状来自保留的真实客体捕获。只运行日历的三组件基线关闭为
13.249 / 17.632 秒；两组件为 20.020 / 18.404 秒，两者均有超时。三组件
第二次关闭页表重建为零，全部准备累计仅 59.716 ms，撤销 4.716 ms。
不能由 wall/syscall 的摊销值断言 IPI、CR3 或 FP 是唯一成本。

CPU0 的 87 个三组件帧边界样本中，43 个命中实际发布 ELF 的
`collect_children` 两段标量交换循环。两组件有 52/93 个样本落在该函数。
这些是有偏的寄存器样本，不是 CPU 时间比例或提速承诺。

最小秒级循环执行提取的生产收集、线程结果回写与状态刷新函数。进程、线程、
receipt 容量直接来自生产声明，覆盖 8/40 进程槽和 8/16 线程槽；Thread 为
明确的 4 KiB 宿主夹具。用户拷贝、退出发布及释放计数边界是 fixture，真实
SIGCHLD/退出发布/账本另由既有 custody 用例验证。这不是硬件 MMU 或客体
CPU 时间证明。

```sh
PYTHONPATH=tools:tests/host python3 -m unittest test_child_collection -v
```

修改生产代码前，两档均稳定失败，每档 8 个 Rust 用例为 2 通过、6 失败，
失败集中在不必要的交换次数。单个无 Child 等待的活动进程仍交换 14/30 次；
40 个活动槽、两次收集为 2400 次。完整客体冷启动不能压缩到秒级，因此使用
这个正确热路径 seam 做内层，再回到原日历场景验收，不能以交换次数代替时延。

## 最小改动与边界

`Supervisor::poll` 每轮调用两次 `collect_children`。旧实现对每个活动进程
遍历全部 parked 线程，无条件交换到 selected 槽、检查等待类型，再换回。
现在仅当 parked 槽确实等待 `Wait::Child` 才交换。该判断在 CPU0 拥有全部
停止上下文时进行，保持线程遍历顺序、选中上下文的 usercopy 路径、结果回写
和最后的 `refresh_thread_state`。

`publish_child_exits` 的时机、SIGCHLD、复制失败保留 receipt、非阻塞返回零、
无子进程返回 ECHILD、auto-reap 排除和单次释放未改。没有增加新的 active
筛选来改变旧方法对等待记录的语义。

首个候选的唯一编译源码差异是 `kernel/src/desktop/user/spawn.rs` 的五行守卫。
候选和基线的嵌入输入、特性、构建生产者及工具链一致。镜像为
`artifacts/v017-os-child-collection-fix-1g-v1`。

## 已完成的宿主检查

- 新收集回归：两档各 8 项，共 16 项通过，覆盖最后合法线程槽、完整上下文
  归属、同时等待者顺序、复制失败后重试、匹配父进程、非阻塞和阻塞等待。
- 同一审计计数器的六个布局/负载场景通过：无 Child 等待的 legacy 8 槽、
  session 8/9/40 活动进程均为零交换，原来对应 224/480/540/2400。
- 原 12 项退出/信号/账本 custody 用例和两项应失败负控通过。初次关联检查
  暴露旧夹具缺少 `has_runnable_thread`、`tee_stderr` 和 ported Unix 状态。
  补齐生产接口与 feature 声明后通过，初次编译错误另存。
- 线程准备两档共 8 项与审计解析三项通过。未宣称全仓 CI 通过。
- 内核核心、POSIX 与 AI runtime 的 applet 配置共 577 项通过。对象边界测试
  分别验证 full-os 的 64 FD／256 OFD 和 applet 的 128 FD／512 OFD；旧测试
  把前一档断言带入后一档，已按实际启用的功能选择预期。

红灯、绿灯、基线源码、计数和构建日志位于
`artifacts/debug/child-collection-fix-20261121/`。基线计数仍保存在
`artifacts/v017-child-collection-audit-v2/`，修复计数另存为
`artifacts/v017-child-collection-fixed-counts-v1/`，没有覆盖旧证据。

## 进程状态刷新中的 grant 快照

移除子线程交换后，日历四个阶段的 71 个 CPU0 样本均离开 `collect_children`。
一次关闭仍超过 15 秒。剩余样本落在 `Supervisor::poll` 内两段步长 96 字节的
循环，分别扫描 1024 个 heap grant 和 128 个 image grant。每轮刷新覆盖全部
40 个进程槽，旧路径最多读取 46,080 条 grant 记录。

`BoundedGrantLedger` 在五种成功变更时同步维护已保留和已使用页数。`snapshot()`
从这两个汇总值计算余量，预留尚未领取的页仍算入占用。所有容量、记录数、属主、
代际及释放凭据检查仍在变更前执行，失败返回保留账本。页表、映射和释放顺序由
原调用方负责。

执行实际 `snapshot()` 函数体的遍历用例在修复前读取 1280 条记录后失败，修复后
在 128 与 1024 条记录两档均为零遍历。另用真实账本从 grant 与 redemption 独立
重算两项汇总，覆盖 1000 轮分配、领取、取消、释放及拒绝，并验证 `u32` 容量边界。

```sh
PYTHONPATH=tools:tests/host python3 -m unittest test_grant_snapshot_cost -v
RUST_MIN_STACK=33554432 cargo test --locked --offline -p cyxia-kernel-core -p cyxia-posix -p cyxia-ai-runtime --features cyxia-posix/cosmic-applets-v1,cyxia-ai-runtime/cosmic-applets-v1
```

## 客体对照

三轮均在 1 GiB、4 vCPU、三个原版 applet 下用同一诊断脚本测量。数字从 QMP
按下按钮到首个满足原截图条件的分析完成。捕获脚本的原 release 后计时另存于
各目录。寄存器采样存在开销，同一轮的 syscall 数也随关闭路径变化。

| 版本 | 打开 | 关闭 | 再打开 | 再关闭 | 原专项判定 |
| --- | ---: | ---: | ---: | ---: | --- |
| `1e1e26a` | 8.998 s | 13.405 s | 8.548 s | 17.793 s | FAIL |
| 跳过无关线程交换 | 7.907 s | 18.997 s | 6.782 s | 6.219 s | FAIL |
| 再使用账本汇总 | 7.321 s | 14.468 s | 6.226 s | 14.594 s | PASS |

前两轮为 `artifacts/v017-calendar-audit-three-v1` 和
`artifacts/v017-calendar-child-collection-fixed-three-v1`。第三轮为
`artifacts/v017-calendar-ledger-fixed-three-v1`，来自
`artifacts/v017-os-calendar-ledger-fix-1g-v1`。镜像清单验证第二次改动仅改变
`crates/kernel-core/src/grants.rs`。第三轮全部原 applet 存活，客体结束用户进程后
共享对象、页面、映射和 grant 计数归零。

首个候选的完整场景 `artifacts/v017-workspace-child-collection-fixed-1g-v1`
两次平铺状态均未变化，随后在工作区点击前等待完整光标超时。串口记录了
`REL_X=-944`，失败截图仍显示光标停在原父图标处。该轮完整场景未到达日历步骤。

原完整场景使用 `tools/os_cosmic_workspace_probe.py`，开启重复平铺和可选工作区
列表。对照和账本候选均嵌入相同的 148 项输入。下表采用原完整场景从释放按钮后
开始计时的口径。

| 完整场景 | 首次关闭 | 再次关闭 | 综合判定 |
| --- | ---: | ---: | --- |
| 基线 `v017-workspace-list-1g-v10` | 22.691 s | 19.900 s | FAIL |
| 账本候选 `v017-workspace-calendar-ledger-1g-v1` | 12.096 s | 7.717 s | PASS |
| 修复观察器后 `v017-workspace-calendar-observer-1g-v1` | 11.562 s | 11.002 s | PASS |

账本候选通过 45 秒启动画面门槛，两轮平铺切换与还原、工作区 1→2→1，
以及日历 6.043 / 12.096 / 6.095 / 7.717 秒的两轮开关。退出回收见
`workspace-result.json` 的 `complete_teardown`。共享对象、物理页、映射、
引用与 grant、匿名页和 OFD 全部归零，128 个端点和 64 个连接全部收回。
三条共享准入收据的 grant/release 数相等，原 applet 全部存活至主动结束，
无异常退出。平铺菜单仍采用按住至观察到弹窗再释放的原测量手势。

同一镜像的原生验证为 `artifacts/v017-native-calendar-ledger-1g-v1`，结果
`OS_NATIVE_PASS`，覆盖实际定时器抢占、寄存器、保护页错误、FP/TLS、堆、
本地 IPC 和存储读写。

## 避免工作区观察器记录被插断

同一账本镜像的复跑 `artifacts/v017-workspace-calendar-ledger-1g-v2` 在第一次
平铺恢复后停止。观察器已经读到 `tiling=0` 并正常退出，但一条 `UNIX_ADMISSION`
日志插在 `name_hex=` 与 `31 active=1 tiling=0` 之间。探针找不到完整活跃行，
判 `Missing independent active workspace state`，这一轮没有进入日历步骤。

旧观察器用多次无缓冲 `printf` 输出一条状态。现在先格式化整行，再通过一次
`writev` 提交至多 64 字节的各段。各段在 CPU0 的同次服务内按序写入，支持原有
名称长度。短写以失败结束。Wayland 状态读取和宿主验收规则沿用原实现。

宿主夹具以生产输出逻辑验证每条状态的一次提交、最长 127 字节名称和短写。
原逻辑在 64 字节 console 边界下因拆行失败，修复后通过。原失败、宿主测试与
寄存器分析脚本存放在 `artifacts/debug/child-collection-fix-20261121/`。

修复后的观察器由 `tools/build_workspace_state_probe.py` 交叉编译，按原装配器重新
校验默认 catalog，再追加原可选工作区配置。构建清单对照显示 148 项嵌入输入中
只有 `workspace-state-probe.elf` 变化。最终镜像
`artifacts/v017-os-calendar-observer-fix-1g-v1` 的 boot SHA-256 为
`acba952e526fbabbc8f52f93e1680a18d1f984e97144c83f0ea0729b43cff6d1`。

最终完整场景通过 45 秒启动画面检查、两轮平铺切换和恢复、工作区 1→2→1、
两轮日历开关及退出回收。日历四步为 6.598 / 11.562 / 6.089 / 11.002 秒。
同一镜像的 `artifacts/v017-native-calendar-observer-1g-v1` 也返回 `OS_NATIVE_PASS`。
本次捕获范围是三组件场景。完整会话与语义首帧的验收标志保留为 false。
[证据索引](v17-cosmic-child-collection-fix-20261121.evidence.json)

```sh
PYTHONPATH=tools:tests/host python3 -m unittest test_workspace_state_output -v
python3 tools/os_cosmic_workspace_probe.py \
  --build artifacts/v017-os-calendar-observer-fix-1g-v1 \
  --output artifacts/v017-workspace-calendar-observer-1g-repro \
  --observe-seconds 60 --workspace-x 60 --workspace-first-x 28 --repeat-tiling
```
