# COSMIC 日历延迟与稳定 epoll 图的重复扫描

后续的原生显示提交容量、完整 compositor 前后构建及日历延迟对照见
[原生提交容量与实际延迟](v17-cosmic-native-tile-capacity-20261120.md)。下方保留本阶段证据。

接续 [Mesa 分配失败传播](v17-cosmic-mesa-wayland-oom-20261120.md)，本轮对真实
日历延迟建立基线，并修复其中一个已采样确认的内核热点。此项修复不等同于
日历达到 15 秒目标，也不代表完整 COSMIC 桌面通过验收。

## 实测与缩小场景

保持原镜像、真实上游时钟和正常五核心服务，只保留一次鼠标打开日历。
`artifacts/debug/cosmic-latency-20261120/measure_calendar.py` 记录每次实际 QMP
截图、像素分析和标题/下方网格/底部设置文字的出现时间。

```sh
python3 artifacts/debug/cosmic-latency-20261120/measure_calendar.py \
  --build artifacts/v017-os-panel-mesa-wayland-oom-v2 \
  --output artifacts/v017-calendar-latency-baseline-v1 \
  --observe-seconds 180 --inspect-bus
```

这个真实 GUI 场景需要 180 秒冷启动等待，不能称作秒级回归。15.094 秒时日历
区域仍没有文字；完整标题、下方网格和底部文字于 48.386 秒匹配。共 87 次截图
耗时 1.154 秒，像素分析累计 3.064 秒；这些时间没有从原交互门槛中扣除。
45 秒启动检查仍失败，剩余 131,130 个启动色条像素。

原始失败信号出现后，依次验证显示提交、软件渲染、调度等待、输入延迟四个
可证伪方向。第二次相同场景增加 QMP 客体 RIP/CR3 采样，没有修改客体。
92 组快照中，CPU0 有 17 次落在 `epoll_topology` 或 `propagate_nested`，19 次
落在 `PageTable::publish`，12 次落在映射计数更新；其他 CPU 大多位于 worker
循环。采样命令累计 0.046 秒。指令快照说明热点位置，不能当作精确 CPU 计费。

原会话前后状态还记录了约 22 秒累计地址空间构建/回收。这是另一个有实测
依据的后续优化方向；本轮没有改变地址空间所有权或退休机制。

## 秒级回归与修复

进一步缩小到实际 POSIX 调用链：两个 owner、四个平面 epoll，循环执行
`epoll_sample`、`observe_backend` 和 `epoll_collect`，同时校验返回事件。

```sh
RUST_MIN_STACK=16777216 cargo test -p cyxia-posix \
  --target aarch64-apple-darwin \
  --target-dir /private/tmp/cyx-epoll-latency-target \
  --features cosmic-session --release --lib \
  unchanged_epoll_graph_has_bounded_sampling_work -- --nocapture --test-threads=1
```

实际执行由 `native_session` 排他 lease 和宿主进程检查包裹。编译缓存预热后，
被测调用链耗时为毫秒级。失败与成功日志位于同名 debug 目录。

| 5000 轮相同调用 | 修复前 | 修复后 |
| --- | ---: | ---: |
| 拓扑重新构建 | 20,000 | 0 |
| 嵌套目标查找 | 150,000 | 10,000 |
| 宿主实际耗时 | 13.376 ms | 2.141 ms |

回归以确定的工作量上限判定，耗时只作测量记录。修复前原运行时代码逐字对照
提交 `6f838b1`；仅增加 `cfg(test)` 的每表计数器，没有通过改坏输入或算法
强制制造失败。原始来源及此项对照保存在 `pristine-reproduction-binding.json`。

原因是每次就绪采样/通知/收集都会重新解析全局嵌套图；即使没有嵌套边，传播
仍扫描所有平面 epoll 的 watch。现由全局 OFD 表保留一个有界拓扑缓存，在
实例创建、嵌套边 ADD/DEL、实例最后引用关闭时失效。候选 ADD 独立校验，
不进入缓存。ONESHOT 解除 armed 和 MOD 不改变图结构；解除 armed 的边仍
参与深度、环路检查。没有子边的实例直接跳过嵌套传播。

回归覆盖稳定图工作量，以及预热后嵌套边增删、dup/最终关闭、FD/实例复用、
可达后端采样、环路、深度、EDGE、ONESHOT 和跨 owner 行为。完整
`cosmic-session` POSIX 套件 290 项通过，默认 profile 的 epoll 17 项通过。
原 FD/OFD、epoll、进程、共享对象和页面容量均未调整。

## 真实镜像

使用原 129 项正常目录重新构建，目录中所有 GUI 二进制、源版本和配置保持原
SHA256。新镜像 `artifacts/v017-os-epoll-topology-cache-v1`：

- boot SHA256：`826b2072c12d3b72835cd5b0d545dd890123c8aec09d4f3106442be0ad056e9e`
- kernel SHA256：`da0f6752c30c283e8d259c1833204d9d6fdb9cf0e1e3a1e4015a241b00125382`
- 资源配置：4 CPU、1 GiB、原 `cosmic-time-applet-v1` profile。

原始两轮开关诊断使用未修改的 `tools/os_cosmic_time_probe.py`，输出位于
`artifacts/v017-epoll-topology-calendar-v1`。与前序相同诊断的一轮实测对照：

| 实际客体操作 | 修复前 | 修复后 | 原 15 秒目标 |
| --- | ---: | ---: | --- |
| 打开日历 | 44.897 s | 38.006 s | FAIL |
| 关闭日历 | 16.884 s | 13.425 s | PASS |
| 再次打开 | 53.970 s | 41.867 s | FAIL |
| 再次关闭 | 17.326 s | 14.085 s | PASS |

这是一轮端到端观察，不是延迟分布或通用加速比。标题、完整月份网格和底部
设置文字均匹配；人工复核真实截图可见 November 2026、20 日高亮及完整页脚。
最终输入后 PID 2–6 和原时钟 PID 8 均存活，没有异常退出。两次关闭都回到
本轮输入前的 12 个对象、113 页、20 个映射和完整引用账本；该基线不要求与
另一启动时刻的页面数量相同。关闭后的两张实际扫描输出在指针区域以外各有
177 个时钟文字候选像素。

45 秒截图仍有 143,418 个启动像素，启动检查仍 FAIL；两次打开也仍 FAIL。
完整交互门槛没有被功能匹配结果覆盖。剩余延迟必须继续测量，不能宣称原始
日历性能问题已经全部解决。

聚合证据：`artifacts/v017-cosmic-epoll-topology-evidence-v1.json`，SHA256
`006c0f40cd15b7e7d4776d0460761937ee48adaaa92ba1ce8124dd2abc1a3b9f`。
其中绑定了当前源码/镜像验证、原失败回归、完整测试日志、采样、原始串口、
QMP、实际图像和人工复核；debug 工具均保留在明确的诊断目录。生产镜像没有
临时采样或调试日志，工作量计数器只编译进 `cfg(test)`。

完整 OS、语义桌面首帧和完整 COSMIC 会话仍未验收。整屏分块提交、地址空间
重复构建，以及缺失 applet/应用仍是后续工作；没有把本轮宿主热点修复当作
这些问题的完成证明。
