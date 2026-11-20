# COSMIC panel 的按需连接与失败所有权

后续已接入真实上游时钟并显示，另修复 XKB 加载与共享对象元数据准入；
日历渲染仍有独立 panel 故障，见
[真实 EGL、时钟与日历交互](v17-cosmic-egl-time-applet-20261120.md)。下方保留本阶段证据。

本轮处理正常 session 中 panel 的提前 FD 耗尽、分配失败 panic，以及实际 system
后端错误路径上的 FD 泄漏。保留全部默认配置、完整依赖和原配额，真实 applet
与应用的供给、交互和完整桌面验收仍是独立的后续工作。

## 原始失败与最小回归

原镜像 `artifacts/v017-os-socket-rights-v2` 的正常入口再次运行 90 秒：
`v017-panel-allocation-baseline-20261120` 中 panel PID 6、9 两次退出 134，
core 存活判定 FAIL。公共通知名称存在、45 秒启动色条替换 PASS，不能据此
判定 panel 存活。前序独立追踪已捕获 64/64 FD 下的
`fcntl(62, F_DUPFD_CLOEXEC, 0) -> EMFILE`，调用者为 `get_client_sock` 的 unwrap。

最小宿主回归直接提取固定上游 `spawn_clients` 的三组配置表达式、实际
`get_client_sock` 函数体，使用真正的 UnixStream pair。包含它们的 GUI 类型和
DisplayHandle 是故障注入 fixture，用于精确验证分配顺序及错误传播，不作为
真实 Wayland 后端证据。初次运行 3.401 秒得到：

```text
backend_emfile_is_returned_without_unwinding ... FAILED
configured_ids_do_not_allocate_before_desktop_resolution ... FAILED
healthy_pair_keeps_both_streams_live ... ok
missing desktop entries must not allocate Wayland clients: left 18, right 0
```

后续加入正常退出/停止子进程不分配替代连接的回归，同样在原代码上失败。
原始宿主输出位于 `artifacts/debug/cosmic-panel-allocation-20261120`。

## 按需分配与错误返回

固定 panel 上游 commit 为 `3ce6ce1cec97669f91e809962d9446aaefe8a06e`。
版本化补丁先将三处配置项转换为没有 FD 的 pending 身份，保留顺序和所有名称。
实际 desktop 文件、Exec 命令及 quoting 解析完成后，才创建 Wayland 客户端。
缺失项发布真实诊断；空命令、非法 quoting 和连接分配失败均跳过该次启动，
不再 unwrap。没有删去默认配置中的 18 个 applet 项。

`get_client_sock` 返回实际 `io::Result`，同时传播 socketpair 和 insert_client
错误。退出回调仅在确实重启且退出带错误时创建替代连接；分配失败时停止该次
重启，不在正常退出路径提前持有 socket 或 security context。

v1 完整 panel 已完成构建，四项源码回归也通过。但真实客体回归继续发现了
第二个所有权问题，故没有把这些局部成功当成最终通过。

## 真实后端的 FD 泄漏

`user/ported/panel_allocation_probe.rs` 使用完整 panel 实际选中的 Smithay/Wayland
依赖，包含从同一完整源码提取的 helper、真实 CompositorClientState 和 ClientData。
它先在真实内核中填满 FD 表，再只释放两个槽，让 socketpair 成功而 C 后端的
额外 FD 复制失败。首版实际结果为：

```text
PANEL_ALLOCATION_PROBE HEALTHY_CLIENT PASS
PANEL_ALLOCATION_PROBE PAIR_EMFILE PASS
PANEL_ALLOCATION_PROBE INSERT_EMFILE PASS
failed insertion must return both pair FDs: left 1, right 2
```

失败证据为 `artifacts/v017-panel-allocation-native-v1`。固定版本
wayland-backend 0.3.17 的 system backend 在调用 `wl_client_create` 前使用
`stream.into_raw_fd()`。实际 Wayland 1.24.0 的源码和 API 约定要求失败时仍由
调用方清理输入 FD；绑定直接返回错误，导致一个 FD 丢失所有权。

`ports/cosmic/native-panel-allocation-v2` 因此从完整、校验过的原 registry archive
导出同版本后端，仅在该 C API 调用处保留 UnixStream 所有权：传入借用的 raw FD，
失败时由 Drop 关闭，成功后才 forget 并转移给 C。无需按 FD 数字补关，也没有
在 registry 缓存中直接修改源码。

新原生绑定明确记录在 Cargo patch/lock 中；473 个包的版本与功能、原三成员
workspace、已有三个 native 绑定、原 SDK 和资源边界均保留。原 v1 配方、工具和
失败证据保留，成功 v1 构建使用的生产工具已逐字节恢复并核对原报告哈希。

修复后的原始客体回归五项 PASS，0.632 秒，包含真实凭据、两种 EMFILE、两个
FD 的退还及同一 display 的后续恢复：`artifacts/v017-panel-allocation-native-v2`。
这个结果来自实际 system 后端，不使用宿主故障注入替代。

## 完整构建与目录边界

最终真实 panel 构建为 `artifacts/v017-panel-allocation-build-v5`，完整离线构建
140.314 秒。ELF 为 33,660,976 字节，SHA-256：

```text
a5552ace1f5de7ecb3cbde177775d798b0acf8fa086ed42ef2504078483114f6
```

旧的来源/Mesa 汇总回执在本地已不可用。本轮没有补造这些历史回执，而是独立
重验完整 canonical Git 树、registry 原 archive 与全部解包文件、支持补丁、
固定 SDK origin、实际 native archives 和编译器。构建与独立目录消费者均重验
完整源码、锁定依赖图、原生链接输入、日志和 FullOs ELF 准入。

为保留实际缓存，构建对已验证 target 做 APFS 写时复制，在原临时路径上恢复
字节未变文件的时间戳；仅复用校验过的原 native 搜索路径。修改过的后端及真正
panel 根包重新编译，父缓存树前后哈希相同。旧依赖 cohort 保留在复制的 target
中，helper 消费者用实际链接 panel 的 Cargo unit 与依赖 fingerprint 选择
对应 Smithay rlib，不按目录顺序或时间戳猜选。

正常目录 `artifacts/v017-panel-allocation-catalog-v4` 为 130,450,576 字节，保留
原目录的所有程序与数据，仅替换真实 panel 并补齐六份上游许可证。
独立机制诊断目录为 132,267,824 字节，仅替换一个不参与桌面运行的旧诊断 ELF，
保留同样的五个真实核心组件。两者都在原 128 MiB ROM 上限内。原 SCM_RIGHTS /
notifications 诊断在正常目录中完整保留。

第一次把大型新诊断加入全部原输入时触发的容量拒绝也保留，没有提高上限或
修改原失败结果。每进程 64 FD、原全局对象池、内核栈和构建预算均未增加。
失败编译的缺失宏/trait 导入已补齐；成功构建重新编译实际修改包，没有复用
此前失败的根包产物。

可重复的关键命令（再次执行须选择新输出目录）：

```sh
python3 tools/os_panel_allocation_probe.py --build artifacts/v017-os-panel-allocation-probe-v2 --output artifacts/panel-allocation-recheck
python3 tools/os_cosmic_panel_allocation_probe.py --build artifacts/v017-os-panel-allocation-v2 --output artifacts/panel-session-recheck
python3 tests/host/test_cosmic_panel_allocation.py
python3 tests/host/test_cosmic_panel_survival.py
```

源码故障注入与真实客体检查分开记录；原生编译、QEMU 和需要编译器的宿主回归
均由共享 native lease 串行执行。没有引入临时内核调试日志；生成补丁的脚本保留
在明确的 `artifacts/debug/cosmic-panel-allocation-20261120` 目录。

## 正常会话结果与剩余工作

最终正常镜像 `artifacts/v017-os-panel-allocation-v2/boot.bin`：

```text
e32cc2c55419597290aec5ec33ea153972cbf5eab772db769ce1138ae78c9434
```

独立机制镜像 `artifacts/v017-os-panel-allocation-probe-v2/boot.bin`：

```text
9f13651cbd00b5d4fb6846344c334a3bfa94cf41695aa23d5de8a989b9ab6380
```

`artifacts/v017-panel-allocation-session-v2` 的 90.049 秒实际状态中，原 panel
PID 6 为 Waiting/code 0，九个线程，134 退出为 0 次；五个核心进程均存活，
原 XDG/core 存活检查转为 PASS。独立判定不允许用重启后的新 panel 替代原进程。
公共通知名称在 47.482 秒存在。实际输出包含完整 18 次 applet desktop 缺失诊断。

原 45 秒像素门槛保持不变：45.015 秒剩余启动色条匹配像素 4,154/786,432，
必要的替换检查 PASS；90.049 秒剩余 58。实际查看两张无损截图仍为深色背景与
指针，45 秒还有底部残留启动色条，尚未显示可用 applet 或应用。

日志仍有一次 notifications 点对点初始化 Broken pipe，以及 EGL BAD_ALLOC /
DRI2 设备诊断。后者可能涉及硬件尝试或软件回退，当前证据不足以单独断定最终
阻塞点。panel 存活不能建立渲染、正常 P2P、实际通知或完整桌面成功。
所有完整会话、语义首帧和 applet 功能标记保持 false。

| 最终检查 | 实际结果 |
| --- | --- |
| 同一真实 helper + system backend，FD 压力与错误恢复 | 五项 PASS，0.632 秒；`v017-panel-allocation-native-v2` |
| 正常 session 原 panel 与五个核心服务存活 | 90.049 秒 PASS，零 134；`v017-panel-allocation-session-v2` |
| 正常镜像中的真实 notifications 模块完整 GetFd/action | 六项 PASS，16.792 秒；`v017-panel-allocation-notifications-v2` |
| 正常镜像的 Socket 传递、循环回收及内核对账 | 十项 PASS，2.833 秒；`v017-panel-allocation-socket-rights-v2` |
| 源码片段回归 | 四项 PASS，包含正常退出不分配替代连接 |
| panel 存活判定的负例与作用域 | 四项 PASS |
| 原目录、镜像、XDG、首帧与串口边界 | 21 项 PASS |

宿主的 26 个 unittest 包含一个执行四项真实源码 Rust 子测试的 wrapper，因此
以上宿主检查按实际断言用例计为 29 项，不把 wrapper 再重复计数。新的 Socket
回归仍实测 OFD/暂存/排队引用归零，202 次消息事件与 203 个引用单位释放对账。

下一步是独立验证真实 Wayland-EGL 面板绘制、正常 P2P 初始化，再逐个供给真实
applet/desktop 和缺失的九个 session 程序。18 个真实 applet 的并发容量与整个
桌面的退出回收须在实际程序供给后验收，不能由当前缺失项场景推定。

完整输入、构建、红绿回归、画面和宿主日志 SHA 汇总在
`artifacts/v017-cosmic-panel-allocation-evidence-v2.json`。
