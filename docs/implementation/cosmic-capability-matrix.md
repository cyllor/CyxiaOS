# COSMIC 组件能力与依赖证据矩阵

2026-11-20 Ask Matt 诊断增量：PC RTC 短暂 Busy 时有界重采真实硬件，正常
样本不增加计时器读取，不缓存墙钟。9 项 clock、291 项架构/PC/core、48 项
runtime 与原生烟测通过；原版最终九项重放为 7 通过、2 失败，修复后均通过。
两轮真实日历功能和共享回收通过，四次捕获之和 67.694/73.968 秒，15 秒
整体交互、语义首帧和完整桌面仍未通过。两项性能候选均已回退，本轮没有
新的可靠提速；一次时钟 panic 的因果仍未确认，格式与全仓 CI 不宣称通过。
见 [性能候选取舍、RTC 瞬态恢复与检查范围](v17-cosmic-rtc-uip-ask-matt-20261120.md)。以下保留历史状态。

2026-11-20 Superpowers 回收性能增量：叶表首段连续页复用既有 alias 认证，
逐页覆盖/引用校验及失败前缀保留。46 项 runtime 集成、Rust 工作区 1559 项
与原生页保护/抢占/FP/TLS/堆/IPC 烟测通过。两轮客体复测的归一化回收耗时
分别降低 30.6%/30.3%，四次日历捕获耗时之和由 69/72 秒降到 60/63 秒。
单项交互仍有波动，15 秒整体目标、语义首帧与完整桌面未通过。全量 Python
和格式检查仍有按名登记的失败，不宣称全 CI 通过。见
[回收诊断、先红后绿及实际桌面对照](v17-cosmic-retire-superpowers-20261120.md)。以下保留历史状态。

2026-11-20 内核映射性能增量：有界连续范围共用一次 alias 所有权认证，原
逐页权限、引用计数、成功前缀与资源上限保留。40 项实际 Rust 映射检查、
13 项驱动回归及原生页保护/抢占/FP/TLS/堆/IPC 烟测通过。两轮独立桌面捕获中，
地址空间构建平均减少约 35%；日历首次打开由约 25 秒降到 17.665/18.875 秒，
再次打开为 17.645/18.322 秒。描述缓存候选虽微基准更快，实际打开更慢，已撤回。
关闭波动较大；15 秒打开、45 秒语义首帧及完整桌面仍未通过。见
[内核连续映射、两版取舍与真实桌面对照](v17-cosmic-kernel-mapping-performance-20261120.md)。以下保留历史状态。

2026-11-20 原生显示容量增量：真实游标额外限制为 16 KiB，现使用 ABI 已有的
64 KiB 上限，整屏提交由 192 次降到 48 次。28 项宿主检查通过，完整 468 包
compositor 原版/修复版各完成九项真实 EGL 检查，整张输出图像逐字相同。
正常会话同驱动的两次打开从 45.241/42.995 秒降到 25.666/22.171 秒；关闭为
14.657/10.264 秒，两轮均无异常退出并恢复共享基线。45 秒色条替换转 PASS，
但该时刻仍只有背景和指针；15 秒整体交互、语义首帧与完整桌面仍未通过。
见 [原生提交容量、完整构建与实测对照](v17-cosmic-native-tile-capacity-20261120.md)。以下保留历史状态。

2026-11-20 epoll 性能增量：实际日历计时与指令采样定位到稳定嵌套图的重复
全局扫描。新增有界拓扑缓存及完整失效路径，5000 轮真实 POSIX 调用的重建
次数由 20,000 降到 0；完整 POSIX 290 项和默认 epoll 17 项通过。原 129 项
GUI 目录与资源上限保持，真实两轮开关无异常退出并回到本轮共享资源基线。
关闭由约 17 秒降到 13.425/14.085 秒；打开仍为 38.006/41.867 秒，15 秒整体
交互和 45 秒启动检查仍 FAIL。见
[日历延迟、epoll 热点与实测对照](v17-cosmic-epoll-topology-20261120.md)。以下保留历史状态。

2026-11-20 Mesa/日历增量：已修复真实 16 槽满额时的软件 back buffer 失败回滚、
延迟复制回调判空及两种 swap 的错误传播。原生当前表面/真实 FD 压力复现同一
空指针错误，修复后拒绝、释放恢复与真实 readback/扫描输出共 15 项通过；
七项真实函数宿主回归通过。完整 473 包 panel 与 127 个其他目录输入保持，
原资源上限不变。正常 session 的真实日历已完成两轮开关，五个核心进程与原
时钟 PID 8 在最终输入后均存活，无异常退出，两次关闭均回到共享资源基线。
打开约 45/54 秒、关闭约 17 秒，15 秒交互与原 45 秒首帧仍 FAIL，完整桌面未通过。
见 [Mesa 失败传播、原生恢复与日历两轮交互](v17-cosmic-mesa-wayland-oom-20261120.md)。以下保留历史状态。

2026-11-20 EGL/时钟增量：同一真实 SDK 的 Wayland EGL、ES3 绘制、readback、
frame callback 和实际扫描输出九项通过。已补入固定 Epoch 1.10.0 的真实时钟，
保留完整 19 成员源码、637 包解析图与全部 GUI 特性，正常 session 显示真实
日期和时间。实际定位并修复 xkbcommon-dl 的动态加载失败，以及零字节 memfd
元数据误用页面保留模型而只允许 14/16 槽的问题；各五项客体回归、54 项 AI
与 22 项宿主回归通过，原页面/FD/堆上限保留。独立镜像目录使用显式 192 MiB
ROM profile，原 profile 不变。日历约 39 秒后有真实输出；后续独立故障栈确认
真实 16 槽满额后 Mesa 软件渲染未传播分配失败，panel 空指针复制、退出 139。
交互回归和原 45 秒首帧保持 FAIL，完整会话未通过。
详见 [真实 EGL、时钟与日历故障证据](v17-cosmic-egl-time-applet-20261120.md)。以下保留历史状态。

2026-11-20 panel 分配增量：保留所有配置身份，在 desktop/Exec 有效后才创建
连接；分配错误正常返回，正常退出不预分配替代连接。真实压力回归另定位到固定
wayland-backend 的 C FD 所有权泄漏，现保留 Rust 所有权直到 C API 成功，两个
FD 的退还与恢复五项实测通过。完整 473 包、默认特性、原三成员、18 个配置项及
原资源上限保留。正常 session 原 panel 和五个核心进程在 90.049 秒均存活，
134 从两次降为零，XDG/core 存活判定转为 PASS。完整 GetFd/action 六项及 Socket
回收十项仍通过。画面仍没有可用 applet，正常 P2P Broken pipe 与 EGL 诊断仍在；
完整会话与语义首帧保持未通过。见
[按需连接、错误传播与 C FD 所有权](v17-cosmic-panel-allocation-20261120.md)。以下保留历史状态。

2026-11-19 Socket FD 增量：已补齐 SCM_RIGHTS 的 Socket 支持及有界循环回收。
真实 notifications 模块的完整 GetFd/action 六项回归由 ENOSYS 转为 PASS；
跨进程身份、创建者退出、弱 watch、自身/交叉/有根环、shutdown 链、截断和取消
十项客体回归通过。96 轮交叉环后内核 OFD/引用/消息/watch 全部归零，202 次
消息事件和 203 个引用单位授予/释放对账。原 SCM 十项、POSIX 全套 288 项、
旧配置九项及宿主边界 21 项均通过，产品资源上限保持不变。
正常会话 45 秒替换检查与公共通知名称查询仍通过，但 panel 再次两次 134，
90 秒画面仍只有背景与指针，core 存活与完整会话保持未通过；panel FD 分配、
真实 applet/应用供给和实际桌面交互仍待补齐。见
[Socket FD 传递与引用环回收](v17-cosmic-socket-rights-20261119.md)。以下保留历史状态。

2026-11-19 前序通知握手增量：真实 notifications 已采用版本化 peer-v2 源码修复，
启动等待与公共服务注册分离，并将主动认证期限与现有 panel 的 5 秒期限对齐。
8 秒启动延迟、停滞认证、取消/FD 回收、EOF 四项实际模块回归通过；完整 GUI、
493 包解析图与资源上限保留。正常会话实际注册公共通知服务，90 秒未再出现旧的
服务端认证超时，45 秒启动色条替换检查通过，但画面仍只有背景与指针。
完整协议仍因 socket FD 的 SCM_RIGHTS 白名单返回 ENOSYS 而 FAIL；panel 仍两次
134，前序已捕获其 FD 64/64 后 F_DUPFD_CLOEXEC 返回 EMFILE。正常 P2P 交互与
完整会话仍未独立验收。见 [通知启动、主动认证与 panel FD 缺口](v17-cosmic-notifications-peer-20261119.md)。

2026-11-19 面板/目录增量：已装入固定上游完整 45 个面板默认配置文件及许可证，
真实配置库验证 Panel/Dock、18 个 applet 项和用户覆盖优先级；启动阶段已准备
实际 config/state watch 根目录，真实 inotify 注册及文件创建事件回归通过。
正常 session 的 NoConfigDirectory 与 state watch ENOENT 消失，panel 推进至
8 线程初始化。本轮 45 秒像素诊断仍为部分扫描输出，保持 FAIL；后续观察到
notifications/panel 的 D-Bus 握手超时。完整会话仍未通过。见
[面板默认配置与 state watch 根目录](v17-cosmic-panel-defaults-state-20261119.md)。

2026-11-19 信号/语言增量：x86 `SA_RESTART` 已完成等待唤醒与信号帧恢复语义，
真实 musl 10 项回归通过，正常 session 的 SIGTERM 注册 EINVAL 不再出现。
已补入完整 libX11 Compose、映射/别名及许可证；真实 xkbcommon 在四种 locale
名称下生成正确组合字符。正常 session 在原 45 秒内替换启动色条，画面仍为背景
和指针。panel 配置、九个缺失程序及通知/输入/回收仍待验证，完整会话保持未通过。
见 [信号重启与完整 Compose 数据](v17-cosmic-signals-compose-20261119.md)。

2026-11-19 后续：真实 notifications 已完成固定源码/离线构建与独立安装校验，
正常 session 两次实际启动 notifications（PID 5）及 panel（PID 6），旧通知 ENOENT
已消失。新增显式 `cosmic-core-services-v1`：要求五个核心程序并使用 128 MiB 原始
ROM 目录；既有 profile 上限保留。完整会话仍失败于 SIGTERM 处理器注册 EINVAL，
其他九个默认程序与通知协议/输入/回收仍待验证。见
[通知供给与核心服务目录](v17-cosmic-notifications-sdk-20261119.md)。

2026-11-19 增量：修复会话并行批次中快速返回的进程提前中止其他 CPU 工作的问题，
真实客体 compositor 抢占计数从 3,817 降至 1；dev 配置的 45 秒首帧诊断仍失败。
相同组件的 release 独立 compositor 在 45 秒通过必要的启动色条替换检查。
相同组件的 release 正常会话两次完成 compositor 环境握手并启动 settings，随后
因目录缺少 `cosmic-notifications.elf` 收到 ENOENT 并失败。完整会话保持未通过。
复现、实际对照和下一项供给缺口见
[并行批次与当前启动阻塞](v17-cosmic-parallel-phase-20261119.md)。下方保留历史证据。

2026-11-15 settings 增量：真实 `cosmic-settings-daemon` 1.10.0 已在 x86 客体
运行，完成 D-Bus 配置／状态通知、Wayland registry 交换、GTK3/GTK4 浅色到深色
导出切换和断连清理。当前未移植的音量／亮度变更接口返回真实 NotSupported。
完整浅色／深色默认数据由固定版本 libcosmic 在独立客体生成，每套 39 个键；
已校验回读、规范化字节及上游许可证，并安装为保留用户覆盖规则的系统数据。

为支撑实际服务，full-os 文件系统提供 128 节点、8 KiB 文件、256 KiB 总保留数据
上限及真实符号链接；默认配置保持原边界。同盘恢复、拒绝与复用已有真实客体证据。
完整 OS/会话仍未通过：真实 session 已成功启动 settings，随后通知服务启动收到
EAGAIN。账本为管道 6 次准入、1 次模型拒绝；源码分析定位到 8 槽池的 2 槽保留策略，
不是 8/8 机械耗尽。下一步是多服务管道预算与真实 notifications，再接面板和应用。

见 [真实设置服务与主题数据](v17-cosmic-settings-daemon-20261115.md)。
以下保留此前会话监督与组件阶段的历史记录。

2026-11-15 会话监督增量：真实 `cosmic-session` 1.10.0 已通过 Cyxia 原生进程
接口启动同一真实 compositor，并收到 `WAYLAND_DISPLAY=wayland-1` 握手。
最终启动、明确的后续失败与清理共 126.359 秒，保持原有 180 秒观察时限。
后续实际缺失 `cosmic-settings-daemon`，会话以 ENOENT / 134 结束；未标记完整桌面通过。

真实 launch-pad 的管道、FD/环境/工作目录继承、回调、重启/退避、TERM 超时后
KILL、等待与回收均已有客体证据。同 UID 跨进程信号返回真实发送者身份；
不支持的进程组操作明确拒绝。原生取消回调现保留实际退出码，TERM143、
优雅退出23、强制KILL137分别验证。高频等待轮询导致的启动超时已保留，
有界退避后握手通过；这不是性能认证。

见 [原生会话与进程监督](v17-cosmic-native-session-20261115.md)。下一步是真实
settings daemon、通知服务和面板，以及实际多服务负载所需的管道/进程容量。
完整 OS/会话标记仍为 false。下方为此前配置与总线阶段记录。


2026-11-15 配置增量：已安装固定版本的真实默认配置，实际库解析 116 条快捷键、
26 个系统动作和 35 条窗口规则。缺失 custom 键初始化、已有/损坏内容保留、
真实通知及两组独立同盘恢复均通过；清理后目录同步修复了重启恢复空临时目录的问题。
16 线程父进程的 15 个 waitpid 等待者现全部返回并回收。

同一真实 COSMIC ELF 的配置/语言错误消失；鼠标响应仍有 751 个变化像素，
持续运行 60.037958 秒、10 线程、12,225 堆页，退出后名称与资源回收。
见 [默认配置与持久设置](v17-cosmic-persistent-config-20261115.md)。
下一步是实际 `cosmic-session` 启动与进程监督，再接 settings daemon、通知和面板。
完整 OS/会话标记仍为 false。以下段落保留上一阶段状态。


2026-11-15 会话总线增量：真实 D-Bus 1.16.4 已在 CyxiaOS 运行，支持当前
UID 0 域的 EXTERNAL 认证、消息路由、名称所有权、断连清理和重启；错误身份
被拒绝。新增真实 fsync/fdatasync、`/dev/null`、Unix socket 路径元数据和命名
冲突保护；并发、中断、提交中杀进程、FD 复用及同盘重启恢复均取得客体证据。

完整 OS 配置提供 16 个有物理内存预留的线程槽，实际验证 16 个线程并发、
第 17 个拒绝及槽位复用。修复显示后端把持续提交的整帧误判为超时的问题后，
重新链接的 COSMIC 在真实总线上注册服务，响应鼠标并持续运行 60 秒：
10 个线程、12,199 堆页、751 个光标变化像素；退出后服务名及资源全部回收。
详情与失败记录见 [真实会话总线与 COSMIC 集成](v17-cosmic-session-bus-20261115.md)。

下一步：默认配置与持久设置、`cosmic-session` 的实际启动与监督、面板和应用。
系统总线、服务激活、多用户和完整桌面仍未完成；完整 OS/会话验证标记保持 false。
以下共享页池段落记录此前无会话总线的观测，不是本轮进程资源峰值。

2026-11-15 前一阶段：真实 x86 `cosmic-comp` 已在 CyxiaOS 输出初始深色背景与鼠标
光标。保持同一份 compositor ELF，full-os v3 将每进程匿名虚拟堆扩为 64 MiB，
并从同一个 256 MiB 物理页池按映射分配；客体仍为四核、1 GiB。五进程总容量
争用、拒绝、回收和强制复用被终止进程的至少 15,328 个物理页均通过，逐字清零
检查与额度账本平衡。此前 32 MiB 堆不足导致的 notify SendError 未再出现。

真实 COSMIC 随后响应 `(320,240)` 鼠标移动，实际 scanout 的旧光标清除、
新光标出现，共 751 个像素改变；持续运行 60 秒，堆保持 11,128 页、八线程。
显示完成计数从 192 增至 384，单位为分块显示操作，不能当作桌面帧数。
终止后匿名页、图像页、共享对象、线程及文件描述全部回收。
这证明初始输出、鼠标响应和有界持续运行，**尚非完整 COSMIC 会话**。
下一步是实际会话与系统 D-Bus、默认配置、会话/面板/启动器和应用交互；
`readlink` 等 ABI 缺口、持久化与完整 OS 服务也仍需推进。

运行时目录、OFD 文件锁、嵌套 epoll、inotify、分离线程退出、官方 XKB 数据及
只读文件映射已有先前真实客体证据。见
[共享页池与真实 COSMIC 输出](v17-cosmic-shared-heap-20261115.md)、
[键盘资源](v17-cosmic-xkb-assets-20261115.md)、
[线程退出修复](v17-x86-detached-thread-exit-20261115.md)、
[inotify](v17-cosmic-inotify-20261115.md) 和
[原生构建](v17-cosmic-native-20261115.md)。完整 OS/会话验证标记保持 false。
下方 2026-10 月清单保留当时的依赖与工具边界；其中“全部未构建/未运行”
及仅支持 ARM 的描述属于历史状态，当前进度以上述链接为准。

2026-10-22 最新：[Smithay 锚定缩放与抓取清理](smithay-resize-native.md) 已通过三次独立客体验收，增加左上角/左边缘的位置与尺寸联合提交、反向缩放、普通重绘，以及按钮仍按住时关闭窗口并处理背景释放。八方向几何有单元测试，客体只声明左上角/左边缘；每次十二个实际显示场景。上一轮移动/右下角缩放回归通过。尚未运行下表的 cosmic-comp；动态客户端接入、通用窗口管理与完整会话仍待实现，30 个组件的状态不变。

2026-10-22 先前阶段：[Smithay xdg-shell 生命周期](smithay-xdg-native.md) 已验证配置/确认、激活、尺寸变更、关闭和错误客户端隔离后继续服务，客户端依次运行。

2026-10-22：[Smithay Wayland 原生显示与输入](smithay-wayland-native.md) 已通过三次独立客体验收，包含共享缓冲区、真实 GLES 渲染、六帧逐像素 scanout 与键鼠事件。该 `wl_surface` 集成没有运行下表的 `cosmic-comp` 或 COSMIC 会话；30 个组件的完成状态保持独立。

2026-10-20 后续基础层增量：[Mio 事件循环](rust-reactor.md) 与
[Smithay 高层渲染器](smithay-static-renderer.md) 已在 CyxiaOS ARM 客体运行。
它们属于依赖基础验证，以下 30 个 COSMIC 组件状态保持独立，未据此标记任何组件完成。

2026-10-18。范围固定于 epoch `364341d52454bf3a016d03185c6aff887247aab7` 的 30 个 gitlink。本轮完成 P1 的有界元数据取证和构建工具基础，**尚未完成 G-LOCK 的全传递依赖闭包，更未构建或运行 COSMIC 组件**。

证据入口：[dependencies.json](../../ports/cosmic/dependencies.json)、[resource-profile.json](../../ports/cosmic/resource-profile.json)。原始固定提交文本及 Git tree 保存在 `artifacts/cosmic-metadata/<component>/<commit>/`。30/30 组件成功取证，包含 27 个根 Cargo.lock、94 个 Cargo.toml，选中文本共 6,531,041 字节；其余三项为资产组件。根锁中的 package 数包含各组件重复依赖，不能相加当作独立 crate 数。

每个文本文件核对固定 tree 的 Git blob SHA1，并记录 SHA256、字节数和官方 URL。取源未递归 clone、未下载图标/壁纸/声音等资产内容。Git tree 中的 blob 大小不是安装体积：LFS、生成产物、外部依赖和运行时数据仍未计入。许可证原文和 Cargo 中声明已留证；整体许可证兼容/分发义务审查尚未完成。

## 全量组件索引

2026-10-20 基础层增量：单调 timerfd、Mesa compute dispatch 分配失败恢复、
Smithay 生成绑定的 Rust 静态 EGL 客体探针已分别取得运行证据，见
[移植记录](cosmic-port.md)。这些依赖基础层的通过不改变下表 30 个 COSMIC
组件的 guest 状态，也不代表完整 Smithay 或 COSMIC 已运行。

下面的“首次阶段”只表示集成顺序。C1/C2 是开发会话/预览；认证、网络、音频、门户、包管理与余下功能仍是 C3 强制项。每个组件的 guest 状态均为未构建、未验收。

| 组件 | Cargo manifests / lock packages | 根默认 features | 首次阶段 |
|---|---:|---|---|
| `cosmic-app-library` | 1 / 697 | wgpu | C1/C2→C3 |
| `cosmic-applets` | 20 / 796 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-bg` | 2 / 353 | avif | C1/C2→C3 |
| `cosmic-comp` | 2 / 698 | systemd | C0 |
| `cosmic-edit` | 1 / 904 | dbus-config, gvfs, wgpu, wayland | C1/C2→C3 |
| `cosmic-files` | 3 / 912 | bzip2, dbus-config, desktop, gvfs, io-uring, lzma-rust2, notify, wayland, wgpu | C1/C2→C3 |
| `cosmic-greeter` | 3 / 858 | logind, networkmanager, upower, systemd | C3 |
| `cosmic-icons` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-idle` | 2 / 297 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-initial-setup` | 2 / 796 | a11y, wgpu, wayland | C3 |
| `cosmic-launcher` | 1 / 740 | wgpu | C1/C2→C3 |
| `cosmic-monitor` | 1 / 706 | dbus-config, nvml, wayland, wgpu | C1/C2→C3 |
| `cosmic-notifications` | 3 / 654 | systemd | C1/C2→C3 |
| `cosmic-osd` | 1 / 718 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-osk` | 2 / 686 | wgpu | C1/C2→C3 |
| `cosmic-panel` | 4 / 555 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-player` | 1 / 754 | mpris-server, xdg-portal, wgpu, wayland | C3 |
| `cosmic-randr` | 4 / 79 | workspace，需逐 member 核对 | C0/C2 |
| `cosmic-screenshot` | 1 / 199 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-session` | 1 / 176 | logind, systemd | C1/C2→C3 |
| `cosmic-settings` | 11 / 914 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-settings-daemon` | 9 / 720 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-sound-theme` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-store` | 2 / 842 | dbus-config, desktop-systemd-scope, flatpak, logind, notify, single-instance, wgpu, wayland, xdg-portal | C3 |
| `cosmic-term` | 1 / 850 | dbus-config, wgpu, wayland, password_manager | C1/C2→C3 |
| `cosmic-viewer` | 8 / 760 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-wallpapers` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-workspaces-epoch` | 1 / 699 | wgpu | C1/C2→C3 |
| `pop-launcher` | 5 / 368 | workspace，需逐 member 核对 | C1/C2→C3 |
| `xdg-desktop-portal-cosmic` | 2 / 924 | systemd | C3 |

`cosmic-applets` 包含 20 个 Cargo manifests，不能按一个仓库预算一个进程。`cosmic-viewer` 也有多个 workspace 成员。`cosmic-theme-editor` 与 `simple-wrapper` 不属于固定树中的这 30 个 gitlink；仍保留额外依赖/范围差异核对任务。

## 已发现的具体接口与默认特性风险

| 证据 | 待关闭能力 | 验收边界 |
|---|---|---|
| cosmic-session 固定 `src/main.rs`；至少 14 个启动意图，先取得 session bus 名称 | 独立进程、继承 socket/FD、readiness、wait/SIGCHLD、bus 生命周期与有界重启 | 14 是源码启动意图，不是实测峰值；还要加 bus、applets、启动器插件、用户应用与恢复余量 |
| cosmic-config / atomicwrites / notify 依赖 | 按 key 原子替换、真实变更通知与配置持久性 | rename、连续修改、溢出、目录同步与断电恢复；不是跨 key 原子事务 |
| cosmic-files 默认 `io-uring,gvfs,notify,wgpu,wayland` | Linux I/O、卷/挂载服务、事件和渲染闭包 | 每项实现或在开发 profile 显式关闭并登记 C3 差异；不能仅去掉 default 就宣称完整功能 |
| cosmic-term 默认 `password_manager`；真实 PTY 与子进程仍必需 | 密码/密钥服务、PTY、作业控制、终端渲染及字体 | 没有凭据服务时明确不可用；不向成功空实现交付秘密 |
| cosmic-monitor 默认 `nvml` | 真实进程/内存/CPU 观测及可选设备后端 | 用内核可信统计替换 Linux 假设；缺 GPU 不伪造 NVML 数据 |
| greeter 的 PAM/greetd 依赖；默认 logind/networkmanager/upower/systemd | 真实账户、凭据、会话授权/锁屏与适用设备服务 | mock/自动登录只允许开发阶段；C3 必须验证错误密码拒绝和用户隔离 |
| applets 的网络/音频服务依赖 | 实际网络栈、DNS/TLS、音频 PCM/路由与状态服务 | UI 状态必须来自真实服务；当前没有这些完整子系统 |
| Store 默认 Flatpak；Player 的 GStreamer；Portal 的 PipeWire/GBM/GVfs | 包管理与签名更新、媒体同步、门户前端/权限/后端 | 安装更新卸载、实际音频输出、文件选择/截图录屏行为分别验收 |

每项原始入口及行号位于 `service_entrypoint_evidence`；直接依赖的 target/workspace 作用域位于 `cargo_manifests.*.dependencies`。`declared_native_or_service_candidates` 只是名称筛选，不能替代完整 native 库、服务方法或 feature 解析。

## 尚未闭合的任务

1. 对每个 Cargo workspace 解析所选 package/bin/target/features 的完整锁定图，审计 Git 子模块和本地 path 依赖，准备带校验和的离线缓存；目前仅留存锁文件，没有 vendoring。
2. 对所有 libcosmic/protocols/settings-daemon 的跨组件 revision 差异做接口兼容核对；不能直接强制合并版本。
3. 枚举 native 链接、运行时 dlopen、插件、shader、fonts/locales/MIME/desktop 文件以及安装后的资产路径和体积。
4. 把服务入口扩展成完整 D-Bus 名称/对象/方法/信号/激活/权限矩阵，单列 epoch 外的 bus、greetd/PAM、网络/音频服务、portal 前端与包后端。
5. 选定可执行的图形 profile，处理 EGL/GLES、库加载和真正所需运行时；当前没有已批准的 compositor 构建 recipe。
6. 在逐组件链接、运行后补测 ELF/BSS/RSS、FD/线程/进程和共享缓冲高水位，更新物理布局与 AI 输入域/模型/账本。源码大小与启动意图不能代替运行测量。
7. 为每项业务功能补上正常、拒绝、设备缺失、服务死亡、持久化和资源回收场景；未完成项持续进入 C3，不能删除分母。

## 可执行工具与边界

```sh
python3 tools/cosmic_dependencies.py inventory --output ports/cosmic/dependencies.json
python3 tools/cosmic_dependencies.py fetch --component cosmic-session
python3 tools/build_cosmic.py check --component cosmic-comp
python3 -m unittest tests.host.test_cosmic_dependencies tests.host.test_cosmic_build tests.host.test_cosmic_ports -v
```

默认 inventory 离线；`fetch` 是明确联网动作，只取得有界固定版本元数据。`fetch --all` 表示同样的 30 项元数据，不是递归源码或依赖下载。已缓存文件会先重新校验，既有内容被修改时拒绝继续。

`build_cosmic.py check --component cosmic-comp` 当前应拒绝缺少 reviewed recipe；这不是 COSMIC 构建失败或已有基础门禁失效。真正构建使用 `build --component NAME --recipe PATH --output NEW_DIRECTORY`，只选一个 package 和一个 bin，强制 `--locked --offline`。不得传任意附加 Cargo 参数。

Recipe schema 1 必须给出 `component/commit/target`、`purpose=bounded-build-experiment`、`package/binary`、`resource_profile`、显式 `default_features/features`、原始及补丁后 `source_lock_sha256/effective_lock_sha256`、带路径/hash 的 `patches` 和 `native_inputs`。native 输入至少包括固定 musl、compiler-rt、crt1/crti/crtn。文件位于 recipe 自身目录，路径不能逃逸；补丁只作用于临时导出的源树。

源码必须是已取得的独立 Git checkout，HEAD/origin 与 epoch 一致、没有修改或额外 ignored/untracked 输入。工具不会 reset/clean/更新源树。含未物化 gitlink 或 Cargo config 的源码会拒绝，后续必须先做明确的移植审查。

独立 Cargo cache 默认 `artifacts/cosmic-cargo-cache`，需另行准备且不得借用全局用户 Cargo home、配置文件或外部 registry/git 目录链接。缓存准备/联网取依赖不包含在构建动作中。Cargo 从仓库外的临时控制目录运行，避免继承项目或上游 `.cargo/config`；Cargo target 独立于内核。

宿主工具和目标 CC/AR/pkg-config 分开配置；目标 .pc 文件输出宿主绝对 include/library 路径会被拒绝。目标 musl/CRT/库和 Rust 标准库记录身份并检查 ARM64 架构。只暴露官方目标 libunwind，不把 Rust 自带另一套 libc/CRT 混入。当前工具只支持既有静态 ET_EXEC profile，动态加载需要后续 P5L 的实际实现。

构建采用共享 sysroot 锁，开始时要求空间留量加构建预算，运行时检查空间、输出/临时目录及缓存增量；超时或超限终止整个子进程组。此限制是周期检查，**不是硬磁盘 quota 或构建脚本网络沙箱**。Cargo 禁止联网解析/下载，受信任的 build.rs 仍是本机程序；报告明确此边界。

每次保存 recipe/源树/补丁/工具/依赖源树/sysroot/最终 ELF 身份；链接后执行真实 AArch64 ET_EXEC、LOAD/W^X、静态符号、映像和初始栈额度检查。失败日志留在新输出目录，已有输出不会覆盖。`cross-built` 只证明链接与映像检查，不提高 guest/session 状态。

## 资源与实验判据

`resource-profile.json` 记录已冻结 r3 基线约束、原有探针实际大小/hash、30 项源码文本大小、会话启动下界及所有未测量字段。P2 后的新容量应另行实测更新；不能把 r3 的上限当作全套 COSMIC 预算。

初始 static-bootstrap 构建实验：1 个构建 job、15 分钟 deadline、2 GiB 构建增长上限、持续保留 2 GiB 空间、既有 16 MiB 映像池并计入 256 KiB 初始栈。新输出尚未验证；超限应报告失败并进入资源 profile 评审。

图形/交互实验先固定 1024×768、像素/丢消息/引用/账本错误为零；至少 100 个交互样本，输入到呈现 P95 不超过 250 ms、启动就绪期限 60 s、稳态观测 60 s。这些是未来实验初始判据，不是已达到的性能。改判据须先新建版本、保留旧失败，不能看结果后降门槛换 PASS。

主机测试使用真实临时 Git、真实子进程和真实小型 Cargo fixture 验证路径/身份/污染/资源拒绝；有目标 sysroot 时，小 fixture 完成 ARM64-musl 交叉链接，不下载依赖、不构建内核、不运行 guest，也不被计为 COSMIC 组件移植。
