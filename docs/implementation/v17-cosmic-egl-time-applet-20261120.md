# 真实 Wayland EGL 与上游时钟 applet

后续已修复此处定位的 Mesa 分配失败空指针路径，真实日历两轮开关及基线恢复
通过；交互和首帧时限仍未达标，见
[Mesa 失败传播与日历交互](v17-cosmic-mesa-wayland-oom-20261120.md)。下方保留本阶段证据。

本轮在前序 panel 存活修复基础上，先独立验证真实 SDK 的显示链路，再补入
默认配置已经引用、此前缺少的上游 `cosmic-applet-time`。组件通过与完整桌面
通过分别记录，探针色块不能作为 COSMIC 界面验收。

## 真实 EGL 显示链路

`user/ported/wayland_egl_probe.c` 使用与正常 panel 相同的真实 Mesa 26.2.3、
Wayland 和 musl 静态库。没有替代函数表或宿主渲染结果。独立镜像只装真实
compositor、会话总线及客户端；继续使用既有 `cosmic-session` 的资源布局和
96 MiB ROM 配置，没有扩大进程 FD、堆、图像或线程额度。

首次最小初始化在 30.035 秒超时，但客户端尚未到达 EGL：compositor 冷启动
仍处于 shader/首帧阶段。驱动改为等待真实 `first_full_scanout_complete`
信号，仍保留原 45 秒期限。随后真实 EGL 1.5 初始化通过：compositor 准备
35.629 秒，客户端初始化 2.885 秒。DRI2 警告仍出现，因此该警告本身不足以
证明此 SDK 不能初始化 Wayland EGL。

扩展客户端创建真实 layer-shell 表面、128×64 EGL window 和 ES3 context，
用 scissor 绘制左右红/绿区域，逐像素 GPU readback，swap 并等待 frame
callback。宿主读取 QEMU 的实际 framebuffer，固定位置各核对 2,304 个红色
和绿色像素；确认后才通知客户端销毁真实资源并退出。

```sh
python3 tools/os_wayland_egl_probe.py \
  --build artifacts/v017-os-wayland-egl-v2 \
  --output artifacts/<new-egl-capture>
```

`artifacts/v017-wayland-egl-draw-v1/result.json` 九项 PASS：连接、初始化、
layer configure、window/context、readback、swap、frame callback、scanout、
cleanup。冷启动准备 34.538 秒，客户端完整回路 13.249 秒，包含截图握手与
清理，不能作为纯 EGL 性能数据。四项像素判定宿主回归覆盖正确画面、空白/
启动色条、错位/缺色和截断输入。

| 证据 | SHA256 |
|---|---|
| 真实绘制 boot.bin | `cd5725a8a6258025f2db85eebbf1fb3729a87bd7c0a4c6f3a61a5423c6022d7b` |
| 实际 frame-0.ppm | `c25bb373490118f5ef30ef649959379ae15f1b153cd846a21c205b7dfc909b8e` |
| 实际串口 | `b2f76c80daf774985a69851d7e2e1725de7d8aaf326218171b74cff47be42ee3` |

EGL/Wayland 产品库未因此改动。正常 panel 的具体 EGL 诊断仍需按其调用路径
验证；这个独立客户端通过不等于真实 panel 或 applet 已显示。

## 固定上游时钟供给

源码采用 [Epoch 1.10.0 固定提交](https://github.com/pop-os/cosmic-applets/commit/406d1b7d627138fdf4078f654268d3d8774e50f1)，
Git tree `c89eb775d158710941fa6084d21682b68d168f41`。完整 19 个 workspace
成员、原 default-members、GUI 特性、时钟/日历代码和内嵌翻译保留。仅三个
manifest/lock 文件选择现有真实 static Wayland bindings；backend 同时保留
此前验证的 C FD 所有权修复。固定锁缺少的公开依赖单独获取，正式构建继续
`--locked --offline`；每个实际 registry archive、完整 Git checkout 和 SDK
输入独立核验。

前序正常核心目录原始输入为 130,450,576 字节，已经接近原 128 MiB 限制。
新时钟镜像使用独立 `cosmic-time-applet-v1`，依赖原完整核心配置，并要求实际
时钟 ELF 与具有正确 Exec/applet 标记的 desktop entry。ROM 上限为
192 MiB（128 MiB 核心目录加一个最大 64 MiB 的 FullOs applet）；原核心
128 MiB、FullOs 96 MiB 及旧 48 MiB 边界保持原义。八项真实目录生成器回归
通过，其中新增两项先观察到失败，再验证缺失/错误 desktop entry 与容量的
实际拒绝；另有六项 OS 工具、四项 EGL 像素判定回归通过。

正式离线构建 315.847 秒，完整解析图 637 包。真实时钟 ELF 为 25,712,792
字节，SHA256 `c397a806f802382d0136f481008a78a70f1c03f2bb0ceb116d0f63cede2e182c`。
独立 consumer 重新验证全部 retained source、Git/registry 依赖、真实 SDK、
工具链与静态 ELF；原核心所有 120 个输入保持逐字一致，仅增加真实时钟及
原 desktop/icon/GPL、libcosmic 与内嵌字体许可。新目录原始输入共
156,225,591 字节。libcosmic 原有 Open Sans/Noto 字体完整内嵌，并非新画的
文字或替代字体。

构建记录及 consumer 使用归档的精确 producer 源码校验历史构建，允许之后
OS 工具增加新镜像选项；不会把更新后的工具冒充历史 producer。所有执行
Cargo、编译器探测或 QEMU 的正式入口使用同一 native lease。进程 image/heap
64 MiB、stack 2 MiB、64 FD、线程槽、物理池及构建两任务/3 GiB/3,600 秒边界
没有扩大。完整桌面仍须实际 applet 显示和交互验证。

## 实际 winit 键盘失败与静态 XKB

原时钟供给后，真实正常会话已经创建 panel 的子进程（PID 8，parent 6）。
90 秒时该进程的实际 PC 位于 `wayland_client::conn::blocking_read`；后续
180 秒诊断显示它先继续完成初始化，再在真实 winit Wayland 键盘路径 panic。
面板较慢的初始化解释了前一段等待，但不是最终退出原因。

将同一原时钟 ELF 直接连接实际 compositor，完整协议日志证明两轮 registry/
output/seat/shm 交换成功。键盘创建之后，`xkbcommon-dl` 尝试加载
`libxkbcommon.so.0` 和 `.so`，收到 `Dynamic loading not supported`，随后
`winit-wayland/src/seat/keyboard/mod.rs:301:41` unwrap `XKBNotFound`，退出 134。
该最小复现的客户端阶段 3.193 秒，冷启动 compositor 另计，没有调整原首帧门槛。

新增 `user/ported/xkb_dl_probe.rs`，从实际时钟 ELF 的 Cargo 指纹递归选择
真实 `xkbcommon_dl` rlib，而非任选旧缓存。无 compositor 的 FullOs 原生回归
在改动前直接复现同一加载失败。`native-time-applet-v2` 保留原完整 0.4.2
registry 源码和全部 GUI 特性，为 core/Compose 的每个原函数表条目绑定现有
真实 `libxkbcommon.a`。X11 分支保留上游动态加载及原特性，未宣称 X11 会话
通过；没有伪造 loader、空函数或降低输入功能。

相同回归随后五项 PASS：bindings、真实 context、Return/中文 UTF-8 键符、
原始 `en_US.UTF-8` Compose 表的 dead-acute+e→é、清理。客体回路 0.264 秒。

```sh
python3 tools/os_xkb_dl_probe.py \
  --build artifacts/v017-os-xkb-dl-after-v1 \
  --output artifacts/<new-xkb-capture>
```

修复后的完整时钟构建 121.466 秒，仍为 637 包；ELF 25,697,824 字节，
SHA256 `fcec343d0ddb0d7406073897966b86d0fc06d1324460e09a7c1df78e8dfa6bb3`。
独立校验后的完整目录为 156,211,705 字节；原 120 个核心/配置/诊断输入保持，
补充 clock ELF、原数据及许可证。修复前后两份源码、镜像、串口和报告分别保留。

| XKB 证据 | SHA256 |
|---|---|
| 修复前原生 boot.bin | `7ba18e375297f01117f8185f454ca5f8dbbef3d3c0e788bdfb4017e49def53f3` |
| 修复后原生 boot.bin | `1236594a3032ceab4a811617f6725a06b1fd92c80554135903975113e2a7d147` |
| 修复后原生串口 | `dd0a15025480f696b74f7bef1578a39da14c3180fcde77dad65bb3bb27c6cb5a` |

采集器遇到 panic 时保持 FAIL，并有界收集两秒日志尾部，避免在 UART 分块
或两层服务日志转发中截断实际原因。真实 Console 回归验证尾部继续落盘且
失败判定不会转绿。目录八项、EGL 像素四项、Console 四项及 OS 工具六项共
22 项宿主回归通过。

## 日历中止：零字节元数据误用了页面保留策略

修复 XKB 后，正常镜像 `v017-os-time-applet-v2` 的真实面板已显示
“Nov 20, 4:52AM”，180 秒时原时钟 PID 8（parent 6）、五个核心进程均存活。
实际点击使时钟退出 134，日历判定仍为 FAIL。显示出来的旧纹理不能作为退出
之后仍可交互的证明；测试同时检查输入之后原进程存活和异常退出。

独立诊断只用用户级 desktop override 调用 FD/日志保持器，再启动完全相同的
原时钟 ELF。两条真实 Wayland FD 原样传递，正常正式目录不装该 override。
协议日志显示 popup 创建、grab、360×446 configure 和 ack 已完成。关闭协议
噪声、仅保留 panic 回溯后，取得 `softbuffer` 的实际错误：
`Failed to create memfd to store buffer ... OutOfMemory`。当时匿名堆峰值
4,033 页（约 15.8 MiB）、线程峰值 6，未触及原 64 MiB/16 线程边界。
临时 PID 定向内核日志曾使诊断未到原显示阶段，该轮保持无结论；内核源码已
按前像 SHA 完全恢复，临时日志只存在隔离镜像和 debug 目录。

实际 `memfd_create` 独立回归进一步确认：旧代码在 14 个零字节对象之后，
第 15 个返回 `ENOMEM`。`shared_memory::create` 复用了保留两个页槽的 MEMORY
模型；这不是元数据表 16 槽实际耗尽，也不是页面池分配失败。空对象尚未请求
任何物理页，页面保留规则属于后续 resize 的独立准入。

增加专用 `SHARED_OBJECT` 模型 8201：原始槽单位，域 free 0..16、request
1..16，教师为 `free >= request`。训练/留出 217/55，留出全对，并穷举核对
272 个输入无边界偏差；生成权重 `[0, 5, -5, 0]`。全部 11 个旧模型的权重和
记录逐项保持一致，原 MEMORY 函数及其保留行为不变。内核仅为零字节对象
创建选择新模型，并在编译时要求模型域与原 16 槽表一致。实际 Backings 表、
每对象 8 MiB、共享物理页池 16 MiB、resize 页面策略和账本不变。

54 项 AI 测试通过，包含完整新域及旧页面策略保留。修复后的实际 memfd 回归
五项 PASS：16 槽全用、第 17 个拒绝、原页面/对象大小边界、释放复用、第二轮
创建/清理。客体回路 0.260 秒（包含退出后账本采集），对象/映射/描述引用/
页面授予与 OFD 全归零，仍报告 metadata_capacity=16、page_capacity=4096。
第一次账本包装误用了必须实际传递 Socket rights 的检查，程序五项已通过但
包装判 FAIL；改为共享对象自己的真实退出快照后重新运行通过，原失败记录保留。

```sh
python3 tools/build_shared_object_probe.py \
  --catalog artifacts/v017-time-applet-catalog-v3 \
  --output artifacts/<new-shared-catalog>
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --sysroot artifacts/<new-shared-catalog> \
  --output artifacts/<new-shared-image>
python3 tools/os_shared_object_probe.py \
  --build artifacts/<new-shared-image> --output artifacts/<new-shared-capture>
```

独立小镜像复用已登记的 `notifications-peer-probe` 诊断槽；正常镜像仍保留原
通知探针。这些原生回归不把未启动的 compositor 算作通过，也不替代正常会话
的实际日历输入验证。

## 正常会话：真实时钟、日历输出与剩余交互失败

最终正式目录为 `artifacts/v017-time-applet-catalog-v3`，正式镜像为
`artifacts/v017-os-time-applet-v3`。原 120 个核心程序、配置和诊断输入逐字保持，
正式目录不装用户 desktop override 或日志保持器。客体仍为四核、1 GiB；镜像
SHA256 `7ed5cabc8aa2cc17a0b297edd04cd578661e17a1562796270e72edddc13a797d`。

`v017-time-applet-session-v4` 在 180.096 秒显示真实日期/时间，原 PID 8 与五个
核心进程存活。首次点击后 15 秒未见日历，但原进程没有再次出现旧的 memfd
创建中止。自动报告保留 FAIL；不能由这个短观察宣称日历始终不显示或已可用。

另开 `v017-time-applet-session-v5`，原 45 秒首帧门槛和独立 15 秒交互时限不变，
只为排查首次渲染耗时另加至多 60 秒观察。180.047 秒显示真实
“Nov 20, 5:54AM”；点击 39.337 秒后出现日历标题和星期表头，随后实际 framebuffer
也出现完整月份日期网格与当天高亮。QMP 的相对鼠标输入经过真实 VirtIO/客体/
compositor，没有用宿主绘图代替。

本轮不能判为日历交互通过：在开始关闭检查时 panel PID 6 退出 139，随后时钟 PID 8
退出 134、notifications PID 5 被监督器停止为 143。实际异常是 x86 页错误，
写地址 `0x0`、指令 `0x279b384`，已在同一真实 panel ELF 映射为 musl `memcpy`
的 `rep movsq`。退出后的日期网格是缓存画面，
不是原进程仍可交互的证据，第二轮打开/关闭没有通过。打开时共享对象实际
16/16、775/4096 页；这个快照本身只证明元数据槽到边界。

隔离的 `v017-panel-popup-fault-runtime-v1` 进一步取得真实错误和故障栈，正式
五个核心组件与 clock ELF 保持相同。panel 实际 `memfd_create`（syscall 319，
flags 3）返回 `ENOMEM`，紧接 `eglMakeCurrent` 报颜色缓冲区分配失败。故障时
目标参数为 0，实际返回地址 `0x2044c59` 属于
`dri2_wl_swrast_put_image2 + 0xc1`，上层依次为 `drisw_put_image`、
`drisw_present_texture` 和 swap 路径。固定 Mesa 的
`dri2_wl_swrast_get_backbuffer_data` 返回 NULL 后，`put_image2` 没有判空即复制。
分配失败分支还留下已选中的 `back` 指针，因此后续访问不能只凭 `back != NULL`
判断该缓冲区有效；后续修复必须同时覆盖失败回滚和错误传播。
这将剩余问题明确分为真实 16 槽容量到边界与 Mesa 分配失败传播缺口；不能把
本轮修复的旧 14 槽误拒绝当作全部解决。

该隔离轮在第二次点击前已故障，因此最初的“关闭时崩溃”时序不能作为销毁
路径故障的证明；实际故障处于日历首次渲染/后续提交阶段。隔离镜像 SHA256
`d7d1ec0892fb876bed6bcb67544b532577d81b1e28db988304fb2db4fb69efd1`，
串口 SHA256 `3d6bd5ccc864dfbf806eb68ccb54323a6f73e0e25b36a6eb692f679aaaffc8bb`。
本轮没有在原 SDK 缓存中直接改 Mesa、伪造分配成功或静默扩大共享对象容量；
这个真实错误路径尚未修复、重建和验收。

首次采集正好捕捉到分块显示更新，标题先于下方日期网格出现。后续采集器因此
同时检查标题与下方网格，避免将刚出现的表头当作完整日历输出；仍保留人工
截图核对和输入之后原 PID 存活检查。临时故障日志仅用于隔离镜像，正式源码
按 SHA 完全恢复。

正常会话原 45 秒扫描输出仍有 131,130 个启动像素，必要首帧检查 FAIL。180 秒
后画面替换和公共通知名称存在不能改变此结论。完整 OS、COSMIC session、
语义首帧及完整 applet 验收均保持 false；其余默认 applet、应用与服务供给、
正常 P2P 错误、信号退出重启语义和日历渲染的 Mesa 失败处理仍是明确缺口。

```sh
python3 tools/os_cosmic_time_probe.py \
  --build artifacts/v017-os-time-applet-v3 \
  --output artifacts/<new-normal-clock-capture> \
  --observe-seconds 180 --inspect-bus
```

## 最终复核与证据入口

在同一正式 `v017-os-time-applet-v3` 上，Socket rights/循环回收十项再次 PASS
（3.176 秒），真实 notifications 的握手、GetFd 与 action 六项 PASS
（16.546 秒）。最终 22 项宿主回归全部通过，`train_resource_models.py --check`
确认生成权重和记录逐字一致；54 项 AI 测试记录单独保留。永久 memfd 构建器
再次编译出的 ELF 与已实际运行的回归 ELF 逐字相同，SHA256
`0db492b293ae524f236209f30856a517c2c5d18cb4d7bb8697954eb68a460162`。

[本轮聚合证据](../../artifacts/v017-cosmic-egl-time-evidence-v1.json) 绑定真实
ELF、目录输入、镜像、串口、图像、模型、测试日志与精确 producer 源码；正常
会话失败和隔离故障诊断分别保留。人工核对只认可时钟实际显示及日历内容曾
出现，不把缓存画面或未完成的第二轮输入算作完整 applet/会话通过。
