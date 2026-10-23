# COSMIC 客体移植：源码、运行时与协议基础

更新于 2026-10-22。本阶段已固定官方源码，完成真实 Rust 标准库、Wayland、libxkbcommon 及 Smithay 原生表面显示/输入、xdg-shell 生命周期、双窗口合成/焦点和交互移动/缩放的有界客体集成，并提供可重复构建和 ARM/QEMU 门禁。**尚未编译或运行 CyxiaOS 客体内的 cosmic-comp，也未实现完整 COSMIC 桌面。** 现有 Xorg/Openbox/LXPanel 桌面的验收不计作 COSMIC 验收；宿主 macOS/Linux 的窗口也不计作客体移植结果。

后续工作按 [COSMIC 移植实施计划](../../CyxiaOS-COSMIC-port-plan.md) 推进：对象/共享缓冲与真实 EGL 路线先验，随后交付合成器、核心开发会话、原生核心桌面和完整冻结套件。计划列出每阶段依赖、AI 资源契约、验收与替代路线；不改变本文记录的已完成范围。

## 按计划实施的新增进展

- 2026-10-22 最新：[锚定缩放与抓取清理](smithay-resize-native.md) 在三次启动中各完成十二个实际场景、十个缓冲提交和十一组配置确认。左上角/左边缘缩放将位置与尺寸一起绑定到真实 ACK 和匹配缓冲；普通重绘保留新原点。按钮按住期间关闭所有者后，没有恢复已关闭表面的焦点，背景释放也没有被误发给剩余客户端。八方向几何有单元测试，客体本轮覆盖左上角/左边缘。累计 442,368 个显示像素、45 次 QMP 输入命令、108 次 AI 显示完成，资源全部归还；旧交互三次回归及原桌面 21 组回归通过。动态客户端接入、Escape 回滚、通用窗口管理与 cosmic-comp 尚未完成。
- 2026-10-22 先前阶段：[交互移动与缩放](smithay-interactive-native.md) 在三次启动中各完成十二个实际场景、八个客户端缓冲提交和九组配置确认。真实鼠标事件驱动 xdg move/右下角 resize；无效、已释放及另一客户端的仍有效序号均被拒绝。移动后普通重绘保持新位置，缩放包含反向移动，关闭后剩余客户端继续响应。累计 442,368 个显示像素、42 次 QMP 输入命令、108 次 AI 显示完成，资源全部归还。
- 2026-10-22 先前阶段：[双窗口原生集成](smithay-multi-native.md) 在三次启动中各证明两个独立客户端同时存活、十个重叠/置顶/关闭场景、七组真实配置确认，以及关闭上层窗口后剩余窗口继续响应。累计 368,640 个实际显示像素、63 次 QMP 输入命令、90 次 AI 显示完成，资源全部归还。堆叠与命中测试抽成独立有界模块。首次并发运行暴露的 64 字节日志短写问题以有界原子记录修复，失败证据保留；没有扩大内核日志预算。
- 2026-10-22 先前阶段：[xdg-shell 原生生命周期](smithay-xdg-native.md) 完成真实 configure/ACK、Activated、resize、close 和未配置缓冲区的错误连接隔离；三次启动中每次先拒绝错误客户端，再完成两个正常客户端，显示与资源回收全部通过。fat LTO 将总启动页数从模型拒绝的 4039 降至批准的 3976，保持模型与容量不变。该阶段的客户端依次运行；并发增量见上。
- 2026-10-22：[Smithay Wayland 原生集成](smithay-wayland-native.md) 已通过三次独立 ARM 启动，每次由两个真正的 libwayland 客户端完成六帧、73,728 个实际显示像素和完整键鼠事件。上游 `wl_surface`、共享池、GLES 渲染、frame callback、buffer release 与原生 VirtIO 显示连通；18 张实际 scanout 共检查 221,184 个像素，全部资源归还。新增 `poll(epollfd)`、接收消息地址缓冲兼容、memfd 写封印、全封印私有快照和 memfd 定位 I/O 均另有 guest 回归。该阶段不覆盖 xdg-shell、多窗口管理、动态 pool resize 或 COSMIC 会话。
- P1 已逐项获取并核对 30 个固定组件的 Cargo 元数据，提供离线、锁定输入和资源预算的 [构建入口](../../tools/build_cosmic.py)；[盘点报告](../../artifacts/cosmic-p1-r1/summary.json) 与 [能力矩阵](cosmic-capability-matrix.md) 保留完整依赖闭包尚未 vendored、真实 COSMIC 尚未构建的状态。
- P2 的 [全局 OFD 与跨进程继承](shared-open-descriptions.md) 已冻结：12 组 ARM 客体门禁通过，包括三次独立启动的 14 阶段对象测试和原桌面回归。当前全局 128 OFD、16 epoll，每进程 16 FD、每创建者 2 epoll、每实例 16 watch；容量扩展仍待实际工作负载。
- P3 的 [SCM_RIGHTS](scm-rights.md)、[共享页 memfd/MAP_SHARED](shared-memory.md) 和 [真实 wl_shm 固定池协议](wayland-shm.md) 已各通过三次独立客体运行。wl_shm 每次由两个独立客户端完成四帧、9696 像素的精确检查，包含 FD 导入后的实时共享写入、frame.done、buffer.release、第二客户端重连及真实 keymap FD 传输；最终对象、引用、页和 AI 额度全部归还。动态池扩容、屏幕图像及完整 G-SHM 仍分别待验收。
- P4a 已加入 [CLOCK_MONOTONIC timerfd](timerfd.md) 和 [边沿触发 epoll](epoll-edge.md)：通知来自实际读写/连接/关闭及到期事件，覆盖重复 eventfd 唤醒、部分读写、PTY 行纪律、OFD 复用、oneshot/MOD 及过去绝对期限重设。三次独立启动各完成 136 项边沿与 sendto ABI 检查。[真实 Mio 1.1.1](rust-reactor.md) 已在三次客体进程中各通过 21 项检查和两项到期时间观察；临时信号掩码、嵌套 epoll、Tokio/calloop 仍未验收。
- P5 的 [真实 Mesa softpipe 静态移植](mesa-softpipe-port.md) 已在 ARM64 客体完成三轮 GLES3 离屏测试和三轮 Xorg 窗口呈现，每轮实际显示的 4096 像素精确匹配。默认约 192 MiB 预分配纹理缓存改为按 sampler view 分配，并修复重新绑定的旧缓存问题。本次 r9 修复已编译 compute shader 的 dispatch 准备阶段 OOM：保留原 8×8 工作组，真实 GL_OUT_OF_MEMORY、4096 个 SSBO 值不变、小工作组恢复均重复验证，六次启动共 18 个失败/恢复循环；旧 r8 同探针对照仍复现原分配故障。shader 编译/创建等其他 OOM 路径和完整 G-EGL 仍未验收。
- P5L 已从生成绑定推进到 [真实 Smithay 高层 EGL/GLES 渲染器](smithay-static-renderer.md)。固定上游 `EGLDisplay/EGLContext/GlesRenderer` 在 ARM 客体实际创建全部七个着色器程序，完成清屏、纯色绘制、纹理导入/更新、离屏目标替换与回读；三次进程各核对 1087 个 RGBA 像素并完整释放资源。Mesa r10 显式采用 4 KiB NIR GC slab，保持 16 MiB 匿名池与本地 AI 准入，原始编译 OOM 失败证据保留。winit、Wayland 合成呈现及 cosmic-comp 仍未运行。

下面 r3 表格及其事件限制描述先前冻结的基础版本；新增范围以上述独立门禁为准。

新的 [共享基础资源配置](../../ports/cosmic/resource-profile-shared-v1.json) 绑定当前内核、模型与协议报告，明确每进程与全局容量、模型 API 输入域和既有特征转换；原 P1 配置保持为历史冻结记录。它是已测子系统配置，不能用于宣称完整 COSMIC 会话容量已足够。

[共享基础联合报告](../../artifacts/cosmic-shared-r3/summary.json) 记录 18 组同镜像客体检查通过，包括 LXPanel、文件管理器、菜单、终端、存储保存与重启恢复。303 项默认 Rust、138 项 large-memory POSIX、135 项 Python 测试通过；两套 Rust 测试存在重叠。旧失败报告保留；测试程序短写、已回收进程槽和菜单焦点时序问题均以新证据重验。格式化后重建内核与已测试镜像逐字节相同。

2026-10-20 的 [实施汇总与最终源码清单](../../artifacts/cosmic-port-20261020/summary.json) 同时绑定共享基础、Mesa 离屏/X11、缓存缺陷反向对照和剩余阻塞。两种配置分别冻结测试，Mesa 诊断镜像未装入完整 LXPanel/PCManFM 组合；现有 52 MiB 启动目录预算及会话容量未被静默扩大。

后续 [timerfd / Mesa r9 / Rust EGL 联合报告](../../artifacts/cosmic-port-20261020-r1/summary.json)
绑定本次三个独立内核配置、构建输入与源码清单。原桌面配置在 Clippy 调整后
重新构建、重新运行；终端回归另修正窗口缩放完成及 shell 实际停驻的观察屏障，
保留首次失败记录。旧库计算分配对照明确记录预期进程故障，不计作 EGL 通过。
该历史报告的 Smithay/Mio 未完成状态由后续独立门禁更新：
[边沿通知与 Mio](../../artifacts/cosmic-reactor-r3/reactor/summary.json)、
[Smithay 渲染器](../../artifacts/smithay-kernel-r3/runtime/summary.json)。
上述历史渲染基础见 [2026-10-20 汇总](../../artifacts/cosmic-port-20261020-r2/summary.json)。
最新 [2026-10-22 联合报告](../../artifacts/cosmic-port-20261022-r5/summary.json)
绑定 Smithay 锚定缩放/抓取清理、上一轮移动/右下角缩放回归与同内核源码的原桌面 21 组回归。内存、ELF 与
52 MiB 启动目录限额未扩大；Smithay 与 LXPanel 使用各自显式选用的镜像。
本地 AI 仍负责资源准入、CPU 派发和显示提交节奏，输入顺序、权限与协议由确定性机制执行。

## 已完成的客体基础层

统一冻结镜像 `artifacts/cosmic-bootstrap-r3/cyxia-kernel.elf`，SHA256：`0d31c3fcb2668b67b31a9e1388c62579f32025aefc47babbb121560c595e2b5d`，配置 `graphics,lxpanel,large-memory,spawn-test`、单核 ARM64、512 MiB。各门禁校验当前探针的完整 ELF 字节恰好嵌入一次，记录进程退出、线程清理和页资源归还。

[联合报告](../../artifacts/cosmic-bootstrap-r3/summary.json)：**9 组同镜像 ARM/QEMU 门禁全部 PASS**，含本轮四组基础层及旧桌面的线程、AI 联合、显示、终端、存储回归；274 项主机 Rust 测试、128 项 large-memory 配置测试（与默认配置有重叠）、109 项 Python 测试通过，主机/ARM 基础/ARM 桌面 Clippy 均无警告。报告同时明确 `cosmic_comp_guest_running=false`、`cosmic_session_ready=false`，并绑定源文件清单与各报告 SHA256。

| 已执行内容 | 真实证据与范围 |
|---|---|
| 官方 Rust 1.95 标准库 + 目标 musl | [两轮八阶段](../../artifacts/cosmic-bootstrap-r3/rust-std/summary.json)：启动/Vec、HashMap、备用信号栈、文件、线程/TLS/同步、超时、futex 位集、睡眠中断与绝对期限；[实现说明](rust-std-foundation.md) |
| Linux 事件与流消息 ABI | [55 项检查](../../artifacts/cosmic-bootstrap-r3/events/summary.json)：level epoll/oneshot/半关闭、向量消息、明确拒绝 FD 附属数据、错误不发送前缀、真实阻塞唤醒、超时不提前、阻塞 FD 复用不误读新连接 |
| 未修改的 upstream libwayland 1.24.0 | [连续三轮](../../artifacts/cosmic-bootstrap-r3/wayland/summary.json)：同一进程的客户端及服务器线程，真实 registry、wl_output 和两次 sync roundtrip；[构建与边界](wayland-foundation.md)。这不包含像素、独立进程共享映射或 wl_shm |
| 未修改的 upstream libxkbcommon 1.13.2 | [连续三轮，每轮 24 断言](../../artifacts/cosmic-bootstrap-r3/xkbcommon/summary.json)：真实内存 keymap、Shift/Caps/Ctrl、序列化与非法输入拒绝；[构建与边界](xkbcommon-foundation.md)。尚未接入 COSMIC 物理键盘流程 |

新增 ABI 属于现有 Linux AArch64 personality，未创建 Linux 内核或旁路宿主服务。模型仍在客体执行：进程/线程与 socket 池准入使用既有 8193，匿名页 8194、ELF 8195，CPU 排序/时间片 12289/12290。r3 的 epoll 元数据原来包含在进程对象内；P2 已迁入全局 OFD 表，创建者额度仍为两实例、每实例 16 个 watch。协议顺序、信号帧、FD 所有权、熵内容和键位解释是确定性机制。

r3 事件接口限制：不支持 epoll edge-trigger、嵌套或临时信号掩码；未连接 stream 注册直接返回 ENOTCONN；只有 connected/listening stream 可监视。r3 的 SCM_RIGHTS 在发送任何 payload 前返回 ENOSYS，尚无文件共享映射；P3 的新增支持与边界见上方专项记录。睡眠支持相对 CLOCK_REALTIME/MONOTONIC 和绝对 MONOTONIC；绝对 REALTIME 返回 ENOSYS。Rust 的通过子集不等于完整 std、Tokio/calloop 或 COSMIC 依赖闭包通过。

本轮真实失败及修复保留在 r0/r1/r2：shell catalog 命令接入遗漏、mmap 未接受 Linux MAP_STACK 提示、毫秒等待提前、缺少 clock_nanosleep。独立审核另修复 socket 等待的 FD 复用和普通 signal handler 更改备用栈后的返回语义。最终报告只汇总 r3 的同一镜像证据，旧失败不被覆盖。

## 源码基线

[manifest](../../ports/cosmic/manifest.json) 固定以下官方来源：

| 项目 | 固定提交 | 用途 |
|---|---|---|
| [cosmic-epoch](https://github.com/pop-os/cosmic-epoch/tree/364341d52454bf3a016d03185c6aff887247aab7) | `364341d52454bf3a016d03185c6aff887247aab7` | 整套组件的版本基准 |
| [cosmic-comp](https://github.com/pop-os/cosmic-comp/tree/41497b42d9744d9963c4c6d17e8add49489b45ee) | `41497b42d9744d9963c4c6d17e8add49489b45ee` | 与 epoch gitlink 一致的 compositor |
| [Smithay](https://github.com/Smithay/smithay/tree/e3d461a057ba244d213a8498ec372b0799cca103) | `e3d461a057ba244d213a8498ec372b0799cca103` | 该 compositor 的 Cargo.lock 依赖 |

epoch 的 Git tree 有 **30 个组件 gitlinks**，每个完整提交和官方 URL 均列入 manifest；`.gitmodules` 另有 `simple-wrapper` 条目，但该 tree 没有对应 gitlink。工具单独报告该遗留条目，不推测提交、不下载其可变分支。

compositor 的 `Cargo.lock` 有 698 个 packages、14 个不同 Git source pins，SHA256 为 `ecfa6705314e3821534170a01afd5014478fd4800bd699abb7ccd04b7dfb34b8`。完整 lock 文件由固定提交提供，SHA256 覆盖 registry checksums 和所有包版本；14 个 Git pins 另行完整列出。**这不是整个 epoch 所有组件的传递依赖闭包已下载或已审计的声明。**

最初审查的 compositor master `742b800b518f0dafd89d0c1ace4de4935334ed18` 留在 `artifacts/cosmic-sources/cosmic-comp`，其 Smithay pin 是另一个版本。选定移植版本位于 `artifacts/cosmic-sources/cosmic-comp-epoch`；二者明确分开，避免将 master 依赖混入 epoch。首次取得的时间、官方 URL 和提交时间保留在 `artifacts/cosmic-sources/cosmic-comp-source.json`；移植 manifest 记录 epoch/comp 的提交时间和审查时间。

## 可复现检查与取源

[tools/cosmic_ports.py](../../tools/cosmic_ports.py) 默认离线只读。它检查真实 Git HEAD、origin、干净工作区、epoch 的完整 gitlink/URL 集合、Cargo.lock 内容、Rust 版本和目标 `libstd`，并逐个检查所选 sysroot 中库对象的 AArch64 ELF 架构。它不会使用宿主 `pkg-config` 的库来充当客体依赖。

```sh
python3 tools/cosmic_ports.py
python3 tools/cosmic_ports.py check
python3 tools/cosmic_ports.py inventory --output artifacts/cosmic-sources/preflight.json
python3 -m unittest tests.host.test_cosmic_ports -v
```

`inventory` 的退出码 0 表示盘点执行成功；`check` 在 compositor 不具备构建前置条件时返回 1；输入、Git 或文件错误返回 2。当前 `compositor_build_ready`、`compositor_built`、`guest_runtime_ready`、`full_cosmic_session_ready` 均为 false。工具不会因所有库文件都出现而自行提升这些状态，也不会把机器上的 Rust target 安装当作客体 Rust std 已验收。

`source_pins_verified` 仅表示 `source_verification_scope` 中的 epoch 和 comp 已核对，并且完整组件锁与 epoch tree 相符。其他组件逐项显示 `not-fetched`；`source_closure_vendored` 仍为 false。未知运行时能力列为“需要实现或客体证据”，不通过搜索源码中的 syscall 数字推断正确性。

仅在明确执行 fetch 时联网，每次只取一个已锁组件，不递归初始化 submodules、不执行 Cargo、不构建、不修改 sysroot：

```sh
python3 tools/cosmic_ports.py fetch --component cosmic-epoch
python3 tools/cosmic_ports.py fetch --component cosmic-comp
```

已有目录若提交、origin 或工作区状态不符，工具保留原目录并失败。新 fetch 使用临时目录和锁，验证准确提交后发布。所有其他组件也必须显式指定，避免在剩余磁盘空间有限时下载整套桌面、Mesa 和 LLVM。

2026-10-18 的本机盘点已验证 epoch/comp 锁及 Rust 1.95.0 的真实 AArch64 `libstd`。所选公共 sysroot 中 X11、Xi、Xrandr、xcb、Pixman、xkbcommon 及 Wayland client/server/egl 库具有正确架构；该次盘点的 EGL、GLESv2、Xcursor 缺失项保留。后续 Mesa 的真实 EGL/GLES 静态库位于独立构建目录，未安装进公共 sysroot，也尚未接入 COSMIC 构建。`libwayland-egl.a` 只是 Wayland surface 辅助库，不是 EGL/GLES 实现。文件/架构证据与客体运行证据分开记录，可用上述命令重新生成当前盘点。

## 首个真实运行目标

建议先移植 **上游 cosmic-comp 的 winit backend，在 CyxiaOS 客体 Xorg 中创建窗口，使用真实 Mesa 软件 EGL/GLES 渲染**。这是基于源码的工程选择，尚未证明该组合可在客体运行。首个成果应是上游 compositor 接收真实 Wayland 客户端、完成内容合成并显示；之后才加入 cosmic-session、panel、applets 等组件。

| 路径 | 上游代码要求 | CyxiaOS 当前差距与选择 |
|---|---|---|
| `COSMIC_BACKEND=x11` | DRM node、EGLDevice、GlowRenderer、GBM/Vulkan DMA-BUF 分配，以及 X11 DRI3/Present | 现有软件 Xorg 禁用 DRI/DRI2/DRI3/GLX。不能直接作为首个后端；这不是 XPutImage fallback |
| `COSMIC_BACKEND=winit` | 真实 EGL window surface、GLES/Glow、Xlib 或 Wayland window backend | 没有 render node 时客户端 DMA-BUF 初始化只告警，允许研究软件 EGL；适合作为首选候选 |
| 自定义 Cyxia direct backend | 保留 COSMIC renderer；建立输出/输入适配和真实 EGL/GLES offscreen context，再读回图像提交 Cyxia blit | 可绕过 Xorg，但需要改 `BackendData`、输出管理和输入事件源；不是只加一个 syscall 的小改动，暂不先行 |
| 只开启 `renderer_pixman` | 上游已有 Pixman 辅助实现，但主 render elements 依赖 `AsGlowRenderer` | 不能据此获得纯 Pixman compositor；需改阴影、模糊、裁剪、光标和纹理等主渲染路径 |

上游 [winit 后端](https://github.com/pop-os/cosmic-comp/blob/41497b42d9744d9963c4c6d17e8add49489b45ee/src/backend/winit.rs) 使用 `WinitGraphicsBackend<GlowRenderer>`，`init_egl_client_side` 在不存在 render node 时允许继续。Smithay 的 [winit 实现](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/winit/mod.rs) 仍创建真实 EGLDisplay/EGLContext/EGLSurface，没有提供成功空实现或软件像素复制替身。

[AsGlowRenderer](https://github.com/pop-os/cosmic-comp/blob/41497b42d9744d9963c4c6d17e8add49489b45ee/src/backend/render/element.rs) 明确约束 GLES texture/renderbuffer 和 GlowFrame。上游 KMS 的软件 fallback 也是 EGL software device 创建的 GlowRenderer。`tiny-skia` 或 `renderer_pixman` 出现在依赖里，不能证明整个 compositor 无需 OpenGL。

Mesa 文档说明 [EGL 可采用软件初始化](https://docs.mesa3d.org/egl.html)，但仍需选定 Mesa 版本、固定源并实测其 X11 软件呈现路径。manifest 中的 `LIBGL_ALWAYS_SOFTWARE=1`、`GALLIUM_DRIVER=softpipe` 等仅为候选配置，**不是可运行启动器**。应先尝试避免 LLVM JIT 体积的 softpipe，再实测其 GLES 扩展和着色器支持；不能声称它已满足 COSMIC 或具有可接受性能。

## 编译入口与阻塞

准确源入口是固定 tree 的 `src/lib.rs::run`，由 `src/main.rs` 调用。该 crate 声明 Rust 1.93、edition 2024。标准构建入口为 Cargo package `cosmic-comp`；目标是 `aarch64-unknown-linux-musl`，不是运行宿主 binary。`cargo build --locked --no-default-features --target aarch64-unknown-linux-musl` 只给出上游交叉构建入口，**当前尚未完成其依赖构建和链接，因此不是成功构建命令记录**。

1. **特性分离。** [Cargo.toml](https://github.com/pop-os/cosmic-comp/blob/41497b42d9744d9963c4c6d17e8add49489b45ee/Cargo.toml) 将 Smithay DRM/GBM/udev/libinput/libseat/Vulkan/X11/winit/multi-renderer 特性同时启用。`--no-default-features` 只去掉默认 systemd 组合，不能关闭这些依赖。需在 `src/backend/mod.rs`、`src/state.rs`、`src/backend/render/{mod,element}.rs` 和 Cargo 特性中真正隔离未使用后端，而不是留出会运行的空函数。`cosmic-comp-config` 也有非可选的 `input` crate，不能假定这个子 crate 已完全脱离 libinput。
2. **真实图形库和加载。** Smithay [EGL ffi](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/egl/ffi.rs) 用 `libloading` 打开 `libEGL.so.1`。现有静态 musl/静态 ELF 方案不能只加 `libEGL.a` 即满足它；需要真实动态加载路径，或明确、可测的静态 EGL 绑定移植，并处理 Mesa driver 与 winit/Xlib 的加载。不能把 `dlopen`、EGL context、shader compile 或 swap 实现为成功 stub。
3. **Rust std 与事件循环。** 需真实验收 startup、TLS、分配、线程/futex、poll/epoll、定时与唤醒。calloop/winit 的等待语义必须保持。目标 rlib 安装、主机 `cargo check` 或单纯 `--version` 输出均不证明 compositor 运行。
4. **Wayland 缓冲区与 IPC。** compositor 即使嵌套于 X11，仍是 Wayland server。需真实 Unix FD 传递、接收所有权、截断/错误清理、文件共享映射和 `wl_shm` 生命周期；只有字节流 socket 或 `wl_display.sync` roundtrip 不足以证明共享图像缓冲区可用。C libwayland 库列作兼容基础盘点；Smithay 可以使用 Rust Wayland server backend，不能把缺 C 库机械等同于 compositor 的硬链接错误。
5. **配置、服务与启动。** compositor 使用 Rust `zbus`，`libdbus-1` 本身不是其必需 C 链接库；真实 session/system bus 服务是另一层要求。上游保留连接错误并记录日志，缺 bus 不应被简单描述为必然在同一位置退出。初步可明确禁用 Xwayland (`--no-xwayland`)，保留错误可见；完整会话仍需独立移植并验证进程启动、配置监控、服务、字体和数据文件。
6. **资源容量。** 当前桌面内存、映像、FD、进程和线程预算来自已有软件实测；不得套用为 COSMIC 容量结论。最终静态/动态库大小、软件渲染内存与 CPU 开销需逐项测量，再通过 AI 资源准入分配。

## 内核接口、AI 边界与验收顺序

现有 [graphics.rs](../../kernel/src/graphics.rs) 提供 VirtIO-GPU 2D 固定 framebuffer、有限 staging 和单次在途 fence。Linux 扩展 ABI `0x43595801..04` 提供显示信息、分块 blit、原始输入和按键快照；[Xorg DDX](../../user/ported/xorg/cyxia_ddx.c) 已真实连接这些接口。当前并无 DRM/GEM/GBM、DMA-BUF 或 3D/virgl 接口。输入提供键盘、相对鼠标、有界 FIFO 与溢出重同步，不能直接当作完整 `/dev/input`/libinput 设备实现。

嵌套 winit 路径继续经客体 Xorg 进入显示 AI 准入/节奏策略。软件 GLES 指令仍是确定性渲染机制；本地模型决定已授权资源和显示节奏，不改变用户输入、窗口内容或 Wayland 协议。应沿用 [系统 AI 状态边界](system-ai-status.md) 和 [显示策略证据](display-ai-pacing.md)，将新内存/IPC/进程请求纳入原有预算与可观测性，不通过私建无限队列绕开模型。已承诺的 DMA 和 Wayland buffer 生命周期必须完成后再释放，模型不得制造虚假完成事件。

按以下顺序建立独立、可失败的门禁：

1. 固定源和架构盘点；此文对应工具的 14 个 host 用例覆盖脏 checkout、origin/commit 变化、缺失 gitlink、锁文件改变、宿主/混合架构库、逃逸 symlink、缺少 libstd，以及“全部库存在仍不能宣称 runtime 就绪”。
2. 客体 Rust std 与真实 Wayland roundtrip，记录实际 ELF/kernel SHA、系统调用和完整回收；这只完成基础层。
3. SCM_RIGHTS、共享文件映射及 `wl_shm` 客户端/服务端跨进程像素验证，覆盖关闭/退出/异常路径。
4. 真实软件 EGL/GLES context、COSMIC shader、readback exact pixels、客体 Xorg window present，并测量资源与延迟。
5. 固定上游 cosmic-comp 的合成器窗口和至少一个真实 Wayland 客户端；验证键鼠、窗口生命周期、退出及所有资源回收。之后逐个加入 session/panel/应用，而不是把单个合成器称作完整桌面。

每次扩展内核或 sysroot 后继续运行已有 graphics exact-pixel、非法参数/无 GPU、正常退出回收、LXPanel taskbar/show-desktop、PCManFM/菜单、终端/PTY、保存双 flush/重启恢复与 AI 状态门禁。现有普通退出和桌面终止回收证据没有通过故障注入强制命中“owner 恰在 DMA 在途时死亡”，不将其写成该场景已验收。原有桌面和已冻结 ELF 保持为回归参考；COSMIC 的新证据需单独报告。
