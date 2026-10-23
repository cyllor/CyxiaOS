# CyxiaOS 轻量桌面与 Linux 图形环境移植设计

版本：0.6 · 日期：2026-10-18 · 关联总体/详细设计 v0.12。
状态更新：真实 X.Org/Openbox/GTK、PCManFM 文件操作和 LXPanel 任务栏已有客体证据；当前第一版组合加入原生 PTY 终端/shell、真实 GLib spawn 和图形检查点保存，使用单核 ARM 512 MiB 配置。实际实现与最终联合报告见 [第一版轻量桌面](docs/implementation/lightweight-desktop.md)。完整 LXDE（LXSession、menu-cache 服务、VTE/LXTerminal）和广泛 Linux 二进制兼容仍保留为后续范围，不把第一版组合等同于整套 LXDE。此路线替代 v0.1 的 LVGL 工作台及原 24 MiB 预算。

2026-10-16 实施增量：[匿名内存、FP/TLS 与 EL0 绘制](docs/implementation/desktop-memory-display.md)，以及 [上游依赖与源码准备](docs/implementation/desktop-port-inventory.md)。本地模型参与进程、映像和匿名页准入及 CPU 派发；GPU 提交通过真实异步 fence 等待，协议与资源所有权由内核机制检查。各阶段完整退出条件仍需独立验收。

## 1. 目标与选型

2026-10-18 用户指定后续桌面为 **COSMIC**。新增 [COSMIC 移植设计与源码锁](docs/implementation/cosmic-port.md)：以固定 cosmic-epoch 的真实 Rust/Wayland 组件为目标，先验证运行时、IPC/共享缓冲区和软件 EGL/GLES，再移植合成器及会话。下面的 LXDE 核心组合是现有可运行基线和回归环境；COSMIC 尚未完成，不能将基础库通信测试称为新桌面。首次候选是客体 Xorg 上的 winit 嵌套后端；原生直接显示后端保持独立接口，跨平台和后续 SMP 边界不绑定于 X11。

用户要求轻量桌面，并运行大多数 Linux 程序。采用 **LXDE 核心桌面 + X.Org/X11 + Linux 应用兼容层 + GTK/Qt 运行库** 的阶段路线；后续增加 Wayland 合成器与 Xwayland。LVGL 不再是桌面主线，也不作为这些组件的移植前置。

桌面负责窗口、启动器和文件交互；Linux 二进制兼容依赖内核 ABI、运行库及服务，不能靠更换桌面实现。当前先交叉构建固定版本的静态 musl 程序，在 CyxiaOS 的 Linux AArch64 syscall 子集上执行。发行版原二进制和动态链接应用仍按 [Linux 应用兼容专项](CyxiaOS-linux-compatibility-design.md)逐项验收，不能由源码移植成功推定兼容。

| 组件 | 交付职责 | 范围 |
|---|---|---|
| X.Org Server | X11 绘图、输入和客户端连接 | 原生移植，编写 CyxiaOS 显示/输入后端，不假设已有 Linux DRM/evdev |
| Openbox | 窗口边框、焦点、移动/缩放、工作区 | 移植现有窗口管理器；默认不启用合成特效 |
| LXPanel | 面板、任务列表、菜单和启动器 | 最小插件集合；缺失网络/音频/电源服务的插件禁用并记录 |
| PCManFM / libfm | 文件管理、桌面图标 | 真实文件操作；依赖 VFS、字体、图标和 MIME 数据 |
| LXSession | 桌面会话、启动和设置 | 与 CyxiaOS 进程服务衔接，恢复请求受权限和资源计划约束 |
| GTK / Qt | 对应应用的控件与绘图运行库 | 桌面首批评估 GTK3，Qt 用于后续 Qt 应用；并非只能运行一种工具包的软件 |
| 终端 | PTY/TTY 上的真实 shell 会话 | 候选 LXTerminal，库及终端协议依赖在冻结清单中列出 |

LXDE 的模块化适合逐组件移植，这是针对本项目的工程选择，不是内存最省的实测结论。[LXDE 官方介绍](https://www.lxde.org/) · [Openbox](https://openbox.org/) · [LXPanel](https://github.com/lxde/lxpanel) · [PCManFM](https://github.com/lxde/pcmanfm) · [LXSession](https://github.com/lxde/lxsession)

PCManFM/libfm 的构建配置提供 GTK3 路线；LXSession 等组件的选项和覆盖仍需逐个核查，不能假设整个桌面一键切换即可运行。D0 冻结一组兼容提交和补丁，拒绝只追踪浮动 master。[PCManFM 构建配置](https://github.com/lxde/pcmanfm/blob/master/configure.ac) · [libfm 构建配置](https://github.com/lxde/libfm/blob/master/configure.ac)

## 2. 图形与运行时架构

```text
LXDE 桌面 / 原生应用 / Linux GTK、Qt 应用
                     ↓
X11 客户端库 → 本地套接字 → 原生 X.Org Server
                     ↓
CyxiaOS 显示/输入后端 → VirtIO GPU 2D / keyboard / mouse

Linux 应用 → Linux ABI → 统一内核对象 ← 原生 POSIX 服务
                              ↑
                     客体本地 AI 资源计划
```

第一阶段采用软件 2D、单显示器 1024×768；GTK 的 GLib、Pango、Cairo 等依赖及字体/图片库按实际配置移植。[GTK3 构建依赖](https://docs.gtk.org/gtk3/building.html)

X.Org 的平台/设备后端必须适配 CyxiaOS，不能把 Linux fbdev、DRM/KMS 或 libinput 当作当前已有接口。Linux 图形客户端先使用 X11 协议与原生服务器通信，避免为了第一个窗口先承诺完整 GPU ioctl 兼容；共享内存扩展只有真正实现后才公布支持，否则使用可用的协议传输路径并验证客户端回退。

后续 Wayland 是独立协议和合成器移植阶段；Xwayland 在 Wayland 会话中承接 X11 应用，不提供 Linux 系统调用兼容。LXDE 的 X11 会话可保留，不能假设全部 LXDE 组件自动变为原生 Wayland 桌面。[Xwayland 官方说明](https://wayland.freedesktop.org/docs/book/Xwayland.html)

## 3. 当前差距和依赖

已有单核 ARM 内核、串口、计时器、RAMFS/Shell、独立 EL0 地址空间及有界原生 IPC/等待；已实现静态 ET_EXEC、musl 静态 TLS、匿名 mmap/mprotect/整块 munmap 子集、命名 AF_UNIX stream、poll/eventfd、部分信号和目录语义。VirtIO 显示/键鼠通过原生 DDX 接入真实 X.Org；Openbox、字体/XML 运行库及 Xlib 客户端已经并发运行。具体映像、输入和回收证据由 [X11 集成记录](docs/implementation/x11-desktop-integration.md)限定。

当前已有 8 个进程槽、最多准入 7 个活动进程，七进程和高槽内存回收已验证。剩余差距包括通用 fork/execve/等待、动态装载、共享映射、完整 pthread/clone 语义、完整信号/PTY、更完整文件服务及 LXDE 应用闭包。当前 Openbox 的 Pango 字体发现仍以受控补丁同步执行；后续单核 8 线程子集已通过真实 musl 验证，但不代表完整 pthread；内核仍按本地 AI 预算抢占该进程。只读字体/配置资产不受 RAMFS 文件大小限制；RAMFS 源码已扩至 64 节点、每文件 4 KiB、UTF-8 名称与保留打开 inode 的普通文件原子重命名，真实 musl 客体验收通过（`thread-abi-r2`）。

正式桌面必须运行在可抢占 EL0，独立进程具有真实地址空间；不能先把全部第三方桌面代码放在 EL1 再宣称完成移植。当前 X.Org/Openbox 已走此路径，并保存 FP/SIMD 与 TLS 上下文；程序不能使用尚未支持的扩展指令。桌面服务持续运行，15 秒交互客户端仅用于验收；演示模式运行至用户关闭。

系统数据分层：只读程序/库/字体映像，可写用户目录、配置和临时运行目录。需要超出现有 4 KiB 可写文件上限的 VFS，正式交付需持久存储。XDG 菜单、MIME、字体发现、D-Bus 会话服务及文件监控逐项实现；不存在的 systemd/udev/logind 服务不得伪报成功。先手动启动一个桌面会话，不把图形登录管理器列为首个窗口的前置。

## 4. AI 与显示安全契约

AI 决定桌面、应用和 X server 的 CPU/内存/I/O 资源份额、刷新准入及可回收缓存预算；协议执行、像素绘制、事件路由和窗口操作保持原语义。用户焦点、输入文本、文件内容及返回结果不得由资源模型改写。X server 有序请求和已提交业务不能为了优先级优化而任意重排。

正常资源竞争纳入统一计划与审计；启动、恢复和防饥饿保护分别记账。模型控制实际应用进程和图形服务，不能只显示一个“AI 已启用”面板。模型训练与受控发布沿用现有授权，样本不默认采集截图和键盘文本。

设备驱动从 DTB 发现资源，使用有界 VirtIO 队列；GPU 缓冲固定至对应操作完成。设备超时须确认停止 DMA 后才可回收，无法确认时隔离保留并回到串口恢复。输入溢出显式重同步，避免丢失释放事件导致粘键；IRQ 中不绘图或等待设备。

首版 X11 会话只接纳同一信任域的应用：拥有进程地址空间隔离不代表传统 X11 客户端间已具备强输入/窗口隔离。默认关闭远程 X 监听，使用本地连接权限与认证。后续不可信应用需要独立显示会话或经过验证的隔离路径；不能以窗口边界宣称安全沙箱。X server 崩溃后应用连接可能断开，恢复必须说明会话数据风险，不自动重放写文件操作。[X 安全扩展规范](https://www.x.org/releases/X11R7.7-RC1/doc/xextproto/security.pdf)

## 5. 实施阶段

D1 的色条/原始键鼠切片已有运行证据，完整阶段其余要求仍待执行；D 编号替代旧 LVGL G 编号，Linux ABI 的 L 编号见专项设计。

| 阶段 | 内容 | 退出条件 |
|---|---|---|
| D0 | 冻结桌面组件、源码/补丁/许可、GTK 配置、构建依赖和应用清单 | 明确原生移植与 Linux 原二进制各自范围；可复现依赖图及预算；核实宿主磁盘空间再下载/构建 |
| D1 | VirtIO MMIO/GPU/Input、DMA 和图形启动配置 | 真实色条、键鼠反馈、故障恢复；原串口启动与回归不受影响 |
| D2 | 多进程/内存/IPC/运行库基础，原生 X.Org 及最小客户端 | 两个独立客户端绘图、输入和退出；权限、资源与崩溃回收通过 |
| D3 | Openbox、面板、文件管理、会话与终端 | 真正多进程桌面；文件保存/重启恢复、菜单启动、窗口操作、PTY 工作流通过 |
| D4 | ARM64 Linux 客户端、GTK/Qt 应用与完整依赖包 | 与 L2—L4 联合验收；直接运行未经重新链接的指定二进制，分别记录 GTK/Qt 和各业务功能 |
| D5 | 更广应用、Wayland/Xwayland、音频/网络/加速及学习调优 | 按明确软件清单逐项扩大支持；不把单个桌面启动结果推广为“大多数 Linux 程序” |

D1 可与运行环境工作独立推进。D2/D3 原生源码移植不必等待全部 Linux ABI，但不能代替 D4 的二进制验收。原生程序和 Linux 程序最终使用统一 AI 资源管理。X11 后端与设备无关层分离，为第二架构、SMP 与实体显示设备保留边界。

## 6. 性能与资源口径

基础配置保留单核 ARM、256 MiB QEMU，第一版完整交互组合使用显式 `large-memory` 512 MiB 配置。内核区均为 64 MiB；程序/资产目录上限默认 48 MiB、大池 52 MiB；八槽匿名物理池默认 64 MiB、大池 128 MiB，静态 ELF/栈池均为 128 MiB。每槽匿名额度默认 2048 页、大池 4096 页，512 条映射记录；映像额度 4096 页含 64 页栈，最多同时准入七进程。正常资源使用经过本地模型及 grant ledger；预留容量不是实际空闲桌面工作集。

第一版常驻 X.Org、Openbox、LXPanel 和 PCManFM 四进程；一个原生终端及其 shell 为六进程，保存对话框短时为七进程。采用上游 LXPanel 静态 Menu 插件和 Openbox 根菜单；PCManFM 同进程管理背景与多个目录窗口。会话引导由宿主工具顺序编排，未声称具有客体登录管理器或完整会话恢复。完整 LXDE 的 LXSession、menu-cached、VTE/LXTerminal 组合仍需新的进程/库预算；它没有被静态菜单或原生终端改名冒充。1 GiB 仍只是后续候选配置，不是当前启动参数。

软件绘制的初步目标为交互时最高 30 FPS、空闲按事件唤醒；输入响应记录 p50/p95/p99，不预先声称达标。分别测桌面空闲、文件浏览、终端和 GTK/Qt 多应用负载；共享库物理页只计一次。应用兼容率、内存、CPU 和模型开销独立报告。实体 ARM 性能不由 QEMU 墙钟替代。

## 7. 验收矩阵

| 编号 | 验证 |
|---|---|
| GUI-T01 | 固定版本、许可/依赖、原生与 Linux 二进制构建身份及指令集 |
| GUI-T02 | 设备发现、特性协商、队列/长度/DMA 范围 |
| GUI-T03 | 客体 X11 绘图、颜色/stride/裁剪、截图与参考像素 |
| GUI-T04 | GPU 完成、缓冲寿命、超时/reset、内存回收 |
| GUI-T05 | 键鼠、焦点、输入重同步、本地连接认证及会话信任边界 |
| GUI-T06 | 桌面/应用内存总账、共享页计量、低内存与长期打开关闭 |
| GUI-T07 | 菜单/文件/配置/终端真实操作与持久化 |
| GUI-T08 | 多进程隔离、FP/TLS、抢占、崩溃、串口恢复 |
| GUI-T09 | AI 对真实资源的控制及计划过期/超时/保护来源 |
| GUI-T10 | Unix socket、共享映射、FD/凭据、IPC 背压与连接退出 |
| GUI-T11 | GTK/Qt 应用清单、原二进制证据、时延/负载与学习回退 |
| GUI-T12 | 原有 M1/Shell/资源/POSIX 回归；Wayland、其他 ISA/SMP 各自另验 |

证据包含源码/包/映像/模型哈希、架构和平台配置、原始日志、输入记录、截图、真实业务结果、失败/跳过原因。宿主只模拟设备和采集测试数据，不能用宿主或远程 Linux 运行应用来冒充移植。

### D3 当前退出条件核对（2026-10-18）

| 必需工作流 | 当前证据与剩余项 |
|---|---|
| 真实图形与窗口管理 | X.Org/Openbox/GTK 有独立证据；第一版联合检查包含任务栏隐藏/恢复、焦点、移动及真实尺寸变化 |
| 文件管理 | PCManFM 已通过真实目录创建、普通文件重命名和内容保持；原生 shell 执行真实读写/删除，仍受 64 节点/4 KiB 文件上限约束 |
| 面板、菜单与会话 | 实际 LXPanel 静态 Menu 和 Openbox 根菜单通过原生 GLib spawn 启动应用；尚无动态 menu-cache、LXSession 或完整会话恢复 |
| 终端 | 原生 Xlib 终端、内核 PTY、独立 EL0 shell 已实现；canonical/echo/EOF、大小通知、信号与超长行拒绝有探针；VTE/LXTerminal 尚未移植 |
| 存储 | 专用 VirtIO 磁盘双槽检查点、两次 flush、CRC 回退和只读磁盘有独立证据；图形保存必须在第二次 flush 完成后显示成功，并在新 VM 中验证恢复 |
| 资源与恢复 | 七进程容量、AI 准入/派发、线程/FP/TLS、故障回收有探针；联合测试核对全部终态、线程及 heap/image grants 回收 |

第一版轻量桌面的实际功能完成与完整 LXDE 移植分别报告。完整 D3 路线中的 LXSession、动态菜单服务、VTE/LXTerminal 不因原生替代组件通过就标为完成；D4 的 Linux 原二进制兼容继续独立验收。最终功能证据必须绑定同一内核与实际嵌入程序身份，见 [联合验收](docs/implementation/lightweight-desktop.md#联合验收)。

## 8. 文档关系与修订

[Linux 应用兼容设计](CyxiaOS-linux-compatibility-design.md)规定运行环境与 L 阶段；[POSIX 设计](CyxiaOS-posix-design.md)保留原生源码兼容要求；[AI 契约](CyxiaOS-ai-decision-contract.md)约束全域策略。总体和详细设计同步至 v0.12，尚未完成全域审核。

v0.1 曾选择 LVGL 单进程工作台。用户进一步明确需要轻量桌面与广泛 Linux 应用支持，因此 v0.2 改为 LXDE/X11 与独立应用兼容层；旧控件演示不作为桌面或兼容交付。

v0.4 同步 GTK 客体交互、七进程准入、匿名映射记录和 RAMFS 扩容状态，并将剩余 D3 工作流逐项列明；线程与文件扩展在客体验收前不标为完成。

v0.3 同步静态 musl/X.Org/Openbox 实施状态、事件/目录接口、256 KiB 栈和当前内存预算；保留 D3 完整桌面的既定退出条件，不把窗口管理器集成升级为完整桌面验收。


历史存储阶段记录（已由上述第一版集成状态更新）：当时已实现 [有界双槽检查点](docs/implementation/persistent-storage.md)，当时由串口 `storage checkpoint` 显式触发，随后已增加图形保存入口；该阶段记录的 D3 用户工作流还需把保存/退出操作接入该真实服务；`write` 返回不等于已持久化，不假装实现未提供的 fsync。线程与文件语义的后续证据为 `thread-runtime-r2` 和 `thread-abi-r2`。另外新增 `large-memory` 候选配置为 512 MiB RAM、每槽 16 MiB 匿名池，保持原 256 MiB 配置；候选配置以自身后续运行证据为准，不能继承本页旧构建的 PASS。


v0.5 明确第一版四常驻进程组合、512 MiB 大池、原生 spawn/PTY/保存和真实资源预算，保留完整 LXDE 与 Linux 二进制兼容的剩余条件；不以单个窗口或截图替代联合验收。
