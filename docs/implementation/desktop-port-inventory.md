# 原生 LXDE/X11 桌面移植清单

日期：2026-10-16。对应 [GUI 设计](../../CyxiaOS-gui-design.md) 的 D0/D2/D3。机器可读版本见 [manifest.json](../../ports/desktop/manifest.json)。

**实施更新（2026-10-18）：** X.Org、Openbox/TWM 和 GTK 已有真实运行验证；PCManFM 文件操作、LXPanel 任务栏已有独立客体验收。当前加入原生 PTY 终端/shell、GLib/CyxiaOS spawn 后端和图形持久检查点，第一版集成状态见 [轻量桌面](lightweight-desktop.md)。采用上游 LXPanel 静态 Menu 插件，未运行动态 menu-cache 服务；会话由启动器编排，LXSession、VTE/LXTerminal 仍未移植。下文保留最初候选依赖快照，不能据旧表把已实现接口视为缺失，也不能把当前第一版称为完整 LXDE。

首次核查的是上游接口、源码身份和构建次序，**当时没有编译或运行 X.Org/LXDE**。初始清单固定了 25 个候选组件版本，其中 7 个 LXDE 组件固定到实际查询到的 tag 对应 commit，4 个 GNOME 包记录上游公布的 SHA-256；首次核查时源码包尚未下载、哈希尚未在本机复核。后续实际源码、目标构建和运行进展见 [目标运行库记录](../../ports/libc/README.md)及上述集成记录。初始列出的 36 项待选身份/资产是历史快照，不能将本清单当成当前完整锁文件、安装器或 D0 验收通过。

## 1. 首次核查结果与历史阻塞

本轮只读核查时，客体有 4 个进程槽、每槽 8 个映射页；现有 AI 准入最多放行 3 个同时活动的进程。ELF 装载布局固定，普通 RAMFS 单文件最多 1 KiB，IPC 为监督器配对的 256 字节流。没有通用 libc、动态装载器、TLS/FP 上下文、pthread、命名 Unix socket、poll/select、PTY 或持久大文件存储。参见 [现有多进程实现边界](desktop-process-foundation.md)。后续实现更新以代码和运行证据为准，不应把本次快照当作长期限制。

**后续更新：** 本文以上段落保留首次核查快照。其后已增加静态 musl 装载、匿名内存、FP/SIMD/静态 TLS、命名 Unix socket、poll/eventfd、目录/部分信号和真实 X.Org/Openbox。当前能力、验证和限制见 [桌面内存与显示基础](desktop-memory-display.md)及 [X11 集成记录](x11-desktop-integration.md)。当前八槽中最多准入七进程，RAMFS 源码为 64 节点/4 KiB；通用进程启动/等待、线程客体验证、动态库、PTY、大文件持久存储和其余 LXDE 应用仍需继续；源码获取工具见 [ports/desktop/README.md](../../ports/desktop/README.md)。

首次核查的缺项分别阻断真实程序装载、内存分配、库运行、客户端连接、终端及文件保存。其后的映射与 AI 授予、运行库及 X11 接口工作已解除部分阻塞；尚未完成的应用功能仍须逐项实施和客体验收。

宿主首次读取剩余 **240 MiB**，当时 `target` 约 465 MiB；该磁盘不足状态已经解除，后续已实际获取并构建大量依赖。最初缺少的 Meson/Ninja/CMake 已按构建脚本在项目内补齐所需工具；不得链接 macOS 库作为 AArch64 CyxiaOS 运行库。完整桌面构建峰值仍未测量，不能把首次快照当作当前阻塞或确定的最低磁盘数值。

## 2. 已固定的组件组合

这是满足已读上游版本约束的**候选组合**，不是整套经过构建验证的兼容发行版。完整安全更新审计尚未执行。未固定摘要且没有精确 Git commit 的来源、空版本或未审计构建约束必须保持明确失败状态，不能自动改用浮动 master 或以宿主库填补。

| 组件 | 固定版本 | 首批配置、证据与限制 |
|---|---|---|
| X.Org Server | 21.1.25 | 官方源码含该版本；新增 CyxiaOS DDX/平台后端，使用软件 fb 路径。关闭未实现的 Linux DRM、udev/logind、GLX/DRI/glamor；具体 Meson 参数须按此版本核验。[构建文件](https://gitlab.freedesktop.org/xorg/xserver/-/raw/xorg-server-21.1.25/meson.build) |
| Openbox | 3.6.1 | 官方发布；保留真实窗口管理。需要 libc、Xlib、GLib、Pango **及 pangoxft**、libxml2；Pango 的 Xft 后端不能省略。首批禁用 startup-notification/imlib2/librsvg。[源码发布](https://openbox.org/download) · [版本配置](https://raw.githubusercontent.com/Mikachu/openbox/release-3.6.1/configure.ac) |
| LXPanel | 0.11.1 | `--enable-gtk3 --with-plugins=none --disable-alsa --disable-indicator-support`。保留核心任务栏/启动器，关闭第一批不支持的服务插件。上游 `AC_DISABLE_STATIC` 仍要求共享库路径；关闭插件不等于免除动态库依赖。[配置](https://raw.githubusercontent.com/lxde/lxpanel/0.11.1/configure.ac) |
| PCManFM | 1.3.2 | `--with-gtk=3`；需要 GIO、Pango、libfm-gtk3 和 Xlib。文件与桌面操作必须实际生效。[配置](https://raw.githubusercontent.com/lxde/pcmanfm/1.3.2/configure.ac) |
| libfm | 1.3.2 | `--with-gtk=3 --disable-old-actions --disable-udisks --disable-exif`；先独立构建 libfm-extra，见下文。[配置](https://raw.githubusercontent.com/lxde/libfm/1.3.2/configure.ac) |
| menu-cache / lxmenu-data | 1.1.0 / 0.1.5 | 必须有真正菜单数据、应用描述与缓存服务，不能用手写固定按钮代替移植结果。[menu-cache 配置](https://raw.githubusercontent.com/lxde/menu-cache/1.1.0/configure.ac) · [菜单数据配置](https://raw.githubusercontent.com/lxde/lxmenu-data/0.1.5/configure.ac) |
| LXSession | 0.5.5 | 首批 `--disable-gtk --disable-man`，运行真实会话管理器；这不包含 LXSession 图形设置、剪贴板及 polkit 程序。Vala 仍是构建要求。[配置](https://raw.githubusercontent.com/lxde/lxsession/0.5.5/configure.ac) |
| LXTerminal | 0.4.0 | `--enable-gtk3 --disable-man`；GTK3 分支优先使用 `vte-2.91`，必须有真实客体 PTY 和 shell。[配置](https://raw.githubusercontent.com/lxde/lxterminal/0.4.0/configure.ac) |
| GTK / GLib | 3.24.52 / 2.86.5 | GTK 只启用 X11 后端。GLib 需真实线程/文件/事件接口；仅有 `read/write` 包装不足。[GTK 构建](https://raw.githubusercontent.com/GNOME/gtk/3.24.52/meson.build) · [GLib 构建](https://raw.githubusercontent.com/GNOME/glib/2.86.5/meson.build) |
| Pango / Cairo / Pixman | 1.56.4 / 1.18.4 / 0.46.4 | Pango 要求 GLib ≥ 2.82、Cairo ≥ 1.18、Fontconfig ≥ 2.15、HarfBuzz ≥ 8.4、FriBidi ≥ 1.0.6；当前固定的 GLib/Cairo 满足其数值约束，其余需完成冻结。[Pango 构建](https://raw.githubusercontent.com/GNOME/pango/1.56.4/meson.build) · [Cairo/Pixman 发布](https://www.cairographics.org/releases/) |
| VTE | 0.78.7 | GTK3 API 对应 LXTerminal；需要 C++20 及目标 C++ 运行库、GLib、PCRE2、LZ4 和 PTY。禁用 GTK4/systemd 等须使用验证过的构建选项。[构建文件](https://raw.githubusercontent.com/GNOME/vte/0.78.7/meson.build) |

X11 基础候选同时固定为：xorgproto 2024.1、xtrans 1.6.0、libX11 1.8.12、libXau 1.0.12、libXfont2 2.0.7、libfontenc 1.1.8、libxkbfile 1.1.3、xkbcomp 1.4.7、xcb-proto/libxcb 1.17.0。文件存在性已对照官方发布索引核验，完整构建选项、传递依赖及归档哈希尚未验证。[X.Org 库](https://www.x.org/releases/individual/lib/) · [协议](https://www.x.org/releases/individual/proto/) · [应用](https://www.x.org/releases/individual/app/) · [XCB](https://xcb.freedesktop.org/dist/)

其余依赖不能省略：Fontconfig/FreeType/HarfBuzz/FriBidi、GdkPixbuf、ATK/AT-SPI 配置、libepoxy、libwnck-3.0、keybinder-3.0、libxml2、libffi、PCRE2、压缩/图片库、D-Bus、X 扩展客户端库、XKB 数据、字体、图标、MIME 数据及客体 shell。每项在 manifest 中显式列为 unresolved；Qt 留在后续应用兼容阶段，尚未冻结。

## 3. 容易遗漏的真实依赖

1. **libfm/menu-cache 的构建循环需要拆阶段。** 同一 libfm 1.3.2 源码先以 `--with-extra-only` 构建并安装 libfm-extra，再构建依赖它的 menu-cache，最后构建完整 libfm-gtk3。把这两个包简单拓扑排序会失败，不能通过忽略依赖继续。[libfm 配置](https://raw.githubusercontent.com/lxde/libfm/1.3.2/configure.ac) · [menu-cache 配置](https://raw.githubusercontent.com/lxde/menu-cache/1.1.0/configure.ac)
2. **LXSession 的 GTK 分支会检查 polkit-agent-1。** 只传 `--disable-buildin-polkit` 不能移除该检查。首个会话采用真实的无 GTK 会话管理器；若要 LXSession 的图形设置，则单独移植 polkit 或审核适配补丁，不伪造认证成功。Makefile 的 Vala 包使用也需审计。[configure.ac](https://raw.githubusercontent.com/lxde/lxsession/0.5.5/configure.ac) · [Makefile.am](https://raw.githubusercontent.com/lxde/lxsession/0.5.5/Makefile.am)
3. **软件绘图不自动消除 GTK 的 libepoxy。** 需要按固定 GTK 版本检查 GL 能力探测与实际回退，不能删掉库名就宣称不需要 GL 相关装载语义。[GTK 构建](https://raw.githubusercontent.com/GNOME/gtk/3.24.52/meson.build)
4. **现有 C 包装不是 libc 移植。** 原生 CyxiaOS libc/loader 的选型、目标 ABI 和 sysdeps 尚未固定。musl 等 Linux libc 不能不经适配就直接调用当前私有 syscall 号。不要以选择一个 libc 包代替实现线程、信号、TLS 和 mmap。Linux 原二进制验收继续属于独立 Linux ABI 路线。
5. **VTE 带来 C++ 运行时与终端语义。** 内核和新原生服务继续使用 Rust；保留上游 C/C++/Vala 的来源身份。目标 C++ ABI/unwinder 尚待选择，宿主 `libc++` 无法直接拷入客体。

## 4. 优先实现的实际接口与验收

以下是面向所选应用的最小推进顺序，并非完整 POSIX 或所有 Linux syscall 列表。接口名表示需要兑现的语义，可由 libc 映射到私有内核 ABI；不能用始终成功的占位函数通过配置检查。

| 顺序 | 实现内容 | 每一步必须在客体验证 |
|---|---|---|
| 1 | 有界 `mmap/munmap/mprotect`、匿名零页、读写/执行权限、堆或 `brk` 路径；真正物理页池与 AI 额度记账 | 不同进程相同 VA 的隔离；错误范围与溢出；部分失败回滚；撤销后不可访问；退出归还；AI 拒绝不泄漏 |
| 2 | 通用 PT_LOAD 装载、BSS、栈、argv/envp/auxv、可执行程序映像；随后 ET_DYN、动态解释器、重定位、共享库和 TLS | 多个不同上游/最小 C ELF；坏段/重叠/越界拒绝；可执行权限；实际 `malloc/free`；不能只接受嵌入的固定 demo |
| 3 | AArch64 FP/SIMD（全部 Q 寄存器、FPCR/FPSR）与 TPIDR_EL0 上下文 | 两个抢占进程保存不同浮点/向量/TLS 值；新进程不看到旧值；异常及退出恢复 |
| 4 | `execve/posix_spawn`、环境/cwd/FD 继承、`waitpid`、退出码、必要信号和进程组 | 一个客体进程启动另一个并等待；关闭继承描述符；回收僵尸状态；崩溃只影响所属进程 |
| 5 | 统一 FD 下的 `socket/socketpair/bind/listen/accept/connect`、AF_UNIX、`read/write/readv/writev`、`fcntl(O_NONBLOCK/FD_CLOEXEC)`、关闭及连接凭据 | 两个客体 X 客户端独立连接；短读写与背压；EOF/EPIPE；路径权限；cookie/身份验证；不开放远程 X 监听 |
| 6 | `poll/select`、单调 `clock_gettime`、超时、阻塞与唤醒、`EINTR` | 可读/可写/挂断/超时同时存在；关闭唤醒；不丢唤醒；等待进程不占忙循环 |
| 7 | `stat/fstat/lstat`、目录枚举、rename、访问权限、符号链接、真实大文件读写、只读程序映像和持久用户盘 | 读取程序/字体/MIME；创建、移动和保存真实文件；关机重启后内容一致 |
| 8 | pthread 创建/退出、TLS、mutex/condvar、线程等待与所需信号屏蔽；libc/libm/dlopen | GLib 主循环、工作线程和模块加载的真实行为；争用和退出无死锁；不以无操作锁替代 |
| 9 | 客体显示对象、可控 framebuffer 映射、提交/完成及输入事件 FD | X.Org 在 EL0 操作受限缓冲；输入重同步；GPU 超时后缓冲不提前回收；服务重启仍能恢复 |
| 10 | PTY 主从、termios、窗口大小 ioctl、会话/前台进程组、Ctrl-C 等信号、客体 shell | LXTerminal 输入执行、回显、调整大小、前台中断及退出；串口转发不是 PTY 实现 |

正常内存、CPU 与设备竞争应由实际本地 AI 模型/计划决定。现有模型按 8 页验证程序训练，不能简单扩大请求范围并宣称覆盖桌面。新资源域需明确训练范围、预算/保护边界及证据。映射撤销、协议字节顺序、权限和已提交事务完成保持确定语义。

## 5. 可分解的构建与运行路径

**A：独立 sysroot 和 ABI。** 固定 `aarch64`、LP64、小端、4 KiB 页、浮点调用约定、原生 ABI 身份和交叉工具链。宿主生成工具放在独立目录；目标 include/lib/bin 只来自 CyxiaOS sysroot。Meson 交叉文件及 pkg-config 搜索路径必须防止读到 `/opt/homebrew` 的目标库。Autoconf 交叉测试不得以随意 `ac_cv_*=yes` 代替真实客体结果。

**B：先验证服务器核心。** 协议头和 XCB 生成器 → 必要 libc/线程/事件/字体基础 → Pixman 和 X11 最小库 → 原生 X.Org。新增 CyxiaOS DDX 使用已有 GPU/input 驱动的受限客体接口，不移植 Linux DRM 作为第一个窗口前置。可借鉴 X.Org 现有 fb/vfb 的内存 framebuffer 路径，但最终必须提交到客体设备并路由客体键鼠；仅生成离屏截图不算桌面。

**C：两个真实客户端。** 单独进程完成 X11 握手、创建窗口、填色、接收键鼠及断开。记录各 ELF 身份、进程、地址空间、AI 授予、原始协议/串口证据与 QMP 截图。X.Org 崩溃不能拖垮内核；该阶段没有 LXDE 时仍不能叫完整桌面。

**D：逐个加入上游桌面程序。** GLib → 文本/图像/GTK3 → Openbox → libfm-extra → menu-cache → 完整 libfm → PCManFM/LXPanel/menu-data → 会话 D-Bus/LXSession → C++ 运行库/VTE/LXTerminal/客体 shell。每一步先处理实际编译或链接错误，再扩大运行测试；保留补丁目录和来源/许可证，不改名后当成自行实现。

**E：桌面退出条件。** 真正 LXPanel 菜单启动 PCManFM 与终端；Openbox 移动、缩放、焦点和关闭多个独立进程窗口；PCManFM 文件写入重启后保留；终端输入、调整大小和中断工作；CPU/内存授予来自本地 AI；程序崩溃与资源不足时有可解释的失败及回收。宿主只提供设备模拟、构建和采证，不运行被验收的桌面应用。

构建采用逐包临时工作目录，安装到目标 sysroot 后只清理该包可再生的对象文件；保留已核验源码归档、补丁、配置日志、许可和产物哈希。内核 `target` 与外部桌面构建树分开。下载前验证来源/哈希、可用空间和包的解压预算；当前清单没有执行这些下载或安装。跨平台、SMP、Linux 原二进制、Qt 及 Wayland 不因第一套 LXDE 通过而自动获得验收。
