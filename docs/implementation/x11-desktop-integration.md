# CyxiaOS 原生 X11 集成会话

更新：2026-10-18。真实上游 X.Org 21.1.25、Openbox 3.6.1 和 Xlib/XCB 客户端已在 CyxiaOS ARM EL0 中并发运行。TWM 1.0.13.1 保留为另一条已验证的窗口管理器路径。内核为本项目 Rust/no_std 内核；QEMU 提供 VirtIO GPU、键鼠和 RNG。宿主没有运行 X server，也没有生成或修补客体画面。

当前集成组合为 **X.Org + Openbox + PCManFM + LXPanel + 原生 PTY 终端/shell + 图形保存**。启动、资源拓扑和限制集中在 [第一版轻量桌面](lightweight-desktop.md)。菜单、终端和持久保存以同一固定映像的联合报告为准；完整 LXDE（含 LXSession、menu-cached、VTE/LXTerminal）及广泛 Linux 原二进制兼容仍未实现。
## 启动与操作

在项目目录运行：

```sh
python3 tools/desktop.py
```

macOS 也可双击项目中的 `Start-CyxiaOS-Desktop.command`。默认构建 512 MiB 桌面配置并挂载专用数据盘，启动桌面背景、面板和文件管理器。左下角菜单可打开 **Files**、**Terminal** 和 **Save Files**；窗口可移动、缩放、最小化及 Alt+F4 关闭。编辑后需显式选择 Save Files 并等待成功提示，未保存修改会在 VM 关闭时丢失。

保留独立验证入口：`--app x11` 显示 Xlib 交互应用，`--app gtk` 显示真实 GTK 控件，`--app files` 仅显示文件管理器；TWM 必须使用 `--wm twm --app x11`。`--display none` 用于无窗口采证。串口入口 `tools/shell.py` 继续保留。
客体串口命令（要求 `graphics,openbox` 内核及 GPU、键鼠、RNG 设备）：

```text
posix exec xorg
posix exec openbox
posix exec x11-demo
posix list
posix kill 3
posix kill 2
posix kill 1
```

`x11-interactive` 是 15 秒验收模式，`x11-demo` 持续运行至关闭；它们装载同一个真实 ELF，传入不同 argv。`x11-probe` 执行短暂的连接/绘图/像素读回测试后退出。

TWM 使用 `graphics,ported` 构建和 `posix exec twm`。两种构建分别嵌入所选窗口管理器；`openbox` feature 包含 `ported`，缺少 `openbox.elf` 时构建失败，不能静默退回其他窗口管理器。

## 实现与边界

| 层次 | 当前实现 |
|---|---|
| 可执行映像 | 静态 AArch64 ET_EXEC，PT_LOAD/BSS、argv/envp/auxv、256 KiB 栈、musl 静态 TLS、FP/SIMD 上下文；每槽 4096 页 / 16 MiB 映像额度包含 64 页栈；拒绝解释器、动态段、重叠和 W+X |
| 匿名内存 | 默认每槽 8 MiB / 2048 页，512 MiB 桌面配置为 16 MiB / 4096 页；512 个活动映射及 grant 记录；模型 8194 正常准入，映射前清零，退出撤销并回收；munmap 仍只接受完整原分配 |
| 调度 | 映像模型 8195、原生进程底座模型 8193、CPU 选择 12289、预算 12290；模型失败/额度不足显式拒绝；8 槽、最多 7 个同时活动进程；保留 8 页底座余量 |
| 通信 | 有界 AF_UNIX stream；pathname 和二进制 abstract 名称；连接、accept 地址、对端 PID/单用户 UID/GID、poll、read/write、向量 I/O、recvmsg 无附属数据、半关闭和 EOF/背压 |
| 事件 | eventfd 的 64 位计数器、semaphore、dup 共享计数、CLOEXEC/NONBLOCK 标志及 poll 就绪；读写长度、溢出和用户缓冲区错误按验证范围返回错误 |
| 兼容层 | Linux AArch64 syscall 子集，与原生 syscall personality 分开；musl 的大文件标志归一化；已验证最多 8 线程上下文的单核 pthread/clone/futex 子集；不支持 TCP、FD passing、完整 pthread、通用 execve/fork |
| 信号 | 有界 signal action/mask/pending、rt_sigreturn、FP/TLS/ucontext、同步故障、定向线程信号、SIGCHLD 和 PTY 前台信号；保留重试 syscall 来源以正确返回 EINTR；不支持 SA_RESTART、altstack、任意跨进程 kill 或完整作业控制 |
| 显示 | 原生 Kdrive DDX → 私有矩形提交 → VirtIO GPU；64 KiB 以内分块，等待真实 fence，设备故障保留 DMA backing；软件绘制、固定 1024×768 |
| 输入 | VirtIO 原始键鼠 → 有界输入环 → DDX → XKB → X 客户端；溢出 SYN_DROPPED 与按键状态重同步；pc105/US XKM 由真实 xkbcomp 生成 |
| 文件 | 真实 RAMFS 加只读引导资产；目录描述符、getdents64、相对目录 openat/fstatat、chdir/getcwd；目录创建与写入走本地 AI 文件策略；源码已扩至 64 节点、每文件 4 KiB、UTF-8 名称与普通文件原子重命名，真实 musl 客体验收通过（`thread-abi-r2`）；已验证专用 VirtIO 磁盘的显式检查点和重启恢复；尚无 fsync/自动保存、硬链接、符号链接和大文件写入 |

RAM 基址为 `0x40000000`，内核/引导保留区上限为 `0x44000000`，覆盖前 64 MiB；实际内核映像从 `0x40200000` 开始。内嵌程序与只读资产目录总上限默认 48 MiB、大池配置 52 MiB。Unix socket backing、八槽合计默认 64 MiB（大池 128 MiB）匿名物理池及 128 MiB 映像物理池是 BOOTSTRAP 预留；两个用户物理池从内核上限之外寻找未占用 RAM 并登记到 BootInfo。正常逻辑准入仍经过本地模型。协议内容、映射权限、所有权和 GPU 完成是确定性 MECHANISM。X.Org 以 `-dumbSched` 关闭其自带信号调度器，CPU 时间仍由 CyxiaOS 本地模型分配。`-nolock` 只用于当前单显示集成环境，待真实 hard-link/文件锁语义完成后移除。

Openbox 使用真实 GLib、Pango/Xft、fontconfig、FreeType、HarfBuzz、XML 库和 Roboto 字体。当前虽已有有界 pthread/clone 子集，Pango 的 fontconfig 初始化、匹配和排序通过受控补丁在调用线程同步执行，结果仍来自上游字体代码；没有伪造线程成功。内核可以抢占这个线程，正常 CPU/页额度继续由本地模型决定。此配置关闭 Openbox 的 startup notification、Xcursor、Imlib2、librsvg，并以 `--sm-disable` 启动；不提供完整会话管理。GLib 原生 spawn 后端以显式私有 ABI 启动独立目录程序，不依赖未实现的 fork。配置、主题、字体及 passwd/group 来自只读引导资产，当前仍为单用户环境。

显示事务已异步等待，但 CPU 拷贝和缓存维护仍可能占据 EL1；尚未宣称 1 ms 输入延迟或任何帧率指标。授权/页表元数据有界；ENOMEM 不仅可能来自 RAM，还可能来自记录容量。

## 构建来源与验收

目标 sysroot、协议库和服务器按 `ports/libc/README.md` 构建；键盘资产按 `ports/xkb/README.md` 构建。随后：

```sh
python3 tools/build_twm.py build --fetch
python3 tools/build_openbox.py foundation --fetch
python3 tools/build_openbox_fonts.py build --fetch
python3 tools/build_openbox.py build --fetch
python3 tools/build_sysroot.py probes
python3 tools/desktop.py --profile release --wm openbox
python3 tools/verify_x11.py \
  --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel \
  --wm openbox --output artifacts/x11-openbox-release
python3 tools/verify_desktop_abi.py \
  --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel \
  --output artifacts/desktop-abi-release
```

构建验证来源哈希，保存许可证，使用隔离目标 sysroot，禁止宿主库混入。上述命令按顺序运行；第一步同时提供 Openbox 链接所需的目标 ICE/SM/Xt/Xext 等库。库构建共享 sysroot 锁，不能在验收时覆盖正在测试的内核或目标 ELF。验证器将实际内核中的 X.Org、所选窗口管理器和客户端 ELF 与当前目标文件逐字节比对，并记录 SHA-256、进程 AI 状态、串口、QMP 和真实 framebuffer 截图。TWM 路径在第一步后完成其构建，启动与验证均选择 `--wm twm`。

已保存的运行证据（仅覆盖各报告的构建）：

- `artifacts/openbox-verified-release-r4/summary.json`：优化版 Openbox 完整交互回归 PASS，覆盖真实窗口托管、拖动坐标、鼠标点击、小写与 Shift 大写、客户端退出及全部三个进程页额度回收；内核 SHA-256 为 `98d5d6c0d986f210e53a0391877dc47671b17651f5c7071dd6eda9e34e233901`。
- `artifacts/graphics-openbox-release-r2/result.json`：上述同一内核的两次矩形更新全画面像素核对、坏参数及无 GPU 路径 PASS。此构建早于为 GTK 扩大的内核/资产预算，不能作为新 GTK 构建的验收。
- `artifacts/openbox-start-r5/desktop.png`：真实 Openbox 窗口装饰、Roboto 字体及 Xlib 客户端画面；对应串口确认窗口托管和三个独立进程。
- `artifacts/openbox-input-trace/console.txt`：诊断构建实际接收 `KEY ... text=a`、`BUTTON ... x=100 y=100`，并在标题栏拖动后报告 `GEOMETRY x=432 y=365`。这是功能诊断记录，不替代优化版完整回归。
- `artifacts/gtk-verified-release-r4/summary.json`：真实 GTK 窗口/按钮/输入框显示、鼠标点击、键盘输入 `aA`、Openbox Alt+F4 关闭、全部三进程回收 PASS；内核 SHA-256 为 `2c1b21eb05a5ed7b43b27ed762f4ecdbbade6736f72353002c6fd4dfd4193e33`。见 [GTK 构建和运行记录](gtk-cross-build.md)。
- `artifacts/desktop-abi-release-r3/summary.json`：eventfd/目录/身份、pipe、信号、socket 和 Xau 真实 musl 程序退出与资源回收 PASS；其内核 SHA-256 为 `93ec98080879e8c67804a9dc566a2286707059fe4d0ba90f40b33700787728e8`，不包含新文件探针的客体验收。
- `artifacts/desktop-capacity-native-r3/summary.json`：七进程并发、第八次模型拒绝、槽复用、部分双进程启动回滚、高槽匿名页操作和回收 PASS；`artifacts/desktop-capacity-high-slot-elf/summary.json` 验证第七槽真实 musl ELF 及高位物理映像 backing。
- `artifacts/desktop-runtime-openbox/summary.json`：并发 FP/TLS、匿名内存隔离、撤销/NX 故障和回收 PASS。
- `artifacts/ported-openbox/summary.json`：静态 musl、malloc、文件、TLS/FP 与 IRQ、包含 64 页栈的映像回收、缺 RNG 拒绝路径 PASS。

较早 TWM 集成记录保留供回归比较：

- `artifacts/x11-verified-dev-r2/summary.json`：开发版 X11/TWM 端到端 PASS。
- `artifacts/x11-verified-release/summary.json`：优化版 X11/TWM 端到端 PASS。
- 两份报告均验证窗口重新挂接、标题栏拖动后的新坐标、图形像素、鼠标点击、小写/Shift 大写、客户端正常退出，以及结束三个进程后的页额度归还。

报告只覆盖各自记录的映像哈希。测试客户的 PASS 不替代完整桌面验收；库交叉构建报告只证明其构建，实际运行范围由客体记录限定，未调用的库路径仍未验收。

## 当前桌面与证据边界

PCManFM 已通过真实目录创建、文件重命名和内容保持验证（`artifacts/filemanager-large-r3/summary.json`）；LXPanel 的任务栏和显示桌面通过独立验证（`artifacts/panel-verified-r1/summary.json`）。这些早期报告覆盖各自内核身份，最终菜单、终端、保存和资源回收以 [第一版轻量桌面联合验收](lightweight-desktop.md#联合验收) 为准。

GLib/libfm 通过受控的 CyxiaOS spawn 后端启动真实子进程；独立探针覆盖同步/异步启动、跨进程管道、退出通知和等待。LXPanel 使用上游静态 Menu 插件，Openbox 配置真实根菜单。GdkPixbuf 构建包含内建 XPM 解码器，防止 libwnck 默认窗口图标导致面板 abort。缺失 menu-cache 服务返回失败，不提供虚假的动态应用列表，也不使 PCManFM 整体退出。

终端为本项目 Xlib 客户端，连接内核 PTY 和独立 EL0 shell，支持有界文本、实际文件命令、窗口大小通知、Ctrl+C/EOF 及退出回收；它不是 VTE/LXTerminal 移植。持久化为显式双槽检查点，图形保存等待实际第二次 VirtIO FLUSH 成功；未实现通用 fsync、自动保存或大文件系统。

原生线程/文件独立证据：`artifacts/thread-runtime-r2/summary.json` 和 `artifacts/thread-abi-r2/summary.json` 对内核 `d10d9f5923bbfc9227ec91aa332672bfa646cbad035c1ce56e7d05d9d2f1ec55` 为 PASS；覆盖 TLS/FP/SIMD、互斥/条件等待、定向信号、futex、线程容量/复用和组退出，以及 4 KiB 文件、UTF-8 名称和原子普通文件替换。独立存储证据 `storage-verified-r2` 覆盖真实写入、两次 flush、重启恢复、CRC 回退和只读磁盘。均不代表完整 POSIX/pthread 或完整 LXDE 认证。
