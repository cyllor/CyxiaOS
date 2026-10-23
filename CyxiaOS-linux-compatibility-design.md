# CyxiaOS Linux 应用兼容架构

版本：0.2 · 日期：2026-10-16 · 关联总体/详细设计 v0.12。
状态：整体兼容架构仍为分阶段目标；独立 Linux AArch64 syscall 子集已执行指定静态 musl、X.Org/Openbox 和探针，见 [X11 集成记录](docs/implementation/x11-desktop-integration.md)。未实现完整 Linux ABI、动态链接或发行版应用普遍兼容。

2026-10-18：为 COSMIC 增加并验收官方 Rust 标准库的有界运行子集、libwayland 协议通信及 libxkbcommon 键位状态；补充 Linux MAP_STACK 提示、sigaltstack、futex 位集、level/oneshot epoll、clock_nanosleep 与真实非阻塞熵路径。精确镜像、报告和未实现接口见 [COSMIC 移植记录](docs/implementation/cosmic-port.md)。这些新增证据不代表 cosmic-comp、完整会话、wl_shm 或通用 Linux 二进制兼容完成。

## 1. 目标与待确认范围

用户要求移植轻量桌面，并运行大多数 Linux 程序。方案保留自研内核和本地 AI 资源决策，增加 Linux 应用兼容层，配套 [轻量桌面与图形环境](CyxiaOS-gui-design.md)。

当前实施先交叉构建固定版本的 **同架构 AArch64 静态 musl ELF**，由自研内核按独立 Linux personality 执行。源码移植与直接运行发行版原二进制分别标记，不能混用测试结果；后续原二进制验收仍需在 L0 冻结发行版用户空间、运行库和应用清单。Linux ABI 子集已是桌面移植路径的一部分，不再按完全未实现分支描述。

“大多数”是产品目标，不是当前能力或可直接验证的无范围承诺。L0 先冻结具体发行版用户空间、架构、应用版本、插件、工作流及必需功能，按清单报告通过数/总数；失败和跳过保留在分母中，不能静默删除难以支持的应用。样本通过率只代表该清单。

首版不承诺 Linux 内核模块、设备驱动、完整 systemd 启动、容器平台、所有发行版软件包或任意专有 GPU 栈。x86-64 二进制在 ARM 上需要另加指令翻译，32 位 ARM 也需单独 ABI；都不能由 X11/Wayland 或 POSIX 自动提供。

参考：FreeBSD 在自有内核上提供 Linuxulator，说明同类架构路线可行；其兼容性和实现不能直接继承到 CyxiaOS。[FreeBSD Linux 二进制兼容](https://docs.freebsd.org/en/books/handbook/linuxemu/) · [Linuxulator 实现说明](https://docs.freebsd.org/en/articles/linux-emulation/)

## 2. 系统分层

```text
ARM64 Linux 应用：CLI / GTK / Qt / 后续大型桌面应用
          ↓                  ↓
Linux 动态链接器与运行库      X11 / 后续 Wayland 客户端协议
          ↓                  ↓
Linux ABI 适配层             原生移植的 X.Org 服务 / 后续合成器
          ↓                  ↓
统一进程、内存、VFS、IPC、设备对象与本地 AI 资源计划
          ↓
CyxiaOS 自研内核 → AArch64 平台 / VirtIO 显示、输入、块设备、网络
```

原生 POSIX 应用通过 CyxiaOS ABI，Linux 应用通过 Linux ABI；二者复用底层对象与计量，避免两个相互竞争的内存/进程管理器。加载器显式绑定 ABI personality，继承/exec 转换受校验；不能仅凭 ELF OSABI 字节或系统调用号码猜测 ABI。图形服务采用原生后端访问设备，Linux 客户端通过本地套接字与其通信。

采用 Linux 用户态库不等于采用 Linux 内核。主路线不在隐藏虚拟机里运行 Linux，也不依赖宿主执行应用或推理。现成 Linux 根目录只提供文件和运行库，不会自动补齐系统调用。

## 3. 必须实现的契约

| 层 | 必需能力与验证边界 |
|---|---|
| ELF/启动 | 静态和 PIE/动态 ELF、PT_INTERP、段权限/重定位所需映射、启动栈 argv/envp/auxv、TLS；验证解释器和依赖库路径。冻结页大小及目标 CPU 能力 |
| AArch64 上下文 | Linux 程序实际需要的 FP/SIMD 寄存器与控制状态、线程 TLS、信号帧及返回。现有仅通用寄存器上下文必须扩展；不支持的 HWCAP 不宣称支持 |
| 系统调用 ABI | AArch64 调用号/参数/结构体布局/负 errno、部分读写、重启和信号交互；逐项适配，未知调用按契约失败，不能用空实现返回成功 |
| 进程与线程 | 多地址空间、exec、fork/clone 所需共享语义、退出/wait、PID/TID、凭据、信号、pthread 所需 TLS/futex/robust-list/退出唤醒；可选新接口按运行库实际探测处理 |
| 内存 | mmap/munmap/mprotect/brk、匿名/文件映射、共享映射和必要 COW、W^X 与安全清零；JIT/动态重定位需求须有受控策略，不能为兼容全局关闭权限保护 |
| 文件 | VFS、大文件、目录枚举、链接/rename、权限/时间戳、FD 继承与锁、真实持久化；/proc、/dev、所需 /sys 项按实际语义提供，禁止仅伪造路径骗过探测 |
| 事件与 IPC | pipe、Unix sockets、poll/epoll、eventfd/timerfd 等实际使用接口；阻塞/超时、FD 传递、对端凭据和关闭竞争。共享内存不可跨所有权泄漏 |
| 运行库 | 冻结一套 glibc/动态链接器及依赖，再支持 libstdc++、图形库、字体/locale、DNS/NSS 等；版本化符号和模块加载真实可用 |
| 系统服务 | 会话 D-Bus、XDG 目录/菜单、文件通知、字体发现；电源/网络/音频由可用的 CyxiaOS 服务适配，缺失功能明确不可用 |
| 终端与网络 | PTY/TTY、termios、进程组/作业控制；网络应用另需 TCP/IP、DNS、时钟与可信证书数据，不能把能开窗口当成网络可用 |
| 设备接口 | Linux ioctl 是设备专用契约，不能由通用 syscall 翻译代替。先原生移植图形服务器并用软件绘图，DRM/KMS、GPU 与音频接口按应用需求另验 |

Linux 兼容范围必须超出 POSIX 核心接口；上表是待细化需求，不能视为完整 Linux API 清单。[Linux 用户空间 API 文档](https://www.kernel.org/doc/html/latest/userspace-api/index.html)

## 4. AI 与兼容语义

本地 AI 决定 Linux 进程的正常 CPU 调度、内存准入、设备/文件请求资源份额和后台缓存预算。Linux ABI 负责解码与行为转换，内核负责隔离、计量、协议顺序及已授资源履约。不能再运行独立 Linux 调度器，也不能让兼容层自行决定资源竞争赢家。

`sched_*`、优先级、时限和资源限制形成明确约束，AI 只在可行集合中决策；尚不支持的策略按适用 ABI 拒绝。futex 唤醒、信号、X11 请求顺序、文件字节与点击目标不由模型改写。恢复和防饥饿路径单独记录来源，模型失效不改变已成功提交的 I/O 结果。

程序与模型都在客体执行。在线学习使用资源特征，不默认收集用户输入、屏幕或文件内容；模型版本切换须回归 Linux 与 POSIX 语义，不因性能提升接受兼容性倒退。

## 5. 分阶段交付

所有阶段均待执行；不以原有 POSIX 测试替代本表证据。

| 阶段 | 交付 | 退出条件 |
|---|---|---|
| L0 | 冻结二进制/源码范围、用户空间版本、应用清单、版本/许可证/哈希、ABI 与资源预算 | 每个样本具有可复现工作流；系统调用/库/服务依赖矩阵和差距清单可追踪；不冻结尚未验证的“全部软件支持” |
| L1 | 通用多进程、映射、ELF/TLS、FP/SIMD、线程基础和 Linux ABI 入口 | 原生与 Linux ABI 进程同时运行且无编号混淆；静态 Linux ELF 正常/错误/抢占用例通过 |
| L2 | 动态链接器、运行库、信号/线程/futex、Unix socket/事件、VFS/PTY | 未重新链接的指定 ARM64 Linux 命令行程序可运行，动态库、线程及文件行为通过差分测试 |
| L3 | 原生 X.Org 与设备后端、Linux X11 客户端连接 | 两个独立 Linux 客户端可绘图/输入/关闭；崩溃回收和权限测试通过；设备资源受 AI 计量 |
| L4 | LXDE 核心桌面、GTK 应用、Qt 应用运行库及会话服务 | 面板、窗口、文件管理、终端与菜单启动真实可用；分别通过至少一个 GTK 和 Qt 应用工作流；不能据此宣称“大多数” |
| L5 | 更广应用、网络/音频、Wayland 与 Xwayland、受限学习和性能调优 | 逐应用公开兼容矩阵，测量资源/响应；大型应用所需沙箱、JIT、服务和设备能力单独关闭差距 |

L1/L2 与图形驱动可并行开发，但窗口服务器和桌面验收依赖真实多进程与 IPC。首批应用可选 shell/文件工具、小型 X11 客户端、文本编辑器和轻量 Qt 示例；准确项目与版本在 L0 冻结。浏览器、Electron/VS Code、办公套件和游戏列为后期目标，不承诺随桌面一同运行。不通过关闭沙箱来宣称正式兼容。

## 6. 包、磁盘与内存

程序运行与包管理是两个验收项。第一阶段使用带哈希和依赖清单的受控用户空间映像；解包不等于安装脚本、触发器、账户创建或服务启动已可用。后续单独验证软件包安装、升级、回退及持久化。

RAMFS 源码当前为 64 节点、可写文件上限 4 KiB，新增 UTF-8 名称和普通文件原子重命名已通过真实 musl 客体验收（`thread-abi-r2`）；只读引导资产已经承载字体和配置，受控目录中的静态 ELF 由装载器映射。每进程已有 16 MiB 映像额度（含 256 KiB 栈）和 8 MiB 匿名额度，详情见 [内存实施记录](docs/implementation/desktop-memory-display.md)。正式桌面仍需持久可写用户目录、大文件及后续动态库装载。X.Org/Openbox 集成仍使用单核 256 MiB QEMU；完整桌面可再评估 1 GiB 集成配置，这只是候选，不能当作最低需求或已改动的启动参数。

LVGL 原方案的 24 MiB 预算撤销，不适用于 Linux 桌面。资源总账分别记录内核/模型保留、页表、共享库唯一物理页、每进程私有页、图形缓冲/缓存、文件缓存及恢复余量；不能把各进程 RSS 相加当成实际总占用。硬上限、AI 授予和实际使用分别报告。

## 7. 验证与支持声明

LC-T01：ELF/解释器/auxv/ABI 分流、未知调用与错误结构；LC-T02：进程/线程/信号/TLS/FP 状态隔离；LC-T03：映射、权限与共享/COW；LC-T04：futex/事件/IPC/FD 传递的竞争和取消；LC-T05：VFS、持久性、PTY、网络及动态库行为；LC-T06：X11/GTK/Qt 实际应用工作流；LC-T07：AI 竞争、超时和模型回退；LC-T08：安装/重启/恢复、内存压力与既有内核回归。

每个应用记录：名称、版本、ISA、二进制/源码移植方式、包/库哈希、窗口协议、必需功能、通过/部分/失败/未测、原因和证据路径。差分参考机使用冻结的真实 ARM64 Linux 环境；参考 Linux 仅用于测试，不成为 CyxiaOS 运行依赖。

主机截图只观察客体输出；不得用远程 Linux 桌面或宿主运行程序充当移植完成。无窗口截图也不能证明文件、线程、信号或沙箱正确。未执行的测试与未知依赖保持可见，不沿用 v0.7 审核结论。
