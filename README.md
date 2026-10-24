# CyxiaOS

不基于 Linux 的实验性操作系统。目标是由本地 AI 决策资源分配，由内核执行安全约束和资源机制。

当前代码包含 **M1 单核 ARM 内核、基础 Shell、AI 文件系统，AI 内存/任务/设备管理切片，以及 EL0/POSIX 文件接口子集**。可在真实 QEMU ARM 客体中管理目录和文件，本地整数模型负责写入准入与缓存排序，并支持候选训练、验证、显式发布及回退。**文件在 RAM 中运行；连接专用 VirtIO 磁盘并执行 `storage checkpoint` 后可重启恢复，未保存修改和学习状态会丢失。尚无全系统统一 AI 调度。** HTML 文件保留为早期设计原型。

## 原生轻量桌面

正在移植 **COSMIC**，当前进度及明确缺口见 [COSMIC 移植记录](docs/implementation/cosmic-port.md)，后续阶段与验收见 [COSMIC 移植计划](CyxiaOS-COSMIC-port-plan.md)。已验证全局文件描述、跨进程 FD 传递和真实共享页，[上游 wl_shm](docs/implementation/wayland-shm.md) 已通过独立客户端图像与键盘映射传输测试；[Mesa 软件 EGL/GLES](docs/implementation/mesa-softpipe-port.md) 已通过离屏与 Xorg 窗口像素验证。现有桌面启动器仍启动下述 Xorg/Openbox/LXPanel 组合，尚不能启动 COSMIC 会话。

2026-10-22 最新增量：[Smithay 锚定缩放与抓取清理](docs/implementation/smithay-resize-native.md) 已通过三次独立 ARM 启动：左上角及左边缘缩放在确认配置并提交匹配缓冲后同时更新位置和尺寸，普通重绘保留新原点；按钮仍按住时关闭窗口后，正确清理焦点并处理背景上的实际释放。通用几何模块实现并单测八个缩放方向，客体验收覆盖左上角和左边缘。36 个实际显示场景累计校验 442,368 个像素，全部资源归还；本地 AI 模型与限额未改变。[本轮证据汇总](artifacts/cosmic-port-20261022-r5/summary.json) 同时记录原桌面 21 组回归及上一轮移动/右下角缩放三次回归。动态客户端接入、通用窗口管理与完整 COSMIC 会话尚未实现。

已实现真实 X.Org、Openbox、PCManFM、LXPanel，以及原生 PTY 终端/shell 和图形保存入口。程序在自研 ARM 内核的独立 EL0 进程中运行，本地模型决定进程、内存和 CPU 资源准入/派发。桌面使用单核、512 MiB QEMU 配置；默认 256 MiB 基础内核继续保留。具体可用功能、联合验收和限制见 [第一版轻量桌面](docs/implementation/lightweight-desktop.md)。

双击 `Start-CyxiaOS-Desktop.command`，或在项目目录运行：

```sh
python3 tools/desktop.py
```

左下角菜单提供 **Files**、**Terminal**、**Save Files**。终端可用 `mkdir`、`write`、`cat`、`ls` 等内建命令操作客体文件，Ctrl+C 中断输入/等待，Alt+F4 关闭窗口。修改后选 **Save Files** 并等成功提示，再退出 VM；默认专用数据盘为 `artifacts/cyxia-data.raw`，已有数据盘不会被自动覆盖。

这是第一版有界轻量桌面。完整 LXDE 的 LXSession、动态应用菜单服务和 VTE/LXTerminal 尚未移植；通用 Linux 二进制、动态链接和完整 POSIX shell 仍未实现。独立 GTK 控件入口为 `--app gtk`，TWM 为 `--wm twm --app x11`。详细历史证据见 [X11 集成记录](docs/implementation/x11-desktop-integration.md)。

## 启动交互 Shell

双击 `Start-CyxiaOS.command`，或在项目目录运行：

```sh
python3 tools/shell.py
```

看到 `cyxia:/>` 后输入 `help`。试用 `mkdir /docs`、`write /docs/hello Hello`、`cat /docs/hello`、`ai status`。Ctrl+C 取消输入，Ctrl+] 退出虚拟机。当前源码容量为 64 个节点、每文件 4096 字节，支持 UTF-8 名称；带空格路径须由文件 API 使用，Shell 尚无引号解析。容量扩展与普通文件原子重命名已通过真实 musl 客体验收，见 `artifacts/thread-abi-r2/summary.json`。详见 [命令、AI 机制与学习边界](docs/implementation/shell-ai-fs.md)。

磁盘持久化：先运行 `python3 tools/storage.py artifacts/cyxia-data.raw` 创建空磁盘，再用 `python3 tools/shell.py --disk artifacts/cyxia-data.raw` 启动。客体中执行 `storage checkpoint`，等待 `STORAGE_DURABLE` 后再退出；下次使用同一磁盘即可恢复。该功能已通过真实写入、重启、CRC 故障回退和只读磁盘验证，详见 [存储实现](docs/implementation/persistent-storage.md)。这是显式检查点，尚无 `fsync` 或自动保存。

## AI 资源管理

新增 `mem status/alloc/free/peek/poke`、`proc spawn/list/pause/resume/kill/reap`、`dev list/read/write/batch/requests`、`ai resources/audit`。本地整数模型控制页准入、协作式任务运行顺序/工作额度和竞争设备请求排序。

```text
proc spawn compute 1000000 1 1
proc spawn memory 9000 2 3
ps
mem status
dev batch 4
ai resources
ai audit
```

当前是 **32 页真实 RAM 池、8 个协作式 EL1 内核任务、UART/Timer 普通请求通道**，此处的 `proc` 命令仍管理协作任务；另有下述可被中断抢占的隔离 EL0 进程入口，尚无全 RAM 虚拟内存服务。详见 [资源管理实现与测试说明](docs/implementation/ai-resource-management.md)。

## POSIX 兼容子集与用户态

```text
posix run demo
posix status
cat /posix-result
posix run preempt
```

真实 C 程序在 EL0 通过系统调用执行 `open/read/write/close/lseek/dup/dup2` 等接口，文件服务与 Shell 共用。AI 控制用户页准入及 1/4 ms 派发预算；内核提供权限检查、IRQ 抢占和故障回收。在原生 POSIX 子集之外，已增加独立的 Linux AArch64 syscall personality，运行本项目交叉构建的静态 musl ELF，支持匿名内存、Unix socket、eventfd、目录读取和部分信号语义。已有单核最多 8 个线程上下文的真实 musl pthread/clone/futex 子集验证。**尚不支持通用 fork/execve、完整 pthread、动态链接和完整 POSIX/Linux ABI；指定静态移植程序的成功不代表任意 Linux 二进制兼容。** production 构建需要已安装的 Clang，链接器复用 Rust LLD。[POSIX 第一阶段说明](docs/implementation/posix-compatibility.md)保留原生接口范围；当前桌面兼容层见 [X11 集成记录](docs/implementation/x11-desktop-integration.md)。

已有 [桌面 D2 多进程与 IPC 基础](docs/implementation/desktop-process-foundation.md)：`posix spawn idle|spin|fault`、`posix pair`、`posix list`、`posix kill PID`。本地 AI 选择活动进程与时间预算，8 个槽最多同时准入 7 个独立进程，并保留 8 页启动余量；支持有界双向通信、等待/唤醒和故障回收。X.Org、窗口管理器和测试客户端使用这条真实调度路径并发运行；七进程并发与第八次拒绝、槽复用和高槽内存回收已经验证；第一版桌面常驻四进程，加一个终端及其 shell 为六进程，保存对话框短时为七进程；更多应用会受实际准入额度限制。

进一步实现了 [匿名内存、FP/TLS 与用户态绘制](docs/implementation/desktop-memory-display.md)：默认每槽 8 MiB 匿名窗口，512 MiB 桌面配置为每槽 16 MiB，本地模型决定内存准入；静态 ELF 映像与 256 KiB 栈共享每槽 16 MiB 映像额度；保存完整浮点/向量与 TLS 寄存器，musl 可初始化静态 TLS。EL0 程序可向真实 GPU 提交矩形并等待异步 fence。可试 `posix spawn heap`、`posix spawn fpu`，或 `python3 tools/graphics.py --paint` 查看绘制验证。**1/4 ms 预算约束 EL0 派发，不是系统调用或交互响应的硬截止。** Linux personality 的 mmap/mprotect/munmap 只覆盖已验证子集；线程子集有独立真实 musl 客体验证，不代表完整 pthread。

## 轻量桌面与 Linux 应用规划

目标为 **LXDE 轻量桌面 + X.Org/X11 + Linux 应用兼容层 + GTK/Qt 运行库**，后续扩展 Wayland/Xwayland。兼容层保留自研内核与本地 AI 调度；当前已运行指定静态移植程序，发行版原二进制与广泛应用兼容仍待逐项验收。`python3 tools/graphics.py` 保留真实客体彩条和原始输入诊断，见 [实现与验证](docs/implementation/graphics-bringup.md)；原生 X11 集成使用独立桌面启动入口。

详见 [桌面移植设计](CyxiaOS-gui-design.md)和 [Linux 应用兼容设计](CyxiaOS-linux-compatibility-design.md)。原 LVGL 工作台路线已被替代；现有 POSIX/Linux ABI 子集及 X11 集成不能视为完整 Linux 应用环境。

桌面上游版本和真实剩余依赖见 [移植清单](docs/implementation/desktop-port-inventory.md)。源码身份、构建和运行验收分别记录；获取到上游源码不代表已经移植成功。

## 最小原型规范与安全核心

`crates/kernel-core/src/control_plane` 和 `cluster` 包含有界控制/集群安全管理逻辑及主机回归测试，但尚未接入独立控制 EL0 服务、次级 CPU、原生网络与集群执行后端。源码合入和主机 CI 通过不代表四核双平面、双原生客体或完整 COSMIC 已验收。

[全系统代码与规范缺口复核](docs/implementation/prototype-gap-review.md) 区分本轮已修缺陷、架构接入缺口和文档歧义；[要求追踪目录](docs/implementation/prototype-requirements.json) 覆盖 A/T/AI/V/组合故障及16个同等地位的一级子系统。`tools/check_prototype_evidence.py` 只检查证据完整性和文件身份，不认证运行真实性；`--release` 在强制项缺少 PASS 证据时拒绝通过。

**持久格式注意：**本轮成员绑定和复制提交历史使用存储版本2，旧版本1因缺少历史返回 `Version`；不能删库重建绕过，生产迁移工具尚未交付。详见 [集群安全核心边界](docs/implementation/cluster-safety-core.md)。正式集群成员仍须原生运行 CyxiaOS，不引入宿主系统代理节点。

## 构建与验证

在项目目录执行，Python 仅需标准库：

```sh
python3 tools/doctor.py --json
python3 tools/build.py --profile dev
python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --case all
python3 tools/verify_m1.py --output artifacts/m1-final
python3 tools/coverage.py
```

环境：Rust/Cargo 1.95.0、目标 aarch64-unknown-none-softfloat、rustfmt/clippy/llvm-tools-preview；QEMU 10.2.2。当前使用已安装 stable 并强制版本校验，避免重复安装；如果本机 stable 升级，须使用精确 1.95.0 工具链或重新验收，不能绕过 doctor。

基础裸机配置：virt-10.2、Cortex-A53、TCG、1 CPU、256 MiB、GICv2，无磁盘和网络；桌面使用独立的 512 MiB 配置及 VirtIO 显示/输入/RNG/数据盘。完整测试包含开发/优化映像、日志停读压力和无 selftest 的启动。`--case pressure` 仅用于默认自检构建。

```sh
python3 tools/build.py --profile release --production
python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --case boot-entry
```

结果保存在指定 artifacts 目录，包括原始串口帧、解析文本、QEMU 参数、映像哈希和 JSON 结果；压力场景的日志不完整是预期结果，会明确记录缺帧。

## 设计与实施

- [轻量桌面与图形环境移植](CyxiaOS-gui-design.md)
- [Linux 应用兼容架构](CyxiaOS-linux-compatibility-design.md)
- [POSIX 兼容需求与架构](CyxiaOS-posix-design.md)
- [完整系统路线](CyxiaOS-code-implementation-plan.md)
- [M1 任务计划](CyxiaOS-code-m1-plan.md)
- [M1 接口与边界](docs/implementation/m1-interfaces.md)
- [M1 实测环境](docs/implementation/m1-environment.md)
- [实现状态](docs/implementation/m1-status.md)
- [AI 决策契约](CyxiaOS-ai-decision-contract.md)

源码按 contracts / kernel-core / arch / platform / drivers / kernel 分层。跨平台和多核已有接口边界，但本轮仅验证上述单核 QEMU 配置，未验证实体硬件。

## 全系统 AI 强化状态

在 CyxiaOS 串口 shell 执行 `ai system`，查看进程/线程、CPU、内存、文件缓存、存储、IPC、显示的真实模型与执行计数、学习状态和未实现项。新增显示提交节奏与存储块请求额度，修正提案/执行混计；全部使用客体本地模型。详见 [落地清单与证据](docs/implementation/system-ai-status.md)。目前只有文件缓存支持受限在线学习；全局协调、全域学习、网络和多核尚未完成。

## 原生多核机制工作包（未替代生产桌面）

新增 `smp-selftest` 在四 vCPU 原生客体执行分离 EL0 上下文、私有定时器抢占、派发排空与测试提案的 1→2→1 核迁移。控制程序是测试 fixture，不是模型；不宣称生产隔离、物理独占、原生集群或完整 COSMIC 已完成。执行及证据范围见 [原生多核机制说明](docs/implementation/native-smp-mechanism.md)。

### 独立 EL0 模型控制服务（显式原生集成配置）

`ai-control-selftest` 在四核原生 CyxiaOS 客体中运行独立编译的 Rust 模型服务，
经受信任边界校验后执行模型提出的核心扩缩容，并检查故障隔离和新代际恢复。
输入为冻结合成遥测，不声明真实性能收益、完整16域模型、默认桌面隔离或联网集群完成。
构建、故障程序和取证方法见 `docs/implementation/native-ai-control-service.md`。
