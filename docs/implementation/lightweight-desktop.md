> 2026-10-18 AI 补强：当前资源策略、真实执行计量及新显示/存储策略的独立候选验收见 [全系统 AI 强化落地清单](system-ai-status.md)。本文原 r4 桌面证据仍作为该历史候选记录保留。

# CyxiaOS 第一版轻量桌面

更新：2026-10-18。本文记录实际可构建的第一版桌面组合；最终验收证据在文末单独列出。完整 LXDE、发行版原二进制与大多数 Linux 程序兼容仍是后续工作。

## 组合与进程

客体为自研 Rust/no_std ARM64 内核，QEMU virt 单核 Cortex-A53、512 MiB RAM、1024×768 VirtIO GPU、VirtIO 键鼠、RNG 和专用数据磁盘。所有桌面程序在客体 EL0 中运行；宿主 Python 负责构建、引导顺序和采证，实际文件操作、窗口、键盘、PTY、子进程与磁盘事务均在客体执行。

| 程序 | 实际职责 |
|---|---|
| X.Org 21.1.25 | CyxiaOS DDX 连接真实 VirtIO 显示和输入；软件绘制 |
| Openbox 3.6.1 | 窗口边框、移动/缩放、焦点、关闭和工作区 |
| PCManFM 1.3.2 / libfm | 桌面背景、图标和目录窗口；同一进程通过真实 Unix socket 单实例 IPC 打开更多目录窗口 |
| LXPanel 0.11.1 | 上游面板、任务栏、显示桌面、工作区、UTC 时钟及静态 Menu 插件 |
| cyxia-terminal | 原生 Xlib 终端，连接内核 PTY；有界 ASCII 字符网格和基本 ANSI 光标/清屏子集 |
| cyxia-sh | 独立 EL0 shell，通过真实 PTY 执行有界文件内建命令 |
| cyxia-save | 原生 Xlib 保存对话框，等待真正的第二次磁盘 flush 后才报告成功 |

空闲桌面常驻四进程；一个终端及其 shell 增至六进程，保存窗口短时增至七进程。内核有八个槽，本地模型最多准入七个活动进程，保留底座余量。PCManFM 单实例启动的临时进程退出后释放额度。此组合不额外常驻 LXSession、menu-cached 或 VTE/LXTerminal；这些上游组件没有被换名宣称已移植。LXPanel 使用其真正的静态 Menu 插件，尚无动态应用菜单扫描。会话启动目前由宿主启动器顺序编排，尚无客体登录管理器、自动服务重启或完整会话恢复。

## 操作

在项目目录执行 `python3 tools/desktop.py`，或双击 `Start-CyxiaOS-Desktop.command`。启动器只使用已构建 sysroot，不自动下载源码。默认挂载 `artifacts/cyxia-data.raw`；不存在时以排他创建方式建立专用空磁盘，已有磁盘不会被覆盖。`--disk PATH` 选择其他已存在的专用 CyxiaOS 数据盘。

左下角菜单提供 **Files**、**Terminal** 和 **Save Files**。标题栏可拖动，按住 Alt＋鼠标右键拖动调整窗口大小，Alt+F4 关闭当前窗口。任务栏点击可最小化/恢复，显示桌面按钮可隐藏/恢复应用窗口。面板时间来自客体 PL031 RTC，当前固定 UTC，精度为一秒。

文件管理器可浏览目录、创建目录、重命名普通文件。文件存储有界：总共 64 个节点（含必要目录）、单个可写文件最多 4096 字节，路径使用 UTF-8 且长度受限；不支持目录整体重命名、符号链接或任意大文件。只读引导应用与资产由独立目录提供，不受单文件 4 KiB 限制。

终端示例：

```text
mkdir /work
write /work/hello.txt hello CyxiaOS
cat /work/hello.txt
ls /work
sleep 10
```

Ctrl+C 中断输入或 sleep，Ctrl+D/`exit` 退出 shell；`help` 查看内建命令。支持简单引号和转义；尚无管道、变量展开、通用外部命令执行和完整作业控制，不能当作 bash 或完整 POSIX shell。

文件编辑先发生于 RAM。完成修改后选 **Save Files**，等待明确的成功提示，再关闭 VM。保存捕获调用时的文件快照；之后的新修改需要再次保存。没有自动保存或通用 `fsync`；直接关闭 QEMU 会丢失未保存修改。保存失败/没有磁盘/只读磁盘必须显示错误，不能把开始提交当成成功。数据盘为自定义双槽快照格式，不能当 FAT/ext4 挂载。

## 资源决策与机制

进程与 PTY 准入使用本地整数模型 8193；匿名内存与检查点 staging 使用模型 8194；ELF 映像页使用 8195；运行选择使用 12289，时间预算使用 12290。文件写入继续经过本地文件策略。模型结果必须经过实际容量、所有权、权限和 grant ledger 检查。失败明确拒绝，不通过随机选择或常量成功代替模型。

固定引导物理池属于 BOOTSTRAP；协议、页表、文件内容、用户输入和已提交 I/O 完成属于确定性机制。AI 不改写命令语义或文件内容。现有本地模型为有界整数策略模型，不能称为已实现大语言模型大脑或已经验证全域自主学习。

512 MiB 桌面配置保留 64 MiB 内核区、128 MiB 匿名池（每槽 16 MiB）、128 MiB 映像池（每槽 16 MiB，含 256 KiB 用户栈），剩余 RAM 未交给通用分配器。默认 256 MiB 内核保持原每槽 8 MiB 匿名池。资源预留不是实际常驻工作集；性能和实体硬件支持没有据 QEMU 成功推定。

## 兼容边界

程序为针对本项目静态交叉链接的 AArch64 ELF。GLib 通过明确启用的 CyxiaOS 原生 spawn 后端启动目录中的独立程序，支持参数/环境/目录、限定 FD 映射、等待和退出通知；没有伪造 fork/vfork/execve。真实线程子集、共享管道、PTY 和 Unix socket 有独立探针，但不能替代完整 POSIX、动态链接或 Linux 原二进制认证。GTK/Qt 通用应用、网络应用、完整 LXDE 服务与 VTE 留在后续兼容阶段。

## 联合验收

联合候选为 [`artifacts/desktop-integrated-r4/cyxia-kernel.elf`](../../artifacts/desktop-integrated-r4/cyxia-kernel.elf)，SHA-256：`f432d168507faf0276f97dd4689401314d91d9b90c5b08c67ca054b990a929ee`。该候选包含 `graphics,lxpanel,large-memory,spawn-test`，最后一项只额外嵌入诊断程序；正常 `tools/desktop.py` 构建不含该额外诊断 feature。各实际嵌入 ELF 的逐字节匹配与哈希在 [identity.json](../../artifacts/desktop-integrated-r4/identity.json)。

| 工作流 | 结果与证据 |
|---|---|
| 物理菜单与文件操作 | [菜单报告](../../artifacts/desktop-integrated-r4/menu/summary.json) PASS：Files 启动、真实重命名、可选应用菜单缺失时不退出、Openbox 根菜单启动的新窗口/父子 PID 因果 |
| 图形保存和重启恢复 | 同一菜单报告 PASS：保存 generation 0→1，FLUSH 0→2，存储完成日志严格早于 GUI 成功，staging 128 页归还；新 VM 恢复文件内容且不包含保存后的修改 |
| 面板 | [面板报告](../../artifacts/desktop-integrated-r4/panel/summary.json) PASS：同一真实窗口的任务栏最小化/恢复、显示桌面隐藏/恢复、四进程资源全部回收 |
| 图形终端 | [终端报告](../../artifacts/desktop-integrated-r4/terminal-final/summary.json) PASS：菜单启动、键盘文件读写、Alt+右拖缩放及 PTY 尺寸读回、阻塞 sleep 的 Ctrl+C、exit 和窗口关闭的 SIGHUP/等待回收 |
| 七进程联合容量 | [并发报告](../../artifacts/desktop-integrated-r4/peak-seven-r3/summary.json) PASS：桌面四常驻＋终端/shell＋保存窗口同时存活，底座余量 8 页；两次 flush 完成、所有资源回收，新 VM 恢复终端写入的精确 17 字节文件 |
| PTY 与 spawn | [PTY](../../artifacts/desktop-integrated-r4/pty/summary.json)、[spawn](../../artifacts/desktop-integrated-r4/spawn-smoke/summary.json) PASS：有界 I/O、canonical/echo/EOF、实际 shell、超长行不执行、信号及生命周期；spawn 参数/环境/cwd、管道、等待、错误原子性和退出收据 |
| Linux ABI 子集 | [六探针报告](../../artifacts/desktop-integrated-r4/abi/summary.json) PASS：事件/目录/身份、pipe、文件、信号、socket、Xau 与资源回收 |

真实 framebuffer 截图：[保存成功](../../artifacts/desktop-integrated-r4/menu/desktop-saved.png)、[终端缩放与命令](../../artifacts/desktop-integrated-r4/terminal-final/terminal-resized.png)。截图未经重绘；交互结论还由客体文件、进程状态与原始 QMP/串口证据交叉确认。

内核基础的完整回归保留在前一个固定候选 `ff69fa8f88598219cc0b6220513045403b085e79655c6f45bd16ae68ea59e138`：[线程三次/GLib spawn/PTY三次/ABI](../../artifacts/final-process-gates-r3)、[内存与 FP/TLS](../../artifacts/desktop-integrated-r3/runtime/summary.json)、[进程容量和 IPC](../../artifacts/desktop-integrated-r3/services/summary.json)、[磁盘多代/损坏回退/只读/无盘](../../artifacts/desktop-integrated-r3/storage/summary.json) 均 PASS。后续 r4 只变更桌面应用与只读配置，重新执行以上 r4 交互及 ABI/PTY/spawn 回归；不把旧报告改写成新哈希的结果。

[最终汇总](../../artifacts/desktop-integrated-r4/summary.json)绑定上述七组报告及文件摘要。主机工作区 249 项测试通过（[日志](../../artifacts/desktop-integrated-r4/host-rust.log)）；大池配置 123 项通过（[日志](../../artifacts/desktop-integrated-r4/host-large-memory.log)）；Python 工具 87 项通过（[日志](../../artifacts/desktop-integrated-r4/host-python.log)）。默认和桌面内核 release Clippy 无警告。64 KiB 带 guard 内核栈保留，消除了 PageBatch 大数组返回复制并隔离大 spawn 帧；反汇编量化的 mmap 与正常 IRQ 调用链约 33,552 字节，不宣称全部内核路径的形式化栈证明。

完整 LXDE 服务集合、动态应用安装、通用 Linux 二进制兼容、多核及实体硬件不在这些 PASS 的覆盖范围。第一版文件容量和显式保存边界仍适用。
