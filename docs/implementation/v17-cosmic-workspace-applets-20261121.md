# COSMIC 工作区与平铺组件移植

本轮固定 Epoch `cosmic-applets` 提交
`406d1b7d627138fdf4078f654268d3d8774e50f1`，构建原版
`cosmic-applet-tiling` 和 `cosmic-applet-workspaces`。原 19 成员工作区、
637 包解析图及根包默认功能保留。工作区列表是可选 applet，不能计作
`cosmic-workspaces` 概览主程序，也不能替换默认 overview button。
完整 COSMIC 会话的验证标记保持 false。

## 构建与运行边界

- SDK 增量：真实 libinput 1.29.0、eudev 3.2.15、libevdev 1.13.4、
  mtdev 1.1.7，Linux 6.18 仅提供 UAPI。固定下载哈希与许可证见
  `ports/cosmic/native-input-sdk-v1/sources.json`。不代表客体支持 Linux
  sysfs/netlink 或 libwacom。原 SDK 的 15 个静态输入逐字保留。
- `libudev-sys` 原 build.rs 的 hwdb 探测调用裸 `rustc`；严格适配器仅对
  固定源码和参数加入真实交叉目标及链接参数，目标链接成功，不在宿主执行。
- 新 session/panel 使用原源码、锁文件和既有功能配置，第一层修改为
  native-child FD 传递上限 64→128；panel 另叠加下述三个文件的输入区域修复。
  完整编译分别为 125/473 包。
  Panel 继续选中已验证的 Mesa Wayland OOM 修复对象。两 applet 最终链接
  未选中这个翻译单元，不能宣称它们执行了该修复路径。
- 新 `cosmic-workspace-applets-v1` profile：FD 128/进程、全局 OFD 512、
  Unix 端点/连接 128/64、共享对象 32、共享映射记录 32/进程。
  对象契约同时绑定两个实际宿主 ELF，拒绝旧宿主混用。OFD 弱身份在新配置
  使用 9 位槽号，旧配置仍为 8 位；测试覆盖实际全槽及不同 generation。
- 映射准入使用版本化模型 8204，复用共享元数据线性权重并穷举 0..32
  空闲、1..32 请求域。映射不分配新的物理页；物理页仍经原独立准入与账本。
  旧配置的共享映射上限 16、准入模型 8193 保留。
- 新会话 bus 每用户/总完成连接上限为 32，旧配置 16 已被实测耗尽并持续重试；
  其他认证、权限、消息和 FD 限额保持。原 SVG 另增加本仓 fallback 主题目录
  索引，未将小型索引声明为完整 COSMIC/Pop 图标主题。
- 所有 QEMU 回归限定 1024 MiB、4 CPU。共享物理页仍 4096 页（16 MiB），
  原映像、堆、线程和页池额度保持。新 ROM 输入上限 256 MiB、内核 ELF
  文件读取上限 384 MiB；文件上限与客体 RAM、进程授权分别约束。

## 真实失败推动的修复

初版客体暴露旧 Unix 端点/连接池接近耗尽，平铺 applet 的 Tokio UnixStream
返回 EAGAIN。随后发现原 panel 稳态已占 60/64 FD，启动子进程还需临时管道；
因此内核扩大 FD 配额必须与原生宿主传递数组同步构建，单改内核不充分。

`v017-workspace-tiling-1g-v3` 实际同时启动了平铺和时钟：panel 占 70 FD，
全局 OFD 256，共享对象 17。点击平铺菜单触发 `wl_shm: Failed to mmap fd 70`，
平铺子进程退出。AI 账本记录共享映射 3 次拒绝、模型 8193；物理共享页远未满。
修正是版本化映射记录及元数据准入，保留失败日志，未将失败转记通过。
该失败捕获的全部用户进程终止后，匿名页、OFD、共享对象/页/映射/引用/授权均归零。

`v017-workspace-tiling-1g-v6` 已观察平铺状态 0→1→0，并恢复共享基线，
但长篇 `ai system` 在 8192 字节处截断，未取得结束标记，整次捕获仍为失败。
新增 `ai objects` 短只读快照，保留实际 OFD/共享/匿名对象、三项共享准入
计数和每进程 FD。原完整快照与旧时钟探针默认路径保留；新探针必须收到
短快照结束标记，仍检查相同资源、原生状态和真实回收，不把截断输出记为通过。

## 重现入口

所有编译器与 QEMU 共用 `native_lease` 排他锁；新输出不得覆盖旧证据。

1. `tools/build_cosmic_input_sdk_v1.py`：构建并验真实静态输入。
2. `tools/build_cosmic_workspace_applets_v1.py`：完整原版两个根包。
3. `tools/build_cosmic_applet_host_v1.py`：分别构建配对 session/panel。
4. `tools/relink_cosmic_workspace_applets_v1.py`：供给修复对象并记录实际选中情况。
5. `tools/build_workspace_state_probe.py`：固定原版 XML 的只读状态观察器和独立
   xdg 测试窗口。观察器不发送激活/平铺请求；窗口只占用动态工作区。
6. `tools/assemble_cosmic_workspace_applets_v1.py`：重验完整源码、SDK、原始链接、
   两宿主后原子安装；仅替换两个宿主及明确记录的会话 bus 配置。
7. `tools/os_x86.py build --profile release --graphics --ported --feature cosmic-workspace-applets-v1 --sysroot CATALOG --output BUILD`。
8. `tools/os_cosmic_workspace_probe.py --build BUILD --output CAPTURE --observe-seconds 60`：
   实际 QMP 鼠标输入→独立工作区状态→原日历两轮→进程存活→全部资源回收。
   首帧仍按原 45 秒门槛，60 秒诊断不能把迟到帧记成通过。
9. 可选工作区列表使用 `tools/assemble_cosmic_optional_workspace_v1.py` 仅追加用户
   plugins_wings 配置，原始 45 项配置和 18 个默认身份保留；单独编译/捕获，
   探针加 `--workspace-x 60 --workspace-first-x 28`。新映射窗口产生第二工作区，
   切换必须由原版 applet 接收鼠标操作完成。

## 尚缺的完整会话

仍须移植或验证原版 cosmic-app-library、cosmic-launcher、cosmic-workspaces、
cosmic-osd、cosmic-osk、cosmic-bg、cosmic-greeter、cosmic-files-applet、cosmic-idle，
以及其余默认 applet。不能删除缺失身份、替换成诊断程序或仅凭交叉编译宣称完整桌面。

## 控制台背压与探针修正

三 applet 捕获 `workspace-list-1g-v1` 的完整进程列表超过串口突发接收能力，
输出中途 QEMU 退出；该捕获仍记为失败。PC OS 原 `try_log` 将 UART 短写
当成整次格式输出失败，长诊断可能截断或触发上层 expect。新增 CPU0 独占
128 KiB raw FIFO：入队全收或拒绝，按真实已发送字节推进，Again/零进展
保留尾部，前后每轮各排出至多 1024 字节。积压超过 4096 字节时暂停接收
下一段命令；用户/共享物理页池保持，另增加 128 KiB bootstrap 诊断存储。
原 CRC 帧的部分发送仍为不可重试失败，未用 raw 队列改变该契约。

实际截图显示中性桌面点击、Escape 均未可靠关闭平铺菜单，原先部分“重复开关”
捕获甚至没有打开菜单，不能当作生命周期证明。最终探针按住同一父图标，
确认菜单上下两区均消失后释放，再检查有界回收；如果第一轮未隐藏，禁止继续
把第二轮当成新打开。点击前确认完整原生光标的位置，并省略
零位移轴；QMP 返回不再当作客体已处理移动。工作区恢复只在切换成功后进行，
避免失败时点击已激活工作区而启动尚未移植的 overview。功能与 15 秒时延
分别记录，原综合 status 仍要求两者通过。

## Panel 代理区域修复与操作时序

复核完整 panel 源码发现：旧代理仅在创建 popup 时读 pending input_region，
复制时又把矩形原点置零并忽略减法；后续内层提交不再更新外层输入区域。
`native-popup-input-v1` 从原 128-FD 宿主导出派生，仅修改三个代理文件，
保留原锁定依赖、功能、文件模式和延迟 map / grab 次序。现在读取已提交状态，
完整保留 None、空区域、偏移及操作顺序；第一次 map 前转发，随后按变化提交，
未变化时不创建新的 wl_region。

实际生产 helper 提取编译覆盖默认/空区域、非零与负偏移、减法顺序和
1×1→360×384 变化；加上对象/安装/catalog 门控共 17 项通过。新 panel 完整
473 包图构建成功，Cargo 编译 4 分 24 秒，包含源与链接复核共 284.305 秒。

- 派生策略 SHA-256：`6c92ad8a1b4ac3945f53c1161e5c4afce4ef2dc84c90e7e8db6be5132d02bfd3`。
- 新 panel SHA-256：`bc706eaa32525ab3ec3e5a16ee9c5f9fab7f085ae447cd6682607e6a356b1175`。
- 原 FD-only 宿主策略及旧源树、回执未改写；新 catalog 另绑定该派生策略，
  拒绝缺少修复标签的旧 panel。

这项源代码缺陷不能解释所有失败：逐帧复核还发现一些“点击无效”捕获的
前置弹窗截图本来就是空背景，原脚本固定等待后仍继续操作。修正后的探针
按住 `on_press_down` 图标，确认原版 popup 的上下区域均出现后才释放，
并记录按住及打开耗时；超出 15 秒仍失败，不再对不存在的弹窗反复点击。
控件上的光标采用空背景完整 140 像素建立的不透明黑白轮廓，避免彩色背景
使抗锯齿边缘 140→139 的误报；错位、缺失、部分光标仍被拒绝。

这种打开方式是按住到首帧出现后释放，不是普通 150 ms 短点击。冷打开约需
按住约 6–9 秒；短点击可靠性和交互流畅度仍未验收，不能据此宣称完整桌面可用。

`workspace-list-1g-v9` 又暴露资源判据误报：首次关闭后对象/页/映射由
23/133/41 降到 22/125/40，旧的“必须完全相等”却等待到 60 秒并失败。
保留该原始 FAIL；新判据要求十个计数完整、七项使用量逐项不增加、空闲页
不减少、两项容量不变，同时记录精确相等标志和有符号差值。不能以某项下降
抵销另一项增长。纯函数反例覆盖每项增长、容量漂移、字段缺失和非法计数；
任何后续步骤异常也会落盘此前完成步骤和 FAIL，不丢弃部分证据。

## 默认配置最终交互证据

`artifacts/v017-workspace-tiling-1g-v9` 使用最终探针和默认 catalog：原核心
1–6、原时钟与平铺 applet 均存活，无非零异常退出。功能和 15 秒门槛均 PASS。
这是一次明确范围的捕获，不代表稳定时延、普通短点击或完整桌面通过。

| 实际操作 | 秒 |
| --- | ---: |
| 首次打开 / 再次打开平铺菜单 | 7.363 / 5.793 |
| 首次平铺 0→1 / 1→0 | 4.795 / 2.817 |
| 第二轮平铺 0→1 / 1→0 | 4.243 / 2.964 |
| 两次关闭和回收 | 5.750 / 5.464 |
| 日历首次打开 / 关闭 | 7.196 / 14.876 |
| 日历再次打开 / 关闭 | 6.069 / 14.897 |

两次平铺关闭均确认弹窗隐藏，共享对象/页/映射精确恢复到 17/120/30，十项
资源差值为零。最终用户终止后的共享/匿名/OFD/端点/连接回收亦通过。
首次/再次打开仍分别按住图标 6.486/4.900 秒，不能记成普通短点击。

## 可选工作区最终交互证据

`artifacts/v017-workspace-list-1g-v10` 使用真实 1024 MiB、4 CPU，原核心进程
1–6 和三个原版 applet 均存活，无非零异常退出。功能判定 PASS，整体 status
仍为 FAIL，原因是下表日历关闭超过原 15 秒门槛。

| 实际操作 | 秒 | 证据 |
| --- | ---: | --- |
| 平铺菜单首次打开 | 9.249 | 实际按住 8.362 秒，确认上下两区出现 |
| 平铺 0→1 / 1→0 | 6.243 / 5.826 | 独立只读客户端观察原 compositor 状态 |
| 首次关闭与回收 | 4.130 | 弹窗隐藏；共享对象/页/映射精确回到 22/125/40 |
| 第二次打开 | 7.987 | 实际按住 7.103 秒，前一弹窗已隐藏 |
| 第二轮 0→1 / 1→0 | 4.947 / 6.567 | 独立状态两次匹配 |
| 第二次关闭与回收 | 5.165 | 弹窗隐藏；22/125/40，十项计数差值全部为零 |
| 工作区 1→2 / 2→1 | 3.125 / 4.916 | 真正窗口产生动态第二工作区，原版列表完成切换 |
| 日历首次打开 / 关闭 | 7.698 / **22.691** | 功能通过，关闭超时 |
| 日历再次打开 / 关闭 | 7.161 / **19.900** | 功能通过，关闭超时 |

全部用户进程终止后，共享对象/页/映射/引用/授权、匿名使用页和 OFD 均为零；
Unix 空闲端点/连接为 128/64。free_bindings 为 126，两个具名 socket 文件系统
节点正常保留，不能把它们写成端点泄漏或宣称所有路径被删除。三项共享准入
模型为 8194/8203/8204，拒绝与失败均零，授予/释放单位完整对账。

旧 `workspace-list-1g-v4` 的“重复稳定”发生在未确认菜单打开的捕获中，
不作为两轮生命周期证明；v9 的错误相等判据 FAIL 亦保留。v10 是新的真实捕获，
不是改写这些历史结果。原 45 秒检查仍只证明启动色条被替换，语义首帧、
完整 OS、完整 COSMIC 会话均未通过。

## 检查范围

| 本轮相关检查 | 通过数 | 原始日志（`artifacts/debug/cosmic-workspace-applets-20261121/`） |
| --- | ---: | --- |
| 新 applet profile 的 POSIX 集合 | 215 | `mapping-posix-new.log` |
| 旧配置 POSIX 集合 | 213 | `mapping-posix-legacy.log` |
| AI 模型，新/旧配置各一组 | 56 / 56 | `mapping-ai-new.log` / `mapping-ai-legacy.log` |
| shell 只读排队/Busy/结束标记 | 15 | `compact-shell-green.log` |
| core 控制台与背压 | 20 | `console-backpressure-green.log` |
| 最终原生输入、catalog、镜像与探针宿主检查 | 63 | `final-workspace-tools-green.log` |

这些宿主 fixture 验证门控、几何语义与失败边界，不是客体运行证据；客体证据为
上面的独立捕获。未重跑全仓 CI，不宣称全量 Python、全量格式检查或完整桌面通过。

最终 `artifacts/v017-workspace-native-1g-v2` 为 `OS_NATIVE_PASS`：在可选配置的
最终镜像上验证寄存器、syscall-free 自旋抢占（实际 PID 3、1 次）、页保护故障、
FP/TLS、堆和 IPC。两个最终 build 都重新通过源码、生产者、完整 catalog 和实际
镜像身份校验，依然是 1024 MiB、4 CPU。

最终镜像为默认 `v017-os-workspace-applets-1g-v14` 和可选
`v017-os-workspace-applets-1g-v15`。补正文档手势后重绑源码，其 kernel/boot 与
先前 v12/v13 逐字节相同：默认 boot SHA-256
`0c4caf191fe0b0654adfd5b270955389143bd5f398db87ad3ed86cb8ef95e7ad`，可选为
`bde1be471c6e7bdf2389911eaaab72e44f36418cfe37ef9d3a37c8b55de41372`。
默认最终探针另收紧“重复关闭必须真的隐藏”门控并完成实际捕获；可选 v10 的原始
回执也满足这项更严后置条件，两轮均为隐藏且资源未增长，未改写其原生产者或状态。

默认 catalog 为 147 项、204,723,970 字节，保留原 129 项中的 126 项，明确替换
两个宿主及 bus 配置、增加 18 项。可选 catalog 只再增加一项用户覆盖配置。
清理仅针对本轮可重建编译缓存，逐文件哈希清单保留；历史失败原始日志和成功
原生输入保留。没有恢复 2 GiB 功能。

机器可读的 [证据索引](v17-cosmic-workspace-applets-20261121.evidence.json) 记录原生
回执、最终镜像、实际捕获、失败历史和检查日志的路径/大小/SHA-256，以及实际
状态与回收计数。原始大文件位于本地 artifacts；索引不能替代原始证据。

源代码和文档的 staged whitespace 检查通过。存储的 unified patch 中另有 11 个
必需的空上下文标记（单个空格），逐行确认；未为消除格式提示破坏补丁或改写
已绑定的补丁哈希。
