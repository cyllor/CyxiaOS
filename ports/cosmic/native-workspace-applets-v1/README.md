# Epoch 工作区与平铺 applet

上游 cosmic-applets 固定为 `406d1b7d627138fdf4078f654268d3d8774e50f1`。
继承 time-applet-v2 的完整 19 成员源码、637 包锁定解析图和真实静态
Wayland/xkbcommon 绑定；本层只修改两个原版根包的静态绑定选择及其
Cargo.lock 根依赖。原 Cargo 默认功能保留，不裁剪 GUI 或替换程序。

`cosmic-applet-tiling` 是上游默认 Panel 的组件。
`cosmic-applet-workspaces` 是可选工作区列表，与默认的
`com.system76.CosmicPanelWorkspacesButton` 及 `cosmic-workspaces` 概览主程序
分别计数。不得替换默认身份或删除缺失的组件来使完整会话检查通过。

原 SDK 的 15 个静态输入保持；新 SDK 另补真实 libinput、libudev、libevdev、
mtdev 和 Linux UAPI 头文件。源码 URL、SHA-256 见
[sources.json](../native-input-sdk-v1/sources.json)。Linux 源码只提供 UAPI，
客体仍为 CyxiaOS。SDK 构建不启用 libwacom 后端，不代表客体已支持真实
Linux 输入设备/sysfs/netlink。

构建使用 `tools/build_cosmic_workspace_applets_v1.py`，显式指定新的
`--sysroot`。`native_sdk_extension` 固定 SDK 回执和生产者快照；四个新增
静态库及许可证独立验哈希。重新生成 SDK 后须复核并显式更新此绑定，
不能复用旧 SDK 的成功回执。Cargo 构建始终 `--locked --offline`，最多两任务。

安装工具 `tools/assemble_cosmic_workspace_applets_v1.py` 重新验证两个原始链接、
完整源码/依赖图及 SDK，原子发布新 catalog。配对安装新 session/panel 时，
仅替换这两个经独立验证的宿主 ELF 及下述会话 bus 配置，其余旧输入逐字保持。生产安装必须同时
提供两个 `--host-build` 和 `--applet-relink`，不能用旧 64-FD 宿主搭配新配额。
`cosmic-workspace-applets-v1` 选择独立的 256 MiB ROM 输入及 384 MiB 内核
ELF 文件读取上限，QEMU 仍为 1024 MiB。新对象 profile 的每进程 FD 为 128，
全局 OFD 为 512、Unix 端点/连接为 128/64、共享对象元数据为 32、每进程共享映射记录为 32；旧 profile
保持。原每进程映像/stack/堆/线程额度和物理映像/匿名/共享页池保持。
本目录 resource-profile.json 约束的是原映像/stack/构建预算，对象配额由
独立的 `cosmic-applets-objects-v1` 契约绑定。
新 profile 的会话 bus 配置另将已实测耗尽的每用户/总连接上限 16 改为 32，
原 UID 0 认证、权限及其他消息/FD 上限保持，契约绑定实际配置哈希。
`hicolor-index.theme` 仅为本仓安装的原 SVG 提供 fallback 目录索引，
不是完整 COSMIC/Pop 图标主题；原 SVG 内容保持。

可选 `tools/build_workspace_state_probe.py` 使用固定原版 XML 生成客户端绑定，
只读 compositor 的工作区和 tiling 状态，不发送切换请求。另一个独立 xdg
测试窗口只负责占用动态工作区；切换由原版 applet 接收真实鼠标输入完成。
构建、准入、客体交互和完整会话通过是分开的证据。

新回归使用 `ai objects` 的短只读快照：CPU0 实际对象、共享准入计数、
每进程 FD、匿名/共享页与结束标记。它不是完整 AI 系统快照；较长的
`ai system` 仍独立保留。客体状态与结束标记不完整时回归失败。

PC OS 控制台使用独立的 128 KiB 有界 FIFO，短写保留尾部，Again 后在后续
CPU0 轮次继续；每轮前后各排出至多 1024 字节，积压时暂停读取新命令。
该 bootstrap 诊断缓冲不改变用户或共享物理页池额度。回归点击前等待完整
原生光标出现在目标，按住父图标至菜单实际出现或消失后释放，并分别记录
按住时间、完整耗时及 15 秒门槛。这不代表普通短点击已经验收。关闭同时要求
弹窗隐藏和各项资源使用量未增加；实际释放允许低于基线，精确差值另行保留。

生产 panel 还必须带 `../native-popup-input-v1` 的独立派生策略，构建宿主时
加 `--popup-input`。对象契约绑定该策略哈希，安装器拒绝只有 FD 扩容而缺少
popup committed input_region 同步的旧宿主。旧 FD 宿主策略及历史回执保留。
