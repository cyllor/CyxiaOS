# COSMIC 组件能力与依赖证据矩阵

2026-10-22 最新：[Smithay 锚定缩放与抓取清理](smithay-resize-native.md) 已通过三次独立客体验收，增加左上角/左边缘的位置与尺寸联合提交、反向缩放、普通重绘，以及按钮仍按住时关闭窗口并处理背景释放。八方向几何有单元测试，客体只声明左上角/左边缘；每次十二个实际显示场景。上一轮移动/右下角缩放回归通过。尚未运行下表的 cosmic-comp；动态客户端接入、通用窗口管理与完整会话仍待实现，30 个组件的状态不变。

2026-10-22 先前阶段：[Smithay xdg-shell 生命周期](smithay-xdg-native.md) 已验证配置/确认、激活、尺寸变更、关闭和错误客户端隔离后继续服务，客户端依次运行。

2026-10-22：[Smithay Wayland 原生显示与输入](smithay-wayland-native.md) 已通过三次独立客体验收，包含共享缓冲区、真实 GLES 渲染、六帧逐像素 scanout 与键鼠事件。该 `wl_surface` 集成没有运行下表的 `cosmic-comp` 或 COSMIC 会话；30 个组件的完成状态保持独立。

2026-10-20 后续基础层增量：[Mio 事件循环](rust-reactor.md) 与
[Smithay 高层渲染器](smithay-static-renderer.md) 已在 CyxiaOS ARM 客体运行。
它们属于依赖基础验证，以下 30 个 COSMIC 组件状态保持独立，未据此标记任何组件完成。

2026-10-18。范围固定于 epoch `364341d52454bf3a016d03185c6aff887247aab7` 的 30 个 gitlink。本轮完成 P1 的有界元数据取证和构建工具基础，**尚未完成 G-LOCK 的全传递依赖闭包，更未构建或运行 COSMIC 组件**。

证据入口：[dependencies.json](../../ports/cosmic/dependencies.json)、[resource-profile.json](../../ports/cosmic/resource-profile.json)。原始固定提交文本及 Git tree 保存在 `artifacts/cosmic-metadata/<component>/<commit>/`。30/30 组件成功取证，包含 27 个根 Cargo.lock、94 个 Cargo.toml，选中文本共 6,531,041 字节；其余三项为资产组件。根锁中的 package 数包含各组件重复依赖，不能相加当作独立 crate 数。

每个文本文件核对固定 tree 的 Git blob SHA1，并记录 SHA256、字节数和官方 URL。取源未递归 clone、未下载图标/壁纸/声音等资产内容。Git tree 中的 blob 大小不是安装体积：LFS、生成产物、外部依赖和运行时数据仍未计入。许可证原文和 Cargo 中声明已留证；整体许可证兼容/分发义务审查尚未完成。

## 全量组件索引

2026-10-20 基础层增量：单调 timerfd、Mesa compute dispatch 分配失败恢复、
Smithay 生成绑定的 Rust 静态 EGL 客体探针已分别取得运行证据，见
[移植记录](cosmic-port.md)。这些依赖基础层的通过不改变下表 30 个 COSMIC
组件的 guest 状态，也不代表完整 Smithay 或 COSMIC 已运行。

下面的“首次阶段”只表示集成顺序。C1/C2 是开发会话/预览；认证、网络、音频、门户、包管理与余下功能仍是 C3 强制项。每个组件的 guest 状态均为未构建、未验收。

| 组件 | Cargo manifests / lock packages | 根默认 features | 首次阶段 |
|---|---:|---|---|
| `cosmic-app-library` | 1 / 697 | wgpu | C1/C2→C3 |
| `cosmic-applets` | 20 / 796 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-bg` | 2 / 353 | avif | C1/C2→C3 |
| `cosmic-comp` | 2 / 698 | systemd | C0 |
| `cosmic-edit` | 1 / 904 | dbus-config, gvfs, wgpu, wayland | C1/C2→C3 |
| `cosmic-files` | 3 / 912 | bzip2, dbus-config, desktop, gvfs, io-uring, lzma-rust2, notify, wayland, wgpu | C1/C2→C3 |
| `cosmic-greeter` | 3 / 858 | logind, networkmanager, upower, systemd | C3 |
| `cosmic-icons` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-idle` | 2 / 297 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-initial-setup` | 2 / 796 | a11y, wgpu, wayland | C3 |
| `cosmic-launcher` | 1 / 740 | wgpu | C1/C2→C3 |
| `cosmic-monitor` | 1 / 706 | dbus-config, nvml, wayland, wgpu | C1/C2→C3 |
| `cosmic-notifications` | 3 / 654 | systemd | C1/C2→C3 |
| `cosmic-osd` | 1 / 718 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-osk` | 2 / 686 | wgpu | C1/C2→C3 |
| `cosmic-panel` | 4 / 555 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-player` | 1 / 754 | mpris-server, xdg-portal, wgpu, wayland | C3 |
| `cosmic-randr` | 4 / 79 | workspace，需逐 member 核对 | C0/C2 |
| `cosmic-screenshot` | 1 / 199 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-session` | 1 / 176 | logind, systemd | C1/C2→C3 |
| `cosmic-settings` | 11 / 914 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-settings-daemon` | 9 / 720 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-sound-theme` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-store` | 2 / 842 | dbus-config, desktop-systemd-scope, flatpak, logind, notify, single-instance, wgpu, wayland, xdg-portal | C3 |
| `cosmic-term` | 1 / 850 | dbus-config, wgpu, wayland, password_manager | C1/C2→C3 |
| `cosmic-viewer` | 8 / 760 | workspace，需逐 member 核对 | C1/C2→C3 |
| `cosmic-wallpapers` | 0 / 不适用 | 未声明 / 非 Cargo 资产 | C1/C2→C3 |
| `cosmic-workspaces-epoch` | 1 / 699 | wgpu | C1/C2→C3 |
| `pop-launcher` | 5 / 368 | workspace，需逐 member 核对 | C1/C2→C3 |
| `xdg-desktop-portal-cosmic` | 2 / 924 | systemd | C3 |

`cosmic-applets` 包含 20 个 Cargo manifests，不能按一个仓库预算一个进程。`cosmic-viewer` 也有多个 workspace 成员。`cosmic-theme-editor` 与 `simple-wrapper` 不属于固定树中的这 30 个 gitlink；仍保留额外依赖/范围差异核对任务。

## 已发现的具体接口与默认特性风险

| 证据 | 待关闭能力 | 验收边界 |
|---|---|---|
| cosmic-session 固定 `src/main.rs`；至少 14 个启动意图，先取得 session bus 名称 | 独立进程、继承 socket/FD、readiness、wait/SIGCHLD、bus 生命周期与有界重启 | 14 是源码启动意图，不是实测峰值；还要加 bus、applets、启动器插件、用户应用与恢复余量 |
| cosmic-config / atomicwrites / notify 依赖 | 按 key 原子替换、真实变更通知与配置持久性 | rename、连续修改、溢出、目录同步与断电恢复；不是跨 key 原子事务 |
| cosmic-files 默认 `io-uring,gvfs,notify,wgpu,wayland` | Linux I/O、卷/挂载服务、事件和渲染闭包 | 每项实现或在开发 profile 显式关闭并登记 C3 差异；不能仅去掉 default 就宣称完整功能 |
| cosmic-term 默认 `password_manager`；真实 PTY 与子进程仍必需 | 密码/密钥服务、PTY、作业控制、终端渲染及字体 | 没有凭据服务时明确不可用；不向成功空实现交付秘密 |
| cosmic-monitor 默认 `nvml` | 真实进程/内存/CPU 观测及可选设备后端 | 用内核可信统计替换 Linux 假设；缺 GPU 不伪造 NVML 数据 |
| greeter 的 PAM/greetd 依赖；默认 logind/networkmanager/upower/systemd | 真实账户、凭据、会话授权/锁屏与适用设备服务 | mock/自动登录只允许开发阶段；C3 必须验证错误密码拒绝和用户隔离 |
| applets 的网络/音频服务依赖 | 实际网络栈、DNS/TLS、音频 PCM/路由与状态服务 | UI 状态必须来自真实服务；当前没有这些完整子系统 |
| Store 默认 Flatpak；Player 的 GStreamer；Portal 的 PipeWire/GBM/GVfs | 包管理与签名更新、媒体同步、门户前端/权限/后端 | 安装更新卸载、实际音频输出、文件选择/截图录屏行为分别验收 |

每项原始入口及行号位于 `service_entrypoint_evidence`；直接依赖的 target/workspace 作用域位于 `cargo_manifests.*.dependencies`。`declared_native_or_service_candidates` 只是名称筛选，不能替代完整 native 库、服务方法或 feature 解析。

## 尚未闭合的任务

1. 对每个 Cargo workspace 解析所选 package/bin/target/features 的完整锁定图，审计 Git 子模块和本地 path 依赖，准备带校验和的离线缓存；目前仅留存锁文件，没有 vendoring。
2. 对所有 libcosmic/protocols/settings-daemon 的跨组件 revision 差异做接口兼容核对；不能直接强制合并版本。
3. 枚举 native 链接、运行时 dlopen、插件、shader、fonts/locales/MIME/desktop 文件以及安装后的资产路径和体积。
4. 把服务入口扩展成完整 D-Bus 名称/对象/方法/信号/激活/权限矩阵，单列 epoch 外的 bus、greetd/PAM、网络/音频服务、portal 前端与包后端。
5. 选定可执行的图形 profile，处理 EGL/GLES、库加载和真正所需运行时；当前没有已批准的 compositor 构建 recipe。
6. 在逐组件链接、运行后补测 ELF/BSS/RSS、FD/线程/进程和共享缓冲高水位，更新物理布局与 AI 输入域/模型/账本。源码大小与启动意图不能代替运行测量。
7. 为每项业务功能补上正常、拒绝、设备缺失、服务死亡、持久化和资源回收场景；未完成项持续进入 C3，不能删除分母。

## 可执行工具与边界

```sh
python3 tools/cosmic_dependencies.py inventory --output ports/cosmic/dependencies.json
python3 tools/cosmic_dependencies.py fetch --component cosmic-session
python3 tools/build_cosmic.py check --component cosmic-comp
python3 -m unittest tests.host.test_cosmic_dependencies tests.host.test_cosmic_build tests.host.test_cosmic_ports -v
```

默认 inventory 离线；`fetch` 是明确联网动作，只取得有界固定版本元数据。`fetch --all` 表示同样的 30 项元数据，不是递归源码或依赖下载。已缓存文件会先重新校验，既有内容被修改时拒绝继续。

`build_cosmic.py check --component cosmic-comp` 当前应拒绝缺少 reviewed recipe；这不是 COSMIC 构建失败或已有基础门禁失效。真正构建使用 `build --component NAME --recipe PATH --output NEW_DIRECTORY`，只选一个 package 和一个 bin，强制 `--locked --offline`。不得传任意附加 Cargo 参数。

Recipe schema 1 必须给出 `component/commit/target`、`purpose=bounded-build-experiment`、`package/binary`、`resource_profile`、显式 `default_features/features`、原始及补丁后 `source_lock_sha256/effective_lock_sha256`、带路径/hash 的 `patches` 和 `native_inputs`。native 输入至少包括固定 musl、compiler-rt、crt1/crti/crtn。文件位于 recipe 自身目录，路径不能逃逸；补丁只作用于临时导出的源树。

源码必须是已取得的独立 Git checkout，HEAD/origin 与 epoch 一致、没有修改或额外 ignored/untracked 输入。工具不会 reset/clean/更新源树。含未物化 gitlink 或 Cargo config 的源码会拒绝，后续必须先做明确的移植审查。

独立 Cargo cache 默认 `artifacts/cosmic-cargo-cache`，需另行准备且不得借用全局用户 Cargo home、配置文件或外部 registry/git 目录链接。缓存准备/联网取依赖不包含在构建动作中。Cargo 从仓库外的临时控制目录运行，避免继承项目或上游 `.cargo/config`；Cargo target 独立于内核。

宿主工具和目标 CC/AR/pkg-config 分开配置；目标 .pc 文件输出宿主绝对 include/library 路径会被拒绝。目标 musl/CRT/库和 Rust 标准库记录身份并检查 ARM64 架构。只暴露官方目标 libunwind，不把 Rust 自带另一套 libc/CRT 混入。当前工具只支持既有静态 ET_EXEC profile，动态加载需要后续 P5L 的实际实现。

构建采用共享 sysroot 锁，开始时要求空间留量加构建预算，运行时检查空间、输出/临时目录及缓存增量；超时或超限终止整个子进程组。此限制是周期检查，**不是硬磁盘 quota 或构建脚本网络沙箱**。Cargo 禁止联网解析/下载，受信任的 build.rs 仍是本机程序；报告明确此边界。

每次保存 recipe/源树/补丁/工具/依赖源树/sysroot/最终 ELF 身份；链接后执行真实 AArch64 ET_EXEC、LOAD/W^X、静态符号、映像和初始栈额度检查。失败日志留在新输出目录，已有输出不会覆盖。`cross-built` 只证明链接与映像检查，不提高 guest/session 状态。

## 资源与实验判据

`resource-profile.json` 记录已冻结 r3 基线约束、原有探针实际大小/hash、30 项源码文本大小、会话启动下界及所有未测量字段。P2 后的新容量应另行实测更新；不能把 r3 的上限当作全套 COSMIC 预算。

初始 static-bootstrap 构建实验：1 个构建 job、15 分钟 deadline、2 GiB 构建增长上限、持续保留 2 GiB 空间、既有 16 MiB 映像池并计入 256 KiB 初始栈。新输出尚未验证；超限应报告失败并进入资源 profile 评审。

图形/交互实验先固定 1024×768、像素/丢消息/引用/账本错误为零；至少 100 个交互样本，输入到呈现 P95 不超过 250 ms、启动就绪期限 60 s、稳态观测 60 s。这些是未来实验初始判据，不是已达到的性能。改判据须先新建版本、保留旧失败，不能看结果后降门槛换 PASS。

主机测试使用真实临时 Git、真实子进程和真实小型 Cargo fixture 验证路径/身份/污染/资源拒绝；有目标 sysroot 时，小 fixture 完成 ARM64-musl 交叉链接，不下载依赖、不构建内核、不运行 guest，也不被计为 COSMIC 组件移植。
