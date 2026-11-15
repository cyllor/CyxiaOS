# V0.17 COSMIC 的 Cyxia 原生后端

2026-11-15，继续完整 CyxiaOS / COSMIC 主线。上游仍固定为
`41497b42d9744d9963c4c6d17e8add49489b45ee`，不改动上游检出或 Cargo 锁文件。
本轮在实际 cosmic-comp 中加入 `backend-cyxia`，复用其 Common、Shell、工作区、
窗口管理和 `render::render_output`。完整 COSMIC 客体会话尚未验证。

真实 x86 静态链接已经完成：最终 ELF 为 42,173,224 字节（40.2 MiB），
4 个 LOAD 段需要 8,548 页（33.4 MiB），没有动态解释器或未解析的强符号。
当前 16 MiB 镜像范围与 4,096 页执行池不足，而且实际 LOAD 段与现有栈地址重叠。
加载验收因此拒绝该映像；不能只放宽构建脚本的大小检查来运行它。

## 实现范围

- 通过现有 Cyxia 显示与输入 ABI 查询输出、提交 XRGB 矩形和读取键鼠事件。
  链接实际 Mesa，以 `eglGetProcAddress` 初始化 Smithay 的真实 EGL 分派表，创建
  surfaceless EGL、GlowRenderer 和持久 GlesRenderbuffer。
- 读回真实渲染结果，每轮最多提交 16 个 tile；EAGAIN/EINTR 保留进度并让出事件循环。
  呈现请求在首次让出前从对应表面取出，最终提交完成后才发送反馈；失败或取消会丢弃反馈。
  提交中的新 commit 保留重绘需求。ABI 没有硬件刷新时序，反馈不声称硬件时间戳或 vsync。
- 每轮最多读取 128 条输入记录，保留 SYN 边界与丢失事件后的按键重同步。
  单独记录实际转发的按键/按钮，防止后续读取失败导致关闭时漏发释放事件。
- 锁屏立即安装内部 Shell 与焦点隔离，取消旧画面，分轮提交全屏黑色。
  真实 `SessionLocker` 只在最后一块黑色提交成功后确认；部分提交、失败及失效所有者
  都不能发送确认。过渡期配置的锁屏表面保留，已按下的非原生输入仍允许释放。
  焦点栈、实际键盘焦点写入和 popup grab 安装入口共同检查锁屏目标，防止普通面板
  在同一批 Wayland 请求中重新夺取焦点。替换锁所有者检查协议资源自身是否存活。
- 默认 KMS 和既有嵌套后端选择保持兼容；原生输出固定尺寸与方向，不宣称支持
  热插拔、VRR、DMA-BUF 或尚无 ABI 的硬件能力。

## 原生依赖与构建约束

新增 `tools/build_pixman.py`，复用已固定的官方 pixman 0.46.4 源码。
所有实际 Meson/编译命令共享截止时间和磁盘增长限额，临时目录计入预算，
发布前校验目标归档与输入身份。只向显式指定的 SDK 输出。

`build_cosmic.py` 的 `static_link_inputs` 只能引用已声明、已校验的目标 `.a` 文件，
通过显式链接组提供 Mesa、C++ 运行库、zlib、xkbcommon 与 pixman。
构建结束再次验证每个原生输入，包含内层 sysroot 目录之外的 Mesa 归档。
真实反例测试确认：未声明 pixman 时链接失败；声明实际归档后产生 x86 ELF；
构建脚本修改 SDK 外层已声明归档时拒绝成功结果。
真实超限 ELF 还复现了 `build_sysroot.BuildError` 未被捕获、报告停留在 `building`
的缺陷；修复后记录 `status=failed`、已完成链接的原始路径/哈希/大小，且不发布
通过验收的 `.elf`。`link_completed` 与 `target_linked` 分别表达这两个阶段。

原生配置独立保存在 `ports/cosmic/native-comp/native-{recipe,series,profile}.json`，
保留旧 Winit 配置。recipe → series → manifest → patch → 文件前后哈希逐层绑定。
构建仍遵守 16 MiB 映像验收边界；不因合成器规模而跳过加载器检查。
所有重型构建和客体执行通过共享 native lease 串行运行。

## 验证记录

本轮证据位于 `artifacts/v017-cosmic-native-20261115-r2/`。

| 证据 | 结果与边界 |
| --- | --- |
| `pixman-x86_64-02/pixman-build-report.json` | 真实 x86 构建通过；归档 1,239,236 字节、35 个 ELF64 machine 62 对象；静态 C 探针 741,968 字节；探针未在客体执行 |
| `native-check-01/build-report.json` | 首次实际原生类型检查发现 GlowRenderer/GlesRenderer 参数不匹配，保留失败证据；随后改用上游现有 BorrowMut 方式 |
| `native-check-02/build-report.json` | 后续真实检查发现输出配置临时 guard 阻止错误清理再次借用 State；已分离配置结果与清理作用域 |
| `tests-native-final-02.log` | source08 实际补丁模块的 40 项 Rust 回归、3 项 Python 补丁校验通过；包含呈现游标、锁屏、输入账本与后端选择，不代表完整合成器运行 |
| `tests-host-final-02.log` | 相关 COSMIC/SDK/源码与构建工具测试运行 108 项，107 项通过，1 项因没有 ARM SDK 跳过 |
| `native-build-01/cargo.log`、`native-build-01/link-measurement.json` | source07 实际 `cargo build` 在 5 分 22 秒完成；独立解析原始 ELF 量出上述容量；原失败报告保留，没有改写成成功 |
| `native-build-02/build-report.json`、`native-build-02/link-measurement.json` | 最终 source08 在 4 分 57 秒完成 Cargo 编译链接；报告正确记录 `link_completed=true`、`status=failed`、`target_linked=false`。独立核验为静态 x86 ET_EXEC，无 W+X 段、页重叠或对齐问题，失败来自旧映像地址范围 |
| `admission-report-red.log`、`admission-report-green.log` | 17 MiB 实际目标静态数组生成超限 ELF，先复现报告错误，再验证错误处理和未发布状态 |

pixman 归档 SHA256 为
`8e31c164c274791a8647a0569ad5cd11b8af11a410e24778b0d9951063605c45`，
固定版构建报告 SHA256 为
`ba6ec6adeefca51c00a54de4b312d6b6aea9b912eda9aa5ffa38588fab4d99a7`。
其与首轮构建归档逐字节相同，SDK 发布记录指向修复资源限额后的第二轮报告。

代码规范审查确认重复的原生 tile 提交参数已归入一个私有函数；需求符合性审查
确认锁屏焦点绕过、死亡资源替换及未完成旧帧提交问题已关闭。18 个补丁前后镜像、
支持源码和最终传递哈希链一致。审查与独立策略测试不替代真实客体会话验证。
为完整链接释放空间，仅清理了两次失败类型检查的 `target/` 派生缓存；对应源码、
日志、metadata 与失败报告均保留，清理记录见 `failed-check-cache-cleanup.json`。
source08 仅将原函数的注释与 profiling 属性移回原位置，避免影响其他后端的计量。
两路最终复核均无剩余问题；实际构建与运行边界仍由对应报告决定。
最终已链接 ELF SHA256 为
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`，
源码树 SHA256 为
`6350b8aba91935c74a492b0354452e2757aa8c74b97f43a81315c0ceeb443f8d`。

## 复现原生构建

需要实际 x86 SDK、固定的 Mesa/pixman 归档和已经准备的独立 Cargo 源码缓存。
构建使用新输出目录；不会联网补齐依赖，也不会修改固定上游检出。

```sh
python3 - <<'PY'
from tools.native_session import native_lease, idle_native_host, DEFAULT_NATIVE_LOCK
from tools.build_cosmic import main
with native_lease(DEFAULT_NATIVE_LOCK):
    idle_native_host()
    raise SystemExit(main([
        'build', '--component', 'cosmic-comp', '--arch', 'x86_64', '--jobs', '2',
        '--recipe', 'ports/cosmic/native-comp/native-recipe.json',
        '--resource-profile', 'ports/cosmic/native-comp/native-profile.json',
        '--output', 'artifacts/comp-native-build-new',
    ]))
PY
```

## 尚需推进

按真实启动顺序，下一步已有以下明确工作，均不以 A03 为前置条件：

1. 镜像容量部分已完成：新增显式 full-os-v1 地址布局、实际执行页池和独立模型 8197，
   同一个真实 ELF 已在客体两次执行并正常退出；旧配置保持不变。
   正式启动还修复了 EPOLLPRI 注册兼容问题，当前实际停在 RuntimeDirNotSet。
   详见 [完整 OS 镜像容量记录](v17-full-os-image-capacity-20261115.md)。
2. 提供可写的绝对路径 `XDG_RUNTIME_DIR` 和真实 `flock` 生命周期/竞争语义。
   Wayland listener 的 `new_auto()` 在进入后端之前即要求两者；当前启动环境未提供该变量，
   x86 syscall 73 也未映射。已有 Unix bind/listen 可以复用。
3. 实现真实 inotify init/add/rm、事件读取与 epoll 就绪，以及可写 HOME/XDG 配置目录。
   `Config::load` 无条件创建 watcher，当前内核 ABI 没有该接口；不能用成功空操作代替。
4. 用实际 ELF 测量线程和 FD 峰值。现有 clone/futex/epoll/eventfd/timerfd 可复用，
   但当前 16 个 FD、8 个线程尚未经完整合成器验证；D-Bus 总线进程、地址和服务顺序也需补齐。
   总线连接失败目前会记录日志，不能误报成无条件的后端初始化前崩溃。
5. 将 cosmic-comp、完整 XKB rules/keycodes/types/compat/symbols 和字体纳入 x86 OS 包。
   当前 rootfs 总文件上限 128；合成器已注册到显式 cosmic-desktop 程序目录，
   但单个 `.xkm` 不等于所需 XKB 数据。
   XKB 在后端成功后创建 seat 时加载，字体按实际文本使用验证。继续接入 cosmic-session、
   panel、launcher、terminal、files，再验证应用生命周期与重启后的数据持久性。

当前依赖图仍含 Wayland/X11 动态加载路径，静态 EGL 接入不能作为这些路径已解决的证据。
