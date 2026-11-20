# 真实 notifications 供给与核心服务目录，2026-11-19

**通知程序缺失导致的 ENOENT 已解除，完整会话仍失败。** 固定上游 notifications
已完成真实离线编译、独立安装校验，并在两次正常 session 启动中作为 PID 5
启动；panel 随后作为 PID 6 启动。新的终止点是 session 注册 SIGTERM 处理器时
收到 EINVAL。此外，九个其他默认会话程序尚未供给。

本轮保留原 SDK、原组件字节和所有旧失败记录。改动未提交或推送。

## 已运行的原始复现

```sh
python3 tools/os_cosmic_startup_probe.py \
  --build artifacts/v017-os-cosmic-phase-release-20261119 \
  --output artifacts/v017-notifications-baseline-20261119
```

实际结果为 FAIL，UART 中仍有：

```text
failed to start notifications daemon: Process(Os { code: 2, kind: NotFound, ... })
```

这是上一轮两次失败后的再次复现。原镜像和 SDK 均没有通知 ELF，kernel catalog
又把该名称当作可选输入。另两种待排除情况是名称/路径错误、非静态或错误 ISA 的
ELF；本轮在真实字节供给与加载路径上验证，没有用空程序或改名绕过启动。

## 固定源码与独立 SDK

上游提交为 `1e4c1f11fdcae273d6954fd0bfc54749a6145267`，原 static-v1 源码策略、
三份补丁、Cargo.lock、GUI/无障碍/X11 特性及资源 profile 保持其原有选择。
实际 493 包解析图 SHA 为
`49a3bee6a78e71ce6f86d8e684776ba5ed1c74a806d8c11585803b85f2520255`。

原本缺少的 Xau、XCB、XCB-XKB、xkbcommon-X11 不是占位库。使用固定 SHA 的
musl/compiler-rt/X.Org 源码和实际 Bison，构建独立 x86_64 SDK，再构建真实
xkbcommon-X11。Wayland/FFI 从保留 SDK 的来源记录逐字校验后复制。

主要输出：

- `artifacts/v017-notifications-sdk-v2`：core、X.Org、独立 SDK 装配来源与原生库；
- `artifacts/v017-notifications-xkb-x11-v2`：XKB 构建、源码/工具身份和安装树；
- `artifacts/v017-notifications-acquisition-v2-complete`：锁定依赖获取与离线解析图；
- `ports/cosmic/native-notifications-static-v2`：新的 SDK 绑定配方和原策略/补丁副本。

新旧配方仅 `native_inputs` 和 `native_sdk_origin` 两个字段不同。冻结的 static-v1
producer、consumer 和旧配方没有改写。新 SDK 来源 SHA 为
`916621b6952f8296d699aa11c5f83f9e4421b5e2c7455b26cac5e158587281a1`。

最初按目标平台 fetch 后，离线 metadata 仍因缺少 `block2 0.5.1` 失败；保留该
日志，补全锁文件所需归档后解析成功。这些其他平台元数据输入不等于客体运行依赖。
临时获取脚本保留在明确的 `artifacts/debug/cosmic-notifications-20261119` 目录。

## 实际构建与安装

冻结 producer 使用 `jobs=2`、锁定/离线 Cargo 和原 3 GiB/3600 秒构建边界。
Cargo release 编译用时 7 分 33 秒，producer 总计 473.430 秒，输出目录约 1.6 GiB。
ELF 为 29,881,456 字节，SHA：
`d846812f58b6e00c7a9fea303c2b4d235e0788722242715c1d4c2ef0f965bcd9`。
实际装入页为 5,939 页，仍须另加原有 512 页用户栈并接受客体准入。

独立安装器完整重放源码、解析图、编译器、原生库、日志及 ELF admission 检查，
安装实际 ELF 和三份完整许可证到 `artifacts/v017-notifications-installed-v2`。
安装状态为 `INSTALLED_NOT_RUN`，不提前声明通知协议或会话通过。

## 显式版本化目录与提前拒绝

保留原目录全部输入并加入通知 ELF/许可证后，为 125,834,353 字节、57 个输入，
超过原 96 MiB 的 100,663,296 字节上限。因此新增明确选择的
`cosmic-core-services-v1` profile，使用 128 MiB 原始 ROM 目录并要求五个真实程序：
compositor、session、settings、notifications、panel。

原 `full-os` 96 MiB、基础 48 MiB 与 `large-memory` 52 MiB 路径保留。新 profile
只改变目录供给约束及 ROM 输入预算；未修改每进程 64 MiB 图像、栈、匿名池、AI
模型、FD/管道/线程/CPU 限制或运行门限。实际客体仍是四核、1 GiB，旧物理池尺寸
保持 20 MiB 页表、256 MiB 匿名池、256 MiB executable pool、16 MiB 共享后备。
真实启动中这些池均完成原物理预留检查；这不是完整会话峰值或回收测量。

`tests/host/test_cosmic_core_catalog.py` 提取实际 kernel catalog producer，使用真实
文件与明确的合成 ELF。修复前，缺少 session/settings/notifications/panel 会静默
生成目录；现在五个必需项逐项缺失都在生成完整目录前拒绝。五项宿主测试同时覆盖
原 48/96 MiB 与新 128 MiB 的精确边界、超一字节拒绝、错误 ISA/解释器拒绝。
这些 fixture 不执行目标程序，也不证明运行时协议。

```sh
python3 -m unittest discover -s tests/host -p test_cosmic_core_catalog.py -v
python3 tools/assemble_cosmic_core_catalog_v1.py \
  --base-build artifacts/v017-os-cosmic-phase-release-20261119 \
  --notifications artifacts/v017-notifications-installed-v2 \
  --output artifacts/v017-cosmic-core-catalog-v1
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-core-services-v1 --sysroot artifacts/v017-cosmic-core-catalog-v1 \
  --output artifacts/v017-os-cosmic-core-services-v1
```

装配器在发布前独立复核通知安装，保持所有原输入字节/模式，并原子发布新目录。
57 是输入数；实际生成的 kernel catalog 嵌入 18 个程序，包括全部五个必需程序。
原输入中的 `pixman-probe.elf` 没有被本 profile 的名称表选入 ROM。

## 两次正常启动与下一项失败

```sh
python3 tools/os_cosmic_startup_probe.py \
  --build artifacts/v017-os-cosmic-core-services-v1 \
  --output artifacts/<新的运行捕获目录>
```

镜像 SHA 为 `205d22b012504deceee539912b7bf9b0147988034a06f2d4f9177bb1ebbc2a2b`。
`artifacts/v017-core-notifications-runtime-v1` 和 `-v2` 两次均观察到正常 session
启动通知与 panel 的请求，以及紧随请求的真实 kernel 子进程发布：通知 PID 5、
panel PID 6，父进程 PID 2。两次均不再出现原通知启动 ENOENT。各捕获的
`spawn-evidence.json` 绑定实际 UART SHA；它是启动观察，不是服务就绪证明。

两次仍为 FAIL，新的终止日志均为 `Failed to bind SIGTERM handler`、EINVAL(22)。
没有通过放开信号标志校验来掩盖它。另有 app-library、launcher、workspaces、
osd、osk、bg、greeter、files-applet、idle 九个未安装程序的 ENOENT，以及 Compose
数据缺失等日志，需要继续逐项处理。

两次错误时的 PPM 相同，仍有 327,738 个启动色条像素；这是中途部分 scanout，
不是完成的桌面或 45 秒首帧通过。QMP quit 与 QEMU 退出码 0 均已观察到，
不等于客体全局资源回收。通知协议、语义帧、完整会话和 FullOs 验证均为 false。

本轮 40 项静态来源/工具链/OS host 检查、20 项独立安装器测试和五项新 catalog
回归通过。SIGTERM 注册需要独立最小复现并落实其信号语义，再继续其余组件供给。
建议提交摘要：`fix(cosmic): supply pinned notifications and require core service images`。
