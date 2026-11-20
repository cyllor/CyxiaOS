# COSMIC 日历渲染的 Mesa 分配失败传播

接续[真实 EGL 与时钟记录](v17-cosmic-egl-time-applet-20261120.md)，本轮修复实际
捕获的 Mesa 空指针复制。共享对象的真实 16 槽边界、4096 页池、每对象 8 MiB、
进程堆/FD/线程额度及原 45 秒首帧门槛保持不变。错误传播、最终画面、交互延迟
和完整桌面验收分别记录。

## 快速回归与原因

前序两轮真实客体复现：panel 的 memfd 创建返回 ENOMEM，随后颜色缓冲区分配
失败，实际写地址为 0；故障返回地址落在固定 Mesa 的
`dri2_wl_swrast_put_image2`。本轮保留完整上游 C 翻译单元和 MIT 通知，直接提取
真实函数构建故障注入单元。Wayland/分配边界是宿主 fixture，复制、状态更新、
两种 swap 及其调用关系来自原函数，不把这个单元当作客体 EGL/IPC 证明。

```sh
python3 -m unittest discover -s tests/host -p test_mesa_wayland_allocation.py -v
```

原代码约 2.966 秒，7 项中 6 项失败，包括实际 SIGSEGV、分配失败却发布 `back`、
重试绕过分配，以及 swap 失败仍返回成功。正常复制基线通过。版本化修复随后
七项全部通过（首次 1.146 秒）：失败清空 `back`；延迟 loader 回调没有有效数据
时设置 EGL_BAD_ALLOC 并返回；damage swap 传播更新失败；ordinary swap 返回
真实下层结果。资源恢复后的原始字节复制与真实提交次序仍通过。

## 真实目标编译与独立安装

`build_mesa_wayland_oom_v1.py` 使用实际原 SDK 的原编译命令，仅替换翻译单元
源码和输出路径，并补回原有同目录头文件搜索。204 项实际源码/头文件/工具/
SDK 输入前后核对，目标为 x86_64 ET_REL，公开符号集合与原对象相同。
完整 EGL archive 仅此成员变化，其余成员逐字一致；原 SDK 没有被改写。

目标对象 SHA256：
`ed1478a5aad96ad0c3fe0f31c9acda68044f618d113195d678a26467d1db5f9e`。

Rust Smithay rlib 内还打包了原 C 对象，因此只替换末尾的 `libEGL.a` 不足以
保证生效。正式重编译保留完整 Rust 源码、473 包解析图、默认 GUI 特性和所有
依赖 archive，仅对真实 panel 根包使用指定链接器，先输入新 C 对象。实际
link map 确认未选入旧的 bundled Wayland 对象。没有修改 ELF 或替代函数实现。

真实 panel 重编译 86.954 秒，仍为 33,660,976 字节，SHA256
`c323487b50084d632525d380050e1f6fd3fa1dab6df4825384a1039064806171`。
原源树、依赖缓存、工具链和 SDK 前后保持。独立 consumer 再验证完整 canonical/
registry 来源、锁图、源树、native repair、link map 和 FullOs 静态 ELF。
正常目录仅替换 panel，增加原上游 MIT 通知；其余 127 个输入保持，原始总量
156,213,022 字节，仍在已有 192 MiB ROM profile 内。

## 原始正常会话对照

正式镜像 `artifacts/v017-os-panel-mesa-wayland-oom-v1` 的 boot SHA256 为
`5da4d20dc9320207c4385b5652db4245319d16535874354372520a21092a86c9`。
`v017-panel-mesa-wayland-oom-session-v1` 保留原启动、真实通知总线和鼠标日历
操作。180.034 秒时真实时钟、原 panel 子进程 PID 8 和五个核心进程存活。

点击后仍实际遇到 EGL_BAD_ALLOC，现由 MakeCurrent、damage swap、ordinary
swap 报告分配失败，没有再次发生旧的 memcpy 页错误、panel 139 或时钟 134。
原时钟 PID 8 在输入后仍存活，异常退出列表为空。日历打开时对象 16、页面
931；关闭后回到输入前的对象 12、页面 105、映射 20 和全部引用账本。

该轮交互仍是 FAIL：标题/下方网格在 59.433 秒匹配，关闭 15 秒时画面还未完全
更新。相应的延迟失败保留，不能把“没有崩溃”当作日历功能或性能通过。后续
诊断增加完整底部设置文字的检查，以避免把分块显示中的部分月份网格当作
完整 popup；扩展观察时间与原 15 秒交互时限分别记录。

该轮 45.002 秒仍有 159,802 个启动像素，首帧 FAIL；晚帧替换及公共通知名存在
不改变原判定。完整 OS、语义首帧、COSMIC session 验证仍为 false。

## 原生 EGL 的拒绝、恢复与实际像素

原生客户端首版对未绑定的第二个表面调用 swap，被 API 以 EGL_BAD_SURFACE
提前拒绝，未进入目标分配路径；保留为 `before-runtime-v1` 的无结论诊断，
不计作这个 Mesa 缺陷的复现。

修正后的最小场景只保留一个真实 EGL window/context，先验证它就是当前绘制
表面。诊断的 `--wrap=memfd_create` 调用真实 libc，再用真实 fcntl 保留一个
FD 引用，使旧 backing 在 resize 时仍存活；没有伪造分配、错误码或 EGL 实现。
随后实际创建 14 个零字节 memfd，得到真实 ENOMEM，耗尽的是原 16 个全局
元数据槽。对当前窗口 resize 触发新 backing 申请，确保进入原失败链。

原 SDK 的 `v017-mesa-wayland-oom-before-runtime-v2` 出现同一页错误：地址 0、
指令 `0x1c43cd4`。直接解析同一 ELF，定位为 `memcpy + 0x24`，真实机器指令
为 `f3 48 a5`（rep movsq）。本轮驱动为收集恢复帧等待了原 30 秒期限，因此
记录的 30.029 秒是失败采集时长，不是 memfd 或复制耗时。compositor 冷启动
35.748 秒另计。

相同客户端只更换经过独立校验的新 EGL archive 后，
`v017-mesa-wayland-oom-after-runtime-v1` 全部通过：真实 FD 引用、当前表面、
实际满额、ordinary/damage swap 的 EGL_FALSE + EGL_BAD_ALLOC、释放后的
恢复六项，以及原有 EGL/Wayland/显示链路九项。恢复后逐个核对 128×64 RGBA
readback，真实扫描输出各有 2,304 个红色/绿色像素，frame callback 和退出
清理通过；与之前健康 EGL 探针的实际图像 SHA 相同。

compositor 冷启动 34.964 秒，客户端整轮 18.021 秒，包含两次故意拒绝、
恢复绘制、截图握手和清理，不能当作纯 EGL 操作性能数据。

| 原生证据 | SHA256 |
|---|---|
| 原 SDK before-v2 boot.bin | `87aa8df4e43e2870f6e2fa4895e5362eedbfd0f656315a78e79f6c4a1c580577` |
| 修复后 after-v1 boot.bin | `c8319abd17985552380a117dc5d9b72565f135a1288c5d4acf86b09d50182a0b` |
| 恢复后 frame-0.ppm | `c25bb373490118f5ef30ef649959379ae15f1b153cd846a21c205b7dfc909b8e` |

```sh
python3 tools/build_wayland_egl_probe.py \
  --base-build artifacts/v017-os-wayland-egl-v2 \
  --panel-build artifacts/v017-panel-allocation-build-v5 \
  --source user/ported/mesa_wayland_oom_probe.c --hold-memfd-backing \
  --repair artifacts/v017-mesa-wayland-oom-build-v1 \
  --output artifacts/<new-native-oom-catalog>
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-session --sysroot artifacts/<new-native-oom-catalog> \
  --output artifacts/<new-native-oom-image>
python3 tools/os_mesa_wayland_oom_probe.py \
  --build artifacts/<new-native-oom-image> --output artifacts/<new-native-oom-capture>
```

省略 `--repair` 即为原 SDK 对照。原正常目录没有该引用保持器、额外 FD 或
诊断程序；真实正常 panel 使用相同 C 修复，时钟和其他核心组件保持原 ELF。

## 正常会话两轮完整交互

`v017-panel-mesa-wayland-oom-session-v2` 使用同一正常镜像和真实 QMP 鼠标输入，
没有改变客体程序。观察器在打开时同时要求标题、下方月份网格和底部设置入口
可见；关闭时要求日历区域完全消失。每一步另保留原 15 秒时限，只把扩展至
120 秒的观察作为独立功能诊断，原失败记录未被修改。

| 操作 | 观测秒数 | 最终画面 | 15 秒时限 |
|---|---:|---|---|
| 首次打开 | 44.897 | PASS | FAIL |
| 首次关闭 | 16.884 | PASS | FAIL |
| 再次打开 | 53.970 | PASS | FAIL |
| 再次关闭 | 17.326 | PASS | FAIL |

这些时间包含采样、截图和像素判定，不是纯渲染耗时。两轮后原时钟 PID 8
持续存活，五个核心进程与时钟均有最终输入之后的 Running/Waiting、code 0
记录，无异常退出。两次关闭后的完整共享对象快照与输入前逐项相同：对象 12、
页面 105、映射 20、描述引用 12、映射引用 20、grant_used 105、reserved 0、
free_pages 3991；实际容量仍为 16 对象、4096 页。

人工核对真实重新打开的截图：完整月份数字、20 日高亮及底部设置入口可见。
两张关闭截图在排除指针后的时钟字形像素均为 166，日历区域为零；转换后的
PNG 也独立核对了时钟字形，避免把指针算作时钟。此处通过的范围是晚到的
日历两轮开关、原进程存活和基线恢复。

正常启动原 45.023 秒仍有 196,666 个启动像素，必要首帧检查 FAIL。
`result.json` 的整体启动状态仍为 FAIL；`time-result.json` 单独记录上述功能
诊断 PASS，15 秒标记为 false。完整 OS、语义首帧与 COSMIC session 均保持 false。

最终镜像 `artifacts/v017-os-panel-mesa-wayland-oom-v2` 已按定稿源码再次构建并
通过当前 source/compiler/catalog 校验。由于之前仅修改了不装入正常目录的
原生诊断客户端，最终 `boot.bin` 和 `kernel.elf` 与已经完成两轮实测的 v1
镜像逐字一致，boot SHA 保持 `5da4d20dc9320207c4385b5652db4245319d16535874354372520a21092a86c9`。

```sh
python3 tools/os_cosmic_time_probe.py \
  --build artifacts/v017-os-panel-mesa-wayland-oom-v2 \
  --output artifacts/<new-normal-calendar-capture> \
  --observe-seconds 180 --inspect-bus
```

最终七项宿主回归通过，原源代码的六项失败以同一最终 fixture 再次确认。
扩展后的 EGL 构建工具在默认模式下重新编译，产物与此前实际通过健康 EGL
回路的 ELF 逐字一致。新 Python 源码解析、diff/临时日志清理检查通过。旧镜像
和失败证据均保留；磁盘空间不足时只清理可再生编译缓存，并对历史 kernel.elf
使用透明压缩，替换前后都核对完整 SHA，未改变逻辑文件字节。

[聚合证据](../../artifacts/v017-cosmic-mesa-wayland-oom-evidence-v1.json) 记录精确
source/producer 快照、原生故障位置、修复前后镜像与串口、真实像素、两轮 UI
结果及最终镜像绑定。后续缺口仍包括启动与交互延迟、其他默认 applet/应用/
服务供给、P2P/监督边界及完整桌面生命周期验收。
