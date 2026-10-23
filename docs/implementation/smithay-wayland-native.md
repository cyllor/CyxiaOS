# Smithay Wayland 前端与原生显示、输入

本阶段把真实 Smithay Wayland 前端、GLES 渲染器和 CyxiaOS 原生显示、输入接口连接起来，已通过三次独立 ARM 客体启动验收。独立 C 客户端使用上游 libwayland 1.24.0 和 xkbcommon。测试使用普通 `wl_surface`，尚不包含 xdg-shell、窗口管理、COSMIC 会话或完整桌面。

## 来源与构建边界

Smithay 固定为 `e3d461a057ba244d213a8498ec372b0799cca103`，版本和 registry checksum 均来自固定 COSMIC lock。新清单 `ports/cosmic/smithay-wayland-source.json` 包含 103 个 registry 归档，比离屏渲染基础新增 14 个；归档总计 14,112,907 字节。实际 ARM 依赖图包含 71 个 registry crate、Smithay 和探针。Wayland backend 使用真实 Rust 协议实现，不装载宿主 Wayland 服务。

功能集合为 `backend_egl_static`、`renderer_gl`、`wayland_frontend`、`cyxia_sync_shm_drop` 和 `cyxia_precompiled_keymap`。构建器保留全部强制依赖和完整上游源码，只排除未启用的可选后端及开发工作区。Mesa 使用已验证的 r10 静态 softpipe SDK，仍保留全部七个上游内建渲染程序。

构建目录、Cargo home、vendor 和 target 全部隔离。下载上限 64 MiB，源码展开上限 256 MiB，单次目录上限 1.5 GiB，至少保留 2 GiB 磁盘，限时 600 秒。关键输入在构建前后校验，包含实际编译的 `main.rs`、`native.rs`、`us.xkb` 副本、锁文件、补丁、工具链、生成绑定和静态库。原有离屏探针及冻结证据保持独立。

映像页数按 ELF 每个 `PT_LOAD` 触及的完整页计算，包含首地址未对齐部分，再加入 64 个强制栈页，合计不得超过 4096。堆上限仍为 4096 页，所有资源申请继续通过内核 AI 授权。

## 显式上游适配

沿用静态 EGL 装载补丁，继续通过真实 `eglGetProcAddress` 填充原始生成入口表。新增补丁为 `ports/cosmic/smithay-wayland-adaptation.patch`：

- `cyxia_sync_shm_drop` 在拥有共享池的最后一个引用释放时，同步执行原始 `InnerPool` 析构。原来的映射和 FD 所有权不变；避免启用上游的常驻析构工作线程及无界队列，代价是析构延迟由合成器线程承担。
- `cyxia_precompiled_keymap` 为 `XkbConfig` 增加可选完整 XKB 文本。仍由真实 xkbcommon 解析并生成状态、修饰键和协议 keymap；没有替换按键翻译。未指定文本时保留原来的 rules 路径。

`us.xkb` 是此前 xkbcomp 基础构建的 60,908 字节完整 US keymap 文本，来源为 `artifacts/xkb-host/runs/build-zf2km8uo/cyxia-us-expanded.xkb`，SHA-256 `0e0746bf5f507ac5d73d7614f65d4c1c6bafcebf64edff570957cc2ddc0a75e5`。发送给客户端的实际 keymap FD 经过上游封印流程，客户端按版本 7 协议以只读 `MAP_PRIVATE` 映射并再次解析。

## 实际数据路径

`CompositorState`、`ShmState`、`SeatState` 和 `Display` 全部来自上游。提交首先调用 `on_commit_buffer_handler`，随后只通过上游 surface element 路径导入并渲染缓冲区，避免重复取走 buffer。缓冲区释放由上游所有权生命周期产生，不发送替代性的假 release。

合成器通过 Unix stream pair 接入两个依次启动的独立客户端，以 CyxiaOS 原生 spawn ABI 启动 `/bin/smithay-wayland-client`，连接继承到 FD 3。每个客户端提交三帧：64×48、内容改变的 64×48、96×64。每帧使用新池；客户端在服务端导入并完成 roundtrip 后才写入共享像素，证明服务端看到的是存活映射。尺寸变化通过替换缓冲区实现，不宣称支持 `wl_shm_pool.resize`。

服务端将表面绘制到黑色 128×96 画布，通过真实 framebuffer/PBO 读回，检查包括背景在内的每个像素，然后调用原生接口显示到屏幕 `(32,48)`。输出变换采用上游显示表面示例的 `Transform::Flipped180`，让逻辑顶边对应 framebuffer 顶边，再根据实际 `TextureMapping::flipped()` 转换读回行顺序。六帧合计检查 73,728 个 RGBA 像素。宿主验收器独立读取 QEMU 实际 scanout，检查对应 73,728 个 RGB 像素；宿主不渲染客户端内容。

每次原生显示完成后输出 `FRAME_READY`，保持实际 frame callback 待处理。验收器先截图，再依次注入 A 按下/释放、相对移动 `(4,3)` 加左键按下/释放、Q 按下/释放。原生输入按 `SYN_REPORT` 组包，Smithay 键码输入为 evdev+8，再由原始 Wayland 事件路径发往客户端。客户端验证真实 keymap、修饰键、键值、焦点、坐标和事件顺序，后续像素种子来自收到的键码和按钮码。只有完整输入序列已经转发，服务端才完成该帧回调。

原生显示使用有界分块、真实完成栅栏和同字节重试；错误不能被当成 frame.done。输入丢失或 `SYN_DROPPED` 会使此严格测试失败；原生模块有状态重同步接口，但此测试不宣称已经验证丢失后的完整恢复。

## 构建与执行

```sh
python3 tools/build_smithay_wayland.py \
  --cache artifacts/smithay-wayland-research \
  --mesa-report artifacts/sysroot/aarch64-musl/mesa-static-r10/reports/20261020T155154-51965.json \
  --output artifacts/smithay-wayland-build-new

python3 tools/build_smithay_wayland_client.py \
  --output artifacts/smithay-wayland-client-new

CYXIA_SMITHAY_WAYLAND_PROBE_ELF="$PWD/artifacts/smithay-wayland-build-new/smithay-wayland.elf" \
CYXIA_SMITHAY_WAYLAND_CLIENT_ELF="$PWD/artifacts/smithay-wayland-client-new/smithay-wayland-client.elf" \
CARGO_TARGET_DIR="$PWD/artifacts/smithay-wayland-kernel-new/target" \
cargo build --release --target aarch64-unknown-none-softfloat \
  -p cyxia-kernel --features smithay-wayland-probe
```

最终验收还要求冻结内核源码清单，精确嵌入两份 ELF，并通过 `tools/verify_smithay_wayland.py` 的来源、六帧图像、真实输入、两个客户端正常退出和全部资源归还检查。单纯交叉编译不构成验收。手动执行 `posix exec smithay-wayland-probe` 后，也必须按帧依次输入 A、移动鼠标并点击、Q；此入口是严格集成测试，不是可自由操作的桌面。

## 保留的问题与证据

初始 r2 客体在创建真实客户端后失败：探针传给原生输入接口的数组长度为 64，而 ABI 最大为 32。证据位于 `artifacts/smithay-wayland-kernel-r0/smoke-r2`。r3 将长度修正为 32。

r3 smoke 随后发现 Rust Wayland backend 在第一次接收协议数据时断开连接。源码核对确定 rustix `recvmsg` 提供合法的输出地址缓冲区，而内核旧路径把非空接收地址缓冲区当成不支持的发送目的地址。失败保存在 `artifacts/smithay-wayland-kernel-r1/smoke` 和 `smoke-exit`。内核修复后，下一轮已成功传递并解析 23,019 字节 keymap，完成共享缓冲区导入和渲染。

r4 客体验证在像素 `(0,0)` 检查时发现黑色背景，拒绝通过。`Transform::Normal` 的上游 GLES 投影将逻辑顶边放在 GL 底边，与原生输出的行方向转换不匹配。r5 按上游显示表面示例设置 `Transform::Flipped180`；读回和原生输出仍使用真实 mapping 元数据，未放宽任何像素判断。失败保存在 `artifacts/smithay-wayland-runtime-r2` 和 `artifacts/smithay-wayland-kernel-r2/smoke-exit`。

构建器原先只按段长度取整，少算最后一个未对齐段的一页。r4 改为计算所有实际触及页，边界回归测试通过。最终 r5 仍为 3951 个映像页加 64 个栈页，共 4015/4096 页，和内核真实 admission 日志一致。

## 最终冻结验收

| 产物 | SHA-256 |
| --- | --- |
| `artifacts/smithay-wayland-build-r5/smithay-wayland.elf` | `7226bd785880337b259a8c13301a6930f37af53521e4ca636643dd69831e2737` |
| `artifacts/smithay-wayland-build-r5/build-report.json` | `ab9ad098395b2a6061668490ef67c998e98dff3a4935ddc93ee37abb2dbcdd97` |
| `artifacts/smithay-wayland-kernel-r3/cyxia-kernel.elf` | `93e9e4f7577912400d4b1cea990a8762be503c32b4d0d2f84284b1098981bcf1` |
| `artifacts/smithay-wayland-runtime-r3/summary.json` | `16220e0012b417dabccf7fc0108551bfbfff03662c8e53fa84d50f36bfd765c1` |

最终运行报告为 **PASS**，`smithay_wayland_verified=true`，`full_cosmic_port=false`、`cosmic_runtime_verified=false`。验收绑定 429 项来源输入，包括精确内核、两份用户态 ELF、构建与编译副本、模块、工具和协议依赖；运行前后再次核对，全部保持一致。

三个独立启动分别完成两个客户端、六帧和 73,728 个实际 scanout 像素检查，总计 18 帧、221,184 个扫描输出像素；服务端同时完成相同数量的真实 GLES 读回像素检查。每次启动有 14 条实际 QMP 键鼠输入命令，客户端真实收到 A/Q、相对移动和左键按下/释放，并解析 23,019 字节实际序列化 keymap。对应六幅画布的哈希跨三次启动相同。每次启动的 18 次原生显示提交均由 AI 准入并完成实际栅栏，没有 guard 准入、失败或遗留提交。

两个客户端和服务端均产生真实正常退出记录，ESR/FAR 为零。客户端先由服务端 waitpid 回收，最终可见进程均无堆、映像或线程占用，堆和映像池各恢复 4096 页。全局 OFD、SCM 权利、共享对象、共享页和映射归零，资源授权与归还守恒；同步共享池析构没有产生后台工作线程。

宿主构建检查四项通过，报告为 `artifacts/smithay-wayland-host-tests-r4.txt`；验证器八项负面与时序检查通过，报告为 `artifacts/smithay-wayland-verifier-host-tests-r2.txt`。Python 语法及 Rust 格式检查通过。最终运行示例：

```sh
python3 tools/verify_smithay_wayland.py \
  --elf artifacts/smithay-wayland-kernel-r3/cyxia-kernel.elf \
  --server artifacts/smithay-wayland-build-r5/smithay-wayland.elf \
  --client artifacts/smithay-wayland-client-r0/smithay-wayland-client.elf \
  --output artifacts/smithay-wayland-runtime-new --iterations 3
```

此阶段不覆盖 xdg-shell、多个并发表面、合成策略、拖放、剪贴板、DMABUF、DRM/GBM、热插拔、动态共享池扩容、SIGBUS 故障恢复或任意复杂 shader 的内存不足处理。完整 COSMIC 运行状态保持 `false`。
