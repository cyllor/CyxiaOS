# Smithay 静态 EGL 与高层 GLES 渲染器

此阶段将固定版本的真实 Smithay `EGLDisplay`、`EGLContext` 和 `GlesRenderer` 连接到 CyxiaOS 的静态 Mesa。其范围是离屏渲染基础，不包含 Smithay Wayland 合成器、窗口管理、显示输出后端或 COSMIC 会话。

## 固定来源与依赖边界

Smithay 提交为 `e3d461a057ba244d213a8498ec372b0799cca103`，来自已固定 COSMIC `cosmic-comp` epoch 的 Cargo.lock。源归档 SHA-256 为 `2589c4bd9b8b13ac430cf22b4263388522b330d114b07a1ec6d764f80b3c7087`，大小 886,949 字节，展开后 4,490,196 字节。

`ports/cosmic/smithay-source.json` 固定源归档、89 个 registry 归档、原始 COSMIC lock 和隔离探针 lock。registry 归档共 13,282,668 字节，展开后 91,235,894 字节；包括 Cargo 锁定需要的其他平台依赖元数据。实际 ARM 构建解析图包含 56 个 registry crate、Smithay 和探针。所有 registry 版本及 checksum 必须与原始 COSMIC lock 一致。

隔离构建仅选择 `backend_egl_static` 和 `renderer_gl`。构建器保留完整上游 Rust 源码及全部强制依赖，将源清单投影到这一功能集合：删除未启用的可选后端、上游工作区成员和开发测试依赖，保留所选依赖的原始选项并固定精确版本。尝试删除任何强制依赖或使用歧义版本都会失败。共享 Cargo 配置、缓存、sysroot 和 Mesa 源码不受修改。

## 静态装载补丁

唯一上游代码补丁是 `ports/cosmic/smithay-static-egl.patch`：

- 新增显式 `backend_egl_static` feature；原有动态装载分支仍保留。
- 静态分支通过实际链接的 `eglGetProcAddress` 填充原始生成入口表，避免打开 `libEGL.so.1`。
- 完成引导后继续运行原始入口装载、扩展检测、上下文、shader 和渲染器实现。

原始 Smithay `build.rs` 未改动。EGL/GLES 生成文件的 SHA-256 与前一阶段 Rust 绑定探针完全一致，构建器强制检查这两个值。绑定中不存在的符号仍返回空地址。

## 实际探针

`ports/cosmic/smithay-probe.rs` 使用上游 `EGLSurfacelessDisplay` 创建并独占 EGL display/context，然后将上下文所有权交给真实 `GlesRenderer`。所有调用和析构保持在创建线程。软件渲染器必须报告 `softpipe`。

探针使用上游 `Offscreen`、`Bind`、`Frame`、`ImportMem` 和 `ExportMem`：

1. 创建 16×16 RGBA8 renderbuffer，清屏后检查 256 个红色像素。
2. 运行上游实体 shader，检查 256 个绿色像素。
3. 导入 2×2 内存纹理并通过上游纹理 shader 放大，检查 256 个蓝色像素。
4. 更新同一纹理，再检查 256 个黄色像素，覆盖纹理更新后的重新采样。
5. 释放目标并创建 9×7 替代 renderbuffer，检查 63 个品红色像素。

总计逐字节验证 1087 个 RGBA 像素。读回使用 Smithay 自身的 framebuffer→PBO→映射路径，帧完成后等待真实同步点。最后检查 GL 错误、解绑上下文、释放渲染器/display，并确认线程不再持有 EGL context。

## 构建与运行

```sh
python3 tools/build_smithay_probe.py \
  --cache artifacts/smithay-research \
  --mesa-report artifacts/sysroot/aarch64-musl/mesa-static-r10/reports/20261020T155154-51965.json \
  --output artifacts/smithay-build-new
```

默认仅使用已缓存且校验一致的归档；需要首次下载时显式增加 `--fetch`。每次必须选择新输出目录。下载上限 64 MiB，源码展开上限 256 MiB，构建目录上限 1.5 GiB，至少保留 2 GiB 磁盘空间，整个构建限时 600 秒。

报告包含原始和修订后的源码树、vendor 树、Cargo 配置和锁、补丁、构建器及辅助脚本、Rust 目标库、工具链、静态链接输入、实际编译产物和生成绑定的哈希；关键输入在构建结束时再次核对。ELF 必须满足静态 ARM64、W^X 和当前 4096 个映像页容量限制。

客体验证器 `tools/verify_smithay.py` 要求完整且严格有序的 13 项检查及最终完成标记。每个进程必须正常退出，堆、映像、线程及全局对象必须回收，AI 资源授权与归还必须守恒。默认在同一客体连续启动三个独立进程，以覆盖释放后的再次使用。源码发生变更、缺失检查、失败记录、重复记录、错误像素数量或越界的 COSMIC 完成声明均不能被接受。

四项宿主负面测试覆盖记录损坏、缺失及夸大声明、强制依赖删除和版本歧义。实际客体结果以对应冻结运行报告为准；交叉编译本身不构成渲染运行验收。

内核提供独立 `smithay-probe` feature，包含 `ported` 和 `large-memory`，通过明确的 ELF 路径装入 catalog；不需要图形设备或修改默认 sysroot。示例：

```sh
CYXIA_SMITHAY_PROBE_ELF="$PWD/artifacts/smithay-build-new/smithay-probe.elf" \
CARGO_TARGET_DIR="$PWD/artifacts/smithay-kernel-new/target" \
cargo build --release --target aarch64-unknown-none-softfloat \
  -p cyxia-kernel --features smithay-probe

python3 tools/verify_smithay.py \
  --elf artifacts/smithay-kernel-new/target/aarch64-unknown-none-softfloat/release/cyxia-kernel \
  --probe artifacts/smithay-build-new/smithay-probe.elf \
  --output artifacts/smithay-kernel-new/runtime --runs 3
```

串口手动运行命令为 `posix exec smithay-probe`。探针只做离屏渲染，不会打开桌面窗口。

## 首次冻结构建与容量失败

`artifacts/smithay-build-r1/smithay-probe.elf` 的 SHA-256 为
`711debe1843dbd5a01c9dd2d668145cf29fbce9b97069554b049fd67379cad1b`，
文件大小 15,184,480 字节，LOAD 段共 3759 页，满足现有 4096 页映像限制。隔离构建目录使用 404,821,491 字节。`build-report.json` 的 SHA-256 为
`da51f028e2905510510d858cd7977aa887a7e39e80fd37d4bebcc6ec93e015eb`。

首次运行使用现有 `CYXIA_PORTED_ELF` 覆盖入口，通过通用 `probe` catalog 项加载这个精确 ELF，没有修改共享内核源码。临时内核为 `artifacts/smithay-kernel-slot-r0/cyxia-kernel.elf`，SHA-256：
`3b9796749e55459b68374d0caba0b6251513d5aa784df2e99868711d60280240`。
验证命令明确使用 `--program probe`，报告保留 `temporary_catalog_slot=true`，不能据此宣称已完成独立 catalog 功能集成。

`artifacts/smithay-kernel-slot-r0/runtime/summary.json` 为 **FAIL**。第一个 ARM 进程完成上游 `EGLDisplay` 和 `EGLContext` 检查；构造 `GlesRenderer` 时，匿名堆只剩 149 页却请求 256 页，内核正确拒绝申请，随后进程出现 SIGSEGV（退出码 139、FAR `0x18`）。进程退出后的堆、映像、线程和 OFD 均被回收。渲染及像素读回尚未执行。

只读 QEMU 异常跟踪及 LLDB 条件断点进一步确定：六个纹理程序已经编译和链接完成，第七个纯色程序在 `LinkProgram` 内进入 `nir_lower_vars_to_ssa`，随后 `nir_instr_create+68` 向空分配结果偏移 `0x18` 写入。证据保存在 `artifacts/smithay-diagnosis-r0` 和 `artifacts/smithay-diagnosis-stack-r0`。Mesa NIR 的小对象 GC slab 为 32 KiB；1 MiB 的失败请求来自其下层 malloc 分组分配，并非单个 shader 对象需要 1 MiB。

`smithay-build-r2` 曾实验性地在编译 shader 后、链接前调用标准 `glReleaseShaderCompiler`。永久 `smithay-probe` catalog 入口在 `artifacts/smithay-kernel-r2` 完成真实加载，但该实验运行仍为 **FAIL**：请求 256 页时只剩 150 页，再次出现相同异常。Mesa 在链接前重新建立内建函数缓存，因此此策略没有有效降低峰值。实验补丁及构建输入保存在 r2 的 `provenance` 中，已从维护中的源码移除。

现有内存模型的空闲页输入上限为 4096，不能仅增加页数、裁剪模型输入或绕过 AI 授权来消除此失败。原始失败证据保持不变，后续修订必须重新构建并使用新的运行目录。

## 最终冻结运行

Mesa r10 的显式静态配置将 NIR GC slab 从 32 KiB 缩小到 4 KiB，保留对象尺寸、对齐、GC 所有权及回收逻辑。此适配减少小型 shader 的分配浪费，代价是可能增加 slab 数量及链表操作；没有更改着色器、GL 结果或内核容量。SDK 报告 SHA-256 为 `032a9f5d90db2a7f6d3beb3b59674fdc89b22098b5e1a75c7c4cc93a45a9846f`。Smithay r3 恢复原始完整的七程序构造路径，仅保留静态 EGL 装载补丁。

| 冻结产物 | SHA-256 |
| --- | --- |
| `artifacts/smithay-build-r3/smithay-probe.elf` | `cf423148ab2307be01816f2c2530a0446e869b8db521c821905d498e994843c8` |
| `artifacts/smithay-build-r3/build-report.json` | `5409c2b59062570b80b0c4c05c69c8bb6bdff6d94296ed1d26b50dfb58f201da` |
| `artifacts/smithay-kernel-r3/cyxia-kernel.elf` | `ed82d6054c3b0e510632b1dbc0b2061f939865031b51f3872332ccb9680f2016` |
| `artifacts/smithay-kernel-r3/runtime/summary.json` | `1098684bba928b6e90271ec63b80918c3915248b00abb2927561e8fd2fefa47f` |

探针仍为 15,184,480 字节、3759 个映像页。内核构建前后校验源码和 catalog 输入未变，精确探针 ELF 只嵌入一次。实际 ARM 客体连续启动三个独立进程，全部 **PASS**：每次完整执行 13 项检查和完成标记，逐字节检查 1087 个像素。三个进程均正常退出，ESR/FAR 为零，堆和映像使用归零、各剩余 4096 页、线程数归零；OFD、SCM、共享对象及 AI 授权归还计数通过守恒检查。

此结果验证了真实 Smithay 高层 EGL/context/GLES 渲染器在当前预算内的指定负载。它没有测量任意负载的完整内存峰值，也没有修复 Mesa NIR 所有内存不足路径；更复杂 shader 仍可能超过容量。`cosmic_runtime_verified` 明确为 `false`。宿主负面测试报告为 `artifacts/smithay-host-tests-r3.txt`，Rust 格式和 Python 语法检查通过。

## 后续范围

此接口基础仍需与真实 Wayland 对象、输入、事件循环、显示输出和会话生命周期整合。当前功能集合没有启用 DRM/GBM、X11/winit、Wayland frontend 或 COSMIC。完整 COSMIC 的依赖和平台适配不能由本探针的成功替代。

上游依据：[固定 EGL FFI](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/egl/ffi.rs)、[固定 GLES 渲染器](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/renderer/gles/mod.rs)、[固定 Cargo 功能清单](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/Cargo.toml)。
