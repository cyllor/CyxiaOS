# Rust 静态 EGL 与 Smithay 生成绑定

此实现把已经交叉编译的真实 Mesa 静态库连接到原生 Rust ARM64 程序，并使用固定 Smithay 版本的原始 `build.rs` 生成 EGL/GLES API。它完成的是 Rust 图形 API 装载与调用基础；不表示 Smithay 的 `EGLContext`、`GlowRenderer` 或 COSMIC 合成器已经编译和运行。

## 来源与实际构建路径

固定 COSMIC epoch 的 `cosmic-comp` 提交为 `41497b42d9744d9963c4c6d17e8add49489b45ee`；它的 Cargo.lock 固定 Smithay 为 `e3d461a057ba244d213a8498ec372b0799cca103`。新增的 `ports/cosmic/rust-egl-source.json` 绑定此 lock 的 SHA-256、Smithay 构建脚本、Cargo 清单、EGL FFI 源码和 MIT 许可证。

构建工具直接编译四个上游宿主 crate，保持默认功能；每个发布归档的 SHA-256 必须与 COSMIC lock 一致：

| 宿主 crate | 版本 | 用途 |
| --- | --- | --- |
| `gl_generator` | 0.14.0 | 生成有类型的 EGL/GLES 入口 |
| `khronos_api` | 3.1.0 | 固定 Khronos XML 注册表；运行其原始 build.rs |
| `log` | 0.4.29 | 上游生成器的日志依赖 |
| `xml-rs` | 0.8.28 | 上游 XML 解析器 |

随后编译并执行**未修改的 Smithay build.rs**，仅启用其 `backend_egl` 与 `renderer_gl` 条件：EGL 1.5 使用上游 GlobalGenerator，GLES 3.2 使用上游 StructGenerator，扩展列表也直接取自该脚本。目标 Rust 程序包含原始生成结果，没有手写替代图形 API，也没有额外目标 Rust crate；运行时使用官方 `aarch64-unknown-linux-musl` Rust std 和项目现有 musl。

来源：[Smithay 固定构建脚本](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/build.rs)、[固定功能清单](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/Cargo.toml)。

## 静态装载和真实绘制

`ports/cosmic/rust-egl/probe.rs` 用一个直接链接的真实 `eglGetProcAddress` 引导生成的入口表。所有必要入口必须实际存在，未知名称必须返回空指针。程序在 EGL 1.5 surfaceless display 上创建 RGBA8、GLES3 的 4×4 pbuffer，要求驱动报告 `softpipe`。

第一次读回检查真实清屏产生的 16 个红色 RGBA 像素；第二次编译真实 ES3 顶点和片元 shader，绘制覆盖整个目标的三角形，再逐字节检查 16 个绿色像素。最后检查 GL/EGL 错误，并要求取消 current、销毁 surface/context、terminate 和 release-thread 均成功。错误路径保留 RAII 清理；所有工作保持在创建上下文的同一线程。

构建使用 Mesa r8 报告中的实际静态归档集合，逐项核对链接前后哈希，不复制或修改 Mesa 源码，不安装宿主驱动，不通过 Linux 客体或远程绘制。生成绑定只表示 API 类型范围；程序只要求实际驱动支持的 GLES3 功能，不声称 Mesa 支持整个 GLES3.2 注册表。

## 有界复现和证据

```sh
python3 tools/build_rust_egl_probe.py \
  --cache artifacts/rust-egl-research \
  --mesa-report artifacts/sysroot/aarch64-musl/mesa-static-r8/latest-report.json \
  --output artifacts/rust-egl-build-new
```

首次缺少输入时可明确加 `--fetch`；默认只接受已经缓存且哈希匹配的输入。整个构建限时 180 秒、目录限额 256 MiB、剩余磁盘至少 1 GiB；下载闭包上限 16 MiB，展开源码上限 32 MiB。源路径、归档路径和链接不能逃逸工作目录。没有修改共享 Cargo.lock、Cargo 配置、sysroot 或内核。已有输出目录会拒绝重用。

冻结 r3 构建完成时的工作目录占用为 64,812,527 字节。`artifacts/rust-egl-build-r3/rust-egl-probe.elf` 为 14,869,640 字节，映射 LOAD 段共 15,077,376 字节，在现有单进程 ELF 容量内；SHA-256：
`1598b8e1197ba612f2d37bfacb631f77d24207557675db5aa4746e23edd72bb1`。

`build-report.json` 保存命令、工具链版本、所有目标 Rust rlib、unwind、Mesa 静态输入、源文件、生成结果、构建器和日志哈希。其 SHA-256：
`3445bce47c7b1b96803a19fa9e490a195b6f379ee868f60e3dd0080bb822839f`。

内核以 `rust-egl-probe` 可选 feature 和 `CYXIA_RUST_EGL_PROBE_ELF` 路径显式嵌入此产物，使用 `large-memory` 配置；不要在同一完整桌面 catalog 中重复嵌入 C 与 Rust 两份大型 Mesa 探针。客体验证入口：

```sh
python3 tools/verify_rust_egl.py \
  --elf artifacts/cosmic-rust-egl-r1/cyxia-kernel.elf \
  --probe artifacts/rust-egl-build-r3/rust-egl-probe.elf \
  --output artifacts/rust-egl-check-new \
  --runs 3
```

验证器要求同一客体中连续三个独立进程的 16 个严格成功断言、实际 softpipe 字符串与最终完成标记，检查堆、映像、线程及全局对象回收，并核对 AI grant/release 守恒。源码和产物哈希必须匹配，缺失、重复、失败、交错损坏或错误驱动的记录均不能通过。四个宿主负面测试已通过。

冻结内核 `artifacts/cosmic-rust-egl-r1/cyxia-kernel.elf` 的 SHA-256 为
`f4b7db26e4b431c29b66b9bf2cc2a851b0e4d7afa17223e28d8eee0b322f9f4e`。
真实 ARM 客体报告 `artifacts/cosmic-rust-egl-r1/runtime/summary.json` **PASS**，SHA-256 为
`f81e098653e8faa2ba40d51ce568fd1bbe90e5db55dc59505cce2b480492dd87`。

本次验收为**一次客体启动、三个连续独立进程**，可检查资源释放后的重复使用。每个进程均得到完整 18 条有序记录，退出码、ESR、FAR 均为 0，线程数、堆页、映像页均归零，堆与映像各恢复 4096 个空闲页。每次结束后 OFD、SCM 引用、共享页及映射均为 0。三个进程合计匿名内存 AI grant/release 为 1845/1845，页额度为 25032/25032；映像 grant/release 为 3/3，页额度为 11238/11238。此运行结果仅证明上述静态装载与真实绘制基础；报告明确保留高层 Smithay 和 COSMIC 运行状态为未验证。

## 后续 Smithay 整体移植入口

固定版本的 `backend_egl` 仍强制依赖 `libloading`；其 `src/backend/egl/ffi.rs` 的 `egl::LIB` 打开 `libEGL.so.1`，`make_sure_egl_is_loaded` 先取得库符号再装载扩展。下一步应在独立、可审核的 Smithay 补丁中增加静态装载分支，保留统一生成入口和扩展检测，再实际构造 `EGLDisplay`/`EGLContext`。当前探针没有修改该高层实现。[固定 EGL FFI](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/egl/ffi.rs)

`GlowRenderer` 进一步依赖真实 GlesRenderer 和 EGLContext，在上下文 current 后通过函数装载器构造 glow；它不是仅添加一个 crate 就能替代当前探针的独立后端。需继续收敛 Smithay 的依赖闭包、事件循环、XKB/Wayland 运行路径和特性集合。COSMIC 的清单显式启用了多个 DRM、GBM、Vulkan、winit、X11 功能；仅给 COSMIC 传 `--no-default-features` 不会移除这些显式依赖。[固定 GlowRenderer](https://github.com/Smithay/smithay/blob/e3d461a057ba244d213a8498ec372b0799cca103/src/backend/renderer/glow.rs)
