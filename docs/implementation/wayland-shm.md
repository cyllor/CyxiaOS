# 真实 Wayland 共享缓冲区与键盘映射门禁

此门禁连接已经移植的真实 libwayland 1.24.0 客户端、服务端和 libxkbcommon 1.13.2，验证 CyxiaOS 原生 ARM64 进程之间的 SCM_RIGHTS、memfd 与共享物理页。它不是 COSMIC 合成器，也不绘制输出或模拟桌面已经完成。

## 协议与所有权

`user/ported/wayland_shm_probe.c` 的父进程通过上游 `wl_display_init_shm` 注册 `wl_shm`，通过真实 `wl_compositor` 与 `wl_seat` 协议提供最小测试服务端。`wl_shm_pool`、缓冲区检查与服务端映射由上游 libwayland 实现。父进程使用已有 `cyxia_spawn` ABI 依次创建两个独立客户端；各客户端的 socketpair 一端作为 FD 3 显式继承，没有宿主代理或 Linux 客体参与。

每个客户端先建立 64×48、再建立 48×37 的 XRGB8888 共享缓冲区。客户端创建并映射 memfd，发送池与缓冲区创建请求，销毁池协议对象并关闭原始 FD，然后执行一次真实 `wl_display_roundtrip`。只有收到此同步回复后才修改共享像素，再发送 `surface.attach`、`surface.frame`、`surface.damage` 和 `surface.commit`。因此，传递 FD 时复制内容不能通过这个测试；服务端必须从已导入的共享映射读取客户端之后写入的数据。

服务端通过 `wl_shm_buffer_get`、`wl_shm_buffer_begin_access` 和 `wl_shm_buffer_get_data` 检查尺寸、stride、格式和每个像素。四帧共检查 9696 个像素。检查后发送真实 `wl_callback.done` 与 `wl_buffer.release`，客户端要求各收到一次，再销毁缓冲区并完整取消本地映射。关闭 FD、提前销毁池协议对象和跨进程引用均遵循实际对象生命周期。

两个尺寸使用两个新建池，**不调用 `wl_shm_pool.resize`**。当前 CyxiaOS 尚无上游动态池扩容路径需要的 `mremap(MREMAP_MAYMOVE)`，本门禁不覆盖池扩容、通用文件 mmap 或截断后的 SIGBUS。

## 键盘映射路径

客户端通过真实 `wl_seat.get_keyboard` 申请键盘。服务端创建包含自包含 XKB keymap 的 memfd，加上缩容、扩容与后续封印限制，通过 `wl_keyboard.keymap` 事件传递 FD，并关闭自己的 FD。客户端以只读 `MAP_SHARED` 映射收到的 FD，关闭 FD，逐字节核对内容，再交给真实 libxkbcommon 解析。键值断言包括普通 `a`、Shift 后 `A`、Caps Lock 后 `A` 和 Ctrl+A 的字节 `0x01`。

这证明键盘布局文件经过 Wayland FD 传输并可解析；不表示物理键盘驱动、座位焦点、真实 `wl_keyboard.key` 事件、完整系统布局数据库或输入法已经完成。

## 构建与验收

构建工具 `tools/build_wayland_shm_probe.py` 使用现有静态 ARM64 musl sysroot，不下载源码、不改写共享 sysroot、不执行 ARM 程序。它核对 Wayland/XKB 原始构建报告中的 manifest、库归档和 libc 哈希，记录源文件、spawn 头文件、编译驱动、compiler-rt、工具链及完整命令；每次必须使用新输出目录。产物经过 ET_EXEC、AArch64、W^X、地址范围、PHDR 与未定义强符号检查。

```sh
python3 tools/build_wayland_shm_probe.py \
  --output artifacts/wayland-shm-build-r1
```

当前通过客体门禁的产物为 `artifacts/wayland-shm-build-r1/wayland-shm-probe.elf`，SHA-256：
`cfba2ad538814e15e099761dd63b2f809cdd895e3aee9161d240d6692e96e573`。源码 SHA-256 为 `d5c2f754652610271754b39d80fcbd0a36caaaba2dca1b5a5d0523ed97ce0301`。上述命令是冻结构建的复现参数；重新构建必须指定尚不存在的输出目录。

内核通过显式 `wayland-shm-probe` feature 注册 `/bin/wayland-shm-probe`，从 `CYXIA_WAYLAND_SHM_PROBE_ELF` 读取构建产物路径，保留默认 sysroot 和旧冻结产物。完整桌面回归候选使用：

```sh
CYXIA_WAYLAND_SHM_PROBE_ELF="$PWD/artifacts/wayland-shm-build-r1/wayland-shm-probe.elf" \
  cargo build -p cyxia-kernel --release --target aarch64-unknown-none \
  --features graphics,lxpanel,large-memory,spawn-test,wayland-shm-probe
```

复制并记录内核哈希后运行：

```sh
python3 tools/verify_wayland_shm.py \
  --elf artifacts/cosmic-shared-r3/cyxia-kernel.elf \
  --output artifacts/wayland-shm-check-new \
  --probe artifacts/wayland-shm-build-r1/wayland-shm-probe.elf \
  --iterations 3
```

验证器绑定内核、嵌入 ELF、探针源码和构建报告哈希。每次独立启动检查三个不同的原生进程正常退出、四个像素帧及对应 done/release、两个键盘映射和两次客户端清理。最终必须满足：

- 所有 OFD、epoll、watch、在途 SCM 引用与消息均为零；
- 共享对象、物理页、映射和 backing 引用均为零，4096 页全部归还；
- 五个相关 AI 资源域都实际经过模型准入，grant/release 数量相等；
- 进程 heap、image、thread 资源全部回收。

### 冻结客体结果

`artifacts/cosmic-shared-r3/wayland-shm-final/summary.json` 的三次独立 ARM64 启动全部 **PASS**。冻结内核 SHA-256：
`294218fb9c8557e25b8478993b78eff51382873871f800a239184fc6f5dd40e5`；验证报告 SHA-256：
`3de228728a0f4a9e73f124f0e8c43519d9fcab4eb48809b92f9573d7339c6e85`。

每次启动都得到 17 个严格匹配的协议标记和 PID 2、3、1 的正常内核退出记录。父进程通过 `waitpid` 回收第一个客户端后，第二个客户端可以复用其进程槽，所以最终 `posix list` 保留 PID 1 和 3；第一个客户端的成功退出同时由内核串口记录和父进程的等待断言证明，不能要求被回收记录永久留在列表中。

每次最终 OFD、SCM 与共享对象均归零，4096 页全部可用。AI 实际批准并最终释放了 6 份消息额度、6 份在途描述符额度、12 份页额度、6 份共享对象额度和 10 份映射额度；五个域均无拒绝、容量失败或未释放额度。这些数字仅描述此固定探针负载，不代表 COSMIC 的容量需求。

早期失败证据保留：`cosmic-shared-r2/wayland-shm` 在首帧真实像素读取后，因为探针错误地要求一次 stdout write 写完整条长标记而退出；r1 探针正确处理短写和 EINTR。`cosmic-shared-r3/wayland-shm` 的所有协议操作已通过，但旧验证器误把已回收的 PID 2 记录消失判为失败；修正的是验证器的进程槽预期，最终测试使用同一未改动的冻结内核与 r1 探针。

本门禁只覆盖固定共享池与键盘映射的协议基础。完整 G-SHM、COSMIC 场景容量验收、EGL 显示、合成器启动与会话验收仍需独立报告。
