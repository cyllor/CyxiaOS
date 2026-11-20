# COSMIC 启动关键路径复核

当前 2 GiB、4 vCPU 镜像有两个启动瓶颈。合成器主线程的同步着色器初始化阻塞会话就绪。背景出来后，面板首帧又用了约 67–71 秒。时钟在面板出现后的下一张截图中可见。

| 原镜像正常启动 | 背景首帧 | 空面板首帧 | 时钟首帧 |
| --- | ---: | ---: | ---: |
| 周期性读取进程状态 | 34.421 s | 105.156 s | 107.191 s |
| 启动期间只截取画面 | 32.376 s | 99.092 s | 101.111 s |

时间从发送 `posix exec cosmic-session` 开始。图像来自实际 VirtIO scanout，采样间隔约两秒。空面板的整条顶栏已出现，时钟区域还没有字形。详细原始数据和图像路径记录在 [首次归因报告](v17-cosmic-startup-attribution-20261120.md)。

合成器先同步运行 `init_shaders()`，随后才发布 `WAYLAND_DISPLAY`。同一 ELF 直接启动时，着色器阶段耗时 16.807 秒。其中第 10–20 秒完整落在该阶段内，发生了 2,191 次系统调用与同数量的地址空间重建。内核累计准备和撤销开销为 4.367 秒。锁定的 Smithay 会为七个效果生成普通、调试及纹理格式变体，共调用 30 次 `glLinkProgram`。这些调用的分项耗时仍缺单独计时。 [合成器布局与就绪发布](../../artifacts/v017-native-pointer-motion-build-v1/source/src/backend/cyxia/mod.rs) · [着色器初始化](../../artifacts/v017-native-pointer-motion-build-v1/source/src/backend/render/mod.rs)

使用同一用户程序的诊断镜像，前 20 秒两轮分别观察到 3,800 / 4,242 和 3,461 / 3,907 次 `mmap`、`munmap`，占合成器调用次数的 89.6% 和 88.6%。两轮中主线程均发出约 96% 的调用。第二轮到第 20 秒累计准备和撤销页表约 6.066 秒。CPU0 每次重新派发均准备新的用户页表，AP 返回后在继续执行服务前撤销该页表。映射开销由内核 HPET 计时。 [页表准备入口](../../kernel/src/desktop/user.rs#L1886) · [并行调度与撤销](../../kernel/src/desktop/user/parallel.rs#L337)

正常采样轮第 60 秒，时钟主线程已在 `wayland_client::conn::blocking_read` 中通过 `ppoll` 等待。面板给它的 `WAYLAND_SOCKET` 指向面板内嵌 Wayland 服务。面板在处理该服务的事件循环上，也要同步完成首次 configure 的 EGL/GLES 初始化。两轮约 99–105 秒才看到面板，已定位到面板首帧链路，EGL 初始化、Wayland 消息分发及绘制呈现的分项耗时仍需独立计时。 [面板传递 Wayland socket](../../artifacts/v017-panel-allocation-build-v5/source/cosmic-panel-bin/src/space/wrapper_space.rs#L604) · [面板首次 EGL 初始化](../../artifacts/v017-panel-allocation-build-v5/source/cosmic-panel-bin/src/space/panel_space.rs#L1378)

同一诊断镜像第 60–90 秒的统计中，合成器主线程发出 3,066 次系统调用，其中 1,780 次读取单调时钟，另有 208 次输入轮询。面板发出 3,245 次调用，其中 1,477 次 `mmap`、`munmap`，1,163 次 `clock_gettime`。这 30 秒内，合成器和面板分别累计新增 8.196 秒、5.853 秒页表处理。时钟只推进了 27 次系统调用，通知进程的计数未增长。这个窗口的调用计数和页表开销来自同一次启动。

面板的 applet worker 先尝试连接通知服务，再取出 applet 启动请求。代码配置了 5 秒超时，该等待在基线轮出现连接失败。无状态采样轮未出现同一条错误，空面板仍到第 99 秒才出现。正常采样第 60–90 秒期间，通知进程调用计数保持不变。 [面板 applet worker](../../artifacts/v017-panel-allocation-build-v5/source/cosmic-panel-bin/src/main.rs#L200)

诊断内核通过隔离的源码副本增设了调用计数。两轮通过串口集中读取时分别在第 60 秒和时钟出现后提前退出。完整的第 20 和 45 秒计数已保留。使用同一诊断镜像，通过 QMP 暂停、读取计数区并恢复运行，绕过了集中串口输出。原始启动时间使用原镜像两轮的截图。 [诊断复算和数据](../../artifacts/debug/cosmic-startup-detail-20261120/attribution.json)
