# COSMIC 原生显示提交容量与实际延迟

接续 [epoll 拓扑热点](v17-cosmic-epoll-topology-20261120.md)，本轮测量显示游标
额外限制单次矩形大小带来的重复提交，并使用完整 compositor 的原版/修复版
进行对照。内核仍只允许每次 16,384 像素，即 65,536 字节；未调整进程、共享
对象、页面、FD 或线程容量，也未放宽 45 秒启动和 15 秒交互门槛。

## 原始失败与快速回归

在上轮 epoll 修复镜像上，仅点击一次真实时钟打开日历：15.305 秒时区域仍无
文字，完整标题、网格及底部设置文字在 38.053 秒匹配。原始记录位于
`artifacts/v017-calendar-latency-baseline-v2`。真实 GUI 冷启动等待保留 180 秒，
不能把该端到端场景称作秒级循环。

缩小后的循环直接运行真实 `PendingPresentation` 游标，注入的只有 syscall
提交边界。相同合法矩形在原代码上被拆成四次提交；实际 1024×768 帧需要
192 次完成，而非该 ABI 容量下的 48 次。

```sh
CYXIA_PRESENTATION_BASELINE=1 python3 -m unittest discover \
  -s tests/host -p test_cosmic_tile_capacity.py -v
python3 -m unittest discover -s tests/host -p test_cosmic_tile_capacity.py -v
```

测试自身取得共享 native lease 并检查宿主互斥。原版 23 项通过、5 项失败；
修复后 28 项全部通过。测试执行约 0.02 秒，首次命令还包含 Rust 编译耗时。
覆盖每个实际输出像素、全局翻转、尾部不足一块、小容量、EAGAIN/EINTR 保留
原块、永久错误、黑屏覆盖、完成回调前置条件、锁屏隔离和输入状态保护。

原代码是固定 phase series 后的完整原生后端文件，SHA256 由原 manifest
和新 port policy 共同绑定。没有通过改坏代码或输入制造失败。宿主观察 feature
关闭，原始完成机制仍实际执行；完整目标构建保留原 feature。

## 单变量源码与完整构建

`ports/cosmic/native-presentation-v1` 保留完整原文件、GPL 通知和独立 patch。
唯一算法变化：将 `min(max_rect_bytes, 16384)` 改为经既有 validator 校验的
`max_rect_bytes`。单个 staging 分配最多增加 48 KiB，仍由原进程堆额度承担。
单次调用预算、像素转换、重试、失败、stall watchdog 和 fence 完成条件不变。

```sh
python3 tools/cosmic_native_tiles_v1.py build \
  --output artifacts/v017-native-tile-capacity-build-v1 \
  --sysroot artifacts/sysroot/x86_64-musl \
  --rust-root /Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin
```

构建在同一受控 source/target 环境中先编译原版，再应用这个单文件 patch。
原版约 375.003 秒，修复版复用完整依赖后约 77.313 秒；两份原始 ELF、完整
源码、metadata、命令与日志均保留。固定 v5 builder、12 项 SDK/native 输入、
468 包锁定离线解析图、两个 workspace 成员及 `backend-cyxia` 特性不变。
独立 source tree 对照确认仅 `src/backend/cyxia/native/presentation.rs` 不同。

构建仍使用原 2 jobs、3 GiB 输出预算、1 GiB 空间保留和 3600 秒期限；目标
仍通过原 FullOs ELF parser 的 64 MiB image、2 MiB stack 合同。

独立安装入口为 `tools/assemble_cosmic_native_tiles_v1.py`。它规范化宿主临时
目录，再重新导出 canonical 原版及 patch，复核完整 Git/registry 闭包、保留
源码、编译器、SDK、日志和原始 ELF。正常目录只替换 `cosmic-comp.elf`，其余
128 个输入逐字保留；原 SDK、源码缓存和历史构建报告未被改写。

## 原生 EGL 与实际像素

同一当前内核、相同客户端和另外 97 项输入，仅替换原版/修复版 compositor：

| 真实客体检查 | 原版 | 修复版 |
| --- | ---: | ---: |
| compositor 首次完整提交 | 32.909 s | 30.307 s |
| EGL 客户端阶段 | 12.063 s | 9.073 s |
| 协议、绘制、回读、swap、callback、扫描输出、清理 | 9 项 PASS | 9 项 PASS |
| 实际红/绿像素 | 各 2304 | 各 2304 |

两张实际输出图像的完整 SHA256 均为
`c25bb373490118f5ef30ef649959379ae15f1b153cd846a21c205b7dfc909b8e`。
实测客户端阶段改善约 25%，不能把提交次数减少四倍描述为总体加速四倍。

运行记录为 `v017-native-tiles-egl-before-runtime-v1` 和
`v017-native-tiles-egl-after-runtime-v1`。捕获所用的 before-v1 镜像与绑定当前
说明文档的 before-v2 镜像，其 kernel 和 boot 字节完全相同；原说明文本有
单独归档。before-v2 与 after-v1 的当前源码一致，嵌入输入只差 compositor。
完整验证及可再生缓存清理记录为 debug 目录的 `native-image-validation-v2.json`。

## 正常会话验证范围

两张正常会话镜像使用相同当前源码、4 CPU、1 GiB 和原时钟 profile。原有
`tools/os_cosmic_time_probe.py` 保持不变，分别检查 45 秒扫描输出、真实总线、
180 秒后时钟、两轮实际鼠标开关、进程存活及共享资源回收。功能匹配与原
15 秒交互限制分别记录，完整桌面与语义首帧仍须单独验收。

| 相同驱动的真实操作 | 原版 | 修复版 | 修复版原 15 秒目标 |
| --- | ---: | ---: | --- |
| 打开日历 | 45.241 s | 25.666 s | FAIL |
| 关闭日历 | 14.029 s | 14.657 s | PASS |
| 再次打开 | 42.995 s | 22.171 s | FAIL |
| 再次关闭 | 12.956 s | 10.264 s | PASS |

这是一次完整前后对照，不是延迟分布。两次打开明显缩短，一次关闭略慢，不能
宣称每项交互都加速或总体快四倍。两版两轮均完成完整月份网格与页脚匹配，
输入后五个核心进程 PID 2–6 及原时钟 PID 8 存活，无异常退出。每次关闭均
恢复到本轮输入前的 12 个对象、113 页、20 个映射及完整共享引用基线。

原版 45 秒仍有 65,594 个启动色条像素；修复版为 58，必要扫描输出替换检查
转为 PASS。但修复版该时刻的实际截图只有背景和指针，时钟区域文字候选为
零，不能据此宣称语义桌面就绪。180 秒后的时钟与完整日历另有实际图像和
人工复核，完整 OS / COSMIC session / semantic frame 标志保持 false。

两轮交互区间内，修复版仍记录约 31.113 秒地址空间构建、8.155 秒回收的
累积 HPET wall 耗时。这不是 CPU 计费；它为后续地址空间与事件循环诊断提供
了实测线索。本轮仅解决过小提交导致的重复工作，打开日历的 15 秒目标仍未通过。

正常镜像分别为 `v017-os-native-tiles-normal-before-v1` 和
`v017-os-native-tiles-normal-after-v1`，会话记录分别为
`v017-native-tiles-normal-before-runtime-v1` 和
`v017-native-tiles-normal-after-runtime-v1`。

聚合证据 `artifacts/v017-cosmic-native-tile-capacity-evidence-v1.json`，SHA256：
`a5f55e7605100dd469eefd8d51d17084465e335abdbaffae0705642adeeb0005`。
它绑定完整构建、原失败和修复回归、独立 consumer、全部实测镜像与串口、
原生像素及日历截图。当前源码/工具链/目录/ELF 重新验证通过，诊断原型与
来源归档均位于 `artifacts/debug/cosmic-native-presentation-20261120`；没有新增
客体调试日志，也没有改写旧证据。
