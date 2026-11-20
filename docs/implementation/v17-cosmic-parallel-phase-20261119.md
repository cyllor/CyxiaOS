# COSMIC 并行批次与当前启动阻塞，2026-11-19

本轮修复了会话 profile 中一个进程的快速系统调用反复中止其他 CPU 工作的问题。
**完整 COSMIC 会话仍未通过**：当前 SDK 目录缺少真实 notifications ELF；两次
release 启动都在 compositor 握手、settings 启动之后因 ENOENT 失败。

工作基于已有大量未提交的会话容量、内存与本地 SDK 改动。本轮没有提交或推送
这些改动，也没有把历史失败重新归类为成功。

## 最小复现与假设

固定 `artifacts/v017-os-session-build46` 的启动图像 SHA 为
`6b2003f6edcfbd2aad87b536eeaa7fbdd7db490d23e5902c8a5c4ab9fa3ca5ff`。
正常 session、直接 compositor 加总线、仅 compositor 三个场景，在 45 秒画面检查
中分别保留 786,432、786,432、733,242 个启动色条像素，均失败。

独立的真实 zbus 探针已在同一客体中完成多线程与单线程 Tokio 的 session 总线
握手，分别获得 `:1.0`、`:1.1`，退出码 0。该结果没有证明完整设置或通知协议。

依次检验的假设是 UART 诊断开销、其他进程引发的提前中止、Mesa 优化器不收敛、
显示提交未完成。去除每个调度周期的 `COMP_OBS` 输出后，45 秒仍为全屏色条，
因此没有将诊断清理当作首帧修复。现有数据也没有证明 Mesa 优化循环不收敛。

## 已修复的实际机制

`Supervisor::dispatch_parallel` 原先收集到第一个返回后，就 drain/stop 其他工作。
这能保持 CPU0 服务期间没有活动用户根，但会让高频时钟/等待调用的父进程反复
打断仍有时间片的计算子进程，随后再次承担完整地址空间构建与退役成本。

现在仅 `cosmic-session` profile 等待各 AP 按其已设置的绝对时间片期限正常返回，
收集全部真实 completion 后才继续。其他 profile 保持 stop-on-first 和原 peer drain。
一秒 completion 失败边界、根退役、所有权归还、CPU0 系统调用顺序不变；未改动
原有时间片数值、AI 模型、池容量、AP 数量或 45 秒诊断窗口。既有本地源码中的
会话时间片倍率并非本轮新增。

宿主测试提取并执行实际 production completion 循环，使用两个同时活跃的工作：
立即返回的轮询父进程与需要 8 ms 的计算子进程。修复前明确失败：
`fast peer cancelled the CPU-bound child before its granted deadline`。
修复后 session 和 legacy 两种编译配置共八个 Rust 场景通过，覆盖三工作乱序返回、
单工作、空批次、重复收集防护及缺失 completion 的保留失败。硬件、计时器和
mailbox 为明确的宿主 fixture，这些测试不证明实际 AP 中断/TLB 行为。

```sh
python3 -m unittest discover -s tests/host -p test_cosmic_parallel_phase.py -v
```

## 实际客体对照

所有新镜像都使用相同的 18 个组件/探针 ELF 和相同 rootfs 字节；compositor SHA
始终为 `0cf59c9624886bdf5f692728f1ea1b3ba132ffdd51827af31916f5e4123a43cd`。
本轮没有安装旁边已构建的 compositor v5，也没有用 NIR 迭代上限将捕获改为成功。
以下进程快照采集于各自 45 秒画面检查之后，属于有界窗口计数，不是 CPU 时间。

| dev 内核正常会话 | compositor 系统调用 | 抢占 | 地址空间重建 | 准备 / 退役累计 |
| --- | ---: | ---: | ---: | --- |
| 去除 UART 热路径输出 | 1,303 | 3,817 | 5,121 | 17.878 s / 4.087 s |
| 再修复并行批次 | 5,084 | 1 | 5,085 | 16.726 s / 4.714 s |

第二组相对第一组只有 `kernel/src/desktop/user/parallel.rs` 的源码身份改变；编译器、
组件字节、features、RAM、CPU 和构建 profile 一致。实际抢占减少验证了提前中止
问题的修复，但两组 45 秒画面均仍是 786,432 个色条像素，不能称为首帧通过。

保留的开发镜像与捕获：

- `artifacts/v017-os-cosmic-diag-baseline-20261119`：当前源码基线，dev；
  `artifacts/v017-session-repro-20261119-red2` 再次 FAIL。
- `artifacts/v017-os-cosmic-diag-fix-20261119`：仅去除高频输出；
  `artifacts/v017-session-repro-20261119-logfix` FAIL。
- `artifacts/v017-os-cosmic-phase-fix-20261119`：并行批次修复；
  `artifacts/v017-session-repro-20261119-phasefix` FAIL。

## release 构建揭示的下一项失败

用同一源码和同一目录执行工具原本支持的 `--profile release`，不是继续扩大窗口。
这属于构建 profile 的独立对照，不把差异归因于某一条优化或宣称 dev 问题已经消失。

```sh
PATH=/Users/robin/.cargo/bin:$PATH python3 tools/os_x86.py build \
  --profile release --graphics --ported --feature cosmic-session \
  --output artifacts/v017-os-cosmic-phase-release-20261119

python3 tools/os_cosmic_startup_probe.py \
  --build artifacts/v017-os-cosmic-phase-release-20261119 \
  --output artifacts/<新的捕获目录>
```

release 启动图像 SHA：
`57541e562c87912f6c114302086118bd638312c8793ada2fcb2322c3c7396333`。
实际清单 SHA：
`308217262e5015c5c35922063938d5eada37719b575303d5e773ef1e619a6577`。

两次正常启动均获得真实 `WAYLAND_DISPLAY=wayland-1` 握手，随后启动 settings
进程，再在 notifications 启动时收到 ENOENT 并 panic。第一次日志中的开始与握手
墙钟相差约 25 秒；不是精确首帧测量。清单与当前 SDK 都没有
`cosmic-notifications.elf`，而 kernel catalog 的可选名称表包含该程序。因此存在
真实供给缺口，不能用空进程、改名或跳过通知来完成会话验收。

捕获 `artifacts/v017-session-repro-20261119-release-repeat` 保留 FAIL、错误时实际
scanout、完整 UART 和原 producer。错误时仍是启动色条。QMP quit 后 QEMU 退出码
0，只证明 VM 正常关闭，未证明客体服务或资源回收。

同一 release 镜像的独立 compositor 加总线场景，在
`artifacts/v017-session-repro-20261119-release-direct` 通过必要的画面替换诊断：
45.002 秒冻结 scanout，786,432 个像素中仅 58 个与原色条对应位置相同，PPM SHA
为 `2e129e506c3100b2f6d9683165166cc279f3163685c5fca6e74e93895d6099f4`。
该捕获明确记录 `normal_session=false`、语义帧与完整会话验证均为 false。
这不解除上面正常会话的 notifications 阻塞，也不证明面板或输入可用。

## 可重复检查与边界

`tools/os_cosmic_startup_probe.py` 使用共享 native lease、独立磁盘、manifest-bound
启动图像、固定 45 秒窗口和实际 QMP PPM。它明确保留失败，记录必要的色条替换
诊断，不把光标、64 行局部更新、panic 后画面或 late observation 判为完整会话。
该检查针对当前深色 compositor 场景，像素差异不是语义桌面证明。

```sh
python3 -m unittest discover -s tests/host -p test_cosmic_startup_probe.py -v
PYTHONPATH=tools python3 -m unittest test_os_x86 test_os_smoke -q
```

三个 scanout fixture 检查及十个既有 OS producer/smoke 宿主检查通过。
完整会话、settings 就绪、通知协议、面板/applets、输入、重启与全局资源回收仍需
逐项验证；所有本轮 capture 的 `full_os_verified` 和 `cosmic_session_verified`
保持 false。下一项可执行工作是为本地 SDK 建立真实 notifications 的版本化构建、
安装来源与许可记录，再从同一正常 session 链继续。

本轮改动的提交摘要应说明实际原因：
`fix(cosmic): preserve granted worker quanta when a polling peer returns`。
