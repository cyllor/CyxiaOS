# COSMIC 内核映射性能：连续范围与真实桌面对照

本轮使用 ECC `benchmark-optimization-loop`，针对上轮真实日历交互中约
31.113 秒地址空间构建、8.155 秒回收的累积 HPET wall 耗时分析。它们不是
CPU 计费。搜索上限为两个内核变体、3600 秒、零外部费用，所有记录保存在
`artifacts/debug/cosmic-kernel-perf-ecc-20261120/search-ledger.json`。

## 变化及正确性边界

原有 staging 发布对每页重新认证 alias batch 的 CPU 所有权。第一个变体
仅为同一叶表内、连续虚拟和物理地址、同权限的固定范围增加入口，最多
512 页。持有既有 alias lease 的固定 CPU 调用者认证一次，范围内仍逐页检查
物理边界、代码权限阶段和三个 20 位引用计数，失败时只发布成功前缀。

实验变体 V2 曾在 `PageTable` 中缓存连续范围描述。`set`、`remove`、`clear`
全部使缓存失效；缓存不包含运行时代码阶段、alias 引用数、实际页表或 TLB
状态。staging 元数据由 CPU0 在旧根退休后独占，`Cell` 不赋予并发发布权限。
结构仍为 8192 字节、4096 字节对齐，利用已有尾部 padding，没有增加页面池。
该版本宿主微基准更快，但真实桌面打开更慢；最终保留 V1 连续范围入口，撤回
描述缓存。实际交互结果优先于单一微基准。

任意调用者迭代器、跨叶表、物理碎片或权限混合仍使用原 `map_pages` 路径。
代码预发布/封存先完成，再取得 alias gate；原始迭代器的 panic 和部分成功
语义保持。实际 PTE、epoch、alias 前缀和回收均与标量路径对照。回收算法、
TLB/IPI、100 ms ACK 期限及用户资源上限没有改动。

宿主测试还修正了平台选择：Apple ARM 宿主明确选中实际 x86 staging 与 runtime
分支。CPU 身份、物理地址背衬、PTE/TLB 硬件效果仍是显式 fixture；实际使用的
`space.rs`、runtime alias 核心、`PageTable`、`ProcessSpace` 和权限 wrapper
从当前源码提取并记录哈希，不能把这些宿主测试称为客体 MMU 验证。

新增范围检查覆盖 RO/RW/RX 全页翻译和回收、冲突、资源耗尽、阶段转换、sealed
页面、引用数溢出、地址错误、错误 CPU/owner、活动根拒绝、跨叶 fallback、
缓存后的物理/权限覆盖、移除与清空，并验证运行时阶段变化不会被缓存绕过。

## 同输入形状的微基准

运行入口为 `tools/benchmark_cosmic_mappings.py`，取得共享 native lease 并先确认
宿主没有其他原生构建或 QEMU。每种形状先预热一次，计时 9 组、每组 8 次；
表分配和逐页结果核验位于计时区间之外。每组取 8 次平均，报告 9 组平均值的
中位数；计时二进制不增加观察计数器。单独
编译的非计时观察版本验证所有权检查数量。此处报告中位数，完整样本摘要与
9 组的最大值（组平均值的 nearest-rank p95，并非单次调用尾延迟）保留在各
目录的 `result.json`。

| 路径 / 映射中位数 | 原路径第一次 / 复测 | 范围 V1 第一次 / 复测 | 缓存 V2 第一次 / 复测 |
| --- | ---: | ---: | ---: |
| 8 页 RW | 244 / 239 ns | 208 / 213 ns | 213 / 229 ns |
| 8818 页 COSMIC RX | 68468 / 68708 ns | 56963 / 55010 ns | 47114 / 46849 ns |
| 16384 页连续 RW | 106629 / 113020 ns | 88468 / 84401 ns | 72843 / 69624 ns |
| 4096 页物理碎片 RW | 26474 / 29916 ns | 29974 / 28521 ns | 29182 / 28437 ns |

最终 V1 的 COSMIC RX 映射改善约 17%–20%，密集 RW 约 17%–25%。两次 V2 的
COSMIC RX 映射均改善约 31%，密集 RW 约 32%–38%。碎片化路径
没有稳定提升，回收未改，也没有稳定提升。不能把这组宿主算法耗时直接换算成
客体总延迟或总体倍数。

连续 RW 的实际所有权读取次数由 16448 降至 96（32 个 staging 表各 3 次）；
8818 页 RX 由逐页认证降至 54。该计数来自真实 CPU slot 调用点的宿主观察版本。
在原实现上要求这个工作量上限，会实际失败，日志为 `work-budget-before.log`；
两种新实现均通过。观察计数不参与上表计时。

原版源文件位于 debug 目录的 `baseline-source`，V1 和 V2 也分别保留了副本。
基线和候选用同一当前宿主 wrapper 生成方式运行，未改坏旧源码制造失败。

```sh
export PATH=/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH
python3 tools/benchmark_cosmic_mappings.py \
  --source-root artifacts/debug/cosmic-kernel-perf-ecc-20261120/baseline-source \
  --output artifacts/ecc-mapping-baseline-replay
python3 tools/benchmark_cosmic_mappings.py --require-coalesced \
  --output artifacts/ecc-mapping-candidate-replay
CYXIA_NATIVE_LOCK="$PWD/artifacts/v016-focus-a03-a10-20261109-r9/native-session.lock" \
  python3 -m unittest discover -s tests/host -p test_page_map_batch.py -v
```

每次输出目录必须是新目录，原始记录不会覆盖。保存的基线 fixture 是本地证据，
在全新 checkout 可从修复前版本取得这三个生产文件，置于相同的相对目录后通过
`--source-root` 复测。

## 实际内核与桌面验证

桌面 A/B 只改变 `space.rs`、x86 runtime 和 `address_space.rs` 三个内核文件。
129 项嵌入输入逐字相同，包含同一完整 compositor、panel 和时钟。保持 4 CPU、
1 GiB、既有 heap/image/stack/FD/线程/共享对象额度，以及原 45 秒启动扫描输出
检查和 15 秒交互期限。

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-time-applet-v1 \
  --sysroot artifacts/v017-native-tiles-normal-catalog-v1 \
  --output artifacts/v017-os-ecc-mapping-run-v1
python3 tools/os_smoke.py --build artifacts/v017-os-ecc-mapping-run-v1 \
  --output artifacts/v017-ecc-mapping-run-v1-native --scenario native
python3 tools/os_cosmic_time_probe.py \
  --build artifacts/v017-os-ecc-mapping-run-v1 \
  --output artifacts/v017-ecc-kernel-run-v1-runtime-v1 \
  --observe-seconds 180 --inspect-bus
```

同一候选镜像已通过 `OS_NATIVE_PASS`：真实 unmapped、只读、NX、kernel、guard
访问均产生预期硬件 fault，寄存器、FP/TLS、堆、IPC 及持久化读写完成，四个
CPU 由 QMP 确认。持续任务在出现真实抢占后被显式回收；最终宿主集成测试的
实际 Rust 用例共 40 项全部通过。

旧烟测先在基线与候选上同样失败：300 万次寄存器循环可以在既有 8 ms
时间片内完成，结束时 `preemptions=0`，旧驱动却在结束后等待非零值。现在保留
寄存器检查，另用无系统调用的持续任务等待自身非零计数，5 秒期限、PID 归属
与 finally 回收均检查。四项新增驱动回归及既有驱动测试合计 13 项通过：

```sh
TMPDIR=/private/tmp python3 -m unittest discover -s tools -p 'test_os_smoke*.py' -v
```

完整 `--scenario ported` 的原始失败另行保留：旧 `wayland-probe.elf` 要求
SCM_RIGHTS 必须返回 ENOSYS，与现有已实现的支持不符。在恢复原三个生产文件后，
原镜像与新驱动复现完全相同断言；独立诊断脚本 finally 逐字恢复候选源码。
另一次可选 Rust std 检查返回 Noent，129 项正常目录本就没有该 probe ELF。
这两项未被计作通过，A/B 输入目录与旧探针断言保留。

## 实际桌面结果与最终选择

每列依次为初次捕获 / 独立复测；每次均执行完整的两轮实际鼠标开关。

| 实际操作 | 原版两次测量 | 最终 V1 两次测量 | 缓存 V2 两次测量 |
| --- | ---: | ---: | ---: |
| 打开日历 | 25.666 / 25.069 s | 17.665 / 18.875 s | 22.241 / 23.198 s |
| 关闭日历 | 14.657 / 16.063 s | 13.795 / 13.859 s | 12.907 / 13.637 s |
| 再次打开 | 22.171 / 21.532 s | 17.645 / 18.322 s | 19.014 / 20.159 s |
| 再次关闭 | 10.264 / 11.218 s | 14.951 / 8.292 s | 12.910 / 13.507 s |

最终选择 V1。首次打开均值改善约 28%，再次打开约 18%；V2 虽在宿主映射微基准
中更快，两次实际桌面捕获的打开均慢于 V1，因此撤回描述缓存。关闭波动较大，
尤其 V1 的第二次关闭为 14.951 / 8.292 秒，不能宣称每项交互均稳定加速。
每种实现仅两次完整捕获，这是本轮实测选择，不是延迟分布或全局最优结论。

| 两轮交互区间内累计 HPET wall | 原版初测 / 复测 | 最终 V1 初测 / 复测 |
| --- | ---: | ---: |
| 地址空间构建次数 | 20618 / 20620 | 21554 / 19988 |
| 构建耗时 | 31.108 / 31.751 s | 21.277 / 19.723 s |
| 回收耗时 | 8.153 / 7.978 s | 8.283 / 7.760 s |

构建平均减少约 35%，回收没有稳定改善。读数窗口统一为输入前与输入后的
`posix list`，覆盖 bus、五个核心进程及实际时钟；不包括随后用于收尾的额外
状态查询，也不是 CPU 计费。两轮仍构建约两万次根页表，重复构建尚未消除。

六次捕获均完成两轮日历，输入后核心进程及原时钟存活，没有异常退出。每次
关闭都恢复到输入前的 12 个共享对象、113 页、20 个映射与完整引用/授予基线。
V1 初测时钟为 PID 7，复测为 PID 8，区别来自它与 45 秒总线查询的创建顺序。
审计以唯一 panel 子进程及原进程存活关联身份，不能把固定 PID 8 当成业务条件。

实际截图确认完整 2026 年 11 月网格、20 日高亮及设置入口。45 秒必要色条
替换检查通过，但截图仍只有背景与指针，时钟文字候选为零。两个打开均超过
原 15 秒期限；完整 OS、COSMIC session 与语义首帧标志保持 false。

最终镜像为 `artifacts/v017-os-ecc-mapping-run-v1`，实际捕获为
`artifacts/v017-ecc-kernel-run-v1-runtime-v1` 和 `-v2`。基线及未选中 V2 的
全部源码、二进制、截图、命令与失败记录继续保留。两版都使用相同 129 项
输入，只相差 `address_space.rs` 的描述缓存；时间驱动 CLI 没有修改，其实际
Console/connect 代码也经 AST 对照确认不变。

聚合证据为 `artifacts/v017-ecc-kernel-mapping-evidence-v1.json`，SHA256：
`580a3e76518bac38943b8a6e5e790fa9edfbf3681ccb982f17725120e6ec09a4`。
最终源码、编译器、输入目录、ELF、boot、串口和实际图像均已重新绑定核验。
原生验证记录为 debug 目录的 `native-validation-run-v1.json`；各 host 与
实际桌面数据及选择理由在 `search-ledger.json` 中。

后续热点是稳定映射的根页表重复构建，以及事件循环/调度对交互延迟的影响。
复用根必须同时验证映射变化失效、AP 退出、W^X、alias 与帧所有权回收；本轮
通过减少固定范围重复工作改善成本，尚未完成持久根复用或 15 秒交互验收。

回滚仅需恢复 debug `baseline-source` 中的三个生产文件；旧镜像、源码和原始
失败证据均保留。磁盘回收仅涉及可再生编译缓存和逐项验证 SHA256 不变的 APFS
透明压缩，没有删除原始镜像、上游源码或完整 compositor 依赖缓存。
