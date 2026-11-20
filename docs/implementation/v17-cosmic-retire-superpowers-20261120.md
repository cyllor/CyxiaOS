# COSMIC 地址空间回收：Superpowers 诊断与实测

接续连续范围映射优化，本轮使用 Superpowers 的 systematic-debugging、
test-driven-development 与 verification-before-completion 工作流，检查
x86 地址空间回收中的重复所有权认证。既有映射优化、129 项桌面输入、
4 CPU / 1 GiB、W^X、TLB/IPI、资源上限及 45 秒 / 15 秒期限保持不变。

## 诊断与最小改动

改动前先保存当前源码并重新测量：16,384 页连续映射的回收实际读取 CPU
所有权 16,386 次，8818 页 RX 为 8820 次。回收已持有同一 alias lease，
遍历函数没有任意调用者迭代器或服务回调，当前 CPU 在固定范围内保持不变。

唯一生产改动位于 `crates/arch-x86_64/src/space.rs` 的析构遍历：每个叶表
跳过前导空位后，只将首段物理连续、P/W/NX 权限相同的 present 页交给现有
`MappingBatch::change_run`。最多 512 页，不跨叶表；后面的空洞、碎片和权限
混合继续走原标量路径，避免给碎片页逐项增加前瞻扫描。

该入口已有 CPU/owner 认证和逐页物理覆盖、20 位引用计数检查。移除继续允许
Transition 阶段，不缓存权限或引用数。A/D/PAT 位不被误当成权限变化；遇到后续
非法帧只结束预扫描，先回收合法前缀，再在原边界失败。引用计数失败仍致命，
不能报告完成或释放不确定的 backing。没有复用根、跳过 alias 退还或新建 FFI。

## 先红后绿及边界回归

先增加回收工作量上限及六项行为回归，原内核的正确性仍通过；独立观察版本的
性能上限实际失败：8 页回收读取 10 次，而允许上限为 6。失败是实际调用次数
断言，不是编译错误或修改旧源码制造的错误。

最小改动后，46 项实际 Rust 映射/回收用例通过。新增用例覆盖跨叶表的
1025 页与混合 RO/RW/RX、Transition、空洞、物理碎片、重复 alias、硬件
A/D/PAT 位，以及 0/1/255/511/512/519 位置的引用下溢、后续非法帧和权限损坏。
失败前后的计数使用独立的字面期望，确认合法前缀和后续 alias 的状态。

宿主夹具明确替代 CPU 身份、物理背衬与 TLB 硬件边界，实际析构函数、alias
核心和权限事务从当前源码提取；不把宿主测试称为客体 MMU 验证。观察计数器
只在单独二进制中启用，并变动 A/D 位；普通计时二进制没有该计数器。

| 回收形状 | 原版所有权读取 | 改动后读取 |
| --- | ---: | ---: |
| 8 页 RW | 10 | 3 |
| 8818 页 RX | 8820 | 20 |
| 16384 页连续 RW | 16386 | 34 |
| 4096 页物理碎片 RW | 4098 | 4098 |

宿主算法计时没有证明提速：8818 页 RX 的中位数由约 12.0 µs 变为
13.25 / 13.19 µs，连续 RW 由约 21.95 µs 变为 24.14 / 23.54 µs。
因此不能用读取次数代替速度结论，是否保留改动以相同真实客体的回收耗时及
桌面实测为依据。每种形状预热一次、9 组各 8 次，记录组平均值的中位数及
nearest-rank p95；这些不是单次调用尾延迟分布。

```sh
export PATH=/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH
python3 tools/benchmark_cosmic_mappings.py --require-coalesced \
  --require-coalesced-retire --output artifacts/retire-candidate-replay
python3 tools/benchmark_cosmic_mappings.py \
  --source-root artifacts/debug/cosmic-retire-superpowers-20261120/baseline-source \
  --require-coalesced-retire --output artifacts/retire-red-replay
```

第二条在原版上应因回收工作量断言失败。输出目录必须全新。

## 项目检查的实际范围

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --offline --workspace --exclude cyxia-kernel` | 1559 项通过 |
| 实际 runtime 映射/回收集成 | 46 项通过 |
| 实际 x86 原生烟测 | `OS_NATIVE_PASS` |
| 全量宿主 Python | 999 项；29 failures、17 errors、3 skipped |
| 全量工具 Python | 2008 项；115 errors、33 skipped |
| `cargo fmt --all -- --check` | 未通过，37 个文件有格式差异 |

原生烟测使用本轮镜像，实际检查 unmapped、readonly、NX、kernel、guard
硬件 fault，以及寄存器、真实抢占、FP/TLS、堆、IPC 和持久化；不是修改测试
结果或只检查日志存在。项目全量检查确实执行，**没有宣称全仓 CI 通过**。

已核对的宿主失败包括旧抽取夹具缺少 prewarm 符号、ARM/macOS 执行特权指令
退出 SIGILL。工具错误分别为 59 项 Linux 生成器边界、53 项原子 no-replace
目录发布不支持，以及 3 项旧 V0.16 路径缺失。每个未通过项的名字和格式文件
见[完整检查缺口清单](v17-cosmic-retire-regression-gaps-20261120.md)，完整堆栈
及退出码保存在 debug 目录。未为变绿删除旧断言或改写历史来源。

全量测试临时生成了多份 Cargo 缓存，超过初始空间估计。测试后仅回收本轮
创建的 42 个可重建目录，保留源码、离线依赖、SDK、发布镜像和全部日志；
回收记录为 `artifacts/debug/cosmic-retire-superpowers-20261120/test-cache-cleanup.json`。

## 真实桌面对照

本轮镜像为 `artifacts/v017-os-superpowers-retire-prefix-v1`，基线为保留的
`artifacts/v017-os-ecc-mapping-run-v1`。两者的编译源码仅 `space.rs` 不同，
其余源码与全部 129 项嵌入输入一致。驱动仍为原始时间探针，观察 180 秒后
用真实输入设备完成两轮日历开关，并检查原进程存活和本轮共享资源基线。

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-time-applet-v1 \
  --sysroot artifacts/v017-native-tiles-normal-catalog-v1 \
  --output artifacts/retire-kernel-replay
python3 tools/os_cosmic_time_probe.py --build artifacts/retire-kernel-replay \
  --output artifacts/retire-desktop-replay --observe-seconds 180 --inspect-bus
```

每格依次为初测 / 独立复测；单位为秒。

| 原始时间驱动的实际操作 | 改动前 | 改动后 |
| --- | ---: | ---: |
| 打开日历 | 21.900 / 21.388 | 14.907 / 20.814 |
| 关闭日历 | 10.920 / 13.183 | 14.332 / 12.096 |
| 再次打开 | 17.499 / 18.072 | 18.183 / 17.498 |
| 再次关闭 | 18.634 / 19.225 | 12.119 / 12.646 |
| 上述四次捕获耗时之和 | 68.953 / 71.868 | 59.541 / 63.054 |

四次捕获区间的总和分别改善约 14% 和 12%，均值约 13%。这个和不包含区间间
的资源查询、鼠标按下保持和冷启动观察，不能当成完整启动到结束的耗时。
再次关闭的改善在两次测量中较一致；首次打开波动很大，再次打开没有稳定
提升，不能只采用 14.907 秒的最快结果宣称所有操作达标或每项都更快。

| 交互区间内客体读数 | 改动前初测 / 复测 | 改动后初测 / 复测 |
| --- | ---: | ---: |
| 地址空间构建次数 | 23610 / 23491 | 21100 / 21878 |
| 累计回收 HPET wall | 8.840 / 8.848 s | 5.483 / 5.743 s |
| 按构建次数归一化的回收指标 | 374.4 / 376.7 µs | 259.8 / 262.5 µs |
| 累计构建 HPET wall | 22.504 / 22.806 s | 20.099 / 20.779 s |

归一化回收指标分别降低 30.6% 和 30.3%，因此保留该最小改动。累计值的变化
还受到构建次数影响；这是七个存活进程在输入前后两个 `posix list` 之间的
HPET wall 差值，不是 CPU 计费，也不是单次 syscall 延迟分布。

四次会话均完成两轮真实输入与完整月份/页脚匹配，输入后的五个核心进程和
原时钟存活、没有异常退出。每次关闭均恢复到本轮输入前的 12 个共享对象、
105 页、20 个映射与完整引用/授予基线，16 个元数据槽及 4096 页容量不变。
本轮实际读数为 105 页，此前捕获曾为 113 页；审计按每次输入前的实际基线
核对，没有扩大容量或用固定旧页数覆盖本轮读数。

实际截图已检查完整 2026 年 11 月、20 日高亮与设置入口。45 秒必要色条替换
仍通过，但该时刻只有背景和指针，没有时钟文字；语义首帧、完整 OS 和
COSMIC session 继续标记 false。两次捕获的 `all_interactions_within_15_seconds`
均为 false，15 秒整体交互目标仍未通过。

运行目录为 `artifacts/v017-superpowers-retire-{baseline,prefix}-runtime-v{1,2}`。
聚合证据 `artifacts/v017-cosmic-retire-superpowers-evidence-v1.json`，SHA256：
`d9ca1daa39747c53d3ea823fb67483266950ca2d691044ced586fc4cff4f935f`。
它重新验证当前源码/工具链/129 项输入、发布 ELF/boot、原生结果、四组扫描
输出与串口，保留 TDD 红灯和所有全仓检查未通过项；`global_ci_passed=false`。
诊断、命令与源文件归档位于 `artifacts/debug/cosmic-retire-superpowers-20261120`。

回滚只需恢复该目录 `baseline-source/crates/arch-x86_64/src/space.rs`。后续
仍应优先测稳定映射的重复构建、事件循环与调度；本轮没有实现持久根复用，
也没有对全量检查暴露的旧夹具与平台移植缺口做无关修改。
