# 控制面隔离软件管理核心与桌面补丁

基线：`desktop/native-wayland-pipeline-20261023@e7a40fccb653a30c4b92f4f644962d0a0dc31e7c`。
本增量新增可编译的内核管理模块、接入补丁和回归用例；不是完整 COSMIC 或物理多核隔离完成声明。

## 已实现的代码

`cyxia_kernel_core::control_plane::Manager<C,D>` 是序列化 EL1 管理入口，组合以下模块。

- `cores`：调用方提供 AI 目标核心集合；检查容量、业务合同、受保护核心和冷却期限。逻辑核心以物理核心/SMT 组整组划分。迁移核心立即停止进入双方派发集合；只有任务、IRQ、RCU、IPI、工作器、引用、定时器、DMA 的排空证明，以及停止、映射、屏障证明齐备，才能发布归属。故障和超时保留旧 owner、隔离核心，恢复重新检查当前合同。代际耗尽遇故障进入所有核心禁止派发的终止态，不回绕。
- `policy`：统一的有界策略缓存，各资源域采用相同接口。核验 boot/controller/model/resources/cores 五类代际、发布者、核心归属、对象代次、决策序号、绝对有效期、单位和预算。缓存被撤销或策略被拒绝不会清除防重放水位；迟到消息不能重获 TTL。`SafeExec` 是执行确定性安全规则的指令，不代表某个旧策略已经重新获批。
- `manager`：核心迁移、模型切换、控制器重启、资源代际变化联动撤销旧策略。旧模型产生的未完成迁移在模型切换时中止并隔离，返回真实恢复 ticket。控制器重启允许新的决策序列，同时保留核心 ticket 代际，拒绝旧 controller epoch。
- `queue`：无 unsafe、无分配、无等待的固定容量 SPSC 原子消息通道。N 个槽可容纳 N−1 条消息。发送/接收 token 不可复制且 !Sync；独占 split/reset 保证唯一生产者/消费者。固定字数 payload 使用 Acquire/Release 发布，业务热路径不消费控制队列。
- `wire`：新的 20×u64、版本 1 消息格式，固定魔数、严格保留位检查。调用者身份和执行 CPU 不在消息里，必须由内核执行上下文提供。不是旧 submit_schedule ABI 的静默改义。
- `budget`：每线程独立 CPU 用量，派发额度同时受剩余配额和绝对窗口期限限制。同窗口的新策略保留已消费量；控制器/模型更新不能借此重置配额。执行器必须使用真实计时器计费。

`Bank<D>` 每个实例、每个域保留一条当前策略；多个对象需由执行器分配独立 bank/策略实例，不能把一个实例解释为整个多对象调度器。缓存接受回执仅表示 Accepted，不代表 Applied、Completed 或 Durable；实际动作仍由对应子系统的权限检查、资源账本和协议决定。

## 接入顺序与可信边界

1. EL1 根据真实拓扑提供 capacity 和物理 sibling masks，构造 Ownership；不会自动把 CPU0、CPU1 固定为某个平面。单核心不能满足两个非空独占平面的配置，会被拒绝。
2. 内核认证控制服务进程及 generation，保留独立 EL0 地址空间与能力。队列先复制固定长度消息，再由 Manager 校验；不能把内核 Environment、Limits、Proof 从共享页直接反序列化。
3. 资源账本提供当前 limits/epoch。控制服务在控制核上提交计划，业务执行器只调用 `select`，得到经过校验的策略或 `SafeExec`，不等待推理。
4. 调度器在每次派发时检查 `snapshot.permits(cpu, plane)`；迁移、隔离和停止状态不能派发。现场测量的 drain/handoff/recovery 完成事件才可生成 Proof。
5. 架构层用真实 IPI、TLB/cache/内存屏障、IRQ 路由、每核上下文、页表和计时器执行交接。内核管理锁或单写者事件循环负责序列化管理更新；本模块的普通 Rust `&mut` 不自动替代跨核同步协议。
6. 故障 watchdog 调用 expire/fault。已接受的 I/O、释放、持久化完成按原协议继续，不能被模型故障或新策略门禁阻塞。恢复前保持故障核原 owner，不能把“没响应”当成“已经停止”。

当前主干 `entry.S` 只允许 CPU0 启动，AI 调用也仍在现有前台路径。本补丁没有删除原 AI 调用、启动次级 CPU、改写所有系统调用、创建真实隔离 EL0 控制服务或安装新的页表。上述接入尚未完成；不得对当前镜像声明物理控制面隔离已经生效。

控制面模型、学习工作器、发布代理应一起放在控制核；专用核心数量与成员由 AI 在安全约束内提出，不是固定核数。所有内核基础机制、资源执行子系统和系统服务具有相同 AI 接入地位。测试宿主不是集群节点，不引入 Android/iOS/Windows/Linux 宿主代理作为正式成员。

## 桌面侧实际修改

`tools/build_mesa.py::download_mesa` 接入 `range_download.py`，把四路突发范围请求改为顺序、有界重试。支持 HTTP 429/408/5xx、Retry-After 秒数与日期、超时；保持精确 Content-Range/长度和最终 SHA256。已验证文件可以重用；坏哈希不发布为完成产物，拒绝符号链接和并发覆盖。此修改只覆盖 Mesa 发行归档下载路径，不声称所有上游或 UAPI 请求均已修复，也没有使用未锁定镜像。

`crates/posix/src/pty.rs` 修正 erase/kill 回显的预留字节计算：按实际换行转换后的长度预留，在修改输入行之前完成检查。换行映射的 erase 可能需要 2 字节；换行映射的 kill 配合 ECHOK 可能需要 4 字节。测试包含背压不改变输入、恢复后重试、四种输出模式及编辑标志的 192 组参数组合。

没有声称实现 cosmic-comp、cosmic-session、会话 D-Bus、完整桌面组件或会话容量扩展；这些仍是后续代码和整机集成缺口。

## 本轮测试的严格范围

统一测试在写完代码后执行。新 control_plane 模块使用原样源码的独立 harness 编译，不依赖模拟的管理实现。34 项 Rust 测试（1 项内部边界测试 + 33 项集成测试）通过，含 50,000 条八字消息的真实双线程队列测试。Clippy `-D warnings` 以及 AArch64 `aarch64-unknown-none-softfloat` 的 no_std 编译检查通过。

下载器 25 项离线 Python 测试通过；网络回应是明确的测试对象，不代表完成真实源站下载或 Mesa 编译。另有 3 项 PTY 回归在行纪律抽取 harness 中执行：旧逻辑全部失败，补丁后全部通过。该 harness 保留被测 receive 方法和相关环形缓冲/读写逻辑，使用测试专用 errno/常量，并省略无关生命周期字段和方法；不是完整 POSIX crate 运行证明。

尚未运行完整仓库测试、真实 Mesa/Smithay/COSMIC 构建、QEMU 双平面隔离、真实 EL0 对抗测试、跨核故障注入或桌面会话验收。任何工作包或主机测试通过均不能把 hardware_isolation_active、cosmic_runtime_verified 或 desktop_session_ready 置为 true。


## 2026-10-24 故障遏制修复

`Manager::fault` / `Ownership::fault` 不再因输入时间戳小于已观察水位而跳过已知故障核心的隔离；遏制使用 `max(now,last_time)` 保持水位，不给租约续期。普通策略和核心迁移仍拒绝倒退时间。此修复只保证软件归属表不再允许派发故障核，真实 stop/IPI/页表与调度器强制约束仍须架构后端实现。

本轮规范追踪新增 `prototype-requirements.json`。它不把这组内核库接口或其主机测试自动升级为 A01–A16 的原生运行 PASS；详细缺口见 `prototype-gap-review.md`。

## 后续原生机制增量

独立 `smp-selftest` profile 已接入真实次级核启动、每核上下文、EL0 页表、定时器抢占和原子派发栅栏。上文“尚未启动次级 CPU”等描述针对首次软件管理核心交付；默认生产桌面仍未改为多核隔离。详见 `native-smp-mechanism.md`。测试中的核心集合来自脚本提案，不是 AI，不关闭 A01–A04 的完整验收门槛。
