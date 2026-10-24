# 独立 EL0 模型控制服务：原生增量与验收边界

## 适用范围

`ai-control-selftest` 是显式的四 vCPU 原生控制服务集成配置，基于上一轮 `smp-selftest`。
默认 Shell、Xorg/COSMIC、生产调度器不被切换到此配置。它继承多核配置与
`ported/graphics/large-memory` 的互斥编译限制。

本增量真正运行独立编译的 Rust EL0 ELF，执行冻结模型的整数推理。提案经 EL1
身份、快照、模型/Schema、代际、有效期、采样窗口、驻留和核心容量检查后，才进入
已有的核心排空/交接/发布流程。正常提案中的目标核心来自模型与其候选核心打分，
不来自内核测试序列的目标 mask 表。测试断言才检查 1→2→1 的预期结果。

输入遥测是明确的冻结合成压力窗口，不是生产采样 P99；模型为合成教师蒸馏得到的
线性分类头与放置评分头，不是完整 16 领域统一模型，不声明学习或性能收益。
所有子系统仍具有同等 AI 强化义务，不将这个增量提升为首要资源域。

## 代码与可信边界

- `crates/control-model`：独立无分配、无 unsafe 的 64-Q15 编码/量化推理/动作解码。
  Mask、五类 epoch、序号和时钟是精确 u64，不经过 Q15 截断。
- `user/control-service`：独立无标准库的 AArch64 ELF；只有快照输入、输出页和结果 SVC。
  不调用 EL1 推理、网络代理或宿主服务；不是宿主程序伪装成 CyxiaOS 节点。
- `control_plane/image.rs`：有界 ELF 装载计划，拒绝 W+X、可写镜像段、动态装载、
  页别名、越界入口、长度/地址溢出及未知关键段。映射执行权限与读权限逐页保留。
- `control_plane/service.rs`：唯一可信发布者、五类 epoch、原始采样期限、窗口防重放、
  两个连续高负载窗口扩容、四个连续低负载窗口缩容、最小驻留及单核心变化。
  身份和 CPU 由内核上下文传入，不采信用户输出中的身份。
- `control_plane/exchange.rs`：固定容量原子邮箱，业务路径无阻塞。超时不会把仍在写入
  的槽直接复用；工作令牌退出只返回明确无效回复，不发布旧内存。
- `kernel/src/control_service.rs`：为每个控制工作器安装独立只读快照、可写结果页与
  带保护页的用户栈；共享的只有 RX/RO 代码和模型。CPU1 是当前唯一发布者，CPU2
  在控制归属期间实际运行同一模型作为辅助工作器，但不能发布归属变化。
  CPU编号和四核拓扑是测试配置，通用解码器不固定专用核心数量或核心编号。

EL0 读取只读快照，自行运行模型，将结果写入自己的输出页并执行 `svc #0x431`。
内核先返回 EL1 停止该上下文，核对调用号、输出页地址及精确长度，再复制输出。
原型中没有 DMA/设备共享引用；生产不能将此条件照搬为通用排空证明。

代码页复制后执行数据缓存维护；各执行 CPU 在进入服务前进行本地指令缓存同步。
定时器预算限制单次运行；一个卡死或故障的服务不会阻止业务核继续抢占和执行。

## ABI 和新鲜度

输入为 44×u64：magic/version、boot/controller/model/resources/cores、request sequence、
issued/original expiry、online/control/protected masks、feature count、window ID、模型
SHA256、Schema SHA256、sample_start/sampled_at、两个保留字及16字打包的64-Q15特征。

输出为 24×u64：魔数/版本、序号、controller/core epoch、目标集合、动作、boot epoch、
模型 SHA256、Schema SHA256、三个有符号16位 logits、model/resources epoch、window ID、
两个零保留字。完整 Schema 描述和摘要在 `ports/control-service`。

采样窗口号严格递增，时间区间不重叠。重复快照不能凑满连续窗口；跳过窗口或非连续
时间区间会清除连续计数。`expires=sampled_at+request_ticks`，请求到达不延长旧采样有效期。
窗口/动作/上下文切换不清除回复序号水位。重新启动控制器必须增加 controller epoch；
资源或模型变化先由唯一管理者调用 `invalidate` 撤回未完成结果。

模型提案通过不等于执行完成。实际 `CoreOwner` 提交之后才更新驻留时间与已发布代际。
当前配置中管理/取证编排仍是测试主循环，不是生产事件驱动调度器。

## 模型与可复现性

`tools/train_control_head.py` 使用标准库、固定训练/留出种子生成 Q12 权重。
`ports/control-service/training.json` 明确记录样本数、训练轮数、留出结果、模型/Schema
哈希和 `performance_benefit_verified=false`。重新运行 `--check` 核对生成物。

`kernel/build.rs` 在该 feature 下单独调用目标 Rust 编译器生成服务 ELF，并在内核
镜像中保留 `CONTROL_SERVICE_ELF`。取证脚本记录服务镜像、模型、Schema、内核、
模拟器与全部源码的 SHA256。验证器独立计算冻结模型的 logits，不以一行 PASS 为证据。

## 原生场景

正常配置执行两个连续高压和四个低压窗口，验证模型提案的实际扩缩容；辅助控制核
执行推理但被拒绝发布。随后将一条快照 Schema 破坏，真正触发服务失败，关门、
隔离、确认业务继续；在真实停止后恢复原归属，以新 controller epoch 重建服务，
拒绝旧回复并成功执行新的模型请求。

另有独立编译的 `hang`、`bad-mask`、`snapshot-write`、`model-write` 故障程序。
这些只存在于显式自检构建，不作为普通服务的运行时特权入口。写保护测试检查
真实异常类别、状态和地址；挂起测试检查实际定时器抢占。它们的通过标志是故障
遏制通过，不是正常模型功能通过。

```sh
cargo test --locked --offline -p cyxia-control-model -p cyxia-kernel-core
python3 tools/train_control_head.py --check
cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features ai-control-selftest
python3 tools/verify_ai_control.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/ai-control/fresh-normal-run

CYXIA_CONTROL_FAULT=hang cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --features ai-control-selftest
python3 tools/verify_ai_control.py --fault hang \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/ai-control/fresh-hang-run
```

使用项目锁定的 Rust 1.95.0 和 QEMU 10.2.2；每次选择全新证据目录。环境变量仅用于
显式故障构建，下一次普通构建需取消设置。工作流 `.github/workflows/ai-control-native.yml`
保留相同检查，不自动把本地主机/客体结果冒充远端 CI 运行结果。

## 尚未解决

生产事件驱动控制进程、真实遥测采集及负载闭环、16 域动作执行、持久模型治理、
完整 IRQ/DMA/RCU/跨核页回收、默认桌面多核调度、原生联网集群后端、v1→v2持久状态
迁移及完整 COSMIC 均未由此增量完成。QEMU逻辑核隔离不证明宿主物理核独占。

规范 A01–A04/A15/A16 的完整系统级验收继续保持 BLOCKED，而不是把本配置的局部
PASS 自动转写为系统 PASS。本增量不修改集群磁盘格式；累计补丁仍包含此前v2变更，
已有v1账本不可直接生产部署或通过清空账本绕过历史检查。
