# V0.20 第十一波：新特性接入生产路径（方案 A）设计

- 日期：2026-11-25
- 基线：HEAD 88288c6（第十波 production-wiring skeleton）
- 状态：APPROVED（2026-11-25）
- 范围标签：production-path（`v020-production` 特性）；不是 G4 验收，不闭合任何门槛

## 1. 意图

第十波已经把生产启动和 in-vector SVC 分发骨架接好（[production.rs](../../../kernel/src/arch/aarch64/production.rs)），
但 2026-11-25 的接线审计显示，生产路径里只有建议链（0x50/0x41）、固定 CPU0 拓扑，以及一个 fail-closed 的快照 0x40 in-vector 入口（production.rs:865，后端返回 EAGAIN）。
其余 V0.20 新特性只在契约层或原生夹具里存在，内核生产路径没有调用方。

本波的目标是让**不依赖 G1 介质字节冻结**的特性真正进入 `v020-production` 启动路径。
**依赖介质**的特性也接进骨架，但放在一个默认关闭的特性开关后面，并标成 golden-vector-pending，
等 G1 字节冻结后再切换。用户于 2026-11-25 选定此方案（方案 A）。

## 2. 目标 / 非目标 / 反目标

**目标**
- G-A（真生产接线，`v020-production` 默认启用）：
  1. **SEC-N 网络**：`net_device::init` 由生产启动调用，在真实 VirtIO-net 上运行（QEMU 不再用 `-nic none`）。
     `net-transport::admission::Admission` 是唯一的连接额度账本。user/local-echo 作为 EL0 服务，
     在生产启动中部署并接入 SVC 0x43 broker，端口用真实设备，不用 mock。完成标准见 §7 Q1。
  2. **FrameMeta 登记生产静态页**：生产配置下，现有静态页全部登记进 FrameMeta，
     守恒校验在发布之前完成，失败时粘性 fail-closed（范围见 §7 Q2）。
  3. **RecoveryProof v2 内存态**：4 个 vCPU 各一个单写者 `RecoveryAccumulator`、饱和粘性计数、
     RECOVERY_REQUIRED 入口规则、消费者接管，都在生产启动中实例化。事件源是 EL0 角色同步异常和权限故障（这些已经在生产异常向量里），
     它们会产生 `DegradedEvent`。进入 RECOVERY_REQUIRED 后，生产建议链的 0x41 发布会被 fail-closed 拒绝；这是 G-A 里唯一的写型副作用。
     持久审计槽回退不在本组（见 G-B）。【事件源与阻断点是实施者决定，已记录】
  4. **policy_lock 计量**：生产建议链的 review/publish 改走 `review_brains_metered` / `publish_metered`。
     超预算时粘性 fail-closed，计量结果进入证据输出。只做计量；生产 policy_lock 对象与 IRQ-off 强制点按 manager.rs:140-142 归 G1 冻结交付，本波不做。
     时间源用 CNTVCT 换算 ns，预算用 policy_lock_v0199 中已登记的基线常量（L1542–1558）。【实施者决定，已记录】
  5. 修正 [aarch64.rs:238](../../../kernel/src/composition/aarch64.rs) 与实际不符的注释，去掉 `net_device` 上的 `#[allow(dead_code)]`。
- G-B（介质暂存，新特性 `v020-production-media-staging`，默认关闭，蕴含 `v020-production`）：
  v1 格式化器与挂载、file_media_unified_v1、FileServiceRequest v4 / ADMIT v3 的 EL1 准入流
  （file_admission_flow_v1）、快照 SVC 0x40 后端，以及持久审计槽。持久 BootEpoch 是否放在这一组，见 §7 的 Q1。
  每个模块都标明 `golden_vector_pending=true`。
- 证据：扩展 `tools/verify_v020_production.py` 和 `.github/workflows/v020-production.yml`，
  为每个 G-A 子项输出独立的布尔标志（例如 `real_net_device`、`frame_meta_production_statics`、
  `recovery_accumulators`、`policy_lock_metered`）。G-B 单独跑一条 staging 泳道。

**非目标**
- G1 字节冻结、黄金向量、独立编解码（属于 G1 工作）。
- 把生产挂载从 V0.18 v2 切到 v1；旧卷迁移工具。
- 8 个真实 EL0 角色的真实模型、真实执行器设备驱动。
- 全负载窗口下的 PMU 控制预算实测；127 个稳定 ID 的验收演练。
- 集群删除的后续阶段。

**反目标（即使能跑也算失败）**
- G-A 默认构建在任何地方依赖 v1 盘上布局（会在冻结前把格式定死）。
- 把骨架或夹具的 PASS 写成 G4 验收；把任何 NOT_RUN 升级成 PASS；不在证据里如实标注 glue 或 mock。
- 同一条生产连接上同时使用 Admission 和遗留的 RateLimiter 两套额度计账。
- 往 EL1 软浮点闭包里引入 NEON、rustls 或 ring。
- 改变默认构建或现有夹具配置的行为。

## 3. 约束

- EL1 目标保持 `aarch64-unknown-none-softfloat`。TLS 只在 EL0 guest（`aarch64-unknown-none`）里运行。
- `v020-production` 的 `compile_error!` 列表不拦 `sec-n-native`。真正的阻塞是：`net_device` 依赖 `crate::virtio_platform::Board`（net_device.rs:30），
  而 `virtio_platform` 在 `selftest` 配置下只对固定的特性列表编译（composition/aarch64.rs:224-235），`v020-production` 不在其中。
  本波需要重做这部分门控，且不能改变其它配置的编译结果。
- 生产路径现有的 unsafe 边界登记声明「没有 IRQ handler、DMA 或副核触碰这些 static」（production.rs:38）。网卡 DMA 和 IRQ 引入后，必须单独登记新的边界，不得破坏原声明。
- 遗留 `RateLimiter` 位于 kernel-core（security/network.rs:103），生产路径从未使用它；反目标的落实方式是加源码守卫，而不是替换代码。
- 控制面全部在 CPU0 上同步执行，不变量见 production.rs 中登记的 unsafe 边界。
  新的 static 必须按同样格式登记 unsafe 边界。
- QEMU 固定为 10.2.2、virt、cortex-a53、4 vCPU。G-A 泳道增加一块 virtio-net 设备（user 网络或 socket 对端）。
- 现有测试和源码守卫不得退化（第十波实测：workspace 2067 项、源码守卫 43 项）。新增数量以实测为准。
- 文档和提交遵守「范围标签 + 实测计数 + 未闭合清单」的写法。

## 4. 考虑过的做法

| 做法 | 内容 | 取舍 | 结论 |
|---|---|---|---|
| A | 非介质特性进真生产；介质特性进默认关闭的 staging 开关 | 不在冻结前定死格式；staging 代码可能要随冻结返工 | **用户选定** |
| B | 先完成 G1 字节冻结，再全部接入 | 最完整，但周期最长，非介质项也被拖住 | 未选 |
| C | 现在全部接入，生产挂载切到 v1 | 最快，但违反 G1 门槛，冻结前把盘上格式定死 | 未选 |

## 5. 已定的做法

- 沿用波次工作流：T1..Tn 并行任务，最后由一个中央验证任务同步文档与证据，作为一个「Land V0.20 … wave 11」提交落地。
- G-A 每一项都要有：宿主测试；进入生产启动路径的调用点；QEMU 生产泳道中的证据标志；源码守卫钉扎（防止退回 dead_code）。
- G-B 每个模块在 staging 开关下有调用点和宿主测试。QEMU staging 泳道只验证「能启动、fail-closed 路径正确」，
  不声称持久性或格式正确。

## 6. 留给实施者

- 任务如何切分、并行度、文件布局（遵守 800 行上限，production.rs 已有 1839 行，新增逻辑拆进子模块）。
- QEMU 网络后端选 user 还是 socket；local-echo 的对端测试程序如何实现。
- 注意：user_heap 只在 `not(selftest)` 下编译，它的 FrameMeta 账本还限定 `full-os`，生产配置里根本没有它，不能作为起点。
- 证据 JSON 字段的具体命名。

## 7. 用户决定（2026-11-25，「按建议实施」）

- **Q1 SEC-N 完成标准 = (b)**：完成网卡初始化，Admission 在真实 virtio-net 上发放连接额度，
  再加一条真实的 TCP 连接打到 local-echo，证据标志为 `real_net_device=true`、`tcp_to_local_echo=true`。
  完整的 TLS 1.3 回显（外部对端信任证书、EL1 smoltcp 到 0x43 的转发、网卡 IRQ/DMA 全面接入）
  不在本波，证据如实写 `tls_echo_turn_verified=false`。
- **Q2 FrameMeta 范围 = (a)**：把生产路径现有的静态页（ROOTS/MIDDLES/LEAVES/DATA_PAGES/USER_STACKS、
  PIE backing/tables、EXEC_TARGET 等）全部登记进 FrameMeta，守恒校验先于发布，失败时粘性 fail-closed。
  不新建分配器。证据标志改名为 `frame_meta_production_statics`，不写「通用分配器切换完成」。
- **Q3 持久 BootEpoch = (a)**：放进 G-B staging（`v020-production-media-staging`）。
  G-A 继续用易失 epoch，证据写 `staged_boot_epoch=true`。
- 本文档就此批准，状态从 DRAFT 改为 APPROVED。
