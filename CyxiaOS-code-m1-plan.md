# CyxiaOS M1：AI 契约与单核 ARM 基础内核 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking. 执行方式为本会话实现；用户已于 2026-10-15 确认执行。不要把浏览器原型的测试结果带入客体内核结果。

**Goal:** 建立遵守全系统 AI 决策契约的代码基础，并使 CyxiaOS 在单核 ARM QEMU 中独立完成 EL1 启动、高地址映射、基础页管理与定时中断，输出可自动检查的证据。

**Architecture:** Rust workspace 内以 `cyxia-contracts` 固定逻辑类型和平台接口，`cyxia-kernel-core` 承载可在主机测试的机制；AArch64、QEMU virt、PL011、GICv2 分别实现适配。最终 kernel 只负责组合。模型推理尚未接入时，所有资源行为标记为启动、机制或保护路径。

**Tech Stack:** Rust 1.95.0 / no_std、AArch64 汇编、rust-lld、`aarch64-unknown-none-softfloat`、QEMU 10.2.2 / `virt-10.2` / Cortex-A53 / TCG、Python 标准库验证器；首批不引入第三方 Rust 运行依赖。

**Spec:** [总体](CyxiaOS-design.md)、[详细](CyxiaOS-detailed-design.md)、[全系统 AI 契约](CyxiaOS-ai-decision-contract.md)、[完整实施路线](CyxiaOS-code-implementation-plan.md)。

实施记录：T1—T10 已完成；实际版本、测试结果与少量执行顺序/接口裁定见 [M1 实现结果](docs/implementation/m1-status.md)。勾选表示任务结果已验证；下文保留原任务说明，不作为当前状态报告。

## Global Constraints

- 首版单核 ARM；建议 ARMv8-A/AArch64，内核 EL1，首批不运行 EL0 应用或模型。
- `virt-10.2,gic-version=2,secure=off,virtualization=off`；`-cpu cortex-a53 -smp 1 -m 256M -accel tcg`，不依赖宿主硬件加速。
- DTB 在裸机启动 RAM 起始 `0x40000000`；入口段物理装载 `0x40200000`；内核高地址基区 `0xffffffc000000000`。地址为本计划平台布局，不允许散落在 kernel-core。
- 4 KiB 页、39 位 TTBR0/TTBR1 地址范围、W^X、MMIO Device 属性；首版不使用 ASID 复用优化。
- 不执行 FP/SIMD；不依赖 Linux 启动约定、libc、宿主文件/网络或外部模型服务。
- 同一资源只有一个所有者；身份 0 无效，检查式代际递增，耗尽不绕回。
- 日志非阻塞；正常内核路径不持锁等待设备/消费者；未知 IRQ 有界处置，不无限重入。
- 现有文档和 HTML 原型保留；本轮不修改其功能或重写历史审核结果。
- 未实现字段返回 Unsupported/NotReady，不能伪造 AI_ACTIVE 或安全验证通过。

## Review Focus

1. DTB 长度、字符串/结构块、保留区和 ELF 段边界溢出 → T4/T5 拒绝并无写越界。
2. 页带有旧所有者数据或重复释放 → T6 不发放脏页，先撤销/清零后重授予。
3. 模型计划失效与已提交授予交错 → T3 继续履约、不重复扣账；未提交额度不得再用。
4. MMU 高地址切换遗漏栈/VBAR/静态引用 → T7 撤销低映射后仍执行并正确进入异常入口。
5. 日志停读、异常 IRQ 与测试进程失联 → T8/T9 定时进度独立可验证，主机超时清理仅回收本次 QEMU 子进程。

## 文件与依赖

以下为原计划文件清单，原计划编写时项目无这些实现文件；当前实现和裁定见 [M1 实现结果](docs/implementation/m1-status.md)。

| 位置 | 责任 |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml`, `.gitignore` | workspace、版本、构建目标配置、产物排除 |
| `crates/contracts/{Cargo.toml,src/lib.rs,src/ids.rs,src/resource.rs,src/platform.rs,src/audit.rs}` | 不含 CPU 寄存器的类型和接口 |
| `crates/kernel-core/{Cargo.toml,src/lib.rs,src/grants.rs,src/frames.rs,src/boot.rs,src/time.rs}` | 授予、页生命周期、启动状态和时间换算 |
| `crates/arch-aarch64/{Cargo.toml,src/lib.rs,src/entry.S,src/vectors.S,src/mmu.rs,src/timer.rs}` | 架构相关实现 |
| `crates/platform-virt/{Cargo.toml,src/lib.rs,src/fdt.rs}` | DTB 校验、逻辑资源转换 |
| `crates/driver-pl011/{Cargo.toml,src/lib.rs}` | 有界串口输出 |
| `crates/driver-gicv2/{Cargo.toml,src/lib.rs}` | GICv2 初始化、确认/结束/源屏蔽 |
| `kernel/{Cargo.toml,build.rs,linker.ld,src/main.rs,src/selftest.rs}` | ELF 入口组合与内核自检 |
| `tools/{doctor.py,build.py,run_qemu.py,check_elf.py,check_dependencies.py,verify_m1.py}` | 工具前提、编译、运行及聚合验证 |
| `tests/host/`, `tests/qemu/`, `tests/fixtures/` | Python harness 测试、场景清单与小型固定输入 |
| `docs/implementation/{m1-environment.md,m1-interfaces.md,m1-status.md}` | 精确版本、接口冻结与结果边界 |

Rust 逻辑测试放在各 crate 的 `tests/*.rs`；纯逻辑 crate 默认 no_std，主机测试用标准测试 harness。`.cargo/config.toml` 不设置全局默认裸机 target，避免主机单元测试被错误交叉编译；只有 `kernel` 构建显式指定裸机目标。各 crate 名称统一为 `cyxia-` 加目录名，例如 `cyxia-kernel-core`、`cyxia-platform-virt`。

依赖顺序：T1 → T2 → T3/T4 → T5 → T6 → T7 → T8 → T9 → T10。T3/T4 逻辑可独立实现，但本轮顺序推进，不默认委派。

## Task T1：可复现工具前提与 workspace

**Files:** 根配置、所有首批 crate 的 Cargo.toml/lib.rs 最小入口，`tools/doctor.py`、`tests/host/test_doctor.py`、`docs/implementation/m1-environment.md`。

**Interfaces:**
- `doctor.py --json`：检查精确 rustc/cargo/QEMU 版本、主机目标、裸机 target、LLVM 工具、项目路径；返回 JSON，全部满足返回 0，缺项返回非零且逐项说明。只检查，不自动安装。
- workspace 初期无模型激活入口；`artifacts/` 与 `target/` 不进入 Git。

- [x] **1. 写前提检查失败用例。** `test_missing_target` 模拟只有主机目标，断言 `baremetal_target.ready == false` 且非零；`test_rust_outside_path` 注入可用绝对 Rust 路径，断言不报告 Rust 缺失；`test_version_mismatch` 断言拒绝未核查 QEMU 版本。
- [x] **2. 运行失败测试。** `python3 -m unittest discover -s tests/host -p test_doctor.py -v`；首次因检查模块尚未实现而失败，记录真实输出。
- [x] **3. 实现 doctor 和 workspace。** `rust-toolchain.toml` 固定 1.95.0，使用 edition 2024；kernel panic abort。把 `~/.cargo/bin` 仅加入本项目进程环境。执行时安装 `aarch64-unknown-none-softfloat` 与 `llvm-tools-preview`，不得在本次规划中安装。由工具链找到 rust-lld 与 llvm-readelf/llvm-objdump，不依赖全局同名工具。
- [x] **4. 核对 QEMU 10.2.2 的 virt 裸机启动和 PL011/ringbuf 路径。** 记录版本源码/安装包来源与摘要；测试配置显式绑定 ringbuf，不能仅引用旧 9.2.0 审核。发现差异先修订环境契约。
- [x] **5. 重跑检查。** 前提测试通过，doctor 所需项 ready；不能把仅创建空 crate 写成内核功能通过。
- [x] **6. 建立本地 Git 基线和提交。** 当前未有仓库；执行阶段在项目根初始化 Git，先保存现有设计原型基线，不添加远端、不推送；检查暂存范围后提交工具与 workspace。后续每任务单独提交，不能 `git add` 项目外文件。

## Task T2：AI 中心化契约、身份和来源

**Files:** `crates/contracts/src/{ids,resource,platform,audit}.rs`、`crates/contracts/tests/{ids,source}.rs`、`docs/implementation/m1-interfaces.md`。

**Interfaces:**
- 强类型 `CpuId(u16)`、`TaskId(u32)`、`Generation(u64)`、`PlanId(u64)`、`GrantId(u64)`、`PhysAddr(u64)`、`VirtAddr(u64)`、`PageCount(u32)`、`TimeNs(u64)`；构造器检查无效值/范围。TaskId、Generation、PlanId、GrantId 的 0 无效；CpuId(0) 是有效首核，时间和数量允许 0，不套用身份规则。
- `Generation::next_checked(self) -> Result<Generation, Exhausted>`。
- `DecisionSource`：AiDirect、AiPlan、Bootstrap、SafetyGuard、Recovery、Operator、Mechanism；`DecisionOrigin` 将来源与可选模型/计划/父授予身份绑定，模型来源无对应证据时构造失败。
- `MemoryRegion { start: PhysAddr, len: u64, kind: RegionKind }`；`PagePermissions` 拒绝 W+X；`BootInfo` 使用固定容量资源集合。
- `ClockSource::now_ns(&self) -> TimeNs`、`ClockEvent::set_deadline(&mut self, TimeNs) -> Result<(), PlatformError>`、`ConsoleOps::try_write(&mut self, &[u8]) -> Result<usize, PlatformError>`。ContextOps、CPU 生命周期等本批未使用接口先留在文档，不堆空实现。

- [x] **1. 写失败测试。** `zero_identity_rejected`；`generation_exhaustion_never_wraps`：MAX.next_checked() 为 Exhausted；`ai_origin_requires_model`；`plan_origin_requires_plan`；`mechanism_receipt_keeps_parent_grant`；`writable_executable_rejected`。
- [x] **2. 运行。** `cargo test -p cyxia-contracts --test ids --test source`，确认新增测试首先失败。
- [x] **3. 实现构造器/枚举/接口。** 不含 ARM 寄存器、MMIO 地址、模型层结构、平台指针布局或动态分配；定长编码后续单独定义，不能直接序列化 Rust 内存布局。
- [x] **4. 重跑测试并检查。** 全部通过，`cargo check -p cyxia-contracts --target aarch64-unknown-none-softfloat` 成功；记录接口，提交 `feat(contracts): define resource origins and checked identities`。

## Task T3：资源授予总账

**Files:** `crates/kernel-core/src/grants.rs`、`crates/kernel-core/tests/grants.rs`。

**Interfaces:**
- `BudgetLimit`、`PlanAllowance`、`ResourceGrant` 是不同类型；Grant 包含 owner、generation、总量、未兑现量、已占用量、状态和原始 DecisionOrigin。
- `GrantLedger::new(capacity: PageCount)`；`commit(request: AuthorizedGrantRequest) -> Result<GrantId, GrantError>`；`redeem(id, owner, pages) -> Result<RedemptionId, GrantError>`；`cancel_unused(id, owner) -> Result<PageCount, GrantError>`；`release_completed(receipt: ReleaseReceipt) -> Result<(), GrantError>`；`snapshot() -> LedgerSnapshot`。
- 每次兑现生成非零、检查式递增的 RedemptionId。ReleaseReceipt 绑定该次兑现、owner、代际及已完成撤销的页数，仅可信回收机制可构造；M1 每次兑现整笔释放，消费后重复回执必须拒绝。不同兑现分别释放，不能仅用总账余额推断回执未重放；部分释放留待 M5 定义。
- `AuthorizedGrantRequest` 只能由受信任准入入口构造；M1 仅开放启动来源。AI 授权证明在 M3/M5 接入前返回 NotReady，测试专用构造器只能存在于测试构建。
- `LedgerSnapshot` 提供 `capacity, free, reserved_unredeemed, in_use`；三者满足 free + reserved_unredeemed + in_use = capacity。账本是主机可测机制，尚不等于真实 AI 内存分配服务。

- [x] **1. 写失败测试。** 容量 200 页，提交 100、兑现 20：free=100/reserved=80/in_use=20；原计划失效后在有效 grant 上再兑现 1：100/79/21；取消未兑现余额：179/0/21；完成撤销后归还 21：200/0/0。检查新分配仅有软上限却无 grant 时拒绝。
- [x] **2. 增加对抗输入。** 重复释放、不符 owner、过期对象代际、超容量、计数耗尽均失败且总账不变；已取消 grant 不能再次兑现；测试构造器不出现在 release API。
- [x] **3. 运行 `cargo test -p cyxia-kernel-core --test grants`，记录失败后实现账本。** 使用有限槽和检查算术；提交失败不保留半条目。
- [x] **4. 重跑通过并提交。** 此时尚不把 grant 兑现接到用户页表或声称 AI 在分配内存。

## Task T4：有界平台资源解析

**Files:** `crates/platform-virt/src/fdt.rs`、`crates/platform-virt/tests/fdt.rs`、`tests/fixtures/fdt/`、`tools/doctor.py` 的 DTB 导出选项。

**Interfaces:**
- `parse_fdt(blob: &[u8]) -> Result<BootInfo, FdtError>`；检查头、版本、总长度、结构块/字符串块、保留区、cell 编码和节点深度，全部算术检查溢出。
- M1 平台配置：DTB 最大 2 MiB（必须在入口装载区之前）；最多 8 个 RAM 区、32 个保留区、16 个识别设备、节点深度 32；超出明确 Capacity 错误。RAM 支持的物理页总数不超过 65536。
- 从实际 DTB 获取 RAM、reserve map、reserved-memory、PL011、GICv2 和物理计时器 PPI；未知节点可跳过，所需资源缺失/冲突必须失败。核心只接收逻辑资源，不解析 DTB。

- [x] **1. 建立有效 fixture。** 在执行阶段用固定 QEMU 配置导出 DTB，记录命令和摘要；添加人工最小固定输入覆盖端序/cell 数，不只测试单个真实样本。
- [x] **2. 写失败测试。** `valid_virt_resources` 验证必需设备；`truncated_header`、`overflowing_block`、`unterminated_string`、`deep_tree`、`reserved_overlap`、`missing_timer`、`wrong_cell_width` 应返回对应错误，不读写越界。
- [x] **3. 运行 `cargo test -p cyxia-platform-virt --test fdt`，记录失败并实现有界解析器。** 不给未知设备猜地址；绝对 DTB 指针只由平台启动适配转换成受检字节范围。
- [x] **4. 测试通过并提交。** 正常启动配置资源清单写入环境文档。

## Task T5：裸机入口、ELF 检查与有界串口

**Files:** `kernel/src/main.rs`、`kernel/{build.rs,linker.ld}`、`crates/arch-aarch64/src/{entry.S,lib.rs}`、`crates/driver-pl011/src/lib.rs`、`tools/{build,check_elf,run_qemu}.py`、`tests/host/test_elf.py`。

**Interfaces:**
- `_start`：仅支持 EL1，关中断，建立对齐栈、清零 BSS，跳转 `extern "C" fn boot_entry() -> !`；未满足入口异常级/DTB 边界时停机，由主机超时判失败。
- `Pl011::new(resource: UartResource)` 经受信任平台适配绑定 MMIO；实现 ConsoleOps，每次最多写 64 字节，FIFO 满返回已写字节数/Again，不忙等消费者。
- `check_elf.py <elf>` 检查 ELF64/AArch64、PT_LOAD 物理范围、段重叠、W+X、入口、DTB 保留区域和链接边界；成功退出 0。
- `build.py --profile dev` 输出明确 ELF 路径。`run_qemu.py --elf <path> --case boot-entry` 启动独立 QMP Unix socket 和 ringbuf，不连宿主真实磁盘/网络。
- Runner 固定使用 `-machine virt-10.2,gic-version=2,secure=off,virtualization=off -cpu cortex-a53 -smp 1 -m 256M -accel tcg -display none -monitor none -nic none -chardev ringbuf,id=cyxlog,size=1048576 -serial chardev:cyxlog`，另以参数数组传入本次 QMP socket 和 kernel ELF；T1 核查后将完整实参记入证据。

- [x] **1. 编写 ELF 检查失败测试。** 合法/截断/段溢出/DTB 覆盖/W+X fixture，断言拒绝原因；先跑 `python3 -m unittest discover -s tests/host -p test_elf.py -v`。
- [x] **2. 定义 boot-entry 客体验收。** 30 s 主机超时内读取 `BOOT_ENTRY`、`PLATFORM_OK`，要求版本、EL1、CPU0 和平台摘要；空输出不是通过。此时因为尚无内核应失败。
- [x] **3. 实现低地址启动阶段和有限串口。** DTB 校验成功后初始化串口；所有输出标为 BOOTSTRAP。QMP `ringbuf-read` 用 base64 解码，有界读取且帧完整性检查；不将 `-serial stdio` 作为验收路径。
- [x] **4. 编译、查 ELF 和启动。** `python3 tools/build.py --profile dev`；`python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --case boot-entry`。得到预期标记后由 harness 结束本次虚拟机。
- [x] **5. 提交阶段代码。** 首个启动仅证明入口/平台/串口；MMU 和时钟尚未完成。

## Task T6：页所有权、清零与回收机制

**Files:** `crates/kernel-core/src/frames.rs`、`crates/kernel-core/tests/frames.rs`、`kernel/src/selftest.rs`。

**Interfaces:**
- `FramePool::from_regions(info: &BootInfo, reserved: &[MemoryRegion], metadata: &mut [FrameMeta]) -> Result<FramePool, FrameError>`；固定 metadata 上限覆盖 65536 页。
- `alloc_clean(owner: TaskId) -> Result<FrameHandle, FrameError>`；`begin_revoke(handle, owner)`；`finish_revoke(handle, completion: RevokeComplete)`；`clean_one(zeroer: &mut impl PageZeroer)`。
- `FrameHandle` 包含物理页及代际；RevokeComplete 只由映射撤销适配生成，主机测试可用测试替身。M1 无用户映射，但不得删除将来的撤销门槛。
- DIRTY_FREE 不计可分配容量；无 CLEAN_FREE 返回 Again，真正容量耗尽和配额不足区分；启动清零属于 BOOTSTRAP，后续有界后台维护留给 M3。

- [x] **1. 写失败测试。** 保留 DTB/映像/栈/页表/设备区域不分配；写入模式后回收、未清零申请必须 Again；清零后整页为 0；错误 owner、旧 handle、重复释放失败且统计不变。
- [x] **2. 跑 `cargo test -p cyxia-kernel-core --test frames`，确认失败后实现。** `clean_one` 每调用最多清一页；配额账本与物理页池分别测试，不能把额度提交冒充页已分配。
- [x] **3. 添加客体 `pages` 自检。** 取出页写固定模式，回收、清零、再次分配检查；不得读写不属于测试池的内存；输出 `PAGE_SELFTEST_OK` 或具体失败码。
- [x] **4. 重跑主机与客体，记录页数守恒，提交。** 内核/元数据总开销按实际链接与分配统计，16 MiB 目标不足时失败，不侵占保留池。

## Task T7：高地址内核、页权限和异常入口

**Files:** `crates/arch-aarch64/src/{mmu.rs,vectors.S}`、`kernel/linker.ld`、`kernel/src/{main,selftest}.rs`、`crates/arch-aarch64/tests/descriptors.rs`。

**Interfaces:**
- 架构纯编码接口 `encode_leaf(pa: PhysAddr, permissions: PagePermissions, attr: MemoryAttr) -> Result<u64, MappingError>` 与建表逻辑可在主机测试；寄存器写入仅 target_arch=aarch64 编译。
- 启动转换函数安装临时 TTBR0 恒等映射与最终 TTBR1 高地址映射；MAIR/TCR/SCTLR、DSB/TLBI/ISB 序列在该任务文档冻结。
- 内核 RX/R/RW 分段、栈保护页和 MMIO Device 属性；切换 PC、SP、VBAR 和静态引用后撤销低地址启动映射。TTBR0 留给后续用户空间。
- 异常帧完整保存通用寄存器、ELR/SPSR/ESR/FAR；FP/SIMD 禁止。仅特定自检故障允许受控返回，其余内核异常记录后停机，不能通用跳过指令掩盖错误。

- [x] **1. 写失败测试。** W+X、非对齐/超范围 PA 拒绝，RX 页不可写、Device 不误标 Normal；测试栈 guard 没有有效 PTE。运行 `cargo test -p cyxia-arch-aarch64 --test descriptors`。
- [x] **2. 建立 `mmu` 客体验收。** 低映射撤销后从高地址主体调用串口/函数、切 VBAR 并触发一个已声明同步异常；失败必须停机和非零测试结果，不能只检测打印到 MMU 启用前的文本。
- [x] **3. 实现并验证。** 输出 `HIGH_VA_OK`、`IDENTITY_UNMAPPED`、`WX_SELFTEST_OK`；地址验证包含栈和异常向量均在合法高映射内。重新跑 check_elf，因为装载/链接布局已变化。
- [x] **4. 完成 host/guest 检查并提交。** 这仍不证明 EL0 隔离，后者归 M2 V00/V03。

## Task T8：GICv2、计时与有界中断处理

**Files:** `crates/driver-gicv2/src/lib.rs`、`crates/arch-aarch64/src/timer.rs`、`crates/kernel-core/src/time.rs`、`crates/kernel-core/tests/time.rs`、`kernel/src/selftest.rs`。

**Interfaces:**
- GIC `acknowledge() -> IrqAck`、`end(IrqAck)`、`mask(IrqHandle)`；spurious 与有效中断分开，确认/结束遵守芯片协议。
- `ticks_to_ns(ticks: u64, freq: u64) -> Result<TimeNs, ClockError>`；频率为 0/换算溢出明确失败；时间不能倒退。
- Generic Timer 使用物理计时器，PPI 来自 DTB，重编绝对截止后结束 IRQ；1 ms tick 仅作 M1 中断自检，不当作以后每次 AI 调度触发器。
- IRQ handler 做有限识别/计数/重编/屏蔽，不调用模型、不循环打印大量日志；未知源屏蔽并留有界记录。

- [x] **1. 写失败测试。** `zero_frequency_rejected`、`conversion_overflow_rejected`、`deadline_monotonic`、重复到期不发无界补偿中断；跑 `cargo test -p cyxia-kernel-core --test time`。
- [x] **2. 定义 `timer` 客体检查。** 连续观察至少 100 个计时中断且前台计数增长；检查 IRQ 返回后寄存器/栈完整。验证空闲 WFI 可被下一中断唤醒。
- [x] **3. 实现并故障注入。** 通过专用自检特性注入未知 IRQ 处理路径，验证有界屏蔽/计数且 timer 继续；不能声称已测试真实所有中断源。普通运行不开放任意用户注入入口。
- [x] **4. 输出 `MMU_TIMER_OK`、计时计数与 `IRQ_SELFTEST_OK`，跑组合 boot/pages/mmu/timer 检查，提交。** QEMU 墙钟开销不用于宣称达到 250 μs 模型接管指标。

## Task T9：可终止的客体测试与证据收集

**Files:** `tools/{run_qemu,verify_m1,check_dependencies}.py`、`tests/host/{test_qmp,test_runner}.py`、`tests/qemu/m1-cases.json`。

**Interfaces:**
- QMP 采用按行 JSON 的标准握手和 `qmp_capabilities`；处理异步事件和半包。每次运行独立 socket/目录，拒绝复用无法证明归属的旧 socket。
- Runner 用 `subprocess` 参数数组调用已核实程序，不拼接未转义 shell；只终止自身启动的进程，先请求退出再有界强制清理。
- `verify_m1.py --output artifacts/<run-id>` 聚合检查并输出 `summary.json`；每场景记录命令、timeout、标记、退出状态、日志丢失、证据路径与哈希。
- `check_dependencies.py` 读取 cargo metadata，禁止 contracts/kernel-core 链接架构驱动或模型运行时；在 core 中发现 MMIO/arch 汇编引用需审查，不用仅有目录名作为解耦证据。
- 独立进度页仅在 selftest 构建启用，链接为一页对齐的专用符号并列入保留区；harness 从 ELF 符号及 PT_LOAD 映射计算物理地址并检查范围。停读日志前后分别用 QMP stop、pmemsave、cont 获取一致快照，快照之间客体必须恢复运行；不能依赖已停读日志传递地址或把暂停时间算作前进时间。

- [x] **1. 写失败测试。** QMP 半包/异步事件/无效 JSON；客体无输出/错误标记/主机超时均失败；清理后无本次子进程遗留，不影响其他 QEMU。
- [x] **2. 运行 `python3 -m unittest discover -s tests/host -v` 并实现 harness。** 所有模板超时都用有限值，主机工具最大等待写进场景配置，不无限轮询。
- [x] **3. 增加日志停读场景。** 消费者连接保持但暂停 ringbuf-read，客体输出量超过后端容量，使用测试专用 RAM 进度页经 QMP pmemsave 读取中断/前台计数，证明输出停读前后仍前进；记录覆盖/缺帧，禁止仅凭 QEMU 进程还活着判断成功。该证据是 M1 进度检查，不是完整用户业务 V18 已完成。
- [x] **4. 跑组合验证。** 日志覆盖不影响通过条件中的独立计数；无法恢复完整日志时标记 incomplete，不假称完整重放。保存依赖检查，提交。

## Task T10：阶段验证、接口审查与状态交接

**Files:** `docs/implementation/{m1-environment,m1-interfaces,m1-status}.md`，根据实际证据调整对应设计中的已实现状态；不修改历史审核快照。

- [x] **1. 执行主机检查。** `cargo fmt --all -- --check`；对 contracts、kernel-core、platform-virt 和可主机构建的驱动编码执行 cargo test/clippy；裸机入口使用目标构建检查，不能用主机不兼容当作跳过所有检查的理由。
- [x] **2. 执行目标构建和 ELF/指令检查。** 构建 softfloat ELF，用工具链 llvm-objdump 检查可执行段无 FP/SIMD 指令；记录检查范围，不能扫描非代码数据后误判，也不能只看目标名字推断无浮点。
- [x] **3. 执行 `python3 tools/verify_m1.py --output artifacts/m1-final`。** 输出每项 PASS/FAIL/NOT_RUN；任一必需检查失败则总体非零，不标完成。
- [x] **4. 自查实现与规范。** 核对分层、unsafe 入口、预算/页所有权、来源语义与上述 5 项 Review Focus；发现缺陷修订后只重跑受影响检查及必要组合检查。
- [x] **5. 写阶段结果并提交。** 报告真实通过项、失败项、未执行项和复现命令。M1 结束状态是 `KERNEL_BASE_READY`，不是 `AI_ACTIVE`；下一阶段 M2 需单独细化 EL0、任务和能力协议。

## 验收与未覆盖范围

M1 全部任务完成才可宣称：自研内核在指定单核 ARM QEMU 启动，页管理基础、内核高地址映射和定时中断通过指定场景；AI 决策来源与授予契约存在可执行主机测试。

本阶段不声称：用户态隔离完成、模型在客体决策、学习已在内核运行、文件系统/网络可用、多核支持、实体硬件安全或性能达标。完整 V00—V23/L/C/S/X 验收仍按后续里程碑进行。

## 计划自查结果

- M1 覆盖 P0/P1 当前可实现切片；CPU 用户模型与其他资源策略明确推迟到后续里程碑，未用手写策略冒充 AI。
- T2 类型供 T3—T8 复用；T3 总账不隐式替代 T6 页状态；T7 撤销规则为未来 RevokeComplete 实现基础。
- 测试命令指向执行时将创建的工具/文件，不代表这些命令现在可运行或已经通过。
- QEMU 版本源码复核、ARM 屏障/页表精确序列在各自任务实施前冻结，未声称设计文档已经提供所有寄存器实现细节。
- Git 仅本地初始化/提交，无远端操作。环境安装和源代码创建已获确认并完成；实际执行记录见 M1 实现结果。
