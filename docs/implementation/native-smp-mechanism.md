# 原生多核执行基础与隔离机制验收

## 状态和边界

本增量在四 vCPU 的原生 CyxiaOS 客体执行，而不是把四个宿主线程当作四台节点。`smp-selftest` 是单独的内核构建配置：真实执行 PSCI 次级核启动、私有 EL1 栈、不同 EL0 页表、私有定时器抢占及派发栅栏。默认桌面/命令行内核仍保留原单核业务路径。

控制角色中的 EL0 程序是确定性测试程序，**不是 AI 模型**。1→2→1 控制核变化来自显式测试输入，不是模型推理。A01–A04 的机制基础得到运行证据，不等于这些完整规范条目已经 PASS。`model_driven`、`production_isolation_verified`、`host_physical_isolation_verified`、`native_cluster_verified` 和 `full_cosmic_port` 必须保持 false。

## 实际代码路径

- `platform-virt` 从设备树读取 enabled CPU、完整 MPIDR affinity 及 PSCI hvc/smc conduit。CPU 节点必须位于 `/cpus`，地址单元数、重复属性、重复 affinity、未知 enable-method 和容量均被检查。逻辑 slot 不再由 MPIDR 低字节代替。
- `arch-aarch64::cpu` 调用 PSCI CPU_ON64。返回成功后还必须收到实际次级核握手；不能把固件返回值单独当作 CPU 已在线。
- 次级启动不重置 BSS；先使用 CPU0 发布的不可变页表，进入高地址，安装每核栈和异常向量，然后关闭低地址翻译。每核 EL1 栈有未映射 guard page。启动区域必须仍从 `0x40200000` 进入，链接器显式固定 primary/secondary 段顺序并限制在一页内。
- `arch-aarch64::user` 用 `TPIDR_EL1` 的可信逻辑 slot 索引每核 ACTIVE 上下文。注册上下文和切换 TTBR0 前先屏蔽异常；返回时先关闭低地址翻译、完成屏障并清理上下文，再恢复原 DAIF。EL0 的整数、TLS、32 个 SIMD 寄存器以及 FP 状态沿用完整保存协议。
- GICv2 次级入口只配置 banked PPI 和本地 CPU 接口，不重新初始化全局 distributor。每个运行核使用物理定时器 PPI 抢占不主动让出的 EL0 循环。
- `control_plane::dispatch::Gate` 用单次 CAS 接纳派发。管理者关闭 gate 后，迟到派发不能进入；已经接纳的派发保留 BUSY，必须真实返回后才释放。交接代次严格增加；permit 不可复制、不可跨线程移动。关闭与进入相撞时返回 Busy，由有期限的管理循环重试，不在热路径内部自旋。

## 私有地址空间、角色与探针

本配置需要且只接受四个 QEMU vCPU，底层启动表的当前上限为八个。这些是测试/GICv2 实现边界，不是 AI 控制核数量的固定规则。

CPU0 仅负责管理与串口记录。CPU1 初始为控制角色，CPU2/3 为业务角色；CPU2 实际在业务→控制→业务之间切换。对应控制集合 bitmask 为 `2→6→2`，业务集合为 `13→9→13`。每核/角色有独立数据页、栈和页表；只共享只读且单独按页对齐的 EL0 代码。cookie、TLS 和 SIMD 哨兵在每次抢占返回后核对，私有数据页实际计数必须增加。

每个被执行的角色完成五个真实权限异常：读取 EL1 高地址、访问未映射地址、写只读代码、执行 NX 数据、写用户栈 guard。判定同时核对异常来源、ESR 的异常类别及 fault status、FAR，而不把任意异常视作成功。CPU2 执行两个角色，因此一轮客体共有 20 次权限探针。测试并不尝试任意生产进程所有映射组合。

核心迁移先关闭真实 gate，再进入所有权状态机；等待旧派发返回且定时器停用、IRQ 已 EOI、低地址翻译关闭及 TLB 屏障完成，才发布新归属并用新代次打开 gate。**只有这个封闭测试配置没有 DMA、RCU、生产工作器和其他在途设备引用**，因此这里可以构造对应的排空证明。不得将测试中的 `Proof::DRAIN/HANDOFF` 常量搬到生产代码替代真实设备排空。

关闭控制角色后，其进度不再变化，而业务核继续至少八次抢占。该场景证明测试业务不等待该控制循环；没有证明生产所有系统调用都已消除同步 AI 推理。

## 可复现执行

需要仓库固定的 Rust 1.95.0、`aarch64-unknown-none-softfloat` 和 QEMU 10.2.2。以下命令不会连接网络，不会改用户的持久数据：

```sh
cargo test --locked --offline -p cyxia-platform-virt
cargo test --locked --offline -p cyxia-kernel-core --test dispatch
python3 -B -m unittest discover -s tests/host -p test_verify_smp.py -v
cargo build --locked --offline -p cyxia-kernel --target aarch64-unknown-none-softfloat --features smp-selftest
python3 tools/verify_smp.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --output artifacts/smp-debug-new
```

输出目录必须不存在。优化构建另加 `--release` 并使用新的输出目录。`--cpus 1` 是负面测试，预期非零退出并保留明确的 guest failure，不是超时或模拟通过。新 CI `.github/workflows/smp-native.yml` 对 debug/release 各执行三轮，并保留单核拒绝证据；提交前的本地运行结果不等于远端 workflow 已经运行。

## 判定与原始证据

`verify_smp.py` 同时要求：固定 ELF profile、QMP 观察到四核、完整且无丢失/损坏的串口帧、精确角色变更记录、控制停止期间业务进展，以及暂停虚拟机后通过 QMP 读取的 4096 字节物理证据页。页和串口中的 IRQ、派发、探针、错误及数据计数必须一致。仅输出一行 PASS 不会通过。

每次运行记录整个源码树文件哈希、ELF 哈希、模拟器版本和二进制哈希、启动参数、QMP 对话、串口原始字节、解码文本、物理证据页和各文件摘要。判定器检查运行前后源码和 ELF 不变。这是可复现实验记录，不是对恶意替换内核或宿主的硬件远程证明。

## 与已有缺口的关系

本增量接续 2026-10-24 的系统审核修复，不丢弃资源授权、状态不确定、防重放、POSIX 和 Mesa 修复。原有持久状态的版本 1→2 兼容性限制不变：没有历史就不能补造去重证明，旧格式返回 Version，尚无可部署的完整离线迁移工具。不得格式化旧账本来使测试通过。

仍需实现：独立原生 EL0 模型服务及能力边界、真实模型生成可变核心集合、16 个一级子系统完整策略/效果回路、生产线程调度接入 gate、跨核共享页回收和定向 shootdown、IRQ 路由和不可迁移设备证明、原生集群传输/密钥/持久事务/任务后端，以及真实 COSMIC 会话。构建时禁止把 `smp-selftest` 与原 CPU0-only 的 ported/graphics/large-memory 组合，避免用测试 profile 冒充多核桌面。

参考原始协议：QEMU 官方 virt machine 文档；Linux 内核设备树 PSCI binding 和 PSCI UAPI 函数号定义。硬件接入仍需验证具体固件、缓存一致性、拓扑和物理核心隔离；QEMU vCPU 不证明宿主物理核独占。
