# M1 已实现接口与边界

## 组合与状态

`contracts` 只包含逻辑类型、来源、平台能力和传输编码；`kernel-core` 包含授予总账、页状态与时间换算。架构、板卡与驱动由 `kernel` 组合。M1 正常启动来源为 BOOTSTRAP，计时和测试维护为 MECHANISM；AI 准入返回 NotReady，没有假模型或优先级规则冒充 AI。AI、EL0、IPC、进程服务、文件系统、网络和学习属于后续里程碑。

所有裸机入口固定单核 virt-10.2。逻辑层不假定 CPU 数量；当前中断单例与启动表明确是单核适配，不能据此声称 SMP 已实现。

## 资源契约

TaskId/Generation/PlanId/GrantId/RedemptionId 非零；CpuId(0) 有效。DecisionOrigin 的模型来源须有非零模型版本，AiPlan 还须有计划 ID。来源元数据不是授权凭据。

GrantLedger 使用 64 个授予槽、128 个兑现槽。提交时预留未来每页一次兑现所需元数据，避免已经承诺的容量因元数据不足而无法兑现。余额满足 free + reserved_unredeemed + in_use = capacity。取消只退还未兑现容量；已兑现部分须有完整撤销回执才释放。每次兑现有唯一 ID，整笔完成后回执不能重放。M1 不支持部分兑现记录释放，不把 BudgetLimit 或 PlanAllowance 当作已占用资源。

Trusted boot admission 与撤销回执构造为带明确安全前提的 unsafe 接口，不能直接暴露给未来用户态。未来 M2/M5 需要接入真实能力和映射生命周期。测试替身 AI 请求只存在于 crate 单元测试。

FramePool 使用调用方固定元数据，最多 65536 页。启动可用页初始 DIRTY_FREE，实际清零成功才成为 CLEAN_FREE；无干净页返回 Again。归还须经过 OWNED→REVOKING→DIRTY_FREE，再由单页清零推进。拥有者不符、旧代际或重复撤销失败。自检仅在自有页中写模式并验证完整 4 KiB 清零；未实现用户映射与 DMA 隔离。

## 启动与内存

ELF 入口物理地址 0x40200000；DTB 位于 0x40000000，最大 2 MiB。低入口与页表段拥有独立 PT_LOAD，主体链接于 HIGH + PA，HIGH=0xffffffc000000000。基础页面 4 KiB，TTBR0/1 均 39 位；TCR=0x2b5193519、MAIR=0xff，Normal WBWA 与 Device-nGnRnE 分开。物理地址空间按 Cortex-A53 配置为 40 位。

板卡启动适配先映射该固定机器的 256 MiB RAM 和 GIC/UART Device 窗口，再在高地址解析 DTB，并验证几何与预置板卡配置一致。它不是通用固件入口；新板卡须提供独立适配。核心不内置 MMIO 地址。RAM 页按链接区间区分 RX/R/RW，UXN 禁止用户执行内核页，PXN 禁止数据页执行，SCTLR.WXN 再限制可写页执行；栈前 4 KiB 无映射。

页表写入后 DSB SY；TLBI VMALLE1、DSB SY、IC IALLU、DSB SY、ISB，然后开启 MMU/cache。该裸机契约要求 QEMU reset 后 MMU/cache 关闭。跳到高地址后设置 SP/VBAR，设置 EPD0，ISB、TLBI VMALLE1IS、DSB ISH、ISB，禁止低地址访问。不会把低地址链接代码带入后续用户页表。新增动态映射的 break-before-make/缓存维护仍是 M2 后续工作。

同步故障恢复只在 selftest 明确武装的指令地址、目标地址和异常码完全匹配时发生：EPD0 引发 level-0 translation fault；栈 guard 引发 level-3 translation fault；代码写入引发 level-3 permission fault。其他异常打印受限诊断后停止。异常帧 288 字节，保存 x0–x30、ELR、SPSR、ESR、FAR，栈保持 16 字节对齐。

参考：[Arm 官方地址转换实现](https://raw.githubusercontent.com/ARM-software/arm-trusted-firmware/master/lib/xlat_tables_v2/aarch64/xlat_tables_arch.c)。QEMU 运行结果不代表真实板卡缓存或 DMA 行为已经验证。

## 中断和日志

GICv2 识别 spurious，不错误 EOI；有效中断用原 IAR token EOI。定时 PPI 来自 DTB，按绝对截止重编；过期不无限补发。未知外设 IRQ 屏蔽且计数。自检使用软件置 pending 的 SPI 40，验证实际 GIC 寄存器路径、WFI 唤醒和寄存器恢复。1 ms tick 仅用于 M1，不是以后 AI 的推理频率。

PL011 单次写最多 64 字节，FIFO 满立即返回；M1 最小诊断记录最多 96 字节，最多两次 UART 写。实际 QEMU ringbuf 1 MiB；宿主用 QMP 异步读取。

传输 v1 为小端：magic CYX1 (4)、version (1)、CPU (1)、payload_len (2)、session (8)、sequence (8)、payload (≤96)、CRC32 (4)。本阶段每次独立启动 session=1，主机 run-id、ELF 哈希和独立 socket 区分运行；多启动合并/热重启会话分配后续实现。损坏、缺号、重放和跨 session 帧不作为有效证据。日志缺帧不等于资源决策或业务暂停。

压力检查读取 ELF 中 selftest 专用进度符号的物理页。每次 QMP stop→pmemsave→cont 获得一致快照，快照之间客体继续运行。暂停 ringbuf-read 后至少新增 2 MiB 串口字节，时钟/前台计数都增长，恢复读取后检测序号缺口。它证明 M1 前进性，不能替代未来用户任务 V18。

## 验收工具

`doctor.py` 强制编译器和 QEMU 版本；`check_elf.py` 检查边界/W^X/入口/重叠；`check_dependencies.py` 检查 Cargo 依赖方向；`verify_m1.py` 汇总主机测试、目标检查、开发/优化映像及 QEMU 场景。错误导致非零退出，完整记录位于 artifacts 中。生产构建关闭保护故障、SPI 注入和日志压力，不导出 selftest 进度符号。
