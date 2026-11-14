# x86-64 PC 平台与多架构边界

V0.17 起 x86-64 为主开发目标，平台约束见 [V0.17 设计](../../CyxiaOS-v0.17-platform-design.md)。
已加入真正的 x86-64 裸机内核入口，复用现有内核核心。首个平台是
QEMU `pc-i440fx-10.2` / `qemu64` / 单 BSP / 256 MiB；这是平台机制支持，
尚不是 ARM `unified-runtime`、桌面或 A01–A16 的 x86 移植完成。

目录职责及新代码放置规则见 [kernel 架构说明](../../kernel/README.md)。

## 代码职责

| 层次 | 共享部分 | ARM64 实现 | x86-64 实现 |
| --- | --- | --- | --- |
| 内核策略 | `contracts`、`kernel-core`、`control-model` | 相同策略库 | 相同策略库 |
| 页框所有权 | `FramePool::from_memory`、清零、代次与撤销状态机 | DTB BootInfo 适配 | Multiboot RAM/保留区适配 |
| CPU 机制 | 接口/值类型 | `arch-aarch64` | `arch-x86_64` |
| 板级设备 | `ConsoleOps`、时间转换 | `platform-virt`、PL011、GICv2 | `platform-pc`、16550、PIC、PIT |
| 可选 SHA 加速 | `arch::sha256` 门面与 portable fallback | 原有 ARM SHA 后端 | 返回无硬件加速，使用共享软件实现 |
| 内核组装 | `kernel/src/main.rs` 选择架构与集成接口 | `kernel/src/arch/aarch64/mod.rs` | `kernel/src/arch/x86_64/mod.rs` |
| 构建组装 | `kernel/build.rs` 只选择目标 | `kernel/build/aarch64.rs` | `kernel/build/x86_64.rs` |
| 宿主运行工具 | `build_sources.py` 源码/缓存身份、`native_session.py` 全局互斥 | ARM 薄适配 | PC 薄适配 |
| ELF 工具 | `tools/elf64.py` 只解析 ELF64 | `check_elf.py` 保留 ARM 地址/入口限制 | `x86_64.py` 校验 PC 地址、Multiboot 与证据 |

`kernel/Cargo.toml` 使用 target dependencies。x86 内核不引入 GIC、PL011、
VirtIO-MMIO、ARM 用户程序编译或 ARM 集群服务。`kernel-core` 和 `prototype`
不直接依赖 ARM CPU 实现。不同架构的启动信息不伪装成对方的设备描述。

x86 低地址映像使用 `small` code model；只在该 target 设置 `-C lto=off`，避免与
预编译 `core` 的 `kernel` code model 合并 LLVM bitcode 时冲突。这关闭 rustc 全图 LTO；
Cargo 仍可让链接器优化采用相同代码模型的依赖 bitcode。release 的优化级别仍生效，
ARM release LTO 保持原配置。目标默认值和参数语义参见
[Rust x86 裸机文档](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html) 与
[Rust LTO 文档](https://doc.rust-lang.org/rustc/codegen-options/index.html#lto)。

## 已实现的机制

- Multiboot1 地址头加载，32 位启动到 long mode，检查 long mode/NX；固定低地址 ELF64。
- 4 KiB 分页，CR0.WP、代码只读可执行、数据不可执行、空页与内核栈保护页不映射。
- GDT/TSS/IDT、独立用户陷阱栈、double-fault IST；176 字节 64 位陷阱帧。
- 16550 有界输出，复用 CYX1 framing；PIC 仅启用 IRQ0，PIT 使用实际 divisor 换算时间。
- CPL3 `int 0x80` 往返、用户写 supervisor 页的真实 page fault，以及回到内核调用栈。
- ARM/x86 共用页框清零、代次和回收自测；共用预算策略与时间转换检查。

Multiboot 解析拒绝截断、溢出、重叠、未支持扩展、非空模块和超过 256 MiB 的可用 RAM，
不截断大内存伪装成功。64 核、128 GiB 机器可以作为宿主运行这个客体；客体尚未使用
64 核或 128 GiB，不能据此推断 A03/A10 的加速倍数。

页框自测的页面没有交给真实任务或 DMA，只证明所有权状态机和清零。硬件页权限由
独立的真实异常探针检查；这不等于进程地址空间撤销或 DMA 隔离已经实现。

## 构建与运行

准备 Rust 工具链（本次验证使用 1.95.0）、`x86_64-unknown-none` target、
QEMU x86_64（含 `pc-i440fx-10.2`），首次 checkout 先准备依赖：

```sh
rustup target add x86_64-unknown-none
cargo fetch --locked
python3 tools/build.py --arch x86_64 --profile dev --output artifacts/x86-build
python3 tools/x86_64.py run --build artifacts/x86-build --output artifacts/x86-run
python3 tools/x86_64.py check --directory artifacts/x86-run
```

输出目录必须是新路径。优化版本使用 `--profile release`。macOS ARM 宿主使用默认 TCG；
Linux x86_64 宿主可显式传 `--accel kvm`，启动失败不会自动回退为 TCG。
本次未验证 KVM 或实体 PC 启动。`--production` 和其他 ARM 内核 feature 在 x86 路径拒绝。

成功要求完整、有序、无损的 8 个 CYX1 检查点和 guest debug-exit 33；超时、强制终止、
故障退出、缺失检查点均失败。保存 ELF、flat boot image、构建命令、编译器身份、源文件
哈希、QEMU 身份、原始串口及复核结果。修改相关源代码后旧证据会被拒绝，需要重新构建。
构建与 VM 复用 A03/A10 的全局 native lease；两种 QEMU 均进入忙碌检测。

ARM 兼容 CLI 显式选择架构（Python 构建 API 保持兼容）：

```sh
python3 tools/build.py --arch aarch64 --profile dev
python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --case all
```

## 验证范围

本次集成记录保存在 `artifacts/v016-x86-port-20261114-r15/`，详细结果见
[R15 验证记录](v16-x86-platform-20261114-r15.md)。

`X86_PLATFORM_SELFTEST_PASS` 仅表示上述 PC 平台检查通过。SMP/APIC、ACPI/UEFI、
PCI/VirtIO 驱动、生产进程调度、x86 原生采集/训练和断电矩阵尚未实现。
A03、A10 与完整 A01–A16 不因平台自测改变状态。
