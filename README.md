# CyxiaOS

不基于 Linux 的实验性操作系统。目标是由本地 AI 决策资源分配，由内核执行安全约束和资源机制。

当前代码为 **M1 单核 ARM 基础内核**：真实裸机启动、内核高地址映射、页管理机制、计时中断、AI 来源/资源授予契约和有界日志测试。**AI 推理、学习、用户进程、文件系统与网络尚未实现。** HTML 文件是早期设计原型，与实际内核分开。

## 构建与验证

在项目目录执行，Python 仅需标准库：

```sh
python3 tools/doctor.py --json
python3 tools/build.py --profile dev
python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel --case all
python3 tools/verify_m1.py --output artifacts/m1-final
python3 tools/coverage.py
```

环境：Rust/Cargo 1.95.0、目标 aarch64-unknown-none-softfloat、rustfmt/clippy/llvm-tools-preview；QEMU 10.2.2。当前使用已安装 stable 并强制版本校验，避免重复安装；如果本机 stable 升级，须使用精确 1.95.0 工具链或重新验收，不能绕过 doctor。

裸机配置：virt-10.2、Cortex-A53、TCG、1 CPU、256 MiB、GICv2，无磁盘和网络。完整测试包含开发/优化映像、日志停读压力和无 selftest 的启动。`--case pressure` 仅用于默认自检构建。

```sh
python3 tools/build.py --profile release --production
python3 tools/run_qemu.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --case boot-entry
```

结果保存在指定 artifacts 目录，包括原始串口帧、解析文本、QEMU 参数、映像哈希和 JSON 结果；压力场景的日志不完整是预期结果，会明确记录缺帧。

## 设计与实施

- [完整系统路线](CyxiaOS-code-implementation-plan.md)
- [M1 任务计划](CyxiaOS-code-m1-plan.md)
- [M1 接口与边界](docs/implementation/m1-interfaces.md)
- [M1 实测环境](docs/implementation/m1-environment.md)
- [实现状态](docs/implementation/m1-status.md)
- [AI 决策契约](CyxiaOS-ai-decision-contract.md)

源码按 contracts / kernel-core / arch / platform / drivers / kernel 分层。跨平台和多核已有接口边界，但本轮仅验证上述单核 QEMU 配置，未验证实体硬件。
