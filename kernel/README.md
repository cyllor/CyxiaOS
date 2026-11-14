# Kernel 目录与模块职责

`kernel` 是裸机集成层。通用所有权、预算和协议策略位于 `crates/kernel-core`、
`crates/contracts`、`crates/prototype`；CPU 指令与页表机制位于 `crates/arch-*`；
本目录负责把它们装配成当前可运行的平台和运行配置。

```text
kernel/
  build.rs                    选择目标架构的构建适配
  build/{aarch64,x86_64}.rs    用户映像、资源及链接参数
  linker/{aarch64,x86_64}.ld   架构链接布局
  layout-migration.json       旧路径到当前路径的显式迁移记录
  src/
    main.rs                   架构选择与小范围集成接口
    composition/aarch64.rs    ARM feature 约束、模块注册
    arch/
      aarch64/                启动、异常、控制台、SMP 接线
      x86_64/                 PC 启动、控制台、平台验证/陷阱接线
    platform/virt/            PL031、GIC、VirtIO、存储与平台快照适配
    runtime/
      control/                控制提案、预算账本、模型/治理服务
      tasks/                  任务生命周期、派发、放置
      services/               共享服务窗口与服务投影
      files/                  文件请求与持久化业务接线
      network/                网络请求与传输接线
      cluster/                双节点会话、任务、存储、重放
      learning/               采集、历史、预热、回放、模型代次
      recovery/               启动恢复与正式恢复验证
    desktop/                  CPU0 桌面、shell、用户 ABI 与内存适配
    diagnostics/              验收负载、证据采集、故障与生命周期诊断
    selftest/                 页框共享自测、网络机制自测
```

## 入口与接口

`main.rs` 不再包含某个架构的实现正文。它选择独立的 `machine` 模块，注册共享自测，
并保留原生模块需要的少量集成接口（如 `log`、`HIGH`、`ExceptionFrame`）。

ARM 的 `boot.rs` 处理启动顺序，`exceptions.rs` 处理异常/保护探针，`console.rs` 处理
日志与 panic。PC 使用对应的 `boot.rs`、`console.rs` 和 `checks.rs`，底层 CPU 机制和
PC 设备实现仍由各自 crate 提供。符号名、陷阱布局、启动检查点和 feature 含义保持原契约。

当前保留 `crate::domain_control`、`crate::domain_tasks` 等逻辑模块接口，通过集中注册
把它们绑定到按职责划分的目录。每份状态只有一个模块实例，没有旧路径的转发源码或符号链接。
宿主源码测试仍跨越相同接口；迁移不会把测试 fake 或证据 fixture 放进生产共享核心。

`runtime` 的归档不意味着这些集成模块已完全架构无关。ARM unified-runtime 与桌面仍含
ARM 适配依赖；PC 当前只提供基础平台支持。移植时应把实际变化的 CPU/设备能力提取为
接口，再接入对应实现，不能仅改 feature 名称就宣称完成另一平台的验收。

## 新代码放置规则

- 新的 CPU 机制放入 `crates/arch-*`；内核启动/异常接线放入对应 `src/arch/`。
- MMIO、板级设备与硬件时钟适配放入 `src/platform/` 或独立设备 crate。
- 新的运行时流程放入其 `runtime` 业务目录，保留明确的公开接口，内部子模块紧邻实现。
- 诊断和验收负载放入 `diagnostics` 或 `selftest`，feature 条件集中登记到 composition。
- 新增可复用的纯策略优先放入现有共享 crate，避免从共享 crate 反向依赖 kernel。

## 检查与证据

```sh
python3 -B tools/check_kernel_layout.py
cargo build --locked --offline -p cyxia-kernel --target aarch64-unknown-none-softfloat --features selftest
cargo build --locked --offline -p cyxia-kernel --target aarch64-unknown-none-softfloat --features smp-selftest
python3 -B tools/build.py --arch x86_64 --output artifacts/x86-layout-build
```

目录检查拒绝根目录重新堆积源码、遗漏迁移文件、失效的字面量模块/include 路径。
`layout-migration.json` 还使源码绑定工具能够识别尚未暂存的重命名：只排除显式记录、
且新文件实际存在的旧 Git 路径。普通编译输入缺失、目标缺失、路径逃逸和重复目标继续拒绝。
迁移表本身也进入源码摘要。

历史证据中的源码路径和固定哈希保持原样；它们描述历史 checkout。目录调整后的源码、
映像和证据应重新绑定，不能把旧 VM 结果自动计为新源码的 PASS。

本次回归记录见 [R16 目录整理验证](../docs/implementation/v16-kernel-layout-20261114-r16.md)。
