# 原生桌面移植执行链：动态 Wayland 工作包

基线：`fc22be9677106d90b50e68c64bc3bbc04e77865a`，`m1-kernel`。

本增量交付源代码和测试，不宣称已经完成 COSMIC 会话。现有 Xorg/Openbox/LXPanel 入口不变；没有修改 AI 模型、资源限额、CPU 拓扑或集群成员定义。

## 实现

`tools/port_smithay_dynamic.py` 将现有环境检查、Python 测试、默认及 large-memory Rust 测试、固定版本 Smithay 服务端构建、独立 Wayland 客户端构建、内核打包、三至五次原生 ARM 客体验收接成一个前台命令。它调用既有构建器和 `verify_smithay_dynamic.py`，不复制或简化它们的协议、像素、输入和资源检查。

服务端和客户端以 `CYXIA_SMITHAY_DYNAMIC_PROBE_ELF`、`CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF` 传入内核；内核构建使用独立 target 目录，随后复制到本轮 `kernel/cyxia-kernel.elf`。打包后的 `kernel-source-manifest.json` 与原验证器接口一致。旧产物不作为隐式回退。

每次运行要求新的输出目录。源码清单包含构建相关已跟踪文件及未忽略的新文件，各阶段前后检查内容、增加和删除。报告绑定 Git 提交、源码清单、ELF、原始日志及截图哈希；失败保留现场，禁止重用旧 PASS 或 FAIL 目录。清除继承的 ELF 路径、构建 wrapper、RUSTFLAGS 与 PYTHONOPTIMIZE，拒绝在 `python -O/-OO` 下执行正式验收。所有子进程均前台等待；超时或失败时终止进程组，不启动后台任务。

`tools/doctor.py` 在缺少工具、无执行权限或查询超时时输出负面检查结果，不再提前抛出 FileNotFoundError。Rust 元数据缺失不能退回当前目录查找 LLVM；Cargo 版本匹配不能误接收 `1.95.01` 或预发布后缀。保留原有固定版本门禁，并让 doctor 与新入口统一使用 CARGO_HOME。

`ports/cosmic/smithay-dynamic/clients.rs` 修正注册表代次耗尽路径：已耗尽且为空的槽位永久退役，但不阻挡其他仍可用槽位。没有可用槽时区分 Full 与 Exhausted；拒绝不消耗连接 ID，不修改仍存活的所有者，不复活旧句柄。新增两项 Rust 边界测试。

## 运行

先准备仓库现有构建器要求的真实静态 musl/Wayland/xkbcommon SDK、Mesa 构建报告、固定上游源码缓存和 Wayland protocol crate。这条命令不负责凭空生成这些前置依赖，也不放宽既有版本或容量约束。

```sh
python3 tools/port_smithay_dynamic.py \
  --output artifacts/smithay-dynamic-new-run \
  --cache /absolute/path/to/verified-source-cache \
  --mesa-report /absolute/path/to/mesa-build-report.json \
  --protocol-crate /absolute/path/to/wayland-protocols-0.32.13.crate \
  --plan
```

`--plan` 只打印命令，不执行子程序、不创建目录。移除它才会真实构建和运行。仅当需要既有服务端构建器按固定哈希下载源码时添加 `--fetch`；默认不允许隐式下载。默认要求三次独立启动，不接受单次运行作为冻结结果。

真实执行的主报告为 `<output>/summary.json`，客体详细报告在 `<output>/runtime/summary.json`。退出码 0 仅表示此动态客户端工作包验收通过；退出码 1 为失败，130 为已记录的中断。

即使工作包通过，`full_cosmic_port`、`cosmic_runtime_verified`、`desktop_session_ready`、`desktop_regression_verified` 仍为 false。原 Xorg 桌面回归需要另外使用原有联合验收流程，不能被本工作包代替。

## 本轮验证边界

本轮隔离工作副本中，42 项 Python 主机测试通过，其中 3 项是原 doctor 测试、39 项为本增量测试。测试覆盖真实前台子进程、超时、日志超限、环境变量污染、源码漂移、产物不匹配、证据缺失和错误完成标志。运行链的成功分支使用明确标记的模拟构建产物和合成测试收据，仅验证编排代码，不是客体验收证据。

当前执行环境未提供 rustc、cargo、qemu-system-aarch64，且外网 DNS 查询失败。因此没有本轮本地 Rust 编译结果、ARM 启动画面或完整 COSMIC 验收结果。新增 GitHub Actions 主机检查工作流可在 PR 中运行 Python、Rust 注册表及两种工作区配置测试；只有实际工作流记录可证明其结果。CI 不包含完整 SDK 构建或 ARM/QEMU 客体验收。

仍未交付的核心目标包括真实 cosmic-comp 客体运行、完整 COSMIC 桌面会话及对应原生显示/输入联合验收；不能把本增量称为桌面移植完成。
