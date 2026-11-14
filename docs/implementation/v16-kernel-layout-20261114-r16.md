# R16：kernel 分层与目录整理

日期：2026-11-14。此轮基于包含 R15 x86 实现的工作区继续整理，没有回退或覆盖前一轮修改。
整理前的源码和测试快照保存在 `artifacts/v016-kernel-layout-20261114-r16/before.tar.gz`，
逐文件摘要为同目录的 `before-sha256.json`。

最终编译输入共 1009 个文件，摘要为：
`9fc04c8383be7ce09f778d09ba0792d448fee0f74fe2e227078754de98d3092d`。

## 结构与边界

完整目录与放置规则见 [kernel 架构说明](../../kernel/README.md)。

- `kernel/src` 根目录从 59 个 Rust 文件整理为仅保留 `main.rs`。
- 183 个源码、汇编和链接脚本迁移到职责目录；没有保留旧路径转发文件或符号链接。
- `arch` 负责 CPU 启动、异常和控制台接线；`platform/virt` 负责 ARM 板级设备适配。
- `runtime` 按控制、任务、服务、文件、网络、集群、学习和恢复归档；桌面、诊断、自测独立。
- `composition/aarch64.rs` 集中保留 feature 约束和模块注册；构建适配与链接脚本分别位于
  `build/`、`linker/`。

原先 9 行的 `main.rs` 使用 `include!` 文本展开完整 CPU 实现；现在 32 行入口选择真正的
`machine` 模块，并明确导出少量集成接口。原 ARM 534 行、x86 371 行的单体入口分别拆成
架构模块、启动、控制台、异常或检查文件。硬件 ABI 符号和帧布局保持原契约。

现有 `crate::domain_control`、`crate::domain_tasks` 等接口保留，每份状态仍只实例化一次。
这次目录归档不代表 ARM unified-runtime 已移植到 PC；部分运行时仍依赖 ARM 适配。
通用策略继续由现有共享 crate 承担。

迁移内容审计显示：183 个迁移文件中，181 个除路径声明、include 路径及空白外相同；
另外两个是拆分后的 CPU 入口。该文本比较是补充检查，不代替编译和运行验证。

## 迁移中的修正

1. 同步生产工具、Rust 源码测试及 Python 宿主测试中的当前源码路径。
2. 补齐 21 处显式子模块路径。通过 composition 的 `#[path]` 装配后，原有隐式路径会查找
   错误目录，甚至将桌面 `user::ai` 误绑定到同名顶层文件；完整运行时和桌面构建发现并验证了修复。
3. 同步构建脚本的 `rerun-if-changed` 输入；临时复制源码的宿主 harness 将跨目录依赖转为绝对路径。
4. `tools/check_kernel_layout.py` 检查根目录职责、迁移完整性、显式子模块/include 路径、
   构建输入与链接脚本，防止再次遗漏。
5. `layout-migration.json` 记录精确迁移关系。源码绑定仅容许已声明且有唯一、真实替代文件的
   未暂存重命名；普通源码缺失仍拒绝，迁移表本身参与摘要。

冻结的 A03/A12 历史源码哈希契约保留原路径。历史证据测试也继续使用历史目录，
不把旧记录绑定到当前源码，更不修改历史 FAIL 结论。

## 验证

最终有效证据位于 `artifacts/v016-kernel-layout-20261114-r16/final/`。
父目录保留首轮失败及诊断记录，不作为最终映像的通过证据。

| 检查 | 结果 | 最终证据 |
| --- | --- | --- |
| 共享内核、prototype、peer-billing、架构/PC Rust 测试 | 939 通过 | `rust-host.log` |
| 双节点 unified-runtime release 构建 | BUILT_NOT_RUN；选定准备调用的栈门禁通过 | `unified-build/build-manifest.json` |
| x86 dev/release 编译、QEMU、独立证据复核 | 两个配置均通过平台自测 | `x86-*-build/`、`x86-*-run/` |
| ARM dev/release 基础全场景 | 两个配置均 PASS | `arm-dev-run/`、`arm-release-run/` |
| ARM production 编译及启动入口 | PASS；不表示完整桌面交互验收 | `arm-production-build.log`、`arm-production-run/` |
| ARM 四核 SMP 机制自测 | PASS | `arm-smp-run/` |
| 工具全量回归 | 807 项：806 通过、1 跳过 | `tools.log`、`tools-result.json` |
| 路径、源码绑定与取消任务复查 | 14 通过 | `path-and-source-binding.log` |
| x86 裸机 Clippy `-D warnings` | PASS | `x86-clippy.log` |
| 目录、格式与空白检查 | PASS | `check_kernel_layout.py`、rustfmt、`git diff --check` |

构建、Cargo 测试和 QEMU 串行运行，复用现有全局 native lease。机器可读原生结果为
`final/native-results.json`；所有最终构建绑定上述编译输入摘要。
工具跳过项需要未配置的 `CYXIA_REWARD_R7_ROOT` 历史输入，不计为通过。
综合记录为 `final/verification-summary.json`。

## 既有宿主测试缺口

额外选择 56 个受路径调整影响的宿主测试模块，执行 224 个测试，首轮未全绿。
随后用整理前的精确源码/测试快照执行失败所在模块：47 个测试中，27 个测试方法同样失败或报错。
主要原因是测试仍按旧函数名摘取源码，或临时 harness 缺少生产实现已有的依赖和字段。

本轮还修复了其中取消任务 harness 的临时模块路径，该用例现已通过；另一个 Rust 可执行文件
查找失败来自测试进程 PATH，配置正确环境后通过。其余 26 个既有失败方法不计为 PASS，
没有通过删除断言、跳过用例或修改业务行为来掩盖它们。

对照材料：`python-host.log`、`python-host-result.json`、`python-baseline.log`、
`python-baseline-result.json`；最终路径复查另存于 `final/`。本轮不宣称全部宿主测试通过。
按测试方法归并的对照清单为 `final/host-baseline-comparison.json`。

本轮未运行 A03 长时间采集、A10 断电矩阵或双节点原生验收。ARM 基础启动与 SMP 机制自测、
x86 平台自测以及 unified 构建通过，均不改变 A01–A16 验收状态。
