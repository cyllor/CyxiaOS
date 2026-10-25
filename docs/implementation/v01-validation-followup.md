# CyxiaOS-V0.1 验证修复与原生回放调查

日期：2026-10-25（Asia/Muscat）。基线：`1fb57508750b2855ee199fac239e198b1b3c3493`。
本记录对应该提交上的本地修改，未提交或推送。没有修改 CPU 预算、发布阈值或验收目录状态。

## 已修复

- `tools/prepare_host_tests.py --fetch` 准备主机测试实际依赖的固定 COSMIC、Smithay 提交和协议归档；复用既有取源、工作区身份及 SHA-256 校验。省略 `--fetch` 时仅检查已有输入。不同客户端的协议归档 pin 不一致时，在任何取源前失败。没有跳过缺依赖的测试。
- `validate-current.yml` 与 `desktop-port.yml` 共用上述准备入口。前者此前缺少协议包和 COSMIC 源码，后者此前只准备协议包。
- 两个主要 push 工作流覆盖 `CyxiaOS-V0.1`；桌面主机工作流的 PR 目标分支也覆盖它。验证工作流增加 `tools/test_*.py`，其中包括原生回放判定器的故障证据测试。
- `domain_network/quote_stop.rs` 的原生模块条件从仅判断 `aarch64` 改为同时要求 `target_os = "none"`。原条件导致 macOS ARM 主机测试引用不存在的内核模块；现有真实 Journal 行为测试保持执行。

干净工作区执行：

```sh
cargo fetch --locked
python3 -B tools/prepare_host_tests.py --fetch
python3 -B tools/prepare_host_tests.py
python3 -B -m unittest discover -s tests/host -p 'test_*.py' -v
python3 -B -m unittest discover -s tools -p 'test_*.py' -v
cargo test --locked --offline --workspace --exclude cyxia-kernel
```

## 本次验证

| 检查 | 结果 | 本地日志 |
|---|---|---|
| 环境检查 | Rust 1.95.0、QEMU 10.2.2、两个裸机目标可用 | `tools/doctor.py --json` |
| 主机 Python | 508 项，0 失败/错误，1 跳过 | `artifacts/v01-host-tests.log` |
| 工具 Python | 46 项通过；新增诊断保留用例先失败后通过 | `artifacts/v01-tool-tests-tcg-green.log` |
| Rust 工作区 | 1071 项通过 | `artifacts/v01-rust-tests-fixed.log` |
| 格式、diff 检查 | 通过 | `cargo fmt --all -- --check`、`git diff --check` |
| 裸机 Clippy | `smp-selftest` 配置、`-D warnings` 通过 | `artifacts/v01-clippy.log` |
| 双节点 release 镜像 | 构建成功，不代表运行通过 | `artifacts/v01-diagnostic-build/build-manifest.json` |
| 1.3 发布门 | 返回 2；69 项 NOT_RUN，文件系统故障矩阵未完成 | `artifacts/v01-release-gate.json` |

唯一 Python 跳过项是 `test_real_single_binary_cargo_cross_build_uses_isolated_target`：本机未安装该测试要求的固定桌面 sysroot。统一原生构建有 126 条警告，基线和诊断构建数量相同；上述严格 Clippy 仅覆盖 `smp-selftest`，不是统一原生配置的无警告证明。GitHub 尚未运行本地修改后的工作流。

## 尚未关闭：原生预算与有效回放

上游同提交 CI `40215264766` 中，CPU0 服务线程 `0x101` 预付 2.5 ms，记录实际支出 4.476480 ms，触发隔离。读取了原始 `run/result.json`，没有把该运行改为通过。

本地原镜像重复运行也失败。新增只读诊断保留两类信息：

- `DOMAIN_PREPARATION_EVIDENCE`：每个控制 CPU 的八个单调时钟时间点，分别为进入候选准备、进入编码、注册后、输入编码后、SHA 后、证据写入后、历史写入后、任务建立后。它是阶段诊断，不是完整性证明或新的验收条件。
- `UNIFIED_EVIDENCE[30]`：CPU0 最后进入的服务阶段；1=安装 capture、2=初始化 peer replay、3=初始化 replay、4=网络轮询、5=域服务、6=EL0 服务。它不是完整调用栈，也不是所有服务路径的独立计费表。

| 配置 | 实际结果 | 原始证据 |
|---|---|---|
| wallclock / single TCG，原镜像两次 | 均 FAIL；CPU0 或 CPU1 超额 | `artifacts/v01-baseline-replay{,-2}/result.json` |
| wallclock / single TCG，诊断镜像 | FAIL；CPU0 网络阶段和 CPU3 超额，另一节点 CPU1 超额 | `artifacts/v01-diagnostic-replay/result.json` |
| wallclock / multi TCG，同一诊断镜像 | FAIL；CPU1 首个提案超额 | `artifacts/v01-diagnostic-multi/result.json` |
| icount / single TCG，同一诊断镜像 | 120 秒诊断期限内未形成有效样本对，FAIL | `artifacts/v01-diagnostic-icount/result.json` |

单线程 wallclock 的一次 CPU1 准备阶段约 5.226 ms，SHA 阶段约 0.079 ms；多线程对照的候选准备阶段约 9.117/10.146 ms。因此现有证据不足以把失败归结为 SHA 或单线程 TCG。当前尚未进一步区分候选枚举、观测/合法性检查、首次代码翻译和宿主调度各自的成本，不能宣称已定位最终根因或修复预算问题。

icount 中两节点均完成普通文件探针和学习机制初始化，各有 1 个已验证侧、1 个被排除侧、2 个持久归档，训练标签为 0；它证明能够推进到回放路径，不能证明训练、有效样本对或 wallclock 预算通过。120 秒是本次诊断时限，现有 CI 时限仍为 600 秒。

`verify_domains.py` 新增 `--tcg-threads single|multi` 供上述对照，默认仍为 single；拒绝 multi 与 icount 组合。CI 的 wallclock 配置和所有拒绝条件保持不变。

## 接下来的关闭条件

1. 将 `next_locked` 的准备区间继续细分为目标/观测、合法候选、CandidateSet 构造等；核对 CPU0 网络片段的逐步支出，区分算法成本与模拟/宿主延迟。
2. 对确认的超长工作做有界分段或性能修复，保持实际计费、归属和失败隔离；同源码镜像重跑双节点 wallclock，不能靠放宽预算或更换时钟宣称修复。
3. 独立核对被排除候选侧的原始归档与完整学习判定器，再推进有效配对及全域数据覆盖。
4. 实现完整 1.3 用例判定器与文件系统故障矩阵后，才更新对应验收状态。

所有本次 QEMU 进程均已退出；身份保存在源码目录外，含开发私钥的镜像和证据保留在忽略的 `artifacts/` 下。
