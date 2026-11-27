# V0.20 G4 归档复验

本次复验以 `0d38261105a0f764ce46db231f41585a5fee1f73` 为基线，盘点于 2026-11-27 UTC。
覆盖表的 127 个稳定 ID 与强制证明清单逐项对齐，现有主题覆盖为 FIXTURE 44、HOST 71、GAP 12，
覆盖表引用的源文件路径均可访问。G4 的 262 条 ID／类别组合包含 RUNTIME_QEMU 127、STATIC_EL1 51、
MODEL_CHECK 84。G5 在这组要求上增加 26 条 ARCH_A53，共 288 条组合。
[覆盖表](v020-acceptance-coverage.md) · [强制证明清单](../../tools/v0199-required-proof-inventory.json)

## 归档检查范围

本地 `artifacts/` 的一次扫描检查 5,249 个文件，另检查下载的 14 个 GitHub ZIP 内 860 个成员。
这个范围内发现冻结运行清单、Verdict v4 候选和按证明键归档的证据清单各 0 份。
4 个本地 JSON 文档未能按单个严格 JSON 解析，其中没有冻结清单标记。工具报告跳过的流日志、
容器和超限文档。覆盖报告、构建 `source-manifest.json`、guest 串口结果和 GitHub 任务结论
分别保留其原有含义。

按完整基线 SHA 查询 GitHub Actions 时返回 0 条运行。所见 V0.20 分支最新四条成功运行属于
`5e27954`，共有 16 个上传项，本次下载其中 11 个构建或机制证据 ZIP。另检查 `911e4fe` 的
ABI3 工作流中 3 个归档（256 MiB、1 GiB、epoch-disk）。14 个下载文件均匹配 GitHub 返回的
SHA-256。剩余上传项仅核对元数据。所有这些运行均按各自 SHA 记录。
[生产机制](https://github.com/cyllor/CyxiaOS/actions/runs/45926533268) · [固定控制](https://github.com/cyllor/CyxiaOS/actions/runs/45926533202) · [快照组件](https://github.com/cyllor/CyxiaOS/actions/runs/45926533184) · [双架构机制](https://github.com/cyllor/CyxiaOS/actions/runs/45926533151) · [ABI3](https://github.com/cyllor/CyxiaOS/actions/runs/45874629310)

## 可进入正式场景准备的诊断产物

下列路径位于本地 `artifacts/v020-formal-prep.GuyiLf/`。每次诊断保留自己的 ELF 和取证范围。

| 运行材料 | 复验范围 | 仍缺少的正式场景 |
|---|---|---|
| `d01-paired/d01` 和 `d01-paired/d01-d11` | 四次启动的物理调度页及受保护留存页核出合计八份回执，两分支分别绑定决策、执行和观测。 | A05 的完整十五域矩阵和 A08 的冻结同种子初态、已签试验、完整奖励及计量窗口。D01 调度域与验收 ID SEC-D01 含义不同。 |
| `durable-fsync-integrated` | 原始串口帧确认 LSN 19、写序号 7；冷重开镜像摘要连续，缺 COMMIT 时拒绝且零写、零刷。参考日志摘要与归档记录匹配。 | A10 A/B 完整断点矩阵，SEC-F05/F06/F10 指定的组合及独立分类裁决。本次可复读的是归档帧、摘要和参考记录。 |
| `sustained-final-tree` | 使用原始 PMU trace 和停机内存页重放 8 个窗口、926 个区间、370 次授权，最大窗口上界 3,337,264 ns。 | A03 的两个生产大脑满载及先后关闭、恢复，整个生产启动至退出的计量。 |
| `signed-resident-pmu-1` 和 `signed-resident-pmu-2` | 两轮各复读四种串口生命周期。新卷与冷重开分别在确认 BootEpoch 1/2 后启动八角色，缺卷和空卷重开受保护。之前的失败归档保留。 | A01 的完整冷启动与故障矩阵，真实生产信任根、业务、服务授权和执行器覆盖。 |

## 正式缺口

- G0 待复审，G1 为 `NOT_READY`。签名生产配置和待审定 ABI、介质字段及正式环境仍需冻结。
- G4-QEMU 为 `NOT_RUN`。需要受信冻结运行清单及独立锚定摘要，绑定部署镜像、设计、规则／安全配置、
  种子、注入点及检查器身份。运行、静态 EL1 与模型检查须各由适用独立检查器生成正式 Verdict v4，
  并附匹配的逐证明证据清单及原始文件。
- G5-ARCH 为 `NOT_RUN`。另外需要锁定实体 Cortex-A53 平台及 26 项对应真机证明。
  [验收口径](../design/v0.20-native-local-system.md#7-验收与发布)

盘点工具只读访问本地目录和 ZIP 成员，并按输入列出运行清单及二进制记录的结构候选。正式裁决由
受信冻结清单、独立检查器和现有聚合验证器处理。

```sh
python3 -B tools/acceptance_coverage.py --strict --json
python3 -B tools/inventory_v0199_archives.py artifacts /path/to/downloaded-ci
PYTHONPATH=tools python3 -B -m unittest -v test_inventory_v0199_archives test_verify_v0199_verdicts
```
