# V0.20 G4 归档复验

本次复验以 `0d38261105a0f764ce46db231f41585a5fee1f73` 为基线，盘点于 2026-11-27 UTC。
覆盖表的 127 个稳定 ID 与强制证明清单逐项对齐，当次主题覆盖为 FIXTURE 44、HOST 71、GAP 12，
覆盖表引用的源文件路径均可访问。G4 的 262 条 ID／类别组合包含 RUNTIME_QEMU 127、STATIC_EL1 51、
MODEL_CHECK 84。V0.20 以这组证据作为标准验收要求。另行发起的 G5 实体平台验收增加 26 条 ARCH_A53，共 288 条组合。
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

盘点工具只读访问本地目录和 ZIP 成员，并按输入列出运行清单及二进制记录的结构候选。正式裁决由
受信冻结清单、独立检查器和现有聚合验证器处理。

```sh
python3 -B tools/acceptance_coverage.py --strict --json
python3 -B tools/inventory_v0199_archives.py artifacts /path/to/downloaded-ci
PYTHONPATH=tools python3 -B -m unittest -v test_inventory_v0199_archives test_verify_v0199_verdicts
```

归档验证默认使用 G4-QEMU 的证明集合。输出中的 `required_gate` 指明退出状态采用的门槛。

```sh
python3 -B tools/verify_v0199_verdicts.py \
  --manifest "$FROZEN_RUN_MANIFEST" --manifest-sha256 "$AUTHENTICATED_RUN_SHA256" \
  --evidence-root "$VERDICT_ARCHIVE" --output "$REPORT_PATH"
```

## 三类证据复验

| 证明类别 | 用例 | 本地观测 | 正式验收尚缺 |
| --- | --- | --- | --- |
| `RUNTIME_QEMU` | SEC-D08 | 同一签名测试卷在关闭 FLUSH 时拒绝可写挂载，设备记录零读、零写、零刷盘。开启 FLUSH 后冷重开确认 BootEpoch 2。 | 冻结运行清单和正式装载配置 |
| `RUNTIME_QEMU` | A10、SEC-F05 | 两组原生冷恢复均核对 BootEpoch 1→2、写序号 7、LSN 19 和持久收据。原始 QMP、串口、停机内存页与盘面可离线复核。 | 完整断电点、损坏拒绝及通用文件服务矩阵 |
| `STATIC_EL1` | SEC-P11、SEC-S09 | 对链接 ELF 核对 16 个异常向量、两处 `VBAR_EL1` 写入及 288 字节整数异常栈帧。 | 指令陷入与 AArch32 拒绝、ABI 写回范围和运行上下文 |
| `STATIC_EL1` | SEC-M08、A06 | 当前常驻和冷重开 ELF 的 FP 指令与上下文保存／恢复子检查通过。 | 冻结 ELF 上 ASID、TLB 和撤销路径的静态断言 |
| `MODEL_CHECK` | H04、H05 | 独立判定器分别匹配 1,872 条队列状态路径和 40,570 条单动作裁决路径。 | 更广的交错、真实业务执行、归档持久性和冻结输入 |

覆盖表中 10 组已有宿主子场景共复跑 43 项测试。127 个 ID 各自有证据路径，当前归档仍缺经认证的运行清单及正式 Verdict v4。G0 待复审，G1 为 `NOT_READY`，G4 为 `NOT_RUN`。[现行覆盖表](v020-acceptance-coverage.md)

[SEC-D08 检查器](../../tools/verify_v0199_d08_flush.py) · [FSYNC 冷重开检查器](../../tools/verify_v0199_a10_fsync.py) · [EL1 异常向量检查器](../../tools/check_v0199_el1_vectors.py) · [H04 判定器](../../tools/check_v0199_h04_model.py)

## 块设备、收据与裁决格式

- SEC-D12 的 AArch64 可写 scratch 路径在启用队列前拒绝只读设备，并且只协商 `VERSION_1` 和 `FLUSH`。在锁定四核 QEMU 上，拒绝的只读盘零 I/O。可写对照完成签名测试卷的 BootEpoch 1。链接 ELF 核对 `FEATURES_OK` 回读至队列启用的顺序。[驱动入口](../../kernel/src/arch/aarch64/scratch_blk.rs) · [静态检查器](../../tools/check_v0199_virtio_blk_admission.py)
- SEC-F12 的独立判定器核对 150 条有界路径。每条路径在一组持久票据满时调用 `FileReadService` 完成十次逐次确认的易失写，并核对另一组和恢复查询，以及跨块收据与索引的 ACK 闭包。生产多组接线、并发和实际持久提交待验证。[F12 判定器](../../tools/check_v0199_sec_f12_model.py)
- Verdict v4 的 Rust 编解码与 Python 归档解析器已按安§0.9 对齐。参考集包含十条合法原因向量以及 127 个稳定 ID 的 262 条 G4 记录。按证明键排序的参考记录共 83,840 字节，Rust 与 Python 得到相同 SHA-256。变更过版本、ID、检查器、状态原因及证据字段的异常样本会被拒绝。[Verdict v4 编解码](../../crates/kernel-core/src/security/verdict_v4.rs) · [参考向量](../../tools/fixtures/v0199-verdict-v4.tsv)

当前 G4 正式归档仍待冻结运行清单和各用例的正式裁决。D12 的网卡与 RNG 部分及 F12 的生产执行证据仍待交付。
