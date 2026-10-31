# V0.13 A01 启动回归：独立来源验证

## 本次交付范围

本增量绑定四种原生启动回归的源码、镜像、输入、模型、构建工具、QEMU、启动参数、预启动配置注入、QMP 请求/回复和停止态内存采集。它不把四种回归等同于完整 A01 验收，也不改正式台账。

基础内核为 `09b5f54baf795097d80b1b8a960b391bcdb6ea57` 的安全启动实现。本次没有修改内核、CPU 预算、策略截止时间、模型或集群授权规则。

## 已执行的候选验证

- 候选提交：`a9add021a35c3f26746d510db612b9623e0c7632`。
- 候选树：`57f44548ef7eacc27583ef393fe110020ea00bb5`。
- CI 执行：<https://github.com/cyllor/CyxiaOS/actions/runs/41172261794>。
- CI 触发提交为 `aa9599167a3bdaaef635a32de88eacdb637561a1`，两个作业实际 checkout 上述候选；不能将触发提交误当成被测源码。
- 23 个启动/来源单元测试通过；包含既有 8 个解码测试与新增 15 个测试方法。
- 4 个固定反例确认旧判定器接受、新判定器拒绝：首份正常样本无模型 CPU、首份故障样本获得模型授权、保留字非零、损坏模型样本超过恢复 CPU 上限。
- 完整 tools 检查线通过。
- 固定 Rust 1.95.0、补丁版 QEMU 10.2.2、两节点镜像及 formatter 构建通过。
- normal、epoch-write、epoch-flush、model-corrupt 四种原生回归通过；全部回执在独立进程中重放通过。
- 同一构建的 A02 原生隔离回归通过。

原生归档 artifact ID 为 `13031229926`，ZIP SHA-256 为
`3dc68d9ce722be8012731247f1b3a57cd89f09cf968e4bcfddd7df321526c146`。
宿主测试归档 artifact ID 为 `13031333489`，ZIP SHA-256 为
`e05283abedf5c76cf28feaa37acfa6b61de08d23af7c96e284517812ff4a5214`。
归档保留期为 30 天，不宣称永久保存。

## 代码入口

| 文件 | 职责 |
| --- | --- |
| `tools/verify_v13_boot_recovery.py` | 两份终态样本独立校验，冻结事实一致，控制 EL0 自检终态与预算检查 |
| `tools/verify_v13_boot_receipt.py` | 固定来源验证器，验证启动参数、工具修订、受限 QMP 协议和停止态采集 |
| `tools/run_v13_boot_evidence.py` | 复用原有原生 runner，封存构建输入、工具、模型并独立重放；失败保留原始记录 |
| `tools/test_verify_v13_boot_receipt.py` | 异常样本、伪造/缺失 QMP、越界路径、重复回复及不完整矩阵的负面测试 |
| `.github/workflows/v13-boot-provenance.yml` | 宿主反例/工具测试与原生构建/运行并行；合入后 checkout 当前提交而非旧候选 |

## 运行方式

沿用 `tools/build_unified.py --selftest` 生成的正常双节点构建及既定工具链，不重新定义构建契约。`BUILD` 指构建目录，`FORMATTER` 指该工具链生成的 prototype-disk，`QEMU_SOURCE` 指可信、固定补丁的 QEMU 源码目录，`OUT` 必须是尚不存在的输出目录。

```sh
python3 -B -m unittest discover -s tools -p 'test_verify_v13_boot*.py' -v

python3 -B tools/run_v13_boot_evidence.py \
  --build "$BUILD" --output "$OUT" \
  --formatter "$FORMATTER" \
  --qemu "$QEMU_SOURCE/build/qemu-system-aarch64" \
  --qemu-source "$QEMU_SOURCE" --timeout 60

python3 -B tools/verify_v13_boot_receipt.py \
  --matrix "$OUT" --source-root "$PWD" \
  --qemu-source "$QEMU_SOURCE"
```

单场景重放使用 `--receipt "$OUT/normal"` 代替 `--matrix`。验证器不导入或执行归档提供的 Python 文件，也不允许回执选择可信源码或可执行程序。

## 判定边界

成功输出的 `native_execution_verified=true` 仅表示该固定四场景回归的构建/启动/采集来源经本地可信验证器复核；它不是硬件签名、远程证明或对任意宿主的运行真实性保证。输出始终保持：

```json
{
  "native_acceptance_status": "NOT_RUN",
  "runtime_truth_attested": false,
  "full_v13_acceptance": false
}
```

生产者的 `PASS` 布尔值不会成为授权条件。工具文件仅作为身份材料保存，所有验证代码来自调用者选择的源码目录。正常/模型失败场景还核对磁盘持久 BootEpoch；存储失败场景不把未确认 epoch 猜测为已分配。

原始记录采用事后本地来源审计：QMP 记录不是 QEMU 签名。样本时序、停止状态和精确物理地址必须成立；不声称 QMP 自身能抵抗恶意宿主伪造。

## 尚未关闭的工作

完整 A01 仍需逐条对照正式用例完成受审查的接纳适配器与运行专属台账，覆盖所需故障子场景，审核正常启动四核/EL0-EL1建立以及失败时无新授权的完整证据。不能只修改状态字符串以宣布通过。

本增量不关闭 A03–A16、T/E、18 动作族、文件格式故障矩阵，也不修复或隐藏全域回放的其他失败。默认 `docs/implementation/v13-requirements.json` 保持原状态。
