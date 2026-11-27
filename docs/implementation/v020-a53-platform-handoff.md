# Cortex-A53 实体平台取证交接

本交接用于单独发起的 G5-ARCH 实体平台验收。V0.20 标准验收使用 Cortex-A53 QEMU 的 G4-QEMU。[V0.20 验收约束](../design/v0.20-native-local-system.md#7-验收与发布)

平台锁由有权操作者事先认证。校验器核对原始清单字节的 SHA-256 和归档文件，再把锁定的 CPU、RAM 与设备记录和 DTB 对照。输出 `STRUCTURE_VALID` 代表结构和文件绑定通过，`ARCH_A53` 仍为 `NOT_RUN`。实体发布还需 G4-QEMU 通过，并审查锁定板卡、勘误适用性、逐核寄存器读回和 26 项实体证明。 [V0.19.9 §11.5、安§7.2 与安§7.4](../design/baselines/v0.19.9-implementation-spec.txt#L5315)

## 已认证清单

| 字段 | 内容 |
|---|---|
| `schema`、`source` | `cyxia-a53-platform-lock/v1`、`physical-board` |
| `source_commit` | 构建对应的完整 40 位小写十六进制 Git 提交 |
| `board` | `vendor`、`model`、`serial`、`soc`、`dt_compatible`，以及 `pcb_revision` 或 `silicon_revision`。`dt_compatible` 为 DTB 根节点首项兼容标识 |
| `firmware` | 已锁定固件或 BSP 原件的文件记录 |
| `boot_image` | 原生 AArch64 内核 ELF 原件的文件记录。此摘要对应 Verdict v4 的 `binary_hash` |
| `dtb` | 板卡实际启动使用的 DTB 原件的文件记录 |
| `raw_capture` | 保留原始字节的板卡采集文件记录 |
| `cpus` | 按零开始连续编号的 `{index,mpidr_el1,midr_el1}` 数组，字段均为 JSON 整数。MIDR 核对 Arm implementer `0x41` 与 Cortex-A53 part `0xd03`，MPIDR affinity 和 DTB 中启用的 CPU 对照。DTB 头部的 `boot_cpuid_phys` 与采集编号 0 的 MPIDR affinity 一致 |
| `ram` | DTB 启用的 RAM 区间 `[[base,bytes], ...]`，按基地址升序 |
| `devices` | `{node,compatible,driver}` 数组，节点为 DTB 绝对节点名。`driver` 含 `id`、`version`、`artifact` 文件记录。静态链接的驱动可引用内核 ELF |

每个文件记录包含归档内相对 `path`、长度 `bytes` 和 64 位小写十六进制 `sha256`。校验以只读方式打开普通文件。相对路径逐级以目录描述符打开。DTB、采集、ELF 的读取上限分别为 2、32、128 MiB，清单读取上限为 256 KiB。

## 板卡采集原件

交接工具直接保留采集方输出的记录。字段之间使用单个空格，每行以 LF 或 CRLF 终止。身份行各一条，每个启用 CPU 各一条读取记录。完整采集可同时保存其他输出。

```text
CYX_A53_BOARD <board.serial>
CYX_A53_SOURCE <source_commit>
CYX_A53_FIRMWARE <firmware.sha256>
CYX_A53_IMAGE <boot_image.sha256>
CYX_A53_DTB <dtb.sha256>
CYX_A53_CPU <decimal index> <0x + 16 lowercase MPIDR_EL1 digits> <0x + 8 lowercase MIDR_EL1 digits>
```

采集方保留真实寄存器读取与同次启动的镜像、DTB、固件关联见证。已知 QEMU virt 的 DTB 会被拒绝。板卡来源认证、寄存器读取的真实性和每项证明判定由独立的签发及原生采集流程提供。

```sh
python3 -B tools/verify_v0199_a53_handoff.py \
  --manifest "$A53_LOCK_MANIFEST" \
  --manifest-sha256 "$AUTHENTICATED_A53_LOCK_SHA256" \
  --evidence-root "$A53_ARCHIVE"
```

成功退出码为 0，结构、摘要或原件不符时退出码为 1。宿主合成用例使用 `PYTHONPATH=tools python3 -B -m unittest tools.test_verify_v0199_a53_handoff`。

`MIDR_EL1` 的实现者和部件字段用于核对 A53 型号。DTB `boot_cpuid_phys` 核对采集逻辑核 0 的 MPIDR affinity，完整启用核集合与 DTB CPU 节点的 `reg` 同时对照。 [Arm Cortex-A53 TRM](https://documentation-service.arm.com/static/6040c321ee937942ba301626) · [DTB 格式](https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html)

## 物理 Verdict 归档

冻结运行清单的每个实体证明条目携带 `platform_lock_sha256`，`binary_hash` 对应平台锁中的 `boot_image`。
每组 `ARCH_A53` 的证据清单同时携带 `run_id`、`test_id`、`proof_class`、`platform_lock_sha256`、`raw_capture_sha256` 和规范排序的 `files`。
归档汇总先核对实体平台原件，再校验 26 个证明键是否绑定到同一平台锁和内核。执行证据仍由各用例的独立判定器提供。

```sh
python3 -B tools/verify_v0199_verdicts.py --scope g5 \
  --manifest "$FROZEN_RUN_MANIFEST" --manifest-sha256 "$AUTHENTICATED_RUN_SHA256" \
  --evidence-root "$VERDICT_ARCHIVE" --output "$REPORT_PATH" \
  --a53-manifest "$A53_LOCK_MANIFEST" --a53-manifest-sha256 "$AUTHENTICATED_A53_LOCK_SHA256" \
  --a53-evidence-root "$A53_ARCHIVE"
```
