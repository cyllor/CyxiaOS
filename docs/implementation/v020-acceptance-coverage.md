# V0.20 验收覆盖矩阵说明（127 个稳定 ID）

**状态：仅覆盖映射（coverage mapping）。全部 127 项稳定 ID 的原生验收判定保持 NOT_RUN；
G0 待复审、G1=NOT_READY、G2/G3 未运行、G4-QEMU/G5-ARCH=NOT_RUN。
本文与配套工具不声称任何 ID PASS；宿主测试与原生机制夹具证据均为部分覆盖，
原生夹具 PASS ≠ G4 验收（安§7.6、设计§7 同口径）。**

配套工具：`tools/acceptance_coverage.py`（人工核定数据表，确定性输出，无 cargo/QEMU 依赖）。
完整逐 ID 矩阵由该工具生成：

```bash
python3 -B tools/acceptance_coverage.py            # Markdown 矩阵 + 统计
python3 -B tools/acceptance_coverage.py --json     # 机器可读 JSON
python3 -B tools/acceptance_coverage.py --strict   # 证据路径缺失即失败
```

## 1. ID 提取来源

127 个稳定 ID 全部从以下两处提取，无缺失、无臆造 ID：

- `docs/design/baselines/v0.19.9-implementation-spec.txt`（V0.19.9 正式 Word 全页文本归档）：
  - 主§11.1（L4840 起）：A01–A11、A15–A16 共 13 项 A 类回归（A12–A14 已删除，不复用）。
  - 主§11.2（L5083 起）：H01–H06 共 6 项 AI 决策权限回归。
  - 主§11.3（L5184 起）：E01–E08、E13–E15 共 11 项实现边界回归（E09–E12 已删除，不复用）。
  - 主§11.5（L5315）：验收基线口径——84 项 SEC 单域 + 13 项 J 跨域 = 97 项安全；
    A13/E11/H6 共 30 项独立回归；总 127 个稳定 ID。
  - 安全附编六专项验收表：SEC-P01～13（L8626 起）、SEC-F01～13（L8944 起）、
    SEC-M01～15（L9319 起）、SEC-N01～16（L9668 起）、SEC-D01～14（L10159 起）、
    SEC-S01～13（L10511 起）。13+13+15+16+14+13 = 84。
  - 安§7.3 必测交错调度矩阵（L10956 起）：J01–J13 共 13 项跨域联合用例。
  - 安§7.4 强制证明矩阵（L11133 起）：每 ID 的 RUNTIME_QEMU/STATIC_EL1/MODEL_CHECK/ARCH_A53
    类别归属；安§7.6（L11299）：127 项均 NOT_RUN。
- `docs/design/v0.20-native-local-system.md` §7（L80–92）：同口径 127 ID 与 G0–G5 门槛状态；
  快照新增断言建立独立需求追溯、保留原 ID，不得以旧测试 PASS 冒充新断言通过。

注意：仓库根 `CyxiaOS-architecture-review-coverage.json` 的 A01/S01 等条目属于旧架构评审
命名空间（P0–P4 阶段场景），与本次 127 稳定 ID 无关，未复用。

## 2. 映射方法与状态规则

每个 ID 映射到三类既有证据之一（取最强类别，全部为**部分覆盖**）：

| 状态 | 含义 |
|---|---|
| FIXTURE | 存在原生 QEMU 机制夹具证据（可伴随宿主证据）：`kernel/src/arch/aarch64/v0199_*.rs` 门控自检、`smp.rs` fixed_cpu0_fixture、boot/selftest 故障探针，及 `tools/verify_smp.py`、`verify_v0199_cpu0_roles.py`、`verify_v0199_eight_packages.py`（bringup）、`verify_v0199_advice_e2e.py`、`verify_v0199_epoch_disk.py`、`verify_v16_a10_matrix_v4.py`、`verify_native_net.py`、`verify_v13_tcp.py`、`boot_reboot_contract.py` 等校验器 |
| HOST | 仅宿主测试证据：`crates/*/tests/`、内联 `#[cfg(test)]` 模块、`tests/host/*.rs` harness（经 `tools/host_prototype_library.py` 对 prototype rlib 编译） |
| GAP | 未发现任何演练该 ID 主题的测试/夹具 |

证据路径均经存在性核验（工具 `--strict` 通过）；高频引用的测试函数名经 grep 逐一确认。
映射按**主题**而非测试名：`kernel-core/src/security/{file,memory,network,device}.rs` 的内联
`sec_*` 测试沿用 V0.19 六专项编号，与 V0.19.9 稳定 ID 不同名同义者按主题归位
（例如旧 `sec_m08_stale_tlb_generation_not_an_ack` 主题是 TLB ACK 校验，归 SEC-M04 证据，
而非 SEC-M08 的 ASID/FP-SIMD 主题；旧 `sec_n07_oversized_payload...` 是超长载荷拒绝，
与 SEC-N07 的密钥日志探测主题无关，后者仍为 GAP）。

### 口径限制（影响证据强度判定）

1. `tests/host/page_*` 用例运行的是 **x86_64 生产页表/别名代码**的宿主适配
   （`crates/arch-x86_64/src/space.rs` 等），不是 AArch64 页表/TLB 证据。
2. TLS 证据全部为**宿主 rustls 夹具握手**（`net-transport/tests/fixtures` 测试证书）；
   `verify_native_net.py`/`verify_v13_tcp.py` 均诚实报告 `tls_verified=false`。
3. `kernel-core/src/security/network.rs` RateLimiter 为遗留宿主契约模型；
   权威生产额度账本指定为 `net-transport::admission::Admission`（原生部署接线未完成）。
4. 原生夹具均标注 `production_wiring=false` / `production_isolation_verified=false`：
   advice-e2e 为 glue（advice intake 直调 Pair、决策在 EL1 glue 构造、执行器为内存设备）；
   bringup PMU 为机制夹具+测量范围；epoch-disk 为跨进程机制取证。均非生产接线、非 G4。
5. `file_auth_v3.rs`（ADMIT v3/COMPLETE v1，12 项内联测试）、`file_format_v1.rs`
   （v1 格式化器，11 项内联测试）、`policy_lock_v0199.rs`（计量脚手架，实测 12 项内联测试）
   均为**契约层宿主测试**，原生 EL1 接线/G1 锁链冻结明确未完成。
6. 生产挂载仍为 V0.18 v2 介质；prototype 的 journal/immutable/storage 测试演练 v2 宿主模型，
   与 V0.19.9 v1 基础介质 + FileServiceRequest v4/Reply v3 授权链存在不兼容差异（G1 待冻结）。

## 3. 覆盖统计（工具实测输出）

总计 127：**HOST=71，FIXTURE=44，GAP=12**。

| 族 | 项数 | HOST | FIXTURE | GAP | GAP ID |
|---|---:|---:|---:|---:|---|
| SEC-P 进程 | 13 | 5 | 7 | 1 | P11 |
| SEC-F 文件 | 13 | 8 | 3 | 2 | F07、F12 |
| SEC-M 内存 | 15 | 7 | 6 | 2 | M11、M12 |
| SEC-N 网络 | 16 | 10 | 2 | 4 | N07、N09、N10、N13 |
| SEC-D 设备 | 14 | 11 | 1 | 2 | D08、D10 |
| SEC-S 系统调用 | 13 | 9 | 3 | 1 | S10 |
| J 跨域 | 13 | 8 | 5 | 0 | — |
| A 回归 | 13 | 2 | 11 | 0 | — |
| E 回归 | 11 | 8 | 3 | 0 | — |
| H 回归 | 6 | 3 | 3 | 0 | — |

- 安全 97 项（84 SEC + 13 J）：HOST=58，FIXTURE=27，GAP=12。
- 回归 30 项（A13 + E11 + H6）：HOST=13，FIXTURE=17，GAP=0。
- **全部 12 个 GAP 都落在 84 项 SEC 单域安全集内**；J 与 A/E/H 均有至少部分证据。
- 没有任何 ID 达到完整验收覆盖：FIXTURE 仅机制夹具范围，HOST 仅契约/模型层。

## 4. 阻断 G4 的关键 GAP（12 项，按影响排序）

1. **SEC-N09 / SEC-N10 / SEC-N13 —— SYN 防洪与可用性负载整体缺失（最高优先）**
   全仓库无 SYN-ACK 令牌/16 桶/challenge ACK 机制（grep `syn_cookie|syn_bucket|challenge_ack`
   零命中），§13.8 冻结环境可用性负载（N10-B 100 源 W≤300ms、N13-A/B W≤600ms、
   ≥95/100 成功率、逐桶滑窗包络）无任何夹具。N13 属 MODEL_CHECK 强制类别。
   网络防洪验收轨道整体未起步。
2. **SEC-M11 / SEC-M12 —— A53 无 PAN 复制窗口与应急栈机制缺失**
   无 EL1 误引用用户 VA 的 copy 窗口/临时映射测试（M11），无 SP_ELx guard fault/
   每 CPU emergency 栈切换/scratch 转存嵌套机制或测试（M12，全仓库搜索仅无关 sp_el0 读取）。
   两者属 STATIC_EL1 强制类别（M12 另涉 ARCH_A53），是内存安全架构证明的硬缺口。
3. **SEC-P11 —— WFI/WFE/CTR_EL0/AArch32 陷入处理未实现未测**
   `exceptions.rs` 无 WFI/AArch32 处理；无 ELR+4 合法陷入、yield/只读模拟、
   AArch32 拒绝、保存帧不泄漏测试。
4. **SEC-S10 —— 查询不可区分性未测**
   无测试断言"不存在对象 vs 真实无权对象"跨权限返回相同外部拒绝；
   cap 查找拒绝错误 holder 但从未比较两种情形（防对象存在性探测）。
5. **SEC-F07 / SEC-F12 —— 文件并发/配额两个主题无演练**
   D04 档位切换×fsync 并发（事务不可拆、元数据闭包）无测试；
   单组 8 持久票据满仅拒本组、≥9 次易失 WRITE 不占票据、其他组/恢复继续无测试
   （收据存储仅扫描类测试）。
6. **SEC-D08 / SEC-D10 —— 设备边界门存在但未测**
   无 FLUSH 拒绝可写 mount 的生产门已存在（`driver-virtio/src/block.rs:49`、
   `block/batched.rs:54`），但测试夹具恒提供 FLUSH，拒绝路径零演练；
   SPI 无进展 999/1000 屏蔽/安静恢复与特殊 ID 不错误 EOI（原生屏蔽路径在 smp.rs、
   driver-gicv2 acknowledge/end）均未测。
7. **SEC-N07 —— 密钥/报文日志探测无断言**
   无"关键秘密不存在于日志或 AI 可读快照"的测试；tls_duplex 的 TestSecret KeyLog
   仅用于伪造测试记录，方向相反。

## 5. GAP 之外的结构性薄弱点（同样阻断 G4，不得因"有覆盖"误判）

- **全部 13 项 J 跨域用例无真实原生多域交错**：宿主 `integration_tests.rs`（j01–j12）
  文件头明确声明不构成安全验收；现有夹具只覆盖单域腿（smp drain、epoch-disk 守恒、
  A10 掉电矩阵、advice-e2e 单族因果链）。J13 的双脑私有模型/端点/工作区原生隔离、
  D12 授权路径与真实 source_role/epoch/snapshot/hash 检测无命名测试。
- **RECOVERY_REQUIRED/EIO 判定缺失**：crates 中无 `RECOVERY_REQUIRED` 符号；
  A10-B、SEC-F05/F09、J05 的"最新代不可证明→拒绝挂载/不分配 BootEpoch/不修改磁盘"
  B 侧判定未作分离原生裁决（宿主 fail-closed 拒绝存在）。
- **RecoveryProof v2 仅存在于规范**（SEC-S11 降级模式，代码零命中）；
  **task_join 在代码库中不存在**（SEC-P07 的无权 join 拒绝无从演练）。
- **policy_lock 为计量脚手架**（SEC-S13/A11）：模块头明示生产 try_lock 机制/DAIF 强制
  待 G1 冻结；无原生 ≤5μs/≤50μs 实测、500/1000ms 截止与竞争失败链测试。
  缺实测不得 PASS（安§7.4/主§3.2 口径）。
- **控制预算全负载窗口原生 PMU 实测未闭合**（A03）：bringup 阶段补丁 QEMU PMU 取证
  为机制范围；双脑满载先后关闭/恢复的端到端 ≤70ms/100ms 计量未演示。
- **8 个真实 EL0 角色生产服务与 0x50/0x41 SVC 生产 in-vector 接线未闭合**：
  advice-e2e 为 glue 夹具（production_wiring=false），影响 A05 完整 15×15×2 矩阵、
  H02 拒绝+回退全链、J10 代际切换竞态等的生产级证据。
- **TLS 常量与规范分歧**（SEC-N11）：宿主实现握手超时 30s（规范 3s）、空闲 60s
  （规范 30s/300s 双限）；无 slowloris/16645B 记录/TIME_WAIT 满测试；
  SEC-N12 缺 CCS 合法窗口、降级注入、证书超限与最后 KeyUpdate 预留夹具。
- **FileServiceRequest v4/ADMIT v3 原生 EL1 接线、格式化器 native 启动接线、
  FrameMeta 通用分配器整合、local-echo 启动部署**均未完成（设计§6 门槛清单），
  SEC-F 族宿主契约证据不能替代原生运行证据。
- 已删除 ID（A12–A14、E09–E12、T01–T20）不得复用；`tools/verify_v16_a12.py` 等
  为历史 V16 校验器，不属于本次 127 ID 验收。

## 6. 诚实性声明

- 127 个 ID 全部定位到定义与原文行号，无未能定位的 ID。
- 证据函数名以 grep 实测为准；个别条目仅引用到文件级（该文件含相关主题测试，
  未逐函数穷尽核验），已在矩阵中保留文件路径供复核。
- 一处命名陷阱已登记：`process.rs` 的 `sec_p07_exiting_cannot_take_new_references`
  测试名与规范 SEC-P07 主题不符（实为退出引用主题），已按主题归入 SEC-P05 证据。
- 设计§6 称 policy_lock "13 项宿主测试"，实测内联 `#[test]` 为 12 项；以实测为准。
- 本矩阵不判定 RUNTIME_QEMU/STATIC_EL1/MODEL_CHECK/ARCH_A53 任何证明类别；
  类别归属见安§7.4 强制证明矩阵。G4-QEMU 须 G0/G1 完成且 127 项各自规定的强制类别
  全部 PASS；当前 G1=NOT_READY，两阶段均 NOT_RUN，状态不因本矩阵改变。

## 7. 第九波契约补全注记（T10 同步，2026-11-25，进行中、未提交）

**计数重跑结果（T10 实测）**：`python3 -B tools/acceptance_coverage.py` 在 HEAD 711c21a
及含第九波工作区改动的树上输出均为 **HOST=71，FIXTURE=44，GAP=12**，`--strict` PASS。
计数未变的原因：工具是**人工核定数据表**（ROWS），第九波新增契约测试的证据路径尚未由
工具所有者登记入表；T10 不拥有该工具，**未编辑工具**，仅在此登记差异。

第九波工作区已落地（未提交、进行中）的 GAP 主题宿主契约测试，待工具所有者核定后
应把对应 ID 从 GAP 改登记为 HOST（部分覆盖），并附下列证据路径：

| GAP ID | 新证据（工作区，未提交） | 新增测试数（实测 diff） |
|---|---|---:|
| SEC-M11 | crates/kernel-core/src/security/memory.rs#sec_m11_*（软件 PAN 复制窗口） | 7 |
| SEC-M12 | crates/kernel-core/src/security/memory.rs#sec_m12_*（应急栈/guard/嵌套） | 8 |
| SEC-P11 | crates/kernel-core/src/security/process.rs#sec_p11_*（WFI/WFE/CTR_EL0/AArch32 陷入） | 10 |
| SEC-S10 | crates/kernel-core/src/security/syscall.rs#sec_s10_*（查询不可区分性） | 8 |
| SEC-D08 | crates/kernel-core/src/security/device.rs#v0199_sec_d08_*（可写 mount FLUSH 门） | 4 |
| SEC-D10 | crates/kernel-core/src/security/device.rs#v0199_sec_d10_*（SPI 风暴屏蔽/安静恢复/特殊 ID） | 4 |
| SEC-F07 | crates/kernel-core/src/security/file.rs#v0199_sec_f07_*（档位×fsync 并发） | 5 |
| SEC-F12 | crates/kernel-core/src/security/file.rs#v0199_sec_f12_*（分组票据/配额） | 5 |
| SEC-N07 | crates/net-transport/src/tls.rs#n07_key_material_never_reaches_key_log_or_diagnostics | 1 |

尚未落地：SEC-N09/N10/N13（SYN 防洪与可用性负载，network.rs 仅新增 sha2 import，
契约疑似编写中）。**即使全部登记，GAP 12→3 也只是覆盖类别变化（GAP→HOST），
127 项原生验收判定仍全 NOT_RUN，HOST/FIXTURE 均不构成 PASS。**

§5 结构性薄弱点中两条已被第九波工作区改动触及（同样未提交、仅契约层）：
「RecoveryProof v2 仅存在于规范（代码零命中）」→ 新增
crates/kernel-core/src/security/recovery_proof_v2.rs（32 项测试，原生 EL1 接线明确
LATER）；「TLS 常量与规范分歧（握手 30s）」→ HANDSHAKE_TIMEOUT_MS 已改 3_000 并加
编译期 pin（空闲双限等其余 reconciliation 以 T5 最终落地为准）。§4/§5 的其余描述
仍按 HEAD 已提交状态有效。

## 8. 正式证据归档

安§7.4 对 127 个稳定 ID 要求 127 份 `RUNTIME_QEMU`、51 份 `STATIC_EL1` 和 84 份 `MODEL_CHECK`，
G4 共 262 份。G5 在同一证据集上另核对 26 份 `ARCH_A53`。正式发布还须核实 G0/G1 完成及冻结清单的签发权限。
[归档复验记录](v020-g4-archive-recheck.md) · [实体平台取证交接](v020-a53-platform-handoff.md)

收到已认证的运行清单、清单摘要和原始归档后，按 G4 范围检查完整性。汇总按证明类型输出 PASS、FAIL、NOT_RUN
以及非法归档计数。缺证据时保留 NOT_RUN，证据对象的身份、字节数和 SHA-256 均由汇总器复核。

```sh
python3 -B tools/verify_v0199_verdicts.py --scope g4 \
  --manifest "$FROZEN_RUN_MANIFEST" --manifest-sha256 "$AUTHENTICATED_RUN_SHA256" \
  --evidence-root "$VERDICT_ARCHIVE" --output "$REPORT_PATH"
```

两个可独立重放的子检查为 A06/SEC-M08 的 ELF 指令检查和 H05 的有界决策与发布检查。子检查报告记录实际输入与
工具摘要，待有权判定器与其余必需证据共同出具正式 Verdict。

```sh
python3 -B tools/check_v0199_el1_fp.py --elf "$KERNEL_ELF" --elf-sha256 "$KERNEL_SHA256" \
  --objdump-sha256 "$OBJDUMP_SHA256" --output "$STATIC_REPORT_DIR"
cargo build --locked --offline -p cyxia-kernel-core --example v0199_h05_model_check
target/debug/examples/v0199_h05_model_check > "$OBSERVED_TSV"
python3 -B tools/check_v0199_h05_model.py --observed "$OBSERVED_TSV" \
  --harness target/debug/examples/v0199_h05_model_check --output "$MODEL_REPORT_PATH"
```
