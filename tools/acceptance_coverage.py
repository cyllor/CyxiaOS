#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V0.20 验收覆盖矩阵（127 个稳定 ID）——仅覆盖映射，不构成任何 PASS 声明。

从人工核定（curated）的数据表确定性地输出 ID → 定义 → 覆盖状态 → 证据路径矩阵。
不运行 cargo/QEMU，不读取运行结果；所有 127 项原生验收判定保持 NOT_RUN。

ID 提取来源（唯一权威）：
  * docs/design/baselines/v0.19.9-implementation-spec.txt
      - 主§11.1 A 类用例（L4840 起）、§11.2 H01–H06（L5083 起）、
        §11.3 E 类用例（L5184 起）、§11.5 完成条件（L5315：84 SEC + 13 J = 97
        安全，A13/E11/H6 = 30 回归，总 127 个稳定 ID；已删除 A12–A14、
        E09–E12、T01–T20 不复用）。
      - 安全附编六专项验收表：SEC-P01～13（L8626 起）、SEC-F01～13（L8944 起）、
        SEC-M01～15（L9319 起）、SEC-N01～16（L9668 起）、SEC-D01～14（L10159 起）、
        SEC-S01～13（L10511 起）。
      - 安§7.3 必测交错调度矩阵 J01–J13（L10956 起）、安§7.4 强制证明矩阵
        （L11133 起）、安§7.6（L11299：127 项均 NOT_RUN）。
  * docs/design/v0.20-native-local-system.md §7（L80–92）：同口径 127 ID 与
    G0–G5 门槛状态。

覆盖状态定义（取最强证据类别，全部为部分覆盖）：
  FIXTURE —— 存在原生 QEMU 机制夹具证据（kernel/src/arch/aarch64/v0199_*.rs、
             smp.rs fixed_cpu0_fixture、boot/selftest 探针及 tools/verify_* 校验器；
             可伴随宿主证据）。机制夹具 ≠ G4 验收。
  HOST    —— 仅宿主测试证据（crates/*/tests、内联 #[cfg(test)]、tests/host  harness）。
  GAP     —— 未发现任何 exercising 该 ID 主题的测试/夹具。

重要口径说明：
  * kernel-core/src/security/{file,memory,network,device}.rs 内联 sec_* 测试沿用
    V0.19 六专项编号，与 V0.19.9 稳定 ID 不同名同义者按主题映射（如旧 sec_m08
    主题是 TLB ACK，归 SEC-M04 而非 SEC-M08）。
  * tests/host/page_* 用例运行的是 x86_64 生产页表/别名代码的宿主适配，不是
    AArch64 页表/TLB 证据。
  * TLS 证据全部为宿主 rustls 夹具握手；两个原生网络校验器均 tls_verified=false。
  * 原生夹具（smp/selftest/bringup/advice-e2e/epoch-disk）均诚实标注
    production_wiring=false / production_isolation_verified=false，非生产接线。

用法：
  python3 -B tools/acceptance_coverage.py            # 输出 Markdown 矩阵 + 统计
  python3 -B tools/acceptance_coverage.py --json     # 机器可读 JSON
  python3 -B tools/acceptance_coverage.py --family P # 只看某族
  python3 -B tools/acceptance_coverage.py --strict   # 证据路径缺失即失败
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BASELINE = "docs/design/baselines/v0.19.9-implementation-spec.txt"
DESIGN = "docs/design/v0.20-native-local-system.md"

# 族顺序与期望数量（84 SEC 单域 + 13 J 跨域 = 97 安全；A13 + E11 + H6 = 30 回归）
FAMILIES = [
    ("P", "SEC-P 进程安全（13）", 13, BASELINE + " 安§1 验收表 L8626–8745"),
    ("F", "SEC-F 文件安全（13）", 13, BASELINE + " 安§2 验收表 L8944–9110"),
    ("M", "SEC-M 内存安全（15）", 15, BASELINE + " 安§3 验收表 L9319–9445"),
    ("N", "SEC-N 网络安全（16）", 16, BASELINE + " 安§4 验收表 L9668–9935"),
    ("D", "SEC-D 设备安全（14）", 14, BASELINE + " 安§5 验收表 L10159–10300"),
    ("S", "SEC-S 系统调用安全（13）", 13, BASELINE + " 安§6 验收表 L10511–10730"),
    ("J", "J 跨域交错（13）", 13, BASELINE + " 安§7.3 矩阵 L10956–11095"),
    ("A", "A 单机/全模块回归（13：A01–A11、A15–A16）", 13, BASELINE + " 主§11.1 L4840–5082"),
    ("E", "E 实现边界回归（11：E01–E08、E13–E15）", 11, BASELINE + " 主§11.3 L5184–5272"),
    ("H", "H AI 决策权限回归（6）", 6, BASELINE + " 主§11.2 L5083–5183"),
]

EXPECTED_IDS = (
    ["SEC-%s%02d" % (f, i) for f, n in
     [("P", 13), ("F", 13), ("M", 15), ("N", 16), ("D", 14), ("S", 13)]
     for i in range(1, n + 1)]
    + ["J%02d" % i for i in range(1, 14)]
    + ["A%02d" % i for i in list(range(1, 12)) + [15, 16]]
    + ["E%02d" % i for i in list(range(1, 9)) + [13, 14, 15]]
    + ["H%02d" % i for i in range(1, 7)]
)

# 证据路径缩写
SEC = "crates/kernel-core/src/security/"
CP = "crates/kernel-core/src/control_plane/"
KCT = "crates/kernel-core/tests/"
PT = "crates/prototype/tests/"
TH = "tests/host/"
A64 = "kernel/src/arch/aarch64/"
DV = "crates/driver-virtio/src/"
NT = "crates/net-transport/src/"
CTT = "crates/cluster-transport/tests/"

# 核定数据表：(ID, 定义, 状态, 证据元组, 覆盖说明)
# 状态规则：有原生夹具证据 → FIXTURE；仅宿主证据 → HOST；无 → GAP。全部部分覆盖。
ROWS = [
    # ---------------- SEC-P 进程安全 ----------------
    ("SEC-P01",
     "未授权调用者/篡改包摘要 spawn 拒绝且线程槽/CPU/页零增量；校验 SPAWN_GROUP/bit0、SNAPSHOT_VIEW/bit28、EXECUTOR_RPC 类型/holder/目标代际，错种类/错组/域及旧 cap 拒绝",
     "FIXTURE",
     (SEC + "process.rs#sec_p01_unauthorized_package_and_caller",
      SEC + "cap_record_v3.rs", CP + "role_manifest_v0199.rs",
      A64 + "v0199_control_bringup.rs"),
     "未授权/篡改 spawn 拒绝与 cap 类型/holder/代际校验已覆盖；SPAWN_GROUP/bit0+EXECUTOR_RPC 完整矩阵与零 CPU/页增量端到端计账未覆盖；夹具仅 role7 快照视图 cap 断言"),
    ("SEC-P02",
     "同 request_id 100 次并发重试至多一个任务对象、同摘要同结果、冲突摘要拒绝；args 复制、初始 x0/x1/SP 及 x2–x30/FP/TPIDR 全 0，坏 args 长度不发布",
     "FIXTURE",
     (SEC + "process.rs#sec_p02_idempotent_retries_and_conflict",
      SEC + "syscall_v3.rs", SEC + "file_auth_v3.rs",
      SEC + "file_admission_flow_v1.rs", A64 + "v0199_control_bringup.rs"),
     "幂等重试/冲突摘要拒绝、args 复制与初始寄存器清零已覆盖（重试为串行非 100 路并发）；x2–x30/FP/TPIDR 全 0 依赖夹具/staging 断言"),
    ("SEC-P03",
     "64 线程满+64 待建满并加 AI 停用：普通创建背压，已建任务和恢复额度继续",
     "HOST",
     (SEC + "process.rs#sec_p03_capacity_and_no_hidden_slot",
      PT + "domain_tasks.rs", PT + "spawn_reservation.rs",
      TH + "ordinary_spawn_reservation_harness.rs"),
     "背压与独立恢复额度分别覆盖；64 线程满+64 待建满+AI 停用组合场景非单一测试"),
    ("SEC-P04",
     "旧 task/cap handle 在退出复用槽后使用全部旧代际拒绝；溢出槽永久停用",
     "FIXTURE",
     (SEC + "process.rs#sec_p04_stale_ticket_fails",
      CP + "task_admission.rs", "crates/contracts/tests/ids.rs",
      KCT + "service_restart.rs", A64 + "v0199_control_bringup.rs"),
     "旧代际拒绝与代际溢出 fail-closed 已覆盖；溢出槽永久停用与复用槽后旧 handle 竞态仅簿记/生命周期层；夹具 restart_each 拒绝旧代际"),
    ("SEC-P05",
     "task_exit 与跨核查询/IPC/缺页交错：无 UAF、无缺失完成、退出前不复用",
     "HOST",
     (SEC + "process.rs#sec_p05_exit_waits_for_refs_and_tlb",
      SEC + "integration_tests.rs#j02_exit_copyin_and_unmap_keep_original_receipt",
      SEC + "memory.rs", TH + "drain_custody_trace_harness.rs",
      TH + "child_exit_custody_harness.rs"),
     "退出托管/回执保留已覆盖；integration_tests 声明不构成原生交错，无真实跨核查询/IPC/缺页竞态"),
    ("SEC-P06",
     "DRAIN 与 spawn/迁移并行：从未在 C/T/Q 或 suspect/draining 核新运行",
     "FIXTURE",
     (SEC + "process.rs#sec_p06_no_control_or_draining_cpu",
      KCT + "control_plane.rs", CP + "cores.rs",
      A64 + "v0199_role_selftest.rs"),
     "C/T/Q 与 draining/suspect 排除经掩码与账本门覆盖；DRAIN 并行 spawn/迁移为模型非活竞态；夹具提供 CPU0-only 控制转与业务进度计数"),
    ("SEC-P07",
     "无权 task_join/D14 任意重启/离线配置重放/同代异 hash 配置拒绝；持久隔离跨启动保持",
     "HOST",
     (SEC + "offline_config_v1.rs", KCT + "service_restart.rs",
      KCT + "control_plane.rs", SEC + "durable_role_epoch_v0199.rs"),
     "离线配置重放/签名绑定与持久隔离已覆盖；task_join 在代码库中不存在，无权 task_join 与 D14 任意重启拒绝未测"),
    ("SEC-P08",
     "AI_DISABLED 下持续创建/退出与故障恢复：确定性令牌与预算运行，无模型等待",
     "FIXTURE",
     (SEC + "process.rs#sec_p08_no_ai_required_for_local_admission",
      SEC + "network.rs#sec_n08_no_model_is_needed_for_rate_limit_and_echo",
      CP + "fixed.rs", CP + "role_budget_v0199.rs",
      A64 + "v0199_control_bringup.rs"),
     "组件级无 AI 确定性已覆盖；无 AI_DISABLED 下持续创建/退出+故障恢复循环断言令牌/预算确定性；夹具含确定性 BudgetMeter 与 Recovery 预留"),
    ("SEC-P09",
     "恶意 ELF（重叠段、文件/内存长度倒置、非法权限、入口越界、篡改复制源）：受保护副本哈希/ELF 校验先拒绝，零 RUNNABLE、零越权页映射",
     "HOST",
     (KCT + "control_service.rs", KCT + "service_image.rs",
      KCT + "image_abi.rs", CP + "pie_image_v0199.rs"),
     "各类畸形 ELF 在解析/哈希阶段拒绝；零 RUNNABLE/零越权映射后果未端到端断言"),
    ("SEC-P10",
     "EL0 非 SVC 异常、DAIF/WFI/WFE/PMU 与 SError 归因：同步非法异常结束当前任务且保留在途义务；受限指令不能改特权状态；不可归因 SError 不伪作任务错误",
     "FIXTURE",
     (A64 + "v0199_control_bringup.rs", "tools/verify_smp.py"),
     "仅同步指令 abort 类（guard 页 PC 注入，V0199_RESTART_GUARD_FAULT、ESR/FAR 断言）；DAIF/WFI/WFE/PMU 受限指令归因与不可归因 SError 无测试"),
    ("SEC-P11",
     "WFI/WFE、CTR_EL0 及 AArch32 向量：合法陷入 ELR+4、yield/只读模拟；AArch32 拒绝；保存帧不泄漏",
     "HOST",
     ("tools/check_v0199_el1_vectors.py",),
     "链接 ELF 已核对低异常级 AArch32 向量各自的分流与整数异常帧布局。WFI/WFE、CTR_EL0、AArch32 拒绝及保存帧泄漏语义待验证。"),
    ("SEC-P12",
     "登记 PIE/ET_DYN 重定位、随机装载与跨启动地址分布：仅受限 RELATIVE 重定位、入口 RX、W^X 与 I-Cache 同步；CSPRNG 失败按安全模式处理",
     "FIXTURE",
     (CP + "pie_image_v0199.rs", A64 + "v0199_control_bringup.rs"),
     "RELATIVE-only 重定位、RX 入口、W^X 与 I-Cache 同步已覆盖；随机基址为调用参数，无跨启动地址分布与 CSPRNG 失败安全模式测试"),
    ("SEC-P13",
     "能力深链、伪造 handle、ADMIT 与撤销及审计满：祖先门原子关闭，门前拒绝、门后原义务收尾；撤销不因审计满阻断；cap 类型/holder/代际校验",
     "HOST",
     (SEC + "cap_record_v3.rs",
      SEC + "file_auth_context_v1.rs#gate_close_rejects_new_authorization_not_obligations",
      KCT + "grants.rs", KCT + "atomic_grants.rs"),
     "单层 cap 校验与门关闭语义已覆盖；无深层祖先链原子撤销、无审计满 vs 撤销测试（kernel-core 无 SecurityAudit 存储）"),
    # ---------------- SEC-F 文件安全 ----------------
    ("SEC-F01",
     "目录 cap 外路径、非法组件、超长路径：副作用前拒绝且未新建 inode 或块",
     "HOST",
     (SEC + "file.rs#sec_f01_rejects_escape_and_invalid_paths",
      SEC + "file_service_v4.rs", PT + "journal.rs", PT + "domain_storage.rs"),
     "逃逸/非法组件/超长拒绝与无磁盘副作用断言在契约+v2 宿主模型层覆盖；无原生 EL1 建 inode 前故障注入"),
    ("SEC-F02",
     "跨文件/组访问、伪造 cap、ADMIT 与撤销交错：重验/预留/受理同门，撤销前后线性化，无越权或 cap 槽泄漏",
     "HOST",
     (SEC + "file.rs#sec_f02_capabilities_do_not_cross_owner_or_rights",
      SEC + "file_auth_context_v1.rs", SEC + "file_auth_v3.rs",
      SEC + "cap_record_v3.rs", SEC + "file_mount_v1.rs"),
     "跨属主/伪造 cap 拒绝与 REVOKED 判定不登记已覆盖（单线程）；真并发 ADMIT↔撤销线性化与 cap 槽泄漏未交错演练"),
    ("SEC-F03",
     "已打开文件 unlink 返回 EBUSY；关闭后 inode 复用，旧代际 handle 永不访问新 inode",
     "HOST",
     (SEC + "file.rs#sec_f03_stale_inode_generation_rejected",
      PT + "domain_storage.rs", PT + "immutable_snapshots.rs"),
     "EBUSY 与旧 handle 代际栅栏在 v2 宿主模型跨重启覆盖；无原生运行时证明"),
    ("SEC-F04",
     "新扩展块跨目录复用、缓存驱逐后读取：新块清零，无旧文件尾数据",
     "HOST",
     (PT + "immutable_cow_audit.rs", PT + "immutable_snapshots.rs",
      PT + "domain_storage.rs"),
     "COW/GC/unlink/重启间块复用内容断言与零填充读计账已覆盖；驱逐缓存后读复用块断言无旧尾的命名场景未演练"),
    ("SEC-F05",
     "BEGIN/REDO/COMMIT/超级块每 FLUSH 边界断电：按 A10 A/B 分别判定，可证提交链恢复已确认 fsync，否则 RECOVERY_REQUIRED/EIO，未确认不虚报",
     "FIXTURE",
     (PT + "journal.rs", SEC + "recovery_v1.rs", SEC + "epoch_redo_v0199.rs",
      SEC + "boot_epoch_v1.rs", SEC + "file_format_v1.rs",
      A64 + "v0199_epoch_disk.rs", "tools/verify_v0199_epoch_disk.py",
      "tools/verify_v13_a10_faults.py", "tools/verify_v0199_a10_fsync.py"),
     "签名 scratch 卷已确认 FSYNC 的冷恢复可从 QMP、串口、停机页及盘面独立复核。完整 A10 A/B 断电点及 RECOVERY_REQUIRED/EIO 挂载拒绝矩阵待验证。"),
    ("SEC-F06",
     "COMMIT/分段 FSYNC 与 ACK 丢失、同键重试：每段前缀与收据同事務，最终 DONE 才承诺目标；UNKNOWN 查询不重做",
     "HOST",
     (SEC + "file.rs#sec_f06_lost_ack_preserves_id_and_rejects_new_body",
      SEC + "file_auth_v3.rs", SEC + "file_receipt_store_v0199.rs",
      PT + "immutable_snapshots.rs",
      SEC + "integration_tests.rs#j03_exit_does_not_cancel_unknown_fsync"),
     "同键重试/UNKNOWN 不重做与收据事务闭包已覆盖；多分段每段前缀+收据同事務、仅最终 DONE 承诺目标未端到端演练"),
    ("SEC-F07",
     "D04 档位切换与 fsync 并发：本事务不可拆，元数据完整闭包",
     "HOST",
     (SEC + "file.rs#v0199_sec_f07_midtransaction_gear_change_keeps_frozen_batch",
      SEC + "file.rs#v0199_sec_f07_background_batch_keeps_metadata_closure_whole"),
     "宿主契约测试检查切档保留已冻结批、FSYNC 顺序与元数据闭包。原生并发及落盘证据待验证。"),
    ("SEC-F08",
     "普通业务访问/删除 BootEpochStore 拒绝；格式、计数和恢复证据保持",
     "FIXTURE",
     (SEC + "file.rs#sec_f08_boot_epoch_store_is_not_ordinary_file",
      SEC + "boot_epoch_v1.rs", PT + "storage.rs", PT + "domain_storage.rs",
      A64 + "v0199_epoch_disk.rs", "tools/verify_v0199_epoch_disk.py"),
     "普通访问/删除拒绝、格式/CRC 与恢复证据保持已覆盖；计数经原生夹具 boot_store 断言"),
    ("SEC-F09",
     "新镜像、畸形目录/extent/ACL/索引及跨启动主体；注入已持久新代日志后最新超级块损坏/单份失效/同代异内容/高代有效记录：全量扫描拒绝畸形，RECOVERY_REQUIRED/EIO 不开放普通文件服务",
     "FIXTURE",
     (SEC + "file_format_v1.rs", SEC + "file_structure_v1.rs",
      SEC + "file_index_v0199.rs", SEC + "file_media_v0199.rs",
      SEC + "file_mount_v1.rs", PT + "storage.rs", PT + "journal.rs",
      A64 + "v0199_epoch_disk.rs", "tools/verify_v0199_epoch_disk.py"),
     "新镜像可写、畸形全扫描、损坏/分裂/分歧超级块已覆盖；显式 RECOVERY_REQUIRED/EIO 服务拒绝门与完整注入日志场景矩阵仅部分"),
    ("SEC-F10",
     "8MiB FSYNC 分段、配额耗尽、易失 WRITE 查询：≤128 home 块/段、中间 BOUND 最终 DONE、易失/持久键分离、UNKNOWN 不重做；固定 D03 档(4096,64)、专用组/主体、2048 脏页预留",
     "HOST",
     (PT + "domain_storage.rs", PT + "journal.rs",
      PT + "immutable_snapshots.rs", PT + "a10_cache_admission.rs",
      TH + "a10_write_backpressure_harness.rs"),
     "≤128 home 事务上限与 8MiB fsync 在 v2 宿主模型覆盖；精确 D03(4096,64) 档、专用组/主体、2048 脏页预留与冻结 WRITE+易失查询矩阵未按规范演示"),
    ("SEC-F11",
     "8 线程多流乱序、alloc_seq 跳号、退休后重放、重启/复用：alloc_seq=issued_hi+1、同键查重、连续退休、旧键不再执行；ADMIT v3/COMPLETE v1 负向矩阵与终态不可回退",
     "HOST",
     (SEC + "file_auth_v3.rs", SEC + "file_auth_context_v1.rs",
      SEC + "file_index_v0199.rs", SEC + "file_receipt_store_v0199.rs"),
     "终态/查重/退休/NO_EFFECT 证据规则单线程覆盖；8 线程乱序交错、并发 alloc_seq 跳号、退休后重放/重启未演练"),
    ("SEC-F12",
     "单组 8 持久票据满：只拒本组新持久票据；≥9 次易失 WRITE（逐次 ACK）不占持久票据，其他组/恢复继续",
     "HOST",
     (SEC + "file.rs#v0199_sec_f12_full_group_rejects_only_its_own_new_tickets",
      SEC + "file.rs#v0199_sec_f12_volatile_writes_never_consume_persistent_tickets",
      SEC + "file.rs#v0199_sec_f12_recovery_continues_while_group_is_full",
      "tools/check_v0199_sec_f12_model.py"),
     "有界模型核对满额组的隔离、实际 FileReadService 的逐次易失写确认，以及持久收据和索引的 ACK 闭包。生产多组接线、并发及落盘待验证。"),
    ("SEC-F13",
     "打开者阻止 unlink、共享目录耗尽、无权撤销：EBUSY；仅 holder/祖先或静态恢复角色撤销，真实引用终结才复用",
     "HOST",
     (PT + "domain_storage.rs",
      SEC + "file.rs#sec_f02_capabilities_do_not_cross_owner_or_rights",
      SEC + "cap_record_v3.rs", SEC + "file_auth_v3.rs", PT + "storage.rs"),
     "EBUSY 与 holder/恢复角色撤销门在契约层覆盖；共享目录耗尽与真实引用终结后复用未作运行时场景演练"),
    # ---------------- SEC-M 内存安全 ----------------
    ("SEC-M01",
     "未授权映射内核/CACP/他任务私有页：完全拒绝，无映射页表项",
     "HOST",
     (SEC + "memory.rs#sec_m01_never_map_private_kernel_or_control_frames",
      KCT + "frames.rs"),
     "契约层拒绝内核/控制/外国帧；无原生 QEMU 负向映射运行证明零 PTE 创建"),
    ("SEC-M02",
     "请求可写且可执行页并执行数据段：不创建 W+X 映射，执行违反权限被捕获",
     "FIXTURE",
     (SEC + "memory.rs#sec_m02_wx_and_aliases_rejected",
      KCT + "service_image.rs", KCT + "image_abi.rs",
      TH + "page_map_batch_cases.rs", A64 + "boot.rs"),
     "W+X 创建各处拒绝；原生夹具（WX_SELFTEST_OK）捕获的是对 RX 的数据写而非指令执行违反——执行数据段陷入未演示；page_* 为 x86 宿主"),
    ("SEC-M03",
     "匿名页反复跨任务分配与释放：每次新所有者看到零内容",
     "FIXTURE",
     (SEC + "memory.rs#sec_m03_unzeroed_user_frame_cannot_be_published",
      KCT + "frames.rs", "crates/kernel-core/src/frame_meta_v0199.rs",
      "kernel/src/selftest/memory.rs"),
     "复用清零含原生启动自检（check_pages 脏页→回收→重分配读全零）与宿主全池搅动覆盖；非原生多任务 EL0 运行时证明"),
    ("SEC-M04",
     "unmap 丢失一个 TLB ACK：页隔离不复用，未证静默核不转属",
     "HOST",
     (SEC + "memory.rs#sec_m04_missing_tlb_ack_retains_frame",
      SEC + "integration_tests.rs#j01_spawn_drain_and_tlb_ack_is_not_free",
      TH + "page_mapping_revoke_cases.rs"),
     "缺 ACK 保留经每 CPU 掩码 Shootdown 契约覆盖；无原生 TLB 故障注入，静默核仅掩码建模；旧 sec_m08 测试主题为 ACK 校验归此"),
    ("SEC-M05",
     "syscall 复制中并发 unmap/重映射：不越界，失败 EFAULT 且原副作用可查",
     "HOST",
     (SEC + "memory.rs#sec_m05_checked_user_copy_range",
      SEC + "integration_tests.rs#j02_exit_copyin_and_unmap_keep_original_receipt",
      TH + "file_input_access_harness.rs"),
     "边界拒绝与原错误/回执可查已覆盖；syscall 复制进行中并发 unmap/重映射未演练（单线程属主门模型）"),
    ("SEC-M06",
     "DMA 正在引用页时普通回收：保留 pin 与占用至真实完成/可靠复位",
     "HOST",
     (SEC + "memory.rs#sec_m06_dma_and_pin_survive_cpu_unmap",
      SEC + "integration_tests.rs#j04_memory_pressure_never_releases_unknown_device_dma",
      "crates/kernel-core/src/frame_meta_v0199.rs#exact_layout_and_full_1g_conservation_with_retained_dma",
      DV + "block/batched.rs", PT + "domain_storage.rs"),
     "pin/占用保留至完成/ACK 在契约+模拟驱动层覆盖；文档明示无物理 DMA 停止证据；可靠复位路径仅 j05 Unknown"),
    ("SEC-M07",
     "匿名内容哨兵和 D03 缓存压力并行：匿名内容不丢，清洁缓存可回收",
     "HOST",
     (SEC + "memory.rs#sec_m07_no_reuse_before_all_references_release",
      PT + "native_a09_memory.rs", PT + "a10_cache_admission.rs",
      PT + "domain_storage.rs"),
     "真实清洁缓存替换下匿名内容保持在宿主 A09/A10/D03 模型覆盖；非原生 QEMU 压力运行"),
    ("SEC-M08",
     "ASID/任务代际过期访问及 FP/SIMD 切换：旧访问拒绝，寄存器无跨任务泄漏",
     "FIXTURE",
     (A64 + "smp.rs", A64 + "v0199_control_bringup.rs", "tools/verify_smp.py", "tools/check_v0199_el1_fp.py"),
     "原生抢占核对 GPR、TPIDR 和 32 个 SIMD 寄存器，静态核对链接 ELF 的 FP 指令位置。过期 ASID 与任务代际访问拒绝待验证。"),
    ("SEC-M09",
     "稀疏地址空间申请耗尽页表页配额：页表页按组计账并在新建前拒绝；不挪控制/恢复页",
     "HOST",
     (SEC + "memory.rs", KCT + "frames.rs",
      TH + "page_space_reuse_cases.rs",
      "crates/kernel-core/src/frame_meta_v0199.rs"),
     "页表页保护、有界表容量与控制/恢复不可变已覆盖；AArch64 按组页表页配额计账与新建前拒绝未演示；page_* 为 x86 宿主"),
    ("SEC-M10",
     "EL0/每 CPU 执行、IRQ、应急栈 guard：EL0 归因退出，EL1 不触故障栈，入口 scratch 检查，无相邻污染",
     "FIXTURE",
     (A64 + "exceptions.rs", A64 + "boot.rs", A64 + "smp.rs"),
     "EL0 归因退出（exception_dispatch_primary fail-stop）与启动栈 guard 故障（GUARD_OK）原生演练；每 CPU 应急栈、入口 scratch 检查、相邻污染断言缺失"),
    ("SEC-M11",
     "A53 无 PAN 下 EL1 误解引用用户 VA，TLB 热/冷命中与嵌套异常：非 copy 窗口不可访问，临时映射回收后不可再访问，无悬空映射",
     "HOST",
     (SEC + "memory.rs#sec_m11_out_of_window_copy_fail_closed",
      SEC + "memory.rs#sec_m11_teardown_invalidation_before_unpin_no_dangling"),
     "宿主契约核对临时 copy 窗口、绑定 CPU/身份、拆除与无效化顺序。原生 EL1 接线和运行证据待验证。"),
    ("SEC-M12",
     "SP_ELx 同步 guard fault、SP 余量不足、入口嵌套：切每 CPU emergency 栈，记录 fail-stop/UNKNOWN，不在故障栈压帧，scratch 转存完成前拒绝可恢复嵌套、两帧不互覆",
     "HOST",
     (SEC + "memory.rs#sec_m12_emergency_switch_closes_admission_no_faulted_frames",
      SEC + "memory.rs#sec_m12_scratch_transfer_gates_nesting"),
     "宿主契约核对应急栈状态、异常准入及帧转存后的嵌套边界。实际 EL1 入口切栈、布局静态证据和原生运行待验证。"),
    ("SEC-M13",
     "BBM、ASID 复用、fixmap、I/D 缓存和远核 ISB：逐核读回/ACK、旧页不复用、远核未确认不执行；唯一 TRANSITION、未 ACK 不释放；QEMU 单独不 PASS",
     "FIXTURE",
     (TH + "page_alias_counter_cases.rs", TH + "page_map_batch_cases.rs",
      A64 + "v0199_control_bringup.rs", A64 + "smp.rs"),
     "唯一 TRANSITION/未 ACK 不释放簿记在 x86 宿主覆盖；夹具 seal_page 真实 BBM+全局 TLBI；A53 读回-ACK/fixmap/I-D 缓存/远核 ISB 与跨锁窗口并发注入未演示"),
    ("SEC-M14",
     "物理承诺耗尽、ref/pin 溢出/下溢、秘密页回收：拒绝不 panic、计数不回绕、秘密页清零且 ACK 后复用；FrameMeta 262144 条、10MiB 永久页预扣不重复计账、表自身页不可回收、账本守恒",
     "HOST",
     ("crates/kernel-core/src/frame_meta_v0199.rs", KCT + "frames.rs",
      TH + "page_alias_counter_cases.rs", TH + "native_private_clear_harness.rs"),
     "全 262144 条账本、10MiB 预扣不双计、守恒与耗尽拒绝已覆盖（18 项内联测试）；秘密页清零+ACK 后复用仅近似；无专门 ref/pin 溢出/下溢测试"),
    ("SEC-M15",
     "随机 EL0/EL1 映射和内核可写别名注入：RX 内核页不可写、不存在可写线性别名；ASLR/KASLR 仅影响合法布局",
     "FIXTURE",
     (A64 + "boot.rs", TH + "page_map_batch_cases.rs",
      TH + "page_space_reuse_cases.rs",
      SEC + "memory.rs#sec_m02_wx_and_aliases_rejected"),
     "RX 内核不可写在启动原生陷入（WX_SELFTEST_OK）；可写别名拒绝在 x86 宿主别名核；随机映射注入、全别名扫描与 ASLR/KASLR 合法布局检查缺失"),
    # ---------------- SEC-N 网络安全 ----------------
    ("SEC-N01",
     "错误公钥指纹/签名/禁用套件/旧 TLS 版本：全部拒绝，不能访问只读回声",
     "HOST",
     (SEC + "network.rs#sec_n01_wrong_pin_or_suite_refuses_service",
      CTT + "tls.rs", NT + "tls.rs"),
     "错误 pin 与 TLS1.2 拒绝已覆盖（契约模型+真实宿主 rustls 握手）；禁用套件/旧版本线路注入未测；无原生 TLS"),
    ("SEC-N02",
     "尝试 0-RTT 及恢复会话：握手路径拒绝，不隐式恢复权限",
     "HOST",
     (SEC + "network.rs#sec_n02_early_data_and_resumption_refused",
      NT + "tls.rs"),
     "标志级契约拒绝+配置强制（Resumption::disabled、enable_early_data=false）；无测试实际尝试 0-RTT/恢复握手"),
    ("SEC-N03",
     "洪泛>32 源、4 待认证与 16 活动配额：有界背压，既有连接与恢复保留进度",
     "HOST",
     (NT + "admission.rs#sec_n03_four_pending_slots_are_bounded_and_released_on_reject",
      NT + "tls_duplex_tests.rs",
      SEC + "network.rs#sec_n03_handshake_capacity_not_unbounded",
      SEC + "integration_tests.rs#j06_handshake_flood_cannot_change_memory_owner"),
     "4 待认证/16 活动/32 源配额与背压已演练；无>32 源洪泛带既有连接/恢复进度负载"),
    ("SEC-N04",
     "源表项欠额后模拟离开再返回：桶补满且无在途即可 LRU 驱逐，无需静默≥1s；欠额源不可借驱逐重置 burst",
     "HOST",
     (NT + "admission.rs", SEC + "network.rs#sec_n04_burst_not_reset_by_repeating_source"),
     "LRU 资格（无在途+补满门）、时钟回拨阻断与 burst 不重置已覆盖；显式离开-返回+无静默≥1s 计时场景未演练"),
    ("SEC-N05",
     "回声长度 4097、尾字节、截断、未知 opcode：拒绝，无业务写入、无未证完成",
     "HOST",
     (NT + "echo.rs", SEC + "network.rs#sec_n05_echo_rejects_tail_or_opcode",
      NT + "tls_duplex_tests.rs"),
     "帧化子集（4097/尾字节/截断/未知 opcode/短输出不变更）宿主覆盖；无未证完成另经 service_tests 退休证据"),
    ("SEC-N06",
     "认证后请求资源授权/任务提交/计划发布：拒绝，认证仅获只读服务权限",
     "HOST",
     (NT + "echo.rs#sec_n06_no_task_or_resource_opcode",
      SEC + "network.rs#sec_n06_service_right_is_read_only_by_construction",
      NT + "tls_duplex_tests.rs"),
     "opcode 白名单在解析与分派层拒绝任务/资源/授权 opcode；构造上不存在此类 op。主题接近完整（仍宿主层）"),
    ("SEC-N07",
     "密钥材料与报文正文经遥测/日志探测：关键秘密不存在于日志或 AI 可读快照",
     "HOST",
     (NT + "tls.rs#n07_key_material_never_reaches_key_log_or_diagnostics",),
     "宿主测试确认固定测试身份的双向 TLS 配置关闭 key log，检查诊断字段。原生全链遥测和 AI 可读快照待验证。"),
    ("SEC-N08",
     "丢包/重传/断链+关闭 AI 与 D10 档位切换：本地服务正常，真实 read-only echo 数据一致",
     "FIXTURE",
     (NT + "admission.rs#sec_n08_restart_never_drops_unknown_pending_or_resets_tokens",
      NT + "service_tests.rs",
      SEC + "network.rs#sec_n08_no_model_is_needed_for_rate_limit_and_echo",
      CTT + "network.rs",
      SEC + "integration_tests.rs#j11_readonly_service_restart_leaves_old_dma_inflight",
      "tools/verify_native_net.py"),
     "丢包/重传/断链+AI-off 独立性+重启令牌保留分别覆盖；原生校验器 --disconnected 负向运行；无组合 AI-off+D10 档位切换原生场景；echo 一致性仅宿主往返"),
    ("SEC-N09",
     "伪造源 SYN 洪泛（含仅 4 源填槽攻击）：伪造源只消耗 16 桶中对应桶的 SYN-ACK 令牌，未完成握手 0 NetConn/0 D12 source，同桶碰撞不越界且无持久副作用",
     "HOST",
     (SEC + "network.rs#sec_n09_cookie_roundtrip_all_mss_tiers",
      SEC + "network.rs#sec_n09_generation_bound_rotation_and_consume"),
     "宿主契约核对 cookie 有效性、代际轮换与一次性消费。生产协议栈中的桶隔离及真实准入计账待验证。"),
    ("SEC-N10",
     "A：32 源每 0.9s 发起超额只判安全；B：预填 32 源+背景 5/s+新合法源 5/s（100 不同源）：W≤300ms、每源≤1 全局≤4、≥95/100 次 2s 入表且 5s 认证，真实关闭/TIME_WAIT/LRU 证据完整",
     "HOST",
     (SEC + "network.rs#sec_n10a_overload_only_safe_bounded_backpressure",),
     "宿主契约检查安全背压和连接表界限。完整原生负载、认证完成与真实关闭及回收证据待验证。"),
    ("SEC-N11",
     "slowloris/慢读、最大 16645B 记录、TIME_WAIT 满：独立重组缓冲不死锁；1s 记录/3s 握手/30s 空闲/300s 绝对；Tx≤16KiB，终态/真实 DMA 后释放",
     "HOST",
     (CTT + "tls.rs", NT + "tls_duplex_tests.rs", NT + "service_tests.rs"),
     "重组背压/不死锁与终态/DMA 静默后释放已覆盖；常量与规范分歧（握手 30s vs 3s、空闲 60s vs 30s/300s）；无 slowloris、16645 记录、TIME_WAIT 满测试"),
    ("SEC-N12",
     "KeyUpdate、越长记录、证书超限、CCS 与降级：合法窗口 CCS 丢弃其余拒绝；记录/证书/KeyUpdate 边界；发送密钥记录/字节双计数及最后 KeyUpdate 预留边界，超限前更新或关闭",
     "HOST",
     (NT + "tls_duplex_tests.rs", CTT + "tls.rs"),
     "KeyUpdate 碎片/非法值与损坏吊销已覆盖；无 CCS 合法窗口、降级注入、证书超限、发送密钥双计数与最后 KeyUpdate 预留夹具"),
    ("SEC-N13",
     "N13-A/B 及同桶/链路饱和，冻结桶映射：按§13.8 冻结源数/时间表、RTT≤20ms 零注入丢包、W≤600ms 与真实关闭；A/B 各≥95/100 次 5s 内完成；逐桶滑窗包络",
     "HOST",
     (SEC + "network.rs#syn_bucket_clock_rollback_rejects_and_preserves_debt",
      SEC + "network.rs#sec_n13_challenge_generation_isolation_and_release"),
     "宿主契约检查时间回退、额度保留和连接代际隔离。原生冻结场景中的可用性、关闭回收与逐桶计量待验证。"),
    ("SEC-N14",
     "校验和错误、VLAN、非法目标 MAC、禁用卸载：拒绝 malformed 帧，设备未协商卸载不得使用，软件计算 IP/TCP 校验和",
     "FIXTURE",
     (DV + "net.rs", "tools/verify_v13_tcp.py", "tools/verify_native_net.py"),
     "未协商卸载/mergeable 拒绝与原生软件校验和正确性有证据（validate_capture 逐帧校验）；无宿主测试注入校验和错误/VLAN/非法目标 MAC 帧验拒绝"),
    ("SEC-N15",
     "DRBG 重播种、Signer 伪造/重放、客户端认证前签名、离线轮换：仅 Verifier 授权预认证连接一次签名；旧身份撤销 1s 停新应用；无密钥泄露；失败停新认证；Signer 隔离夹具 16 jobs/s",
     "HOST",
     (CTT + "crypto.rs", NT + "tls.rs", CTT + "network.rs"),
     "签名伪造绑定与熵失败门已覆盖；无 DRBG 重播种、认证前签名、离线轮换/撤销≤1s、Signer 16 jobs/s 与 N13 5 conn/s 测量"),
    ("SEC-N16",
     "D12 4/8 诱导、默认 16/绝对 32、档位切换：未离线预授权不降底线、不重置令牌、攻击建议无权限；安全脑 kind/target 来自登记快照，伪造高分不触发独立授权，SHADOW/无证据不得改参数",
     "HOST",
     (CP + "security_finding.rs", CP + "registered_gate_v3.rs",
      CP + "advice_ledger_v0199.rs",
      SEC + "integration_tests.rs#j10_ai_advice_cannot_become_publish_right",
      SEC + "network.rs"),
     "SHADOW/无证据不改参数、FindingDisposition 非 APPLIED、score/severity fail-closed 与建议无权限已覆盖；无 D12 4/8 诱导、离线预授权底线与伪造高分授权测试"),
    # ---------------- SEC-D 设备安全 ----------------
    ("SEC-D01",
     "普通 EL0 伪造 MMIO/IRQ/设备服务权限：访问拒绝、无设备副作用",
     "HOST",
     (SEC + "device.rs#sec_d01_unreserved_dma_or_credit_denied",
      SEC + "device.rs#sec_d07_irq_must_target_healthy_business_only"),
     "未预留 DMA/credit 与 IRQ 目标权限在契约层拒绝；无 EL0 伪造 MMIO 访问测试"),
    ("SEC-D02",
     "畸形 DTB/MMIO 重叠或 IRQ 无效：启动校验拒绝，不进入普通设备服务",
     "HOST",
     ("crates/platform-virt/tests/fdt.rs",
      "crates/driver-virtio/tests/pci_transport.rs"),
     "畸形 DTB/MMIO 重叠/无效 IRQ 启动校验在设备枚举前 fail-closed。主题接近完整（宿主层）"),
    ("SEC-D03",
     "描述符链越界、旧 submit_id 或重复完成：拒绝且 pin/credit 不二次释放",
     "HOST",
     (SEC + "device.rs#sec_d02_bounded_descriptor_chains",
      SEC + "device.rs#sec_d03_duplicate_submit_is_not_a_second_lease",
      SEC + "device.rs#sec_d06_old_or_forged_completion_rejected",
      DV + "queue.rs", DV + "lib.rs"),
     "越界链、旧/重复 submit_id 与完成拒绝已覆盖；无二次 pin/credit 释放（另见 D09 隔离测试）"),
    ("SEC-D04",
     "I/O 超时与设备仍访问 DMA 页：页保留至可靠设备停止或真实完成",
     "HOST",
     (SEC + "device.rs#sec_d04_timeout_is_unknown_not_dma_release",
      SEC + "integration_tests.rs#j04_memory_pressure_never_releases_unknown_device_dma",
      DV + "block/batched.rs", DV + "rng/batched.rs", DV + "rng.rs"),
     "超时→Unknown、DMA 保留至可靠复位证明或真实完成。主题接近完整（宿主+模拟设备层）"),
    ("SEC-D05",
     "设备 fault/reset 与文件 fsync 并发：UNKNOWN 无成功 ACK；双超级块与提交链可证按 A10 恢复，否则 RECOVERY_REQUIRED/EIO；设备复位不构成持久成功证明",
     "HOST",
     (SEC + "integration_tests.rs#j05_fsync_unknown_and_device_reset_need_independent_proofs",
      SEC + "device.rs#sec_d05_reset_needs_reliable_proof",
      SEC + "recovery_v1.rs", SEC + "epoch_redo_v0199.rs",
      DV + "snapshot.rs"),
     "UNKNOWN 无成功 ACK、复位≠持久证明与双槽/提交链崩溃保留已覆盖；并发 fsync+fault 下完整 A10 恢复 vs RECOVERY_REQUIRED/EIO 判定未作单一场景演练"),
    ("SEC-D06",
     "DRAIN 中 IRQ 迁移并出现迟到中断：无新普通 IRQ 到 C/T/Q 或 draining 核",
     "HOST",
     (SEC + "device.rs#sec_d07_irq_must_target_healthy_business_only",
      SEC + "integration_tests.rs#j07_irq_change_cannot_route_to_draining_core",
      "crates/driver-gicv2/tests/route.rs"),
     "静态路由对 draining/healthy 掩码校验已覆盖；无 DRAIN 迁移中迟到中断动态测试"),
    ("SEC-D07",
     "通知 batch 中途变档及孤立请求：下批才变，孤立≤50μs 提交义务仍推进",
     "HOST",
     (SEC + "device.rs#sec_d08_lonely_chain_reaches_notification_deadline",
      DV + "queue.rs#first_deadline_sync_and_isolated_never_wait_for_threshold",
      DV + "queue.rs#version_is_frozen_at_actual_batch_and_completion_not_install",
      SEC + "integration_tests.rs#j08_network_batch_does_not_hold_lonely_virtqueue_request"),
     "孤立≤50μs 提交义务与中途批版本冻结均已演练。主题接近完整（宿主层）"),
    ("SEC-D08",
     "block 设备不支持 FLUSH 却请求可写 mount：拒绝可写配置，无法假冒持久性",
     "FIXTURE",
     ("tools/verify_v0199_d08_flush.py", DV + "block/batched.rs"),
     "锁定 QEMU 对同一已签名 scratch 卷切换 FLUSH 能力。缺 FLUSH 时拒绝可写挂载且零 I/O，恢复能力后冷重开推进 BootEpoch。范围为签名暂存路径。"),
    ("SEC-D09",
     "used.idx 跳跃>qsize、未提交 used.id、used.len 越过可写字节数：设备完成拒绝/隔离，无释放 pin 或解析未初始化 Rx 数据",
     "HOST",
     (DV + "lib.rs#malformed_head_and_index_are_rejected",
      DV + "lib.rs#invalid_used_length_quarantines_queue",
      DV + "lib.rs#idle_poll_quarantines_unsolicited_used_index",
      DV + "lib.rs#input_out_of_range_id_does_not_read_outside_pool",
      DV + "queue.rs#exact_capacity_and_malformed_used_quarantine",
      DV + "queue.rs#unsolicited_used_head_is_rejected_before_first_publication",
      DV + "net.rs", DV + "net/batched.rs"),
     "used.idx/used.id/used.len 违规拒绝或隔离；无 pin 释放、无未初始化 Rx 解析/投递。主题接近完整（宿主层）"),
    ("SEC-D10",
     "普通 SPI 无进展 999/1000 次每 100ms、特殊 ID 及 CPU0 隔离：达 1000 屏蔽，安静 1000ms+证明后恢复；特殊 ID 不错误 EOI",
     "HOST",
     (SEC + "device.rs#v0199_sec_d10_masks_at_1000_not_999",
      SEC + "device.rs#v0199_sec_d10_recovery_needs_quiet_and_supervisor_generations"),
     "宿主契约核对屏蔽阈值、安静期和恢复代际。实际 GICv2 路由、特殊 ID 和恢复证据待验证。"),
    ("SEC-D11",
     "virtio-rng 全零/重复块、无法重新建立熵：停止新认证/CSPRNG 重播/身份生成；本地既有完成和恢复继续",
     "HOST",
     (DV + "rng.rs", DV + "rng/batched.rs", NT + "tls.rs", CTT + "network.rs"),
     "静默/畸形设备原子失败与熵失败阻断新配对/重连已覆盖；无全零/重复块健康检测、CSPRNG 重播/身份生成停止断言与本地完成继续证明"),
    ("SEC-D12",
     "QEMU 固定 argv、逐位特性白名单及 FEATURES_OK 失败：只协商登记 bit，不接受旧 MMIO/卸载，失败停止设备准入",
     "FIXTURE",
     (DV + "lib.rs#invalid_mmio_and_unnegotiated_version_rejected",
      DV + "block/batched.rs#writable_attach_waits_for_features_ok_before_queue_enable_and_driver_ok",
      DV + "net.rs", "crates/driver-virtio/tests/pci_transport.rs",
      "tools/verify_native_net.py", "tools/verify_v13_tcp.py",
      "tools/check_v0199_virtio_blk_admission.py"),
     "签名 scratch 块路径的只读拒绝和 VERSION_1/FLUSH 白名单经 QEMU 与链接 ELF 核对。完整网卡、RNG 和旧版本路径仍待整体验证。"),
    ("SEC-D13",
     "短帧/virtio-net header/发送填充残留随机填充压力：DMA 读范围全部已初始化并按线长显式清零，无旧对象数据外泄",
     "HOST",
     (DV + "net.rs",
      DV + "queue.rs#release_clears_only_the_descriptor_owned_ranges"),
     "header 清零+精确线长+_owned 范围清零有证据；无最小帧填充零填充与随机填充/旧对象泄漏压力测试"),
    ("SEC-D14",
     "容量漂移、同时致命异常、CPU/DMA 无 ACK、复位超时：唯一 stop owner；100ms CPU/每设备期限；UNKNOWN 不释放 pin，不伪造 FLUSH",
     "HOST",
     (DV + "gpu.rs", DV + "block/batched.rs",
      SEC + "device.rs#sec_d05_reset_needs_reliable_proof"),
     "故障/超时隔离、无假成功/FLUSH 与原期限保持已覆盖；无容量漂移、唯一 stop owner 与同时致命异常测试"),
    # ---------------- SEC-S 系统调用安全 ----------------
    ("SEC-S01",
     "未知 x8 调用号、各调用参数保留位非法、地址长度/乘法溢出：副作用前拒绝内核状态不变；遍历 19 个调用号、新旧 ABI、0x32 头/逐项权限/对齐；cap 位校验",
     "FIXTURE",
     (SEC + "syscall.rs#sec_s01_unknown_syscall_and_overflow_rejected",
      SEC + "syscall_v3.rs", A64 + "v0199_role_selftest.rs",
      "tools/verify_v0199_cpu0_roles.py"),
     "解码阶段分发前拒绝已覆盖（19 调用号唯一性、旧 ABI/保留位、溢出矩阵）；内核状态不变未单独断言；0x32 逐项权限/对齐仅 validate_vector/j09 非全头+项扫描；夹具 SVC64 preflight 0–6"),
    ("SEC-S02",
     "另线程修改/撤映射 copyin 输入：只解析稳定副本，失败 EFAULT",
     "FIXTURE",
     (SEC + "syscall.rs#sec_s02_user_input_frozen_once",
      SEC + "integration_tests.rs#j02_exit_copyin_and_unmap_keep_original_receipt",
      "crates/arch-aarch64/src/mmu.rs", A64 + "v0199_role_selftest.rs"),
     "冻结副本语义+叶所有权证明已覆盖；无另线程并发修改/撤映射竞态；夹具 SVC copy 用例 7–10（仅自有可写叶通过）"),
    ("SEC-S03",
     "完成写操作后使输出 buffer 不可写：EFAULT 但同 request_id 查询到原完成；reply_cap<552 前置拒绝、copyout 失败保留队首、同 recv_seq 重试、DONE 丢回复、ACK 及旧 seq 拒绝、出队最多一次",
     "HOST",
     (SEC + "syscall.rs#sec_s03_output_fault_does_not_redo_commit",
      SEC + "ipc_receive_v3.rs", PT + "domain_ipc_receive_v3.rs"),
     "出队最多一次与故障后回执查询已覆盖（551 前置拒绝/队首保留/同 seq 重试/DONE 丢回复/ACK 幂等/旧 seq Stale）；完整跨权限场景为模型非原生"),
    ("SEC-S04",
     "AI/网络/业务伪造 submit_plan 或控制登记：全部 E_AUTH，不生策略版本/资源变化",
     "HOST",
     (SEC + "syscall.rs#sec_s04_only_publisher_can_submit_plan",
      SEC + "integration_tests.rs#j10_ai_advice_cannot_become_publish_right",
      SEC + "integration_tests.rs#j12_failed_boot_epoch_does_not_grant_new_publish_right",
      CP + "svc_bridge_v3.rs", CP + "registered_gate_v3.rs"),
     "E_AUTH+授权前不登记已覆盖（含固定 CPU0 发布者拒绝业务核）；网络/业务伪造 submit_plan 变体未分别演练"),
    ("SEC-S05",
     "伪造 report_result 及旧执行器代际：拒绝，无依赖开放/资源释放；逐 15 域真实执行者/对象绑定，EL1 域 0x43 拒绝、role12 仅 D04、role13 无回执权；D10 批量和回执仅 EL1；TLS 伪造 FETCH/REPORT 拒绝",
     "HOST",
     (SEC + "syscall.rs#sec_s05_old_executor_generation_cannot_report",
      CP + "apply_report_v1.rs", CP + "apply_work_v1.rs",
      SEC + "file_admission_flow_v1.rs", CP + "registered_gate_v3.rs"),
     "旧代际 E_STALE+执行器绑定+role12 门已覆盖；完整逐 15 域矩阵、role13 无回执权、D10 批量 EL1-only 与 TLS 伪造 FETCH/REPORT 未穷尽测试"),
    ("SEC-S06",
     "16 项 svc_submitv 含非法 op/重复 tag：执行前整体拒绝，零项投递",
     "HOST",
     (SEC + "syscall.rs#sec_s06_vector_format_invalid_is_whole_vector_failure",
      SEC + "integration_tests.rs#j09_invalid_readonly_vector_is_rejected_before_file_access",
      PT + "domain_tasks.rs"),
     "整批预检拒绝已覆盖；kernel-core 向量为 2 项——16 项规模零投递未在单一测试确认"),
    ("SEC-S07",
     "16 项合法向量中 1 项能力撤销 1 项超时：逐项结果隔离，其余正确 tag 与值",
     "HOST",
     (SEC + "syscall.rs#sec_s07_vector_tags_stable_and_single_item_does_not_cancel_peer",
      PT + "domain_tasks.rs"),
     "逐项隔离、tag 稳定、撤销 cap 与超时行为分别覆盖；16 合法+1 撤销+1 超时组合场景非单一测试"),
    ("SEC-S08",
     "AI 停机、完成队列已满、syscall 并发：确定性完成/恢复继续，先背压后接单",
     "HOST",
     (SEC + "syscall.rs#sec_s08_full_receipt_credit_causes_precommit_backpressure",
      CP + "registered_gate_v3.rs", CP + "control_rpc_v1.rs",
      SEC + "ipc_receive_v3.rs", TH + "preparation_admission_harness.rs"),
     "接单前背压与确定性恢复已覆盖（64 在途+1 冻结、恢复不可借用）；AI 停机+队列满+syscall 并发未组合"),
    ("SEC-S09",
     "SVC 返回 EL0、异步异常上下文切换与临时寄存器污染：仅写回 ABI 指定结果且不泄露 EL1 临时状态；正常 EL0 x1–x30、SP_EL0、TPIDR_EL0 保存语义不被破坏",
     "FIXTURE",
     (A64 + "v0199_control_bringup.rs", A64 + "v0199_role_selftest.rs", "tools/check_v0199_el1_vectors.py"),
     "链接 ELF 已核对 16 个异常向量的 x0–x30、ELR/SPSR 保存和恢复。现有夹具检查 TPIDR 与抢占恢复。运行时全部异常路径的写回范围与 SP_EL0 保存待验证。"),
    ("SEC-S10",
     "跨权限 task_query/file 查询同一不存在对象与真实无权对象：对外返回相同拒绝错误，非授权侧无法凭结果确认其他对象存在",
     "HOST",
     (SEC + "syscall.rs#sec_s10_absent_and_unauthorized_present_identical",
      SEC + "syscall.rs#sec_s10_task_query_and_file_stat_share_the_rule"),
     "宿主契约核对对象缺失和无授权的查询返回一致。原生 task_query 与文件请求的实际入口证据待验证。"),
    ("SEC-S11",
     "DENY 洪泛、组/管理/恢复槽满、消费者停摆、强制撤销：DENY 独立、新授权拒绝、撤销/隔离/必要完成继续、RecoveryProof 降级；接管不覆盖未确认槽；审计读取/ACK 验证真实 role11 与代际",
     "HOST",
     (SEC + "file_auth_context_v1.rs", CP + "control_rpc_v1.rs",
      SEC + "file_auth_v3.rs", SEC + "durable_role_epoch_v0199.rs"),
     "DENY 独立、槽满、门关闭与 role11 审计门已覆盖；RecoveryProof v2 降级模式仅存在于规范（代码零命中）；接管未确认槽保护仅部分"),
    ("SEC-S12",
     "双向 IPC 应答伪造与同请求不同代际：应答绑定内核端点真实 sender、request_id、service_gen 与目标任务/超时；ControlRPC 逐 op 角色/代际/序号/ACK 重放及旧封包拒绝；advice sidecar 关联及伪 COMPLETE 拒绝",
     "HOST",
     (SEC + "ipc_receive_v3.rs", CP + "control_rpc_v1.rs",
      CP + "advice_disposition_v1.rs", CP + "advice_ledger_v0199.rs",
      CP + "advice_envelope_v1.rs", PT + "domain_ipc_grants.rs",
      SEC + "file_auth_v3.rs"),
     "应答/sender/request_id/代际绑定与 ControlRPC 序号/ACK 已覆盖；完整 service_gen+目标任务+超时绑定矩阵与双向伪造未穷尽"),
    ("SEC-S13",
     "try_lock 竞争、IRQ-off 超限、500/1000ms 截止、寄存器图样：不持锁等待，≤5μs 尝试/≤50μs IRQ-off，超时保留原键；工作≤45μs、≤8 锁最深合法链与竞争失败链；FIFO 票门按序推进、45+5≤50μs 强制计量",
     "HOST",
     (CP + "policy_lock_v0199.rs", PT + "native_task_owner_gate.rs",
      KCT + "control_plane.rs", CP + "role_budget_v0199.rs"),
     "模块头明示生产 try_lock 机制/DAIF 强制待冻结——预算/秩/8 锁上限为脚手架断言（12 项内联测试）；无原生≤5μs/≤50μs 实测、500/1000ms 截止、寄存器图样泄漏与竞争失败链测试"),
    # ---------------- J 跨域交错 ----------------
    ("J01",
     "spawn 与 DRAIN、旧 CPU ACK 滞后（P+M+S）：无 C/T/Q 违规；预算不双记",
     "FIXTURE",
     (SEC + "integration_tests.rs#j01_spawn_drain_and_tlb_ack_is_not_free",
      SEC + "process.rs#sec_p06_no_control_or_draining_cpu",
      PT + "cores.rs", PT + "spawn_reservation.rs", A64 + "smp.rs"),
     "P+M 宿主账本+夹具 drain 门（STOPPED==14、无 C/T/Q 违规）已覆盖；S 预算双记仅预留守恒；无原生三域交错"),
    ("J02",
     "任务退出与 syscall copyin/unmap（P+M+S）：无 UAF；EFAULT 结果可查",
     "HOST",
     (SEC + "integration_tests.rs#j02_exit_copyin_and_unmap_keep_original_receipt",
      SEC + "process.rs#sec_p05_exit_waits_for_refs_and_tlb",
      SEC + "memory.rs#sec_m05_checked_user_copy_range",
      TH + "file_input_access_harness.rs", TH + "page_mapping_revoke_cases.rs"),
     "P+M 覆盖、EFAULT 经保留回执可查；S 侧仅宿主调度门；无原生退出/copyin/unmap 竞态下 UAF 证明"),
    ("J03",
     "任务退出与 FSYNC 分段 COMMIT、ACK 丢失、撤销交错（P+F+S）：PREPARED 与 EL1 ADMIT 线性化；NO_EFFECT 须权威；UNKNOWN 保持引用；原票据不重做、已证前缀保留、最终 DONE 才承诺目标、门后义务收尾",
     "HOST",
     (SEC + "integration_tests.rs#j03_exit_does_not_cancel_unknown_fsync",
      SEC + "file_auth_context_v1.rs", SEC + "file_auth_v3.rs",
      SEC + "file.rs#sec_f06_lost_ack_preserves_id_and_rejects_new_body",
      PT + "journal.rs", TH + "file_retry_harness.rs"),
     "PREPARED/ADMIT 线性化、UNKNOWN 保留、NO_EFFECT 与门后义务在宿主；原生 ACK 丢失/撤销交错未演练"),
    ("J04",
     "内存压迫与脏页回写/普通完成槽满（F+M+D）：不丢匿名/脏数据；保留完成 credit",
     "FIXTURE",
     (SEC + "integration_tests.rs#j04_memory_pressure_never_releases_unknown_device_dma",
      SEC + "memory.rs#sec_m06_dma_and_pin_survive_cpu_unmap",
      KCT + "frames.rs", PT + "native_a09_memory.rs",
      PT + "a10_cache_admission.rs", "tools/verify_v0199_epoch_disk.py"),
     "F+M+D 账本契约覆盖（夹具 FrameMeta dump 守恒）；无原生回写 vs 完成槽满竞态"),
    ("J05",
     "日志检查点/掉电与 block reset（F+D）：按 A10 A/B 分别判定；可证提交链恢复已确认 fsync 且 UNKNOWN 正确；最新代不可证明时 RECOVERY_REQUIRED/EIO，不开放普通文件、不分配 BootEpoch、不修改磁盘",
     "FIXTURE",
     (SEC + "integration_tests.rs#j05_fsync_unknown_and_device_reset_need_independent_proofs",
      SEC + "device.rs#sec_d05_reset_needs_reliable_proof",
      PT + "journal.rs", PT + "storage.rs", "tools/verify_v16_a10_matrix_v4.py"),
     "A/B 语义存在但未作分离原生判定；block reset+检查点掉电组合竞态仅宿主；原生 A10 矩阵校验器覆盖掉电侧"),
    ("J06",
     "连接洪泛与 net 设备 DMA 及 AI 停机（N+D+M）：TLS 完成仍推进；无超量分配",
     "HOST",
     (SEC + "integration_tests.rs#j06_handshake_flood_cannot_change_memory_owner",
      SEC + "network.rs#sec_n03_handshake_capacity_not_unbounded",
      SEC + "memory.rs#sec_m06_dma_and_pin_survive_cpu_unmap",
      SEC + "device.rs#sec_d01_unreserved_dma_or_credit_denied"),
     "N+D 洪泛/容量+M 所有权已覆盖；AI 停机腿仅经退休 ai-control-selftest（legacy-coreset）；无当前原生组合运行"),
    ("J07",
     "D06 仅在业务核迁路由且固定控制 CPU0（D+P+M）：迟到普通 IRQ 不进入 C/T/Q",
     "FIXTURE",
     (SEC + "integration_tests.rs#j07_irq_change_cannot_route_to_draining_core",
      SEC + "device.rs#sec_d07_irq_must_target_healthy_business_only",
      PT + "native_irq_sources.rs", PT + "native_replay_workloads.rs",
      PT + "domain_platform.rs", A64 + "smp.rs"),
     "D+P 路由守卫覆盖（夹具 IRQS 仅在 B 核）；M（内存压力下迟到普通 IRQ）未组合"),
    ("J08",
     "D11 batch 变档与 D10 发包积压（N+D）：无无限凑批等待、只改下批；D10 批量和回执仅 EL1；TLS Verifier/Signer/解析器伪造 FETCH/REPORT 拒绝；真实发送/完成仍计账",
     "HOST",
     (SEC + "integration_tests.rs#j08_network_batch_does_not_hold_lonely_virtqueue_request",
      SEC + "device.rs#sec_d08_lonely_chain_reaches_notification_deadline",
      PT + "domain_platform.rs", PT + "native_service_transport.rs",
      CP + "apply_report_v1.rs"),
     "无无限凑批等待+逐项结果已覆盖；D11 变档 vs D10 积压组合竞态与伪造 TLS FETCH/REPORT 未命名"),
    ("J09",
     "svc_submitv 混合法项+旧代际+非法 op（S+P+F）：非法 op 整批拒绝；合法项按项隔离",
     "HOST",
     (SEC + "integration_tests.rs#j09_invalid_readonly_vector_is_rejected_before_file_access",
      SEC + "syscall.rs#sec_s06_vector_format_invalid_is_whole_vector_failure",
      SEC + "syscall.rs#sec_s07_vector_tags_stable_and_single_item_does_not_cancel_peer",
      SEC + "syscall_v3.rs", SEC + "file_auth_context_v1.rs"),
     "整批拒绝+逐项隔离在宿主；旧代际项与合法项混合于原生 svc_submitv 未交错"),
    ("J10",
     "RuleProfile/模型代际切换与错误 AI 建议（S+全部）：ControlRPC 晋升/回退/许可/验证/候选、旧代际与副作用前审计门；无越权新计划；已受理义务保留；AI 无授权",
     "HOST",
     (CP + "control_rpc_v1.rs", PT + "model_bank.rs",
      PT + "domain_policy_model_change.rs", CP + "registered_gate_v3.rs",
      PT + "learning_governance.rs",
      SEC + "integration_tests.rs#j10_ai_advice_cannot_become_publish_right"),
     "晋升/回退/许可/候选 RPC 契约+旧代际门已覆盖；错误 AI 建议与代际切换并发为单一原生竞态未演练"),
    ("J11",
     "D14 网络服务重启与旧回声结果回传（P+N+S+D）：旧服务不接新请求；不丢终态",
     "HOST",
     (SEC + "integration_tests.rs#j11_readonly_service_restart_leaves_old_dma_inflight",
      KCT + "service_restart.rs",
      SEC + "network.rs#sec_n06_service_right_is_read_only_by_construction",
      SEC + "device.rs#sec_d04_timeout_is_unknown_not_dma_release"),
     "P+N+D 重启/旧结果托管已覆盖；S 终态保留经回执表；重启后旧回声结果回传未原生竞态"),
    ("J12",
     "BootEpoch 持久失败与新计划提交（F+S+P）：不发布未经持久身份的新计划",
     "FIXTURE",
     (SEC + "integration_tests.rs#j12_failed_boot_epoch_does_not_grant_new_publish_right",
      PT + "boot.rs#uncertain_flush_prevents_any_new_authority_this_boot",
      SEC + "file.rs#sec_f08_boot_epoch_store_is_not_ordinary_file",
      PT + "boot_fault_matrix.rs", "tools/boot_reboot_contract.py",
      "tools/verify_v13_boot_recovery.py", A64 + "v0199_epoch_disk.rs"),
     "F+S+P 无持久身份不发布在宿主+原生托管契约覆盖；持久失败期间并发新计划提交竞态仅宿主"),
    ("J13",
     "跨脑篡改/旧代际/伪造 Finding（SEC-P+SEC-S+SEC-N+控制器）：两脑无法读写对方私有模型/端点/工作区；高严重度 Finding 不能生成 cap/RuleProfile 变更或 D12 新授权；规则路径与已受理操作继续；检测真实 source_role/epoch/snapshot/hash，记录独立 FindingDisposition，任一越权为 FAIL",
     "HOST",
     (CP + "fixed.rs#distinct_brains_have_no_cross_channel_write",
      CP + "security_finding.rs", KCT + "control_plane.rs"),
     "跨通道写拒绝、伪造高分/无授权与独立 FindingDisposition 已覆盖；私有模型/端点/工作区隔离（原生）、D12 授权路径与真实 source_role/epoch/snapshot/hash 检测未命名测试"),
    # ---------------- A 回归 ----------------
    ("A01",
     "冷启动、AI 停用、模型自检失败及 BootEpoch 分配/FLUSH 失败：4 vCPU 与 EL0/EL1 正确建立；确定性启动/调度/内存/IPC/恢复不依赖模型；新 BootEpoch 持久后才受理新计划键；模型自检失败只禁用 AI 建议",
     "FIXTURE",
     (PT + "boot.rs", PT + "boot_fault_matrix.rs", PT + "boot_model.rs",
      "tools/test_a01_boot_worker.py", "tools/boot_reboot_contract.py",
      "tools/verify_v13_boot_recovery.py", "tools/verify_v13_boot_reboots.py",
      A64 + "smp.rs"),
     "epoch 分配/FLUSH 故障矩阵、模型自检向量、重启托管与 fail-closed SAFE_EXEC 已覆盖；无单一原生运行建立完整 A01；boot worker 原生路径已退休"),
    ("A02",
     "普通业务试图绑定控制核：准入被拒绝；完整调度轨迹中无业务执行于 C/T/Q",
     "FIXTURE",
     (SEC + "process.rs#sec_p06_no_control_or_draining_cpu",
      SEC + "syscall.rs", KCT + "control_service.rs",
      A64 + "smp.rs", A64 + "v0199_role_selftest.rs",
      "tools/verify_v13_a02.py"),
     "准入拒绝+固定拓扑负向夹具坚实（业务上 CPU0/控制上 B/第二控制核均拒）；完整调度轨迹无业务于 C/T/Q 仅夹具进度计数，非完整原生调度轨迹"),
    ("A03",
     "运营 AI 和安全大脑同时满载、先后关闭与恢复：CPU0 唯一控制核、无扩张/CoreSet 计划；≤70ms/100ms 控制预算、背压只丢建议/训练；计费守恒、缺计量证据不判 PASS；伪造高分不触发授权",
     "FIXTURE",
     (CP + "cpu0_v0199.rs", KCT + "control_plane.rs",
      CP + "role_budget_v0199.rs", PT + "native_control_settlement.rs",
      PT + "native_measured_interval.rs", PT + "a03_completion.rs",
      CP + "fixed.rs", CP + "security_finding.rs",
      "tools/verify_v17_a03_demand.py"),
     "固定 CPU0、预算守恒与伪造高分拒绝已覆盖；双脑满载先后关闭/恢复带原生≤70/100ms 计量与建议-only 背压未端到端演示"),
    ("A04",
     "CPU0 失联、业务核 IRQ/DMA 交错及 SMP fail-stop：CPU0 未可靠恢复前不把 B 转 C；保留原归属和在途页/DMA/账本，可靠停机/隔离才回收；可进入明确 UNKNOWN，不伪造所有核已停",
     "FIXTURE",
     (PT + "cores.rs", KCT + "control_plane.rs",
      SEC + "memory.rs#sec_m06_dma_and_pin_survive_cpu_unmap",
      SEC + "device.rs#sec_d04_timeout_is_unknown_not_dma_release",
      A64 + "smp.rs"),
     "fail-stop/无假证明账本语义+模拟 CPU0 故障隔离（ownership.fault(0)→quarantined=1、无 B→C 提升）已覆盖；真实 CPU0 失联带业务 IRQ/DMA 交错与在途页/账本保留未原生演练"),
    ("A05",
     "15 域 15 动作族每族两组可区分负载：逐族分析/建议与独立裁决证据、执行器≥2 合法配置真实行为差异；ASSISTED/TrialPermit 仍独立裁决、默认 SHADOW 不发布；完整因果链与回执；11 个可 ASSISTED 族有效推荐异于 fallback 且实际 APPLIED，4 敏感族规则动作不变",
     "FIXTURE",
     (CP + "advisory.rs#no_model_is_a_complete_deterministic_path",
      CP + "advisory.rs#security_sensitive_domains_never_adopt_model_candidates",
      CP + "decision_record_v3.rs", CP + "advice_disposition_v1.rs",
      CP + "rule_profile_v2.rs", CP + "trial_permit_v1.rs",
      CP + "registered_gate_v3.rs", PT + "domain_policy.rs",
      A64 + "v0199_advice_e2e.rs", "tools/verify_domains.py"),
     "因果链组件、4 敏感域拒绝、ASSISTED/TrialPermit 权限与旧动作拒绝已覆盖；完整 15×15×2 负载矩阵、≥2 执行器配置与 11 族 APPLIED-vs-fallback 分歧未作单一验收运行（夹具仅一族，causal_label=2）"),
    ("A06",
     "对象并发撤销、FP/SIMD 抢占与旧 APPLY 延迟：任务/cap 旧代际拒绝；TLB 未确认页不重用、锁内不等待外部事件；FPCR/FPSR 保留无泄漏；新 desired 生效前未开始旧动作不覆盖，已开始操作与新版本串行各自回执",
     "FIXTURE",
     (SEC + "memory.rs#sec_m04_missing_tlb_ack_retains_frame",
      TH + "page_mapping_revoke_cases.rs", TH + "page_space_reuse_cases.rs",
      KCT + "dispatch.rs", PT + "domain_policy.rs",
      CP + "registered_gate_v3.rs", PT + "domain_stability.rs",
      TH + "active_scheduler_publication_harness.rs",
      CP + "policy_lock_v0199.rs", "crates/posix/src/signal.rs",
      A64 + "v0199_role_selftest.rs", "tools/verify_v15_registers.py", "tools/check_v0199_el1_fp.py"),
     "原生寄存器子用例核对 FPCR/FPSR、SIMD 与抢占/SVC 恢复，静态扫描核对 FP 指令。对象撤销、TLB ACK 及旧 APPLY 的联合场景待验证。"),
    ("A07",
     "畸形 ABI、伪调用者、旧候选/根/模型代际、重复键与超容量：PlanHeader v2 64B/PolicyEnvelope v2 144B/6464B 总长/索引/摘要/代际精确核验；非法新提交无资源变化；同键异摘要冲突；纯规则计划 model_hash=0 合法；负向 allowed_mask=0 等",
     "FIXTURE",
     (CP + "plan_wire_v2.rs", SEC + "syscall_v3.rs",
      SEC + "process.rs#sec_p02_idempotent_retries_and_conflict",
      SEC + "file_auth_context_v1.rs", PT + "domain_policy.rs",
      PT + "task_receipt_expiry.rs", PT + "domain_policy_model_change.rs",
      CP + "decision_record_v3.rs", A64 + "v0199_role_selftest.rs"),
     "头/容量/摘要/代际/冲突/到期语义宿主覆盖良好；原生畸形 ABI 边界仅 7 例 SVC preflight；负向 allowed_mask=0 未发现命名断言"),
    ("A08",
     "同种子同初态确定性基线与 AI 辅助配置配对回放：固定工作单元、10s 观测窗、惩罚延迟保存原始计数；trial 关联首次动作及合法同值续期；逐域真实延迟/拒绝/超时/成本与负结果；D13 去重、U/C_raw、clip 后 C；同吞吐/延迟且 C_raw<1 时增加执行 CPU 必须降低 R",
     "FIXTURE",
     (PT + "learning_reward.rs", "crates/prototype/src/learning/reward.rs",
      PT + "learning_capture.rs", PT + "learning_replay_bounded.rs",
      PT + "learning_replay_verified.rs", PT + "native_measured_interval.rs",
      TH + "prehash_decision_budget_harness.rs",
      TH + "carried_publication_budget_harness.rs",
      "tools/verify_ai_accounting.py"),
     "10s 窗/惩罚/去重/raw-vs-clipped/配对标签机制已覆盖；同种子配对基线-vs-AI 原生回放带吞吐/延迟 R 比较与逐域负结果账本未作单一配对实验"),
    ("A09",
     "匿名哨兵+页缓存压力：地址空间隔离/清零/权限/所有权正确；无交换时匿名内容不丢失；FrameMeta 全 262144 条、10MiB 永久页预扣不重复计入控制/进度池；表自身页不可回收，账本守恒",
     "FIXTURE",
     ("crates/kernel-core/src/frame_meta_v0199.rs", KCT + "frames.rs",
      PT + "native_a09_memory.rs",
      SEC + "memory.rs#sec_m01_never_map_private_kernel_or_control_frames",
      A64 + "v0199_ram_inventory.rs", A64 + "v0199_epoch_disk.rs",
      "tools/verify_v0199_epoch_disk.py"),
     "全表守恒+匿名 vs 缓存压力在宿主与原生 dump（262144×40B FrameMeta 物理转储）覆盖；10MiB 预扣双计与表自身页不可回收经静态登记测试断言，非原生压力扫描"),
    ("A10",
     "redo/COMMIT/超级块每个边界断电：A：双超级块有效且提交链可证恢复已确认 fsync 目标序号，未确认按完整提交链决定；B：最新超级块损坏/单份失效/同代异内容/高代有效日志必须 RECOVERY_REQUIRED/EIO，不开放普通文件、不分配 BootEpoch、不修改磁盘；A/B 分别判定",
     "FIXTURE",
     (PT + "journal.rs", PT + "storage.rs", PT + "a10_cache_admission.rs",
      PT + "immutable_snapshots.rs", "tools/verify_v16_a10_matrix_v4.py",
      "tools/verify_v13_a10_native_receipt.py",
      "tools/verify_v16_a10_cut_v4.py", A64 + "v0199_epoch_disk.rs", "tools/verify_v0199_a10_fsync.py"),
     "A 侧已确认 FSYNC 的停机冷恢复读回写序号 7 和 LSN 19。仍需冻结环境下的完整断电矩阵与 B 侧损坏拒绝、BootEpoch 和零写入证据。"),
    ("A11",
     "满内存、普通完成槽/消费者阻塞、维护份额已借出并同时模型停机：新普通请求副作用前背压、reserved+inflight+queued≤capacity、完成事实不丢；恢复槽独立可用、按优先级收回借用；100ms 窗口实际计费、每核聚合≤900 与单线程≤900 不同键另留 10ms；FIFO 票门按序推进、45+5≤50μs 强制计量",
     "HOST",
     (SEC + "syscall.rs#sec_s08_full_receipt_credit_causes_precommit_backpressure",
      CP + "policy_lock_v0199.rs", CP + "role_budget_v0199.rs",
      PT + "control_extra_budget.rs", PT + "domain_maintenance.rs",
      KCT + "grants.rs",
      SEC + "process.rs#sec_p03_capacity_and_no_hidden_slot",
      TH + "submission_completion_harness.rs", PT + "domain_ipc_grants.rs",
      SEC + "ipc_receive_v3.rs"),
     "副作用前背压、守恒、恢复槽独立、45+5≤50μs 计量与 FIFO 票序已覆盖；每核/单线程≤900 不同键+10ms 与 8MiB recv 子预算核账未发现命名断言"),
    ("A15",
     "推理超时、运营/安全大脑建议洪泛、双大脑分别停止；固定 CPU0 上再分别停止确定性控制器/唯一发布代理：停 AI 只隔离旧 advisor_epoch 及建议、controller_epoch 与发布权保持；停控制器/发布者撤销旧发布权、提升 controller_epoch 进入 SAFE_EXEC 在保留资源恢复，AI 不得接管；无热路径等待模型、在途义务不取消",
     "FIXTURE",
     (KCT + "control_plane.rs", PT + "domain_policy.rs", CP + "advisory.rs",
      SEC + "device.rs#sec_d07_irq_must_target_healthy_business_only",
      PT + "native_replay_workloads.rs", CP + "control_rpc_v1.rs",
      A64 + "v0199_control_bringup.rs"),
     "控制器重启/旧 epoch 拒绝、优化器停止/恢复权限与 IRQ 健康-B 路由已覆盖；唯一发布者单独停止带 controller_epoch 提升+SAFE_EXEC+保留资源恢复与建议洪泛/推理超时隔离未作单一原生序列（夹具 restart_each 覆盖角色重启）"),
    ("A16",
     "本地训练、Shadow/Canary 及模型切换/回退：重现 15 动作族 120/60 分组数据与完整量化推理黄金向量；模型不改 RuleProfile 或自授发布权；Shadow 无副作用、Canary 须许可+独立裁决+真实 APPLIED+无 UNKNOWN 晋升；学习/验证/额外评分≤8.5ms/100ms、控制总量≤70ms/100ms；留出集按候选一次使用与训练互斥",
     "HOST",
     (PT + "learning_train.rs", PT + "learning_validation.rs",
      PT + "learning_governance.rs#v0199_mandatory_and_optional_roles_share_exact_70ms_control_ceiling",
      PT + "learning_governance.rs#shadow_has_no_execution_permit_and_canary_lease_excludes_old_target_writes",
      PT + "learning_review_governance.rs", PT + "learning_governance_faults.rs",
      PT + "native_canary_measurements.rs",
      PT + "native_canary_publication_clock.rs",
      PT + "native_canary_console_baseline.rs", PT + "model_bank.rs"),
     "黄金向量、分组数据泄漏密封、Shadow 无许可、Canary 许可+APPLIED+无 UNKNOWN 晋升、8.5/61.5/70ms 预算与 ABA 回退宿主覆盖；120/60 分组跨 15 族重现与留出集按候选一次使用未发现显式断言；无原生 Canary 执行证据"),
    # ---------------- E 回归 ----------------
    ("E01",
     "同域两个不同目标均 generation1：不同 action_index/target_id 分别产生回执，不互相去重",
     "HOST",
     (CP + "apply_work_v1.rs", CP + "apply_report_v1.rs",
      CP + "registered_gate_v3.rs", PT + "domain_policy.rs"),
     "逐动作/目标回执绑定与不同键历史已覆盖；同域两个 generation-1 目标分别回执不互相去重的精确正向对未发现命名测试"),
    ("E02",
     "同一 CPU 亲和的两个线程各 600milli：即使其他 CPU 空闲也拒绝不可放置的总预算；迁移过程无重复执行",
     "HOST",
     (PT + "cores.rs#aggregate_spare_capacity_does_not_allow_per_core_overcommit",
      KCT + "control_plane.rs"),
     "精确 600+600 同 CPU 拒绝场景已演练（Err(Capacity)、快照不变、600+300=900 承诺）；迁移无重复执行经预留守恒；原生亲和放置竞态未演练"),
    ("E03",
     "业务核故障/IRQ/DMA 新派发与固定 C 的隔离：业务任务/IRQ 不越界至 CPU0；故障 B 核不得被重分配为 C；无 ACK 不作停止证明",
     "FIXTURE",
     (SEC + "device.rs#sec_d07_irq_must_target_healthy_business_only",
      SEC + "process.rs", PT + "native_irq_sources.rs",
      PT + "native_irq_replay.rs",
      SEC + "integration_tests.rs#j07_irq_change_cannot_route_to_draining_core",
      A64 + "smp.rs"),
     "IRQ 路由/名册+业务核守卫已覆盖（夹具 IRQS 仅 CPU1–3）；故障 B 不重分配为 C 与无 ACK 无停止证明仅经 A04 账本测试，非组合原生故障/IRQ/DMA 派发竞态"),
    ("E04",
     "普通完成 credit 全满并集中完成：终态不丢，未受理请求无副作用，恢复 credit 仍可推进",
     "HOST",
     (SEC + "syscall.rs#sec_s08_full_receipt_credit_causes_precommit_backpressure",
      SEC + "file.rs#sec_f07_unknown_transaction_keeps_capacity",
      PT + "a10_cache_admission.rs", TH + "submission_completion_harness.rs",
      TH + "vector_pump_credit_harness.rs", TH + "file_retry_harness.rs",
      SEC + "ipc_receive_v3.rs"),
     "终态保留、未受理无副作用与恢复推进跨回执/credit 表覆盖；全 credit 满后集中完成爆发作为单一命名场景未发现"),
    ("E05",
     "请求解析/阻塞期间修改或 unmap 用户缓冲：只使用受保护副本，无越权；输出失败可查询原副作用",
     "FIXTURE",
     (SEC + "syscall.rs#sec_s02_user_input_frozen_once",
      SEC + "syscall.rs#sec_s03_output_fault_does_not_redo_commit",
      SEC + "memory.rs#sec_m05_checked_user_copy_range",
      TH + "file_input_access_harness.rs",
      SEC + "integration_tests.rs#j02_exit_copyin_and_unmap_keep_original_receipt",
      A64 + "v0199_role_selftest.rs"),
     "受保护副本/越权/输出失败可查在宿主+夹具 copy preflight（V0199_SVC_COPY 用例 7–11）覆盖；解析中用户缓冲修改/unmap 未原生交错"),
    ("E06",
     "伪造 report_result 与旧执行器代际：伪回执拒绝，不开放依赖准入或释放资源；role12 错域、role13 无回执权限及伪造 ApplyReport 拒绝；SAFE_OVERRIDE 记录不当作 APPLIED；D10 批量和回执仅 EL1；TLS 伪造 FETCH/REPORT 拒绝；真实发送/完成仍计账",
     "FIXTURE",
     (SEC + "syscall.rs#sec_s05_old_executor_generation_cannot_report",
      SEC + "device.rs#sec_d06_old_or_forged_completion_rejected",
      CP + "apply_report_v1.rs", SEC + "file_auth_v3.rs",
      SEC + "file_auth_context_v1.rs", CP + "registered_gate_v3.rs",
      SEC + "offline_config_v1.rs", CP + "svc_bridge_v3.rs",
      A64 + "v0199_advice_e2e.rs"),
     "伪回执/旧代际/角色门/EL1-only 报告路径已覆盖（夹具 5 项负向拒绝）；SAFE_OVERRIDE 不计 APPLIED 与 TLS 解析器伪造 FETCH/REPORT 未发现命名断言"),
    ("E07",
     "提案受理≤100ms、参数租期+10000ms 与旧 CoreSet 请求：只触发相应状态转换、续期不重置最短保持；根发布余期 9.9–10s、执行器采用沿用原到期点；到期不清空本地资源承诺/在途义务；AI 建议期限与已批准计划期限分别判定；旧核心集合动作返回 E_UNSUPPORTED",
     "HOST",
     (PT + "domain_policy.rs", PT + "domain_policy_one_shot.rs",
      PT + "task_receipt_expiry.rs", CP + "control_rpc_v1.rs",
      KCT + "control_plane.rs"),
     "租期锚定/不续期/到期保留义务已覆盖；+10000ms 参数租期与 9.9–10s 根发布余期窗口未发现显式测试；旧 CoreSet E_UNSUPPORTED 仅经通用未知 op 解码+旧动作门"),
    ("E08",
     "发布/读侧抢占/迁核/中断交错：无悬空指针、锁反入与过时代际执行",
     "HOST",
     (KCT + "control_plane.rs", KCT + "control_service.rs",
      KCT + "dispatch.rs", TH + "active_scheduler_publication_harness.rs",
      TH + "carried_publication_budget_harness.rs", PT + "domain_policy.rs"),
     "撕裂发布/锁反入/过时代际守卫以宿主线程覆盖；真实抢占/迁核/中断交错未原生演练"),
    ("E13",
     "业务 IRQ 变更后配置过期；OPTIONAL 有 200milli 承诺：SAFE_EXEC 不迁入固定 CPU0，不减已承诺硬预算、不凭空增缓存",
     "HOST",
     (PT + "domain_maintenance.rs", PT + "native_replay_workloads.rs",
      CP + "cpu0_v0199.rs"),
     "过期配置承诺保留（400/200-milli、freeze_admission）+固定 CPU0 可选放置已覆盖；SAFE_EXEC 不凭空增缓存与业务 IRQ 配置过期派发竞态未发现命名测试"),
    ("E14",
     "学习/Shadow/Canary 与控制高负载并发：AI 分析/学习/Shadow/Canary 角色仅在 C 运行；确定性裁决/发布/恢复保留预算优先；额外工作不得侵占 61.5ms 上界（含安全大脑）和每控制核 70ms/100ms 总上限；AI 过载不停止独立裁决",
     "HOST",
     (PT + "learning_governance.rs#v0199_mandatory_and_optional_roles_share_exact_70ms_control_ceiling",
      PT + "learning_governance_faults.rs", PT + "learning_review_governance.rs",
      CP + "role_budget_v0199.rs", TH + "governance_priority_harness.rs"),
     "预算优先级/上限（含安全大脑份额，MANDATORY_NS=61.5ms、EXTRA_NS=8.5ms 断言）宿主覆盖良好；并发原生控制高负载交错未演练"),
    ("E15",
     "检查点后空日志重启；本地任务创建与资源预留并发竞争：事务完整键不复用；已预占线程槽/子账/完成额度不被夺走；请求失败前不得产生未登记副作用，结果复制失败仍可按原 request_id 查询；并发 AI 建议不能绕过同一资源账本",
     "HOST",
     (PT + "journal.rs", PT + "boot.rs", TH + "checkpoint_reuse_harness.rs",
      PT + "spawn_reservation.rs", TH + "ordinary_spawn_reservation_harness.rs",
      SEC + "file_auth_context_v1.rs",
      SEC + "syscall.rs#sec_s03_output_fault_does_not_redo_commit",
      KCT + "grants.rs"),
     "键不复用、预占槽保护、无未登记副作用与结果复制失败可查已覆盖；检查点后空日志重启+本地创建 vs 预留竞态作为单一命名场景未发现"),
    # ---------------- H 回归 ----------------
    ("H01",
     "AI 角色直接调用 submit_plan、写资源账本、扩权或伪造执行回执：全部在副作用前以权限错误拒绝；仅唯一可信发布者可提交经裁决计划，AI 只读授权遥测并写建议通道；篡改发布者/裁决标识/权限字段不能改变权限；校验 cap 类型/holder/代际",
     "FIXTURE",
     (SEC + "syscall.rs#sec_s04_only_publisher_can_submit_plan",
      SEC + "integration_tests.rs#j10_ai_advice_cannot_become_publish_right",
      SEC + "integration_tests.rs#j12_failed_boot_epoch_does_not_grant_new_publish_right",
      CP + "advice_envelope_v1.rs", CP + "role_manifest_v0199.rs",
      SEC + "syscall_v3.rs",
      CP + "fixed.rs#distinct_brains_have_no_cross_channel_write",
      A64 + "v0199_advice_e2e.rs"),
     "AI submit/账本写/扩权/伪回执在副作用前拒绝已覆盖（夹具 V0199_ADVICE_BAD_PUBLISH  ops-role 发布拒绝）；AI 只读遥测正向路径仅经 role-manifest caps"),
    ("H02",
     "默认 SHADOW 及 ASSISTED 中合法 AI 建议与冻结目标/优先级/稳定性规则冲突：SHADOW 只记录建议不发布计划；ASSISTED 至少演示一次独立拒绝及一次合法建议确定性回退，记录 RuleProfile/AdviceKey/DecisionRecord 与理由；拒绝建议无副作用/无 APPLIED，回退动作单独关联批准计划与回执；未经目标/动作预授权不得进入 ASSISTED，TrialPermit 不能 AI 自授",
     "FIXTURE",
     (CP + "advisory.rs", CP + "advice_disposition_v1.rs",
      CP + "decision_record_v3.rs", CP + "rule_profile_v2.rs",
      CP + "trial_permit_v1.rs", CP + "registered_gate_v3.rs",
      TH + "scheduler_publication_contract_harness.rs",
      A64 + "v0199_advice_e2e.rs"),
     "SHADOW 不发布、独立拒绝+回退关联与 TrialPermit 不自授已覆盖；拒绝+回退带分离批准计划+执行回执仅在夹具对一族演示（causal_label=2 AdoptedDifferentFallback、unique_native_accept_count=1）"),
    ("H03",
     "从冷启动起不加载 AI 模型，随后关闭全部 AI 分析与学习进程：启动/调度/任务创建/内存/文件持久化/IPC/网络/驱动及故障恢复全部有原生运行证据；确定性规则在固定单核约束下独立调整各领域资源；AI 关闭只影响辅助信息，不造成等待模型/无法准入/资源无主",
     "FIXTURE",
     (SEC + "process.rs#sec_p08_no_ai_required_for_local_admission",
      SEC + "network.rs#sec_n08_no_model_is_needed_for_rate_limit_and_echo",
      CP + "advisory.rs#no_model_is_a_complete_deterministic_path",
      KCT + "control_plane.rs",
      "kernel/src/runtime/recovery/boot_recovery.rs",
      TH + "os_ready_idle_harness.rs", TH + "runtime_loop_evidence.rs",
      TH + "baseline_progress_harness.rs", A64 + "smp.rs"),
     "无模型确定性路径+原生 fail-closed 启动（BOOT_SAFE_EXEC new_ai=closed、夹具无模型业务进度）已覆盖；全部 AI 分析与学习停止、每域原生运行证据作为单一 AI-off 原生扫描未发现"),
    ("H04",
     "建议超时、畸形、过期、重复、乱序及建议队列持续满载：有界拒绝/去重/丢弃尚未采用的建议；确定性裁决和本地服务持续推进，AI 建议不得占用最后完成/恢复资源；已发布义务按原计划收尾，重放旧建议不能恢复已失效授权",
     "HOST",
     (CP + "advice_envelope_v1.rs", CP + "advisory.rs",
      CP + "security_finding.rs", KCT + "control_plane.rs",
      CP + "role_budget_v0199.rs", PT + "domain_policy.rs",
      CP + "registered_gate_v3.rs", "tools/check_v0199_h04_model.py"),
     "有界宿主模型核对 64 槽下的建议处置、归档交接和独立 RULE_ONLY 发布，以及原计划的唯一工作领取。原生并发、本地服务推进与真实完成回执待验证。"),
    ("H05",
     "重放相同快照、建议、规则版本、授权配置与对象代际：确定性裁决结果及理由可复现；每个实际动作关联唯一受保护 DecisionRecord 与发布记录；无建议输入验证独立 RuleProfile 完整定义、纯规则计划模型字段 0 合法；仅注入/改变 AI 建议且裁决与已发布计划均不变时不得直接引起资源变化；越集合/过期/敏感域 flags=1 必须拒绝",
     "HOST",
     (PT + "learning_replay_verified.rs", CP + "decision_record_v3.rs",
      CP + "plan_wire_v2.rs", CP + "advisory.rs", CP + "rule_profile_v2.rs",
      CP + "registered_gate_v3.rs", CP + "advice_disposition_v1.rs", "tools/check_v0199_h05_model.py"),
     "十五域宿主有限状态模型核对单动作确定性裁决、回退与唯一发布。真实执行回执及原生交错待验证。"),
    ("H06",
     "训练者试图改准入规则或发布模型，交错模型切换和执行：训练者只写候选模型区；RuleProfile/TrialPermit/权限/账本和发布身份不受模型更新影响；只有授权模型管理器可验证并切换建议模型，新模型所有建议仍经同一独立裁决和内核校验；切换不自动把 SHADOW 改为 ASSISTED，回退不撤销已完成操作",
     "HOST",
     (PT + "model_bank.rs#switches_require_generation_plus_one_and_rollback_only_the_previous_active",
      PT + "learning_validation.rs", PT + "domain_policy_model_change.rs",
      KCT + "control_plane.rs", PT + "learning_governance.rs",
      CP + "registered_gate_v3.rs", CP + "rule_profile_v2.rs"),
     "训练者候选区-only、授权切换、回退不撤销已完成操作与不自动 SHADOW→ASSISTED 已覆盖；交错模型切换 vs 执行原生竞态未演练"),
]


def family_of(test_id):
    if test_id.startswith("SEC-"):
        return test_id[4]
    return test_id[0]


def validate(rows):
    errors = []
    ids = [r[0] for r in rows]
    if len(ids) != 127:
        errors.append("行数 %d != 127" % len(ids))
    if len(set(ids)) != len(ids):
        errors.append("存在重复 ID")
    if set(ids) != set(EXPECTED_IDS):
        missing = sorted(set(EXPECTED_IDS) - set(ids))
        extra = sorted(set(ids) - set(EXPECTED_IDS))
        errors.append("ID 集合不符：缺失=%s 多余=%s" % (missing, extra))
    for fam, _title, count, _src in FAMILIES:
        got = sum(1 for i in ids if family_of(i) == fam)
        if got != count:
            errors.append("族 %s 数量 %d != %d" % (fam, got, count))
    for tid, definition, status, evidence, note in rows:
        if status not in ("HOST", "FIXTURE", "GAP"):
            errors.append("%s 非法状态 %s" % (tid, status))
        if status == "GAP" and evidence:
            errors.append("%s GAP 不得携带证据" % tid)
        if status != "GAP" and not evidence:
            errors.append("%s 非 GAP 必须有证据" % tid)
        if not definition or not note:
            errors.append("%s 定义/说明为空" % tid)
    return errors


def check_paths(rows):
    missing = []
    for tid, _d, _s, evidence, _n in rows:
        for item in evidence:
            path = item.split("#", 1)[0]
            if not (ROOT / path).exists():
                missing.append("%s -> %s" % (tid, path))
    return missing


def counts(rows):
    by_status = {"HOST": 0, "FIXTURE": 0, "GAP": 0}
    by_family = {}
    for tid, _d, status, _e, _n in rows:
        by_status[status] += 1
        fam = family_of(tid)
        bucket = by_family.setdefault(fam, {"HOST": 0, "FIXTURE": 0, "GAP": 0})
        bucket[status] += 1
    security = [r for r in rows if family_of(r[0]) in "PFMNDSJ"]
    regression = [r for r in rows if family_of(r[0]) in "AEH"]
    return {
        "total": len(rows),
        "by_status": by_status,
        "by_family": by_family,
        "security_97": {
            "total": len(security),
            "by_status": {s: sum(1 for r in security if r[2] == s)
                          for s in ("HOST", "FIXTURE", "GAP")},
        },
        "regression_30": {
            "total": len(regression),
            "by_status": {s: sum(1 for r in regression if r[2] == s)
                          for s in ("HOST", "FIXTURE", "GAP")},
        },
        "gap_ids": [r[0] for r in rows if r[2] == "GAP"],
    }


def render_markdown(rows):
    lines = []
    lines.append("# V0.20 验收覆盖矩阵（127 个稳定 ID）")
    lines.append("")
    lines.append("**本矩阵仅为覆盖映射：所有 127 项原生验收判定保持 NOT_RUN。"
                 "HOST/FIXTURE 均表示部分覆盖，不构成任何 PASS 声明；"
                 "原生夹具 PASS ≠ G4 验收。**")
    lines.append("")
    lines.append("ID 来源：%s（主§11.1–11.5、安§1–6 验收表、安§7.3/7.4/7.6）；"
                 "%s §7。" % (BASELINE, DESIGN))
    lines.append("")
    lines.append("状态规则：FIXTURE=存在原生 QEMU 机制夹具证据（可伴随宿主证据）；"
                 "HOST=仅宿主侧测试或静态检查；GAP=无覆盖。证据格式：路径[#测试函数]。")
    lines.append("")
    c = counts(rows)
    lines.append("## 统计")
    lines.append("")
    lines.append("- 总计：%d（97 安全 = 84 SEC 单域 + 13 J 跨域；30 回归 = A13 + E11 + H6）"
                 % c["total"])
    lines.append("- HOST=%d，FIXTURE=%d，GAP=%d"
                 % (c["by_status"]["HOST"], c["by_status"]["FIXTURE"],
                    c["by_status"]["GAP"]))
    lines.append("- 安全 97 项：HOST=%d，FIXTURE=%d，GAP=%d"
                 % (c["security_97"]["by_status"]["HOST"],
                    c["security_97"]["by_status"]["FIXTURE"],
                    c["security_97"]["by_status"]["GAP"]))
    lines.append("- 回归 30 项：HOST=%d，FIXTURE=%d，GAP=%d"
                 % (c["regression_30"]["by_status"]["HOST"],
                    c["regression_30"]["by_status"]["FIXTURE"],
                    c["regression_30"]["by_status"]["GAP"]))
    lines.append("- GAP 清单：%s" % ", ".join(c["gap_ids"]))
    lines.append("")
    for fam, title, _count, source in FAMILIES:
        fam_rows = [r for r in rows if family_of(r[0]) == fam]
        if not fam_rows:
            continue
        lines.append("## %s" % title)
        lines.append("")
        lines.append("来源：%s" % source)
        lines.append("")
        lines.append("| ID | 定义 | 状态 | 证据 | 覆盖说明（部分） |")
        lines.append("|---|---|---|---|---|")
        for tid, definition, status, evidence, note in fam_rows:
            ev = "<br>".join(evidence) if evidence else "—"
            lines.append("| %s | %s | %s | %s | %s |"
                         % (tid, definition, status, ev, note))
        lines.append("")
    lines.append("## 口径与限制")
    lines.append("")
    lines.append("1. kernel-core/src/security/{file,memory,network,device}.rs 内联 sec_* 测试沿用"
                 " V0.19 六专项编号，按主题而非名称映射到 V0.19.9 稳定 ID。")
    lines.append("2. tests/host/page_* 用例运行 x86_64 生产页表/别名代码的宿主适配，"
                 "不是 AArch64 页表/TLB 证据。")
    lines.append("3. TLS 证据全部为宿主 rustls 夹具握手；verify_native_net.py/verify_v13_tcp.py"
                 " 均 tls_verified=false。")
    lines.append("4. 原生夹具（smp-selftest/bringup/advice-e2e/epoch-disk/framemeta-boot）均标注"
                 " production_wiring=false 或 production_isolation_verified=false，非生产接线。")
    lines.append("5. 已删除 ID（A12–A14、E09–E12、T01–T20）不在矩阵内，不得复用。")
    lines.append("6. G4-QEMU 要求每项 ID 的 RUNTIME_QEMU/STATIC_EL1/MODEL_CHECK 强制类别全部 PASS；"
                 "本矩阵不判定任何类别，G1=NOT_READY、G4-QEMU/G5-ARCH=NOT_RUN 状态不变。")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="V0.20 127 稳定 ID 验收覆盖矩阵（仅覆盖映射，全部 NOT_RUN）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--family", help="只输出指定族（P/F/M/N/D/S/J/A/E/H）")
    parser.add_argument("--strict", action="store_true",
                        help="证据路径缺失时以非零码退出")
    args = parser.parse_args(argv)

    errors = validate(ROWS)
    if errors:
        for e in errors:
            print("数据表错误: %s" % e, file=sys.stderr)
        return 2

    rows = ROWS
    if args.family:
        fam = args.family.upper()
        rows = [r for r in ROWS if family_of(r[0]) == fam]
        if not rows:
            print("未知族: %s" % args.family, file=sys.stderr)
            return 2

    missing = check_paths(rows)
    for m in missing:
        print("警告: 证据路径缺失 %s" % m, file=sys.stderr)
    if missing and args.strict:
        return 1

    if args.json:
        payload = {
            "scope": "coverage-mapping-only",
            "acceptance_verdict": "NOT_RUN for all 127 stable IDs",
            "sources": {
                "baseline": BASELINE,
                "design": DESIGN + " §7",
                "families": {f: src for f, _t, _c, src in FAMILIES},
            },
            "status_rule": "FIXTURE=native QEMU mechanism fixture evidence present; "
                           "HOST=host-side tests or static checks only; GAP=no coverage; all partial",
            "counts": counts(rows),
            "rows": [
                {"id": tid, "family": family_of(tid), "definition": d,
                 "status": s, "evidence": list(e), "note": n}
                for tid, d, s, e, n in rows
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(render_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
