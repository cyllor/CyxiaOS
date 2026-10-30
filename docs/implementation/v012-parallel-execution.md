# V0.12 并行实施记录

日期：2026-10-29，Asia/Muscat。基线：`5ab75ab8e9c664246ec9cddd1c24b7f65f340e39`。

用户已在完成[路线图](v012-parallel-roadmap.md)后授权并行实施。本记录区分工作树内实现、主工作区集成、主机验证和原生验收；完成一项不自动证明其他项。

## 工作卡与所有权

| ID | 所有者 | 状态 | 分支 / 工作树 | 交付及集成门 |
| --- | --- | --- | --- | --- |
| V12-00 | 主集成者 | 前置完成；原生回放 FAIL，待针对性修复 | `CyxiaOS-V0.12` / 当前工作区 | 固定测试输入、补丁 QEMU、回放工具、双镜像均通过；新原生记录已停止并保留 |
| V12-01 | `control_learning_audit` | 已集成，统一主机门通过 | `work/v012-regression` / `../CyxiaOS-V0.12-lanes/regression` | 11 个测试文件适配；17 项 Python 定向和 5 项 Rust 定向通过；100 个负向控制中涉及的 21 个增加明确编译门 |
| V12-02 | `acceptance_tooling_audit` | 已集成，统一主机门通过；native 准入待后续契约 | `work/v012-evidence` / `../CyxiaOS-V0.12-lanes/evidence` | 四文件及独立复核修正完成；A10 原始重建、串口残帧与故障模式绑定反例均通过，native 准入仍关闭 |
| V12-03 | `cluster_storage_audit` | 判定器已集成并通过主机门；原生重启验收待运行 | `work/v012-cluster` / `../CyxiaOS-V0.12-lanes/cluster` | 两文件修复 READY 时序与健康对端计数；15 项定向及统一检查通过，未声称五 profile 原生 PASS |

Agent 在各自工作树中保留未提交修改，由主集成者按明确路径审查并移入主工作区。共享 ABI、构建器、`verify_domains.py` 和 catalogue 均由主集成者持有。原生计时阶段暂停同宿主构建和重型检查。

## 已完成前置检查

- `tools/prepare_host_tests.py` 首次离线检查确认缺少固定 `cosmic-comp` 输入，随后显式 `--fetch` 准备成功；COSMIC/Smithay 源与 Wayland 协议归档均经现有固定散列检查。
- `prototype-disk` 与 `verify-domain-evidence` 已用固定 Cargo lock、离线构建成功。
- 补丁 QEMU `/tmp/cyxia-qemu-10.2.2-patched/build/qemu-system-aarch64` 通过 `verify_unified.attest_qemu`：固定 commit、四个 changed-source hashes、补丁反向检查和二进制身份一致，`qemu_pmu_patch_attested=true`。
- 本机 QEMU binary SHA-256：`c6313c66831bf0aa6cd53c4b6a3829ab8dab8984a3e9db7b6ee8db3b1f5f07f0`；补丁 SHA-256：`b92d2ce14bca13cae43338729de3226c1ad9f469dc9947e1bd5c465d753876fd`。
- 当前源码的双节点/治理镜像构建输出：`artifacts/v012-parallel-build-20261029`，构建成功，状态 `BUILT_NOT_RUN`；源码 SHA-256 为 `facca7e141ec7cd821dd6b7278f3b06978b7ba854fe0fa29e2b52ca4e6293435`。两节点选定 preparation 栈峰值均为 33,104/65,536 字节，保留 4,096 字节异常余量。独立 governance ELF 为 22,416 字节。

## 已集成的服务重启判定修复

`tools/verify_unified.py` 先从受保护状态确认 generation 2 / 一次 restart，再要求匹配的原始 fault 行先于该 BootEpoch 的精确 restart 行；只有之后依次出现服务进入、driver 初始化、TLS 和 READY，才能证明重启后的恢复。整次启动中已有的两轮 READY 不能替代新 generation 的证据。

健康对端不重建服务上下文，只重新认证和 READY，因此其最初服务进入/driver 初始化各一次合法；重启节点仍要求各至少两次。新增及更新反例覆盖旧 READY、未完成或乱序恢复、fault/restart 顺序、错误 generation 和缺少健康对端重连事件。工作树定向结果为 11 项 acceptance、2 项工作流、2 项 TLS 诊断检查通过；这是判定器回归，不代表原生服务重启已通过。

## 验收边界

实施开始时，catalogue 为 69 项 NOT_RUN，文件故障矩阵未完成。现有 A10 matrix reviewer 对部分 child summary 字段的信任不足以直接开放完整 A10 原生 PASS；本轮回执任务需先闭合该证据边界。当前没有新原生 PASS 声明。

## 联合验证进度

第一批八项检查保留在 `artifacts/v012-parallel-checks-base-20261029`。fixtures、两项格式检查、TLS、tools、kernel Clippy 和 governance Clippy 全部通过；Rust workspace 因 `native_task_publication.rs` 仍缺新 publication 模块所需类型/字段而编译失败。随后单独适配该测试边界，RED→GREEN 为 5 项通过，没有修改生产实现。

全部修改和独立审查修正已在主机测试开始前移入主工作区。标准九项入口 `python3 -B tools/prototype.py test --output artifacts/v012-parallel-final-checks-20261029` 最终全部 PASS，详见该目录的 `summary.json`：Rust workspace 共 1,172 项通过；host 共 733 项，其中 731 通过、2 跳过；tools 84 项通过；TLS、两项格式、fixtures 和两项严格 Clippy 通过。先前失败日志保留，未以跳过或放宽断言规避。

## A10 离线重建交付及独立审查

新增 `tools/verify_v13_a10_receipt.py`，使用固定本地判定器重新读取 NBD 请求/ACK/FLUSH 与最终持久字节、初始/最终文件系统 oracle、受保护文件 trace/progress、FSYNC 消费、boot 记录和原始 framed serial；派生值必须与归档 observation 一致。源码、构建器和归档工具均与当前固定代码核对，不执行归档脚本。

独立审查补齐两类实际反例：有效串口后附单字节或半帧时完整模式拒绝残留；原始 NBD 的 `cut`、`phase`、`unflushed` 与冻结 input 必须值和类型一致，不能重算 input/binding/inventory hash 后把 drop 重标为 reverse-half 或另一切点。最终适配器 14 项、catalogue 22 项定向通过。此前另有 A10/entrypoint/matrix 工具回归通过；统一 host 门将在主工作区再次覆盖新增代码。

CLI：`python3 -B tools/verify_v13_a10_receipt.py <matrix-evidence> --source-root .`。即使原始矩阵重建完整，它仍输出 `NOT_RUN` 并退出 2；原生 launch、preboot injection 与 QMP capture 尚缺完整独立来源契约，中央 A10 native admission 保持关闭。该交付不能把历史 matrix summary 的 PASS 升格为完整 A10 PASS。

## 新原生双节点结果

冻结镜像、已核验补丁 QEMU、wallclock / MTTCG、要求至少 1 个有效 pair 的新运行位于 `artifacts/v012-parallel-native-pair-20261029/result.json`。本机没有同时运行构建、测试或其他 Agent 的重型解析。

- 状态 **FAIL**，退出 1；580.357059 秒时实际错误为 `ValueError: unified event trace overflow`，不是 600 秒观察超时。
- 两节点普通业务 probe 均完成。最后保留的控制统计分别为 jobs 402/317、Applied 279/213。
- 最后稳定采样：节点一 trial 3 / Archive，verified=0、excluded=2、durable archives=2；节点二 trial 2 / Drain，verified=0、excluded=1、durable archives=1。有效 labels、训练与验证样本均未取得。
- 这是轨迹容量边界导致的直接运行失败；此前的学习排除、归档和收尾进展需分别依据原始记录诊断，不能仅凭最终错误归因为同一缺陷。
- runner 的整体 `source_build_attested=false`、release acceptance=false 保持原义。独立调用 `verify_source_build` 在运行后重新核对，编译源码 map 和双镜像仍与 build manifest 完全相同（`facca7e...` / manifest `0ad273b7...`）；这项身份检查不把失败运行转为原生 PASS。
- 已确认本轮 QEMU、构建、测试进程全部退出。原始 bin、串口、磁盘、PCAP、QMP 与最终报告保留。修改仍未提交或推送。

最终 catalogue 报告仍退出 2，69 项 NOT_RUN、FS incomplete、完整验收 false。下一批必须关闭实际回放失败与有效配对缺口，不能靠提高预算、忽略 trace overflow 或填入 PASS 完成。

## 停机后的三路独立诊断

### Publication CPU 与 jobs 停滞

两个 `DOMAIN_CONTROL_EVIDENCE.bin` 的不可变停止银行均为一次停止、偶数封口 word191=2。实际同 CPU 计费如下；不是用 wall 时间估算：

| 字段 | node1 | node2 |
| --- | --- | --- |
| 原 Job / 族 | 402 / D8 ServiceBatch | 317 / D2 SpawnTokens |
| target | `[5461571,1]` | `[8,1]` |
| accept 开始 | 14.649614992 s | 12.777588992 s |
| decode / 其余 publication | 93,875 / 425,416 ns | 84,419 / 416,331 ns |
| 总 CPU / 超出 500,000 ns | 519,291 / 19,291 ns | 500,750 / 750 ns |
| stop flags | 3：Registry 与最终累计计费均停止 | 2：最终累计计费停止 |
| 原版本 / 保留结果 | 309 / Applied，error0 | 234 / Applied，error0 |

`domain_control.rs` 的累计 cap 含 decode；`next_locked_inner` 在 `optimization_stopped()` 后不再创建 Job，解释 jobs 固定在 402/317。原回执保留与停止后续优化可同时成立。两个动作从 snapshot 到完成约 5.429/5.587 ms，未触及原 50 ms wall deadline。任务 overruns/quarantine、runtime quarantine/control faults/failed CPUs 及 panic bank 均为零；不能把 publication 优化预算停止写作任务 CPU 隔离。当前没有足够分段证据把超限归因于某个回调或锁持有者。

### 会话重连与统一事件溢出

Node1 原始事件总数 201，槽内只能保留前 200，验证器据此正确拒绝。前缀中 TLS 认证/driver.connect 成功事件 3 有 73 次，会话拆除事件 4 有 74 次，成员证明绑定 `0x211` 有 50 次；没有 READY `0x212`，远程任务 starts/finishes 均为零。反复认证/退出的原因仍需原始退出阶段证据，不能将此误写为业务正常而仅诊断空间不足。

Node1 串口包含 214 个完整帧、loss/corrupt=0，但尾部还有 16 字节残留帧头；只有同样的 200 条完整服务事件，第 201 条既不在保留槽中也没有完整串口副本，无法补回。Node2 有 166 完整帧、152 服务事件、无残帧。当前失败必须保留。

### 学习归档的容量与收尾期限

现有文件系统 oracle 验证两盘的 redo CRC、COMMIT SHA 链、inode/extents/bitmap，均无丢弃尾部。按当前 producer 格式诊断出四段长度完整的磁盘记录：node1 trials 1/3 与 node2 trial1 各有 8,192 intervals，Capture/Verify 均为 Capacity；node1 trial2 为 Deadline，seal 比 observation end 晚 8.404986 秒，超过原五秒收尾界限。三个 Capacity 记录中 CPU0 ExecutorWork 分别占 7,959 / 7,930 / 7,980 条。

Node1 的第三段虽已完整出现在磁盘，owner 仍为 Archive、`archive_complete=false`，不能算第三次完成读回并退休。owner 的 error14 是保留的 Conflict，与归档中的 Capacity/Deadline 分开。字节范围、SHA、请求结果及验证限制见 [归档核对记录](v012-native-learning-archive-inspection.md)。这不是独立重放 event hash 或合格样本证明。

## 已确认的下一批任务

| 任务 | 可并行写入边界 | 完成门 |
| --- | --- | --- |
| P0：D8/D2 publication 实际分段归因 | `domain_control` 专用诊断与真实函数回归，主集成者持有共享 accept | 关联同 Job/CPU 的 precommit、Registry 返回、release、最终 sample，复现“回执成功后累计越界”；以实际热点选择最小优化，预算不变 |
| P0：会话退出原因与有界事件持续归档 | cluster runtime/监督专用诊断、独立原始事件 checker | 每事件绑定 boot/service generation/序号/时间/参数，核对总数、保留前缀和归档完整序列；缺号、重复、乱序、残帧均拒绝，定位 READY 前反复退出的实际阶段 |
| P0：CPU0 ExecutorWork capture 与收尾进展 | learning capture/Work/Task 专用诊断；共享控制文件由主集成者串行接入 | 识别用满 8,192 条的真实 owner/物理区间；保持完整 CPU union、固定工作区和原收尾界限，按精确 trial/request/caller 查清 Deadline/Conflict |

这些任务由本轮新原始事实形成，尚未实施，不以猜测的算法修复替代分段测量。三个实施工作树及取证结果保留；没有后台构建、测试、QEMU 或轮询继续运行。

## 现有远端 CI 的结束状态

[40927380240](https://github.com/cyllor/CyxiaOS/actions/runs/40927380240) 最后只读查询已为 failure：首次 pair 26.564 秒报 `native governance runtime fault 1793`；五个服务重启场景均到 180 秒 TCP deadline，原始证据上传成功。它与本机本轮的 publication 停止/轨迹溢出是不同运行，不能直接合并根因，也不能再将历史 Actions 额度不足视作当前阻塞。
