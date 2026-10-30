# V0.12 完整原型并行推进计划

日期：2026-10-29（Asia/Muscat）。规划基线：`CyxiaOS-V0.12@5ab75ab8e9c664246ec9cddd1c24b7f65f340e39`。

实施已获后续用户指令启动，实际工作树、集成与验证状态见 [并行实施记录](v012-parallel-execution.md)。本路线图中的 Backlog 与“尚未启动”描述保留为制定计划时的快照。

本轮已完成三个只读并行审计：控制/学习、集群/存储、验收工具。下列实施任务尚未启动；分支和工作树名称为分配方案，尚未创建。此前的 [并行执行清单](../superpowers/plans/2026-10-29-parallel-prototype-execution.md) 保留为历史记录，其 A/B 实现已进入当前提交，不应重复开发。

## 目标与完成信号

“完整原型”按仓库已锁定的设计配置 **1.3 原生最小原型**执行。规范文件为 `CyxiaOS_Minimal_Prototype_Design_Final.docx`，本次实测 SHA-256 为 `01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0`，与机器目录一致。完整 COSMIC 会话另按桌面移植计划推进，不作为这份 1.3 验收计划的完成条件。

完成必须同时满足：

- A01–A16、T01–T20、E01–E15 共 51 个原生验收 ID，及覆盖 16 域的 18 个动作族全部具有独立核验的 PASS 回执。
- 每个动作族至少两个不同合法选择具有真实行为差异；训练/验证每族至少 8/4 个合格样本，总计至少 144/72，完整 group 不交叉。
- 普通文件断电、乱序、恢复中再次断电及缓存驱逐矩阵完整通过；实际覆盖范围、输入和判定器身份冻结。
- 独立 EL0 治理、学习、Shadow/Canary/Active 转换和回退，双节点任务唯一执行及五个同 BootEpoch 服务重启边界均有原生证据。
- 最终源码的九项主机检查、双节点及治理镜像构建、独立审查通过；`prototype.py report` 与 release gate 仅在所有强制证据齐备时成功退出。

固定约束：4 vCPU、1 GiB RAM、每节点 512 MiB 数据盘；模型工作 CPU 2 ms、publication CPU 500 µs、原始 wall deadline 50 ms；必需控制工作 61 ms/100 ms，每控制核总上限 70 ms/100 ms。保留实际计费、代际、授权、去重、隔离与恢复约束。

## 当前事实与首要瓶颈

1. `domain_control.rs` 已实现 Active 原 Job 重试和累计 publication debit；`domain_tasks/publication.rs` 已实现原生 D1/D13 注册身份匹配。当前待完成的是集成验证和原生效果确认。
2. 两组定向测试本次实际运行 5 项，其中 1 项通过、4 项失败。`test_native_publication_clock.py` 的 Executor 缺 `publication_debit`；`test_native_submission_provenance.py` 的 Job/Executor 与截取的 accept 片段未跟随新字段及 `ActivePublication`、budget/borrow 局部变量更新。这首先是测试夹具适配任务，尚不能据此判定内核运行缺陷。
3. `prototype.py report` 实测退出 2：PASS=0、FAIL=0、NOT_RUN=69，文件矩阵未完成。69 是 51 个 ID 加 18 个动作族，不是 69 个从零开发任务或完成率。
4. 中央 `check_v13_evidence.py` 目前仅接入 A02 原生 PASS 回执，拒绝其他 ID/动作族，并固定文件矩阵及整体 incomplete。需要增加严格的分场景适配与最终聚合逻辑，不能靠填写状态完成验收。
5. 同启动代际服务监督、五个故障 profile、A10 可恢复完整矩阵执行器已存在。主线是执行、定位失败及闭合证据。
6. 最后已归档的旧原生记录有 9 个持久归档、4 个 verified baseline sides，但有效 pair、training、validation 仍为 0。完整归档、单侧有效、有效配对和合格样本是不同阶段。
7. 基础 doctor 通过；仓库外开发身份目录存在，未读取密钥。当前 `/opt/homebrew/bin/qemu-system-aarch64` 的版本检查通过，但其 per-vCPU PMU 补丁来源和二进制身份尚未核验。
8. 本次查询 [现有原生 CI 40927380240](https://github.com/cyllor/CyxiaOS/actions/runs/40927380240)，其 HEAD 正是本基线。补丁 QEMU、双镜像和栈检查步骤通过；首次 protected pair 步骤失败，服务重启步骤仍在运行。失败原因待日志/产物确认；不能把历史 Actions 额度不足视为当前阻塞。
9. 旧计划引用的 `.superpowers/sdd/2026-10-25-prototype-v13-acceptance/active-task-publication-brief.md` 不在本 checkout。关键约束应进入受 Git 跟踪的实施记录。

## 并发与所有权

并发上限为 **主集成者 + 3 个工作 Agent**。开发阶段各自使用独立工作树 `../CyxiaOS-V0.12-lanes/<任务ID>`、分支 `work/v012-<任务ID>` 和构建缓存；本计划不预先创建它们。

| 任务 | 优先级 / 建议负责人 | 可并行阶段 | 独占写入范围 | 依赖及合并门 |
| --- | --- | --- | --- | --- |
| V12-00 环境、证据调度和源冻结 | P0 / 主集成者 | 与只读审计、契约设计并行 | 本计划、证据索引、必要的 `.github/workflows/native-replay-current.yml` 和 `build-cyxia-qemu.yml` 改动 | 先读取现有 CI，确认补丁 QEMU 与身份；所有原生运行由此统一排队 |
| V12-01 旧回归夹具适配 | P0 / 回归 Agent | 首批工作槽 1 | 下文列出的 harness 与对应专用 Python 测试 | 当前可开工；原断言及负向变异保留，定向通过后交主集成者跑九项检查 |
| V12-02 严格回执注册与聚合门 | P0 / 证据 Agent | 首批工作槽 2 | `tools/check_v13_evidence.py`、`tests/host/test_v13_evidence.py`、新回执适配模块 | 可先完成契约/反篡改测试；实际登记依赖各场景完整回执与独立审查 |
| V12-03 双节点与五个服务重启边界 | P0 / 集群 Agent | 首批工作槽 3：日志与代码诊断；原生运行排队 | `tools/verify_unified.py`、集群/网络/监督实现及专用测试，详见任务卡 | 先用现有 CI 事实定位失败；普通双节点 READY 成功后逐一验证五边界 |
| V12-04 Active 发布与首个合格配对 | P0 / 主集成者 | 集成与原生运行阶段 | `kernel/src/domain_control.rs`、`domain_tasks/publication.rs`、`prototype_runtime/native.rs`，以及实际证据指向的控制修复 | 依赖 V12-01、九项检查、独立审查和新双镜像；600 秒原生回放独占执行 |
| V12-05 A10 完整文件故障矩阵 | P0 / 存储 Agent | 先核对工具/诊断契约，矩阵运行排队 | A10 runner/verifier/fault-disk 工具及专用测试；FS 修复另设子任务 | 依赖冻结的 `--selftest --storage-fault` 镜像；子集后执行 `all/all` 并独立重建 |
| V12-06 18 族采样与学习治理闭环 | P1 / 学习 Agent | 可先设计覆盖表；正式采样在 V12-04 后 | 独立学习分析工具/测试；生产修改限 `domain_control/{learning,learning_driver,governance}.rs` 和 `crates/prototype/src/learning/` | 保留与 V12-04 的源码冻结边界；先小规模合格 pair，再达到每族 8/4 和模型转换/回退 |
| V12-07a/b/c 其余场景独立注入与判定 | P1 / 三个场景 Agent，后续批次 | 三组新模块可并行；运行排队 | 各自新建 `run_v13_{control,resource,cluster}_cases.py`、`verify_v13_*_cases.py` 和对应测试；不并改中央 checker | 先交付逐 ID 契约和缺失原生钩子清单，再按最小场景实施；V12-02 串行接入 |
| V12-08 最终证据归档与验收 | P0 终门 / 主集成者 | 顺序执行 | `v13-requirements.json`、发布记录和最终证据索引 | 依赖所有任务及独立审查；任何强制 FAIL/NOT_RUN 均保持未完成 |

所有实施卡当前状态为 **Backlog（规划完成，待分支/工作树分配）**。运行或审查卡在前置条件满足后进入 Ready；不能把本轮审计完成记成实施完成。

共享文件规则：中央 checker 归 V12-02；`verify_domains.py`、`build_unified.py`、共享 ABI 和 catalogue 由主集成者串行接入。跨任务 API 先提交字段、错误语义与原始事件契约；其他 Agent 不直接改写该所有者的文件。

## 首批任务卡

### V12-00：优先复用现有 CI，建立原生运行前置条件

- 只读获取本基线 CI 的结束状态、首次回放错误、原始记录及五 profile 结果。失败必须按真实阶段分类；当前尚无日志证据支持根因判断。
- 本地运行前核验固定 QEMU commit `f8ed81651e61d9c2166df6121ce2af0f44f06b3e`、`cyxia-per-vcpu-pmu.patch`、changed-source hashes 和 binary hash。基础 doctor 不替代该门。
- 核对固定测试输入，复用现有私有身份；输出使用新目录。每个运行记录源码、规范、模型/schema、镜像、工具、QEMU 及场景参数身份。
- 显式构建 `target/debug/examples/prototype-disk` 和 `verify-domain-evidence`，登记路径与 hash。原生镜像 builder 不生成这两个回放辅助工具；当前 checkout 均缺失，必须在运行前准备。
- 完成信号：所需输入可解析，双镜像及 governance ELF 和栈门齐备，计时宿主空闲，具备可复现命令及失败证据目录。

### V12-01：适配已有新接口，恢复回归可信度

文件：`tests/host/{native_publication_clock_harness.rs,native_submission_harness.rs,submission_completion_harness.rs,submission_accept_segment.rs,first_candidate_rejection_harness.rs}`，及 `test_native_publication_clock.py`、`test_native_submission_provenance.py`、`test_first_candidate_rejection.py` 等实际受影响的专用测试。

- Job/Executor 显式初始化新增 debit；截取的生产 accept 片段具备完整局部环境，ActivePublication 跟随真实构造。
- 保留原始时钟、计费、交付/abort、拒绝来源断言。负向变异必须先成功编译，再因预期的行为断言失败，不能用编译错误作为变异有效的证据。
- 与 `test_active_accept_retry.py`、`test_scheduler_publication_contract.py`、`test_carried_publication_budget.py`、`test_active_scheduler_publication.py`、候选初始进展测试共同验证。生产实现缺陷另报告给 V12-04 所有者。

### V12-02：补齐最终验收器，而不提前开放通过

- 先复用 A02 和 A10 独立原始事件 checker，为各类回执定义固定注册接口；后续各场景提交自足 adapter，不由 manifest 指定任意可执行判定器。
- 原始记录、源码/构建/镜像/工具身份、参数、完整覆盖及篡改反例必须可重放；缺证据、旧版本、错误场景或不完整矩阵均拒绝。
- 仅在所有 51 ID、18 族和 FS 证据确实通过时计算整体完成；实现过程中保持缺项非零退出。一个功能探针或汇总 PASS 不自动关闭多个 ID。

### V12-03：从双节点 READY 到同启动代际恢复

已有监督与 profile 优先复用。实现归属限定为 `kernel/src/{unified.rs,unified_task.rs,unified_task/custody.rs,unified_store*.rs,domain_network*.rs}`、`user/prototype-cluster/src/{runtime,broker,abi,driver/custody}.rs`、`tools/verify_unified.py` 及专用测试。只有证据指向的文件才修改，共享 ABI 交主集成者。

- 先从新 CI 产物识别普通会话失败的实际阶段，不将历史 pre-TLS 超时直接认作本轮根因。
- 依次运行 `after-ready`、`after-reserve`、`after-start`、`after-completion`、`after-result-record`。每种 profile 使用各自构建和证据目录。
- 每次必须真正到达所选故障边界，保持 BootEpoch，服务 generation 1→2、恰好一次重启、再次 READY；原任务唯一执行，结果、额度及 completion token custody 不丢失。

### V12-04：确认 Active 修复有效，再扩大采样

- 独立审查同 Job、sequence、snapshot、输出不变；只对借用获取 Busy 保留原 Job，累计所有前提交 CPU，abort/交付保留原 Registry 回执，交付前释放 Guard。
- 冻结源并以新镜像执行 wallclock / MTTCG 原生回放。先读取本基线现有 CI 的失败证据，决定重跑或最小修复；无需盲目重复同一失败配置。
- 停机后核对 CRC/extents/SHA、原始时间/成本、首次动作和续期连续覆盖。首个合格 pair 是扩大采样的门，不代表 A08 全部通过。
- 若仍无合格 pair，保存失败，以真实拒绝阶段拆下一修复；保持原始预算和 deadline。

## 后续任务与完整场景覆盖

### V12-05：复用 A10 矩阵，先诊断后完整执行

工具范围：`tools/{run_v13_a10,run_v13_a10_matrix,verify_v13_a10,verify_v13_a10_faults,verify_v13_a10_matrix,v13_a10_budget,v13_fault_disk,check_v13_fault_disk}.py` 及相关测试。发现 FS 实现缺陷时，单独分配 `crates/prototype/src/fs/**` 修复并重新冻结镜像。

先验证 clean modes 1/2/3/4、少量 cut 及实际乱序，再运行所有实测 overwrite mutation × 两切点 × 两种 volatile-loss，并对恢复中各 mutation 再次中断、第三次启动及缓存驱逐场景出证据。只有完整 `all/all`、受保护 FSYNC 消费切点及独立重建均通过才验收。旧 boot/journal point92 四例及子集通过均不能替代普通 EL0 文件矩阵。完整规模根据 clean run 的实测 mutation 数确定。

### V12-06：有效 pair → 冻结数据 → 模型治理

逐族安排不同合法选择、可区分负载、同 seed/初态配对、完整计费和行为差异。复用已有 FrozenData 与学习实现：每族 8 个训练、4 个验证，group 隔离，最终至少 144/72。随后验证训练、独立验证、Shadow、Canary、Active 模型哈希转换及拒绝/回退；UNKNOWN、未完成 loan 和副作用仍保持义务。数据采样可先做小批以尽早暴露失败，不以合成样本替代原生证据。

### V12-07a/b/c：51 ID 的责任映射

下表分配逐 ID 场景责任；实现任务可提供证据，但必须由对应 checker 按该 ID 的全部 `required_outcome` 判定。

| 场景组 | 负责 ID | 与已有任务关系 |
| --- | --- | --- |
| 07a 控制/学习 | A03、A04、A05、A07、A08、A15、A16；E01、E06、E07、E08、E14（12 项） | 复用 V12-04/06，逐族行为另交 18 族回执 |
| 07b 资源/持久化 | A01、A06、A09、A10、A11；E02、E03、E04、E05、E13、E15（11 项） | 复用 V12-05；A10矩阵以外的隔离、内存、IRQ/DMA、背压仍需各自场景 |
| 07c 成员/合同/远程任务 | A12、A13、A14；T01–T20；E09、E10、E11、E12（27 项） | 复用 V12-03 及现有 reconnect/hang-once/no-stop-ack/leave 入口，逐项证明故障语义 |
| 主集成者 A02 刷新 | A02（1 项） | 复用现有 A02 runner；以最终新基线证据替代不能自动继承的历史回执 |

每组先产出 `ID → runner → 注入点 → 原始事件 → 固定 checker → 缺失钩子` 表，再实施缺失项。12+11+27+1=51；18 族另列为 `D01_WEIGHT`、`D01_CORESET`、D02–D15、`D16_QUOTE`、`D16_PLACE`。目录语义及规范散列由中央门保持锁定。

## 批次、关键路径与合并顺序

1. **批次一，并行开发准备：** V12-01、02、03 分别占三个工作槽；主集成者 V12-00 获取现有 CI、物化设计约束和检查输入。此阶段不并行开展本机原生计时运行。
2. **集成门：** 先合并 V12-01，再按独立审查结果合并 02/03；涉及生产源时由主集成者判断新构建范围。运行九项检查、双镜像及栈门，冻结源。
3. **原生证据窗口：** 同宿主停止所有构建、测试与重型解析；顺序执行 V12-04、V12-03 各场景、A02 刷新、V12-05 诊断与完整矩阵。没有相互资源影响且各自有来源证明的不同宿主，才可以各跑独立场景。
4. **批次二，并行补齐覆盖：** V12-07a/b/c 各自开发新 runner/checker；V12-06 的数据/模型实施按依赖排入空闲槽。中央 checker 由 V12-02 所有者串行集成。
5. **最终门：** 对最终源码完成必要原生重验、全部场景/族/FS 证据冻结、独立审查、九项检查和 release report。源码、模型或判定器变化须重新检查证据适用性，不能静默沿用旧 PASS。

关键路径是 **旧回归适配 → 联合检查/双镜像 → 原生发布/续期连续性 → 合格 pair → 18 族与学习数据 → 全场景独立登记 → 最终验收**。集群、存储、回执开发提前并行，原生计时窗口统一排队。

## 现有入口与验证命令

下列为后续任务使用的真实入口，本轮没有启动全套构建或原生运行。`PAIR`、`BUILD`、`QEMU`、`QEMU_SOURCE`、`EVIDENCE` 等变量须在运行卡中填写核验过的实际绝对路径。每次输出为新目录；矩阵继续运行时显式使用其 `--resume`。

```sh
# 定向重现首批回归失败；适配后再运行相同命令。
python3 -B -m unittest discover -s tests/host -p 'test_native_publication_clock.py'
python3 -B -m unittest discover -s tests/host -p 'test_native_submission_provenance.py'
python3 -B -m unittest discover -s tests/host -p 'test_active_accept_retry.py'
python3 -B -m unittest discover -s tests/host -p 'test_scheduler_publication_contract.py'

# 九项主机检查；首次准备固定测试输入时才用 --fetch。
python3 -B tools/prototype.py test --fetch --output artifacts/v012-integrated-checks
cargo build --locked --offline -p cyxia-prototype --example prototype-disk --example verify-domain-evidence
python3 tools/prototype.py build --identity-a "$PAIR/a" --identity-b "$PAIR/b" --output "$BUILD" --selftest

# 受保护控制/学习原生回放；与 run-pair 的集群场景验证入口分开。
python3 tools/verify_domains.py --elf "$BUILD/node-a.elf" --peer-elf "$BUILD/node-b.elf" --build-manifest "$BUILD/build-manifest.json" --source-root . --qemu "$QEMU" --output "$EVIDENCE" --timeout 600 --hold 1 --sample-ms 250 --clock-profile wallclock --tcg-threads multi --replay-pairs 1

# 五个服务故障 profile 分别构建；这里展示第一个。
python3 tools/build_unified.py --identity-a "$PAIR/a" --identity-b "$PAIR/b" --output "$RESTART_BUILD" --selftest --service-fault after-ready
python3 tools/prototype.py run-pair --elf "$RESTART_BUILD/node-a.elf" --peer-elf "$RESTART_BUILD/node-b.elf" --public "$RESTART_BUILD/node-a.pub" --public "$RESTART_BUILD/node-b.pub" --package "$RESTART_BUILD/task.elf" --build-manifest "$RESTART_BUILD/build-manifest.json" --qemu "$QEMU" --qemu-source "$QEMU_SOURCE" --output "$RESTART_EVIDENCE" --expect service-restart-ready --clock-profile wallclock --tcg-threads multi --timeout 180

# 普通文件 A10：专用统一镜像，不使用 boot/journal-only 构建替代。
python3 tools/build_unified.py --identity-a "$PAIR/a" --identity-b "$PAIR/b" --output "$A10_BUILD" --selftest --storage-fault
python3 tools/run_v13_a10_matrix.py --build-manifest "$A10_BUILD/build-manifest.json" --output "$A10_EVIDENCE" --qemu "$QEMU" --qemu-source "$QEMU_SOURCE" --overwrite-points all --recovery-points all
python3 tools/verify_v13_a10_matrix.py "$A10_EVIDENCE"

# 最终目录门：目前仍应非零退出。
python3 -B tools/prototype.py report
python3 -B tools/check_v13_evidence.py --release
```

九项检查分别为 fixtures、workspace format、governance format、Rust workspace、TLS、host Python、tools Python、kernel Clippy、governance Clippy。构建、主机测试或局部功能探针均不自动产生完整原生验收状态。

## 本轮已核验结果

| 检查 | 实际结果 | 对本计划的影响 |
| --- | --- | --- |
| 三个并行审计任务 | 已完成，只读，无源码改动 | 明确文件所有权、依赖与现有实现，避免重复建设 |
| 路线图独立复核 | 51 ID 无漏重、18 族、四槽并发及主要 CLI 参数核对通过；发现缺失回放辅助工具准备步骤，已补入 | 首批任务与验证命令可据当前源码执行 |
| 规范 SHA-256 | 与固定 1.3 散列相同 | 使用当前规范定义目标 |
| `tools/doctor.py --json` | 通过 | 基础工具链可用；补丁 QEMU 来源仍须独立核验 |
| `prototype.py report` | 退出 2；69 NOT_RUN，FS 未完成 | 保持开发状态，规划回执适配和原生证据任务 |
| native publication clock 测试 | 1 项失败：缺 Executor debit | V12-01 可立即形成明确修复交付 |
| native submission provenance 测试 | 4 项中 1 通过、3 失败：夹具接口漂移 | 与 V12-01 同一所有者，保留行为与变异断言 |
| 现有原生 CI 的只读查询 | 本基线构建/栈门步骤通过，首次回放步骤失败，任务仍运行 | V12-00 优先读取结束产物；尚不判定运行根因 |

本轮交付为规划文档和以上诊断结果；实施任务的测试、分支、运行目录和验收状态将在实际推进时逐卡记录。
