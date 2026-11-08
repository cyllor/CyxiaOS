# V0.16 实现恢复与验证 — 2026-11-08

本轮新源码A01/A02/A09已重新采集并独立通过：A项3 PASS、13 NOT_RUN；全部51个A/T/E项为3 PASS、48 NOT_RUN，18动作族仍NOT_RUN。新A06寄存器子集通过但完整A06未通过；A10新prepare/reference局部通过，mode4中断且完整A10仍NOT_RUN。当前功能测试通过，额外严格特性/示例Clippy存在保留的既有FAIL，整体engineering_status=FAIL，不能概括为全部工程门禁PASS。旧最终源码B的三项A PASS已封存，没有继承给新源码；完整原型和release未通过。

## 来源与本轮身份

V0.16 初始审核提交 `abd8fa01d0dab42c43ecd4c1a4cf29e24ba9906f` 的父提交为 `32057802e6e7d9239d04f1e7e3fed4f82f90db7e`。此前恢复来源与 V0.15 A09 r7 的编译清单 957/957 文件 SHA256 一致；这证明恢复来源，不代表新 V0.16 与旧 r7 相同。V0.16 R01–R09、软件版本 0.16.0-dev 和设计配置 1.3 均保留；历史 `v16-verification.json` 的原字节与固定审核提交不变。

2026-11-07 最终源码 B 为 `fc44e8d90d9d0d06773c9828fdd9870ca480b0149f7bfe48a9f74c5a21f6ffae`，其 record、源码和原生证据保存在 `artifacts/v016-progress-20261108/prior-sealed-source/`。B 的 SOURCE_INTEGRATION_METADATA_ONLY 批准只属于原范围，不给新源码或完整验收继承 APPROVED。

本轮编译输入 C2 为 957 项，SHA256 `e01a6dca5a266b72daabeaf45d53bd0ebe83c2e49c7b4ef82ee24827cc98dd0c`。实际工程执行分两阶段：

| 执行阶段 | Git 文件数及完整 map SHA256（自排除 record） | 实际适用范围 |
|---|---|---|
| 本轮主要源码修复后、cache 修复前 | 1790；`455e32033902cbfe9659efa9d29a79cd2a933fcc7438aece2593fe8dfb21072b` | main prototype599/620、默认及 feature 严格 Clippy、cluster decoder25 等实际执行 |
| cache 修复冻结后 | 1791；`57dcad00a307ec6b7e1e3f9413a2282a6e5dcc5554d0f976e32a1a5295f9b3b0` | 完整 tools382、builder host8、新 normal/memory/storage 构建；编译输入仍是 C2 |

本轮共13个受审实现/工具/测试文件落地，清单见 `artifacts/v016-progress-20261108/integration-file-map.json`。后一个阶段只修改 `tools/build_unified.py`、`tools/build_v15_registers.py` 并增加 `tools/test_build_source_cache.py`，没有改模型/学习或其他编译源码。因此旧阶段的599/620保留实际执行身份，经这三个工具文件的范围核对关联，不声称在 cache 修复后重跑。两阶段执行前后 source maps 均实际相同。文档落地后的最终 fullGit 身份要另生成，不把未来 metadata 字节倒写进捕获期身份。

## 工程结果

| 实际命令范围 | 结果 | 执行与限制 |
|---|---|---|
| main `cyxia-prototype` 默认完整测试 | 599 通过，0失败/0忽略；86.672s | 107组输出，含新增四项 SGD 回归；主仓库真实执行，非候选结果 |
| main `cyxia-prototype --features cluster-engine` 完整测试 | 620 通过，0失败/0忽略；124.822s | 与默认套件重叠；feature多出cluster_engine16及native_unified_store5，不能相加成独立总数 |
| 默认 `--lib --test learning_rounding -- -D warnings` | PASS；rc0 | 修改的生产库及新增回归实际 strict gate |
| cluster-engine 同 scope 严格 Clippy | FAIL；rc101 | 未修改的 `cluster/engine.rs:887` collapsible_if、`:1205` nonminimal_bool；两处与落地前来源 SHA 逐字一致，无规则放宽 |
| 额外 `--all-targets -- -D warnings` 探测 | FAIL；rc101 | 未修改 example `verify-ownership-evidence.rs:165` manual_is_multiple_of；原日志保留，与上述两处不同 |
| cache 修复后完整 tools | 382 通过，0失败/0跳过；25.976s | 实际1791文件快照，含新五项真实Cargo测试一次 |
| cache 修复后 builder host | 8 通过，0失败/0跳过；0.232s | 与完整tools分范围记录，不能并总数 |
| cluster typed-journal decoder 相关 main host | 25 通过；1.799s | 实际1790文件快照，自己对自己实现的报告不算独立代码审核 |
| 当前 static 工作流四项 | 格式、governance格式、native kernel Clippy、governance Clippy PASS | 此scope没有执行 feature库或全部example的strict检查，不能覆盖其已知FAIL |
| cache 隔离补丁独立复验 | 5 通过；4.270s，0 findings | 真实Cargo/真实可执行文件；与完整tools中的五项重叠 |

日志、完整 argv、返回码、每配置计数、before/after map 在 `artifacts/v016-progress-20261108/model-main-verification/`、`control-storage-cache-fixed-gates-01/`、`model-cache-independent-review/` 和 `main-static/`。host使用 `CARGO_INCREMENTAL=0`、`CARGO_PROFILE_DEV_DEBUG=0`；model完整测试另用 `CARGO_BUILD_JOBS=2`，只调缓存、调试信息及并发，没有改变 guest 预算、优化或断言。

2026-11-07 的859项完整host（856通过/3跳过）、135项scoped host、371项tools及Rust工作区1217/feature616/TLS44/集群96均保留原执行范围，不改称本轮完整重跑。旧完整host三项跳过仍是历史A02输入缺失、musl libc.a缺失、Darwin不具Linux subreaper/procfs。当前599/620套件没有忽略项。候选136项通过只属于先前候选阶段，也不替代本轮main执行。

## 已修的实际缺陷与未消除的边界

SGD 的正确路径 `reward::pair → FrozenData → Trainer/数值worker` 出现合法有限数据在已完成34步、处理零基index34的下一样本时被 Numeric 拒绝。最小公开API回归只需两步：合法量化初值和有限奖励产生裁剪梯度1，更新项恰为1/256；但规定RNE减法得到的新参数位于更粗浮点格点，重新相减两个已舍入端点会略超1/256。软件与独立硬件IEEE位完全一致，故不是softfloat算错。修复在RNE减法前检查实际裁剪更新项，再按原顺序减法、投影；没有epsilon、seed变更、学习率/clip/144/72门槛或黄金向量变化。新增weight、bias、1280状态独立IEEE逐位比较及真实奖励API下144/72机制fixture四项，在原版全部RED，候选和实际main全部GREEN。fixture的authority及数据是合成机制输入，没有导出原生144/72数据或Learned包。

设计§6.3同时要求规范RNE更新及字面“存储参数每步差值≤1/256”；上述反例揭示舍入边界冲突。本修复保留规范运算和裁剪更新项上限，不声称满足任意已舍入端点的字面差值不等式；该解释/符合性问题保留 OPEN_INTERPRETATION，冻结规范原文未改。

A10真实mode4 reverse尝试约60.869s失败，原始收据没有被升级。实际普通client重现已完成WRITE返回EAGAIN被当成终止失败；修复仅在该完成状态做有界、新request的重试，保留原总deadline、原CPU/采样/文件规模，以及对象、offset和完整count核验。独立字节oracle和背压机制回归不代替新的原生selected slice，更不代替完整A10矩阵。

集群的真实持久journal body使用typed schema2。旧解码契约不兼容，现由source-bound本地helper按精确类型、长度、摘要和闭包解码；不接纳任意caller revision或未知schema。修复前e3e pair实际四次mutual READY但远程任务STARTED为0，180s full runner仍FAIL；decoder host25通过不把它改写为原生A12成功。

## 已拒绝的缓存污染与可信重建

控制器在启动任何新VM之前发现，第一轮normal/memory/storage的两节点共六个ELF含 `CYXIA_A01_TIMEOUT_DIAGNOSTIC`，而本轮main C2不含临时探针。仅有manifest声明的源码map不足以证明Cargo复用的依赖正确。六个错误镜像及相关driver archive已保留，三个build全部标记 `INVALID_BUILD_PROVENANCE_DO_NOT_USE`；这些镜像没有启动VM，也没有产生可继承的native PASS。

忠实保留旧共享target选择策略的真实Cargo反馈循环两次RED：请求源码B、把mtime恢复成A，却执行二进制A。修复把CLI、环境和默认target参数统一解释为cache base，在其内按“canonical source_root + canonical compiled source map”生成独立namespace；临时checkout和main、不同源码内容、保留mtime的改动都隔离。unified与register builder共用此契约，拒绝namespace symlink，验证Cargo实际返回的kernel executable/OUT_DIR属于选定namespace。manifest记录base/effective目录及key；不是通过删除证据、放宽阈值或把mock当真实编译证明。

真实Cargo五项回归覆盖backdated B、新checkout编译路径见证、稳定key、namespace链接和artifact逃逸；作者和独立复验通过，并纳入完整tools382。随后仅清理已保管的自有停止bare-metal release缓存，重建以下三profile：

| 新profile | 当前状态 | build-manifest SHA256 | node-a ELF SHA256 |
|---|---|---|---|
| normal | BUILT_NOT_RUN | `be772f7fba68007ab36bed14dab2ea1929ea325ab17aaaba45058192cd71e7fe` | `1f7ae93d741e727d18d06f332c0e96e4f475c7fe3f6e0ee553cabe73dccf5dc5` |
| memory | BUILT_NOT_RUN | `3b6a5e71e8512f94335a0e91006eb97363de2a88ee0c8d96b40911849a48dedd` | `d87abd7c2ce051d0c7a95a2cc28538d64037b79fecd0c920f157aa2c8ed8f3f8` |
| storage | BUILT_NOT_RUN | `bda98c876ed36f85239cc14fc7642c5e161d4ae23164c2aa88321a8d7f57647b` | `592896b9515d445e30b9431aad21a093ca1b52c6a2f0fe48198e5eeda17d9a00` |

实际新目录为 `artifacts/v016-progress-20261108/builds-current/{normal,memory,storage}/`；三个build均实际rc0、两节点都未检出诊断探针，编译map仍是C2，执行入口为该目录的 `execution.json`。表中BUILT_NOT_RUN是不可变build-manifest的构建状态，不表示后续没有运行；实际native结果单列如下。旧A06寄存器子集不能因未检出某个标记就推定缓存可信。本轮已用同契约新建registers-02并实际运行，旧registers01不升级。

## 原生状态、失败历史与下一步

当前新源码的A01/A02/A09三项PASS来自以下fresh captures及独立验证，原始工具/镜像/源码身份与旧B分开。全部16项范围见 [2026-11-08进度](v16-a01-a16-progress-20261108.md)。

| 当前原生范围 | 实际结果 | 完整验收边界 |
|---|---|---|
| A01 `a01-current-01` | 新八profile采集41.444543s、独验8.181001s，PASS | 本次A01通过；旧IoTimeout风险仍OPEN，不声称production driver修复 |
| A02 `a02-current-01` | 采集3.729244s、独验0.666515s，PASS；1次绑核请求拒绝、接受0 | 只代表A02，runtime_truth=false |
| A09 `a09-current-02` | 采集232.082963s、独验0.771026s，PASS；4097文件页、3909淘汰、8匿名哨兵 | full_a09=true、actual_cache_pressure=true、runtime_truth=false；不是完整原型验收 |
| A06 `a06-registers-02` | 六context各timer4/SVC4，native runtime0.189496s、独验约0.207s，子集PASS | GPR/FP/SIMD/FPCR/FPSR架构边界；normal quit/wait0非forced。完整A06仍NOT_RUN |
| A10新reverse prepare/reference | prepare60.820s/独验3.052s，reference60.788s/独验3.770s，分别局部PASS | 两个clean child，不是cut/recovery或完整A10矩阵 |
| A10新mode4 cache-eviction | 外部298.046s中断；producer300.860s原样FAIL/INCOMPLETE、QEMU exited，无独立PASS | 不是源码21720s budget timeout；mode4与完整A10仍NOT_RUN |

A01/A02绑定本轮normal ELF，A09绑定本轮memory ELF，上表构建hash不换成失效镜像。A09本次 `source-manifest.json` 原文件SHA256为 `5f9e9d52c413d0f359870c8362a048f9a79b3dcd5b35101076e741b66b665259`；这是原文件字节摘要，不能与957编译map的C2或1791文件fullGit的57dc互换。

A09第一次 `a09-current-01` 约6.271s失败，CREATE `/a09`/flag返回-2、client103，原因是控制器误传普通 `prototype-disk`；独立验证也保留incomplete inventory拒绝。纠正为真实Cargo报告的专用 `prototype-memory-disk`，artifact SHA256 `fc38b549b4afb91ccdae1845d56ad02b3614cb970697471aadf4669737ae93b0` 后，按原host timeout300重新采集current02，没有源码或guest预算变化。前次FAIL原raw保留为错误setup历史，不改写成PASS或内存/预算回归。

A10 mode4的最后可读诊断包含guest_now约122s、returns4236、service stage53。采样长期未推进、若干关键banks缺失不足以确认source C2下的根因；当前保留为未闭合的原生进度问题，不因client host修复或前两阶段通过归因/升级。外部停止和producer原始FAIL分层记录，不能把人工中断记成达到源码总deadline或成功完成。

| 保留的旧证据 | 原始结论及边界 |
|---|---|
| 旧最终B的A01/A02/A09 | 当时独立3 PASS，已封存；不是C2的PASS，不能迁移hash |
| A01旧after-flush故障 | 真实MountError Io(Timeout)，reads2891/writes0/flushes0；仍OPEN_UNATTRIBUTED |
| A01本轮32次探针诊断 | 基于旧B的临时checkout，32次未复现、timeout banks均0；非正式A01、无production driver修复，不能证明原故障消失或采样频率因果 |
| A03旧60s/独立20s | 60s成本515546ns>500000ns cap，20s无stop；两场分开，不以后者最新低成本替前者解释 |
| A10历史局部与拒绝 | 旧固定node selected四阶段独验通过；更早unaccounted-event和自动#block131/假设#block101的两代拒绝仍拒绝，未跑mode3者不写成恢复PASS |
| A10本轮旧mode4 reverse | 实际FAIL，不以新client或oracle通过改写旧收据 |
| A09本轮current01错误setup | 普通formatter导致client103/CREATE -2，原raw及独立拒绝保留；专用formatter下新current02是另一条通过记录 |
| A10本轮新C2 mode4 | 外部中断，producer FAIL/INCOMPLETE/QEMU exited；未达到21720s源码budget，无mode4验收PASS |
| A12修复前e3e pair | mutual READY四次、STARTED0；180s runner FAIL，尚无原生任务准入闭环 |
| 首轮三profile缓存污染 | 六错误镜像保管、build全部INVALIDPROVENANCE、未启动VM；新构建与新capture必须独立绑定 |

A03的合法头层可表达轻重差异；当前未改冷seed，固定quiet特征的首轮144步可达界不能推导多轮学习不可能。A08的CPU单调奖励API检查不等于完整native paired成本证据。A16至少需18族各8/4共216个真实accepted labels，。若每标签各执行一对不复用的串行10s试次，则432个观测侧合计4320s，另加apply/warm/cleanup和验证/Shadow/Canary；这是该执行方案估算，不是本轮实测或不可缩减下界。60s诊断不能完成该数据门槛，storage profile还会暂停普通learning trial。本轮不造数据、不导入伪trained模型、不放宽500000ns发布cap或学习预算。

原IoTimeout、模型响应/旧成本、SGD规范解释、新C2 mode4未闭合进度、完整A10和其余A/T/E义务继续开放。whole_branch_review保持CHANGES_REQUIRED，release_acceptance_verified=false。最终source_binding、独立重放与SOURCE_INTEGRATION_METADATA_ONLY结论分别登记在[恢复验证记录](v16-reintegration-verification.json)；狭义来源审核不覆盖全分支或原型验收。

## 证据与最终关联

源码归档只含源码和公开metadata；raw/native私有镜像、build上下文、测试原日志和诊断失败另存ignored目录，不假称它们随Git源码分发。当前本机保管根为 `artifacts/v016-progress-20261108/`；旧B保管根与当前分开。A09保留实际构建/捕获时main绝对source_root；镜像路径迁移不是重编译，换源码根也不承诺panic rodata或二进制可移植逐字复现。

capture_identity必须固定真实编译map、当前build/镜像/profile、run nonce、工具closure、raw及独立结果；最终source关联/离线重放是另外一层，不能把未来metadata写成capture-time全部Git字节。文档/README落地后仅允许核验过的metadata差分，再生成自排除record的最终fullGit binding；记录、审核和外部archive raw SHA单独封装防自引用。固定初始审核仍用abd8fa0的Git blobs重验，不能改历史hash继承APPROVED。

最终record和metadata完成后，使用与源码工作流相同的检查命令：

```sh
python3 -B - <<'PY'
from pathlib import Path
import textwrap
workflow=Path('.github/workflows/v16-source.yml').read_text()
start=workflow.index('          import hashlib, json, subprocess\n')
end=workflow.index('          PY\n',start)
exec(compile(textwrap.dedent(workflow[start:end]),'v16-source:metadata','exec'))
PY
```

source-boundary检查只表明历史blob、当前map与必要字段满足来源边界；实际执行结果以恢复验证记录为准。本轮功能测试、feature/example Clippy FAIL、原生独立结果、全分支审核和release仍分别保留，不能被该命令覆盖。
