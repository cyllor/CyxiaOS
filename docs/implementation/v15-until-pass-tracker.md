# A01–A16 持续实现与验收

用户最新目标（2026-11-06）：使用 diagnosing-bugs，多任务推进 A01–A16，直到全部正式 PASS。
本任务仍在执行。禁止把组件、诊断或未闭合子场景写成正式 PASS；最终须在同一源码上重跑并独立登记。
上一批历史结果保留在 `v15-a01-a16-progress-20261106.md`，不因本次源码修改自动续用。

## 当前工作线

| 范围 | 现状 | 正在执行的下一步 |
| --- | --- | --- |
| A01 | integration-r2 八次同盘正式链及单独进程重放 PASS；r1 DataAbort 锁槽失败保留，真实 recorder 双调用回归修复 | 后续最终 integration 源码冻结后重跑；不能继承 r2 PASS |
| A02 | integration-r2 与 A01 同源码原生 PASS，652 调度事件、绑定控制核被拒绝 | 后续最终 integration 源码冻结后重跑 |
| A03–A04 | 已集成真实 ApplyId/DecisionKey→handoff→owner publication→APPLIED 原始模型链及完整 MLP/Plan 独立重放；组件与负例契约通过 | r4 原生采集真实 1→2→1；A04 仍缺实际 IRQ/DMA 交错与完整故障矩阵 |
| A05、A08、A16 | 修复启动全零 optional runtime-loop bank 误报；实际单节点已运行到 494 jobs/416 APPLIED，随后 D16 请求到期 | 先用真实请求阶段 bank 收敛 D16 进度；再完成首个配对、18 族真实行为、144/72 分组数据和学习生命周期 |
| A06、A07、A09、A11、A15 | 既有组件通过，完整原生组合场景和正式 verifier 尚未闭合 | 将现有真实 ABI/寄存器/页/credit/恢复路径接入逐断言的原生故障触发与独立记录 |
| A10 | 冻结旧基线的 mode1 实际原生及独立 custody replay PASS（60.863s、14966 请求），仍不是完整 A10 | 新增显式 caller build/formatter/QEMU 的严格总门禁接入；待最终源码执行完整 overwrite/recovery/cache 矩阵 |
| A12–A14 | r3 原 180 秒配对仍失败，初始注册修复尚未闭合整个协议；调用者采样时间不足以判定实际 EL1 拒绝原因 | 已新增实际 EL1 phase9 时间、Authority 前后状态与拒绝来源 bank，r4 复跑区分到期/连接/代际；隔离 lane 实现实际 UDP→候选→TCP 并核验 PCAP |

## r4/r5 后续实测（均非全量 PASS）

- r4 A03 60s 仅完成真实 2→6 扩核、完整模型/所有权/APPLIED 回执，缺少 6→2，正式 A03 保持 NOT_RUN。晚期完整 ring 的 CoreSet seq564 仍有两个合法候选，控制 ratio=9，真实分数95/175仍选6，正在对实际种子模型做可证伪诊断。
- r4 单节点四个 D16 请求全部 Created、完成并 ACK；配对回放仍超时。trial1 因真实十秒观测后的五秒收尾超限468.858ms而排除，原始归档保留；trial2停在Quiescing。不能据此宣称 r2 UNKNOWN 故障已修复。
- r4 SESSION bank 证明实际 EL1 活动间隔2432ms，正确因1500ms期限拒绝；r5 version2加入三个原始内核阶段时间，实测 phase9 入口至接纳仅10–13ms，此次主要空档在入口之前，未修改期限。
- r5 UDP 原生双节点独立 PCAP 重建确认双向合法60B发现、真实候选随机数/IP/端口与随后SYN匹配。仍缺完整A12 READY/双签配置/原生任务准入闭环；重连重建TCP会重置公告节拍，部分间隔小于约2秒，需要修复节拍保管，不能宣称整个发现条款PASS。
- r5 首次单节点在0.667s暴露新增DISCOVERY optional全零启动解析错误。真实捕获对照及调用路径测试先红，修正仅对已发布记录绑定BootEpoch后72相关测试通过。同一冻结guest已用修正工具再次运行；首次失败保留。r5 guest未重建、仅tools/verify_domains.py有此明示修正。
- A06独立寄存器子合同在隔离lane已原生活体及独立重放通过（6个private上下文，各4timer+4SVC，GPR/TPIDR/SIMD/FPCR/FPSR），全A06仍未完成且尚未集成root。正式verifier正在加强精确平台查询/DTB来源负例。

## 已完成的实现增量

- `verify_domains.py` 仅将精确 512B 全零 optional terminal bank 标为 not_published，非零坏记录、截短、奇序列仍严格拒绝。
- A01 新增 protected formal bank、真实 EL1/EL0/DecisionKey/publication hook、八次同盘 runner 和独立 verifier。
  首次真实 native 发现记录器选择条件过宽，已用真实 recorder 的 probe→SVC/preemption 双调用回归修复；解析器条件未放宽。
- 提取实际 `session_turn`，生产和 host 使用同一 TLS/Driver/Authority 执行顺序。
  三个候选行为变更均未解决受控到期模式，已全部还原；授权到期仍按 fresh clock 拒绝。
- 记录级 v2/origin9 显式保留 activity admission 的原 broker 错误，容器布局不变，v1 仍只允许原 origin 范围。
- 临时有界 `APPLICATION_REQUEST_EVIDENCE` 只记录真实队列状态、ID、target、actor 和时间，零 payload；明确标记 `[DEBUG-v15-placement]`，修复后清理或转为正式定义的诊断。
- 总门禁新增固定 A01 adapter、显式可信上下文下的完整 A10 native matrix adapter，以及独立新目录登记入口 `tools/enroll_v15_a.py`。
  单元 mock 仅用于验证路由，不作为真实执行证据；总目录尚未写入新的 PASS。
- A03 新增受保护 ownership bank、原生 collector 和固定总门禁 adapter。实际 recorder 与完整 MLP/Plan 篡改测试通过；正式 A03 尚未运行，不登记 PASS。
- 临时 LOCAL 和 SESSION_ACTIVITY bank 分别记录实际本地创建/查询边界与 EL1 phase9 接纳事实。真实调用路径测试已通过；仅增观测，不改变状态规则或期限。

## 源码与运行隔离

- 初始精确源码：`32057802e6e7d9239d04f1e7e3fed4f82f90db7e`。
- r2 精确 compiled-source 摘要：`40113cadf63a95642b3d5e4f62a0a75e5e535502d430e9c4456affac2fa8e9bd`。
  `catalogue-r2-a01-a02.json` 经固定 verifier 校验后登记 2 PASS / 14 NOT_RUN。它属于 r2，不能当作后续源码的状态。
- `/tmp/cyxia-v015-frozen-3205780` 保留原基线，用于首次 A10 原生有限场景，不与 integration 源码混算。
- `/tmp/cyxia-v015-integration-r1-20261106`、`...r2...` 及同名 tar 保存每次未提交源码的独立快照；编译前核对真实 source map。
- 本批产物：`artifacts/v15-until-pass-20261106/`。旧失败、未运行后代和所有原始捕获保留。
- QEMU 为 `/tmp/cyxia-v015-qemu-exact-20261106/build/qemu-system-aarch64`，精确源码和补丁认证未变。
- 私有节点身份只在源码目录之外，不上传、不写进公共日志。

## 完成条件

1. 修复均由实际调用路径的失败反馈证明，逐变量诊断；临时调试信息按技能清理。
2. 16 项各自全部强制断言、故障矩阵和原生来源合同独立验证成功。
3. 在同一最终源码冻结上重建、运行、重放并登记；不复用旧源码 PASS。
4. `tools/prototype.py report --scope A` 对本批目录退出 0，16 PASS、0 FAIL、0 NOT_RUN。

该 A-only 目标不自动等于全部 T/E、18 动作族目录及独立文件格式矩阵的完整发行验收。
