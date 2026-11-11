# V0.16 完整原生采集入口修复 — 2026-11-11 R14

本轮实现独立的双客体 Full 采集入口，继续采用客体原生采集、训练及验证路线。没有离线训练或改写启动模型，也没有修改原生预算、实验时长、族划分及数据门。基线为 `fc37f1f2a453e58bb74c35bae0b9163c34d31106`。

## 原入口为什么不能完成完整采集

`run_v16_a03_full_frontier.py` 和 `run_v16_a03_full_retry_v2.py` 的契约是首两组配对观察；它们主动在该前沿结束，不能承载 18 族完整采集及后续数据阶段。只延长宿主超时并不能改变它们的终点。Full 后续 D10、D12、D16 还需要真实对端，单客体 listener 不足以运行完整链。

另修复 v2 的两个已复现工具问题：合法的冷启动 boot 发布计数可以为零；较长 QMP transcript 应使用独立、严格且有大小上限的 JSON 读取器，不能误用通用 4 MiB 文件限制。v2 仍保持首两组观察用途。

## 新入口与终点

- `tools/run_v16_a03_full_collection.py` 同时准备两份新 512 MiB 磁盘、独立 UUID/nonce、不同公有身份和 MAC，以及 listener/connector 私有链路。两客体均完成初始化后才开始执行，每客体维持 4 CPU、1 GiB RAM。
- `--until validated` 为默认终点：Full owner 完成、18 族各 8 条训练及 4 条验证配对、共 216 对、没有待配 baseline，collector 自有 scratch 已释放，原生 data phase 到达 11（验证候选交接）。该交接不证明 Active 切换或最终学习会话全部资源释放。
- `--until collected` 可选择仅等待完整计数及 collector 自有资源释放，允许 data phase 为 2–11。该状态不宣称训练和验证完成。
- 每 5 秒读取较小的进度 bank；命中终点提示后先暂停两客体，再分别读取全部 13 个 bank 并复读。撕裂的发布快照允许恢复重试，历史暂停轮次及其证据保留。Full 的 focused-complete 标志合法地保持零，不能误作失败。
- 普通排除、准备失败的 drain/archive 和重试属于真实采集过程。Tasks quarantine/overrun、optimization stop、learning worker 硬失败、collector Failed 和 data Rejected 仍立即失败，保留两客体暂停诊断并分别正常关闭所属进程。
- 宿主默认观察窗口为 172800 秒，最大 259200 秒；这只调整宿主等待窗口。原生 10 秒观测、1 秒预热、5 秒收尾、500 μs 发布、2 ms MLP 和 1 MiB 学习工作区保持不变。

## 独立校验与证据边界

`tools/verify_v16_a03_full_collection.py` 独立重验 source/build/ELF/model/QEMU/工具闭包、公有节点身份、精确启动 argv、配置注入、原始 QMP 收发与解析记录、物理地址和宽度、暂停双读、进程 quit→EOF→wait0、独立第一启动磁盘以及磁盘最终哈希。拒绝符号链接、硬链接及超限工件。

`tools/v16_a03_collection_journal.py` 从已提交卷重建 regular/preparation/late journal，按磁盘 UUID、boot epoch、schema、长度和原生格式导出原始字节。分别核对 regular 成功、regular/preparation 排除及包含 late 的总归档计数；显式允许对端没有自己的 journal。它只核验已提交字节及格式，不认证 peer 签名，不重算完整 Reward 标签或整数 MLP。

最终成功前再次比较完整工件清单与独立校验器刚刚验证的清单。证据被等长替换、清单写盘失败或 summary 写盘失败都撤销成功，并返回非零 CLI 状态。

因此工具成功为 `FULL_COLLECTION_VERIFIED`，仍明确输出 `full_dataset_verified=false`、`model_trained=false`、`active_model_verified=false`、`A03_complete=false`、`native_acceptance_status=NOT_RUN`。完整数据标签复验、候选发布链及最终实际 1→2→1 验收另行完成。

## 使用

从仓库根目录执行，输出目录必须尚不存在；默认使用现有原生互斥锁，不能与 VM 或构建任务并行：

```sh
python3 -B tools/run_v16_a03_full_collection.py \
  --source-root "$PWD" \
  --build-manifest /Users/robin/cyxia-native/scratch/frontier-b7e4/build/build-manifest.json \
  --formatter "$PWD/target/source-58a44230007c9e89dd99b0d87a17a8c38d9cc875977747106ba3c1d4f1f09208/aarch64-apple-darwin/debug/examples/prototype-disk" \
  --qemu-binary /Users/robin/cyxia-native/qemu-exact-20261106/build/qemu-system-aarch64 \
  --qemu-source /Users/robin/cyxia-native/qemu-exact-20261106 \
  --output "$PWD/artifacts/v016-a03-full-collection-next" \
  --until validated --timeout 172800
```

`progress.json` 原子更新两节点 phase/family/group、配对与逐族计数；失败详情在 `summary.json`、每节点 `failure-*.bin`、serial、QMP 及进程退出记录。输出不能复用为原生断点续跑。本轮工具修复没有新增跨进程恢复协议。

独立复验使用 `verify_v16_a03_full_collection.py --directory <输出目录>`，另传同样的五个 source/build/formatter/QEMU 参数；重放旧工具快照时可显式选 `--producer-tools-root`。

## 验证记录

定向工具测试 59 项通过，覆盖首两组及后续族继续推进、全部计数终点、普通排除恢复、双客体先停后读、撕裂恢复、历史致命错误、正常清理与写盘失败、严格大 transcript、归档正反例及贯穿双节点 `verify_capture` 的宿主证据集成。集成 fixture 的原生 ABI/归档解析边界明确使用替身，不能作为原生采集成功证据。

完整工具回归首轮 **784 项全部通过**，耗时 141.777 秒、退出码 0。最终暂停终点另补 family/group 与 collection bank 一致性约束后，59 项定向测试再次通过（10.671 秒）；最终完整回归仍为 **784 项全部通过、142.013 秒、退出码 0**，见 `suite-final.log`。

限时原生探测设置 600 秒观察上限，使用现有 Full 构建 `b8cedda5eb8117d2ac4582429fe2f2988d9e59cbd1b98f3793897ab0c44d272e`、977 个原生输入、源认证 QEMU `e5be7d6a…`。原生输入没有改变，未重编原生二进制。入口 PID 97673 因真实原生失败提前退出 1（含准备共 10.291 秒），配对数为 0：

- 两节点均正常冷启动，boot epoch=1、online mask=15；真实 boot 核验通过，模型自检分别为 171255 ns、184292 ns。
- 节点 B 的首个 CORE Job（sequence=1、CPU1）触发 optimization-stop。原始 bank 给出解码 57838 ns、发布 467494 ns、合计 **525332 ns**，超过保持不变的 **500000 ns** 上限。触发时原生 collector 处于 Prepare、首族首组，未产生成功配对。
- 两客体先暂停并保存全部失败 bank。所属 PID 97766/97767 均经 QMP quit、EOF、wait0 正常退出，forced=false，errors 为空。

当前修复完成的是完整工具入口及其失败证据链；**整轮 18 族原生采集仍未跑通，A03 没有 PASS**。本次触发点需要进一步定位原生首次 CORE 发布的耗时，500 μs 门及 optimization-stop 保持有效。本轮只运行一次原生探测。

命令、PID、退出码、原始工件与小型诊断报告位于 `artifacts/v016-a03-full-entry-20261111-r14/`。该捕获保留当次 source/tool 快照，后续终点校验补强没有改写它；`native-pilot-diagnosis.json` 将上述实际失败与正常退出绑定。该探测不是 18 族完整采集、训练或 Active 验收证据。
