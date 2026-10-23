# Shell 与本地 AI 文件系统

> 最新 EL0 与 POSIX 子集进展见 [POSIX 第一阶段说明](posix-compatibility.md)；以下保留原切片的历史范围。

后续已加入 [AI 内存/任务/设备管理](ai-resource-management.md)。本页容量/路径更新至 2026-10-18 源码，末节 2026-10-15 测试数字保留原切片范围；文件扩展已通过 `thread-abi-r2`，显式磁盘检查点通过 `storage-verified-r2`。

日期：2026-10-15。此次切片在 M1 上增加真实 ARM 客体中的交互 Shell、RAM 文件系统和文件域本地模型。代码路径为 `crates/shell`、`crates/ai-fs`，ARM 接入在 `kernel/src/shell.rs`。它们不是网页模拟器。

## 启动与手动测试

macOS 双击项目中的 `Start-CyxiaOS.command`，或者在项目目录运行：

```sh
python3 tools/shell.py
```

入口会构建优化版 production 内核并启动 QEMU。看到 `cyxia:/>` 后，输入的是 **CyxiaOS Shell 命令**。Ctrl+C 取消当前输入；Ctrl+] 关闭此虚拟机。不要用 M1 的 selftest 映像运行 Shell。

```text
help
mkdir /docs
cd /docs
write hello Hello-CyxiaOS
append hello -AI
cat hello
cat hello
ls
stat hello
ai status
ai cache
cd /
rm /docs/hello
rmdir /docs
df
```

`write` 覆盖正文，`append` 追加正文，`touch` 不截断已有文件。路径支持 `/`、`.`、`..` 和相对目录；文件 API 接受 UTF-8 名称和空格，拒绝 NUL，路径长度按字节计；Shell 仍按空白分隔路径参数，因此不能直接输入带空格文件名。正文支持 UTF-8。命令将路径后剩余文字作为字面正文，没有引号转义、管道、重定向、脚本或可执行文件加载；前导分隔空白不保留。目录不能非空删除，当前目录及祖先不能删除。文件输出中的终端控制字符会转义。

## 实现边界

| 项目 | 当前实现 |
|---|---|
| 平台 | 单核 Cortex-A53 / QEMU virt-10.2；EL1 内核调试 Shell |
| 存储 | 根目录外 64 个文件/目录节点，每个文件最多 4096 字节；路径最多 95 字节 |
| 缓存 | 4 个完整文件副本；正文权威副本不被 AI 淘汰 |
| 持久化 | 专用 VirtIO 磁盘的显式 `storage checkpoint` 已验证；等待 `STORAGE_DURABLE` 后可重启恢复文件，未保存更改、访问统计和学习结果不恢复 |
| 本地模型 | 两个四维整数线性分类器：写入准入、下一次读取重用评分；无联网、无宿主推理 |
| 在线学习 | 仅更新重用评分模型；准入模型固定；操作员触发 train/apply/rollback |
| 隔离 | 文件域由 CPU0 单一所有者串行访问；EL0 文件调用经过权限/用户指针检查，尚无多用户身份切换和 SMP 文件同步 |

文件数据、缓存、模型、64 条学习样本和命令缓冲全部固定预留于内核映像，文件域 Shell 静态对象小于 384 KiB，组合内核 Shell 上限为 768 KiB（编译期与测试检查）。这是文件域独立 BOOTSTRAP 预留，非 CPU 控制器或用户页授予。运行无堆分配；64 节点扫描、4 个缓存位置、4 维打分、最多 8×48 次训练样本更新均有固定上限。定时中断可抢占，但此文件域切片未证明 CPU 控制器的 250 μs 调度预算；其他 CPU 策略以对应域报告为准。内核已有 64 KiB 栈独立计账。

`renameat`/`renameat2(RENAME_NOREPLACE)` 的普通文件实现先校验两个父目录及只读引导资产，再完成一次元数据发布；替换时旧文件的打开 FD 保留旧内容，源 inode 身份不变。目录移动、硬链接、符号链接和任意非 UTF-8 路径不在本次范围；重命名本身不承诺落盘，仍需显式检查点。`artifacts/desktop-fs-host-r3.txt` 记录扩容/重命名主机测试通过；`file-probe` 的真实 musl 客体验证已在 `artifacts/thread-abi-r2/summary.json` 通过。

## AI 决策链

1. Shell 解析用户请求；路径、类型、长度、目录和容量硬约束先验证。
2. 写入准入模型使用剩余节点数和增长块数决定是否接受。拒绝返回 `AiDenied`，已有正文保持原样。满容量时允许删除、读取和不增长写入；增长请求可能被模型提前拒绝。
3. 成功读取后，候选文件超过四个缓存位置时，文件域模型根据截断的读取次数、距上次访问的读取事件数、文件大小块数排序。最多四个候选时复制全部候选，属于无竞争机制，不调用排名模型或计为 AI 选择。
4. 提交层检查文件系统修订号、模型版本、索引范围、类型与重复项，再复制正文；缓存提案不能删除正文或改变内容。当前提案私有、同步提交，没有对外的异步授权接口。
5. 写入/删除使读缓存失效；删除会清零节点。访问结果进入元数据学习窗口，模型不接触路径或正文。

`ai status` 展示模型版本、累计模型决策/拒绝、缓存命中/未命中、样本数量、候选与回退状态。`source=AiDirect` 仅指本文件域实际模型决策；删除及模型发布/回退标为 `Operator`，初始预留为 `Bootstrap`。此计数不表示 CPU、设备或全系统已经由 AI 调度，也不是完整逐动作审计日志。

当前源码另提供分域计数：准入提案/通过/模型拒绝/容量保护、缓存提案/竞争选择/无竞争机制/无效提案拒绝。POSIX `read_at` 与 Shell `read` 共用读取观测、缓存和学习路径，`write_at` 也经过写入准入；新增主机测试经打开的 inode 实际读取并检查样本累积与来源。空文件大小观测限制到训练域下界 1；1 KiB 以上仍截断到 4 个 256 字节单位，不声称区分大文件尺寸。

RAM 本身已是内存存储，增加缓存副本用于验证 AI 策略与一致性接口，**不宣称这一版提高读取性能**。普通读取依据此前承诺的静态文件资源完成，缓存排名是真实策略决策，而路径解析和字节拷贝是机制。

## 模型来源与学习

`tools/train_fs_model.py` 保留固定种子 0x435958 的缓存/访问样本。桌面容量准入扩展为 free=0..64、growth=0..16 个 256 字节单位的全部 1105 个组合，使用独立种子 0x43595841 打乱并训练 32 轮；缓存排名参数与既有样本未改，文件大小特征保守限幅到原训练范围 1..4。生成文件为 `crates/ai-fs/src/weights.rs`，训练统计在 `fs-model-training.json`。参数不是手写策略表。可复现检查：

```sh
python3 tools/train_fs_model.py --check
```

读取反馈每次生成一个完整事件组：被读取文件的正样本，以及一个确定性轮换选择的其他文件负样本；仅一个文件时使用重复正样本。窗口共 32 组、64 条样本。前 24 组训练、后 8 组时间后置验证；同一次读取不会横跨分区。目录/正文变化会清除待标注的身份快照，防止节点复用污染反馈。

```text
ai status
ai train
ai apply
ai rollback
```

至少需要 33 次没有中间文件变更的读取，才能得到 32 次访问转移。`NeedSamples` 表示数据不足；`CandidateRejected` 表示参数未变化，或分类验证/固定 canary 成绩下降。两者均保留当前模型。`ai train` 只生成候选，`ai apply` 才发布并增加版本，`ai rollback` 恢复上一个参数版本并再次增加版本；发布和回退都会清空新学习窗口与缓存。

验证门检查 16 条后置样本和 16 条独立合成 canary 的**分类正确数不下降**，以及参数限制 ±512；不是缓存命中率或实际延迟保证。候选可能改变排序并降低实际命中率。合成样本、很小的验证集、单文件重复样本及无工作负载归一化均限制泛化能力；这属于可运行的学习切片，尚未完成正式 P3/P5 生产模型验收。功能测试中的固定接受轨迹仅验证发布/回退路径，不当作性能基准。

学习状态现在分别报告训练请求、样本不足、验证拒绝、显式发布和回退次数，以及最近一次训练的 active/candidate 后置验证与 canary 正确数（各自分母 16）。发布或回退后清除该次验证记录，避免把旧验证展示成新模型的观测结果。准入模型固定，学习状态和已发布权重不进入文件检查点；重启恢复内置模型。当前没有自动发布、性能回归自动回滚或跨资源域学习。

## 验证与审核

2026-10-18 分域统计修正后，同一冻结内核
`1a0f5534cdb50ab2e8e291ad0fd6890899f35e55ce536c6756ffc8c8e42aae81`
的[真实 ARM Shell 回归](../../artifacts/ai-system-r2/shell/summary.json) **PASS**（99 项检查），
包括元数据学习、train 后不切换、显式 apply、回退以及文件内容/容量/重启语义。
文件域主机 17 项测试通过，其中新增 inode 读取共用学习窗口、无竞争缓存归因、
空文件训练域边界及实际验证分数检查。此结果不证明候选的缓存性能更优，也不代表全系统学习。

```sh
cargo test --locked
python3 -m unittest discover -s tests/host -v
python3 tools/verify_m1.py --output artifacts/shell-m1-regression
python3 tools/build.py --profile release --production
python3 tools/verify_shell.py --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel --output artifacts/shell-release
```

交互验收使用双向 Unix socket 搬运 PL011 UART 字节，QMP 只控制虚拟机生命周期。宿主不解析/执行文件命令，不代算 AI。记录包括映像 SHA-256、串口原始数据和控制台文本；输出帧丢失/损坏会显式中止测试。

独立审核发现并修复：粘贴队列溢出后误执行残留命令、UART 接收错误后误执行残留命令、学习验证切分同一次读取事件。对应回归测试验证整行丢弃和完整事件分组。最终实测结果记录在 artifacts 的 summary.json；M1 历史报告保留其原始范围和日期。

### 2026-10-15 原切片实际结果

- Rust 主机测试共 51 项（新增文件系统 10 项、Shell 7 项），全部通过。
- Python 主机测试共 29 项（新增输入队列回归 3 项），全部通过。
- M1 回归：22 项检查通过，见 `artifacts/shell-m1-regression/summary.json`；该门不评价 AI 效果。
- production 开发版与优化版：各 96 个检查步骤通过，包括 UART 文件操作、模型候选发布/回退、超长行拒绝、重启清空；见 `artifacts/shell-dev/summary.json`、`artifacts/shell-release/summary.json`。
- production 开发版装载跨度 757760 字节，优化版 737280 字节；两者 ELF 检查及无 FP/SIMD 指令检查通过。
- 模型参数可复现检查通过。未重复声称 M1 历史覆盖率适用于新增模块。
- 独立审核的 3 个重要问题全部修复并复核；另修复溢出块内已有换行时误丢弃下一条命令的恢复问题，新增对应 Python 回归测试。


## 后续持久化实现

`python3 tools/storage.py artifacts/cyxia-data.raw` 创建不覆盖既有数据的专用空磁盘；`python3 tools/shell.py --disk artifacts/cyxia-data.raw` 连接它。客体 `storage checkpoint` 异步写入，`storage status` 显示代际与资源归还；`STORAGE_DURABLE` 仅在两个真实 flush 完成后输出。恢复在接收首个 Shell 命令之前完成。此阶段没有自动保存、fsync 或学习模型持久化，详见 [格式、AI 授予及真实重启证据](persistent-storage.md)。
