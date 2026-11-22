# V0.18 日志文件系统不可变快照

## 范围与实现入口

此变更基于 `CyxiaOS-V0.18@e9442cd7ffb56373ca180beb532e99aa4a736385`，
保持软件版本 `0.18.0-dev`。实现对象是 `cyxia-prototype` 的持久日志文件系统，
并接入原生 `domain_file_abi → domain_storage → prototype_storage` 唯一卷所有者。

磁盘与协议合同以历史设计修订 V1.4 第 9、16 章为依据：业务数据不可变、保护状态不回退、
写入不等待模型。新功能不增加 AI 动作族，也不把清理、恢复权限赋予普通文件能力。

主要源码：

- [v2 介质格式与间接 extent](../../crates/prototype/src/storage.rs)
- [有序数据提交及恢复](../../crates/prototype/src/journal.rs)
- [业务 CoW](../../crates/prototype/src/domains/filesystem/cow.rs)
- [文件句柄、快照、恢复、回收与维护](../../crates/prototype/src/domains/filesystem/snapshots.rs)
- [流式树和块所有权校验](../../crates/prototype/src/domains/filesystem/validation.rs)
- [持久控制与请求管理](../../crates/prototype/src/snapshot/manager.rs)
- [共享 EL0 协议](../../user/prototype-task/snapshot_abi.rs)
- [EL0 调用封装](../../user/prototype-task/snapshot_client.rs)

## 数据与提交保证

已公布业务块永不原位覆盖：文件内容、目录页、间接 extent 页都写入新的空闲块。
只有管理元数据和固定系统对象允许进入 REDO。`Journal::commit_ordered` 在任何写盘前核对
日志容量、完整 I/O 额度、地址分类、重复目标和当前已提交位图；每个新数据块必须是
`free → allocated`，且不能是本 epoch 旧 REDO 的目标。

提交顺序是新数据与 BEGIN/REDO、第一次 FLUSH、COMMIT、第二次 FLUSH、内存发布。
写入或完成结果不确定时卷进入不可写状态；恢复前不得把超时视为取消或复用 DMA。
读取错误同样使 journal 失效。挂载和 GC 使用设备 quiescence 检查，原生适配器检查队列、
未完成请求和保管额度，不通过重置未知请求来制造空闲状态。

页面 CRC32C 使用 1 KiB 只读查表，与独立逐位算法核对，磁盘编码不变。完整页面校验和
复制结束、以及完整请求记录校验结束之后，通过 `BlockDevice::cpu_progress` 接入原有
CPU 计费和进度边界。该边界不释放卷所有权、事务保管或 DMA 保管；失败的读取不调用
成功进度钩子。树校验逐页复用 inode 缓存，避免为同一页中的每个 inode 重读磁盘。

`write` 的成功仅表示已受理；脏页持有新的数据块及有界间接页预留。
在受理前检查整个写入及每个可分批发布的脏页前缀能否表示。`fsync` 的回执绑定
`live_view_epoch`、文件身份和已确认写序号。最多 354 个 extent（16 内联 + 338 间接），
文件上限 8 MiB，单次 I/O 上限 64 KiB。超出表示或资源容量时返回背压/空间错误，
不会借用受保护快照空间。

## v2 固定布局与迁移

卷仍为 512 MiB，块大小 4096 字节。

| 块范围 | 内容 |
| --- | --- |
| 0–1 | 双超级块，version=2，112 字节头 |
| 2–4097 | 线性 REDO 日志 |
| 4098–4101 | 分配位图 |
| 4102–4117 | 当前 256 个 inode |
| 4118 | FSControl |
| 4119 | SnapshotCatalog |
| 4120–4239 | 8 个快照槽，每槽 1 描述页 + 14 业务 inode 页 |
| 4240–8353 | 系统固定容量：系统目录、BootEpoch、16 MiB 集群日志和 64 KiB 请求对象 |
| 8354 起 | 业务 CoW 数据 |

业务 inode 为 0–223，根为 0。系统 inode 为 224–255，根为 224；BootEpoch=225、
集群文件=226/227、快照请求对象=228。系统容量在格式化时全部保留，集群 inode 的
`size` 继续表示已用日志长度。系统文件不出现在业务路径中，业务快照和恢复不触及系统 inode。

**v1 卷不能按 v2 可写挂载，也不会被静默升级或重新格式化。** 已有 v1 数据应使用旧版本
离线导出，在新的空白设备上建立 v2 卷，再导入并校验；本次没有提供一键迁移器。
[旧版检查器](../../tools/check_v13_filesystem.py) 保留 v1 读取能力，
[新版检查器](../../tools/check_v2_filesystem.py) 独立解码 v2。

## 快照、恢复与回收

创建先持久登记 PENDING 和主体水位，再关闭新业务修改、完成此前已受理的脏页，
从包含已提交 REDO 的逻辑视图复制 14 页业务 inode。描述页、镜像、目录、控制状态和
DONE 在同一事务公布。描述页和 inode 镜像分别受 SHA-256 保护，结构另有 CRC32C。
同一槽代际的镜像不再改变；延长保留只改 catalog。

历史路径在快照自己的目录树中解析。历史能力绑定文件系统 UUID 和规范路径前缀；
该前缀在历史视图中不存在时返回 ENOENT，不退到父目录或活动视图。历史句柄只读，
钉住槽及完整 inode，并绕过活动缓存。带句柄的快照不能删除；本实现采用完整槽保管，
没有在删除后继续保留一个脱离槽的单文件视图。

恢复必须显式指定 PRESERVE_DIRTY 或 DISCARD_VOLATILE。先持久 PREPARING、
源身份、请求、旧/新 epoch 和 FROZEN 写门，再处理已受理旧写；最后一个事务只替换
14 页业务 inode，并发布新 epoch 和 DONE。BootEpoch、集群记录、请求水位、保护代际、
保留期限和快照 ID 均不回退。旧 LIVE 句柄、服务能力和任务缓存失效；历史句柄保持原身份。
恢复后写门仍关闭，只有带准确保护代际和完成证明的独立 OPEN_WRITES 才能重开。
ACK 恢复结果不清除 Control 中的开门证明。

删除只把 ACTIVE 改为 DELETING，返回 `gc_pending`，不承诺立刻获得空间。
GC 在本地停写状态下检查当前根、系统保留容量和所有 ACTIVE 历史根，逐视图检查唯一块
归属，再合并共享根。第一次检查点先清除旧日志回写义务；位图释放与 FREE_COMMITTED
同事务；第二次检查点、设备 quiescence 和缓存收尾完成后才把槽标为 FREE 并开放块复用。
损坏或无法证明完整的根阻止回收。清理冻结禁止新的根移除，但允许保留所有有效根后回收
已证明不可达的普通 CoW 垃圾。

## 保留与资源

- 8 个槽固定分为 6 周期、2 按需，不能互借。
- 短期层 0–2：每 6 小时建立保护点，保留 18 小时。
- 长期层 3–5：每 48 小时建立保护点，保留 144 小时。
- 按需保留最少 1 小时、默认 24 小时、最多 7 天；不能缩短已有截止。
- 保留时间采用可信内核单调计时累积的持久在线年龄，60 秒粒度推进；停机、提交等待、
  小数秒和创建前未确认时间不计入。宿主时钟、用户载荷和 AI 动作不能推进保护时间。
- 新卷首先创建两层初始保护点，再由可信初始化路径开放写入；既存冻结卷不会因重启自动开门。
- 每层自动维护保留至少一个 ACTIVE 点。先闭合既有 DELETING 槽，避免断电后的维护饥饿。
- 128 个句柄分为 112 普通、16 恢复；64 个冻结视图分为 56 普通、8 恢复。
  普通请求不能占用恢复分区。
- 管理器常驻内存不超过 8 KiB；句柄预算同时计入 core 与 native broker，合计不超过
  128 字节/槽。冻结视图和 CoW 版本元数据也有编译期大小断言。
- GC 的 mark、ownership、扫描数组固定为 48 KiB，复用已有事务区的第 24–35 页；
  inode 流式解码，间接 extent 使用借用式校验，没有第二张 inode 表或间接数组栈副本。

设计的 68 KiB 管理预算由句柄 16 KiB、冻结视图 24 KiB、控制/目录缓存 8 KiB、
共享分配位图 16 KiB、协调状态 4 KiB 五项组成，已经包含句柄和冻结视图。
CoW 版本记录的 128 KiB 上限与 GC 的 48 KiB 工作区另列。实现中，core 句柄 56 字节
加 broker 句柄 72 字节，128 个槽合计 16 KiB；冻结视图 288 字节，64 个槽占 18 KiB。
4096 页的 Cache 记录加 256 个 inode 的 committed_size 共 98 KiB，合计检查 CoW
预算，不能把这张版本记录表隐藏在协调项外而不计账。

挂载去重的 2304 字节规范请求键表复用事务页 2；GC 的 48 KiB 也复用同一已有
160 KiB 事务工作区。权限表从复制路径改为长度与摘要绑定，回执正文复用已有 DATA，
没有另设路径或完成正文池。编译期协调断言保守计入完整 Manager、权限表、完成身份、
捕获屏障、维护时点和 GC 引用计数。内核调用栈按原有栈额度独立核对，4 KiB 并非
所有 Rust 调用帧的总上限。

## 请求与权限接口

保留原 v1 文件接口。新增 `SVC 0x45 / service_call 0x50`，请求头 64 字节、请求总长
64–1024 字节，响应头 32 字节、响应总长不超过 2048 字节。外层完整能力身份与请求头
能力索引必须一致；未知版本、非零保留字段、越界、输入输出重叠都在副作用前拒绝。

| opcode | 操作 |
| --- | --- |
| 0x20 | SNAP_CREATE |
| 0x21 | SNAP_EXTEND |
| 0x22 | SNAP_DELETE |
| 0x23 | SNAP_RESTORE |
| 0x24 | SNAP_LIST |
| 0x25 | SNAP_QUERY（SnapshotKey 元数据） |
| 0x26 | SNAP_OPEN |
| 0x27 / 0x28 | FREEZE_SET / FREEZE_CLEAR |
| 0x29 | OPEN_WRITES |
| 0x2a / 0x2b | QUERY_REQUEST / ACK_REQUEST |

`SnapshotKey` 为 40 字节，绑定 UUID、snapshot ID、slot 和 slot generation。
`FileReqKey` 为 36 字节，绑定 UUID、client slot、client generation 和 request sequence。
64 条持久请求按 48 普通 / 8 维护 / 8 恢复分配，16 主体水位保留已受理序号。
同键同摘要只返回原状态，同键异摘要冲突，已安全 ACK 的旧键为 STALE，不能重新执行。
历史结果查询先于当前 epoch、源仍存在等副作用条件；PENDING 冷恢复只闭合为 INCOMPLETE，
不重新选择捕获时刻。ACK 验证原主体和终态摘要，不回收 PENDING/UNKNOWN。
自动维护只能清理自己的终态请求记录，普通与恢复记录仍由其主体确认。

创建、列举、历史读取、延长、到期删除、恢复和保护控制是独立能力。
普通 `ALL_RIGHTS` 不增加管理权限。恢复角色通过单独的可信授予入口登记。
权限表用前缀字节长度和域分离 SHA-256 绑定完整规范前缀；历史打开先核对请求路径的
对应前缀、组件边界和摘要，再在历史树中解析已验证的前缀，不缩短 512 字节的路径上限。
已完成操作若用户 copyout 失败，broker 在既有 DATA 区保管原回执；v1/v2 共用
待交付所有者门禁，其他调用不能覆盖该正文，再次交付不会重复执行副作用。

0x2a/0x2b 及请求聚合对象页头/主体水位的逐字段编码补全了设计中没有冻结的细节，
代码明确命名为 `SnapshotRequestSchemaV1`，没有把 `SNAP_QUERY` 混作请求状态查询。

## 验证与原生入口

核心回归命令：

```sh
export RUSTUP_TOOLCHAIN=1.95.0
cargo +1.95.0 test --locked --offline --workspace --exclude cyxia-kernel
PYTHONPATH=tools:tests/host python3 -B -m unittest \
  tests.host.test_v13_disk tests.host.test_v13_filesystem \
  tests.host.test_v2_filesystem tests.host.test_snapshot_file_abi \
  tests.host.test_snapshot_capability_custody tests.host.test_snapshot_probe_budget \
  tools.test_snapshot_probe
cargo +1.95.0 clippy --locked --offline -p cyxia-kernel \
  --target x86_64-unknown-none --features selftest -- -D warnings
```

故障模型分别在创建、恢复和 GC 每次块写与 FLUSH 的前后断电，实际丢弃未 FLUSH 的写入。
覆盖历史字节/目录、unlink 与 inode 复用、checkpoint/remount、保留/冻结/请求重试、
普通/恢复配额、354 extent 及第 355 项拒绝、未知 I/O 禁止 GC、系统不回退与旧能力失效。
独立 Python 检查器还读取真实 Rust 生成的 v2 镜像，核验提交前缀和所有活动根。

4096 脏页压力测试完成两份 8 MiB 文件的快照屏障，核对脏页全部提交和写序号，并从
两份文件的头部、中部、尾部各抽验一页历史内容。
本次宿主模型样本为 5280 次写盘/FLUSH 事件、约 2.6 秒；该数字只用于宿主回归，
不能作为物理设备或 QEMU 的 R30 时延上限。

原生专用入口是 `tools/build_unified.py --snapshot-probe --selftest`，也可通过
`CYXIA_SNAPSHOT_PROBE=1` 选择专用构建。它使用独立的新 v2 测试盘、两个显式授权的 EL0
角色，执行创建/改写/历史读取/恢复/开门和陈旧句柄拒绝流程，不改变默认普通客户权限。
本文件的宿主测试结果不代表 R01–R30 原生整体验收通过；原生构建、客体执行和生产保留期
经过的真实时间必须分别出具证据。

客体执行使用 `tools/run_snapshot_probe.py`，默认 `--scope full-unified` 连接两个节点的
网络；显式 `--scope local-filesystem` 为每台 QEMU 保留同样的 virtio 网卡，但接入各自
独立的单端口内部 hub。两种模式使用相同镜像、CPU/RAM、预算、初始化和维护入口，
以及相同的角色退出与磁盘判据。输出目录必须全新，每个节点都会创建独立 UUID 的新盘。
本地模式的 `full_unified_accepted` 固定为 false，不能证明联网整体运行通过。

### 本次验证状态

| 检查 | 结果与范围 |
| --- | --- |
| 工作区 Rust（排除内核测试目标） | 1,661 项通过，0 失败、0 忽略，包含 2 项编译失败型文档测试 |
| v1/v2 磁盘检查器、真实文件服务 broker 与探针 | 37 项 Python 测试通过；schema harness 内含 4 项 Rust 测试 |
| 恢复与能力撤销 | 真实 owner/publication 函数注入竞态检查通过 |
| A10 回执来源与负例 | 冻结源码后 18 项通过 |
| 原 V0.17 CI 修复移植 | 精确移植 d34d895 的 9 个文件；26 项定向 Python 回归和 395 项受影响组件测试通过 |
| x86 内核门禁 | `x86_64-unknown-none`、`selftest`、Clippy `-D warnings` 通过 |
| AArch64 原生双节点构建 | 两个独立节点的真实 EL0 service、EL1 unified-runtime 和快照探针编译链接成功；构建后源码逐项复核相等 |
| 快照探针代码额度 | 每节点 ELF 14,400 字节，唯一 RX PT_LOAD 7,796 字节，小于沿用的 16,384 字节额度 |
| 原生准备路径栈门禁 | 两节点所选准备路径各 34,576 字节，加 4,096 字节异常预留，小于 65,536 字节；不是快照全部调用路径的栈证明 |
| QEMU 环境 | 固定 QEMU 10.2.2；每 vCPU 线程 CPU 时钟 PMU 补丁身份校验通过，4 vCPU、1 GiB、MTTCG |
| 原生完整联机快照流程 | `FAIL`；最新运行在既有网络 `IpcDrain` 段触发 6,106,048 ns / 2,500,000 ns CPU 预算超限，尚未完成全部角色 |
| 同镜像的原生本地文件系统流程 | `FAIL`；CPU0 网卡 `QueueIdleAck` 段 4,112,474 ns 超过 2,500,000 ns；另一节点 CPU1 控制任务也发生 3,123,719 ns / 2,500,000 ns 超限 |
| 原生断电矩阵、R01–R30、最大脏页原生时延 | `NOT_RUN`；宿主故障注入与客体冒烟不代替这些验收 |

完整联机运行使用 `immutable-snapshot-native-build-004`，源码摘要为
`05db276789fbd6a05733549c97447b0408ff6c7c59d9a2152a150854040efe72`。
`immutable-snapshot-native-smoke-003/summary.json` 保留失败、停止内存、磁盘和启动参数。
该次 CPU 账单的网络诊断阶段为 27（`IpcDrain`），调度序号 80206；没有提高原有
2.5 ms 额度、关闭隔离或放宽通过条件。网络路径在本次功能之前已经存在；当前证据
定位到该片段，没有证明其内部哪条指令造成超限。

`immutable-snapshot-native-local-004/summary.json` 保留隔离网络后的独立运行，网卡空队列
诊断阶段为 14（`QueueIdleAck`），调度序号 21569。两种模式均在全部角色完成之前停止，
停止后的两块盘通过 v2 结构检查，但仍为 epoch 1，未完成恢复。没有把已有 DONE、
角色准入或有效盘面单独当作端到端通过；目前不能声明原生 create → history → restore
闭环通过。源码与构建、宿主回归、两种原生失败的摘要见
[机器可读验证记录](v18-immutable-snapshot-validation.json)。

全量 Python host lane 在本次环境中未全绿：旧源码提取 harness、已有 stub/manifest
失配、环境权限和两个 page-map harness SIGSEGV 仍有独立问题。并行编辑时出现的
A10 源码身份错误已由冻结后 18 项重跑消除；新增 `ReadOnly` 的穷尽匹配已补全。
不把快照定向检查通过表述为整个旧 host lane 通过。

`cargo fmt --all -- --check` 仍报告基线中的格式差异；避免将全仓格式化并入此功能。
快照源码的格式检查与全仓格式基线问题分别记录。
