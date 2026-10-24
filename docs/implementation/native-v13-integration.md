# CyxiaOS 1.3 原生接入状态

**历史范围说明：**本文保留前一轮独立 `prototype-runtime` / `tcp-v13-selftest` 配置的实现与测试记录。后续 `unified-runtime` 已接入动态分核、客体 TLS、持久成员与合同执行；当前实现和联合证据以 [原生控制面与双节点集群联合实现](unified-native-control-cluster.md) 为准。下面“仍需实现”“互斥配置”等描述对应前轮状态，不能作为当前四项接入状态。当前设计文档已更新为 Rust 修订版；下面语言偏离保留原决策历史。

本文记录 2026-10-24 起的实际实现和证据边界。实施计划见
[native integration plan](../superpowers/plans/2026-10-24-v13-native-integration.md)，
逐项映射见 [1.3 acceptance map](v13-acceptance-map.md)。

## 已批准的语言偏离

用户明确选择“沿用 Rust 接入功能，并明确记录对 1.3 语言要求的偏离”。
因此继续使用 Rust `no_std` 和 AArch64 汇编，没有迁移为 §1.2 要求的 C11。
此决定仅覆盖语言选择，不豁免隔离、持久化、认证、预算或故障证据。
原始 DOCX 保持不变，以 SHA256 固定规范身份；不能宣称逐条无偏离符合原规范。

## 当前代码边界

| 部分 | 已接入内容 | 仍需实现/验证 |
|---|---|---|
| 验收目录 | 单独的 51 项 A/T/E、18 动作族、规范和条款文本散列；未完成时 `--release` 返回 2 | 完整原生用例判定器和文件系统故障矩阵 |
| 核心所有权 | `cyxia-prototype::cores` 保留 DRAIN 原所有权、六域停止收集和逐核预算；新增持续运行配置将业务派发接到预扣预算 | 真实任务/IRQ/DMA/TLB 停止域完整登记、动态 C 核转换、16 任务组、最低服务保证 |
| 整数模型 | 精确 2772B、64→32→16→1、i64 累加、对称舍入、隐藏层 ReLU、稳定首最大值；每层 trace | 从真实执行回放训练的模型、全域决策和学习/晋升路径 |
| 网络 | 原生 VirtIO-net；新增 smoltcp Ethernet/ARP/IPv4/TCP、96B RPC 解析和有界流缓冲；可选 rustls 双向固定公钥 TLS1.3 | TLS 原生服务、UDP 发现、持久成员协议、合同及远程任务；TCP 连接不授予资源 |
| 磁盘 | 512 MiB formatter、CRC32C/SHA256、两次 FLUSH 提交、检查点/恢复、已分配文件中的 BootEpoch；原生 VirtIO-block 适配 | 通用文件服务、持久身份/成员/合同、异步完成 credit、原生断电模型 |

现有桌面和旧 `ai-control-selftest` 保留各自运行配置。新增功能通过显式
feature 运行；`prototype-runtime` 已持续运行独立 EL0 控制服务，仍未作为完整控制面或认证集群接入桌面。旧自检的有限序列和
合成遥测不能填入新规范的完整用例 PASS。

## 原生以太网验证

```sh
cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features net-selftest
python3 tools/verify_native_net.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/net-pair-new-run --timeout 30
```

输出目录必须不存在。工具启动两台 QEMU，分别配置四核、1 GiB 和不同 MAC，
用本机回环 socket 连接模拟网卡。帧生成、校验及确认都发生在客体内；主机
只提供链路、采集 QMP/串口/内存页/PCAP 并作独立判定。当前为实验 EtherType
`0x88b5` 的 EL1 驱动测试，不是 TCP、TLS 或集群资源授权。

`--disconnected` 在客体运行前通过 QMP 关闭实际网卡链路；预期工具非零退出、
客体在十秒期限失败，不能出现 READY。它不覆盖运行中断链和集群重连语义。

QEMU 10.2.2 的非 MRG 接收路径未写入现代头的 `num_buffers`，首次原生运行
因此严格失败。驱动现仅在设备提供时协商 MRG_RXBUF，仍只提供单个 1526B
缓冲区并要求 `num_buffers == 1`；未放宽零计数或越界报文检查。此为实现选择
调整，不更改 1.3 功能契约。依据见
[QEMU 10.2.2 接收代码](https://github.com/qemu/qemu/blob/v10.2.2/hw/net/virtio-net.c)。

## 整数模型原生工程向量

```sh
cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features model-v13-selftest
python3 tools/verify_v13_model.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/model-v13-new-run --timeout 30
```

该配置在 CPU1 的独立 EL0 映射内运行六个固定工程模型、八组请求、十六个
候选，保存每层整数输出并与独立 Python 任意精度参考比较；同时检查只读
模型/输入、栈保护和定时器切出。工程向量明确标记 `synthetic=true`、
`trained_model_verified=false`，不用于证明性能收益或学习成功。

## 完成判定

前一批组件保存的原生证据：

- 以太网正常路径：`artifacts/v13-native-net-reviewed/summary.json`，PASS；
  两节点 TX 分别 163/161、RX 分别 161/163，PCAP 与客体一致。
- 链路关闭：`artifacts/v13-native-net-reviewed-link-down/summary.json`，预期 FAIL；
  两客体实际启动，十秒期限内未完成握手，没有成功标记。
- 整数工程向量：`artifacts/v13-model-native-first/summary.json`，PASS；
  四项保护探针、一次故意停滞的定时器切出，推理本身抢占数为零，业务核各前进四次。
- 旧 AI 自检回归：`artifacts/v13-legacy-ai-control-regression/summary.json`，PASS；
  保留其原有合成遥测与有限夹具标签。

源码与镜像散列属于各次运行当时的快照。随后判定器加强了 CPU 启动握手及
畸形 ELF 拒绝，保存的网卡和模型原始证据已用加强后的判定器再次验证。
该批次 Rust 工作区569项、主机Python439项测试通过；桌面release构建通过。运行工具均已清理自己
启动的 QEMU，未留下正在运行的桌面或集群实例。

运行 `python3 tools/check_v13_evidence.py --release`。当前所有完整用例与动作族
仍为 NOT_RUN，发布门保持关闭。组件测试、原生网卡收发和整数内核工程向量
分别出证据，不相互替代。完整控制隔离及双节点集群完成仍需动态核心转换、通用持久服务、
客体 TLS、成员/合同执行和关联故障用例全部落实。

## 本轮持续控制、磁盘和传输接入

`prototype-runtime` 使用真实业务派发计数、单调时钟和异步请求邮箱，EL0 模型
决定两个业务执行者下一窗口的权重。EL1 按已准入预算派发，接受提案和实际
窗口生效分别记录；独立验证器计算整数模型结果，并暂停、恢复、再次采样以
验证运行持续推进。控制服务保护页错误与定时器切出均由真实异常路径产生。
固定核心和未训练的稀疏启动模型仍是当前限制，不能宣称动态核隔离、16 域
强化、学习晋升或全成本控制预算已经完成。

磁盘 `journal` 使用调用者提供的8 KiB缓冲、固定16 KiB索引、每事务至多128
个 after-image。BEGIN/REDO 完成并 FLUSH 后写 COMMIT，再 FLUSH 后发布可见
索引；I/O 结果不明时禁止新写，恢复根据磁盘证据判断。检查点合并最新块后
FLUSH，再更新另一超级块并 FLUSH，之后才能复用日志。主机故障模型明确丢弃
未 FLUSH 的写入，覆盖提交、检查点和格式化的中断；它不冒充原生断电验证。

启动服务通过真实 VirtIO-block 访问同一磁盘。`.cyxia-boot` 是根目录内的已
分配普通文件，与 inode/位图在同一事务持久化；启动所有者只尝试一次分配，
失败或溢出禁止新授权。当前支持专用的根目录＋启动文件卷，扫描全部 inode
和位图拒绝冲突；通用文件系统分配及持续磁盘服务尚未接入。控制服务重启使用
已有 BootIdentity，不递增代际。磁盘损坏不会触发自动格式化。

```sh
cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features storage-v13-selftest
python3 tools/verify_v13_storage.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/storage-v13-new-run

cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features prototype-runtime
python3 tools/verify_v13_runtime.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/runtime-v13-new-run
```

这些工具仅在新的输出目录内创建新的512 MiB稀疏磁盘，不覆盖已有镜像。
磁盘验证还使用独立 Python 解码器检查超级块、日志事务摘要、分配、目录、
inode 与 BootEpoch 正文；两次 QEMU 启动证明重启回放，`native_powercut_verified`
保持 false。

传输依赖锁定为 smoltcp 0.14.0、rustls 0.23.45、ring 0.17.14。TCP/RPC 无堆
代码可编译到当前 AArch64 soft-float 目标。TLS 可选模块执行真实双向
Ed25519 固定公钥认证、X25519 和 AES-128-GCM；禁止 TLS1.2、恢复与0-RTT。
主机 TLS 测试使用公开的专用测试证书，不作为节点生产身份。

ring 的 AArch64 实现要求 NEON，当前 soft-float 内核目标不能直接链接该
TLS 配置。下一步需要独立支持 FP/SIMD 的 EL0 TLS 服务、受限 allocator、
真实熵与身份能力，随后才能验证客体 TLS。当前 TCP 测试即使通过，也只
证明字节流，不关闭成员/合同/远程执行的验收项。


## 本轮最终原生验证

| 配置/证据目录 | 结果与实际观测 |
|---|---|
| `artifacts/v13-storage-final` | PASS；同一磁盘两次启动 BootEpoch 1→2，第二次回放4块；独立Python日志摘要/目录/inode/位图解码与客体一致 |
| `artifacts/v13-runtime-final` | PASS；22次持续推理、业务核各126次派发；12个已完成窗口记录显示AI权重实际改变8/4与4/8派发比例；4项保护探针 |
| `artifacts/v13-runtime-hang-final` | PASS；第5请求在EL0实际停滞100ms、8次定时切出；期间业务继续，服务代际1→2且BootEpoch仍1；恢复后共22次成功推理 |
| `artifacts/v13-tcp-final` | PASS；两台四核/1GiB客体、独立512MiB卷，各方向65,616字节；ARP/握手/校验和/重组/完整ACK时序及磁盘身份独立检查 |
| `artifacts/v13-tcp-final-link-down` | 预期FAIL；节点1在20秒客体期限报告code10，未传数据，无READY；两节点PCAP均只有文件头 |
| `artifacts/v13-tcp-final-no-entropy` | 预期FAIL；节点2报告熵不可用与code5，无TCP_START/READY；首个失败即停止两机，不宣称另一个节点完成了磁盘恢复 |

持续控制正常与停滞测试使用同一源码清单散列，分别保存独立ELF；所有运行
都绑定各自执行时的源码/ELF/工具散列，后续文档汇总不修改原始证据。
运行工具已清理所有自己启动的QEMU。

`prototype-runtime` 与 `tcp-v13-selftest` 目前为互斥运行配置。前者验证持续
EL0控制和业务派发；后者为EL1明文TCP接入。它们尚未合并成同时运行、具有
原生TLS和持久成员/合同的系统，不能把两项局部PASS相加当成完整集群。

```sh
cargo build --locked --offline -p cyxia-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features --features tcp-v13-selftest
python3 tools/verify_v13_tcp.py \
  --elf target/aarch64-unknown-none-softfloat/debug/cyxia-kernel \
  --output artifacts/tcp-v13-new-run
```

可分别添加 `--disconnected` 或 `--without-entropy` 运行网络负例，期望非零退出。
持续控制停滞配置通过构建时 `CYXIA_RUNTIME_FAULT=hang-once` 注入，验证器仍
要求故障期间业务真实前进、恢复后的代际和预算一致。

独立审核已关闭本轮具体问题：接受/应用回执混用、并发完成时间戳、控制EL0
预扣、TLS满缓冲停滞与断连撤销、抓包握手/过早ACK/ARP身份、超级块代际与
跨抓包/磁盘身份绑定。范围仍限上述新增组件；69项完整1.3用例/动作族保持
NOT_RUN，原生断电、动态分核、全成本预算、训练/学习、16域和认证集群仍未完成。


最终回归：工作区603项Rust测试通过；TLS feature专项17项通过（含8项已有网络
测试与9项TLS测试）；Python主机465项通过，另43项v1.3测试在 `python -O`
下通过；桌面release构建通过。日志分别为 `artifacts/v13-final-rust-tests.log`、
`v13-final-tls-tests.log`、`v13-final-host-tests.log`、
`v13-final-optimized-host-tests.log`、`v13-final-desktop-build.log`。
`git diff --check` 通过。未暂存、提交或推送，本轮之前的71个暂存路径保持不动。
