# CyxiaOS 原生控制面与双节点集群联合实现

日期：2026-10-24。对应当前 1.3 Rust 修订设计文档，SHA256 `01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0`。用户已批准继续使用 Rust；旧 C11 语言偏离记录作为历史保留。

## 实现范围

`unified-runtime` 将原来独立的控制面、网络、持久成员和合同执行接入同一原生内核启动路径。CPU0 执行机制协调、VirtIO I/O 和受保护的 EL0 集群服务；CPU1 是控制面锚点；CPU2 按本地模型提案在控制面和业务面之间切换；CPU3 是业务面锚点，并执行远端纯计算任务。客体中没有 Linux，也没有由宿主机代办 TLS、签名、合同或任务的代理。

本地模型仍是手工初始化、未训练的引导模型。该实现验证四项集成目标，不代表全部 1.3 条款、全部 AI 管理领域、学习效果或物理硬实时保证已验收。

## 动态分核与隔离

模型输出分核提案，EL1 检查版本、预算、1 秒调整间隔和 200 毫秒交接截止时间。CPU2 的 DRAIN 先关闭真实执行闸门；任务退出、IRQ、DMA 所有权、TLB 和引用条件全部满足后才发布新 C/B 集合。设备与 DMA 当前固定归 CPU0，不能由被迁移的 CPU2 或 EL0 直接取得。

没有停止 ACK 时保留旧归属，关闭疑似 CPU 的执行入口，不把超时当成停止证明。模型有独立页表和可抢占 EL0 上下文；模型挂起不会阻塞业务 CPU。控制与业务时间都预付后执行，实测超额即停止继续授权，不通过重启或跨窗口抹掉支出。

## 客体 TLS 与可信边界

独立 EL0 服务使用 Rust 标准 AArch64 freestanding 目标和 rustls/ring：TLS 1.3、X25519、Ed25519 双向固定身份认证、AES-128-GCM，禁用会话恢复和 0-RTT。每个镜像只有本节点私钥和对端公钥/NodeID。EL1 使用软浮点目标，EL0 的 SIMD 上下文完整保存；ring 的汇编目标选择有一个受控 vendor 修补，密码实现未替换。

随机数来自客体 VirtIO RNG。没有熵时不创建 TCP/TLS 会话，但继续本地控制与已接收任务的结果保管。TLS 服务独立页表、只读代码/常量、8 MiB 有界堆、独立栈和 16 KiB 固定共享 ABI；没有任意内核指针、其他进程页或 MMIO 映射。固定公钥认证不宣称 WebPKI 公共证书时间验证。

## 持久成员、合同和任务

先在真实 512 MiB VirtIO 磁盘上提交 BootEpoch，再启动服务。两个预留普通文件保存身份绑定、形成锁、双方签名的成员证明、合同、任务意图、结果、ACK 和离群证明；每条记录走现有 journal 的提交与 flush。未知 I/O 结果冻结新授权，空间不足作为确定拒绝处理，并保留 1 MiB 关闭与恢复空间。重启从原磁盘恢复，不自动格式化。

成员状态与连接 READY 分离；重新连接须完成 TLS、BootEpoch/会话绑定与历史对账。形成锁冻结随机数和计数器，单边确认后不能悄悄发起另一轮形成。LEAVING 冻结离群 ID 与已持久签名，断线后继续同一证明；已解锁一端可重发最终证明。

合同经 PREPARE/COMMIT/ACTIVATE。EL1 维护自己的预约与连接代次，在最后入队处再次检查合同、包哈希、输入哈希、期限、grant epoch 和资源数值。预装 `vector_sum` 包使用单独的 EL0 页表，对只读 i64 输入进行检查溢出的求和；没有文件或设备能力。当前原生验证包只支持这一纯计算 ABI，不是任意远程程序装载器。

STARTED 必须先落盘；若最终入队失败，仅在内核证明任务从未入队时记录 Cancelled，否则继续查询实际执行结果。重启遇到无确定终态的 STARTED 记录 LOST，不重跑。收件方只接受本地持久请求所绑定的 TaskKey、输入哈希和合同，先持久保存结果再 ACK。资源释放绑定具体合同和 token，延迟的旧 CLOSE 不能释放新预约。

容量边界为 32 个活动合同、128 个结果、4096 个历史墓碑，单项输入/输出最多 32 KiB。持久空间与有界内存耗尽时拒绝新的工作，不承诺无限运行或自动压缩。分页对账每页最多 32 项；当前单合同单任务原型将两者合并为最多 4096 项，并非完整通用对象模式的 8192 项。41 项历史与 128 项结果回归覆盖了分页及满容量重传边界。

完整 1.3 仍有独立范围：通用 RPC 的持久 request_id→载荷摘要表、离群后的全介质压缩回收，以及同一 BootEpoch 下集群服务崩溃后查询未完成任务 token 的自动恢复。当前依靠持久 ContractID/TaskKey/请求哈希保护执行；未恢复 token 时保留未决义务，不重跑任务。内核重启恢复与模型服务重启是已实现的不同路径，不能混为完整服务热恢复。

## 构建与验收

构建工具 `tools/build_unified.py` 接收两个外部配置的身份目录，生成两个内核镜像、各自服务镜像、纯任务包、公钥与构建清单。不要将私钥、身份目录或含私钥镜像提交到代码仓库。

`tools/verify_unified.py` 启动两个四核客体，采集 QMP 页、串口、PCAP 和磁盘；独立解码器检查文件/journal CRC、实际 Ed25519 签名、任务唯一性、结果保管、ACK 与关闭。每次使用新的输出目录。复用磁盘时复制稀疏磁盘到新目录，保留原始证据。

在项目目录执行以下命令可生成新的开发身份、构建并运行正常联合场景。需要已安装 QEMU 10.2.2、OpenSSL、Rust 标准及 softfloat AArch64 freestanding 目标，依赖按锁文件离线构建。身份目录与构建/证据目录须为新目录；工具拒绝覆盖已有身份或结果。

```sh
CYXIA_PAIR_DIR="$HOME/.local/share/cyxiaos-dev-pair"
CYXIA_BUILD_DIR="artifacts/unified-local-build"
python3 user/prototype-cluster/tools/provision.py "$CYXIA_PAIR_DIR"
cargo build --locked --offline -p cyxia-prototype --example prototype-disk
python3 tools/build_unified.py \
  --identity-a "$CYXIA_PAIR_DIR/a" --identity-b "$CYXIA_PAIR_DIR/b" \
  --output "$CYXIA_BUILD_DIR"
python3 tools/verify_unified.py \
  --elf "$CYXIA_BUILD_DIR/node-a.elf" --peer-elf "$CYXIA_BUILD_DIR/node-b.elf" \
  --public "$CYXIA_BUILD_DIR/node-a.pub" --public "$CYXIA_BUILD_DIR/node-b.pub" \
  --package "$CYXIA_BUILD_DIR/task.elf" --build-manifest "$CYXIA_BUILD_DIR/build-manifest.json" \
  --output artifacts/unified-local-run --tcg-threads single --reconnect
```

复用同一镜像，将 `--reconnect` 换成两项 `--disk artifacts/unified-local-run/node-1/disk.raw --disk artifacts/unified-local-run/node-2/disk.raw`，并使用新的输出目录，可检查原盘重启。加上 `--expect no-entropy --without-entropy` 可检查无熵重启的离线结果保管。模型挂起和停止确认缺失需要分别以 `--fault hang-once`、`--fault no-stop-ack` 重建并以对应 `--expect` 验证；离群使用构建 `--leave` 与验证 `--expect leave`。

原生测试默认 `wallclock`，可显式选择 `--tcg-threads single` 或 `multi`。单线程 TCG 的四个虚拟核心不证明物理核心的并行时序；实际 Gate 并发另由宿主多线程测试覆盖。实验性 `icount` 使用单线程 TCG、显式 shift、`align=on,sleep=on` 和 VM RTC；SMP 共享虚拟时钟及轮转会影响时间片。这些配置都不证明硬件实时延迟，两台 VM 的外部网络 I/O 也不是确定性重放。

开发运行 `artifacts/unified-dev-01` 观察到完整正常链路，但不是最终证据。`artifacts/unified-dev-02` 在多线程 TCG 下出现真实 10 毫秒预付预算超额并按设计停止授权，失败证据保留；没有放宽内核预算以使其通过。

`artifacts/unified-dev-03`（icount shift=4）与 `artifacts/unified-native-normal-01`（shift=0）也因虚拟时钟成本/超额或会话超时失败。`artifacts/unified-native-normal-02` 多线程运行已完成完整协议和重连，独立 PCAP/磁盘证明通过，但一次业务时间片为 10.11 ms，整体验收仍记 FAIL。后续修复使用空闲核心 WFE/事件唤醒降低忙等开销，未增加时间预算。

`unified-native-normal-03/04` 与 `unified-dev-04` 的失败同样保留。DEV04 的 CPU2 超额已在最终停机前约 200 ms 被计入，不能归因于最终 QMP stop；当前没有足够证据区分宿主调度与模拟器 I/O 延迟。中途进度采样已改为不停机读取，并用发布序号验证 RUNTIME 页；最终仍停机采集，任何预算超额均拒绝通过。DEV05 在同一单线程 wallclock 配置下完成完整链路及重连，所有预算检查通过，但它使用旧镜像，只记 OBSERVED。

Native04 暴露的另一条退出路径已修复：CPU3 在执行信用检查前处理已入队/挂起任务的取消与期限，即使业务信用冻结也能发布终态。先 Acquire 任务状态，再读取该次发布的取消/期限元数据，避免误读旧任务期限。该处理不执行任务代码、不返还未知执行结果，也不放宽 CPU 预算。

第一轮完整矩阵的 `unified-complete-badpin` 因 CPU3 实测超额而失败，`unified-complete-noentropy` 因 TLS 配置的熵探测在 Driver 恢复前退出而失败，两者均保留 FAIL。后者已修复为先验证身份并恢复 Driver，再按连接状态创建 TLS；每个外层服务轮次先执行离线结果保管，仅熵不足返回网络隔离，其他配置错误继续拒绝运行。真实 Driver 回归覆盖已接收任务的离线完成与已关闭历史的离线重启；这个主机回归与下表原生闭合历史恢复的证明范围分别记录。

## 最终联合验收结果

2026-10-24 最终五种镜像均来自同一份 627 项源码/资源摘要：`9bafff02df7f5386b9cf7ad1c417f774b326cfcdddda8870050d5c8377b65710`。目录为 `artifacts/unified-build-complete2-{normal,leave,hang,noack,badpin}`，每种镜像的构建清单都通过验收器实际使用的 `bind_build` 校验。最终八个场景全部 PASS，未使用 `--development`，也未放宽预算或把旧失败改为成功。

| 场景 | 原生证据结果 | 本地证据 |
|---|---|---|
| 正常与断网重连 | 同一次运行完成 AI 分核 1→2→1、EL0 TLS、BOUND/READY、唯一任务 DONE、结果保管、ACK/CLOSE；断网期间 AI/业务继续，重连重新认证 | [normal](../../artifacts/unified-final-normal/summary.json) |
| 原盘重启 | 两端 BootEpoch 从 1 增至 2；既有结果和关闭证明恢复，新执行次数为 0 | [reboot](../../artifacts/unified-final-reboot/summary.json) |
| 双方离群 | 双签名证明验证通过，两端持久状态均回到 Standalone | [leave](../../artifacts/unified-final-leave/summary.json) |
| 模型挂起一次 | 每端恰好记录一次模型故障；本地业务与合同任务继续完成 | [hang](../../artifacts/unified-final-hang/summary.json) |
| 停止确认缺失 | CPU2 不交接，保留旧 C/B 所有权并标记疑似失联；CPU3 仍完成任务 | [noack](../../artifacts/unified-final-noack/summary.json) |
| 对端固定身份错误 | TLS 尝试后拒绝；没有认证、成员形成或任务授权，本地 AI/业务继续 | [badpin](../../artifacts/unified-final-badpin/summary.json) |
| 无熵冷启动 | Driver 已初始化、TCP 收发为 0、任务开销为 0，本地 AI/业务继续 | [noentropy](../../artifacts/unified-final-noentropy/summary.json) |
| 原盘无熵重启 | BootEpoch 增至 2，成员/结果事件记录逐字节不变，独立签名与结果证明仍通过，无新任务执行 | [noentropy-reboot](../../artifacts/unified-final-noentropy-reboot/summary.json) |

最终全部场景记录的预算超额均为 0，最大的已完成时间片为 8.431008 ms，低于 10 ms 上限。中途读取采用序号一致性检查，最终仍使用停机快照。这是这些有限 QEMU 运行的结果，不能由此推断物理多核最坏延迟；前述真实超额失败仍是适用范围的重要限制。

回归结果为 Rust 工作区 622 项、独立客体服务 19 项（15 个 Driver、4 个 ABI/分配器）、Python 491 项，均通过。源码审查发现的 R1–R15 均已修复并复核。每个原生目录保留串口帧、QMP、PCAP、原始磁盘、源码/镜像绑定和逐文件摘要；汇总及测试日志见 [最终证据汇总](../../artifacts/unified-final-evidence/summary.json)。其中镜像含开发私钥，不应提交到仓库。

四项请求目标已在同一原生配置中完成集成与上述验收。全量 1.3 的 69 项目录保持独立，未自动改为 PASS；默认桌面集成、实体多核实时性、完整学习和生产系统认证不在本次通过范围内。
