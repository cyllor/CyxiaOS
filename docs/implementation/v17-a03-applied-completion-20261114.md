# V0.17 A03：实际所有权完成门禁

日期：2026-11-14。A03 仍未 PASS；x86 A03 为 NOT_RUN。
本轮承接平台提交 `72fdd322141a4f1caaf6e0b773645d98cac42869`。

## 问题与结果

原普通需求场景在队列排空、quiet 时间到达并收到较晚的模型回复后就进入 phase 6。
模型回复不能证明控制核心已经收缩；历史 `a03-ordinary-demand-04` 只有 1→2 的实际变化，
quiet 模型仍选双核。原本的场景完成标记不应作为完整 A03 通过依据。

现在只有同次普通负载内的实际扩核及排空之后的实际收缩都完成，场景才结束。
保留既有 `A03_DEMAND_V16` 和 `OWNERSHIP_V15` 证据 ABI；旧场景解码器仍只声明原有范围。
新验证器对这些原始记录追加关联验证，不更改或补造旧记录。

## 实现边界

- `crates/prototype/src/a03.rs` 提供与架构无关的有界门禁。最多读 8 条实际所有权记录，
  检查同一 boot、ApplyID、模型任务/版本、预算、分区、迁移 ACK、完成快照及发布封印。
  扩核必须发生在本次 high 负载窗口，最终收缩的模型输入必须晚于本次 drain。
  不另外分配一份 58 KiB 所有权快照；该门禁不替代模型数值重放或原生来源验证。
- ARM 诊断适配从最后一次实际收缩记录留存 640 字模型回执，复制后重新检查整条所有权链。
  root 模型回复与 C0 收尾通过同一个发布计数器 CAS 互斥，竞争时立即放弃本次尝试，后续重试。
  写入中、撕裂、错误身份、Pending 或未来完成时间均不能使场景进入 phase 6。
- `tools/verify_v17_a03_demand.py` 先执行既有普通采集的 QMP、源码、镜像、模型身份及 quiet
  数值验证，再要求 quiet 原始回执与最终实际收缩记录逐字节相同，并重放全部扩缩核 MLP/Plan。
  重放器由调用方指定的源码重新编译，不执行证据目录附带的二进制。
- 即使上述关联成功，新工具也输出 `A03_complete=false`、
  `trained_active_provenance_verified=false`、`x86_native_verified=false`。
  当前原生采集适配仍属于 ARM；共享逻辑支持 x86 编译不等于 x86 原生链已经可运行。

对未来真实采集使用：

```sh
python3 -B tools/verify_v17_a03_demand.py \
  --directory /path/to/capture \
  --source-root /path/to/reviewed/source \
  --build-manifest /path/to/build-manifest.json \
  --formatter /path/to/formatter \
  --qemu-binary /path/to/qemu-system-aarch64 \
  --qemu-source /path/to/qemu-source
```

沿用 native lease；需要旧生产工具时显式指定 `--producer-tools-root`。该命令不会训练模型，
也不会为缺失的原始采集、训练数据或 Active 来源补写证据。

## 验证

本地证据位于 `artifacts/v017-a03-20261114-r2/`，不把生成物提交到 Git。
最终结果以 `final-v2/results.json` 和对应源码清单为准。
最终编译源码摘要为 `c73ab290471b76036370aa805bffb6bc83d9414e4fc5f9463a2a51fda2c24e53`。

- 最终共享 Rust 回归 942 项通过，另通过 x86 裸机目标编译检查；覆盖结构门禁、真实普通队列状态机、实际记录器及既有逻辑。
  新增反例包括 Pending、错 ApplyID、缺 ACK、时间窗外扩核、过期/未来回执、读中变化、并发写入。
- 工具全量验证在互斥收尾修正前完成：811 项中 810 通过，1 项缺历史 R7 输入跳过。
  互斥修正后重验 18 项 A03/所有权相关工具测试；没有声称 26 个既存宿主测试失败已修复。
- ARM 双节点普通 A03 profile 编译用于覆盖条件编译适配；构建成功状态为 BUILT_NOT_RUN。
  PC dev/release 以 TCG 启动并独立复核通过，x86 内核严格 Clippy 与 kernel 目录检查通过。
  这些都是构建或平台机制验证，不能代替原生 A03。
- 只读检查历史 `a03-ordinary-demand-04`，新关联检查拒绝缺少收缩的链。
  `historical-negative.json` 保留三个原始文件的 SHA-256；检查前后未改动历史输入。
  此次历史检查仅为结构诊断，没有重新认证该旧采集的原生来源。

## 未完成部分

1. 18 族真实训练/验证数据及实验组互斥，最低 144/72 条。
2. 客体原生训练、独立验证、Shadow/Canary/Active 切换及可重放来源。
3. 使用新 Active 在普通需求变化下实际完成 1→2→1 的原生采集。
4. x86 四核、所有权停机、执行计量、设备及生产运行时移植。

既有 500 μs 发布（含解码）、2 ms 模型及 1 MiB 工作区预算保持不变。
ARM 完整采集曾出现的 525332 ns 发布超限仍是有效失败；本轮未证明它在 x86 上消失。
