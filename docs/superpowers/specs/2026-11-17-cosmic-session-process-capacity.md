# COSMIC 会话进程容量：Linux 进程分配与 demo Arena 版本化分离

状态：设计草案（source-backed），待实施。基线 `CyxiaOS-V0.17` 的 `cc8d7c2`。
本文件是完整 COSMIC 会话容量五步计划（见
`docs/implementation/v17-cosmic-service-integration-20261117.md` "Full-session
resource capacity: source findings"）第 1 步的实施规格。A03 已取消。完整 OS 与
完整 COSMIC 会话标志保持 false，直到实际客体验收。

## 1. 问题与需求（源码事实）

默认 COSMIC 会话的进程需求超过当前内核准入：

| 资源 | 当前机制 | 完整默认会话需求 |
| --- | --- | --- |
| 进程槽 | `MAX_PROCESSES = 8`（`crates/posix/src/usermem.rs:9`）；模型 8193 拒绝第 8 个请求 → 7 常驻 | panel + 18 常驻 applet = 19 进程；session 列出 13 个直接子组件 |
| 子进程 receipt | `RECEIPTS = 10`（`kernel/src/desktop/user/spawn.rs:7`）；准入允许 8 占用 | 13 个直接受管子进程 |
| 匿名管道对 | 32 物理对，准入 30 | 每子进程 3 管理管道：18 applet 需 54，31 子进程需 93 |
| 每进程 FD 表 | 64 项（native child adapter 同 ABI） | panel 18 活 applet 至少 72 FD（管理 + 嵌套 Wayland），尚未计 stdio/D-Bus/reactor |

需求数字来自保留的 session/panel 源码盘点（53 文件审查，SHA
`dbead437…`），是条件性完整默认场景，不是观测计数也不是普适上界。

## 2. 当前准入机制（已读源码）

- `Runner::start`（`kernel/src/desktop/user.rs:238`）：对象表预检（≥3 空闲）→
  `load_for` 加载镜像 → `attempt.proposed(8193)` →
  `user_memory_policy(ledger.snapshot().free, MAPPED_PAGES)` →
  `AuthorizedGrantRequest::validated_ai` → `ledger.commit`/`redeem` → lease →
  页表/context 建立 → `Process::new`（stdio）→ `publish_code`。失败路径
  `cancel_unused` + `arena.clear`；`publish_code` 失败保留 grant 并隔离代码。
- `user_memory_policy`（`crates/ai-runtime/src/lib.rs:730`）：域 free≤64、
  requested 1..=8；`model::memory(min(free,32), requested)`，`MEMORY_ID = 8193`。
  注释明确：该模型为 8 槽/64 页 demo Arena 训练，32 页饱和是保守截断，不外推权重。
  第 8 个请求 free=requested=8 → 分数 -79 → 拒绝。
- `launch_accounted`（`user.rs:1354`）：`publish_child_exits()` 先保留旧 PID 退出
  receipt → 找 inactive 槽 → 单调 `next_pid`（<0x1000_0000）→
  `space.bind(slot,pid)` → `start()` → `heap.bind(slot,owner)`。槽复用是核心机制；
  进程列表是当前槽库存，不是历史 PID 全集（capture v2 的最终 arena 误判即源于此）。
- `MAX_PROCESSES` 被 posix 静态数组引用：`pipe.rs:32` holders、`pty.rs:107`
  holders、`open_description.rs:430` processes 数组；以及
  `address_space.rs:145` 页表池（`TABLE_PAGES_PER_PROCESS * 4096 * MAX_PROCESSES`）。
  仅改常量会同时改变这些静态布局与页表池预留。

## 3.  established 先例：版本化新域，不改旧模型

项目已有容量版本化先例，本工作必须沿用而非修改旧模型：

- `anonymous_memory_policy`（模型 `0x2002`，lib.rs:741）：free≤4096/request≤2048，
  16 页特征单元，独立训练域。
- `full_os_anonymous_memory_policy`（模型 `0x2006`，lib.rs:760）：full-os v2
  32 MiB 私有 arena 的**独立合成策略**，free≤8192/request≤2048，保留两单元
  （32 页）储备与历史 2048 页请求上限；**域外输入拒绝，绝不截断**；内核仍执行
  实际容量、所有权与映射权限。

结论：会话进程容量扩展 = 为 full-os 会话 profile 新建**版本化进程准入策略**
（新模型 ID、新训练/合成域），与 demo Arena 的 8193 分离。8193 的域、权重、
行为保持不变；demo/历史回归路径继续走 8193。

## 4. 第 1 步范围（最小可验证切片）

**目标**：Linux 进程与 child-receipt 分配从 demo Arena 版本化分离，按真实元数据
计费，保留 PID/generation、wait、失败回滚与槽复用前回收。

切片分解（每片独立 RED/GREEN，按序实施）：

1. **S1 进程准入策略版本化**：✅ 已完成（2026-11-18，52 项 ai-runtime 宿主测试通过，
   训练 `--check` 可复现）。实现：`SESSION_PROCESS_MODEL_ID=0x2008`(8200)，
   `session_process_memory_policy(free, requested)`（`crates/ai-runtime/src/lib.rs`），
   raw-page 特征，域 0..`SESSION_LEDGER_PAGES` free / 1..8 requested，域外拒绝。
   profile 常量：`SESSION_PROCESS_SLOTS=40`（33 完整需求+余量）、
   `SESSION_PROCESS_BASE_GRANT=8`、`SESSION_PROCESS_RESERVE=2`、
   `SESSION_LEDGER_PAGES=40*8+2=322`（由槽位推导）。weights `SESSION_PROCESS=
   [-81,90,-103,0]` 由 `train_resource_models.py` append-only 数据集蒸馏
   （teacher `free-need>=2`，epochs=256 收敛大域；legacy weights 逐字节保留，
   unsafe_grants=0，min spare=2）。实际准入 39 进程（≥33），demo 8193 边界不变
   （仍 7 准入）。测试 `session_process_admission_versions_domain_and_admits_full_session_demand`。
2. **S2 会话槽位与元数据版本化**：为 full-os 会话 profile 定义独立槽位常量与
   receipt 容量（≥19 进程 + 余量；receipt ≥13 直接子进程 + 余量），与
   `MAX_PROCESSES=8` demo 布局分离。posix 静态数组（pipe/pty holders、OFD
   processes）与 address_space 页表池按 profile 版本化，不改 demo 布局。
   RED：槽位/receipt 容量边界、静态数组尺寸与 profile 一致性测试。
   - ✅ **dispatch 域已版本化**（2026-11-18，53 项测试通过）：
     `session_process_dispatch_policy`（`ai-runtime/src/lib.rs`）候选域
     ≤`SESSION_PROCESS_SLOTS`(40)，复用不变的 `rank_user_candidates` 排名/饥饿保护
     （仿 `full_os_thread_dispatch_policy` 16 槽先例）；demo `user_dispatch_policy`
     仍 ≤8。测试 `session_process_dispatch_reaches_full_slot_count_without_changing_demo_limit`。
   - ✅ **进程布局已 feature-gate 版本化**（2026-11-18）：沿用 `PIPES` 的 feature-gate
     先例（`full-os`→32），新增 **`cosmic-session` feature**（posix=`["full-os"]`，
     kernel=`["cosmic-desktop","cyxia-posix/cosmic-session"]`，全新 opt-in，demo/
     现有 full-os/cosmic-desktop 构建零影响）。`usermem::MAX_PROCESSES`：
     cosmic-session→40，否则→8；`POOL_PAGES` 及所有 holders/页表池/内存池自动缩放。
     kernel `user.rs` 加编译期断言 `MAX_PROCESSES == SESSION_PROCESS_SLOTS`。
     验证：posix demo 210 测试不变；posix cosmic-session **212 测试全过**；
     kernel cosmic-session（x86_64-unknown-none，40 槽+断言）编译通过。
     **关键发现**：full-os posix 测试需 `RUST_MIN_STACK=16777216`（大 limits
     fds=64/open_descriptions=256 使栈分配结构超 2MB 默认测试线程栈）——此溢出
     **full-os 单独亦现，是预存测试 harness 行为，非 S2 改动引入**；cosmic-session
     大栈下 212 全过。pipe handle 低字节编码 pipe index（非进程槽，PIPES≤128 已断言），
     40 槽仅放大 holders 数组，handle 编码不受影响。
   - ⬜ receipt 容量：`spawn.rs:7` `RECEIPTS=10`（8 占用准入）需 session 版本
     （≥13 直接子进程+余量）；`publish_child_exits` 回收路径核实。
3. **S3 真实元数据计费**：进程启动按真实 ELF/栈/页表帧与元数据计费（替代固定
   8 页 base grant 的单一计费），保留 owner 标记、generation、wait、失败回滚、
   槽复用前完整回收。物理帧分配沿用现有 owner-aware 机制（第 2 步再扩 on-demand）。
   RED：计费/回收/回滚守恒测试（启动-退出-复用循环无泄漏）。
4. **S4 接线与回归**：`launch_accounted`/`Runner::start` 在 full-os 会话 profile
   下走新策略；demo/历史路径不变。全套既有宿主测试 + 基础镜像冒烟
   （`os_smoke.py --scenario native`）必须保持 PASS。
   - ✅ **准入接线已完成**（2026-11-18，feature-gate）：`Runner::start`
     （`user.rs`）与 spawn receipt 准入（`spawn.rs`）在 cosmic-session 下改用
     `session_process_memory_policy`（model 8200）+ `attempt.proposed(8200)`；
     demo 路径 `#[cfg(not(cosmic-session))]` 保持 8193 逐字节不变。ledger 经
     `USER_POOL=POOL_PAGES=8*40=320` 自动扩容（策略 2 页储备由准入函数保证，
     320 页可准入 39 进程）。验证：demo 内核（os-runtime,graphics）与
     cosmic-session 内核（x86_64-unknown-none）均编译通过。
   - ✅ **demo 基线冒烟回归 PASS**（2026-11-18）：`os_x86.py build --graphics` +
     `os_smoke.py --scenario native` → `OS_NATIVE_PASS`（artifacts/v017-os-smoke-s4check）。
     feature-gate 隔离证实 demo 路径（8193/8 槽）受 S1/S2/S4 改动零影响。
   - ✅ **客体验收 PASS**（2026-11-18）：cosmic-session 镜像（artifacts/v017-os-session-build4，
     features=os-runtime,graphics,ported,cosmic-session）QEMU 实际启动 **39 进程**，
     全部 `USER pid=N started; memory AI_DIRECT model=8200 pages=8`，第 40 次
     `start failed: Nomem`（精确版本化准入边界）。census=artifacts/v017-session-census-39b
     （status=PASS, admitted=39, models={8200:39}, boundary="denied at spawn 40: Nomem"）。
     ≥33 文档完整默认需求达成。census 脚本修正为等待**异步**启动标记（spawn 命令
     立即返回 prompt，实际启动在 poll 循环稍后发生；旧版等 prompt 导致归因错位假象）。
   - ✅ **第 2 步 on-demand exec 帧分配已实施**（2026-11-18，解除 guest 启动阻塞）：
     原阻塞根因 `exec_memory::RESERVED_BYTES = BYTES * MAX_PROCESSES`，FullOsV3
     `exec_pool_pages=16384`（64MiB/slot）×40=**2.5GiB > 1GiB 客体 RAM** → boot panic
     `user executable pool: Nomem`（runtime/os.rs:64）。修复镜像 heap 的
     `user_heap/pool.rs` 范式（固定共享池 + 按需 owner-tagged 分配）：
     - 新增 `cyxia-kernel-core::contig_frames::ContigFramePool<N>`——有界**连续 run**
       owner-tagged 分配器（first-fit gap，占用集重算自动合并，release 校验
       owner/base/pages，伪造拒绝）。7 项宿主测试 + 变异 red 证明（移除 owner 守卫
       精确使 2 项安全测试失败）。选连续 run 而非逐页 FramePool，因 exec 初始栈
       构建/resolve/clear 依赖单一连续基址；保留虚拟布局/W^X/完整退役逐字不变。
     - `exec_memory/arena.rs`（cosmic-session 门控薄包装）：固定共享 `PAGES=65536`
       （256MiB，镜像 heap 共享预算，版本化常量），`allocate/release` 委托
       `ContigFramePool<MAX_PROCESSES>`，owner 用 `Owner.task`。
     - `exec_memory.rs` cfg-gate：`RESERVED_BYTES`=arena::BYTES（session）/
       BYTES×MAX_PROCESSES（demo）；`init_pc`/aarch64 `init` 调 arena::init；
       `load_accounted` 在 grant commit **前**分配 run（commit 失败归还，无泄漏），
       `self.base`=run_base；`clear` 退役+zero+ledger release 后 arena::release。
       编译期断言 `BYTES<=arena::BYTES && arena::PAGES>=PAGES`。
     - 验证：启动回路 artifacts/exec_pool_boot_check.py RED（Nomem panic）→GREEN
       （prompt, reserved_exec_bytes=268435456）；demo 路径 cfg 隔离零改动。
   - ✅ **dispatch 域接线已完成**（2026-11-18，解除第二个 guest panic）：exec pool
     修复后 census 暴露 `parallel.rs:245` panic `user_dispatch_policy(...).unwrap()
     → Err(Invalid)`——demo 进程选择器域 ≤8，session 候选数组 SLOTS=40。S2 已加
     `session_process_dispatch_policy`（域 ≤40）但未接线。新增 `user.rs::
     process_dispatch_policy`（cfg!(cosmic-session) 选 session/demo，内部 unwrap，
     镜像 threads.rs 的 `full_os_thread_dispatch_policy` feature-gate 先例），接线
     三处进程选择点（user.rs aarch64 路径 + parallel.rs 单/多 CPU 分支）。threads.rs
     用 ≤16 线程域不受影响。排名/饥饿保护复用不变。
   - ✅ **全套回归 PASS**（2026-11-18）：kernel-core 18（11 旧+7 新）、ai-runtime 53、
     posix demo 210、posix cosmic-session 212（RUST_MIN_STACK=16777216）；demo 镜像
     `os_smoke.py --scenario native` → **OS_NATIVE_PASS**
     （artifacts/v017-os-smoke-demo-regress）。demo 8193/8 槽路径零回归。
   - 注：S3 真实元数据计费是精度细化——base grant 仍 8 页（与 demo 一致），
     39 进程核心容量已由 S1+S2+S4+第 2 步达成；S3 进一步按 ELF/栈/页表帧精确计费。
     exec arena 256MiB 对当前 ported 组件（comp≈34MiB+session+settings）与 census
     余量充足；applet 聚合需求待第 5 步落地时对此版本化预算复核。

**不在第 1 步范围**：on-demand 物理帧分配（第 2 步）、FD ABI/管道/Unix 容量协调
（第 3 步）、可变核心租约（第 4 步）、applet 入口供给（第 5 步）。不提高任何
现有运行时 deadline、镜像/catalog 上限或资源池；新 profile 的容量是显式版本化
新增，不是静默扩容。

## 5. 待确认事实（S1 实施已核实部分）

- ✅ `GrantLedger::new(capacity: PageCount)`（`kernel-core/src/grants.rs:112`）容量
  **参数化**，64 页来自调用方（Supervisor），非硬编码——会话 profile 可传入
  `SESSION_LEDGER_PAGES=322` 版本化 ledger，commit 按 `r.pages > s.free` 拒绝超额。
- ✅ weights 由 `tools/train_resource_models.py` 合成 teacher 感知机蒸馏生成
  （append-only 保留 legacy RNG 流）；模型 ID 序列 0x2001(8193 demo)/0x2002/0x2006
  (8198 full-os-v2 anon)/0x2007(8199 full-os-v3 pool anon)/8197(exec full-os)；
  会话进程取 **0x2008(8200)**。demo `weights::MEMORY=[-39,42,-47,0]`，
  `model::memory` 饱和 free 于 `PAGES=32`。
- ⬜ 进程选择器 8 候选域：`user_dispatch_policy(&[Option<UserCandidate>; 8])`
  （`lib.rs:866`，测试 `eight_dispatch_candidates...`）——S2/S4 槽位 >8 时需版本化
  候选数组域（不改 demo 8 候选路径）。
- ⬜ `spawn.rs` `RECEIPTS=10`（8 占用准入）与 `publish_child_exits` 回收路径——S2/S3 核实。
- ⬜ `address_space.rs` 页表池（`TABLE_PAGES_PER_PROCESS*4096*MAX_PROCESSES`）与
  `ProcessSpace` profile 版本化接缝——S2 核实。
- ✅ full-os profile 常量模式（`FULL_OS_ANON_MODEL_ID` 周边）：独立域 + 域外拒绝 +
  内核执行实际容量；会话进程策略沿用此模式（S1 已实现）。

## 6. 验收与边界

- 每片 RED/GREEN 宿主测试；S4 后基础镜像冒烟 PASS；不声称客体会话成功。
- 完整会话进程容量的客体验收（19+ 进程实际启动、协议所有权、渲染、输入、
  重启、全局回收）需要 ported sysroot 与原生环境，见第 7 节。
- 不重新分类任何保留捕获；四次服务捕获保持 FAIL 记录。
- AI 选择与内核权限分离不变；新策略不授予超出实际容量的权限。

## 7. 构建链阻塞（完整桌面镜像）

本机（macOS ARM）完整 COSMIC 构建链调查结论（2026-11-17）：

- 基础 x86-64 镜像可本机构建并冒烟通过（已验证，`artifacts/v017-os-build`）。
- 完整桌面需要 `--ported` + sysroot（默认 `artifacts/sysroot/x86_64-musl`，
  须含 `probe.elf`）。sysroot 是**预构建 SDK**：musl 交叉工具链
  （`x86_64-linux-musl-cc/cxx/ar/ranlib`）+ SHA-pinned native archives
  （libc.a、CRT、builtins、wayland/xkbcommon 等，见
  `tools/cosmic_notifications_toolchain.py:69` `tools_and_sysroot`）。
- **仓库内无 SDK 重建工具**；recipe 的 native_inputs SHA pin 意味着即使重建
  SDK，字节 SHA 不匹配也会被 producer 拒绝。SDK 字节必须来自原构建环境。
- 源码缓存 `artifacts/cosmic-sources`（`tools/cosmic_ports.py:29`）gitignored、
  本机 absent；但 `prepare --fetch` 支持在线获取（git + crates.io），可本机重建。
- 本机全盘搜索确认无 SDK/源码缓存/组件 ELF 残留。

**解阻所需（用户提供）**：原环境的 `artifacts/sysroot/x86_64-musl`（完整 SDK）
与 `artifacts/cosmic-sources`（可选，可在线重建）。拿到 SDK 后，组件 producer
（prepare/build）与 full-os 镜像构建可在本机尝试；客体验收仍需 QEMU（本机有
qemu-system-x86_64，TCG 可用）。