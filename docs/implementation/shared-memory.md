# 有界 memfd 与共享映射基础

本实现提供真实共享物理页，供后续 Wayland `wl_shm` 使用。它不是完整 Linux VM，也不表示 COSMIC 合成器或桌面已经运行。首批只在 `large-memory` 的 512 MiB 配置启用；256 MiB 配置保留原匿名堆及 ELF 池，`memfd_create` 返回 `ENODEV`。

## 所有权与 AI 决策

`kernel/src/shared_memory.rs` 从 `BootInfo` 的真实空闲区域独立预留 16 MiB。池包含 4096 个 4 KiB 页、16 个对象元数据槽；每对象最多 8 MiB。对象创建通过本地模型 8193 的元数据准入；物理增长通过模型 8194，以实际全局可用页和新增页为输入。每次请求最多 2048 页，保持既有模型训练数域；这只是既有容量策略的分域复用，没有声称训练了共享桌面负载模型。

每进程拥有独立 16 MiB 虚拟窗口 `0x06000000..0x07000000`，最多 16 个映射记录；创建映射也经过 8193。上述数值是机制上限，模型保留余量可能更早拒绝。映射只消耗映射元数据额度；同一物理页的多个别名不重复计费。

OFD 的 FD、dup、spawn 继承与 SCM 在途引用由统一描述符表持有。共享池保留一份对应 OFD 的 backing 引用，另为每个映射保留引用。因此，发送方退出、接收方 `close(fd)` 或一方 `munmap` 都不会提前清除其他进程仍映射的页面。只有 description 和 mapping 两类引用全部归零，且映射撤销已完成 PTE 更新与现有 CPU0 的 TLB 同步后，才清零物理页并释放真实 grant。对象代次不回绕复用。

`AI_DOMAIN name=shared_objects/shared_pages/shared_mappings` 分别记录准入与额度。`SHARED_OBJECTS` 输出实际对象、页、映射、backing description 引用及 ledger 占用；`description_refs` 是 backing 的 OFD 引用数量，数字 FD 与 SCM 引用的细分属于全局 OFD 状态。计数不是估算 RSS。

`shared_pages.committed` 包含已完成的机制操作。相同大小、缩容、同一已分配页内的增长无需申请新物理页，不增加 `proposals/approved/ai/grant_units`；`ai` 只记录模型批准后实际完成的准入。缩容与最终回收不需要再次取得模型批准。

## 当前 ABI

支持 `memfd_create` 的 `MFD_CLOEXEC`、`MFD_ALLOW_SEALING`；名称只验证 Linux 长度和可读性，不创建 RAMFS 路径。memfd 为匿名、可读写文件，支持真实 `fstat`、共享 OFD offset 的 `read/write/lseek`、`O_APPEND`、`ftruncate`。扩展区域零填充；未映射对象可以缩容并回收尾页；对象存在任何映射时，缩容明确返回 `EBUSY`。文件大小为 0 时不分配物理页。

2026-10-22 增加 AArch64 `pread64(67)`、`pwrite64(68)` 的 memfd 路径。它们直接使用调用给出的偏移，不临时移动或恢复共享 OFD offset，dup 和继承的描述符观察到的当前位置保持不变。完整用户缓冲区先验证，每次实际读写最多 1024 字节，返回真实短读写长度；EOF 读取返回 0，跨 EOF 写入使用原有零填充与 AI 增长准入。负偏移返回 `EINVAL`，无效用户范围返回 `EFAULT`，pipe、Unix socket、PTY 和事件描述符返回 `ESPIPE`。其他普通文件的定位 I/O 仍返回 `ENOSYS`，此处没有声称通用 VFS 定位 I/O 已实现。

`pwritev2` 保持 `ENOSYS`，固定 musl 1.2.6 的普通非追加 `pwrite` 经其真实 fallback 调用 `pwrite64`。原始 Linux `pwrite64` 对 `O_APPEND` 仍写入 EOF，但不改变 OFD offset；musl 为保持其 POSIX 包装器语义，在缺少 `RWF_NOAPPEND` 时会拒绝追加 FD 的该 fallback。零长度定位写入不扩容；写封印同时约束普通写入、定位写入和追加写入。

支持 `F_GET_SEALS` 和 `F_ADD_SEALS` 的 `F_SEAL_SEAL`、`F_SEAL_SHRINK`、`F_SEAL_GROW`、`F_SEAL_WRITE`。未指定 `MFD_ALLOW_SEALING` 的对象初始带 `F_SEAL_SEAL`。`F_SEAL_FUTURE_WRITE` 及其他未实现位返回 `EINVAL`。

写封印按映射的未来可写能力处理：从未封印的可写描述符建立的 `MAP_SHARED`，即使当前为只读或 `PROT_NONE`，仍保留 `may_write`。只要任一进程存在这类别名，添加 `F_SEAL_WRITE` 返回 `EBUSY`；`mprotect` 降为只读不消除该能力。解除所有这类映射后才能封印。检查失败时，同一次请求中的其他封印位也不生效。

封印后，正长度 `write` 和新建可写共享映射返回 `EPERM`，写入不改变 EOF、OFD offset、原数据或页额度。此时仍可新建只读或不可访问映射，但它们不能通过 `mprotect` 升级为可写，升级返回 `EACCES`。映射独立保活及最后引用回收规则不变。`F_SEAL_WRITE` 本身不隐含增长或缩容封印；需要固定大小时须同时指定 `F_SEAL_GROW | F_SEAL_SHRINK`。这些权限规则与 Linux 的 `VM_MAYWRITE` 约束一致，使用每对象一个有界计数和每映射一个权限位实现，无额外堆分配。[Linux memfd 实现](https://github.com/torvalds/linux/blob/v6.18/mm/memfd.c)

共享映射支持 memfd 的 `MAP_SHARED`，页对齐 offset，且请求字节范围不得超过当前文件大小。`PROT_NONE`、只读、读写均映射到真实权限 PTE，执行权限不支持。首版 `munmap` 和 `mprotect` 仅接受完整原映射；无 `MAP_FIXED`、`mremap`、通用文件 mmap 或截断后的 SIGBUS 兼容。用户复制当前要求一个缓冲范围属于同一个共享映射。末尾不足页的映射按硬件页面边界可见，文件读写仍遵守字节 EOF。

同时具备 `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` 的不可变 memfd 可建立有界 `MAP_PRIVATE`。实现先通过现有匿名堆 AI 准入分配页面，复制映射覆盖的完整页内文件字节，EOF 后尾部保持为零，再设置请求的真实 PTE 权限。允许只读、不可访问及读写私有快照；后续 `mprotect`、`munmap` 和进程退出复用匿名堆机制。私有修改不会改变原件，关闭最后文件描述符不影响快照；未封印或封印不完整的文件私有映射返回 `EINVAL`。复制失败会撤销整个新分配。此实现不声称提供可变文件映射或按需写时复制，不提高既有 AI 数域与每进程堆上限。

真实 Wayland 1.24.0 在映射共享池后会立即关闭接收到的 fd，映射独立保活正是本实现必须满足的边界。[固定池 wl_shm 门禁](wayland-shm.md) 已通过；池 resize 的上游路径还会调用 `mremap(MREMAP_MAYMOVE)`，尚不能据此声称支持动态池 resize。

## 验证状态

当前共有 12 个纯机制主机测试。原有 7 项覆盖描述符关闭后的映射保活、最后别名回收、增长缩容与封印、容量/范围错误原子性、对象代次耗尽、反复回收以及每进程映射上限与权限。新增 5 项覆盖写封印、跨进程只读和不可访问别名的未来可写能力、失败操作原子性、封印后权限升级拒绝、引用计数回收，以及私有快照要求完整不可变封印和正确页边界。测试入口：

```sh
cargo test -p cyxia-posix shared_memory --lib
python3 tools/verify_shared_objects.py \
  --elf artifacts/cosmic-foundation-r5/cyxia-kernel.elf \
  --output artifacts/memfd-new-run --probe memfd-probe --iterations 3
```

2026-10-22 的 [r5 memfd 来宾报告](../../artifacts/cosmic-foundation-r5/memfd/summary.json) 已在三个独立 ARM64 启动中通过十个阶段：原有 `FILE_MAPPING_BOUNDS`、`CROSS_PROCESS_ALIASES`、`SCM_CREATOR_EXIT`、`PTE_PERMISSIONS`、`AI_DENIAL_ATOMICITY`、`RECLAIM_ZERO`，以及新增 `POSITIONED_IO`、`WRITE_SEAL_ATOMICITY`、`CROSS_PROCESS_WRITE_SEAL`、`SEALED_PRIVATE_SNAPSHOT`。同一内核的 [SCM_RIGHTS 三次回归](../../artifacts/cosmic-foundation-r5/scm/summary.json) 也通过。

定位 I/O 阶段验证真实成功读写、dup 偏移不变、EOF、空洞零填充、负偏移/坏指针失败无副作用、原始追加 syscall、封印后的拒绝，以及 pipe/socket 的 `ESPIPE` 不消费或注入数据。跨进程阶段让子进程关闭 FD 后保留只读映射，再改为不可访问映射；两者都确实阻止父进程添加写封印，直到子进程解除映射。私有快照阶段验证完整封印要求、权限与范围边界、页尾零填充、三份独立快照、升级私有写权限不影响 backing，以及关闭最后 FD 后快照仍有效。每轮私有快照实际获批并归还 5 个匿名页；所有进程的堆/ELF 页面、共享页、映射、OFD 与在途引用均回收。只读 PTE 测试中指定子进程的真实权限异常是预期结果，其余进程正常退出。

冻结内核 SHA256 为 `a423d4feb8080d6384bc4a798a6aef0469c9fca47fbe9f19cfadba5b435153ef`，memfd 探针 SHA256 为 `7235045236ef8b8e65a37b1942bb153a98601cf798724a678d378cec5567236e`。较早的 [r4 失败报告](../../artifacts/cosmic-foundation-r4/memfd/summary.json) 保留：当时 musl 的 `pwritev2` fallback 到未实现的 `pwrite64`，返回 `ENOSYS`，尚未执行完新增封印和私有快照阶段。r5 实现定位路径后重新执行全部阶段，没有将旧失败改写为成功。

历史基础证据：ARM64 `ported,large-memory` 编译检查与 256 MiB `ported` 的 Clippy `-D warnings` 已通过。冻结候选 `artifacts/cosmic-shared-r1/cyxia-kernel.elf`（SHA256 `02510c23d1ca710433d58cf4963444aacb9c42a303a0234e5117a7305bb64dc2`）已完成各三次独立 ARM64 启动的 [memfd 测试](../../artifacts/cosmic-shared-r1/memfd/summary.json) 与 [SCM_RIGHTS 测试](../../artifacts/cosmic-shared-r1/scm/summary.json)，这些历史报告不包含新增写封印及私有快照场景：

- 真实物理页跨进程双向可见；发送者退出、接收方关闭 FD 后映射仍有效，最后解除映射后回收。
- SCM 接收方在创建者退出后继续扩容，保留原数据并验证新区域零填充。
- 只读 PTE 上的实际写入触发 AArch64 权限异常，父进程收到 `SIGSEGV` 退出状态。
- AI 拒绝增长时，原文件大小、OFD 偏移、数据及其他对象映射保持不变。
- 零长度 `O_APPEND` 写入不移动共享偏移；反复分配、关闭、解除映射后，对象、映射、引用及 grant 占用全部归零，4096 页完整归还。

这些是原始接口与生命周期证据。上游固定池 `wl_shm` 的三次独立启动另见 [协议报告](../../artifacts/cosmic-shared-r3/wayland-shm-final/summary.json)；动态 pool resize、屏幕内容与完整 G-SHM、COSMIC 会话仍须分别验收，不由原始接口测试自动推定。

来源：[Linux memfd_create 手册](https://man7.org/linux/man-pages/man2/memfd_create.2.html)；固定上游源码 `artifacts/sysroot/aarch64-musl/wayland-source/wayland-1.24.0/src/wayland-shm.c` 的 `shm_create_pool` 与 `shm_pool_grow_mapping`。
