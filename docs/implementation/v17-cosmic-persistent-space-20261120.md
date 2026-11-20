# COSMIC 持久页表与增量映射

已移除 x86 桌面每次派发的全量根页表重建。最终 2 GiB 镜像两轮分别在
62.635 / 62.627 秒观察到时钟；相同用户输入的原记录为 107.191 / 101.111 秒。
本轮没有修改 COSMIC、Mesa、用户 ELF、资源额度、45 秒首帧检查或 15 秒交互期限。
完整 OS 与 COSMIC session 验收标志仍为 false。

## 实现与回收边界

- `ProcessSpace::begin` 保留已有、无驻留 CPU 的根，只在首次准备时创建根。
  单核返回和多 AP 完成阶段均保留页表；多 AP 仍必须全部回到内核 CR3，
  归还所有 Runner 所有权后才执行系统调用。
- x86 staging 表增加 512 位 dirty bitmap，利用原有 padding，仍为
  8192 字节、4096 字节对齐。首次全量发布；后续只检查 dirty 项，跳过
  与现有 PTE 相同的映射，按需撤销、封存和发布。失败保留 dirty 集及成功前缀，
  Runner 不会带着失败的页表重新进入用户态。
- `munmap` 的完整分配/共享映射验证发生在撤销前，真正的硬件 PTE 和 alias
  引用撤销发生在物理页清零、帧池释放、共享 mapping ref 和 grant 退还之前。
  native 与 Linux 调用均接入该边界。退出继续销毁完整根后再回收镜像、堆及共享映射。
- W^X、物理别名计数、代码封存、AP 所有权、内核 CR3 返回、无 PCID/无 global
  用户映射的原约束保持。没有缓存 TLB、放宽 alias 检查或允许活动根修改。
- 页表 arena 仍使用原 128 页。反复映射当前全部准入 VA 窗口的回归确认，
  中间表用量到达窗口上限后不再增长；本轮不增加页表池或内存额度。

`space_rebuilds` 现在只计实际建根，新增 `space_reuses` 计保留根的准备次数。
`space_prepare_ns` 包含增量同步；`space_revoke_ns` 单独记录释放 backing 前的
即时撤销；`space_retire_ns` 记录整根销毁。三个 HPET wall 区间不重叠，均不是 CPU 计费。

## 相同输入的启动观察

QEMU TCG、4 vCPU、2 GiB、1024×768 VirtIO scanout，使用同一
`artifacts/v017-native-pointer-motion-catalog-v1`。最终镜像为
`artifacts/v017-os-persistent-space-2g-v2`，boot SHA-256：

`9f20b10191f7e28d47a91d1392722a1bc0ba674c09758b1eb82d2aa3217bc1da`

| 采集 | 原背景 | 新背景 | 原时钟 | 新时钟 |
| --- | ---: | ---: | ---: | ---: |
| 周期进程状态查询 | 34.421 s | 24.265 s | 107.191 s | 62.635 s |
| 无周期状态查询 | 32.376 s | 24.286 s | 101.111 s | 62.627 s |

原数据来自[启动归因报告](v17-cosmic-startup-attribution-20261120.md)。这些是不同轮次的
墙钟观察，截图间隔约两秒，不是延迟分布。新两轮使用同一最终镜像，用户输入逐字相同；
原镜像与最终镜像的源码差异均绑定到本轮保存的原始文件。时钟观察时间减少约 38%–42%，
背景约 25%–30%；不能据此承诺其他宿主或真实硬件的同等改善。

周期查询轮最后一次读取在 74.676 秒，七个任务仍存活，各建根一次，合计复用
45,874 次。准备、即时撤销与整根退休合计 0.371359 秒。原报告的 44.066580 秒
读取于约第 90 秒；两个窗口不同，不能将其差值直接当作启动节省时间。

早期诊断版 `v017-os-persistent-space-2g-v1` 曾在 54.497 秒看到时钟，但该版尚未增加
即时撤销独立计时；其完整产物保留，不与最终版两轮混报。

## 测试与已保留失败

- 原始 `ProcessSpace::begin` 在独立回放中失败：准备已有根会销毁其稳定映射。
  当前实现通过同一回归。完整页表套件 59 项执行实际生产 `PageTable`、`ProcessSpace`、
  页表/alias 算法及 heap/shared 撤销函数；CPU、物理内存、TLB、帧/grant 后果是
  显式宿主 fixture，不能将这些用例称为真实 MMU 验证。
- POSIX、x86 与 contracts 默认配置共 341 项通过，多 AP 完成阶段回归通过。
  完整 `cosmic-session` 配置的 POSIX 测试 295 项亦通过；该宿主大夹具先触及 Rust 默认
  测试线程栈，复测仅设置 `RUST_MIN_STACK=16777216`，没有修改客体栈或任何客体额度。
  AArch64 `graphics` 内核兼容编译通过；未执行新的 ARM 客体验收。
- 最终镜像两次 `OS_NATIVE_PASS`，额外覆盖真正的匿名页撤销后访问 fault
  （vector 14/error 4）及匿名数据页 NX fault（error 0x15），故障地址均为
  `0x0c000000`。既有寄存器、真实抢占、FP/TLS、堆零填充/重用、IPC 与持久化测试保持。
  原 1 GiB、非 full-OS 配置另行构建并通过 `OS_NATIVE_PASS`，实际覆盖其独立的
  匿名页清零与回收分支；镜像为 `v017-os-persistent-space-legacy-v1`。
- 首轮真实日历的打开、关闭、再打开、再关闭为 12.151 / 8.808 / 9.890 / 8.273 秒，
  均在原 15 秒期限内；原时钟与核心进程存活，无异常退出。实际 scanout 已人工确认
  完整 2026 年 11 月网格、20 日高亮和设置入口。
- 输入前共享状态为 12 对象 / 81 页 / 19 映射；首次关闭后为
  12 / 105 / 20，第二次关闭完全相同。这里只能证明两次关闭后的稳定状态相同，
  不能宣称回到输入前状态，也未将其未经拆分地称为内核泄漏或应用缓存。
- 独立复测的四次交互为 9.872 / 8.216 / 10.402 / 8.257 秒，全部在 15 秒内；
  此轮输入前及两次关闭后均为 12 对象 / 105 页 / 20 映射。完成原进程存活检查后，
  再明确结束七个用户进程；匿名帧使用量、共享对象/页/映射/引用、grant 与 OFD
  引用全部归零，证明保留的映射随进程退出完整释放。
- 一次附加总线检查在第 45 秒遇到既有 `max_completed_connections=16`，
  诊断用 `dbus-send` 退出 1，未进入该轮日历/回收检查。失败目录完整保留，
  不计为通过；后续独立回收验证省去这次可选查询，未增加连接额度或放宽交互断言。

## 复算与产物

主要命令：

```sh
python3 -m unittest discover -s tests/host -p test_page_map_batch.py -v
python3 artifacts/debug/cosmic-persistent-space-20261120/replay_regression.py
RUST_MIN_STACK=16777216 cargo test --locked --offline -p cyxia-posix --features cosmic-session
python3 artifacts/debug/cosmic-persistent-space-20261120/verify.py
```

诊断脚本、原始源码、编译/测试日志及聚合证据位于
`artifacts/debug/cosmic-persistent-space-20261120/`。2 GiB 原生和交互 wrapper 仅显式选择
2 GiB 验证/启动 profile，保留原测试函数、ELF、期限和断言；额外硬件故障与完整退出
断言分别保存在独立脚本中。启动产物为
`artifacts/v017-persistent-space-startup-2g-v2`、`-v3`；交互、原生及失败目录均保留。

本轮消除的是重复页表工作。最终时钟仍在约 63 秒出现，不能称为完整的启动性能达标；
后续剩余初始化与事件调度成本需要基于新镜像重新归因。
