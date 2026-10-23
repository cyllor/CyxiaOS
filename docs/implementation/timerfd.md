# 单调时钟 timerfd

2026-10-20：P4a 已实现 CLOCK_MONOTONIC 的 timerfd 子集。计时状态在
[POSIX OFD 层](../../crates/posix/src/timerfd.rs)，AArch64 用户内存及
`timerfd_create/settime/gettime`（85/86/87）接入位于
[内核适配](../../kernel/src/user/timerfd.rs)。

支持相对和绝对期限、一次性及周期计数、8 字节读取与 readv 分散写入、
disarm/rearm、NONBLOCK、每 FD 的 CLOEXEC、dup 和显式 native spawn 共享
同一个计时器。gettime 返回下一次到期的相对剩余量，不消费未读取的计数。
poll 和 level/oneshot/edge epoll 从真实单调时钟计算可读性，计时器不可写。
成功重设到已过去的绝对期限会发布新的就绪通知，即使上次到期尚未读取；
读取、取消及未来期限重设同步更新观察状态，避免丢失后续边沿。

settime 在更新前复制新值、验证旧值输出范围、标志和时间溢出；错误不修改
计时器。read/readv 在消费到期数前验证完整输出范围。阻塞读取由
`Wait::TimerRead` 停驻，重新启用别名可唤醒；不会每毫秒反复进入 EL0。
等待绑定 OFD 代次，关闭并复用原 FD 后返回 EBADF，不消费新对象。
最后引用关闭时，同一套 OFD 回收移除弱引用 epoll watch。

资源仍受每进程 16 FD、全局 128 OFD 及既有 epoll 上限约束。状态内嵌于
已预留的 OFD 元数据，不新增动态分配、无限队列、后台线程或独立额度池。
进程/线程准入、内存及实际恢复后的 CPU 排序继续使用本地模型；到期时间、
计数、权限和 FD 代次由确定性机制执行，模型不能改写调用者的期限。
这不是新增一个已训练的“AI 定时器模型”。

不支持 REALTIME、BOOTTIME、alarm clocks、CANCEL_ON_SET、SCM_RIGHTS
传递 timerfd、临时信号掩码或嵌套 epoll。已知但未实现的 clock
返回 ENOSYS，非法 clock/flags 返回 EINVAL。纳秒表示溢出返回 EOVERFLOW。
当下一周期超出 u64 纳秒域时不回绕，读取已到期计数后停止计时。
真实固定版本 [Mio reactor](rust-reactor.md) 已通过三次客体进程检查；
Tokio/calloop 尚未验收，P4a 整体仍未完成。

## 验证

6 项 Rust 单元测试覆盖周期累计、gettime 不消费、过去绝对期限、
disarm、错误重设原子性、纳秒溢出、共享描述符及标志。ARM
[探针](../../user/ported/timerfd_probe.c) 在三次独立启动中各完成 73 项
检查，报告位于
[timerfd](../../artifacts/cosmic-timer-r2/timerfd/summary.json)。

新增过去绝对期限连续重设的 ET 回归先复现漏通知，再验证修复。
[edge 客体测试](../../artifacts/cosmic-reactor-r3/edge/summary.json) 在三次启动中
同时覆盖读取后的相对重设及不读取的过去绝对期限重设；每次仅投递一次就绪。

测试包含真实独立子进程消费同一计时器、周期累计、epoll oneshot、
完整 usercopy/readv 错误前置校验。两阶段外部门控先观察真实等待次数增加，
再执行别名重启或关闭复用，不靠固定 sleep 推测线程已经阻塞。
各次退出后 OFD、watch、共享对象/页和资源 grant/release 均回到基线。
内核、探针、libc、构建驱动、源码与验证器身份保留在报告中。

```sh
python3 tools/build_sysroot.py probes --probe timerfd-probe
python3 tools/verify_timerfd.py \
  --elf artifacts/cosmic-timer-r2/cyxia-kernel.elf \
  --output artifacts/timerfd-new-run --iterations 3
```

验收工具拒绝覆盖已存在的 summary。首轮 r0 实际通过 65 项，但验证器误设
70 项下限而判失败；原报告保留。r1 增加真实溢出及 oneshot 检查后，以确切
73 项和更严格的退出状态重新验收。随后 Clippy 的 checked_div 改写产生新的
r2 内核，专项及桌面回归均在 r2 重新执行，不将旧报告改为成功。

接口语义参考 [Linux timerfd 手册](https://man7.org/linux/man-pages/man2/timerfd_create.2.html)；
上述边界是 CyxiaOS 当前实现的明确子集。
