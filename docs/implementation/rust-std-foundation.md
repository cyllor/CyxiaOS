# Rust 标准库基础移植

本阶段使用官方 Rust 1.95.0 的 `aarch64-unknown-linux-musl` 标准库，在 CyxiaOS 的 ARM64 EL0 上执行真实 `std` 程序。它为后续 COSMIC 移植建立基础；不是 `no_std` 替代实现，也不表示完整 Rust 标准库、Tokio、calloop 或 COSMIC 已可运行。

## 构建与身份

`tools/build_rust_std_probe.py` 直接调用目标 `rustc`，不运行 Cargo 的宿主 `build.rs`，不把 macOS 库链接进客体。采用：

- 官方 `aarch64-unknown-linux-musl` target 的 `libstd`，`panic=abort`。
- 现有 `aarch64-linux-musl-cc` 包装器及固定的 musl 1.2.6 CRT、libc、AArch64 compiler-rt。
- `link-self-contained=no`；仅从官方目标复制 `libunwind.a` 到隔离搜索目录，避免其自带 libc/CRT 抢先被链接。
- 静态 `ET_EXEC`、`0x01000000` 映像基址、4 KiB 页、独立代码页；仍受现有 ELF 装载器的 W^X、地址空间与容量检查。

输出位于 `artifacts/sysroot/aarch64-musl/`：`rust-std-probe.elf`、带符号 ELF、链接日志以及 `rust-std-probe-build-report.json`。报告记录完整 rustc 版本、命令、源文件、libstd、libunwind、libc 和包装器摘要。交叉构建报告中的 `guest_execution=not performed` 不能代替来宾运行验收。

## 已实现的机制与边界

| 接口 | 本阶段实际行为 | 显式边界 |
|---|---|---|
| `sigaltstack` 132 | 每线程注册、查询、禁用真实用户内存范围；最小 6144 字节；查询真实 `SS_ONSTACK` 状态；当前已在备用栈时禁止更改 | 不支持 `SS_AUTODISARM`；注册及恢复要求完整范围当前可写 |
| `SA_ONSTACK` | 用户处理函数与嵌套帧实际进入备用栈，校验帧不会越过栈底；sigreturn 验证并恢复 `uc_stack` | 保留最多四层信号帧；不支持 SVE/SME、siglongjmp 和作业控制 |
| `SA_RESTART` | 仅对 `SIG_DFL` / `SIG_IGN` 保留此标志；这两种 disposition 不存在返回的用户处理函数，因此没有重启义务 | 普通用户处理函数仍拒绝 `SA_RESTART`，返回 `EINVAL`，不谎称自动重启阻塞 syscall |
| `MAP_STACK` | Linux 的已知兼容提示；继续经过真实匿名页 AI 准入，并由 `mprotect(PROT_NONE)` 建立保护页 | 不增加可执行堆、共享映射、文件映射、动态栈增长或 `MAP_FIXED` 支持 |
| futex `WAIT_BITSET` / `WAKE_BITSET` | 私有/当前进程地址空间内按位集选择唤醒；非零位集验证；`WAIT_BITSET` 使用绝对 `CLOCK_MONOTONIC` 截止时间 | 不支持 `FUTEX_CLOCK_REALTIME`、跨进程共享 futex、PI futex、robust-list |
| futex 超时 | 绝对纳秒时间向上取整为调度毫秒；相对 WAIT 的起点向上取整，避免提前超时 | 调度和量化可能使完成稍晚，不保证实时调度 |
| `clock_nanosleep` 115 / `nanosleep` 101 | `CLOCK_REALTIME` / `CLOCK_MONOTONIC` 相对睡眠；MONOTONIC 绝对睡眠；保存精确纳秒截止时间，阻塞等待，EINTR 返回实际剩余时间；绝对模式忽略 remaining 指针 | REALTIME 绝对截止依赖 RTC 改时追踪，当前明确 `ENOSYS`；未知 flags/clock 拒绝 |
| `getrandom(GRND_NONBLOCK)` | 引导时提交真实 VirtIO RNG 请求；读取时只轮询一次，消费已完成数据；可返回短读；已消费字节清除、不会重发 | 无设备 `ENODEV`；尚无数据 `EAGAIN`；设备/队列失败 `EIO`；单次最多 256 字节 |

普通 `getrandom(0)` 保留有限期的真实设备读取：一次完整读取最多等待 250 ms，失败不发布半填充结果。缓存与阻塞调用共用同一消费状态；缓存不会被另一读者重放。预取没有忙等循环，IRQ 不访问缓存。

`GRND_INSECURE` 仍返回 `EINVAL`。本实现只有有限的真实熵缓存，没有一个能够在空池时立即生成字节的 CSPRNG，因此不能把 `GRND_INSECURE` 加 `EAGAIN` 宣称为 Linux 兼容行为。官方 Rust 的 HashMap 初始化会在 `EINVAL` 后尝试 `GRND_NONBLOCK`；正常预取完成后本探针验证这条真实路径。若该时刻设备数据仍未就绪，Rust 会尝试 `/dev/urandom`，当前没有该字符设备，HashMap 初始化仍可能失败。此限制必须保留，不能用固定种子或重用熵遮盖。

## AI 资源路径

本阶段没有给 Rust 独立的旁路资源池。实际线程仍经过上下文准入模型 8193，匿名堆、pthread 栈和 Rust 备用栈的 mmap 经过模型 8194，ELF 与初始栈经过模型 8195；进程/线程排序及时间片仍使用 12289 / 12290。已有执行与授予/回收统计继续记录这些真实动作。

`sigaltstack` 注册的是已拥有的用户内存，futex 和睡眠管理的是已准入线程的等待状态；它们不是第二次内存授权。信号帧复制、位集匹配、时钟期限和随机字节不能由 AI 任意改写。硬件 RNG 是熵机制，AI 模型不是随机数来源。线程固定上下文仍有 4 KiB 编译期大小断言。

## 验证

源探针 `user/ported/rust_std_probe.rs` 检查：

1. 真正进入标准库 `main`，Vec 分配与运算、argv、HashMap。
2. Rust 自身已注册备用栈；两层嵌套处理函数的局部变量位于实际备用栈；栈内更改返回 EPERM；小栈、未知 flags 被拒绝；普通栈处理函数成功禁用后，sigreturn 正确恢复原 `uc_stack`。
3. `std::fs` 创建、写入、metadata、重命名、读回和删除。
4. 两个真实 pthread 的 Rust TLS、Barrier、Mutex、Condvar、join 结果与主线程 TLS 隔离。
5. Condvar 超时与 `thread::sleep` 没有提前完成。
6. 非匹配 futex 位集不会唤醒、匹配位集唤醒真实阻塞线程，零位集和已过期绝对期限返回准确错误。
7. 真实 SIGUSR2 中断 100 ms `clock_nanosleep`，返回 EINTR 与剩余时间；重试后总耗时满足原请求；绝对截止与已过期截止行为正确。

`tools/verify_rust_std.py` 校验当前探针完整字节确实嵌入固定内核、构建摘要对应、各阶段与真实退出码。默认在同一 VM 重复执行两次，核查线程峰值、四次真实线程准入、AI 模型来源、真实派发关系与全部进程/线程/堆/映像资源回收。未知 syscall 日志作为事实保留在报告，不自动等同于失败或成功。

```sh
rustup target add aarch64-unknown-linux-musl
python3 tools/build_rust_std_probe.py
cargo test -p cyxia-posix -p cyxia-driver-virtio
python3 tools/verify_rust_std.py --elf <固定内核ELF> --output <报告目录>
```

本轮主机测试 `artifacts/rust-std-host-tests.txt`：VirtIO 驱动 39 项、POSIX 单元 92 项、Unix socket 集成 17 项通过。随机数模拟器验证未完成时立即返回、短读消费与擦除、阻塞/非阻塞交替没有重放、超时不发布数据。信号单元测试覆盖备用栈边界、嵌套帧地址、无效 flags/范围和 ucontext 格式。

历史候选 `artifacts/cosmic-bootstrap-r2/cyxia-kernel.elf`（`f55d6c0d32adf7277f8d4b54ff2babdb3135610aa00d16e300b006ed14700205`）已实际通过启动、HashMap、备用栈、文件与线程同步阶段；随后缺少 syscall 115 导致真实标准库 panic/退出 134。其 `rust-std/summary.json` 保留 FAIL，不能作为全套通过证据。后续完整固定映像的结果必须单独记录。

2026-10-18 固定 r3 候选 `artifacts/cosmic-bootstrap-r3/cyxia-kernel.elf`，SHA256 `0d31c3fcb2668b67b31a9e1388c62579f32025aefc47babbb121560c595e2b5d`，完成完整八阶段两轮验收，报告为 `artifacts/cosmic-bootstrap-r3/rust-std/summary.json`。嵌入探针 SHA256 为 `7aa8359308a7255e50ce152ad233828a5c79ada022006d2c4103748e3b9d8176`。两轮均真实退出 0，没有 unsupported-syscall 日志；每轮四次额外线程准入、线程峰值三、零存活线程，`free_pages=64`、`heap_free=4096`、`image_free=4096`，全部已用堆/映像页为零。两轮分别实际执行 2201 / 2200 次 syscall、5 / 15 次抢占，进程与线程 AI 派发计数一致。此证据仅适用于该固定映像与上述明确范围。

## 尚未覆盖

没有验证完整 `std::process::Command`、fork/exec、动态链接、panic unwind、网络栈、所有文件 API、共享 mmap/memfd、SCM_RIGHTS、跨进程 futex。默认 Rust 线程栈可大于当前有界资源预算，探针明确请求 128 KiB 栈。

后续 [ET epoll](epoll-edge.md)、[timerfd](timerfd.md)、[真实 Mio](rust-reactor.md) 和 [Wayland 共享缓冲](wayland-shm.md) 已取得各自子集的客体证据；本页标准库门禁未覆盖的共享对象由这些专项记录说明。Tokio/calloop 与完整 COSMIC 合成器仍需单独集成验收，不能用标准库探针或 Mio 子集代替。

上游依据：[官方 ARM64 musl target](https://doc.rust-lang.org/rustc/platform-support/aarch64-unknown-linux-musl.html)、[Rust 1.95 备用信号栈](https://raw.githubusercontent.com/rust-lang/rust/1.95.0/library/std/src/sys/pal/unix/stack_overflow.rs)、[Rust futex](https://raw.githubusercontent.com/rust-lang/rust/1.95.0/library/std/src/sys/pal/unix/futex.rs)、[Rust 随机数路径](https://raw.githubusercontent.com/rust-lang/rust/1.95.0/library/std/src/sys/random/linux.rs)。
