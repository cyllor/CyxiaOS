# 有界边沿触发 epoll

2026-10-20：在既有 OFD 与单核 AArch64 执行模型中实现 `EPOLLET`，
覆盖 eventfd、CLOCK_MONOTONIC timerfd、Unix stream、pipe 和 PTY。
[epoll 实现](../../crates/posix/src/epoll.rs) 将已提交的后端通知记录到
watch，而不只比较两次 `epoll_wait` 看到的电平。因此在两次等待之间发生的
“读空后重新写入”，以及 Mio Waker 不读取 eventfd 时的连续写入，都能产生新事件。

每个 watch 保存当前兴趣范围内的就绪位及一个 pending 位。后端在正长度
写入、读取释放容量、连接、关闭、shutdown 或终端记录完成时记录通知；
内核包装器在操作结束后发布给全部关联 watch，再清除后端通知。
失败调用不产生成功通知，部分写入已提交的前缀仍保留通知。
canonical PTY 的未完成新行不会因已有旧行可读而伪造新 IN；
完成新行与无字节 VEOF 记录会通知。timerfd 的过去绝对期限重设成功后
显式发布可读通知，包括上一次到期尚未读取的情况。

取事件时重新检查当前就绪状态，已被消费且不再就绪的候选不返回。
每次先观察全部 watch，再根据 `maxevents` 返回；未返回的候选保持 pending，
轮转游标防止总是返回首个 watch。`EPOLLONESHOT` 在成功返回后解除武装，
`MOD` 更新用户数据并重新检查已经就绪的对象。level 模式仍重复返回就绪状态。

watch 通过带代次的弱 OFD 身份关联对象。关闭原数字 FD 后，dup 或 native spawn
仍持有的同一对象可以继续触发旧 watch；复用该数字 FD 的新对象不会。
最后一个引用关闭时自动移除 watch。每进程最多 16 FD、2 个 epoll，
每个 epoll 最多 16 watch，全局最多 128 OFD、16 个 epoll。
新增状态都在已有有界元数据中，不分配事件堆、后台线程或新的内存额度。

2026-10-22 增加 epoll FD 自身的 `poll/ppoll` 可读性。它使用与
`epoll_wait` 相同的真实后端就绪检查，但仅观察可交付的候选，不消费事件、
移动轮转游标或解除 ONESHOT 武装。重复观察仍返回 `POLLIN`，直到实际
`epoll_wait` 取走边沿或后端数据被其他操作消费；过期候选不会伪造可读。
timerfd 期限到达能够唤醒真实阻塞的 poll。该功能不允许将 epoll 注册到
另一个 epoll，嵌套 epoll 仍明确不支持。

本地模型继续决定实际进程、资源准入和 CPU 排序；通知时机、用户请求的期限、
错误原子性及对象代次由确定性机制保证。Unix/pipe/PTY 的固定池准入有真实
AI 决策，但不应将其零页 grant 计数描述为动态页分配。该 C 探针不申请匿名堆页，
因此退出后的 `heap_model=0` 正常，不能伪称运行了匿名内存模型。

## connected Unix send

AArch64 `sendto(206)` 接入已连接的 Unix stream，支持 `MSG_DONTWAIT` 与
`MSG_NOSIGNAL`。检查完整用户缓冲区范围后，每次最多复制并发送 1024 字节。
即使 FD 本身阻塞，DONTWAIT 在满队列时也返回 EAGAIN。无 NOSIGNAL 的 EPIPE
按真实信号路径递送 SIGPIPE；带 NOSIGNAL 则只返回 EPIPE。
不支持的消息标志或非空目标地址明确返回 ENOSYS，不假装具备 datagram 能力。

未命名的已连接 Unix stream 在 `recvmsg` 收到非空 `msg_name` 缓冲区时，
返回真实载荷并将 `msg_namelen` 设为 0，不写入地址缓冲区。因为没有地址
字节要复制，零字节地址输出不访问该用户地址；iovec、控制消息和头部仍
经过各自真实验证。这允许上游 Rust Unix stream 接收路径使用通用地址结构，
不意味着实现了有名字的对端地址或 datagram 接收。

## 验证与边界

[ARM 探针](../../user/ported/edge_probe.c) 包含 168 项父进程检查和真实 native
子进程的一项共享对象检查。父进程总数不重复计算子进程计数。
覆盖重复 eventfd 写入、兴趣过滤、消费后的过期通知、ONESHOT/MOD、Unix
部分读取与再次写入、RDHUP/HUP/EOF、pipe 容量释放/ERR、canonical PTY/VEOF、
maxevents 公平性、dup/spawn/FD 复用及三次相对/过去绝对 timerfd 重设。
send 检查包含非法标志/目标/指针/FD、零字节发送、满队列、实际数据和
SIGPIPE 发送/抑制。输出显式关闭 stdio 缓冲，保证跨父子进程阶段顺序可核对。
新增检查覆盖 epoll FD 的空/就绪状态、三次重复观察不消费 ONESHOT、
MOD 重武装、已消费数据消除过期通知、level 模式重复可读，以及 timerfd
唤醒阻塞 poll；Unix 接收同时检查无名字地址输出和原地址缓冲内容保持不变。

[验收工具](../../tools/verify_edge.py) 每次启动新 QEMU，要求精确顺序的九个
标记、确切检查数、子进程再父进程的实际正常退出、所有保留进程记录无故障，
并验证 OFD/watch、共享对象、ancillary 引用及 AI grant/release 回到基线。
它重新解析探针 ELF 布局，验证它只在内核只读 load 段出现一次，绑定源码、
libc、驱动、118 项内核构建输入和自身依赖，并在完成后复查未变。
任何已有输出目录都拒绝覆盖；失败日志保持原样。

```sh
python3 tools/verify_edge.py \
  --elf artifacts/cosmic-foundation-r5/cyxia-kernel.elf \
  --output artifacts/edge-new-run --iterations 3
python3 -m unittest discover -s tests/host -p test_edge_verification.py
```

五项 host 验收器测试拒绝缺失/重复/失败/重排标记、错误计数、故障退出、
错误进程顺序、未回收对象、伪造 AI 或不守恒 grant，以及覆盖既有证据。
2026-10-22 的 [r5 来宾回归](../../artifacts/cosmic-foundation-r5/edge/summary.json)
在三个独立 ARM64 启动中分别通过准确的 168 项父进程检查，包含新的
`POLL_EPOLL` 阶段；九个阶段/最终标记、真实子进程检查和正常退出顺序均通过。
OFD、watch、共享对象、在途引用及 AI 额度全部回到基线。
冻结内核 SHA256 为
`a423d4feb8080d6384bc4a798a6aef0469c9fca47fbe9f19cfadba5b435153ef`，
探针 SHA256 为
`d7a7a5e6c22bc5dfcbb946f5defe504ae4960f39d6617f6d591d31261c675f2b`。

以下历史记录保留原来的检查范围，不作为新接口的验收：
r2 首次实际运行已经通过 136 项，但验收器误判 stdio 缓冲导致的物理输出顺序；
同时修正了未申请匿名堆和固定池没有页 grant 的错误验收假设。
[原失败](../../artifacts/cosmic-reactor-r2/edge/summary.json) 与随后
[r2 三次通过记录](../../artifacts/cosmic-reactor-r2/edge-final/summary.json)
均保留。最终探针改为无缓冲输出后，在
[r3 内核上重新完成三次独立启动](../../artifacts/cosmic-reactor-r3/edge/summary.json)，
每次准确通过 136 项父进程检查，阶段与两次正常退出严格按时间顺序出现。
最终内核 SHA256 为
`45c4b52e96bc57cafce5433885e73ae3c9757a235d2c6d47a45171e408ef36c0`，
探针 SHA256 为
`6e7854bfad505768cb79bb24b9ab5492f3bdc6292b6f9fb6b9ee44751c40f358`。

当前不支持嵌套 epoll、EPOLLEXCLUSIVE、EPOLLWAKEUP、EPOLLPRI、
临时信号掩码、网络 socket 或 SMP 并发就绪发布。
timerfd 的新 ET 能力取代 [原 timerfd 阶段文档](timerfd.md) 中对应的
“edge epoll 不支持”限制；其他时钟、SCM_RIGHTS 传递等限制不因此改变。
该专项不等于完整 Linux 兼容，也不单独证明 Mio/Tokio/calloop 或 COSMIC
整体运行通过。上层真实库使用独立构建和运行证据。
