# 有界 SCM_RIGHTS 与跨进程 FD 传递

2026-10-18。首批 SCM_RIGHTS 已运行在 CyxiaOS 的 Linux AArch64 personality 中，使用全局 OFD 的实际强引用。普通 RAMFS 文件、只读启动资产、eventfd、pipe 和 memfd 可传递；socket、epoll、PTY 和目录明确返回 `ENOSYS`，尚无 socket 引用环回收。

固定元数据容纳 16 条消息、64 个在途引用，每条最多 8 个 FD。创建消息先完整验证控制头、源 FD 和所有 iovec，再用本地 8193 模型分别决定消息和引用占用。固定存储属于启动预留，模型只决定逻辑占用，不把元数据引用冒充新分配的物理页。账本区分数字 FD、staged 与 inflight 引用，记录准入、提交、取消及释放；清理不等待模型。

权利记录绑定流的逻辑字节位置。正数短写只附带一次引用，短读不会重复安装 FD；接收停在附属数据区间的末尾。接收控制缓冲或 FD 表不足时，安装可容纳的前缀、丢弃其余引用并设置 `MSG_CTRUNC`，数据读取仍成功。`MSG_CMSG_CLOEXEC` 原子设置新 FD 的私有属性。所有输出地址先验证，地址错误不消费消息。普通 read/readv 和没有控制缓冲的 recvmsg 消费附属数据时也释放相应引用。

close、SHUT_RD、未 accept 连接取消和进程退出都处理未接收的引用。SHUT_WR 或发送者退出不销毁已经提交给对端的消息。普通文件的 inode unpin 与弱 epoll watch 清理统一发生在 OFD 的最终引用释放时，因此发送者关闭最后一个 FD 后，在途消息仍保活文件和对应 watch。

当前发送边界：带 FD 的 sendmsg 只尝试一次提交，即使 socket 设置为阻塞也不进入内核等待；字节环满返回 `EAGAIN`，消息/引用队列或模型拒绝返回 `ENOBUFS`。这是明确的兼容性限制。支持阻塞附属数据发送时，必须将 staged ticket 保留在线程等待状态，并覆盖信号、取消及退出路径；不能重放控制缓冲里的 FD 数字而误传其他线程新打开的对象。`MSG_PEEK` 等未实现标志明确失败。

[SCM 客体探针](../../user/ported/scm_probe.c) 覆盖创建者退出、只读资产与 pipe/eventfd、重复引用和弱 watch、流边界、错误原子性、控制截断、FD 表耗尽、队列背压、正数短写、满环阻塞发送限制及无人接收关闭。每次运行由 [验证工具](../../tools/verify_shared_objects.py) 校验实际嵌入的 ELF/源码身份，等待完整系统快照，核对最终对象与 AI 额度守恒。

当前三次独立启动证据：[SCM](../../artifacts/cosmic-shared-r1/scm/summary.json)、[memfd/MAP_SHARED](../../artifacts/cosmic-shared-r1/memfd/summary.json)。这是 syscall 与对象基础，不代表完整 POSIX 或 COSMIC 会话完成。真实 wl_shm 协议验收单独记录。
