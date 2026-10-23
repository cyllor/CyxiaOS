# 跨进程打开文件描述

2026-10-18。COSMIC 计划 P2 的对象基础已在单核 ARM64 来宾通过验证。冻结镜像为 `artifacts/cosmic-objects-r2/cyxia-kernel.elf`，SHA256 `0a7dceb4460ed9555dd81ed72042ee8997a0477565e3667c0e8056bd8f1789cb`；[联合报告](../../artifacts/cosmic-objects-r2/summary.json) 绑定源码和 12 组客体门禁。本记录对应此冻结版本，后续 SCM_RIGHTS、共享页和容量扩展分别验收。

每进程 FD 表现在引用全局、带代际的 OFD。文件偏移、状态标志、eventfd 计数和 epoll 实例按 OFD 共享，CLOEXEC 仍是每个 FD 独有属性。dup、显式 native spawn 的 FD 映射及创建者退出均维护引用；最后引用消失后才释放 inode、socket、pipe、PTY 后端及弱 epoll watch。后端访问身份与当前调用者 PID 分开，因此继承后的 SO_PEERCRED 仍记录真正连接/监听的进程。

本阶段仍有 128 个全局 OFD、16 FD/进程、16 个全局 epoll，每创建者最多 2 个实例、每实例 16 watch。固定元数据是启动预留；没有扩大模型输入域，也未宣称完成 COSMIC 会话容量。CPU0 前台串行访问，尚未实现多核同步。

阻塞读写重放前检查 FD 对应的 OFD 代际。另一线程关闭或改绑该 FD 时返回 `EBADF`，同一 OFD 的别名保持身份有效。此处只防止重试访问替换对象，尚不是 Linux 在执行中的系统调用持有旧 OFD 强引用的完整语义。

`fd-share-probe` 在三个独立启动中各执行 14 个阶段：共享文件偏移/标志、unlink 后存活、eventfd、epoll、socket、peer credentials、创建者退出、失败映射回滚，以及 pipe/eventfd/PTY 各自的阻塞读写 FD 复用。后六项由观察器确认内核等待次数增加后才开放替换门禁，避免以固定睡眠推断已阻塞；新对象的数据必须保持未被错误读写。每轮最终 OFD、引用、epoll 和 watch 均归零。

其余门禁覆盖原有 Rust 标准库、Wayland、xkbcommon、线程、spawn/GLib、PTY、真实桌面终端、AI 联合状态、精确图形及存储恢复。119 项 POSIX 主机测试及主机/ARM Clippy `-D warnings` 通过。最初探针对 PTY 短写的错误假设、串口提示符解析和异步快照采集失败均保留在旧报告；最终验证使用完整 `AI_SYSTEM_END` 快照。

运行冻结镜像的探针门禁（要求当前 sysroot 探针与镜像相同，工具会校验完整 ELF 和源哈希）：

```sh
python3 tools/verify_fd_share.py \
  --elf artifacts/cosmic-objects-r2/cyxia-kernel.elf \
  --output artifacts/ofd-manual-check --iterations 3
```

该结果不代表 SCM_RIGHTS、memfd、MAP_SHARED、完整 POSIX 或 COSMIC 已完成。
