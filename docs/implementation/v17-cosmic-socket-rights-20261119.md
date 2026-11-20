# COSMIC GetFd 的 Socket 引用与循环回收

后续已补齐当前 panel 启动的按需分配和错误所有权路径，正常会话原 panel 持续
存活 90 秒。最新结果见 [panel 连接与失败所有权](v17-cosmic-panel-allocation-20261120.md)；
本文保留此前 Socket 缺口修复及当时的会话状态。

真实 notifications 模块的完整 `GetFd` / applet action 回归已从 `ENOSYS` 转为
六项 PASS。本轮补齐 Socket 的 SCM_RIGHTS 传递、跨进程身份及最终引用回收，
包含 Socket 引用环。正常 COSMIC 会话仍有 panel 退出和缺失应用，完整会话、
语义首帧及完整 OS 验证均保持 false。

## 从原始失败到最小回归

在上一版正常组件镜像上重新运行完整协议，前四项认证/取消检查通过，随后得到：

```text
NOTIFICATIONS_PEER_PROBE FAIL org.freedesktop.DBus.Error.Failed: I/O error: Function not implemented (os error 38)
```

证据为 `artifacts/v017-socket-rights-notifications-red-v1`。最小真实 musl C 回归
只保留两个 `socketpair`、传递一个已连接端点和一次接收；同一路径立即返回：

```text
SOCKET_RIGHTS_PROBE FAIL send-connected-socket errno=38
```

证据为 `artifacts/v017-socket-rights-red-v1`。宿主回归直接调用真实 POSIX OFD
和 UnixSockets 实现，也报 `connected sockets must support SCM_RIGHTS: Nosys`；
相同控制头布局传递 eventfd 则成功，排除了 cmsghdr 布局和接收 flags。

根因是 `Process::validate_rights` 的支持类型未包含 `Object::Socket`。但仅放开
类型检查不足以完成修复：最小引用环测试在这个中间状态仍失败，弱 epoll watch
存在时，最后一个真实 FD 关闭后回收消息数为 0，预期为 1。该红色回归保留在
`artifacts/debug/cosmic-socket-rights-20261119/whitelist-only-cycle-red.log`。

## 修复的所有权边界

`crates/posix/src/ancillary/socket.rs` 提供有界的回收操作，内核在一次 Unix pool
借用内完成 Socket 释放，再在借用结束后处理 Pipe/Pty/Memfd 等其他后端的释放。
关闭、shutdown、取消发送和控制数据截断均使用相同的最终引用路径，回调只收集
待处理 ticket，不再从关闭回调重入 Socket pool。

回收器使用固定大小工作队列和可达性扫描：

- 真实 FD、继承映射和尚未提交的 staged 引用为根；epoll watch 为弱引用。
- 已提交消息从其接收队列的所有者指向传递的 OFD；accept 前的队列归 listener。
- 逐步标记可达对象，先从所有不可达队列移除 ticket，再按原最终释放路径处理。
  这同时覆盖自身引用、相互引用、跨队列链和经排队 listener 保活的连接。
- 消息与 OFD generation 均经验证；Socket 释放采用迭代工作队列，不沿引用链递归。
- 每条被回收消息单独发布释放 receipt，保留事件次数、引用单位及取消状态。

没有增加产品配额：core profile 仍为每进程 64 FD、全局 256 OFD、64 个 Unix
端点/32 条连接，以及 16 条 ancillary 消息/64 个排队引用。旧配置仍使用原边界。
宿主 fixture 的较大线程栈仅容纳测试中的完整池值，没有改变内核栈或产品限额。

## 客体与宿主回归

所有以下客体检查使用同一 release 镜像：

```text
artifacts/v017-os-socket-rights-v2/boot.bin
SHA-256 8258463b82ecd66d28b82cf14a20661bc52a410c636cbe5880b209a20338ca76
```

新目录 `artifacts/v017-socket-rights-catalog-v2` 仅在已验证组件目录上添加两个
真实 musl 回归 ELF，所有原组件和数据的字节保持相同。目录输入共 130,412,820
字节，仍在原 core-v1 的 128 MiB 上限内；notifications/panel 的真实完整构建及
GUI/a11y/X11 特性均沿用，未以替代服务通过检查。

| 已执行检查 | 实际结果与目录 |
| --- | --- |
| 真实 notifications 模块：延迟握手、取消、认证超时、EOF、GetFd、action | 六项 PASS，16.875 秒；`v017-socket-rights-notifications-v3` |
| Socket SCM_RIGHTS：传递后关闭、双向 IO、最终 EOF、创建者退出、弱 watch、自身/交叉/有根环、shutdown 链、截断、失败发送 | 十项 PASS，3.494 秒；`v017-socket-rights-reclamation-v3` |
| 原有 SCM_RIGHTS 的十项兼容检查，含 FD 容量、背压、短写和未接收释放 | 十项 PASS，0.758 秒；`v017-socket-rights-compatibility-v4` |
| SA_RESTART/EINTR 的真实 musl 回归 | 十项 PASS，2.551 秒；`v017-socket-rights-signals-v2` |
| 四种 locale 的真实 xkbcommon Compose | 四项 PASS，0.690 秒；`v017-socket-rights-compose-v2` |
| POSIX `cosmic-session` 全套 | 288 项 PASS，含九项 Socket 所有权/回收回归 |
| 原默认配置的 Socket 回归 | 九项 PASS，未启用 full-os |
| 目录准入、首帧判定、OS 构建和串口失败边界 | 21 项 PASS |

Socket 客体运行 96 轮交叉引用环后，`ai system` 的 OFD、FD/staged/inflight
引用、排队消息、epoll 与 watch 均恢复为 0，OFD 容量保持 256。真实内核账本
记录消息授予/释放各 202 次、引用授予/释放各 202 次，引用单位为 203/203，
另有一次取消。兼容回归的消息事件为 26/26、引用单位为 32/32，同样全部归零。
这些断言由客体输出验证，避免仅凭进程退出或未耗尽对象池推断已回收。

兼容回归还暴露了独立的宿主判定错误：`Console.pump` 将成功阶段
`SCM_PROBE FAILURE_ATOMICITY PASS` 误识别为 `_PROBE FAIL`。现改为要求 FAIL
后的实际分隔符；新增三项回归覆盖成功词、跨 UART 分段前缀和真正失败标记。
真正的 FAIL、RESULT FAIL 及内核 panic 仍被拒绝。旧失败捕获保留，没有重写。

重复执行须使用新的输出目录：

```sh
python3 tools/os_notifications_peer_probe.py --scope full --build artifacts/v017-os-socket-rights-v2 --output artifacts/socket-rights-notifications-recheck
python3 tools/os_socket_rights_probe.py --build artifacts/v017-os-socket-rights-v2 --output artifacts/socket-rights-reclamation-recheck
python3 tools/os_scm_probe.py --build artifacts/v017-os-socket-rights-v2 --output artifacts/socket-rights-compatibility-recheck
RUST_MIN_STACK=33554432 cargo test --locked --offline -p cyxia-posix --features cosmic-session
cargo test --locked --offline -p cyxia-posix --no-default-features --test socket_rights
```

宿主完整套件使用 `RUST_MIN_STACK=33554432`；上述 native 构建与 QEMU 均由
`native_session` 的全局互斥锁串行运行。完整宿主日志在
`artifacts/debug/cosmic-socket-rights-20261119`。

## 正常会话与剩余缺口

`artifacts/v017-socket-rights-cosmic-session-v2` 沿正常 session 入口运行，公共
`org.freedesktop.Notifications` 名称在 47.500 秒的真实总线查询中存在。
45.016 秒画面检查剩余启动色条匹配像素为 58/786,432，必要的替换检查 PASS；
90.030 秒画面哈希相同。实际查看截图仍只有深色背景和指针。

Panel PID 6、9 再次以 134 退出；第一次通知点对点初始化记录 Broken pipe，
完整 core 存活判定仍 FAIL。此前独立追踪已确认 panel 在 64/64 FD 时复制
Wayland client FD 遇到 EMFILE，该缺口尚未修复。本轮没有把正常 P2P 初始化、
公共总线注册或像素替换混同为完整通知交互成功；正向 GetFd/action 证据来自
同一真实模块的隔离客体回归。

下一项是 panel 分配与真实 applet/desktop 元数据供给，以及 session 中缺失的
app-library、launcher、workspaces、osd、osk、bg、greeter、files-applet、idle。
完整默认配置中的 18 个 applet 项保持保留；应先解析有效启动项再分配连接并处理
真实失败，再逐个接入真实程序。后续仍需独立验收面板内容、交互通知、输入和
整个会话的退出回收。

汇总及输入/输出 SHA 为 `artifacts/v017-cosmic-socket-rights-evidence-v2.json`。
临时 C 扩展脚本移入明确的 debug 目录，没有新增或遗留 Socket 调试日志。
