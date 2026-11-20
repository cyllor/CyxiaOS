# COSMIC notifications 的启动错位与 panel FD 耗尽

后续 Socket SCM_RIGHTS 及循环回收已补齐，完整真实模块的 GetFd/action 回归已通过。
最新状态见 [Socket 引用与循环回收](v17-cosmic-socket-rights-20261119.md)；本文保留
该修复之前的握手诊断、失败证据及仍未解决的 panel FD 缺口。

本轮沿用正常 `cosmic-session`、真实 notifications/panel ELF、原 45 秒像素门槛和
64 FD/进程边界。完整桌面与完整会话验证保持 false。以下分别记录已修复的启动
错位，以及继续推进后确认的两个独立缺口；握手通过不代表通知交互通过。

## 正常会话中的最小证据

`artifacts/v017-peer-session-boundary-debug-v2` 捕获了继承 socketpair 的实际 IO。
notifications 第一次配置 FD 位于启动后 37.396508 秒，在 38.606633 秒 shutdown；
panel 到 41.031124 秒才首次发送认证数据，随后收到 EOF。启动错位为 3.634616 秒，
服务端比首条认证数据提前 2.424491 秒关闭。原来的 1 秒期限在对端尚未开始时已耗尽。
这条连接是继承 FD 的点对点 D-Bus，区别于公共会话总线。

`artifacts/v017-panel-client-allocation-failure` 的首次相关失败为：

| 实际调用 | 实际结果 |
| --- | --- |
| PID 6，`fcntl(62, F_DUPFD_CLOEXEC, 0)` | `EMFILE` / 24 |
| 失败时打开的 FD | 64 / 64 |
| Rust panic 的返回地址 | `0x1cdc931` |
| 对应真实源代码 | `get_client_sock` 中 `DisplayHandle::insert_client(...).unwrap()` |

同一真实系统 Wayland server 库创建单个客户端、以及干净进程一次创建 18 个客户端
均通过。正常 panel 同时持有总线、reactor、配置监听和两侧 applet socket；这不是
单个 `wl_client_create` 的 ABI 错误。完整事件与输入 SHA 见
`artifacts/v017-cosmic-peer-gap-evidence-v1.json`。

## 版本化修复

`ports/cosmic/native-notifications-peer-v2` 在冻结 static-v2 导出之上仅修改两个
实际订阅模块，完整源码树和每个修改文件的 before/after SHA 均固定：

1. `setup_panel_conn` 先等待继承 socket 可读，再启动认证期限。
2. `Conns` 持有可取消的 `PanelTask`，点对点初始化与公共
   `org.freedesktop.Notifications` 注册独立进行；`Conns` 失败或销毁时取消任务。
3. 复制继承 FD 失败时返回真实错误，避免对该结果直接 unwrap。

v1 保留 1 秒主动认证期限，四项隔离回归通过，但正常会话仍未通过。没有附加总线
查询的定点时间线记录到双方完成了 19、37、26、15 字节的实际认证交换，服务端
第一次读取至 shutdown 相隔 0.988588 秒，最后一步前被自身期限截断。该时间线
用于区分协议阶段，含日志开销，不能作为性能基准。

v2 因此把服务端主动认证期限与**未修改的 panel 客户端既有 5 秒期限**对齐，
保留首条流量之前的独立等待及任务取消。没有改变首帧的 45 秒门槛、会话观察
上限、FD/内存/AI 限额或构建预算。v1 的源码、配方、构建和失败会话证据全部保留。

上游 commit、Cargo.toml/Cargo.lock、493 包解析图、GUI/a11y/X11 特性、SDK、
每进程资源限制和构建预算均沿用已验证 static-v2。新构建器重新做完整离线构建，
独立目录消费者重新验证源码、依赖、编译器、SDK、日志、真实链接输出和 FullOsV3
ELF 准入。v2 对已校验旧 target 做 APFS 写时复制，恢复已空出的临时构建路径，
只为字节未变的文件恢复原时间戳；复用同一已校验原生库搜索路径。修改的真实根包
必须重新编译，原缓存的完整树哈希前后相同。旧构建、配方和原始目录保持原样。

## 回归边界

`user/ported/notifications_peer_probe.rs` 直接包含实际 `applet.rs`，使用同一真实
zbus/Tokio/rustix 依赖。v1 使用 4 秒启动延迟；v2 延迟 8 秒，始终超过选定的
主动认证期限，不能通过单纯延长期限掩盖启动错位。另检查空闲 peer 的取消与
FD 回收、不完整认证必须在选定期限内失败，以及 peer EOF。

`tools/os_notifications_peer_probe.py --scope full` 继续调用真实 `GetFd` 并进行
applet action 往返。初次回放中延迟握手通过，`GetFd` 返回 `ENOSYS`：当前
`Process::validate_rights` 明确不允许 `Object::Socket` 经 SCM_RIGHTS 传递。
完整模式继续保持失败，不以握手模式替代它。

最终构建 `artifacts/v017-notifications-peer-build-v2` 的真实 ELF 为 29,898,520 字节，
SHA-256 `e1372fab00c388ec87a07cccb4365b747e83d3691946e2ff94cb0dd67b91cadf`。
构建总耗时 295.812 秒；原 target 输入树 SHA-256
`c994ef45cb352abcc2ad94e2b7d0130189a2588a49fadc1e2aa33582ef9390ca` 前后相同。
新目录为 130,321,324 字节，保持在已有 128 MiB core-v1 ROM 上限内。
最终镜像 `artifacts/v017-os-cosmic-peer-v2/boot.bin` 的 SHA-256 为
`45324f95892c8b596c9a2eb126884742a551048e8c11441d6e4bcc14e35177c8`。

| 已执行的客体回归 | 结果与证据目录 |
| --- | --- |
| 原版实际模块、正确 rustix 1.1.5 | FAIL：启动回放超时；`v017-notifications-peer-red-v3` |
| v1 的四项认证/取消检查 | PASS，但正常会话仍主动超时；`v017-cosmic-peer-handshake-v1`、`v017-cosmic-peer-session-v1` |
| v2 的 8 秒启动延迟、5 秒停滞认证、取消、EOF | 四项 PASS，15.889 秒；`v017-cosmic-peer-handshake-v2` |
| 同一 v2 镜像的完整真实 GetFd/action 流程 | 四项先通过，GetFd 返回 ENOSYS，完整模式 FAIL；`v017-cosmic-peer-full-v2` |

实际命令（保留原输出；再次执行须选新的输出目录）：

```sh
python3 tools/os_notifications_peer_probe.py --scope delay --build artifacts/v017-os-notifications-peer-red-v3 --output artifacts/v017-notifications-peer-red-v3
python3 tools/os_notifications_peer_probe.py --scope handshake --build artifacts/v017-os-cosmic-peer-v2 --output artifacts/v017-cosmic-peer-handshake-v2
python3 tools/os_notifications_peer_probe.py --scope full --build artifacts/v017-os-cosmic-peer-v2 --output artifacts/v017-cosmic-peer-full-v2
```

## 最终正常会话结果

`artifacts/v017-cosmic-peer-session-v2` 按正常 session 入口运行 90 秒，QEMU 正常
退出。真实 `dbus-send` 在 47.215 秒列出 `org.freedesktop.Notifications`；旧的
`Failed to setup panel dbus server deadline has elapsed` 为 0 次。此前正常
v1 会话仍报该错误，其失败证据未覆盖。

45.023 秒截图剩余启动色条匹配像素 58 / 786,432，必要的替换检查 PASS；
90.047 秒像素相同。实际查看无损截图仍只有深色背景和指针，没有可用面板或应用。
panel PID 6、9 两次以 134 退出，session 重启了配对进程，XDG/core 存活检查仍 FAIL。

正常会话默认日志没有正向 INFO 握手标记，故**不把错误缺席单独当作正常会话
P2P 交互成功**；认证阶段的正向断言来自同一真实模块的四项客体回归。
完整 GetFd/action 模式仍 FAIL。综合证据为
`artifacts/v017-cosmic-peer-final-evidence-v2.json`，其中正常会话 P2P 独立验证、
完整 OS、完整会话和语义首帧标记均保持 false。

同一最终镜像另通过 SA_RESTART/EINTR 十项真实 musl 回归（2.469 秒），
四种 locale 的真实 Compose 回归（0.636 秒）；目录/首帧判定/OS 构建边界的
18 项宿主检查也全部通过。

## 尚待补齐

- Socket FD 传递：需要同时处理跨进程 OFD 身份、排队引用、断连/退出回收与
  socket 引用环。当前 Unix close/shutdown 的释放回调在 socket pool 借用内执行，
  直接放开白名单还会引入递归借用问题；应先改为分离释放并补足回收回归。
- Panel FD：真实上游先为所有配置项创建客户端，再解析 desktop 文件。当前目录
  尚缺真实 applet 与 desktop 元数据；可在完整源码移植中先解析有效启动项、再
  分配连接，并正确处理分配失败。配置仍应保留全部 18 个项，不能删项掩盖缺口。
  仅提高内核 FD 上限也不够：当前 NativeChild 自身仍固定支持 64 个 FD。
- 正常会话的最终首帧、实际通知/输入、面板应用与资源回收仍须分别验收。

临时 `[DEBUG-peer9]`、`[DEBUG-peer10]` IO/栈/分配错误日志已从内核源码清理；
失败镜像与串口证据保留。
