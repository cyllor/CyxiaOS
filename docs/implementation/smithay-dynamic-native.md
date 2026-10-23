# Smithay 动态客户端接入与断开清理

日期：2026-10-22。本文记录独立工作包的设计与验收契约，实际结果在文末单列。

## 连接与身份

合成器在 CyxiaOS 客体内创建真实 Unix listener `/tmp/cyxia-wayland-0`，不派生客户端，也不以 `waitpid` 管理客户端。客户端通过串口 shell 分别启动，以 `XDG_RUNTIME_DIR=/tmp`、`WAYLAND_DISPLAY=cyxia-wayland-0` 调用上游 `wl_display_connect(NULL)`；连接前确认没有 `WAYLAND_SOCKET` 环境变量或继承的 fd 3。

`clients.rs` 提供两槽连接注册表。连接身份包含槽号、代次、递增连接 ID 与真实 Wayland `ClientId`，服务端同时记录实际 `SO_PEERCRED`。槽位复用不能让旧句柄指向新客户端；满额拒绝不消耗成功连接 ID 或代次。客户端参数只选择测试工作负载，不作为认证依据。当前 ABI 的 uid/gid 均为开发身份 0，不据此宣称多用户身份隔离。

新源位于 `ports/cosmic/smithay-dynamic/`，复用已有场景及原生显示模块，保留旧移动/缩放 profile。连接、协议、所有权和焦点处理属于确定性机制；进程、ELF、匿名/共享页、Unix 资源、CPU 和显示继续经过原有本地模型与执行账本，不改变模型、限额或学习能力。

## 生命周期

客户端 A 先连接并响应，B 随后加入。A/B 同时存活时，另一个独立探针尝试连接；服务端在注册表满额时关闭连接，探针只将实际 EOF 认定为拒绝，错误、超时或收到数据均失败。拒绝前后分别采集画面，证明已有窗口保持不变。

B 正常关闭后，C 复用空槽但取得新的代次和连接 ID。C 使用 `wl_display_disconnect` 后直接 `_exit`，保留活跃协议对象及共享映射，不发送正常的空缓冲提交或对象销毁请求。服务端依据真实断开和对象销毁回调移除窗口与焦点，之后 A 必须继续响应实际键盘事件并重绘。已断开的客户端不被要求接收不可达的 buffer release。

正常关闭的 A/B 则必须完成空缓冲提交、buffer release、对象销毁和最后一次同步。注册表清理必须晚于断开，不可在画面变黑时提前结束服务端。监听路径只在本次成功绑定后清理，最后验证关闭、unlink、同路径重新绑定及清理；启动时不无条件 unlink 现有路径。

## 十二个场景与额外拒绝观察

128×96 画布位于实际屏幕 `(32,48)`，黑色背景。A 为 `(8,8,64,48)`，B 为 `(40,24,64,48)`，C 为 `(48,16,64,48)`。所有健康检查使用真实 D 键；Q 触发正常关闭，X 触发 C 的异常断开。

| 场景 | 触发与画面 |
| --- | --- |
| 0 | listener 就绪，空画布；随后从 shell 启动 A |
| 1 | A 初始帧与焦点 |
| 2 | A 响应 D 后重绘；随后从 shell 启动 B |
| 3 | B 加入，位于 A 上方并持有焦点 |
| 4 | B 响应 D 后重绘；启动满额探针，实际 EOF 与进程退出后额外采集不变画面 |
| 5 | B 响应 Q 正常关闭，只剩 A，焦点回退 |
| 6 | A 再次响应 D；随后从 shell 启动 C |
| 7 | C 复用 B 的槽位，以新代次加入并持有焦点 |
| 8 | C 响应 D 后重绘 |
| 9 | C 响应 X，实际断开后只剩 A，焦点回退 |
| 10 | A 再次响应 D 后重绘 |
| 11 | A 响应 Q 正常关闭，空画布，全部连接清理 |

每次启动十二次渲染、十三张实际 scanout、159,744 个像素、十六次 QMP 输入命令、八个缓冲提交和七组配置确认。第十三张图是场景 4 拒绝后的额外观察，不另计渲染或 AI 显示提交。主机按独立公式重新计算像素，并绑定真实串口启动命令、进程身份、输入顺序与截图。

进程均由 shell 独立启动，`parent_pid=0`。进程槽可在退出后复用，因此在 B 退出后、C 启动前保存进程快照；最终进程列表不能替代完整生命周期记录。所有并发协议记录包含换行且不超过 64 字节，单次真实写入，不在主机拼补交错的日志。

## 构建与验证入口

服务端由 `tools/build_smithay_dynamic.py` 构建，客户端由 `tools/build_smithay_dynamic_client.py` 构建。内核 feature 为 `smithay-dynamic-probe`，`CYXIA_SMITHAY_DYNAMIC_PROBE_ELF` 和 `CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF` 指定实际产物。

该 profile 提供以下串口命令，由验证器按上述场景分别调用：

```text
posix exec smithay-dynamic-probe
posix exec smithay-dynamic-a
posix exec smithay-dynamic-b
posix exec smithay-dynamic-reject
posix exec smithay-dynamic-c
```

这是有界集成入口，不是可任意启动应用的 COSMIC 会话。本工作包只验证两槽、三个正常连接和一个满额探针，不覆盖任意数量客户端、通用布局、跨用户认证、完整会话恢复或 cosmic-comp。

## 当前验收状态

代码与验证器正在实现；构建及 ARM 客体验收结果尚未冻结。
