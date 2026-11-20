# Cosmic：信号重启与完整 Compose 数据，2026-11-19

正常 session 的 SIGTERM 注册崩溃已解除；同一真实 musl 客体还验证了信号处理后
阻塞调用的重启与 EINTR 边界。补入完整 libX11 Compose 数据后，真实 xkbcommon
在四种 locale 名称下均输出正确组合字符。

正常会话已通过原有 45 秒启动色条替换诊断，画面为背景和指针。这不代表面板、
应用、通知协议或完整桌面验收通过。所有完整会话/语义帧标志继续为 false。
原 SDK、旧失败镜像和原始捕获均保留；本轮未提交或推送。

## 根因与可重复失败对照

此前真实 `cosmic-session` 启动通知和 panel 后，Tokio 的 SIGTERM 注册返回
EINVAL。内核实际使用的 `Action::decode_for` 对照测试将动作缩小到
`SA_SIGINFO | SA_RESTORER | SA_RESTART`；仅去掉 `SA_RESTART` 即可注册。
修复前该测试连续两次失败。

优先假设是未实现 restart 语义；另外两项是假设 restorer/frame 错误，以及
Tokio 事件源或资源不足。真实 musl 回归区分了这三种情况：

| 对照 | 真实结果 |
| --- | --- |
| `artifacts/v017-signal-restart-red-ready` | 注册失败，errno=22 |
| `artifacts/v017-signal-registration-only` | 注册通过，随后 read 失败，errno=4，handler 已调用一次 |
| `artifacts/v017-signal-restart-v1` | 10 项全部通过，2.413 秒 |
| `artifacts/v017-signal-restart-v2` | 最终 Compose 镜像上再次通过全部 10 项，2.430 秒 |

第二行是刻意保留的诊断中间状态，证明仅允许标志无法完成修复。

```sh
PATH=/Users/robin/.cargo/bin:$PATH cargo test --offline -p cyxia-posix --test x86_signal
python3 tools/os_signal_restart.py \
  --build artifacts/v017-os-cosmic-compose-v2 \
  --output artifacts/NEW-signal-restart-capture
```

原始失败的实际 guest 输出为：

```text
SIGNAL_RESTART_PROBE FAIL register-restart errno=22 calls=0 bad=0 worker=0
```

仅允许标志的对照则为：

```text
SIGNAL_RESTART_PROBE REGISTRATION PASS
SIGNAL_RESTART_PROBE FAIL read-restart errno=4 calls=1 bad=0 ...
```

## 实际修复与边界

`crates/posix/src/signal.rs` 按 ABI 判断 restart 资格。x86 返回型处理器允许
`SA_RESTART`；Arm 返回型处理器保留原拒绝行为，未知标志仍拒绝。

`Runner::wake` 对尚未完成、符合资格的等待保存可重放上下文。真正构造 handler
frame 时才读取最终 disposition，避免唤醒后动作改变的竞态。带 restart 的 frame
保留 SYSCALL 指令地址、号码和参数；其他 frame 恢复调用后 PC 和 EINTR。
`rt_sigreturn` 继续使用完整验证后的用户帧，允许已有的用户寄存器修改行为。

被时钟抢占但尚未执行重放 SYSCALL 的 x86 上下文保留原返回 PC，直到实际 syscall
或 fault 消费它。无处理器的普通 readiness replay 保留原 FD/OFD 弱绑定验证；
经过实际 handler 和 sigreturn 的重放执行新的 FD 查找。

真实 C/pthreads 回归覆盖注册、pipe read 重启、无 restart 的 read EINTR、poll
EINTR、nanosleep EINTR 与剩余时间、timerfd read 重启、无超时 futex 重启、
定时 futex EINTR、flock 重启、实际 Cyxia 子进程 waitpid 重启。处理器验证
siginfo、signal number 和 context；最终父子退出码均由 UART 实际观察。

分类依据核对了固定版本的
[Linux x86 信号处理](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/x86/kernel/signal.c)
和 [futex wait](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/futex/waitwake.c)：
定时 futex 的 restart-block 在捕获处理器后返回 EINTR；不能把所有等待统一重启。
本轮也未把 fsync、epoll、poll 或 nanosleep 归入 SA_RESTART。

## 完整 Compose 供给

原正常 session 捕获中 notifications 重复报：

```text
xkbcommon: ERROR: [XKB-679] couldn't find a Compose file for locale "en_US.UTF-8"
```

三项假设依次是镜像缺文件、映射/别名不完整、locale 环境不一致。目录检查确认
没有 Compose 数据。旧 v1 installer 绑定的历史 SDK 已不在本机，因此保留它，
新增 `tools/install_cosmic_locale_v2.py`，明确绑定本轮独立重建的 SDK。

新安装器校验 SDK 来源、X.Org 报告、固定 libX11 1.8.12 归档与来源记录，复制：

- `/usr/share/X11/locale/en_US.UTF-8/Compose`，456,142 字节；
- 完整 `compose.dir` 和 `locale.alias`；
- 完整多作者 libX11 `COPYING`。

总计 610,981 字节。生成表中的 5,145 条规则与固定上游 `Compose.pre` 逐条字节
相等，无额外 include。与旧生成文件的差异在注释中的构建路径，不改写规则。
安装器验证 UTF-8 映射和三个别名，保留原目录输入的全部字节和模式，原子发布
新目录。最终目录为 126,687,190 字节，仍在现有显式 core v1 的 128 MiB 内；
没有新增或放宽运行时预算。

```sh
python3 tools/install_cosmic_locale_v2.py \
  --base-build artifacts/v017-os-compose-probe-red \
  --output artifacts/NEW-compose-catalog
python3 tools/install_cosmic_locale_v2.py \
  --validate-prefix artifacts/v017-cosmic-compose-catalog-v2
```

`user/ported/compose_probe.c` 链接同一 SDK 的真实 `libxkbcommon.a`，通过实际 locale
加载接口读取 guest 文件，组合 `á`、`œ` 和 `^`，检查完整状态和 UTF-8 输出。
同一个探针的旧目录对照 `artifacts/v017-compose-probe-red` 稳定失败，实际文本
为原缺文件错误；新目录 `artifacts/v017-compose-probe-v2` 在 `en_US.UTF-8`、
`C.UTF-8`、`C.utf8`、`en_US.utf8` 下全部通过，用时 0.615 秒。

```sh
python3 tools/os_compose_probe.py \
  --build artifacts/v017-os-cosmic-compose-v2 \
  --output artifacts/NEW-compose-capture
```

## 运行证据与尚未完成的能力

最终镜像为 `artifacts/v017-os-cosmic-compose-v2`，boot SHA256：
`3dd944e8f14c55694153456f0bf081dc0d3e51c5f1afb925162557eb8160fa7a`。
来源与全部输入由其 build manifest 绑定；两个回归及正常 session 使用同一镜像。
所有真实构建与 QEMU 串行持有原 native lease，使用独立新磁盘并正常 QMP 退出。

第一轮已修复信号的正常会话记录为
`artifacts/v017-cosmic-signal-restart-runtime-v1`：45.007 秒门槛时，786,432 个像素中
仅 58 个仍等于启动色条，总线与五个核心进程的实际状态均已保存。
Compose 完整镜像的正常会话记录为 `artifacts/v017-cosmic-compose-runtime-v2`：
45.015 秒，同样只剩 58 个启动像素，串口中 SIGTERM 注册与 Compose 缺失错误均为
零，PID 1–6 均为 Running/Waiting、code=0，PID 3–6 的实际 parent 均为 session
PID 2。`startup-gap-evidence.json` 绑定原始 UART SHA 与同一镜像 SHA。

宿主 `cargo test --offline -p cyxia-posix` 全部通过，包括 210 项单元测试和所有
集成测试；新增 x86 signal 文件共 6 项。Compose 来源/安装校验、启动像素工具
3 项边界测试、kernel catalog 5 项边界测试、并行阶段回归和 OS 工具 6 项测试通过。

剩余已观察缺口包括 panel 的 `NoConfigDirectory`、settings 的 XDG state 路径，
以及九个缺失程序：app-library、launcher、workspaces、osd、osk、bg、greeter、
files-applet、idle。系统总线服务、真实通知交互、面板/应用内容、输入及整体退出
回收也仍需各自的 guest 验证。背景和指针通过必要的像素替换检查，不构成这些
能力的证明。
