# Cosmic 面板默认配置与 state watch 根目录，2026-11-19

已补齐固定上游的完整面板默认配置，并在恢复后的启动阶段准备实际 config/state
目录。真实配置库回归和真实 inotify 回归均已通过；正常 session 中原有两类路径
错误均不再出现。面板已从此前单线程配置回退推进到 8 线程初始化。

完整桌面仍未通过。本轮第一次正常 session 的固定 45 秒扫描输出为部分替换，
首帧诊断保留 FAIL；后续还观察到 notifications/panel 的 D-Bus 握手超时。
这与已解除的目录错误分开记录，不能用路径检查通过替代完整会话验收。

## 原始失败与排除对照

```sh
python3 tools/os_cosmic_xdg_probe.py \
  --build artifacts/v017-os-cosmic-compose-v2 \
  --output artifacts/NEW-original-xdg-capture
```

实际运行的 `artifacts/v017-cosmic-xdg-baseline` 返回 FAIL，UART 包含：

```text
Panel Entry Error: NoConfigDirectory
Failed to watch xdg state dir: No path was found.
```

第二条会被 STORAGE 日志插入，因此检查器使用错误前缀判断，不能只匹配整句。
原像素诊断本次也失败，剩余 94,266 个启动色条像素；这个历史结果原样保留。

最初三项假设是子进程环境变化、目标配置库差异、文件系统目录创建失败。
直接启动的真实 Rust/dirs 探针可以读到 XDG 路径；普通 Cyxia spawn 后的 Rust
子进程读到 HOME=/，解析 config 为 `/.config`、state 为 `/.local/state`。
临时的 `[DEBUG-c9xdg]` 仅观察 settings/panel 的 HOME/XDG 参数，确认真实 session
确实传入 HOME=/；没有通过改环境或用户 HOME 位置来掩盖原问题。

进一步直接运行同一 panel ELF，日志明确显示：

```text
Using standard config dir: Some("/run/user/0/.config")
Panel Entry Error: NoConfigDirectory
```

因此面板错误不等于用户目录不存在。实际调用是：`Config::new` 成功，随后
`get::<Vec<String>>("entries")` 先找用户覆盖，再找系统默认；系统默认目录未进入
镜像时，同样返回 `NoConfigDirectory`。正确原因是缺系统默认数据。

## 秒级回归与单变量对照

`user/ported/panel_config_probe.rs` 使用真实已编译的 libcosmic 配置库，重放同一
创建/读取模式，不复制配置解析实现。其来源是保留的 compositor 构建 rlib，
libcosmic 提交 `d922ac380134c00208d2acf93947d44fb217eec5`；诊断链接脚本位于明确的
`artifacts/debug/cosmic-panel-xdg-20261119/prepare.py`。这不替代实际 panel。

```sh
python3 tools/os_cosmic_config_paths.py \
  --build artifacts/v017-os-panel-config-red --check panel \
  --output artifacts/NEW-panel-red
```

真实 guest 输出：

```text
PANEL_CONFIG_PROBE USER_DIRECTORY PASS
PANEL_CONFIG_PROBE FAIL NoConfigDirectory
```

`user/ported/session_env_probe.c` 让真正的 Rust 子进程验证实际继承环境，然后按
相同 HOME/state 路径执行 `inotify_add_watch`。另一个最小失败为：

```text
RUST_ENV_PROBE dirs_state=Some("/.local/state")
SESSION_ENV_PROBE FAIL state-watch errno=2 path=/.local/state/cosmic
```

| 镜像/捕获 | 面板默认配置回归 | state watch 回归 |
| --- | --- | --- |
| `v017-os-panel-config-red` | FAIL：用户路径成功，entries 缺默认数据 | FAIL：ENOENT |
| `v017-os-panel-defaults-v1` | PASS，1.385 秒 | 仍 FAIL：ENOENT |
| `v017-os-cosmic-panel-state-v2` | PASS，1.748 秒 | PASS，0.202 秒 |

最后一行两项均在同一最终镜像上执行。配置回归实际解析完整 45 个 RON 文件，
校验 Panel/Dock、18 个 applet 项，并写入一个用户覆盖、回读用户值及原系统值，
确认用户覆盖优先且系统数据未被修改。state 回归不仅注册 watch，还创建文件并
核对实际返回的 watch ID、IN_CREATE 和文件名。

## 完整上游数据安装

新增 `tools/install_cosmic_panel_defaults_v1.py`，来源为实际固定 Git 提交
`3ce6ce1cec97669f91e809962d9446aaefe8a06e`，tree 为
`664e1b3dec3d7790a80375a50361bcc09bd54988`。逐项核对 Git 对象和工作文件字节，
复制完整 `data/default_schema` 的 45 个文件，共 1,072 字节，到
`/usr/share/cosmic/`。同时保留完整 34,902 字节 `LICENSE.md`。

未删减上游 applet 项、生成简化面板、改写 RON 或替换任何原始组件 ELF。
安装器校验父镜像 manifest 所绑定的完整目录，保留原输入字节/模式，拒绝重名
覆盖，原子发布新目录并可独立重验。

```sh
python3 tools/install_cosmic_panel_defaults_v1.py \
  --base-build artifacts/v017-os-panel-config-red \
  --output artifacts/NEW-panel-defaults-catalog
python3 tools/install_cosmic_panel_defaults_v1.py \
  --validate-prefix artifacts/v017-panel-defaults-catalog-v1
```

实际新目录 `artifacts/v017-panel-defaults-catalog-v1` 共 111 个输入、127,493,844
字节，处于既有显式 core v1 的 128 MiB 内。没有放宽 ROM 或运行时资源上限。

## 启动目录准备

settings 的路径能解析，失败原因是 `/.local/state/cosmic` 不存在。notify 不负责
创建被观察的根目录。新增 `runtime_directory::prepare_cosmic`，在现有 durable
recovery 和 runtime reset 之后、任何用户进程之前调用，仅作用于 cosmic-session
profile。它准备固定单 UID 平台既有 HOME=/ 路径，以及直接服务入口既有的私有
`/run/user/0` config/state 路径。

新建目录 mode=0700；已有目录的 mode、inode、内容保持；冲突文件或链接明确
拒绝，不替换。`/.config` 和 `/.local/state` 沿用原路径；没有搬迁用户设置。
原 runtime reset 的清理范围不扩大到持久用户数据。四项真实文件系统宿主回归
覆盖新建权限、反复准备、重启时持久数据保留/runtime 清理、冲突文件保留。

## 同一镜像与正常 session

最终 `artifacts/v017-os-cosmic-panel-state-v2` boot SHA256：
`b8db66e8012c7caa3f0b78cb00be1f43fb8f52a5d73bfe5fcba614aa714fb01d`。
build manifest SHA256：
`dca08af9a2f17c0206fbe9bc4e9dc9b085bef8268f1e30a4940672f9e7f6a81c`。

`artifacts/v017-cosmic-panel-state-runtime-v2` 的路径检查 PASS，五个核心进程均为
Running/Waiting、code=0，settings 已越过 watch 设置进入 theme 初始化；旧的
NoConfigDirectory/config watch/state watch 错误均为零。原 45 秒门槛为 45.012 秒，
仍剩 241,722 个启动像素，因此其 `result.json` 首帧诊断保持 FAIL。

另一次 `artifacts/v017-cosmic-panel-state-runtime-extended-v2` 在 45.007 秒仍剩
196,666 个启动像素，保持 FAIL；到 120.017 秒才剩 58 个，画面仍是背景和指针。
晚到扫描输出放在 `later.ppm` 与 `later_diagnostic`，不能改变固定门槛的原判定。
过程中真实 notifications 报面板 D-Bus 服务设置超时，panel 随后报无法连接通知
守护进程；panel 两次实际以 134 退出，session 以 TERM/143 结束旧 notifications
后重启这一对组件。最终为新 PID 9/10，故延长观察的核心进程存活判定也保持 FAIL。
尚未把握手超时认定为 134 的唯一原因，下一轮需要独立复现这一失败链。

九个主会话默认程序仍为 ENOENT；面板 applet 真实程序与协议、完整画面/输入/
通知交互及整体退出回收也未验收。宿主 POSIX 全量测试（包括新四项目录回归）、
kernel catalog 五项边界检查、诊断工具四项判定测试和原三项扫描输出边界测试
全部通过，OS 工具六项测试通过。

同一最终镜像还重新通过原 10 项真实信号回归（2.444 秒）及四种 locale 的真实
Compose 回归（0.699 秒）。`path-gap-evidence.json` 绑定两次正常会话 UART、同一
镜像、四个独立客体回归及实际退出码，并核对原目录 63 个输入的字节/模式均保留。

所有完整 OS/会话/语义帧标志继续为 false。临时内核标记已移除；旧失败和诊断
捕获保留。构建与 QEMU 串行持有共享 native lease。本轮未提交或推送。
