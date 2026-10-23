# 桌面源码准备

`tools/desktop_ports.py` 使用本目录的 [manifest.json](manifest.json) 准备选定组件的源码。它不会解压源码、运行 configure/构建脚本、安装软件或启动桌面。原生 X.Org/LXDE 尚未构建；已实现的内核基础见 [桌面内存与显示](../../docs/implementation/desktop-memory-display.md)，完整移植缺口见 [移植清单](../../docs/implementation/desktop-port-inventory.md)。

## 默认检查

在项目根目录运行：

```sh
python3 tools/desktop_ports.py
python3 tools/desktop_ports.py check
python3 tools/desktop_ports.py check --package lxmenu-data
```

默认 `inventory` 和 `check` 只读取清单、检查本地工具路径，不联网、不创建缓存、不执行 Git 或包内脚本。`inventory` 展示信息；`check` 在缺少固定来源、依赖版本或完整闭包时返回非零。选定 `lxmenu-data` 的源码闭包可以通过，但输出仍明确 `desktop_build_ready: false`，不代表完整桌面可以编译。

当前完整清单仍有未固定摘要的发布归档以及 36 项待冻结依赖/资产。一个正确的源码版本、一次下载成功和整个桌面依赖闭合是不同状态。工具不提供构建入口。

## 显式获取一个包

```sh
python3 tools/desktop_ports.py --max-bytes 4194304 fetch --package pango --online
python3 tools/desktop_ports.py --max-bytes 4194304 fetch --package lxmenu-data --online
```

`fetch` 每次必须明确指定一个包，并在 `--online` 与 `--offline-file` 中选择一种来源；不存在全部下载或自动递归下载。未固定 SHA-256、也没有精确 Git commit 和仓库 URL 的组件直接拒绝。允许先准备一个已固定组件的源码，即使完整桌面闭包尚未完成；这不会绕过后续构建所需的依赖审计。

- SHA-256 路径：只接受 HTTPS，读取时计算摘要并与清单对比，拒绝降级到 HTTP、带凭据 URL、超限响应及摘要不符。
- Git 路径：获取清单中的完整 40 位 commit，确认 FETCH_HEAD/commit 身份，检查对象完整性，再由 Git 导出 tar。保留 bare 对象库用于离线重新导出比对，不依赖一个可修改的来源说明文件证明提交身份。
- 使用同一缓存文件系统中的临时目录；核验完成后才原子发布目录。错误会移除本次临时数据与锁，不替换已有损坏缓存，也不执行任何源码内容。
- 默认单个源码文件上限 32 MiB，并保留 64 MiB 磁盘余量；Git 在启动前为对象/导出/复核预留三倍文件上限，同时监测实际占用和剩余空间。Git 大小监测是周期检查，并非操作系统磁盘配额。归档超过设置须由使用者明确调整上限。

全局选项 `--manifest`、`--cache`、`--max-bytes` 放在子命令前。默认缓存位于项目的 `artifacts/desktop-sources/`，受到现有 `.gitignore` 管理。系统中断遗留 `.lock-*` 时，工具会停止并指出路径；先确认对应进程已退出，再人工处理该锁。

## 离线导入与复核

```sh
python3 tools/desktop_ports.py fetch --package pango --offline-file /path/to/pango-1.56.4.tar.xz
python3 tools/desktop_ports.py fetch --package lxmenu-data --offline-file /path/to/lxmenu-data.bundle
python3 tools/desktop_ports.py verify --package pango
python3 tools/desktop_ports.py verify --package lxmenu-data
```

离线摘要包使用原始归档；Git 包使用包含目标提交及所需对象、可单独验证的 Git bundle，不能用未附摘要的 tar 代替 Git 身份证明。Git 的离线操作禁用网络协议与惰性远程对象获取。`verify` 重新读取源码、检查身份和摘要；对于 Git 还会重新导出已验证提交，防止同时改写归档和 provenance 后冒充原提交。复核 Git 导出需要临时磁盘空间。

每个缓存目录包含 `provenance.json` 和 `source.archive`（保留官方原始压缩字节）或 `source.tar`（Git 导出）；Git 路径另含 `repository.git`。记录固定来源、提交/预期摘要、实际 SHA-256、字节数、实际获取地址、时间和在线/离线方式。`signature_verified: false` 表示此工具未执行发布者签名验证，不把 SHA-256/Git 对象验证称为签名认证。`extracted` 和 `built` 均保持 false。

## 本次实测

2026-10-16 已验证两个小组件，缓存总占用约 3 MiB；没有解压或编译。第一次 Git HTTPS 获取遇到 TLS 连接错误，工具正确清理临时目录，后续重试成功。为核验摘要路径另取一个小归档，此后没有批量下载。

| 来源 | 实际结果 |
|---|---|
| LXMenu Data 0.1.5 | commit `3b14415ff9862e6b79577fd4b9a097965001b270`；导出 983040 字节；SHA-256 `264c97f820749d80f5ee40e78c1839046ef250c9721dbbfd6f83b2e8edd70f47` |
| Pango 1.56.4 | 官方归档 1883988 字节；SHA-256 `17065e2fcc5f5a5bdbffc884c956bfc7c451a96e8c4fb2f8ad837c6413cb5a01`，与清单内官方摘要一致 |

上述两项已进一步离线复核。来源分别为 [LXDE 官方仓库](https://github.com/lxde/lxmenu-data) 和 [GNOME 官方归档](https://download.gnome.org/sources/pango/1.56/pango-1.56.4.tar.xz)；Pango 的原始摘要见 [官方 SHA-256 文件](https://download.gnome.org/sources/pango/1.56/pango-1.56.4.sha256sum)。

针对性测试覆盖严格 JSON/名称/路径/来源解析、缺失 pin、依赖缺口、离线归档和 Git bundle、摘要不符、缓存篡改、链接文件、磁盘不足、大小限制和失败清理：

```sh
python3 -m unittest tests.host.test_desktop_ports -v
```

本次宿主能找到 Git、Clang 和 pkg-config；Meson、Ninja、Vala、intltoolize 仍不在 PATH。它们和目标 libc/sysroot、X.Org 平台后端、桌面库闭包及真实运行验证，是后续工作，不能由源码获取结果替代。
