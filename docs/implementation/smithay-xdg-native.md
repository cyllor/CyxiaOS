# Smithay xdg-shell 原生窗口生命周期

2026-10-22。本工作包已通过三次独立 ARM/QEMU 启动，扩展了此前的 [普通表面集成](smithay-wayland-native.md)。真实上游 Smithay 负责 `xdg_surface` / `xdg_toplevel` 协议；独立 [libwayland 客户端](smithay-xdg-client.md) 验证收到的事件。当前是固定单窗口生命周期测试，尚未实现多窗口管理或运行 cosmic-comp。

## 已实现行为

服务端和客户端分别为 `ports/cosmic/smithay-xdg/main.rs` 与 `user/ported/smithay_xdg_client.c`。每次启动先运行一个错误客户端，再依次运行两个正常客户端，均通过原生 spawn 在独立 EL0 进程中执行。

错误客户端在初始配置之前提交缓冲区。Smithay 原始 pre-commit 检查产生 `xdg_surface.unconfigured_buffer`，客户端必须收到真实 `EPROTO`、错误码 3 和匹配的协议对象 ID。普通断开、超时或其他错误不能通过验收。此连接的对象被清理后，同一服务端继续处理两个正常客户端。

正常客户端先创建 toplevel 并作空提交，再接收 64×48、Activated 配置，确认相同序列号后才提交缓冲区。真实 A 键事件驱动第二帧；鼠标移动和左键事件后，服务端发送 96×64 配置，客户端确认后提交第三帧。Q 键事件触发真实 `xdg_toplevel.close`。每次配置、确认、渲染、输入及关闭均有跨进程顺序检查。

缓冲区替换期间保持窗口映射；仅在最终关闭时提交 NULL 缓冲区。所有 `wl_buffer.release` 由上游所有权生命周期产生，允许协议规定的提前释放，不以 frame callback 代替 buffer release。共享池仍在服务端导入后由客户端写入，再通过真实 GLES 渲染、读回、原生显示提交和 VirtIO scanout 校验像素。

## AI 准入与构建修正

初版 thin LTO 产物需要 3975 个映像页加 64 个栈页，共 4039 页。虽然物理池为 4096 页，现有本地模型 8195 拒绝该请求，客体没有启动服务端。失败记录保留在 `artifacts/smithay-xdg-runtime-r1`。

本轮没有改变模型权重、内存额度或准入机制。显式使用 fat LTO 后，映像减少为 3912 页，总请求为 3976 页，获得同一模型批准。构建器新增宿主预检程序 `crates/ai-runtime/examples/check_exec_admission.rs`，直接调用客体使用的 `executable_memory_policy`，绑定实际模型源码、依赖和程序哈希；验收器再次执行该程序。当前权重下，4016 页批准、4017 页及原 4039 页拒绝，域外输入报错。该阈值是当前模型的结果，不是另增的固定资源上限。

Smithay commit、103 个归档、静态 Mesa SDK、完整 US keymap 和上游适配沿用前一工作包；新建隔离构建目录，保留原有产物。新增 `smithay-xdg-probe` 内核 feature 与 shell 入口，现有轻量桌面启动器仍启动 Xorg/Openbox/LXPanel。

## 冻结验收

[运行报告](../../artifacts/smithay-xdg-runtime-r2/summary.json) 为 PASS，绑定 482 项输入。三次启动累计：

- 3 个错误客户端被协议拒绝，随后 6 个正常客户端完成生命周期。
- 12 次配置及匹配确认、6 次关闭、18 帧，校验 221,184 个实际显示像素。
- 42 条真实 QMP 输入命令；每次启动的 22 条 QMP 命令均有成功响应，含最终退出。
- 54 次显示模型准入、提交与真实 fence 完成，无 guard 代替；对象、映射、页、进程资源及授权全部归还。

| 产物 | SHA-256 |
| --- | --- |
| 内核 `smithay-xdg-kernel-r1/cyxia-kernel.elf` | `17c6d443c2908a69771ad0f764f997b3e0027c03c7f3797329f31c40b1aad6f3` |
| 服务端构建 `smithay-xdg-build-r1/build-report.json` | `86e192e920eb38b27ed3b838d615523a74b9fea80578c620db9356592eae988a` |
| 客户端 `smithay-xdg-client-r0/smithay-xdg-client.elf` | `264adfcf319ccd9366846cefe2c1e5b511a5e94032efc1f5ce523d0c47688994` |
| 运行报告 `smithay-xdg-runtime-r2/summary.json` | `e996b83212e9cb32dec8ef288a9cde6e73ad7eedd424cac4f26a79b775f424c6` |

[原始证据复核](../../artifacts/smithay-xdg-audit-r0/review.json) 另外解码 UART 序列与 CRC、检查扫描输出和 QMP 请求/响应。`runtime-r0` 保留验证器最初引用错误客户端清单的失败，该次没有启动客体。所有失败记录均未覆盖。

## 复现与下一阶段

```sh
python3 tools/build_smithay_xdg.py \
  --cache artifacts/smithay-wayland-research \
  --mesa-report artifacts/sysroot/aarch64-musl/mesa-static-r10/reports/20261020T155154-51965.json \
  --output artifacts/smithay-xdg-build-new
python3 tools/build_smithay_xdg_client.py --output artifacts/smithay-xdg-client-new

CYXIA_SMITHAY_XDG_PROBE_ELF="$PWD/artifacts/smithay-xdg-build-new/smithay-xdg.elf" \
CYXIA_SMITHAY_XDG_CLIENT_ELF="$PWD/artifacts/smithay-xdg-client-new/smithay-xdg-client.elf" \
cargo build --locked --offline --release --target aarch64-unknown-none-softfloat \
  -p cyxia-kernel --features smithay-xdg-probe
```

正式验收还需保存内核源码清单，使用 `tools/verify_smithay_xdg.py --elf … --server … --client … --output … --iterations 3` 运行新目录。手动 `posix exec smithay-xdg-probe` 是严格输入序列测试，并非可自由操作的桌面。

下一阶段为多个并发表面的合成、窗口位置与堆叠、点击聚焦、移动和交互 resize；还需处理弹出窗口及更广泛错误路径。当前未覆盖这些功能、桌面会话、应用启动器、完整协议兼容或所有 COSMIC 组件。`full_cosmic_port` 与 `cosmic_runtime_verified` 继续为 false。
