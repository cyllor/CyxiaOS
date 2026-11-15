# V0.17 cosmic-comp 源码解耦与 x86 交叉类型检查

本文保留第一轮 `backend-winit` 验证记录；后续原生后端、静态依赖与链接进展见
[Cyxia 原生后端记录](v17-cosmic-native-20261115.md)。下面的能力边界以第一轮结束时为准。

2026-11-15，完整 CyxiaOS / COSMIC 主线。固定上游 cosmic-comp
`41497b42d9744d9963c4c6d17e8add49489b45ee` 的真实合成器代码已通过
`x86_64-unknown-linux-musl` 交叉类型检查；当前选用 `backend-winit` 检查公共代码。
**尚未链接 cosmic-comp ELF，未实现 Cyxia 原生后端，也未运行完整 COSMIC 会话。**

## 本轮代码

- 在既有后端特性分离补丁上，新增 `OffscreenTarget` 请求接口，替换六处接收
  `KmsState` 回调的截图/捕获调用。设备选择、跨设备目标格式和软件渲染回退归入真实 KMS
  后端；原有 State、Shell、工作区和窗口渲染继续使用。
- `prepare_cosmic_comp.py` 从干净的固定 Git 提交导出，逐层校验
  recipe → series → manifest → patch 及文件前后哈希。复制完成并核对整棵树后，
  才原子发布 `source/`；失败仅留下未发布的临时目录和失败报告。
- `cosmic_port_source.py` 支持显式架构、补丁序列、特性选择和离线准备。
  `build_cosmic.py typecheck` 使用真实 SDK、隔离缓存和资源限额；类型检查不报告链接或客体运行成功。
  C++ SDK 尚未安装，依赖若请求 C++ 编译会明确失败，不会使用宿主编译器代替目标编译器。
- 只读 `cosmic_comp_preflight.py` 校验完整锁文件源码，包含归档校验和、固定 Git blob、
  递归子模块及受控 Cargo 标记文件。它自身不执行 Cargo，故仍明确报告构建与运行能力未验证。

## 实际证据

证据位于 `artifacts/v017-cosmic-native-20261115-r1/`：

| 记录 | 结果与边界 |
| --- | --- |
| `source-availability-final.json` | 698 个锁定输入全部可用：662 个 registry 包、34 个 Git 包、2 个本地包；不代表全部同时用于目标构建 |
| `upstream-source-01/preparation.json` | 上游 x86 配置实际离线解析 509 个包；获取缓存新增 1,038,313,345 字节 |
| `patched-dependencies-01/preparation.json` | 补丁后 `--no-default-features --features backend-winit` 实际离线解析 487 个包，其中 454 个 registry 包；缓存增量为零 |
| `cross-check-01/build-report.json` | 真正的 cosmic-comp 库与二进制目标通过 `cargo check --release --target x86_64-unknown-linux-musl`；编译器约 2 分 46 秒，合成器有 41 条警告；没有链接 ELF |
| `patched-source-02/preparation.json`、`final-source-binding.json` | 审查修复后的传递哈希清单产生与交叉检查完全相同的源码树：`8de18b38b654206b1e2d48a4337a3cb7d1c0311fdba9920bb1886d31e5d35dfb` |
| `tests-final.log` | 相关 COSMIC/SDK 测试运行 92 项，91 项通过、1 项因缺少 ARM SDK 跳过；另有实际补丁设备选择模块的 7 项 Rust 测试通过 |

交叉检查使用的原始 recipe、series 和生产工具留在 `cross-check-01/producer-inputs/`。
之后加强了清单之间的哈希绑定与复制发布，但没有改变被检查的 Rust 源码；
`final-source-binding.json` 明确记录这一关系，不冒充第二次编译。

代码规范和需求符合性两路审查均发现清单传递绑定、复制失败发布两项缺陷。
新增测试先复现失败，修复后通过，两路复核确认关闭。较早一轮测试还发现旧 Smithay
研究缓存已不存在；回归测试现在可读取独立 Cargo 缓存中的准确固定 Git blob。

## 复现

需要已构建的 x86 musl SDK 与已获取的固定源码。准备不会修改上游检出：

```sh
python3 tools/prepare_cosmic_comp.py --output artifacts/comp-source-new
python3 tools/cosmic_comp_preflight.py
python3 tools/build_cosmic.py typecheck --component cosmic-comp --arch x86_64 \
  --recipe ports/cosmic/native-comp/cross-check-recipe.json \
  --resource-profile ports/cosmic/native-comp/cross-check-profile.json \
  --output artifacts/comp-cross-check-new
```

重型编译和客体捕获必须继续通过 `tools/native_session.py` 的共享租约串行运行。
只读 preflight 即使源码齐全仍以退出码 1 表示它没有执行目标解析、链接和客体验证；
真实解析及类型检查的结果由上面的独立报告提供。

## 下一步

1. 接入真正的 Cyxia 输出、EGL 渲染与呈现、事件调度、键鼠输入和关闭路径，复用
   cosmic-comp 的公共渲染与窗口管理。当前 Winit 分支不能作为 Cyxia 原生桌面运行。
2. 补齐已解析图中的原生链接依赖：`pixman-sys` 确实无条件链接 `pixman-1`，当前 SDK 缺少该库；
   Wayland/X11 的动态加载路径也需要目标适配。当前图未激活 GBM/libdrm 探测，不能仅凭包名推断缺库。
3. 为 KMS 启用配置另做整体类型检查；本轮七项独立 Rust 测试只验证其设备选择策略。
4. 实际链接并测量映像、堆、线程和文件描述符需求后，推进正式容量、服务、会话和应用。
   不放宽旧容量阈值来冒充桌面完成，A03 不再是推进条件。
