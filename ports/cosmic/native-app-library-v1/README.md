# COSMIC 应用库

`cosmic-app-library-v1` 在包含壁纸和面板小部件的 1 GiB 桌面上运行仓库锁定的
`cosmic-app-library` 1.10.0。构建使用静态 Wayland 和 XKB 绑定及 Iced 的软件渲染器。
应用库沿用单实例 D-Bus 激活。CyxiaOS 上的应用启动复用会话的 128 FD 原生 spawn 适配，
并将 Wayland 激活令牌传给从 Desktop Entry 选中的应用。安装阶段去掉非加载符号表，
核对入口、程序头和加载段后再放入镜像。

应用库镜像为会话子进程、小部件和一次应用启动提供 40 个管道槽。内核使用现有的
管道准入模型，客体回归记录实际使用量和剩余槽位。

进入桌面后，在客体控制台执行 `posix exec cosmic-app-library` 打开应用库。
它从标准 XDG 目录读取应用条目，支持输入搜索词、回车启动和 Escape 关闭。

## 构建和回归

在仓库根目录使用 `native-recipe.json` 锁定的源码、Cargo 缓存和现有输入 SDK。

```sh
python3 -B tools/build_cosmic_app_library_v1.py --output artifacts/cosmic-app-library-build
python3 -B tools/install_cosmic_app_library_v1.py --build artifacts/cosmic-app-library-build \
  --base-build artifacts/v017-os-cosmic-bg-1g-v3 --output artifacts/cosmic-app-library-catalog \
  --with-test-fixtures
python3 -B tools/os_x86.py build --profile release --graphics --ported --feature cosmic-app-library-v1 \
  --sysroot artifacts/cosmic-app-library-catalog --output artifacts/cosmic-app-library-os
python3 -B tools/os_cosmic_app_library_probe.py --build artifacts/cosmic-app-library-os \
  --output artifacts/cosmic-app-library-regression
```

可选的回归辅助程序只在测试客体的可写目录中创建两个应用条目。回归通过真实 D-Bus
打开会话中的应用库，输入搜索词并通过回车启动已安装的 Wayland 测试窗口。验证记录包含
客体截图、启动的子进程和关闭应用库前后的共享资源计数。
从应用库启动时，测试窗口等待 Wayland 注册表和首次配置各最多 20 秒。应用库回归对
窗口首帧设 45 秒上限，面板回归仍使用 15 秒交互门限。
