# COSMIC 壁纸

`cosmic-bg-v1` 让正常 COSMIC 会话启动原版 `cosmic-bg` 1.10.0。
构建使用仓库锁定的提交、Cargo.lock 和已有的静态 Wayland 绑定，保留上游默认 AVIF 特性，
并链接 x86_64 musl 的 dav1d 1.5.0。附带的猎户座壁纸按原图比例缩放为
1920×1080，镜像内包含图像署名及程序许可证。

纯色和渐变按 XRGB8888 输出所用的精度生成 RGB 中间图。1024×768 时每张
中间图使用 2.25 MiB，符合内核 8 MiB 的单次匿名内存分配上限。

## 构建和回归

在仓库根目录运行以下命令。源码与依赖缓存使用
`native-recipe.json`、`dav1d.json` 和 `wallpaper.json` 的固定版本。

```sh
python3 tools/build_cosmic_bg_sdk_v1.py --output artifacts/cosmic-bg-sdk
python3 tools/build_cosmic_bg_v1.py --sysroot artifacts/cosmic-bg-sdk --output artifacts/cosmic-bg-build
python3 tools/install_cosmic_bg_v1.py --build artifacts/cosmic-bg-build \
  --base-build artifacts/v017-os-notifications-applet-1g-v5 --output artifacts/cosmic-bg-catalog
python3 tools/os_x86.py build --profile release --graphics --ported --feature cosmic-bg-v1 \
  --sysroot artifacts/cosmic-bg-catalog --output artifacts/cosmic-bg-os
python3 tools/os_cosmic_bg_probe.py --build artifacts/cosmic-bg-os \
  --output artifacts/cosmic-bg-regression
```

1 GiB、4 vCPU 回归在客体写入真实 COSMIC 用户配置以切换到纯色和渐变，再删除覆盖值恢复系统壁纸。
测试核对画面像素以及切换前后的会话进程，并保存原始客体截图。
