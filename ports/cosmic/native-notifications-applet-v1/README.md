# COSMIC 通知中心

`cosmic-applet-notifications` 使用 Epoch 1.10.0 的原版应用代码，固定在
`cosmic-applets` 提交 `406d1b7d627138fdf4078f654268d3d8774e50f1`。
构建补丁沿用静态 Wayland 和 XKB 绑定。面板根据原始 desktop 文件建立应用进程，
通过私有套接字接收后台服务推送的通知。原版状态图标、锁定 COSMIC 图标主题中的关闭图标
以及各自的许可证随应用安装。

镜像特性 `cosmic-notifications-applet-v1` 继承现有工作区 applet 配置，
沿用 1 GiB、4 vCPU、256 MiB ROM 目录和 4096 页共享内存池。
通知中心展开时已经占用 31 个共享对象，新通知的卡片和悬浮横幅需要同时分配缓冲区。
版本化对象配置为该镜像提供 48 个元数据槽。

## 构建与回归

在仓库根目录运行以下命令。回归使用已有的配对面板、会话、通知后台和 SDK。

```sh
python3 tools/build_cosmic_notifications_applet_v1.py build \
  --sysroot artifacts/v017-cosmic-input-sdk-v3 \
  --cache-from artifacts/v017-workspace-applets-build-v6 --output artifacts/notification-center-build
python3 tools/build_notification_probe.py --panel-clear \
  --sysroot artifacts/sysroot/x86_64-musl --dbus-build artifacts/v017-dbus-build \
  --native-lock artifacts/v016-focus-a03-a10-20261109-r9/native-session.lock \
  --output artifacts/notification-center-probe
python3 tools/build_cosmic_notifications_applet_v1.py assemble \
  --build artifacts/notification-center-build --base-build artifacts/v017-os-epoll-sampling-1g-v1 \
  --probe-build artifacts/notification-center-probe --output artifacts/notification-center-catalog
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature cosmic-notifications-applet-v1 --sysroot artifacts/notification-center-catalog \
  --output artifacts/notification-center-os
python3 tools/os_cosmic_notifications_applet_probe.py --build artifacts/notification-center-os \
  --output artifacts/notification-center-regression --observe-seconds 60
```

`--probe-build` 为回归镜像加入通知发送器。发送器在真实会话总线上等待由面板清除触发的
`NotificationClosed`，校验通知 ID 和服务进程。回归通过卡片上的关闭按钮清除通知，
保存打开、显示、清除和关闭四个状态的客体画面，并检查共享对象回收。
