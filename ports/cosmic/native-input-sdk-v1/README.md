# 静态输入库 SDK 扩展

`sources.json` 固定真实 eudev、libinput、libevdev、mtdev、Linux UAPI 和私有
宿主 GNU make 的上游归档、字节数及 SHA-256。构建只写全新的独立 SDK，
保留旧 SDK。Linux 源码只用于安装 UAPI 头文件，客体仍运行 CyxiaOS。

`tools/build_cosmic_input_sdk_v1.py` 使用实际 x86_64 musl 编译器，限制两任务、
1800 秒和 6 GiB 构建输出。libinput 的改动只将共享库链接形式改为静态库；
libwacom 后端明确未启用。Linux UAPI 脚本只补 POSIX sed 命令分隔符，使
原 SPDX 拒绝检查在 BSD/GNU sed 上都执行，失败不能被 make 的退出码掩盖。

发布前逐成员核验四个静态归档的 ISA，并真实链接含 udev、libevdev、libinput
入口的静态 ET_EXEC。回执保留源码、命令日志、生产者快照和实际输出哈希。
构建完成不代表客体已实现 Linux 设备、sysfs、netlink 或 Wacom 后端。
