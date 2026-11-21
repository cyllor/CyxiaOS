# 原生 panel 弹窗输入区域同步

从完整的 128-FD panel 宿主源码叠加三个文件的补丁，Cargo 配方、锁文件、
默认功能和其余源码保持。原导出及派生完整树、文件模式、补丁和 helper
均由 source-policy.json 绑定；原宿主策略不改写，旧构建证据保留。

旧代理只在创建 popup 时读取 pending input_region，并丢弃矩形位置和减法；
后续内层提交不会更新外层区域。初始 1×1 / 空区域可在弹窗变大后仍用于命中。
现在在内层提交后读取 committed SurfaceAttributes，保留 None 与空区域区别、
矩形位置和操作顺序；在第一次外层 map 前同步，后续变化提交到外层。
未变化的区域不重新创建 wl_region。原延迟 map / pre-commit grab 次序保持。

只改变代理输入机制，严格转发客户已提交的区域，保留完整原版 GUI 与 applet。
构建和真实客体回归分别记录；完整 COSMIC 的验证标记保持 false。
