# M1 实测环境

Rust 1.95.0 / Cargo 1.95.0 / QEMU 10.2.2 / virt-10.2 / Cortex-A53 / TCG / 1 CPU / 256 MiB。ARM softfloat 和 LLVM 工具已安装。

磁盘不足时复用已安装 stable（其实际版本为 1.95.0）；doctor 强制检查版本，后续升级必须重新验收。

QEMU 10.2.2 PL011 write_txdata 调用同步 write_all；指定 ringbuf_chr_write 写内存、满时覆盖、返回 len，不等待消费者。本结论仅适用于指定 ringbuf，不推广到其他 chardev。裸机 ELF 从 e_entry 进入，DTB 放在 RAM 起始。

- [pl011.c](https://raw.githubusercontent.com/qemu/qemu/v10.2.2/hw/char/pl011.c) SHA256 `a069524b7f559c1c01f3064ff61dfa030fd937ae084c1a62dc6adaf9ff8271af`
- [char-ringbuf.c](https://raw.githubusercontent.com/qemu/qemu/v10.2.2/chardev/char-ringbuf.c) SHA256 `46e058bd0932232aa8d51025e561a8472a7c15524343a0f4989e66bd7ce7d754`
- [boot.c](https://raw.githubusercontent.com/qemu/qemu/v10.2.2/hw/arm/boot.c) SHA256 `87d532e800bacb4a10f2f8e9a4e11be355cec973793d809ba0e85540c4199297`

设备树 fixture SHA256 `9f697b782dea301044a3e8f5b9a1f4347d7bee318e6557c32af16812d7b5adbf`。导出参数与 M1 machine/cpu/smp/m/accel 相同，追加 dumpdtb。
