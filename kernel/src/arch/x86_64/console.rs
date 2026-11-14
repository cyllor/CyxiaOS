use super::*;

static mut SERIAL: Option<pc::hardware::Serial16550> = None;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub(super) fn log(payload: &[u8]) {
    // BSP owns the UART. Normal interrupt handlers never use it; fatal paths
    // have interrupts disabled and never return to an interrupted writer.
    unsafe {
        if let Some(serial) = (&mut *core::ptr::addr_of_mut!(SERIAL)).as_mut() {
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            if cyxia_kernel_core::console::write_frame(serial, 1, sequence, payload).is_err() {
                exit(false);
            }
        }
    }
}

pub(super) fn exit(success: bool) -> ! {
    arch::cpu::disable_interrupts();
    unsafe { arch::io::outl(0xf4, if success { 0x10 } else { 0x11 }) };
    arch::cpu::halt()
}

struct Message {
    bytes: [u8; 96],
    len: usize,
}
impl core::fmt::Write for Message {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let n = value.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&value.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    arch::cpu::disable_interrupts();
    let mut message = Message {
        bytes: [0; 96],
        len: 0,
    };
    let _ = write!(&mut message, "X86_FAIL {}", info);
    log(&message.bytes[..message.len]);
    exit(false)
}

pub(super) unsafe fn init() {
    unsafe { core::ptr::addr_of_mut!(SERIAL).write(Some(pc::hardware::Serial16550::init())) };
}
