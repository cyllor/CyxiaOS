use super::*;

static mut SERIAL: Option<pc::hardware::Serial16550> = None;
#[cfg(feature = "os-runtime")]
static mut OUTPUT: cyxia_kernel_core::console::OutputQueue<{ 128 * 1024 }> =
    cyxia_kernel_core::console::OutputQueue::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub(crate) fn log(payload: &[u8]) {
    #[cfg(feature = "os-runtime")]
    {
        if try_log(payload).is_err() {
            exit(false);
        }
        return;
    }
    #[cfg(not(feature = "os-runtime"))]
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

pub(crate) fn exit(success: bool) -> ! {
    arch::cpu::disable_interrupts();
    #[cfg(feature = "os-runtime")]
    let _ = flush_logs(128 * 1024);
    unsafe { arch::io::outl(0xf4, if success { 0x10 } else { 0x11 }) };
    arch::cpu::halt()
}

struct Message {
    // A file/line prefix plus a complete kernel trap record exceeds 96 bytes.
    // Keep fatal diagnostics bounded without discarding the fault address and
    // registers needed to distinguish permission faults from invalid backing.
    bytes: [u8; 512],
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
    #[cfg(all(feature = "smp-selftest", not(feature = "os-runtime")))]
    if super::smp::panic_on_ap() {
        arch::cpu::halt();
    }
    #[cfg(feature = "os-runtime")]
    if super::runtime::panic_on_ap() {
        arch::cpu::halt();
    }
    let mut message = Message {
        bytes: [0; 512],
        len: 0,
    };
    let _ = write!(&mut message, "X86_FAIL {}", info);
    log(&message.bytes[..message.len]);
    exit(false)
}

pub(crate) unsafe fn init() {
    unsafe { core::ptr::addr_of_mut!(SERIAL).write(Some(pc::hardware::Serial16550::init())) };
}

#[cfg(feature = "os-runtime")]
pub(crate) fn try_log(bytes: &[u8]) -> Result<(), cyxia_contracts::PlatformError> {
    // CPU0 alone enqueues. IRQ handlers and AP panic never borrow this queue.
    // Acceptance is atomic; only the foreground drain touches the UART.
    unsafe { (&mut *core::ptr::addr_of_mut!(OUTPUT)).enqueue(bytes) }
}
#[cfg(feature = "os-runtime")]
pub(crate) fn log_pending() -> usize {
    unsafe { (&*core::ptr::addr_of!(OUTPUT)).pending() }
}
#[cfg(feature = "os-runtime")]
pub(crate) fn flush_logs(budget: usize) -> Result<usize, cyxia_contracts::PlatformError> {
    use cyxia_contracts::PlatformError;
    let serial =
        unsafe { (&mut *core::ptr::addr_of_mut!(SERIAL)).as_mut() }.ok_or(PlatformError::Again)?;
    unsafe { (&mut *core::ptr::addr_of_mut!(OUTPUT)).drain(serial, budget) }
}
#[cfg(feature = "os-runtime")]
pub(crate) fn try_read() -> Result<Option<u8>, cyxia_contracts::PlatformError> {
    let serial = unsafe { (&mut *core::ptr::addr_of_mut!(SERIAL)).as_mut() }
        .ok_or(cyxia_contracts::PlatformError::Again)?;
    serial.try_read()
}
#[cfg(feature = "os-runtime")]
pub(crate) fn hex(value: u64) {
    let mut text = *b"0000000000000000\n";
    for (index, byte) in text[..16].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[((value >> (60 - index * 4)) & 15) as usize];
    }
    log(&text);
}
#[cfg(feature = "os-runtime")]
pub(crate) fn halt() -> ! {
    arch::cpu::halt()
}
