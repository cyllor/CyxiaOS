//! PC i440fx MC146818 UTC wall clock. CMOS time is never written by the OS.
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_platform_pc::rtc::{self, Cmos};
use cyxia_posix::Errno;
static READY: AtomicBool = AtomicBool::new(false);
struct Hardware;
impl Cmos for Hardware {
    fn read(&mut self, register: u8) -> u8 {
        // CPU0 alone owns CMOS; IRQ handlers never select CMOS registers. Keep
        // the board's NMI policy enabled while selecting the requested byte.
        unsafe {
            cyxia_arch_x86_64::io::outb(0x70, register);
            cyxia_arch_x86_64::io::inb(0x71)
        }
    }
}
pub fn init() {
    if rtc::read_seconds(&mut Hardware, 0x32).is_ok() {
        READY.store(true, Ordering::Release);
        crate::log(b"WALL_CLOCK_READY MC146818 resolution=1s\n");
    } else {
        crate::log(b"WALL_CLOCK_UNAVAILABLE MC146818\n");
    }
}
pub fn realtime_seconds() -> Result<u64, Errno> {
    if crate::machine::runtime::cpu_slot() != 0 { return Err(Errno::Again); }
    if !READY.load(Ordering::Acquire) { return Err(Errno::Nodev); }
    rtc::read_seconds(&mut Hardware, 0x32).map_err(|e| match e {
        rtc::Error::Busy => Errno::Again,
        rtc::Error::Unavailable => Errno::Nodev,
        rtc::Error::Invalid => Errno::Io,
    })
}
