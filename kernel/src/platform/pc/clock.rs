//! PC i440fx MC146818 UTC wall clock. CMOS time is never written by the OS.
use cyxia_platform_pc::rtc::{self, Cmos};
use cyxia_posix::Errno;
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
    // This probe reports boot status; it must not latch a transient update or
    // invalid sample into permanent unavailability. Every request samples CMOS.
    match rtc::read_seconds(&mut Hardware, 0x32) {
        Ok(_) => crate::log(b"WALL_CLOCK_READY MC146818 resolution=1s\n"),
        Err(rtc::Error::Busy) => crate::log(b"WALL_CLOCK_BUSY MC146818 retry=on-demand\n"),
        Err(rtc::Error::Unavailable) => crate::log(b"WALL_CLOCK_UNAVAILABLE MC146818\n"),
        Err(rtc::Error::Invalid) => crate::log(b"WALL_CLOCK_INVALID MC146818\n"),
    }
}
pub fn realtime_seconds() -> Result<u64, Errno> {
    if crate::machine::runtime::cpu_slot() != 0 { return Err(Errno::Again); }
    let mut sample = rtc::read_seconds(&mut Hardware, 0x32);
    if sample == Err(rtc::Error::Busy) {
        // A normal RTC update may outlast the decoder's immediate samples.
        // Retry fresh hardware reads, bounded by both elapsed time and work.
        // Successful reads keep their original path and never sample HPET.
        let started = crate::process_arch::now_ns();
        for _ in 0..1024 {
            if crate::process_arch::now_ns().saturating_sub(started) >= 1_000_000 {
                break;
            }
            core::hint::spin_loop();
            sample = rtc::read_seconds(&mut Hardware, 0x32);
            if sample != Err(rtc::Error::Busy) { break; }
        }
    }
    sample.map_err(|e| match e {
        rtc::Error::Busy => Errno::Again,
        rtc::Error::Unavailable => Errno::Nodev,
        rtc::Error::Invalid => Errno::Io,
    })
}
