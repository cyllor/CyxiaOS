//! Read-only PL031 wall clock for the virt board, discovered through the DTB.
//! RTC data has one-second resolution. No invented epoch or wall time fallback.
//! Register contract: QEMU v10.2.0 hw/rtc/pl031.c (ARM PrimeCell PL031).
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_contracts::BootInfo;
#[cfg(feature = "ported")]
use cyxia_posix::Errno;

static RTC: AtomicU64 = AtomicU64::new(0);

pub fn init(info: &BootInfo) {
    let Some(rtc) = info.rtc else {
        return;
    };
    // This board's existing device mapping spans 0x09000000..0x09200000.
    if rtc.base.0 < 0x09000000
        || rtc
            .base
            .0
            .checked_add(rtc.len)
            .is_none_or(|end| end > 0x09200000)
    {
        return;
    }
    let base = super::HIGH + rtc.base.0;
    let expected = [0x31, 0x10, 0x14, 0, 0x0d, 0xf0, 5, 0xb1];
    for (index, value) in expected.into_iter().enumerate() {
        // SAFETY: the validated DTB range is mapped Device/RW/NX, all ID
        // registers lie within its first 4KiB; CPU0 alone performs discovery.
        let actual =
            unsafe { core::ptr::read_volatile((base + 0xfe0 + index as u64 * 4) as *const u32) };
        if actual != value {
            return;
        }
    }
    RTC.store(base, Ordering::Release);
    super::log(b"WALL_CLOCK_READY PL031 resolution=1s MECHANISM\n");
}

#[cfg(feature = "ported")]
pub fn realtime_seconds() -> Result<u64, Errno> {
    let base = RTC.load(Ordering::Acquire);
    if base == 0 {
        return Err(Errno::Nodev);
    }
    // SAFETY: init published a validated, permanently mapped PL031 resource.
    Ok(unsafe { core::ptr::read_volatile(base as *const u32) } as u64)
}
