#![no_std]
use cyxia_contracts::*;
pub struct Pl011 {
    base: usize,
}
impl Pl011 {
    /// Attach to an initialized console without resetting its receive FIFO.
    /// # Safety
    /// The resource must remain mapped as Device memory; callers must serialize
    /// all access and must not initialize or reconfigure it while this handle is used.
    pub unsafe fn attach(resource: UartResource) -> Result<Self, PlatformError> {
        if resource.len < 0x1000 || !resource.base.0.is_multiple_of(4096) {
            return Err(PlatformError::Invalid);
        }
        Ok(Self {
            base: resource.base.0 as usize,
        })
    }
    /// # Safety
    /// Resource must be an exclusively owned mapped PL011 device with Device attributes.
    pub unsafe fn new(resource: UartResource) -> Result<Self, PlatformError> {
        if resource.len < 0x1000 || !resource.base.0.is_multiple_of(4096) {
            return Err(PlatformError::Invalid);
        };
        let s = Self {
            base: resource.base.0 as usize,
        };
        unsafe {
            s.write(0x30, 0);
            s.write(0x38, 0);
            s.write(0x44, 0x7ff);
            s.write(0x24, 13);
            s.write(0x28, 1);
            s.write(0x2c, 0x70);
            s.write(0x30, 0x301);
        }
        Ok(s)
    }
    unsafe fn write(&self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
    pub fn try_read(&mut self) -> Result<Option<u8>, PlatformError> {
        if unsafe { core::ptr::read_volatile((self.base + 0x18) as *const u32) } & 0x10 != 0 {
            return Ok(None);
        }
        let value = unsafe { core::ptr::read_volatile(self.base as *const u32) };
        if value & 0xf00 != 0 {
            unsafe { self.write(4, 0) }; // Clear receive error flags; never execute a damaged command.
            return Err(PlatformError::Invalid);
        }
        Ok(Some(value as u8))
    }

    /// One nonblocking TX attempt of at most 64 bytes. Stop on the first full
    /// FIFO or when the caller's nonblocking deadline check returns false.
    /// The check runs before both the status read and the data write.
    pub fn try_write_before(&mut self, data: &[u8], mut permitted: impl FnMut() -> bool) -> usize {
        let mut n = 0;
        for &byte in data.iter().take(64) {
            if !permitted()
                || unsafe { core::ptr::read_volatile((self.base + 0x18) as *const u32) } & 0x20 != 0
                || !permitted()
            {
                break;
            }
            unsafe { self.write(0, byte as u32) }
            n += 1;
        }
        n
    }
}
impl ConsoleOps for Pl011 {
    fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError> {
        let n = self.try_write_before(data, || true);
        if n == 0 && !data.is_empty() {
            Err(PlatformError::Again)
        } else {
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct Page([u32; 1024]);

    #[test]
    fn full_fifo_is_checked_once_and_never_written() {
        let mut page = Page([0; 1024]);
        page.0[0] = 0x5a;
        page.0[6] = 0x20;
        let mut checks = 0;
        // SAFETY: the aligned page models device registers for this test.
        let mut uart = unsafe {
            Pl011::attach(UartResource {
                base: PhysAddr(page.0.as_mut_ptr() as u64),
                len: 4096,
            })
            .unwrap()
        };
        assert_eq!(
            uart.try_write_before(b"terminal", || {
                checks += 1;
                true
            }),
            0
        );
        assert_eq!(checks, 1);
        assert_eq!(page.0[0], 0x5a);
        assert_eq!(uart.try_write(b"default"), Err(PlatformError::Again));
    }

    #[test]
    fn elapsed_deadline_between_status_and_data_leaves_the_unsent_suffix() {
        let mut page = Page([0; 1024]);
        let mut checks = 0;
        // SAFETY: the aligned page models device registers for this test.
        let mut uart = unsafe {
            Pl011::attach(UartResource {
                base: PhysAddr(page.0.as_mut_ptr() as u64),
                len: 4096,
            })
            .unwrap()
        };
        assert_eq!(
            uart.try_write_before(b"abc", || {
                checks += 1;
                checks <= 3
            }),
            1
        );
        assert_eq!(checks, 4);
        assert_eq!(page.0[0], u32::from(b'a'));
        assert_eq!(uart.try_write(&[0xff; 65]), Ok(64));
    }
}
