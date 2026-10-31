//! Diagnostic output after a failed mount; never grants authority or retries I/O.
use core::fmt::Write;

pub(super) fn mount_failure<E: core::fmt::Debug>(error: &E, reads: u64, writes: u64, flushes: u64) {
    struct Text {
        bytes: [u8; 256],
        len: usize,
    }
    impl Write for Text {
        fn write_str(&mut self, value: &str) -> core::fmt::Result {
            let end = self.len.checked_add(value.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut text = Text {
        bytes: [0; 256],
        len: 0,
    };
    if writeln!(
        &mut text,
        "STORAGE_V13_MOUNT_ERROR {error:?} reads={reads} writes={writes} flushes={flushes}"
    )
    .is_ok()
    {
        crate::log(&text.bytes[..text.len]);
    } else {
        crate::log(b"STORAGE_V13_MOUNT_ERROR diagnostic_truncated\n");
    }
}
