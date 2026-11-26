//! Bounded framed writes. Retrying is legal only before any frame byte was accepted.
use cyxia_contracts::{ConsoleOps, PlatformError, transport};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitError {
    Again,
    Failed(usize),
    Invalid,
}
pub fn write_frame(
    console: &mut impl ConsoleOps,
    session: u64,
    sequence: u64,
    payload: &[u8],
) -> Result<usize, TransmitError> {
    let mut frame = [0u8; 128];
    let n = transport::encode(session, sequence, payload, &mut frame)
        .map_err(|_| TransmitError::Invalid)?;
    let mut written = 0;
    for chunk in frame[..n].chunks(64) {
        match console.try_write(chunk) {
            Ok(count) if count == chunk.len() => written += count,
            Ok(0) | Err(PlatformError::Again) if written == 0 => return Err(TransmitError::Again),
            Ok(count) if count <= chunk.len() => {
                return Err(TransmitError::Failed(written + count));
            }
            _ => return Err(TransmitError::Failed(written)),
        }
    }
    Ok(written)
}

/// CPU-owned raw stream queue. Admission is atomic; drain retains the exact
/// unwritten suffix across short writes and Again, without replaying a prefix.
pub struct OutputQueue<const N: usize> {
    bytes: [u8; N],
    head: usize,
    len: usize,
}
impl<const N: usize> OutputQueue<N> {
    pub const fn new() -> Self {
        assert!(N > 0);
        Self {
            bytes: [0; N],
            head: 0,
            len: 0,
        }
    }
    pub fn pending(&self) -> usize {
        self.len
    }
    pub fn enqueue(&mut self, bytes: &[u8]) -> Result<(), PlatformError> {
        if bytes.len() > N - self.len {
            return Err(PlatformError::Again);
        }
        for &byte in bytes {
            self.bytes[(self.head + self.len) % N] = byte;
            self.len += 1;
        }
        Ok(())
    }
    pub fn drain(
        &mut self,
        console: &mut impl ConsoleOps,
        budget: usize,
    ) -> Result<usize, PlatformError> {
        let mut done = 0;
        while self.len != 0 && done < budget {
            let count = self.len.min(N - self.head).min(budget - done).min(64);
            match console.try_write(&self.bytes[self.head..self.head + count]) {
                Ok(0) | Err(PlatformError::Again) => break,
                Ok(n) if n <= count => {
                    self.head = (self.head + n) % N;
                    self.len -= n;
                    done += n;
                }
                Ok(_) => return Err(PlatformError::Invalid),
                Err(error) => return Err(error),
            }
        }
        Ok(done)
    }
}
impl<const N: usize> Default for OutputQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    struct Console {
        calls: usize,
        mode: u8,
        bytes: std::vec::Vec<u8>,
    }
    impl ConsoleOps for Console {
        fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError> {
            self.calls += 1;
            if (self.mode == 0 && self.calls == 1) || (self.mode == 1 && self.calls == 2) {
                return Err(PlatformError::Again);
            }
            let n = if self.mode == 2 { 3 } else { data.len() };
            self.bytes.extend_from_slice(&data[..n]);
            Ok(n)
        }
    }
    #[test]
    fn queued_stream_keeps_partial_tail_across_again_and_wrap_without_duplication() {
        struct Short {
            calls: usize,
            bytes: std::vec::Vec<u8>,
        }
        impl ConsoleOps for Short {
            fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError> {
                self.calls += 1;
                if self.calls % 3 == 0 {
                    return Err(PlatformError::Again);
                }
                let n = data.len().min(3);
                self.bytes.extend_from_slice(&data[..n]);
                Ok(n)
            }
        }
        let mut queue = OutputQueue::<16>::new();
        let mut c = Short {
            calls: 0,
            bytes: std::vec::Vec::new(),
        };
        queue.enqueue(b"abcdefghij").unwrap();
        assert_eq!(queue.drain(&mut c, 5), Ok(5));
        assert_eq!(queue.pending(), 5);
        assert_eq!(queue.enqueue(b"012345678901"), Err(PlatformError::Again));
        assert_eq!(queue.pending(), 5);
        queue.enqueue(b"klmnopqrst").unwrap();
        for _ in 0..32 {
            queue.drain(&mut c, 4).unwrap();
        }
        assert_eq!(queue.pending(), 0);
        assert_eq!(c.bytes, b"abcdefghijklmnopqrst");
    }
    #[test]
    fn queued_stream_zero_budget_and_zero_progress_do_not_consume_data() {
        struct Busy;
        impl ConsoleOps for Busy {
            fn try_write(&mut self, _: &[u8]) -> Result<usize, PlatformError> {
                Ok(0)
            }
        }
        let mut queue = OutputQueue::<4>::new();
        queue.enqueue(b"full").unwrap();
        assert_eq!(queue.drain(&mut Busy, 0), Ok(0));
        assert_eq!(queue.drain(&mut Busy, 100), Ok(0));
        assert_eq!(queue.pending(), 4);
        assert_eq!(queue.enqueue(b"x"), Err(PlatformError::Again));
    }
    #[test]
    fn zero_progress_can_retry_same_sequence_without_corrupting_frame() {
        let mut c = Console {
            calls: 0,
            mode: 0,
            bytes: std::vec::Vec::new(),
        };
        assert_eq!(
            write_frame(&mut c, 1, 7, b"test"),
            Err(TransmitError::Again)
        );
        assert!(c.bytes.is_empty());
        let n = write_frame(&mut c, 1, 7, b"test").unwrap();
        let mut expected = [0; 128];
        let length = transport::encode(1, 7, b"test", &mut expected).unwrap();
        assert_eq!(n, length);
        assert_eq!(c.bytes, &expected[..length]);
    }
    #[test]
    fn partial_frame_is_terminal_not_retryable() {
        let mut c = Console {
            calls: 0,
            mode: 1,
            bytes: std::vec::Vec::new(),
        };
        assert_eq!(
            write_frame(&mut c, 1, 1, &[1; 96]),
            Err(TransmitError::Failed(64))
        );
        let mut c = Console {
            calls: 0,
            mode: 2,
            bytes: std::vec::Vec::new(),
        };
        assert_eq!(
            write_frame(&mut c, 1, 1, b"hello"),
            Err(TransmitError::Failed(3))
        );
    }
}
