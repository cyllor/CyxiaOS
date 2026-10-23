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
