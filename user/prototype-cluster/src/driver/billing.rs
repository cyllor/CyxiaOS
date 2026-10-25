//! Opaque delivery for kernel-signed replay envelopes. The TLS process never
//! possesses billing keys and is not an authority for protected CPU intervals.
use super::*;
impl Driver {
    pub(super) fn billing_tick(&mut self) -> Result<(), ()> {
        if !self.engine.ready() { return Ok(()); }
        let mut status = [0; 32];
        for (i, value) in [self.native.as_ref().map_or(0, |n| n.queue.pending_count()) as u64,
            self.engine.contracts.len() as u64, u64::from(self.kernel_token.is_some()), u64::from(self.replay.is_some())].into_iter().enumerate() {
            status[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        match broker::request(OP_TASK, &status, &mut [], 0, [29, 0, 0]) {
            Ok((0, _)) | Err(AGAIN | FAILED | NOT_FOUND) => {}, _ => return Err(()),
        }
        if let Some(bytes) = self.billing_incoming.first() {
            match broker::request(OP_TASK, bytes, &mut [], 0, [22, 0, 0]) {
                Ok((0, _)) => { self.billing_incoming.remove(0); }
                Err(AGAIN) => {},
                // An invalid/stale envelope has no effect on the kernel
                // owner. Dropping it does not close a retained obligation.
                Err(NOT_FOUND | FAILED) => { self.billing_incoming.remove(0); }
                _ => return Err(()),
            }
        }
        let (used, count) = self.queued_class(false)?;
        if count >= 31 || used > 128 * 1024 { return Ok(()); }
        let mut bytes = [0; 2048];
        match broker::request(OP_TASK, &[], &mut bytes, 0, [21, 0, 0]) {
            Ok((n, sequence)) if n >= 196 && n <= bytes.len() && sequence != 0 => {
                self.send(56, bytes[..n].to_vec(), None)?;
                match broker::request(OP_TASK, &[], &mut [], 0, [23, sequence, 0]) {
                    Ok((0, _)) | Err(AGAIN) => {}, _ => return Err(()),
                }
            }
            Err(AGAIN | NOT_FOUND | FAILED) => {},
            _ => return Err(()),
        }
        Ok(())
    }
}
