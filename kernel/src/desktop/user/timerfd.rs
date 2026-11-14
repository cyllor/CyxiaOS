//! AArch64 timerfd ABI; validate all user memory before changing timer state.
use super::{Errno, Runner, fd};
use cyxia_posix::timerfd::Setting;

fn decode_timespec(bytes: &[u8]) -> Result<u64, Errno> {
    let seconds = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| Errno::Inval)?);
    let nanos = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| Errno::Inval)?);
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(Errno::Inval);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos as u64))
        .ok_or(Errno::Overflow)
}

fn encode(setting: Setting) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (out, ns) in bytes
        .chunks_exact_mut(16)
        .zip([setting.interval, setting.value])
    {
        out[..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
        out[8..].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
    }
    bytes
}

impl Runner {
    pub(super) fn timerfd_settime(
        &mut self,
        descriptor: u64,
        flags: u64,
        new: u64,
        old: u64,
    ) -> Result<u64, Errno> {
        let descriptor = fd(descriptor)?;
        let flags = u32::try_from(flags).map_err(|_| Errno::Inval)?;
        let mut bytes = [0; 32];
        self.copy_from(new, &mut bytes)?;
        let setting = Setting {
            interval: decode_timespec(&bytes[..16])?,
            value: decode_timespec(&bytes[16..])?,
        };
        if old != 0 {
            self.validate(old, 32, true)?;
        }
        let previous = self
            .process
            .timerfd_set(descriptor, super::now_ns(), flags, setting)?;
        if old != 0 {
            self.copy_to(old, &encode(previous))?;
        }
        Ok(0)
    }
    pub(super) fn timerfd_gettime(&mut self, descriptor: u64, address: u64) -> Result<u64, Errno> {
        let setting = self.process.timerfd_get(fd(descriptor)?, super::now_ns())?;
        self.copy_to(address, &encode(setting))?;
        Ok(0)
    }
}
