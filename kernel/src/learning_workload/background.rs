//! D13's fixed optional load is distinct from the 100 foreground observations.
//! This queue owns every future arrival before activation; completion always
//! comes from the real echo owner's immutable response receipt.
use cyxia_prototype::domains::{Error, ObjectKey};
use sha2::{Digest, Sha256};
pub const FOREGROUND: ObjectKey = ObjectKey {
    id: 12,
    generation: 1,
};
pub const OPTIONAL: ObjectKey = ObjectKey {
    id: 16,
    generation: 1,
};
pub const REQUESTS: usize = 100;
const PERIOD: u64 = 100_000_000;
const MEASURED: u64 = 0x1_0000;
const WARM: u64 = 0x2_0000;
pub trait Echo {
    fn submit(&mut self, id: u64, value: u64) -> Result<(), Error>;
    fn result(&mut self, id: u64) -> Result<Option<Result<u64, Error>>, Error>;
    fn acknowledge(&mut self, id: u64) -> Result<(), Error>;
}
#[derive(Clone, Copy)]
pub struct Queue {
    next: usize,
    pending: Option<(u64, bool)>,
    completed: usize,
    rejected: usize,
    warm_serial: u64,
    warm_at: u64,
}
impl Queue {
    pub const fn new() -> Self {
        Self {
            next: 0,
            pending: None,
            completed: 0,
            rejected: 0,
            warm_serial: 0,
            warm_at: 0,
        }
    }
    pub fn frozen_request(seed: u64, index: usize) -> Result<(u64, u64, u64), Error> {
        if index >= REQUESTS {
            return Err(Error::Range);
        }
        let id = MEASURED + index as u64;
        Ok((id, index as u64 * PERIOD, seed ^ id))
    }
    pub fn commit_request(hash: &mut Sha256, seed: u64, index: usize) -> Result<(), Error> {
        let (id, offset, value) = Self::frozen_request(seed, index)?;
        for v in [OPTIONAL.id, OPTIONAL.generation, id, offset, value] {
            hash.update(v.to_le_bytes());
        }
        Ok(())
    }
    pub fn settled(&self) -> bool {
        self.next == REQUESTS
            && self.pending.is_none()
            && self.completed + self.rejected == REQUESTS
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.completed, self.rejected)
    }
    pub fn poll(
        &mut self,
        at: u64,
        observation: u64,
        seed: u64,
        echo: &mut impl Echo,
    ) -> Result<(), Error> {
        if let Some((id, measured)) = self.pending {
            let Some(result) = echo.result(id)? else {
                return Ok(());
            };
            if result == Err(Error::Io) {
                return Err(Error::Io);
            }
            echo.acknowledge(id)?;
            if measured {
                if result.is_ok() {
                    self.completed += 1;
                } else {
                    self.rejected += 1;
                }
            } else {
                self.warm_at = at.checked_add(PERIOD).ok_or(Error::Overflow)?;
            }
            self.pending = None;
        }
        if self.next < REQUESTS {
            let (id, offset, value) = Self::frozen_request(seed, self.next)?;
            if at >= observation.checked_add(offset).ok_or(Error::Overflow)? {
                echo.submit(id, value)?;
                self.pending = Some((id, true));
                self.next += 1;
                return Ok(());
            }
        }
        if at < observation.saturating_sub(50_000_000) && at >= self.warm_at {
            let serial = self
                .warm_serial
                .checked_add(1)
                .filter(|v| *v < MEASURED)
                .ok_or(Error::Overflow)?;
            let id = WARM + serial;
            echo.submit(id, seed ^ id)?;
            self.pending = Some((id, false));
            self.warm_serial = serial;
        }
        Ok(())
    }
}
