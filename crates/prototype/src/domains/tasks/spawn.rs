use super::{MAX_GROUPS, MAX_SPAWNS, MAX_THREADS, UNSET, valid_key};
use crate::domains::{Action, Error, ObjectKey, PolicyStamp, WINDOW_NS};

const NORMAL_RECEIPTS: usize = 256;
const RECOVERY_RECEIPTS: usize = 32;
const RECEIPTS: usize = NORMAL_RECEIPTS + RECOVERY_RECEIPTS;
pub const RECOVERY_SPAWNS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnRequest {
    pub caller: ObjectKey,
    pub request_id: u64,
    pub package: ObjectKey,
    pub group: ObjectKey,
    pub payload_hash: [u8; 32],
    pub recovery: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnState {
    Queued,
    Created(ObjectKey),
    Failed(Error),
    Unknown,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created(ObjectKey),
    Rejected(Error),
    Uncertain,
    /// A fresh construction attempt acquired no task, scheduler, memory, or
    /// capability custody. The original queued request may wait and reauthorize.
    Deferred,
}
pub trait TaskBackend {
    /// Includes registered-package and recovery-authority checks. Runs before a
    /// receipt is admitted, and again immediately before actual construction.
    fn authorize(&mut self, request: &SpawnRequest) -> Result<(), Error>;
    /// Rejected certifies that no task or resource ownership remains. Deferred
    /// certifies that this attempt never acquired any such ownership. A backend
    /// which cannot establish either must return Uncertain, never retry creation.
    fn create(&mut self, request: &SpawnRequest) -> CreateOutcome;
}
#[derive(Clone, Copy)]
struct Group {
    key: ObjectKey,
    stamp: PolicyStamp,
    tokens: u16,
    window: u64,
    used: u16,
    recovery_used: u16,
}
#[derive(Clone, Copy)]
struct Receipt {
    request: SpawnRequest,
    state: SpawnState,
    sequence: u64,
    submitted: u64,
    occupied: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpawnStats {
    pub pending: u16,
    pub live: u16,
    pub recovery_pending: u16,
    pub recovery_live: u16,
    pub submitted: u64,
    pub created: u64,
    pub rejected: u64,
    pub cancelled: u64,
    pub duplicates: u64,
    pub wait_ns: u64,
}
pub struct SpawnAdmission {
    groups: [Option<Group>; MAX_GROUPS],
    receipts: [Option<Receipt>; RECEIPTS],
    sequence: u64,
    last_now: u64,
    stats: SpawnStats,
}
impl Default for SpawnAdmission {
    fn default() -> Self {
        Self::new()
    }
}
impl SpawnAdmission {
    pub const fn new() -> Self {
        Self {
            groups: [None; MAX_GROUPS],
            receipts: [None; RECEIPTS],
            sequence: 0,
            last_now: 0,
            stats: SpawnStats {
                pending: 0,
                live: 0,
                recovery_pending: 0,
                recovery_live: 0,
                submitted: 0,
                created: 0,
                rejected: 0,
                cancelled: 0,
                duplicates: 0,
                wait_ns: 0,
            },
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        self.last_now = now;
        Ok(())
    }
    fn group(&self, key: ObjectKey) -> Result<usize, Error> {
        self.groups
            .iter()
            .position(|g| g.is_some_and(|g| g.key == key))
            .ok_or(Error::Stale)
    }
    fn receipt(&self, caller: ObjectKey, id: u64) -> Result<usize, Error> {
        self.receipts
            .iter()
            .position(|r| {
                r.is_some_and(|r| r.request.caller == caller && r.request.request_id == id)
            })
            .ok_or(Error::NotFound)
    }
    fn refresh(g: &mut Group, now: u64) {
        if g.window != now / WINDOW_NS {
            g.window = now / WINDOW_NS;
            g.used = 0;
            g.recovery_used = 0;
        }
    }
    fn limit(g: Group, now: u64) -> u16 {
        if g.stamp.live(now) { g.tokens } else { 2 }
    }
    pub fn register_group(&mut self, key: ObjectKey) -> Result<(), Error> {
        valid_key(key)?;
        if self.groups.iter().flatten().any(|g| g.key.id == key.id) {
            return Err(Error::Exists);
        }
        *self
            .groups
            .iter_mut()
            .find(|g| g.is_none())
            .ok_or(Error::Capacity)? = Some(Group {
            key,
            stamp: UNSET,
            tokens: 2,
            window: u64::MAX,
            used: 0,
            recovery_used: 0,
        });
        Ok(())
    }
    pub fn install_tokens(
        &mut self,
        key: ObjectKey,
        tokens: u16,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        Action::SpawnTokens(tokens).validate()?;
        let i = self.group(key)?;
        let g = self.groups[i].as_mut().ok_or(Error::Stale)?;
        g.stamp.accepts(stamp, now)?;
        if stamp.version == g.stamp.version && tokens != g.tokens {
            return Err(Error::Conflict);
        }
        Self::refresh(g, now);
        g.stamp = stamp;
        g.tokens = tokens;
        Ok(())
    }
    pub fn submit(
        &mut self,
        request: SpawnRequest,
        now: u64,
        backend: &mut impl TaskBackend,
    ) -> Result<SpawnState, Error> {
        // Stable receipts are authoritative even after policy/authorization
        // changes. A repeated key can never be used to execute a new request.
        if let Ok(i) = self.receipt(request.caller, request.request_id) {
            let r = self.receipts[i].ok_or(Error::Stale)?;
            if r.request != request {
                return Err(Error::Conflict);
            }
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
            return Ok(r.state);
        }
        self.time(now)?;
        valid_key(request.caller)?;
        valid_key(request.package)?;
        self.group(request.group)?;
        if request.request_id == 0 {
            return Err(Error::Format);
        }
        backend.authorize(&request)?;
        let pending = self
            .receipts
            .iter()
            .flatten()
            .filter(|r| r.request.recovery == request.recovery && r.state == SpawnState::Queued)
            .count();
        if pending
            >= if request.recovery {
                RECOVERY_SPAWNS
            } else {
                MAX_SPAWNS
            }
        {
            return Err(Error::Again);
        }
        let range = if request.recovery {
            NORMAL_RECEIPTS..RECEIPTS
        } else {
            0..NORMAL_RECEIPTS
        };
        let slot = range
            .into_iter()
            .find(|i| self.receipts[*i].is_none())
            .ok_or(Error::Capacity)?;
        let sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        self.receipts[slot] = Some(Receipt {
            request,
            state: SpawnState::Queued,
            sequence,
            submitted: now,
            occupied: false,
        });
        self.sequence = sequence;
        self.stats.submitted = self.stats.submitted.saturating_add(1);
        Ok(SpawnState::Queued)
    }
    pub fn query(&self, caller: ObjectKey, id: u64) -> Result<SpawnState, Error> {
        Ok(self.receipts[self.receipt(caller, id)?]
            .ok_or(Error::Stale)?
            .state)
    }
    pub fn request(&self, caller: ObjectKey, id: u64) -> Result<SpawnRequest, Error> {
        Ok(self.receipts[self.receipt(caller, id)?]
            .ok_or(Error::Stale)?
            .request)
    }
    pub fn cancel(&mut self, caller: ObjectKey, id: u64) -> Result<SpawnState, Error> {
        let i = self.receipt(caller, id)?;
        let r = self.receipts[i].as_mut().ok_or(Error::Stale)?;
        match r.state {
            SpawnState::Queued => {
                r.state = SpawnState::Cancelled;
                self.stats.cancelled = self.stats.cancelled.saturating_add(1);
            }
            SpawnState::Unknown => return Err(Error::Busy),
            _ => {}
        }
        Ok(r.state)
    }
    pub fn service_one(
        &mut self,
        now: u64,
        backend: &mut impl TaskBackend,
    ) -> Result<Option<(SpawnRequest, SpawnState)>, Error> {
        self.time(now)?;
        for group in self.groups.iter_mut().flatten() {
            Self::refresh(group, now);
        }
        let normal = self
            .receipts
            .iter()
            .flatten()
            .filter(|r| r.occupied && !r.request.recovery)
            .count();
        let recovery = self
            .receipts
            .iter()
            .flatten()
            .filter(|r| r.occupied && r.request.recovery)
            .count();
        let mut selected: Option<usize> = None;
        for (i, r) in self
            .receipts
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|r| (i, r)))
        {
            if r.state != SpawnState::Queued
                || (if r.request.recovery {
                    recovery >= RECOVERY_SPAWNS
                } else {
                    normal >= MAX_THREADS
                })
            {
                continue;
            }
            let g = self.groups[self.group(r.request.group)?].ok_or(Error::Stale)?;
            // Recovery owns separate slots and per-group creation tokens; normal
            // queue saturation cannot consume that admission capacity.
            if if r.request.recovery {
                g.recovery_used >= 2
            } else {
                g.used >= Self::limit(g, now)
            } {
                continue;
            }
            if selected
                .is_none_or(|prior| self.receipts[prior].is_some_and(|p| r.sequence < p.sequence))
            {
                selected = Some(i);
            }
        }
        let Some(i) = selected else {
            return Ok(None);
        };
        let request = self.receipts[i].ok_or(Error::Stale)?.request;
        if let Err(error) = backend.authorize(&request) {
            self.receipts[i].as_mut().ok_or(Error::Stale)?.state = SpawnState::Failed(error);
            self.stats.rejected = self.stats.rejected.saturating_add(1);
            return Ok(Some((request, SpawnState::Failed(error))));
        }
        let gi = self.group(request.group)?;
        let group = self.groups[gi].as_mut().ok_or(Error::Stale)?;
        if request.recovery {
            group.recovery_used += 1;
        } else {
            group.used += 1;
        }
        let r = self.receipts[i].as_mut().ok_or(Error::Stale)?;
        r.state = SpawnState::Unknown;
        r.occupied = true;
        let outcome = backend.create(&request);
        if outcome == CreateOutcome::Deferred {
            // Only this synchronous no-custody outcome may undo the placeholder.
            // No construction token was used. Keep the original submission,
            // request, FIFO sequence, and external deadline intact.
            r.state = SpawnState::Queued;
            r.occupied = false;
            if request.recovery {
                group.recovery_used -= 1;
            } else {
                group.used -= 1;
            }
            return Ok(Some((request, SpawnState::Queued)));
        }
        self.stats.wait_ns = self
            .stats
            .wait_ns
            .saturating_add(now.saturating_sub(r.submitted));
        let state = self.finish(i, outcome)?;
        Ok(Some((request, state)))
    }
    fn finish(&mut self, i: usize, outcome: CreateOutcome) -> Result<SpawnState, Error> {
        let r = self.receipts[i].as_mut().ok_or(Error::Stale)?;
        match outcome {
            // An asynchronous/unknown attempt cannot prove that it never began.
            CreateOutcome::Deferred => return Err(Error::Conflict),
            CreateOutcome::Created(key) => {
                if valid_key(key).is_err() {
                    return Ok(SpawnState::Unknown);
                }
                r.state = SpawnState::Created(key);
                self.stats.created = self.stats.created.saturating_add(1);
            }
            CreateOutcome::Rejected(error) => {
                r.state = SpawnState::Failed(error);
                r.occupied = false;
                self.stats.rejected = self.stats.rejected.saturating_add(1);
            }
            CreateOutcome::Uncertain => {}
        }
        Ok(r.state)
    }
    /// Only a trusted backend reconciler may supply a definitive outcome after
    /// proving whether construction occurred or proving all resources stopped.
    pub fn reconcile(
        &mut self,
        caller: ObjectKey,
        id: u64,
        outcome: CreateOutcome,
    ) -> Result<SpawnState, Error> {
        let i = self.receipt(caller, id)?;
        if self.receipts[i].is_none_or(|r| r.state != SpawnState::Unknown) {
            return Err(Error::Conflict);
        }
        self.finish(i, outcome)
    }
    pub fn exited(&mut self, key: ObjectKey) -> Result<(), Error> {
        let r = self
            .receipts
            .iter_mut()
            .flatten()
            .find(|r| r.state == SpawnState::Created(key))
            .ok_or(Error::NotFound)?;
        r.occupied = false;
        Ok(())
    }
    pub fn tokens(&self, key: ObjectKey, now: u64) -> Result<u16, Error> {
        Ok(Self::limit(
            self.groups[self.group(key)?].ok_or(Error::Stale)?,
            now,
        ))
    }
    pub fn queued(&self, key: ObjectKey) -> Result<usize, Error> {
        self.group(key)?;
        Ok(self
            .receipts
            .iter()
            .flatten()
            .filter(|r| r.request.group == key && r.state == SpawnState::Queued)
            .count())
    }
    /// Retire receipts only after the protected caller generation has closed
    /// admission and acknowledged every terminal result. The caller owner must
    /// never authorize this generation again. Live/uncertain custody blocks the
    /// whole operation; no partial purge can hide an unresolved task.
    pub fn retire_closed_caller(&mut self, caller: ObjectKey) -> Result<usize, Error> {
        valid_key(caller)?;
        if self.receipts.iter().flatten().any(|r| {
            r.request.caller == caller
                && (r.occupied || matches!(r.state, SpawnState::Queued | SpawnState::Unknown))
        }) {
            return Err(Error::Busy);
        }
        let mut count = 0;
        for r in &mut self.receipts {
            if r.is_some_and(|r| r.request.caller == caller) {
                *r = None;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn stats(&self) -> SpawnStats {
        let mut stats = self.stats;
        for r in self.receipts.iter().flatten() {
            if r.request.recovery {
                stats.recovery_pending += u16::from(r.state == SpawnState::Queued);
                stats.recovery_live += u16::from(r.occupied);
            } else {
                stats.pending += u16::from(r.state == SpawnState::Queued);
                stats.live += u16::from(r.occupied);
            }
        }
        stats
    }
}
