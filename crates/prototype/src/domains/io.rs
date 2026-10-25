//! Bounded I/O admission with independent completion custody and byte escrow.
//! Submission callbacks publish real work. Completion never consults a policy.
use super::{Action, Error, ObjectKey, PolicyStamp, WINDOW_NS};

pub const QUEUE_CAPACITY: usize = 256;
pub const COMPLETION_CREDITS: u16 = 64;
pub const ORDINARY_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: u32 = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Foreground,
    Background,
    Recovery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub object: ObjectKey,
    pub class: Class,
    pub bytes: u32,
    pub pages: u32,
    pub descriptors: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    pub slot: u16,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    Accepted,
    Deferred,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Reserved,
    Queued,
    Inflight,
    Unknown,
    Complete(Result<(), Error>),
}
#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    order: u64,
    request: Request,
    state: State,
    queued_at: u64,
    completed_at: u64,
    version: u64,
    reservation: Option<u64>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub queued: u16,
    pub inflight: u16,
    pub completed: u16,
    pub submit_credits: u16,
    pub ordinary_credits: u16,
    pub recovery_credits: u16,
    pub pages: u32,
    pub descriptors: u32,
    pub foreground_bytes: u64,
    pub background_bytes: u64,
    pub recovery_bytes: u64,
    pub borrowed_foreground_bytes: u64,
    pub borrowed_background_bytes: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub submitted: u64,
    pub completed: u64,
    pub errors: u64,
    pub cancelled: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub object: ObjectKey,
    pub result: Result<(), Error>,
    pub bytes: u32,
    pub latency_ns: u64,
    pub policy_version: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytePermit {
    generation: u64,
}
/// A real upstream allocation for a future bounded transaction. The queue
/// slot, DMA capacity and both ordinary credits are owned, but no device
/// submission or completion has occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub permit: BytePermit,
    pub ticket: Ticket,
    pub bytes: u64,
    pub policy_version: u64,
}
#[derive(Clone, Copy)]
struct Escrow {
    generation: u64,
    class: Class,
    remaining: u64,
    version: u64,
    share: u16,
}

pub struct Scheduler {
    slots: [Option<Slot>; QUEUE_CAPACITY],
    generations: [u64; QUEUE_CAPACITY],
    order: u64,
    page_capacity: u32,
    descriptor_capacity: u32,
    recovery_pages: u32,
    recovery_descriptors: u32,
    usage: Usage,
    stats: Stats,
    stamp: PolicyStamp,
    share: u16,
    window: Option<u64>,
    window_share: u16,
    window_version: u64,
    window_until: u64,
    last_ns: u64,
    escrow: Option<Escrow>,
    escrow_generation: u64,
    upstream: [bool; 2],
}
impl Scheduler {
    pub const fn new(pages: u32, descriptors: u32) -> Self {
        Self {
            slots: [None; QUEUE_CAPACITY],
            generations: [0; QUEUE_CAPACITY],
            order: 0,
            page_capacity: pages,
            descriptor_capacity: descriptors,
            recovery_pages: pages / 4,
            recovery_descriptors: descriptors / 4,
            usage: Usage {
                queued: 0,
                inflight: 0,
                completed: 0,
                submit_credits: 0,
                ordinary_credits: 0,
                recovery_credits: 0,
                pages: 0,
                descriptors: 0,
                foreground_bytes: 0,
                background_bytes: 0,
                recovery_bytes: 0,
                borrowed_foreground_bytes: 0,
                borrowed_background_bytes: 0,
            },
            stats: Stats {
                submitted: 0,
                completed: 0,
                errors: 0,
                cancelled: 0,
            },
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            share: 250,
            window: None,
            window_share: 250,
            window_version: 0,
            window_until: 0,
            last_ns: 0,
            escrow: None,
            escrow_generation: 0,
            upstream: [false; 2],
        }
    }
    /// The serialized block owner reports real upstream ordinary work before
    /// each new admission. It must retain true while that class has validated
    /// disk work waiting above this queue; unknown observations also forbid
    /// borrowing. This changes neither credits nor already issued escrow.
    pub fn set_upstream_demand(&mut self, foreground: bool, background: bool) {
        self.upstream = [foreground, background];
    }
    fn upstream_other(&self, class: Class) -> bool {
        match class {
            Class::Foreground => self.upstream[1],
            Class::Background => self.upstream[0],
            Class::Recovery => false,
        }
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_ns {
            return Err(Error::Range);
        }
        self.last_ns = now;
        let window = now / WINDOW_NS;
        if self.window != Some(window) {
            self.window = Some(window);
            (self.window_share, self.window_version) = if self.stamp.live(now) {
                (self.share, self.stamp.version)
            } else {
                (250, 0)
            };
            self.window_until = self.stamp.installed_until_ns;
            self.usage.foreground_bytes = 0;
            self.usage.background_bytes = 0;
            self.usage.recovery_bytes = 0;
            self.usage.borrowed_foreground_bytes = 0;
            self.usage.borrowed_background_bytes = 0;
        }
        if self.window_version != 0 && now >= self.window_until {
            self.window_share = 250;
            self.window_version = 0;
        }
        Ok(())
    }
    pub fn apply(&mut self, action: Action, stamp: PolicyStamp, now: u64) -> Result<(), Error> {
        self.validate_apply(action, stamp, now)?;
        let Action::IoShare(share) = action else {
            return Err(Error::Schema);
        };
        self.stamp = stamp;
        self.share = share;
        Ok(())
    }
    pub fn validate_apply(
        &self,
        action: Action,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        action.validate()?;
        let Action::IoShare(share) = action else {
            return Err(Error::Schema);
        };
        self.stamp.accepts(stamp, now)?;
        if self.stamp == stamp && self.share != share {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn current_action(&self, now: u64) -> Action {
        Action::IoShare(if self.window == Some(now / WINDOW_NS) {
            if self.window_version != 0 && now >= self.window_until {
                250
            } else {
                self.window_share
            }
        } else if self.stamp.live(now) {
            self.share
        } else {
            250
        })
    }
    /// Validity of a read-only copy of current_action. Window transitions and
    /// TTL can change it without a new policy installation; no grant is made.
    pub fn control_view_until_ns(&self, now: u64) -> Result<u64, Error> {
        let next_window = (now / WINDOW_NS)
            .checked_add(1)
            .and_then(|v| v.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        let policy_end = if self.window == Some(now / WINDOW_NS) {
            if self.window_version != 0 {
                self.window_until
            } else {
                0
            }
        } else {
            self.stamp.installed_until_ns
        };
        Ok(if policy_end > now {
            next_window.min(policy_end)
        } else {
            next_window
        })
    }
    pub fn usage(&self) -> Usage {
        self.usage
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn reserved_bytes(&self) -> u64 {
        self.escrow.map_or(0, |e| e.remaining)
    }
    pub fn recovery_reserve(&mut self, pages: u32, descriptors: u32) -> Result<(), Error> {
        if self.slots.iter().any(Option::is_some) {
            return Err(Error::Busy);
        }
        if pages == 0
            || descriptors == 0
            || pages > self.page_capacity
            || descriptors > self.descriptor_capacity
        {
            return Err(Error::Capacity);
        }
        self.recovery_pages = pages;
        self.recovery_descriptors = descriptors;
        Ok(())
    }
    /// Configure the real pinned device pool before any request is admitted.
    /// This supports initialization in static storage without a large stack copy.
    pub fn configure_capacity(&mut self, pages: u32, descriptors: u32) -> Result<(), Error> {
        if pages == 0 || descriptors == 0 {
            return Err(Error::Capacity);
        }
        if self.slots.iter().any(Option::is_some) || self.escrow.is_some() {
            return Err(Error::Busy);
        }
        self.page_capacity = pages;
        self.descriptor_capacity = descriptors;
        self.recovery_pages = pages / 4;
        self.recovery_descriptors = descriptors / 4;
        Ok(())
    }
    fn allowance(&self, class: Class, bytes: u64, other: bool) -> bool {
        if class == Class::Recovery {
            return true;
        }
        let total =
            self.usage.foreground_bytes + self.usage.background_bytes + self.reserved_bytes();
        if bytes > ORDINARY_BYTES.saturating_sub(total) {
            return false;
        }
        let bg = ORDINARY_BYTES * u64::from(self.window_share) / 1000;
        let (used, share) = if class == Class::Background {
            (self.usage.background_bytes, bg)
        } else {
            (self.usage.foreground_bytes, ORDINARY_BYTES - bg)
        };
        let reserved = self
            .escrow
            .filter(|e| e.class == class)
            .map_or(0, |e| e.remaining);
        !(other || self.upstream_other(class)) || bytes <= share.saturating_sub(used + reserved)
    }
    pub fn reserve_transaction(
        &mut self,
        class: Class,
        bytes: u64,
        now: u64,
    ) -> Result<BytePermit, Error> {
        self.clock(now)?;
        if class == Class::Recovery || bytes == 0 || bytes > ORDINARY_BYTES {
            return Err(Error::Range);
        }
        if self.escrow.is_some() {
            return Err(Error::Busy);
        }
        let other = self.slots.iter().flatten().any(|s| {
            s.state == State::Queued
                && s.request.class != class
                && s.request.class != Class::Recovery
        });
        if !self.allowance(class, bytes, other) {
            return Err(Error::Budget);
        }
        self.escrow_generation = self
            .escrow_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.escrow = Some(Escrow {
            generation: self.escrow_generation,
            class,
            remaining: bytes,
            version: self.window_version,
            share: self.window_share,
        });
        Ok(BytePermit {
            generation: self.escrow_generation,
        })
    }
    pub fn finish_transaction(&mut self, permit: BytePermit) -> Result<(), Error> {
        let e = self
            .escrow
            .filter(|e| e.generation == permit.generation)
            .ok_or(Error::Stale)?;
        if e.remaining != 0
            || self
                .slots
                .iter()
                .flatten()
                .any(|s| s.reservation == Some(permit.generation))
        {
            return Err(Error::Busy);
        }
        self.escrow = None;
        Ok(())
    }
    /// Allocate bytes and the first genuine send/completion/DMA slot before
    /// downstream admission. The expected version must already govern this
    /// aligned byte window; installing a future parameter alone cannot earn
    /// a resource receipt.
    pub fn reserve_admission(
        &mut self,
        first: Request,
        bytes: u64,
        expected_version: u64,
        now: u64,
    ) -> Result<Admission, Error> {
        if first.class == Class::Recovery || first.bytes == 0 || bytes < u64::from(first.bytes) {
            return Err(Error::Format);
        }
        self.clock(now)?;
        if self.window_version != expected_version {
            return Err(Error::Again);
        }
        let permit = self.reserve_transaction(first.class, bytes, now)?;
        let ticket = match self.enqueue_transaction(first, permit, now) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.escrow = None;
                return Err(error);
            }
        };
        self.slots[usize::from(ticket.slot)].as_mut().unwrap().state = State::Reserved;
        self.usage.queued -= 1;
        Ok(Admission {
            permit,
            ticket,
            bytes,
            policy_version: self.window_version,
        })
    }
    fn held_admission(&self, admission: Admission) -> Result<(&Slot, Escrow), Error> {
        let slot = self.slot(admission.ticket)?;
        let escrow = self
            .escrow
            .filter(|e| e.generation == admission.permit.generation)
            .ok_or(Error::Stale)?;
        if slot.state != State::Reserved
            || slot.reservation != Some(escrow.generation)
            || escrow.class != slot.request.class
            || escrow.version != admission.policy_version
        {
            return Err(Error::Busy);
        }
        Ok((slot, escrow))
    }
    /// The selected closure can be smaller than the reserved upper bound.
    /// Return only unused, never submitted bytes while retaining all credits.
    pub fn begin_admission(&mut self, admission: Admission, bytes: u64) -> Result<(), Error> {
        let (slot, escrow) = self.held_admission(admission)?;
        if bytes < u64::from(slot.request.bytes)
            || bytes > escrow.remaining
            || escrow.remaining != admission.bytes
        {
            return Err(Error::Budget);
        }
        self.escrow.as_mut().unwrap().remaining = bytes;
        Ok(())
    }
    /// Bind the already owned first slot to its actual device request.
    pub fn activate_admission(
        &mut self,
        admission: Admission,
        request: Request,
        now: u64,
    ) -> Result<Ticket, Error> {
        self.clock(now)?;
        let (slot, escrow) = self.held_admission(admission)?;
        if request != slot.request || u64::from(request.bytes) > escrow.remaining {
            return Err(Error::Conflict);
        }
        let slot = self.slots[usize::from(admission.ticket.slot)]
            .as_mut()
            .unwrap();
        slot.state = State::Queued;
        slot.queued_at = now;
        self.usage.queued += 1;
        Ok(admission.ticket)
    }
    /// Cancellation is possible only before the first request is published.
    /// A queued/inflight/unknown/completed request still owns its resources.
    pub fn cancel_admission(&mut self, admission: Admission) -> Result<(), Error> {
        let (_, escrow) = self.held_admission(admission)?;
        if escrow.remaining != admission.bytes
            || self.slots.iter().enumerate().any(|(i, s)| {
                i != usize::from(admission.ticket.slot)
                    && s.is_some_and(|s| s.reservation == Some(escrow.generation))
            })
        {
            return Err(Error::Busy);
        }
        self.usage.submit_credits -= 1;
        self.release(admission.ticket);
        self.escrow = None;
        Ok(())
    }
    pub fn reserved_slots(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.state == State::Reserved)
            .count()
    }
    pub fn enqueue_transaction(
        &mut self,
        request: Request,
        permit: BytePermit,
        now: u64,
    ) -> Result<Ticket, Error> {
        let e = self
            .escrow
            .filter(|e| e.generation == permit.generation && e.class == request.class)
            .ok_or(Error::Stale)?;
        let queued: u64 = self
            .slots
            .iter()
            .flatten()
            .filter(|s| s.state == State::Queued && s.reservation == Some(permit.generation))
            .map(|s| u64::from(s.request.bytes))
            .sum();
        if u64::from(request.bytes) > e.remaining.saturating_sub(queued) {
            return Err(Error::Budget);
        }
        self.enqueue_inner(request, now, Some(permit.generation))
    }
    pub fn enqueue(&mut self, request: Request, now: u64) -> Result<Ticket, Error> {
        self.enqueue_inner(request, now, None)
    }
    fn enqueue_inner(
        &mut self,
        r: Request,
        now: u64,
        reservation: Option<u64>,
    ) -> Result<Ticket, Error> {
        self.clock(now)?;
        if r.object.generation == 0
            || r.descriptors == 0
            || r.bytes > MAX_REQUEST_BYTES
            || (r.bytes != 0 && r.pages == 0)
        {
            return Err(Error::Format);
        }
        let recovery = r.class == Class::Recovery;
        let normal_pages: u32 = self
            .slots
            .iter()
            .flatten()
            .filter(|s| s.request.class != Class::Recovery)
            .map(|s| s.request.pages)
            .sum();
        let normal_descriptors: u32 = self
            .slots
            .iter()
            .flatten()
            .filter(|s| s.request.class != Class::Recovery)
            .map(|s| u32::from(s.request.descriptors))
            .sum();
        if (!recovery && self.usage.submit_credits == COMPLETION_CREDITS)
            || (if recovery {
                self.usage.recovery_credits
            } else {
                self.usage.ordinary_credits
            }) == COMPLETION_CREDITS
            || r.pages > self.page_capacity.saturating_sub(self.usage.pages)
            || u32::from(r.descriptors)
                > self
                    .descriptor_capacity
                    .saturating_sub(self.usage.descriptors)
            || (!recovery
                && (r.pages
                    > self
                        .page_capacity
                        .saturating_sub(self.recovery_pages)
                        .saturating_sub(normal_pages)
                    || u32::from(r.descriptors)
                        > self
                            .descriptor_capacity
                            .saturating_sub(self.recovery_descriptors)
                            .saturating_sub(normal_descriptors)))
        {
            return Err(Error::Again);
        }
        let at = self
            .slots
            .iter()
            .enumerate()
            .position(|(i, s)| s.is_none() && self.generations[i] != u64::MAX)
            .ok_or(Error::Capacity)?;
        self.order = self.order.checked_add(1).ok_or(Error::Overflow)?;
        self.generations[at] += 1;
        self.slots[at] = Some(Slot {
            generation: self.generations[at],
            order: self.order,
            request: r,
            state: State::Queued,
            queued_at: now,
            completed_at: 0,
            version: 0,
            reservation,
        });
        self.usage.queued += 1;
        self.usage.pages += r.pages;
        self.usage.descriptors += u32::from(r.descriptors);
        if recovery {
            self.usage.recovery_credits += 1;
        } else {
            self.usage.submit_credits += 1;
            self.usage.ordinary_credits += 1;
        }
        Ok(Ticket {
            slot: at as u16,
            generation: self.generations[at],
        })
    }
    fn slot(&self, t: Ticket) -> Result<&Slot, Error> {
        self.slots
            .get(usize::from(t.slot))
            .and_then(Option::as_ref)
            .filter(|s| s.generation == t.generation)
            .ok_or(Error::Stale)
    }
    fn permitted(&self, at: usize, other: bool) -> bool {
        let s = self.slots[at].unwrap();
        if let Some(id) = s.reservation {
            return self.escrow.is_some_and(|e| {
                e.generation == id
                    && e.class == s.request.class
                    && e.remaining >= u64::from(s.request.bytes)
            });
        }
        self.allowance(s.request.class, u64::from(s.request.bytes), other)
    }
    pub fn dispatch(
        &mut self,
        now: u64,
        mut ready: impl FnMut(Ticket, &Request) -> bool,
        mut submit: impl FnMut(Ticket, &Request) -> Submission,
    ) -> Result<Option<Ticket>, Error> {
        self.clock(now)?;
        let mut candidates: [Option<usize>; 3] = [None; 3];
        for (i, s) in self.slots.iter().enumerate() {
            let Some(s) = s else {
                continue;
            };
            if s.state != State::Queued
                || !ready(
                    Ticket {
                        slot: i as u16,
                        generation: s.generation,
                    },
                    &s.request,
                )
            {
                continue;
            }
            let c = match s.request.class {
                Class::Recovery => 0,
                Class::Foreground => 1,
                Class::Background => 2,
            };
            if candidates[c].is_none_or(|old| self.slots[old].unwrap().order > s.order) {
                candidates[c] = Some(i);
            }
        }
        let selected = candidates[0].or_else(|| {
            let fg = candidates[1].filter(|&i| self.permitted(i, candidates[2].is_some()));
            let bg = candidates[2].filter(|&i| self.permitted(i, candidates[1].is_some()));
            match (fg, bg) {
                (Some(a), Some(b)) => Some(
                    if self.slots[a].unwrap().order < self.slots[b].unwrap().order {
                        a
                    } else {
                        b
                    },
                ),
                (a, b) => a.or(b),
            }
        });
        let Some(at) = selected else {
            return Ok(None);
        };
        let s = self.slots[at].as_mut().unwrap();
        let ticket = Ticket {
            slot: at as u16,
            generation: s.generation,
        };
        let sent = submit(ticket, &s.request);
        if sent == Submission::Deferred {
            return Ok(None);
        }
        s.state = if sent == Submission::Accepted {
            State::Inflight
        } else {
            State::Unknown
        };
        let escrow = self.escrow.filter(|e| Some(e.generation) == s.reservation);
        // Only an ordinary nonzero byte admission exercises IoShare. Recovery
        // and zero-byte barriers must never create its APPLIED receipt.
        s.version = if s.request.class == Class::Recovery || s.request.bytes == 0 {
            0
        } else {
            escrow.map_or(self.window_version, |e| e.version)
        };
        let share = escrow.map_or(self.window_share, |e| e.share);
        if let Some(e) = self
            .escrow
            .as_mut()
            .filter(|e| Some(e.generation) == s.reservation)
        {
            e.remaining -= u64::from(s.request.bytes);
        }
        self.usage.queued -= 1;
        self.usage.inflight += 1;
        self.stats.submitted += 1;
        if s.request.class != Class::Recovery {
            self.usage.submit_credits -= 1;
        }
        let bytes = u64::from(s.request.bytes);
        let bg = ORDINARY_BYTES * u64::from(share) / 1000;
        match s.request.class {
            Class::Recovery => {
                self.usage.recovery_bytes = self.usage.recovery_bytes.saturating_add(bytes)
            }
            Class::Foreground => {
                let before = self.usage.foreground_bytes;
                self.usage.foreground_bytes += bytes;
                self.usage.borrowed_foreground_bytes += self
                    .usage
                    .foreground_bytes
                    .saturating_sub(ORDINARY_BYTES - bg)
                    - before.saturating_sub(ORDINARY_BYTES - bg);
            }
            Class::Background => {
                let before = self.usage.background_bytes;
                self.usage.background_bytes += bytes;
                self.usage.borrowed_background_bytes +=
                    self.usage.background_bytes.saturating_sub(bg) - before.saturating_sub(bg);
            }
        }
        Ok(Some(ticket))
    }
    pub fn complete(
        &mut self,
        t: Ticket,
        result: Result<(), Error>,
        now: u64,
    ) -> Result<(), Error> {
        let s = *self.slot(t)?;
        if !matches!(s.state, State::Inflight | State::Unknown) {
            return Err(Error::Conflict);
        }
        if now < s.queued_at {
            return Err(Error::Range);
        }
        let s = self.slots[usize::from(t.slot)].as_mut().unwrap();
        s.state = State::Complete(result);
        s.completed_at = now;
        self.usage.inflight -= 1;
        self.usage.completed += 1;
        self.stats.completed += 1;
        if result.is_err() {
            self.stats.errors += 1;
        }
        Ok(())
    }
    pub fn completion(&self, t: Ticket) -> Result<Option<Completion>, Error> {
        let s = self.slot(t)?;
        let State::Complete(result) = s.state else {
            return Ok(None);
        };
        Ok(Some(Completion {
            object: s.request.object,
            result,
            bytes: s.request.bytes,
            latency_ns: s.completed_at - s.queued_at,
            policy_version: s.version,
        }))
    }
    fn release(&mut self, t: Ticket) {
        let s = self.slots[usize::from(t.slot)].take().unwrap();
        self.usage.pages -= s.request.pages;
        self.usage.descriptors -= u32::from(s.request.descriptors);
        if s.request.class == Class::Recovery {
            self.usage.recovery_credits -= 1;
        } else {
            self.usage.ordinary_credits -= 1;
        }
    }
    pub fn acknowledge(&mut self, t: Ticket) -> Result<Completion, Error> {
        let result = self.completion(t)?.ok_or(Error::Busy)?;
        self.release(t);
        self.usage.completed -= 1;
        Ok(result)
    }
    pub fn cancel(&mut self, t: Ticket) -> Result<(), Error> {
        let s = *self.slot(t)?;
        if s.state != State::Queued {
            return Err(Error::Busy);
        }
        self.usage.queued -= 1;
        if s.request.class != Class::Recovery {
            self.usage.submit_credits -= 1;
        }
        self.release(t);
        self.stats.cancelled += 1;
        Ok(())
    }
}
