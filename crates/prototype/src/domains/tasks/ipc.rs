use super::{EMPTY_KEY, MAX_ENDPOINTS, MAX_MESSAGES, UNSET, valid_key};
use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

pub const RECOVERY_ENDPOINTS: usize = 2;
const ENDPOINTS: usize = MAX_ENDPOINTS + RECOVERY_ENDPOINTS;
const NORMAL_WAITERS: usize = 64;
const WAITERS: usize = NORMAL_WAITERS + 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcOperation {
    Send,
    Receive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<const B: usize> {
    pub sender: ObjectKey,
    pub request_id: u64,
    pub sequence: u64,
    pub len: usize,
    pub bytes: [u8; B],
}
impl<const B: usize> Message<B> {
    const EMPTY: Self = Self {
        sender: EMPTY_KEY,
        request_id: 0,
        sequence: 0,
        len: 0,
        bytes: [0; B],
    };
    fn new(sender: ObjectKey, request_id: u64, data: &[u8]) -> Result<Self, Error> {
        valid_key(sender)?;
        if B == 0 || data.len() > B || request_id == 0 {
            return Err(Error::Range);
        }
        let mut m = Self {
            sender,
            request_id,
            len: data.len(),
            ..Self::EMPTY
        };
        m.bytes[..data.len()].copy_from_slice(data);
        Ok(m)
    }
}
pub trait IpcBackend<const B: usize> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        operation: IpcOperation,
    ) -> Result<(), Error>;
    /// Wake delivery may fail transiently. Executors retain pending notices and
    /// retry without needing another policy evaluation.
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error>;
    /// Copy/transfer to an actual receiver. Err must leave the receiver without
    /// the message; the executor retains its head until successful delivery.
    fn deliver(
        &mut self,
        receiver: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<B>,
    ) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcStats {
    pub depth: usize,
    pub admitted: u64,
    pub delivered: u64,
    pub notifications: u64,
    pub notification_failures: u64,
    pub blocked: u64,
    pub waiting_ns: u64,
    pub receive_wait_ns: u64,
}
struct Endpoint {
    key: ObjectKey,
    owner: ObjectKey,
    recovery: bool,
    stamp: PolicyStamp,
    applied_version: u64,
    budget: usize,
    batch: usize,
    sequence: u64,
    head: usize,
    len: usize,
    wake: bool,
    stats: IpcStats,
    since: [u64; MAX_MESSAGES],
}
impl Endpoint {
    const fn new(key: ObjectKey, owner: ObjectKey, recovery: bool) -> Self {
        Self {
            key,
            owner,
            recovery,
            stamp: UNSET,
            applied_version: 0,
            budget: 32,
            batch: 4,
            sequence: 0,
            head: 0,
            len: 0,
            wake: false,
            stats: IpcStats {
                depth: 0,
                admitted: 0,
                delivered: 0,
                notifications: 0,
                notification_failures: 0,
                blocked: 0,
                waiting_ns: 0,
                receive_wait_ns: 0,
            },
            since: [0; MAX_MESSAGES],
        }
    }
    fn limits(&self, now: u64) -> (usize, usize) {
        if self.recovery {
            (MAX_MESSAGES, 16)
        } else if self.stamp.live(now) {
            (self.budget, self.batch)
        } else {
            (32, 4)
        }
    }
    fn enqueue<const B: usize>(
        &mut self,
        messages: &mut [Message<B>; MAX_MESSAGES],
        mut m: Message<B>,
        now: u64,
    ) -> Result<u64, Error> {
        if self.len >= self.limits(now).0 {
            return Err(Error::Again);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        m.sequence = sequence;
        messages[(self.head + self.len) % MAX_MESSAGES] = m;
        self.since[(self.head + self.len) % MAX_MESSAGES] = now;
        if self.len == 0 {
            self.wake = true;
        }
        self.len += 1;
        self.sequence = sequence;
        self.stats.admitted = self.stats.admitted.saturating_add(1);
        if self.stamp.live(now) {
            self.applied_version = self.stamp.version;
        }
        Ok(sequence)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTicket {
    pub id: u64,
    pub endpoint: ObjectKey,
    pub sender: ObjectKey,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    Pending,
    Sent(u64),
    Cancelled,
    Failed(Error),
}
struct Waiter<const B: usize> {
    ticket: WaitTicket,
    message: Message<B>,
    state: WaitResult,
    since: u64,
    wake: bool,
}
pub struct Ipc<const BYTES: usize = 64> {
    endpoints: [Option<Endpoint>; ENDPOINTS],
    // Keep payload backing out of Endpoint so opening a slot never constructs
    // an entire 128-message queue on a bounded kernel stack. Native owners put
    // this const-initialized pool in static storage; open only sets metadata.
    messages: [[Message<BYTES>; MAX_MESSAGES]; ENDPOINTS],
    waiters: [Option<Waiter<BYTES>>; WAITERS],
    generation: u64,
    waiter_sequence: u64,
    last_now: u64,
}
impl<const B: usize> Default for Ipc<B> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const B: usize> Ipc<B> {
    pub const fn new() -> Self {
        Self {
            endpoints: [const { None }; ENDPOINTS],
            messages: [[Message::EMPTY; MAX_MESSAGES]; ENDPOINTS],
            waiters: [const { None }; WAITERS],
            generation: 0,
            waiter_sequence: 0,
            last_now: 0,
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        self.last_now = now;
        Ok(())
    }
    fn index(&self, key: ObjectKey) -> Result<usize, Error> {
        let i = key
            .id
            .checked_sub(1)
            .and_then(|i| usize::try_from(i).ok())
            .filter(|i| *i < ENDPOINTS)
            .ok_or(Error::Stale)?;
        if self.endpoints[i].as_ref().is_some_and(|e| e.key == key) {
            Ok(i)
        } else {
            Err(Error::Stale)
        }
    }
    pub fn open(&mut self, owner: ObjectKey, recovery: bool) -> Result<ObjectKey, Error> {
        valid_key(owner)?;
        if B == 0 {
            return Err(Error::Range);
        }
        let range = if recovery {
            MAX_ENDPOINTS..ENDPOINTS
        } else {
            0..MAX_ENDPOINTS
        };
        let slot = range
            .into_iter()
            .find(|i| self.endpoints[*i].is_none())
            .ok_or(Error::Capacity)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let key = ObjectKey {
            id: slot as u64 + 1,
            generation,
        };
        self.endpoints[slot] = Some(Endpoint::new(key, owner, recovery));
        self.generation = generation;
        Ok(key)
    }
    pub fn install(
        &mut self,
        key: ObjectKey,
        budget: u16,
        batch: u8,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        Action::Ipc { budget, batch }.validate()?;
        let i = self.index(key)?;
        let e = self.endpoints[i].as_mut().ok_or(Error::Stale)?;
        if e.recovery {
            return Err(Error::Auth);
        }
        e.stamp.accepts(stamp, now)?;
        if stamp.version == e.stamp.version
            && (usize::from(budget) != e.budget || usize::from(batch) != e.batch)
        {
            return Err(Error::Conflict);
        }
        e.stamp = stamp;
        e.budget = usize::from(budget);
        e.batch = usize::from(batch);
        Ok(())
    }
    fn notify_endpoint(&mut self, i: usize, backend: &mut impl IpcBackend<B>) {
        if let Some(e) = self.endpoints[i].as_mut()
            && e.wake
        {
            match backend.notify(e.owner, e.key) {
                Ok(()) => {
                    e.wake = false;
                    e.stats.notifications = e.stats.notifications.saturating_add(1);
                }
                Err(_) => {
                    e.stats.notification_failures = e.stats.notification_failures.saturating_add(1);
                }
            }
        }
    }
    pub fn flush_notifications(&mut self, backend: &mut impl IpcBackend<B>) {
        for i in 0..ENDPOINTS {
            self.notify_endpoint(i, backend);
        }
        for w in self.waiters.iter_mut().flatten() {
            if w.wake && backend.notify(w.ticket.sender, w.ticket.endpoint).is_ok() {
                w.wake = false;
            }
        }
    }
    pub fn send(
        &mut self,
        sender: ObjectKey,
        key: ObjectKey,
        request_id: u64,
        data: &[u8],
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<u64, Error> {
        self.time(now)?;
        let message = Message::new(sender, request_id, data)?;
        let i = self.index(key)?;
        backend.authorize(sender, key, IpcOperation::Send)?;
        if self
            .waiters
            .iter()
            .flatten()
            .any(|w| w.ticket.endpoint == key && w.state == WaitResult::Pending)
        {
            return Err(Error::Again);
        }
        let sequence = self.endpoints[i].as_mut().ok_or(Error::Stale)?.enqueue(
            &mut self.messages[i],
            message,
            now,
        )?;
        self.notify_endpoint(i, backend);
        // Notification failure does not turn a committed send into a retryable
        // send error. A pending notification remains independently serviceable.
        Ok(sequence)
    }
    pub fn wait_send(
        &mut self,
        sender: ObjectKey,
        key: ObjectKey,
        request_id: u64,
        data: &[u8],
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<WaitTicket, Error> {
        self.time(now)?;
        let message = Message::new(sender, request_id, data)?;
        let i = self.index(key)?;
        backend.authorize(sender, key, IpcOperation::Send)?;
        for w in self.waiters.iter().flatten() {
            if w.ticket.sender == sender
                && w.ticket.endpoint == key
                && w.message.request_id == request_id
            {
                if w.message != message {
                    return Err(Error::Conflict);
                }
                return Ok(w.ticket);
            }
        }
        let recovery = self.endpoints[i].as_ref().ok_or(Error::Stale)?.recovery;
        let range = if recovery {
            NORMAL_WAITERS..WAITERS
        } else {
            0..NORMAL_WAITERS
        };
        let slot = range
            .into_iter()
            .find(|j| self.waiters[*j].is_none())
            .ok_or(Error::Capacity)?;
        let id = self.waiter_sequence.checked_add(1).ok_or(Error::Overflow)?;
        let ticket = WaitTicket {
            id,
            endpoint: key,
            sender,
        };
        self.waiters[slot] = Some(Waiter {
            ticket,
            message,
            state: WaitResult::Pending,
            since: now,
            wake: false,
        });
        self.waiter_sequence = id;
        let e = self.endpoints[i].as_mut().ok_or(Error::Stale)?;
        e.stats.blocked = e.stats.blocked.saturating_add(1);
        self.promote(i, now, backend)?;
        Ok(ticket)
    }
    fn promote(
        &mut self,
        endpoint: usize,
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<(), Error> {
        let key = self.endpoints[endpoint].as_ref().ok_or(Error::Stale)?.key;
        for _ in 0..16 {
            let e = self.endpoints[endpoint].as_ref().ok_or(Error::Stale)?;
            if e.len >= e.limits(now).0 {
                break;
            }
            let Some(i) = self
                .waiters
                .iter()
                .enumerate()
                .filter_map(|(i, w)| w.as_ref().map(|w| (i, w)))
                .filter(|(_, w)| w.ticket.endpoint == key && w.state == WaitResult::Pending)
                .min_by_key(|(_, w)| w.ticket.id)
                .map(|(i, _)| i)
            else {
                break;
            };
            let w = self.waiters[i].as_mut().ok_or(Error::Stale)?;
            let state = match backend.authorize(w.ticket.sender, key, IpcOperation::Send) {
                Err(e) => WaitResult::Failed(e),
                Ok(()) => {
                    let e = self.endpoints[endpoint].as_mut().ok_or(Error::Stale)?;
                    match e.enqueue(&mut self.messages[endpoint], w.message, now) {
                        Ok(seq) => {
                            e.stats.waiting_ns = e
                                .stats
                                .waiting_ns
                                .saturating_add(now.saturating_sub(w.since));
                            WaitResult::Sent(seq)
                        }
                        Err(error) => WaitResult::Failed(error),
                    }
                }
            };
            w.state = state;
            w.wake = backend.notify(w.ticket.sender, key).is_err();
        }
        self.notify_endpoint(endpoint, backend);
        Ok(())
    }
    pub fn service_waiters(
        &mut self,
        key: ObjectKey,
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<(), Error> {
        self.time(now)?;
        let i = self.index(key)?;
        self.promote(i, now, backend)
    }
    pub fn cancel(
        &mut self,
        ticket: WaitTicket,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<WaitResult, Error> {
        let w = self
            .waiters
            .iter_mut()
            .flatten()
            .find(|w| w.ticket == ticket)
            .ok_or(Error::Stale)?;
        if w.state == WaitResult::Pending {
            w.state = WaitResult::Cancelled;
            w.wake = backend.notify(ticket.sender, ticket.endpoint).is_err();
        }
        Ok(w.state)
    }
    pub fn wait_result(&mut self, ticket: WaitTicket) -> Result<WaitResult, Error> {
        let i = self
            .waiters
            .iter()
            .position(|w| w.as_ref().is_some_and(|w| w.ticket == ticket))
            .ok_or(Error::Stale)?;
        let result = self.waiters[i].as_ref().ok_or(Error::Stale)?.state;
        if result != WaitResult::Pending {
            self.waiters[i] = None;
        }
        Ok(result)
    }
    pub fn receive_batch(
        &mut self,
        receiver: ObjectKey,
        key: ObjectKey,
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<usize, Error> {
        self.time(now)?;
        let i = self.index(key)?;
        let e = self.endpoints[i].as_mut().ok_or(Error::Stale)?;
        if e.owner != receiver {
            return Err(Error::Auth);
        }
        backend.authorize(receiver, key, IpcOperation::Receive)?;
        let count = e.len.min(e.limits(now).1);
        let mut delivered = 0;
        for _ in 0..count {
            let message = &self.messages[i][e.head];
            if let Err(error) = backend.deliver(receiver, key, message) {
                // Earlier items remain completed; the failing head remains in
                // FIFO order. Report progress rather than invite a batch replay.
                if delivered == 0 {
                    return Err(error);
                }
                break;
            }
            e.stats.receive_wait_ns = e
                .stats
                .receive_wait_ns
                .saturating_add(now.saturating_sub(e.since[e.head]));
            self.messages[i][e.head] = Message::EMPTY;
            e.head = (e.head + 1) % MAX_MESSAGES;
            e.len -= 1;
            e.stats.delivered = e.stats.delivered.saturating_add(1);
            if e.stamp.live(now) {
                e.applied_version = e.stamp.version;
            }
            delivered += 1;
        }
        if e.len != 0 {
            e.wake = true;
        }
        self.promote(i, now, backend)?;
        self.notify_endpoint(i, backend);
        Ok(delivered)
    }
    pub fn close(
        &mut self,
        owner: ObjectKey,
        key: ObjectKey,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<(), Error> {
        let i = self.index(key)?;
        if self.endpoints[i].as_ref().is_none_or(|e| e.owner != owner) {
            return Err(Error::Auth);
        }
        for w in self
            .waiters
            .iter_mut()
            .flatten()
            .filter(|w| w.ticket.endpoint == key)
        {
            if w.state == WaitResult::Pending {
                w.state = WaitResult::Failed(Error::NotFound);
            }
            w.wake = backend.notify(w.ticket.sender, key).is_err();
        }
        // Messages own copied bytes, not dangling references to sender memory.
        // Clear one slot at a time: no queue-sized temporary is permitted here.
        for message in &mut self.messages[i] {
            *message = Message::EMPTY;
        }
        self.endpoints[i] = None;
        Ok(())
    }
    pub fn exit(&mut self, owner: ObjectKey, backend: &mut impl IpcBackend<B>) {
        for i in 0..ENDPOINTS {
            if let Some(e) = self.endpoints[i].as_ref()
                && e.owner == owner
            {
                let _ = self.close(owner, e.key, backend);
            }
        }
        for w in &mut self.waiters {
            if w.as_ref().is_some_and(|w| w.ticket.sender == owner) {
                *w = None;
            }
        }
    }
    pub fn stats(&self, key: ObjectKey) -> Result<IpcStats, Error> {
        let e = self.endpoints[self.index(key)?]
            .as_ref()
            .ok_or(Error::Stale)?;
        Ok(IpcStats {
            depth: e.len,
            ..e.stats
        })
    }
    pub fn policy_receipt(&self, key: ObjectKey) -> Result<u64, Error> {
        Ok(self.endpoints[self.index(key)?]
            .as_ref()
            .ok_or(Error::Stale)?
            .applied_version)
    }
    pub fn endpoint_at(&self, ordinal: usize) -> Option<ObjectKey> {
        self.endpoints
            .iter()
            .flatten()
            .filter(|e| !e.recovery)
            .nth(ordinal)
            .map(|e| e.key)
    }
    pub fn policy(&self, key: ObjectKey, now: u64) -> Result<(u16, u8), Error> {
        let e = self.endpoints[self.index(key)?]
            .as_ref()
            .ok_or(Error::Stale)?;
        if e.recovery {
            return Err(Error::Auth);
        }
        let (p, b) = e.limits(now);
        Ok((p as u16, b as u8))
    }
}
