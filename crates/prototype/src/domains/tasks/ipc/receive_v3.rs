//! Ordinary IPC receive v3 over the actual FIFO and send-reservation owner.
//! This is an opt-in protected EL1 component, not the legacy receive path.
//! The trap adapter authenticates holders, reserves real completion credits,
//! pins the full output range, copies outside the queue lock and revalidates
//! mappings/identity before commit. No user-provided pointer is trusted here.
use super::*;

pub const RECEIVE_V3_HEADER: usize = 40;
pub const RECEIVE_V3_MAX_PAYLOAD: usize = 512;
pub const RECEIVE_V3_REPLY_CAP: usize = 552;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveTicket {
    endpoint: ObjectKey,
    holder: ObjectKey,
    recv_seq: u64,
    head_sequence: u64,
    completion_credit: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceivePrepared {
    New(ReceiveTicket),
    Existing(ReceiveTicket),
}
impl ReceivePrepared {
    pub fn ticket(self) -> ReceiveTicket {
        match self {
            Self::New(t) | Self::Existing(t) => t,
        }
    }
}
/// Unique kernel-owned copy attempt. The receive identity survives faults and
/// lost returns, but a completed/aborted copy attempt is never reusable.
/// The native adapter must retain this lease until copyout and pin release
/// are reliably joined, even if the holder exits or its cap is revoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveCopyLease {
    ticket: ReceiveTicket,
    serial: u64,
    len: usize,
}
impl ReceiveCopyLease {
    pub fn len(self) -> usize {
        self.len
    }
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}
#[derive(Clone, Copy)]
struct ReceiveRecord {
    ticket: ReceiveTicket,
    bytes: [u8; RECEIVE_V3_REPLY_CAP],
    len: u16,
    done: bool,
    active_copy: u64, // 0 means no copy/pin obligation
}
#[derive(Clone, Copy)]
struct ReceiveSlot {
    high: u64,
    retired: u64,
    closed: bool,
    record: Option<ReceiveRecord>,
}
impl ReceiveSlot {
    const EMPTY: Self = Self {
        high: 0,
        retired: 0,
        closed: false,
        record: None,
    };
}
const _: () = assert!(core::mem::size_of::<ReceiveSlot>() <= 1024);
const _: () = assert!(core::mem::size_of::<[ReceiveSlot; MAX_ENDPOINTS]>() <= 32 * 1024);

/// Separately instantiated owner so the legacy Ipc memory layout and
/// unversioned receive entrypoints are not silently changed. No mutable
/// reference to the wrapped FIFO escapes (there is no alternate dequeue).
pub struct IpcV3<const B: usize = 512> {
    fifo: Ipc<B>,
    receivers: [ReceiveSlot; MAX_ENDPOINTS],
    copy_serial: u64,
}
impl<const B: usize> Default for IpcV3<B> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const B: usize> IpcV3<B> {
    pub const fn new() -> Self {
        Self {
            fifo: Ipc::new(),
            receivers: [ReceiveSlot::EMPTY; MAX_ENDPOINTS],
            copy_serial: 0,
        }
    }
    pub fn open(&mut self, holder: ObjectKey) -> Result<ObjectKey, Error> {
        if B == 0 || B > RECEIVE_V3_MAX_PAYLOAD {
            return Err(Error::Range);
        }
        let key = self.fifo.open(holder, false)?;
        let at = self.fifo.index(key)?;
        self.receivers[at] = ReceiveSlot::EMPTY;
        Ok(key)
    }
    fn index(&self, endpoint: ObjectKey) -> Result<usize, Error> {
        let at = self.fifo.index(endpoint)?;
        if at >= MAX_ENDPOINTS {
            return Err(Error::Auth);
        }
        Ok(at)
    }
    fn authorized(
        &self,
        holder: ObjectKey,
        endpoint: ObjectKey,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<usize, Error> {
        let at = self.index(endpoint)?;
        if self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?.owner != holder {
            return Err(Error::Auth);
        }
        if self.receivers[at].closed {
            return Err(Error::Stale);
        }
        backend.authorize(holder, endpoint, IpcOperation::Receive)?;
        Ok(at)
    }
    pub fn reserve_send(
        &mut self,
        sender: ObjectKey,
        endpoint: ObjectKey,
        request_id: u64,
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<SendGrant, Error> {
        let at = self.index(endpoint)?;
        if self.receivers[at].closed {
            return Err(Error::Stale);
        }
        self.fifo
            .reserve_send(sender, endpoint, request_id, now, backend)
    }
    pub fn send_reserved(
        &mut self,
        grant: SendGrant,
        request_id: u64,
        bytes: &[u8],
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<u64, Error> {
        // Previously admitted send grants retain their exact custody.
        self.fifo
            .send_reserved(grant, request_id, bytes, now, backend)
    }
    pub fn cancel_send(&mut self, grant: SendGrant) -> Result<(), Error> {
        self.fifo.cancel_send(grant)
    }
    pub fn stats(&self, endpoint: ObjectKey) -> Result<IpcStats, Error> {
        self.fifo.stats(endpoint)
    }

    /// Under the serialized owner lock, reserve one fixed receipt and the
    /// external completion credit. The callback is invoked only on a new,
    /// ready head, after every fallible admission check; Err is no-effect.
    /// No head means no sequence advancement and no output-page pin.
    // Stable wide receive-preparation API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &mut self,
        holder: ObjectKey,
        endpoint: ObjectKey,
        recv_seq: u64,
        reply_cap: usize,
        now: u64,
        backend: &mut impl IpcBackend<B>,
        reserve_credit: impl FnOnce() -> Result<u64, Error>,
    ) -> Result<ReceivePrepared, Error> {
        self.fifo.time(now)?;
        let at = self.authorized(holder, endpoint, backend)?;
        if recv_seq == 0 || reply_cap < RECEIVE_V3_REPLY_CAP {
            return Err(Error::Range);
        }
        let slot = &self.receivers[at];
        if recv_seq <= slot.retired {
            return Err(Error::Stale);
        }
        if let Some(r) = slot.record {
            return if r.ticket.recv_seq == recv_seq {
                Ok(ReceivePrepared::Existing(r.ticket))
            } else {
                Err(Error::Busy)
            };
        }
        if slot.high.checked_add(1).ok_or(Error::Overflow)? != recv_seq {
            return Err(Error::Again);
        }
        let e = self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?;
        if e.len == 0 {
            return Err(Error::Again);
        }
        let cell = usize::from(e.order[e.head]);
        let m = &self.fifo.messages[at][cell];
        if !e.owns(cell)
            || m.sequence == 0
            || m.sender.id == 0
            || m.sender.generation == 0
            || m.request_id == 0
            || m.len > B
            || m.len > RECEIVE_V3_MAX_PAYLOAD
        {
            return Err(Error::Conflict);
        }
        let mut bytes = [0; RECEIVE_V3_REPLY_CAP];
        for (offset, value) in [
            (0, m.sender.id),
            (8, m.sender.generation),
            (16, m.request_id),
            (24, endpoint.generation),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[32..36].copy_from_slice(&(m.len as u32).to_le_bytes());
        bytes[40..40 + m.len].copy_from_slice(&m.bytes[..m.len]);
        let length = (40 + m.len) as u16;
        let head_sequence = m.sequence;
        let completion_credit = reserve_credit()?;
        // The trusted pool must never return a zero or aliased credit.
        // A violated adapter contract fails closed before any FIFO change.
        if completion_credit == 0
            || self.receivers.iter().any(|slot| {
                slot.record
                    .is_some_and(|r| r.ticket.completion_credit == completion_credit)
            })
        {
            return Err(Error::Conflict);
        }
        let ticket = ReceiveTicket {
            endpoint,
            holder,
            recv_seq,
            head_sequence,
            completion_credit,
        };
        let slot = &mut self.receivers[at];
        slot.high = recv_seq;
        slot.record = Some(ReceiveRecord {
            ticket,
            bytes,
            len: length,
            done: false,
            active_copy: 0,
        });
        Ok(ReceivePrepared::New(ticket))
    }
    fn record(&self, ticket: ReceiveTicket, at: usize) -> Result<&ReceiveRecord, Error> {
        self.receivers[at]
            .record
            .as_ref()
            .filter(|r| r.ticket == ticket)
            .ok_or(Error::Stale)
    }
    /// Acquire an exclusive copy lease and stage the exact frozen response
    /// under the owner lock. A concurrent exact receive retry cannot acquire
    /// a second copy lease. The adapter drops the lock, pins/copies/unpins,
    /// and then commits or aborts only after that copy obligation has joined.
    pub fn stage(
        &mut self,
        ticket: ReceiveTicket,
        out: &mut [u8; RECEIVE_V3_REPLY_CAP],
        backend: &mut impl IpcBackend<B>,
    ) -> Result<ReceiveCopyLease, Error> {
        let at = self.authorized(ticket.holder, ticket.endpoint, backend)?;
        let serial = self.copy_serial.checked_add(1).ok_or(Error::Overflow)?;
        let r = self.receivers[at]
            .record
            .as_mut()
            .filter(|r| r.ticket == ticket)
            .ok_or(Error::Stale)?;
        if r.active_copy != 0 {
            return Err(Error::Busy);
        }
        out.copy_from_slice(&r.bytes);
        r.active_copy = serial;
        let len = usize::from(r.len);
        self.copy_serial = serial;
        Ok(ReceiveCopyLease {
            ticket,
            serial,
            len,
        })
    }
    fn copy_record(&self, lease: ReceiveCopyLease, at: usize) -> Result<&ReceiveRecord, Error> {
        let r = self.record(lease.ticket, at)?;
        if lease.serial == 0 || r.active_copy != lease.serial || usize::from(r.len) != lease.len {
            return Err(Error::Stale);
        }
        Ok(r)
    }
    /// Trusted copy adapter only: after proving all copying/pins have
    /// stopped, release the attempt without changing FIFO or DONE custody.
    /// This is also available after revoke/close; it grants no new copy.
    pub fn abort_copy(&mut self, lease: ReceiveCopyLease) -> Result<(), Error> {
        let at = self.index(lease.ticket.endpoint)?;
        self.copy_record(lease, at)?;
        self.receivers[at].record.as_mut().unwrap().active_copy = 0;
        Ok(())
    }
    /// Verified full copyout plus joined pin/copy obligation and current
    /// authenticated holder. Exact DONE retries stage a fresh lease, never
    /// pop another head. A failed validation leaves the old lease owned.
    pub fn commit_copied(
        &mut self,
        lease: ReceiveCopyLease,
        copied_bytes: usize,
        now: u64,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<usize, Error> {
        self.fifo.time(now)?;
        let ticket = lease.ticket;
        let at = self.authorized(ticket.holder, ticket.endpoint, backend)?;
        let record = self.copy_record(lease, at)?;
        let len = usize::from(record.len);
        if copied_bytes != len {
            return Err(Error::Range);
        }
        if record.done {
            self.receivers[at].record.as_mut().unwrap().active_copy = 0;
            return Ok(len);
        }
        let e = self.fifo.endpoints[at].as_mut().ok_or(Error::Stale)?;
        if e.len == 0 {
            return Err(Error::Conflict);
        }
        let cell = usize::from(e.order[e.head]);
        if !e.owns(cell) || self.fifo.messages[at][cell].sequence != ticket.head_sequence {
            return Err(Error::Conflict);
        }
        // All fallible head/identity checks precede this single owner commit.
        e.stats.receive_wait_ns = e
            .stats
            .receive_wait_ns
            .saturating_add(now.saturating_sub(e.since[cell]));
        self.fifo.messages[at][cell] = Message::EMPTY;
        e.set_owned(cell, false);
        e.head = (e.head + 1) % MAX_MESSAGES;
        e.len -= 1;
        e.stats.delivered = e.stats.delivered.saturating_add(1);
        if e.stamp.live(now) {
            e.applied_version = e.applied_version.max(e.stamp.version);
        }
        if e.len != 0 {
            e.wake = true;
        }
        let r = self.receivers[at].record.as_mut().unwrap();
        r.done = true;
        r.active_copy = 0;
        // Independent notification failure never undoes the committed receive.
        self.fifo.notify_endpoint(at, backend);
        Ok(len)
    }
    /// Credit release is a protected, serialized callback. It must return
    /// Err without effect; a successful callback and slot retirement are
    /// one owner operation. Exact latest ACK replay does not release again.
    pub fn ack(
        &mut self,
        holder: ObjectKey,
        endpoint: ObjectKey,
        recv_seq: u64,
        backend: &mut impl IpcBackend<B>,
        release: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let at = self.authorized(holder, endpoint, backend)?;
        let slot = &mut self.receivers[at];
        if recv_seq == 0 {
            return Err(Error::Range);
        }
        if recv_seq == slot.retired {
            return Ok(());
        }
        if recv_seq < slot.retired {
            return Err(Error::Stale);
        }
        let r = slot.record.as_ref().ok_or(Error::Again)?;
        if r.ticket.recv_seq != recv_seq {
            return Err(Error::Again);
        }
        if !r.done || r.active_copy != 0 {
            return Err(Error::Busy);
        }
        release(r.ticket.completion_credit)?;
        slot.retired = recv_seq;
        slot.record = None;
        Ok(())
    }
    /// Protected lifecycle owner closes the receive/send admission gate.
    /// Existing grants/records remain owned; no caller can reuse the slot.
    pub fn close_admission(&mut self, holder: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        let at = self.index(endpoint)?;
        if self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?.owner != holder {
            return Err(Error::Auth);
        }
        self.receivers[at].closed = true;
        Ok(())
    }
    /// EL1 supervisor supplies real stop/no-in-flight-copy proof. For DONE,
    /// audit must have taken custody before release. A reserved head is not
    /// dequeued here. These booleans are adapter observations, not wire fields.
    pub fn retire_closed(
        &mut self,
        endpoint: ObjectKey,
        stopped: bool,
        done_audited: bool,
        release: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let at = self.index(endpoint)?;
        let slot = &mut self.receivers[at];
        if !slot.closed || !stopped {
            return Err(Error::Busy);
        }
        let Some(r) = slot.record else {
            return Ok(());
        };
        if r.active_copy != 0 || (r.done && !done_audited) {
            return Err(Error::Busy);
        }
        release(r.ticket.completion_credit)?;
        slot.retired = r.ticket.recv_seq;
        slot.record = None;
        Ok(())
    }
    /// Only completely drained closed endpoints are reusable. A nonempty
    /// abandoned FIFO needs a separate supervised transfer/discard protocol.
    pub fn close_empty(
        &mut self,
        holder: ObjectKey,
        endpoint: ObjectKey,
        backend: &mut impl IpcBackend<B>,
    ) -> Result<(), Error> {
        let at = self.index(endpoint)?;
        if !self.receivers[at].closed || self.receivers[at].record.is_some() {
            return Err(Error::Busy);
        }
        let stats = self.fifo.stats(endpoint)?;
        if stats.depth != 0 || stats.reserved != 0 {
            return Err(Error::Busy);
        }
        self.fifo.close(holder, endpoint, backend)?;
        self.receivers[at] = ReceiveSlot::EMPTY;
        Ok(())
    }
}
