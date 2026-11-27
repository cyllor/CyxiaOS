//! Ordinary D05 FIFO policy owner, distinct from the static control IPC
//! and recovery channels. The native allocator must charge this entire
//! endpoint to its business allocation (128 fixed message slots).
//! This is the current component executor, not a native scheduler or
//! permission to copy to arbitrary user pages.
use super::control_rpc_v1::Error as RpcError;
use super::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_report_v1::{ActionStatus, ApplyReportV1, MAX_APPLY_REPORT_BYTES, PlanKey},
    apply_work_v1::ApplyWorkV1,
};
use crate::security::ipc_receive_v3::{
    DirectionalEndpoint, Endpoint, FRAME_BYTES, Message, ReceiveTicket,
};
const HOLD: u64 = 100_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Batch {
    serial: u64,
    version: u64,
    limit: u8,
}
#[derive(Clone, Copy)]
struct Active {
    key: Batch,
    delivered: u8,
    inflight: Option<(u64, ReceiveTicket, u64)>,
}
#[derive(Clone, Copy)]
struct Work {
    key: PlanKey,
    index: u16,
    version: u64,
    budget: u16,
    batch: u8,
    until: u64,
    accepted: u64,
    effect: Option<(ActionStatus, u64)>,
}
pub struct Owner {
    queue: DirectionalEndpoint<128>,
    boot: u64,
    executor: u64,
    target: Identity,
    version: u64,
    budget: u16,
    batch: u8,
    until: u64,
    last: u64,
    last_change: u64,
    changes: [u64; 4],
    change_count: usize,
    serial: u64,
    active: Option<Active>,
    work: Option<Work>,
    fenced: bool,
}
fn rpc(e: RpcError) -> Error {
    match e {
        RpcError::Auth => Error::Denied,
        RpcError::Stale => Error::Stale,
        RpcError::Busy => Error::Busy,
        RpcError::Again => Error::NotReady,
        RpcError::Timeout | RpcError::Expired => Error::Expired,
        RpcError::Capacity => Error::Exhausted,
        _ => Error::Invalid,
    }
}
impl Owner {
    /// Storage for a native business owner. It admits no operations until
    /// its exact endpoint and executor generation have been bound.
    pub const fn empty() -> Self {
        Self {
            queue: DirectionalEndpoint::unbound(),
            boot: 0,
            executor: 0,
            target: Identity {
                id: 0,
                generation: 0,
            },
            version: 0,
            budget: 32,
            batch: 4,
            until: 0,
            last: 0,
            last_change: 0,
            changes: [0; 4],
            change_count: 0,
            serial: 0,
            active: None,
            work: None,
            fenced: false,
        }
    }
    pub fn bind(
        boot: u64,
        executor: u64,
        ep: Endpoint,
        sender: Identity,
        verify_ordinary: impl FnOnce(Endpoint, Identity) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut owner = Self::empty();
        owner.initialize(boot, executor, ep, sender, verify_ordinary)?;
        Ok(owner)
    }
    pub fn initialize(
        &mut self,
        boot: u64,
        executor: u64,
        ep: Endpoint,
        sender: Identity,
        verify_ordinary: impl FnOnce(Endpoint, Identity) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.boot != 0 || self.fenced {
            return Err(Error::Busy);
        }
        if boot == 0 || executor == 0 {
            return Err(Error::Invalid);
        }
        verify_ordinary(ep, sender)?;
        self.queue.bind_unbound(ep, sender).map_err(rpc)?;
        self.boot = boot;
        self.executor = executor;
        self.target = Identity {
            id: ep.id,
            generation: ep.generation,
        };
        Ok(())
    }
    fn clock(&self, now: u64) -> Result<(), Error> {
        if self.boot == 0 {
            return Err(Error::NotReady);
        }
        if now == 0 || now < self.last {
            return Err(Error::Clock);
        }
        Ok(())
    }
    fn ready(&self, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        if self.fenced {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn current(&self, now: u64) -> (u16, u8, u64) {
        if now < self.until {
            (self.budget, self.batch, self.version)
        } else {
            (32, 4, 0)
        }
    }
    pub fn pending(&self) -> usize {
        self.queue.pending()
    }
    pub fn observe(&self, now: u64) -> Result<[Option<u64>; 4], Error> {
        self.clock(now)?;
        Ok([
            Some(self.pending() as u64),
            None,
            None,
            Some((self.pending() * 1000 / 128) as u64),
        ])
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn legal(&self, budget: u16, batch: u8, now: u64) -> bool {
        if self.ready(now).is_err()
            || self.active.is_some()
            || self.work.is_some()
            || !(ActionV2::Ipc { budget, batch }).valid()
        {
            return false;
        }
        let (b, n, _) = self.current(now);
        (b, n) == (budget, batch)
            || !(self.last_change != 0 && now - self.last_change < HOLD
                || self.changes[..self.change_count]
                    .iter()
                    .filter(|&&t| now - t < 1_000_000_000)
                    .count()
                    >= 4)
    }
    pub fn accept(
        &mut self,
        w: &ApplyWorkV1<'_>,
        base: u64,
        until: u64,
        now: u64,
        verify_live: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ready(now)?;
        if !w.key.valid()
            || w.key.boot_epoch != self.boot
            || w.domain != 5
            || w.target != self.target
            || w.executor_generation != self.executor
            || w.action_index >= 16
        {
            return Err(Error::Denied);
        }
        if base != self.version || w.plan_version <= base {
            return Err(Error::Stale);
        }
        if until <= now || until - now > 10_000_000_000 {
            return Err(Error::Expired);
        }
        let ActionV2::Ipc { budget, batch } = ActionV2::decode(5, 1, w.payload)? else {
            return Err(Error::Invalid);
        };
        if !self.legal(budget, batch, now) {
            return Err(Error::Busy);
        }
        verify_live()?;
        let (b, n, _) = self.current(now);
        if (b, n) != (budget, batch) {
            if self.change_count < 4 {
                self.changes[self.change_count] = now;
                self.change_count += 1;
            } else {
                self.changes.rotate_left(1);
                self.changes[3] = now;
            }
            self.last_change = now;
        }
        self.version = w.plan_version;
        self.budget = budget;
        self.batch = batch;
        self.until = until;
        self.work = Some(Work {
            key: w.key,
            index: w.action_index,
            version: w.plan_version,
            budget,
            batch,
            until,
            accepted: now,
            effect: None,
        });
        self.last = now;
        Ok(())
    }
    /// New ordinary sends only. The protected caller must authenticate
    /// current SEND cap, actual sender and stable copied message bytes.
    pub fn send(
        &mut self,
        actor: Identity,
        request: u64,
        payload: &[u8],
        now: u64,
        authorize: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ready(now)?;
        authorize()?;
        let (budget, _, _) = self.current(now);
        self.queue
            .send_limited(
                actor,
                self.target.generation,
                request,
                payload,
                usize::from(budget),
            )
            .map_err(rpc)?;
        self.last = now;
        Ok(())
    }
    /// A bounded native dequeue pump. Empty queue returns immediately,
    /// never waits for a complete batch. Retains its exact policy snapshot.
    pub fn start_batch(&mut self, now: u64) -> Result<Option<Batch>, Error> {
        self.ready(now)?;
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        if self.pending() == 0 {
            return Ok(None);
        }
        let (_, limit, version) = self.current(now);
        self.serial = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let key = Batch {
            serial: self.serial,
            version,
            limit,
        };
        self.active = Some(Active {
            key,
            delivered: 0,
            inflight: None,
        });
        self.last = now;
        Ok(Some(key))
    }
    fn active(&self, key: Batch) -> Result<Active, Error> {
        self.active.filter(|a| a.key == key).ok_or(Error::Stale)
    }
    pub fn reserve(
        &mut self,
        key: Batch,
        receiver: Identity,
        seq: u64,
        now: u64,
        authorize: impl FnOnce() -> Result<(), Error>,
        reserve_credit: impl FnOnce() -> Result<(), RpcError>,
    ) -> Result<ReceiveTicket, Error> {
        self.ready(now)?;
        let a = self.active(key)?;
        if a.delivered >= key.limit && a.inflight.is_none() {
            return Err(Error::Busy);
        }
        if let Some((old, _, _)) = a.inflight {
            if old != seq {
                return Err(Error::Busy);
            }
        } else if key.version != 0 && now >= self.until {
            return Err(Error::Expired);
        }
        authorize()?;
        let t = self
            .queue
            .reserve_receive(
                receiver,
                self.target.generation,
                seq,
                FRAME_BYTES,
                true,
                0,
                now,
                reserve_credit,
            )
            .map_err(rpc)?;
        let reserved = a.inflight.map_or(now, |(_, _, ns)| ns);
        self.active.as_mut().unwrap().inflight = Some((seq, t, reserved));
        self.last = now;
        Ok(t)
    }
    /// A real successful copyout consumes exactly one queue head. Recopy
    /// of a DONE ticket is not a second delivery or effect. A fault does
    /// not dequeue, and the retained credit survives until ACK/recovery.
    pub fn finish_copy(
        &mut self,
        key: Batch,
        t: ReceiveTicket,
        now: u64,
        verify_copy: impl FnOnce(&Message) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        self.ready(now)?;
        let a = self.active(key)?;
        let (_, old, reserved) = a.inflight.ok_or(Error::Stale)?;
        if old != t {
            return Err(Error::Stale);
        }
        verify_copy(t.message())?;
        let before = self.pending();
        let bytes = self.queue.finish_copy(t, true).map_err(rpc)?;
        if self.pending() < before {
            let a = self.active.as_mut().unwrap();
            a.delivered += 1;
            assert!(a.delivered <= key.limit);
            if let Some(w) = self.work.as_mut()
                && w.effect.is_none()
                && key.version == w.version
                && reserved >= w.accepted
                && reserved < w.until
            {
                w.effect = Some((ActionStatus::Applied, now));
            }
        }
        self.last = now;
        Ok(bytes)
    }
    pub fn ack(
        &mut self,
        key: Batch,
        receiver: Identity,
        seq: u64,
        now: u64,
        authorize: impl FnOnce() -> Result<(), Error>,
        release_credit: impl FnOnce() -> Result<(), RpcError>,
    ) -> Result<(), Error> {
        self.ready(now)?;
        let a = self.active(key)?;
        authorize()?;
        if a.inflight.is_some_and(|(old, _, _)| old != seq) {
            return Err(Error::Stale);
        }
        self.queue
            .ack(receiver, self.target.generation, seq, release_credit)
            .map_err(rpc)?;
        self.active.as_mut().unwrap().inflight = None;
        self.last = now;
        Ok(())
    }
    pub fn end_batch(&mut self, key: Batch, now: u64) -> Result<u8, Error> {
        self.ready(now)?;
        let a = self.active(key)?;
        if a.inflight.is_some() {
            return Err(Error::Busy);
        }
        self.active = None;
        self.last = now;
        Ok(a.delivered)
    }
    pub fn fence(&mut self) {
        self.fenced = true;
        self.queue.fence();
    }
    pub fn recover_idle_batch(
        &mut self,
        verify_stopped: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.fenced {
            return Err(Error::Busy);
        }
        let a = self.active.ok_or(Error::Stale)?;
        if a.inflight.is_some() {
            return Err(Error::Busy);
        }
        verify_stopped()?;
        self.active = None;
        Ok(())
    }
    pub fn recover_receive(
        &mut self,
        verify: impl FnOnce(ReceiveTicket, bool) -> Result<(), RpcError>,
    ) -> Result<(), Error> {
        self.queue.recover_receive(verify).map_err(rpc)?;
        if let Some(a) = self.active.as_mut() {
            a.inflight = None;
        }
        self.active = None;
        Ok(())
    }
    pub fn recover_head(
        &mut self,
        verify: impl FnOnce(&Message) -> Result<(), RpcError>,
    ) -> Result<(), Error> {
        self.queue.recover_head(verify).map_err(rpc)
    }
    pub fn drained(&self) -> bool {
        self.queue.drained()
    }
    pub fn expire(
        &mut self,
        now: u64,
        verify_no_effect: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.clock(now)?;
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        let w = self.work.as_mut().ok_or(Error::Stale)?;
        if now < w.until || w.effect.is_some() {
            return Err(Error::Busy);
        }
        verify_no_effect()?;
        w.effect = Some((ActionStatus::Cancelled, now));
        self.last = now;
        Ok(())
    }
    pub fn report(&self, out: &mut [u8; MAX_APPLY_REPORT_BYTES]) -> Result<usize, Error> {
        let w = self.work.ok_or(Error::Stale)?;
        let (state, completed_ns) = w.effect.ok_or(Error::NotReady)?;
        let b = w.budget.to_le_bytes();
        let payload = [b[0], b[1], w.batch];
        ApplyReportV1 {
            key: w.key,
            action_index: w.index,
            domain_id: 5,
            target: self.target,
            executor_generation: self.executor,
            plan_version: w.version,
            state,
            result: if state == ActionStatus::Applied {
                0
            } else {
                -7
            },
            completed_ns,
            action: &payload,
        }
        .encode(out)
    }
    pub fn retire(
        &mut self,
        r: &ApplyReportV1<'_>,
        verify_custody: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut raw = [0; MAX_APPLY_REPORT_BYTES];
        let n = self.report(&mut raw)?;
        if ApplyReportV1::decode(&raw[..n])? != *r {
            return Err(Error::Denied);
        }
        verify_custody()?;
        self.work = None;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const SEND: Identity = Identity {
        id: 20,
        generation: 1,
    };
    const RECV: Identity = Identity {
        id: 21,
        generation: 1,
    };
    #[test]
    fn business_arena_binds_once_without_replacing_live_queue() {
        let ep = Endpoint {
            id: 5,
            generation: 1,
            receiver: RECV,
        };
        let mut owner = Owner::empty();
        assert_eq!(
            owner.send(SEND, 1, b"first", 10, || panic!()),
            Err(Error::NotReady)
        );
        assert_eq!(
            owner.initialize(4, 1, ep, SEND, |_, _| Err(Error::Denied)),
            Err(Error::Denied)
        );
        owner.initialize(4, 1, ep, SEND, |_, _| Ok(())).unwrap();
        owner.send(SEND, 1, b"first", 10, || Ok(())).unwrap();
        assert_eq!(
            owner.initialize(4, 1, ep, SEND, |_, _| panic!()),
            Err(Error::Busy)
        );
        assert_eq!(owner.pending(), 1);
    }

    #[test]
    fn shrink_keeps_fifo_and_exact_retry_batch_effect_after_copy() {
        let ep = Endpoint {
            id: 5,
            generation: 1,
            receiver: RECV,
        };
        let mut o = Owner::bind(1, 1, ep, SEND, |_, _| Ok(())).unwrap();
        for id in 1..=10 {
            o.send(SEND, id, &[id as u8], 100, || Ok(())).unwrap();
        }
        let w = ApplyWorkV1 {
            key: PlanKey {
                boot_epoch: 1,
                controller_epoch: 1,
                plan_seq: 1,
            },
            action_index: 0,
            domain: 5,
            target: Identity {
                id: 5,
                generation: 1,
            },
            executor_generation: 1,
            plan_version: 1,
            payload: &[8, 0, 1],
        };
        o.accept(&w, 0, 10_000_000, 101, || Ok(())).unwrap();
        assert_eq!(o.pending(), 10);
        o.send(SEND, 1, &[1], 102, || Ok(())).unwrap();
        assert_eq!(
            o.send(SEND, 11, &[11], 102, || Ok(())),
            Err(Error::NotReady)
        );
        let k = o.start_batch(103).unwrap().unwrap();
        let t = o.reserve(k, RECV, 1, 104, || Ok(()), || Ok(())).unwrap();
        assert_eq!(t.message().request_id(), 1);
        assert_eq!(
            o.finish_copy(k, t, 105, |_| Err(Error::Denied)),
            Err(Error::Denied)
        );
        let mut out = [0; MAX_APPLY_REPORT_BYTES];
        assert_eq!(o.report(&mut out), Err(Error::NotReady));
        o.finish_copy(k, t, 106, |m| {
            assert_eq!(m.request_id(), 1);
            Ok(())
        })
        .unwrap();
        o.finish_copy(k, t, 107, |_| Ok(())).unwrap();
        assert_eq!(o.pending(), 9);
        assert_eq!(o.end_batch(k, 108), Err(Error::Busy));
        o.ack(k, RECV, 1, 109, || Ok(()), || Ok(())).unwrap();
        assert_eq!(
            o.reserve(k, RECV, 2, 110, || panic!(), || panic!()),
            Err(Error::Busy)
        );
        assert_eq!(o.end_batch(k, 111), Ok(1));
        let n = o.report(&mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(
            (r.state, r.completed_ns, r.action),
            (ActionStatus::Applied, 106, &[8, 0, 1][..])
        );
        o.retire(&r, || Ok(())).unwrap();
        let k = o.start_batch(112).unwrap().unwrap();
        let t = o.reserve(k, RECV, 2, 113, || Ok(()), || Ok(())).unwrap();
        assert_eq!(t.message().request_id(), 2);
        o.fence();
        assert_eq!(o.finish_copy(k, t, 114, |_| panic!()), Err(Error::NotReady));
        o.recover_receive(|v, done| {
            assert_eq!(v, t);
            assert!(!done);
            Ok(())
        })
        .unwrap();
        assert_eq!(o.pending(), 9);
        for id in 2..=10 {
            o.recover_head(|m| {
                assert_eq!(m.request_id(), id);
                Ok(())
            })
            .unwrap();
        }
        assert!(o.drained());
    }
}
