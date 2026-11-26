//! Current D07 soft-timer policy and native effect custody. EL1 serialized
//! owner; no model, user or old generation may arm via this control interface.
//! The backend is the actual timer scheduler/compare owner, not an EL0 receipt.
//! Only ordinary soft timers enter this owner. Hard deadlines, lease and
//! recovery timers keep independent deterministic scheduling and never wait
//! for a policy, an uncertain ordinary arm, or an AI report.
use super::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_report_v1::{ActionStatus, ApplyReportV1, MAX_APPLY_REPORT_BYTES, PlanKey},
    apply_work_v1::ApplyWorkV1,
};

pub const DOMAIN: u16 = 7;
pub const CAPACITY: usize = 256;
const HOLD: u64 = 100_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerClass {
    Soft,
    Hard,
    Lease,
    Recovery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerArm {
    pub timer: Identity,
    pub serial: u64,
    pub requested_ns: u64,
    pub programmed_ns: u64,
    pub policy_version: u64,
}
#[derive(Clone, Copy)]
struct Entry {
    timer: Identity,
    class: TimerClass,
    slack_ns: u64,
    live: bool,
    active: Option<TimerArm>,
    pending: Option<PendingArm>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingArm {
    arm: TimerArm,
    started_ns: u64,
}
/// An independent timer backend must prove either that the proposed
/// compare was accepted at the recorded time, or that it had no effect
/// and the retained prior arm is unchanged. Mere timeout is neither.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmResolution {
    PriorUnchanged,
    Programmed { completed_ns: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UncertainArm {
    pub prior: Option<TimerArm>,
    pub proposed: TimerArm,
    pub started_ns: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmEvidence {
    pub arm: TimerArm,
    pub started_ns: u64,
    pub completed_ns: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Pending,
    Applied(ArmEvidence),
    Cancelled(u64),
    Unknown(u64),
}
#[derive(Clone, Copy)]
struct Work {
    key: PlanKey,
    index: u16,
    version: u64,
    until: u64,
    value: u16,
    accepted_ns: u64,
    effect: Effect,
}
pub struct Owner {
    boot: u64,
    target: Identity,
    executor_generation: u64,
    entries: [Option<Entry>; CAPACITY],
    value: u16,
    version: u64,
    until: u64,
    work: Option<Work>,
    last_clock: u64,
    serial: u64,
    last_change: u64,
    changes: [u64; 4],
    change_count: usize,
    poisoned: bool,
}
/// Exact ceil-to-grid with explicit slack and due checks; u128 avoids
/// rounding overflow. The representable slack endpoint is saturated,
/// not wrapped. Hard/lease/recovery requests must declare zero slack.
pub fn programmed_ns(
    class: TimerClass,
    slack: u64,
    deadline: u64,
    now: u64,
    us: u16,
) -> Result<u64, Error> {
    if !ActionV2::SoftCoalesce(us).valid() {
        return Err(Error::Invalid);
    }
    if class != TimerClass::Soft {
        if slack != 0 {
            return Err(Error::Denied);
        }
        return Ok(deadline);
    }
    if deadline <= now || us == 0 {
        return Ok(deadline);
    }
    let q = u128::from(us) * 1000;
    let rounded = u128::from(deadline).div_ceil(q) * q;
    Ok(rounded.min(u128::from(deadline.saturating_add(slack))) as u64)
}
impl Owner {
    pub const fn empty() -> Self {
        Self {
            boot: 0,
            target: Identity {
                id: 0,
                generation: 0,
            },
            executor_generation: 0,
            entries: [None; CAPACITY],
            value: 0,
            version: 0,
            until: 0,
            work: None,
            last_clock: 0,
            serial: 0,
            last_change: 0,
            changes: [0; 4],
            change_count: 0,
            poisoned: false,
        }
    }
    pub fn bind(
        &mut self,
        boot: u64,
        target: Identity,
        generation: u64,
        verify: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.boot != 0 {
            return Err(Error::Busy);
        }
        if boot == 0 || !target.valid() || generation == 0 {
            return Err(Error::Invalid);
        }
        verify()?;
        self.boot = boot;
        self.target = target;
        self.executor_generation = generation;
        Ok(())
    }
    pub fn target(&self) -> Identity {
        self.target
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn current(&self, now: u64) -> u16 {
        if now < self.until { self.value } else { 0 }
    }
    fn ready(&self, now: u64) -> Result<(), Error> {
        if self.boot == 0 || self.poisoned {
            return Err(Error::NotReady);
        }
        if now == 0 || now < self.last_clock {
            return Err(Error::Clock);
        }
        Ok(())
    }
    fn index(&self, id: Identity) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|v| v.is_some_and(|e| e.live && e.timer == id))
            .ok_or(Error::Stale)
    }
    pub fn register(
        &mut self,
        id: Identity,
        class: TimerClass,
        slack_ns: u64,
        verify: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.boot == 0 || self.poisoned {
            return Err(Error::NotReady);
        }
        if !id.valid() || class != TimerClass::Soft {
            return Err(Error::Denied);
        }
        // Retain a bounded generation tombstone. Unrelated object IDs
        // may not evict it and thereby resurrect stale timer tickets.
        let old = self
            .entries
            .iter()
            .position(|v| v.is_some_and(|e| e.timer.id == id.id));
        let i = if let Some(i) = old {
            let e = self.entries[i].unwrap();
            if e.live || e.active.is_some() || e.pending.is_some() {
                return Err(Error::Busy);
            }
            if id.generation <= e.timer.generation {
                return Err(Error::Stale);
            }
            i
        } else {
            self.entries
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Exhausted)?
        };
        verify()?;
        self.entries[i] = Some(Entry {
            timer: id,
            class,
            slack_ns,
            live: true,
            active: None,
            pending: None,
        });
        Ok(())
    }
    pub fn unregister(
        &mut self,
        id: Identity,
        verify: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::NotReady);
        }
        let i = self.index(id)?;
        let e = self.entries[i].unwrap();
        if e.active.is_some() || e.pending.is_some() {
            return Err(Error::Busy);
        }
        verify()?;
        self.entries[i].as_mut().unwrap().live = false;
        Ok(())
    }
    /// Only actual registered timers and minimum declared slack here.
    /// Rate and overrun windows are absent until separately measured.
    pub fn observe(&self, now: u64) -> Result<[Option<u64>; 4], Error> {
        self.ready(now)?;
        let mut n = 0;
        let mut slack = None;
        for e in self
            .entries
            .iter()
            .flatten()
            .filter(|e| e.live && e.class == TimerClass::Soft)
        {
            n += 1;
            let us = e.slack_ns / 1000;
            slack = Some(slack.map_or(us, |old: u64| old.min(us)));
        }
        Ok([Some(n), None, slack, None])
    }
    pub fn legal(&self, us: u16, now: u64) -> bool {
        if self.ready(now).is_err() || self.work.is_some() || !ActionV2::SoftCoalesce(us).valid() {
            return false;
        }
        if us == self.current(now) {
            return true;
        }
        if self.last_change != 0 && now - self.last_change < HOLD {
            return false;
        }
        self.changes[..self.change_count]
            .iter()
            .filter(|&&v| now - v < 1_000_000_000)
            .count()
            < 4
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
        if w.domain != DOMAIN
            || w.target != self.target
            || w.key.boot_epoch != self.boot
            || !w.key.valid()
            || w.action_index >= 16
            || w.executor_generation != self.executor_generation
            || base != self.version
            || w.plan_version <= base
        {
            return Err(Error::Stale);
        }
        if until <= now || until - now > 10_000_000_000 {
            return Err(Error::Expired);
        }
        let ActionV2::SoftCoalesce(value) = ActionV2::decode(DOMAIN, 1, w.payload)? else {
            return Err(Error::Invalid);
        };
        if !self.legal(value, now) {
            return Err(Error::Busy);
        }
        verify_live()?;
        if value != self.current(now) {
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
        self.value = value;
        self.until = until;
        self.last_clock = now;
        self.work = Some(Work {
            key: w.key,
            index: w.action_index,
            version: w.plan_version,
            until,
            value,
            accepted_ns: now,
            effect: Effect::Pending,
        });
        Ok(())
    }
    fn expire(&mut self, now: u64) {
        if let Some(w) = self.work.as_mut()
            && w.effect == Effect::Pending
            && now >= w.until
        {
            w.effect = Effect::Cancelled(now);
        }
    }
    fn poison(&mut self, now: u64) {
        self.poisoned = true;
        if let Some(w) = self.work.as_mut()
            && w.effect == Effect::Pending
        {
            w.effect = Effect::Unknown(now.max(1));
        }
    }
    /// Program/rearm only at this real queue or hardware safe point.
    /// Retain previous and proposed arms if backend result is uncertain.
    /// A reported completion time must come from the authoritative backend
    /// after verified acceptance; this API never trusts a model timestamp.
    pub fn arm(
        &mut self,
        id: Identity,
        deadline: u64,
        now: u64,
        program: impl FnOnce(TimerArm) -> Result<u64, Error>,
    ) -> Result<TimerArm, Error> {
        self.ready(now)?;
        self.last_clock = now;
        self.expire(now);
        let i = self.index(id)?;
        let e = self.entries[i].unwrap();
        if e.pending.is_some() {
            return Err(Error::Busy);
        }
        let eligible = e.class == TimerClass::Soft && deadline > now && now < self.until;
        let version = if eligible { self.version } else { 0 };
        let chosen = programmed_ns(
            e.class,
            e.slack_ns,
            deadline,
            now,
            if eligible { self.value } else { 0 },
        )?;
        let serial = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let arm = TimerArm {
            timer: id,
            serial,
            requested_ns: deadline,
            programmed_ns: chosen,
            policy_version: version,
        };
        self.serial = serial;
        self.entries[i].as_mut().unwrap().pending = Some(PendingArm {
            arm,
            started_ns: now,
        });
        let done = match program(arm) {
            Ok(t) if t >= now && t != 0 => t,
            Ok(_) => {
                self.poison(now);
                return Err(Error::Clock);
            }
            Err(e) => {
                self.poison(now);
                return Err(e);
            }
        };
        self.last_clock = done;
        let entry = self.entries[i].as_mut().unwrap();
        entry.active = Some(arm);
        entry.pending = None;
        if let Some(w) = self.work.as_mut()
            && w.effect == Effect::Pending
            && eligible
            && version == w.version
        {
            w.effect = Effect::Applied(ArmEvidence {
                arm,
                started_ns: now,
                completed_ns: done,
            });
        }
        Ok(arm)
    }
    /// Independent read-only reconciliation of an uncertain arm. The
    /// protected native supervisor must establish exact comparator/queue
    /// state AND whether delivery already occurred; this API is restricted
    /// to still-retained, undelivered arms. An already delivered effect
    /// requires a separately reconciled native completion before release.
    /// No old proposal is executed again, even after a no-effect proof.
    pub fn reconcile_arm(
        &mut self,
        id: Identity,
        now: u64,
        resolution: ArmResolution,
        verify_independent: impl FnOnce(UncertainArm, ArmResolution) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.poisoned {
            return Err(Error::NotReady);
        }
        if now == 0 || now < self.last_clock {
            return Err(Error::Clock);
        }
        let i = self.index(id)?;
        let e = self.entries[i].unwrap();
        let p = e.pending.ok_or(Error::Stale)?;
        if let ArmResolution::Programmed { completed_ns } = resolution
            && (completed_ns < p.started_ns || completed_ns > now)
        {
            return Err(Error::Clock);
        }
        verify_independent(
            UncertainArm {
                prior: e.active,
                proposed: p.arm,
                started_ns: p.started_ns,
            },
            resolution,
        )?;
        let entry = self.entries[i].as_mut().unwrap();
        if matches!(resolution, ArmResolution::Programmed { .. }) {
            entry.active = Some(p.arm);
        }
        entry.pending = None;
        // Faulted ordinary policy does not silently resume. Already accepted
        // timer arms and the plan version remain owned; future arms use SAFE_EXEC.
        self.until = 0;
        if let Some(w) = self.work.as_mut()
            && matches!(w.effect, Effect::Unknown(_))
        {
            w.effect = match resolution {
                ArmResolution::Programmed { completed_ns }
                    if p.arm.policy_version == w.version
                        && p.started_ns >= w.accepted_ns
                        && p.started_ns < w.until =>
                {
                    Effect::Applied(ArmEvidence {
                        arm: p.arm,
                        started_ns: p.started_ns,
                        completed_ns,
                    })
                }
                _ => Effect::Cancelled(now),
            };
        }
        self.poisoned = self.entries.iter().flatten().any(|e| e.pending.is_some());
        self.last_clock = now;
        Ok(())
    }
    /// Record exact callback delivery from the actual timer owner. No
    /// delivery before the chosen deadline and no retry of unknown arms.
    pub fn complete(
        &mut self,
        arm: TimerArm,
        now: u64,
        verify_delivery: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ready(now)?;
        let i = self.index(arm.timer)?;
        let e = self.entries[i].unwrap();
        if e.active != Some(arm) || e.pending.is_some() {
            return Err(Error::Stale);
        }
        if now < arm.programmed_ns {
            return Err(Error::NotReady);
        }
        verify_delivery()?;
        self.entries[i].as_mut().unwrap().active = None;
        self.last_clock = now;
        Ok(())
    }
    pub fn report(
        &mut self,
        now: u64,
        out: &mut [u8; MAX_APPLY_REPORT_BYTES],
    ) -> Result<usize, Error> {
        if now < self.last_clock {
            return Err(Error::Clock);
        }
        self.last_clock = now;
        self.expire(now);
        let w = self.work.ok_or(Error::Stale)?;
        let (state, result, completed_ns) = match w.effect {
            Effect::Pending => return Err(Error::NotReady),
            Effect::Applied(e) => (ActionStatus::Applied, 0, e.completed_ns),
            Effect::Cancelled(t) => (ActionStatus::Cancelled, -7, t),
            Effect::Unknown(t) => (ActionStatus::Unknown, -16, t),
        };
        ApplyReportV1 {
            key: w.key,
            action_index: w.index,
            domain_id: DOMAIN,
            state,
            target: self.target,
            executor_generation: self.executor_generation,
            plan_version: w.version,
            result,
            completed_ns,
            action: &w.value.to_le_bytes(),
        }
        .encode(out)
    }
    pub fn applied_evidence(&self) -> Option<ArmEvidence> {
        match self.work?.effect {
            Effect::Applied(e) => Some(e),
            _ => None,
        }
    }
    pub fn verify_report(&self, r: &ApplyReportV1<'_>) -> Result<(), Error> {
        let w = self.work.ok_or(Error::Stale)?;
        if r.key != w.key
            || r.action_index != w.index
            || r.domain_id != DOMAIN
            || r.target != self.target
            || r.executor_generation != self.executor_generation
            || r.plan_version != w.version
            || r.action != w.value.to_le_bytes()
        {
            return Err(Error::Denied);
        }
        match w.effect {
            Effect::Applied(e)
                if r.state == ActionStatus::Applied
                    && r.result == 0
                    && r.completed_ns == e.completed_ns
                    && e.arm.policy_version == w.version
                    && e.started_ns >= w.accepted_ns
                    && e.started_ns < w.until
                    && e.completed_ns >= e.started_ns =>
            {
                Ok(())
            }
            Effect::Cancelled(t)
                if r.state == ActionStatus::Cancelled && r.result == -7 && r.completed_ns == t =>
            {
                Ok(())
            }
            _ => Err(Error::NotReady),
        }
    }
    pub fn retire(
        &mut self,
        r: &ApplyReportV1<'_>,
        verify_custody: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.verify_report(r)?;
        verify_custody()?;
        self.work = None;
        Ok(())
    }
}
const _: () = assert!(core::mem::size_of::<Owner>() < 64 * 1024);

#[cfg(test)]
mod tests {
    use super::*;
    const TARGET: Identity = Identity {
        id: 7,
        generation: 1,
    };
    const SOFT: Identity = Identity {
        id: 101,
        generation: 1,
    };
    fn owner() -> Owner {
        let mut o = Owner::empty();
        o.bind(1, TARGET, 1, || Ok(())).unwrap();
        o.register(SOFT, TimerClass::Soft, 80_000, || Ok(()))
            .unwrap();
        assert_eq!(
            o.register(
                Identity {
                    id: 102,
                    generation: 1
                },
                TimerClass::Hard,
                0,
                || panic!()
            ),
            Err(Error::Denied)
        );
        o
    }
    fn work() -> ApplyWorkV1<'static> {
        ApplyWorkV1 {
            key: PlanKey {
                boot_epoch: 1,
                controller_epoch: 1,
                plan_seq: 1,
            },
            action_index: 0,
            domain: DOMAIN,
            target: TARGET,
            executor_generation: 1,
            plan_version: 1,
            payload: &[200, 0],
        }
    }
    #[test]
    fn exact_grid_slack_and_hard_deadlines() {
        assert_eq!(
            programmed_ns(TimerClass::Soft, 80_000, 1_016_000, 1, 200),
            Ok(1_096_000)
        );
        assert_eq!(
            programmed_ns(TimerClass::Soft, 1_000_000, 1_016_000, 1, 200),
            Ok(1_200_000)
        );
        assert_eq!(
            programmed_ns(TimerClass::Soft, 1_000_000, 1_016_000, 1_016_000, 200),
            Ok(1_016_000)
        );
        for c in [TimerClass::Hard, TimerClass::Lease, TimerClass::Recovery] {
            assert_eq!(programmed_ns(c, 0, 1_016_000, 1, 200), Ok(1_016_000));
            assert_eq!(programmed_ns(c, 1, 1_016_000, 1, 200), Err(Error::Denied));
        }
        assert_eq!(
            programmed_ns(TimerClass::Soft, u64::MAX, u64::MAX - 1, 1, 1000),
            Ok(u64::MAX)
        );
    }
    #[test]
    fn applied_requires_actual_soft_arm_and_exact_delivery() {
        let mut o = owner();
        let mut out = [0; MAX_APPLY_REPORT_BYTES];
        let old = o.arm(SOFT, 1000, 100, |_| Ok(101)).unwrap();
        assert_eq!(old.programmed_ns, 1000);
        assert_eq!(o.complete(old, 999, || panic!()), Err(Error::NotReady));
        o.complete(old, 1000, || Ok(())).unwrap();
        o.accept(&work(), 0, 10_000_000, 1100, || Ok(())).unwrap();
        assert_eq!(
            programmed_ns(TimerClass::Hard, 0, 2000, 1100, o.current(1100)),
            Ok(2000)
        );
        assert_eq!(o.report(1101, &mut out), Err(Error::NotReady));
        let a = o
            .arm(SOFT, 1_016_000, 1200, |v| {
                assert_eq!(v.programmed_ns, 1_096_000);
                Ok(1201)
            })
            .unwrap();
        let n = o.report(1201, &mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state, ActionStatus::Applied);
        o.verify_report(&r).unwrap();
        assert_eq!(
            o.verify_report(&ApplyReportV1 {
                action: &[50, 0],
                ..r
            }),
            Err(Error::Denied)
        );
        assert_eq!(o.retire(&r, || Err(Error::NotReady)), Err(Error::NotReady));
        o.retire(&r, || Ok(())).unwrap();
        assert_eq!(o.unregister(SOFT, || panic!()), Err(Error::Busy));
        o.complete(a, 1_096_000, || Ok(())).unwrap();
        o.unregister(SOFT, || Ok(())).unwrap();
    }
    #[test]
    fn unknown_programmed_arm_requires_exact_independent_proof_before_applied() {
        let mut o = owner();
        o.accept(&work(), 0, 10_000_000, 100, || Ok(())).unwrap();
        assert_eq!(
            o.arm(SOFT, 1_016_000, 200, |_| Err(Error::NotReady)),
            Err(Error::NotReady)
        );
        let mut out = [0; MAX_APPLY_REPORT_BYTES];
        let n = o.report(300, &mut out).unwrap();
        assert_eq!(
            ApplyReportV1::decode(&out[..n]).unwrap().state,
            ActionStatus::Unknown
        );
        assert_eq!(
            o.reconcile_arm(
                SOFT,
                400,
                ArmResolution::Programmed { completed_ns: 199 },
                |_, _| panic!()
            ),
            Err(Error::Clock)
        );
        o.reconcile_arm(
            SOFT,
            400,
            ArmResolution::Programmed { completed_ns: 250 },
            |e, _| {
                assert_eq!(e.proposed.programmed_ns, 1_096_000);
                assert_eq!(e.started_ns, 200);
                Ok(())
            },
        )
        .unwrap();
        let n = o.report(401, &mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state, ActionStatus::Applied);
        assert_eq!(r.completed_ns, 250);
        o.verify_report(&r).unwrap();
        o.retire(&r, || Ok(())).unwrap();
        assert_eq!(o.current(401), 0);
        assert_eq!(o.unregister(SOFT, || panic!()), Err(Error::Busy));
        let armed = o.entries[o.index(SOFT).unwrap()].unwrap().active.unwrap();
        o.complete(armed, armed.programmed_ns, || Ok(())).unwrap();
    }
    #[test]
    fn unknown_arm_retains_old_and_new_and_expiry_cannot_reopen() {
        let mut o = owner();
        let old = o.arm(SOFT, 1000, 100, |_| Ok(101)).unwrap();
        o.accept(&work(), 0, 10_000_000, 200, || Ok(())).unwrap();
        assert_eq!(
            o.arm(SOFT, 2000, 300, |_| Err(Error::NotReady)),
            Err(Error::NotReady)
        );
        let e = o.entries[o.index(SOFT).unwrap()].unwrap();
        assert_eq!(e.active, Some(old));
        assert!(e.pending.is_some());
        let mut out = [0; MAX_APPLY_REPORT_BYTES];
        let n = o.report(400, &mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state, ActionStatus::Unknown);
        assert_eq!(o.retire(&r, || panic!()), Err(Error::NotReady));
        assert_eq!(o.arm(SOFT, 3000, 500, |_| panic!()), Err(Error::NotReady));
        assert_eq!(
            o.reconcile_arm(SOFT, 399, ArmResolution::PriorUnchanged, |_, _| panic!()),
            Err(Error::Clock)
        );
        assert_eq!(
            o.reconcile_arm(SOFT, 500, ArmResolution::PriorUnchanged, |_, _| Err(
                Error::NotReady
            )),
            Err(Error::NotReady)
        );
        assert!(o.poisoned);
        o.reconcile_arm(SOFT, 500, ArmResolution::PriorUnchanged, |e, resolution| {
            assert_eq!(e.prior, Some(old));
            assert_eq!(e.proposed.requested_ns, 2000);
            assert_eq!(resolution, ArmResolution::PriorUnchanged);
            Ok(())
        })
        .unwrap();
        let n = o.report(501, &mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state, ActionStatus::Cancelled);
        o.retire(&r, || Ok(())).unwrap();
        assert_eq!(o.current(501), 0);
        assert_eq!(o.version(), 1);
        o.complete(old, 1000, || Ok(())).unwrap();
        o.unregister(SOFT, || Ok(())).unwrap();
        assert_eq!(
            o.register(SOFT, TimerClass::Soft, 80_000, || panic!()),
            Err(Error::Stale)
        );
        let next = Identity {
            generation: 2,
            ..SOFT
        };
        o.register(next, TimerClass::Soft, 80_000, || Ok(()))
            .unwrap();
        assert_eq!(o.arm(SOFT, 3000, 1001, |_| panic!()), Err(Error::Stale));
        let mut o = owner();
        o.accept(&work(), 0, 200, 100, || Ok(())).unwrap();
        let n = o.report(200, &mut out).unwrap();
        let r = ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state, ActionStatus::Cancelled);
        assert_eq!(o.arm(SOFT, 1000, 199, |_| panic!()), Err(Error::Clock));
        let a = o.arm(SOFT, 1000, 201, |_| Ok(202)).unwrap();
        assert_eq!(a.policy_version, 0);
        assert_eq!(a.programmed_ns, 1000);
    }
}
