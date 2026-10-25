//! Fixed, normally published partner configuration for a placement trial.
//! Every renewal retains its original snapshot and true owner receipt. This
//! is an explicit frozen value, not a permit to change another AI parameter.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Fixed {
    pub target: ObjectKey,
    pub action: Action,
}
pub(super) struct Ledger {
    receipts: [Option<Receipt>; 32],
    count: usize,
    issuing: Option<Snapshot>,
    cancelled_issuance: Option<Snapshot>,
    stopping: Option<Snapshot>,
    stopped: Option<Receipt>,
}
impl Ledger {
    pub const fn new() -> Self {
        Self {
            receipts: [None; 32],
            count: 0,
            issuing: None,
            cancelled_issuance: None,
            stopping: None,
            stopped: None,
        }
    }
}
fn fixed(r: &Root) -> Option<Fixed> {
    r.spectator.and_then(|p| p.fixture)
}
fn last(r: &Root) -> Option<Receipt> {
    r.fixture
        .count
        .checked_sub(1)
        .and_then(|i| r.fixture.receipts[i])
}
pub(super) fn ready(r: &Root) -> bool {
    fixed(r).is_none()
        || r.fixture.stopping.is_none()
            && last(r).is_some_and(|v| v.state == ExecutionState::Applied && v.stamp.live(now()))
}
pub(super) fn skip_wait(r: &Root, d: &Desired) -> bool {
    fixed(r).is_some_and(|f| f.target == d.apply.target && f.action == d.action)
}
pub(super) fn skip_config(r: &Root, c: Configuration) -> bool {
    r.fixture.stopping.is_some()
        && fixed(r).is_some_and(|f| f.target == c.target && f.action == c.action)
}
pub(super) fn closed(r: &Root) -> bool {
    fixed(r).is_none()
        || r.fixture
            .stopped
            .is_some_and(|v| v.state == ExecutionState::Applied && v.action == Action::OfferCpu(0))
}
fn snapshot(s: &State) -> Result<Snapshot, Error> {
    Ok(Snapshot {
        sequence: s.sequence.checked_add(1).ok_or(Error::Overflow)?,
        taken_ns: now(),
        core_generation: s.owner.context.core_generation,
        ledger_generation: s.owner.context.ledger_generation,
    })
}
pub(super) fn poll(s: &mut State, token: Token) -> Result<(), Error> {
    let Some(fixed) = fixed(root()) else {
        return Ok(());
    };
    if root().token != Some(token) {
        return Err(Error::Stale);
    }
    if root().fixture.stopping.is_some() {
        let _ = stop(s, token)?;
        return Ok(());
    }
    if let Some(mut old) = last(root()) {
        if !old.state.terminal() {
            let observed = receipt(s, old.apply, old.stamp, old.snapshot, old.action)?;
            let r = root_mut();
            let i = r.fixture.count.checked_sub(1).ok_or(Error::Stale)?;
            r.fixture.receipts[i] = Some(observed);
            if !observed.state.terminal() {
                return Ok(());
            }
            if observed.state != ExecutionState::Applied {
                return Err(Error::Conflict);
            }
            old = observed;
        }
        if old.state != ExecutionState::Applied {
            return Err(Error::Conflict);
        }
        if old.state == ExecutionState::Applied
            && old.stamp.installed_until_ns > now().saturating_add(2_000_000_000)
        {
            return Ok(());
        }
    }
    if root().fixture.count == root().fixture.receipts.len() {
        return Err(Error::Capacity);
    }
    if root().fixture.issuing.is_none() {
        let value = snapshot(s)?;
        root_mut().fixture.issuing = Some(value);
    }
    let value = root().fixture.issuing.ok_or(Error::Stale)?;
    let _cost = Prefix {
        start: now(),
        attempt: crate::learning_evidence::attempt(
            fixed.target,
            learning::reward::CpuClass::Policy,
        )
        .ok()
        .flatten(),
    };
    let published = publish_value(s, token, fixed.target, fixed.action, value)?;
    let r = root_mut();
    let index = r.fixture.count;
    r.fixture.receipts[index] = Some(published);
    r.fixture.count += 1;
    r.fixture.issuing = None;
    Ok(())
}
pub(super) fn stop(s: &mut State, token: Token) -> Result<bool, Error> {
    let Some(fixed) = fixed(root()) else {
        return Ok(true);
    };
    if root().token != Some(token) {
        return Err(Error::Stale);
    }
    if closed(root()) {
        return Ok(true);
    }
    if let Some(snapshot) = root().fixture.issuing {
        // Publication is synchronous under this root gate. A returned Busy
        // may precede commit or follow it while reading its receipt. Resolve
        // the retained identity against the real Desired table before stop;
        // never renew its deadline or publish a new positive fixture here.
        if s.job.is_some() || s.owner.prepared_count != 0 {
            return Err(Error::Busy);
        }
        let published = locate(&s.owner, fixed.action, fixed.target)
            .and_then(|i| s.owner.desired[i])
            .filter(|d| {
                d.apply.boot_epoch == token.boot_epoch && d.apply.plan_seq == snapshot.sequence
            });
        if let Some(d) = published {
            if d.action != fixed.action || d.stamp.snapshot_ns != snapshot.taken_ns {
                return Err(Error::Conflict);
            }
            let observed = receipt(s, d.apply, d.stamp, snapshot, fixed.action)?;
            let r = root_mut();
            let i = r.fixture.count;
            if i == r.fixture.receipts.len() {
                return Err(Error::Capacity);
            }
            r.fixture.receipts[i] = Some(observed);
            r.fixture.count += 1;
            r.fixture.issuing = None;
        } else {
            let r = root_mut();
            r.fixture.cancelled_issuance = Some(snapshot);
            r.fixture.issuing = None;
        }
    }
    if let Some(old) = last(root()).filter(|r| !r.state.terminal()) {
        let observed = receipt(s, old.apply, old.stamp, old.snapshot, old.action)?;
        let r = root_mut();
        let index = r.fixture.count.checked_sub(1).ok_or(Error::Stale)?;
        r.fixture.receipts[index] = Some(observed);
    }
    if last(root()).is_some_and(|r| !r.state.terminal()) {
        return Err(Error::Busy);
    }
    if root().fixture.stopping.is_none() {
        let snapshot = snapshot(s)?;
        s.sequence = snapshot.sequence;
        root_mut().fixture.stopping = Some(snapshot);
    }
    let snapshot = root().fixture.stopping.ok_or(Error::Stale)?;
    let callback = root()
        .registered
        .iter()
        .flatten()
        .find(|o| o.owner == token.owner)
        .ok_or(Error::Auth)?
        .stop_offer;
    let _cost = Prefix {
        start: now(),
        attempt: crate::learning_evidence::attempt(
            fixed.target,
            learning::reward::CpuClass::Policy,
        )
        .ok()
        .flatten(),
    };
    match callback(token, fixed.target, snapshot) {
        Ok(receipt)
            if receipt.action == Action::OfferCpu(0)
                && receipt.state == ExecutionState::Applied
                && receipt.snapshot == snapshot
                && receipt.apply.target == fixed.target =>
        {
            root_mut().fixture.stopped = Some(receipt);
            Ok(true)
        }
        Ok(_) => Err(Error::Conflict),
        Err(Error::Busy | Error::Again | Error::NotReady) => Ok(false),
        Err(e) => Err(e),
    }
}
