//! Per-object stability from executor receipts and owner-measured service
//! windows. No policy score or invented default metric is evidence of service.
use crate::domains::{Action, Error, ObjectKey};
use crate::policy::ExecutionState;

pub const SECOND_NS: u64 = 1_000_000_000;
const REVERSALS_TO_FREEZE: usize = 5;
const BREACHES_TO_FREEZE: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreezeReason {
    Reversals,
    ServiceBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionEffect {
    Ignored,
    Duplicate,
    Renewal,
    Changed,
}

/// Units and metric identity are chosen by the registered executor before
/// collecting the first window. Limits are inclusive. A new threshold requires
/// a different object generation; renewal cannot rewrite this configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub id: u64,
    pub metric: u16,
    pub minimum: u64,
    pub maximum: u64,
    pub min_samples: u64,
}

/// Supplied only through the protected owner callback. Coverage measures the
/// actually observed part of this exact window, not its nominal wall duration.
/// None, partial coverage, or too few samples is explicitly incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceWindow {
    pub target: ObjectKey,
    pub domain: u16,
    pub kind: u16,
    pub boundary_id: u64,
    pub metric: u16,
    pub start_ns: u64,
    pub end_ns: u64,
    pub covered_ns: u64,
    pub samples: u64,
    pub value: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Unregistered,
    Awaiting,
    Missing,
    Incomplete,
    WithinBoundary,
    Breached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowOutcome {
    pub status: ServiceStatus,
    pub repeated: bool,
    pub missed_windows: u64,
    pub consecutive_breaches: u8,
    pub frozen: Option<FreezeReason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegisteredBoundary {
    boundary: Boundary,
    origin_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowRecord {
    start_ns: u64,
    covered_ns: u64,
    samples: u64,
    value: Option<u64>,
}

/// Copyable fixed backing for one exact (target, action-family) identity. Root
/// keeps this state across desired versions and only retires it with the real
/// object generation. Freeze is sticky; completing old obligations is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guard {
    target: ObjectKey,
    current: Action,
    observed_action: Action,
    observed_version: u64,
    applied_version: u64,
    last_now_ns: u64,
    last_change_ns: u64,
    reversal_ns: [u64; REVERSALS_TO_FREEZE],
    boundary: Option<RegisteredBoundary>,
    last_window: Option<WindowRecord>,
    direction: i8,
    reversals: u8,
    breaches: u8,
    frozen: Option<FreezeReason>,
}

impl Guard {
    /// Baseline is actual owner state, not an APPLIED event. Initialization
    /// establishes the initial hold origin without recording a reversal.
    pub fn new(target: ObjectKey, baseline: Action, now_ns: u64) -> Result<Self, Error> {
        if target.id == 0 || target.generation == 0 {
            return Err(Error::Stale);
        }
        if baseline != Action::OfferCpu(0) { baseline.validate()?; }
        Ok(Self {
            target,
            current: baseline,
            observed_action: baseline,
            observed_version: 0,
            applied_version: 0,
            last_now_ns: now_ns,
            last_change_ns: now_ns,
            reversal_ns: [0; REVERSALS_TO_FREEZE],
            boundary: None,
            last_window: None,
            direction: 0,
            reversals: 0,
            breaches: 0,
            frozen: None,
        })
    }

    pub const fn target(&self) -> ObjectKey {
        self.target
    }
    pub const fn family(&self) -> (u16, u16) {
        (self.current.domain(), self.current.kind())
    }
    pub const fn current(&self) -> Action {
        self.current
    }
    pub const fn applied_version(&self) -> u64 {
        self.applied_version
    }
    pub const fn last_change_ns(&self) -> u64 {
        self.last_change_ns
    }
    pub const fn frozen(&self) -> bool {
        self.frozen.is_some()
    }
    pub const fn freeze_reason(&self) -> Option<FreezeReason> {
        self.frozen
    }
    pub const fn consecutive_breaches(&self) -> u8 {
        self.breaches
    }
    /// The quote owner may expire or explicitly stop new quotes without a
    /// model action. Preserve version, freeze and reversal history, and start
    /// a conservative new hold when that real stopped state is observed.
    pub fn observe_stopped_offer(&mut self, now_ns: u64) -> Result<(), Error> {
        self.time(now_ns)?;
        if self.family() != (16, 1) { return Err(Error::Conflict); }
        if self.current != Action::OfferCpu(0) {
            self.current = Action::OfferCpu(0);
            self.last_change_ns = now_ns;
        }
        self.last_now_ns = now_ns;
        Ok(())
    }
    fn time(&self, now_ns: u64) -> Result<(), Error> {
        if now_ns < self.last_now_ns {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn ordered(action: Action) -> bool {
        !action.one_shot() && !matches!(action, Action::IrqTarget(_))
    }

    /// Closed rolling interval [now - 1 s, now]: events exactly one second
    /// apart remain included. No arbitrary bucket origin can hide reversals.
    pub fn reversals_in_window(&self, now_ns: u64) -> Result<u8, Error> {
        self.time(now_ns)?;
        let count = self.reversal_ns[..usize::from(self.reversals)]
            .iter()
            .filter(|at| now_ns - **at <= SECOND_NS)
            .count();
        u8::try_from(count).map_err(|_| Error::Overflow)
    }

    /// Pending, Failed, and Unknown never move the actual current value, hold
    /// time, or reversal history. Their exact version/action identity is still
    /// retained, preventing a retry from rebinding an observed version.
    pub fn observe_execution(
        &mut self,
        version: u64,
        action: Action,
        state: ExecutionState,
        now_ns: u64,
    ) -> Result<ExecutionEffect, Error> {
        self.time(now_ns)?;
        action.validate()?;
        if (action.domain(), action.kind()) != self.family() {
            return Err(Error::Conflict);
        }
        if version == 0 || version < self.observed_version {
            return Err(Error::Stale);
        }
        if version == self.observed_version && action != self.observed_action {
            return Err(Error::Conflict);
        }
        self.observed_action = action;
        self.observed_version = version;
        self.last_now_ns = now_ns;
        if state != ExecutionState::Applied {
            return Ok(ExecutionEffect::Ignored);
        }
        if version == self.applied_version {
            return Ok(ExecutionEffect::Duplicate);
        }
        self.applied_version = version;
        if action == self.current {
            return Ok(ExecutionEffect::Renewal);
        }
        if Self::ordered(action) {
            let direction = match action.order().cmp(&self.current.order()) {
                core::cmp::Ordering::Greater => 1,
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
            };
            if self.frozen.is_none() && direction != 0 {
                let mut retained = 0;
                for index in 0..usize::from(self.reversals) {
                    if now_ns - self.reversal_ns[index] <= SECOND_NS {
                        self.reversal_ns[retained] = self.reversal_ns[index];
                        retained += 1;
                    }
                }
                if self.direction != 0 && self.direction != direction {
                    // At most four reversals exist before the sticky freeze.
                    self.reversal_ns[retained] = now_ns;
                    retained += 1;
                    if retained == REVERSALS_TO_FREEZE {
                        self.frozen = Some(FreezeReason::Reversals);
                    }
                }
                self.reversals = retained as u8;
            }
            if direction != 0 {
                self.direction = direction;
            }
        }
        self.current = action;
        self.last_change_ns = now_ns;
        Ok(ExecutionEffect::Changed)
    }

    /// The first measurement window starts no earlier than registration. This
    /// rules out choosing thresholds after seeing the measured first window.
    /// An exact retry is idempotent and does not reset evidence or unfreeze.
    pub fn register_boundary(
        &mut self,
        boundary: Boundary,
        starts_at_ns: u64,
        now_ns: u64,
    ) -> Result<(), Error> {
        self.time(now_ns)?;
        let registration = RegisteredBoundary {
            boundary,
            origin_ns: starts_at_ns,
        };
        if let Some(old) = self.boundary {
            if old != registration {
                return Err(Error::Conflict);
            }
            self.last_now_ns = now_ns;
            return Ok(());
        }
        if boundary.id == 0 {
            return Err(Error::Format);
        }
        if boundary.minimum > boundary.maximum || boundary.min_samples == 0 {
            return Err(Error::Range);
        }
        if starts_at_ns < now_ns {
            return Err(Error::Stale);
        }
        starts_at_ns.checked_add(SECOND_NS).ok_or(Error::Overflow)?;
        self.boundary = Some(registration);
        self.last_now_ns = now_ns;
        Ok(())
    }

    pub const fn boundary(&self) -> Option<Boundary> {
        match self.boundary {
            Some(registered) => Some(registered.boundary),
            None => None,
        }
    }
    pub const fn window_origin_ns(&self) -> Option<u64> {
        match self.boundary {
            Some(registered) => Some(registered.origin_ns),
            None => None,
        }
    }
    fn classify(boundary: Boundary, window: WindowRecord) -> ServiceStatus {
        if window.covered_ns != SECOND_NS || window.samples < boundary.min_samples {
            return ServiceStatus::Incomplete;
        }
        match window.value {
            None => ServiceStatus::Incomplete,
            Some(value) if value < boundary.minimum || value > boundary.maximum => {
                ServiceStatus::Breached
            }
            Some(_) => ServiceStatus::WithinBoundary,
        }
    }

    pub fn observe_service(
        &mut self,
        window: ServiceWindow,
        now_ns: u64,
    ) -> Result<WindowOutcome, Error> {
        self.time(now_ns)?;
        let registered = self.boundary.ok_or(Error::NotReady)?;
        let boundary = registered.boundary;
        if window.target != self.target
            || (window.domain, window.kind) != self.family()
            || window.boundary_id != boundary.id
            || window.metric != boundary.metric
        {
            return Err(Error::Auth);
        }
        if window
            .start_ns
            .checked_add(SECOND_NS)
            .ok_or(Error::Overflow)?
            != window.end_ns
            || window.covered_ns > SECOND_NS
        {
            return Err(Error::Range);
        }
        if window.end_ns > now_ns {
            return Err(Error::NotReady);
        }
        let elapsed = window
            .start_ns
            .checked_sub(registered.origin_ns)
            .ok_or(Error::Stale)?;
        if elapsed % SECOND_NS != 0 {
            return Err(Error::Format);
        }
        let record = WindowRecord {
            start_ns: window.start_ns,
            covered_ns: window.covered_ns,
            samples: window.samples,
            value: window.value,
        };
        let status = Self::classify(boundary, record);
        let missed_windows = if let Some(old) = self.last_window {
            if record.start_ns < old.start_ns {
                return Err(Error::Stale);
            }
            if record.start_ns == old.start_ns {
                if record != old {
                    return Err(Error::Conflict);
                }
                self.last_now_ns = now_ns;
                return Ok(WindowOutcome {
                    status,
                    repeated: true,
                    missed_windows: 0,
                    consecutive_breaches: self.breaches,
                    frozen: self.frozen,
                });
            }
            let next = old.start_ns.checked_add(SECOND_NS).ok_or(Error::Overflow)?;
            record.start_ns.checked_sub(next).ok_or(Error::Stale)? / SECOND_NS
        } else {
            elapsed / SECOND_NS
        };
        let previous_breaches = if missed_windows == 0 {
            self.breaches
        } else {
            0
        };
        let breaches = if status == ServiceStatus::Breached {
            if previous_breaches < BREACHES_TO_FREEZE {
                previous_breaches.checked_add(1).ok_or(Error::Overflow)?
            } else {
                BREACHES_TO_FREEZE
            }
        } else {
            0
        };
        self.last_window = Some(record);
        self.last_now_ns = now_ns;
        self.breaches = breaches;
        if breaches == BREACHES_TO_FREEZE && self.frozen.is_none() {
            self.frozen = Some(FreezeReason::ServiceBoundary);
        }
        Ok(WindowOutcome {
            status,
            repeated: false,
            missed_windows,
            consecutive_breaches: breaches,
            frozen: self.frozen,
        })
    }

    /// Historical good service is never reported as current evidence after a
    /// complete subsequent window has elapsed without its owner measurement.
    pub fn service_status(&self, now_ns: u64) -> Result<ServiceStatus, Error> {
        self.time(now_ns)?;
        let Some(registered) = self.boundary else {
            return Ok(ServiceStatus::Unregistered);
        };
        let first_end = registered
            .origin_ns
            .checked_add(SECOND_NS)
            .ok_or(Error::Overflow)?;
        if now_ns < first_end {
            return Ok(ServiceStatus::Awaiting);
        }
        let Some(window) = self.last_window else {
            return Ok(ServiceStatus::Missing);
        };
        let next_end = window
            .start_ns
            .checked_add(2 * SECOND_NS)
            .ok_or(Error::Overflow)?;
        if now_ns >= next_end {
            return Ok(ServiceStatus::Missing);
        }
        Ok(Self::classify(registered.boundary, window))
    }
}

/// One adjacent step in the owner's sorted legal set. Stopped quotes are
/// owner state, never a candidate: reopening admits only the first positive
/// legal tier. Callers still enforce their hold, freeze, and authority gates.
pub fn adjacent(current: Action, selected: Action, legal: &[Option<Action>]) -> Result<bool, Error> {
    selected.validate()?;
    let selected_index = legal.iter().position(|a| *a == Some(selected)).ok_or(Error::Conflict)?;
    if current == Action::OfferCpu(0) {
        return Ok(matches!(selected, Action::OfferCpu(_))
            && legal.iter().position(Option::is_some) == Some(selected_index));
    }
    let previous = legal.iter().position(|a| *a == Some(current)).ok_or(Error::Stale)?;
    Ok(selected_index.abs_diff(previous) <= 1)
}
