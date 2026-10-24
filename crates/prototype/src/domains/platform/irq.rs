use crate::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp};

pub const IRQ_ROUTE_TIMEOUT_NS: u64 = 50_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrqTopology {
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub route_generation: u64,
    pub healthy_business: u64,
    pub draining: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqCommitGuard {
    pub object: ObjectKey,
    pub desired_version: u64,
    pub topology: IrqTopology,
    pub allowed: u64,
    pub target_cpu: u16,
}

/// `synchronized` is a nonblocking observation, called without a cross-domain
/// lock. `commit_route` takes the core/route commit lock, rechecks every guard
/// field against current authority, writes the GIC route, then unmasks. On any
/// error it must leave the source masked and retain all DMA/IRQ obligations.
pub trait IrqHardware {
    fn topology(&self, irq: u32) -> Result<IrqTopology, Error>;
    fn mask(&mut self, irq: u32) -> Result<(), Error>;
    fn synchronized(&mut self, irq: u32) -> Result<bool, Error>;
    fn commit_route(&mut self, irq: u32, guard: IrqCommitGuard) -> Result<u64, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqReceipt {
    pub apply: Option<ApplyId>,
    pub target_cpu: u16,
    pub route_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqProgress {
    Pending,
    Applied(IrqReceipt),
    Degraded(Error),
}

#[derive(Clone, Copy)]
struct Pending {
    apply: Option<ApplyId>,
    guard: IrqCommitGuard,
    deadline_ns: u64,
}

/// One registered migratable device SPI. Timers, SGIs/IPIs and critical
/// exceptions cannot be constructed as this executor.
pub struct IrqRouter {
    key: ObjectKey,
    irq: u32,
    allowed: u64,
    policy: PolicyStamp,
    pending: Option<Pending>,
    last_apply: Option<ApplyId>,
    last_target: u16,
    last_result: Option<IrqProgress>,
    result: Option<IrqProgress>,
    masked: bool,
    pub handled: u64,
    pub handler_ns: u64,
    pub last_handler_cpu: Option<u16>,
}

impl IrqRouter {
    pub fn new(key: ObjectKey, irq: u32, allowed: u64) -> Result<Self, Error> {
        if key.generation == 0 || !(32..1020).contains(&irq) || allowed == 0 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            key,
            irq,
            allowed,
            policy: PolicyStamp::default(),
            pending: None,
            last_apply: None,
            last_target: 0,
            last_result: None,
            result: None,
            masked: false,
            handled: 0,
            handler_ns: 0,
            last_handler_cpu: None,
        })
    }

    pub fn request<H: IrqHardware>(
        &mut self,
        apply: ApplyId,
        stamp: PolicyStamp,
        target_cpu: u16,
        now_ns: u64,
        hardware: &mut H,
    ) -> Result<IrqProgress, Error> {
        Action::IrqTarget(target_cpu).validate()?;
        if apply.target != self.key {
            return Err(Error::Stale);
        }
        if self.last_apply == Some(apply) {
            return if self.last_target == target_cpu && self.policy == stamp {
                Ok(self.last_result.unwrap_or(IrqProgress::Pending))
            } else {
                Err(Error::Conflict)
            };
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.policy.accepts(stamp, now_ns)?;
        let topology = hardware.topology(self.irq)?;
        self.begin(
            Some(apply),
            stamp.version,
            target_cpu,
            topology,
            now_ns,
            hardware,
        )?;
        self.policy = stamp;
        self.last_apply = Some(apply);
        self.last_target = target_cpu;
        self.last_result = Some(IrqProgress::Pending);
        Ok(IrqProgress::Pending)
    }

    fn begin<H: IrqHardware>(
        &mut self,
        apply: Option<ApplyId>,
        version: u64,
        target_cpu: u16,
        topology: IrqTopology,
        now_ns: u64,
        hardware: &mut H,
    ) -> Result<(), Error> {
        let legal = self.allowed & topology.healthy_business & !topology.draining;
        if target_cpu >= 64 || legal & (1u64 << target_cpu) == 0 {
            return Err(Error::Auth);
        }
        let deadline_ns = now_ns
            .checked_add(IRQ_ROUTE_TIMEOUT_NS)
            .ok_or(Error::Overflow)?;
        hardware.mask(self.irq)?;
        self.masked = true;
        self.pending = Some(Pending {
            apply,
            guard: IrqCommitGuard {
                object: self.key,
                desired_version: version,
                topology,
                allowed: self.allowed,
                target_cpu,
            },
            deadline_ns,
        });
        self.result = Some(IrqProgress::Pending);
        Ok(())
    }

    /// SAFE_EXEC recomputes the current legal target. It never restores an old
    /// CPU that has since become control, unhealthy or draining.
    pub fn force_baseline<H: IrqHardware>(
        &mut self,
        now_ns: u64,
        hardware: &mut H,
    ) -> Result<IrqProgress, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let topology = hardware.topology(self.irq)?;
        let legal = self.allowed & topology.healthy_business & !topology.draining;
        if legal == 0 {
            hardware.mask(self.irq)?;
            self.masked = true;
            self.result = Some(IrqProgress::Degraded(Error::NotReady));
            return Ok(IrqProgress::Degraded(Error::NotReady));
        }
        self.begin(
            None,
            self.policy.version,
            legal.trailing_zeros() as u16,
            topology,
            now_ns,
            hardware,
        )?;
        Ok(IrqProgress::Pending)
    }

    pub fn poll<H: IrqHardware>(
        &mut self,
        now_ns: u64,
        hardware: &mut H,
    ) -> Result<IrqProgress, Error> {
        let Some(pending) = self.pending else {
            return self.result.ok_or(Error::NotFound);
        };
        let error = if now_ns >= pending.deadline_ns {
            Some(Error::Expired)
        } else if !hardware.synchronized(self.irq)? {
            return Ok(IrqProgress::Pending);
        } else {
            let current = hardware.topology(self.irq)?;
            let legal = self.allowed & current.healthy_business & !current.draining;
            if current != pending.guard.topology || legal & (1u64 << pending.guard.target_cpu) == 0
            {
                Some(Error::Stale)
            } else {
                None
            }
        };
        if let Some(error) = error {
            self.pending = None;
            let progress = IrqProgress::Degraded(error);
            self.result = Some(progress);
            if pending.apply.is_some() {
                self.last_result = Some(progress);
            }
            return Ok(progress);
        }
        let committed = hardware.commit_route(self.irq, pending.guard);
        self.pending = None;
        let progress = match committed {
            Ok(generation) if generation > pending.guard.topology.route_generation => {
                self.masked = false;
                IrqProgress::Applied(IrqReceipt {
                    apply: pending.apply,
                    target_cpu: pending.guard.target_cpu,
                    route_generation: generation,
                })
            }
            Ok(_) => {
                hardware.mask(self.irq)?;
                IrqProgress::Degraded(Error::Stale)
            }
            Err(error) => IrqProgress::Degraded(error),
        };
        self.result = Some(progress);
        if pending.apply.is_some() {
            self.last_result = Some(progress);
        }
        Ok(progress)
    }

    pub fn policy_expired(&self, now_ns: u64) -> bool {
        !self.policy.live(now_ns)
    }
    pub fn query(
        &self,
        apply: ApplyId,
        stamp: PolicyStamp,
        target: u16,
    ) -> Result<IrqProgress, Error> {
        if self.last_apply != Some(apply) {
            return Err(Error::Stale);
        }
        if self.policy != stamp || self.last_target != target {
            return Err(Error::Conflict);
        }
        Ok(self.last_result.unwrap_or(IrqProgress::Pending))
    }
    pub fn masked(&self) -> bool {
        self.masked
    }
    /// Invoke from the real handler's completion path, not from route install.
    pub fn record_handler(&mut self, cpu: u16, elapsed_ns: u64) {
        self.handled = self.handled.saturating_add(1);
        self.handler_ns = self.handler_ns.saturating_add(elapsed_ns);
        self.last_handler_cpu = Some(cpu);
    }
}
