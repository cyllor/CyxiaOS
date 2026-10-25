//! Host execution of the production session owner. Pool allocation/pin rules
//! and Governance are real sources; CPUs, clock, root registration and worker
//! exits are explicit synthetic fixtures. No native training data is created.
extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    learning::{
        Error,
        governance::*,
        validate::ValidatedCandidate,
        worker_wire::{JobBinding, JobIdentity},
    },
    model::MODEL_BYTES,
    policy::ModelBinding,
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
#[path = "../../../kernel/src/control_pool/ledger.rs"]
mod ledger;
#[path = "../../../kernel/src/learning_session.rs"]
mod session;
#[path = "support/learning.rs"]
mod support;
pub const HIGH: u64 = 0;
pub mod domain_services {
    pub fn canary_target() -> Result<cyxia_prototype::learning::governance::TargetRegistration, cyxia_prototype::domains::Error> {
        Err(cyxia_prototype::domains::Error::NotReady)
    }
}
pub mod learning_canary {
    use super::*;
    pub fn prepare_baseline(_: ObjectKey) -> Result<bool, Error> { Err(Error::DataIncomplete) }
    pub fn begin(_: CanaryPermit) -> Result<(), Error> { Err(Error::DataIncomplete) }
    pub fn changed_permit(_: CanaryPermit) -> Result<(), Error> { Err(Error::DataIncomplete) }
    pub fn request_release() {}
}
pub mod cpu {
    use super::*;
    static CPU: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        CPU.load(Ordering::Acquire)
    }
    pub fn set(value: usize) {
        CPU.store(value, Ordering::Release);
    }
}
pub mod domain_platform {
    use super::*;
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 {
        CLOCK.load(Ordering::Acquire)
    }
    pub fn set(value: u64) {
        CLOCK.store(value, Ordering::Release);
    }
}
pub mod domain_tasks {
    use super::*;
    pub static PAID: AtomicBool = AtomicBool::new(false);
    pub fn authorize_service_turn() -> Result<(), DomainError> {
        if cpu::slot() == 0 && PAID.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(DomainError::Auth)
        }
    }
}
pub mod control_pool {
    pub use super::ledger::{Allocation, Lease};
    use super::*;
    static LEDGER: Mutex<ledger::Ledger> = Mutex::new(ledger::Ledger::new());
    static ADDRESS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    pub static PIN_BUSY: AtomicBool = AtomicBool::new(false);
    pub static UNPIN_BUSY: AtomicBool = AtomicBool::new(false);
    fn base() -> usize {
        *ADDRESS.get_or_init(|| unsafe {
            let layout = std::alloc::Layout::from_size_align(8 * 1024 * 1024, 4096).unwrap();
            let p = std::alloc::alloc_zeroed(layout);
            assert!(!p.is_null());
            p as usize
        })
    }
    pub fn allocate(owner: ObjectKey, pages: usize) -> Result<Allocation, DomainError> {
        LEDGER.lock().unwrap().allocate(owner, pages)
    }
    pub fn pin(a: Allocation) -> Result<Lease, DomainError> {
        if PIN_BUSY.swap(false, Ordering::AcqRel) {
            return Err(DomainError::Busy);
        }
        LEDGER.lock().unwrap().pin(a)
    }
    pub fn pin_readonly(a: Allocation) -> Result<Lease, DomainError> {
        let mut l = LEDGER.lock().unwrap();
        if !l.sealed(a)? {
            return Err(DomainError::Auth);
        }
        l.pin(a)
    }
    pub fn unpin(p: &Lease) -> Result<(), DomainError> {
        if UNPIN_BUSY.swap(false, Ordering::AcqRel) {
            return Err(DomainError::Busy);
        }
        LEDGER.lock().unwrap().unpin(p)
    }
    pub fn span(a: Allocation) -> Result<(usize, u64, usize), DomainError> {
        LEDGER.lock().unwrap().validate(a)?;
        let p = base() + a.first() * 4096;
        Ok((p, p as u64, a.bytes()))
    }
    pub fn seal(a: Allocation, value: bool) -> Result<(), DomainError> {
        LEDGER.lock().unwrap().seal(a, value)
    }
    pub fn write(a: Allocation, bytes: &[u8]) -> Result<(), DomainError> {
        LEDGER.lock().unwrap().writable(a)?;
        assert!(bytes.len() <= a.bytes());
        let p = span(a)?.0;
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len()) }
        Ok(())
    }
    pub fn usage() -> (usize, usize, usize) {
        LEDGER.lock().unwrap().usage()
    }
}
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn binding(id: u64) -> JobBinding {
    JobBinding {
        boot_epoch: 11,
        job_id: id,
        controller_epoch: 9,
        core_generation: 1,
        model_generation: 7,
        data_generation: 1,
        role_context: key(99),
        image_hash: [9; 32],
        ledger_generation: 1,
    }
}
static ROOT_GATE: Mutex<Option<CommitGate>> = Mutex::new(None);
static ACTIVE_MODEL: Mutex<Option<(control_pool::Allocation, ModelBinding)>> = Mutex::new(None);
static FINISH_BUSY: AtomicBool = AtomicBool::new(false);
static SEQUENCE: AtomicU64 = AtomicU64::new(100);
static ROOT_SCORE: Mutex<Option<ObjectKey>> = Mutex::new(None);

pub mod domain_control {
    use super::*;
    pub struct NativeModelPin {
        lease: control_pool::Lease,
        physical: u64,
        binding: ModelBinding,
    }
    impl NativeModelPin {
        pub fn physical_address(&self) -> u64 {
            self.physical
        }
        pub fn binding(&self) -> ModelBinding {
            self.binding
        }
    }
    pub fn release_job_model(p: &NativeModelPin) -> Result<(), DomainError> {
        control_pool::unpin(&p.lease)
    }
    pub fn pin(a: control_pool::Allocation, binding: ModelBinding) -> NativeModelPin {
        NativeModelPin {
            lease: control_pool::pin_readonly(a).unwrap(),
            physical: control_pool::span(a).unwrap().1,
            binding,
        }
    }
    pub mod learning_driver {
        use super::*;
        pub struct ValidationDelivery {
            pub job: JobBinding,
            pub binding: ModelBinding,
            candidate: Option<ValidatedCandidate<'static>>,
            pin: Option<NativeModelPin>,
        }
        impl ValidationDelivery {
            pub fn new(
                job: JobBinding,
                candidate: ValidatedCandidate<'static>,
                pin: NativeModelPin,
            ) -> Self {
                Self {
                    job,
                    binding: pin.binding(),
                    candidate: Some(candidate),
                    pin: Some(pin),
                }
            }
            pub fn candidate<'a>(&'a self) -> Result<&'a ValidatedCandidate<'a>, Error> {
                self.candidate.as_ref().ok_or(Error::State)
            }
            pub fn release(&mut self) -> Result<(), Error> {
                self.candidate = None;
                if let Some(pin) = self.pin.as_ref() {
                    release_job_model(pin).map_err(|_| Error::Unknown)?;
                    self.pin = None;
                }
                Ok(())
            }
        }
    }
    pub mod learning_coordinator {
        use super::*;
        pub fn pin_active() -> Result<NativeModelPin, Error> {
            let (a, b) = ACTIVE_MODEL.lock().unwrap().ok_or(Error::State)?;
            Ok(super::pin(a, b))
        }
        pub fn prepare_governance<'a, 'm>(
            c: &'a ValidatedCandidate<'m>,
            old: &'a [u8; MODEL_BYTES],
            window: u64,
        ) -> Result<GovernanceInit<'a, 'm>, Error> {
            GovernanceInit::new(ROOT_GATE.lock().unwrap().as_ref().unwrap(), c, old, window)
        }
        pub fn finish_governance<'a, 'm>(
            init: &mut Option<GovernanceInit<'a, 'm>>,
        ) -> Result<InitComplete<'a, 'm>, Error> {
            if FINISH_BUSY.swap(false, Ordering::AcqRel) {
                return Err(Error::Unknown);
            }
            let lock = ROOT_GATE.lock().unwrap();
            let gate = lock.as_ref().unwrap();
            init.as_ref().ok_or(Error::State)?.check_finish(gate)?;
            init.take().unwrap().finish(gate)
        }
        pub fn promote(g: &mut Governance<'_, '_>) -> Result<ModelBinding, Error> {
            g.promote(
                ROOT_GATE.lock().unwrap().as_mut().unwrap(),
                domain_platform::now_ns(),
            )
        }
        pub fn rollback(g: &mut Governance<'_, '_>) -> Result<ModelBinding, Error> {
            g.rollback(ROOT_GATE.lock().unwrap().as_mut().unwrap())
        }
    }
    pub mod governance {
        use super::*;
        use cyxia_prototype::{
            features::RawFeatures,
            learning::{
                Family,
                reward::{RewardWorkspace, WorkRequest},
                score::{PreparedScore, Scored},
            },
            policy::{Candidate, CandidateSet, ExecutionState, Snapshot},
        };
        pub enum CanaryPublication {
            Published {
                apply: cyxia_prototype::domains::ApplyId,
                version: u64,
            },
            Rejected(Error),
        }
        pub fn prepare_score(
            g: &Governance<'_, '_>,
            role: Role,
            domain: u16,
            kind: u16,
            _: usize,
        ) -> Result<(CandidateSet, JobBinding), Error> {
            assert_eq!(role, Role::Shadow);
            assert!(ROOT_SCORE.lock().unwrap().is_none());
            let seq = SEQUENCE.fetch_add(1, Ordering::AcqRel);
            let choices: Vec<_> = support::choices(Family { domain, kind })
                .into_iter()
                .map(|action| Candidate {
                    action,
                    features: RawFeatures {
                        control_capacity: Some(1000),
                        ..RawFeatures::default()
                    },
                })
                .collect();
            let set = CandidateSet::new(
                Snapshot {
                    sequence: seq,
                    taken_ns: domain_platform::now_ns(),
                    core_generation: 1,
                    ledger_generation: 1,
                },
                key(15),
                g.original_binding(),
                &choices,
                Some(choices[0].action),
            )
            .unwrap();
            let b = binding(seq);
            *ROOT_SCORE.lock().unwrap() = Some(ObjectKey {
                id: b.job_id,
                generation: b.boot_epoch,
            });
            Ok((set, b))
        }
        pub fn prepare_score_into(
            out: &mut core::mem::MaybeUninit<CandidateSet>,
            g: &Governance<'_, '_>,
            role: Role,
            domain: u16,
            kind: u16,
            ordinal: usize,
        ) -> Result<JobBinding, Error> {
            let (set, binding) = prepare_score(g, role, domain, kind, ordinal)?;
            out.write(set);
            Ok(binding)
        }
        pub fn submit_score(
            _: &Governance<'_, '_>,
            p: &PreparedScore,
            a: control_pool::Allocation,
        ) -> Result<ObjectKey, Error> {
            smp::prototype_runtime::submit(p.identity(), a)
        }
        pub fn accept_score(
            _: &Governance<'_, '_>,
            _: &mut PreparedScore,
            _: &[u8],
            _: &WorkReceipt,
        ) -> Result<Scored, Error> {
            Err(Error::DataIncomplete)
        }
        pub fn record_shadow(
            _: &mut Governance<'_, '_>,
            _: &mut Option<Scored>,
            _: &mut Option<WorkReceipt>,
        ) -> Result<(), Error> {
            Err(Error::DataIncomplete)
        }
        pub fn publish_canary(
            _: &mut Governance<'_, '_>,
            _: &mut Option<Scored>,
            _: &mut Option<WorkReceipt>,
        ) -> Result<CanaryPublication, Error> {
            Err(Error::DataIncomplete)
        }
        pub fn close_score(job: ObjectKey) -> Result<(), Error> {
            assert_eq!(*ROOT_SCORE.lock().unwrap(), Some(job));
            smp::prototype_runtime::ack(job)?;
            *ROOT_SCORE.lock().unwrap() = None;
            Ok(())
        }
        pub fn close_shadow_window(g: &mut Governance<'_, '_>) -> Result<(), Error> {
            g.close_shadow_window(domain_platform::now_ns())
        }
        pub fn begin_canary(_: &mut Governance<'_, '_>) -> Result<CanaryPermit, Error> {
            Err(Error::DataIncomplete)
        }
        pub fn reconcile(
            _: &mut Governance<'_, '_>,
            _: cyxia_prototype::domains::ApplyId,
            _: u64,
        ) -> Result<ExecutionState, Error> {
            Err(Error::DataIncomplete)
        }
        pub fn tick(g: &mut Governance<'_, '_>) -> Result<(), Error> {
            g.tick(
                ROOT_GATE.lock().unwrap().as_mut().unwrap(),
                domain_platform::now_ns(),
            );
            Ok(())
        }
        pub fn abort(g: &mut Governance<'_, '_>, reason: Error) -> Result<(), Error> {
            g.abort(ROOT_GATE.lock().unwrap().as_mut().unwrap(), reason);
            Ok(())
        }
        pub fn restore(_: &mut Governance<'_, '_>) -> Result<ExecutionState, Error> {
            Err(Error::DataIncomplete)
        }
        pub fn observe_second(
            _: &mut Governance<'_, '_>,
            _: u16,
            _: &[WorkRequest],
            _: &[WorkRequest],
            _: &mut RewardWorkspace,
        ) -> Result<(), Error> {
            Err(Error::DataIncomplete)
        }
        pub fn extend(_: &mut Governance<'_, '_>, _: u16) -> Result<(), Error> {
            Err(Error::DataIncomplete)
        }
        pub fn observe_second_bounded(_: &mut Governance<'_, '_>, _:u16, _:&[WorkRequest], _:&[WorkRequest], _:&mut[u64])->Result<(),Error> {
            Err(Error::DataIncomplete)
        }
        pub fn safety_tick(g: &mut Governance<'_, '_>) -> Result<(), Error> {
            domain_tasks::authorize_service_turn().map_err(|_| Error::State)?;
            tick(g)
        }
        pub fn safety_abort(g: &mut Governance<'_, '_>, e: Error) -> Result<(), Error> {
            domain_tasks::authorize_service_turn().map_err(|_| Error::State)?;
            abort(g, e)
        }
        pub fn safety_reconcile(
            g: &mut Governance<'_, '_>,
            a: cyxia_prototype::domains::ApplyId,
            v: u64,
        ) -> Result<ExecutionState, Error> {
            domain_tasks::authorize_service_turn().map_err(|_| Error::State)?;
            reconcile(g, a, v)
        }
        pub fn safety_restore(g: &mut Governance<'_, '_>) -> Result<ExecutionState, Error> {
            domain_tasks::authorize_service_turn().map_err(|_| Error::State)?;
            restore(g)
        }
    }
}
pub mod smp {
    pub mod prototype_runtime {
        use super::super::*;
        pub static EXTRA: AtomicBool = AtomicBool::new(false);
        pub static ACKS: AtomicUsize = AtomicUsize::new(0);
        pub static CANCELS: AtomicUsize = AtomicUsize::new(0);
        static WORKSPACE: Mutex<Option<control_pool::Allocation>> = Mutex::new(None);
        static INPUT: Mutex<Option<control_pool::Allocation>> = Mutex::new(None);
        static PENDING: Mutex<Option<(ObjectKey, LearningStatus, control_pool::Lease)>> =
            Mutex::new(None);
        #[derive(Clone, Copy)]
        pub enum LearningStatus {
            Pending,
            Running,
            Complete { bytes: usize },
            DataIncomplete,
            Cancelled,
            Failed(u64),
        }
        pub struct LearningInputLoan {
            a: control_pool::Allocation,
            pin: Option<control_pool::Lease>,
        }
        pub fn authorize_learning_turn() -> Result<(), DomainError> {
            if cpu::slot() == 1 && EXTRA.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(DomainError::Auth)
            }
        }
        pub fn learning_session_workspace() -> Result<control_pool::Allocation, DomainError> {
            let mut slot = WORKSPACE.lock().unwrap();
            if let Some(a) = *slot {
                return Ok(a);
            }
            let a = control_pool::allocate(
                ObjectKey {
                    id: 0x4c4553455353,
                    generation: 1,
                },
                6,
            )?;
            *slot = Some(a);
            Ok(a)
        }
        pub fn prepare_input() {
            *INPUT.lock().unwrap() = Some(control_pool::allocate(key(333), 128).unwrap());
        }
        pub fn borrow_learning_input() -> Result<LearningInputLoan, DomainError> {
            authorize_learning_turn()?;
            assert!(PENDING.lock().unwrap().is_none());
            let a = INPUT.lock().unwrap().unwrap();
            control_pool::seal(a, false)?;
            Ok(LearningInputLoan {
                a,
                pin: Some(control_pool::pin(a)?),
            })
        }
        pub fn learning_input_span(l: &LearningInputLoan) -> Result<(usize, usize), DomainError> {
            if l.pin.is_none() {
                return Err(DomainError::Auth);
            }
            let (b, _, n) = control_pool::span(l.a)?;
            Ok((b, n))
        }
        pub fn seal_learning_input(
            l: &mut LearningInputLoan,
        ) -> Result<control_pool::Allocation, DomainError> {
            if let Some(pin) = l.pin.as_ref() {
                control_pool::unpin(pin)?;
                l.pin = None;
            }
            control_pool::seal(l.a, true)?;
            Ok(l.a)
        }
        pub fn abandon_learning_input(l: &mut LearningInputLoan) -> Result<(), DomainError> {
            assert!(PENDING.lock().unwrap().is_none());
            if let Some(pin) = l.pin.as_ref() {
                control_pool::unpin(pin)?;
                l.pin = None;
            }
            control_pool::seal(l.a, false)
        }
        pub fn submit(
            identity: JobIdentity,
            a: control_pool::Allocation,
        ) -> Result<ObjectKey, Error> {
            let job = ObjectKey {
                id: identity.binding.job_id,
                generation: identity.binding.boot_epoch,
            };
            let pin = control_pool::pin_readonly(a).unwrap();
            *PENDING.lock().unwrap() = Some((job, LearningStatus::Pending, pin));
            Ok(job)
        }
        pub fn query_learning(job: ObjectKey) -> Result<LearningStatus, DomainError> {
            let p = PENDING.lock().unwrap();
            let p = p.as_ref().ok_or(DomainError::NotReady)?;
            assert_eq!(p.0, job);
            Ok(p.1)
        }
        pub fn cancel_learning(job: ObjectKey) -> Result<(), DomainError> {
            assert!(query_learning(job).is_ok());
            CANCELS.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        pub fn read_learning_result(
            _: ObjectKey,
            _: usize,
            _: &mut [u8],
        ) -> Result<(), DomainError> {
            Err(DomainError::NotReady)
        }
        pub fn take_learning_score_receipt(_: ObjectKey) -> Result<WorkReceipt, DomainError> {
            Err(DomainError::NotReady)
        }
        pub fn cancelled() {
            PENDING.lock().unwrap().as_mut().unwrap().1 = LearningStatus::Cancelled;
        }
        pub fn ack(job: ObjectKey) -> Result<(), Error> {
            let mut p = PENDING.lock().unwrap();
            let Some((id, status, pin)) = p.as_ref() else {
                return Ok(());
            };
            assert_eq!(*id, job);
            if matches!(status, LearningStatus::Pending | LearningStatus::Running) {
                return Err(Error::Unknown);
            }
            control_pool::unpin(pin).map_err(|_| Error::Unknown)?;
            *p = None;
            ACKS.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }
}

#[test]
fn real_session_initializes_in_place_retries_exact_pins_and_keeps_unknown_score_custody() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            support::with_candidate(|candidate, old| {
                cpu::set(0);
                domain_platform::set(1_000_000);
                let active = ModelBinding {
                    generation: 7,
                    model_hash: candidate.parent_hash(),
                    schema_hash: support::schemas().feature.hash,
                };
                *ROOT_GATE.lock().unwrap() = Some(CommitGate::new(11, active).unwrap());
                let old_a = control_pool::allocate(key(101), 1).unwrap();
                control_pool::write(old_a, old).unwrap();
                control_pool::seal(old_a, true).unwrap();
                *ACTIVE_MODEL.lock().unwrap() = Some((old_a, active));
                let new_a = control_pool::allocate(key(102), 1).unwrap();
                control_pool::write(new_a, candidate.model().bytes()).unwrap();
                control_pool::seal(new_a, true).unwrap();
                let frozen =
                    unsafe { &*(control_pool::span(new_a).unwrap().0 as *const [u8; MODEL_BYTES]) };
                let next = ModelBinding {
                    model_hash: candidate.model().manifest().parameters_hash,
                    ..active
                };
                let delivery = domain_control::learning_driver::ValidationDelivery::new(
                    binding(50),
                    candidate.rebind(frozen).unwrap(),
                    domain_control::pin(new_a, next),
                );
                smp::prototype_runtime::prepare_input();
                control_pool::PIN_BUSY.store(true, Ordering::Release);
                assert_eq!(session::init(), Err(DomainError::Busy));
                let partial = control_pool::usage();
                session::init().unwrap();
                session::init().unwrap();
                let ready = control_pool::usage();
                assert_eq!(ready.0, partial.0 + 35);
                assert_eq!(ready.1, partial.1 + 1);
                let sizes = session::test_support::sizes();
                assert!(
                    sizes[0] <= 4096
                        && sizes[1] <= 8192
                        && sizes[2] <= 12288
                        && sizes[3] <= 35 * 4096
                );
                println!("native session actual typed sizes: anchors/set/state/Gov={sizes:?}");
                cpu::set(1);
                assert_eq!(session::turn(), Err(DomainError::Auth));
                smp::prototype_runtime::EXTRA.store(true, Ordering::Release);
                assert_eq!(session::turn().unwrap(), session::Turn::Progress);
                let delivery = session::test_support::with_gate(|| session::accept(delivery))
                    .unwrap_err()
                    .1;
                session::accept(delivery).map_err(|(e, _)| e).unwrap();
                for _ in 0..500 {
                    if session::status().unwrap().phase == session::Phase::FinishInit {
                        break;
                    }
                    session::turn().unwrap();
                }
                assert_eq!(session::status().unwrap().phase, session::Phase::FinishInit);
                FINISH_BUSY.store(true, Ordering::Release);
                assert_eq!(session::turn().unwrap(), session::Turn::Retry);
                // The same initialized allocation survives Busy and a missed future
                // window. Only the final shadow-start typed field is written again.
                domain_platform::set(251_000_000);
                session::turn().unwrap();
                assert_eq!(session::status().unwrap().phase, session::Phase::Initialize);
                session::turn().unwrap();
                session::turn().unwrap();
                assert_eq!(session::status().unwrap().stage, Some(Stage::Shadow));
                assert_eq!(session::turn().unwrap(), session::Turn::Retry);
                domain_platform::set(300_001_000);
                for _ in 0..100 {
                    if session::status().unwrap().phase == session::Phase::Wait {
                        break;
                    }
                    session::turn().unwrap();
                }
                let waiting = session::status().unwrap();
                assert_eq!(waiting.phase, session::Phase::Wait);
                assert!(waiting.job.is_some());
                assert_eq!(session::turn().unwrap(), session::Turn::Waiting);
                let pins = control_pool::usage().2;
                cpu::set(0);
                assert_eq!(session::safety_turn(), Err(DomainError::Auth));
                session::request_abort(Error::Budget).unwrap();
                domain_tasks::PAID.store(true, Ordering::Release);
                session::safety_turn().unwrap();
                assert_eq!(session::status().unwrap().stage, Some(Stage::Rejected));
                assert_eq!(control_pool::usage().2, pins);
                assert_eq!(smp::prototype_runtime::ACKS.load(Ordering::Acquire), 0);
                cpu::set(1);
                for _ in 0..4 {
                    session::turn().unwrap();
                }
                assert_eq!(
                    session::status().unwrap().phase,
                    session::Phase::CleanupScore
                );
                assert_eq!(smp::prototype_runtime::CANCELS.load(Ordering::Acquire), 1);
                assert_eq!(smp::prototype_runtime::ACKS.load(Ordering::Acquire), 0);
                assert_eq!(control_pool::usage().2, pins);
                smp::prototype_runtime::cancelled();
                control_pool::UNPIN_BUSY.store(true, Ordering::Release);
                assert_eq!(session::turn().unwrap(), session::Turn::Retry);
                assert_eq!(control_pool::usage().2, pins);
                for _ in 0..16 {
                    session::turn().unwrap();
                    if session::status().unwrap().phase == session::Phase::Idle {
                        break;
                    }
                }
                assert_eq!(session::status().unwrap().phase, session::Phase::Idle);
                assert_eq!(smp::prototype_runtime::ACKS.load(Ordering::Acquire), 1);
                assert_eq!(control_pool::usage().2, 2); // only the two permanent owner banks
                assert_eq!(ROOT_GATE.lock().unwrap().as_ref().unwrap().active(), active);
                assert_eq!(session::status().unwrap().completed, 0);

                // If the extra executor stops during preparation, CPU0 must
                // still enforce the original 50 ms boundary. It ends only
                // the encoder borrow; C1 retains exact cleanup custody.
                let delivery = domain_control::learning_driver::ValidationDelivery::new(
                    binding(51),
                    candidate.rebind(frozen).unwrap(),
                    domain_control::pin(new_a, next),
                );
                session::accept(delivery).map_err(|(e, _)| e).unwrap();
                for _ in 0..500 {
                    session::turn().unwrap();
                    if session::status().unwrap().phase == session::Phase::Manage {
                        break;
                    }
                }
                domain_platform::set(400_001_000);
                for _ in 0..100 {
                    session::turn().unwrap();
                    if session::status().unwrap().phase == session::Phase::Encode {
                        break;
                    }
                }
                assert_eq!(session::status().unwrap().phase, session::Phase::Encode);
                let preparation_pins = control_pool::usage().2;
                domain_platform::set(450_001_001);
                cpu::set(0);
                session::safety_turn().unwrap();
                assert_eq!(
                    session::status().unwrap().phase,
                    session::Phase::CleanupScore
                );
                assert_eq!(session::status().unwrap().stage, Some(Stage::Rejected));
                assert_eq!(control_pool::usage().2, preparation_pins);
                assert_eq!(smp::prototype_runtime::ACKS.load(Ordering::Acquire), 1);
                cpu::set(1);
                for _ in 0..16 {
                    session::turn().unwrap();
                    if session::status().unwrap().phase == session::Phase::Idle {
                        break;
                    }
                }
                assert_eq!(session::status().unwrap().phase, session::Phase::Idle);
                assert_eq!(control_pool::usage().2, 2);
                assert_eq!(smp::prototype_runtime::ACKS.load(Ordering::Acquire), 1);
                assert_eq!(smp::prototype_runtime::CANCELS.load(Ordering::Acquire), 1);
            })
        })
        .unwrap()
        .join()
        .unwrap();
}
