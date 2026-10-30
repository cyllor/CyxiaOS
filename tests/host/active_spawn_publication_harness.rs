mod domain_tasks {
    use super::*;
    use cyxia_prototype::domains::tasks::{CpuLayout, Scheduler, SpawnAdmission};
    struct State {
        scheduler: Scheduler,
        admission: SpawnAdmission,
        layout: CpuLayout,
        draining: u64,
        spawn_receipts: [u64; 16],
    }
    static mut STATE: State = State {
        scheduler: Scheduler::new(),
        admission: SpawnAdmission::new(),
        layout: CpuLayout {
            business_mask: 9,
            healthy_mask: 15,
            generation: 4,
        },
        draining: 0,
        spawn_receipts: [0; 16],
    };
    // OWNER_GATE_PATH
    fn now_ns() -> u64 {
        WALL.load(Ordering::Acquire)
    }
    fn control_target(_: u16, _: u16, _: usize) -> Option<ObjectKey> {
        panic!("target discovery outside publication")
    }
    fn control_features(_: Action, _: ObjectKey) -> Result<TargetFeatures, Error> {
        panic!("feature extraction outside publication")
    }
    fn control_apply(
        _: Action,
        _: ApplyId,
        _: PolicyStamp,
        _: u64,
    ) -> Result<ExecutionState, Error> {
        panic!("execution outside publication")
    }
    fn control_reconcile(
        _: Action,
        _: ApplyId,
        _: PolicyStamp,
        _: u64,
    ) -> Result<ExecutionState, Error> {
        panic!("reconcile outside publication")
    }
    fn observation(_: u16, _: ObjectKey) -> Result<[u64; 4], Error> {
        panic!("observation outside publication")
    }
    // TASK_BODIES
    pub(super) fn fixture() {
        unsafe {
            let s = &mut *core::ptr::addr_of_mut!(STATE);
            s.scheduler = Scheduler::new();
            s.admission = SpawnAdmission::new();
            s.layout = CpuLayout {
                business_mask: 9,
                healthy_mask: 15,
                generation: 4,
            };
            s.draining = 0;
            s.scheduler.register_group(key(12)).unwrap();
            s.admission.register_group(key(12)).unwrap();
        }
    }
    pub(super) fn while_held(f: impl FnOnce()) {
        let guard = acquire_guard().unwrap();
        f();
        drop(guard);
        WALL.fetch_add(1_000_001, Ordering::AcqRel);
    }
    pub(super) fn set_role(mode: usize) {
        unsafe {
            let s = &mut *core::ptr::addr_of_mut!(STATE);
            match mode {
                0 => s.layout.business_mask |= 2,
                1 => s.draining = 2,
                2 => s.layout.healthy_mask &= !2,
                _ => panic!(),
            }
        }
    }
    pub(super) fn validate_foreign(
        action: Action,
        target: ObjectKey,
        at: u64,
    ) -> Result<(), Error> {
        super::CUSTOM_CALLS.fetch_add(1, Ordering::AcqRel);
        validate_action(action, target, at)
    }
    pub(super) fn query_foreign(
        domain: u16,
        kind: u16,
        target: ObjectKey,
    ) -> Result<Action, Error> {
        super::CUSTOM_CALLS.fetch_add(1, Ordering::AcqRel);
        control_current(domain, kind, target)
    }
    pub(super) fn options_foreign(
        options: &[Option<Action>],
        target: ObjectKey,
        at: u64,
        out: &mut [Option<Action>],
    ) -> Result<usize, Error> {
        super::CUSTOM_CALLS.fetch_add(1, Ordering::AcqRel);
        legal_options(options, target, at, out)
    }
}
// TESTS
use cyxia_prototype::{
    domains::stability::Guard as StabilityGuard, learning::governance::CommitGate,
};
static SLOT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
static ROOT_ALLOWED: AtomicBool = AtomicBool::new(true);
static CUSTOM_CALLS: AtomicU64 = AtomicU64::new(0);
static VALIDATIONS: AtomicU64 = AtomicU64::new(0);
static CURRENTS: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Debug, PartialEq, Eq)]
struct History {
    apply: ApplyId,
    version: u64,
    stamp: PolicyStamp,
    model: ModelBinding,
    selected: u16,
    scores: Vec<i16>,
    concurrent: Vec<ApplyId>,
}
thread_local! {static HISTORY:std::cell::RefCell<Option<History>>=const{std::cell::RefCell::new(None)};}
thread_local! {static FAMILIES:std::cell::RefCell<Vec<Family>>=const{std::cell::RefCell::new(Vec::new())};}
// ADMISSION_PATH
mod learning_canary {
    pub fn blocks_active() -> bool {
        false
    }
}
static ADMISSION: admission_view::AdmissionView = admission_view::AdmissionView::new();
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn setup_spawn(selected: u16) -> [u64; 512] {
    VALIDATIONS.store(0, Ordering::Release);
    CURRENTS.store(0, Ordering::Release);
    CPU.store(0, Ordering::Release);
    WALL.fetch_add(2_000_000_000, Ordering::AcqRel);
    SLOT.store(1, Ordering::Release);
    READS.store(0, Ordering::Release);
    EFFECTS.store(0, Ordering::Release);
    ACQUIRES.store(0, Ordering::Release);
    BORROWS.store(0, Ordering::Release);
    RELEASE_CPU.store(0, Ordering::Release);
    RELEASE_WALL.store(0, Ordering::Release);
    ACQUIRE_CPU.store(0, Ordering::Release);
    FINISHES.store(0, Ordering::Release);
    DELIVERY_BUSY.store(false, Ordering::Release);
    ROOT_ALLOWED.store(true, Ordering::Release);
    *FINISHED.lock().unwrap() = None;
    domain_tasks::fixture();
    FAMILIES.with(|v| v.borrow_mut().clear());
    domain_tasks::register_control().unwrap();
    let started = WALL.load(Ordering::Acquire);
    let mut original = candidates();
    original = CandidateSet::new(
        Snapshot {
            taken_ns: started,
            ..original.snapshot
        },
        key(12),
        binding(),
        &[1, 2, 4, 8].map(|n| Candidate {
            action: Action::SpawnTokens(n),
            features: RawFeatures::default(),
        }),
        Some(Action::SpawnTokens(2)),
    )
    .unwrap();
    let mut registry = Registry::new(11, publisher_fixture(), binding()).unwrap();
    registry.register(publisher_fixture(), &original).unwrap();
    let mut families = [None; 18];
    FAMILIES.with(|v| {
        for f in v.borrow().iter() {
            families[family_index(f.domain, f.kind).unwrap()] = Some(*f)
        }
    });
    let owner = Owner {
        context: Context {
            core_generation: 2,
            ledger_generation: 3,
            control_mask: 6,
            business_mask: 9,
            healthy_mask: 15,
            ..Default::default()
        },
        families,
        stability: [Some(
            StabilityGuard::new(key(12), Action::SpawnTokens(2), started - WINDOW_NS).unwrap(),
        )],
        stability_high: 1,
        dependencies: [None; 16],
        dependency_binders: [None; 16],
        prepared: [0; 16],
        prepared_count: 0,
        desired: [None],
    };
    let job = Job {
        cpu: 1,
        set: original,
        sequence: 1,
        controller: 9,
        base_version: 0,
        started,
        encode_ns: 1,
        evidence: Some(0),
        dependencies: [None; 2],
        work: None,
        read_only: false,
        completion: None,
        publication_debit: CpuTime { cpu: 1, ns: 0 },
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            owner,
            job: Some(job),
            registry,
            model_gate: Some(CommitGate::new(1, binding()).unwrap()),
            sequence: 1,
            boot: 11,
        })
    });
    let plan_header = PlanHeader {
        plan_seq: 1,
        base_plan_version: 0,
        active_model_generation: 1,
        controller_epoch: 9,
        snapshot_seq: original.snapshot.sequence,
        active_until_local_ns: started + POLICY_NS,
    };
    let decision = Decision {
        action: Action::SpawnTokens(selected),
        candidate_index: match selected {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => panic!(),
        },
        envelope: Envelope {
            controller_epoch: 9,
            decision_seq: 1,
            snapshot_seq: original.snapshot.sequence,
            target: key(12),
            ledger_generation: 3,
            core_generation: 2,
            expires_local_ns: started + WINDOW_NS,
            model_hash: binding().model_hash,
            candidate_set_hash: original.hash(),
        },
    };
    let mut wire = [0; MAX_PLAN_BYTES];
    let n = encode_plan(plan_header, &[decision], &mut wire).unwrap();
    let mut out = [0; 512];
    out[..8].copy_from_slice(&[
        77,
        3,
        1,
        9,
        decision.candidate_index as u64,
        n as u64,
        4,
        11,
    ]);
    out[8] = 1 << (16 * decision.candidate_index);
    for (i, chunk) in wire[..n].chunks(8).enumerate() {
        let mut b = [0; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        out[16 + i] = u64::from_le_bytes(b);
    }
    out
}
#[test]
fn spawn_exact_native_shares_one_physical_owner_acquisition_and_real_receipt() {
    let out = setup_spawn(4);
    assert_eq!(accept(&out, 10), Ok(1));
    assert_eq!(
        (
            VALIDATIONS.load(Ordering::Acquire),
            CURRENTS.load(Ordering::Acquire)
        ),
        (19, 4),
        "publication omitted validation, tier checks or final current selection"
    );
    assert_eq!(EFFECTS.load(Ordering::Acquire), 1);
    assert_eq!(FINISHED.lock().unwrap().unwrap().2, 1);
    assert_eq!(BORROWS.load(Ordering::Acquire), 0);
    assert_eq!(
        ACQUIRES.load(Ordering::Acquire),
        1,
        "native Spawn publication reacquired its physical owner gate"
    );
    with(|s| {
        let receipt = s.registry.query(
            publisher_fixture(),
            PlanId {
                boot_epoch: 11,
                controller_epoch: 9,
                plan_seq: 1,
            },
        )?;
        assert_eq!(receipt.version, 1);
        assert!(!s.registry.optimization_stopped());
        Ok(())
    })
    .unwrap();
}
fn receipt() -> PlanReceipt {
    with(|s| {
        s.registry.query(
            publisher_fixture(),
            PlanId {
                boot_epoch: 11,
                controller_epoch: 9,
                plan_seq: 1,
            },
        )
    })
    .unwrap()
}
#[test]
fn spawn_current_minhold_freeze_and_nonadjacent_keep_ordinary_selection() {
    for borrowed in [false, true] {
        for mode in 0..4 {
            let out = setup_spawn(if mode == 0 {
                2
            } else if mode == 3 {
                8
            } else {
                4
            });
            with(|s| {
                if !borrowed {
                    s.owner.families[2].as_mut().unwrap().current = domain_tasks::query_foreign;
                }
                let guard = s.owner.stability[0].as_mut().unwrap();
                if mode == 1 {
                    *guard = StabilityGuard::new(
                        key(12),
                        Action::SpawnTokens(2),
                        WALL.load(Ordering::Acquire),
                    )
                    .unwrap();
                }
                if mode == 2 {
                    let origin = WALL.load(Ordering::Acquire) - 1_900_000_000;
                    *guard = StabilityGuard::new(key(12), Action::SpawnTokens(2), origin).unwrap();
                    for (i, n) in [4, 2, 4, 2, 4, 2].into_iter().enumerate() {
                        guard
                            .observe_execution(
                                i as u64 + 1,
                                Action::SpawnTokens(n),
                                ExecutionState::Applied,
                                origin + (700 + i as u64 * 100) * 1_000_000,
                            )
                            .unwrap();
                    }
                    assert!(guard.frozen());
                }
                Ok(())
            })
            .unwrap();
            let expected = match mode {
                0 => Ok(1),
                1 | 2 => Err(Error::Busy),
                _ => Err(Error::Conflict),
            };
            assert_eq!(
                accept(&out, 10),
                expected,
                "ordinary Spawn selection changed: {borrowed}/{mode}"
            );
            assert_eq!(BORROWS.load(Ordering::Acquire), 0);
            if let Err(e) = expected {
                assert_eq!(receipt().state(), ExecutionState::Failed(e));
                assert_eq!(EFFECTS.load(Ordering::Acquire), 0);
            } else {
                assert_eq!(receipt().version, 1);
            }
        }
    }
}
#[test]
fn spawn_ineligible_callbacks_resolver_and_binder_keep_original_path() {
    for mode in 0..5 {
        let out = setup_spawn(4);
        CUSTOM_CALLS.store(0, Ordering::Release);
        with(|s| {
            let f = s.owner.families[2].as_mut().unwrap();
            match mode {
                0 => f.legal = domain_tasks::validate_foreign,
                1 => f.current = domain_tasks::query_foreign,
                2 => f.legal_options = domain_tasks::options_foreign,
                3 => {
                    s.owner.dependencies[1] =
                        Some(|_| panic!("ordinary D02 never resolves dependencies"))
                }
                4 => {
                    s.owner.dependency_binders[1] =
                        Some(|_, _| panic!("ordinary D02 never binds dependencies"))
                }
                _ => panic!(),
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(accept(&out, 10), Ok(1));
        assert_eq!(
            ACQUIRES.load(Ordering::Acquire),
            11,
            "ineligible native registration used a borrowed owner"
        );
        if mode < 3 {
            assert!(
                CUSTOM_CALLS.load(Ordering::Acquire) > 0,
                "custom callback was bypassed"
            );
        }
        assert_eq!(BORROWS.load(Ordering::Acquire), 0);
    }
}
#[test]
fn spawn_busy_precedes_registry_identity_retains_debit_and_original_deadline() {
    let out = setup_spawn(4);
    SLOT.store(0, Ordering::Release);
    domain_tasks::while_held(|| {
        SLOT.store(1, Ordering::Release);
        ACQUIRE_CPU.store(100_000, Ordering::Release);
        for debit in [100_001, 200_002] {
            assert_eq!(accept(&out, 10), Err(Error::Busy));
            with(|s| {
                let j = s.job.unwrap();
                assert_eq!(
                    (
                        j.sequence,
                        j.started,
                        j.completion.is_none(),
                        j.publication_debit.ns
                    ),
                    (1, j.set.snapshot.taken_ns, true, debit)
                );
                assert_eq!(s.registry.version(), 0);
                assert_eq!(
                    s.registry
                        .query(
                            publisher_fixture(),
                            PlanId {
                                boot_epoch: 11,
                                controller_epoch: 9,
                                plan_seq: 1
                            }
                        )
                        .err(),
                    Some(Error::Stale)
                );
                Ok(())
            })
            .unwrap();
        }
        SLOT.store(0, Ordering::Release);
    });
    SLOT.store(1, Ordering::Release);
    assert_eq!(accept(&out, 10), Ok(1));
    assert_eq!(
        FINISHED.lock().unwrap().unwrap().1,
        300_012,
        "same Job lost charged acquisition retry debit"
    );
    let out = setup_spawn(4);
    SLOT.store(0, Ordering::Release);
    domain_tasks::while_held(|| {
        SLOT.store(1, Ordering::Release);
        assert_eq!(accept(&out, 10), Err(Error::Busy));
        WALL.fetch_add(50_000_000, Ordering::AcqRel);
        SLOT.store(0, Ordering::Release);
    });
    SLOT.store(1, Ordering::Release);
    let acquisitions = ACQUIRES.load(Ordering::Acquire);
    assert_eq!(accept(&out, 10), Err(Error::Expired));
    assert_eq!(
        ACQUIRES.load(Ordering::Acquire),
        acquisitions,
        "retry renewed original deadline"
    );
    assert_eq!(BORROWS.load(Ordering::Acquire), 0);
}
#[test]
fn spawn_paid_release_overrun_keeps_real_receipt_and_delivery_retries_do_not_republish() {
    let out = setup_spawn(4);
    RELEASE_CPU.store(500_000, Ordering::Release);
    with(|s| {
        s.job.as_mut().unwrap().work = Some(core_replay::WorkId);
        Ok(())
    })
    .unwrap();
    DELIVERY_BUSY.store(true, Ordering::Release);
    assert_eq!(accept(&out, 10), Err(Error::Busy));
    assert_eq!(BORROWS.load(Ordering::Acquire), 0);
    assert_eq!(receipt().version, 1);
    with(|s| {
        assert!(s.registry.optimization_stopped());
        assert_eq!(s.job.unwrap().completion.unwrap().result, Ok(1));
        Ok(())
    })
    .unwrap();
    let cpu = CPU.load(Ordering::Acquire);
    DELIVERY_BUSY.store(false, Ordering::Release);
    assert_eq!(accept(&out, 10), Ok(1));
    assert_eq!(CPU.load(Ordering::Acquire), cpu);
    assert_eq!(ACQUIRES.load(Ordering::Acquire), 1);
    assert_eq!(FINISHED.lock().unwrap().unwrap().2, 1);
}
#[test]
fn spawn_model_root_generation_and_control_role_still_refuse() {
    for mode in 0..6 {
        let out = setup_spawn(4);
        with(|s| {
            match mode {
                0 => s.owner.context.ledger_generation += 1,
                1 => {
                    s.model_gate = Some(
                        CommitGate::new(
                            1,
                            ModelBinding {
                                generation: 2,
                                ..binding()
                            },
                        )
                        .unwrap(),
                    )
                }
                2 => ROOT_ALLOWED.store(false, Ordering::Release),
                3 => s.owner.context.control_mask = 0,
                4 => {
                    s.owner.stability[0] = Some(
                        StabilityGuard::new(
                            ObjectKey {
                                id: 12,
                                generation: 2,
                            },
                            Action::SpawnTokens(2),
                            WALL.load(Ordering::Acquire) - WINDOW_NS,
                        )
                        .unwrap(),
                    );
                }
                5 => domain_tasks::set_role(0),
                _ => panic!(),
            }
            Ok(())
        })
        .unwrap();
        assert!(
            accept(&out, 10).is_err(),
            "native Spawn bypassed existing authority check: {mode}"
        );
        assert_eq!(BORROWS.load(Ordering::Acquire), 0);
        assert_eq!(EFFECTS.load(Ordering::Acquire), 0);
    }
}
// SPAWN_VIEW_TESTS
#[test]
fn spawn_distinct_view_keeps_generations_cpu_identity_and_owner_role() {
    let _ = setup_spawn(4);
    assert!(
        matches!(
            domain_tasks::reserve_scheduler_publication(Action::SpawnTokens(4)),
            Ok(None)
        ),
        "D01 capability broadened to D02"
    );
    assert!(matches!(
        domain_tasks::reserve_spawn_publication(Action::CpuWeight(2)),
        Ok(None)
    ));
    let view = domain_tasks::reserve_spawn_publication(Action::SpawnTokens(4))
        .unwrap()
        .unwrap();
    let foreign = ObjectKey {
        id: 12,
        generation: 2,
    };
    assert_eq!(
        view.validate(Action::SpawnTokens(4), foreign, now()),
        Err(Error::Stale),
        "legal query reentered its held owner gate"
    );
    assert_eq!(
        view.current(2, foreign),
        Err(Error::Stale),
        "current query reentered its held owner gate"
    );
    assert_eq!(
        view.current(2, key(12)),
        Ok(Action::SpawnTokens(2)),
        "current query reentered its held owner gate"
    );
    assert_eq!(
        view.validate(Action::SpawnTokens(4), key(12), now()),
        Ok(()),
        "legal query reentered its held owner gate"
    );
    assert_eq!(
        view.validate(Action::CpuWeight(2), key(12), now()),
        Err(Error::Unsupported)
    );
    assert_eq!(view.current(1, key(12)), Err(Error::Unsupported));
    SLOT.store(2, Ordering::Release);
    assert_eq!(
        view.current(2, key(12)),
        Err(Error::Auth),
        "borrow changed control CPU identity"
    );
    SLOT.store(1, Ordering::Release);
    drop(view);
    for mode in 0..3 {
        let _ = setup_spawn(4);
        domain_tasks::set_role(mode);
        assert!(
            matches!(
                domain_tasks::reserve_spawn_publication(Action::SpawnTokens(4)),
                Err(Error::Auth)
            ),
            "invalid native Spawn control role"
        );
        assert_eq!(BORROWS.load(Ordering::Acquire), 0);
    }
}
#[test]
fn spawn_exact_matcher_requires_every_native_identity_and_no_custom_contract() {
    let _ = setup_spawn(4);
    let native = with(|s| Ok(s.owner.families[2].unwrap())).unwrap();
    assert!(domain_tasks::spawn_publication_matches(
        &native, None, false
    ));
    let changes: [fn(&mut Family); 10] = [
        |f| f.domain = 1,
        |f| f.kind = 2,
        |f| f.target_source = TargetSource::Services,
        |f| f.target = |_, _, _| None,
        |f| f.current = domain_tasks::query_foreign,
        |f| f.legal = domain_tasks::validate_foreign,
        |f| f.legal_options = domain_tasks::options_foreign,
        |f| f.target_features = |_, _| Err(Error::Stale),
        |f| f.apply = |_, _, _, _| Err(Error::Stale),
        |f| f.reconcile = |_, _, _, _| Err(Error::Stale),
    ];
    for change in changes {
        let mut foreign = native;
        change(&mut foreign);
        assert!(
            !domain_tasks::spawn_publication_matches(&foreign, None, false),
            "native callback and metadata identity must be exact"
        );
    }
    assert!(
        !domain_tasks::spawn_publication_matches(&native, Some(|_| Ok([None; 2])), false),
        "resolver must retain original path"
    );
    assert!(
        !domain_tasks::spawn_publication_matches(&native, None, true),
        "binder must retain original path"
    );
}
#[test]
fn spawn_decode_failure_and_wall_overrun_release_inside_original_accounting() {
    let mut out = setup_spawn(4);
    out[0] = 0;
    assert_eq!(accept(&out, 10), Err(Error::Format));
    assert_eq!(
        BORROWS.load(Ordering::Acquire),
        0,
        "decode error retained Spawn owner guard"
    );
    assert_eq!(EFFECTS.load(Ordering::Acquire), 0);
    let out = setup_spawn(4);
    RELEASE_WALL.store(50_000_000, Ordering::Release);
    assert_eq!(accept(&out, 10), Ok(1));
    assert_eq!(receipt().version, 1);
    assert!(with(|s| Ok(s.registry.optimization_stopped())).unwrap());
    assert_eq!(BORROWS.load(Ordering::Acquire), 0);
}
#[test]
fn spawn_real_desired_admission_history_and_subsequent_resource_current_match_fallback() {
    for borrowed in [false, true] {
        let out = setup_spawn(4);
        HISTORY.with(|h| *h.borrow_mut() = None);
        ADMISSION.retire(0);
        if !borrowed {
            with(|s| {
                s.owner.families[2].as_mut().unwrap().legal = domain_tasks::validate_foreign;
                Ok(())
            })
            .unwrap();
        }
        let started = with(|s| Ok(s.job.unwrap().started)).unwrap();
        assert_eq!(accept(&out, 10), Ok(1));
        let desired =
            with(|s| Ok(s.owner.desired[0].expect("publication lost actual Desired intent")))
                .unwrap();
        assert_eq!(desired.action, Action::SpawnTokens(4));
        assert_eq!(desired.state, ExecutionState::Pending);
        assert_eq!(
            desired.apply,
            ApplyId {
                boot_epoch: 11,
                controller_epoch: 9,
                plan_seq: 1,
                action_index: 0,
                target: key(12)
            }
        );
        assert_eq!(
            (
                desired.stamp.version,
                desired.stamp.snapshot_ns,
                desired.stamp.installed_until_ns
            ),
            (1, started, started + POLICY_NS)
        );
        assert_eq!(
            (
                desired.job,
                desired.model,
                desired.dependencies,
                desired.core_generation,
                desired.ledger_generation
            ),
            (1, binding(), [None; 2], 2, 3)
        );
        assert_eq!(
            ADMISSION.snapshot(),
            [2, 12, 1, 1, started + POLICY_NS, 1],
            "publication lost actual ADMISSION intent"
        );
        let history = HISTORY.with(|h| {
            h.borrow()
                .clone()
                .expect("publication omitted history metadata")
        });
        assert_eq!(
            history,
            History {
                apply: desired.apply,
                version: 1,
                stamp: desired.stamp,
                model: binding(),
                selected: 2,
                scores: vec![0, 0, 1, 0],
                concurrent: vec![desired.apply]
            }
        );
        assert_eq!(
            domain_tasks::current_action(2, key(12)),
            Ok(Action::SpawnTokens(2)),
            "publication changed owner before actual install"
        );
        domain_tasks::install(desired.action, desired.apply.target, desired.stamp, now()).unwrap();
        assert_eq!(
            domain_tasks::current_action(2, key(12)),
            Ok(Action::SpawnTokens(4)),
            "actual installed owner differs after publication"
        );
        assert_eq!(BORROWS.load(Ordering::Acquire), 0);
    }
}
