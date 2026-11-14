//! Real replay-window gate and Registry commit callbacks with explicit host
//! clocks. These fixtures create no native sample, model or executor receipt.
#[path = "../../../kernel/src/runtime/control/domain_control/replay/candidate_window.rs"]
mod candidate_window;
use candidate_window::{Observation, Window};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey, POLICY_NS, WINDOW_NS},
    features::RawFeatures,
    learning::{Family, capture::RunKey},
    policy::{
        self, Candidate, CandidateSet, Clock, Executor, ModelBinding, Publisher, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use std::collections::VecDeque;

const OBS: u64 = 204_616_730_992;
const END: u64 = 214_616_730_992;
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn observation() -> Observation {
    Observation {
        run: RunKey {
            boot_epoch: 1,
            trial_id: 2,
            generation: 2,
        },
        family: Family { domain: 1, kind: 1 },
        target: key(12),
        first_ns: 198_616_730_992,
        observation_ns: OBS,
    }
}
fn bound() -> Window {
    let mut window = Window::new();
    window.bind(observation()).unwrap();
    window
}

#[test]
fn actual_window_layout_is_charged_in_addition_to_the_frozen_old_peak() {
    // These are the actual aarch64 Root symbol sizes from immutable Full01/02
    // ELFs and old trial2 header760, not a modified old producer receipt.
    const OLD_ROOT_BYTES: usize = 34_872;
    const WINDOW_ROOT_BYTES: usize = 34_952;
    const OLD_REPORTED_PEAK: usize = 995_996;
    let window_bytes = core::mem::size_of::<Window>();
    assert_eq!(core::mem::size_of::<Observation>(), 64);
    assert_eq!(window_bytes, WINDOW_ROOT_BYTES - OLD_ROOT_BYTES);
    let revised = OLD_REPORTED_PEAK.checked_add(window_bytes).unwrap();
    assert_eq!(revised, 996_076);
    assert_eq!((1024 * 1024usize).checked_sub(revised), Some(52_500));
    // The full live producer equation retains its separate compile-time
    // WORKSPACE_PEAK_BYTES <= 1MiB assertion in owner.rs; this test checks the
    // evidenced incremental charge, not a new allocator or native peak proof.
}

#[test]
fn actual_native_late_renewal_is_rejected_by_the_production_gate() {
    let window = bound();
    assert!(window.allows_new(true, END - 1));
    assert!(!window.allows_new(true, END));
    assert!(!window.allows_new(true, END + 1));
    // Actual seq616 snapshot and submit times from the retained trial2 row.
    assert!(!window.allows_new(true, 215_655_606_992));
    assert!(!window.allows_new(true, 215_656_482_992));
}

#[test]
fn first_activation_is_possible_but_an_unbound_renewal_is_not() {
    let window = Window::new();
    assert!(window.allows_new(false, OBS));
    assert!(!window.allows_new(true, OBS));
}

#[test]
fn scope_binding_is_exact_idempotent_and_cannot_extend_the_window() {
    let mut window = bound();
    assert_eq!(window.bind(observation()), Ok(()));
    for changed in [
        Observation {
            observation_ns: OBS + 1,
            ..observation()
        },
        Observation {
            run: RunKey {
                generation: 3,
                ..observation().run
            },
            ..observation()
        },
        Observation {
            target: key(13),
            ..observation()
        },
    ] {
        assert_eq!(window.bind(changed), Err(Error::Conflict));
        assert!(!window.allows_new(true, END));
    }
    let mut empty = Window::new();
    assert_eq!(
        empty.bind(Observation {
            observation_ns: u64::MAX,
            ..observation()
        }),
        Err(Error::Overflow)
    );
    assert!(!empty.allows_new(true, OBS));
}

fn publisher() -> Publisher {
    Publisher {
        object: key(7),
        controller_epoch: 1,
    }
}
fn model() -> ModelBinding {
    ModelBinding {
        generation: 1,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    }
}
fn set(seq: u64, at: u64) -> CandidateSet {
    CandidateSet::new(
        Snapshot {
            sequence: seq,
            taken_ns: at,
            ledger_generation: 3,
            core_generation: 4,
        },
        key(12),
        model(),
        &[Candidate {
            action: Action::CpuWeight(1),
            features: RawFeatures::default(),
        }],
        Some(Action::CpuWeight(1)),
    )
    .unwrap()
}
fn frame(set: &CandidateSet, base: u64) -> Vec<u8> {
    let header = PlanHeader {
        plan_seq: set.snapshot.sequence,
        base_plan_version: base,
        active_model_generation: 1,
        controller_epoch: 1,
        snapshot_seq: set.snapshot.sequence,
        active_until_local_ns: set.snapshot.taken_ns + POLICY_NS,
    };
    let decision = Decision {
        action: Action::CpuWeight(1),
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: 1,
            decision_seq: set.snapshot.sequence,
            snapshot_seq: set.snapshot.sequence,
            target: set.target,
            ledger_generation: 3,
            core_generation: 4,
            expires_local_ns: set.snapshot.taken_ns + WINDOW_NS,
            model_hash: model().model_hash,
            candidate_set_hash: set.hash(),
        },
    };
    let mut bytes = vec![0; policy_wire::MAX_PLAN_BYTES];
    let n = policy_wire::encode_plan(header, &[decision], &mut bytes).unwrap();
    bytes.truncate(n);
    bytes
}
struct Times(VecDeque<u64>);
impl Clock for Times {
    fn read(&mut self) -> policy::PublicationTime {
        policy::PublicationTime {
            wall_ns: self.0.pop_front().unwrap(),
            cpu: policy::CpuTime { cpu: 1, ns: 100 },
        }
    }
}
struct Owner {
    window: Window,
    issued: bool,
    publishes: usize,
    cancels: usize,
}
impl Owner {
    fn gate(&self, at: u64) -> Result<(), Error> {
        if self.window.allows_new(self.issued, at) {
            Ok(())
        } else {
            Err(Error::Busy)
        }
    }
}
impl Executor for Owner {
    fn check(&mut self, _: Decision, _: &policy::RegisteredSet, at: u64) -> Result<(), Error> {
        self.gate(at)
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, at: u64) -> Result<(), Error> {
        self.gate(at)
    }
    fn publish(&mut self, _: &Plan, _: u64, at: u64) -> Result<(), Error> {
        self.gate(at)?;
        self.publishes += 1;
        self.issued = true;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.cancels += 1;
    }
}

#[test]
fn real_registry_job_started_before_end_cannot_commit_after_end_or_clear_old_pending() {
    for commit_at in [END, END + 1] {
        let mut registry = Registry::new(1, publisher(), model()).unwrap();
        let mut owner = Owner {
            window: bound(),
            issued: false,
            publishes: 0,
            cancels: 0,
        };
        let old_set = set(1, END - 100);
        registry.register(publisher(), &old_set).unwrap();
        let old = registry
            .submit(
                publisher(),
                &frame(&old_set, 0),
                &mut Times([END - 90; 6].into()),
                &mut owner,
            )
            .unwrap();
        assert_eq!(old.version, 1);
        assert_eq!(old.state(), policy::ExecutionState::Pending);
        let pending = set(2, END - 2);
        registry.register(publisher(), &pending).unwrap();
        let late = registry
            .submit(
                publisher(),
                &frame(&pending, 1),
                &mut Times([END - 1, END - 1, END - 1, END - 1, commit_at, commit_at].into()),
                &mut owner,
            )
            .unwrap();
        assert_eq!(late.version, 0);
        assert_eq!(late.state(), policy::ExecutionState::Failed(Error::Busy));
        assert_eq!(owner.publishes, 1);
        assert_eq!(owner.cancels, 1);
        assert_eq!(registry.query(publisher(), old.id), Ok(old));
        assert!(!registry.optimization_stopped());
    }
}
