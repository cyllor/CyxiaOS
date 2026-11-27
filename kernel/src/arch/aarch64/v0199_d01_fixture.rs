//! A bounded scheduler effect on CPU1 under the existing business gate.
//! The equal-weight and approved-weight phases execute two identical EL0
//! programs via distinct native roots. The QMP checker replays each choice
//! from the measured CPU debits. Rule identity is fixture-only.
use super::{
    v0199_effect_fixture::{encode_decision, rule, sha},
    *,
};
use crate::virtio_platform::Board;
use cyxia_driver_virtio::Platform;
use cyxia_kernel_core::{
    control_plane::{
        Error, Identity,
        action_schema_v2::ActionV2,
        apply_report_v1::{
            ActionStatus, ApplyReportV1, BoundReport, ExecutorBindingV1, MAX_APPLY_REPORT_BYTES,
            ReportOrigin, TrustedApplyScope,
        },
        apply_work_v1::{ApplyWorkV1, WorkFrame},
        candidate_registry_v0199::{CatalogEntry, FrozenCandidates},
        desired_plan_v0199::DesiredBank,
        feedback_v0199::{CausalLabel, FeedbackInbox},
        plan_wire_v2::PlanV2,
        registered_gate_v3::{
            Publication, RegisteredDecisionGate, Registration, TrustedRegistrationScope,
        },
        rule_profile_v2::{Candidates, Profile},
        snapshot_store_v3::{DomainObservation, SnapshotStore, Target},
    },
    security::{syscall::Syscall, syscall_v3::decode_aarch64_svc_v3},
};
use cyxia_prototype::domains::{
    ObjectKey, PolicyStamp, WINDOW_NS,
    tasks::{CpuLayout, DispatchReason, RunState, Scheduler, ThreadSpec},
};

const CTL: Identity = Identity {
    id: 2,
    generation: 1,
};
const PUB: Identity = Identity {
    id: 8,
    generation: 1,
};
const SUP: Identity = Identity {
    id: 11,
    generation: 1,
};
const LEARN: Identity = Identity {
    id: 10,
    generation: 1,
};
const TARGET: Identity = Identity {
    id: 17,
    generation: 1,
};
const GROUPS: [ObjectKey; 2] = [
    ObjectKey {
        id: TARGET.id,
        generation: TARGET.generation,
    },
    ObjectKey {
        id: 18,
        generation: 1,
    },
];
const THREADS: [ObjectKey; 2] = [
    ObjectKey {
        id: 0xd0101,
        generation: 1,
    },
    ObjectKey {
        id: 0xd0102,
        generation: 1,
    },
];
const CPU: usize = 1;
const TURNS: usize = 24;
const ITERATIONS: u64 = 2048;
const APPROVED: u16 = 4;
const WORK_BYTES: usize = 82;
const WORDS: usize = 16;
const PRIVATE_SLOTS: [usize; 2] = [PRIVATE_SPACES - 2, PRIVATE_SPACES - 1];

// Only CPU0 writes the request and only CPU1 mutates the owned Scheduler
// and the corresponding private slots. DONE releases the exact result.
static REQUEST: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static INPUT: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
static OUTPUT: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
static mut SCHEDULER: Scheduler = Scheduler::new();

#[repr(C, align(4096))]
struct NativeEvidence {
    header: [AtomicU64; 512],
    turns: [[AtomicU64; 10]; TURNS * 2],
}
#[used]
#[unsafe(no_mangle)]
static V0199_D01_EVIDENCE: NativeEvidence = NativeEvidence {
    header: [const { AtomicU64::new(0) }; 512],
    turns: [const { [const { AtomicU64::new(0) }; 10] }; TURNS * 2],
};
unsafe extern "C" {
    static smp_d01_yield: u8;
}

fn copy_words(bytes: &[u8], into: &[AtomicU64]) {
    assert!(bytes.len() <= into.len() * 8);
    for (part, dst) in bytes.chunks(8).zip(into) {
        let mut word = [0; 8];
        word[..part.len()].copy_from_slice(part);
        dst.store(u64::from_le_bytes(word), Ordering::Relaxed);
    }
}
fn exchange(round: u64, args: &[u64], bytes: &[u8]) -> [u64; WORDS] {
    assert_eq!(cpu::slot(), 0);
    assert_eq!(DONE.load(Ordering::Acquire) + 1, round);
    for (at, value) in INPUT.iter().zip(args) {
        at.store(*value, Ordering::Relaxed);
    }
    copy_words(bytes, &INPUT[args.len()..]);
    REQUEST.store(round, Ordering::Release);
    wait(|| DONE.load(Ordering::Acquire) == round);
    core::array::from_fn(|i| OUTPUT[i].load(Ordering::Relaxed))
}

fn data(index: usize) -> *mut Page {
    let slot = PRIVATE_SLOTS[index];
    let data = unsafe { core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(slot) };
    let leaf = unsafe { core::ptr::addr_of!(LEAVES).cast::<Page>().add(slot) };
    let pte = unsafe { (*leaf).0[(DATA / 4096) as usize] };
    mmu::checked_user_leaf_span(pte, PhysAddr(phys(data as u64)), 0, 8, true).unwrap();
    data
}

fn wall_phase() -> u64 {
    let now = Board.now_ns();
    let next = (now / WINDOW_NS + 1) * WINDOW_NS;
    // The aligned phases must not refill a scheduler window by resetting it.
    // This waits for a real window boundary with no user context entered.
    let delta = next - now;
    let ticks =
        u64::try_from((u128::from(delta) * u128::from(timer::frequency())).div_ceil(1_000_000_000))
            .unwrap();
    unsafe {
        timer::arm(timer::ticks().checked_add(ticks).unwrap());
        while Board.now_ns() < next {
            timer::idle();
        }
        cpu::disable_timer();
    }
    let start = Board.now_ns();
    assert_eq!(start / WINDOW_NS, next / WINDOW_NS);
    start
}

fn phase(scheduler: &mut Scheduler, layout: CpuLayout, index: usize) {
    let start = wall_phase();
    let window = start / WINDOW_NS;
    let mut contexts: [user::Context; 2] = core::array::from_fn(|i| {
        scheduler.set_runnable(THREADS[i], false, start).unwrap();
        scheduler.set_runnable(THREADS[i], true, start).unwrap();
        let mut ctx = user::Context::empty();
        let entry =
            core::ptr::addr_of!(smp_d01_yield) as u64 - core::ptr::addr_of!(smp_user_start) as u64;
        assert!(entry < 4096);
        ctx.pc = CODE + entry;
        ctx.sp = STACK + 4096;
        ctx.regs[20] = DATA;
        unsafe {
            core::ptr::addr_of_mut!((*data(i)).0[0]).write_volatile(0);
        }
        ctx
    });
    let mut spent = [0u64; 2];
    let mut completed = [0u64; 2];
    let mut waited = [0u64; TURNS];
    for (i, wait_sample) in waited.iter_mut().enumerate() {
        let turn = scheduler
            .dispatch_with_window_headroom(CPU, layout, Board.now_ns(), 2_000_000, 3_000_000)
            .unwrap()
            .expect("D01 scheduler retained runnable tasks and CPU credit");
        assert_eq!(
            (turn.cpu, turn.core_generation, turn.window, turn.reason),
            (
                CPU as u16,
                layout.generation,
                window,
                DispatchReason::Weighted
            )
        );
        let selected = THREADS.iter().position(|k| *k == turn.thread).unwrap();
        assert_eq!(turn.group, GROUPS[selected]);
        let count = unsafe { core::ptr::addr_of!((*data(selected)).0[0]).read_volatile() };
        let ctx = &mut contexts[selected];
        let began = timer::cpu_ticks();
        for _ in 0..3 {
            execute(ctx, PRIVATE_SLOTS[selected]);
            if ctx.kind != 9 {
                break;
            }
            assert!(Board.now_ns() / WINDOW_NS == window);
        }
        let actual = timer::cpu_elapsed_ns(began);
        let finished = Board.now_ns();
        assert_eq!(ctx.kind, 8);
        let call = decode_aarch64_svc_v3(3, ctx.esr, &ctx.regs).unwrap();
        assert_eq!(call.operation, Syscall::Yield);
        let after = unsafe { core::ptr::addr_of!((*data(selected)).0[0]).read_volatile() };
        assert_eq!(after - count, ITERATIONS);
        assert!(actual > 0 && finished / WINDOW_NS == window);
        scheduler
            .complete(turn, actual, RunState::Runnable, finished)
            .unwrap();
        spent[selected] += actual;
        completed[selected] += 1;
        *wait_sample = turn.waited_ns;
        let row = [
            turn.sequence,
            selected as u64,
            turn.started_ns,
            finished,
            actual,
            turn.waited_ns,
            turn.policy_version,
            after,
            ctx.esr,
            turn.reserved_ns,
        ];
        for (at, v) in V0199_D01_EVIDENCE.turns[index * TURNS + i].iter().zip(row) {
            at.store(v, Ordering::Relaxed);
        }
    }
    assert_eq!(scheduler.stats().overruns, 0);
    assert!(completed.iter().all(|&n| n > 0));
    waited.sort_unstable();
    let p99 = waited[(99 * TURNS).div_ceil(100) - 1].div_ceil(1000);
    let ended = Board.now_ns();
    let result = [
        start,
        ended,
        spent[0],
        spent[1],
        completed[0],
        completed[1],
        p99,
        u64::from(scheduler.stats().runnable),
        scheduler.policy_receipt(GROUPS[0]).unwrap(),
        phys(data(0) as u64),
        phys(data(1) as u64),
    ];
    for (at, v) in OUTPUT.iter().zip(result) {
        at.store(v, Ordering::Relaxed);
    }
}

pub(super) fn worker_step(generation: u64) -> bool {
    assert_eq!(cpu::slot(), CPU);
    assert_eq!(generation, 1, "fixed business core epoch");
    let round = REQUEST.load(Ordering::Acquire);
    let previous = DONE.load(Ordering::Relaxed);
    if round == previous {
        return false;
    }
    assert_eq!(round, previous + 1);
    let scheduler = unsafe { &mut *core::ptr::addr_of_mut!(SCHEDULER) };
    let layout = CpuLayout {
        business_mask: 14,
        healthy_mask: ONLINE.load(Ordering::Acquire),
        generation,
    };
    match round {
        1 => {
            let now = Board.now_ns();
            for (key, group) in THREADS.into_iter().zip(GROUPS) {
                scheduler.register_group(group).unwrap();
                scheduler
                    .admit(
                        ThreadSpec {
                            key,
                            group,
                            cpu: CPU as u16,
                            allowed_mask: 1 << CPU,
                            minimum_ns: 0,
                            budget_ns: 10_000_000,
                        },
                        layout,
                        now,
                    )
                    .unwrap();
            }
            phase(scheduler, layout, 0);
        }
        2 => {
            let mut raw = [0; WORK_BYTES];
            for (chunk, field) in raw.chunks_mut(8).zip(INPUT.iter().skip(4)) {
                chunk.copy_from_slice(&field.load(Ordering::Relaxed).to_le_bytes()[..chunk.len()]);
            }
            let work = ApplyWorkV1::decode(&raw).unwrap();
            let load = |i: usize| INPUT[i].load(Ordering::Relaxed);
            assert_eq!(
                (
                    work.key.boot_epoch,
                    work.target,
                    work.executor_generation,
                    work.domain
                ),
                (load(0), TARGET, generation, 1)
            );
            let Ok(ActionV2::GroupWeight(weight)) = ActionV2::decode(1, 1, work.payload) else {
                panic!("invalid D01 accepted work");
            };
            assert_eq!(weight, APPROVED);
            let now = Board.now_ns();
            let stamp = PolicyStamp::new(work.plan_version, load(1), now).unwrap();
            assert_eq!(stamp.installed_until_ns, load(2));
            assert!(load(3) <= now);
            assert_eq!(scheduler.weight(GROUPS[0], now), Ok(1));
            scheduler
                .install_weight(GROUPS[0], weight, stamp, now)
                .unwrap();
            assert_eq!(scheduler.policy_receipt(GROUPS[0]), Ok(0));
            OUTPUT[0].store(work.plan_version, Ordering::Relaxed);
        }
        3 => phase(scheduler, layout, 1),
        _ => panic!("unexpected D01 request"),
    }
    DONE.store(round, Ordering::Release);
    true
}

pub(super) fn run(
    boot: u64,
    gate: &mut RegisteredDecisionGate<'_>,
    snapshots: &mut SnapshotStore,
    inbox: &mut FeedbackInbox,
    desired: &mut DesiredBank,
) {
    let baseline = exchange(1, &[], &[]);
    let sampled = baseline[1];
    assert_eq!(baseline[7], 2);
    let target = Target {
        domain: 1,
        object: TARGET,
        owner: Identity {
            id: 1,
            generation: 1,
        },
    };
    snapshots
        .register_target(target, |t| {
            if t == target {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let fields = [Some(baseline[7]), Some(baseline[6]), None, None];
    let seq = snapshots
        .capture(
            1,
            1,
            sampled,
            [None; 8],
            &[DomainObservation { target, fields }],
            |o| {
                if o.target == target && o.fields == fields {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            },
        )
        .unwrap();
    let snap = snapshots
        .frozen_for_owner(target, 1, 1, Board.now_ns(), |t| {
            if t == target {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    assert_eq!(seq, desired.version() + 1);
    let tiers = ActionV2::values(1).unwrap();
    let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
        ordinal: i as u16,
        value: tiers[i],
    });
    let catalog_hash = sha(b"CYX/D01-CPU1-FIXTURE/0=1,1=2,2=4,3=8");
    let candidates = FrozenCandidates::capture(
        snap,
        &catalog,
        catalog_hash,
        ActionV2::GroupWeight(1),
        Some(2),
        Some(true),
        false,
        |c, h| {
            if c == &catalog && h == catalog_hash {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |v| Ok(matches!(v, ActionV2::GroupWeight(1 | 2 | 4 | 8))),
    )
    .unwrap();
    let rules = rule(target, seq, 1, 2, 2);
    let profile = Profile::parse(&rules).unwrap();
    let matched = profile
        .match_candidates(
            1,
            TARGET.id,
            candidates.rule_fields(),
            Candidates {
                static_ordinals: candidates.ordinals(),
            },
        )
        .unwrap()
        .unwrap();
    let view = candidates.view();
    let local = view.selected(matched.fallback_index).unwrap();
    assert_eq!(local.action_payload, &APPROVED.to_le_bytes());
    let scope = TrustedRegistrationScope {
        boot_epoch: boot,
        controller_epoch: 1,
        rules_generation: seq,
        rules_hash: sha(&rules),
        base_plan_version: desired.version(),
        ledger_generation: 1,
        core_generation: 1,
        snapshot_seq: seq,
        sampled_ns: sampled,
        now_ns: Board.now_ns(),
    };
    let (plan, decision) = encode_decision::<212>(
        target,
        seq,
        scope,
        matched,
        candidates.digest(),
        local.action_payload,
    );
    let actions = [local];
    let decisions = [decision];
    assert_eq!(
        gate.register_rule_only(CTL, &plan, &decisions, &profile, &actions, scope),
        Ok(Registration::Frozen)
    );
    let binding = ExecutorBindingV1 {
        domain: 1,
        role: 1,
        active: true,
        target: TARGET,
        executor_generation: 1,
        holder: Identity {
            id: 0,
            generation: 0,
        },
        endpoint_cap_id: 0,
    };
    desired
        .register_target(binding, |b| {
            if b.target == target.object {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let publication = TrustedRegistrationScope {
        now_ns: Board.now_ns(),
        ..scope
    };
    assert_eq!(
        gate.publish_once(
            PUB,
            &plan,
            &decisions,
            &profile,
            &actions,
            publication,
            || {
                desired
                    .publish_registered(PUB, cpu::slot(), &plan, publication, |stage| {
                        let a = stage[0].ok_or(Error::Denied)?;
                        if stage.len() == 1
                            && a.binding == binding
                            && a.value == ActionV2::GroupWeight(APPROVED)
                            && a.prior_target_version == baseline[8]
                        {
                            Ok(())
                        } else {
                            Err(Error::Denied)
                        }
                    })
                    .map(|_| ())
            }
        ),
        Ok(Publication::AdapterAccepted)
    );
    let apply = TrustedApplyScope {
        boot_epoch: boot,
        plan_version: desired.version(),
        now_ns: Board.now_ns(),
    };
    let parsed_plan = PlanV2::decode(&plan).unwrap();
    let accepted = gate
        .claim_apply_work(&plan, 0, apply, binding, ReportOrigin::Kernel, |work| {
            desired.accept(work, ReportOrigin::Kernel, apply.now_ns, |action| {
                let frame = WorkFrame::from_plan(
                    &parsed_plan,
                    0,
                    boot,
                    work.plan_version,
                    binding,
                    ReportOrigin::Kernel,
                )?;
                if ApplyWorkV1::decode(frame.bytes())? != *work {
                    return Err(Error::Denied);
                }
                let result = exchange(
                    2,
                    &[boot, sampled, action.until_ns, apply.now_ns],
                    frame.bytes(),
                );
                if result[0] == work.plan_version {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            })
        })
        .unwrap();
    let work = ApplyWorkV1::decode(accepted.bytes()).unwrap();
    let weighted = exchange(3, &[], &[]);
    let actual_change = || {
        baseline[0] / WINDOW_NS < weighted[0] / WINDOW_NS
            && apply.now_ns <= weighted[0]
            && weighted[8] == work.plan_version
            && weighted[7] == baseline[7]
            && u128::from(weighted[2]) * u128::from(baseline[3])
                > u128::from(weighted[3]) * u128::from(baseline[2])
    };
    assert!(
        actual_change(),
        "D01 selected task group did not gain share"
    );
    let mut raw = [0; MAX_APPLY_REPORT_BYTES];
    let len = ApplyReportV1 {
        key: work.key,
        action_index: work.action_index,
        domain_id: 1,
        state: ActionStatus::Applied,
        target: TARGET,
        executor_generation: work.executor_generation,
        plan_version: work.plan_version,
        result: 0,
        completed_ns: weighted[1],
        action: work.payload,
    }
    .encode(&mut raw)
    .unwrap();
    let applied = ApplyReportV1::decode(&raw[..len]).unwrap();
    let verify = |r: &ApplyReportV1<'_>| {
        if *r == applied && work.matches_report(*r) && actual_change() {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    };
    let summary = gate
        .settle_verified_apply_reports_with_feedback(
            SUP,
            &plan,
            &[BoundReport {
                bytes: &raw[..len],
                origin: ReportOrigin::Kernel,
            }],
            &[binding],
            TrustedApplyScope {
                now_ns: Board.now_ns(),
                ..apply
            },
            None,
            |_, r| verify(r),
            |batch| inbox.retain(SUP, batch),
        )
        .unwrap();
    let feedback = inbox.read(LEARN, seq as usize - 1).unwrap().unwrap();
    assert_eq!(
        (
            feedback.decision,
            feedback.report_bytes(),
            feedback.causal_label
        ),
        (decision, &raw[..len], CausalLabel::NoAdoption)
    );
    desired
        .finish(&applied, ReportOrigin::Kernel, Board.now_ns(), |action| {
            if action.key.plan_seq == summary.plan_seq && inbox.len() == seq as usize {
                verify(&applied)
            } else {
                Err(Error::NotReady)
            }
        })
        .unwrap();
    let head = &V0199_D01_EVIDENCE.header;
    for (at, v) in head.iter().zip([
        0x4359443031465831,
        boot,
        seq,
        apply.now_ns,
        len as u64,
        inbox.len() as u64,
    ]) {
        at.store(v, Ordering::Relaxed);
    }
    for (at, v) in head[8..]
        .iter()
        .zip(baseline[..11].iter().chain(&weighted[..11]))
    {
        at.store(*v, Ordering::Relaxed);
    }
    for (i, slot) in PRIVATE_SLOTS.into_iter().enumerate() {
        let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(slot) };
        head[30 + i].store(phys(root as u64), Ordering::Relaxed);
    }
    copy_words(&snap.encode().unwrap(), &head[32..]);
    copy_words(&rules, &head[65..]);
    copy_words(&plan, &head[76..]);
    copy_words(&decision, &head[103..]);
    copy_words(&raw[..len], &head[135..]);
    report("V0199_D01_EFFECT", baseline[4], weighted[4], seq);
}
