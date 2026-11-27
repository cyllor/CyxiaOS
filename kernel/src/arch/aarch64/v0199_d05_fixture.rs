//! Native D05 integration on the isolated epoch-disk diagnostic profile.
//! CPU0 owns the registered rule, desired plan, observation and receipt.
//! CPU1 owns the ordinary IPC endpoint and both short-lived EL0 clients.
//! Cap selectors and the test rule come from this immutable fixture.
use super::v0199_effect_fixture::{encode_decision, rule, sha};
use super::*;
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
        d05_owner_v0199::{Batch, Owner},
        desired_plan_v0199::DesiredBank,
        feedback_v0199::{CausalLabel, FeedbackInbox},
        plan_wire_v2::PlanV2,
        registered_gate_v3::{
            Publication, RegisteredDecisionGate, Registration, TrustedRegistrationScope,
        },
        rule_profile_v2::{Candidates, Profile},
        snapshot_store_v3::{DomainObservation, SnapshotStore, Target},
    },
    security::{
        ipc_receive_v3::{Endpoint, FRAME_BYTES},
        syscall::Syscall,
        syscall_v3::{ValidatedCall, decode_aarch64_svc_v3},
    },
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
const SEND: Identity = Identity {
    id: 0xd0501,
    generation: 1,
};
const RECV: Identity = Identity {
    id: 0xd0502,
    generation: 1,
};
const TARGET: Identity = Identity {
    id: 5,
    generation: 1,
};
const EP: Endpoint = Endpoint {
    id: TARGET.id,
    generation: TARGET.generation,
    receiver: RECV,
};
const SEND_SELECTOR: u64 = 0xd0521;
const RECEIVE_SELECTOR: u64 = 0xd0522;
const SLOT: usize = 3;
const SEQ: u64 = 4;
const RECEIVE_BYTES: usize = 48;
const EAGAIN: i64 = -11;
const EBUSY: i64 = -16;
const WORK_BYTES: usize = 83;
const REPORT_BYTES: usize = 99;
const WORDS: usize = 16;
const SHRUNK: ActionV2 = ActionV2::Ipc {
    budget: 8,
    batch: 1,
};
const BASELINE: ActionV2 = ActionV2::Ipc {
    budget: 32,
    batch: 4,
};
static REQUEST: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static INPUT: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
static OUTPUT: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

// Fully allocated in one business-core-owned arena before the first turn.
#[repr(align(4096))]
struct BusinessArena(Owner);
static mut BUSINESS: BusinessArena = BusinessArena(Owner::empty());
#[used]
#[unsafe(no_mangle)]
static V0199_D05_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};

unsafe extern "C" {
    static smp_d05_ipc: u8;
}

fn now() -> u64 {
    (u128::from(timer::ticks()) * 1_000_000_000 / u128::from(timer::frequency()))
        .try_into()
        .unwrap()
}

fn atomically_copy(bytes: &[u8], into: &[AtomicU64]) {
    assert!(bytes.len() <= into.len() * 8);
    for (part, dst) in bytes.chunks(8).zip(into) {
        let mut word = [0; 8];
        word[..part.len()].copy_from_slice(part);
        dst.store(u64::from_le_bytes(word), Ordering::Relaxed);
    }
}

fn word_bytes<const N: usize>(words: &[u64]) -> [u8; N] {
    assert!(N <= words.len() * 8);
    let mut bytes = [0; N];
    for (part, word) in bytes.chunks_mut(8).zip(words) {
        part.copy_from_slice(&word.to_le_bytes()[..part.len()]);
    }
    bytes
}

/// Single-writer input and output regions. The request release publishes
/// the complete input. Only the CPU1 release of DONE permits reuse.
fn exchange(round: u64, args: &[u64], bytes: &[u8]) -> [u64; WORDS] {
    assert_eq!(cpu::slot(), 0);
    assert_eq!(DONE.load(Ordering::Acquire) + 1, round);
    for (at, value) in INPUT.iter().zip(args) {
        at.store(*value, Ordering::Relaxed);
    }
    atomically_copy(bytes, &INPUT[args.len()..]);
    REQUEST.store(round, Ordering::Release);
    wait(|| DONE.load(Ordering::Acquire) == round);
    core::array::from_fn(|i| OUTPUT[i].load(Ordering::Relaxed))
}

struct PrivateClient {
    data: *mut Page,
    root: *mut Page,
    mid: *mut Page,
    leaf: *mut Page,
    stack: *mut Page,
}

impl PrivateClient {
    fn new() -> Self {
        assert_eq!(cpu::slot(), 1);
        let client = unsafe {
            Self {
                root: core::ptr::addr_of_mut!(ROOTS).cast::<Page>().add(SLOT),
                mid: core::ptr::addr_of_mut!(MIDDLES).cast::<Page>().add(SLOT),
                leaf: core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(SLOT),
                data: core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(SLOT),
                stack: core::ptr::addr_of_mut!(USER_STACKS)
                    .cast::<Page>()
                    .add(SLOT),
            }
        };
        client.scrub();
        // Only this stopped CPU1 slot is used. The EL0 data/stack never
        // share mappings with another entered context.
        unsafe {
            (*client.root).0[0] = phys(client.mid as u64) | 3;
            (*client.mid).0[0] = phys(client.leaf as u64) | 3;
            (*client.leaf).0[(CODE / 4096) as usize] = mmu::encode_user_leaf(
                PhysAddr(phys(core::ptr::addr_of!(smp_user_start) as u64)),
                false,
                true,
            )
            .unwrap();
            (*client.leaf).0[(DATA / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(client.data as u64)), true, false).unwrap();
            (*client.leaf).0[(STACK / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(client.stack as u64)), true, false).unwrap();
        }
        client
    }

    fn scrub(&self) {
        unsafe {
            (*self.root).0[0] = 0;
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack)
            );
            for p in [self.root, self.mid, self.leaf, self.data, self.stack] {
                p.cast::<u8>().write_bytes(0, 4096);
            }
        }
    }

    fn span(&self, addr: u64, len: usize, writable: bool) -> Result<*mut u8, Error> {
        if addr != DATA || len > FRAME_BYTES {
            return Err(Error::Denied);
        }
        let pte = unsafe { (*self.leaf).0[(DATA / 4096) as usize] };
        mmu::checked_user_leaf_span(pte, PhysAddr(phys(self.data as u64)), 0, len, writable)
            .map_err(|_| Error::Denied)?;
        Ok(self.data.cast::<u8>())
    }

    fn trap(&self, ctx: &mut user::Context) -> ValidatedCall {
        for _ in 0..64 {
            execute(ctx, SLOT);
            if ctx.kind != 9 {
                assert_eq!(ctx.kind, 8);
                return decode_aarch64_svc_v3(3, ctx.esr, &ctx.regs).unwrap();
            }
        }
        panic!("D05 diagnostic client timed out");
    }

    fn syscall(
        &mut self,
        number: u64,
        args: [u64; 6],
        ipc: impl FnOnce(ValidatedCall, &Self) -> i64,
    ) -> [u64; 3] {
        let mut ctx = user::Context::empty();
        ctx.sp = STACK + 4096;
        let offset =
            core::ptr::addr_of!(smp_d05_ipc) as u64 - core::ptr::addr_of!(smp_user_start) as u64;
        assert!(offset < 4096);
        ctx.pc = CODE + offset;
        ctx.regs[..6].copy_from_slice(&args);
        ctx.regs[6] = DATA + FRAME_BYTES as u64 + 8;
        ctx.regs[8] = number;
        let op = self.trap(&mut ctx);
        let status = ipc(op, self);
        ctx.regs[0] = status as u64;
        assert_eq!(self.trap(&mut ctx).operation, Syscall::Exit);
        let row = unsafe {
            core::array::from_fn(|i| {
                core::ptr::addr_of!((*self.data).0[FRAME_BYTES / 8 + 1 + i]).read_volatile()
            })
        };
        assert_eq!(row[0], status as u64);
        row
    }
}

impl Drop for PrivateClient {
    fn drop(&mut self) {
        self.scrub();
    }
}

fn payload(seq: u64) -> u64 {
    0xc5_0000 + seq
}

fn send(owner: &mut Owner, seq: u64) -> i64 {
    let mut sender = PrivateClient::new();
    // Initial data image of this fixture's actual EL0 sender.
    unsafe {
        (*sender.data).0[0] = payload(seq);
    }
    sender.syscall(0x30, [SEND_SELECTOR, DATA, 8, seq, 0, 1], |op, user| {
        assert_eq!(op.operation, Syscall::IpcSend);
        let args = op.args;
        assert_eq!((args[0], args[2], args[5]), (SEND_SELECTOR, 8, 1));
        let mut stable = [0; 8];
        let source = user.span(args[1], stable.len(), false).unwrap();
        unsafe {
            core::ptr::copy_nonoverlapping(source, stable.as_mut_ptr(), stable.len());
        }
        match owner.send(SEND, args[3], &stable, now(), || Ok(())) {
            Ok(()) => 0,
            Err(Error::NotReady) => EAGAIN,
            result => panic!("D05 ordinary send: {result:?}"),
        }
    })[0] as i64
}

fn receive(owner: &mut Owner, batch: Batch, seq: u64, credit: &mut bool) {
    let mut recver = PrivateClient::new();
    let row = recver.syscall(
        0x31,
        [RECEIVE_SELECTOR, DATA, FRAME_BYTES as u64, 0, 1, seq],
        |op, client| {
            assert_eq!(op.operation, Syscall::IpcRecv);
            let args = op.args;
            assert_eq!(
                (args[0], args[2], args[4]),
                (RECEIVE_SELECTOR, FRAME_BYTES as u64, 1)
            );
            let destination = client.span(args[1], FRAME_BYTES, true).unwrap();
            let ticket = owner
                .reserve(
                    batch,
                    RECV,
                    args[5],
                    now(),
                    || Ok(()),
                    || {
                        assert!(!*credit);
                        *credit = true;
                        Ok(())
                    },
                )
                .unwrap();
            let m = ticket.message();
            assert_eq!(
                (m.sender(), m.endpoint_generation(), m.request_id()),
                (SEND, EP.generation, seq)
            );
            let bytes = m.bytes();
            assert_eq!(bytes.len(), RECEIVE_BYTES);
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
            }
            owner
                .finish_copy(batch, ticket, now(), |m| {
                    let copied =
                        unsafe { core::slice::from_raw_parts(destination, m.bytes().len()) };
                    if copied == m.bytes() {
                        Ok(())
                    } else {
                        Err(Error::Denied)
                    }
                })
                .unwrap() as i64
        },
    );
    // Both values are read and returned by the real native EL0 instructions
    // after copyout. A kernel-only simulated receive cannot supply this.
    assert_eq!(row, [RECEIVE_BYTES as u64, seq, payload(seq)]);
    let copied_ns = now();
    assert!(*credit);
    assert_eq!(
        recver.syscall(0x31, [RECEIVE_SELECTOR, 0, 0, 0, 2, seq], |op, _| {
            assert_eq!(op.operation, Syscall::IpcRecv);
            assert_eq!((op.args[0], op.args[4]), (RECEIVE_SELECTOR, 2));
            owner
                .ack(
                    batch,
                    RECV,
                    op.args[5],
                    now(),
                    || Ok(()),
                    || {
                        assert!(*credit);
                        *credit = false;
                        Ok(())
                    },
                )
                .unwrap();
            0
        })[0],
        0
    );
    assert!(!*credit);
    let proof = [row[0], row[1], row[2], copied_ns, now(), cpu::slot() as u64];
    for (at, v) in V0199_D05_EVIDENCE.words[144 + (seq as usize - 1) * 6..]
        .iter()
        .zip(proof)
    {
        at.store(v, Ordering::Relaxed);
    }
}

fn check_batch_limit(owner: &mut Owner, batch: Batch, seq: u64) {
    let before = owner.pending();
    let mut recver = PrivateClient::new();
    let [status, ..] = recver.syscall(
        0x31,
        [RECEIVE_SELECTOR, DATA, FRAME_BYTES as u64, 0, 1, seq],
        |op, client| {
            assert_eq!(
                (op.operation, op.args[0]),
                (Syscall::IpcRecv, RECEIVE_SELECTOR)
            );
            client.span(op.args[1], FRAME_BYTES, true).unwrap();
            assert_eq!(
                owner.reserve(
                    batch,
                    RECV,
                    op.args[5],
                    now(),
                    || Ok(()),
                    || panic!("batch limit reserved credit")
                ),
                Err(Error::Busy)
            );
            EBUSY
        },
    );
    assert_eq!(status as i64, EBUSY);
    assert_eq!(owner.pending(), before);
}

fn observe_baseline(owner: &mut Owner, boot: u64) {
    owner
        .initialize(boot, 1, EP, SEND, |ep, sender| {
            if (ep, sender) == (EP, SEND) {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    for seq in 1..=9 {
        assert_eq!(send(owner, seq), 0);
    }
    let batch = owner.start_batch(now()).unwrap().unwrap();
    let mut credit = false;
    for seq in 1..=4 {
        receive(owner, batch, seq, &mut credit);
    }
    assert!(!credit);
    check_batch_limit(owner, batch, 5);
    let baseline = owner.end_batch(batch, now()).unwrap();
    assert_eq!(baseline, 4);
    V0199_D05_EVIDENCE.words[12].store(u64::from(baseline), Ordering::Relaxed);
    for seq in 10..=13 {
        assert_eq!(send(owner, seq), 0);
    }
    let sampled = now();
    let observed = owner.observe(sampled).unwrap();
    let values = ActionV2::values(5).unwrap();
    let mask = values.iter().enumerate().fold(0u64, |mask, (i, value)| {
        let ActionV2::Ipc { budget, batch } = *value else {
            unreachable!()
        };
        mask | (u64::from(owner.legal(budget, batch, sampled)) << i)
    });
    let result = [
        sampled,
        observed[0].unwrap(),
        observed[3].unwrap(),
        mask,
        owner.version(),
        cpu::slot() as u64,
    ];
    for (word, value) in OUTPUT.iter().zip(result) {
        word.store(value, Ordering::Relaxed);
    }
}

fn exercise_shrink(owner: &mut Owner) {
    let mut report_bytes = [0u8; MAX_APPLY_REPORT_BYTES];
    assert_eq!(owner.report(&mut report_bytes), Err(Error::NotReady));
    let mut credit = false;
    // Shrink below the old head count. New sends pause without losing any
    // admitted messages. Admission resumes only below the new budget.
    assert_eq!(owner.pending(), 9);
    assert_eq!(send(owner, 14), EAGAIN);
    let mut max_batch = 0;
    let mut applied_total = 0;
    for seq in 5..=14 {
        let batch = owner.start_batch(now()).unwrap().unwrap();
        receive(owner, batch, seq, &mut credit);
        if owner.pending() != 0 {
            check_batch_limit(owner, batch, seq + 1);
        }
        let delivered = owner.end_batch(batch, now()).unwrap();
        max_batch = max_batch.max(delivered);
        applied_total += delivered;
        if seq == 5 {
            assert_eq!(send(owner, 14), EAGAIN);
        } else if seq == 6 {
            assert_eq!(send(owner, 14), 0);
            assert_eq!(send(owner, 14), 0);
            assert_eq!(owner.pending(), 8);
        }
    }
    assert!(!credit);
    assert_eq!(owner.pending(), 0);
    assert!(matches!(owner.start_batch(now()), Ok(None)));
    let n = owner.report(&mut report_bytes).unwrap();
    assert_eq!(n, REPORT_BYTES);
    atomically_copy(&report_bytes[..n], &OUTPUT);
    OUTPUT[13].store(u64::from(max_batch), Ordering::Relaxed);
    OUTPUT[14].store(u64::from(applied_total), Ordering::Relaxed);
    OUTPUT[15].store(timer::cpu_ticks(), Ordering::Relaxed);
}

/// Called only with the built-in CPU1 Business gate permit held.
pub(super) fn worker_step() -> bool {
    assert_eq!(cpu::slot(), 1);
    let round = REQUEST.load(Ordering::Acquire);
    let prior = DONE.load(Ordering::Relaxed);
    if round == prior {
        return false;
    }
    assert_eq!(round, prior + 1);
    let input: [u64; WORDS] = core::array::from_fn(|i| INPUT[i].load(Ordering::Relaxed));
    let owner = unsafe { &mut *core::ptr::addr_of_mut!(BUSINESS.0) };
    match round {
        1 => observe_baseline(owner, input[0]),
        2 => {
            let wire = word_bytes::<WORK_BYTES>(&input[3..]);
            let work = ApplyWorkV1::decode(&wire).unwrap();
            assert_eq!(work.key.plan_seq, SEQ);
            assert!(now() < input[2] + 50_000_000);
            owner
                .accept(&work, input[0], input[1], input[2], || Ok(()))
                .unwrap();
            OUTPUT[0].store(owner.version(), Ordering::Relaxed);
        }
        3 => exercise_shrink(owner),
        4 => {
            let wire = word_bytes::<REPORT_BYTES>(&input);
            let report = ApplyReportV1::decode(&wire).unwrap();
            owner.retire(&report, || Ok(())).unwrap();
            let mut old = [0; MAX_APPLY_REPORT_BYTES];
            assert_eq!(owner.report(&mut old), Err(Error::Stale));
            OUTPUT[0].store(1, Ordering::Relaxed);
        }
        _ => panic!("unexpected D05 fixture round"),
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
    let [sampled, depth, occupancy, legal, version, cpu, ..] = exchange(1, &[boot], &[]);
    assert_eq!((depth, occupancy, legal, version, cpu), (9, 70, 15, 0, 1));
    let target = Target {
        domain: 5,
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
    let observation = DomainObservation {
        target,
        fields: [Some(depth), None, None, Some(occupancy)],
    };
    let snapshot_seq = snapshots
        .capture(1, 1, sampled, [None; 8], &[observation], |o| {
            if o.target == target && o.fields == observation.fields {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    assert_eq!(snapshot_seq, SEQ);
    let snap = snapshots
        .frozen_for_owner(target, 1, 1, now(), |t| {
            if t == target {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let tiers = ActionV2::values(5).unwrap();
    let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
        ordinal: i as u16,
        value: tiers[i],
    });
    let catalog_digest = sha(b"CYX/D05-FIXTURE/0=8,1/1=32,4/2=64,8/3=128,16");
    let candidates = FrozenCandidates::capture(
        snap,
        &catalog,
        catalog_digest,
        BASELINE,
        Some(depth),
        Some(true),
        false,
        |c, h| {
            if c == &catalog && h == catalog_digest {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |v| {
            tiers
                .iter()
                .position(|&x| x == v)
                .map(|i| legal & (1 << i) != 0)
                .ok_or(Error::Denied)
        },
    )
    .unwrap();
    let rules = rule(target, SEQ, 1, 8, 0);
    let profile = Profile::parse(&rules).unwrap();
    let matched = profile
        .match_candidates(
            5,
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
    assert_eq!(ActionV2::decode(5, 1, local.action_payload), Ok(SHRUNK));
    let scope = TrustedRegistrationScope {
        boot_epoch: boot,
        controller_epoch: 1,
        rules_generation: SEQ,
        rules_hash: sha(&rules),
        base_plan_version: desired.version(),
        ledger_generation: 1,
        core_generation: 1,
        snapshot_seq,
        sampled_ns: sampled,
        now_ns: now(),
    };
    assert_eq!(scope.base_plan_version, SEQ - 1);
    let (plan, decision) = encode_decision::<213>(
        target,
        SEQ,
        scope,
        matched,
        candidates.digest(),
        local.action_payload,
    );
    let actions = [local];
    let decisions = [decision];
    assert_eq!(
        gate.register_rule_only(CTL, &plan, &decisions, &profile, &actions, scope),
        Ok(Registration::Frozen),
    );
    let binding = ExecutorBindingV1 {
        domain: 5,
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
            if b.target == target.object && b.executor_generation == 1 {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let publish = TrustedRegistrationScope {
        now_ns: now(),
        ..scope
    };
    assert_eq!(
        gate.publish_once(PUB, &plan, &decisions, &profile, &actions, publish, || {
            desired
                .publish_registered(PUB, cpu::slot(), &plan, publish, |stage| {
                    let action = stage[0].ok_or(Error::Denied)?;
                    if stage.len() == 1
                        && action.value == SHRUNK
                        && action.binding == binding
                        && action.prior_target_version == version
                    {
                        Ok(())
                    } else {
                        Err(Error::Denied)
                    }
                })
                .map(|_| ())
        }),
        Ok(Publication::AdapterAccepted),
    );
    let apply = TrustedApplyScope {
        boot_epoch: boot,
        plan_version: desired.version(),
        now_ns: now(),
    };
    let decoded = PlanV2::decode(&plan).unwrap();
    gate.claim_apply_work(&plan, 0, apply, binding, ReportOrigin::Kernel, |work| {
        desired.accept(work, ReportOrigin::Kernel, apply.now_ns, |action| {
            let frame = WorkFrame::from_plan(
                &decoded,
                0,
                boot,
                work.plan_version,
                binding,
                ReportOrigin::Kernel,
            )?;
            if !ApplyWorkV1::decode(frame.bytes()).is_ok_and(|w| w == *work) {
                return Err(Error::Denied);
            }
            let result = exchange(
                2,
                &[action.prior_target_version, action.until_ns, apply.now_ns],
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
    let effect = exchange(3, &[], &[]);
    let raw = word_bytes::<REPORT_BYTES>(&effect);
    let applied = ApplyReportV1::decode(&raw).unwrap();
    assert_eq!(applied.state, ActionStatus::Applied);
    assert_eq!(applied.key.plan_seq, SEQ);
    let verify = |seen: &ApplyReportV1<'_>| {
        if *seen == applied && effect[13..15] == [1, 10] && effect[15] != 0 {
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
                bytes: &raw,
                origin: ReportOrigin::Kernel,
            }],
            &[binding],
            TrustedApplyScope {
                now_ns: now(),
                ..apply
            },
            None,
            |_, r| verify(r),
            |batch| inbox.retain(SUP, batch),
        )
        .unwrap();
    let feedback = inbox.read(LEARN, 3).unwrap().unwrap();
    assert_eq!(
        (
            feedback.decision,
            feedback.report_bytes(),
            feedback.causal_label
        ),
        (decision, raw.as_slice(), CausalLabel::NoAdoption)
    );
    desired
        .finish(&applied, ReportOrigin::Kernel, now(), |a| {
            if a.key.plan_seq == summary.plan_seq && inbox.len() == 4 {
                verify(&applied)
            } else {
                Err(Error::NotReady)
            }
        })
        .unwrap();
    assert_eq!(exchange(4, &[], &raw)[0], 1);
    let evidence = &V0199_D05_EVIDENCE.words;
    let row = [
        0x4359443035465831,
        boot,
        sampled,
        apply.now_ns,
        cpu,
        depth,
        occupancy,
        effect[13],
        effect[14],
        SEQ,
        applied.completed_ns,
        inbox.len() as u64,
    ];
    for (at, value) in evidence.iter().zip(row) {
        at.store(value, Ordering::Relaxed);
    }
    atomically_copy(&snap.encode().unwrap(), &evidence[16..]);
    atomically_copy(&rules, &evidence[49..]);
    atomically_copy(&plan, &evidence[60..]);
    atomically_copy(&decision, &evidence[87..]);
    atomically_copy(&raw, &evidence[119..]);
    report("V0199_D05_EFFECT", 4, effect[13], SEQ);
}
