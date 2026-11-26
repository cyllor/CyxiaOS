//! Actual generic-timer comparator and expiry evidence for current D07.
//! Same diagnostic snapshot, decision, publisher and feedback custody as
//! D15, distinct plan/decision/snapshot sequences. The two immutable test
//! catalogs are fixture inputs, not production signed configurations.
//! CPU0 orchestration only; no production business timer scheduler or WCET.
use super::*;
use cyxia_kernel_core::control_plane::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_report_v1::{
        ActionStatus, ApplyReportV1, BoundReport, ExecutorBindingV1, MAX_APPLY_REPORT_BYTES,
        ReportOrigin, TrustedApplyScope,
    },
    candidate_registry_v0199::{CatalogEntry, FrozenCandidates},
    d07_owner_v0199::{Owner, TimerClass, programmed_ns},
    desired_plan_v0199::DesiredBank,
    feedback_v0199::{CausalLabel, FeedbackInbox},
    registered_gate_v3::{
        Publication, RegisteredDecisionGate, Registration, TrustedRegistrationScope,
    },
    rule_profile_v2::{Candidates, Profile},
    snapshot_store_v3::{DomainObservation, SnapshotStore, Target},
};
use sha2::{Digest, Sha256};
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
    id: 7,
    generation: 1,
};
const SOFT: Identity = Identity {
    id: 701,
    generation: 1,
};
const SLACK: u64 = 80_000;
fn now() -> u64 {
    (u128::from(timer::ticks()) * 1_000_000_000 / u128::from(timer::frequency()))
        .try_into()
        .unwrap()
}
fn future() -> u64 {
    now().div_ceil(1_000_000) * 1_000_000 + 10_016_000
}
fn tick_ns() -> u64 {
    let f = timer::frequency();
    assert!(f != 0 && 1_000_000_000 % f == 0);
    1_000_000_000 / f
}
fn program(deadline: u64) -> (u64, u64) {
    let quantum = tick_ns();
    assert_eq!(deadline % quantum, 0);
    let ticks = deadline / quantum;
    let daif: u64;
    let cmp: u64;
    let ctl: u64;
    unsafe {
        core::arch::asm!("mrs {}, daif",out(reg)daif,options(nomem,nostack));
        assert_ne!(daif & (1 << 7), 0);
        timer::arm(ticks);
        core::arch::asm!("mrs {}, cntp_cval_el0","mrs {}, cntp_ctl_el0",
            out(reg)cmp,out(reg)ctl,options(nomem,nostack));
    }
    assert_eq!(cmp, ticks);
    assert_eq!(ctl & 3, 1);
    (cmp, now())
}
fn finish(deadline: u64) -> u64 {
    while now() < deadline {
        timer::idle();
    }
    let ctl: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntp_ctl_el0",out(reg)ctl,options(nomem,nostack));
    }
    assert_eq!(ctl & 7, 5); // ENABLE and real comparator ISTATUS, not guessed wake.
    let done = now();
    assert!(done >= deadline);
    unsafe {
        cpu::disable_timer();
    }
    done
}
fn p16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn rule() -> [u8; 88] {
    let mut b = [0; 88];
    p32(&mut b, 0, 0x43595255);
    p16(&mut b, 4, 2);
    p16(&mut b, 6, 32);
    p64(&mut b, 8, 2);
    p32(&mut b, 16, 1);
    p32(&mut b, 20, 88);
    p32(&mut b, 32, 2);
    p16(&mut b, 36, 7);
    p16(&mut b, 38, 1);
    p64(&mut b, 40, TARGET.id);
    p16(&mut b, 50, 1);
    p16(&mut b, 52, 1);
    p32(&mut b, 56, 56);
    p16(&mut b, 64, 1);
    b[66] = 3;
    p64(&mut b, 72, 1);
    p16(&mut b, 80, 2);
    b
}
fn retain_bytes(at: usize, bytes: &[u8]) {
    for (i, part) in bytes.chunks(8).enumerate() {
        let mut word = [0u8; 8];
        word[..part.len()].copy_from_slice(part);
        SMP_EVIDENCE.words[at + i].store(u64::from_le_bytes(word), Ordering::Relaxed);
    }
}
pub(super) fn run(
    boot: u64,
    gate: &mut RegisteredDecisionGate<'_>,
    snapshots: &mut SnapshotStore,
    inbox: &mut FeedbackInbox,
    desired: &mut DesiredBank,
    owner: &mut Owner,
) {
    assert_eq!(cpu::slot(), 0);
    owner
        .bind(boot, TARGET, 1, || {
            if cpu::slot() == 0 && timer::frequency() != 0 {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    owner
        .register(SOFT, TimerClass::Soft, SLACK, || Ok(()))
        .unwrap();
    let requested = future();
    let mut base_cmp = 0;
    let baseline = owner
        .arm(SOFT, requested, now(), |a| {
            let (compare, done) = program(a.programmed_ns);
            base_cmp = compare;
            Ok(done)
        })
        .unwrap();
    assert_eq!(baseline.programmed_ns, requested);
    let base_wake = finish(baseline.programmed_ns);
    owner.complete(baseline, base_wake, || Ok(())).unwrap();
    let sample = now();
    let fields = owner.observe(sample).unwrap();
    let target = Target {
        domain: 7,
        object: TARGET,
        owner: Identity {
            id: 1,
            generation: 1,
        },
    };
    snapshots
        .register_target(target, |t| {
            if t.object == owner.target() {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    assert_eq!(
        snapshots.capture(
            1,
            1,
            sample,
            [None; 8],
            &[DomainObservation { target, fields }],
            |o| if o.target == target && o.fields == owner.observe(sample)? {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        ),
        Ok(2)
    );
    let snap = snapshots
        .frozen_for_owner(target, 1, 1, now(), |t| {
            if t.object == owner.target() {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let values = ActionV2::values(7).unwrap();
    let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
        ordinal: i as u16,
        value: values[i],
    });
    let catalog_digest = sha(b"CYX/D07-FIXTURE-ORDINALS/0=0,1=50,2=200,3=1000");
    let candidates = FrozenCandidates::capture(
        snap,
        &catalog,
        catalog_digest,
        ActionV2::SoftCoalesce(0),
        Some(1),
        Some(true),
        false,
        |r, h| {
            if r == &catalog && h == catalog_digest {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |v| match v {
            ActionV2::SoftCoalesce(n) => Ok(owner.legal(n, sample)),
            _ => Err(Error::Denied),
        },
    )
    .unwrap();
    let rules = rule();
    let profile = Profile::parse(&rules).unwrap();
    let matched = profile
        .match_candidates(
            7,
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
    assert_eq!(local.action_payload, &[200, 0]);
    let expiry = sample + 100_000_000;
    let until = sample + 10_000_000_000;
    let mut plan = [0u8; 212];
    p32(&mut plan, 0, 0x43594c31);
    p16(&mut plan, 4, 2);
    p16(&mut plan, 6, 64);
    p32(&mut plan, 8, 212);
    p16(&mut plan, 12, 1);
    p64(&mut plan, 16, 2);
    p64(&mut plan, 24, 1);
    p64(&mut plan, 40, 1);
    p64(&mut plan, 48, 2);
    p64(&mut plan, 56, until);
    p32(&mut plan, 64, 0x43595031);
    p16(&mut plan, 68, 2);
    p16(&mut plan, 70, 144);
    p16(&mut plan, 72, 7);
    p16(&mut plan, 74, 1);
    p32(&mut plan, 76, 4);
    for (at, v) in [
        (80, 1),
        (88, 2),
        (96, 2),
        (104, TARGET.id),
        (112, TARGET.generation),
        (120, 1),
        (128, 1),
        (136, expiry),
    ] {
        p64(&mut plan, at, v);
    }
    plan[176..208].copy_from_slice(&candidates.digest());
    p16(&mut plan, 208, matched.fallback_index);
    plan[210..212].copy_from_slice(local.action_payload);
    let mut record = [0u8; 256];
    p32(&mut record, 0, 0x43594431);
    p16(&mut record, 4, 3);
    p16(&mut record, 6, 256);
    for (at, v) in [
        (8, boot),
        (16, 1),
        (24, 2),
        (32, 2),
        (40, 2),
        (48, TARGET.id),
        (56, TARGET.generation),
        (64, 1),
        (72, 1),
        (80, 2),
        (144, expiry),
    ] {
        p64(&mut record, at, v);
    }
    p32(&mut record, 88, matched.rule_id);
    p16(&mut record, 94, 7);
    p16(&mut record, 96, 1);
    p16(&mut record, 102, matched.fallback_index);
    p16(&mut record, 104, u16::MAX);
    p32(&mut record, 108, 2);
    p32(&mut record, 152, matched.allowed_mask);
    p16(&mut record, 156, matched.fallback_index);
    p16(&mut record, 158, matched.choice_policy);
    record[160..192].copy_from_slice(&sha(&rules));
    record[192..224].copy_from_slice(&sha(&plan));
    record[224..].copy_from_slice(&candidates.digest());
    let ctx = TrustedRegistrationScope {
        boot_epoch: boot,
        controller_epoch: 1,
        rules_generation: 2,
        rules_hash: sha(&rules),
        base_plan_version: 1,
        ledger_generation: 1,
        core_generation: 1,
        snapshot_seq: 2,
        sampled_ns: sample,
        now_ns: now(),
    };
    let actions = [local];
    let records = [record];
    assert_eq!(
        gate.register_rule_only(CTL, &plan, &records, &profile, &actions, ctx),
        Ok(Registration::Frozen)
    );
    assert_eq!(desired.version(), ctx.base_plan_version);
    let binding = ExecutorBindingV1 {
        domain: 7,
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
            if b.target == owner.target() {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let pubctx = TrustedRegistrationScope {
        now_ns: now(),
        ..ctx
    };
    assert_eq!(
        gate.publish_once(PUB, &plan, &records, &profile, &actions, pubctx, || {
            desired
                .publish_registered(PUB, cpu::slot(), &plan, pubctx, |stage| {
                    let a = stage[0].ok_or(Error::Denied)?;
                    if stage.len() == 1
                        && a.value == ActionV2::SoftCoalesce(200)
                        && a.binding == binding
                        && a.prior_target_version == owner.version()
                        && owner.legal(200, pubctx.now_ns)
                    {
                        Ok(())
                    } else {
                        Err(Error::Denied)
                    }
                })
                .map(|_| ())
        }),
        Ok(Publication::AdapterAccepted)
    );
    assert_eq!(desired.version(), 2);
    let scope = TrustedApplyScope {
        boot_epoch: boot,
        plan_version: desired.version(),
        now_ns: now(),
    };
    gate.claim_apply_work(&plan, 0, scope, binding, ReportOrigin::Kernel, |w| {
        desired.accept(w, ReportOrigin::Kernel, scope.now_ns, |a| {
            owner.accept(w, a.prior_target_version, a.until_ns, scope.now_ns, || {
                Ok(())
            })
        })
    })
    .unwrap();
    let mut report_bytes = [0; MAX_APPLY_REPORT_BYTES];
    assert_eq!(owner.report(now(), &mut report_bytes), Err(Error::NotReady));
    // Hard timer remains outside the soft owner, even with a live 200us
    // policy. Program and observe the real comparator without coalescing.
    let hard_req = future();
    let hard = programmed_ns(TimerClass::Hard, 0, hard_req, now(), owner.current(now())).unwrap();
    assert_eq!(hard, hard_req);
    let (hard_cmp, _) = program(hard);
    let hard_wake = finish(hard);
    assert_eq!(owner.report(now(), &mut report_bytes), Err(Error::NotReady));
    let soft_req = future();
    let mut soft_cmp = 0;
    let soft = owner
        .arm(SOFT, soft_req, now(), |a| {
            let (compare, done) = program(a.programmed_ns);
            soft_cmp = compare;
            Ok(done)
        })
        .unwrap();
    assert_eq!(soft.programmed_ns, soft_req + SLACK);
    assert_eq!(soft.policy_version, 2);
    let first = owner.applied_evidence().unwrap();
    assert_eq!(first.arm, soft);
    let soft_wake = finish(soft.programmed_ns);
    owner.complete(soft, soft_wake, || Ok(())).unwrap();
    let n = owner.report(now(), &mut report_bytes).unwrap();
    let r = ApplyReportV1::decode(&report_bytes[..n]).unwrap();
    assert_eq!(r.state, ActionStatus::Applied);
    let frames = [BoundReport {
        bytes: &report_bytes[..n],
        origin: ReportOrigin::Kernel,
    }];
    let summary = gate
        .settle_verified_apply_reports_with_feedback(
            SUP,
            &plan,
            &frames,
            &[binding],
            TrustedApplyScope {
                now_ns: now(),
                ..scope
            },
            None,
            |_, r| owner.verify_report(r),
            |batch| inbox.retain(SUP, batch),
        )
        .unwrap();
    let feedback = inbox.read(LEARN, 1).unwrap().unwrap();
    assert_eq!(feedback.report_bytes(), &report_bytes[..n]);
    assert_eq!(feedback.decision, record);
    assert_eq!(feedback.causal_label, CausalLabel::NoAdoption);
    desired
        .finish(&r, ReportOrigin::Kernel, now(), |a| {
            if a.key.plan_seq == summary.plan_seq && inbox.len() == 2 {
                owner.verify_report(&r)
            } else {
                Err(Error::NotReady)
            }
        })
        .unwrap();
    owner
        .retire(&r, || {
            if summary.plan_seq == 2 && inbox.len() == 2 {
                Ok(())
            } else {
                Err(Error::NotReady)
            }
        })
        .unwrap();
    let row = [
        0x4359443037465831,
        timer::frequency(),
        requested,
        baseline.programmed_ns,
        base_cmp,
        base_wake,
        hard_req,
        hard,
        hard_cmp,
        hard_wake,
        soft_req,
        soft.programmed_ns,
        soft_cmp,
        soft_wake,
        first.started_ns,
        first.completed_ns,
        sample,
        scope.now_ns,
        soft.policy_version,
        n as u64,
        inbox.len() as u64,
        SLACK,
        200,
        soft.serial,
    ];
    for (i, v) in row.into_iter().enumerate() {
        SMP_EVIDENCE.words[220 + i].store(v, Ordering::Relaxed);
    }
    retain_bytes(244, &snap.encode().unwrap());
    retain_bytes(277, &rules);
    retain_bytes(288, &plan);
    retain_bytes(315, &record);
    retain_bytes(347, &report_bytes[..n]);
    report("V0199_D07_EFFECT", soft_req, soft.programmed_ns, soft_wake);
}
