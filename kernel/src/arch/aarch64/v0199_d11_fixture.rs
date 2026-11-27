//! Dedicated VirtIO RNG descriptor/notification effect in the epoch fixture.
//! This queue is independent of VirtIO-blk. The fixed rule and target are
//! fixture authorities. Both waves exercise real DMA, used-ring completion,
//! and release, while the accepted policy and terminal feedback use the
//! same protected gate as the other epoch-disk domains.
use super::{
    v0199_effect_fixture::{encode_decision, rule, sha},
    *,
};
use crate::virtio_platform::Board;
use cyxia_driver_virtio::{Platform, Transport, queue::BatchMemory, rng::BatchedRng};
use cyxia_kernel_core::control_plane::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_report_v1::{
        ActionStatus, ApplyReportV1, BoundReport, ExecutorBindingV1, MAX_APPLY_REPORT_BYTES,
        ReportOrigin, TrustedApplyScope,
    },
    candidate_registry_v0199::{CatalogEntry, FrozenCandidates},
    desired_plan_v0199::DesiredBank,
    feedback_v0199::{CausalLabel, FeedbackInbox},
    registered_gate_v3::{
        Publication, RegisteredDecisionGate, Registration, TrustedRegistrationScope,
    },
    rule_profile_v2::{Candidates, Profile},
    snapshot_store_v3::{DomainObservation, SnapshotStore, Target},
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
    id: 11,
    generation: 1,
};
const SEQ: u64 = 5;
const APPROVED: u8 = 4;
const BASELINE: u8 = 1;
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
static mut V0199_D11_DMA: BatchMemory = BatchMemory::zeroed();

#[used]
#[unsafe(no_mangle)]
static V0199_D11_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};

fn attach(info: &BootInfo) -> (u64, BatchedRng) {
    assert_eq!(cpu::slot(), 0);
    assert!(!CLAIMED.swap(true, Ordering::AcqRel));
    let mut found = None;
    for resource in info
        .virtio
        .get(..info.virtio_count)
        .expect("parsed VirtIO resources")
    {
        let pa = resource.base.0;
        if pa < 0x0a00_0000
            || pa
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a20_0000)
        {
            continue;
        }
        let Ok(transport) =
            (unsafe { Transport::attach((crate::HIGH + pa) as usize, resource.len as usize) })
        else {
            continue;
        };
        if transport.device_id() == 4 {
            assert!(
                found.replace((pa, transport)).is_none(),
                "dedicated RNG must be unique"
            );
        }
    }
    let (pa, transport) = found.expect("D11 needs a dedicated real VirtIO RNG");
    // CPU0 claims this pinned diagnostic pool once. No live block driver
    // or bus peer can acquire these pages, even after a failed completion.
    let dma = unsafe { &mut *core::ptr::addr_of_mut!(V0199_D11_DMA) };
    let mut rng = BatchedRng::attach(transport, dma, &Board).unwrap();
    rng.set_completion_interrupts(false, &Board);
    (pa, rng)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Wave {
    bytes: usize,
    published: u64,
    completed: u64,
    doorbells: u64,
    batch: u8,
    version: u64,
    finished_ns: u64,
}

fn drain_wave(rng: &mut BatchedRng) -> Wave {
    let before = rng.notify_stats();
    assert_eq!(
        (
            before.pending,
            before.inflight,
            before.descriptors,
            before.errors
        ),
        (0, 0, 0, 0)
    );
    let deadline = Board.now_ms().checked_add(250).unwrap();
    rng.prefetch(&Board).unwrap();
    let mut bytes = 0;
    let mut chunk = [0; 256];
    // Stop at the exact wave boundary, before try_fill() could request
    // another prefetch. Never expose the entropy itself as test evidence.
    while rng.notify_stats().descriptors != 0 {
        assert!(Board.now_ms() < deadline, "RNG completion deadline");
        bytes += rng.try_fill(&mut chunk, &Board).unwrap();
        chunk.fill(0);
    }
    let after = rng.notify_stats();
    assert_eq!(
        (
            after.pending,
            after.inflight,
            after.descriptors,
            after.errors
        ),
        (0, 0, 0, 0)
    );
    let published = after.published - before.published;
    let completed = after.completed - before.completed;
    assert_eq!(
        (published, completed),
        (rng.capacity() as u64, rng.capacity() as u64)
    );
    assert!((rng.capacity()..=rng.capacity() * 256).contains(&bytes));
    assert_eq!(after.last_published_version, after.last_completed_version);
    Wave {
        bytes,
        published,
        completed,
        doorbells: after.doorbells - before.doorbells,
        batch: after.max_batch,
        version: after.last_completed_version,
        finished_ns: Board.now_ns(),
    }
}

fn retain(at: usize, bytes: &[u8]) {
    for (i, part) in bytes.chunks(8).enumerate() {
        let mut word = [0; 8];
        word[..part.len()].copy_from_slice(part);
        V0199_D11_EVIDENCE.words[at + i].store(u64::from_le_bytes(word), Ordering::Relaxed);
    }
}

pub(super) fn run(
    boot: u64,
    info: &BootInfo,
    gate: &mut RegisteredDecisionGate<'_>,
    snapshots: &mut SnapshotStore,
    inbox: &mut FeedbackInbox,
    desired: &mut DesiredBank,
) {
    let (device_pa, mut rng) = attach(info);
    assert_eq!(rng.current_batch(Board.now_ns()), BASELINE);
    assert_eq!(rng.capacity(), 8);
    let baseline = drain_wave(&mut rng);
    assert_eq!((baseline.batch, baseline.version), (BASELINE, 0));
    let sampled = Board.now_ns();
    let observed = rng.notify_stats();
    let target = Target {
        domain: 11,
        object: TARGET,
        owner: Identity {
            id: 1,
            generation: 1,
        },
    };
    snapshots
        .register_target(target, |t| {
            if t == target && rng.capacity() >= usize::from(APPROVED) {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let fields = [
        Some(u64::from(observed.pending)),
        Some(observed.errors),
        Some(u64::from(observed.descriptors)),
        None,
    ];
    let seq = snapshots
        .capture(
            1,
            1,
            sampled,
            [None; 8],
            &[DomainObservation { target, fields }],
            |o| {
                if o.target == target && o.fields == fields && rng.notify_stats() == observed {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            },
        )
        .unwrap();
    assert_eq!(seq, SEQ);
    let snap = snapshots
        .frozen_for_owner(target, 1, 1, Board.now_ns(), |t| {
            if t == target {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })
        .unwrap();
    let tiers = ActionV2::values(11).unwrap();
    let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
        ordinal: i as u16,
        value: tiers[i],
    });
    let catalog_hash = sha(b"CYX/D11-RNG-FIXTURE/0=1,1=2,2=4,3=8");
    let native_legal = |value| {
        matches!(value, ActionV2::NotifyBatch(n) if usize::from(n) <= rng.capacity())
            && rng.notify_stats().errors == 0
    };
    let candidates = FrozenCandidates::capture(
        snap,
        &catalog,
        catalog_hash,
        ActionV2::NotifyBatch(BASELINE),
        Some(u64::from(observed.descriptors)),
        Some(observed.errors == 0),
        false,
        |c, h| {
            if c == &catalog && h == catalog_hash {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |value| Ok(native_legal(value)),
    )
    .unwrap();
    let rules = rule(target, SEQ, 5, 0, 2);
    let profile = Profile::parse(&rules).unwrap();
    let matched = profile
        .match_candidates(
            11,
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
    assert_eq!(local.action_payload, &[APPROVED]);
    let scope = TrustedRegistrationScope {
        boot_epoch: boot,
        controller_epoch: 1,
        rules_generation: SEQ,
        rules_hash: sha(&rules),
        base_plan_version: desired.version(),
        ledger_generation: 1,
        core_generation: 1,
        snapshot_seq: seq,
        sampled_ns: sampled,
        now_ns: Board.now_ns(),
    };
    assert_eq!(scope.base_plan_version, SEQ - 1);
    let (plan, decision) = encode_decision::<211>(
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
        Ok(Registration::Frozen)
    );
    let binding = ExecutorBindingV1 {
        domain: 11,
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
            if b.target == target.object && rng.notify_stats() == observed {
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
                        let action = stage[0].ok_or(Error::Denied)?;
                        if stage.len() == 1
                            && action.value == ActionV2::NotifyBatch(APPROVED)
                            && action.binding == binding
                            && action.prior_target_version == baseline.version
                            && native_legal(action.value)
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
    let accepted = gate
        .claim_apply_work(&plan, 0, apply, binding, ReportOrigin::Kernel, |work| {
            desired.accept(work, ReportOrigin::Kernel, apply.now_ns, |action| {
                rng.set_notify_policy(APPROVED, work.plan_version, action.until_ns, apply.now_ns)
                    .map_err(|_| Error::Denied)
            })
        })
        .unwrap();
    let work =
        cyxia_kernel_core::control_plane::apply_work_v1::ApplyWorkV1::decode(accepted.bytes())
            .unwrap();
    // Merely installing a notify tier is no effect. An entire later,
    // version-matched wave must pass through actual MMIO and DMA.
    assert_eq!(rng.notify_stats(), observed);
    let candidate = drain_wave(&mut rng);
    let proves_effect = |wave: Wave| {
        wave.version == work.plan_version
            && wave.completed == wave.published
            && wave.published == baseline.published
            && (2..=APPROVED).contains(&wave.batch)
            && wave.finished_ns >= apply.now_ns
            && wave.doorbells != 0
            && wave.doorbells < baseline.doorbells
    };
    assert!(
        proves_effect(candidate),
        "D11 policy did not change actual notifications: {baseline:?} {candidate:?}"
    );
    let mut raw = [0; MAX_APPLY_REPORT_BYTES];
    let n = ApplyReportV1 {
        key: work.key,
        action_index: work.action_index,
        domain_id: 11,
        state: ActionStatus::Applied,
        target: TARGET,
        executor_generation: work.executor_generation,
        plan_version: work.plan_version,
        result: 0,
        completed_ns: candidate.finished_ns,
        action: work.payload,
    }
    .encode(&mut raw)
    .unwrap();
    let applied = ApplyReportV1::decode(&raw[..n]).unwrap();
    let verify = |r: &ApplyReportV1<'_>| {
        if *r == applied
            && work.matches_report(*r)
            && proves_effect(candidate)
            && rng.notify_stats().descriptors == 0
        {
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
                bytes: &raw[..n],
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
    let feedback = inbox.read(LEARN, SEQ as usize - 1).unwrap().unwrap();
    assert_eq!(
        (
            feedback.decision,
            feedback.report_bytes(),
            feedback.causal_label
        ),
        (decision, &raw[..n], CausalLabel::NoAdoption)
    );
    desired
        .finish(&applied, ReportOrigin::Kernel, Board.now_ns(), |action| {
            if action.key.plan_seq == summary.plan_seq && inbox.len() == SEQ as usize {
                verify(&applied)
            } else {
                Err(Error::NotReady)
            }
        })
        .unwrap();
    let statistics = [
        0x4359443131465831,
        boot,
        device_pa,
        rng.capacity() as u64,
        sampled,
        apply.now_ns,
        baseline.published,
        baseline.completed,
        baseline.doorbells,
        u64::from(baseline.batch),
        baseline.version,
        baseline.bytes as u64,
        baseline.finished_ns,
        candidate.published,
        candidate.completed,
        candidate.doorbells,
        u64::from(candidate.batch),
        candidate.version,
        candidate.bytes as u64,
        candidate.finished_ns,
        inbox.len() as u64,
        n as u64,
    ];
    for (at, word) in V0199_D11_EVIDENCE.words.iter().zip(statistics) {
        at.store(word, Ordering::Relaxed);
    }
    retain(24, &snap.encode().unwrap());
    retain(57, &rules);
    retain(68, &plan);
    retain(95, &decision);
    retain(127, &raw[..n]);
    report(
        "V0199_D11_EFFECT",
        baseline.doorbells,
        candidate.doorbells,
        candidate.version,
    );
}
