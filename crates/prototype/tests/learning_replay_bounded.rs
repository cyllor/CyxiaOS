//! Synthetic mechanism fixtures only; never native training evidence.
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::learning::{
    Error, Family,
    reward::{
        self, CpuClass, CpuInterval, EvidenceAuthority, IncrementalAuthority, JointPolicySplit,
        ReplayKind, ReplayPiece, ReplayVerification, RewardWorkspace, Trial, VerifiedReplay,
    },
};
use std::cell::{Cell, RefCell};

struct TestOwner {
    binding: Cell<[u8; 32]>,
    block: bool,
    begin_wait: Cell<bool>,
    piece_wait: Cell<bool>,
    finish_wait: Cell<bool>,
    reject_cpu: Cell<bool>,
    pieces: RefCell<Vec<ReplayPiece>>,
}
impl TestOwner {
    fn new(block: bool) -> Self {
        Self {
            binding: Cell::new([0x61; 32]),
            block,
            begin_wait: Cell::new(block),
            piece_wait: Cell::new(block),
            finish_wait: Cell::new(block),
            reject_cpu: Cell::new(false),
            pieces: RefCell::new(Vec::new()),
        }
    }
}
impl IncrementalAuthority for TestOwner {
    fn begin(&self, t: &Trial<'_>) -> Result<Option<[u8; 32]>, Error> {
        support::TestAuthority.attest(t, [0x61; 32])?;
        if self.block && self.begin_wait.replace(!self.begin_wait.get()) {
            return Ok(None);
        }
        Ok(Some(self.binding.get()))
    }
    fn attest_piece(
        &self,
        _: &Trial<'_>,
        binding: [u8; 32],
        piece: ReplayPiece,
    ) -> Result<bool, Error> {
        assert_eq!(binding, self.binding.get());
        if self.block && self.piece_wait.replace(!self.piece_wait.get()) {
            return Ok(false);
        }
        match piece {
            ReplayPiece::Model { start, end, .. } => assert!(end >= start && end - start <= 256),
            ReplayPiece::Requests { start, end } | ReplayPiece::Cpu { start, end } => {
                assert!(end >= start && end - start <= 16);
            }
            _ => {}
        }
        if self.reject_cpu.get() && matches!(piece, ReplayPiece::Cpu { .. }) {
            return Err(Error::Evidence);
        }
        self.pieces.borrow_mut().push(piece);
        Ok(true)
    }
    fn finish(&self, t: &Trial<'_>, _: [u8; 32], digest: [u8; 32]) -> Result<bool, Error> {
        support::TestAuthority.attest(t, digest)?;
        if self.finish_wait.replace(false) {
            return Ok(false);
        }
        Ok(true)
    }
}
fn drive(
    t: &Trial<'_>,
    kind: ReplayKind,
    owner: &TestOwner,
) -> Result<(VerifiedReplay, usize), Error> {
    let mut cursor = ReplayVerification::new(kind);
    let mut work = Box::new(RewardWorkspace::new());
    for turns in 1..200_000 {
        if let Some(proof) = cursor.step(t, owner, &mut work)? {
            assert_eq!(cursor.step(t, owner, &mut work).err(), Some(Error::Stale));
            return Ok((proof, turns));
        }
    }
    panic!("bounded replay did not finish");
}
fn same(a: &VerifiedReplay, b: &VerifiedReplay) {
    assert_eq!(a.evidence_hash(), b.evidence_hash());
    assert_eq!(a.schedule_hash(), b.schedule_hash());
    assert_eq!(a.performance(), b.performance());
    assert_eq!(a.cpu(), b.cpu());
    assert_eq!(a.kind(), b.kind());
    assert_eq!(a.family(), b.family());
    assert_eq!(a.group(), b.group());
    assert_eq!(a.trial_id(), b.trial_id());
    assert_eq!(a.candidate_set_hash(), b.candidate_set_hash());
}
fn compare(t: &Trial<'_>, kind: ReplayKind) -> Result<VerifiedReplay, Error> {
    let golden = reward::verify_replay(
        t,
        kind,
        &support::TestAuthority,
        &mut RewardWorkspace::new(),
    )?;
    let (bounded, turns) = drive(t, kind, &TestOwner::new(false))?;
    assert!(turns > 1);
    same(&golden, &bounded);
    Ok(bounded)
}

#[test]
fn every_family_has_identical_canonical_sides_and_paired_reward() {
    for family in support::FAMILIES {
        support::with_trials(family, 91, 4, Default::default(), |candidate, baseline| {
            let expected = reward::pair(
                candidate,
                baseline,
                &support::TestAuthority,
                &mut RewardWorkspace::new(),
            )?;
            let c = compare(candidate, ReplayKind::Candidate)?;
            let b = compare(baseline, ReplayKind::Baseline)?;
            let actual = reward::pair_verified(&c, &b)?;
            assert_eq!(expected.evidence_hash(), actual.evidence_hash());
            assert_eq!(expected.input(), actual.input());
            assert_eq!(expected.reward(), actual.reward());
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn original_faults_keep_the_same_acceptance_and_errors() {
    for fault in 0..9 {
        let mut faults = support::Faults::default();
        match fault {
            0 => faults.unknown = true,
            1 => faults.missing_partner = true,
            2 => faults.mismatched_arrival = true,
            3 => faults.wrong_score = true,
            4 => faults.unsafe_candidate = true,
            5 => faults.pending_request = true,
            6 => faults.broken_renewal = true,
            7 => faults.stale_schema = true,
            _ => faults.saturated_cpu = true,
        }
        support::with_trials(
            Family {
                domain: 15,
                kind: 1,
            },
            3,
            7,
            faults,
            |c, b| {
                for (trial, kind) in [(c, ReplayKind::Candidate), (b, ReplayKind::Baseline)] {
                    let old = reward::verify_replay(
                        trial,
                        kind,
                        &support::TestAuthority,
                        &mut RewardWorkspace::new(),
                    );
                    let next = drive(trial, kind, &TestOwner::new(false));
                    match (old, next) {
                        (Ok(old), Ok((next, _))) => same(&old, &next),
                        (Err(old), Err(next)) => assert_eq!(old, next, "fault={fault}"),
                        _ => panic!("acceptance diverged for fault={fault}"),
                    }
                }
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn real_owner_waits_preserve_every_chunk_and_emit_only_one_capability() {
    support::with_trials(
        Family { domain: 1, kind: 1 },
        3,
        7,
        Default::default(),
        |c, _| {
            let direct_owner = TestOwner::new(false);
            let waiting_owner = TestOwner::new(true);
            let (direct, fast) = drive(c, ReplayKind::Candidate, &direct_owner)?;
            let (waiting, slow) = drive(c, ReplayKind::Candidate, &waiting_owner)?;
            assert!(slow > fast);
            same(&direct, &waiting);
            assert_eq!(
                *direct_owner.pieces.borrow(),
                *waiting_owner.pieces.borrow()
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn a_changed_seal_or_trial_cannot_resume_old_partial_validation() {
    support::with_trials(
        Family {
            domain: 15,
            kind: 1,
        },
        3,
        7,
        Default::default(),
        |_, b| {
            let owner = TestOwner::new(false);
            let mut cursor = ReplayVerification::new(ReplayKind::Baseline);
            let mut work = RewardWorkspace::new();
            assert!(cursor.step(b, &owner, &mut work)?.is_none());
            owner.binding.set([0x62; 32]);
            assert_eq!(cursor.step(b, &owner, &mut work).err(), Some(Error::Stale));
            owner.binding.set([0x61; 32]);
            assert_eq!(cursor.step(b, &owner, &mut work).err(), Some(Error::Stale));
            let mut cursor = ReplayVerification::new(ReplayKind::Baseline);
            assert!(cursor.step(b, &owner, &mut work)?.is_none());
            let changed = Trial {
                closing_ns: b.closing_ns + 1,
                ..*b
            };
            assert_eq!(
                cursor.step(&changed, &owner, &mut work).err(),
                Some(Error::Stale)
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn an_unattested_cpu_piece_is_sticky_and_never_becomes_a_label() {
    support::with_trials(
        Family {
            domain: 15,
            kind: 1,
        },
        3,
        7,
        Default::default(),
        |_, b| {
            let owner = TestOwner::new(false);
            owner.reject_cpu.set(true);
            let mut cursor = ReplayVerification::new(ReplayKind::Baseline);
            let mut work = RewardWorkspace::new();
            let mut rejected = false;
            for _ in 0..1000 {
                match cursor.step(b, &owner, &mut work) {
                    Err(Error::Evidence) => {
                        rejected = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unattested CPU reached a successful seal"),
                }
            }
            assert!(rejected);
            owner.reject_cpu.set(false);
            assert_eq!(
                cursor.step(b, &owner, &mut work).err(),
                Some(Error::Evidence)
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn full_8192_interval_trace_is_hashed_and_merged_in_bounded_pieces() {
    support::with_trials(
        Family {
            domain: 15,
            kind: 1,
        },
        3,
        7,
        Default::default(),
        |_, b| {
            let rows: Vec<_> = (0..reward::MAX_CPU_INTERVALS)
                .rev()
                .map(|i| CpuInterval {
                    node: b.local_node,
                    core: (i % 4) as u16,
                    start_ns: b.coverage[0].first_ns + (i as u64) * 1000,
                    end_ns: b.coverage[0].first_ns + (i as u64) * 1000 + 600,
                    class: CpuClass::Policy,
                })
                .collect();
            let large = Trial { cpu: &rows, ..*b };
            let golden = reward::verify_replay(
                &large,
                ReplayKind::Baseline,
                &support::TestAuthority,
                &mut RewardWorkspace::new(),
            )?;
            let owner = TestOwner::new(false);
            let (bounded, turns) = drive(&large, ReplayKind::Baseline, &owner)?;
            same(&golden, &bounded);
            let pieces = owner.pieces.borrow();
            let cpu: Vec<_> = pieces
                .iter()
                .filter_map(|p| match p {
                    ReplayPiece::Cpu { start, end } => Some((*start, *end)),
                    _ => None,
                })
                .collect();
            assert_eq!(cpu.len(), 512);
            for (i, (start, end)) in cpu.into_iter().enumerate() {
                assert_eq!((start, end), (16 * i, 16 * (i + 1)));
            }
            assert!(turns > 512);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn shared_policy_cost_has_the_same_hash_and_rejects_double_charging() {
    support::with_trials(
        Family {
            domain: 15,
            kind: 1,
        },
        3,
        7,
        Default::default(),
        |c, _| {
            let first = c.adoptions[0].apply;
            let concurrent = [
                first,
                cyxia_prototype::domains::ApplyId {
                    action_index: 1,
                    target: cyxia_prototype::domains::ObjectKey {
                        id: 2,
                        generation: 1,
                    },
                    ..first
                },
            ];
            let source = CpuInterval {
                node: c.local_node,
                core: 1,
                start_ns: c.coverage[0].first_ns + 1_000_000,
                end_ns: c.coverage[0].first_ns + 1_090_001,
                class: CpuClass::Policy,
            };
            let shared = [source];
            let mut adoptions: Vec<_> = c
                .adoptions
                .iter()
                .map(|a| reward::Adoption { ..*a })
                .collect();
            adoptions[0].concurrent = &concurrent;
            adoptions[0].shared_policy_intervals = &shared;
            let joints = [JointPolicySplit {
                source,
                actions: &concurrent,
                action_index: 0,
            }];
            let mut cpu = c.cpu.to_vec();
            cpu.push(reward::split_joint_policy(source, 2, 0)?);
            let trial = Trial {
                adoptions: &adoptions,
                joint_policy: &joints,
                cpu: &cpu,
                ..*c
            };
            compare(&trial, ReplayKind::Candidate)?;
            cpu.push(source);
            let bad = Trial {
                adoptions: &adoptions,
                joint_policy: &joints,
                cpu: &cpu,
                ..*c
            };
            assert_eq!(
                reward::verify_replay(
                    &bad,
                    ReplayKind::Candidate,
                    &support::TestAuthority,
                    &mut RewardWorkspace::new()
                )
                .err(),
                Some(Error::Evidence)
            );
            assert_eq!(
                drive(&bad, ReplayKind::Candidate, &TestOwner::new(false)).err(),
                Some(Error::Evidence)
            );
            Ok(())
        },
    )
    .unwrap();
}
