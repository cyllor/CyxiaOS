//! Mechanism regression fixtures, not native training evidence.
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::learning::{
    Error, Family,
    reward::{
        self, Adoption, EvidenceAuthority, IncrementalAuthority, ReplayKind, ReplayPiece,
        ReplayVerification, RequestResult, RewardWorkspace, Trial, VerifiedReplay, WorkRequest,
    },
};
use std::cell::{Cell, RefCell};

/// Every request-piece lookup is genuinely unavailable once. A cursor may
/// neither consume that piece nor move to another phase until its retry passes.
struct RequestOwner {
    pending: Cell<Option<(usize, usize)>>,
    accepted: RefCell<Vec<(usize, usize)>>,
    last: Cell<Option<ReplayPiece>>,
}
impl RequestOwner {
    fn new() -> Self {
        Self {
            pending: Cell::new(None),
            accepted: RefCell::new(Vec::new()),
            last: Cell::new(None),
        }
    }
}
impl IncrementalAuthority for RequestOwner {
    fn begin(&self, trial: &Trial<'_>) -> Result<Option<[u8; 32]>, Error> {
        support::TestAuthority.attest(trial, [0x73; 32])?;
        Ok(Some([0x73; 32]))
    }

    fn attest_piece(
        &self,
        _: &Trial<'_>,
        binding: [u8; 32],
        piece: ReplayPiece,
    ) -> Result<bool, Error> {
        assert_eq!(binding, [0x73; 32]);
        if let ReplayPiece::Requests { start, end } = piece {
            assert!(end > start && end - start <= 16);
            let range = (start, end);
            if let Some(prior) = self.pending.take() {
                assert_eq!(prior, range, "a busy request lookup was skipped");
                self.accepted.borrow_mut().push(range);
                self.last.set(Some(piece));
                Ok(true)
            } else {
                self.pending.set(Some(range));
                Ok(false)
            }
        } else {
            assert!(self.pending.get().is_none(), "advanced past a busy piece");
            self.last.set(Some(piece));
            Ok(true)
        }
    }

    fn finish(&self, trial: &Trial<'_>, _: [u8; 32], digest: [u8; 32]) -> Result<bool, Error> {
        assert!(self.pending.get().is_none());
        support::TestAuthority.attest(trial, digest)?;
        Ok(true)
    }
}

fn view<'a>(
    t: &Trial<'a>,
    requests: &'a [WorkRequest],
    adoptions: &'a [Adoption<'a>],
) -> Trial<'a> {
    Trial {
        id: t.id,
        family: t.family,
        group: t.group,
        frozen_other_domains: t.frozen_other_domains,
        schemas: t.schemas,
        local_node: t.local_node,
        controlled_nodes: t.controlled_nodes,
        observation_ns: t.observation_ns,
        observation_end_ns: t.observation_end_ns,
        warmed_from_ns: t.warmed_from_ns,
        closing_ns: t.closing_ns,
        requests,
        adoptions,
        coverage: t.coverage,
        cpu: t.cpu,
        baseline: t.baseline,
        joint_policy: t.joint_policy,
        correct: t.correct,
        frozen: t.frozen,
        closing: t.closing,
        ordinary_warmup_cpu_ns: t.ordinary_warmup_cpu_ns,
        later_workload_cpu_ns: t.later_workload_cpu_ns,
        peak_workspace_bytes: t.peak_workspace_bytes,
    }
}

fn adoption_view<'a>(a: &Adoption<'a>) -> Adoption<'a> {
    Adoption {
        decision_seq: a.decision_seq,
        apply: a.apply,
        plan_version: a.plan_version,
        executor_generation: a.executor_generation,
        candidates: a.candidates,
        model: a.model,
        scores: a.scores,
        selected: a.selected,
        actual: a.actual,
        executed: a.executed,
        issued_ns: a.issued_ns,
        accepted_ns: a.accepted_ns,
        expires_local_ns: a.expires_local_ns,
        active_until_local_ns: a.active_until_local_ns,
        target_request_id: a.target_request_id,
        started_ns: a.started_ns,
        finished_ns: a.finished_ns,
        installed_until_ns: a.installed_until_ns,
        approved_deadline_ns: a.approved_deadline_ns,
        concurrent: a.concurrent,
        shared_policy_intervals: a.shared_policy_intervals,
    }
}

fn drive(t: &Trial<'_>, kind: ReplayKind, owner: &RequestOwner) -> Result<VerifiedReplay, Error> {
    let mut cursor = ReplayVerification::new(kind);
    let mut work = Box::new(RewardWorkspace::new());
    for _ in 0..200_000 {
        match cursor.step(t, owner, &mut work) {
            Ok(Some(proof)) => {
                assert_eq!(cursor.step(t, owner, &mut work).err(), Some(Error::Stale));
                return Ok(proof);
            }
            Err(error) => {
                assert_eq!(cursor.step(t, owner, &mut work).err(), Some(error));
                return Err(error);
            }
            Ok(None) => {}
        }
    }
    panic!("one-shot replay did not finish");
}

#[test]
fn one_shot_last_of_4096_and_missing_targets_use_authenticated_bounded_scans() {
    support::with_trials(
        Family {
            domain: 16,
            kind: 2,
        },
        91,
        4,
        Default::default(),
        |candidate, baseline| {
            for (source, kind) in [
                (candidate, ReplayKind::Candidate),
                (baseline, ReplayKind::Baseline),
            ] {
                let mut requests: Vec<_> = (1..4096_u64)
                    .map(|i| WorkRequest {
                        id: i + 1,
                        arrived_ns: source.observation_ns + i * 1_000_000,
                        result: RequestResult::Completed {
                            finished_ns: source.observation_ns + i * 1_000_000 + 5000,
                        },
                    })
                    .collect();
                requests.push(source.requests[0]);
                assert_eq!(requests[4095].id, 1);
                assert_eq!(requests[4095].arrived_ns, source.observation_ns);

                let trial = view(source, &requests, source.adoptions);
                let canonical = reward::verify_replay(
                    &trial,
                    kind,
                    &support::TestAuthority,
                    &mut RewardWorkspace::new(),
                )?;
                let owner = RequestOwner::new();
                let actual = drive(&trial, kind, &owner)?;
                assert_eq!(canonical.evidence_hash(), actual.evidence_hash());
                assert_eq!(canonical.schedule_hash(), actual.schedule_hash());
                assert_eq!(canonical.performance(), actual.performance());
                assert_eq!(canonical.cpu(), actual.cpu());

                let pass: Vec<_> = (0..4096).step_by(16).map(|i| (i, i + 16)).collect();
                let expected: Vec<_> = pass.iter().chain(pass.iter()).copied().collect();
                // The target lookup and the later canonical request stream
                // each authenticate all 256 pieces. Only the latter hashes.
                assert_eq!(*owner.accepted.borrow(), expected);

                for missing_id in [true, false] {
                    let mut invalid = requests.clone();
                    if missing_id {
                        invalid[4095].id = 4097;
                    } else {
                        // The correct id at a different arrival is not the
                        // original one-shot request and must stay Evidence.
                        invalid[4095].arrived_ns += 1;
                    }
                    let invalid = view(source, &invalid, source.adoptions);
                    assert_eq!(
                        reward::verify_replay(
                            &invalid,
                            kind,
                            &support::TestAuthority,
                            &mut RewardWorkspace::new(),
                        )
                        .err(),
                        Some(Error::Evidence)
                    );
                    let owner = RequestOwner::new();
                    assert_eq!(drive(&invalid, kind, &owner).err(), Some(Error::Evidence));
                    assert_eq!(*owner.accepted.borrow(), pass);
                }
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn changing_adoption_during_model_or_choice_is_sticky_stale_without_indexing() {
    support::with_trials(
        Family {
            domain: 16,
            kind: 2,
        },
        92,
        5,
        Default::default(),
        |source, _| {
            for during_choice in [false, true] {
                for fault in 0..3 {
                    let mut cursor = ReplayVerification::new(ReplayKind::Candidate);
                    let mut work = Box::new(RewardWorkspace::new());
                    let owner = RequestOwner::new();
                    let mut entered = false;
                    for _ in 0..100 {
                        assert!(cursor.step(source, &owner, &mut work)?.is_none());
                        entered = if during_choice {
                            matches!(
                                owner.last.get(),
                                Some(ReplayPiece::Candidate {
                                    adoption: 0,
                                    index: 0
                                })
                            )
                        } else {
                            matches!(
                                owner.last.get(),
                                Some(ReplayPiece::Model {
                                    adoption: 0,
                                    start: 0,
                                    ..
                                })
                            )
                        };
                        if entered {
                            break;
                        }
                    }
                    assert!(entered);
                    let original = &source.adoptions[0];
                    let replacement_set = *original.candidates;
                    let mut changed = adoption_view(original);
                    match fault {
                        0 => {
                            changed.selected = (changed.selected + 1) % changed.scores.len() as u16
                        }
                        1 => changed.scores = &changed.scores[..0],
                        _ => changed.candidates = &replacement_set,
                    }
                    let adoptions = [changed];
                    let changed = view(source, source.requests, &adoptions);
                    assert_eq!(
                        cursor.step(&changed, &owner, &mut work).err(),
                        Some(Error::Stale)
                    );
                    // Returning to the old view cannot revive the rejected walk.
                    assert_eq!(
                        cursor.step(source, &owner, &mut work).err(),
                        Some(Error::Stale)
                    );
                }
            }

            // Rebuilding only the temporary view, as the native caller does,
            // retains the same protected loans and is still valid.
            let canonical = reward::verify_replay(
                source,
                ReplayKind::Candidate,
                &support::TestAuthority,
                &mut RewardWorkspace::new(),
            )?;
            let mut cursor = ReplayVerification::new(ReplayKind::Candidate);
            let mut work = Box::new(RewardWorkspace::new());
            let owner = RequestOwner::new();
            assert!(cursor.step(source, &owner, &mut work)?.is_none());
            assert!(cursor.step(source, &owner, &mut work)?.is_none());
            let rebuilt = [adoption_view(&source.adoptions[0])];
            let rebuilt = view(source, source.requests, &rebuilt);
            let mut complete = false;
            for _ in 0..200_000 {
                if let Some(proof) = cursor.step(&rebuilt, &owner, &mut work)? {
                    assert_eq!(proof.evidence_hash(), canonical.evidence_hash());
                    complete = true;
                    break;
                }
            }
            assert!(complete);
            Ok(())
        },
    )
    .unwrap();
}
