//! Synthetic owner fixtures exercise the sequential replay capability. They
//! are deliberately never submitted as the native 144/72 learning corpus.
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    domains::Action,
    learning::{
        Error, Family, baseline,
        reward::{self, ReplayKind, RequestResult, RewardWorkspace, Trial, WorkRequest},
    },
};

#[test]
fn sequential_capabilities_produce_the_same_checked_label() {
    let family = Family {
        domain: 15,
        kind: 1,
    };
    support::with_trials(family, 7, 9, Default::default(), |candidate, baseline| {
        let mut work = RewardWorkspace::new();
        let expected = reward::pair(candidate, baseline, &support::TestAuthority, &mut work)?;
        let candidate = reward::verify_replay(
            candidate,
            ReplayKind::Candidate,
            &support::TestAuthority,
            &mut work,
        )?;
        let baseline = reward::verify_replay(
            baseline,
            ReplayKind::Baseline,
            &support::TestAuthority,
            &mut work,
        )?;
        let actual = reward::pair_verified(&candidate, &baseline)?;
        assert_eq!(actual.evidence_hash(), expected.evidence_hash());
        assert_eq!(actual.reward(), expected.reward());
        assert_eq!(actual.input(), expected.input());
        assert!(reward::pair_verified(&baseline, &candidate).is_err());
        assert!(reward::pair_verified(&candidate, &candidate).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn shifted_clock_origin_preserves_pairing_but_changed_frozen_arrival_does_not() {
    let family = Family {
        domain: 15,
        kind: 1,
    };
    support::with_trials(family, 7, 9, Default::default(), |candidate, baseline| {
        let delta = 100_000_000_000;
        let requests: Vec<_> = baseline
            .requests
            .iter()
            .map(|r| WorkRequest {
                id: r.id,
                arrived_ns: r.arrived_ns + delta,
                result: match r.result {
                    RequestResult::Completed { finished_ns } => RequestResult::Completed {
                        finished_ns: finished_ns + delta,
                    },
                    value => value,
                },
            })
            .collect();
        let coverage: Vec<_> = baseline
            .coverage
            .iter()
            .map(|c| reward::CpuCoverage {
                first_ns: c.first_ns + delta,
                observation_ns: c.observation_ns + delta,
                observation_end_ns: c.observation_end_ns + delta,
                closing_ns: c.closing_ns + delta,
                ..*c
            })
            .collect();
        let cpus: Vec<_> = baseline
            .cpu
            .iter()
            .map(|c| reward::CpuInterval {
                start_ns: c.start_ns + delta,
                end_ns: c.end_ns + delta,
                ..*c
            })
            .collect();
        let receipts: Vec<_> = baseline
            .baseline
            .iter()
            .map(|r| reward::BaselineAdoption {
                snapshot: cyxia_prototype::policy::Snapshot {
                    taken_ns: r.snapshot.taken_ns + delta,
                    ..r.snapshot
                },
                issued_ns: r.issued_ns + delta,
                accepted_ns: r.accepted_ns + delta,
                started_ns: r.started_ns + delta,
                finished_ns: r.finished_ns + delta,
                approved_deadline_ns: r.approved_deadline_ns + delta,
                ..*r
            })
            .collect();
        let mut shifted = Trial {
            requests: &requests,
            coverage: &coverage,
            cpu: &cpus,
            baseline: &receipts,
            observation_ns: baseline.observation_ns + delta,
            observation_end_ns: baseline.observation_end_ns + delta,
            warmed_from_ns: baseline.warmed_from_ns + delta,
            closing_ns: baseline.closing_ns + delta,
            ..*baseline
        };
        let mut work = RewardWorkspace::new();
        let candidate = reward::verify_replay(
            candidate,
            ReplayKind::Candidate,
            &support::TestAuthority,
            &mut work,
        )?;
        let checked = reward::verify_replay(
            &shifted,
            ReplayKind::Baseline,
            &support::TestAuthority,
            &mut work,
        )?;
        assert_eq!(checked.schedule_hash(), candidate.schedule_hash());
        reward::pair_verified(&candidate, &checked)?;
        let mut changed = requests.clone();
        changed[1].arrived_ns += 1;
        shifted.requests = &changed;
        let checked = reward::verify_replay(
            &shifted,
            ReplayKind::Baseline,
            &support::TestAuthority,
            &mut work,
        )?;
        assert!(matches!(
            reward::pair_verified(&candidate, &checked),
            Err(Error::Evidence)
        ));
        Ok(())
    })
    .unwrap();
}

#[test]
fn stopped_quotes_is_a_baseline_effect_and_never_an_ai_action() {
    assert!(Action::OfferCpu(0).validate().is_err());
    let mut bytes = [0xaa; 16];
    assert_eq!(baseline::encode(Action::OfferCpu(0), &mut bytes), Ok(4));
    assert_eq!(
        baseline::decode(16, 1, &bytes[..4]),
        Ok(Action::OfferCpu(0))
    );
    assert!(baseline::decode(15, 1, &bytes[..4]).is_err());
    assert!(cyxia_prototype::policy_wire::decode_payload(16, 1, &bytes[..4]).is_err());
    support::with_trials(
        Family {
            domain: 16,
            kind: 1,
        },
        7,
        9,
        Default::default(),
        |candidate, b| {
            let receipt = reward::BaselineAdoption {
                actual: Action::OfferCpu(0),
                installed_until_ns: 0,
                ..b.baseline[0]
            };
            let receipts = [receipt];
            let baseline = Trial {
                baseline: &receipts,
                ..*b
            };
            reward::pair(
                candidate,
                &baseline,
                &support::TestAuthority,
                &mut RewardWorkspace::new(),
            )?;
            Ok(())
        },
    )
    .unwrap();
}
