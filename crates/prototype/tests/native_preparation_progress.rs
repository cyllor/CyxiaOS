//! Production diagnostic transitions with literal host fixtures; no native authority.
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_control/replay/preparation_progress.rs"]
mod progress;
use cyxia_prototype::{
    domains::{ApplyId, Error, ObjectKey, PolicyStamp},
    policy::ExecutionState,
};
use progress::{Bank, Blocker, Identity, Job, Observation, Reason};
fn id(n: u64) -> Identity {
    Identity([1, n, n, 90457653395801, 1, 1, 2, 1, 2, 16379340000])
}
fn obs(reason: Reason) -> Observation {
    let (stage, result, before, end, after) = match reason {
        Reason::AuthError => (1, Err(Error::Busy), 0, 0, 0),
        Reason::OtherError => (2, Err(Error::Stale), 0, 0, 0),
        Reason::JobReset => (5, Ok(false), 8, 0, 0),
        Reason::DesiredReset => (6, Ok(false), 8, 16, 0),
        Reason::Advance => (7, Ok(false), 8, 16, 16),
        Reason::AlreadyReady => (4, Ok(true), 512, 0, 512),
        Reason::ScanComplete => (8, Ok(true), 504, 512, 512),
    };
    Observation {
        reason,
        stage,
        result,
        service_entry_ns: 599550562000,
        before,
        end,
        after,
        job: None,
        prepared_count: if reason == Reason::JobReset { 2 } else { 0 },
        blocker: if reason == Reason::DesiredReset {
            Some(blocker())
        } else {
            None
        },
    }
}
fn blocker() -> Blocker {
    Blocker {
        slot: 9,
        reason: 4,
        apply: ApplyId {
            boot_epoch: 1,
            controller_epoch: 3,
            plan_seq: 595,
            action_index: 0,
            target: ObjectKey {
                id: 4153,
                generation: 11,
            },
        },
        stamp: PolicyStamp {
            version: 560,
            snapshot_ns: 123456789123,
            installed_until_ns: 987654321987,
        },
        state: ExecutionState::Applied,
        started: true,
        observed: true,
        predicate_at: Some(599550562000),
    }
}
#[test]
fn actual_auth_busy_is_distinct_from_no_call_and_survives_later_scan_progress() {
    let b = Bank::new();
    assert_eq!(b.snapshot(0), [0; 128]);
    b.observe(id(1), obs(Reason::AuthError));
    let first = b.snapshot(0);
    assert_eq!(first[15], 1);
    assert_eq!(first[17], 1);
    assert_eq!(first[16], 0);
    assert_eq!(first[4], 8);
    assert_eq!(first[27], 3 | (10 << 8));
    assert_eq!(first[32], 1);
    assert_eq!(first[33], 599550562000);
    assert_eq!((first[34] >> 18) & 255, 10);
    b.observe(id(1), obs(Reason::Advance));
    let after = b.snapshot(0);
    assert_eq!(after[15], 2);
    assert_eq!(after[21], 1);
    assert_eq!(after[24], 16);
    assert_eq!(&after[32..64], &first[32..64]);
    assert_eq!(
        (after[26], after[27], after[28], after[29], after[30]),
        (7, 1, 8, 16, 16)
    );
}
#[test]
fn first_and_last_resets_keep_real_job_and_desired_operands_without_truncation() {
    let b = Bank::new();
    let mut o = obs(Reason::JobReset);
    o.job = Some(Job {
        controller: 7,
        sequence: 595,
        cpu: 2,
        read_only: true,
        family: Some((14, 1)),
        target: [4153, 11],
        started_ns: u64::MAX - 123,
        completion: true,
    });
    b.observe(id(1), o);
    let first = b.snapshot(0);
    assert_eq!(
        &first[68..80],
        &[1, 2, 7, 595, 2, 1, 14, 1, 4153, 11, u64::MAX - 123, 1]
    );
    b.observe(id(1), obs(Reason::DesiredReset));
    let row = b.snapshot(0);
    assert_eq!(&row[64..80], &first[64..80]);
    assert_eq!(row[80], 2);
    assert_eq!(row[96], 2);
    assert_eq!(
        &row[100..111],
        &[
            10,
            4,
            1,
            3,
            595,
            4153,
            11,
            560,
            123456789123,
            987654321987,
            599550562000
        ]
    );
    let first_blocker = row[96..112].to_vec();
    let mut other = obs(Reason::DesiredReset);
    other.blocker.as_mut().unwrap().predicate_at = Some(0);
    other.service_entry_ns = 1;
    b.observe(id(1), other);
    let row = b.snapshot(0);
    assert_eq!(&row[96..112], first_blocker);
    assert_eq!(row[112], 3);
    assert_eq!(row[126], 0);
    assert_ne!(
        row[127] & (1 << 28),
        0,
        "observed zero predicate is not absent"
    );
}
#[test]
fn every_original_branch_counts_its_actual_result_and_ready_has_no_reset() {
    let b = Bank::new();
    for r in [
        Reason::AuthError,
        Reason::OtherError,
        Reason::JobReset,
        Reason::DesiredReset,
        Reason::Advance,
        Reason::AlreadyReady,
        Reason::ScanComplete,
    ] {
        b.observe(id(1), obs(r));
    }
    let s = b.snapshot(0);
    assert_eq!(s[15], 7);
    assert_eq!(&s[17..24], &[1; 7]);
    assert_eq!(s[24], 512);
    assert_eq!((s[26], s[27]), (8, 2));
    assert_eq!(s[4], 8);
    assert_eq!(s[15], s[17..24].iter().sum());
}
#[test]
fn six_identities_never_recycle_first_rows_and_seventh_is_explicitly_untracked() {
    let b = Bank::new();
    for n in 1..=6 {
        b.observe(id(n), obs(Reason::AuthError));
    }
    let first = b.snapshot(0);
    let last = b.snapshot(5);
    b.observe(id(7), obs(Reason::Advance));
    assert_eq!(b.snapshot(0), first);
    assert_eq!(&b.snapshot(5)[5..], &last[5..]);
    assert_eq!(b.snapshot(5)[4], 10);
    let mut changed = id(1);
    changed.0[8] = 1;
    b.observe(changed, obs(Reason::Advance));
    let now = b.snapshot(0);
    assert_eq!(now[4], 12);
    assert_eq!(&now[5..], &first[5..]);
}
#[test]
fn saturation_is_flagged_only_on_actual_overflow_and_impossible_events_do_not_fabricate_progress() {
    let b = Bank::new();
    b.observe(id(1), obs(Reason::AuthError));
    b.seed_counter(0, 15, u64::MAX - 1);
    b.seed_counter(0, 17, u64::MAX - 1);
    b.observe(id(1), obs(Reason::AuthError));
    assert_eq!(b.snapshot(0)[15], u64::MAX);
    assert_eq!(b.snapshot(0)[4], 8);
    b.observe(id(1), obs(Reason::AuthError));
    assert_eq!(b.snapshot(0)[4], 9);
    assert_eq!(b.snapshot(0)[15], u64::MAX);
    let b = Bank::new();
    let mut impossible = obs(Reason::Advance);
    impossible.result = Err(Error::Busy);
    b.observe(id(1), impossible);
    let s = b.snapshot(0);
    assert_eq!(s[4], 12);
    assert_eq!(s[15], 0);
    assert_eq!(&s[32..], [0; 96]);
}

#[test]
fn blocked_scan_end_is_not_maximum_progress_and_absent_predicate_is_explicit() {
    let bank = Bank::new();
    let mut o = obs(Reason::DesiredReset);
    let b = o.blocker.as_mut().unwrap();
    b.reason = 1;
    b.state = ExecutionState::Unknown;
    b.predicate_at = None;
    bank.observe(id(1), o);
    let row = bank.snapshot(0);
    assert_eq!(row[24], 8);
    assert_eq!(row[110], 0);
    assert_eq!(row[111] & (1 << 28), 0);
    assert_eq!((row[111] >> 16) & 3, 3);
    let mut o = obs(Reason::DesiredReset);
    o.blocker.as_mut().unwrap().state = ExecutionState::Failed(Error::Io);
    bank.observe(id(1), o);
    let row = bank.snapshot(0);
    assert_eq!((row[127] >> 16) & 3, 2);
    assert_eq!((row[127] >> 18) & 255, 18);
    let bank = Bank::new();
    bank.observe(id(1), obs(Reason::JobReset));
    let row = bank.snapshot(0);
    assert_eq!((row[68], row[69]), (0, 2));
    assert_eq!(&row[70..80], [0; 10]);
}

#[test]
fn production_bank_outbound_bytes_are_explicit_host_fixture_only() {
    use std::io::Write;
    let bank = Bank::new();
    let mut visit = obs(Reason::AuthError);
    bank.observe(id(1), visit);
    visit = obs(Reason::Advance);
    visit.before = 0;
    visit.end = 8;
    visit.after = 8;
    bank.observe(id(1), visit);
    visit = obs(Reason::JobReset);
    visit.job = Some(Job {
        controller: 7,
        sequence: 595,
        cpu: 2,
        read_only: true,
        family: Some((14, 1)),
        target: [4153, 11],
        started_ns: 16300000000,
        completion: true,
    });
    bank.observe(id(1), visit);
    visit = obs(Reason::Advance);
    visit.before = 0;
    visit.end = 8;
    visit.after = 8;
    bank.observe(id(1), visit);
    bank.observe(id(1), obs(Reason::DesiredReset));
    for before in (0..512).step_by(8) {
        let mut visit = obs(if before == 504 {
            Reason::ScanComplete
        } else {
            Reason::Advance
        });
        visit.before = before;
        visit.end = before + 8;
        visit.after = before + 8;
        bank.observe(id(1), visit);
    }
    bank.observe(id(1), obs(Reason::AlreadyReady));
    for n in 2..=6 {
        bank.observe(id(n), obs(Reason::AuthError));
        let mut visit = obs(Reason::Advance);
        visit.before = 0;
        visit.end = 8;
        visit.after = 8;
        bank.observe(id(n), visit);
    }
    let bytes: Vec<u8> = (0..6)
        .flat_map(|slot| bank.snapshot(slot).into_iter().flat_map(u64::to_le_bytes))
        .collect();
    assert_eq!(bytes.len(), 6144);
    if let Some(path) = std::env::var_os("CYXIA_A03_PREPARATION_PROGRESS_HOST_FIXTURE") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
    }
    println!(
        "host-only diagnostic fixture; Bank={}B temporary allowance={}B Observation={}B Identity={}B",
        progress::BYTES,
        progress::LOCAL_BYTES,
        core::mem::size_of::<Observation>(),
        core::mem::size_of::<Identity>()
    );
}
