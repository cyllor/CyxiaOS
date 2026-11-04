#[path = "../../kernel/src/unified_runtime_loop.rs"]
mod evidence;

#[test]
fn terminal_summary_is_identity_bound_and_even_published() {
    let mut record = [0u64; evidence::RECORD_WORDS];
    record[..9].copy_from_slice(&[1, 9, 2, 100, 900, 1200, 300, 600, 900]);
    for (at, values) in [
        (9, [40, 910, 950]), (12, [80, 960, 1040]),
        (15, [50, 970, 1020]), (18, [30, 1020, 1050]),
        (21, [20, 1060, 1080]), (24, [90, 1090, 1180]),
    ] {
        record[at..at + 3].copy_from_slice(&values);
    }
    record[27..31].copy_from_slice(&[875, 1200, 12, 0]);
    let mut inexact = record;
    inexact[6] -= 1;
    assert!(!evidence::retain(&inexact, 7, 3, 9));
    assert!(!evidence::retain(&record, 7, 3, 8));
    assert!(evidence::retain(&record, 7, 3, 9));
    let mut latest = record;
    latest[1] = 10;
    latest[2] = 3;
    latest[3] = 2_000;
    latest[4] = 2_900;
    latest[5] = 3_200;
    for at in [6, 9, 12, 15, 18, 21, 24] {
        latest[at + 1] += 2_000;
        latest[at + 2] += 2_000;
    }
    latest[27] += 2_000;
    latest[28] = 3_200;
    latest[29] = 1;
    assert!(evidence::retain(&latest, 7, 3, 10));
    let bank = evidence::snapshot();
    assert_eq!(bank[0], 4);
    assert_eq!(&bank[1..8], &[evidence::MAGIC, 1, 2, 7, 3, 10, 0]);
    assert_eq!(&bank[8..40], &latest);
}
