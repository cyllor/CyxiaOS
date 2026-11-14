//! Structural gate fixtures, never native observations or trained-model evidence.
use cyxia_prototype::a03::{DemandWindow, OWNER_ROW, OWNER_WORDS, completed_roundtrip};

const WINDOW: DemandWindow = DemandWindow {
    first_ns: 500,
    withdrawn_ns: 1400,
    drained_ns: 1500,
};

fn trace() -> Vec<u64> {
    let mut w = vec![0; OWNER_WORDS];
    w[..12].copy_from_slice(&[
        0x4359_4f57_4e31_3531,
        1,
        OWNER_WORDS as u64,
        7,
        2,
        0,
        0,
        0,
        896,
        8,
        2,
        2,
    ]);
    for index in 0..2 {
        let row = 128 + index * OWNER_ROW;
        let r = &mut w[row..row + OWNER_ROW];
        let (before, desired) = if index == 0 { (2, 6) } else { (6, 2) };
        let time = 1000 + index as u64 * 1000;
        let operation = index as u64 + 1;
        let job = 20 + index as u64;
        r[0] = 8;
        r[1] = 31;
        r[2..8].copy_from_slice(&[7, 1, job, 0, 0x434f5245, 1]);
        r[8..13].copy_from_slice(&[desired, time, time + 1, operation, operation]);
        r[14..20].copy_from_slice(&[job, 2, 32, 0, operation, 9]);
        for (phase, at) in [32, 48, 64, 80].into_iter().enumerate() {
            let control = if phase < 2 { before } else { desired };
            r[at..at + 16].copy_from_slice(&[
                time + 1 + phase as u64,
                15,
                control,
                15 ^ control,
                0,
                0,
                if phase == 1 { 4 } else { 0 },
                0,
                operation + u64::from(phase >= 2),
                9,
                1,
                900,
                300,
                if phase == 2 { 63 } else { 0 },
                if phase > 0 { operation } else { 0 },
                if phase == 2 { operation } else { 0 },
            ]);
        }
        let m = &mut r[192..832];
        m[0..8].copy_from_slice(&[job, job, 1, 2, 0x434f5245, 1, 1, 7]);
        m[13] = operation;
        m[14] = 2;
        m[19] = 1;
        m[28] = time + 5;
        m[30] = 1;
        m[639] = 8;
        let input = &mut m[32..544];
        input[2..5].copy_from_slice(&[job, 1, time]);
        input[6..12].copy_from_slice(&[operation, 9, 1, 2, 0x434f5245, 1]);
        input[14] = 7;
        input[36..39].copy_from_slice(&[job, job, job]);
        input[400..404].copy_from_slice(&[before, 15 ^ before, 15, 0]);
    }
    w
}

#[test]
fn only_a_complete_later_contraction_can_close_the_ordinary_scene() {
    let w = trace();
    let done = completed_roundtrip(|i| w[i], WINDOW).unwrap();
    assert!(
        completed_roundtrip(
            |i| w[i],
            DemandWindow {
                first_ns: 1100,
                ..WINDOW
            }
        )
        .is_none()
    );
    assert!(
        completed_roundtrip(
            |i| w[i],
            DemandWindow {
                withdrawn_ns: 1002,
                ..WINDOW
            }
        )
        .is_none()
    );
    assert_eq!(
        (done.job, done.version, done.input_ns, done.applied_ns),
        (21, 2, 2000, 2005)
    );
    assert!(
        completed_roundtrip(
            |i| w[i],
            DemandWindow {
                drained_ns: 2000,
                ..WINDOW
            }
        )
        .is_none()
    );
    assert!(
        completed_roundtrip(
            |i| w[i],
            DemandWindow {
                first_ns: 0,
                ..WINDOW
            }
        )
        .is_none()
    );
}

#[test]
fn pending_wrong_identity_partial_handoff_and_unfinished_owner_are_rejected() {
    let original = trace();
    let second = 128 + OWNER_ROW;
    // Each changed value corrupts an independently required execution fact.
    let mutations = [
        (0, 0),
        (3, 0),
        (4, 1),
        (5, 1),
        (6, 1),
        (7, 1),
        (10, 1),
        (11, 1),
        (second, 9),
        (second + 1, 15),
        (second + 2, 8),
        (second + 4, 99),
        (second + 5, 1),
        (second + 6, 99),
        (second + 8, 6),
        (second + 11, 1),
        (second + 12, 99),
        (second + 14, 20),
        (second + 18, 99),
        (second + 34, 2),
        (second + 54, 0),
        (second + 62, 99),
        (second + 66, 6),
        (second + 68, 4),
        (second + 72, 2),
        (second + 75, 200),
        (second + 76, 0),
        (second + 77, 31),
        (second + 79, 99),
        (second + 82, 6),
        (second + 192 + 14, 1),
        (second + 192 + 28, 2003),
        (second + 192 + 36, 1000),
        (second + 192 + 639, 9),
        (second + 224 + 37, 99),
        (second + 224 + 400, 2),
        (second + 224 + 403, 4),
    ];
    for (at, value) in mutations {
        let mut w = original.clone();
        w[at] = value;
        assert!(
            completed_roundtrip(|i| w[i], WINDOW).is_none(),
            "accepted changed field {at}"
        );
    }
}

#[test]
fn changing_an_earlier_publication_during_the_read_is_rejected() {
    let w = trace();
    let mut reads = 0;
    assert!(
        completed_roundtrip(
            |i| {
                if i == 128 {
                    reads += 1;
                    if reads >= 3 {
                        return w[i] + 2;
                    }
                }
                w[i]
            },
            WINDOW
        )
        .is_none()
    );
}
