//! Protected diagnostic custody, not a filesystem acceptance verdict.
#[path = "../../../kernel/src/domain_file_abi/diagnostics.rs"]
mod diagnostics;

#[test]
fn pending_operation_retains_the_previous_completed_receipt() {
    let mut capture = diagnostics::Capture::new();
    // owner, generation, request, operation, result, count, object,
    // object generation, write sequence, durable sequence, handle, generation.
    let sync = [4096, 4, 6, 5, 0, 0, 5, 1, 1, 1, 1, 2];
    let sequence = capture.begin(100, &sync).unwrap();
    assert!(capture.finish(sequence, 200, &sync));
    let stat = [4096, 4, 7, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(capture.begin(300, &stat), Some(2));
    assert_eq!(capture.words[8..12], [2, 300, 0, 1]);
    assert_eq!(capture.words[12..16], [4096, 4, 7, 10]);
    assert_eq!(capture.words[24..28], [1, 100, 200, 2]);
    assert_eq!(capture.words[28..40], sync);
    assert_eq!(capture.words[4], 0);
}

#[test]
fn duplicate_stale_and_conflicting_results_cannot_replace_a_receipt() {
    let mut capture = diagnostics::Capture::new();
    let original = [4096, 4, 7, 10, 0, 16, 5, 1, 1, 1, 0, 0];
    let sequence = capture.begin(100, &original).unwrap();
    let mut wrong = original;
    wrong[0] = 4097;
    assert!(!capture.finish(sequence, 200, &wrong));
    assert!(!capture.finish(sequence + 1, 200, &original));
    assert!(!capture.finish(sequence, 99, &original));
    assert_eq!(capture.words[8..12], [1, 100, 0, 1]);
    assert!(capture.finish(sequence, 200, &original));
    let completed = capture.words[8..24].to_vec();
    assert!(!capture.finish(sequence, 201, &original));
    assert_eq!(&capture.words[8..24], completed);
    assert_eq!(capture.words[4], 4);
}

#[test]
fn busy_receipt_and_inflight_state_are_distinct_and_never_report_success() {
    let mut capture = diagnostics::Capture::new();
    let request = [4096, 4, 7, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    let sequence = capture.begin(100, &request).unwrap();
    assert_eq!(capture.begin(101, &request), None);
    let mut busy = request;
    busy[4] = (-16i64) as u64;
    assert!(capture.finish(sequence, 200, &busy));
    assert_eq!(capture.words[11], 2);
    assert_eq!(capture.words[16] as i64, -16);
    assert_eq!(
        capture
            .publication
            .load(core::sync::atomic::Ordering::Acquire)
            % 2,
        0
    );
}

#[test]
fn failed_credit_admission_keeps_receipts_and_the_exact_owner_error() {
    let mut capture = diagnostics::Capture::new();
    let sync = [4096, 4, 6, 5, 0, 0, 5, 1, 1, 1, 1, 2];
    let sequence = capture.begin(100, &sync).unwrap();
    assert!(capture.finish(sequence, 200, &sync));
    let completed = capture.words[8..24].to_vec();
    capture.credit_attempt(300, 4096, 4, 2, 10);
    assert_eq!(capture.words[40..46], [1, 300, 4096, 4, 2, 10]);
    assert_eq!(&capture.words[8..24], completed);
    assert_eq!(capture.words[2], 1);
    capture.credit_attempt(400, 4096, 4, 3, 0);
    assert_eq!(capture.words[40..46], [2, 400, 4096, 4, 3, 0]);
}
