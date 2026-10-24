use super::*;
#[test]
fn full_result_queue_defers_and_all_128_max_results_eventually_drain_once() {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut driver, _) = crate::setup(1);
    for i in 0..128u8 {
        let key = TaskKey {
            cluster: [1; 32],
            contract: [i; 16],
            task: [i; 16],
            attempt: 1,
        };
        driver.engine.results.push(cluster::ResultRecord {
            key,
            state: TaskState::Done,
            input_hash: [1; 32],
            result_hash: [2; 32],
            body: alloc::vec![i;32768],
            acknowledged: false,
            received: false,
        });
    }
    driver.output = alloc::vec![0;131000];
    assert!(
        driver.resend_results().is_ok(),
        "full output must defer, not abort TLS"
    );
    assert!(driver.sent_results.is_empty());
    driver.output.clear();
    for queued in 1..=128 {
        driver.resend_results().unwrap();
        assert_eq!(
            driver.sent_results.len(),
            queued,
            "one bounded result per turn"
        );
        assert_eq!(driver.outgoing().len(), 96 + 141 + 32768);
        let n = driver.outgoing().len();
        driver.consume_outgoing(n);
    }
    driver.resend_results().unwrap();
    assert!(driver.outgoing().is_empty());
}
