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

#[test]
fn closure_replay_waits_for_full_frame_capacity_after_partial_drain() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
            let (mut driver, _) = crate::native_setup(1);
            driver.peer_boot = 1;
            let key = TaskKey {
                cluster: [1; 32],
                contract: [7; 16],
                task: [9; 16],
                attempt: 1,
            };
            driver.engine.results.push(cluster::ResultRecord {
                key,
                state: TaskState::Done,
                input_hash: [3; 32],
                result_hash: [4; 32],
                body: Vec::new(),
                acknowledged: true,
                received: true,
            });
            for _ in 0..32 {
                driver.send(22, vec![8; 16], None).unwrap();
            }
            driver
                .resume_closure()
                .expect("full reserved queue must defer closure work");
            driver.consume_outgoing(1);
            driver
                .service_closure()
                .expect("a partial frame still occupies capacity");
            let remaining = driver.outgoing().len();
            driver.consume_outgoing(remaining);
            driver.service_closure().unwrap();
            let bytes = driver.outgoing();
            let ack = Header::decode(&bytes[..96]).unwrap();
            assert_eq!(ack.kind, 21);
            assert_eq!(&bytes[128..144], &[7; 16]);
            let at = 96 + ack.body_len as usize;
            let close = Header::decode(&bytes[at..at + 96]).unwrap();
            assert_eq!(close.kind, 22);
            assert_eq!(&bytes[at + 96..], &[7; 16]);
        })
        .unwrap()
        .join()
        .unwrap();
}
