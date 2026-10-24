use super::*;
#[test]
fn ordinary_outbox_capacity_preserves_independent_control_admission_and_fifo() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
            let (mut a, _) = crate::native_setup(1);
            a.peer_boot = 1;
            a.send(16, alloc::vec![1;65536], None).unwrap();
            a.send(16, alloc::vec![2;65536], None).unwrap();
            assert!(a.send(16, alloc::vec![3], None).is_err());
            // Both ordinary byte credits are full. Heartbeat still has its own
            // real queue storage and credit; stream sequence remains FIFO.
            a.send(2, alloc::vec![4], None).unwrap();
            assert_eq!(a.queued_class(false).unwrap(), (131264, 2));
            assert_eq!(a.queued_class(true).unwrap(), (97, 1));
            let headers = [0usize, 65632, 131264];
            for (index, at) in headers.into_iter().enumerate() {
                assert_eq!(
                    Header::decode(&a.output[at..at + 96]).unwrap().sequence,
                    index as u64 + 1
                );
            }
            a.consume_outgoing(65632);
            a.send(16, alloc::vec![5;100], None).unwrap();
            assert_eq!(a.sent, 0);
            assert_eq!(Header::decode(&a.outgoing()[..96]).unwrap().sequence, 2);
        })
        .unwrap()
        .join()
        .unwrap();
}
