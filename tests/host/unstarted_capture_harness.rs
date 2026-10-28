// EVIDENCE_MODULE
mod domain_platform { pub fn now_ns() -> u64 { super::now_ns() } }
// This first counterexample exercises the real local collector. Separate
// native-source tests exercise the peer ledger and the prewarm custodian.
mod learning_prewarm {
    pub struct Attempt;
    pub fn attempt_task(_: super::ObjectKey) -> Option<Attempt> { None }
    pub fn finish(_: &mut Attempt, _: u64, _: u64) -> Result<(), ()> { Ok(()) }
    pub fn cancel_unstarted(_: &mut Attempt, _: &super::Cancellation) -> Result<(), ()> { Ok(()) }
}
#[test]
fn successful_unstarted_cancellation_is_not_a_missing_cpu_event() {
    std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(|| {
        let mut scheduler = Scheduler::new();
        scheduler.register_group(group(14)).unwrap();
        let layout = CpuLayout { business_mask: 9, healthy_mask: 15, generation: 1 };
        scheduler.admit(ThreadSpec { key: group(3), group: group(14), cpu: 3,
            allowed_mask: 8, minimum_ns: 10_000_000, budget_ns: 20_000_000 },
            layout, 100_000_000).unwrap();
        let missing = scheduler.dispatch_with_window_headroom(3, layout, 100_000_000,
            2_000_000, BUILTIN_WINDOW_HEADROOM_NS).unwrap().unwrap();
        scheduler.cancel_unstarted(missing, 180_000_001).unwrap();
        CPU.store(3, Ordering::Release);
        capture_credit::cancelled(3, missing, None);
        assert!(!capture_credit::retire(3), "missing capture custody became a clean cancellation");
        assert!(!capture_credit::available(3));
        CPU.store(0, Ordering::Release);
        NOW.store(1_000_000_000, Ordering::Release);
        let storage = Box::leak(Box::new(learning_evidence::Storage::empty()));
        learning_evidence::install(storage, [1; 32], 1, group(44), |_, _, _| Ok(()))
            .map_err(|(error, _)| error).unwrap();
        learning_evidence::start(1,
            cyxia_prototype::learning::Family { domain: 1, kind: 1 },
            1_000_000_000, 7_000_000_000, [7; 32],
            &[
                cyxia_prototype::learning::reward::CpuClass::Policy,
                cyxia_prototype::learning::reward::CpuClass::ExecutorAction,
                cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
            ].map(|class| cyxia_prototype::learning::capture::Source {
                owner: group(0x101), class, allowed_cores: 1,
            }),
            &core::array::from_fn::<_, 100, _>(|i|
                cyxia_prototype::learning::capture::FrozenRequest {
                    owner: group(20), id: i as u64 + 1,
                    arrived_ns: 7_000_000_000 + i as u64 * 1_000_000,
                })).unwrap();
        locked(|s| s.scheduler.register_group(group(14))).unwrap();
        let first = begin_service_segment().unwrap();
        NOW.store(1_080_000_001, Ordering::Release);
        let held = acquire_guard().unwrap();
        assert!(revalidate_service_segment(), "task gate Busy cancelled physical custody");
        assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire), 5);
        drop(held);
        locked(|s| {
            // Inject a scheduler-time rejection without consuming its actual
            // dispatch: set_runnable advances time, then rejects active work.
            assert_eq!(s.scheduler.set_runnable(first.thread, false, 1_090_000_000), Err(Error::Busy));
            Ok(())
        }).unwrap();
        assert!(revalidate_service_segment(), "failed scheduler cancellation lost the live dispatch");
        locked(|s| {
            assert_eq!(s.active[0].unwrap().dispatch.sequence, first.sequence);
            assert_eq!(s.scheduler.active(0).unwrap().sequence, first.sequence);
            Ok(())
        }).unwrap();
        assert_eq!(learning_evidence::status().unwrap().0.missing_events, 0);
        NOW.store(1_090_000_000, Ordering::Release);
        assert!(!revalidate_service_segment());
        assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire), 0);
        let status = learning_evidence::status().unwrap().0;
        assert_eq!(status.missing_events, 0,
            "successful cancellation manufactured an unfinished CPU event");
        locked(|s| {
            assert!(s.active[0].is_none());
            assert!(s.scheduler.active(0).is_none());
            assert_eq!(s.scheduler.thread_cpu_ns(first.thread)?, 0);
            Ok(())
        }).unwrap();
        NOW.store(1_100_000_000, Ordering::Release);
        let next = begin_service_segment().unwrap();
        assert_ne!(next.sequence, first.sequence);
        NOW.store(1_100_100_000, Ordering::Release);
        finish_capture(0, 1_100_000_000, 1_100_100_000);
        COMPLETE_READY[0].store(true, Ordering::Release);
        locked(|s| complete_locked(s, 0)).unwrap();
        assert_eq!(locked(|s| s.scheduler.thread_cpu_ns(first.thread)), Ok(100_000));
        assert_eq!(learning_evidence::status().unwrap().0.missing_events, 0);
    }).unwrap().join().unwrap();
}
