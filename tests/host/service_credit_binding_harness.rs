// OWNER_FACADE
// PRODUCTION_BODIES
fn setup(base: u64) {
    CPU.store(0, Ordering::Release); NOW.store(base, Ordering::Release); CPU_WORK.store(1_000, Ordering::Release);
    CREDIT_KIND[0].store(0, Ordering::Release); COMPLETE_READY[0].store(false, Ordering::Release);
    unsafe { let s = &mut *core::ptr::addr_of_mut!(STATE);
        s.scheduler = Scheduler::new(); s.active = [None]; s.service_admitted = false;
        s.scheduler.register_group(group(14)).unwrap(); }
    assert_eq!(begin_service_segment().unwrap().reserved_ns, 2_500_000);
}
#[test]
fn a_long_host_pause_does_not_refresh_or_expire_the_original_execution_origin() {
    setup(100_000_000); NOW.store(108_300_000, Ordering::Release); CPU_WORK.store(101_000, Ordering::Release);
    assert_eq!(authorize_service_turn(), Ok(()), "live witness treated CPU credit as a wall lease");
    assert_eq!(locked(|s| Ok(s.active[0].unwrap().cpu_started)), Ok(Some(1_000)));
    NOW.store(109_100_000, Ordering::Release);
    assert_eq!(authorize_service_turn(), Ok(()));
    assert_eq!(locked(|s| Ok(s.active[0].unwrap().cpu_started)), Ok(Some(1_000)), "reborrow renewed the CPU origin");
    COMPLETE_READY[0].store(true, Ordering::Release);
    assert_eq!(authorize_service_turn(), Err(Error::Auth));
    locked(|s| complete_locked(s, 0)).unwrap();
    assert_eq!(locked(|s| s.scheduler.thread_cpu_ns(group(0x101))), Ok(100_000));
    assert_eq!(authorize_service_turn(), Err(Error::NotReady));
}
#[test]
fn missing_or_regressed_counter_origin_fails_without_changing_dispatch_custody() {
    setup(300_000_000); CPU_WORK.store(999, Ordering::Release);
    assert_eq!(authorize_service_turn(), Err(Error::Range), "PMU rollback became zero execution cost");
    let original = locked(|s| Ok(s.active[0].unwrap().dispatch)).unwrap();
    CPU_WORK.store(101_000, Ordering::Release);
    locked(|s| { s.active[0].as_mut().unwrap().cpu_started = None; Ok(()) }).unwrap();
    assert_eq!(authorize_service_turn(), Err(Error::Auth));
    assert_eq!(locked(|s| Ok(s.active[0].unwrap().dispatch)), Ok(original));
    locked(|s| { s.active[0].as_mut().unwrap().cpu_started = Some(1_000); Ok(()) }).unwrap();
    assert_eq!(authorize_service_turn(), Ok(()));
    CPU_WORK.store(2_501_000, Ordering::Release);
    assert_eq!(authorize_service_turn(), Err(Error::Budget));
    assert_eq!(locked(|s| Ok(s.active[0].unwrap().cpu_started)), Ok(Some(1_000)));
}
