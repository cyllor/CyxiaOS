#[path = "../../kernel/src/domain_tasks/deadline.rs"]
mod deadline;
#[path = "../../crates/prototype/src/a10_budget.rs"]
mod a10_budget;

#[test]
fn ordinary_one_shot_deadline_stays_bounded_to_sixty_seconds() {
    assert!(deadline::valid(10, 60_000_000_010, 0, deadline::ORDINARY_NS));
    assert!(!deadline::valid(10, 60_000_000_011, 0, deadline::ORDINARY_NS));
}

#[test]
fn storage_fault_client_deadline_allows_each_exact_mode_window_only() {
    for mode in 1..=4 {
        let window = a10_budget::client_deadline_ns(mode).unwrap();
        assert!(deadline::valid(10, window + 10, 0, window));
        assert!(!deadline::valid(10, window + 11, 0, window));
    }
}

#[test]
fn cache_pressure_client_has_room_for_every_declared_private_page() {
    for mode in 1..=3 {
        assert_eq!(a10_budget::client_memory_pages(mode), Some(16));
    }
    // 2 launch-input pages + 1 progress page + 8 stack pages + 16 data pages.
    assert_eq!(a10_budget::client_memory_pages(4), Some(27));
    assert_eq!(a10_budget::client_memory_pages(0), None);
    assert_eq!(a10_budget::client_memory_pages(5), None);
}

#[test]
fn expired_deadlines_fail_and_recoverable_recipes_keep_their_existing_policy() {
    assert!(!deadline::valid(10, 10, 0, deadline::ORDINARY_NS));
    assert!(!deadline::valid(10, 9, 1, deadline::ORDINARY_NS));
    assert!(deadline::valid(10, u64::MAX, 1, deadline::ORDINARY_NS));
}
