//! Execute the native owner's production selector with stopped task facts.
//! These counterexamples exercise fairness and custody, not guest timing.
#[path = "../../../kernel/src/domain_tasks/lifecycle.rs"]
mod lifecycle;
use lifecycle::View;

const IDLE: View = View {
    occupied: false,
    exiting: false,
    deadline_ns: 0,
    return_pending: false,
    file_done: false,
    file_busy: false,
};

#[test]
fn expired_waiting_and_ready_tasks_cannot_starve_behind_continuous_receipts() {
    const TASKS: usize = 60;
    let mut tasks = [IDLE; TASKS];
    tasks[3].return_pending = true;
    tasks[42].file_done = true;
    // A blocked Waiting task and a Ready task need no new return to expire.
    // The selector deliberately does not require either to be runnable.
    for i in [17, 59] {
        tasks[i].occupied = true;
        tasks[i].deadline_ns = 100;
    }
    for initial in 0..TASKS {
        let mut cursor = initial;
        let mut serviced = [false; TASKS];
        for _ in 0..TASKS {
            let i = lifecycle::select::<TASKS>(cursor, 100, |i| tasks[i]);
            serviced[i] = true;
            cursor = (i + 1) % TASKS;
            // Keep both return/receipt sources continuously ready, including
            // when the previous turn already serviced that source.
        }
        assert!(serviced[17] && serviced[59], "initial cursor {initial}");
    }
}

#[test]
fn timeout_becomes_ready_at_the_real_deadline_without_expiring_a_free_slot() {
    let tasks = [
        IDLE, // Its stale zero deadline cannot turn it into timeout work.
        View {
            occupied: true,
            deadline_ns: 10,
            ..IDLE
        },
        View {
            return_pending: true,
            ..IDLE
        },
    ];
    assert_eq!(lifecycle::select::<3>(0, 9, |i| tasks[i]), 2);
    assert_eq!(lifecycle::select::<3>(0, 10, |i| tasks[i]), 1);
    assert_eq!(lifecycle::select::<3>(2, 10, |i| tasks[i]), 2);
}

#[test]
fn in_flight_file_custody_defers_timeout_until_its_actual_completion() {
    let mut tasks = [
        View {
            occupied: true,
            deadline_ns: 1,
            file_busy: true,
            ..IDLE
        },
        View {
            return_pending: true,
            ..IDLE
        },
    ];
    assert_eq!(lifecycle::select::<2>(0, 100, |i| tasks[i]), 1);
    // The completion must be consumed even while FILE_BUSY is still held;
    // lifecycle_piece clears custody before it performs deadline cleanup.
    tasks[0].file_done = true;
    assert_eq!(lifecycle::select::<2>(0, 100, |i| tasks[i]), 0);
    tasks[0].file_done = false;
    tasks[0].file_busy = false;
    assert_eq!(lifecycle::select::<2>(0, 100, |i| tasks[i]), 0);
}

#[test]
fn retrying_exit_and_idle_work_keep_the_rotating_cursor() {
    let mut tasks = [IDLE; 4];
    for cursor in 0..4 {
        assert_eq!(lifecycle::select::<4>(cursor, 100, |i| tasks[i]), cursor);
    }
    tasks[0].exiting = true;
    tasks[2].occupied = true;
    tasks[2].deadline_ns = 100;
    assert_eq!(lifecycle::select::<4>(0, 100, |i| tasks[i]), 0);
    assert_eq!(lifecycle::select::<4>(1, 100, |i| tasks[i]), 2);
    assert_eq!(lifecycle::select::<4>(3, 100, |i| tasks[i]), 0);
}
