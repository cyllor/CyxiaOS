use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
struct Ticket(usize);
#[derive(Debug)]
struct Completion;
#[derive(Clone)]
struct State {
    now: u64,
    ready: [u64; 3],
    collected: [bool; 3],
    cancelled: Vec<usize>,
}
static STATE: Mutex<State> = Mutex::new(State {
    now: 0, ready: [0; 3], collected: [false; 3], cancelled: Vec::new(),
});
fn now_ns() -> u64 { STATE.lock().unwrap().now }
mod runtime {
    pub fn idle_until(until: u64) -> Result<(), ()> {
        STATE.lock().unwrap().now = until;
        Ok(())
    }
    use super::STATE;
}
mod dispatch {
    use super::*;
    pub struct Drained { pub completions: [Option<Completion>; 3] }
    pub fn try_collect(ticket: Ticket) -> Result<Option<Completion>, ()> {
        let mut state = STATE.lock().unwrap();
        assert!(!state.collected[ticket.0], "completion collected twice");
        if state.now < state.ready[ticket.0] { return Ok(None); }
        state.collected[ticket.0] = true;
        Ok(Some(Completion))
    }
    pub fn drain(tickets: &[Ticket], _deadline: u64) -> Result<Drained, ()> {
        let mut state = STATE.lock().unwrap();
        let mut completions = core::array::from_fn(|_| None);
        for &Ticket(index) in tickets {
            assert!(!state.collected[index]);
            if state.now < state.ready[index] { state.cancelled.push(index); }
            state.collected[index] = true;
            completions[index] = Some(Completion);
        }
        Ok(Drained { completions })
    }
}

fn run(ready: [u64; 3], active: [bool; 3]) -> [Option<Completion>; 3] {
    *STATE.lock().unwrap() = State {
        now: 0, ready, collected: [false; 3], cancelled: Vec::new(),
    };
    let started = now_ns();
    let mut tickets = core::array::from_fn::<_, 3, _>(|i| active[i].then_some(Ticket(i)));
    let mut completions = core::array::from_fn::<_, 3, _>(|_| None);
    // PRODUCTION_PHASE
    completions
}

#[test]
fn polling_parent_does_not_cancel_the_session_childs_granted_quantum() {
    let result = run([0, 8_000_000, 0], [true, true, false]);
    let state = STATE.lock().unwrap().clone();
    assert!(result[0].is_some() && result[1].is_some() && result[2].is_none());
    if cfg!(feature = "cosmic-session") {
        assert!(state.cancelled.is_empty(), "fast peer cancelled the CPU-bound child before its granted deadline");
        assert_eq!(state.now, 8_000_000);
    } else {
        assert_eq!(state.now, 0, "legacy stop-on-first behavior changed");
        assert_eq!(state.cancelled, vec![1]);
    }
}

#[test]
fn all_three_owned_completions_are_collected_exactly_once() {
    let result = run([2_000_000, 0, 5_000_000], [true; 3]);
    let state = STATE.lock().unwrap().clone();
    assert!(result.iter().all(Option::is_some));
    assert_eq!(state.collected, [true; 3]);
    if cfg!(feature = "cosmic-session") {
        assert!(state.cancelled.is_empty());
        assert_eq!(state.now, 5_000_000);
    }
}

#[test]
fn empty_and_single_worker_batches_finish_without_a_peer_drain() {
    assert!(run([0; 3], [false; 3]).iter().all(Option::is_none));
    let result = run([0, 3_000_000, 0], [false, true, false]);
    assert!(result[1].is_some());
    assert!(STATE.lock().unwrap().cancelled.is_empty());
    assert_eq!(now_ns(), 3_000_000);
}

#[test]
fn a_missing_completion_retains_the_timeout_failure() {
    let failed = std::panic::catch_unwind(|| run([0, u64::MAX, 0], [true, true, false]));
    if cfg!(feature = "cosmic-session") {
        assert!(failed.is_err(), "missing worker completion was silently released");
        assert!(!STATE.lock().unwrap().collected[1]);
    } else {
        assert!(failed.is_ok());
    }
}
