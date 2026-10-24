use cyxia_kernel_core::control_plane::{
    Error, Plane,
    dispatch::{Gate, MAX_GENERATION, Token},
};
fn token(n: u64, plane: Plane) -> Token {
    Token {
        generation: n,
        plane,
    }
}
#[test]
fn close_does_not_forget_in_flight_and_stale_role_cannot_dispatch() {
    let gate = Gate::new();
    let t = token(1, Plane::Business);
    gate.open(t).unwrap();
    let running = gate.try_enter(t).unwrap();
    gate.close(t).unwrap();
    assert!(!gate.quiescent());
    assert!(matches!(gate.try_enter(t), Err(Error::NotReady)));
    assert_eq!(gate.open(token(2, Plane::Control)), Err(Error::Busy));
    drop(running);
    assert!(gate.quiescent());
    gate.open(token(2, Plane::Control)).unwrap();
    assert!(matches!(gate.try_enter(t), Err(Error::Stale)));
    assert_eq!(gate.close(t), Err(Error::Stale));
}
#[test]
fn generation_never_reused_and_a_gate_has_one_runner() {
    let gate = Gate::new();
    let t = token(1, Plane::Control);
    assert!(matches!(gate.try_enter(t), Err(Error::Stale)));
    gate.open(t).unwrap();
    let p = gate.try_enter(t).unwrap();
    assert!(matches!(gate.try_enter(t), Err(Error::Busy)));
    drop(p);
    gate.close(t).unwrap();
    assert_eq!(gate.open(t), Err(Error::Stale));
    assert_eq!(gate.open(token(0, Plane::Business)), Err(Error::Invalid));
    assert_eq!(
        gate.open(token(MAX_GENERATION + 1, Plane::Business)),
        Err(Error::Invalid)
    );
    gate.open(token(MAX_GENERATION, Plane::Business)).unwrap();
    gate.close(token(MAX_GENERATION, Plane::Business)).unwrap();
    assert_eq!(gate.open(t), Err(Error::Stale));
}
#[test]
fn concurrent_close_and_return_preserve_exactly_one_fence() {
    for _ in 0..2000 {
        let gate = Gate::new();
        let t = token(1, Plane::Business);
        gate.open(t).unwrap();
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Ok(p) = gate.try_enter(t) {
                    std::thread::yield_now();
                    drop(p);
                }
            });
            loop {
                match gate.close(t) {
                    Ok(()) => break,
                    Err(Error::Busy) => std::thread::yield_now(),
                    result => panic!("unexpected close result: {result:?}"),
                }
            }
        });
        assert!(gate.quiescent());
        assert!(!gate.view().enabled);
        assert!(matches!(gate.try_enter(t), Err(Error::NotReady)));
    }
}
