#![allow(dead_code)]
#[path="src/backend/cyxia/native.rs"] mod native;
#[path="src/backend/cyxia/delivery.rs"] mod delivery;
use native::InputAction;
use delivery::DeliveredInput;
#[derive(Clone,Copy)] struct InputTime;
impl InputTime { fn now() -> Self { Self } }
enum InputBackendId { Normal }
struct Pointer { focused: bool, grabbed: bool }
impl Pointer {
    fn current_focus(&self) -> Option<()> { self.focused.then_some(()) }
    fn is_grabbed(&self) -> bool { self.grabbed }
}
struct Seat { pointer: Pointer }
impl Seat { fn get_pointer(&self) -> Option<&Pointer> { Some(&self.pointer) } }
struct Shell { seats: Vec<Seat> }
impl Shell { fn read(&self) -> &Self { self } }
struct Common { shell: Shell }
struct Bridge { delivered: DeliveredInput }
impl Bridge {
    fn event(&mut self, action: InputAction, _: InputTime) -> InputAction {
        self.delivered.record(action); action
    }
}
struct Backend { suspended: bool, bridge: Bridge }
impl Backend {
    fn cyxia(&mut self) -> &mut Self { self }
    fn input_suspended(&self) -> bool { self.suspended }
}
struct State { common: Common, backend: Backend, events: Vec<InputAction> }
impl State {
    fn process_input_event(&mut self, event: InputAction, _: InputBackendId) { self.events.push(event); }
}

// PRODUCTION_DISPATCH

fn state() -> State {
    State { common: Common { shell: Shell { seats: vec![Seat { pointer: Pointer { focused:false, grabbed:false } }] } },
            backend: Backend { suspended:false, bridge:Bridge { delivered:DeliveredInput::default() } },
            events:Vec::new() }
}
fn motion(dx: i32, dy: i32) -> InputAction { InputAction::Motion { dx, dy } }

#[test]
fn background_burst_dispatches_once_without_losing_any_delta() {
    let mut s=state();
    dispatch_actions(&mut s,vec![motion(8,0);24]);
    assert_eq!(s.events,[motion(192,0)],"one background burst repeated the expensive COSMIC input path");
}
#[test]
fn negative_and_collinear_diagonal_motion_keep_the_exact_endpoint() {
    for actions in [vec![motion(-4,0);96],vec![motion(2,-3);16]] {
        let mut s=state();let expected=if actions.len()==96 { motion(-384,0) } else { motion(32,-48) };
        dispatch_actions(&mut s,actions);assert_eq!(s.events,[expected]);
    }
}
#[test]
fn focus_grabs_and_held_keys_or_buttons_keep_every_report() {
    for case in 0..4 {
        let mut s=state();
        match case {
            0=>s.common.shell.seats[0].pointer.focused=true,
            1=>s.common.shell.seats[0].pointer.grabbed=true,
            2=>s.backend.bridge.delivered.record(InputAction::Button {code:272,pressed:true}),
            _=>s.backend.bridge.delivered.record(InputAction::Key {code:30,pressed:true}),
        }
        let actions=vec![motion(8,0);24];dispatch_actions(&mut s,actions.clone());assert_eq!(s.events,actions);
    }
}
#[test]
fn mixed_key_and_button_batches_keep_exact_order() {
    for barrier in [InputAction::Key {code:30,pressed:true},InputAction::Button {code:272,pressed:true}] {
        let mut s=state();
        let actions=vec![motion(1,0),motion(1,0),barrier,motion(2,0),motion(2,0)];
        dispatch_actions(&mut s,actions.clone());assert_eq!(s.events,actions);
    }
}
#[test]
fn turns_reversals_and_overflow_remain_separate() {
    for actions in [vec![motion(10,0),motion(-10,0)],vec![motion(10,0),motion(0,10)],
                    vec![motion(i32::MAX,0),motion(1,0)],vec![motion(i32::MIN,0),motion(-1,0)]] {
        let mut s=state();dispatch_actions(&mut s,actions.clone());assert_eq!(s.events,actions);
    }
}
#[test]
fn lock_suspension_does_not_deliver_or_record_any_motion_or_keys() {
    let mut s=state();s.backend.suspended=true;
    dispatch_actions(&mut s,vec![motion(8,0),InputAction::Key {code:30,pressed:true}]);
    assert!(s.events.is_empty());assert!(s.backend.bridge.delivered.releases().unwrap().is_empty());
}
