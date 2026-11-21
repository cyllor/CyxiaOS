#![allow(dead_code, unused_variables)]

struct PointerMotionEvent {
    location: i32,
    serial: u32,
    time: u32,
}

struct Pointer;
impl Pointer {
    fn motion(&self, state: &mut State, focus: Option<u32>, event: &PointerMotionEvent) {
        state.focus = focus;
        state.location = event.location;
    }
}

struct Position(i32);
impl Position {
    fn as_logical(&self) -> i32 {
        self.0
    }
}

struct Event;
impl Event {
    fn time(&self) -> u32 {
        1
    }
}

#[derive(Default)]
struct State {
    focus: Option<u32>,
    location: i32,
}
impl State {
    fn move_then_click(&mut self, under: Option<u32>, new_under: Option<u32>) -> Option<u32> {
        let ptr = Pointer;
        let position = Position(985);
        let serial = 1;
        let event = Event;
        // PRODUCTION_MOTION
        self.focus
    }
}

#[test]
fn first_click_after_relative_motion_uses_destination_focus() {
    let mut state = State::default();
    assert_eq!(state.move_then_click(Some(1), Some(2)), Some(2));
    assert_eq!(state.location, 985);
    assert_eq!(state.move_then_click(Some(2), None), None);
}
