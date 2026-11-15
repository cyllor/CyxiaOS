// SPDX-License-Identifier: GPL-3.0-only
//! Cyxia evdev records enter the normal COSMIC focus/shortcut/input pipeline.
use smithay::backend::input::{
    ButtonState, Device, DeviceCapability, Event, InputBackend, InputEvent, InputTime, KeyState,
    KeyboardKeyEvent, Keycode, PointerButtonEvent, PointerMotionEvent, UnusedEvent,
};
use std::path::PathBuf;

use super::{delivery::DeliveredInput, native::InputAction};

#[derive(Debug)]
pub struct CyxiaInput;

/// ABI v1 exposes one ordered keyboard and relative-pointer queue.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CyxiaDevice;

impl Device for CyxiaDevice {
    fn id(&self) -> String {
        "cyxia-abi-1".into()
    }
    fn name(&self) -> String {
        "Cyxia native keyboard and pointer".into()
    }
    fn has_capability(&self, capability: DeviceCapability) -> bool {
        matches!(
            capability,
            DeviceCapability::Keyboard | DeviceCapability::Pointer
        )
    }
    fn usb_id(&self) -> Option<(u32, u32)> {
        None
    }
    fn syspath(&self) -> Option<PathBuf> {
        None
    }
}

#[derive(Debug)]
pub struct KeyEvent {
    time: InputTime,
    code: u16,
    pressed: bool,
    count: u32,
}
#[derive(Debug)]
pub struct ButtonEvent {
    time: InputTime,
    code: u16,
    pressed: bool,
}
#[derive(Debug)]
pub struct MotionEvent {
    time: InputTime,
    dx: i32,
    dy: i32,
}

macro_rules! event {
    ($ty:ty) => {
        impl Event<CyxiaInput> for $ty {
            fn time(&self) -> InputTime {
                self.time
            }
            fn device(&self) -> CyxiaDevice {
                CyxiaDevice
            }
        }
    };
}
event!(KeyEvent);
event!(ButtonEvent);
event!(MotionEvent);

impl KeyboardKeyEvent<CyxiaInput> for KeyEvent {
    fn key_code(&self) -> Keycode {
        (u32::from(self.code) + 8).into()
    }
    fn state(&self) -> KeyState {
        if self.pressed {
            KeyState::Pressed
        } else {
            KeyState::Released
        }
    }
    fn count(&self) -> u32 {
        self.count
    }
}
impl PointerButtonEvent<CyxiaInput> for ButtonEvent {
    fn button_code(&self) -> u32 {
        self.code.into()
    }
    fn state(&self) -> ButtonState {
        if self.pressed {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        }
    }
}
impl PointerMotionEvent<CyxiaInput> for MotionEvent {
    fn delta_x(&self) -> f64 {
        self.dx.into()
    }
    fn delta_y(&self) -> f64 {
        self.dy.into()
    }
    fn delta_x_unaccel(&self) -> f64 {
        self.dx.into()
    }
    fn delta_y_unaccel(&self) -> f64 {
        self.dy.into()
    }
}

impl InputBackend for CyxiaInput {
    type Device = CyxiaDevice;
    type KeyboardKeyEvent = KeyEvent;
    type PointerButtonEvent = ButtonEvent;
    type PointerMotionEvent = MotionEvent;
    type PointerAxisEvent = UnusedEvent;
    type PointerMotionAbsoluteEvent = UnusedEvent;
    type GestureSwipeBeginEvent = UnusedEvent;
    type GestureSwipeUpdateEvent = UnusedEvent;
    type GestureSwipeEndEvent = UnusedEvent;
    type GesturePinchBeginEvent = UnusedEvent;
    type GesturePinchUpdateEvent = UnusedEvent;
    type GesturePinchEndEvent = UnusedEvent;
    type GestureHoldBeginEvent = UnusedEvent;
    type GestureHoldEndEvent = UnusedEvent;
    type TouchDownEvent = UnusedEvent;
    type TouchUpEvent = UnusedEvent;
    type TouchMotionEvent = UnusedEvent;
    type TouchCancelEvent = UnusedEvent;
    type TouchFrameEvent = UnusedEvent;
    type TabletToolAxisEvent = UnusedEvent;
    type TabletToolProximityEvent = UnusedEvent;
    type TabletToolTipEvent = UnusedEvent;
    type TabletToolButtonEvent = UnusedEvent;
    type SwitchToggleEvent = UnusedEvent;
    type SpecialEvent = UnusedEvent;
}

/// Decoder actions are already de-duplicated, including authoritative resync.
#[derive(Debug, Default)]
pub struct InputBridge {
    pub delivered: DeliveredInput,
}

impl InputBridge {
    pub fn event(&mut self, action: InputAction, time: InputTime) -> InputEvent<CyxiaInput> {
        self.delivered.record(action);
        match action {
            InputAction::Key { code, pressed } => InputEvent::Keyboard {
                event: KeyEvent {
                    time,
                    code,
                    pressed,
                    count: self.delivered.key_count(),
                },
            },
            InputAction::Button { code, pressed } => InputEvent::PointerButton {
                event: ButtonEvent {
                    time,
                    code,
                    pressed,
                },
            },
            InputAction::Motion { dx, dy } => InputEvent::PointerMotion {
                event: MotionEvent { time, dx, dy },
            },
            InputAction::Resync => unreachable!("resync must query the native held-key bitmap"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keycode_offset_counts_and_release_are_preserved() {
        let mut bridge = InputBridge::default();
        for (code, pressed, count) in [(30, true, 1), (42, true, 2), (30, false, 1), (42, false, 0)]
        {
            let InputEvent::Keyboard { event } = bridge.event(
                InputAction::Key { code, pressed },
                InputTime::from_micros(101),
            ) else {
                panic!()
            };
            assert_eq!(u32::from(event.key_code()), u32::from(code) + 8);
            assert_eq!(event.count(), count);
            assert_eq!(event.time().micros(), 101);
            assert_eq!(
                event.state(),
                if pressed {
                    KeyState::Pressed
                } else {
                    KeyState::Released
                }
            );
        }
    }

    #[test]
    fn pointer_uses_evdev_buttons_and_relative_deltas() {
        let mut bridge = InputBridge::default();
        let time = InputTime::from_millis(5);
        let InputEvent::PointerButton { event } = bridge.event(
            InputAction::Button {
                code: 272,
                pressed: true,
            },
            time,
        ) else {
            panic!()
        };
        assert_eq!(event.button_code(), 272);
        assert_eq!(event.state(), ButtonState::Pressed);
        let InputEvent::PointerMotion { event } =
            bridge.event(InputAction::Motion { dx: -7, dy: 13 }, time)
        else {
            panic!()
        };
        assert_eq!((event.delta_x(), event.delta_y()), (-7.0, 13.0));
        assert_eq!(event.delta(), event.delta_unaccel());
        assert!(!CyxiaDevice.has_capability(DeviceCapability::Touch));
    }
}
