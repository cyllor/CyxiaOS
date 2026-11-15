// SPDX-License-Identifier: GPL-3.0-only
//! Track transitions actually forwarded to COSMIC, independently of decoding.
//! A later read/resync failure can discard a decoded batch; cleanup must still
//! release everything the compositor received, not the decoder's newer state.
use super::native::InputAction;
use std::io;

#[derive(Debug)]
pub struct DeliveredInput {
    held: [u8; 96],
}

impl Default for DeliveredInput {
    fn default() -> Self {
        Self { held: [0; 96] }
    }
}

impl DeliveredInput {
    pub fn record(&mut self, action: InputAction) {
        if let InputAction::Key { code, pressed } | InputAction::Button { code, pressed } = action {
            let byte = &mut self.held[usize::from(code) / 8];
            let mask = 1 << (code % 8);
            if pressed {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
    }

    pub fn key_count(&self) -> u32 {
        self.held[..31].iter().map(|byte| byte.count_ones()).sum()
    }

    pub fn releases(&self) -> io::Result<Vec<InputAction>> {
        let mut actions = Vec::new();
        actions.try_reserve_exact(251).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "native delivered input cleanup")
        })?;
        for code in (0u16..248).chain(272..=274) {
            if self.held[usize::from(code) / 8] & (1 << (code % 8)) != 0 {
                actions.push(if code < 248 {
                    InputAction::Key {
                        code,
                        pressed: false,
                    }
                } else {
                    InputAction::Button {
                        code,
                        pressed: false,
                    }
                });
            }
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::super::native::{InputDecoder, InputEvent};
    use super::*;

    fn packet(decoder: &mut InputDecoder, pressed: bool) -> Vec<InputAction> {
        for code in [30, 272] {
            decoder
                .push(InputEvent {
                    kind: 1,
                    code,
                    value: i32::from(pressed),
                })
                .unwrap();
        }
        decoder
            .push(InputEvent {
                kind: 0,
                code: 0,
                value: 0,
            })
            .unwrap()
            .unwrap()
    }

    #[test]
    fn discarded_decoded_release_cannot_hide_delivered_holds_at_shutdown() {
        let mut decoder = InputDecoder::new();
        let mut delivered = DeliveredInput::default();
        for action in packet(&mut decoder, true) {
            delivered.record(action);
        }
        // poll_input can decode these releases then encounter an I/O error in
        // its next read. The entire undelivered Vec is discarded on that path.
        drop(packet(&mut decoder, false));
        assert!(decoder.resynchronize([0; 96]).unwrap().is_empty());
        assert_eq!(
            delivered.releases().unwrap(),
            vec![
                InputAction::Key {
                    code: 30,
                    pressed: false
                },
                InputAction::Button {
                    code: 272,
                    pressed: false
                },
            ]
        );
    }

    #[test]
    fn decoded_but_undelivered_press_does_not_invent_a_cleanup_release() {
        let mut decoder = InputDecoder::new();
        let delivered = DeliveredInput::default();
        drop(packet(&mut decoder, true));
        assert!(!decoder.resynchronize([0; 96]).unwrap().is_empty());
        assert!(delivered.releases().unwrap().is_empty());
    }

    #[test]
    fn delivered_releases_clear_keyboard_count_and_buttons_exactly_once() {
        let mut delivered = DeliveredInput::default();
        for action in [
            InputAction::Key {
                code: 42,
                pressed: true,
            },
            InputAction::Button {
                code: 274,
                pressed: true,
            },
        ] {
            delivered.record(action);
            delivered.record(action); // duplicate delivery cannot inflate count
        }
        assert_eq!(delivered.key_count(), 1);
        for action in delivered.releases().unwrap() {
            delivered.record(action);
        }
        assert_eq!(delivered.key_count(), 0);
        assert!(delivered.releases().unwrap().is_empty());
    }
}
