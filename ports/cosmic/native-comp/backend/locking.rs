// SPDX-License-Identifier: GPL-3.0-only
//! Session-lock ownership cannot advance past native scanout completion.
use super::native::{DisplayInfo, presentation::PendingPresentation};
use std::io;

#[derive(Clone, Copy, Debug)]
pub(crate) enum PendingInput {
    DeviceLifecycle,
    Release,
    Other,
}

/// Releases reconcile pre-lock holds without opening the isolation barrier.
/// New presses, movement and gestures remain blocked until black is complete.
pub(crate) fn input_allowed(shielded: bool, input: PendingInput) -> bool {
    !shielded || matches!(input, PendingInput::DeviceLifecycle | PendingInput::Release)
}

/// A live client does not imply that its lock protocol resource still exists.
pub(crate) fn owner_is_live(resource_alive: bool, client_exists: bool) -> bool {
    resource_alive && client_exists
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LockFocusTarget {
    Clear,
    LockSurface {
        alive: bool,
        current_owner: bool,
        registered: bool,
    },
    Layer {
        show_on_lock: bool,
    },
    Popup {
        root_show_on_lock: bool,
    },
    Other,
}

/// Applied at focus writes and before installing a popup keyboard grab. The
/// provisional Shell barrier counts as locked even before public acknowledgment.
pub(crate) fn lock_focus_allowed(locked: bool, target: LockFocusTarget) -> bool {
    if !locked {
        return true;
    }
    match target {
        LockFocusTarget::Clear => true,
        LockFocusTarget::LockSurface {
            alive,
            current_owner,
            registered,
        } => alive && current_owner && registered,
        LockFocusTarget::Layer { show_on_lock } => show_on_lock,
        LockFocusTarget::Popup { root_show_on_lock } => root_show_on_lock,
        LockFocusTarget::Other => false,
    }
}

pub struct LockBarrier<T> {
    pending: Option<(T, PendingPresentation)>,
    shielded: bool,
}

impl<T> Default for LockBarrier<T> {
    fn default() -> Self {
        Self {
            pending: None,
            shielded: false,
        }
    }
}

impl<T> LockBarrier<T> {
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn shielded(&self) -> bool {
        self.shielded
    }
    pub fn owner(&self) -> Option<&T> {
        self.pending.as_ref().map(|(owner, _)| owner)
    }
    pub fn cancel(&mut self) {
        self.pending.take();
        self.shielded = true;
    }

    /// Rejected owners are dropped, which refuses a real SessionLocker.
    /// The old normal cursor is canceled before any black tile can be queued.
    pub fn begin(
        &mut self,
        owner: T,
        info: DisplayInfo,
        cancel_normal: impl FnOnce(),
    ) -> io::Result<bool> {
        if self.pending() {
            return Ok(false);
        }
        self.shielded = true;
        cancel_normal();
        let cursor = PendingPresentation::new(info, false)?;
        self.pending = Some((owner, cursor));
        Ok(true)
    }

    pub fn advance(
        &mut self,
        budget: usize,
        valid: impl FnOnce(&T) -> bool,
    ) -> io::Result<Option<T>> {
        self.advance_with(|cursor| cursor.advance_black(budget), valid)
    }

    fn advance_with(
        &mut self,
        advance: impl FnOnce(&mut PendingPresentation) -> io::Result<bool>,
        valid: impl FnOnce(&T) -> bool,
    ) -> io::Result<Option<T>> {
        let Some((_, cursor)) = self.pending.as_mut() else {
            return Ok(None);
        };
        match advance(cursor) {
            Ok(false) => Ok(None),
            Ok(true) => {
                let (owner, _) = self.pending.take().unwrap();
                if valid(&owner) {
                    self.shielded = false;
                    Ok(Some(owner))
                } else {
                    // Finish black even if its client died, but never acknowledge
                    // a dead owner or re-enable an unlocked normal render.
                    self.shielded = true;
                    Ok(None)
                }
            }
            Err(err) => {
                self.pending.take(); // Refuse/drop owner, never return it for acknowledgment.
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    struct Owner(Rc<Cell<usize>>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    fn info() -> DisplayInfo {
        DisplayInfo {
            width: 6,
            height: 3,
            stride_bytes: 24,
            format: 1,
            max_rect_bytes: 16,
            abi: 1,
        }
    }

    #[test]
    fn pending_input_releases_preserve_isolation_and_do_not_complete_the_lock() {
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(input_allowed(barrier.shielded(), PendingInput::Release));
        assert!(input_allowed(
            barrier.shielded(),
            PendingInput::DeviceLifecycle
        ));
        assert!(!input_allowed(barrier.shielded(), PendingInput::Other));
        assert!(barrier.pending());
        assert!(barrier.shielded());
        assert_eq!(dropped.get(), 0);
        for input in [
            PendingInput::Release,
            PendingInput::DeviceLifecycle,
            PendingInput::Other,
        ] {
            assert!(input_allowed(false, input));
        }
    }

    #[test]
    fn destroyed_lock_with_connected_client_can_be_replaced_without_stale_ack() {
        assert!(!owner_is_live(false, true));
        assert!(!owner_is_live(true, false));
        assert!(owner_is_live(true, true));
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(1, |_, _| Ok(0)),
                    |_| true
                )
                .unwrap()
                .is_none()
        );
        // The Wayland client remains connected after destroying its lock.
        if !owner_is_live(false, true) {
            barrier.cancel();
        }
        assert_eq!(dropped.get(), 1);
        assert!(barrier.shielded());
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(1, |_, _| Ok(0)),
                    |_| true
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(dropped.get(), 1);
        let replacement = barrier
            .advance_with(
                |cursor| cursor.advance_black_with(16, |_, _| Ok(0)),
                |_| owner_is_live(true, true),
            )
            .unwrap();
        assert!(replacement.is_some());
        drop(replacement);
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    fn pending_lock_rejects_layer_commit_and_popup_grab_focus_bypasses() {
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier.begin(Owner(dropped), info(), || {}).unwrap();
        for target in [
            LockFocusTarget::Layer {
                show_on_lock: false,
            },
            LockFocusTarget::Popup {
                root_show_on_lock: false,
            },
            LockFocusTarget::Other,
        ] {
            // The shell barrier exists immediately, not only after locked ACK.
            assert!(!lock_focus_allowed(barrier.shielded(), target));
            assert!(lock_focus_allowed(false, target));
        }
        assert!(barrier.pending());
        assert!(lock_focus_allowed(true, LockFocusTarget::Clear));
        assert!(lock_focus_allowed(
            true,
            LockFocusTarget::Layer { show_on_lock: true }
        ));
        assert!(lock_focus_allowed(
            true,
            LockFocusTarget::Popup {
                root_show_on_lock: true
            }
        ));
    }

    #[test]
    fn early_lock_surface_focus_requires_live_current_registered_owner() {
        for (alive, current_owner, registered) in [
            (true, true, true),
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert_eq!(
                lock_focus_allowed(
                    true,
                    LockFocusTarget::LockSurface {
                        alive,
                        current_owner,
                        registered,
                    }
                ),
                alive && current_owner && registered
            );
        }
    }

    #[test]
    fn partial_unlocked_frame_is_canceled_and_busy_black_cannot_acknowledge() {
        let dropped = Rc::new(Cell::new(0));
        let mut normal = Some(PendingPresentation::new(info(), false).unwrap());
        // A real old cursor already submitted a partial frame.
        assert!(
            !normal
                .as_mut()
                .unwrap()
                .advance_black_with(1, |_, _| Ok(0))
                .unwrap()
        );
        let mut barrier = LockBarrier::default();
        assert!(
            barrier
                .begin(Owner(dropped.clone()), info(), || {
                    normal.take();
                })
                .unwrap()
        );
        assert!(normal.is_none());
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(16, |_, bytes| {
                        assert!(bytes.iter().all(|byte| *byte == 0));
                        Err(io::ErrorKind::WouldBlock.into())
                    }),
                    |_| true
                )
                .unwrap()
                .is_none()
        );
        assert!(barrier.pending());
        assert_eq!(dropped.get(), 0);
        for index in 0..5 {
            let owner = barrier
                .advance_with(
                    |cursor| {
                        cursor.advance_black_with(1, |_, bytes| {
                            assert!(bytes.iter().all(|byte| *byte == 0));
                            Ok(0)
                        })
                    },
                    |_| true,
                )
                .unwrap();
            assert_eq!(owner.is_some(), index == 4);
        }
        assert!(!barrier.pending());
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn fatal_submission_refuses_owner_without_acknowledgment() {
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(1, |_, _| Ok(0)),
                    |_| true
                )
                .unwrap()
                .is_none()
        );
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor
                        .advance_black_with(1, |_, _| Err(io::Error::from_raw_os_error(19))),
                    |_| true
                )
                .is_err()
        );
        assert!(!barrier.pending());
        assert!(barrier.shielded());
        assert_eq!(dropped.get(), 1);
        assert!(
            barrier
                .advance_with(|_| panic!("failed blank resumed"), |_| true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn duplicate_request_is_refused_without_restarting_the_active_blank() {
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            !barrier
                .begin(Owner(dropped.clone()), info(), || panic!(
                    "duplicate canceled active cursor"
                ))
                .unwrap()
        );
        assert_eq!(dropped.get(), 1);
        assert!(barrier.pending());
        drop(barrier);
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    fn dead_owner_finishes_black_without_ack_and_replacement_owns_new_completion() {
        let dropped = Rc::new(Cell::new(0));
        let mut barrier = LockBarrier::default();
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(16, |_, _| Ok(0)),
                    |_| false
                )
                .unwrap()
                .is_none()
        );
        assert!(barrier.shielded());
        assert!(!barrier.pending());
        assert_eq!(dropped.get(), 1);
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        assert!(
            barrier
                .advance_with(
                    |cursor| cursor.advance_black_with(1, |_, _| Ok(0)),
                    |_| true
                )
                .unwrap()
                .is_none()
        );
        barrier.cancel(); // A dead pending owner is replaced before final tile.
        assert!(barrier.shielded());
        assert_eq!(dropped.get(), 2);
        barrier
            .begin(Owner(dropped.clone()), info(), || {})
            .unwrap();
        let replacement = barrier
            .advance_with(
                |cursor| cursor.advance_black_with(16, |_, _| Ok(0)),
                |_| true,
            )
            .unwrap();
        assert!(replacement.is_some());
        assert!(!barrier.shielded());
        drop(replacement);
        assert_eq!(dropped.get(), 3);
    }
}
