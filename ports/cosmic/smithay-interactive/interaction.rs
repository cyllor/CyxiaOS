//! Protocol-independent, bounded interactive geometry and authorization.
use crate::scene::Rect;

/// Accept a committed size without treating an old configure as a new window
/// position. Ordinary repaint after a move must retain the current origin.
/// This profile supports bottom-right resize; top/left anchor changes belong
/// to a separate geometry transaction, not to a buffer commit.
pub(crate) fn apply_committed_size(
    current: Rect,
    negotiated: (i32, i32),
    committed: (i32, i32),
) -> Result<Rect, Denied> {
    if negotiated != committed || committed.0 <= 0 || committed.1 <= 0 {
        return Err(Denied::Geometry);
    }
    Ok(Rect {
        width: committed.0,
        height: committed.1,
        ..current
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Move,
    Resize,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "move",
            Self::Resize => "resize",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    Seat,
    Serial,
    Owner,
    Busy,
    Edge,
    Geometry,
}
impl Denied {
    pub fn name(self) -> &'static str {
        match self {
            Self::Seat => "seat",
            Self::Serial => "serial",
            Self::Owner => "owner",
            Self::Busy => "busy",
            Self::Edge => "edge",
            Self::Geometry => "geometry",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Authority {
    pub same_seat: bool,
    pub requested: u32,
    pub held: Option<u32>,
    pub requester: u32,
    pub owner: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub min_width: i32,
    pub min_height: i32,
    pub max_width: i32,
    pub max_height: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Drag {
    pub id: u32,
    pub serial: u32,
    pub kind: Kind,
    pub initial: Rect,
    pub latest: Rect,
    start: (i32, i32),
    limits: Limits,
}
#[derive(Default)]
pub(crate) struct Interaction {
    active: Option<Drag>,
}
impl Interaction {
    pub fn active(&self) -> Option<Drag> {
        self.active
    }
    pub fn begin(
        &mut self,
        authority: Authority,
        kind: Kind,
        edge: u32,
        rect: Rect,
        pointer: (i32, i32),
        limits: Limits,
    ) -> Result<Drag, Denied> {
        // Owner is tested before Busy so a foreign live serial cannot be hidden
        // behind a generic busy rejection. No error path mutates interaction.
        if !authority.same_seat {
            return Err(Denied::Seat);
        }
        if authority.requested == 0 || authority.held != Some(authority.requested) {
            return Err(Denied::Serial);
        }
        if authority.owner != Some(authority.requester) {
            return Err(Denied::Owner);
        }
        if self.active.is_some() {
            return Err(Denied::Busy);
        }
        if kind == Kind::Resize && edge != 10 {
            return Err(Denied::Edge);
        }
        if rect.width <= 0
            || rect.height <= 0
            || limits.min_width <= 0
            || limits.min_height <= 0
            || limits.max_width < limits.min_width
            || limits.max_height < limits.min_height
        {
            return Err(Denied::Geometry);
        }
        let drag = Drag {
            id: authority.requester,
            serial: authority.requested,
            kind,
            initial: rect,
            latest: rect,
            start: pointer,
            limits,
        };
        self.active = Some(drag);
        Ok(drag)
    }
    pub fn motion(&mut self, pointer: (i32, i32)) -> Result<Drag, Denied> {
        let mut drag = self.active.ok_or(Denied::Serial)?;
        let dx = i64::from(pointer.0) - i64::from(drag.start.0);
        let dy = i64::from(pointer.1) - i64::from(drag.start.1);
        let mut rect = drag.initial;
        match drag.kind {
            Kind::Move => {
                rect.x = i32::try_from(i64::from(rect.x) + dx).map_err(|_| Denied::Geometry)?;
                rect.y = i32::try_from(i64::from(rect.y) + dy).map_err(|_| Denied::Geometry)?;
            }
            Kind::Resize => {
                rect.width = (i64::from(rect.width) + dx).clamp(
                    i64::from(drag.limits.min_width),
                    i64::from(drag.limits.max_width),
                ) as i32;
                rect.height = (i64::from(rect.height) + dy).clamp(
                    i64::from(drag.limits.min_height),
                    i64::from(drag.limits.max_height),
                ) as i32;
            }
        }
        drag.latest = rect;
        self.active = Some(drag);
        Ok(drag)
    }
    pub fn finish(&mut self) -> Option<Drag> {
        self.active.take()
    }
    /// Cancel only this owner; unrelated unmaps cannot cancel another drag.
    /// The caller restores `initial` when the window remains mapped.
    pub fn cancel(&mut self, id: u32) -> Option<Drag> {
        if self.active.is_some_and(|drag| drag.id == id) {
            self.active.take()
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn authority() -> Authority {
        Authority {
            same_seat: true,
            requested: 10,
            held: Some(10),
            requester: 1,
            owner: Some(1),
        }
    }
    fn rect() -> Rect {
        Rect {
            x: 8,
            y: 8,
            width: 64,
            height: 48,
        }
    }
    fn limits() -> Limits {
        Limits {
            min_width: 32,
            min_height: 24,
            max_width: 96,
            max_height: 80,
        }
    }
    #[test]
    fn authority_rejections_are_atomic_and_owner_precedes_busy() {
        let mut state = Interaction::default();
        for (a, error) in [
            (
                Authority {
                    same_seat: false,
                    ..authority()
                },
                Denied::Seat,
            ),
            (
                Authority {
                    requested: 0,
                    ..authority()
                },
                Denied::Serial,
            ),
            (
                Authority {
                    held: None,
                    ..authority()
                },
                Denied::Serial,
            ),
            (
                Authority {
                    requester: 2,
                    ..authority()
                },
                Denied::Owner,
            ),
        ] {
            assert_eq!(
                state.begin(a, Kind::Move, 0, rect(), (16, 16), limits()),
                Err(error)
            );
            assert_eq!(state.active(), None);
        }
        let active = state
            .begin(authority(), Kind::Move, 0, rect(), (16, 16), limits())
            .unwrap();
        assert_eq!(
            state.begin(
                Authority {
                    requester: 2,
                    ..authority()
                },
                Kind::Move,
                0,
                rect(),
                (16, 16),
                limits()
            ),
            Err(Denied::Owner)
        );
        assert_eq!(
            state.begin(authority(), Kind::Move, 0, rect(), (16, 16), limits()),
            Err(Denied::Busy)
        );
        assert_eq!(state.active(), Some(active));
    }
    #[test]
    fn move_deltas_are_from_grab_origin_and_overflow_is_atomic() {
        let mut state = Interaction::default();
        state
            .begin(authority(), Kind::Move, 0, rect(), (16, 16), limits())
            .unwrap();
        assert_eq!(
            state.motion((24, 20)).unwrap().latest,
            Rect {
                x: 16,
                y: 12,
                ..rect()
            }
        );
        assert_eq!(
            state.motion((32, 24)).unwrap().latest,
            Rect {
                x: 24,
                y: 16,
                ..rect()
            }
        );
        let final_drag = state.finish().unwrap();
        assert_eq!(state.active(), None);
        assert_eq!(
            final_drag.latest,
            Rect {
                x: 24,
                y: 16,
                ..rect()
            }
        );
        state
            .begin(
                authority(),
                Kind::Move,
                0,
                Rect {
                    x: i32::MAX,
                    ..rect()
                },
                (0, 0),
                limits(),
            )
            .unwrap();
        let before = state.active();
        assert_eq!(state.motion((1, 0)), Err(Denied::Geometry));
        assert_eq!(state.active(), before);
    }
    #[test]
    fn resize_reversal_uses_original_size_and_clamps_bounds() {
        let mut state = Interaction::default();
        state
            .begin(authority(), Kind::Resize, 10, rect(), (32, 24), limits())
            .unwrap();
        assert_eq!(
            state.motion((40, 28)).unwrap().latest,
            Rect {
                width: 72,
                height: 52,
                ..rect()
            }
        );
        assert_eq!(
            state.motion((36, 32)).unwrap().latest,
            Rect {
                width: 68,
                height: 56,
                ..rect()
            }
        );
        assert_eq!(
            state.motion((i32::MIN, i32::MIN)).unwrap().latest,
            Rect {
                width: 32,
                height: 24,
                ..rect()
            }
        );
        assert_eq!(
            state.motion((i32::MAX, i32::MAX)).unwrap().latest,
            Rect {
                width: 96,
                height: 80,
                ..rect()
            }
        );
    }
    #[test]
    fn cancel_on_removal_or_reset_releases_authority_and_returns_original() {
        let mut state = Interaction::default();
        state
            .begin(authority(), Kind::Resize, 10, rect(), (16, 16), limits())
            .unwrap();
        state.motion((24, 20)).unwrap();
        assert_eq!(state.cancel(2), None);
        assert!(state.active().is_some());
        assert_eq!(state.cancel(1).unwrap().initial, rect());
        assert_eq!(state.active(), None);
        assert_eq!(state.cancel(1), None);
        state
            .begin(authority(), Kind::Move, 0, rect(), (16, 16), limits())
            .unwrap();
        assert!(state.finish().is_some());
        assert_eq!(state.active(), None);
    }
    #[test]
    fn invalid_edge_or_limits_do_not_acquire_grab() {
        let mut state = Interaction::default();
        assert_eq!(
            state.begin(authority(), Kind::Resize, 0, rect(), (16, 16), limits()),
            Err(Denied::Edge)
        );
        assert_eq!(
            state.begin(
                authority(),
                Kind::Resize,
                10,
                rect(),
                (16, 16),
                Limits {
                    min_width: 97,
                    ..limits()
                }
            ),
            Err(Denied::Geometry)
        );
        assert_eq!(state.active(), None);
    }

    #[test]
    fn repaint_after_move_retains_origin_and_resize_accepts_only_negotiated_size() {
        let moved = Rect {
            x: 24,
            y: 16,
            ..rect()
        };
        assert_eq!(apply_committed_size(moved, (64, 48), (64, 48)), Ok(moved));
        assert_eq!(
            apply_committed_size(moved, (72, 52), (72, 52)),
            Ok(Rect {
                width: 72,
                height: 52,
                ..moved
            })
        );
        assert_eq!(
            apply_committed_size(moved, (72, 52), (64, 48)),
            Err(Denied::Geometry)
        );
        assert_eq!(
            apply_committed_size(moved, (0, 48), (0, 48)),
            Err(Denied::Geometry)
        );
        assert_eq!(
            moved,
            Rect {
                x: 24,
                y: 16,
                ..rect()
            }
        );
    }
}
