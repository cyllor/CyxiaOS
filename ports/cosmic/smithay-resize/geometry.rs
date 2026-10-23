//! Bounded, protocol-independent resize authorization and geometry transactions.
use crate::scene::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Edge {
    Top,
    Bottom,
    Left,
    TopLeft,
    BottomLeft,
    Right,
    TopRight,
    BottomRight,
}
impl Edge {
    pub fn parse(raw: u32) -> Result<Self, Denied> {
        match raw {
            1 => Ok(Self::Top),
            2 => Ok(Self::Bottom),
            4 => Ok(Self::Left),
            5 => Ok(Self::TopLeft),
            6 => Ok(Self::BottomLeft),
            8 => Ok(Self::Right),
            9 => Ok(Self::TopRight),
            10 => Ok(Self::BottomRight),
            _ => Err(Denied::Edge),
        }
    }
    fn left(self) -> bool {
        matches!(self, Self::Left | Self::TopLeft | Self::BottomLeft)
    }
    fn right(self) -> bool {
        matches!(self, Self::Right | Self::TopRight | Self::BottomRight)
    }
    fn top(self) -> bool {
        matches!(self, Self::Top | Self::TopLeft | Self::TopRight)
    }
    fn bottom(self) -> bool {
        matches!(self, Self::Bottom | Self::BottomLeft | Self::BottomRight)
    }
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
    edge: Option<Edge>,
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
        raw_edge: u32,
        rect: Rect,
        pointer: (i32, i32),
        limits: Limits,
    ) -> Result<Drag, Denied> {
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
        let edge = match kind {
            Kind::Move => None,
            Kind::Resize => Some(Edge::parse(raw_edge)?),
        };
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
            edge,
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
                let edge = drag.edge.ok_or(Denied::Edge)?;
                if edge.left() || edge.right() {
                    rect.width = (i64::from(rect.width) + if edge.left() { -dx } else { dx }).clamp(
                        i64::from(drag.limits.min_width),
                        i64::from(drag.limits.max_width),
                    ) as i32;
                }
                if edge.top() || edge.bottom() {
                    rect.height = (i64::from(rect.height) + if edge.top() { -dy } else { dy })
                        .clamp(
                            i64::from(drag.limits.min_height),
                            i64::from(drag.limits.max_height),
                        ) as i32;
                }
                // Clamp the dimensions first, then derive the origin from the
                // fixed opposite edge. This avoids anchor drift at a limit.
                if edge.left() {
                    rect.x = i32::try_from(
                        i64::from(drag.initial.x) + i64::from(drag.initial.width)
                            - i64::from(rect.width),
                    )
                    .map_err(|_| Denied::Geometry)?;
                }
                if edge.top() {
                    rect.y = i32::try_from(
                        i64::from(drag.initial.y) + i64::from(drag.initial.height)
                            - i64::from(rect.height),
                    )
                    .map_err(|_| Denied::Geometry)?;
                }
            }
        }
        drag.latest = rect;
        self.active = Some(drag);
        Ok(drag)
    }
    pub fn finish(&mut self) -> Option<Drag> {
        self.active.take()
    }
    /// Removes only this owner's interaction. The window lifecycle decides
    /// whether to discard it, or negotiate a separate rollback transaction.
    pub fn cancel(&mut self, id: u32) -> Option<Drag> {
        if self.active.is_some_and(|drag| drag.id == id) {
            self.active.take()
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Offered {
    serial: u32,
    rect: Rect,
    anchored: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Applied {
    pub rect: Rect,
    pub serial: Option<u32>,
    pub anchored: bool,
}
/// One configure transaction is pending at a time in this bounded profile.
/// An ACK authorizes a size; only a matching buffer commit consumes its origin.
/// Subsequent ordinary repaints retain the scene's current origin.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct CommitGeometry {
    offered: Option<Offered>,
    acknowledged: Option<Offered>,
    size: Option<(i32, i32)>,
}
impl CommitGeometry {
    pub fn offer(&mut self, serial: u32, rect: Rect, anchored: bool) -> Result<(), Denied> {
        if serial == 0 {
            return Err(Denied::Serial);
        }
        if self.offered.is_some() {
            return Err(Denied::Busy);
        }
        if rect.width <= 0 || rect.height <= 0 {
            return Err(Denied::Geometry);
        }
        self.offered = Some(Offered {
            serial,
            rect,
            anchored,
        });
        Ok(())
    }
    pub fn ack(&mut self, serial: u32) -> Result<(), Denied> {
        let offered = self.offered.ok_or(Denied::Serial)?;
        if offered.serial != serial {
            return Err(Denied::Serial);
        }
        self.size = Some((offered.rect.width, offered.rect.height));
        self.acknowledged = Some(offered);
        self.offered = None;
        Ok(())
    }
    pub fn commit(&mut self, current: Rect, size: (i32, i32)) -> Result<Applied, Denied> {
        if self.offered.is_some() || self.size != Some(size) || size.0 <= 0 || size.1 <= 0 {
            return Err(Denied::Geometry);
        }
        let transaction = self.acknowledged;
        let anchored = transaction.is_some_and(|item| item.anchored);
        let rect = if let Some(item) = transaction.filter(|item| item.anchored) {
            item.rect
        } else {
            Rect {
                width: size.0,
                height: size.1,
                ..current
            }
        };
        self.acknowledged = None;
        Ok(Applied {
            rect,
            serial: transaction.map(|item| item.serial),
            anchored,
        })
    }
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn is_empty(&self) -> bool {
        self.offered.is_none() && self.acknowledged.is_none() && self.size.is_none()
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
            x: 24,
            y: 16,
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
    fn all_eight_edges_keep_the_opposite_anchor() {
        for (edge, expected) in [
            (1, (24, 12, 64, 52)),
            (2, (24, 16, 64, 44)),
            (4, (16, 16, 72, 48)),
            (5, (16, 12, 72, 52)),
            (6, (16, 16, 72, 44)),
            (8, (24, 16, 56, 48)),
            (9, (24, 12, 56, 52)),
            (10, (24, 16, 56, 44)),
        ] {
            let mut state = Interaction::default();
            state
                .begin(authority(), Kind::Resize, edge, rect(), (32, 24), limits())
                .unwrap();
            let actual = state.motion((24, 20)).unwrap().latest;
            assert_eq!(
                (actual.x, actual.y, actual.width, actual.height),
                expected,
                "edge {edge}"
            );
        }
    }
    #[test]
    fn reversing_motion_uses_grab_origin_and_limits_preserve_anchor() {
        let mut state = Interaction::default();
        state
            .begin(authority(), Kind::Resize, 5, rect(), (32, 24), limits())
            .unwrap();
        state.motion((24, 20)).unwrap();
        assert_eq!(
            state.motion((36, 28)).unwrap().latest,
            Rect {
                x: 28,
                y: 20,
                width: 60,
                height: 44
            }
        );
        assert_eq!(
            state.motion((i32::MAX, i32::MAX)).unwrap().latest,
            Rect {
                x: 56,
                y: 40,
                width: 32,
                height: 24
            }
        );
        assert_eq!(
            state.motion((i32::MIN, i32::MIN)).unwrap().latest,
            Rect {
                x: -8,
                y: -16,
                width: 96,
                height: 80
            }
        );
    }
    #[test]
    fn every_edge_clamps_both_extremes_without_moving_orthogonal_axes() {
        for raw in [1, 2, 4, 5, 6, 8, 9, 10] {
            let edge = Edge::parse(raw).unwrap();
            let mut state = Interaction::default();
            state
                .begin(authority(), Kind::Resize, raw, rect(), (0, 0), limits())
                .unwrap();
            for extreme in [i32::MIN, i32::MAX] {
                let current = state.motion((extreme, extreme)).unwrap().latest;
                if edge.left() || edge.right() {
                    assert!(current.width == 32 || current.width == 96);
                    if edge.left() {
                        assert_eq!(current.x + current.width, rect().x + rect().width);
                    } else {
                        assert_eq!(current.x, rect().x);
                    }
                } else {
                    assert_eq!((current.x, current.width), (rect().x, rect().width));
                }
                if edge.top() || edge.bottom() {
                    assert!(current.height == 24 || current.height == 80);
                    if edge.top() {
                        assert_eq!(current.y + current.height, rect().y + rect().height);
                    } else {
                        assert_eq!(current.y, rect().y);
                    }
                } else {
                    assert_eq!((current.y, current.height), (rect().y, rect().height));
                }
            }
        }
    }
    #[test]
    fn overflow_is_atomic_for_both_resize_axes_and_move() {
        for (kind, edge, initial, pointer) in [
            (
                Kind::Resize,
                4,
                Rect {
                    x: i32::MIN,
                    ..rect()
                },
                (-1, 0),
            ),
            (
                Kind::Resize,
                1,
                Rect {
                    y: i32::MIN,
                    ..rect()
                },
                (0, -1),
            ),
            (
                Kind::Move,
                0,
                Rect {
                    x: i32::MAX,
                    ..rect()
                },
                (1, 0),
            ),
        ] {
            let mut state = Interaction::default();
            let before = state
                .begin(authority(), kind, edge, initial, (0, 0), limits())
                .unwrap();
            assert_eq!(state.motion(pointer), Err(Denied::Geometry));
            assert_eq!(state.active(), Some(before));
        }
    }
    #[test]
    fn typed_edges_and_authority_fail_without_mutation() {
        for raw in [0, 3, 7, 11, u32::MAX] {
            assert_eq!(Edge::parse(raw), Err(Denied::Edge));
        }
        let mut state = Interaction::default();
        for (auth, why) in [
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
                state.begin(auth, Kind::Resize, 5, rect(), (0, 0), limits()),
                Err(why)
            );
            assert_eq!(state.active(), None);
        }
        assert_eq!(
            state.begin(authority(), Kind::Resize, 0, rect(), (0, 0), limits()),
            Err(Denied::Edge)
        );
        assert_eq!(
            state.begin(
                authority(),
                Kind::Resize,
                5,
                rect(),
                (0, 0),
                Limits {
                    min_width: 97,
                    ..limits()
                }
            ),
            Err(Denied::Geometry)
        );
        let before = state
            .begin(authority(), Kind::Resize, 5, rect(), (0, 0), limits())
            .unwrap();
        assert_eq!(
            state.begin(
                Authority {
                    requester: 2,
                    ..authority()
                },
                Kind::Resize,
                5,
                rect(),
                (0, 0),
                limits()
            ),
            Err(Denied::Owner)
        );
        assert_eq!(
            state.begin(authority(), Kind::Resize, 5, rect(), (0, 0), limits()),
            Err(Denied::Busy)
        );
        assert_eq!(state.active(), Some(before));
    }
    #[test]
    fn cancellation_is_owner_scoped_and_releases_authority() {
        let mut state = Interaction::default();
        state
            .begin(authority(), Kind::Resize, 4, rect(), (0, 0), limits())
            .unwrap();
        state.motion((-16, 0)).unwrap();
        assert_eq!(state.cancel(2), None);
        assert!(state.active().is_some());
        assert_eq!(state.cancel(1).unwrap().initial, rect());
        assert_eq!(state.cancel(1), None);
        assert_eq!(state.active(), None);
        state
            .begin(authority(), Kind::Resize, 4, rect(), (0, 0), limits())
            .unwrap();
        assert!(state.finish().is_some());
        assert_eq!(state.active(), None);
    }
    #[test]
    fn origin_transaction_requires_ack_and_matching_commit_then_is_consumed_once() {
        let mut state = CommitGeometry::default();
        let target = Rect {
            x: 16,
            y: 12,
            width: 72,
            height: 52,
        };
        state.offer(42, target, true).unwrap();
        assert_eq!(state.commit(rect(), (72, 52)), Err(Denied::Geometry));
        assert_eq!(state.ack(41), Err(Denied::Serial));
        state.ack(42).unwrap();
        assert_eq!(state.commit(rect(), (64, 48)), Err(Denied::Geometry));
        assert_eq!(
            state.commit(rect(), (72, 52)),
            Ok(Applied {
                rect: target,
                serial: Some(42),
                anchored: true
            })
        );
        let moved = Rect {
            x: 40,
            y: 30,
            ..target
        };
        assert_eq!(
            state.commit(moved, (72, 52)),
            Ok(Applied {
                rect: moved,
                serial: None,
                anchored: false
            })
        );
        state.clear();
        assert!(state.is_empty());
        assert_eq!(state.commit(moved, (72, 52)), Err(Denied::Geometry));
    }
    #[test]
    fn activation_ack_keeps_origin_and_new_configure_supersedes_before_repaint() {
        let mut state = CommitGeometry::default();
        assert_eq!(state.offer(0, rect(), false), Err(Denied::Serial));
        assert!(state.is_empty());
        state.offer(40, rect(), false).unwrap();
        assert_eq!(state.offer(41, rect(), true), Err(Denied::Busy));
        state.ack(40).unwrap();
        state.offer(41, rect(), false).unwrap();
        state.ack(41).unwrap();
        let moved = Rect {
            x: 28,
            y: 20,
            ..rect()
        };
        assert_eq!(
            state.commit(moved, (64, 48)),
            Ok(Applied {
                rect: moved,
                serial: Some(41),
                anchored: false
            })
        );
        assert_eq!(state.ack(41), Err(Denied::Serial));
        assert_eq!(
            state.offer(42, Rect { width: 0, ..rect() }, false),
            Err(Denied::Geometry)
        );
    }
}
