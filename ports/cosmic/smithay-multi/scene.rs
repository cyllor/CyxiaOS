//! Bounded window stacking and focus mechanisms, independent of Wayland,
//! renderer, policy source, and the integration fixture.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl Rect {
    fn contains(self, x: f64, y: f64) -> bool {
        x >= f64::from(self.x)
            && y >= f64::from(self.y)
            && x < f64::from(self.x) + f64::from(self.width)
            && y < f64::from(self.y) + f64::from(self.height)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub id: u32,
    pub rect: Rect,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SceneError {
    Duplicate,
    Full,
    InvalidGeometry,
    UnknownWindow,
}

pub(crate) struct Scene<const N: usize> {
    // Dense bottom-to-top storage makes removal/raise bounded and preserves
    // the order of all unaffected windows without allocation or stale slots.
    windows: [Option<Window>; N],
    len: usize,
    focus: Option<u32>,
}

impl<const N: usize> Scene<N> {
    pub fn new() -> Self {
        Self {
            windows: [None; N],
            len: 0,
            focus: None,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn focus(&self) -> Option<u32> {
        self.focus
    }

    pub fn top_to_bottom(&self) -> impl Iterator<Item = Window> + '_ {
        self.windows[..self.len].iter().rev().flatten().copied()
    }

    pub fn get(&self, id: u32) -> Option<Window> {
        self.top_to_bottom().find(|window| window.id == id)
    }

    /// Update geometry without changing stacking or keyboard focus. Invalid
    /// geometry and unknown identities leave the entire scene unchanged.
    pub fn set_geometry(&mut self, id: u32, rect: Rect) -> Result<(), SceneError> {
        if rect.width <= 0 || rect.height <= 0 {
            return Err(SceneError::InvalidGeometry);
        }
        let window = self.windows[..self.len]
            .iter_mut()
            .flatten()
            .find(|window| window.id == id)
            .ok_or(SceneError::UnknownWindow)?;
        window.rect = rect;
        Ok(())
    }

    pub fn insert(&mut self, window: Window) -> Result<(), SceneError> {
        if window.rect.width <= 0 || window.rect.height <= 0 {
            return Err(SceneError::InvalidGeometry);
        }
        if self.get(window.id).is_some() {
            return Err(SceneError::Duplicate);
        }
        if self.len == N {
            return Err(SceneError::Full);
        }
        self.windows[self.len] = Some(window);
        self.len += 1;
        Ok(())
    }

    pub fn hit_test(&self, x: f64, y: f64) -> Option<Window> {
        if !x.is_finite() || !y.is_finite() {
            return None;
        }
        self.top_to_bottom()
            .find(|window| window.rect.contains(x, y))
    }

    pub fn focus_raise(&mut self, id: u32) -> Result<(), SceneError> {
        let index = self.windows[..self.len]
            .iter()
            .position(|window| window.is_some_and(|window| window.id == id))
            .ok_or(SceneError::UnknownWindow)?;
        let window = self.windows[index];
        self.windows[index..self.len].rotate_left(1);
        self.windows[self.len - 1] = window;
        self.focus = Some(id);
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Result<(), SceneError> {
        let index = self.windows[..self.len]
            .iter()
            .position(|window| window.is_some_and(|window| window.id == id))
            .ok_or(SceneError::UnknownWindow)?;
        self.windows[index..self.len].rotate_left(1);
        self.len -= 1;
        self.windows[self.len] = None;
        if self.focus == Some(id) {
            let fallback = self.top_to_bottom().next().map(|window| window.id);
            self.focus = fallback;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn window(id: u32, x: i32, y: i32) -> Window {
        Window {
            id,
            rect: Rect {
                x,
                y,
                width: 64,
                height: 48,
            },
        }
    }

    #[test]
    fn overlap_follows_stack_and_half_open_edges() {
        let mut scene = Scene::<4>::new();
        scene.insert(window(10, 8, 8)).unwrap();
        scene.insert(window(20, 40, 24)).unwrap();
        assert_eq!(scene.hit_test(48.0, 32.0).unwrap().id, 20);
        assert_eq!(scene.hit_test(16.0, 16.0).unwrap().id, 10);
        scene.focus_raise(10).unwrap();
        assert_eq!(scene.hit_test(56.0, 40.0).unwrap().id, 10);
        assert_eq!(scene.hit_test(72.0, 40.0).unwrap().id, 20);
        assert_eq!(scene.hit_test(104.0, 40.0), None);
        assert_eq!(scene.hit_test(48.0, 72.0), None);
        assert_eq!(scene.hit_test(f64::NAN, 0.0), None);
        assert_eq!(scene.hit_test(0.0, f64::INFINITY), None);
    }

    #[test]
    fn removal_preserves_order_and_only_focused_removal_falls_back() {
        let mut scene = Scene::<4>::new();
        for id in 1..=4 {
            scene.insert(window(id, 0, 0)).unwrap();
        }
        scene.focus_raise(2).unwrap();
        scene.remove(3).unwrap();
        assert_eq!(scene.focus(), Some(2));
        assert_eq!(
            scene.top_to_bottom().map(|w| w.id).collect::<Vec<_>>(),
            [2, 4, 1]
        );
        scene.remove(2).unwrap();
        assert_eq!(scene.focus(), Some(4));
        scene.remove(4).unwrap();
        assert_eq!(scene.focus(), Some(1));
        scene.remove(1).unwrap();
        assert_eq!(scene.focus(), None);
        assert_eq!(scene.len(), 0);
        scene.insert(window(5, 0, 0)).unwrap();
        assert_eq!(scene.top_to_bottom().next().unwrap().id, 5);
    }

    #[test]
    fn rejected_operations_leave_scene_unchanged() {
        let mut scene = Scene::<1>::new();
        let mut invalid = window(1, 0, 0);
        invalid.rect.width = 0;
        assert_eq!(scene.insert(invalid), Err(SceneError::InvalidGeometry));
        scene.insert(window(1, i32::MAX, i32::MAX)).unwrap();
        assert_eq!(scene.insert(window(1, 0, 0)), Err(SceneError::Duplicate));
        assert_eq!(scene.insert(window(2, 0, 0)), Err(SceneError::Full));
        assert_eq!(scene.remove(2), Err(SceneError::UnknownWindow));
        assert_eq!(scene.focus_raise(2), Err(SceneError::UnknownWindow));
        assert_eq!(scene.len(), 1);
        assert_eq!(scene.focus(), None);
        // Right edges are computed without overflowing signed coordinates.
        assert_eq!(
            scene.hit_test(f64::from(i32::MAX) + 2.0, f64::from(i32::MAX)),
            scene.get(1)
        );
    }

    #[test]
    fn zero_capacity_and_repeated_raise_are_well_defined() {
        assert_eq!(
            Scene::<0>::new().insert(window(1, 0, 0)),
            Err(SceneError::Full)
        );
        let mut scene = Scene::<2>::new();
        scene.insert(window(1, 0, 0)).unwrap();
        scene.insert(window(2, 0, 0)).unwrap();
        for _ in 0..4 {
            scene.focus_raise(1).unwrap();
        }
        assert_eq!(
            scene.top_to_bottom().map(|w| w.id).collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn geometry_update_preserves_order_focus_and_is_atomic_on_error() {
        let mut scene = Scene::<2>::new();
        scene.insert(window(1, 8, 8)).unwrap();
        scene.insert(window(2, 40, 24)).unwrap();
        scene.focus_raise(1).unwrap();
        let resized = Rect {
            x: 24,
            y: 16,
            width: 68,
            height: 56,
        };
        scene.set_geometry(1, resized).unwrap();
        assert_eq!(scene.get(1).unwrap().rect, resized);
        assert_eq!(scene.focus(), Some(1));
        assert_eq!(
            scene.top_to_bottom().map(|w| w.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(scene.hit_test(91.0, 71.0).unwrap().id, 1);
        assert_eq!(scene.hit_test(92.0, 71.0).unwrap().id, 2);
        assert_eq!(
            scene.set_geometry(
                1,
                Rect {
                    width: 0,
                    ..resized
                }
            ),
            Err(SceneError::InvalidGeometry)
        );
        assert_eq!(
            scene.set_geometry(3, resized),
            Err(SceneError::UnknownWindow)
        );
        assert_eq!(scene.get(1).unwrap().rect, resized);
        assert_eq!(scene.focus(), Some(1));
    }
}
