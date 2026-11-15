// SPDX-License-Identifier: GPL-3.0-only
use std::time::{Duration, Instant};

/// 60 Hz is a pacing policy; ABI v1 does not measure physical refresh.
const FRAME_INTERVAL: Duration = Duration::from_nanos(16_666_667);

#[derive(Debug)]
pub struct RenderSchedule {
    dirty: bool,
    not_before: Instant,
}

impl RenderSchedule {
    pub fn new(now: Instant) -> Self {
        Self {
            dirty: true,
            not_before: now,
        }
    }
    pub fn request(&mut self) {
        self.dirty = true;
    }
    pub fn due(&self, now: Instant, pending: bool) -> bool {
        !pending && self.dirty && now >= self.not_before
    }
    pub fn begin(&mut self) {
        self.dirty = false;
    }
    pub fn completed(&mut self, now: Instant) {
        self.not_before = now + FRAME_INTERVAL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_while_presenting_survives_completion_and_is_paced() {
        let now = Instant::now();
        let mut schedule = RenderSchedule::new(now);
        assert!(schedule.due(now, false));
        schedule.begin();
        schedule.request(); // A new Wayland commit while native scanout is busy.
        assert!(!schedule.due(now + Duration::from_secs(1), true));
        let completed = now + Duration::from_millis(50);
        schedule.completed(completed);
        assert!(!schedule.due(completed, false));
        assert!(schedule.due(completed + FRAME_INTERVAL, false));
    }

    #[test]
    fn completed_clean_frame_does_not_create_a_busy_render_loop() {
        let now = Instant::now();
        let mut schedule = RenderSchedule::new(now);
        schedule.begin();
        schedule.completed(now);
        assert!(!schedule.due(now + Duration::from_secs(10), false));
        schedule.request();
        assert!(schedule.due(now + Duration::from_secs(10), false));
    }
}
