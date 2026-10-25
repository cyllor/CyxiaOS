//! CPU0's bounded heartbeat for secondary workers waiting on budget or deadlines.
//! Delays coalesce into one notification; catching up never floods wake events.
pub struct WakePulse {
    period: u64,
    last: Option<u64>,
}
impl WakePulse {
    pub fn new(period: u64) -> Self {
        assert!(period != 0);
        Self { period, last: None }
    }
    pub fn due(&mut self, now: u64) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_sub(last) < self.period)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}
