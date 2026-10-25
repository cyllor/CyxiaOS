//! Final Canary clock check after the owner's last fallible legal callback.
//! The root gate keeps the permit immutable across this linearization point.
use cyxia_prototype::{
    domains::WINDOW_NS,
    learning::{Error, governance::CanaryPermit},
    policy::PUBLICATION_BUDGET_NS,
};

#[derive(Clone, Copy)]
pub(super) struct PublicationClock {
    pub started_ns: u64,
    pub deadline_ns: u64,
    pub permit: CanaryPermit,
}
impl PublicationClock {
    pub fn check(self, commit_ns: u64, checked_ns: u64) -> Result<(), Error> {
        if commit_ns < self.started_ns || checked_ns < commit_ns {
            return Err(Error::Deadline);
        }
        if checked_ns > self.deadline_ns
            || commit_ns < self.permit.start_ns
            || checked_ns < self.permit.start_ns
            || checked_ns >= self.permit.expires_ns
            || checked_ns / WINDOW_NS != commit_ns / WINDOW_NS
        {
            return Err(Error::Deadline);
        }
        if checked_ns - self.started_ns > PUBLICATION_BUDGET_NS {
            return Err(Error::Budget);
        }
        Ok(())
    }
}
