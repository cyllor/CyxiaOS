//! Final Canary clock check after the owner's last fallible legal callback.
//! The root gate keeps the permit immutable across this linearization point.
use cyxia_prototype::{
    domains::WINDOW_NS,
    learning::{Error, governance::CanaryPermit},
    policy::{self, PublicationTime},
};

#[derive(Clone, Copy)]
pub(super) struct PublicationClock {
    pub started: PublicationTime,
    pub deadline_ns: u64,
    pub permit: CanaryPermit,
}
impl PublicationClock {
    pub fn check(self, commit_ns: u64, checked: PublicationTime) -> Result<(), Error> {
        let checked_ns = checked.wall_ns;
        if commit_ns < self.started.wall_ns || checked_ns < commit_ns {
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
        policy::publication_budget(self.started, checked).map_err(|error| match error {
            cyxia_prototype::domains::Error::Budget => Error::Budget,
            _ => Error::Evidence,
        })?;
        Ok(())
    }
}
