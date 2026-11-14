//! Admission for new replay renewals. Existing issued obligations are not inputs
//! to this gate and cannot be changed by closing the observation window.
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{Family, capture::RunKey, reward::OBSERVATION_NS},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub run: RunKey,
    pub family: Family,
    pub target: ObjectKey,
    pub first_ns: u64,
    pub observation_ns: u64,
}

#[derive(Clone, Copy)]
pub(super) struct Window {
    observation: Option<Observation>,
    end_ns: u64,
}
impl Window {
    pub const fn new() -> Self {
        Self {
            observation: None,
            end_ns: 0,
        }
    }
    /// The caller must hold Root's synchronous activation authority and match
    /// this exact actual FrozenScope against its token/request/first snapshot.
    pub fn bind(&mut self, observation: Observation) -> Result<(), Error> {
        if observation.run.boot_epoch == 0
            || observation.run.trial_id == 0
            || observation.run.generation == 0
            || observation.family.index().is_err()
            || observation.target.id == 0
            || observation.target.generation == 0
            || observation.observation_ns < observation.first_ns
        {
            return Err(Error::Stale);
        }
        if let Some(old) = self.observation {
            return if old == observation {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let end = observation
            .observation_ns
            .checked_add(OBSERVATION_NS)
            .ok_or(Error::Overflow)?;
        self.observation = Some(observation);
        self.end_ns = end;
        Ok(())
    }
    /// `at` is the caller's existing generation/selection/commit clock.
    /// First publication can establish its scope; a renewal requires a bound
    /// scope and may not enter at or after its exact half-open window end.
    pub fn allows_new(&self, issued: bool, at: u64) -> bool {
        !issued || self.observation.is_some() && at < self.end_ns
    }
}
