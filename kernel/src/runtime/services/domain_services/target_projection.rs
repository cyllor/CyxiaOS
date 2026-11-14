//! Bounded projection of service target identities from one immutable view.
//! No executor or live service-owner operation is permitted in the projection.
use crate::domain_platform::read_snapshot::ReadSnapshot;
use cyxia_prototype::domains::{Error, ObjectKey};

#[derive(Clone, Copy)]
pub struct Query {
    pub domain: u16,
    pub kind: u16,
    pub ordinal: usize,
}
#[derive(Clone, Copy)]
pub struct Targets {
    pub published_ns: u64,
    pub core: Option<ObjectKey>,
    pub services: [Option<ObjectKey>; 2],
    pub console: ObjectKey,
}
impl Targets {
    pub fn get(&self, query: Query) -> Option<ObjectKey> {
        match (query.domain, query.kind) {
            (1, 2) if query.ordinal == 0 => self.core,
            (14, 1) => self.services.get(query.ordinal).copied().flatten(),
            (15, 1) if query.ordinal == 0 => Some(self.console),
            _ => None,
        }
    }
}

pub fn target<T: Copy>(
    snapshot: &ReadSnapshot<T>,
    query: Query,
    clock: impl FnOnce() -> u64,
    project: impl FnOnce(&T) -> Targets,
) -> Option<ObjectKey> {
    targets(snapshot, clock, project).ok()?.get(query)
}

pub fn targets<T: Copy>(
    snapshot: &ReadSnapshot<T>,
    clock: impl FnOnce() -> u64,
    project: impl FnOnce(&T) -> Targets,
) -> Result<Targets, Error> {
    snapshot
        .inspect(|source| {
            let targets = project(source);
            let now = clock();
            if now < targets.published_ns || now - targets.published_ns >= 50_000_000 {
                return Err(Error::Busy);
            }
            Ok(targets)
        })
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
}
