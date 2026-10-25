//! Invocation-local, bounded collection of released mandatory evaluations.
use cyxia_prototype::domains::{Error, ObjectKey};

pub const FAMILIES: usize = 18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Tasks,
    Services,
    Network,
    Storage,
    Platform,
}
impl Source {
    pub const ALL: [Self; 5] = [
        Self::Tasks,
        Self::Services,
        Self::Network,
        Self::Storage,
        Self::Platform,
    ];

    pub fn for_family(domain: u16, kind: u16) -> Option<Self> {
        match (domain, kind) {
            (1 | 2 | 3 | 5 | 8 | 13, 1) => Some(Self::Tasks),
            (1, 2) | (14 | 15, 1) => Some(Self::Services),
            (10 | 12 | 16, 1) | (16, 2) => Some(Self::Network),
            (4 | 9 | 11, 1) => Some(Self::Storage),
            (6 | 7, 1) => Some(Self::Platform),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub domain: u16,
    pub kind: u16,
    pub ordinal: usize,
}
#[derive(Clone, Copy)]
pub struct Released {
    pub source: Source,
    pub query: Query,
    pub due_ns: u64,
}

pub fn resolve(
    queries: &[Query],
    output: &mut [Option<ObjectKey>],
    mut target: impl FnMut(Query) -> Option<ObjectKey>,
) -> Result<(), Error> {
    if queries.len() > FAMILIES || queries.len() != output.len() {
        return Err(Error::Range);
    }
    for (query, result) in queries.iter().copied().zip(output) {
        *result = target(query).or_else(|| {
            (query.ordinal != 0)
                .then(|| {
                    target(Query {
                        ordinal: 0,
                        ..query
                    })
                })
                .flatten()
        });
    }
    Ok(())
}

pub fn queued_wcet_us(
    active: usize,
    at: u64,
    mut released: impl FnMut(usize) -> Option<Released>,
    mut read: impl FnMut(Source, &[Query], &mut [Option<ObjectKey>]) -> Result<(), Error>,
    mut eligible: impl FnMut(usize, ObjectKey) -> bool,
) -> Result<u64, Error> {
    if active >= FAMILIES {
        return Err(Error::Range);
    }
    let pending: [Option<Released>; FAMILIES] = core::array::from_fn(|index| {
        if index == active {
            None
        } else {
            released(index).filter(|f| f.due_ns <= at)
        }
    });
    let mut targets = [None; FAMILIES];
    for source in Source::ALL {
        let mut queries = [Query::default(); FAMILIES];
        let mut families = [0; FAMILIES];
        let mut count = 0;
        for (index, family) in pending.iter().enumerate() {
            if let Some(family) = family.filter(|f| f.source == source) {
                queries[count] = family.query;
                families[count] = index;
                count += 1;
            }
        }
        if count == 0 {
            continue;
        }
        let mut output = [None; FAMILIES];
        // An unavailable source invalidates the whole estimate. No eligibility
        // callback sees a partial queue, and nothing survives this invocation.
        read(source, &queries[..count], &mut output[..count])?;
        for index in 0..count {
            targets[families[index]] = output[index];
        }
    }
    let mut jobs = 1;
    for (index, target) in targets.into_iter().enumerate() {
        if target.is_some_and(|target| eligible(index, target)) {
            jobs += 1;
        }
    }
    Ok(jobs * 2_500)
}
