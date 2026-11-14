//! Invocation-local, bounded collection of released mandatory evaluations.
use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS};

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
    pub fallback: bool,
}
impl Query {
    pub const fn exact(domain: u16, kind: u16, ordinal: usize) -> Self {
        Self {
            domain,
            kind,
            ordinal,
            fallback: false,
        }
    }

    pub const fn fallback(domain: u16, kind: u16, ordinal: usize) -> Self {
        Self {
            domain,
            kind,
            ordinal,
            fallback: true,
        }
    }
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
            (query.fallback && query.ordinal != 0)
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

/// Advance exactly the one successfully visited mandatory family. An EMPTY
/// result is still a visit; unrelated due families keep their own next turn.
pub fn complete_visit(
    index: usize,
    at: u64,
    ordinal: usize,
    lookahead_present: bool,
    due: &mut [u64; FAMILIES],
    family_cursor: &mut usize,
    cursor: &mut [usize; FAMILIES],
) -> Result<(), Error> {
    if index >= FAMILIES {
        return Err(Error::Range);
    }
    due[index] = at.saturating_add(if index == 1 || index == 16 {
        1_000_000_000
    } else {
        WINDOW_NS
    });
    *family_cursor = (index + 1) % FAMILIES;
    cursor[index] = if lookahead_present { ordinal + 1 } else { 0 };
    Ok(())
}

/// Deterministic remaining mandatory-control WCET for the current evaluation.
///
/// Every released action-family slot is itself a required control job, even when
/// its object walk later records EMPTY or discovers that current hard constraints
/// admit no candidate. Counting only targets that can be projected up front both
/// under-counts those mandatory visits and makes one evaluation synchronously read
/// every owner publication. The estimate is a scoring input only; real admission,
/// owner generations and the 70 ms control ceiling are revalidated separately.
pub fn queued_wcet_us(
    active: usize,
    at: u64,
    mut due_ns: impl FnMut(usize) -> Option<u64>,
) -> Result<u64, Error> {
    if active >= FAMILIES {
        return Err(Error::Range);
    }
    let mut jobs = 1u64;
    for index in 0..FAMILIES {
        if index != active && due_ns(index).is_some_and(|due| due <= at) {
            jobs = jobs.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    jobs.checked_mul(2_500).ok_or(Error::Overflow)
}
