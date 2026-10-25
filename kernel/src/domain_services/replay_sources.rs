//! Identity facts from the real CPU0 service owner. CPU cost classification
//! must not depend on the sampling age of unrelated policy features.
use super::{READY, replay};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::reward::CpuClass,
};

// CPU0 is the sole writer, inside the live service gate. Atomic fields avoid
// borrowing that owner from a measured segment or from another CPU.
static VERSION: AtomicU64 = AtomicU64::new(0);
static FIELDS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
pub(super) const IDENTITY_BYTES: usize = core::mem::size_of::<AtomicU64>() * 9;

pub(super) fn publish(console: ObjectKey, services: [Option<(ObjectKey, u16)>; 2]) {
    let mut values = [0; 8];
    values[0] = console.id;
    values[1] = console.generation;
    for (index, item) in services.into_iter().enumerate() {
        if let Some((key, recipe)) = item {
            let at = 2 + index * 3;
            values[at] = key.id;
            values[at + 1] = key.generation;
            values[at + 2] = u64::from(recipe);
        }
    }
    let version = VERSION.load(Ordering::SeqCst);
    if version & 1 != 0 {
        return;
    }
    if version != 0
        && FIELDS
            .iter()
            .zip(values)
            .all(|(field, value)| field.load(Ordering::SeqCst) == value)
    {
        return;
    }
    let Some(next) = version.checked_add(2) else {
        // Never reuse a publication identity after wraparound.
        VERSION.store(u64::MAX, Ordering::SeqCst);
        return;
    };
    VERSION.store(version + 1, Ordering::SeqCst);
    for (field, value) in FIELDS.iter().zip(values) {
        field.store(value, Ordering::SeqCst);
    }
    VERSION.store(next, Ordering::SeqCst);
}

fn snapshot() -> Result<[u64; 8], Error> {
    let first = VERSION.load(Ordering::SeqCst);
    if first == 0 {
        return Err(Error::NotReady);
    }
    if first & 1 != 0 {
        return Err(Error::Busy);
    }
    let values = core::array::from_fn(|i| FIELDS[i].load(Ordering::SeqCst));
    if VERSION.load(Ordering::SeqCst) != first {
        return Err(Error::Busy);
    }
    Ok(values)
}

pub(super) fn outside_source(key: ObjectKey, class: CpuClass) -> Result<bool, Error> {
    if key.id == 0
        || key.generation == 0
        || !matches!(class, CpuClass::ExecutorWork | CpuClass::ExecutorAction)
    {
        return Ok(false);
    }
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let values = snapshot()?;
    Ok(match class {
        CpuClass::ExecutorWork => (key.id, key.generation) == (values[0], values[1]),
        CpuClass::ExecutorAction => (0..2).any(|index| {
            let at = 2 + index * 3;
            (key.id, key.generation) == (values[at], values[at + 1])
                && values[at + 2] != 0
                && !replay::owns(values[at + 2] as u16)
        }),
        _ => false,
    })
}

const _: () = assert!(IDENTITY_BYTES == 72);
