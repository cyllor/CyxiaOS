//! Diagnostic source attribution, never CPU evidence or execution authority.
//! Writers hold the existing collector gate. No owner query, allocation, clock
//! read or independent lock occurs here. Four buckets are a bounded sample:
//! overflow and absent caller identity are explicit, never complete coverage.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{capture::RunKey, reward::CpuClass},
};

pub const OWNED_BYTES: usize = 1024;
#[derive(Clone, Copy)]
pub struct TaskIdentity {
    /// 1 construction, 2 cleanup, 3 recipe, 4 deferred return.
    pub site: u64,
    pub caller: ObjectKey,
    pub request: u64,
    pub child: ObjectKey,
    pub recipe: u16,
}
/// 0 magic, 1 schema, 2 seqlock; 3..5 full RunKey; 6 record calls,
/// 7 accepted, 8 Capacity, 9 other error, 10 bucket overflow, 11 bucket count,
/// 12 replaced runs, 13 absent task identity, 14 overflow sample tag (0 absent,
/// 1 first overflow, 2 first overflowing Capacity), 15 reserved. Four24-word
/// rows start at16. Row0..5 is original owner/resolved source/class/core;
/// 6 calls, 7 raw duration, 8..9 first interval, 10..11 sampled interval,
/// 12 result (1 success,0x100+learning error+1 otherwise),13 identity presence,
/// 14 site,15..20 caller/request/child/recipe,21..22 first Capacity interval,
/// 23 Capacity count. Words112..127 retain the overflow sample: original and
/// resolved keys, class|(core<<16), original first/last, result, identity-present,
/// site, caller key, request, child key, recipe. Buckets key full owner and
/// source generations, class/core/site; caller changes replace only the latest
/// complete sample. No request-only join or cross-caller identity is inferred.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 128]);
#[used]
#[unsafe(no_mangle)]
pub static TRACE_SOURCE_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 128]);
const _: () = assert!(core::mem::size_of::<Evidence>() == OWNED_BYTES);
impl Evidence {
    fn get(&self, at: usize) -> u64 {
        self.0[at].load(Ordering::Relaxed)
    }
    fn put(&self, at: usize, value: u64) {
        self.0[at].store(value, Ordering::Relaxed);
    }
    fn add(&self, at: usize, value: u64) {
        self.put(at, self.get(at).saturating_add(value));
    }
    fn row(&self, at: usize, values: &[u64]) {
        for (i, value) in values.iter().enumerate() {
            self.put(at + i, *value);
        }
    }
}
pub(super) struct Completion {
    pub run: RunKey,
    pub owner: ObjectKey,
    pub source: ObjectKey,
    pub class: CpuClass,
    pub core: u16,
    pub first: u64,
    pub last: u64,
    pub result: Result<(), super::Error>,
    pub identity: Option<TaskIdentity>,
}
/// The last recorded run survives seal/retirement; the next run's first actual
/// record replaces it and increments word12. Original interval collection and
/// its seal remain authoritative. Each definitive record call is counted once;
/// temporary collector/classifier/peer replies do not manufacture records.
pub(super) fn completed(e: Completion) {
    let b = &TRACE_SOURCE_EVIDENCE;
    b.0[2].fetch_add(1, Ordering::AcqRel);
    let run = [e.run.boot_epoch, e.run.trial_id, e.run.generation];
    if [b.get(3), b.get(4), b.get(5)] != run {
        let replaced = b.get(12).saturating_add(u64::from(b.get(0) != 0));
        for i in 3..128 {
            b.put(i, 0);
        }
        b.row(0, &[0x4359_5352_4345_0001, 1]);
        b.row(3, &run);
        b.put(12, replaced);
    }
    let capacity = e.result
        == Err(super::Error::Capture(
            cyxia_prototype::learning::Error::Capacity,
        ));
    b.add(6, 1);
    b.add(
        if e.result.is_ok() {
            7
        } else if capacity {
            8
        } else {
            9
        },
        1,
    );
    if e.identity.is_none() {
        b.add(13, 1);
    }
    let key = [
        e.owner.id,
        e.owner.generation,
        e.source.id,
        e.source.generation,
        e.class as u64,
        u64::from(e.core),
    ];
    let site = e.identity.map_or(0, |i| i.site);
    let result = match e.result {
        Ok(()) => 1,
        Err(super::Error::Capture(error)) => 0x100 + (error as u64 + 1),
        Err(_) => 2,
    };
    let count = b.get(11) as usize;
    let found = (0..count).find(|i| {
        let at = 16 + i * 24;
        key.iter().enumerate().all(|(j, v)| b.get(at + j) == *v) && b.get(at + 14) == site
    });
    let at = if let Some(i) = found {
        16 + i * 24
    } else if count < 4 {
        let at = 16 + count * 24;
        b.row(at, &key);
        b.row(at + 8, &[e.first, e.last]);
        b.put(at + 14, site);
        b.put(11, count as u64 + 1);
        at
    } else {
        b.add(10, 1);
        if b.get(14) == 0 || capacity && b.get(14) != 2 {
            b.row(
                112,
                &[
                    e.owner.id,
                    e.owner.generation,
                    e.source.id,
                    e.source.generation,
                    e.class as u64 | (u64::from(e.core) << 16),
                    e.first,
                    e.last,
                    result,
                    u64::from(e.identity.is_some()),
                ],
            );
            let context = e.identity.map_or([0; 7], |i| {
                [
                    i.site,
                    i.caller.id,
                    i.caller.generation,
                    i.request,
                    i.child.id,
                    i.child.generation,
                    u64::from(i.recipe),
                ]
            });
            b.row(121, &context);
            b.put(14, if capacity { 2 } else { 1 });
        }
        b.0[2].fetch_add(1, Ordering::Release);
        return;
    };
    b.add(at + 6, 1);
    b.add(at + 7, e.last - e.first);
    // Freeze the first Capacity-producing sample, including its exact task
    // identity. Counts still advance; no later caller may replace that sample.
    if b.get(at + 23) == 0 {
        b.row(at + 10, &[e.first, e.last]);
        b.put(at + 12, result);
        b.put(at + 13, u64::from(e.identity.is_some()));
        if let Some(i) = e.identity {
            b.row(
                at + 15,
                &[
                    i.caller.id,
                    i.caller.generation,
                    i.request,
                    i.child.id,
                    i.child.generation,
                    u64::from(i.recipe),
                ],
            );
        } else {
            b.row(at + 15, &[0; 6]);
        }
    }
    if capacity {
        if b.get(at + 23) == 0 {
            b.row(at + 21, &[e.first, e.last]);
        }
        b.add(at + 23, 1);
    }
    b.0[2].fetch_add(1, Ordering::Release);
}
#[cfg(test)]
pub(super) fn snapshot() -> [u64; 128] {
    core::array::from_fn(|i| TRACE_SOURCE_EVIDENCE.0[i].load(Ordering::Acquire))
}
