//! Incomplete paid CPU0 invocation observations, never admission/completion.
//! Caller owns both original PMCC samples. Writers hold only the existing
//! collector gate, with immutable configuration/roster inspection. Contended
//! probes are omitted; no classifier, owner query, capture mutation or clock.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{capture::RunKey, reward::CpuClass},
};
pub const OWNED_BYTES: usize = 1024;
#[derive(Clone, Copy)]
pub struct TaskIdentity {
    /// 2 cleanup, 3 recipe, 4 deferred return; sites5/6 have no task identity.
    pub site: u64,
    pub caller: ObjectKey,
    pub request: u64,
    pub child: ObjectKey,
    pub recipe: u16,
}
/// 0 magic,1 schema2,2 seqlock,3..5 RunKey,6 observations,7 direct-known,
/// 8 unresolved,9 unknown task identity,10 bucket overflow,11 buckets,
/// 12 replaced runs,13 reserved,14 overflow sample present,15 reserved.
/// Four24-word buckets begin16: offered key, direct-known key (zero otherwise),
/// class,core,site,count,first/last original PMCC start ticks,direct-present,
/// identity-present,caller key,request,child key,recipe,then6 reserved words.
/// Final16 words retain first overflow: offered/direct keys,class/core/site,
/// original PMCC start ticks,direct-present,identity-present,caller key,request,
/// child key,recipe. No wall interval,end,result,admission or Capacity claim.
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
        for (i, v) in values.iter().enumerate() {
            self.put(at + i, *v);
        }
    }
}
pub(super) struct Observation {
    pub run: RunKey,
    pub offered: ObjectKey,
    pub direct: Option<ObjectKey>,
    pub class: CpuClass,
    pub core: u16,
    pub started: u64,
    pub site: u64,
    pub identity: Option<TaskIdentity>,
}
/// Last successfully observed run survives seal/retire. A subsequent observed
/// run replaces it explicitly; a run with no observation does not gain evidence.
pub(super) fn observed(e: Observation) {
    // Site1 remains unproved. Ordinary poll supplies no caller/child identity;
    // reject malformed scope before touching the retained observed-run bank.
    if !matches!(e.site, 2..=6) || (e.site == 6 && e.identity.is_some()) {
        return;
    }
    let b = &TRACE_SOURCE_EVIDENCE;
    b.0[2].fetch_add(1, Ordering::AcqRel);
    let run = [e.run.boot_epoch, e.run.trial_id, e.run.generation];
    if [b.get(3), b.get(4), b.get(5)] != run {
        let replaced = b.get(12).saturating_add(u64::from(b.get(0) != 0));
        for i in 3..128 {
            b.put(i, 0);
        }
        b.row(0, &[0x4359_5352_4345_0001, 2]);
        b.row(3, &run);
        b.put(12, replaced);
    }
    b.add(6, 1);
    b.add(if e.direct.is_some() { 7 } else { 8 }, 1);
    if e.identity.is_none() {
        b.add(9, 1);
    }
    let direct = e.direct.unwrap_or(ObjectKey {
        id: 0,
        generation: 0,
    });
    let key = [
        e.offered.id,
        e.offered.generation,
        direct.id,
        direct.generation,
        e.class as u64,
        u64::from(e.core),
        e.site,
    ];
    let identity = e.identity.map_or([0; 6], |i| {
        [
            i.caller.id,
            i.caller.generation,
            i.request,
            i.child.id,
            i.child.generation,
            u64::from(i.recipe),
        ]
    });
    let count = b.get(11) as usize;
    let found = (0..count).find(|i| {
        key.iter()
            .enumerate()
            .all(|(j, v)| b.get(16 + i * 24 + j) == *v)
    });
    let at = if let Some(i) = found {
        16 + i * 24
    } else if count < 4 {
        let at = 16 + count * 24;
        b.row(at, &key);
        b.put(at + 8, e.started);
        b.put(11, count as u64 + 1);
        at
    } else {
        b.add(10, 1);
        if b.get(14) == 0 {
            b.row(112, &key);
            b.row(
                119,
                &[
                    e.started,
                    u64::from(e.direct.is_some()),
                    u64::from(e.identity.is_some()),
                ],
            );
            b.row(122, &identity);
            b.put(14, 1);
        }
        b.0[2].fetch_add(1, Ordering::Release);
        return;
    };
    b.add(at + 7, 1);
    b.row(
        at + 9,
        &[
            e.started,
            u64::from(e.direct.is_some()),
            u64::from(e.identity.is_some()),
        ],
    );
    b.row(at + 12, &identity);
    b.0[2].fetch_add(1, Ordering::Release);
}
#[cfg(test)]
pub(super) fn snapshot() -> [u64; 128] {
    core::array::from_fn(|i| TRACE_SOURCE_EVIDENCE.0[i].load(Ordering::Acquire))
}
