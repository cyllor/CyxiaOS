//! Protected caller for actual EL0, IPC and service-vector replay work.
//! The caller's generation is retired only after every child and grant drains.
use super::*;
use core::sync::atomic::AtomicUsize;
use cyxia_prototype::learning::{Family, capture::RunKey};
pub const CALLER_ID: u64 = 0x5245_504c_4341;
const LIMIT: usize = 256;
#[derive(Clone, Copy)]
pub struct Image {
    pub target: ObjectKey,
    pub digest: [u8; 32],
}
struct Replay {
    serial: u64,
    actor: ObjectKey,
    family: Family,
    seed: u64,
    run: Option<RunKey>,
    closed: bool,
    prepared: bool,
    endpoint: ObjectKey,
    file: ObjectKey,
    file_cap: u64,
    task: ObjectKey,
    task_cap: u64,
    vector: Option<SubmitVector>,
    vector_id: u64,
    lease: VectorLease,
    local_spawn: u64,
    delivered: [Option<Result<u64, Error>>; LIMIT],
    expected: [u64; LIMIT],
    deadlines: [u64; LIMIT],
}
static mut REPLAY: Replay = Replay {
    serial: 0,
    actor: ZERO,
    family: Family { domain: 0, kind: 0 },
    seed: 0,
    run: None,
    closed: true,
    prepared: false,
    endpoint: ZERO,
    file: ZERO,
    file_cap: 0,
    task: ZERO,
    task_cap: 0,
    vector: None,
    vector_id: 0,
    lease: VectorLease::EMPTY,
    local_spawn: 0,
    delivered: [None; LIMIT],
    expected: [0; LIMIT],
    deadlines: [0; LIMIT],
};
// The mapping is published only from Creator's actual successful construction
// under the task gate. Cleanup cannot erase it before the final credit returns.
static MEMBERS: [[AtomicU64; 5]; TASKS] = [const { [const { AtomicU64::new(0) }; 5] }; TASKS];
static KNOWN: [[AtomicU64; 4]; TASKS] = [const { [const { AtomicU64::new(0) }; 4] }; TASKS];
static SERVICE_LIVE: AtomicBool = AtomicBool::new(false);
static mut PACKAGE_DIGEST: Option<[u8; 32]> = None;
fn package_digest_locked() -> [u8; 32] {
    // The kernel's embedded ELF is immutable. This cache is protected by the
    // task gate and initialized from its actual bytes, never supplied by a caller.
    unsafe {
        let digest = &mut *core::ptr::addr_of_mut!(PACKAGE_DIGEST);
        *digest.get_or_insert_with(|| Sha256::digest(ELF).into())
    }
}
static WORK_DEPTH: AtomicUsize = AtomicUsize::new(0);
struct WorkGuard;
impl Drop for WorkGuard {
    fn drop(&mut self) {
        WORK_DEPTH.fetch_sub(1, Ordering::Release);
    }
}
/// A synchronous replay submission is already charged to the caller's actual
/// CPU0 segment. Deferred admission and cleanup have their own later segment.
pub fn within_work<R>(body: impl FnOnce() -> R) -> R {
    debug_assert_eq!(cpu::slot(), 0);
    WORK_DEPTH.fetch_add(1, Ordering::Acquire);
    let _guard = WorkGuard;
    body()
}
pub(super) fn work_measured() -> bool {
    cpu::slot() == 0 && WORK_DEPTH.load(Ordering::Acquire) != 0
}
pub(super) fn service_admitted() {
    SERVICE_LIVE.store(true, Ordering::Release);
}
fn state() -> &'static mut Replay {
    unsafe { &mut *core::ptr::addr_of_mut!(REPLAY) }
}
fn owner() -> Result<(), Error> {
    if cpu::slot() == 0 {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}
fn index(id: u64) -> Result<usize, Error> {
    usize::try_from(id)
        .ok()
        .filter(|i| *i > 0 && *i < LIMIT)
        .ok_or(Error::Range)
}
pub fn payload_digest(seed: u64, id: u64) -> [u8; 32] {
    Sha256::digest(payload(seed, id).0).into()
}
fn payload(seed: u64, id: u64) -> ([u8; 64], u64) {
    let mut bytes = [0; 64];
    let mut sum = 0;
    for (i, b) in bytes.chunks_exact_mut(8).enumerate() {
        let value = (seed.rotate_left(i as u32) ^ id.wrapping_mul(17) ^ i as u64) & 0xffff;
        sum += value;
        b.copy_from_slice(&value.to_le_bytes());
    }
    (bytes, sum)
}
pub fn prepare(family: Family, seed: u64, file: ObjectKey) -> Result<Image, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if r.prepared {
            if r.family != family || r.seed != seed || r.file != file {
                return Err(Error::Conflict);
            }
        } else {
            if r.run.is_some()
                || s.tasks
                    .iter()
                    .any(|t| t.life != Life::Free && t.parent.id == CALLER_ID)
                || s.launches
                    .iter()
                    .any(|l| l.request.is_some_and(|v| v.caller.id == CALLER_ID))
            {
                return Err(Error::Busy);
            }
            if r.actor == ZERO {
                r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
                r.actor = ObjectKey {
                    id: CALLER_ID,
                    generation: r.serial,
                };
                r.family = family;
                r.seed = seed;
                r.file = file;
                r.closed = false;
                r.delivered.fill(None);
                r.expected.fill(0);
                r.deadlines.fill(0);
                r.local_spawn = 0;
            } else if r.family != family || r.seed != seed || r.file != file {
                return Err(Error::Conflict);
            }
            if family.domain == 5 && r.endpoint == ZERO {
                r.endpoint = s.ipc.open(r.actor, false)?;
            }
            if family.domain == 8 {
                if r.file_cap == 0 {
                    r.file_cap =
                        s.services
                            .grant(r.actor, file, FILE_SERVICE, FILE_STAT_BY_CAP as u8)?;
                }
            }
            r.prepared = true;
        }
        let target = match (family.domain, family.kind) {
            (1, 1) | (2, 1) => group(12),
            (13, 1) => group(16),
            (3, 1) => MEMORY_KEY,
            (5, 1) => r.endpoint,
            (8, 1) => SERVICE_KEY,
            (1, 2) => ZERO,
            _ => ZERO,
        };
        if family.domain == 5 && {
            let v = s.ipc.stats(r.endpoint)?;
            v.depth != 0 || v.reserved != 0
        } {
            return Err(Error::Busy);
        }
        let mut h = Sha256::new();
        h.update(b"CYXIA_EMPTY_TASK_WORKING_SET_1.3\0");
        h.update(package_digest_locked());
        h.update(seed.to_le_bytes());
        h.update(family.domain.to_le_bytes());
        h.update(family.kind.to_le_bytes());
        h.update(b"no-owned-child;no-launch;no-vector;no-grants\0");
        Ok(Image {
            target,
            digest: h.finalize().into(),
        })
    })
}
pub fn activate(run: RunKey) -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if !r.prepared || r.closed || r.run.is_some_and(|old| old != run) {
            return Err(Error::Stale);
        }
        r.run = Some(run);
        if matches!(
            (r.family.domain, r.family.kind),
            (13, 1) | (14, 1) | (16, 2)
        ) {
            let t = s
                .tasks
                .iter()
                .find(|t| t.recipe == 2 && t.life != Life::Free)
                .ok_or(Error::NotReady)?;
            member_created(t.key, t.parent, t.spawn_id, t.recipe, t.optional)?;
        }
        Ok(())
    })
}
pub(super) fn authorize_request(
    request: &SpawnRequest,
    input: &[u8],
    cpu: u16,
    deadline: u64,
    recipe: u16,
) -> Result<(), Error> {
    let r = state();
    let i = index(request.request_id)?;
    let expected_group = crate::learning_workload::background::FOREGROUND;
    if !r.prepared
        || r.closed
        || r.run.is_none()
        || request.caller != r.actor
        || request.group != expected_group
        || request.package != PACKAGE
        || request.recovery
        || recipe != 0
        || cpu != 3
        || r.deadlines[i] != deadline
        || payload(r.seed, request.request_id).0 != input
    {
        return Err(Error::Auth);
    }
    Ok(())
}
pub fn claim_local(run: RunKey, spawn_id: u64) -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if r.run != Some(run)
            || r.closed
            || r.family
                != (Family {
                    domain: 16,
                    kind: 2,
                })
            || spawn_id == 0
        {
            return Err(Error::Auth);
        }
        if r.local_spawn != 0 {
            return if r.local_spawn == spawn_id {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        // Existing ordinary local tasks can never be relabelled into a new
        // replay generation. The network owner claims before real admission.
        if s.admission.query(CLUSTER_CALLER, spawn_id).is_ok() {
            return Err(Error::Stale);
        }
        r.local_spawn = spawn_id;
        Ok(())
    })
}
pub(super) fn work_source(parent: ObjectKey, spawn_id: u64, recipe: u16) -> Option<ObjectKey> {
    let r = state();
    (r.run.is_some()
        && (parent == r.actor
            || parent == CLUSTER_CALLER && spawn_id != 0 && spawn_id == r.local_spawn
            || recipe == 2 && crate::domain_services::replay::owns(2)))
    .then_some(crate::learning_workload::TASK_OWNER)
}
pub(super) fn member_created(
    key: ObjectKey,
    parent: ObjectKey,
    spawn_id: u64,
    recipe: u16,
    optional: bool,
) -> Result<(), Error> {
    let slot = key
        .id
        .checked_sub(0x1000)
        .filter(|i| *i < TASKS as u64)
        .ok_or(Error::Stale)? as usize;
    let known = &KNOWN[slot];
    known[0].store(0, Ordering::Release);
    known[1].store(parent.id, Ordering::Relaxed);
    known[2].store(parent.generation, Ordering::Relaxed);
    known[3].store(
        (u64::from(recipe) << 1) | u64::from(optional),
        Ordering::Relaxed,
    );
    known[0].store(key.generation, Ordering::Release);
    let echo = recipe == 2 && crate::domain_services::replay::owns(2);
    let r = state();
    let local = parent == CLUSTER_CALLER && spawn_id != 0 && spawn_id == r.local_spawn;
    if parent.id != CALLER_ID && !echo && !local {
        return Ok(());
    }
    if echo && r.run.is_none() {
        return Ok(());
    }
    let run = r.run.ok_or(Error::NotReady)?;
    if r.closed
        || (echo
            && !matches!(
                (r.family.domain, r.family.kind),
                (13, 1) | (14, 1) | (16, 2)
            ))
        || (!echo && !local && parent != r.actor)
    {
        return Err(Error::Auth);
    }
    let m = &MEMBERS[slot];
    m[0].store(0, Ordering::Release);
    m[1].store(parent.generation, Ordering::Relaxed);
    m[2].store(run.boot_epoch, Ordering::Relaxed);
    m[3].store(run.trial_id, Ordering::Relaxed);
    m[4].store(run.generation, Ordering::Relaxed);
    m[0].store(key.generation, Ordering::Release);
    Ok(())
}
pub(super) fn member_retired(key: ObjectKey) {
    if let Some(slot) = key.id.checked_sub(0x1000).filter(|i| *i < TASKS as u64) {
        let _ = KNOWN[slot as usize][0].compare_exchange(
            key.generation,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}
pub fn source_for(
    run: RunKey,
    key: ObjectKey,
) -> Result<Option<ObjectKey>, cyxia_prototype::learning::Error> {
    let Some(slot) = key.id.checked_sub(0x1000).filter(|i| *i < TASKS as u64) else {
        return Ok(None);
    };
    let m = &MEMBERS[slot as usize];
    let generation = m[0].load(Ordering::Acquire);
    if generation != key.generation {
        return Ok(None);
    }
    if m[1].load(Ordering::Relaxed) == 0
        || m[2].load(Ordering::Relaxed) != run.boot_epoch
        || m[3].load(Ordering::Relaxed) != run.trial_id
        || m[4].load(Ordering::Relaxed) != run.generation
        || m[0].load(Ordering::Acquire) != generation
    {
        return Err(cyxia_prototype::learning::Error::Stale);
    }
    Ok(Some(crate::learning_workload::TASK_OWNER))
}
pub fn spawn(id: u64, deadline: u64) -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let (actor, target, bytes) = {
            let r = state();
            let i = index(id)?;
            if r.closed || r.run.is_none() {
                return Err(Error::Auth);
            }
            if r.deadlines[i] != 0 && r.deadlines[i] != deadline {
                return Err(Error::Conflict);
            }
            let (bytes, sum) = payload(r.seed, id);
            r.deadlines[i] = deadline;
            r.expected[i] = sum;
            (
                r.actor,
                crate::learning_workload::background::FOREGROUND,
                bytes,
            )
        };
        execution::submit_locked(s, actor, id, target, &bytes, 3, deadline, false, 0)?;
        Ok(())
    })
}
pub fn spawn_result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        let i = index(id)?;
        if let Some(result) = r.delivered[i] {
            return Ok(Some(result));
        }
        let result = match s.admission.query(r.actor, id)? {
            SpawnState::Queued | SpawnState::Unknown => None,
            SpawnState::Cancelled => Some(Err(Error::Expired)),
            SpawnState::Failed(e) => Some(Err(e)),
            SpawnState::Created(key) => {
                if let Some(at) = s
                    .exits
                    .iter()
                    .position(|v| v.is_some_and(|v| v.key == key && v.parent == r.actor))
                {
                    let exit = s.exits[at].ok_or(Error::Stale)?;
                    if exit.code != 0 && exit.code != 110
                        || exit.code == 0 && exit.value != r.expected[i]
                    {
                        return Err(Error::Io);
                    }
                    s.exits[at] = None;
                    Some(if exit.code == 110 {
                        Err(Error::Expired)
                    } else {
                        Ok(exit.finished_ns)
                    })
                } else {
                    None
                }
            }
        };
        if result.is_some() {
            r.delivered[i] = result;
        }
        Ok(result)
    })
}
pub fn vector(id: u64, deadline: u64) -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let r = state();
        let i = index(id)?;
        if r.closed || r.run.is_none() || r.family.domain != 8 {
            return Err(Error::Auth);
        }
        if r.delivered[i].is_some() || (r.vector.is_some() && r.vector_id == id) {
            return Ok(());
        }
        if r.vector.is_some() {
            return Err(Error::Busy);
        }
        let items = core::array::from_fn::<_, 16, _>(|j| ServiceItem {
            op: FILE_STAT_BY_CAP,
            flags: 0,
            cap: r.file_cap,
            object_gen: r.file.generation,
            tag: id * 32 + j as u64,
        });
        r.vector = Some(s.services.submit(r.actor, &items, deadline, now_ns())?);
        r.vector_id = id;
        r.lease = VectorLease {
            needed: 3,
            deadline,
            ..VectorLease::EMPTY
        };
        r.deadlines[i] = deadline;
        Ok(())
    })
}
fn release_lease(s: &mut State, lease: &mut VectorLease) -> Result<(), Error> {
    for grant in &mut lease.grants {
        if let Some(g) = *grant {
            match s.ipc.cancel_send(g) {
                Ok(()) | Err(Error::Stale) => (),
                Err(e) => return Err(e),
            };
            *grant = None;
        }
    }
    *lease = VectorLease::EMPTY;
    Ok(())
}
pub fn vector_result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        let i = index(id)?;
        if let Some(result) = r.delivered[i] {
            return Ok(Some(result));
        }
        if r.vector_id != id {
            return Err(Error::Stale);
        }
        if !r.lease.ready && now_ns() < r.lease.deadline {
            for j in 0..2 {
                let (service, endpoint) = if j == 0 {
                    (TASK_SERVICE, s.task_endpoint)
                } else {
                    (FILE_SERVICE, s.file_endpoint)
                };
                let mut authority = abi::ServiceAuthority { service, endpoint };
                if r.lease.grants[j].is_none() {
                    let request = s.service_sequence.checked_add(1).ok_or(Error::Overflow)?;
                    s.service_sequence = request;
                    r.lease.grants[j] = Some(s.ipc.reserve_send(
                        service,
                        endpoint,
                        request,
                        now_ns(),
                        &mut authority,
                    )?);
                    r.lease.requests[j] = request;
                }
                s.ipc.validate_confirmed_send_grant(
                    r.lease.grants[j].ok_or(Error::NotReady)?,
                    service,
                    endpoint,
                    &mut authority,
                )?;
            }
            r.lease.ready = true;
        }
        let vector = r.vector.as_mut().ok_or(Error::NotFound)?;
        let mut transport = abi::Transport {
            tasks: &s.tasks,
            validate: s.validate_file,
            stat: s.stat_file,
            ipc: &mut s.ipc,
            task_endpoint: s.task_endpoint,
            file_endpoint: s.file_endpoint,
            sequence: &mut s.service_sequence,
            lease: &mut r.lease,
        };
        s.services.step(vector, now_ns(), &mut transport)?;
        if !vector.complete() {
            return Ok(None);
        }
        let mut result = Ok(now_ns());
        for (j, item) in vector.results().iter().enumerate() {
            if item.tag != id * 32 + j as u64 {
                return Err(Error::Conflict);
            }
            match item.status {
                ItemStatus::Value(value) if value == crate::domain_storage::replay::FILE_BYTES => {
                    ()
                }
                ItemStatus::TimedOut => result = Err(Error::Expired),
                ItemStatus::Error(e) => result = Err(e),
                _ => return Err(Error::Io),
            }
        }
        release_lease(s, &mut r.lease)?;
        r.vector = None;
        r.delivered[i] = Some(result);
        Ok(Some(result))
    })
}

struct Delivery<'a> {
    actor: ObjectKey,
    endpoint: ObjectKey,
    seed: u64,
    output: &'a mut [Option<Result<u64, Error>>; LIMIT],
}
impl IpcBackend<IPC_BYTES> for Delivery<'_> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        _: IpcOperation,
    ) -> Result<(), Error> {
        if actor == self.actor && endpoint == self.endpoint {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)
    }
    fn deliver(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<IPC_BYTES>,
    ) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)?;
        let i = index(message.request_id)?;
        if message.sender != self.actor
            || message.len != 64
            || message.bytes[..64] != payload(self.seed, message.request_id).0
            || self.output[i].is_some()
        {
            return Err(Error::Conflict);
        }
        self.output[i] = Some(Ok(now_ns()));
        Ok(())
    }
}
pub fn ipc(id: u64, deadline: u64) -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let r = state();
        let i = index(id)?;
        if r.closed || r.run.is_none() || r.family.domain != 5 {
            return Err(Error::Auth);
        }
        if r.deadlines[i] != 0 {
            return if r.deadlines[i] == deadline {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let mut backend = Delivery {
            actor: r.actor,
            endpoint: r.endpoint,
            seed: r.seed,
            output: &mut r.delivered,
        };
        s.ipc.send(
            r.actor,
            r.endpoint,
            id,
            &payload(r.seed, id).0,
            now_ns(),
            &mut backend,
        )?;
        r.deadlines[i] = deadline;
        Ok(())
    })
}
pub fn ipc_result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        let i = index(id)?;
        if r.delivered[i].is_none() {
            let mut backend = Delivery {
                actor: r.actor,
                endpoint: r.endpoint,
                seed: r.seed,
                output: &mut r.delivered,
            };
            s.ipc
                .receive_batch(r.actor, r.endpoint, now_ns(), &mut backend)?;
        }
        Ok(r.delivered[i])
    })
}
fn drained_locked(s: &State, r: &Replay) -> Result<bool, Error> {
    if s.tasks
        .iter()
        .any(|t| t.life != Life::Free && t.parent == r.actor)
        || s.launches
            .iter()
            .any(|l| l.request.is_some_and(|v| v.caller == r.actor))
        || s.exits.iter().flatten().any(|v| v.parent == r.actor)
        || r.vector.is_some()
        || r.local_spawn != 0
            && (s.tasks.iter().any(|t| {
                t.life != Life::Free && t.parent == CLUSTER_CALLER && t.spawn_id == r.local_spawn
            }) || s.launches.iter().any(|l| {
                l.request
                    .is_some_and(|v| v.caller == CLUSTER_CALLER && v.request_id == r.local_spawn)
            }))
    {
        return Ok(false);
    }
    if r.endpoint != ZERO {
        let stats = s.ipc.stats(r.endpoint)?;
        if stats.depth != 0 || stats.reserved != 0 {
            return Ok(false);
        }
    }
    Ok(r.lease.grants.iter().all(Option::is_none))
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if r.run != Some(run) {
            return Err(Error::Stale);
        }
        r.closed = true;
        drained_locked(s, r)
    })
}
fn release_locked(s: &mut State, r: &mut Replay) -> Result<(), Error> {
    if r.actor != ZERO {
        s.admission.retire_closed_caller(r.actor)?;
        if r.endpoint != ZERO {
            let mut backend = abi::ServiceAuthority {
                service: r.actor,
                endpoint: r.endpoint,
            };
            s.ipc.close(r.actor, r.endpoint, &mut backend)?;
            r.endpoint = ZERO;
        }
        s.services.revoke_owner(r.actor);
    }
    r.file_cap = 0;
    r.task_cap = 0;
    r.prepared = false;
    r.run = None;
    r.actor = ZERO;
    Ok(())
}
/// Preparation has no capture/run identity. Only an actually empty caller can
/// retire; queued/unknown admissions or retained responses keep custody here.
pub fn abort_prepared() -> Result<bool, Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if r.run.is_some() {
            return Err(Error::Auth);
        }
        r.closed = true;
        drained_locked(s, r)
    })
}
pub fn release_prepared() -> Result<(), Error> {
    owner()?;
    locked(|s| {
        let r = state();
        if r.run.is_some() || !r.closed || !drained_locked(s, r)? {
            return Err(Error::Busy);
        }
        release_locked(s, r)
    })
}
pub fn release(run: RunKey) -> Result<(), Error> {
    if !drain(run)? {
        return Err(Error::Busy);
    }
    locked(|s| {
        let r = state();
        if r.run != Some(run) || !r.closed || !drained_locked(s, r)? {
            return Err(Error::Busy);
        }
        for member in &MEMBERS {
            if member[2].load(Ordering::Acquire) == run.boot_epoch
                && member[3].load(Ordering::Acquire) == run.trial_id
                && member[4].load(Ordering::Acquire) == run.generation
            {
                member[0].store(0, Ordering::Release);
            }
        }
        release_locked(s, r)
    })
}
pub fn reset_echo(key: ObjectKey) -> Result<[u8; 32], Error> {
    owner()?;
    if !crate::domain_services::replay::owns(2) {
        return Err(Error::Auth);
    }
    locked(|s| {
        let i = task_index(&s.tasks, key)?;
        let task = s.tasks[i];
        let ipc = s.ipc.stats(task.endpoint)?;
        if task.recipe != 2
            || task.closed
            || task.pending
            || ipc.depth != 0
            || ipc.reserved != 0
            || s.active.iter().flatten().any(|a| a.dispatch.thread == key)
            || s.vectors[i].is_some()
        {
            return Err(Error::Busy);
        }
        let zero = [0u8; 16];
        memory::copy_to(&s.memory, key, 0x21000, &zero[..8])?;
        memory::copy_to(&s.memory, key, 0x30000, &zero)?;
        let mut actual = [0u8; 16];
        memory::copy_from(&s.memory, &s.tasks, key, 0x30000, &mut actual)?;
        let mut input = [0u8; 8];
        memory::copy_from(&s.memory, &s.tasks, key, 0x21000, &mut input)?;
        if actual != zero || input != [0; 8] {
            return Err(Error::Io);
        }
        s.tasks[i].completed_sequence = 0;
        s.tasks[i].response = 0;
        s.tasks[i].pending_sequence = 0;
        let mut h = Sha256::new();
        h.update(b"CYXIA_RESTORED_READONLY_ECHO_1.3\0");
        h.update(package_digest_locked());
        h.update(actual);
        h.update([task.recipe as u8]);
        h.update(b"input-zero;empty-ipc;no-dispatch;no-vector\0");
        Ok(h.finalize().into())
    })
}
pub fn echo_result(key: ObjectKey, sequence: u64) -> Result<(u64, u64), Error> {
    owner()?;
    if !crate::domain_services::replay::owns(2) || sequence == 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let task = s.tasks[task_index(&s.tasks, key)?];
        if task.completed_sequence == sequence {
            Ok((task.response, task.heartbeat_ns))
        } else if task.completed_sequence > sequence {
            Err(Error::Stale)
        } else {
            Err(Error::Again)
        }
    })
}
/// Read-only work may be idle without being closed by a recovery action.
/// Drain witnesses therefore inspect the actual queues and dispatch slots,
/// rather than requiring the recovery-only `closed` admission flag.
pub fn echo_idle(key: ObjectKey) -> Result<bool, Error> {
    locked(|s| {
        let i = task_index(&s.tasks, key)?;
        let task = s.tasks[i];
        if task.recipe != 2 || !crate::domain_services::replay::owns(2) {
            return Err(Error::Auth);
        }
        let ipc = s.ipc.stats(task.endpoint)?;
        Ok(!task.pending
            && !FILE_BUSY[i].load(Ordering::Acquire)
            && ipc.depth == 0
            && ipc.reserved == 0
            && s.vectors[i].as_ref().is_none_or(SubmitVector::complete)
            && !s.active.iter().flatten().any(|a| a.dispatch.thread == key))
    })
}
/// Membership is checked against the live protected task table. A retired or
/// unrecognized generation, or any replay-owned child, is never called outside.
pub fn outside_source(
    key: ObjectKey,
    class: cyxia_prototype::learning::reward::CpuClass,
) -> Result<bool, Error> {
    use cyxia_prototype::learning::reward::CpuClass;
    if !matches!(class, CpuClass::ExecutorWork | CpuClass::Optional) {
        return Ok(false);
    }
    if !READY.load(Ordering::Acquire) {
        return Ok(false);
    }
    if class == CpuClass::ExecutorWork && matches!(key.id, 2 | 3) && key.generation == 1 {
        return Ok(true);
    }
    if class == CpuClass::ExecutorWork && key == group(0x101) {
        return Ok(SERVICE_LIVE.load(Ordering::Acquire));
    }
    let Some(slot) = key.id.checked_sub(0x1000).filter(|i| *i < TASKS as u64) else {
        return Ok(false);
    };
    let known = &KNOWN[slot as usize];
    let generation = known[0].load(Ordering::Acquire);
    if generation == 0 || generation != key.generation {
        return Ok(false);
    }
    let parent = known[1].load(Ordering::Relaxed);
    let flags = known[3].load(Ordering::Relaxed);
    if known[2].load(Ordering::Relaxed) == 0 || known[0].load(Ordering::Acquire) != generation {
        return Err(Error::Busy);
    }
    if parent == CALLER_ID || flags >> 1 == 2 && crate::domain_services::replay::owns(2) {
        return Ok(false);
    }
    Ok(class == CpuClass::ExecutorWork || flags & 1 != 0)
}
