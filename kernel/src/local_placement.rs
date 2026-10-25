//! At-most-once native LOCAL admission for the isolated cluster service.
//! A fixed receipt table never evicts an uncertain operation. Recovery queries
//! from a later boot cannot manufacture a fresh execution from an old intent.
use cyxia_prototype::domains::{ObjectKey, tasks::SpawnState};
use sha2::{Digest, Sha256};

const CAPACITY: usize = 256;
#[derive(Clone, Copy)]
struct Entry {
    key: ObjectKey,
    input_hash: [u8; 32],
    package_hash: [u8; 32],
    deadline_ns: u64,
    input_len: u64,
    spawn_id: u64,
    state: SpawnState,
    retryable: bool,
    completion: Option<Result<(u64, u64), cyxia_prototype::domains::Error>>,
    acknowledged: bool,
}
static mut ENTRIES: [Option<Entry>; CAPACITY] = [None; CAPACITY];
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn answer(payload: &mut [u8; 4096], state: SpawnState) -> (u64, usize, u64) {
    let (status, key) = match state {
        SpawnState::Queued => (0u64, ObjectKey::default()),
        SpawnState::Created(key) => (1, key),
        SpawnState::Failed(_) | SpawnState::Cancelled => (2, ObjectKey::default()),
        SpawnState::Unknown => (3, ObjectKey::default()),
    };
    payload[..8].copy_from_slice(&status.to_le_bytes());
    payload[8..16].copy_from_slice(&key.id.to_le_bytes());
    payload[16..24].copy_from_slice(&key.generation.to_le_bytes());
    (0, 24, 0)
}
fn query(entry: &mut Entry) {
    if matches!(entry.state, SpawnState::Queued | SpawnState::Unknown) {
        if let Ok(state) = crate::domain_tasks::query_local(entry.spawn_id) {
            entry.state = state;
        }
    }
    crate::domain_tasks::bind_local_failure_request(entry.spawn_id, entry.key, entry.deadline_ns);
}
fn admit(entry: &mut Entry, input: &[u8]) -> Result<(), ()> {
    // Only an explicit error before SpawnAdmission publishes its Queued
    // receipt permits another call. UNKNOWN is visible before callbacks;
    // a lost reply, accepted Failed, or uncertain construction never retries.
    entry.retryable = false;
    entry.state = SpawnState::Unknown;
    let result = crate::domain_network::replay::claim_local(entry.key, entry.spawn_id)
        .and_then(|()| crate::domain_tasks::submit_local(entry.spawn_id, input, entry.deadline_ns));
    let outcome = match result {
        Err(
            cyxia_prototype::domains::Error::Busy
            | cyxia_prototype::domains::Error::Again
            | cyxia_prototype::domains::Error::NotReady,
        ) => {
            entry.retryable = true;
            Err(())
        }
        Ok(state) => {
            entry.state = state;
            Ok(())
        }
        Err(error) => {
            entry.state = SpawnState::Failed(error);
            Ok(())
        }
    };
    crate::domain_tasks::bind_local_failure_request(entry.spawn_id, entry.key, entry.deadline_ns);
    outcome
}
/// Phase 11 body: id/gen/deadline_ms/cpu/pages/hash32/package32/len/input.
/// Phase 12 body: id/gen/input_hash32. Only CPU0 may access this table.
pub fn request(
    phase: u64,
    payload: &mut [u8; 4096],
    len: usize,
    package_hash: [u8; 32],
) -> (u64, usize, u64) {
    assert_eq!(cyxia_arch_aarch64::cpu::slot(), 0);
    if len > payload.len() || !matches!(phase, 11 | 12 | 27) {
        return (3, 0, 0);
    }
    if (phase == 11 && len < 112) || (matches!(phase, 12 | 27) && len != 48) {
        return (3, 0, 0);
    }
    let key = ObjectKey {
        id: word(payload, 0),
        generation: word(payload, 8),
    };
    if key.id == 0 || key.generation == 0 {
        return (3, 0, 0);
    }
    // Exclusive CPU0 broker ownership; no callback or IRQ handler borrows it.
    let entries = unsafe { &mut *core::ptr::addr_of_mut!(ENTRIES) };
    if matches!(phase, 12 | 27) {
        let Some(entry) = entries.iter_mut().flatten().find(|entry| entry.key == key) else {
            return (4, 0, 0);
        };
        if payload[16..48] != entry.input_hash {
            return (3, 0, 0);
        }
        if entry.retryable {
            // A query cannot turn an uncertain service/recovery invocation
            // into a new admission. Only an explicitly retried phase 11 can.
            return (1, 0, 0);
        }
        query(entry);
        if phase == 27 {
            if entry.completion.is_none() {
                match crate::domain_tasks::local_result(entry.spawn_id) {
                    Ok(Some(value)) => entry.completion = Some(Ok(value)),
                    Ok(None)
                    | Err(
                        cyxia_prototype::domains::Error::Busy
                        | cyxia_prototype::domains::Error::Again,
                    ) => return (1, 0, 0),
                    Err(error) => entry.completion = Some(Err(error)),
                }
            }
            // Keep the exact result in this identity table before releasing
            // the bounded task-exit receipt slot. A lost broker reply reads
            // these same bytes and never re-runs the task.
            if !entry.acknowledged && matches!(entry.state, SpawnState::Created(_)) {
                if crate::domain_tasks::acknowledge_local_result(entry.spawn_id).is_err() {
                    return (1, 0, 0);
                }
                entry.acknowledged = true;
            }
            return match entry.completion.unwrap() {
                Ok((sum, finished)) => {
                    payload[..8].copy_from_slice(&sum.to_le_bytes());
                    payload[8..16].copy_from_slice(&finished.to_le_bytes());
                    (0, 16, 0)
                }
                Err(_) => (3, 0, 0),
            };
        }
        return answer(payload, entry.state);
    }
    let Some(deadline_ns) = word(payload, 16).checked_mul(1_000_000) else {
        return (3, 0, 0);
    };
    let input_len = word(payload, 104);
    let input_hash: [u8; 32] = payload[40..72].try_into().unwrap();
    if word(payload, 24) != 100
        || word(payload, 32) != 16
        || payload[72..104] != package_hash
        || input_len == 0
        || input_len > 3984
        || !input_len.is_multiple_of(8)
        || len != 112 + input_len as usize
        || Sha256::digest(&payload[112..len])[..] != input_hash
    {
        return (3, 0, 0);
    }
    if let Some(entry) = entries.iter_mut().flatten().find(|entry| entry.key == key) {
        if entry.input_hash != input_hash
            || entry.package_hash != package_hash
            || entry.deadline_ns != deadline_ns
            || entry.input_len != input_len
        {
            return (3, 0, 0);
        }
        if entry.retryable {
            if entry.deadline_ns <= crate::domain_platform::now_ns() {
                entry.retryable = false;
                entry.state = SpawnState::Failed(cyxia_prototype::domains::Error::Expired);
            } else if admit(entry, &payload[112..len]).is_err() {
                return (1, 0, 0);
            }
        }
        query(entry);
        return answer(payload, entry.state);
    }
    let now = crate::domain_platform::now_ns();
    if deadline_ns <= now || deadline_ns - now > 60_000_000_000 {
        return (3, 0, 0);
    }
    let Some(index) = entries.iter().position(Option::is_none) else {
        return (5, 0, 0);
    };
    let spawn_id = index as u64 + 1;
    // Retain the immutable identity and spawn id even when a later explicit
    // no-custody reply permits retry. Other requests cannot reuse this slot.
    entries[index] = Some(Entry {
        key,
        input_hash,
        package_hash,
        deadline_ns,
        input_len,
        spawn_id,
        state: SpawnState::Unknown,
        retryable: false,
        completion: None,
        acknowledged: false,
    });
    let entry = entries[index].as_mut().unwrap();
    if admit(entry, &payload[112..len]).is_err() {
        return (1, 0, 0);
    }
    answer(payload, entry.state)
}
