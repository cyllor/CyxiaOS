//! Run the production CPU0 vector transport with the real endpoint queues and
//! ServiceBatch policy owner. Only the clock and read-only object owners are
//! host fixtures; receipts are earned by actual copied-message delivery.
use cyxia_prototype::domains::{
    Error, ObjectKey, PolicyStamp,
    tasks::{
        FILE_STAT_BY_CAP, Ipc, IpcBackend, IpcOperation, ItemStatus, Message, ResolvedItem,
        SendGrant, ServiceBackend, ServiceBatch, ServiceItem, TASK_QUERY_BY_CAP,
    },
};
use std::sync::atomic::{AtomicU64, Ordering};
#[path = "../../../kernel/src/domain_tasks/vector_transport.rs"]
mod vector_transport;
const TASKS: usize = 2;
const IPC_BYTES: usize = 256;
const TASK_SERVICE: ObjectKey = key(900);
const FILE_SERVICE: ObjectKey = key(901);
const FILE_OBJECT: ObjectKey = key(12);
const fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
#[derive(Clone, Copy, PartialEq)]
enum Life {
    Free,
    Ready,
}
#[derive(Clone, Copy)]
struct Task {
    key: ObjectKey,
    life: Life,
    exit_code: u64,
}
type ValidateFile = fn(ObjectKey) -> Result<(), Error>;
type StatFile = fn(ObjectKey) -> Result<u64, Error>;
struct VectorLease {
    grants: [Option<SendGrant>; 2],
    requests: [u64; 2],
}
static CLOCK: AtomicU64 = AtomicU64::new(100);
static FILE_READS: AtomicU64 = AtomicU64::new(0);
fn now_ns() -> u64 {
    CLOCK.load(Ordering::Relaxed)
}
fn task_index(tasks: &[Task; TASKS], target: ObjectKey) -> Result<usize, Error> {
    tasks
        .iter()
        .position(|t| t.life != Life::Free && t.key == target)
        .ok_or(Error::Stale)
}
fn validate_file(target: ObjectKey) -> Result<(), Error> {
    if target == FILE_OBJECT {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}
fn file_size(target: ObjectKey) -> Result<u64, Error> {
    validate_file(target)?;
    FILE_READS.fetch_add(1, Ordering::Relaxed);
    Ok(8 * 4096)
}

#[test]
fn two_native_service_policies_change_real_ipc_batches_and_retain_per_item_results() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let caller = key(100);
            let tasks = [
                Task {
                    key: caller,
                    life: Life::Ready,
                    exit_code: 0,
                },
                Task {
                    key: key(101),
                    life: Life::Free,
                    exit_code: 0,
                },
            ];
            let mut ipc = Ipc::<IPC_BYTES>::new();
            let task_endpoint = ipc.open(TASK_SERVICE, false).unwrap();
            let file_endpoint = ipc.open(FILE_SERVICE, false).unwrap();
            let mut services = ServiceBatch::new();
            let task_cap = services.grant(caller, caller, TASK_SERVICE, 2).unwrap();
            let file_cap = services
                .grant(caller, FILE_OBJECT, FILE_SERVICE, 1)
                .unwrap();
            let items: [ServiceItem; 16] = core::array::from_fn(|i| ServiceItem {
                op: if i % 2 == 0 {
                    FILE_STAT_BY_CAP
                } else {
                    TASK_QUERY_BY_CAP
                },
                flags: 0,
                cap: if i % 2 == 0 { file_cap } else { task_cap },
                object_gen: 1,
                tag: 1000 + i as u64,
            });
            let mut previous = None;
            let mut sequence = 0;
            for (version, batch, expected_calls) in [(1, 1, 16), (2, 4, 4)] {
                let now = 100 + version;
                CLOCK.store(now, Ordering::Relaxed);
                let stamp = PolicyStamp::new(version, now, now).unwrap();
                services.install(batch, stamp, now).unwrap();
                assert_eq!(services.policy_receipt(), version - 1);
                let mut vector = services.submit(caller, &items, 1000, now).unwrap();
                let before = services.stats().ipc_calls;
                let mut lease = VectorLease {
                    grants: [None; 2],
                    requests: [0; 2],
                };
                for (index, (service, endpoint)) in
                    [(TASK_SERVICE, task_endpoint), (FILE_SERVICE, file_endpoint)]
                        .into_iter()
                        .enumerate()
                {
                    sequence += 1;
                    let mut authority = vector_transport::ServiceAuthority { service, endpoint };
                    let grant = ipc
                        .reserve_send(service, endpoint, sequence, now, &mut authority)
                        .unwrap();
                    ipc.validate_confirmed_send_grant(grant, service, endpoint, &mut authority)
                        .unwrap();
                    lease.grants[index] = Some(grant);
                    lease.requests[index] = sequence;
                }
                while !vector.complete() {
                    services
                        .step(
                            &mut vector,
                            now,
                            &mut vector_transport::Transport {
                                tasks: &tasks,
                                validate: Some(validate_file),
                                stat: Some(file_size),
                                ipc: &mut ipc,
                                task_endpoint,
                                file_endpoint,
                                sequence: &mut sequence,
                                lease: &mut lease,
                            },
                        )
                        .unwrap();
                }
                assert_eq!(services.policy_receipt(), version);
                assert_eq!(services.stats().ipc_calls - before, expected_calls);
                for (i, result) in vector.results().iter().enumerate() {
                    assert_eq!(result.tag, items[i].tag);
                    assert_eq!(
                        result.status,
                        ItemStatus::Value(if i % 2 == 0 {
                            8 * 4096
                        } else {
                            Life::Ready as u64
                        })
                    );
                }
                if let Some(ref old) = previous {
                    assert_eq!(vector.results(), old);
                }
                previous = Some(vector.results().to_vec());
                assert!(lease.grants.iter().all(Option::is_none));
                assert_eq!(ipc.stats(file_endpoint).unwrap().depth, 0);
                assert_eq!(ipc.stats(task_endpoint).unwrap().depth, 0);
            }
            assert_eq!(FILE_READS.load(Ordering::Relaxed), 16);
            assert_eq!(ipc.stats(file_endpoint).unwrap().delivered, 10);
            assert_eq!(ipc.stats(task_endpoint).unwrap().delivered, 10);

            // A stale legitimate item is not an invalid-vector rejection. The
            // unchanged neighbour still executes through the real IPC receiver.
            let mut changed = items;
            changed[0].object_gen += 1;
            let mut vector = services.submit(caller, &changed, 1000, now_ns()).unwrap();
            let mut lease = VectorLease {
                grants: [None; 2],
                requests: [0; 2],
            };
            while !vector.complete() {
                services
                    .step(
                        &mut vector,
                        now_ns(),
                        &mut vector_transport::Transport {
                            tasks: &tasks,
                            validate: Some(validate_file),
                            stat: Some(file_size),
                            ipc: &mut ipc,
                            task_endpoint,
                            file_endpoint,
                            sequence: &mut sequence,
                            lease: &mut lease,
                        },
                    )
                    .unwrap();
            }
            assert_eq!(vector.results()[0].status, ItemStatus::Error(Error::Stale));
            assert_eq!(&vector.results()[1..], &previous.unwrap()[1..]);
            let before = services.stats();
            changed[15].op = 3;
            assert!(matches!(
                services.submit(caller, &changed, 1000, now_ns()),
                Err(Error::Format)
            ));
            assert_eq!(services.stats(), before);
        })
        .unwrap()
        .join()
        .unwrap();
}
