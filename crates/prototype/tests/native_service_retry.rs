//! Production read-only vector transport, IPC queues, and snapshot gates.
//! Host object metadata and clock are fixtures, never native replay evidence.
use cyxia_prototype::domains::{
    Error, ObjectKey, PolicyStamp,
    tasks::{
        FILE_STAT_BY_CAP, Ipc, IpcBackend, IpcOperation, ItemStatus, Message, ResolvedItem,
        SendGrant, ServiceBackend, ServiceBatch, ServiceItem, SubmitVector, TASK_QUERY_BY_CAP,
    },
};
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
#[path = "../../../kernel/src/domain_platform/read_snapshot.rs"]
mod read_snapshot;
#[path = "../../../kernel/src/domain_tasks/vector_transport.rs"]
mod vector_transport;

const TASKS: usize = 2;
const IPC_BYTES: usize = 256;
const TASK_SERVICE: ObjectKey = key(900);
const FILE_SERVICE: ObjectKey = key(901);
const FILE_OBJECT: ObjectKey = key(12);
const DEADLINE: u64 = 1_000;
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
static CLOCK: AtomicU64 = AtomicU64::new(0);
static READ_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static READ_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static HEALTH: read_snapshot::ReadSnapshot<bool> = read_snapshot::ReadSnapshot::new();
static METADATA: read_snapshot::ReadSnapshot<u64> = read_snapshot::ReadSnapshot::new();
fn now_ns() -> u64 {
    CLOCK.load(Ordering::Acquire)
}
fn task_index(tasks: &[Task; TASKS], object: ObjectKey) -> Result<usize, Error> {
    tasks
        .iter()
        .position(|t| t.life != Life::Free && t.key == object)
        .ok_or(Error::Stale)
}
fn validate_file(object: ObjectKey) -> Result<(), Error> {
    if object != FILE_OBJECT {
        return Err(Error::Stale);
    }
    if HEALTH
        .inspect(|healthy| *healthy)
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
    {
        Ok(())
    } else {
        Err(Error::Io)
    }
}
fn file_size(object: ObjectKey) -> Result<u64, Error> {
    validate_file(object)?;
    READ_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let size = METADATA
        .inspect(|size| *size)
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?;
    READ_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
    Ok(size)
}
struct Native {
    tasks: [Task; TASKS],
    ipc: Ipc<IPC_BYTES>,
    services: ServiceBatch,
    file_endpoint: ObjectKey,
    task_endpoint: ObjectKey,
    sequence: u64,
    lease: VectorLease,
    items: [ServiceItem; 16],
}
impl Native {
    fn new() -> Self {
        CLOCK.store(10, Ordering::Release);
        READ_ATTEMPTS.store(0, Ordering::Release);
        READ_COMPLETIONS.store(0, Ordering::Release);
        HEALTH.publish(true).unwrap();
        METADATA.publish(32 * 1024).unwrap();
        let caller = key(100);
        let mut ipc = Ipc::new();
        let task_endpoint = ipc.open(TASK_SERVICE, false).unwrap();
        let file_endpoint = ipc.open(FILE_SERVICE, false).unwrap();
        let mut services = ServiceBatch::new();
        services
            .install(4, PolicyStamp::new(1, 10, 10).unwrap(), 10)
            .unwrap();
        let file_cap = services
            .grant(caller, FILE_OBJECT, FILE_SERVICE, 1)
            .unwrap();
        let task_cap = services.grant(caller, caller, TASK_SERVICE, 2).unwrap();
        let items = core::array::from_fn(|i| ServiceItem {
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
        Self {
            tasks: [
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
            ],
            ipc,
            services,
            file_endpoint,
            task_endpoint,
            sequence: 0,
            lease: VectorLease {
                grants: [None; 2],
                requests: [0; 2],
            },
            items,
        }
    }
    fn submit(&mut self) -> SubmitVector {
        self.services
            .submit(key(100), &self.items, DEADLINE, now_ns())
            .unwrap()
    }
    fn step(&mut self, vector: &mut SubmitVector) {
        CLOCK.fetch_add(1, Ordering::AcqRel);
        self.services
            .step(
                vector,
                now_ns(),
                &mut vector_transport::Transport {
                    tasks: &self.tasks,
                    validate: Some(validate_file),
                    stat: Some(file_size),
                    ipc: &mut self.ipc,
                    task_endpoint: self.task_endpoint,
                    file_endpoint: self.file_endpoint,
                    sequence: &mut self.sequence,
                    lease: &mut self.lease,
                },
            )
            .unwrap();
    }
    fn finish(&mut self, vector: &mut SubmitVector) {
        for _ in 0..16 {
            if vector.complete() {
                return;
            }
            self.step(vector);
        }
        panic!("bounded read-only vector did not finish after its owner became ready");
    }
    fn values(&self, vector: &SubmitVector) {
        assert!(vector.complete());
        for (i, result) in vector.results().iter().enumerate() {
            assert_eq!(result.tag, 1000 + i as u64);
            assert_eq!(
                result.status,
                ItemStatus::Value(if i % 2 == 0 {
                    32 * 1024
                } else {
                    Life::Ready as u64
                })
            );
        }
        assert_eq!(self.ipc.stats(self.file_endpoint).unwrap().depth, 0);
        assert_eq!(self.ipc.stats(self.task_endpoint).unwrap().depth, 0);
        assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 8);
    }
}
struct BlockerDrain;
impl IpcBackend<IPC_BYTES> for BlockerDrain {
    fn authorize(&mut self, actor: ObjectKey, _: ObjectKey, _: IpcOperation) -> Result<(), Error> {
        if actor == FILE_SERVICE {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, _: ObjectKey, _: ObjectKey) -> Result<(), Error> {
        Ok(())
    }
    fn deliver(
        &mut self,
        _: ObjectKey,
        _: ObjectKey,
        message: &Message<IPC_BYTES>,
    ) -> Result<(), Error> {
        assert_eq!(&message.bytes[..message.len], b"occupied");
        Ok(())
    }
}

#[test]
fn busy_native_readers_keep_pending_recheck_authority_and_obey_original_deadline() {
    // Several independent real bounded endpoint tables coexist in this host
    // fixture's stack frame; no native allocation or CPU budget is changed.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // The same short snapshot gate used by the production I/O health
            // observer can be held by a control reader at validation time.
            let mut n = Native::new();
            let mut v = n.submit();
            HEALTH
                .inspect(|_| {
                    for _ in 0..3 {
                        n.step(&mut v);
                    }
                    for (i, result) in v.results().iter().enumerate() {
                        assert_eq!(
                            result.status,
                            if i % 2 == 0 {
                                ItemStatus::Pending
                            } else {
                                ItemStatus::Value(Life::Ready as u64)
                            }
                        );
                    }
                    assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 0);
                    assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().delivered, 0);
                })
                .unwrap();
            n.finish(&mut v);
            n.values(&v);
            assert_eq!(n.services.stats().errors, 0);

            // The object can be valid at dispatch but temporarily busy when the
            // actual copied IPC is delivered. That message drains once; only its
            // unfinished read-only items get a fresh later observation.
            let mut n = Native::new();
            let mut v = n.submit();
            METADATA.inspect(|_| n.step(&mut v)).unwrap();
            assert!(v.results().iter().all(|r| r.status == ItemStatus::Pending));
            assert_eq!(READ_ATTEMPTS.load(Ordering::Acquire), 4);
            assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 0);
            assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().delivered, 1);
            assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().depth, 0);
            n.finish(&mut v);
            n.values(&v);
            assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().delivered, 3);
            let before = n.services.stats();
            n.step(&mut v);
            assert_eq!(n.services.stats(), before);
            assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 8);

            // A transport refusal before publication must not turn untouched
            // items into errors or consume/deliver the vector more than once.
            let mut n = Native::new();
            let mut v = n.submit();
            n.sequence += 1;
            n.ipc
                .send(
                    FILE_SERVICE,
                    n.file_endpoint,
                    n.sequence,
                    b"occupied",
                    now_ns(),
                    &mut vector_transport::ServiceAuthority {
                        service: FILE_SERVICE,
                        endpoint: n.file_endpoint,
                    },
                )
                .unwrap();
            n.step(&mut v);
            assert!(v.results().iter().all(|r| r.status == ItemStatus::Pending));
            assert_eq!(n.services.policy_receipt(), 0);
            assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().depth, 1);
            n.ipc
                .receive_batch(FILE_SERVICE, n.file_endpoint, now_ns(), &mut BlockerDrain)
                .unwrap();
            n.finish(&mut v);
            n.values(&v);
            assert_eq!(n.ipc.stats(n.file_endpoint).unwrap().delivered, 3);

            // A Pending item does not retain old authorization. Already completed
            // neighbours keep their exact values when its capability is revoked.
            let mut n = Native::new();
            let mut v = n.submit();
            HEALTH.inspect(|_| n.step(&mut v)).unwrap();
            let neighbour = v.results()[1];
            n.services.revoke(key(100), n.items[0].cap).unwrap();
            n.finish(&mut v);
            assert_eq!(v.results()[1], neighbour);
            assert!(v.results().iter().enumerate().all(|(i, r)| r.status
                == if i % 2 == 0 {
                    ItemStatus::Error(Error::Auth)
                } else {
                    ItemStatus::Value(Life::Ready as u64)
                }));
            assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 0);

            // A permanent I/O failure still terminates the file items, whereas a
            // busy owner may wait only until the originally submitted deadline.
            let mut n = Native::new();
            let mut v = n.submit();
            HEALTH.publish(false).unwrap();
            n.finish(&mut v);
            assert!(v.results().iter().enumerate().all(|(i, r)| r.status
                == if i % 2 == 0 {
                    ItemStatus::Error(Error::Io)
                } else {
                    ItemStatus::Value(Life::Ready as u64)
                }));

            let mut n = Native::new();
            let mut v = n.submit();
            HEALTH
                .inspect(|_| {
                    n.step(&mut v);
                    let completed = v.results()[1];
                    CLOCK.store(DEADLINE - 1, Ordering::Release);
                    n.step(&mut v);
                    assert!(v.complete());
                    assert_eq!(v.results()[1], completed);
                    assert!(
                        v.results()
                            .iter()
                            .step_by(2)
                            .all(|r| r.status == ItemStatus::TimedOut)
                    );
                    assert_eq!(READ_COMPLETIONS.load(Ordering::Acquire), 0);
                })
                .unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
