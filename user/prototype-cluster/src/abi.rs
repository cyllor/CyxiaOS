//! Shared fixed-address broker ABI. No field is a guest pointer.
pub const SHARED_VA: u64 = 0x0200_0000;
pub const SHARED_BYTES: usize = 16384;
pub const STACK_TOP: u64 = 0x01ff_0000;
pub const STACK_BYTES: usize = 128 * 1024;
pub const SVC: u16 = 0x43;
pub const MAGIC: u64 = 0x4359_5843_4c53_3031;
pub const VERSION: u64 = 4;
pub const PAYLOAD: usize = 4096;
pub const OK: u64 = 0;
pub const AGAIN: u64 = 1;
pub const EOF: u64 = 2;
pub const FAILED: u64 = 3;
pub const NOT_FOUND: u64 = 4;
/// Pre-I/O capacity rejection; no durable write was attempted.
pub const REJECTED: u64 = 5;
pub const OP_ENTROPY: u64 = 1;
pub const OP_TIME: u64 = 2;
pub const OP_POLL: u64 = 3;
pub const OP_READ: u64 = 4;
pub const OP_WRITE: u64 = 5;
pub const OP_CLOSE: u64 = 6;
pub const OP_STORE_GET: u64 = 7;
pub const OP_STORE_PUT: u64 = 8;
pub const OP_STORE_FLUSH: u64 = 9;
pub const OP_TASK: u64 = 10;
/// Extended task custody operations. Phase 0 retains its original 104-byte ABI.
/// RESERVE: 104-byte terms followed by the 120-byte custody key.
/// LOOKUP: exact custody key; reply state:u64, admitted:u64; returned arg0 token.
/// INVENTORY: owner_boot:u64, requester:[u8;32], with 136-byte request capacity;
/// reply key followed by LOOKUP reply.
/// Key: owner_boot:u64, cluster:[u8;32], requester:[u8;32], contract:[u8;16], hash:[u8;32].
/// These read operations require the dedicated service and grant no START authority.
pub const TASK_RESERVE_CUSTODY: u64 = 31;
pub const TASK_LOOKUP_CUSTODY: u64 = 32;
pub const TASK_CUSTODY_INVENTORY: u64 = 33;
pub const TASK_CUSTODY_KEY_BYTES: usize = 120;
pub const OP_TRACE: u64 = 11;
pub const OP_YIELD: u64 = 12;
/// OP_TRACE arg0 distinguishes a terminal service failure from an ordinary event.
/// This is a value convention; the shared page layout and ABI version are unchanged.
pub const TRACE_FATAL_BIT: u64 = 1 << 63;
pub const SERVICE_FAULT_NONE: u64 = 0;
pub const SERVICE_FAULT_AFTER_READY: u64 = 1;
pub const SERVICE_FAULT_AFTER_RESERVE: u64 = 2;
pub const SERVICE_FAULT_AFTER_START: u64 = 3;
pub const SERVICE_FAULT_AFTER_COMPLETION: u64 = 4;
pub const SERVICE_FAULT_AFTER_RESULT_RECORD: u64 = 5;
/// Native restart evidence injects one real synchronous EL0 exception only
/// at an exact successful generation-1 broker receipt boundary.
pub const fn service_fault_due(profile: u64, generation: u64, op: u64, arg0: u64) -> bool {
    generation == 1
        && matches!(
            (profile, op, arg0),
            (SERVICE_FAULT_AFTER_READY, OP_TRACE, 0x212)
                | (SERVICE_FAULT_AFTER_RESERVE, OP_TASK, TASK_RESERVE_CUSTODY)
                | (SERVICE_FAULT_AFTER_START, OP_TASK, 2)
                | (SERVICE_FAULT_AFTER_COMPLETION, OP_TASK, 3)
                | (SERVICE_FAULT_AFTER_RESULT_RECORD, OP_TRACE, 0x216)
        )
}
/// POLL value: 0 disconnected, 1 connected. Epoch changes on every connection.
/// STORE offset selects a record chunk; arg0 record key; arg1 total record
/// bytes. PUT arg2 transaction phase: 0 stage,1 commit after complete staging.
/// GET/PUT offsets and total record sizes are bounded by MAX_RECORD.
pub const MAX_RECORD: u64 = 1024 * 1024;
pub const TX_SERVICE_ID: u64 = 10;
pub const UNAUTH_SERVICE_ID: u64 = 12;
pub const OFFER_SERVICE_ID: u64 = 16;
pub const DOMAIN_PENDING: u64 = 0;
pub const DOMAIN_APPLIED: u64 = 1;
pub const DOMAIN_REJECTED: u64 = 2;
pub const DOMAIN_UNKNOWN: u64 = 3;
pub const DOMAIN_EXPIRED: u64 = 4;
pub const PLACEMENT_STORAGE_BYTES: usize =
    core::mem::size_of::<cyxia_prototype::domains::platform::PlacementQueue>().div_ceil(4096)
        * 4096;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyWire {
    pub version: u64,
    pub snapshot_ns: u64,
    pub installed_until_ns: u64,
    pub value: u64,
    pub plan_seq: u64,
    pub controller_epoch: u64,
    pub action_index: u64,
}
/// Protected replay operation, deliberately outside the model Action ABI.
/// The replay owner keeps this identity until the real quote owner replies.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuoteStopWire {
    pub boot_epoch: u64,
    pub replay_id: u64,
    pub owner_id: u64,
    pub owner_generation: u64,
    pub sequence: u64,
    pub issued_ns: u64,
}
impl QuoteStopWire {
    pub const EMPTY: Self = Self {
        boot_epoch: 0,
        replay_id: 0,
        owner_id: 0,
        owner_generation: 0,
        sequence: 0,
        issued_ns: 0,
    };
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuoteStopReceiptWire {
    pub command: QuoteStopWire,
    pub offer_version: u64,
    pub started_ns: u64,
    pub finished_ns: u64,
    pub outcome: u64,
}
impl QuoteStopReceiptWire {
    pub const EMPTY: Self = Self {
        command: QuoteStopWire::EMPTY,
        offer_version: 0,
        started_ns: 0,
        finished_ns: 0,
        outcome: DOMAIN_PENDING,
    };
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DomainInput {
    pub tx: PolicyWire,
    pub unauth: PolicyWire,
    pub offer: PolicyWire,
    pub placement: PolicyWire,
    pub placement_request_id: u64,
    pub placement_request_generation: u64,
    pub peer_ipv4: u64,
    pub available_cpu_milli: u64,
    pub memory_pages: u64,
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub network_valid: u64,
    pub network_sample_ms: u64,
    pub network_rtt_us: u64,
    pub network_retrans_milli: u64,
    pub network_queued_bytes: u64,
    pub network_queue_depth: u64,
    pub network_active: u64,
    pub quote_stop: QuoteStopWire,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyReceiptWire {
    pub version: u64,
    pub actual: u64,
    pub outcome: u64,
    pub plan_seq: u64,
    pub controller_epoch: u64,
    pub action_index: u64,
    pub request_id: u64,
    pub request_generation: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PendingPlacementWire {
    pub request_id: u64,
    pub request_generation: u64,
    pub queued_us: u64,
    pub cpu_milli: u64,
    pub memory_pages: u64,
    pub peer_ready: u64,
}
impl PendingPlacementWire {
    pub const EMPTY: Self = Self {
        request_id: 0,
        request_generation: 0,
        queued_us: 0,
        cpu_milli: 0,
        memory_pages: 0,
        peer_ready: 0,
    };
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DomainFeedback {
    pub tx: PolicyReceiptWire,
    pub unauth: PolicyReceiptWire,
    pub offer: PolicyReceiptWire,
    pub placement: PolicyReceiptWire,
    pub tx_ordinary: u64,
    pub tx_reserved: u64,
    pub auth_attempts: u64,
    pub auth_rejected: u64,
    pub auth_failures: u64,
    pub auth_slots: u64,
    pub recovery_slots: u64,
    pub pending_placements: u64,
    pub waiting_request_id: u64,
    pub waiting_request_generation: u64,
    pub peer_cpu_milli: u64,
    pub peer_memory_pages: u64,
    pub placement_fallbacks: u64,
    pub measurement_ms: u64,
    pub measurement_valid: u64,
    pub network: [u64; 4],
    pub security: [u64; 4],
    pub cluster: [u64; 4],
    pub tx_last_ordinary: u64,
    pub tx_last_reserved: u64,
    pub waiting: [PendingPlacementWire; 32],
    pub quote_stop: QuoteStopReceiptWire,
    pub quotes_stopped: u64,
}
#[repr(C, align(4096))]
pub struct Shared {
    pub magic: u64,
    pub version: u64,
    pub sequence: u64,
    pub op: u64,
    pub status: u64,
    pub len: u64,
    pub offset: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub monotonic_ms: u64,
    pub unix_seconds: u64,
    pub boot_epoch: u64,
    /// Same-BootEpoch supervisor generation; increases on every service reset.
    pub service_generation: u64,
    pub connection_epoch: u64,
    pub uuid: [u8; 16],
    pub local_node: [u8; 32],
    pub peer_node: [u8; 32],
    pub domains: DomainInput,
    pub domain_feedback: DomainFeedback,
    pub payload: [u8; PAYLOAD],
    pub monotonic_ns: u64,
    /// Odd while EL0 is publishing feedback, nonzero even when complete.
    /// Timer/SPI preemption can return to EL1 between any two payload stores.
    pub feedback_sequence: u64,
}
pub fn valid_request(op: u64, len: u64, offset: u64) -> bool {
    if len > PAYLOAD as u64 {
        return false;
    }
    match op {
        OP_ENTROPY | OP_READ | OP_WRITE | OP_TRACE | OP_TASK => offset == 0,
        OP_STORE_GET | OP_STORE_PUT => offset.checked_add(len).is_some_and(|n| n <= MAX_RECORD),
        OP_TIME | OP_POLL | OP_CLOSE | OP_STORE_FLUSH | OP_YIELD => len == 0 && offset == 0,
        _ => false,
    }
}
pub fn valid_service_identity(shared: &Shared, boot_epoch: u64, generation: u64) -> bool {
    boot_epoch != 0
        && generation != 0
        && shared.magic == MAGIC
        && shared.version == VERSION
        && shared.boot_epoch == boot_epoch
        && shared.service_generation == generation
}
const _: () = assert!(core::mem::size_of::<Shared>() <= SHARED_BYTES);
