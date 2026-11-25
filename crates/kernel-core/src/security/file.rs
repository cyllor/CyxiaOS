//! SEC-F: path/capability validation and a non-forgetting durability receipt.
//! Media ordering and actual FLUSH completion are owned by the native LogFS.
use super::Error;

pub const MAX_PATH: usize = 512;
pub const MAX_COMPONENT: usize = 63;
pub const MAX_WRITE: usize = 64 * 1024;

/// Validate one absolute, component-anchored path before looking up any inode.
/// This accepts root "/" but rejects "."/"..", duplicate slashes, NUL,
/// invalid UTF-8, excessive lengths and trailing separators.
pub fn validate_absolute_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' {
        return Err(Error::Invalid);
    }
    core::str::from_utf8(path).map_err(|_| Error::Invalid)?;
    if path == b"/" {
        return Ok(());
    }
    let tail = &path[1..];
    for component in tail.split(|b| *b == b'/') {
        if component.is_empty()
            || component.len() > MAX_COMPONENT
            || component == b"."
            || component == b".."
            || component.contains(&0)
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
pub const DIRECTORY: u8 = 4;
pub const DELETE: u8 = 8;
pub const SYSTEM_STORE: u8 = 16;

/// Unforgeable only at its native capability table boundary; a model or a
/// network message must never be treated as a constructor for FileCapability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileCapability {
    owner: u64,
    inode: u16,
    generation: u64,
    permissions: u8,
}
impl FileCapability {
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_registry(
        owner: u64,
        inode: u16,
        generation: u64,
        permissions: u8,
    ) -> Self {
        Self {
            owner,
            inode,
            generation,
            permissions,
        }
    }
    pub fn permits(
        self,
        owner: u64,
        inode: u16,
        generation: u64,
        requested: u8,
    ) -> Result<(), Error> {
        if owner == 0 || self.owner != owner {
            return Err(Error::Unauthorized);
        }
        if self.inode != inode || self.generation != generation || generation == 0 {
            return Err(Error::Stale);
        }
        if requested == 0 || requested & !self.permissions != 0 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    /// BootEpoch and other protected-system records cannot be reached by
    /// ordinary file capabilities, including through a fabricated path.
    /// A caller supplies *trusted native registry* identity and generation;
    /// no protected inode encoding is invented here (DEC-01 is not frozen).
    /// A matching SYSTEM_STORE bit on an unrelated normal inode is insufficient.
    pub fn protected_store(
        self,
        owner: u64,
        protected_inode: u16,
        protected_generation: u64,
    ) -> Result<(), Error> {
        if self.owner != owner || owner == 0 || self.permissions & SYSTEM_STORE == 0 {
            return Err(Error::Unauthorized);
        }
        if self.inode != protected_inode
            || self.generation == 0
            || protected_generation == 0
            || self.generation != protected_generation
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Reserved,
    RedoFlushed,
    CommitFlushed,
    Visible,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Receipt {
    request_id: u64,
    payload_hash: [u8; 32],
    stage: Stage,
}
/// UNKNOWN retains its original key and cannot be resubmitted as a fresh
/// operation. COMMIT/FLUSH is evidence from LogFS, never inferred here.
pub struct DurableReceipts<const N: usize> {
    rows: [Option<Receipt>; N],
}
impl<const N: usize> Default for DurableReceipts<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> DurableReceipts<N> {
    pub const fn new() -> Self {
        Self { rows: [None; N] }
    }
    pub fn submit(&mut self, id: u64, hash: [u8; 32]) -> Result<Stage, Error> {
        if id == 0 {
            return Err(Error::Invalid);
        }
        if let Some(row) = self.rows.iter().flatten().find(|r| r.request_id == id) {
            return if row.payload_hash == hash {
                Ok(row.stage)
            } else {
                Err(Error::Conflict)
            };
        }
        let pos = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.rows[pos] = Some(Receipt {
            request_id: id,
            payload_hash: hash,
            stage: Stage::Reserved,
        });
        Ok(Stage::Reserved)
    }
    fn row(&mut self, id: u64) -> Result<&mut Receipt, Error> {
        self.rows
            .iter_mut()
            .flatten()
            .find(|r| r.request_id == id)
            .ok_or(Error::Stale)
    }
    pub fn advance(&mut self, id: u64, from: Stage, to: Stage) -> Result<(), Error> {
        if !matches!(
            (from, to),
            (Stage::Reserved, Stage::RedoFlushed)
                | (Stage::RedoFlushed, Stage::CommitFlushed)
                | (Stage::CommitFlushed, Stage::Visible)
        ) {
            return Err(Error::Invalid);
        }
        let row = self.row(id)?;
        if row.stage != from {
            return Err(Error::Stale);
        }
        row.stage = to;
        Ok(())
    }
    pub fn uncertain(&mut self, id: u64) -> Result<(), Error> {
        let row = self.row(id)?;
        if row.stage != Stage::Visible {
            row.stage = Stage::Unknown;
        }
        Ok(())
    }
    pub fn state(&mut self, id: u64) -> Result<Stage, Error> {
        Ok(self.row(id)?.stage)
    }
    pub fn acknowledge_fsync(&mut self, id: u64) -> Result<(), Error> {
        if self.row(id)?.stage != Stage::Visible {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}

/// SEC-F07 (V0.19.9 stable ID): D04 readahead/flush gear change concurrent
/// with fsync. Baseline: 主§8.4 (spec L3238–3272), SEC-F 并发交错 (L8921),
/// SEC-F07 验收行 (L9023), 主§9.3 写入与确认顺序 (L3936–3948).
///
/// Contract-only model of the file service's serial commit point under gear
/// changes. Native LogFS wiring (real redo writes, device FLUSH evidence and
/// power-fail drills) is a separate acceptance track; nothing here invents
/// wire bytes or claims native SEC-F07/A05 acceptance.
pub const D04_GEARS: [(u16, u16); 4] = [(0, 4), (2, 8), (8, 16), (16, 32)];
/// 主§8.4 基线/失败行为: baseline gear is (0, 4).
pub const D04_BASELINE: (u16, u16) = (0, 4);
/// 主§9.3 / SEC-F 资源计账: at most 128 distinct home blocks per transaction.
pub const MAX_TX_HOME_BLOCKS: u32 = 128;

/// One frozen D04 action plus its version. A transaction fixes its batch
/// action and version at start; an already-started transaction is never
/// split, reordered or cancelled by a later gear change or policy expiry
/// (主§8.4 执行/生效点, L3254–3257).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D04Gear {
    readahead: u16,
    flush: u16,
    version: u64,
}
impl D04Gear {
    pub const fn baseline() -> Self {
        Self {
            readahead: D04_BASELINE.0,
            flush: D04_BASELINE.1,
            version: 1,
        }
    }
    pub const fn readahead_pages(self) -> u16 {
        self.readahead
    }
    pub const fn background_flush_pages(self) -> u16 {
        self.flush
    }
    pub const fn version(self) -> u64 {
        self.version
    }
    /// Install a candidate gear at a batch boundary. Only the four frozen
    /// (readahead, background_flush) pairs are legal (主§8.4 AI 建议/编码).
    /// The version advances only when the pair actually changes; reinstalling
    /// the same pair is a no-op. Callers must apply this only between batches:
    /// in-flight transactions keep their frozen copy (see FsyncGearLedger).
    pub fn install(&mut self, readahead: u16, flush: u16) -> Result<(), Error> {
        if !D04_GEARS.contains(&(readahead, flush)) {
            return Err(Error::Invalid);
        }
        if (self.readahead, self.flush) != (readahead, flush) {
            self.version = self.version.checked_add(1).ok_or(Error::Exhausted)?;
            self.readahead = readahead;
            self.flush = flush;
        }
        Ok(())
    }
}

/// Select dirty *data* pages for one new ordinary background writeback batch
/// under a frozen gear (主§8.4, L3250–3257). The metadata closure
/// (inode/bitmap/receipt home blocks) is indivisible: it is always included
/// whole, and the data selection shrinks so data + metadata stay within the
/// 128-home-block transaction cap. A metadata closure that alone exceeds the
/// cap cannot be split and fails closed with Capacity.
///
/// This cap applies only to new ordinary background batches. It never limits
/// the completion of an already-started transaction: fsync, checkpoints and
/// emergency log reclaim use the reserved progress path (主§8.4 硬约束).
/// One 4 KiB data page counts as one home block in this model.
pub fn background_batch_data_pages(
    flush_pages: u16,
    dirty_data_pages: u32,
    metadata_home_blocks: u32,
) -> Result<u32, Error> {
    if metadata_home_blocks > MAX_TX_HOME_BLOCKS {
        return Err(Error::Capacity);
    }
    let room = MAX_TX_HOME_BLOCKS - metadata_home_blocks;
    Ok(u32::from(flush_pages).min(dirty_data_pages).min(room))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GearTx {
    txid: u64,
    frozen: D04Gear,
    stage: Stage,
}

/// Serial fsync ordering under D04 gear changes (SEC-F07). Transactions are
/// admitted in BEGIN order with a frozen gear; visibility is published only
/// at the serial commit point in txid order (主§9.3 ④, L3940–3942), so a gear
/// change can never reorder durable fsync completion. An older UNKNOWN
/// transaction blocks newer durable publication fail-closed (SEC-F 降级与
/// 失败路径, L8929: stop new durable-success ACKs while the outcome is
/// uncertain). Background writeback has no path to advance a stage or to
/// claim FSYNC success (主§9.6.1, L4484).
pub struct FsyncGearLedger<const N: usize> {
    gear: D04Gear,
    txs: [Option<GearTx>; N],
    next_txid: u64,
}
impl<const N: usize> Default for FsyncGearLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> FsyncGearLedger<N> {
    pub const fn new() -> Self {
        Self {
            gear: D04Gear::baseline(),
            txs: [None; N],
            next_txid: 1,
        }
    }
    pub const fn gear(&self) -> D04Gear {
        self.gear
    }
    /// Boundary gear install; never touches already-begun transactions.
    pub fn install_gear(&mut self, readahead: u16, flush: u16) -> Result<(), Error> {
        self.gear.install(readahead, flush)
    }
    /// Begin one fsync transaction, freezing the current gear and version.
    pub fn begin(&mut self) -> Result<u64, Error> {
        let pos = self
            .txs
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let txid = self.next_txid;
        self.next_txid = self.next_txid.checked_add(1).ok_or(Error::Exhausted)?;
        self.txs[pos] = Some(GearTx {
            txid,
            frozen: self.gear,
            stage: Stage::Reserved,
        });
        Ok(txid)
    }
    fn tx(&self, txid: u64) -> Result<&GearTx, Error> {
        self.txs
            .iter()
            .flatten()
            .find(|t| t.txid == txid)
            .ok_or(Error::Stale)
    }
    fn tx_mut(&mut self, txid: u64) -> Result<&mut GearTx, Error> {
        self.txs
            .iter_mut()
            .flatten()
            .find(|t| t.txid == txid)
            .ok_or(Error::Stale)
    }
    pub fn frozen_gear(&self, txid: u64) -> Result<D04Gear, Error> {
        Ok(self.tx(txid)?.frozen)
    }
    /// Stage evidence transitions, identical to DurableReceipts, plus serial
    /// visibility: a transaction may become Visible only after every older
    /// transaction is Visible. Older UNKNOWN blocks newer durable publication
    /// (fail-closed); older in-flight stages yield Busy, never a reorder.
    pub fn advance(&mut self, txid: u64, from: Stage, to: Stage) -> Result<(), Error> {
        if !matches!(
            (from, to),
            (Stage::Reserved, Stage::RedoFlushed)
                | (Stage::RedoFlushed, Stage::CommitFlushed)
                | (Stage::CommitFlushed, Stage::Visible)
        ) {
            return Err(Error::Invalid);
        }
        if self.tx(txid)?.stage != from {
            return Err(Error::Stale);
        }
        if to == Stage::Visible {
            for older in self.txs.iter().flatten() {
                if older.txid < txid {
                    match older.stage {
                        Stage::Visible => {}
                        Stage::Unknown => return Err(Error::Unknown),
                        _ => return Err(Error::Busy),
                    }
                }
            }
        }
        self.tx_mut(txid)?.stage = to;
        Ok(())
    }
    pub fn uncertain(&mut self, txid: u64) -> Result<(), Error> {
        let tx = self.tx_mut(txid)?;
        if tx.stage != Stage::Visible {
            tx.stage = Stage::Unknown;
        }
        Ok(())
    }
    pub fn state(&self, txid: u64) -> Result<Stage, Error> {
        Ok(self.tx(txid)?.stage)
    }
    /// Durable success ACK requires the full BEGIN→REDO→FLUSH→COMMIT→FLUSH→
    /// visible chain (主§9.3). Gear selection and background writeback are not
    /// evidence and cannot reach this point.
    pub fn acknowledge_fsync(&self, txid: u64) -> Result<(), Error> {
        if self.tx(txid)?.stage != Stage::Visible {
            return Err(Error::Unknown);
        }
        Ok(())
    }
    /// Size one new ordinary background batch under the *current* gear.
    pub fn background_batch_pages(
        &self,
        dirty_data_pages: u32,
        metadata_home_blocks: u32,
    ) -> Result<u32, Error> {
        background_batch_data_pages(
            self.gear.background_flush_pages(),
            dirty_data_pages,
            metadata_home_blocks,
        )
    }
}

/// SEC-F12 (V0.19.9 stable ID): single-group persistent receipt isolation.
/// Baseline: 主§9.6.1 (spec L4079–4088 volatile keys / L4407–4432 allocation
/// and retirement), 安§0.8 FILE_ALLOC/RETIRE 行 (L7403–7407: 每组各≤8/s,
/// 持久票据≤8, 只计持久操作), SEC-F12 验收行 (L9122–9125).
///
/// Contract-only runtime ledger of the per-group quota boundary. The native
/// adapter must bind the full 56-byte ReceiptKey (fs_uuid, issued_boot_epoch,
/// group_id/generation, stream_slot/generation, request_seq) plus the durable
/// owner_principal; those media fields live in file_media_v0199 /
/// file_index_v0199 / file_receipt_store_v0199 and are not re-invented here.
/// The ≤8/s allocation/retirement pacing is a SecurityProfile v3 admission
/// concern with a monotonic clock and is not modeled by this quota ledger.
pub const GROUP_TICKETS: usize = 8;
pub const GROUP_VOLATILE_SLOTS: usize = 8;
/// request_seq occupies 53 bits of the local request_id (主§9.6.1, L4427).
pub const MAX_REQUEST_SEQ: u64 = (1u64 << 53) - 1;

/// Persistent receipt states 1..6 (主§9.6.1, L4410–4412).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketState {
    Issued,
    Bound,
    Done,
    Partial,
    Unknown,
    Cancelled,
}
impl TicketState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Partial | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ticket {
    seq: u64,
    stream_slot: u64,
    stream_generation: u64,
    state: TicketState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VolatileResult {
    seq: u64,
    write_seq: u64,
}
#[derive(Clone, Copy)]
struct GroupLedger {
    generation: u32,
    tickets: [Option<Ticket>; GROUP_TICKETS],
    volatile: [Option<VolatileResult>; GROUP_VOLATILE_SLOTS],
    issued_hi: u64,
    retired_through: u64,
    volatile_issued_hi: u64,
    volatile_retired_through: u64,
}
const EMPTY_GROUP: GroupLedger = GroupLedger {
    generation: 1,
    tickets: [None; GROUP_TICKETS],
    volatile: [None; GROUP_VOLATILE_SLOTS],
    issued_hi: 0,
    retired_through: 0,
    volatile_issued_hi: 0,
    volatile_retired_through: 0,
};

/// Per-group receipt isolation: durable tickets and volatile WRITE results
/// are separate ledgers. Ordinary WRITE never consumes a persistent ticket
/// (主§9.6.1, L4088). A full group rejects only its own new durable tickets;
/// other groups and read-only recovery reconciliation continue (SEC-F12).
pub struct GroupReceiptLedger<const GROUPS: usize> {
    groups: [GroupLedger; GROUPS],
}
impl<const GROUPS: usize> Default for GroupReceiptLedger<GROUPS> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const GROUPS: usize> GroupReceiptLedger<GROUPS> {
    pub const fn new() -> Self {
        Self {
            groups: [EMPTY_GROUP; GROUPS],
        }
    }
    fn group(&self, group: usize) -> Result<&GroupLedger, Error> {
        self.groups.get(group).ok_or(Error::Invalid)
    }
    fn group_mut(&mut self, group: usize) -> Result<&mut GroupLedger, Error> {
        self.groups.get_mut(group).ok_or(Error::Invalid)
    }
    fn check_generation(g: &GroupLedger, generation: u32) -> Result<(), Error> {
        if g.generation != generation || generation == 0 {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn check_seq(seq: u64) -> Result<(), Error> {
        if seq == 0 || seq > MAX_REQUEST_SEQ {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn ticket(g: &GroupLedger, seq: u64) -> Result<&Ticket, Error> {
        g.tickets
            .iter()
            .flatten()
            .find(|t| t.seq == seq)
            .ok_or(Error::Stale)
    }
    fn ticket_mut(g: &mut GroupLedger, seq: u64) -> Result<&mut Ticket, Error> {
        g.tickets
            .iter_mut()
            .flatten()
            .find(|t| t.seq == seq)
            .ok_or(Error::Stale)
    }
    /// Allocate one durable ticket (CREATE/MKDIR/UNLINK/FSYNC class).
    /// seq must equal issued_hi+1; older watermarks and gaps follow
    /// 主§9.6.1 分配 (L4407–4410): ≤retired → E_STALE, within issued range →
    /// only the matching existing record, beyond issued_hi+1 → EAGAIN.
    pub fn alloc_durable(
        &mut self,
        group: usize,
        generation: u32,
        stream_slot: u64,
        stream_generation: u64,
        seq: u64,
    ) -> Result<(), Error> {
        Self::check_seq(seq)?;
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        if seq <= g.retired_through {
            return Err(Error::Stale);
        }
        if seq <= g.issued_hi {
            let t = Self::ticket(g, seq)?;
            return if t.stream_slot == stream_slot && t.stream_generation == stream_generation {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if seq != g.issued_hi.checked_add(1).ok_or(Error::Exhausted)? {
            return Err(Error::Busy);
        }
        // 旧流有未退休记录时禁止复用其槽 (主§9.6.1, L4437–4438).
        if g.tickets
            .iter()
            .flatten()
            .any(|t| t.stream_slot == stream_slot && t.stream_generation != stream_generation)
        {
            return Err(Error::Conflict);
        }
        // 同一流只允许一个未绑定/在途请求 (主§9.6.1, L4438). A terminal but
        // unretired record still occupies its slot yet no longer blocks the
        // stream; UNKNOWN is unresolved and blocks fail-closed.
        if g.tickets.iter().flatten().any(|t| {
            t.stream_slot == stream_slot
                && t.stream_generation == stream_generation
                && !t.state.is_terminal()
        }) {
            return Err(Error::Busy);
        }
        let pos = g
            .tickets
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        g.tickets[pos] = Some(Ticket {
            seq,
            stream_slot,
            stream_generation,
            state: TicketState::Issued,
        });
        g.issued_hi = seq;
        Ok(())
    }
    /// ADMIT then persistent BOUND (model of the bind step). Rebinding an
    /// already-bound ticket is an idempotent state query.
    pub fn bind(&mut self, group: usize, generation: u32, seq: u64) -> Result<(), Error> {
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        let t = Self::ticket_mut(g, seq)?;
        match t.state {
            TicketState::Issued => {
                t.state = TicketState::Bound;
                Ok(())
            }
            TicketState::Bound => Ok(()),
            _ => Err(Error::Busy),
        }
    }
    /// COMPLETE v1 terminal transition with authoritative evidence supplied
    /// by the caller (native redo/FLUSH proof). Terminal states never regress;
    /// a different terminal for the same key is E_CONFLICT. An unbound ticket
    /// may only reach Cancelled (proof of no side effects is the caller's
    /// obligation); Bound/Unknown may reach any terminal.
    pub fn complete(
        &mut self,
        group: usize,
        generation: u32,
        seq: u64,
        terminal: TicketState,
    ) -> Result<(), Error> {
        if !terminal.is_terminal() {
            return Err(Error::Invalid);
        }
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        let t = Self::ticket_mut(g, seq)?;
        if t.state.is_terminal() {
            return if t.state == terminal {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if t.state == TicketState::Issued && terminal != TicketState::Cancelled {
            return Err(Error::Busy);
        }
        t.state = terminal;
        Ok(())
    }
    /// Non-terminal uncertainty: keeps the ticket, never retires it.
    pub fn uncertain(&mut self, group: usize, generation: u32, seq: u64) -> Result<(), Error> {
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        let t = Self::ticket_mut(g, seq)?;
        if !t.state.is_terminal() {
            t.state = TicketState::Unknown;
        }
        Ok(())
    }
    /// ACK/retire only a verified terminal at seq == retired_through+1
    /// (主§9.6.1, L4415–4417). Out-of-order ACK is EAGAIN (Busy); UNKNOWN and
    /// in-flight tickets can never retire, never redo on timeout.
    pub fn retire(&mut self, group: usize, generation: u32, seq: u64) -> Result<(), Error> {
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        let state = Self::ticket(g, seq)?.state;
        if state == TicketState::Unknown {
            return Err(Error::Unknown);
        }
        if !state.is_terminal() {
            return Err(Error::Busy);
        }
        if seq != g.retired_through.checked_add(1).ok_or(Error::Exhausted)? {
            return Err(Error::Busy);
        }
        let pos = g
            .tickets
            .iter()
            .position(|t| t.is_some_and(|t| t.seq == seq))
            .ok_or(Error::Stale)?;
        g.tickets[pos] = None;
        g.retired_through = seq;
        Ok(())
    }
    /// Generation-scoped query: a receipt is visible only inside its own
    /// group and generation; there is no cross-group lookup path.
    pub fn ticket_state(
        &self,
        group: usize,
        generation: u32,
        seq: u64,
    ) -> Result<TicketState, Error> {
        let g = self.group(group)?;
        Self::check_generation(g, generation)?;
        Ok(Self::ticket(g, seq)?.state)
    }
    pub fn tickets_in_use(&self, group: usize) -> Result<usize, Error> {
        Ok(self.group(group)?.tickets.iter().flatten().count())
    }
    /// Read-only recovery reconciliation (恢复角色可对账所有记录, 主§9.6.1
    /// L4490): continues even when the group's tickets are full, never
    /// consumes a ticket and never executes new work for a principal.
    pub fn recovery_query(&self, group: usize, seq: u64) -> Result<TicketState, Error> {
        Ok(Self::ticket(self.group(group)?, seq)?.state)
    }
    /// Volatile WRITE result admission (READ/READDIR/OPEN/CLOSE/WRITE class).
    /// Uses only the separate volatile result slots; never touches durable
    /// tickets (普通 WRITE 不消耗持久票据, 主§9.6.1 L4088).
    pub fn write_volatile(
        &mut self,
        group: usize,
        generation: u32,
        seq: u64,
        write_seq: u64,
    ) -> Result<(), Error> {
        Self::check_seq(seq)?;
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        if seq <= g.volatile_retired_through {
            return Err(Error::Stale);
        }
        if seq <= g.volatile_issued_hi {
            let row = g
                .volatile
                .iter()
                .flatten()
                .find(|r| r.seq == seq)
                .ok_or(Error::Conflict)?;
            return if row.write_seq == write_seq {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if seq
            != g.volatile_issued_hi
                .checked_add(1)
                .ok_or(Error::Exhausted)?
        {
            return Err(Error::Busy);
        }
        let pos = g
            .volatile
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        g.volatile[pos] = Some(VolatileResult { seq, write_seq });
        g.volatile_issued_hi = seq;
        Ok(())
    }
    /// Per-ACK continuous retirement of volatile results (终态可
    /// FILE_ACK_VOLATILE 连续退休, 主§9.6.1 L4085–4087). This is why ≥9
    /// sequential ACKed WRITEs fit the 8 volatile slots without any ticket.
    pub fn ack_volatile(&mut self, group: usize, generation: u32, seq: u64) -> Result<(), Error> {
        let g = self.group_mut(group)?;
        Self::check_generation(g, generation)?;
        if !g.volatile.iter().flatten().any(|r| r.seq == seq) {
            return Err(Error::Stale);
        }
        if seq
            != g.volatile_retired_through
                .checked_add(1)
                .ok_or(Error::Exhausted)?
        {
            return Err(Error::Busy);
        }
        let pos = g
            .volatile
            .iter()
            .position(|r| r.is_some_and(|r| r.seq == seq))
            .ok_or(Error::Stale)?;
        g.volatile[pos] = None;
        g.volatile_retired_through = seq;
        Ok(())
    }
    /// Persistently increment the group generation before enabling new work
    /// after restart (主§9.6.1, L4432–4434). Retained records stay queryable
    /// through recovery_query; new admissions must use the new generation.
    pub fn bump_generation(&mut self, group: usize) -> Result<u32, Error> {
        let g = self.group_mut(group)?;
        g.generation = g.generation.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(g.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap() -> FileCapability {
        FileCapability::from_registry(7, 2, 3, READ | WRITE | DIRECTORY)
    }
    #[test]
    fn sec_f01_rejects_escape_and_invalid_paths() {
        for path in [
            b"relative".as_slice(),
            b"/a/../b",
            b"/./b",
            b"/a//b",
            b"/a/",
            b"/a\0b",
        ] {
            assert_eq!(validate_absolute_path(path), Err(Error::Invalid));
        }
        assert_eq!(validate_absolute_path(b"/valid/path"), Ok(()));
    }
    #[test]
    fn native_path_guard_rejects_duplicate_slashes_nul_and_invalid_utf8() {
        assert_eq!(validate_absolute_path(b"/a//b"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/dir/"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/a\0b"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(&[b'/', 0xff]), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/a/b"), Ok(()));
    }
    #[test]
    fn sec_f02_capabilities_do_not_cross_owner_or_rights() {
        assert_eq!(cap().permits(8, 2, 3, READ), Err(Error::Unauthorized));
        assert_eq!(cap().permits(7, 2, 3, DELETE), Err(Error::Unauthorized));
        assert_eq!(cap().permits(7, 2, 3, READ), Ok(()));
    }
    #[test]
    fn sec_f03_stale_inode_generation_rejected() {
        assert_eq!(cap().permits(7, 2, 4, READ), Err(Error::Stale));
    }
    #[test]
    fn sec_f04_component_and_write_bounds() {
        let mut path = [b'a'; 65];
        path[0] = b'/';
        assert_eq!(validate_absolute_path(&path), Err(Error::Invalid));
        assert_eq!(MAX_WRITE, 65536);
    }
    #[test]
    fn sec_f05_commit_order_cannot_be_skipped() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        assert_eq!(
            t.advance(1, Stage::Reserved, Stage::CommitFlushed),
            Err(Error::Invalid)
        );
        assert_eq!(t.acknowledge_fsync(1), Err(Error::Unknown));
        t.advance(1, Stage::Reserved, Stage::RedoFlushed).unwrap();
        t.advance(1, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        t.advance(1, Stage::CommitFlushed, Stage::Visible).unwrap();
        assert_eq!(t.acknowledge_fsync(1), Ok(()));
    }
    #[test]
    fn sec_f06_lost_ack_preserves_id_and_rejects_new_body() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        t.uncertain(1).unwrap();
        assert_eq!(t.submit(1, [2; 32]), Ok(Stage::Unknown));
        assert_eq!(t.submit(1, [3; 32]), Err(Error::Conflict));
    }
    #[test]
    fn sec_f07_unknown_transaction_keeps_capacity() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        t.uncertain(1).unwrap();
        assert_eq!(t.submit(2, [4; 32]), Err(Error::Capacity));
    }
    #[test]
    fn sec_f08_boot_epoch_store_is_not_ordinary_file() {
        assert_eq!(cap().protected_store(7, 0, 1), Err(Error::Unauthorized));
        let system = FileCapability::from_registry(7, 0, 1, SYSTEM_STORE);
        assert_eq!(system.protected_store(7, 0, 1), Ok(()));
        assert_eq!(system.protected_store(8, 0, 1), Err(Error::Unauthorized));
    }
    #[test]
    fn v019_sec_f08_trusted_system_registry_scope_and_generation_required() {
        let malicious = FileCapability::from_registry(7, 2, 3, SYSTEM_STORE);
        assert_eq!(malicious.protected_store(7, 0, 1), Err(Error::Stale));
        let stale = FileCapability::from_registry(7, 0, 0, SYSTEM_STORE);
        assert_eq!(stale.protected_store(7, 0, 1), Err(Error::Stale));
    }

    // SEC-F07 (V0.19.9): D04 gear change × fsync concurrency. The legacy
    // sec_f07_unknown_transaction_keeps_capacity above keeps its V0.19 topic
    // (UNKNOWN capacity retention); these drills cover the stable-ID topic.

    fn flush_to_visible(ledger: &mut FsyncGearLedger<4>, txid: u64) {
        ledger
            .advance(txid, Stage::Reserved, Stage::RedoFlushed)
            .unwrap();
        ledger
            .advance(txid, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        ledger
            .advance(txid, Stage::CommitFlushed, Stage::Visible)
            .unwrap();
    }

    #[test]
    fn v0199_sec_f07_gear_candidates_baseline_and_version() {
        let mut gear = D04Gear::baseline();
        assert_eq!(
            (gear.readahead_pages(), gear.background_flush_pages()),
            (0, 4)
        );
        assert_eq!(gear.version(), 1);
        for (ra, flush) in D04_GEARS {
            assert!(gear.install(ra, flush).is_ok());
        }
        // Non-candidate pairs are rejected before any effect.
        for (ra, flush) in [(1, 4), (0, 8), (16, 31), (32, 64), (2, 4)] {
            assert_eq!(gear.install(ra, flush), Err(Error::Invalid));
        }
        // Reinstalling the current pair is a no-op, not a new version.
        let version = gear.version();
        gear.install(16, 32).unwrap();
        assert_eq!(gear.version(), version);
        gear.install(0, 4).unwrap();
        assert_eq!(gear.version(), version + 1);
    }

    #[test]
    fn v0199_sec_f07_midtransaction_gear_change_keeps_frozen_batch() {
        let mut ledger = FsyncGearLedger::<4>::new();
        let tx = ledger.begin().unwrap();
        let frozen = ledger.frozen_gear(tx).unwrap();
        assert_eq!(frozen, D04Gear::baseline());
        // Gear switches while the transaction is in every stage.
        ledger
            .advance(tx, Stage::Reserved, Stage::RedoFlushed)
            .unwrap();
        ledger.install_gear(16, 32).unwrap();
        assert_eq!(ledger.frozen_gear(tx).unwrap(), frozen);
        ledger
            .advance(tx, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        ledger.install_gear(2, 8).unwrap();
        assert_eq!(ledger.frozen_gear(tx).unwrap(), frozen);
        // The started transaction completes unsplit and uncancelled; the
        // background writeback gear never gates fsync completion.
        ledger
            .advance(tx, Stage::CommitFlushed, Stage::Visible)
            .unwrap();
        assert_eq!(ledger.acknowledge_fsync(tx), Ok(()));
        // Only transactions begun after the install see the new gear.
        let next = ledger.begin().unwrap();
        assert_eq!(
            ledger.frozen_gear(next).unwrap().background_flush_pages(),
            8
        );
        assert_ne!(
            ledger.frozen_gear(next).unwrap().version(),
            frozen.version()
        );
    }

    #[test]
    fn v0199_sec_f07_gear_change_cannot_reorder_durable_fsync() {
        let mut ledger = FsyncGearLedger::<4>::new();
        let first = ledger.begin().unwrap();
        let second = ledger.begin().unwrap();
        ledger.install_gear(16, 32).unwrap();
        // The newer transaction's redo/commit FLUSH evidence may arrive first,
        // but durable visibility stays in BEGIN order at the serial commit
        // point; a faster gear cannot overtake the older fsync.
        ledger
            .advance(second, Stage::Reserved, Stage::RedoFlushed)
            .unwrap();
        ledger
            .advance(second, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        assert_eq!(
            ledger.advance(second, Stage::CommitFlushed, Stage::Visible),
            Err(Error::Busy)
        );
        assert_eq!(ledger.acknowledge_fsync(second), Err(Error::Unknown));
        flush_to_visible(&mut ledger, first);
        assert_eq!(ledger.acknowledge_fsync(first), Ok(()));
        ledger
            .advance(second, Stage::CommitFlushed, Stage::Visible)
            .unwrap();
        assert_eq!(ledger.acknowledge_fsync(second), Ok(()));
    }

    #[test]
    fn v0199_sec_f07_unknown_older_fsync_blocks_newer_durable_ack() {
        let mut ledger = FsyncGearLedger::<4>::new();
        let first = ledger.begin().unwrap();
        let second = ledger.begin().unwrap();
        ledger.uncertain(first).unwrap();
        // Redo/commit stages are reachable, but the durable publication fails
        // closed while the older outcome is UNKNOWN (SEC-F 降级与失败路径).
        ledger
            .advance(second, Stage::Reserved, Stage::RedoFlushed)
            .unwrap();
        ledger
            .advance(second, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        assert_eq!(ledger.state(second), Ok(Stage::CommitFlushed));
        assert_eq!(
            ledger.advance(second, Stage::CommitFlushed, Stage::Visible),
            Err(Error::Unknown)
        );
        assert_eq!(ledger.acknowledge_fsync(second), Err(Error::Unknown));
        // UNKNOWN keeps its key and capacity; it is never silently dropped.
        assert_eq!(ledger.state(first), Ok(Stage::Unknown));
    }

    #[test]
    fn v0199_sec_f07_background_batch_keeps_metadata_closure_whole() {
        // Data selection shrinks to keep data + metadata within 128 homes.
        assert_eq!(background_batch_data_pages(32, 64, 120), Ok(8));
        assert_eq!(background_batch_data_pages(32, 64, 0), Ok(32));
        assert_eq!(background_batch_data_pages(32, 4, 0), Ok(4));
        assert_eq!(background_batch_data_pages(32, 64, 128), Ok(0));
        // An indivisible metadata closure over the cap cannot be split.
        assert_eq!(
            background_batch_data_pages(32, 64, 129),
            Err(Error::Capacity)
        );
        let mut ledger = FsyncGearLedger::<2>::new();
        assert_eq!(ledger.background_batch_pages(64, 120), Ok(4)); // baseline flush 4
        ledger.install_gear(16, 32).unwrap();
        assert_eq!(ledger.background_batch_pages(64, 120), Ok(8)); // new batch boundary
        // Background batch selection is not fsync evidence: the transaction
        // stage and durable ACK are untouched by writeback (主§9.6.1 L4484).
        let tx = ledger.begin().unwrap();
        ledger.background_batch_pages(64, 0).unwrap();
        assert_eq!(ledger.state(tx), Ok(Stage::Reserved));
        assert_eq!(ledger.acknowledge_fsync(tx), Err(Error::Unknown));
    }

    // SEC-F12 (V0.19.9): single-group receipt isolation.

    fn fill_group_tickets(ledger: &mut GroupReceiptLedger<2>, group: usize) {
        for seq in 1..=8u64 {
            ledger.alloc_durable(group, 1, seq - 1, 1, seq).unwrap();
            ledger.bind(group, 1, seq).unwrap();
        }
    }

    #[test]
    fn v0199_sec_f12_full_group_rejects_only_its_own_new_tickets() {
        let mut ledger = GroupReceiptLedger::<2>::new();
        fill_group_tickets(&mut ledger, 0);
        assert_eq!(ledger.tickets_in_use(0), Ok(8));
        // A terminal-but-unretired record frees its stream for a new request
        // while still occupying its slot: the ninth durable ticket of the
        // full group is rejected on quota...
        ledger.complete(0, 1, 1, TicketState::Done).unwrap();
        assert_eq!(ledger.alloc_durable(0, 1, 0, 1, 9), Err(Error::Capacity));
        // ...and reusing a stream slot with unretired records is refused too.
        assert_eq!(ledger.alloc_durable(0, 1, 0, 2, 9), Err(Error::Conflict));
        // ...while another group allocates and retires normally.
        ledger.alloc_durable(1, 1, 0, 1, 1).unwrap();
        ledger.bind(1, 1, 1).unwrap();
        ledger.complete(1, 1, 1, TicketState::Done).unwrap();
        ledger.retire(1, 1, 1).unwrap();
        assert_eq!(ledger.tickets_in_use(1), Ok(0));
        // Freeing one slot re-admits exactly one new ticket in the full group.
        ledger.complete(0, 1, 1, TicketState::Done).unwrap();
        ledger.retire(0, 1, 1).unwrap();
        ledger.alloc_durable(0, 1, 0, 2, 9).unwrap();
        assert_eq!(ledger.tickets_in_use(0), Ok(8));
    }

    #[test]
    fn v0199_sec_f12_volatile_writes_never_consume_persistent_tickets() {
        let mut ledger = GroupReceiptLedger::<2>::new();
        fill_group_tickets(&mut ledger, 0);
        // ≥9 sequential volatile WRITEs, each ACKed, while all 8 durable
        // tickets stay outstanding: per-ACK retirement reuses the 8 volatile
        // result slots and no WRITE touches the ticket ledger.
        for seq in 1..=12u64 {
            ledger.write_volatile(0, 1, seq, 100 + seq).unwrap();
            ledger.ack_volatile(0, 1, seq).unwrap();
        }
        assert_eq!(ledger.tickets_in_use(0), Ok(8));
        ledger.complete(0, 1, 1, TicketState::Done).unwrap();
        assert_eq!(ledger.alloc_durable(0, 1, 0, 1, 9), Err(Error::Capacity));
        // A retired volatile seq cannot be replayed as new (E_STALE).
        assert_eq!(ledger.write_volatile(0, 1, 12, 999), Err(Error::Stale));
        // Same-key different-body volatile retry is a conflict, not a redo.
        ledger.write_volatile(0, 1, 13, 7).unwrap();
        assert_eq!(ledger.write_volatile(0, 1, 13, 8), Err(Error::Conflict));
        assert_eq!(ledger.write_volatile(0, 1, 13, 7), Ok(()));
    }

    #[test]
    fn v0199_sec_f12_receipts_do_not_leak_across_groups_or_generations() {
        let mut ledger = GroupReceiptLedger::<2>::new();
        ledger.alloc_durable(0, 1, 3, 1, 1).unwrap();
        ledger.bind(0, 1, 1).unwrap();
        // Group 1 has no seq-1 record: no cross-group state is observable.
        assert_eq!(ledger.ticket_state(1, 1, 1), Err(Error::Stale));
        assert_eq!(ledger.retire(1, 1, 1), Err(Error::Stale));
        assert_eq!(
            ledger.complete(1, 1, 1, TicketState::Done),
            Err(Error::Stale)
        );
        // A stale group generation cannot act on or read current receipts.
        assert_eq!(ledger.ticket_state(0, 2, 1), Err(Error::Stale));
        assert_eq!(ledger.retire(0, 2, 1), Err(Error::Stale));
        // After a generation bump, old admissions are stale but retained
        // records remain reconcilable read-only by recovery.
        assert_eq!(ledger.bump_generation(0), Ok(2));
        assert_eq!(ledger.alloc_durable(0, 1, 4, 1, 2), Err(Error::Stale));
        assert_eq!(ledger.ticket_state(0, 1, 1), Err(Error::Stale));
        assert_eq!(ledger.recovery_query(0, 1), Ok(TicketState::Bound));
        ledger.alloc_durable(0, 2, 4, 1, 2).unwrap();
        // Out-of-range group indices are rejected, never aliased.
        assert_eq!(ledger.ticket_state(2, 1, 1), Err(Error::Invalid));
    }

    #[test]
    fn v0199_sec_f12_retirement_order_and_unknown_fail_closed() {
        let mut ledger = GroupReceiptLedger::<2>::new();
        ledger.alloc_durable(0, 1, 0, 1, 1).unwrap();
        ledger.alloc_durable(0, 1, 1, 1, 2).unwrap();
        ledger.bind(0, 1, 1).unwrap();
        ledger.bind(0, 1, 2).unwrap();
        // In-flight and UNKNOWN tickets never retire.
        assert_eq!(ledger.retire(0, 1, 1), Err(Error::Busy));
        ledger.uncertain(0, 1, 1).unwrap();
        assert_eq!(ledger.retire(0, 1, 1), Err(Error::Unknown));
        // Terminal but out-of-order ACK is EAGAIN, even with evidence.
        ledger.complete(0, 1, 2, TicketState::Done).unwrap();
        assert_eq!(ledger.retire(0, 1, 2), Err(Error::Busy));
        // UNKNOWN may later reach a terminal with real evidence, then retire
        // in watermark order; terminal states never regress.
        ledger.complete(0, 1, 1, TicketState::Done).unwrap();
        assert_eq!(
            ledger.complete(0, 1, 1, TicketState::Partial),
            Err(Error::Conflict)
        );
        ledger.retire(0, 1, 1).unwrap();
        ledger.retire(0, 1, 2).unwrap();
        // Retired watermarks reject old keys; gaps beyond issued_hi+1 wait.
        assert_eq!(ledger.alloc_durable(0, 1, 0, 2, 1), Err(Error::Stale));
        assert_eq!(ledger.alloc_durable(0, 1, 0, 2, 4), Err(Error::Busy));
        assert_eq!(ledger.alloc_durable(0, 1, 0, 2, 3), Ok(()));
        // seq bounds follow the 53-bit request_seq encoding.
        assert_eq!(ledger.alloc_durable(0, 1, 1, 2, 0), Err(Error::Invalid));
        assert_eq!(
            ledger.alloc_durable(0, 1, 1, 2, MAX_REQUEST_SEQ + 1),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn v0199_sec_f12_recovery_continues_while_group_is_full() {
        let mut ledger = GroupReceiptLedger::<2>::new();
        fill_group_tickets(&mut ledger, 0);
        ledger.uncertain(0, 1, 3).unwrap();
        // Recovery reconciliation reads every record without consuming a
        // ticket or executing new principal work, even at capacity.
        for seq in 1..=8u64 {
            assert!(ledger.recovery_query(0, seq).is_ok());
        }
        assert_eq!(ledger.recovery_query(0, 3), Ok(TicketState::Unknown));
        assert_eq!(ledger.tickets_in_use(0), Ok(8));
        ledger.complete(0, 1, 1, TicketState::Done).unwrap();
        assert_eq!(ledger.alloc_durable(0, 1, 0, 1, 9), Err(Error::Capacity));
        // Other groups keep allocating/retiring while group 0 is full.
        ledger.alloc_durable(1, 1, 0, 1, 1).unwrap();
        ledger.bind(1, 1, 1).unwrap();
        ledger.complete(1, 1, 1, TicketState::Done).unwrap();
        ledger.retire(1, 1, 1).unwrap();
        // A stream slot with unretired records cannot be reused by a new
        // stream generation (主§9.6.1 FileStreamIndex v4).
        assert_eq!(ledger.alloc_durable(0, 1, 0, 9, 9), Err(Error::Conflict));
    }
}
