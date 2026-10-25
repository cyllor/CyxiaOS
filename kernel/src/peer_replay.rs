//! Kernel-owned partner replay authority. The isolated TLS process transports
//! signed bytes; it cannot supply a CPU interval or a billing private key.
pub use cyxia_peer_billing::{Binding, TraceSeal, Exclusion};
use cyxia_prototype::{domains::{Error as DomainError, ObjectKey}, learning::{self,
    capture::RunKey, reward::{CpuClass, CpuCoverage, CpuInterval}}};
#[path = "peer_replay/ledger.rs"]
mod ledger;
#[path = "peer_replay/owner.rs"]
mod owner;
#[path = "../../user/prototype-cluster/src/replay_work.rs"]
pub(crate) mod work_wire;
pub use owner::{Attempt, attempt, family, finish, init, poll, transport, broker,
    prepare, bind_scope, start, close, release, set_pair_continuation, partner, retained_partner, copy_intervals, seal_packet_bytes, copy_seal_packet, attest, settled,
    local_ready, local_idle, fixture_stop_authorized, faulted_settled, take_work, finish_work, work_result, submit_work,
    accept_remote, abort_remote, close_remote, source_for};
pub use owner::{abort_prepared, abort_unactivated, release_prepared, prepared_packet_bytes, copy_prepared_packet};
pub use owner::{late_failure, copy_late_packet, late_archived};
pub use owner::{partner_bounded, copy_intervals_bounded};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartnerSeal { pub binding: Binding, pub seal: TraceSeal }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartnerEvidence { pub binding: Binding, pub seal: TraceSeal, pub exclusion: Option<Exclusion> }
/// A separately signed failure observed after the immutable CPU window closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LateFailureReceipt {
    key: RunKey, binding: Binding, failure: cyxia_peer_billing::Failure,
    packet_hash: [u8; 32], packet_bytes: usize, sequence: u64, closing_ns: u64,
}
impl LateFailureReceipt {
    pub const fn key(self) -> RunKey { self.key }
    pub const fn binding(self) -> Binding { self.binding }
    pub const fn failure(self) -> cyxia_peer_billing::Failure { self.failure }
    pub const fn packet_hash(self) -> [u8; 32] { self.packet_hash }
    pub const fn packet_bytes(self) -> usize { self.packet_bytes }
    pub const fn sequence(self) -> u64 { self.sequence }
    pub const fn closing_ns(self) -> u64 { self.closing_ns }
}
impl PartnerEvidence {
    pub fn packet_bytes(self) -> usize { if self.exclusion.is_some() { cyxia_peer_billing::EXCLUDED_PACKET_BYTES }
        else { cyxia_peer_billing::SEALED_PACKET_BYTES } }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, learning::Error> {
        match self.exclusion {
            Some(exclusion) => cyxia_peer_billing::ExcludedSeal { trace: self.seal, exclusion }.encode(out),
            None => self.seal.encode(out),
        }.map_err(|_| learning::Error::Evidence)
    }
}

pub const OWNER: ObjectKey = ObjectKey { id: 0x5045_4552_4249_4c4c, generation: 1 };
pub const REMOTE_WORK_OWNER: ObjectKey = ObjectKey { id: 0x5045_4552_574f_524b, generation: 1 };
pub const MAX_INTERVALS: usize = cyxia_peer_billing::MAX_INTERVALS;
pub const OWNED_BYTES: usize = owner::TOTAL_PAGES * 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub run: RunKey, pub id: u64, pub family: u16, pub kind: u16,
    pub arrived_ns: u64, pub deadline_ns: u64, pub seed: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkResult { pub id: u64, pub outcome: u64, pub target: ObjectKey,
    pub started_ns: u64, pub finished_ns: u64 }
