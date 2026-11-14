//! Latest public discovery observations. This bounded bank grants no rights;
//! independent capture must reconstruct the wire hint and TCP destination.
//! observed_ms records the latest change in public facts, not every idle poll.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_cluster_transport::tcp::{DiscoverySnapshot, State};
#[repr(C, align(64))]
struct Bank {
    words: [AtomicU64; 64],
}
#[used]
#[unsafe(no_mangle)]
static DISCOVERY_EVIDENCE: Bank = Bank {
    words: [const { AtomicU64::new(0) }; 64],
};
const _: () = assert!(core::mem::size_of::<Bank>() == 512);
pub(super) fn publish(boot: u64, epoch: u64, now: u64, state: Option<State>, s: DiscoverySnapshot) {
    let mut words = [0u64; 64];
    words[1] = 0x4359_4449_5343_3031;
    words[2] = 1;
    words[3] = boot;
    words[4] = epoch;
    words[5] = now;
    words[6] = s.counters.prepared;
    words[7] = s.sent;
    words[8] = s.counters.received;
    words[9] = s.counters.accepted;
    words[10] = s.counters.rejected;
    words[11] = s.candidates as u64;
    words[12] = s.attempts as u64;
    words[13] = s.counters.max_auth;
    words[20] = s.sent_ms;
    words[37] = s.selected_ms;
    words[39] = u32::from_be_bytes(s.local_ip) as u64;
    words[40] = s.local_port as u64;
    words[41] = s.next_ms;
    for (i, part) in s.sent_nonce.chunks_exact(8).enumerate() {
        words[21 + i] = u64::from_le_bytes(part.try_into().unwrap());
    }
    for (at, bytes) in [(23, s.local_node), (27, s.peer_node)] {
        for (i, part) in bytes.chunks_exact(8).enumerate() {
            words[at + i] = u64::from_le_bytes(part.try_into().unwrap());
        }
    }
    if let Some(a) = s.selected {
        words[14] = a.generation;
        words[15] = a.candidate_generation;
        words[16] = s.candidate_ms;
        words[17] = u32::from_be_bytes(a.ipv4) as u64;
        words[18] = a.port as u64;
        for (i, part) in a.nonce.chunks_exact(8).enumerate() {
            words[31 + i] = u64::from_le_bytes(part.try_into().unwrap());
        }
        for (i, part) in a.node.chunks_exact(8).enumerate() {
            words[33 + i] = u64::from_le_bytes(part.try_into().unwrap());
        }
    }
    words[38] = match state {
        Some(State::Established) => 2,
        Some(State::Listen | State::SynSent | State::SynReceived) => 1,
        _ => 3,
    };
    let bank = &DISCOVERY_EVIDENCE;
    // CPU0 is the sole writer. Compare every public field, including complete
    // nonce/NodeID bytes, before opening a publication. Only the observation
    // timestamp is excluded: an idle paid poll is not a discovery event.
    if bank.words[0].load(Ordering::Relaxed) != 0
        && (1..42)
            .filter(|&i| i != 5)
            .all(|i| bank.words[i].load(Ordering::Relaxed) == words[i])
    {
        return;
    }
    bank.words[0].fetch_add(1, Ordering::AcqRel);
    for (dst, value) in bank.words[1..].iter().zip(&words[1..]) {
        dst.store(*value, Ordering::Relaxed);
    }
    bank.words[0].fetch_add(1, Ordering::Release);
}
