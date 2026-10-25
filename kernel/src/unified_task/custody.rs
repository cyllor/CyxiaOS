//! Read-only task custody broker codec, shared with host boundary tests.
use cyxia_kernel_core::control_plane::task_admission::{Authority, CustodyKey};

pub struct Scope {
    pub boot: u64,
    pub requester: [u8; 32],
    pub state: u64,
    pub token: u64,
}
impl Scope {
    pub fn accepts(&self, boot: u64, requester: [u8; 32]) -> bool {
        boot != 0 && boot == self.boot && requester == self.requester
    }
}
pub fn query(
    authority: &Authority,
    scope: Scope,
    inventory: bool,
    payload: &mut [u8; 4096],
    len: usize,
) -> (u64, usize, u64) {
    let custody = if !inventory {
        if len != 120 {
            return (3, 0, 0);
        }
        let key = key(&payload[..120]);
        if !scope.accepts(key.owner_boot, key.requester) {
            return (3, 0, 0);
        }
        authority.custody(key)
    } else {
        // The shared ABI carries max(input length, output capacity).
        if len != 136 {
            return (3, 0, 0);
        }
        let boot = u64::from_le_bytes(payload[..8].try_into().unwrap());
        let requester = payload[8..40].try_into().unwrap();
        if !scope.accepts(boot, requester) {
            return (3, 0, 0);
        }
        authority.inventory(boot, requester)
    };
    let Ok(custody) = custody else {
        return (4, 0, 0);
    };
    if scope.state == 0 || custody.token != scope.token {
        return (4, 0, 0);
    }
    let at = if inventory {
        write_key(custody.key, &mut payload[..120]);
        120
    } else {
        0
    };
    payload[at..at + 8].copy_from_slice(&scope.state.to_le_bytes());
    payload[at + 8..at + 16].copy_from_slice(&u64::from(custody.started).to_le_bytes());
    (0, at + 16, custody.token)
}
pub fn key(bytes: &[u8]) -> CustodyKey {
    CustodyKey {
        owner_boot: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        cluster: bytes[8..40].try_into().unwrap(),
        requester: bytes[40..72].try_into().unwrap(),
        contract: bytes[72..88].try_into().unwrap(),
        request_hash: bytes[88..120].try_into().unwrap(),
    }
}
fn write_key(key: CustodyKey, out: &mut [u8]) {
    out[..8].copy_from_slice(&key.owner_boot.to_le_bytes());
    out[8..40].copy_from_slice(&key.cluster);
    out[40..72].copy_from_slice(&key.requester);
    out[72..88].copy_from_slice(&key.contract);
    out[88..120].copy_from_slice(&key.request_hash);
}
