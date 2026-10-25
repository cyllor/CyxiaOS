#[path = "../../../kernel/src/unified_task/custody.rs"]
mod custody;
use cyxia_kernel_core::control_plane::task_admission::{
    Authority, CustodyKey, StartRequest, Terms,
};

fn held() -> (Authority, u64, [u8; 120]) {
    let mut a = Authority::new();
    a.session(7, 1, 0).unwrap();
    a.session(7, 2, 0).unwrap();
    let key = CustodyKey {
        owner_boot: 1,
        cluster: [4; 32],
        requester: [5; 32],
        contract: [1; 16],
        request_hash: [6; 32],
    };
    let token = a
        .reserve_with_custody(
            Terms {
                cpu_milli: 100,
                memory_pages: 16,
                runtime_ms: 50,
                contract: [1; 16],
                input_hash: [2; 32],
                package_hash: [3; 32],
            },
            [3; 32],
            key,
            0,
        )
        .unwrap();
    a.grant(token, [1; 16], 1, 50, 0).unwrap();
    a.start(
        StartRequest {
            token,
            contract: [1; 16],
            grant: 1,
            deadline: 50,
            session: 7,
            input_hash: [2; 32],
        },
        1,
    )
    .unwrap();
    a.disconnect();
    let mut bytes = [0; 120];
    bytes[..8].copy_from_slice(&1u64.to_le_bytes());
    bytes[8..40].fill(4);
    bytes[40..72].fill(5);
    bytes[72..88].fill(1);
    bytes[88..].fill(6);
    (a, token, bytes)
}
fn scope(token: u64) -> custody::Scope {
    custody::Scope {
        boot: 1,
        requester: [5; 32],
        state: 4,
        token,
    }
}
#[test]
fn broker_inventory_uses_shared_request_capacity_and_returns_the_surviving_key() {
    let (a, token, key) = held();
    let mut payload = [0; 4096];
    payload[..8].copy_from_slice(&1u64.to_le_bytes());
    payload[8..40].fill(5);
    // broker::request publishes max(input.len(), output.len()), not input.len().
    assert_eq!(
        custody::query(&a, scope(token), true, &mut payload, 40usize.max(136)),
        (0, 136, token)
    );
    assert_eq!(payload[..120], key);
    assert_eq!(
        &payload[120..136],
        &[4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    );
}
#[test]
fn broker_exact_lookup_rejects_wrong_identity_and_never_mutates_admission() {
    let (a, token, key) = held();
    for at in [0, 8, 40, 72, 88, 120] {
        let mut payload = [0; 4096];
        payload[..120].copy_from_slice(&key);
        if at < 120 {
            payload[at] ^= 1;
        }
        let result = custody::query(&a, scope(token), false, &mut payload, 120);
        if at == 120 {
            assert_eq!(result, (0, 16, token));
            assert_eq!(
                &payload[..16],
                &[4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
            );
        } else {
            assert!(matches!(result, (3 | 4, 0, 0)));
        }
    }
    let mut payload = [0; 4096];
    payload[..120].copy_from_slice(&key);
    assert_eq!(
        custody::query(&a, scope(token + 1), false, &mut payload, 120),
        (4, 0, 0)
    );
    assert!(a.custody(custody::key(&key)).unwrap().started);
}
