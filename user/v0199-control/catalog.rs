//! Independent EL0 client for the staged empty snapshot catalog.

use super::{call, put16, put32, put64, reject_startup, yield_now};
#[cfg(control_role = "6")]
use super::{clock, snapshot};

const ENDPOINT_CAP: u64 = 0x534e_4150_0000_0011;
const LIST_SELECTOR: u64 = 0x534e_4150_0000_0024;
const LIST: u16 = 0x24;
const REQUEST_BYTES: usize = 32;
const REPLY_BYTES: usize = 128;
const SENTINEL: u8 = 0xa5;
const E_AUTH: i64 = -1;
#[cfg(control_role = "11")]
const EXPECTED_SERVICE_GENERATION: u64 = 3;

fn request(op: u16, id: u64, auth_context_id: u64) -> [u8; REQUEST_BYTES] {
    let mut wire = [0; REQUEST_BYTES];
    put32(&mut wire, 0, 0x4359_4651);
    put16(&mut wire, 4, 4);
    put16(&mut wire, 6, REQUEST_BYTES as u16);
    put16(&mut wire, 8, op);
    put64(&mut wire, 16, id);
    put64(&mut wire, 24, auth_context_id);
    wire
}

fn invoke(selector: u64, request: *mut u8, request_len: usize, reply: *mut u8) -> i64 {
    call(
        0x50,
        [
            ENDPOINT_CAP,
            request as u64,
            request_len as u64,
            selector,
            reply as u64,
            REPLY_BYTES as u64,
        ],
    )
}

fn expect_refusal<const N: usize>(selector: u64, request: [u8; N], status: i64) {
    let mut wire = request;
    let mut reply = [SENTINEL; REPLY_BYTES];
    let outcome = invoke(selector, wire.as_mut_ptr(), N, reply.as_mut_ptr());
    if outcome != status || wire != request || reply.iter().any(|&byte| byte != SENTINEL) {
        reject_startup();
    }
}

#[cfg(control_role = "6")]
pub(super) fn probe_operations(cap: u64, target: u64) {
    loop {
        if clock() >= 0 && snapshot(cap, target, 1) == 0 {
            break;
        }
        yield_now();
    }
    expect_refusal(LIST_SELECTOR, request(LIST, 100, 0), E_AUTH);
    yield_now();
}

#[cfg(control_role = "11")]
fn expect_list(id: u64) {
    // Exercise ordinary nonoverlapping LIST buffers crossing adjacent stack
    // pages. Both spans start 16 bytes before distinct page boundaries.
    const PAGE: usize = 4096;
    let mut buffers = [SENTINEL; 2 * PAGE + REPLY_BYTES];
    let base = buffers.as_ptr() as usize;
    let start = (base + 16).next_multiple_of(PAGE) - base - 16;
    let (input, output) = buffers.split_at_mut(start + PAGE);
    let wire = &mut input[start..start + REQUEST_BYTES];
    let reply = &mut output[..REPLY_BYTES];
    wire.copy_from_slice(&request(LIST, id, 0));
    let outcome = invoke(
        LIST_SELECTOR,
        wire.as_mut_ptr(),
        REQUEST_BYTES,
        reply.as_mut_ptr(),
    );
    let mut expected = [0; REPLY_BYTES];
    put32(&mut expected, 0, 0x4359_4652);
    put16(&mut expected, 4, 3);
    put16(&mut expected, 6, REPLY_BYTES as u16);
    put64(&mut expected, 8, id);
    put64(&mut expected, 16, EXPECTED_SERVICE_GENERATION);
    put64(&mut expected, 72, 1);
    if outcome != 0 || reply != &expected {
        reject_startup();
    }
}

#[cfg(control_role = "11")]
fn expect_overlap_refusal() {
    const REPLY_OFFSET: usize = 16;
    let mut stack = [SENTINEL; REPLY_OFFSET + REPLY_BYTES];
    stack[..REQUEST_BYTES].copy_from_slice(&request(LIST, 6, 0));
    let expected = stack;
    // Both spans belong to this role's stack and share the last 16 request bytes.
    let base = stack.as_mut_ptr();
    let outcome = invoke(
        LIST_SELECTOR,
        base,
        REQUEST_BYTES,
        base.wrapping_add(REPLY_OFFSET),
    );
    if outcome != -12 || stack != expected {
        reject_startup();
    }
}

#[cfg(control_role = "11")]
pub(super) fn probe_supervisor() -> ! {
    // Return the completed audit turn before the first catalog request.
    yield_now();
    expect_refusal(LIST_SELECTOR, request(LIST, 1, 0), -13);
    #[cfg(snapshot_read_probe)]
    snapshot_read::probe_unready();
    yield_now();

    expect_refusal(LIST_SELECTOR ^ 1, request(LIST, 2, 0), E_AUTH);
    expect_refusal(LIST_SELECTOR, request(LIST, 3, 1), -2);
    let mut legacy = [0; 64];
    put32(&mut legacy, 0, 0x4359_4632);
    put16(&mut legacy, 4, 2);
    put16(&mut legacy, 6, 64);
    put16(&mut legacy, 8, LIST);
    put32(&mut legacy, 12, 64);
    put32(&mut legacy, 52, LIST_SELECTOR as u32);
    expect_refusal(LIST_SELECTOR, legacy, -3);
    expect_refusal(LIST_SELECTOR, request(0x20, 5, 0), -11);
    expect_overlap_refusal();
    expect_refusal(LIST_SELECTOR, [], -2);

    expect_list(10);
    expect_list(11);
    #[cfg(snapshot_read_probe)]
    snapshot_read::probe_active();
    // The stopped role has validated the active requests before retirement.
    yield_now();
    expect_refusal(LIST_SELECTOR, request(LIST, 12, 0), -4);
    #[cfg(snapshot_read_probe)]
    snapshot_read::probe_stale();
    loop {
        yield_now();
    }
}

#[cfg(all(control_role = "11", snapshot_read_probe))]
mod snapshot_read {
    use super::{
        E_AUTH, LIST_SELECTOR, REQUEST_BYTES, expect_refusal, put16, put32, put64, request,
    };

    const QUERY: u16 = 0x25;
    const HISTORY_OPEN: u16 = 0x26;
    const HISTORY_SELECTOR: u64 = 0x534e_4150_0000_0026;
    const E_FORMAT: i64 = -2;
    const E_STALE: i64 = -4;
    const STAGING_UUID: &[u8; 16] = b"CYX-W11-STAGING!";
    const FOREIGN_UUID: &[u8; 16] = b"CYX-W11-FOREIGN!";
    const LIVE_PATH: &[u8] = b"/readme.txt";
    const PREFIX_COLLISION_PATH: &[u8] = b"/readme.txtx";
    const QUERY_REQUEST_BYTES: usize = REQUEST_BYTES + 40;
    const HISTORY_PATH_OFFSET: usize = QUERY_REQUEST_BYTES + 8;

    fn request_with_key<const N: usize>(op: u16, id: u64, fs_uuid: &[u8; 16]) -> [u8; N] {
        let mut wire = [0; N];
        wire[..REQUEST_BYTES].copy_from_slice(&request(op, id, 0));
        put32(&mut wire, 12, (N - REQUEST_BYTES) as u32);
        let key = &mut wire[REQUEST_BYTES..QUERY_REQUEST_BYTES];
        key[..16].copy_from_slice(fs_uuid);
        put64(key, 16, 1);
        put64(key, 32, 1);
        wire
    }

    fn query_request(id: u64, fs_uuid: &[u8; 16]) -> [u8; QUERY_REQUEST_BYTES] {
        request_with_key(QUERY, id, fs_uuid)
    }

    fn history_request<const N: usize>(id: u64, path: &[u8]) -> [u8; N] {
        let mut wire = request_with_key(HISTORY_OPEN, id, STAGING_UUID);
        put16(&mut wire, QUERY_REQUEST_BYTES, path.len() as u16);
        wire[HISTORY_PATH_OFFSET..].copy_from_slice(path);
        wire
    }

    fn live_history_request(id: u64) -> [u8; HISTORY_PATH_OFFSET + LIVE_PATH.len()] {
        history_request(id, LIVE_PATH)
    }

    pub(super) fn probe_unready() {
        const E_AGAIN: i64 = -13;
        expect_refusal(LIST_SELECTOR, query_request(16, STAGING_UUID), E_AGAIN);
        expect_refusal(HISTORY_SELECTOR, live_history_request(17), E_AGAIN);
        expect_refusal(HISTORY_SELECTOR, query_request(18, STAGING_UUID), E_AUTH);
        expect_refusal(LIST_SELECTOR, live_history_request(19), E_AUTH);
    }

    pub(super) fn probe_active() {
        expect_refusal(LIST_SELECTOR, query_request(20, STAGING_UUID), E_AUTH);
        expect_refusal(HISTORY_SELECTOR, live_history_request(21), E_AUTH);
        expect_refusal(LIST_SELECTOR, query_request(22, FOREIGN_UUID), E_AUTH);
        expect_refusal(
            HISTORY_SELECTOR,
            history_request::<{ HISTORY_PATH_OFFSET + PREFIX_COLLISION_PATH.len() }>(
                23,
                PREFIX_COLLISION_PATH,
            ),
            E_AUTH,
        );
        expect_refusal(LIST_SELECTOR, live_history_request(24), E_AUTH);
        expect_refusal(HISTORY_SELECTOR, query_request(25, STAGING_UUID), E_AUTH);
        let mut malformed = query_request(26, STAGING_UUID);
        malformed[REQUEST_BYTES + 28] = 1;
        expect_refusal(LIST_SELECTOR, malformed, E_FORMAT);
    }

    pub(super) fn probe_stale() {
        expect_refusal(HISTORY_SELECTOR, live_history_request(27), E_STALE);
    }
}
