//! Independently encoded FileService v4 requests from the Operations and Supervisor PIEs.

use super::{call, put16, put32, put64, reject_startup, yield_now};
#[cfg(control_role = "6")]
use super::{clock, snapshot};

const ENDPOINT: u64 = 0x4649_4c45_0000_0011;
const ROOT_SELECTOR: u64 = 0x4649_4c45_0000_0001;
const READDIR: u16 = 8;
const REQUEST_HEADER: usize = 32;
const REPLY_CAPACITY: usize = 256;
const SENTINEL: u8 = 0xa5;

fn request<const N: usize>(op: u16, id: u64) -> [u8; N] {
    let mut wire = [0; N];
    put32(&mut wire, 0, 0x4359_4651);
    put16(&mut wire, 4, 4);
    put16(&mut wire, 6, REQUEST_HEADER as u16);
    put16(&mut wire, 8, op);
    put32(&mut wire, 12, (N - REQUEST_HEADER) as u32);
    put64(&mut wire, 16, id);
    wire
}

fn readdir_request(id: u64) -> [u8; REQUEST_HEADER + 8] {
    let mut wire = request(READDIR, id);
    put16(&mut wire, REQUEST_HEADER + 4, 1);
    wire
}

fn invoke(selector: u64, request: *mut u8, len: usize, reply: *mut u8) -> i64 {
    call(
        0x50,
        [
            ENDPOINT,
            request as u64,
            len as u64,
            selector,
            reply as u64,
            REPLY_CAPACITY as u64,
        ],
    )
}

fn exchange<const N: usize>(
    selector: u64,
    request: [u8; N],
    reply: &mut [u8; REPLY_CAPACITY],
) -> i64 {
    let mut wire = request;
    let result = invoke(selector, wire.as_mut_ptr(), N, reply.as_mut_ptr());
    if wire != request {
        reject_startup();
    }
    result
}

fn expect_refusal<const N: usize>(selector: u64, request: [u8; N], status: i64) {
    let mut reply = [SENTINEL; REPLY_CAPACITY];
    if exchange(selector, request, &mut reply) != status
        || reply.iter().any(|&byte| byte != SENTINEL)
    {
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
    expect_refusal(ROOT_SELECTOR, readdir_request(100), -1);
    yield_now();
}

#[cfg(control_role = "11")]
pub(super) use supervisor::probe_supervisor;

#[cfg(control_role = "11")]
mod supervisor {
    use super::*;

    const OPEN: u16 = 2;
    const READ: u16 = 3;
    const WRITE: u16 = 4;
    const CLOSE: u16 = 6;
    const QUERY_VOLATILE: u16 = 14;
    const ACK_VOLATILE: u16 = 15;
    const FILE_READ: u32 = 1 << 8;
    #[cfg(file_volatile_write_probe)]
    const FILE_WRITE: u32 = 1 << 9;
    const REPLY_HEADER: usize = 128;
    const DIRENT_BYTES: usize = 128;
    const FILE_NAME: &[u8; 10] = b"readme.txt";
    const FILE_BYTES: &[u8; 29] = b"CyxiaOS V0.20 signed scratch\n";
    #[cfg(any(file_sessions_probe, file_volatile_write_probe))]
    const E_AUTH: i64 = -1;
    const E_FORMAT: i64 = -2;
    const E_STALE: i64 = -4;
    const E_CONFLICT: i64 = -5;
    #[cfg(not(file_volatile_write_probe))]
    const E_UNSUPPORTED: i64 = -11;
    const E_FAULT: i64 = -12;
    const E_AGAIN: i64 = -13;

    fn dirent() -> [u8; DIRENT_BYTES] {
        let mut wire = [0; DIRENT_BYTES];
        put32(&mut wire, 0, 1);
        put16(&mut wire, 4, FILE_NAME.len() as u16);
        put64(&mut wire, 8, 1);
        wire[16..16 + FILE_NAME.len()].copy_from_slice(FILE_NAME);
        let mut crc = !0u32;
        for byte in wire {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            }
        }
        put32(&mut wire, 124, !crc);
        wire
    }

    fn open_request(
        id: u64,
        listing: &[u8; REPLY_CAPACITY],
        rights: u32,
    ) -> [u8; REQUEST_HEADER + 20] {
        let dirent = &listing[REPLY_HEADER..];
        let mut wire = request(OPEN, id);
        wire[32..34].copy_from_slice(&dirent[4..6]);
        wire[34..44].copy_from_slice(&dirent[16..26]);
        put32(&mut wire, 44, rights);
        wire
    }

    fn read_request(id: u64, offset: u64, len: u32) -> [u8; REQUEST_HEADER + 12] {
        let mut wire = request(READ, id);
        put64(&mut wire, REQUEST_HEADER, offset);
        put32(&mut wire, REQUEST_HEADER + 8, len);
        wire
    }

    fn write_request<const N: usize>(id: u64, offset: u64, bytes: &[u8]) -> [u8; N] {
        let mut wire = request(WRITE, id);
        put64(&mut wire, REQUEST_HEADER, offset);
        put32(&mut wire, REQUEST_HEADER + 8, bytes.len() as u32);
        wire[REQUEST_HEADER + 12..].copy_from_slice(bytes);
        wire
    }

    fn receipt_request<const N: usize>(op: u16, boot: u64, id: u64) -> [u8; N] {
        let mut wire = request(op, id);
        put64(&mut wire, REQUEST_HEADER, boot);
        put64(&mut wire, REQUEST_HEADER + 8, boot);
        put64(&mut wire, REQUEST_HEADER + 16, id);
        wire
    }

    fn ack_request(boot: u64, id: u64, digest: &[u8; 32]) -> [u8; 88] {
        let mut wire = receipt_request(ACK_VOLATILE, boot, id);
        wire[56..].copy_from_slice(digest);
        wire
    }

    fn acknowledge(boot: u64, id: u64, digest: &[u8; 32]) {
        let reply = success(0, ack_request(boot, id, digest));
        expect_reply(&reply, boot, id, 0, 0, &[], digest);
    }

    fn success<const N: usize>(selector: u64, request: [u8; N]) -> [u8; REPLY_CAPACITY] {
        let mut reply = [SENTINEL; REPLY_CAPACITY];
        if exchange(selector, request, &mut reply) != 0 {
            reject_startup();
        }
        reply
    }

    fn reply_frame(
        boot: u64,
        id: u64,
        target_generation: u64,
        new_cap: u64,
        output: &[u8],
        digest: &[u8; 32],
    ) -> [u8; REPLY_CAPACITY] {
        let mut expected = [SENTINEL; REPLY_CAPACITY];
        expected[..REPLY_HEADER].fill(0);
        put32(&mut expected, 0, 0x4359_4652);
        put16(&mut expected, 4, 3);
        put16(&mut expected, 6, REPLY_HEADER as u16);
        put64(&mut expected, 8, id);
        put64(&mut expected, 16, boot);
        put32(&mut expected, 36, output.len() as u32);
        put64(&mut expected, 64, new_cap);
        put64(&mut expected, 72, target_generation);
        expected[80..112].copy_from_slice(digest);
        for (dest, &byte) in expected[REPLY_HEADER..].iter_mut().zip(output) {
            *dest = byte;
        }
        expected
    }

    fn expect_reply(
        wire: &[u8; REPLY_CAPACITY],
        boot: u64,
        id: u64,
        target_generation: u64,
        new_cap: u64,
        output: &[u8],
        digest: &[u8; 32],
    ) {
        if wire != &reply_frame(boot, id, target_generation, new_cap, output, digest) {
            reject_startup();
        }
    }

    fn reply_digest(wire: &[u8; REPLY_CAPACITY]) -> [u8; 32] {
        let mut digest = [0; 32];
        digest.copy_from_slice(&wire[80..112]);
        if digest == [0; 32] {
            reject_startup();
        }
        digest
    }

    fn expect_file_reply(
        wire: &[u8; REPLY_CAPACITY],
        boot: u64,
        id: u64,
        new_cap: u64,
        output: &[u8],
    ) -> [u8; 32] {
        let digest = reply_digest(wire);
        expect_reply(wire, boot, id, 1, new_cap, output, &digest);
        digest
    }

    #[cfg(file_volatile_write_probe)]
    fn expect_write_reply(wire: &[u8; REPLY_CAPACITY], boot: u64, id: u64, seq: u64) -> [u8; 32] {
        let digest = reply_digest(wire);
        let mut expected = reply_frame(boot, id, 1, 0, &[], &digest);
        put64(&mut expected, 120, seq);
        if wire != &expected {
            reject_startup();
        }
        digest
    }

    fn expect_open_reply(wire: &[u8; REPLY_CAPACITY], boot: u64, id: u64) -> (u64, [u8; 32]) {
        let mut cap_wire = [0; 8];
        cap_wire.copy_from_slice(&wire[64..72]);
        let child = u64::from_le_bytes(cap_wire);
        if child == 0 || child == ROOT_SELECTOR {
            reject_startup();
        }
        (child, expect_file_reply(wire, boot, id, child, &[]))
    }

    fn expect_overlap_refusal() {
        const REPLY_OFFSET: usize = 16;
        let mut stack = [SENTINEL; REPLY_OFFSET + REPLY_CAPACITY];
        let request = readdir_request(10);
        stack[..request.len()].copy_from_slice(&request);
        let expected = stack;
        let base = stack.as_mut_ptr();
        let result = invoke(
            ROOT_SELECTOR,
            base,
            request.len(),
            base.wrapping_add(REPLY_OFFSET),
        );
        if result != E_FAULT || stack != expected {
            reject_startup();
        }
    }

    #[cfg(file_volatile_write_probe)]
    fn probe_volatile_write(listed: &[u8; REPLY_CAPACITY], boot: u64) {
        const REPLACEMENT: &[u8; 4] = b"WAVE";
        let opened = success(
            ROOT_SELECTOR,
            open_request(12, listed, FILE_READ | FILE_WRITE),
        );
        let (child, opened_digest) = expect_open_reply(&opened, boot, 12);

        expect_refusal(child, write_request::<48>(13, 28, REPLACEMENT), E_FORMAT);
        let first_request = write_request::<48>(13, 0, REPLACEMENT);
        let written = success(child, first_request);
        let written_digest = expect_write_reply(&written, boot, 13, 1);

        let mut changed = *FILE_BYTES;
        changed[..REPLACEMENT.len()].copy_from_slice(REPLACEMENT);
        let read = success(child, read_request(14, 0, 64));
        let changed_digest = expect_file_reply(&read, boot, 14, 0, &changed);

        let original_prefix = &FILE_BYTES[..REPLACEMENT.len()];
        expect_refusal(
            child,
            write_request::<48>(13, 0, original_prefix),
            E_CONFLICT,
        );
        let restored = success(child, write_request::<48>(15, 0, original_prefix));
        let restored_digest = expect_write_reply(&restored, boot, 15, 2);
        if success(child, first_request) != written {
            reject_startup();
        }
        let read = success(child, read_request(16, 0, 64));
        let original_digest = expect_file_reply(&read, boot, 16, 0, FILE_BYTES);

        let closed = success(child, request::<36>(CLOSE, 17));
        let closed_digest = expect_file_reply(&closed, boot, 17, 0, &[]);
        expect_refusal(child, write_request::<48>(18, 0, REPLACEMENT), E_STALE);
        expect_refusal(
            ROOT_SELECTOR,
            write_request::<48>(19, 0, REPLACEMENT),
            E_AUTH,
        );

        let digests = [
            opened_digest,
            written_digest,
            changed_digest,
            restored_digest,
            original_digest,
            closed_digest,
        ];
        for (id, digest) in (12..=17).zip(digests) {
            acknowledge(boot, id, &digest);
        }
    }

    #[cfg(file_sessions_probe)]
    fn probe_sessions(listed: &[u8; REPLY_CAPACITY], boot: u64, previous_child: u64) -> [u64; 4] {
        let mut children = [0; 4];
        let mut open_digests = [[0; 32]; 4];
        for slot in 0..children.len() {
            let id = 20 + slot as u64;
            let opened = success(ROOT_SELECTOR, open_request(id, listed, FILE_READ));
            let (child, digest) = expect_open_reply(&opened, boot, id);
            if child == previous_child || children[..slot].contains(&child) {
                reject_startup();
            }
            children[slot] = child;
            open_digests[slot] = digest;
        }
        let [first, second, third, fourth] = children;

        expect_refusal(ROOT_SELECTOR, open_request(24, listed, FILE_READ), E_AGAIN);
        let full_request = read_request(24, 0, 64);
        let full = success(second, full_request);
        let full_digest = expect_file_reply(&full, boot, 24, 0, FILE_BYTES);

        let first_open = open_request(20, listed, FILE_READ);
        let replay = success(ROOT_SELECTOR, first_open);
        expect_reply(&replay, boot, 20, 1, first, &[], &open_digests[0]);
        if full != success(second, full_request) {
            reject_startup();
        }
        expect_refusal(third, full_request, E_CONFLICT);
        expect_refusal(0, ack_request(boot, 24, &full_digest), E_AGAIN);

        let closed = success(first, request::<36>(CLOSE, 25));
        let closed_digest = expect_file_reply(&closed, boot, 25, 0, &[]);
        expect_refusal(ROOT_SELECTOR, first_open, E_STALE);
        let partial_request = read_request(26, 2, 10);
        expect_refusal(first, partial_request, E_STALE);
        let partial = success(second, partial_request);
        let partial_digest = expect_file_reply(&partial, boot, 26, 0, &FILE_BYTES[2..12]);

        let opened = success(ROOT_SELECTOR, open_request(27, listed, FILE_READ));
        let (replacement, replacement_digest) = expect_open_reply(&opened, boot, 27);
        if replacement == previous_child || children.contains(&replacement) {
            reject_startup();
        }

        // Eight receipts are held until the oldest is acknowledged.
        let retry = read_request(28, 0, 64);
        expect_refusal(ROOT_SELECTOR, retry, E_AUTH);
        expect_refusal(replacement, retry, E_AGAIN);
        let remaining_digests = [
            full_digest,
            closed_digest,
            partial_digest,
            replacement_digest,
        ];
        for (id, digest) in (20..=27).zip(open_digests.into_iter().chain(remaining_digests)) {
            acknowledge(boot, id, &digest);
        }
        let reply = success(replacement, retry);
        let digest = expect_file_reply(&reply, boot, 28, 0, FILE_BYTES);
        acknowledge(boot, 28, &digest);

        [second, third, fourth, replacement]
    }

    pub(crate) fn probe_supervisor() {
        // Return the completed audit turn before the first file request.
        yield_now();
        expect_refusal(ROOT_SELECTOR, readdir_request(1), E_AGAIN);
        yield_now();

        let listed = success(ROOT_SELECTOR, readdir_request(1));
        // The file service is bound to the volume's confirmed BootEpoch.
        let mut boot_wire = [0; 8];
        boot_wire.copy_from_slice(&listed[16..24]);
        let boot = u64::from_le_bytes(boot_wire);
        if boot == 0 {
            reject_startup();
        }
        let listed_digest = expect_file_reply(&listed, boot, 1, 0, &dirent());

        let opened = success(ROOT_SELECTOR, open_request(2, &listed, FILE_READ));
        let (child, opened_digest) = expect_open_reply(&opened, boot, 2);

        let full_request = read_request(3, 0, 64);
        let full = success(child, full_request);
        let full_digest = expect_file_reply(&full, boot, 3, 0, FILE_BYTES);
        if full != success(child, full_request) {
            reject_startup();
        }
        expect_refusal(child, read_request(3, 1, 64), E_CONFLICT);

        let query = success(0, receipt_request::<56>(QUERY_VOLATILE, boot, 3));
        expect_reply(&query, boot, 3, 0, 0, &[], &full_digest);
        for (id, digest) in [(1, listed_digest), (2, opened_digest), (3, full_digest)] {
            acknowledge(boot, id, &digest);
        }

        let partial = success(child, read_request(4, 2, 10));
        let _partial_digest = expect_file_reply(&partial, boot, 4, 0, &FILE_BYTES[2..12]);
        let eof = success(child, read_request(5, FILE_BYTES.len() as u64, 1));
        let _eof_digest = expect_file_reply(&eof, boot, 5, 0, &[]);

        let write = write_request::<45>(8, 0, b"X");
        #[cfg(file_volatile_write_probe)]
        expect_refusal(child, write, E_AUTH);
        #[cfg(not(file_volatile_write_probe))]
        expect_refusal(child, write, E_UNSUPPORTED);
        let mut forged = readdir_request(9);
        put64(&mut forged, 24, 1);
        expect_refusal(ROOT_SELECTOR, forged, E_FORMAT);
        expect_overlap_refusal();

        let closed = success(child, request::<36>(CLOSE, 6));
        let _closed_digest = expect_file_reply(&closed, boot, 6, 0, &[]);
        expect_refusal(child, read_request(7, 0, 1), E_STALE);

        // Return the completed Wave 18 turn before continuing or revoking.
        yield_now();
        #[cfg(any(file_sessions_probe, file_volatile_write_probe))]
        for (id, digest) in [(4, _partial_digest), (5, _eof_digest), (6, _closed_digest)] {
            acknowledge(boot, id, &digest);
        }
        #[cfg(file_volatile_write_probe)]
        {
            probe_volatile_write(&listed, boot);
            yield_now();
        }
        #[cfg(file_sessions_probe)]
        let survivors = {
            let survivors = probe_sessions(&listed, boot, child);
            yield_now();
            survivors
        };
        expect_refusal(ROOT_SELECTOR, readdir_request(100), E_STALE);
        #[cfg(file_sessions_probe)]
        for (id, child) in (101..=104).zip(survivors) {
            expect_refusal(child, read_request(id, 0, 1), E_STALE);
        }
        yield_now();
    }
}
