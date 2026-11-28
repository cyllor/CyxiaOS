//! Two-boot verification of the signed ordinary FILE owner.

use super::{call, check, clock, exit, file_header, get, put, sha256, sleep_until, svc};

const DATA: &[u8; 8] = b"G1 write";
const LOGICAL_BYTES: &[u8] = b"G1 writeckpoint bytes\n";
const RECEIPT_ID: u64 = (1 << 56) | 1;
const RETRY: i64 = -13;

fn retry(endpoint: u64, cap: u64, request: &[u8], reply: &mut [u8]) -> i64 {
    loop {
        let code = call(endpoint, cap, request, reply);
        if code != RETRY {
            return code;
        }
        sleep_until(clock() + 1_000_000);
    }
}

fn retire_volatile(epoch: u64, endpoint: u64, id: u64, reply: &[u8]) {
    let mut ack = [0; 88];
    file_header(&mut ack, 15, id);
    put(&mut ack, 32, epoch);
    put(&mut ack, 40, get(reply, 16));
    put(&mut ack, 48, id);
    ack[56..].copy_from_slice(&reply[80..112]);
    check(retry(endpoint, 0, &ack, &mut [0; 128]) == 0, 40);
}

fn first_boot(epoch: u64, endpoint: u64, cap: u64) {
    let mut write = [0; 52];
    file_header(&mut write, 4, 1);
    write[40..44].copy_from_slice(&8u32.to_le_bytes());
    write[44..].copy_from_slice(DATA);
    let mut ack = [0; 128];
    check(call(endpoint, cap ^ 1, &write, &mut ack) != 0, 41);
    check(retry(endpoint, cap, &write, &mut ack) == 0, 42);
    check(
        get(&ack, 8) == 1
            && get(&ack, 120) == 1
            && ack[24..26] == [0; 2]
            && ack[40..64] == [0; 24]
            && get(&ack, 112) == 0,
        43,
    );
    retire_volatile(epoch, endpoint, 1, &ack);

    let mut alloc = [0; 48];
    file_header(&mut alloc, 10, 0);
    put(&mut alloc, 40, 1);
    let mut ticket = [0; 184];
    check(retry(endpoint, 0, &alloc, &mut ticket) == 0, 44);
    check(
        get(&ticket, 8) == RECEIPT_ID && ticket[128..] == receipt_key(),
        45,
    );

    let mut fsync = [0; 40];
    file_header(&mut fsync, 5, RECEIPT_ID);
    put(&mut fsync, 32, 2);
    check(call(endpoint, cap, &fsync, &mut ack) == -4, 46);
    put(&mut fsync, 32, 1);
    check(retry(endpoint, cap, &fsync, &mut ack) == 0, 47);
    check_terminal(&ack);
    verify_query(endpoint);
}

fn hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => exit(49),
    }
}

fn receipt_key() -> [u8; 56] {
    let uuid = env!("CYXIA_FIXTURE_FS_UUID_HEX").as_bytes();
    let mut key = [0; 56];
    for (slot, bytes) in key[..16].iter_mut().zip(uuid.chunks_exact(2)) {
        *slot = (hex(bytes[0]) << 4) | hex(bytes[1]);
    }
    put(&mut key, 16, 1);
    key[28..32].copy_from_slice(&1u32.to_le_bytes());
    put(&mut key, 40, 1);
    put(&mut key, 48, 1);
    key
}

fn check_terminal(reply: &[u8]) {
    let mut page = [0; 4096];
    page[..LOGICAL_BYTES.len()].copy_from_slice(LOGICAL_BYTES);
    check(
        get(reply, 8) == RECEIPT_ID
            && reply[24..26] == [3, 0]
            && reply[28..32] == [0; 4]
            && reply[32..36] == (LOGICAL_BYTES.len() as u32).to_le_bytes()
            && get(reply, 40) > 0
            && get(reply, 48) > 0
            && get(reply, 56) > 0
            && get(reply, 112) == RECEIPT_ID
            && get(reply, 120) == 1
            && reply[80..112] == sha256(&page),
        48,
    );
}

fn verify_query(endpoint: u64) {
    let mut query = [0; 88];
    file_header(&mut query, 11, RECEIPT_ID);
    query[32..].copy_from_slice(&receipt_key());
    let mut reply = [0; 128];
    check(retry(endpoint, 0, &query, &mut reply) == 0, 50);
    check_terminal(&reply);
}

pub(super) fn reader(epoch: u64, endpoint: u64, cap: u64) -> ! {
    if epoch == 1 {
        first_boot(epoch, endpoint, cap);
    } else {
        verify_query(endpoint);
        let mut read = [0; 44];
        file_header(&mut read, 3, 1);
        read[40..44].copy_from_slice(&8u32.to_le_bytes());
        let mut reply = [0; 136];
        check(
            retry(endpoint, cap, &read, &mut reply) == 0 && &reply[128..] == DATA,
            51,
        );
        retire_volatile(epoch, endpoint, 1, &reply);
    }
    super::idle();
}

fn receive(epoch: u64, seq: u64) -> ([u8; 552], usize) {
    let mut work = [0; 552];
    let selector = (epoch << 16) | 0xf201;
    let used = loop {
        let code = svc(0x31, [selector, work.as_mut_ptr() as u64, 552, 0, 1, seq]);
        if code != RETRY {
            break code;
        }
        sleep_until(clock() + 1_000_000);
    };
    check(
        (40..=552).contains(&used) && get(&work, 16) == seq && get(&work, 24) == epoch,
        60,
    );
    (work, used as usize)
}

fn ack_ipc(epoch: u64, seq: u64) {
    check(
        svc(0x31, [(epoch << 16) | 0xf201, 0, 0, 0, 2, seq]) == 0,
        61,
    );
}

fn admit(
    epoch: u64,
    endpoint: u64,
    work: &[u8],
    original: &[u8],
    rights: u64,
    version: u64,
    frozen: [u8; 32],
) -> (u64, [u8; 32]) {
    let context = get(work, 24);
    let mut admit = [0; 128];
    put(&mut admit, 0, 0x0080_0003_4359_5646);
    for (index, word) in [
        context,
        get(work, 48),
        get(work, 56),
        rights,
        1,
        version,
        get(work, 64),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut admit, 8 + index * 8, word);
    }
    admit[64..96].copy_from_slice(&frozen);
    let mut material = [0; 145];
    material[..17].copy_from_slice(b"CYX/FILE-ADMIT/v3");
    put(&mut material, 17, epoch);
    put(&mut material, 25, context);
    material[33..65].copy_from_slice(&sha256(original));
    material[65..145].copy_from_slice(&admit[16..96]);
    let operation = sha256(&material);
    admit[96..].copy_from_slice(&operation);
    let mut reply = [0; 48];
    check(
        call(endpoint, 0, &admit, &mut reply) == 0 && reply[16..18] == [1, 0],
        62,
    );
    (get(&reply, 32), operation)
}

fn complete(endpoint: u64, admission: u64, digest: [u8; 32]) -> i64 {
    let mut frame = [0; 56];
    put(&mut frame, 0, 0x0038_0001_4359_4643);
    put(&mut frame, 8, admission);
    put(&mut frame, 16, 1);
    frame[24..].copy_from_slice(&digest);
    call(endpoint, 0, &frame, &mut [0; 8])
}

fn volatile(epoch: u64, generation: u64, endpoint: u64, write: bool) {
    let (message, len) = receive(epoch, 1);
    let work = &message[40..len];
    let op = if write { 4 } else { 3 };
    check(
        work[8..10] == [op, 0] && get(work, 72) == generation && work[80..88] == *DATA,
        63,
    );
    let mut original = [0; 52];
    original[..44].copy_from_slice(&work[..44]);
    original[24..32].fill(0);
    let (domain, original_len, reply_len, frozen, rights): (&[u8], _, _, _, _) = if write {
        original[44..].copy_from_slice(DATA);
        (b"CYX/FILE-WRITE-EFFECT/v1", 52, 128, sha256(DATA), 1 << 9)
    } else {
        (b"CYX/FILE-READ-EFFECT/v1", 44, 136, [0; 32], 1 << 8)
    };
    let (admission, operation) = admit(
        epoch,
        endpoint,
        work,
        &original[..original_len],
        rights,
        1,
        frozen,
    );
    let mut reply = [0; 136];
    put(&mut reply, 0, 0x0080_0003_4359_4652);
    put(&mut reply, 8, 1);
    put(&mut reply, 16, generation);
    put(&mut reply, 72, get(work, 56));
    if write {
        put(&mut reply, 120, get(work, 88));
    } else {
        reply[36..40].copy_from_slice(&8u32.to_le_bytes());
        reply[128..].copy_from_slice(DATA);
    }
    let mut material = [0; 112];
    let length = domain.len();
    material[..length].copy_from_slice(domain);
    put(&mut material, length, epoch);
    put(&mut material, length + 8, generation);
    put(&mut material, length + 16, admission);
    material[length + 24..length + 56].copy_from_slice(&operation);
    material[length + 56..length + 88].copy_from_slice(&sha256(&reply[..reply_len]));
    check(
        complete(endpoint, admission, sha256(&material[..length + 88])) == 0,
        64,
    );
    ack_ipc(epoch, 1);
}

pub(super) fn service(epoch: u64, generation: u64, endpoint: u64) -> ! {
    volatile(epoch, generation, endpoint, epoch == 1);
    if epoch == 1 {
        let (message, len) = receive(epoch, 2);
        let work = &message[40..len];
        check(
            work[8..10] == [5, 0] && get(work, 16) == RECEIPT_ID && get(work, 32) == 1,
            65,
        );
        let mut original = [0; 40];
        original.copy_from_slice(&work[..40]);
        original[24..32].fill(0);
        let mut frozen = [0; 32];
        frozen.copy_from_slice(&work[80..112]);
        let (admission, _) = admit(epoch, endpoint, work, &original, 1 << 13, 2, frozen);
        check(complete(endpoint, admission, [1; 32]) == RETRY, 66);
        ack_ipc(epoch, 2);

        let (message, len) = receive(epoch, 3);
        let work = &message[40..len];
        check(&work[..8] == b"CYXFSYNC" && get(work, 8) == admission, 67);
        check_terminal(&work[48..]);
        let mut digest = [0; 32];
        digest.copy_from_slice(&work[16..48]);
        check(complete(endpoint, admission, [1; 32]) != 0, 68);
        check(complete(endpoint, admission, digest) == 0, 69);
        ack_ipc(epoch, 3);
    }
    sleep_until(clock() + 200_000_000);
    exit(0);
}
