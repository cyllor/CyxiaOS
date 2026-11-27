//! Bounded SEC-F12 checks of group credit, acknowledged WRITE and receipt homes.
//! The trace is checked by an independent state and wire oracle. The mount
//! and durable after-images in this host harness are explicit fixture inputs.
use cyxia_kernel_core::security::{
    Error,
    file::{GroupReceiptLedger, TicketState},
    file_format_v1::{SCRATCH_FILE_DATA, SCRATCH_FILE_NAME, SCRATCH_WRITABLE_FILE_OWNER_RIGHTS},
    file_index_v0199::{FileStreamIndexV4, GroupIndex, StreamIndex},
    file_media_v0199::{FileReceiptV4, crc32c_zeroed, local_request_id},
    file_read_v4::{FileReadService, MAX_REPLY, ROOT_SELECTOR, StagedFile},
    file_receipt_store_v0199::{
        BLOCK_BYTES, RECEIPT_BYTES, RECEIPT_STORE_BYTES, home_closure, scan_receipts_with_index,
        verify_single_ack_transition,
    },
    file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION, Reply},
    offline_config_v1::Principal,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    io::{self, BufWriter, Write},
};

const UUID: [u8; 16] = [0x46; 16];
const OWNER_A: u64 = 101;
const WRITE_COUNT: u64 = 10;
const A: usize = 0;
const B: usize = 1;
const ACKS: &[&str] = &[
    "exact",
    "missing_index",
    "missing_home",
    "wrong_principal",
    "no_commit",
];

fn put<const N: usize>(b: &mut [u8], at: usize, v: [u8; N]) {
    b[at..at + N].copy_from_slice(&v);
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn status<T: Debug, E: Debug>(r: Result<T, E>) -> String {
    r.map_or_else(|e| format!("err_{e:?}"), |v| format!("ok_{v:?}"))
}
fn request(op: u16, id: u64, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0; REQUEST_HEADER + payload.len()];
    put(&mut b, 0, REQUEST_MAGIC.to_le_bytes());
    put(&mut b, 4, REQUEST_VERSION.to_le_bytes());
    put(&mut b, 6, (REQUEST_HEADER as u16).to_le_bytes());
    put(&mut b, 8, op.to_le_bytes());
    put(&mut b, 12, (payload.len() as u32).to_le_bytes());
    put(&mut b, 16, id.to_le_bytes());
    b[REQUEST_HEADER..].copy_from_slice(payload);
    b
}
fn custody(op: u16, id: u64, boot: u64, generation: u64, digest: &[u8]) -> Vec<u8> {
    let mut p = boot.to_le_bytes().to_vec();
    p.extend_from_slice(&generation.to_le_bytes());
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(digest);
    request(op, id, &p)
}
fn rejected(service: &mut FileReadService, selector: u64, frame: &[u8]) -> String {
    let mut out = [0xa5; MAX_REPLY];
    let observed = status(service.serve(selector, frame, &mut out).map(|_| ()));
    assert_eq!(out, [0xa5; MAX_REPLY]);
    observed
}
fn read_service(generation: u32) -> FileReadService {
    let mut entry = [0; 128];
    put(&mut entry, 0, 1u32.to_le_bytes());
    put(
        &mut entry,
        4,
        (SCRATCH_FILE_NAME.len() as u16).to_le_bytes(),
    );
    put(&mut entry, 8, 1u64.to_le_bytes());
    entry[16..16 + SCRATCH_FILE_NAME.len()].copy_from_slice(SCRATCH_FILE_NAME);
    let crc = crc32c_zeroed(&entry, 124).unwrap();
    put(&mut entry, 124, crc.to_le_bytes());
    FileReadService::new(
        StagedFile::new_with_owner_rights(
            u64::from(generation),
            Principal {
                id: OWNER_A,
                generation: u64::from(generation),
            },
            entry,
            *SCRATCH_FILE_DATA,
            SCRATCH_WRITABLE_FILE_OWNER_RIGHTS,
        )
        .unwrap(),
    )
}
fn volatile_writes(group: &mut GroupReceiptLedger<2>, generation: u32) -> (String, String) {
    let boot = u64::from(generation);
    let mut service = read_service(generation);
    let mut out = [0; MAX_REPLY];
    let mut open = (SCRATCH_FILE_NAME.len() as u16).to_le_bytes().to_vec();
    open.extend_from_slice(SCRATCH_FILE_NAME);
    open.extend_from_slice(&SCRATCH_WRITABLE_FILE_OWNER_RIGHTS.to_le_bytes());
    open.extend_from_slice(&[0; 4]);
    let served = service
        .serve(ROOT_SELECTOR, &request(2, 1, &open), &mut out)
        .unwrap();
    let opened = Reply::decode(&out[..served.len]).unwrap();
    let child = opened.new_cap_selector;
    let ack = custody(15, 1, boot, boot, &opened.result_digest);
    service.serve(0, &ack, &mut out).unwrap();

    let mut events = Vec::new();
    for write in 1..=WRITE_COUNT {
        let id = write + 1;
        let mut payload = (write - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.push(b'0' + (write - 1) as u8);
        let frame = request(4, id, &payload);
        let record = service.serve(child, &frame, &mut out).unwrap();
        let reply = Reply::decode(&out[..record.len]).unwrap();
        let seq = reply.write_seq;
        let digest = reply.result_digest;
        let quota = status(group.write_volatile(A, generation, write, seq));
        let retry = service.serve(child, &frame, &mut out).unwrap();
        let query = service
            .serve(0, &custody(14, id, boot, boot, &[]), &mut out)
            .unwrap();
        let query_digest = Reply::decode(&out[..query.len]).unwrap().result_digest;
        let empty_wrong = rejected(&mut service, 0, &custody(15, id, boot, boot - 1, &digest));
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        let bad_ack = rejected(&mut service, 0, &custody(15, id, boot, boot, &wrong_digest));
        let waiting = service.retained_count();
        let ack = service
            .serve(0, &custody(15, id, boot, boot, &digest), &mut out)
            .unwrap();
        let ack_digest = Reply::decode(&out[..ack.len]).unwrap().result_digest;
        let ack_quota = status(group.ack_volatile(A, generation, write));
        let replay_retired = rejected(&mut service, child, &frame);
        let quota_retired = status(group.write_volatile(A, generation, write, seq));
        events.push(format!(
            "{id},{seq},{},{},{},{quota},{empty_wrong},{bad_ack},{waiting},{ack_quota},{replay_retired},{quota_retired},{},{},{},{}",
            hex(&digest),
            hex(&query_digest),
            hex(&ack_digest),
            u8::from(retry.replay),
            service.retained_count(),
            service.write_sequence(),
            group.tickets_in_use(A).unwrap(),
        ));
    }
    let mut range = 0u64.to_le_bytes().to_vec();
    range.extend_from_slice(&(SCRATCH_FILE_DATA.len() as u32).to_le_bytes());
    let id = WRITE_COUNT + 2;
    let read = service
        .serve(child, &request(3, id, &range), &mut out)
        .unwrap();
    let reply = Reply::decode(&out[..read.len]).unwrap();
    let read_bytes = hex(reply.output);
    let ack = custody(15, id, boot, boot, &reply.result_digest);
    service.serve(0, &ack, &mut out).unwrap();
    assert_eq!(service.retained_count(), 0);
    (events.join(";"), read_bytes)
}

fn state_code(state: TicketState) -> u16 {
    match state {
        TicketState::Bound => 2,
        TicketState::Done => 3,
        TicketState::Unknown => 5,
        _ => unreachable!(),
    }
}
fn media_receipt(stream: u64, seq: u64, generation: u32, status: u16) -> FileReceiptV4 {
    let done = status == 3;
    FileReceiptV4 {
        fs_uuid: UUID,
        issued_boot_epoch: u64::from(generation),
        group_id: 0,
        group_generation: generation,
        stream_slot: stream,
        stream_generation: if seq == 1 { 1 } else { 2 },
        request_seq: seq,
        log_epoch: u64::from(done),
        txid: if done { 11 } else { 0 },
        commit_lsn: if done { 13 } else { 0 },
        write_seq: 0,
        status,
        result: 0,
        completed_prefix: 0,
        operation_digest: if status == 1 { [0; 32] } else { [6; 32] },
        output_digest: if done { [7; 32] } else { [0; 32] },
        request_id: local_request_id(0, stream, seq).unwrap(),
        owner_principal_id: OWNER_A,
    }
}
fn encode_index(index: &FileStreamIndexV4) -> [u8; BLOCK_BYTES] {
    let mut raw = [0; BLOCK_BYTES];
    index.encode_into(&mut raw).unwrap();
    raw
}
fn image_hash(data: &[u8], index: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.update(index);
    hex(&h.finalize())
}
fn receipt_image(
    primary: usize,
    generation: u32,
    head: TicketState,
) -> ([u8; RECEIPT_STORE_BYTES], FileStreamIndexV4) {
    let mut data = [0; RECEIPT_STORE_BYTES];
    let empty = StreamIndex {
        generation: 0,
        flags: 0,
        issued_hi: 0,
        retired_through: 0,
    };
    let mut index = FileStreamIndexV4 {
        fs_uuid: UUID,
        global_request_id_hi: 0,
        generation: 10,
        groups: core::array::from_fn(|i| GroupIndex {
            generation: if i == 0 {
                generation
            } else {
                u32::from(i == 1)
            },
            flags: u32::from(i < 2),
            boot_epoch: if i == 0 {
                u64::from(generation)
            } else {
                u64::from(i == 1)
            },
            manifest_principal_id: OWNER_A + i as u64,
        }),
        streams: [empty; 128],
    };
    for stream in 0..8 {
        index.streams[stream] = StreamIndex {
            generation: 1,
            flags: 1,
            issued_hi: 1,
            retired_through: 0,
        };
        let slot = if stream == 0 { primary } else { 8 + stream };
        let status = if stream == 0 {
            state_code(head)
        } else if stream == 7 {
            3
        } else {
            2
        };
        let at = slot * RECEIPT_BYTES;
        data[at..at + RECEIPT_BYTES]
            .copy_from_slice(&media_receipt(stream as u64, 1, 1, status).encode().unwrap());
    }
    // Group B's own completed ticket is already retired in this media view.
    index.streams[8] = StreamIndex {
        generation: 1,
        flags: 1,
        issued_hi: 1,
        retired_through: 1,
    };
    (data, index)
}
fn media(primary: usize, generation: u32, head: TicketState, shape: &str) -> String {
    let (mut before, index) = receipt_image(primary, generation, head);
    let old_index = encode_index(&index);
    let s = scan_receipts_with_index(&before, &old_index, UUID).unwrap();
    let old_hash = image_hash(&before, &old_index);
    let at = primary * RECEIPT_BYTES;
    let closure = home_closure(primary).unwrap();
    let mut homes = vec![closure.receipt.first];
    homes.extend(closure.receipt.second);
    let physical_homes = homes.len();
    if shape == "missing_home" {
        homes.pop();
    }
    let mut advanced = index;
    advanced.streams[0].generation = 2;
    let premature =
        status(scan_receipts_with_index(&before, &encode_index(&advanced), UUID).map(|_| ()));
    let mut after = before;
    after[at..at + RECEIPT_BYTES].fill(0);
    let mut retired = index;
    retired.generation += 1;
    retired.streams[0].retired_through = 1;
    let retired_index = encode_index(&retired);
    let mut callbacks = 0;
    let ack = status(verify_single_ack_transition(
        &before,
        &after,
        &old_index,
        &retired_index,
        UUID,
        primary,
        if shape == "wrong_principal" {
            OWNER_A + 1
        } else {
            OWNER_A
        },
        &homes,
        shape != "missing_index",
        |r, h| {
            callbacks += 1;
            assert_eq!(
                (r.owner_principal_id, r.status, h),
                (OWNER_A, state_code(head), closure)
            );
            if shape == "no_commit" {
                Err(Error::Unknown)
            } else {
                Ok(())
            }
        },
    ));
    let verified_after = if ack == "ok_()" {
        let mut reopened = retired;
        reopened.generation += 1;
        reopened.streams[0].generation = 2;
        reopened.streams[0].issued_hi = 2;
        after[at..at + RECEIPT_BYTES]
            .copy_from_slice(&media_receipt(0, 2, generation, 1).encode().unwrap());
        let raw = encode_index(&reopened);
        let replacement = scan_receipts_with_index(&after, &raw, UUID).unwrap();
        assert_eq!(replacement.occupied, 8);
        image_hash(&after, &raw)
    } else {
        String::from("-")
    };
    // One inert half-record mutation is rejected both at one-home and
    // straddling positions. Neither scanner performs media writes.
    before[at + RECEIPT_BYTES - 1] ^= 1;
    let torn = status(scan_receipts_with_index(&before, &old_index, UUID).map(|_| ()));
    format!(
        "{}\t{}\t{}\t{old_hash}\t{physical_homes}\t{ack}\t{callbacks}\t{premature}\t{torn}\t{verified_after}",
        s.occupied, s.unresolved, s.across_block,
    )
}

fn run_case(
    out: &mut impl Write,
    slot: usize,
    generation: u32,
    head: TicketState,
    ack: &str,
) -> io::Result<()> {
    let mut groups = GroupReceiptLedger::<2>::new();
    for seq in 1..=8 {
        groups.alloc_durable(A, 1, seq - 1, 1, seq).unwrap();
        groups.bind(A, 1, seq).unwrap();
    }
    groups.complete(A, 1, 8, TicketState::Done).unwrap();
    match head {
        TicketState::Done => groups.complete(A, 1, 1, head).unwrap(),
        TicketState::Unknown => groups.uncertain(A, 1, 1).unwrap(),
        TicketState::Bound => {}
        _ => unreachable!(),
    }
    if generation == 2 {
        assert_eq!(groups.bump_generation(A), Ok(2));
    }
    // The last stream is terminal but not retired. A ninth allocation
    // reaches group quota rather than being rejected for a busy stream.
    let full = status(groups.alloc_durable(A, generation, 7, 1, 9));
    let stream_reuse = status(groups.alloc_durable(A, generation, 7, 2, 9));
    let stale = status(groups.ticket_state(A, 3 - generation, 1));
    let recovery = (1..=8)
        .map(|seq| status(groups.recovery_query(A, seq)))
        .collect::<Vec<_>>()
        .join(",");
    let b = [
        status(groups.alloc_durable(B, 1, 0, 1, 1)),
        status(groups.bind(B, 1, 1)),
        status(groups.complete(B, 1, 1, TicketState::Done)),
        status(groups.retire(B, 1, 1)),
    ]
    .join(",");
    let left_b = groups.tickets_in_use(B).unwrap();
    let (writes, data) = volatile_writes(&mut groups, generation);
    let still_full = status(groups.alloc_durable(A, generation, 7, 1, 9));
    let ahead = status(groups.retire(A, generation, 8));
    let first_retire = status(groups.retire(A, generation, 1));
    if head != TicketState::Done {
        groups
            .complete(A, generation, 1, TicketState::Done)
            .unwrap();
        groups.retire(A, generation, 1).unwrap();
    }
    let gone = status(groups.recovery_query(A, 1));
    let old = status(groups.alloc_durable(A, generation, 0, 1, 1));
    let replacement = status(groups.alloc_durable(A, generation, 0, 2, 9));
    let owner_count = groups.tickets_in_use(A).unwrap();
    let image = media(slot, generation, head, ack);
    writeln!(
        out,
        "{slot}\t{generation}\t{}\t{ack}\t{full}\t{stream_reuse}\t{stale}\t{recovery}\t{b}\t{left_b}\t{writes}\t{data}\t{still_full}\t{ahead}\t{first_retire}\t{gone}\t{old}\t{replacement}\t{owner_count}\t{image}",
        state_code(head),
    )
}
fn main() -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(
        out,
        "slot\tgeneration\thead\tack_shape\tfull\tstream_reuse\tstale\trecovery\tother_group\tother_pending\twrites\treadback\tstill_full\tretire_ahead\tinitial_retire\tretired_query\tretired_request\treplacement\towner_pending\tmedia_pending\tmedia_unresolved\tmedia_straddling\tmedia_sha256\tmedia_homes\tmedia_ack\tmedia_callback\tmedia_premature_reuse\tmedia_torn\tmedia_reopened_sha256"
    )?;
    for slot in [0, 21, 42, 85, 106] {
        for generation in [1, 2] {
            for head in [TicketState::Bound, TicketState::Done, TicketState::Unknown] {
                for &shape in ACKS {
                    run_case(&mut out, slot, generation, head, shape)?;
                }
            }
        }
    }
    out.flush()
}
