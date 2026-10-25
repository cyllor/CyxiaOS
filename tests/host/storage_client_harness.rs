//! Deterministic ABI stand-in: exercises the real client on the host, not a
//! filesystem implementation or native acceptance oracle. Native SVC cannot run
//! in a host unit test; protected capture and independent disk replay stay separate.
#![allow(dead_code)]
#[path = "../../user/prototype-task/files_abi.rs"]
mod file;
#[path = "../../user/prototype-client/storage_fault.rs"]
mod storage_fault;
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

#[derive(Clone)]
struct Object {
    id: u64,
    generation: u64,
    directory: bool,
    data: Vec<u64>,
    sequence: u64,
    durable: u64,
}
#[derive(Default)]
struct Machine {
    memory: BTreeMap<u64, u64>,
    objects: BTreeMap<String, Object>,
    handles: BTreeMap<u64, (u64, String)>,
    next_id: u64,
    next_handle: u64,
    now: u64,
    requests: Vec<(u64, u16, u64)>,
    wrong_fsync: bool,
    mutate_after_read: bool,
}
static MACHINE: LazyLock<Mutex<Machine>> = LazyLock::new(|| Mutex::new(Machine::default()));
fn call(op: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> [u64; 4] {
    assert!(matches!(op, 14 | 15));
    [0; 4]
}
fn clock() -> u64 {
    MACHINE.lock().unwrap().now
}
fn waiting(deadline: u64) -> bool {
    let mut m = MACHINE.lock().unwrap();
    m.now += 1_000_000_000;
    m.now < deadline
}
fn get(address: u64) -> u64 {
    MACHINE
        .lock()
        .unwrap()
        .memory
        .get(&address)
        .copied()
        .unwrap_or(0)
}
fn put(address: u64, value: u64) {
    MACHINE.lock().unwrap().memory.insert(address, value);
}
fn handle(frame: &mut file::Frame, id: u64, generation: u64) {
    frame.set_u64(file::OFF_HANDLE_ID, id);
    frame.set_u64(file::OFF_HANDLE_GENERATION, generation);
}
fn object_reply(frame: &mut file::Frame, object: &Object) {
    frame.set_u64(file::OFF_OBJECT_ID, object.id);
    frame.set_u64(file::OFF_OBJECT_GENERATION, object.generation);
}
fn file_call(frame: &mut file::Frame, _: u64) -> bool {
    let mut m = MACHINE.lock().unwrap();
    let operation = frame.u16(file::OFF_OPERATION);
    let owner = frame.u64(file::OFF_AUTH_ID);
    let request = frame.u64(file::OFF_REQUEST);
    if let Some((_, _, previous)) = m.requests.iter().rev().find(|(id, _, _)| *id == owner) {
        assert!(
            request > *previous,
            "logical file request IDs must increase per endpoint"
        );
    }
    m.requests.push((owner, operation, request));
    let path = std::str::from_utf8(
        &frame.bytes
            [file::OFF_PATH..file::OFF_PATH + usize::from(frame.u16(file::OFF_PATH_LENGTH))],
    )
    .unwrap()
    .to_owned();
    frame.set_u64(file::OFF_RESULT, 0);
    if matches!(operation, file::CREATE | file::MKDIR) {
        if m.objects.contains_key(&path) {
            frame.set_u64(file::OFF_RESULT, (-17i64) as u64);
        } else {
            m.next_id += 1;
            let object = Object {
                id: m.next_id,
                generation: 1,
                directory: operation == file::MKDIR,
                data: Vec::new(),
                sequence: 0,
                durable: 0,
            };
            object_reply(frame, &object);
            m.objects.insert(path, object);
        }
        return true;
    }
    if matches!(operation, file::OPEN | file::STAT) {
        let Some(object) = m.objects.get(&path).cloned() else {
            frame.set_u64(file::OFF_RESULT, (-2i64) as u64);
            return true;
        };
        object_reply(frame, &object);
        if operation == file::STAT {
            frame.set_u64(file::OFF_COUNT, (object.data.len() * 8) as u64);
            frame.set_u16(file::OFF_MODE, if object.directory { 2 } else { 1 });
            frame.set_u64(file::OFF_WRITE_SEQ, object.sequence);
            frame.set_u64(file::OFF_DURABLE_SEQ, object.durable);
        } else {
            m.next_handle += 1;
            let id = m.next_handle;
            m.handles.insert(id, (owner, path));
            frame.set_u64(file::OFF_HANDLE_ID, id);
            frame.set_u64(file::OFF_HANDLE_GENERATION, 1);
        }
        return true;
    }
    let id = frame.u64(file::OFF_HANDLE_ID);
    let (handle_owner, path) = m.handles.get(&id).cloned().expect("live file handle");
    assert_eq!(
        handle_owner, owner,
        "file handles belong to their admitted endpoint"
    );
    assert_eq!(frame.u64(file::OFF_HANDLE_GENERATION), 1);
    let mut object = m.objects[&path].clone();
    match operation {
        file::WRITE => {
            assert_eq!(frame.u64(file::OFF_OFFSET), 0);
            assert_eq!(frame.u32(file::OFF_DATA_LENGTH), 4096);
            let address = frame.u64(file::OFF_DATA);
            object.data = (0..512)
                .map(|word| m.memory[&(address + word * 8)])
                .collect();
            object.sequence += 1;
            frame.set_u64(file::OFF_COUNT, 4096);
            object_reply(frame, &object);
        }
        file::READ => {
            assert_eq!(frame.u64(file::OFF_OFFSET), 0);
            assert_eq!(frame.u32(file::OFF_DATA_LENGTH), 4096);
            let address = frame.u64(file::OFF_DATA);
            for (word, value) in object.data.iter().enumerate() {
                m.memory.insert(address + word as u64 * 8, *value);
            }
            frame.set_u64(file::OFF_COUNT, (object.data.len() * 8) as u64);
            object_reply(frame, &object);
            if m.mutate_after_read {
                object.generation += 1;
            }
        }
        file::FSYNC => {
            object.durable = object.sequence;
            object_reply(frame, &object);
            frame.set_u64(file::OFF_WRITE_SEQ, object.sequence);
            frame.set_u64(
                file::OFF_DURABLE_SEQ,
                object.durable + u64::from(m.wrong_fsync),
            );
        }
        file::CLOSE => {
            m.handles.remove(&id);
        }
        _ => panic!("unexpected operation {operation}; workload must never delete files"),
    }
    m.objects.insert(path, object);
    true
}
fn launch(mode: u64, role: u64, epoch: u64, owner: u64) -> u64 {
    for (address, value) in [
        (0x20000, 32),
        (0x21000, 1),
        (0x21008, mode),
        (0x21010, role),
        (0x21018, epoch),
    ] {
        put(address, value);
    }
    for i in 0..13 {
        put(0x30000 + i * 8, 0);
    }
    storage_fault::run(file::Capability {
        id: owner,
        generation: 1,
    })
}
fn reset() {
    *MACHINE.lock().unwrap() = Machine::default();
}
fn value() -> Object {
    MACHINE.lock().unwrap().objects["/a10/value"].clone()
}
fn marker(epoch: u64) -> bool {
    MACHINE
        .lock()
        .unwrap()
        .objects
        .contains_key(&format!("/a10/seen-{epoch:016x}"))
}
fn prepare() {
    assert_eq!(launch(1, 1, 1, 101), 0);
}

#[test]
fn two_endpoints_consume_exact_ack_and_retain_version_two() {
    reset();
    prepare();
    assert_eq!(value().durable, 2);
    assert_eq!(value().data.len(), 512);
    for (word, data) in value().data.iter().enumerate() {
        assert_eq!(*data, 0xa100000200000000 | word as u64);
    }
    assert_eq!(launch(1, 2, 1, 102), 0);
    assert!(marker(1));
    assert_eq!(get(0x30000 + 6 * 8), 8);
    assert_eq!(get(0x30000 + 11 * 8), 4096);
    assert_eq!(get(0x30000) % 2, 0);
    assert!(MACHINE.lock().unwrap().handles.is_empty());
}
#[test]
fn old_epoch_marker_cannot_authorize_new_overwrite() {
    reset();
    prepare();
    assert_eq!(launch(1, 2, 1, 102), 0);
    assert_ne!(launch(2, 1, 2, 201), 0);
    assert_eq!(value().durable, 2);
    assert!(!marker(2));
}
#[test]
fn fresh_reader_marker_then_writer_produces_version_three() {
    reset();
    prepare();
    assert_eq!(launch(2, 2, 2, 202), 0);
    assert!(marker(2));
    assert_eq!(launch(2, 1, 2, 201), 0);
    assert_eq!(value().durable, 3);
    assert_eq!(value().data[511], 0xa1000003000001ff);
    assert_eq!(get(0x30000 + 9 * 8), 3);
    assert_eq!(launch(3, 2, 3, 302), 0);
    assert!(!marker(3));
}
#[test]
fn wrong_fsync_receipt_is_never_reported_consumed() {
    reset();
    MACHINE.lock().unwrap().wrong_fsync = true;
    assert_ne!(launch(1, 1, 1, 101), 0);
    assert_eq!(get(0x30000 + 9 * 8), 0);
    assert_eq!(get(0x30000 + 6 * 8), 255);
}
#[test]
fn final_word_corruption_cannot_create_visibility_marker() {
    reset();
    prepare();
    MACHINE
        .lock()
        .unwrap()
        .objects
        .get_mut("/a10/value")
        .unwrap()
        .data[511] ^= 1;
    assert_ne!(launch(1, 2, 1, 102), 0);
    assert!(!marker(1));
    assert_eq!(get(0x30000 + 11 * 8), 0);
}
#[test]
fn generation_changed_after_read_cannot_create_visibility_marker() {
    reset();
    prepare();
    MACHINE.lock().unwrap().mutate_after_read = true;
    assert_ne!(launch(1, 2, 1, 102), 0);
    assert!(!marker(1));
}
#[test]
fn invalid_launch_never_issues_file_requests() {
    reset();
    assert_ne!(launch(3, 1, 1, 101), 0);
    assert_ne!(launch(1, 1, 0, 101), 0);
    assert!(MACHINE.lock().unwrap().requests.is_empty());
}
