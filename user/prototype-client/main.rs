#![no_std]
#![no_main]
#[path = "../prototype-task/files_abi.rs"]
mod file;

#[inline(never)]
fn call(operation: u64, a: u64, b: u64, c: u64, d: u64, e: u64) -> [u64; 4] {
    let (mut x0, mut x1, mut x2, mut x3) = (a, b, c, d);
    unsafe {
        core::arch::asm!("svc #0x45",inlateout("x0")x0,inlateout("x1")x1,inlateout("x2")x2,inlateout("x3")x3,inlateout("x4")e=>_,in("x8")operation,options(nostack));
    }
    [x0, x1, x2, x3]
}
fn finish(code: u64) -> ! {
    let _ = call(1, code, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}
fn stage(value: u64) {
    unsafe {
        (0x30000 as *mut u64).write_volatile(value);
    }
}
fn clock() -> u64 {
    call(17, 0, 0, 0, 0, 0)[1]
}
fn waiting(deadline: u64) -> bool {
    let _ = call(0, 0, 0, 0, 0, 0);
    clock() < deadline
}
fn put(address: u64, value: u64) {
    unsafe {
        (address as *mut u64).write_volatile(value);
    }
}
fn get(address: u64) -> u64 {
    unsafe { (address as *const u64).read_volatile() }
}
fn file_call(frame: &mut file::Frame, deadline: u64) -> bool {
    loop {
        let result = call(file::DISPATCH, 0, frame.bytes.as_mut_ptr() as u64, 0, 0, 0);
        if result[0] as i64 == frame.result() {
            return true;
        }
        if result[0] as i64 != -11 || !waiting(deadline) {
            return false;
        }
    }
}
fn handle(frame: &mut file::Frame, id: u64, generation: u64) {
    frame.set_u64(file::OFF_HANDLE_ID, id);
    frame.set_u64(file::OFF_HANDLE_GENERATION, generation);
}

#[inline(never)]
fn mixed_vector(file_cap: u64, generation: u64, deadline: u64) -> u64 {
    let own = call(16, 0, 0, 0, 0, 0);
    if own[0] != 0 {
        return 121;
    }
    for i in 0..16 {
        let address = 0x52000 + i * 32;
        let is_file = i % 2 == 0;
        put(address, if is_file { 1 } else { 2 });
        put(address + 8, if is_file { file_cap } else { own[1] });
        put(address + 16, if is_file { generation } else { own[2] });
        put(address + 24, 1000 + i);
    }
    let vector = loop {
        let out = call(11, 0x52000, 16, deadline, 0x53000, 0);
        if out[0] == 0 {
            break out[1];
        }
        if out[0] as i64 != -11 || !waiting(deadline) {
            return 122;
        }
    };
    loop {
        let out = call(12, vector, 0, 0, 0, 0);
        if out[0] != 0 {
            return 123;
        }
        if out[1] == 1 {
            if out[2] != 16 {
                return 124;
            }
            break;
        }
        if !waiting(deadline) {
            return 125;
        }
    }
    for i in 0..16 {
        if get(0x53000 + i * 24) != 1000 + i
            || get(0x53008 + i * 24) != 1
            || (i % 2 == 0 && get(0x53010 + i * 24) != 16)
        {
            return 126;
        }
    }
    // A stale capability generation is an error of that item. The valid
    // neighbour still executes and retains its original tag/result position.
    put(0x52010, generation + 1);
    let vector = loop {
        let out = call(11, 0x52000, 2, deadline, 0x53000, 0);
        if out[0] == 0 {
            break out[1];
        }
        if out[0] as i64 != -11 || !waiting(deadline) {
            return 127;
        }
    };
    loop {
        let out = call(12, vector, 0, 0, 0, 0);
        if out[0] != 0 {
            return 128;
        }
        if out[1] == 1 {
            break;
        }
        if !waiting(deadline) {
            return 129;
        }
    }
    if get(0x53000) != 1000
        || get(0x53008) != 2
        || get(0x53010) as i64 != -116
        || get(0x53018) != 1001
        || get(0x53020) != 1
    {
        return 130;
    }
    0
}

/// Ordinary bounded demand for the installed file/cache policies. Dirty pages
/// remain eligible for the background owner between calls; this client never
/// fabricates a policy receipt or waits synchronously for an AI decision.
#[inline(never)]
fn file_workload(authority: file::Capability, deadline: u64) -> u64 {
    let mut frame = file::Frame::new(file::OPEN, 18, authority);
    frame.set_path("/domain-probe/value");
    frame.set_u16(file::OFF_MODE, file::MODE_READ_WRITE);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 132;
    }
    let (id, generation) = (
        frame.u64(file::OFF_HANDLE_ID),
        frame.u64(file::OFF_HANDLE_GENERATION),
    );
    let mut request = 19;
    for turn in 0..8u64 {
        let offset = (turn % 4) * 4096;
        for word in 0..512u64 {
            put(
                0x50000 + word * 8,
                0xc0ff_ee00_0000_0000 | (turn << 16) | word,
            );
        }
        frame = file::Frame::new(file::WRITE, request, authority);
        request += 1;
        handle(&mut frame, id, generation);
        frame.set_u64(file::OFF_OFFSET, offset);
        frame.set_u64(file::OFF_DATA, 0x50000);
        frame.set_u32(file::OFF_DATA_LENGTH, 4096);
        if !file_call(&mut frame, deadline)
            || frame.result() != 0
            || frame.u64(file::OFF_COUNT) != 4096
        {
            return 133;
        }
        // Yield through the ordinary scheduler, leaving the storage owner free
        // to execute its own admitted background work before the next read.
        if !waiting(deadline) {
            return 134;
        }
        for word in 0..512u64 {
            put(0x50000 + word * 8, 0);
        }
        frame = file::Frame::new(file::READ, request, authority);
        request += 1;
        handle(&mut frame, id, generation);
        frame.set_u64(file::OFF_OFFSET, offset);
        frame.set_u64(file::OFF_DATA, 0x50000);
        frame.set_u32(file::OFF_DATA_LENGTH, 4096);
        if !file_call(&mut frame, deadline)
            || frame.result() != 0
            || frame.u64(file::OFF_COUNT) != 4096
        {
            return 135;
        }
        for word in 0..512u64 {
            if get(0x50000 + word * 8) != 0xc0ff_ee00_0000_0000 | (turn << 16) | word {
                return 136;
            }
        }
    }
    frame = file::Frame::new(file::FSYNC, request, authority);
    handle(&mut frame, id, generation);
    if !file_call(&mut frame, deadline)
        || frame.result() != 0
        || frame.u64(file::OFF_WRITE_SEQ) == 0
        || frame.u64(file::OFF_WRITE_SEQ) != frame.u64(file::OFF_DURABLE_SEQ)
    {
        return 137;
    }
    frame = file::Frame::new(file::CLOSE, request + 1, authority);
    handle(&mut frame, id, generation);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 138;
    }
    0
}

#[inline(never)]
fn files(authority: file::Capability, deadline: u64) -> u64 {
    let mut frame = file::Frame::new(file::MKDIR, 1, authority);
    if !frame.set_path("/domain-probe") {
        return 100;
    }
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 101;
    }
    frame = file::Frame::new(file::CREATE, 2, authority);
    if !frame.set_path("/domain-probe/value") {
        return 102;
    }
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 103;
    }
    let (object_id, object_generation) = (
        frame.u64(file::OFF_OBJECT_ID),
        frame.u64(file::OFF_OBJECT_GENERATION),
    );
    if object_id == 0 || object_generation == 0 {
        return 104;
    }
    frame = file::Frame::new(file::OPEN, 3, authority);
    frame.set_path("/domain-probe/value");
    frame.set_u16(file::OFF_MODE, file::MODE_READ_WRITE);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 105;
    }
    let (id, generation) = (
        frame.u64(file::OFF_HANDLE_ID),
        frame.u64(file::OFF_HANDLE_GENERATION),
    );
    if id == 0 || generation == 0 {
        return 106;
    }
    // A referenced file cannot be removed. This is a delivered business error,
    // distinct from a transport receipt that has not yet reached user memory.
    frame = file::Frame::new(file::UNLINK, 4, authority);
    frame.set_path("/domain-probe/value");
    if !file_call(&mut frame, deadline) || frame.result() != -16 {
        return 107;
    }
    put(0x50000, 0x1122334455667788);
    put(0x50008, 0xaabbccdd55667788);
    frame = file::Frame::new(file::WRITE, 5, authority);
    handle(&mut frame, id, generation);
    frame.set_u64(file::OFF_DATA, 0x50000);
    frame.set_u32(file::OFF_DATA_LENGTH, 16);
    if !file_call(&mut frame, deadline) || frame.result() != 0 || frame.u64(file::OFF_COUNT) != 16 {
        return 108;
    }
    frame = file::Frame::new(file::FSYNC, 6, authority);
    handle(&mut frame, id, generation);
    if !file_call(&mut frame, deadline)
        || frame.result() != 0
        || frame.u64(file::OFF_WRITE_SEQ) == 0
        || frame.u64(file::OFF_WRITE_SEQ) != frame.u64(file::OFF_DURABLE_SEQ)
    {
        return 109;
    }
    let durable = frame.u64(file::OFF_DURABLE_SEQ);
    frame = file::Frame::new(file::STAT, 7, authority);
    frame.set_path("/domain-probe/value");
    if !file_call(&mut frame, deadline)
        || frame.result() != 0
        || frame.u64(file::OFF_COUNT) != 16
        || frame.u64(file::OFF_OBJECT_ID) != object_id
        || frame.u64(file::OFF_OBJECT_GENERATION) != object_generation
        || frame.u64(file::OFF_DURABLE_SEQ) != durable
    {
        return 110;
    }
    frame = file::Frame::new(file::CLOSE, 8, authority);
    handle(&mut frame, id, generation);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 111;
    }
    frame = file::Frame::new(file::OPEN, 9, authority);
    frame.set_path("/domain-probe/value");
    frame.set_u16(file::OFF_MODE, file::MODE_READ);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 112;
    }
    let (read_id, read_generation) = (
        frame.u64(file::OFF_HANDLE_ID),
        frame.u64(file::OFF_HANDLE_GENERATION),
    );
    put(0x50000, 0);
    put(0x50008, 0);
    frame = file::Frame::new(file::READ, 10, authority);
    handle(&mut frame, read_id, read_generation);
    frame.set_u64(file::OFF_DATA, 0x50000);
    frame.set_u32(file::OFF_DATA_LENGTH, 16);
    if !file_call(&mut frame, deadline)
        || frame.result() != 0
        || frame.u64(file::OFF_COUNT) != 16
        || get(0x50000) != 0x1122334455667788
        || get(0x50008) != 0xaabbccdd55667788
    {
        return 113;
    }
    frame = file::Frame::new(file::GET_STAT_CAP, 11, authority);
    handle(&mut frame, read_id, read_generation);
    if !file_call(&mut frame, deadline) || frame.result() != 0 || frame.u64(file::OFF_COUNT) == 0 {
        return 131;
    }
    let mixed = mixed_vector(frame.u64(file::OFF_COUNT), object_generation, deadline);
    if mixed != 0 {
        return mixed;
    }
    frame = file::Frame::new(file::CLOSE, 12, authority);
    handle(&mut frame, read_id, read_generation);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 114;
    }
    frame = file::Frame::new(file::OPEN, 13, authority);
    frame.set_path("/domain-probe");
    frame.set_u16(file::OFF_MODE, file::MODE_DIRECTORY);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 115;
    }
    let (dir_id, dir_generation) = (
        frame.u64(file::OFF_HANDLE_ID),
        frame.u64(file::OFF_HANDLE_GENERATION),
    );
    frame = file::Frame::new(file::READDIR, 14, authority);
    handle(&mut frame, dir_id, dir_generation);
    frame.set_u64(file::OFF_DATA, 0x51000);
    frame.set_u32(file::OFF_DATA_LENGTH, 128);
    if !file_call(&mut frame, deadline)
        || frame.result() != 0
        || frame.u64(file::OFF_COUNT) != 1
        || get(0x51000) != object_id
        || get(0x51008) != object_generation
    {
        return 116;
    }
    let name = unsafe { core::slice::from_raw_parts(0x51018 as *const u8, 5) };
    if name != b"value" {
        return 117;
    }
    frame = file::Frame::new(file::CLOSE, 15, authority);
    handle(&mut frame, dir_id, dir_generation);
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 118;
    }
    let workload = file_workload(authority, deadline);
    if workload != 0 {
        return workload;
    }
    frame = file::Frame::new(file::UNLINK, 100, authority);
    frame.set_path("/domain-probe/value");
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 119;
    }
    frame = file::Frame::new(file::UNLINK, 101, authority);
    frame.set_path("/domain-probe");
    if !file_call(&mut frame, deadline) || frame.result() != 0 {
        return 120;
    }
    0
}

#[inline(never)]
fn run(authority: file::Capability) -> u64 {
    let deadline = clock().saturating_add(45_000_000_000);
    stage(1);
    if authority.id == 0 || authority.generation == 0 {
        return 1;
    }
    if call(14, 0x50000, 4, 1, 0, 0)[0] != 0 {
        return 2;
    }
    // Direct loads/stores produce real EL0 translation faults. Every new page
    // must be zero, including words away from the first faulting cache line.
    for page in 0..4 {
        for word in [0, 511] {
            let address = 0x50000 + page * 4096 + word * 8;
            if get(address) != 0 {
                return 3;
            }
            put(address, 0xfeed0000 + page * 512 + word);
        }
    }
    stage(2);
    let endpoint = call(5, 0, 0, 0, 0, 0);
    if endpoint[0] != 0 {
        return 4;
    }
    for sequence in 1..=2 {
        put(0x50000, sequence * 11);
        let address = if sequence == 1 {
            b"\x0b\0\0\0\0\0\0\0".as_ptr() as u64
        } else {
            0x50000
        };
        if call(6, endpoint[1], endpoint[2], sequence, address, 8)[0] != 0 {
            return 5;
        }
    }
    if call(7, 0x21000, 128, 0, 0, 0)[0] as i64 != -13 {
        return 6;
    }
    let mut received = 0;
    while received < 2 {
        let out = call(7, 0x51000, 4096, 0, 0, 0);
        if out[0] != 0 {
            if out[0] as i64 == -11 && waiting(deadline) {
                continue;
            }
            return 7;
        }
        if out[1] == 0 || out[1] > 2 - received || out[2] != out[1] * 40 {
            return 8;
        }
        for i in 0..out[1] {
            if get(0x51000 + i * 40) != received + i + 1
                || get(0x51018 + i * 40) != 8
                || get(0x51020 + i * 40) != (received + i + 1) * 11
            {
                return 9;
            }
        }
        received += out[1];
    }
    stage(3);
    let cap = call(16, 0, 0, 0, 0, 0);
    if cap[0] != 0 || cap[1] == 0 || cap[2] == 0 {
        return 10;
    }
    for (i, tag) in [11u64, 22].into_iter().enumerate() {
        let address = 0x52000 + i as u64 * 32;
        put(address, 2);
        put(address + 8, cap[1]);
        put(address + 16, cap[2]);
        put(address + 24, tag);
    }
    put(0x52020, 2 | (1 << 16));
    if call(11, 0x52000, 2, deadline, 0x53000, 0)[0] as i64 != -22 {
        return 11;
    }
    put(0x52020, 2);
    let vector = call(11, 0x52000, 2, deadline, 0x53000, 0);
    if vector[0] != 0 {
        return 12;
    }
    loop {
        let out = call(12, vector[1], 0, 0, 0, 0);
        if out[0] != 0 {
            return 13;
        }
        if out[1] == 1 {
            if out[2] != 2 {
                return 14;
            }
            break;
        }
        if !waiting(deadline) {
            return 15;
        }
    }
    if get(0x53000) != 11 || get(0x53008) != 1 || get(0x53018) != 22 || get(0x53020) != 1 {
        return 16;
    }
    stage(4);
    let result = files(authority, deadline);
    if result != 0 {
        return result;
    }
    stage(5);
    for (i, value) in [1u64, 2, 3, 4].into_iter().enumerate() {
        put(0x50000 + i as u64 * 8, value);
    }
    let id = 0x5151;
    let submitted = call(2, id, 0x50000, 32, 3, deadline);
    if submitted[0] != 0 {
        return 17;
    }
    let child = loop {
        let result = call(3, id, 0, 0, 0, 0);
        if result[0] != 0 {
            return 18;
        }
        if result[1] == 1 {
            break (result[2], result[3]);
        }
        if result[1] != 0 || !waiting(deadline) {
            return 19;
        }
    };
    loop {
        let result = call(18, child.0, child.1, 0, 0, 0);
        if result[0] != 0 {
            return 20;
        }
        if result[1] == 1 {
            if result[2] != 0 || result[3] != 10 {
                return 21;
            }
            break;
        }
        if !waiting(deadline) {
            return 22;
        }
    }
    stage(6);
    if call(15, 0x50000, 0, 0, 0, 0)[0] != 0 {
        return 23;
    }
    if call(14, 0x50000, 4, 1, 0, 0)[0] != 0 {
        return 24;
    }
    for page in 0..4 {
        for word in [0, 1, 511] {
            if get(0x50000 + page * 4096 + word * 8) != 0 {
                return 25;
            }
        }
    }
    if call(15, 0x50000, 0, 0, 0, 0)[0] != 0 {
        return 26;
    }
    stage(7);
    0
}
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(id: u64, generation: u64) -> ! {
    finish(run(file::Capability { id, generation }))
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    finish(255)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(destination: *mut u8, source: *const u8, len: usize) -> *mut u8 {
    for i in 0..len {
        unsafe {
            destination
                .add(i)
                .write_volatile(source.add(i).read_volatile());
        }
    }
    destination
}
#[unsafe(no_mangle)]
unsafe extern "C" fn memset(destination: *mut u8, value: i32, len: usize) -> *mut u8 {
    for i in 0..len {
        unsafe {
            destination.add(i).write_volatile(value as u8);
        }
    }
    destination
}
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    for i in 0..len {
        let (left, right) = unsafe { (a.add(i).read_volatile(), b.add(i).read_volatile()) };
        if left != right {
            return i32::from(left) - i32::from(right);
        }
    }
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    unsafe { memcmp(a, b, len) }
}
