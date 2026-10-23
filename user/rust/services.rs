#![no_std]
#![no_main]
//! Native EL0 integration workloads for the desktop process/IPC foundation.
//! This fixed image is not X.Org, a desktop app, or a Linux binary.
use core::arch::asm;
core::arch::global_asm!(include_str!("fpu.S"));
unsafe extern "C" {
    fn cyxia_fp_probe(pid: u64) -> u64;
}
use core::panic::PanicInfo;

// Identical virtual addresses in every process, different expected contents.
static mut PRIVATE: [u64; 16] = [0; 16];

fn call(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut result = a;
    // CyxiaOS native ABI preserves all registers except x0 across SVC. Pointer
    // ranges are checked in EL1; this assembly does not claim nomem/nostack.
    unsafe {
        asm!("svc #0", inout("x0") result, in("x1") b, in("x2") c, in("x8") number);
    }
    result as i64
}
fn yield_cpu() {
    call(18, 0, 0, 0);
}
fn clock() -> u64 {
    call(19, 0, 0, 0) as u64
}
fn exit(code: u64) -> ! {
    call(15, code, 0, 0);
    loop {
        yield_cpu();
    }
}
fn print(text: &[u8]) {
    let mut done = 0;
    let start = clock();
    while done < text.len() && clock().saturating_sub(start) < 100 {
        let n = call(
            4,
            1,
            text[done..].as_ptr() as u64,
            (text.len() - done) as u64,
        );
        if n > 0 {
            done += n as usize;
        } else {
            yield_cpu();
        }
    }
}
fn require(condition: bool) {
    if !condition {
        print(b"NATIVE_SERVICE_CHECK_FAILED\r\n");
        exit(90);
    }
}
fn private_check(pid: u64) {
    // Sole owner in this EL0 address space. Volatile accesses prevent the
    // compiler proving the values unchanged across real context switches.
    unsafe {
        let base = core::ptr::addr_of!(PRIVATE).cast::<u64>();
        for i in 0..16 {
            require(base.add(i).read_volatile() == pid ^ (i as u64 * 0x1957));
        }
    }
}
fn exchange(channel: u64, bytes: &mut [u8], send: bool, pid: u64, deadline: u64) {
    let mut done = 0;
    while done < bytes.len() {
        private_check(pid);
        require(clock() < deadline);
        let n = call(
            if send { 16 } else { 17 },
            channel,
            bytes[done..].as_mut_ptr() as u64,
            (bytes.len() - done) as u64,
        );
        if n == -32 || (!send && n == 0) {
            print(b"NATIVE_IPC_PEER_CLOSED\r\n");
            exit(0);
        }
        if n == -11 {
            require(call(20, channel, if send { 2 } else { 1 }, 0) == 0);
            continue;
        }
        require(n > 0 && n as usize <= bytes.len() - done);
        done += n as usize;
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.start")]
pub extern "C" fn _start(mode: u64, channel: u64) -> ! {
    let pid = call(13, 0, 0, 0) as u64;
    require(pid > 0);
    unsafe {
        let base = core::ptr::addr_of_mut!(PRIVATE).cast::<u64>();
        for i in 0..16 {
            require(base.add(i).read_volatile() == 0);
            base.add(i).write_volatile(pid ^ (i as u64 * 0x1957));
        }
    }
    if mode == 5 || mode == 6 || mode == 9 {
        heap_test(mode, pid);
    }
    if mode == 7 {
        paint();
    }
    if mode == 8 {
        require(unsafe { cyxia_fp_probe(pid) } == 0);
        print(b"NATIVE_FP_TLS_PASS\r\n");
        exit(0);
    }
    if mode == 1 {
        loop {
            core::hint::spin_loop();
        }
    }
    let start = clock();
    // All normal native services remain live beyond the old test-only 500 ms cap.
    while mode != 4 && clock().saturating_sub(start) < 750 {
        private_check(pid);
        require(call(21, 20, 0, 0) == 0);
    }
    if mode == 2 {
        // Deliberate isolation test: never expose the kernel mapping at EL0.
        unsafe {
            core::ptr::read_volatile(0xffffffc040200000usize as *const u8);
        }
        exit(91);
    }
    if mode == 0 {
        print(b"NATIVE_SERVICE_ALIVE private-memory=PASS\r\n");
        loop {
            private_check(pid);
            require(call(21, 20, 0, 0) == 0);
        }
    }
    require(mode == 3 || mode == 4);
    let mut bytes = [0u8; 512];
    require(call(16, channel, 0xffffffc040200000, 1) == -14);
    require(call(17, channel, 0x100000, 1) == -14);
    require(call(16, 0, bytes.as_ptr() as u64, 1) == -9);
    let deadline = clock() + 5000;
    for round in 0..32 {
        if mode == 3 {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (i + round) as u8;
            }
            exchange(channel, &mut bytes, true, pid, deadline);
            bytes.fill(0);
            exchange(channel, &mut bytes, false, pid, deadline);
            for (i, byte) in bytes.iter().enumerate() {
                require(*byte == (i + round) as u8);
            }
        } else {
            exchange(channel, &mut bytes, false, pid, deadline);
            for (i, byte) in bytes.iter().enumerate() {
                require(*byte == (i + round) as u8);
            }
            exchange(channel, &mut bytes, true, pid, deadline);
        }
    }
    private_check(pid);
    print(if mode == 3 {
        b"NATIVE_IPC_SERVER_PASS\r\n"
    } else {
        b"NATIVE_IPC_CLIENT_PASS\r\n"
    });
    exit(0)
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    print(b"NATIVE_SERVICE_PANIC\r\n");
    exit(92)
}

// Compiler-generated fixed-buffer operations; no C runtime or allocator.
#[unsafe(no_mangle)]
unsafe extern "C" fn memset(destination: *mut u8, value: i32, count: usize) -> *mut u8 {
    for i in 0..count {
        unsafe {
            destination.add(i).write_volatile(value as u8);
        }
    }
    destination
}
#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    for i in 0..count {
        unsafe {
            destination
                .add(i)
                .write_volatile(source.add(i).read_volatile());
        }
    }
    destination
}

fn heap_test(mode: u64, pid: u64) -> ! {
    let heap_pages = if cfg!(cyxia_large_memory) { 4096 } else { 2048 };
    let heap_base = if cfg!(cyxia_large_memory) { 0x04000000 } else { 0x200000 };
    require(call(22, 0, 0, 0) == -22);
    require(call(22, heap_pages + 1, 0, 0) == -22);
    let address = call(22, 96, 0, 0);
    require(address == heap_base);
    require(call(4, 1, address as u64, 0) == 0);
    require(call(4, 1, u64::MAX, 0) == 0);
    require(call(4, 999, address as u64, 0) == -9);
    let p = address as *mut u8;
    for i in 0..96 * 4096 {
        unsafe {
            require(p.add(i).read_volatile() == 0);
            p.add(i).write_volatile((i as u64 ^ pid) as u8);
        }
    }
    if mode == 9 {
        unsafe {
            p.cast::<u32>().write_volatile(0xd65f03c0);
            let target: extern "C" fn() = core::mem::transmute(p);
            target();
        }
        exit(94);
    }
    let other = call(22, 32, 0, 0);
    require(other > address);
    require(call(22, heap_pages, 0, 0) == -12);
    require(call(23, address as u64, 1, 0) == -22);
    // Cross-page copy-in/out uses the new anonymous mapping, not the fixed image.
    require(call(12, address as u64 + 4095, 2, 0) == address + 4095);
    unsafe {
        require(p.add(4095).read_volatile() == b'/' && p.add(4096).read_volatile() == 0);
    }
    let message = b"NATIVE_HEAP_BUFFER_PASS\r\n";
    for (i, b) in message.iter().enumerate() {
        unsafe {
            p.add(8190 + i).write_volatile(*b);
        }
    }
    require(call(4, 1, address as u64 + 8190, message.len() as u64) == message.len() as i64);
    // Leave both processes resident long enough for the host to observe them
    // together. Each checks its PID-specific bytes at the same virtual address.
    require(call(21, 500, 0, 0) == 0);
    for i in 9000..96 * 4096 {
        unsafe {
            require(p.add(i).read_volatile() == (i as u64 ^ pid) as u8);
        }
    }
    require(call(23, address as u64, 96, 0) == 0);
    if mode == 6 {
        unsafe {
            p.read_volatile();
        }
        exit(93);
    }
    require(call(4, 1, address as u64, 1) == -14);
    let recycled = call(22, 96, 0, 0);
    require(recycled == address);
    for i in 0..96 * 4096 {
        unsafe {
            require(p.add(i).read_volatile() == 0);
        }
    }
    require(call(23, other as u64, 32, 0) == 0);
    // Deliberately leave recycled mapped: exit must reclaim the active grant.
    print(b"NATIVE_HEAP_PASS\r\n");
    exit(0)
}
fn paint() -> ! {
    let mut pixels = [0x00123456u32; 512];
    let at = 17u64 | (23u64 << 32);
    let dimensions = 32u64 | (16u64 << 32);
    let first = call(24, at, dimensions, pixels.as_ptr() as u64);
    if first == -19 {
        print(b"NATIVE_PAINT_NO_DEVICE\r\n");
        exit(0);
    }
    require(first == 0);
    require(call(24, at, dimensions, 0xffffffc040200000) == -14);
    require(call(24, 1023 | (767 << 32), dimensions, pixels.as_ptr() as u64) == -22);
    require(call(24, at, 0, pixels.as_ptr() as u64) == -22);
    print(b"NATIVE_PAINT_FIRST_PASS\r\n");
    require(call(21, 1000, 0, 0) == 0);
    pixels.fill(0x00a1b2c3);
    require(call(24, at, dimensions, pixels.as_ptr() as u64) == 0);
    print(b"NATIVE_PAINT_SECOND_PASS\r\n");
    exit(0)
}
