#![no_std]
#![no_main]
//! Ordinary authenticated file requests and anonymous faults, no test syscall.
#[path = "../prototype-task/files_abi.rs"]
mod file;
const MAGIC: u64 = 0x435958413039434c;
const PROGRESS: u64 = 0x30000;
const DATA: u64 = 0x60000;
const BUFFER: u64 = 0x80000;
const BARRIER: u64 = 0x71000;
const READONLY: u64 = 0x72000;
const PAGES: u64 = 4097;
const BUFFER_PAGES: u64 = file::MAX_IO as u64 / 4096;
fn put(a: u64, v: u64) {
    unsafe { (a as *mut u64).write_volatile(v) }
}
fn get(a: u64) -> u64 {
    unsafe { (a as *const u64).read_volatile() }
}
fn progress(i: u64, v: u64) {
    put(PROGRESS + i * 8, v)
}
#[inline(never)]
fn call(op: u64, a: u64, b: u64, c: u64) -> [u64; 3] {
    call5(op, a, b, c, 0, 0)
}
#[inline(never)]
fn call5(op: u64, a: u64, b: u64, c: u64, d: u64, e: u64) -> [u64; 3] {
    let (mut x0, mut x1, mut x2) = (a, b, c);
    unsafe {
        core::arch::asm!("svc #0x45",inlateout("x0")x0,inlateout("x1")x1,inlateout("x2")x2,inlateout("x3")d=>_,inlateout("x4")e=>_,in("x8")op,options(nostack));
    }
    [x0, x1, x2]
}
fn yield_now() {
    let _ = call(0, 0, 0, 0);
}
fn clock() -> u64 {
    call(17, 0, 0, 0)[1]
}
fn fail(code: u64) -> ! {
    progress(3, code);
    loop {
        yield_now();
    }
}
fn word(nonce: [u64; 2], role: u64, page: u64, index: u64) -> u64 {
    nonce[0]
        ^ nonce[1].rotate_left(17)
        ^ role.wrapping_mul(0x9e3779b185ebca87)
        ^ page.wrapping_mul(0xc2b2ae3d27d4eb4f)
        ^ index.wrapping_mul(0x165667b19e3779f9)
}
struct Client {
    authority: file::Capability,
    next: u64,
    deadline: u64,
    role: u64,
    nonce: [u64; 2],
    notification: [u64; 2],
}
impl Client {
    fn frame(&mut self, op: u16) -> file::Frame {
        self.next = self.next.checked_add(1).unwrap_or_else(|| fail(100));
        file::Frame::new(op, self.next, self.authority)
    }
    fn run(&self, frame: &mut file::Frame) {
        loop {
            let result = call(file::DISPATCH, 0, frame.bytes.as_mut_ptr() as u64, 0);
            if result[0] as i64 == frame.result() {
                return;
            }
            if result[0] as i64 != -11 || clock() >= self.deadline {
                fail(101);
            }
            yield_now();
        }
    }
    fn close(&mut self, id: u64, generation: u64) {
        let mut f = self.frame(file::CLOSE);
        f.set_u64(file::OFF_HANDLE_ID, id);
        f.set_u64(file::OFF_HANDLE_GENERATION, generation);
        self.run(&mut f);
        if f.result() != 0 {
            fail(102);
        }
    }
    fn write_flag(&mut self, path: &str, time: u64) {
        let mut f = self.frame(file::CREATE);
        f.set_path(path);
        self.run(&mut f);
        if f.result() != 0 {
            fail(103);
        }
        f = self.frame(file::OPEN);
        f.set_path(path);
        f.set_u16(file::OFF_MODE, file::MODE_WRITE);
        self.run(&mut f);
        if f.result() != 0 {
            fail(104);
        }
        let (id, generation) = (
            f.u64(file::OFF_HANDLE_ID),
            f.u64(file::OFF_HANDLE_GENERATION),
        );
        put(BARRIER, time);
        let length = if path == "/a09/filled-b" {
            put(BARRIER + 8, self.notification[0]);
            put(BARRIER + 16, self.notification[1]);
            24
        } else {
            8
        };
        f = self.frame(file::WRITE);
        f.set_u64(file::OFF_HANDLE_ID, id);
        f.set_u64(file::OFF_HANDLE_GENERATION, generation);
        f.set_u64(file::OFF_DATA, BARRIER);
        f.set_u32(file::OFF_DATA_LENGTH, length);
        self.run(&mut f);
        if f.result() != 0 || f.u64(file::OFF_COUNT) != u64::from(length) {
            fail(105);
        }
        self.close(id, generation);
    }
    fn read_flag(&mut self, path: &str) -> u64 {
        loop {
            let mut f = self.frame(file::OPEN);
            f.set_path(path);
            f.set_u16(file::OFF_MODE, file::MODE_READ);
            self.run(&mut f);
            if f.result() == -2 {
                if clock() >= self.deadline {
                    fail(106);
                }
                yield_now();
                continue;
            }
            if f.result() != 0 {
                fail(107);
            }
            let (id, generation) = (
                f.u64(file::OFF_HANDLE_ID),
                f.u64(file::OFF_HANDLE_GENERATION),
            );
            f = self.frame(file::READ);
            f.set_u64(file::OFF_HANDLE_ID, id);
            f.set_u64(file::OFF_HANDLE_GENERATION, generation);
            f.set_u64(file::OFF_DATA, BARRIER);
            let length = if path == "/a09/filled-b" { 24 } else { 8 };
            f.set_u32(file::OFF_DATA_LENGTH, length);
            self.run(&mut f);
            if f.result() != 0 {
                fail(108);
            }
            if f.u64(file::OFF_COUNT) != u64::from(length) {
                self.close(id, generation);
                if clock() >= self.deadline {
                    fail(108);
                }
                yield_now();
                continue;
            }
            let value = get(BARRIER);
            if length == 24 {
                self.notification = [get(BARRIER + 8), get(BARRIER + 16)];
            }
            self.close(id, generation);
            if value == 0 {
                fail(109);
            }
            return value;
        }
    }
    fn barrier(&mut self, stage: u64) {
        let (own, peer) = match (stage, self.role) {
            (1, 1) => ("/a09/zero-a", "/a09/zero-b"),
            (1, 2) => ("/a09/zero-b", "/a09/zero-a"),
            (2, 1) => ("/a09/filled-a", "/a09/filled-b"),
            (2, 2) => ("/a09/filled-b", "/a09/filled-a"),
            _ => fail(110),
        };
        let at = clock();
        self.write_flag(own, at);
        let other = self.read_flag(peer);
        let until = at
            .max(other)
            .checked_add(2_000_000_000)
            .unwrap_or_else(|| fail(111));
        while clock() < until {
            yield_now();
        }
    }
    fn check_sentinel(&self) {
        for page in 0..4 {
            for index in 0..512 {
                if get(DATA + page * 4096 + index * 8) != word(self.nonce, self.role, page, index) {
                    fail(112);
                }
            }
        }
        for index in 0..512 {
            if get(READONLY + index * 8) != 0 {
                fail(113);
            }
        }
    }
    fn read_batch(&mut self, id: u64, generation: u64, offset: u64, length: u32) -> file::Frame {
        loop {
            let mut f = self.frame(file::READ);
            f.set_u64(file::OFF_HANDLE_ID, id);
            f.set_u64(file::OFF_HANDLE_GENERATION, generation);
            f.set_u64(file::OFF_OFFSET, offset);
            f.set_u64(file::OFF_DATA, BUFFER);
            f.set_u32(file::OFF_DATA_LENGTH, length);
            let started = clock();
            self.run(&mut f);
            progress(11, get(PROGRESS + 11 * 8) + 1);
            progress(12, get(PROGRESS + 12 * 8).max(clock() - started));
            progress(14, f.result() as u64);
            progress(15, f.u64(file::OFF_COUNT));
            if f.result() != -11 || clock() >= self.deadline {
                return f;
            }
            // A delivered READ result consumes its request identity, including
            // AGAIN. Retry this position-explicit read with a fresh identity;
            // Client::run retains the old identity for transport/copyout retry.
            // No write/create/fsync operation is replayed here.
            progress(13, get(PROGRESS + 13 * 8) + 1);
            yield_now();
        }
    }
    fn pressure(&mut self) {
        let mut f = self.frame(file::OPEN);
        f.set_path("/a09/blob-a");
        f.set_u16(file::OFF_MODE, file::MODE_READ);
        self.run(&mut f);
        if f.result() != 0 {
            fail(114);
        }
        let (mut id, mut generation) = (
            f.u64(file::OFF_HANDLE_ID),
            f.u64(file::OFF_HANDLE_GENERATION),
        );
        let mut page = 0;
        progress(9, clock());
        while page < PAGES {
            if page > 0 && page % 2048 == 0 {
                self.close(id, generation);
                f = self.frame(file::OPEN);
                f.set_path(if page == 2048 {
                    "/a09/blob-b"
                } else {
                    "/a09/blob-c"
                });
                f.set_u16(file::OFF_MODE, file::MODE_READ);
                self.run(&mut f);
                if f.result() != 0 {
                    fail(117);
                }
                id = f.u64(file::OFF_HANDLE_ID);
                generation = f.u64(file::OFF_HANDLE_GENERATION);
            }
            let batch = BUFFER_PAGES.min(PAGES - page).min(2048 - page % 2048);
            let length = batch * 4096;
            f = self.read_batch(id, generation, (page % 2048) * 4096, length as u32);
            if f.result() != 0 || f.u64(file::OFF_COUNT) != length {
                fail(115);
            }
            for offset in 0..batch {
                if get(BUFFER + offset * 4096) != word(self.nonce, 0, page + offset, 0)
                    || get(BUFFER + offset * 4096 + 4088) != word(self.nonce, 0, page + offset, 511)
                {
                    fail(116);
                }
            }
            page += batch;
            progress(6, page);
            if page % 64 == 0 {
                self.check_sentinel();
            }
        }
        self.close(id, generation);
        progress(10, clock());
        put(BARRIER, word(self.nonce, 2, PAGES, 0));
        loop {
            let r = call5(6, self.notification[0], self.notification[1], 1, BARRIER, 8);
            if r[0] == 0 {
                break;
            }
            if r[0] as i64 != -11 || clock() >= self.deadline {
                fail(118);
            }
            yield_now();
        }
    }
    fn wait_done(&self) {
        loop {
            let r = call(22, BARRIER, 128, 0);
            // Empty receive blocks. Its eventual return is AGAIN, including a
            // spurious wake; retry until an authenticated message is delivered.
            if r[0] as i64 == -11 {
                continue;
            }
            if r[0] != 0
                || r[1] != 1
                || r[2] != 40
                || get(BARRIER + 32) != word(self.nonce, 2, PAGES, 0)
            {
                fail(119);
            }
            break;
        }
    }
}
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(authority: u64, generation: u64) -> ! {
    for n in 0..16 {
        progress(n, 0);
    }
    progress(0, MAGIC);
    if get(0x20000) != 40 || get(0x21000) != MAGIC {
        fail(120);
    }
    let role = get(0x21008);
    progress(1, role);
    if !(1..=2).contains(&role) {
        fail(121);
    }
    let nonce = [get(0x21010), get(0x21018)];
    let mut c = Client {
        authority: file::Capability {
            id: authority,
            generation,
        },
        next: 0,
        deadline: clock()
            .checked_add(get(0x21020))
            .unwrap_or_else(|| fail(122)),
        role,
        nonce,
        notification: [0, 0],
    };
    for (base, pages, writable) in [
        (DATA, 4, 1),
        (BUFFER, BUFFER_PAGES, 1),
        (BARRIER, 1, 1),
        (READONLY, 1, 0),
    ] {
        if call(14, base, pages, writable)[0] != 0 {
            fail(123);
        }
    }
    if role == 2 {
        let r = call(5, 0, 0, 0);
        if r[0] != 0 || r[1] == 0 || r[2] == 0 {
            fail(126);
        }
        c.notification = [r[1], r[2]];
        progress(7, r[1]);
        progress(8, r[2]);
    }
    let mut zero = 0;
    for page in 0..4 {
        for index in 0..512 {
            if get(DATA + page * 4096 + index * 8) != 0 {
                fail(124);
            }
            zero += 1;
        }
    }
    for index in 0..512 {
        if get(READONLY + index * 8) != 0 {
            fail(125);
        }
        zero += 1;
    }
    // Ensure pressure buffer is mapped before the first protected snapshot.
    let _ = get(BUFFER);
    progress(4, zero);
    progress(2, 1);
    yield_now();
    c.barrier(1);
    for page in 0..4 {
        for index in 0..512 {
            put(
                DATA + page * 4096 + index * 8,
                word(nonce, role, page, index),
            );
        }
    }
    c.check_sentinel();
    progress(5, 1);
    progress(2, 2);
    yield_now();
    c.barrier(2);
    if role == 1 {
        c.pressure();
    } else {
        c.wait_done();
    }
    c.check_sentinel();
    progress(2, 3);
    loop {
        yield_now();
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail(199)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(out: *mut u8, input: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            out.add(i).write_volatile(input.add(i).read_volatile());
        }
    }
    out
}
#[unsafe(no_mangle)]
unsafe extern "C" fn memset(out: *mut u8, value: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            out.add(i).write_volatile(value as u8);
        }
    }
    out
}
