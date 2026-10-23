//! CPU0 foreground supervisor: independent EL0 roots, AI scheduling, native local IPC.
use core::fmt::Write;
use cyxia_ai_fs::FileSystem;
use cyxia_ai_runtime::accounting::Attempt;
use cyxia_arch_aarch64::{
    mmu,
    user::{self, Context},
};
use cyxia_contracts::{DecisionSource, Generation, PageCount, PhysAddr, RedemptionId, TaskId};
use cyxia_kernel_core::grants::{AuthorizedGrantRequest, GrantLedger, Owner, ReleaseReceipt};
use cyxia_posix::{
    Console, Errno, Process, UserRequest, UserState, UserStatus,
    ipc::{Interest, LocalIpc},
    usermem::*,
};
const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/posix-demo.elf"));
const SERVICES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-services.elf"));
#[cfg(feature = "ported")]
include!(concat!(env!("OUT_DIR"), "/ported_catalog.rs"));
pub(crate) mod ai;
#[cfg(feature = "ported")]
mod event;
#[cfg(feature = "ported")]
mod files;
#[cfg(feature = "ported")]
mod linux;
mod objects;
#[cfg(feature = "ported")]
mod pipes;
#[cfg(feature = "ported")]
mod pty;
#[cfg(feature = "ported")]
mod shared_memory;
#[cfg(feature = "ported")]
mod signals;
#[cfg(feature = "ported")]
mod spawn;
mod threads;
#[cfg(feature = "ported")]
mod timerfd;
use ai::Domain as AiDomain;
#[cfg(feature = "ported")]
mod unix;
use threads::Thread;
const SLOTS: usize = MAX_PROCESSES;
const USER_POOL: u32 = POOL_PAGES;
const _: () = assert!(core::mem::size_of::<Arena>() == MAPPED_PAGES as usize * 4096);
#[repr(C, align(4096))]
struct Table([u64; 512]);
#[derive(Clone, Copy)]
enum Wait {
    Sleep(u64),
    #[cfg(feature = "ported")]
    Nanosleep {
        until: u64,
        deadline_ns: u64,
        remaining: u64,
    },
    #[cfg(feature = "ported")]
    Spawn,
    #[cfg(feature = "ported")]
    Child {
        pid: i32,
        status: u64,
        nonblock: bool,
    },
    #[cfg(feature = "ported")]
    Futex {
        address: u64,
        until: u64,
    },
    Ipc(u32, Interest),
    #[cfg(feature = "graphics")]
    Display,
    #[cfg(feature = "ported")]
    Unix {
        handle: u64,
        descriptor: i32,
        write: bool,
    },
    #[cfg(feature = "ported")]
    Retry(u64),
    #[cfg(feature = "ported")]
    TimerRead {
        descriptor: i32,
        identity: u64,
    },
    #[cfg(feature = "ported")]
    Poll {
        address: u64,
        count: usize,
        until: u64,
    },
    #[cfg(feature = "ported")]
    Epoll {
        descriptor: i32,
        identity: u64,
        address: u64,
        count: usize,
        until: u64,
    },
}
struct Runner {
    arena: Arena,
    heap: super::user_heap::Heap,
    #[cfg(feature = "ported")]
    executable: super::exec_memory::ExecMemory,
    #[cfg(feature = "ported")]
    shared: shared_memory::SharedMappings,
    #[cfg(feature = "ported")]
    linux: bool,
    thread: Thread,
    #[cfg(feature = "ported")]
    threads: threads::Group,
    #[cfg(feature = "ported")]
    pending_spawn: Option<spawn::Request>,
    l1: Table,
    l2: Table,
    l3: Table,
    process: Process<'static>,
    lease: Option<(Owner, RedemptionId)>,
    status: UserStatus,
    started: u64,
    test_lifetime: Option<u64>,
}
impl Runner {
    const fn new() -> Self {
        Self {
            arena: Arena::new(),
            heap: super::user_heap::Heap::new(),
            #[cfg(feature = "ported")]
            executable: super::exec_memory::ExecMemory::new(),
            #[cfg(feature = "ported")]
            shared: shared_memory::SharedMappings::new(),
            #[cfg(feature = "ported")]
            linux: false,
            thread: Thread::new(),
            #[cfg(feature = "ported")]
            threads: threads::Group::new(),
            #[cfg(feature = "ported")]
            pending_spawn: None,
            l1: Table([0; 512]),
            l2: Table([0; 512]),
            l3: Table([0; 512]),
            process: Process::empty(objects::table(), 0),
            lease: None,
            status: UserStatus::EMPTY,
            started: 0,
            test_lifetime: None,
        }
    }
}
struct Supervisor {
    runners: [Runner; SLOTS],
    ledger: GrantLedger,
    ipc: LocalIpc,
    next_pid: u32,
    focus_pid: u32,
    #[cfg(feature = "ported")]
    children: spawn::Children,
    #[cfg(feature = "graphics")]
    display_owner: Option<(u32, u32)>,
}
static mut SUPERVISOR: Supervisor = Supervisor {
    runners: [const { Runner::new() }; SLOTS],
    ledger: GrantLedger::new(PageCount(USER_POOL)),
    ipc: LocalIpc::new(),
    next_pid: 1,
    focus_pid: 0,
    #[cfg(feature = "ported")]
    children: spawn::Children::new(),
    #[cfg(feature = "graphics")]
    display_owner: None,
};
fn now() -> u64 {
    now_ns() / 1_000_000
}
fn now_ns() -> u64 {
    cyxia_kernel_core::time::ticks_to_ns(
        cyxia_arch_aarch64::timer::ticks(),
        cyxia_arch_aarch64::timer::frequency(),
    )
    .unwrap()
    .0
}
struct Output;
impl Console for Output {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
        let n = bytes.len().min(64);
        super::try_log(&bytes[..n]).map_err(|e| match e {
            cyxia_contracts::PlatformError::Again => Errno::Again,
            _ => Errno::Io,
        })?;
        Ok(n)
    }
}
impl Runner {
    fn start(
        &mut self,
        mode: &str,
        image: &[u8],
        pid: u32,
        lifetime: Option<u64>,
        ledger: &mut GrantLedger,
        attempt: &mut Attempt,
    ) -> Result<(), Errno> {
        if self.status.state.active() {
            return Err(Errno::Busy);
        }
        #[cfg(feature = "ported")]
        {
            self.linux = false;
            self.pending_spawn = None;
            self.threads.reset();
        }
        self.thread.reset();
        let objects = objects::table().snapshot();
        if objects.capacity - objects.live - objects.retired < 3 {
            return Err(Errno::Mfile);
        }
        let entry = cyxia_posix::image::load(image, &mut self.arena)?;
        attempt.proposed(8193);
        let (admitted, model) =
            cyxia_ai_runtime::user_memory_policy(ledger.snapshot().free, MAPPED_PAGES)
                .map_err(|_| Errno::Io)?;
        attempt.decided(admitted, model);
        if !admitted {
            self.arena.clear();
            return Err(Errno::Nomem);
        }
        let owner = Owner {
            task: TaskId::new(pid).map_err(|_| Errno::Overflow)?,
            generation: Generation::new(1).map_err(|_| Errno::Overflow)?,
        };
        // Trusted admission: current local model evaluated this fixed request and
        // private ledger. PID never reused; no user-provided provenance is accepted.
        let request =
            unsafe { AuthorizedGrantRequest::validated_ai(owner, PageCount(MAPPED_PAGES), model) }
                .map_err(|_| Errno::Io)?;
        let grant = ledger.commit(request).map_err(|_| Errno::Nomem)?;
        let redemption = match ledger.redeem(grant, owner, PageCount(MAPPED_PAGES)) {
            Ok(r) => r,
            Err(_) => {
                ledger.cancel_unused(grant, owner).map_err(|_| Errno::Io)?;
                self.arena.clear();
                return Err(Errno::Io);
            }
        };
        self.lease = Some((owner, redemption));
        ai::record(AiDomain::Process, |c| c.grant(u64::from(MAPPED_PAGES)));
        // All following sizes and addresses are fixed and proved by the loader.
        self.l1.0.fill(0);
        self.l2.0.fill(0);
        self.l3.0.fill(0);
        self.l1.0[0] = (&self.l2 as *const Table as u64 - super::HIGH) | 3;
        self.l2.0[0] = (&self.l3 as *const Table as u64 - super::HIGH) | 3;
        let base = self.arena.base_ptr() as u64 - super::HIGH;
        for i in 0..MAPPED_PAGES as usize {
            let page = if i < 6 { 256 + i } else { 257 + i };
            self.l3.0[page] =
                mmu::encode_user_leaf(PhysAddr(base + i as u64 * 4096), i >= 4, i < 4).unwrap();
        }
        let name = STACK_TOP - 128;
        let arg = STACK_TOP - 96;
        let argv = STACK_TOP - 64;
        self.arena.write(name, b"posix-test\0").unwrap();
        self.arena.write(arg, mode.as_bytes()).unwrap(); // Arena zeroing supplies NUL.
        self.arena.write(argv, &name.to_le_bytes()).unwrap();
        self.arena.write(argv + 8, &arg.to_le_bytes()).unwrap();
        self.arena.write(argv + 16, &0u64.to_le_bytes()).unwrap();
        self.thread.context = Context {
            regs: [0; 31],
            pc: entry,
            status: 0,
            sp: STACK_TOP - 256,
            esr: 0,
            far: 0,
            kind: 0,
            ..Context::empty()
        };
        self.thread.context.regs[0] = 2;
        self.thread.context.regs[1] = argv;
        self.process = Process::new(objects::table(), pid).expect("preflighted stdio capacity");
        self.started = now();
        self.thread.ready_since = self.started;
        self.test_lifetime = lifetime;
        self.thread.waiting = None;
        self.thread.cpu_bound = false;
        self.thread.active = true;
        self.thread.tid = pid;
        self.status = UserStatus {
            pid,
            state: UserState::Running,
            free_pages: ledger.snapshot().free,
            thread_count: 1,
            thread_peak: 1,
            ..UserStatus::EMPTY
        };
        // Publish generated user instructions. Clean D-cache by architectural line
        // size before invalidating I-cache; user and kernel aliases share physical RAM.
        unsafe {
            let ctr: u64;
            core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr);
            let line = 4u64 << ((ctr >> 16) & 15);
            let start = self.arena.base_ptr() as u64;
            let mut p = start;
            while p < start + CODE_BYTES as u64 {
                core::arch::asm!("dc cvau, {}",in(reg)p);
                p += line;
            }
            core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
        }
        Ok(())
    }
    fn finish(
        &mut self,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
        state: UserState,
        code: u32,
    ) {
        #[cfg(feature = "ported")]
        {
            self.pending_spawn = None;
            self.clear_all_threads();
        }
        self.status.exit_signal = match state {
            UserState::Killed => 9,
            UserState::Fault => 11,
            _ => self.status.exit_signal,
        };
        self.thread.active = false;
        self.status.thread_count = 0;
        // enter() has disabled TTBR0 walks and completed TLBI+DSB. No DMA/other CPU
        // can reference this private arena. Revoke descriptors before releasing grant.
        self.l1.0.fill(0);
        self.l2.0.fill(0);
        self.l3.0.fill(0);
        #[cfg(feature = "ported")]
        self.executable.clear();
        #[cfg(feature = "ported")]
        self.shared.clear();
        self.heap.clear();
        #[cfg(feature = "ported")]
        pty::release_actor(self.status.pid);
        for released in self.process.close_all(fs).unwrap() {
            objects::release(fs, released).expect("live OFD backend release");
        }
        ipc.close_owner(self.status.pid);
        if let Some((owner, id)) = self.lease.take() {
            let receipt =
                unsafe { ReleaseReceipt::after_revoke(id, owner, PageCount(MAPPED_PAGES)) };
            ledger.release_completed(receipt).unwrap();
            ai::record(AiDomain::Process, |c| c.release(u64::from(MAPPED_PAGES)));
        }
        self.arena.clear();
        self.thread.waiting = None;
        self.status.state = state;
        self.status.code = code;
        self.status.free_pages = ledger.snapshot().free;
    }
    fn validate(&self, address: u64, len: usize, write: bool) -> Result<(), Errno> {
        // No bytes are accessed for an empty I/O request; descriptor/handle
        // validity is still checked by Process/LocalIpc after this check.
        if len == 0 {
            return Ok(());
        }
        #[cfg(feature = "ported")]
        if self.linux {
            return self
                .executable
                .validate(address, len, write)
                .or_else(|_| self.heap.validate_access(address, len, write))
                .or_else(|_| self.shared.validate(address, len, write));
        }
        let fixed = if write {
            self.arena.validate_write(address, len)
        } else {
            self.arena.read(address, len).map(|_| ())
        };
        fixed.or_else(|_| self.heap.validate_access(address, len, write))
    }
    fn copy_from(&self, address: u64, out: &mut [u8]) -> Result<(), Errno> {
        if out.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "ported")]
        if self.linux {
            return self
                .executable
                .read(address, out)
                .or_else(|_| self.heap.read(address, out))
                .or_else(|_| self.shared.read(address, out));
        }
        match self.arena.read(address, out.len()) {
            Ok(bytes) => {
                out.copy_from_slice(bytes);
                Ok(())
            }
            Err(_) => self.heap.read(address, out),
        }
    }
    fn copy_to(&mut self, address: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "ported")]
        if self.linux {
            return self
                .executable
                .write(address, data)
                .or_else(|_| self.heap.write(address, data))
                .or_else(|_| self.shared.write(address, data));
        }
        if self.arena.validate_write(address, data.len()).is_ok() {
            self.arena.write(address, data)
        } else {
            self.heap.write(address, data)
        }
    }
    fn path(&self, addr: u64, out: &mut [u8; 96]) -> Result<usize, Errno> {
        for (i, byte) in out.iter_mut().enumerate() {
            self.copy_from(
                addr.checked_add(i as u64).ok_or(Errno::Fault)?,
                core::slice::from_mut(byte),
            )?;
            if *byte == 0 {
                return Ok(i);
            }
        }
        Err(Errno::Nametoolong)
    }
    fn syscall(
        &mut self,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
    ) -> Result<u64, Errno> {
        #[cfg(feature = "ported")]
        if self.linux {
            // Readiness only made the context runnable. Validate the saved
            // OFD generation now, immediately before the actual SVC replay;
            // another thread may have closed/reused the FD in that interval.
            let binding = self.thread.retry_descriptor.take();
            self.thread.retry_syscall = false;
            if let Some((descriptor, identity)) = binding {
                self.process
                    .validate_description_identity(descriptor, identity)?;
            }
            let result = self.linux_syscall(fs, ledger, ipc);
            #[cfg(feature = "abi-trace")]
            if self.status.pid > 1 {
                super::log(
                    b"ABI_TRACE pid,tid,pc,number,arg0,arg1,arg2,arg3,arg4,result MECHANISM\n",
                );
                for value in [
                    self.status.pid as u64,
                    self.thread.tid as u64,
                    self.thread.context.pc,
                    self.thread.context.regs[8],
                    self.thread.context.regs[0],
                    self.thread.context.regs[1],
                    self.thread.context.regs[2],
                    self.thread.context.regs[3],
                    self.thread.context.regs[4],
                    result.unwrap_or_else(|e| (-(e as i64)) as u64),
                ] {
                    super::hex(value);
                }
            }
            return result;
        }
        let [a, b, c] = [
            self.thread.context.regs[0],
            self.thread.context.regs[1],
            self.thread.context.regs[2],
        ];
        let mut buf = [0u8; 1024];
        let mut path = [0u8; 96];
        match self.thread.context.regs[8] {
            1 | 8 | 9 | 10 | 11 => {
                let n = self.path(a, &mut path)?;
                let p = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                match self.thread.context.regs[8] {
                    1 => self
                        .process
                        .open(fs, p, u32::try_from(b).map_err(|_| Errno::Inval)?, c as u16)
                        .map(|n| n as u64),
                    8 => self.process.unlink(fs, p).map(|_| 0),
                    9 => self.process.mkdir(fs, p, b as u16).map(|_| 0),
                    10 => self.process.rmdir(fs, p).map(|_| 0),
                    11 => self.process.chdir(fs, p).map(|_| 0),
                    _ => unreachable!(),
                }
            }
            2 => {
                let released = self.process.close(fs, fd(a)?)?;
                objects::release(fs, released).map(|_| 0)
            }
            3 => {
                let n = count(c)?;
                self.validate(b, n, true)?;
                let n = self.process.read(fs, fd(a)?, &mut buf[..n.min(1024)])?;
                self.copy_to(b, &buf[..n])?;
                Ok(n as u64)
            }
            4 => {
                let n = count(c)?;
                self.validate(b, n, false)?;
                let n = n.min(buf.len());
                self.copy_from(b, &mut buf[..n])?;
                self.process
                    .write(fs, &mut Output, fd(a)?, &buf[..n])
                    .map(|n| n as u64)
            }
            5 => self.process.lseek(
                fs,
                fd(a)?,
                b as i64,
                u32::try_from(c).map_err(|_| Errno::Inval)?,
            ),
            6 => self.process.dup(fd(a)?).map(|n| n as u64),
            7 => {
                let (descriptor, released) = self.process.dup2(fs, fd(a)?, fd(b)?)?;
                objects::release(fs, released)?;
                Ok(descriptor as u64)
            }
            12 => {
                let n = count(b)?;
                if n == 0 {
                    return Err(Errno::Inval);
                }
                self.validate(a, n, true)?;
                let n = self.process.getcwd(&mut buf[..n.min(1024)])?;
                self.copy_to(a, &buf[..n])?;
                Ok(a)
            }
            13 => Ok(self.status.pid as u64),
            14 => Ok(self.process.umask(a as u16) as u64),
            15 => {
                self.finish(fs, ledger, ipc, UserState::Exited, (a & 255) as u32);
                Ok(0)
            }
            16 => {
                let handle = u32::try_from(a).map_err(|_| Errno::Badf)?;
                let n = count(c)?;
                self.validate(b, n, false)?;
                let n = n.min(buf.len());
                self.copy_from(b, &mut buf[..n])?;
                let sent = ipc.write(self.status.pid, handle, &buf[..n])?;
                self.status.ipc_sent = self.status.ipc_sent.saturating_add(sent as u64);
                Ok(sent as u64)
            }
            17 => {
                let handle = u32::try_from(a).map_err(|_| Errno::Badf)?;
                let n = count(c)?;
                self.validate(b, n, true)?;
                let received = ipc.read(self.status.pid, handle, &mut buf[..n.min(1024)])?;
                self.copy_to(b, &buf[..received])?;
                self.status.ipc_received = self.status.ipc_received.saturating_add(received as u64);
                Ok(received as u64)
            }
            18 => Ok(0),     // Yield; dispatch loop returns after storing the result.
            19 => Ok(now()), // Native monotonic milliseconds; not POSIX clock_gettime.
            20 => {
                let handle = u32::try_from(a).map_err(|_| Errno::Badf)?;
                let interest = match b {
                    1 => Interest::Readable,
                    2 => Interest::Writable,
                    _ => return Err(Errno::Inval),
                };
                if !ipc.ready(self.status.pid, handle, interest)? {
                    self.block(Wait::Ipc(handle, interest));
                }
                Ok(0)
            }
            21 => {
                if a > 60_000 {
                    return Err(Errno::Inval);
                }
                let until = now().checked_add(a).ok_or(Errno::Overflow)?;
                if a != 0 {
                    self.block(Wait::Sleep(until));
                }
                Ok(0)
            }
            22 => {
                if b != 0 || c != 0 {
                    return Err(Errno::Inval);
                }
                self.heap
                    .allocate(usize::try_from(a).map_err(|_| Errno::Inval)?)
            }
            23 => {
                if c != 0 {
                    return Err(Errno::Inval);
                }
                self.heap
                    .unmap(a, usize::try_from(b).map_err(|_| Errno::Inval)?)?;
                Ok(0)
            }
            24 => {
                #[cfg(feature = "graphics")]
                {
                    let (x, y) = (a as u32 as usize, (a >> 32) as usize);
                    let (width, height) = (b as u32 as usize, (b >> 32) as usize);
                    let n = width
                        .checked_mul(height)
                        .filter(|n| *n > 0 && *n <= 1024)
                        .ok_or(Errno::Inval)?;
                    let mut bytes = [0u8; 4096];
                    let mut pixels = [0u32; 1024];
                    self.copy_from(c, &mut bytes[..n * 4])?;
                    for (pixel, raw) in pixels[..n].iter_mut().zip(bytes[..n * 4].chunks_exact(4)) {
                        *pixel = u32::from_le_bytes(raw.try_into().map_err(|_| Errno::Inval)?);
                    }
                    super::graphics::begin_blit(self.status.pid, x, y, width, height, &pixels[..n])
                        .map_err(|error| match error {
                            cyxia_driver_virtio::Error::Address => Errno::Inval,
                            cyxia_driver_virtio::Error::Device => Errno::Nodev,
                            cyxia_driver_virtio::Error::Busy => Errno::Again,
                            _ => Errno::Io,
                        })?;
                    self.block(Wait::Display);
                    Ok(0)
                }
                #[cfg(not(feature = "graphics"))]
                {
                    Err(Errno::Nodev)
                }
            }
            _ => Err(Errno::Nosys),
        }
    }
    fn block(&mut self, wait: Wait) {
        self.thread.waiting = Some(wait);
        self.status.state = UserState::Waiting;
        self.status.waits = self.status.waits.saturating_add(1);
        self.refresh_thread_state();
    }
    fn wake(&mut self, time: u64, ipc: &mut LocalIpc) {
        if !self.thread.active || self.thread.waiting.is_none() {
            return;
        }
        #[cfg(feature = "ported")]
        if self.linux && self.thread.signals.ready() {
            // Blocking descriptor calls saved the SVC for retry. A caught signal
            // interrupts that call instead; SA_RESTART is explicitly unsupported.
            if self.thread.retry_syscall {
                self.thread.context.pc += 4;
                self.thread.retry_syscall = false;
            }
            self.thread.retry_descriptor = None;
            let error = self.sleep_interrupted().err().unwrap_or(Errno::Intr);
            self.thread.context.regs[0] = (-(error as i64)) as u64;
            self.thread.waiting = None;
            self.status.state = UserState::Running;
            self.thread.ready_since = time;
            self.status.wakeups = self.status.wakeups.saturating_add(1);
            return;
        }
        let ready = match self.thread.waiting {
            #[cfg(feature = "ported")]
            Some(Wait::Nanosleep { until, .. }) => time >= until,
            #[cfg(feature = "ported")]
            Some(Wait::Spawn | Wait::Child { .. }) => false,
            #[cfg(feature = "ported")]
            Some(Wait::Retry(until)) => time >= until,
            #[cfg(feature = "ported")]
            Some(Wait::TimerRead {
                descriptor,
                identity,
            }) => {
                // Keep a disarmed timer parked without repeatedly dispatching
                // EL0. Rearming an alias is visible through the shared OFD.
                match self
                    .process
                    .validate_description_identity(descriptor, identity)
                {
                    Ok(()) => self
                        .process
                        .timerfd_ready(descriptor, now_ns())
                        .unwrap_or(true),
                    Err(_) => true, // Replay returns EBADF, never reads a reused FD.
                }
            }
            #[cfg(feature = "ported")]
            Some(Wait::Futex { until, .. }) => {
                if time >= until {
                    self.thread.context.regs[0] = (-(Errno::Timedout as i64)) as u64;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "ported")]
            Some(Wait::Poll {
                address,
                count,
                until,
            }) => match self.poll_result(address, count) {
                Ok(n) if n > 0 || time >= until => {
                    self.thread.context.regs[0] = n as u64;
                    true
                }
                Ok(_) => false,
                Err(error) => {
                    self.thread.context.regs[0] = (-(error as i64)) as u64;
                    true
                }
            },
            #[cfg(feature = "ported")]
            Some(Wait::Epoll {
                descriptor,
                identity,
                address,
                count,
                until,
            }) => {
                let result = if self.process.epoll_identity(descriptor) == Ok(identity) {
                    self.epoll_result(descriptor, address, count)
                } else {
                    Err(Errno::Badf)
                };
                match result {
                    Ok(n) if n > 0 || time >= until => {
                        self.thread.context.regs[0] = n as u64;
                        true
                    }
                    Ok(_) => false,
                    Err(error) => {
                        self.thread.context.regs[0] = (-(error as i64)) as u64;
                        true
                    }
                }
            }
            #[cfg(feature = "ported")]
            Some(Wait::Unix {
                handle,
                descriptor,
                write,
            }) => {
                // Wake a cancelled binding even if an alias keeps the old
                // endpoint alive and unready. The actual retry also rechecks.
                match (|| {
                    let (bound_fd, identity) = self.thread.retry_descriptor.ok_or(Errno::Badf)?;
                    if bound_fd != descriptor {
                        return Err(Errno::Badf);
                    }
                    self.process
                        .validate_description_identity(descriptor, identity)?;
                    unix::with(|s| {
                        s.poll(
                            self.process.backend_owner(descriptor)?,
                            unix::handle(handle),
                        )
                    })
                })() {
                    Ok(ready) => {
                        ready.hangup
                            || if write {
                                ready.writable
                            } else {
                                ready.readable
                            }
                    }
                    Err(_) => true, // Retry the syscall to return its precise error.
                }
            }
            #[cfg(feature = "graphics")]
            Some(Wait::Display) => false,
            Some(Wait::Sleep(until)) => time >= until,
            Some(Wait::Ipc(handle, interest)) => match ipc.ready(self.status.pid, handle, interest)
            {
                Ok(ready) => ready,
                Err(error) => {
                    self.thread.context.regs[0] = (-(error as i64)) as u64;
                    true
                }
            },
            None => unreachable!(),
        };
        if ready {
            self.thread.waiting = None;
            self.status.state = UserState::Running;
            self.thread.ready_since = time;
            self.status.wakeups = self.status.wakeups.saturating_add(1);
        }
    }
    fn tick(
        &mut self,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
        competing: usize,
    ) -> bool {
        if self.status.state != UserState::Running
            || !self.thread.active
            || self.thread.waiting.is_some()
        {
            return false;
        }
        let start = now();
        if self
            .test_lifetime
            .is_some_and(|limit| start.saturating_sub(self.started) >= limit)
        {
            self.finish(fs, ledger, ipc, UserState::Timeout, 124);
            return false;
        }
        #[cfg(feature = "ported")]
        let thread_decision = self.threads.shared.dispatch.take();
        let (budget, model) =
            cyxia_ai_runtime::user_cpu_policy(self.thread.cpu_bound, competing.min(8)).unwrap();
        ai::record(AiDomain::CpuQuantum, |c| c.proposal(model));
        let mut entered = false;
        // AI controls 1/4ms dispatch budget; IRQ exits bound uncooperative code.
        // At most 32 syscall returns per dispatch is an independent safety cap.
        for _ in 0..32 {
            #[cfg(feature = "ported")]
            match self.deliver_signal() {
                Ok(None) => {}
                Ok(Some(code)) => {
                    self.status.exit_signal = code.saturating_sub(128);
                    self.finish(fs, ledger, ipc, UserState::Exited, code);
                    break;
                }
                Err(_) => {
                    self.finish(fs, ledger, ipc, UserState::Fault, 139);
                    break;
                }
            }
            let root = &self.l1 as *const Table as u64 - super::HIGH;
            // Receipt at the actual execution boundary. Pending fatal signals or
            // expired test lifetimes must not inflate successful AI dispatches.
            if !entered {
                entered = true;
                self.status.last_slice_ms = budget;
                self.status.cpu_model = model;
                self.status.ai_slices = self.status.ai_slices.saturating_add(1);
                ai::record(AiDomain::CpuQuantum, |c| {
                    c.dispatch(DecisionSource::AiDirect)
                });
                #[cfg(feature = "ported")]
                if let Some((model, source)) = thread_decision {
                    self.status.thread_rank_model = model;
                    match source {
                        DecisionSource::AiDirect => {
                            self.status.thread_ai_selections =
                                self.status.thread_ai_selections.saturating_add(1)
                        }
                        DecisionSource::SafetyGuard => {
                            self.status.thread_guard_selections =
                                self.status.thread_guard_selections.saturating_add(1)
                        }
                        _ => unreachable!(),
                    }
                    ai::record(AiDomain::CpuThread, |c| c.dispatch(source));
                }
            }
            ai::record(AiDomain::CpuQuantum, |c| c.entered());
            // Arena/context/tables are static, exclusively owned on CPU0; validated RX/RW
            // leaves expose no kernel memory. Handler only captures context, never FS.
            unsafe { user::enter(&mut self.thread.context, root) };
            ai::record(AiDomain::CpuQuantum, |c| c.returned());
            if self.thread.context.kind == 9 {
                self.status.preemptions += 1;
                self.thread.cpu_bound = true;
            } else if self.thread.context.esr >> 26 == 0x15 && self.thread.context.esr & 0xffff == 0
            {
                self.status.syscalls += 1;
                self.thread.cpu_bound = false;
                let result = self.syscall(fs, ledger, ipc);
                self.thread.context.regs[0] = match result {
                    Ok(n) => n,
                    Err(e) => (-(e as i64)) as u64,
                };
            } else {
                self.status.esr = self.thread.context.esr;
                self.status.far = self.thread.context.far;
                #[cfg(feature = "ported")]
                if self.linux {
                    let signal = if matches!(self.thread.context.esr >> 26, 0x20 | 0x24) {
                        11
                    } else {
                        4
                    };
                    let info = cyxia_posix::signal::Info {
                        code: 1,
                        sender_pid: self.status.pid,
                        address: if signal == 4 {
                            self.thread.context.pc
                        } else {
                            self.thread.context.far
                        },
                    };
                    if self.queue_signal(signal, info, true).is_ok() {
                        continue;
                    }
                }
                self.finish(fs, ledger, ipc, UserState::Fault, 139);
            }
            let yield_number = 18;
            #[cfg(feature = "ported")]
            let yield_number = if self.linux { 124 } else { yield_number };
            if self.status.state != UserState::Running
                || !self.thread.active
                || self.thread.waiting.is_some()
                || self.thread.context.regs[8] == yield_number
                || now().saturating_sub(start) >= budget
            {
                break;
            }
        }
        if entered {
            ai::record(AiDomain::CpuQuantum, |c| {
                c.elapsed(now().saturating_sub(start))
            });
        } else {
            ai::record(AiDomain::CpuQuantum, |c| c.cancelled());
            #[cfg(feature = "ported")]
            if thread_decision.is_some() {
                ai::record(AiDomain::CpuThread, |c| c.cancelled());
            }
        }
        entered
    }
}
fn fd(v: u64) -> Result<i32, Errno> {
    i32::try_from(v).map_err(|_| Errno::Badf)
}
fn count(v: u64) -> Result<usize, Errno> {
    if v > isize::MAX as u64 {
        Err(Errno::Inval)
    } else {
        usize::try_from(v).map_err(|_| Errno::Inval)
    }
}
impl Supervisor {
    #[cfg(feature = "ported")]
    // ELF/argv preparation is occasional; do not retain its large temporaries
    // on the foreground dispatch stack while unrelated user syscalls execute.
    #[inline(never)]
    fn launch_executable(&mut self, name: &str, fs: &mut FileSystem) -> Result<usize, Errno> {
        let image_name = if matches!(name, "x11-interactive" | "x11-demo") {
            "x11-probe"
        } else if name == "egl-x11-probe" {
            "egl-probe"
        } else if name == "gtk-smoke" {
            "gtk-probe"
        } else if matches!(name, "pcmanfm-desktop" | "pcmanfm-home") {
            "pcmanfm"
        } else if matches!(
            name,
            "smithay-dynamic-a"
                | "smithay-dynamic-b"
                | "smithay-dynamic-c"
                | "smithay-dynamic-reject"
        ) {
            "smithay-dynamic-client"
        } else {
            name
        };
        let (_, path, bytes) = PORTED
            .iter()
            .find(|(n, _, _)| *n == image_name)
            .ok_or(Errno::Noent)?;
        let plan = cyxia_posix::executable::parse(bytes).map_err(|_| Errno::Inval)?;
        // Read-only boot assets retain their bytes in kernel ROM mappings.
        // Directories use the real RAM filesystem and its ordinary AI admission.
        let mut directories = Process::empty(objects::table(), 0);
        for path in ["/tmp", "/var", "/var/log"]
            .into_iter()
            .chain(ROOT_FILES.iter().map(|(path, _)| *path))
        {
            for (index, _) in path.match_indices('/').skip(1) {
                match directories.mkdir(fs, &path[..index], 0o755) {
                    Ok(()) | Err(Errno::Exist) => {}
                    Err(error) => return Err(error),
                }
            }
            if !ROOT_FILES.iter().any(|(file, _)| *file == path) {
                match directories.mkdir(fs, path, 0o777) {
                    Ok(()) | Err(Errno::Exist) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        for (path, _) in ROOT_FILES {
            let path = cyxia_ai_fs::Path::resolve(cyxia_ai_fs::Path::ROOT, path)?;
            fs.register_boot_file(path)?;
        }
        let mut random = [0u8; 16];
        super::entropy::fill(&mut random)?;
        // Keep the existing per-process 8-page admission floor while the image
        // obtains its own separately accounted executable-memory grant. The old
        // fixed user image is immediately unmapped before any entry occurs.
        let slot = self.launch("idle", true)?;
        let runner = &mut self.runners[slot];
        let owner = runner.lease.ok_or(Errno::Io)?.0;
        let normal_argv: &[&[u8]] = &[path.as_bytes()];
        // Fixture roles select a workload, never the authenticated Wayland
        // identity: the compositor obtains that from the connected socket.
        let dynamic_role: &[u8] = match name {
            "smithay-dynamic-a" => b"1",
            "smithay-dynamic-b" => b"2",
            "smithay-dynamic-c" => b"3",
            "smithay-dynamic-reject" => b"0",
            _ => b"",
        };
        let dynamic_argv: &[&[u8]] = &[path.as_bytes(), dynamic_role];
        let xorg_argv: &[&[u8]] = &[
            path.as_bytes(),
            b":0",
            b"-fp",
            b"built-ins",
            b"-noreset",
            b"-retro",
            b"-a",
            b"1",
            b"-t",
            b"0",
            b"-nolock",
            b"-dumbSched",
        ];
        let interactive_argv: &[&[u8]] = &[
            path.as_bytes(),
            if name == "x11-demo" {
                b"--demo"
            } else {
                b"--interactive"
            },
        ];
        let twm_argv: &[&[u8]] = &[path.as_bytes(), b"-f", b"/etc/X11/twm/system.twmrc"];
        let gtk_argv: &[&[u8]] = &[path.as_bytes(), b"--smoke"];
        let pcmanfm_argv: &[&[u8]] = &[
            path.as_bytes(),
            if name == "pcmanfm-desktop" {
                b"--desktop"
            } else {
                b"/"
            },
        ];
        let openbox_argv: &[&[u8]] = &[
            path.as_bytes(),
            b"--sm-disable",
            b"--config-file",
            b"/etc/xdg/openbox/rc.xml",
        ];
        let egl_x11_argv: &[&[u8]] = &[path.as_bytes(), b"x11"];
        let sp = match runner.executable.load(
            slot,
            owner,
            &plan,
            super::exec_memory::StackInput {
                random,
                argv: if name == "xorg" {
                    xorg_argv
                } else if name == "twm" {
                    twm_argv
                } else if name == "openbox" {
                    openbox_argv
                } else if name == "gtk-smoke" {
                    gtk_argv
                } else if matches!(name, "pcmanfm-desktop" | "pcmanfm-home") {
                    pcmanfm_argv
                } else if matches!(name, "x11-interactive" | "x11-demo") {
                    interactive_argv
                } else if name == "egl-x11-probe" {
                    egl_x11_argv
                } else if !dynamic_role.is_empty() {
                    dynamic_argv
                } else {
                    normal_argv
                },
                envp: &[
                    b"PATH=/bin",
                    b"LANG=C",
                    b"TZ=UTC",
                    b"DISPLAY=:0",
                    b"HOME=/",
                    b"GSETTINGS_BACKEND=memory",
                    b"GIO_USE_VFS=local",
                    b"GTK_USE_PORTAL=0",
                    b"GTK_IM_MODULE=simple",
                ],
                execfn: path.as_bytes(),
            },
        ) {
            Ok(sp) => sp,
            Err(error) => {
                runner.finish(fs, &mut self.ledger, &mut self.ipc, UserState::Killed, 137);
                return Err(error);
            }
        };
        runner.l2.0[0] = 0;
        runner.arena.clear();
        for (i, root) in runner.executable.roots() {
            runner.l2.0[i] = root;
        }
        runner.thread.context = Context {
            pc: plan.entry,
            sp,
            ..Context::empty()
        };
        runner.linux = true;
        Ok(slot)
    }
    fn launch(&mut self, mode: &str, native: bool) -> Result<usize, Errno> {
        let mut attempt = Attempt::default();
        let result = self.launch_accounted(mode, native, &mut attempt);
        ai::admission(AiDomain::Process, attempt, &result);
        result
    }
    fn launch_accounted(
        &mut self,
        mode: &str,
        native: bool,
        attempt: &mut Attempt,
    ) -> Result<usize, Errno> {
        let slot = self
            .runners
            .iter()
            .position(|r| !r.status.state.active())
            .ok_or(Errno::Again)?;
        let pid = self.next_pid;
        let next = pid
            .checked_add(1)
            .filter(|p| *p < 0x1000_0000)
            .ok_or(Errno::Overflow)?;
        self.runners[slot].start(
            mode,
            if native { SERVICES } else { IMAGE },
            pid,
            if native { None } else { Some(500) },
            &mut self.ledger,
            attempt,
        )?;
        let owner = self.runners[slot].lease.ok_or(Errno::Io)?.0;
        self.runners[slot].heap.bind(slot, owner);
        for (index, root) in self.runners[slot].heap.roots().into_iter().enumerate() {
            self.runners[slot].l2.0[index + (cyxia_posix::vm::BASE / 0x200000) as usize] = root;
        }
        #[cfg(feature = "ported")]
        for (index, root) in self.runners[slot].shared.roots() {
            self.runners[slot].l2.0[index] = root;
        }
        self.next_pid = next;
        self.focus_pid = pid;
        if native {
            self.runners[slot].thread.context.regs[0] = match mode {
                "idle" => 0,
                "spin" => 1,
                "fault" => 2,
                "server" => 3,
                "client" => 4,
                "heap" => 5,
                "heapfault" => 6,
                "paint" => 7,
                "fpu" => 8,
                "heapexec" => 9,
                _ => unreachable!(),
            };
            self.runners[slot].thread.context.regs[1] = 0;
        }
        Ok(slot)
    }
    fn pair(&mut self, fs: &mut FileSystem) -> Result<[u32; 2], Errno> {
        let a = self.launch("server", true)?;
        let b = match self.launch("client", true) {
            Ok(slot) => slot,
            Err(error) => {
                self.runners[a].finish(fs, &mut self.ledger, &mut self.ipc, UserState::Killed, 137);
                return Err(error);
            }
        };
        let pids = [self.runners[a].status.pid, self.runners[b].status.pid];
        match self.ipc.pair(pids[0], pids[1]) {
            Ok(handles) => {
                self.runners[a].thread.context.regs[1] = handles[0] as u64;
                self.runners[b].thread.context.regs[1] = handles[1] as u64;
                Ok(pids)
            }
            Err(error) => {
                for slot in [a, b] {
                    self.runners[slot].finish(
                        fs,
                        &mut self.ledger,
                        &mut self.ipc,
                        UserState::Killed,
                        137,
                    );
                }
                Err(error)
            }
        }
    }
    fn poll(&mut self, shell: &mut cyxia_shell::Shell, out: &mut impl Write) {
        #[cfg(feature = "ported")]
        {
            self.collect_children();
            // The bounded PTY queue carries only validated controlling-owner
            // PIDs. No IRQ delivers a signal or accesses a user context.
            for _ in 0..16 {
                let Some((pid, signal)) = pty::take_signal() else {
                    break;
                };
                if let Some(runner) = self
                    .runners
                    .iter_mut()
                    .find(|r| r.status.pid == pid && r.status.state.active())
                {
                    let _ = runner.threads.shared.pending.raise(
                        &runner.threads.shared.actions,
                        u32::from(signal),
                        cyxia_posix::signal::Info {
                            code: 128,
                            ..cyxia_posix::signal::Info::EMPTY
                        },
                        false,
                    );
                }
            }
        }
        if let Some(request) = shell.take_user_request() {
            match request {
                UserRequest::Execute(name) => {
                    #[cfg(feature = "ported")]
                    match self.launch_executable(name, shell.fs_mut()) {
                        Ok(slot)=> writeln!(out,"\r\nELF pid={} started; ABI=Linux-AArch64-subset image AI_DIRECT model=8195 pages={}\r",self.runners[slot].status.pid,self.runners[slot].executable.pages()).unwrap(),
                        Err(error)=>writeln!(out,"\r\nELF start failed: {error:?}\r").unwrap(),
                    }
                    #[cfg(not(feature = "ported"))]
                    writeln!(
                        out,
                        "\r\nELF {name} start failed: ported feature unavailable\r"
                    )
                    .unwrap();
                }
                UserRequest::Run(mode) | UserRequest::Spawn(mode) => {
                    match self.launch(mode, matches!(request, UserRequest::Spawn(_))) {
                        Ok(slot) => writeln!(
                            out,
                            "\r\nEL0 pid={} started; memory AI_DIRECT model=8193 pages=8\r",
                            self.runners[slot].status.pid
                        )
                        .unwrap(),
                        Err(error) => writeln!(out, "\r\nEL0 start failed: {error:?}\r").unwrap(),
                    }
                }
                UserRequest::Pair => match self.pair(shell.fs_mut()) {
                    Ok(pids) => writeln!(
                        out,
                        "\r\nEL0 IPC pair server={} client={} memory AI_DIRECT model=8193\r",
                        pids[0], pids[1]
                    )
                    .unwrap(),
                    Err(error) => writeln!(out, "\r\nEL0 pair failed: {error:?}\r").unwrap(),
                },
                UserRequest::Kill(pid) => {
                    let pid = pid.unwrap_or(self.focus_pid);
                    if let Some(runner) = self
                        .runners
                        .iter_mut()
                        .find(|r| r.status.pid == pid && r.status.state.active())
                    {
                        runner.finish(
                            shell.fs_mut(),
                            &mut self.ledger,
                            &mut self.ipc,
                            UserState::Killed,
                            137,
                        );
                        writeln!(out, "\r\nEL0 pid={pid} killed; pages reclaimed\r").unwrap();
                    } else {
                        writeln!(out, "\r\nEL0 kill failed: Noent\r").unwrap();
                    }
                }
            }
        }
        let time = now();
        #[cfg(feature = "graphics")]
        if let Some((pid, tid)) = self.display_owner
            && let Some(result) = super::graphics::poll_blit()
        {
            self.display_owner = None;
            if let Some(runner) = self.runners.iter_mut().find(|r| r.status.pid == pid) {
                runner.complete_display(tid, result.is_ok(), time);
            }
        }
        for runner in &mut self.runners {
            runner.prepare_threads(time, &mut self.ipc);
        }
        let candidates = core::array::from_fn::<_, SLOTS, _>(|i| {
            let runner = &self.runners[i];
            (runner.status.state == UserState::Running).then_some(cyxia_ai_runtime::UserCandidate {
                waiting_ms: time.saturating_sub(runner.thread.ready_since),
                cpu_bound: runner.thread.cpu_bound,
            })
        });
        if let Some(decision) = cyxia_ai_runtime::user_dispatch_policy(&candidates).unwrap() {
            ai::record(AiDomain::CpuProcess, |c| c.proposal(decision.model));
            let ready = candidates.iter().flatten().count();
            let competing = shell
                .runtime_mut()
                .tasks()
                .filter(|t| t.state == cyxia_ai_runtime::TaskState::Ready && !t.paused)
                .count()
                + ready
                - 1;
            let runner = &mut self.runners[decision.index];
            if runner.tick(shell.fs_mut(), &mut self.ledger, &mut self.ipc, competing) {
                runner.status.rank_model = decision.model;
                match decision.source {
                    DecisionSource::AiDirect => {
                        runner.status.ai_selections = runner.status.ai_selections.saturating_add(1)
                    }
                    DecisionSource::SafetyGuard => {
                        runner.status.guard_selections =
                            runner.status.guard_selections.saturating_add(1)
                    }
                    _ => unreachable!(),
                }
                ai::record(AiDomain::CpuProcess, |c| c.dispatch(decision.source));
            } else {
                ai::record(AiDomain::CpuProcess, |c| c.cancelled());
            }
            #[cfg(feature = "graphics")]
            if matches!(runner.thread.waiting, Some(Wait::Display)) {
                // A successful submission copied pixels into pinned DMA memory;
                // retain this PID until its fence even if the process is killed.
                assert!(self.display_owner.is_none());
                self.display_owner = Some((runner.status.pid, runner.thread.tid));
            }
            runner.thread.ready_since = now();
            if !runner.status.state.active() {
                writeln!(
                    out,
                    "\r\nEL0 pid={} {:?} code={} free_pages={} esr={:#x} far={:#x}\r",
                    runner.status.pid,
                    runner.status.state,
                    runner.status.code,
                    self.ledger.snapshot().free,
                    runner.status.esr,
                    runner.status.far
                )
                .unwrap();
            }
        }
        #[cfg(feature = "ported")]
        {
            for index in 0..SLOTS {
                self.service_spawn(index, shell.fs_mut());
            }
            self.collect_children();
        }
        let free = self.ledger.snapshot().free;
        for runner in &mut self.runners {
            runner.status.free_pages = free;
            runner.status.heap_pages = runner.heap.used();
            runner.status.heap_free = runner.heap.free();
            runner.status.heap_model = runner.heap.model;
            #[cfg(feature = "ported")]
            {
                runner.status.image_pages = runner.executable.pages();
                runner.status.image_free = runner.executable.free();
            }
        }
        shell.set_user_processes(core::array::from_fn(|i| self.runners[i].status));
        if let Some(runner) = self.runners.iter().find(|r| r.status.pid == self.focus_pid) {
            shell.set_user_status(runner.status);
        }
    }
}
pub fn poll(shell: &mut cyxia_shell::Shell, out: &mut impl Write) {
    // Static process roots/arenas are never moved. Only the CPU0 foreground owns
    // this service; IRQ capture touches only the currently entered Context.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SUPERVISOR)).poll(shell, out);
    }
}
/// Single-core foreground cumulative execution receipts; never resets on PID reuse.
pub fn ai_status(out: &mut impl Write) {
    ai::status(out);
    object_status(out);
    #[cfg(feature = "ported")]
    crate::shared_memory::status(out);
}
pub fn object_snapshot() -> cyxia_posix::open_description::Snapshot {
    objects::table().snapshot()
}
pub fn object_status(out: &mut impl Write) {
    let s = object_snapshot();
    writeln!(
        out,
        "OFD_OBJECTS live={} references={} retired={} capacity={} epolls={} watches={} fd_refs={} staged_refs={} inflight_refs={} staged_messages={} inflight_messages={}\r",
        s.live, s.references, s.retired, s.capacity, s.epolls, s.watches, s.fd_references, s.staged_references, s.inflight_references, s.staged_messages, s.inflight_messages
    )
    .unwrap();
    writeln!(out, "ANCILLARY_OBJECTS messages={} references={} staged_messages={} inflight_messages={} staged_refs={} inflight_refs={} capacity_messages={} capacity_references={} backing=BOOTSTRAP policy=AI_DIRECT model=8193\r", s.staged_messages + s.inflight_messages, s.staged_references + s.inflight_references, s.staged_messages, s.inflight_messages, s.staged_references, s.inflight_references, cyxia_posix::ancillary::MESSAGES, cyxia_posix::ancillary::REFERENCES).unwrap();
}
