// Process-owned dependencies for the production wake, restart, and nanosleep
// bodies. Keep the syscall context and wait descriptor on the target thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Errno { Intr = 4, Io = 5, Badf = 9, Again = 11, Fault = 14, Timedout = 110 }
type Interest = ();
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// PRODUCTION_WAIT

#[derive(Clone, Debug, PartialEq, Eq)]
struct Context {
    bytes: [u8; 3800],
    result: u64,
    syscall: u64,
    pc: u64,
}
impl Context {
    fn set_result(&mut self, result: u64) { self.result = result; }
    fn restart_syscall(&mut self) -> Result<(), Errno> { self.pc -= 2; Ok(()) }
    fn cancel_restart(&mut self) -> Result<(), Errno> { self.pc += 2; Ok(()) }
    fn syscall_number(&self) -> u64 { self.syscall }
    fn arguments(&self) -> [u64; 6] { [0; 6] }
}
impl Signals { fn ready(&self) -> bool { self.signalled } }

mod process_arch { pub const IMAGE_ABI: () = (); }
mod signal {
    // This fixture models one restartable and one non-restartable syscall.
    pub fn restartable_syscall(_: (), number: u64, _: [u64; 6]) -> bool { number == 0 }
}
impl Thread {
    // PRODUCTION_RESTART
}

struct Process;
impl Process {
    fn validate_description_identity(&self, fd: i32, id: u64) -> Result<(), Errno> {
        if fd == 7 && id == 99 { Ok(()) } else { Err(Errno::Badf) }
    }
    fn epoll_wait_needs_sample(&self, fd: i32, identity: u64, epoch: u64) -> Result<bool, Errno> {
        self.validate_description_identity(fd, identity)?;
        Ok(epoch != self.epoll_invalidation_epoch())
    }
    fn epoll_invalidation_epoch(&self) -> u64 { 0 }
    fn timerfd_ready(&self, _: i32, _: u64) -> Result<bool, Errno> { Ok(false) }
    fn backend_owner(&self, _: i32) -> Result<u32, Errno> { Ok(41) }
}
mod unix {
    pub struct Socket;
    pub struct Ready { pub readable: bool, pub writable: bool, pub hangup: bool }
    impl Socket {
        pub fn poll(&self, _: u32, _: u64) -> Result<Ready, super::Errno> {
            Ok(Ready { readable: false, writable: true, hangup: false })
        }
    }
    pub fn inspect<R>(f: impl FnOnce(&Socket) -> R) -> R { f(&Socket) }
    pub fn handle(raw: u64) -> u64 { raw }
}
impl LocalIpc {
    fn readiness_epoch(&self) -> u64 { IPC_EPOCH.load(Ordering::SeqCst) as u64 }
    fn ready(&mut self, pid: u32, handle: u32, _: Interest) -> Result<bool, Errno> {
        assert_eq!(pid, 41);
        self.wakes.push(handle);
        if handle == 100 {
            Ok(self.readiness_epoch() != 0)
        } else {
            Err(Errno::Badf)
        }
    }
}
impl Runner {
    fn copy_to(&mut self, address: u64, bytes: &[u8]) -> Result<(), Errno> {
        let at = address as usize;
        self.memory.get_mut(at..at + bytes.len()).ok_or(Errno::Fault)?.copy_from_slice(bytes);
        Ok(())
    }
    fn poll_result(&mut self, address: u64, count: usize, _: Option<usize>) -> Result<usize, Errno> {
        self.copy_to(address, &[count as u8])?;
        Ok(1)
    }
    fn epoll_result(&mut self, fd: i32, address: u64, count: usize, resample: bool) -> Result<usize, Errno> {
        assert_eq!(fd, 7);
        if !resample { return Ok(0); }
        if address == 0 {
            EPOLL_SAMPLES.fetch_add(1, Ordering::SeqCst);
            return Ok(0);
        }
        self.copy_to(address, &[count as u8])?;
        Ok(2)
    }
    // PRODUCTION_WAKE
    // PRODUCTION_SLEEP_INTERRUPTED
}
