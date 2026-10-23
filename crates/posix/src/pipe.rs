//! Bounded anonymous byte pipes; the supervisor admits each pair and owns waits.
//! Spawn may grant an existing endpoint to another process. Closing duplicated
//! descriptors releases each process endpoint only on its last local reference.
use crate::{
    Errno,
    epoll::{ERR, HUP, IN, OUT},
};

pub const PIPES: usize = 8;
pub const PIPE_BUF: usize = 4096;
pub const CAPACITY: usize = PIPE_BUF;
const GENERATION_MAX: u64 = u64::MAX >> 8;

#[derive(Clone, Copy)]
struct Holder {
    owner: u32,
    open: [bool; 2],
}
impl Holder {
    const EMPTY: Self = Self {
        owner: 0,
        open: [false; 2],
    };
}
struct Pipe {
    generation: u64,
    holders: [Holder; crate::usermem::MAX_PROCESSES],
    open: [bool; 2],
    flags: [u32; 2],
    wakes: [u32; 2],
    bytes: [u8; CAPACITY],
    head: usize,
    len: usize,
}
impl Pipe {
    const fn new() -> Self {
        Self {
            generation: 0,
            holders: [Holder::EMPTY; crate::usermem::MAX_PROCESSES],
            open: [false; 2],
            flags: [crate::O_RDONLY, crate::O_WRONLY],
            wakes: [0; 2],
            bytes: [0; CAPACITY],
            head: 0,
            len: 0,
        }
    }
    fn clear(&mut self) {
        self.holders.fill(Holder::EMPTY);
        self.open = [false; 2];
        self.flags = [crate::O_RDONLY, crate::O_WRONLY];
        self.wakes = [0; 2];
        self.bytes.fill(0);
        self.head = 0;
        self.len = 0;
    }
}

pub struct Pipes {
    entries: [Pipe; PIPES],
}
impl Default for Pipes {
    fn default() -> Self {
        Self::new()
    }
}
impl Pipes {
    pub const fn new() -> Self {
        Self {
            entries: [const { Pipe::new() }; PIPES],
        }
    }
    pub fn free(&self) -> usize {
        self.entries
            .iter()
            .filter(|p| p.open == [false; 2] && p.generation < GENERATION_MAX)
            .count()
    }
    /// The returned pair is read end then write end; no partial allocation.
    pub fn pair(&mut self, owner: u32) -> Result<[u64; 2], Errno> {
        if owner == 0 {
            return Err(Errno::Inval);
        }
        let (index, pipe) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, p)| p.open == [false; 2] && p.generation < GENERATION_MAX)
            .ok_or(Errno::Nospc)?;
        pipe.generation += 1;
        pipe.holders[0] = Holder {
            owner,
            open: [true; 2],
        };
        pipe.open = [true; 2];
        let read = (pipe.generation << 8) | (index as u64 * 2);
        Ok([read, read | 1])
    }
    fn endpoint(&self, owner: u32, handle: u64) -> Result<(usize, usize), Errno> {
        let index = ((handle & 255) >> 1) as usize;
        let side = (handle & 1) as usize;
        let pipe = self.entries.get(index).ok_or(Errno::Badf)?;
        if owner == 0
            || pipe.generation != handle >> 8
            || !pipe
                .holders
                .iter()
                .any(|h| h.owner == owner && h.open[side])
        {
            return Err(Errno::Badf);
        }
        Ok((index, side))
    }
    /// Coalesced committed notifications, not the current readiness level.
    /// The supervisor observes every weak watch before clearing these bits.
    pub fn wake_mask(&self, owner: u32, handle: u64) -> Result<u32, Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        Ok(self.entries[index].wakes[side])
    }
    pub fn clear_wakes(&mut self) {
        for pipe in &mut self.entries {
            pipe.wakes = [0; 2];
        }
    }
    pub fn read(&mut self, owner: u32, handle: u64, out: &mut [u8]) -> Result<usize, Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        if side != 0 {
            return Err(Errno::Badf);
        }
        let pipe = &mut self.entries[index];
        if !out.is_empty() && pipe.len == 0 && pipe.open[1] {
            return Err(Errno::Again);
        }
        let n = out.len().min(pipe.len);
        for (i, byte) in out[..n].iter_mut().enumerate() {
            let offset = (pipe.head + i) % CAPACITY;
            *byte = pipe.bytes[offset];
            pipe.bytes[offset] = 0;
        }
        pipe.head = (pipe.head + n) % CAPACITY;
        pipe.len -= n;
        if n != 0 {
            pipe.wakes[1] |= OUT;
        }
        Ok(n)
    }
    pub fn write(&mut self, owner: u32, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        self.write_prefix(owner, handle, bytes, bytes.len())
    }
    /// A kernel copy window may cover only the beginning of a larger write.
    /// Preserve the original length so such writes do not acquire PIPE_BUF
    /// atomicity merely because the bounded copy window is one page.
    pub fn write_prefix(
        &mut self,
        owner: u32,
        handle: u64,
        bytes: &[u8],
        requested: usize,
    ) -> Result<usize, Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        if side != 1 {
            return Err(Errno::Badf);
        }
        if requested < bytes.len()
            || (requested <= PIPE_BUF && requested != bytes.len())
            || (requested != 0 && bytes.is_empty())
        {
            return Err(Errno::Inval);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let pipe = &mut self.entries[index];
        if !pipe.open[0] {
            return Err(Errno::Pipe);
        }
        let free = CAPACITY - pipe.len;
        // A write of at most PIPE_BUF is all-or-nothing even on a nonblocking
        // descriptor. The supervisor gathers writev before invoking this method.
        if free == 0 || (requested <= PIPE_BUF && free < bytes.len()) {
            return Err(Errno::Again);
        }
        let n = free.min(bytes.len());
        for (i, byte) in bytes[..n].iter().enumerate() {
            pipe.bytes[(pipe.head + pipe.len + i) % CAPACITY] = *byte;
        }
        pipe.len += n;
        pipe.wakes[0] |= IN;
        Ok(n)
    }
    /// Linux poll bits, including unconditional HUP/ERR on closed peers.
    pub fn poll(&self, owner: u32, handle: u64) -> Result<u16, Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        let pipe = &self.entries[index];
        Ok(if side == 0 {
            (u16::from(pipe.len != 0) * 0x41) | (u16::from(!pipe.open[1]) << 4)
        } else {
            (u16::from(pipe.len < CAPACITY) * 0x104) | (u16::from(!pipe.open[0]) << 3)
        })
    }
    pub fn pending(&self, owner: u32, handle: u64) -> Result<usize, Errno> {
        let (index, _) = self.endpoint(owner, handle)?;
        Ok(self.entries[index].len)
    }
    /// Share an endpoint once per process/open-description, preserving queued
    /// bytes and status flags. The caller owns rollback on a failed spawn.
    pub fn share(&mut self, owner: u32, handle: u64, child: u32) -> Result<(), Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        if child == 0 || child == owner {
            return Err(Errno::Inval);
        }
        let pipe = &mut self.entries[index];
        let slot = pipe
            .holders
            .iter()
            .position(|h| h.owner == child)
            .or_else(|| pipe.holders.iter().position(|h| h.owner == 0))
            .ok_or(Errno::Nospc)?;
        if pipe.holders[slot].open[side] {
            return Err(Errno::Exist);
        }
        pipe.holders[slot].owner = child;
        pipe.holders[slot].open[side] = true;
        Ok(())
    }
    pub fn flags(&self, owner: u32, handle: u64) -> Result<u32, Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        Ok(self.entries[index].flags[side])
    }
    pub fn set_flags(&mut self, owner: u32, handle: u64, flags: u32) -> Result<(), Errno> {
        if flags & !(3 | crate::O_APPEND | crate::O_NONBLOCK) != 0 {
            return Err(Errno::Inval);
        }
        let (index, side) = self.endpoint(owner, handle)?;
        let old = self.entries[index].flags[side];
        self.entries[index].flags[side] =
            (old & 3) | (flags & (crate::O_APPEND | crate::O_NONBLOCK));
        Ok(())
    }
    fn refresh(pipe: &mut Pipe) {
        let previous = pipe.open;
        for side in 0..2 {
            pipe.open[side] = pipe.holders.iter().any(|h| h.open[side]);
        }
        if previous[0] && !pipe.open[0] {
            pipe.wakes[1] |= ERR;
        }
        if previous[1] && !pipe.open[1] {
            pipe.wakes[0] |= HUP;
        }
        if pipe.open == [false; 2] {
            pipe.clear();
        }
    }
    pub fn close(&mut self, owner: u32, handle: u64) -> Result<(), Errno> {
        let (index, side) = self.endpoint(owner, handle)?;
        let pipe = &mut self.entries[index];
        let holder = pipe
            .holders
            .iter_mut()
            .find(|h| h.owner == owner)
            .ok_or(Errno::Badf)?;
        holder.open[side] = false;
        if holder.open == [false; 2] {
            holder.owner = 0;
        }
        Self::refresh(pipe);
        Ok(())
    }
    pub fn close_owner(&mut self, owner: u32) {
        for pipe in &mut self.entries {
            for holder in &mut pipe.holders {
                if holder.owner == owner {
                    *holder = Holder::EMPTY;
                }
            }
            Self::refresh(pipe);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wake_notifications_survive_ready_levels_and_respect_lifetime() {
        use crate::epoll::{HUP, IN, OUT};
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(10).unwrap();
        assert_eq!(pipes.wake_mask(10, r), Ok(0));
        pipes.write(10, w, b"a").unwrap();
        assert_eq!(pipes.wake_mask(10, r), Ok(IN));
        pipes.clear_wakes();
        pipes.write(10, w, b"b").unwrap();
        assert_eq!(pipes.wake_mask(10, r), Ok(IN));
        assert_ne!(pipes.poll(10, r).unwrap() & 1, 0);
        pipes.clear_wakes();
        pipes.read(10, r, &mut [0; 1]).unwrap();
        assert_eq!(pipes.wake_mask(10, w), Ok(OUT));
        pipes.clear_wakes();
        assert_eq!(pipes.write(10, w, &[]), Ok(0));
        assert_eq!(pipes.write(20, w, b"forged"), Err(Errno::Badf));
        assert_eq!(pipes.wake_mask(10, r), Ok(0));
        assert_eq!(pipes.wake_mask(20, r), Err(Errno::Badf));
        pipes.share(10, w, 20).unwrap();
        pipes.close(10, w).unwrap();
        assert_eq!(pipes.wake_mask(10, r), Ok(0));
        pipes.close_owner(20);
        assert_eq!(pipes.wake_mask(10, r), Ok(HUP));
        pipes.close(10, r).unwrap();
        let [fresh, _] = pipes.pair(10).unwrap();
        assert_ne!(fresh, r);
        assert_eq!(pipes.wake_mask(10, r), Err(Errno::Badf));
        assert_eq!(pipes.wake_mask(10, fresh), Ok(0));
    }

    #[test]
    fn full_pipe_failed_write_does_not_notify_but_read_releases_writer() {
        use crate::epoll::{ERR, IN, OUT};
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(1).unwrap();
        pipes.write(1, w, &[7; CAPACITY]).unwrap();
        pipes.clear_wakes();
        assert_eq!(pipes.write(1, w, b"x"), Err(Errno::Again));
        assert_eq!(pipes.wake_mask(1, r), Ok(0));
        pipes.read(1, r, &mut [0; 1]).unwrap();
        assert_eq!(pipes.wake_mask(1, w), Ok(OUT));
        pipes.write(1, w, b"x").unwrap();
        assert_eq!(pipes.wake_mask(1, r), Ok(IN));
        assert_eq!(pipes.poll(1, w).unwrap() & 4, 0);
        pipes.clear_wakes();
        pipes.close(1, r).unwrap();
        assert_eq!(pipes.wake_mask(1, w), Ok(ERR));
    }

    #[test]
    fn atomic_small_writes_wrap_eof_and_poll() {
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(10).unwrap();
        let mut data = [0; CAPACITY];
        assert_eq!(pipes.read(10, r, &mut data), Err(Errno::Again));
        assert_eq!(pipes.poll(10, r), Ok(0));
        assert_eq!(pipes.poll(10, w), Ok(0x104));
        assert_eq!(pipes.write(10, w, &[3; CAPACITY - 2]), Ok(CAPACITY - 2));
        assert_eq!(pipes.write(10, w, &[7; 3]), Err(Errno::Again));
        assert_eq!(pipes.pending(10, r), Ok(CAPACITY - 2));
        assert_eq!(
            pipes.read(10, r, &mut data[..CAPACITY - 3]),
            Ok(CAPACITY - 3)
        );
        assert!(data[..CAPACITY - 3].iter().all(|v| *v == 3));
        assert_eq!(pipes.write(10, w, &[9; CAPACITY - 1]), Ok(CAPACITY - 1));
        assert_eq!(pipes.poll(10, w), Ok(0));
        pipes.close(10, w).unwrap();
        assert_eq!(pipes.poll(10, r), Ok(0x41 | 16));
        assert_eq!(pipes.read(10, r, &mut data), Ok(CAPACITY));
        assert_eq!(data[0], 3);
        assert!(data[1..].iter().all(|v| *v == 9));
        assert_eq!(pipes.read(10, r, &mut data), Ok(0));
        assert_eq!(pipes.poll(10, r), Ok(16));
        pipes.close(10, r).unwrap();
        assert_eq!(pipes.free(), PIPES);
    }
    #[test]
    fn direction_owner_stale_handles_and_cleanup() {
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(1).unwrap();
        assert_eq!(pipes.read(1, w, &mut []), Err(Errno::Badf));
        assert_eq!(pipes.write(1, r, &[]), Err(Errno::Badf));
        assert_eq!(pipes.write(2, w, b"x"), Err(Errno::Badf));
        pipes.close(1, r).unwrap();
        assert_eq!(pipes.poll(1, w), Ok(0x104 | 8));
        assert_eq!(pipes.write(1, w, b"x"), Err(Errno::Pipe));
        assert_eq!(pipes.write(1, w, &[]), Ok(0));
        pipes.close_owner(1);
        let next = pipes.pair(1).unwrap();
        assert_ne!(r, next[0]);
        assert_eq!(pipes.poll(1, w), Err(Errno::Badf));
        assert_eq!(pipes.pending(1, next[0]), Ok(0));
        for _ in 1..PIPES {
            pipes.pair(1).unwrap();
        }
        assert_eq!(pipes.pair(1), Err(Errno::Nospc));
        pipes.close_owner(1);
        assert_eq!(pipes.free(), PIPES);
    }
    #[test]
    fn inherited_endpoints_keep_bytes_flags_and_peer_lifetime_across_parent_exit() {
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(10).unwrap();
        pipes.share(10, w, 20).unwrap();
        pipes.share(10, r, 30).unwrap();
        assert_eq!(pipes.share(10, w, 20), Err(Errno::Exist));
        pipes.set_flags(20, w, crate::O_NONBLOCK).unwrap();
        assert_eq!(pipes.flags(10, w), Ok(crate::O_WRONLY | crate::O_NONBLOCK));
        pipes.write(10, w, b"before").unwrap();
        pipes.close_owner(10);
        assert_eq!(pipes.poll(30, r), Ok(0x41));
        assert_eq!(pipes.write(20, w, b"after"), Ok(5));
        pipes.close_owner(20);
        assert_eq!(pipes.poll(30, r), Ok(0x41 | 16));
        let mut bytes = [0; 16];
        assert_eq!(pipes.read(30, r, &mut bytes), Ok(11));
        assert_eq!(&bytes[..11], b"beforeafter");
        assert_eq!(pipes.read(30, r, &mut bytes), Ok(0));
        pipes.close_owner(30);
        assert_eq!(pipes.free(), PIPES);
        assert_eq!(pipes.poll(30, r), Err(Errno::Badf));
    }
    #[test]
    fn large_writes_may_partially_progress() {
        let mut pipes = Pipes::new();
        let [r, w] = pipes.pair(5).unwrap();
        assert_eq!(pipes.write(5, w, b"start"), Ok(5));
        assert_eq!(pipes.write(5, w, &[6; CAPACITY + 1]), Ok(CAPACITY - 5));
        let mut data = [0; CAPACITY];
        assert_eq!(pipes.read(5, r, &mut data), Ok(CAPACITY));
        assert_eq!(&data[..5], b"start");
        assert!(data[5..].iter().all(|v| *v == 6));
    }
}
