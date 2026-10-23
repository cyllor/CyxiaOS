//! Native, bounded local byte streams. Not a POSIX socket implementation.
//! Only the supervisor creates pairs; callers supply their authenticated PID.
use crate::Errno;

pub const CHANNELS: usize = 4;
pub const CAPACITY: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interest {
    Readable,
    Writable,
}

struct Stream {
    bytes: [u8; CAPACITY],
    head: usize,
    len: usize,
}
impl Stream {
    const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            head: 0,
            len: 0,
        }
    }
    fn write(&mut self, data: &[u8]) -> Result<usize, Errno> {
        let n = data.len().min(CAPACITY - self.len);
        if n == 0 && !data.is_empty() {
            return Err(Errno::Again);
        }
        for (i, byte) in data[..n].iter().enumerate() {
            self.bytes[(self.head + self.len + i) % CAPACITY] = *byte;
        }
        self.len += n;
        Ok(n)
    }
    fn read(&mut self, out: &mut [u8], peer_open: bool) -> Result<usize, Errno> {
        let n = out.len().min(self.len);
        if n == 0 && !out.is_empty() && peer_open {
            return Err(Errno::Again);
        }
        for (i, byte) in out[..n].iter_mut().enumerate() {
            let slot = (self.head + i) % CAPACITY;
            *byte = self.bytes[slot];
            self.bytes[slot] = 0;
        }
        self.head = (self.head + n) % CAPACITY;
        self.len -= n;
        Ok(n)
    }
}
struct Channel {
    handles: [u32; 2],
    owners: [Option<u32>; 2],
    incoming: [Stream; 2],
}
pub struct LocalIpc {
    channels: [Option<Channel>; CHANNELS],
    next: u32,
}
impl Default for LocalIpc {
    fn default() -> Self {
        Self::new()
    }
}
impl LocalIpc {
    pub const fn new() -> Self {
        Self {
            channels: [const { None }; CHANNELS],
            next: 1,
        }
    }
    /// Trusted supervisor only: attach a pair to two live process identities.
    /// This allocates no dynamic pages; bounded rings are boot-reserved metadata.
    pub fn pair(&mut self, a: u32, b: u32) -> Result<[u32; 2], Errno> {
        if a == 0 || b == 0 || a == b {
            return Err(Errno::Inval);
        }
        let next = self.next.checked_add(2).ok_or(Errno::Overflow)?;
        let slot = self
            .channels
            .iter_mut()
            .find(|c| c.is_none())
            .ok_or(Errno::Nospc)?;
        let handles = [self.next, self.next + 1];
        *slot = Some(Channel {
            handles,
            owners: [Some(a), Some(b)],
            incoming: [const { Stream::new() }; 2],
        });
        self.next = next;
        Ok(handles)
    }
    fn endpoint(&mut self, owner: u32, handle: u32) -> Result<(&mut Channel, usize), Errno> {
        for channel in self.channels.iter_mut().flatten() {
            for side in 0..2 {
                if channel.handles[side] == handle && channel.owners[side] == Some(owner) {
                    return Ok((channel, side));
                }
            }
        }
        Err(Errno::Badf)
    }
    pub fn write(&mut self, owner: u32, handle: u32, data: &[u8]) -> Result<usize, Errno> {
        let (channel, side) = self.endpoint(owner, handle)?;
        let peer = side ^ 1;
        if channel.owners[peer].is_none() {
            return Err(Errno::Pipe);
        }
        channel.incoming[peer].write(data)
    }
    pub fn read(&mut self, owner: u32, handle: u32, out: &mut [u8]) -> Result<usize, Errno> {
        let (channel, side) = self.endpoint(owner, handle)?;
        channel.incoming[side].read(out, channel.owners[side ^ 1].is_some())
    }
    /// A closed peer is ready: the next operation must observe EOF/EPIPE instead
    /// of sleeping forever. Check and registration are serialized by the caller.
    pub fn ready(&mut self, owner: u32, handle: u32, interest: Interest) -> Result<bool, Errno> {
        let (channel, side) = self.endpoint(owner, handle)?;
        Ok(channel.owners[side ^ 1].is_none()
            || match interest {
                Interest::Readable => channel.incoming[side].len != 0,
                Interest::Writable => channel.incoming[side ^ 1].len < CAPACITY,
            })
    }
    /// Discard unread data belonging to the exiting process; its peer may drain
    /// already-sent bytes before EOF. Slots are reusable only after both close.
    pub fn close_owner(&mut self, owner: u32) {
        for slot in &mut self.channels {
            if let Some(channel) = slot {
                for side in 0..2 {
                    if channel.owners[side] == Some(owner) {
                        channel.owners[side] = None;
                        channel.incoming[side] = Stream::new();
                    }
                }
                if channel.owners == [None, None] {
                    *slot = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_duplex_partial_io_wrap_and_backpressure() {
        let mut ipc = LocalIpc::new();
        let [a, b] = ipc.pair(10, 20).unwrap();
        let mut out = [0; CAPACITY];
        assert_eq!(ipc.read(20, b, &mut out), Err(Errno::Again));
        assert_eq!(ipc.write(10, a, &[7; CAPACITY + 1]), Ok(CAPACITY));
        assert_eq!(ipc.write(10, a, b"x"), Err(Errno::Again));
        assert_eq!(ipc.write(20, b, b"reply"), Ok(5));
        assert_eq!(ipc.read(10, a, &mut out), Ok(5));
        assert_eq!(&out[..5], b"reply");
        assert_eq!(ipc.read(20, b, &mut out[..200]), Ok(200));
        assert_eq!(&out[..200], &[7; 200]);
        assert_eq!(ipc.write(10, a, &[9; 200]), Ok(200));
        assert_eq!(ipc.read(20, b, &mut out), Ok(CAPACITY));
        assert_eq!(&out[..56], &[7; 56]);
        assert_eq!(&out[56..], &[9; 200]);
        assert_eq!(ipc.read(20, b, &mut []), Ok(0));
    }

    #[test]
    fn identity_close_drain_and_stale_handle() {
        let mut ipc = LocalIpc::new();
        let [a, b] = ipc.pair(10, 20).unwrap();
        let mut out = [0; 8];
        assert_eq!(ipc.write(20, a, b"forged"), Err(Errno::Badf));
        assert_eq!(ipc.read(10, b, &mut out), Err(Errno::Badf));
        ipc.write(10, a, b"last").unwrap();
        ipc.close_owner(10);
        assert_eq!(ipc.write(20, b, b"late"), Err(Errno::Pipe));
        assert_eq!(ipc.read(20, b, &mut out), Ok(4));
        assert_eq!(&out[..4], b"last");
        assert_eq!(ipc.read(20, b, &mut out), Ok(0));
        assert_eq!(ipc.write(10, a, b"late"), Err(Errno::Badf));
        ipc.close_owner(20);
        let [c, _] = ipc.pair(10, 20).unwrap();
        assert_ne!(c, a);
        assert_eq!(ipc.write(10, a, b"stale"), Err(Errno::Badf));
        assert_eq!(ipc.read(10, c, &mut out), Err(Errno::Again));
    }

    #[test]
    fn capacity_failure_is_atomic_and_close_reclaims() {
        let mut ipc = LocalIpc::new();
        assert_eq!(ipc.pair(0, 20), Err(Errno::Inval));
        assert_eq!(ipc.pair(10, 10), Err(Errno::Inval));
        for _ in 0..CHANNELS {
            ipc.pair(10, 20).unwrap();
        }
        assert_eq!(ipc.pair(30, 40), Err(Errno::Nospc));
        ipc.close_owner(10);
        assert_eq!(ipc.pair(30, 40), Err(Errno::Nospc));
        ipc.close_owner(20);
        assert!(ipc.pair(30, 40).is_ok());
    }

    #[test]
    fn readiness_tracks_backpressure_and_peer_exit() {
        let mut ipc = LocalIpc::new();
        let [a, b] = ipc.pair(10, 20).unwrap();
        assert_eq!(ipc.ready(10, a, Interest::Readable), Ok(false));
        assert_eq!(ipc.ready(10, a, Interest::Writable), Ok(true));
        ipc.write(10, a, &[1; CAPACITY]).unwrap();
        assert_eq!(ipc.ready(10, a, Interest::Writable), Ok(false));
        assert_eq!(ipc.ready(20, b, Interest::Readable), Ok(true));
        ipc.read(20, b, &mut [0; 1]).unwrap();
        assert_eq!(ipc.ready(10, a, Interest::Writable), Ok(true));
        ipc.close_owner(20);
        assert_eq!(ipc.ready(10, a, Interest::Readable), Ok(true));
        assert_eq!(ipc.ready(10, a, Interest::Writable), Ok(true));
        assert_eq!(ipc.ready(20, a, Interest::Readable), Err(Errno::Badf));
    }
}
