//! Bounded PTYs and a small, explicit terminal line discipline. The supervisor
//! owns admission, waits and delivery of the returned foreground-process signals.
//! One endpoint description per process/side; dup and spawn share that endpoint.
use crate::{
    Errno, O_NONBLOCK, O_RDWR,
    epoll::{HUP, IN, OUT},
};

pub const PTYS: usize = 4;
pub const CAPACITY: usize = 4096;
const LINE: usize = 512;
const RECORDS: usize = 64;
const GENERATION_MAX: u64 = u64::MAX >> 8;
pub const ISIG: u32 = 1;
pub const ICANON: u32 = 2;
pub const ECHO: u32 = 8;
const ECHOE: u32 = 0x10;
const ECHOK: u32 = 0x20;
const ECHONL: u32 = 0x40;
const NOFLSH: u32 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub input: u32,
    pub output: u32,
    pub control: u32,
    pub local: u32,
    pub cc: [u8; 19],
}
impl Termios {
    pub const DEFAULT: Self = Self {
        input: 0x100,
        output: 5,
        control: 0x4bf,
        local: ISIG | ICANON | ECHO | ECHOE | ECHOK,
        cc: [3, 0, 127, 21, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    fn validate(self) -> Result<(), Errno> {
        if self.input & !(0x40 | 0x80 | 0x100) != 0
            || self.output & !5 != 0
            || self.control & !(0x100f | 0x30 | 0x80 | 0x400 | 0x800) != 0
            || self.control & 0x30 != 0x30
            || self.local & !(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL | NOFLSH) != 0
            || self.cc[5] != 0
            || self.cc[6] != 1
            || self
                .cc
                .iter()
                .enumerate()
                .any(|(i, &v)| !matches!(i, 0 | 2 | 3 | 4 | 5 | 6) && v != 0)
        {
            return Err(Errno::Inval);
        }
        Ok(())
    }
}

struct Ring {
    bytes: [u8; CAPACITY],
    head: usize,
    len: usize,
}
impl Ring {
    const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            head: 0,
            len: 0,
        }
    }
    fn free(&self) -> usize {
        CAPACITY - self.len
    }
    fn push(&mut self, byte: u8) {
        self.bytes[(self.head + self.len) % CAPACITY] = byte;
        self.len += 1;
    }
    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        for byte in &mut out[..n] {
            *byte = self.bytes[self.head];
            self.bytes[self.head] = 0;
            self.head = (self.head + 1) % CAPACITY;
            self.len -= 1;
        }
        n
    }
    fn clear(&mut self) {
        self.bytes.fill(0);
        self.head = 0;
        self.len = 0;
    }
}
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
struct Pty {
    generation: u64,
    holders: [Holder; crate::usermem::MAX_PROCESSES],
    open: [bool; 2],
    locked: bool,
    flags: [u32; 2],
    wakes: [u32; 2],
    input: Ring,
    output: Ring,
    line: [u8; LINE],
    line_len: usize,
    line_overflow: bool,
    records: [usize; RECORDS],
    record_head: usize,
    record_len: usize,
    termios: Termios,
    winsize: [u16; 4],
    foreground: u32,
    signals: u32,
}
impl Pty {
    const fn new() -> Self {
        Self {
            generation: 0,
            holders: [Holder::EMPTY; crate::usermem::MAX_PROCESSES],
            open: [false; 2],
            locked: true,
            flags: [O_RDWR; 2],
            wakes: [0; 2],
            input: Ring::new(),
            output: Ring::new(),
            line: [0; LINE],
            line_len: 0,
            line_overflow: false,
            records: [0; RECORDS],
            record_head: 0,
            record_len: 0,
            termios: Termios::DEFAULT,
            winsize: [24, 80, 0, 0],
            foreground: 0,
            signals: 0,
        }
    }
    fn flush_input(&mut self) {
        if self.input.len != 0 || self.record_len != 0 || self.line_len != 0 || self.line_overflow {
            self.wakes[0] |= OUT;
        }
        self.input.clear();
        self.line.fill(0);
        self.line_len = 0;
        self.line_overflow = false;
        self.records.fill(0);
        self.record_head = 0;
        self.record_len = 0;
    }
    fn flush_output(&mut self) {
        if self.output.len != 0 {
            // Slave output and master input echo share this ring's capacity.
            self.wakes[0] |= OUT;
            self.wakes[1] |= OUT;
        }
        self.output.clear();
    }
    fn clear(&mut self) {
        self.holders.fill(Holder::EMPTY);
        self.open = [false; 2];
        self.locked = true;
        self.flags = [O_RDWR; 2];
        self.flush_input();
        self.flush_output();
        self.termios = Termios::DEFAULT;
        self.winsize = [24, 80, 0, 0];
        self.foreground = 0;
        self.signals = 0;
        self.wakes = [0; 2];
    }
    fn hold(&mut self, owner: u32, side: usize) -> Result<(), Errno> {
        if owner == 0 {
            return Err(Errno::Inval);
        }
        let slot = self
            .holders
            .iter()
            .position(|h| h.owner == owner)
            .or_else(|| self.holders.iter().position(|h| h.owner == 0))
            .ok_or(Errno::Nospc)?;
        if self.holders[slot].open[side] {
            return Err(Errno::Exist);
        }
        self.holders[slot].owner = owner;
        self.holders[slot].open[side] = true;
        if !self.open[side] {
            self.wakes[side] = 0;
            self.wakes[side ^ 1] |= OUT;
        }
        self.open[side] = true;
        Ok(())
    }
    fn output_byte(&mut self, byte: u8) {
        if byte == b'\n' && self.termios.output & 5 == 5 {
            self.output.push(b'\r');
        }
        self.output.push(byte);
        self.wakes[0] |= IN;
    }
    fn output_size(&self, byte: u8) -> usize {
        if byte == b'\n' && self.termios.output & 5 == 5 {
            2
        } else {
            1
        }
    }
    fn readiness(&self, side: usize) -> u32 {
        let readable = if side == 0 {
            self.output.len != 0
        } else if self.termios.local & ICANON != 0 {
            self.record_len != 0
        } else {
            self.input.len != 0
        };
        let writable = if side == 0 {
            let input_room = self.termios.local & ICANON != 0 || self.input.free() != 0;
            input_room && (self.termios.local & ECHO == 0 || self.output.free() >= 2)
        } else {
            self.output.free() >= 2
        };
        (u32::from(readable) * 0x41)
            | (u32::from(writable && self.open[1 - side]) * 0x104)
            | if !self.open[1 - side] { HUP } else { 0 }
    }
    fn commit(&mut self) {
        for &byte in &self.line[..self.line_len] {
            self.input.push(byte);
        }
        self.records[(self.record_head + self.record_len) % RECORDS] = self.line_len;
        self.record_len += 1;
        self.wakes[1] |= IN;
        self.line.fill(0);
        self.line_len = 0;
    }
    fn receive(&mut self, mut byte: u8) -> Result<(), Errno> {
        let t = self.termios;
        if byte == b'\r' {
            if t.input & 0x80 != 0 {
                return Ok(());
            }
            if t.input & 0x100 != 0 {
                byte = b'\n';
            }
        } else if byte == b'\n' && t.input & 0x40 != 0 {
            byte = b'\r';
        }
        let echo = t.local & ECHO != 0;
        if t.local & ISIG != 0 && t.cc[0] != 0 && byte == t.cc[0] {
            if echo && self.output.free() < 4 {
                return Err(Errno::Again);
            }
            if t.local & NOFLSH == 0 {
                self.flush_input();
                self.flush_output();
            }
            if echo {
                self.output.push(b'^');
                self.output.push(b'C');
                self.output_byte(b'\n');
            }
            if self.foreground != 0 {
                self.signals |= 1 << 2;
            }
            return Ok(());
        }
        if t.local & ICANON == 0 {
            let echo_len = if echo { self.output_size(byte) } else { 0 };
            if self.input.free() == 0 || self.output.free() < echo_len {
                return Err(Errno::Again);
            }
            self.input.push(byte);
            self.wakes[1] |= IN;
            if echo {
                self.output_byte(byte);
            }
            return Ok(());
        }
        if t.cc[2] != 0 && byte == t.cc[2] {
            if self.line_len != 0 {
                let n = if echo && t.local & ECHOE != 0 {
                    3
                } else {
                    usize::from(echo)
                };
                if self.output.free() < n {
                    return Err(Errno::Again);
                }
                self.line_len -= 1;
                self.line[self.line_len] = 0;
                if n == 3 {
                    for b in [8, b' ', 8] {
                        self.output.push(b);
                    }
                    self.wakes[0] |= IN;
                } else if echo {
                    self.output_byte(byte);
                }
            }
            return Ok(());
        }
        if t.cc[3] != 0 && byte == t.cc[3] {
            if echo && self.output.free() < 3 {
                return Err(Errno::Again);
            }
            self.line.fill(0);
            self.line_len = 0;
            self.line_overflow = false;
            if echo {
                self.output_byte(byte);
                if t.local & ECHOK != 0 {
                    self.output_byte(b'\n');
                }
            }
            return Ok(());
        }
        let eof = t.cc[4] != 0 && byte == t.cc[4];
        let newline = byte == b'\n';
        let echo = !eof && (echo || (newline && t.local & ECHONL != 0));
        if echo && self.output.free() < self.output_size(byte) {
            return Err(Errno::Again);
        }
        if eof || newline {
            if self.line_overflow {
                if self.record_len == RECORDS {
                    return Err(Errno::Again);
                }
                // A full line must never become a truncated shell command.
                // Queue one error record, then resume at the next complete line.
                self.records[(self.record_head + self.record_len) % RECORDS] = usize::MAX;
                self.record_len += 1;
                self.wakes[1] |= IN;
                self.line.fill(0);
                self.line_len = 0;
                self.line_overflow = false;
                if echo {
                    self.output_byte(byte);
                }
                return Ok(());
            }
            let n = self.line_len + usize::from(newline);
            if self.input.free() < n || self.record_len == RECORDS {
                return Err(Errno::Again);
            }
            if newline {
                self.line[self.line_len] = byte;
                self.line_len += 1;
            }
            self.commit();
        } else {
            // Reserve one byte for newline. Discard an over-capacity line up to
            // its delimiter so queued input can still reach newline/erase/kill.
            if self.line_overflow || self.line_len >= LINE - 1 {
                self.line.fill(0);
                self.line_len = 0;
                self.line_overflow = true;
            } else {
                self.line[self.line_len] = byte;
                self.line_len += 1;
            }
        }
        if echo {
            self.output_byte(byte);
        }
        Ok(())
    }
    fn refresh(&mut self) {
        let previous = self.open;
        for (side, was_open) in previous.into_iter().enumerate() {
            self.open[side] = self.holders.iter().any(|h| h.open[side]);
            if was_open && !self.open[side] {
                self.wakes[side ^ 1] |= HUP;
            }
        }
        if previous[0] && !self.open[0] && self.foreground != 0 {
            self.signals |= 1 << 1;
        }
        if self.open == [false; 2] {
            self.clear();
        }
    }
}

pub struct Ptys {
    entries: [Pty; PTYS],
}
impl Default for Ptys {
    fn default() -> Self {
        Self::new()
    }
}
impl Ptys {
    pub const fn new() -> Self {
        Self {
            entries: [const { Pty::new() }; PTYS],
        }
    }
    pub fn free(&self) -> usize {
        self.entries
            .iter()
            .filter(|p| p.open == [false; 2] && p.generation < GENERATION_MAX)
            .count()
    }
    pub fn open_master(&mut self, owner: u32, flags: u32) -> Result<u64, Errno> {
        if flags & !O_NONBLOCK != 0 || owner == 0 {
            return Err(Errno::Inval);
        }
        let (i, p) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, p)| p.open == [false; 2] && p.generation < GENERATION_MAX)
            .ok_or(Errno::Nospc)?;
        p.hold(owner, 0)?;
        p.generation += 1;
        p.flags[0] = O_RDWR | flags;
        Ok((p.generation << 8) | (i as u64 * 2))
    }
    pub fn open_slave(&mut self, owner: u32, index: usize, flags: u32) -> Result<u64, Errno> {
        if flags & !O_NONBLOCK != 0 {
            return Err(Errno::Inval);
        }
        let p = self.entries.get_mut(index).ok_or(Errno::Noent)?;
        if !p.open[0] {
            return Err(Errno::Noent);
        }
        if p.locked {
            return Err(Errno::Io);
        }
        p.hold(owner, 1)?;
        p.flags[1] = O_RDWR | flags;
        Ok((p.generation << 8) | (index as u64 * 2) | 1)
    }
    fn endpoint(&self, owner: u32, handle: u64) -> Result<(usize, usize), Errno> {
        let i = ((handle & 255) >> 1) as usize;
        let side = (handle & 1) as usize;
        let p = self.entries.get(i).ok_or(Errno::Badf)?;
        if owner == 0
            || p.generation != handle >> 8
            || !p.holders.iter().any(|h| h.owner == owner && h.open[side])
        {
            return Err(Errno::Badf);
        }
        Ok((i, side))
    }
    /// Bounded notification bits survive multiple mutations until the
    /// supervisor observes all weak watches. Readiness remains a separate poll.
    pub fn wake_mask(&self, owner: u32, handle: u64) -> Result<u32, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].wakes[side])
    }
    pub fn clear_wakes(&mut self) {
        for p in &mut self.entries {
            p.wakes = [0; 2];
        }
    }
    pub fn number(&self, owner: u32, handle: u64) -> Result<usize, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        if side != 0 {
            return Err(Errno::Notty);
        }
        Ok(i)
    }
    pub fn lock(&mut self, owner: u32, handle: u64, locked: bool) -> Result<(), Errno> {
        let i = self.number(owner, handle)?;
        self.entries[i].locked = locked;
        Ok(())
    }
    pub fn read(&mut self, owner: u32, handle: u64, out: &mut [u8]) -> Result<usize, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        let p = &mut self.entries[i];
        if out.is_empty() {
            return Ok(0);
        }
        if side == 0 {
            if p.output.len != 0 {
                let n = p.output.read(out);
                p.wakes[0] |= OUT;
                p.wakes[1] |= OUT;
                return Ok(n);
            }
            return Err(if p.open[1] { Errno::Again } else { Errno::Io });
        }
        if p.termios.local & ICANON != 0 {
            if p.record_len == 0 {
                return if p.open[0] { Err(Errno::Again) } else { Ok(0) };
            }
            if p.records[p.record_head] == usize::MAX {
                p.records[p.record_head] = 0;
                p.record_head = (p.record_head + 1) % RECORDS;
                p.record_len -= 1;
                p.wakes[0] |= OUT;
                return Err(Errno::TooBig);
            }
            let len = out.len().min(p.records[p.record_head]);
            let n = p.input.read(&mut out[..len]);
            p.records[p.record_head] -= n;
            if p.records[p.record_head] == 0 {
                p.record_head = (p.record_head + 1) % RECORDS;
                p.record_len -= 1;
                p.wakes[0] |= OUT;
            }
            if n != 0 {
                p.wakes[0] |= OUT;
            }
            Ok(n)
        } else if p.input.len != 0 {
            let n = p.input.read(out);
            p.wakes[0] |= OUT;
            Ok(n)
        } else if p.open[0] {
            Err(Errno::Again)
        } else {
            Ok(0)
        }
    }
    pub fn write(&mut self, owner: u32, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        let p = &mut self.entries[i];
        if bytes.is_empty() {
            return Ok(0);
        }
        if !p.open[1 - side] {
            return Err(Errno::Io);
        }
        let mut n = 0;
        for &byte in bytes {
            if side == 0 {
                if let Err(e) = p.receive(byte) {
                    return if n == 0 { Err(e) } else { Ok(n) };
                }
            } else {
                if p.output.free() < p.output_size(byte) {
                    break;
                }
                p.output_byte(byte);
            }
            n += 1;
        }
        if n == 0 { Err(Errno::Again) } else { Ok(n) }
    }
    pub fn pending(&self, owner: u32, handle: u64) -> Result<usize, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        let p = &self.entries[i];
        Ok(if side == 0 { p.output.len } else { p.input.len })
    }
    pub fn output_pending(&self, owner: u32, handle: u64) -> Result<usize, Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].output.len)
    }
    pub fn poll(&self, owner: u32, handle: u64) -> Result<u16, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].readiness(side) as u16)
    }
    pub fn termios(&self, owner: u32, handle: u64) -> Result<Termios, Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].termios)
    }
    pub fn set_termios(
        &mut self,
        owner: u32,
        handle: u64,
        t: Termios,
        flush: bool,
        drain: bool,
    ) -> Result<(), Errno> {
        t.validate()?;
        let (i, _) = self.endpoint(owner, handle)?;
        let p = &mut self.entries[i];
        if drain && p.output.len != 0 {
            return Err(Errno::Again);
        }
        if !flush
            && (t.local ^ p.termios.local) & ICANON != 0
            && (p.input.len != 0 || p.line_len != 0 || p.line_overflow || p.record_len != 0)
        {
            return Err(Errno::Again);
        }
        let previous = [p.readiness(0), p.readiness(1)];
        if flush {
            p.flush_input();
        }
        p.termios = t;
        for (side, before) in previous.into_iter().enumerate() {
            p.wakes[side] |= p.readiness(side) & !before & (IN | OUT | HUP);
        }
        Ok(())
    }
    pub fn flush(&mut self, owner: u32, handle: u64, which: u64) -> Result<(), Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        if which > 2 {
            return Err(Errno::Inval);
        }
        if which != 1 {
            self.entries[i].flush_input();
        }
        if which != 0 {
            self.entries[i].flush_output();
        }
        Ok(())
    }
    pub fn winsize(&self, owner: u32, handle: u64) -> Result<[u16; 4], Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].winsize)
    }
    pub fn set_winsize(&mut self, owner: u32, handle: u64, size: [u16; 4]) -> Result<(), Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        let p = &mut self.entries[i];
        if size[0] == 0 || size[1] == 0 || size[0] > 512 || size[1] > 512 {
            return Err(Errno::Inval);
        }
        if p.winsize != size && p.foreground != 0 {
            p.signals |= 1 << 28;
        }
        p.winsize = size;
        Ok(())
    }
    /// Current subset has one foreground process, not arbitrary process groups.
    /// A slave holder may claim itself; it cannot signal another process by PID.
    pub fn controlling(&mut self, owner: u32, handle: u64) -> Result<(), Errno> {
        self.controlling_for(owner, handle, owner)
    }
    /// The kernel supplies the current PID separately from the OFD capability.
    pub fn controlling_for(&mut self, owner: u32, handle: u64, actor: u32) -> Result<(), Errno> {
        if actor == 0 {
            return Err(Errno::Inval);
        }
        let (i, side) = self.endpoint(owner, handle)?;
        if side != 1 {
            return Err(Errno::Notty);
        }
        let p = &mut self.entries[i];
        if p.foreground != 0 && p.foreground != actor {
            return Err(Errno::Perm);
        }
        p.foreground = actor;
        Ok(())
    }
    /// Process exit ends its foreground claim, without closing shared endpoints.
    pub fn release_actor(&mut self, actor: u32) {
        for p in &mut self.entries {
            if p.foreground == actor {
                p.foreground = 0;
                p.signals = 0;
            }
        }
    }
    pub fn foreground(&self, owner: u32, handle: u64) -> Result<u32, Errno> {
        let (i, _) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].foreground)
    }
    pub fn take_signal(&mut self) -> Option<(u32, u8)> {
        for p in &mut self.entries {
            if p.signals != 0 && p.foreground != 0 {
                let signal = p.signals.trailing_zeros() as u8;
                p.signals &= !(1 << signal);
                return Some((p.foreground, signal));
            }
        }
        None
    }
    pub fn share(&mut self, owner: u32, handle: u64, child: u32) -> Result<(), Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        if child == owner {
            return Err(Errno::Inval);
        }
        self.entries[i].hold(child, side)
    }
    pub fn flags(&self, owner: u32, handle: u64) -> Result<u32, Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        Ok(self.entries[i].flags[side])
    }
    pub fn set_flags(&mut self, owner: u32, handle: u64, flags: u32) -> Result<(), Errno> {
        if flags & !(3 | crate::O_APPEND | O_NONBLOCK) != 0 {
            return Err(Errno::Inval);
        }
        let (i, side) = self.endpoint(owner, handle)?;
        self.entries[i].flags[side] = O_RDWR | (flags & (crate::O_APPEND | O_NONBLOCK));
        Ok(())
    }
    pub fn close(&mut self, owner: u32, handle: u64) -> Result<(), Errno> {
        let (i, side) = self.endpoint(owner, handle)?;
        let p = &mut self.entries[i];
        let h = p
            .holders
            .iter_mut()
            .find(|h| h.owner == owner)
            .ok_or(Errno::Badf)?;
        h.open[side] = false;
        if h.open == [false; 2] {
            h.owner = 0;
        }
        if p.foreground == owner && side == 1 {
            p.foreground = 0;
            p.signals = 0;
        }
        p.refresh();
        Ok(())
    }
    pub fn close_owner(&mut self, owner: u32) {
        for p in &mut self.entries {
            for h in &mut p.holders {
                if h.owner == owner {
                    *h = Holder::EMPTY;
                }
            }
            if p.foreground == owner {
                p.foreground = 0;
                p.signals = 0;
            }
            p.refresh();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair(p: &mut Ptys) -> (u64, u64) {
        let m = p.open_master(10, O_NONBLOCK).unwrap();
        assert_eq!(p.open_slave(10, 0, 0), Err(Errno::Io));
        p.lock(10, m, false).unwrap();
        let s = p.open_slave(10, p.number(10, m).unwrap(), 0).unwrap();
        (m, s)
    }
    #[test]
    fn wake_notifications_cover_canonical_records_echo_and_final_close() {
        use crate::epoll::{HUP, IN, OUT};
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        p.clear_wakes();
        p.write(10, m, b"a\n").unwrap();
        assert_eq!(p.wake_mask(10, s).unwrap() & IN, IN);
        assert_eq!(p.wake_mask(10, m).unwrap() & IN, IN);
        p.clear_wakes();
        p.write(10, m, b"b\n").unwrap();
        assert_eq!(p.wake_mask(10, s).unwrap() & IN, IN);
        assert_ne!(p.poll(10, s).unwrap() & 1, 0);
        p.clear_wakes();
        p.read(10, s, &mut [0; 2]).unwrap();
        assert_eq!(p.wake_mask(10, m).unwrap() & OUT, OUT);
        p.clear_wakes();
        p.read(10, m, &mut [0; 16]).unwrap();
        assert_eq!(p.wake_mask(10, s).unwrap() & OUT, OUT);
        assert_eq!(p.wake_mask(10, m).unwrap() & OUT, OUT);
        p.clear_wakes();
        p.share(10, s, 20).unwrap();
        p.close(10, s).unwrap();
        assert_eq!(p.wake_mask(10, m), Ok(0));
        p.close_owner(20);
        assert_eq!(p.wake_mask(10, m), Ok(HUP));
        p.close(10, m).unwrap();
        let (fresh, _) = pair(&mut p);
        assert_ne!(fresh, m);
        assert_eq!(p.wake_mask(10, m), Err(Errno::Badf));
        p.clear_wakes();
        assert_eq!(p.wake_mask(10, fresh), Ok(0));
    }

    #[test]
    fn wake_notifications_preserve_partial_write_and_error_record_progress() {
        use crate::epoll::{IN, OUT};
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        let mut raw = p.termios(10, s).unwrap();
        raw.local = 0;
        p.set_termios(10, s, raw, false, false).unwrap();
        p.clear_wakes();
        assert_eq!(p.write(10, m, &[b'a'; CAPACITY + 1]), Ok(CAPACITY));
        assert_eq!(p.wake_mask(10, s), Ok(IN));
        p.clear_wakes();
        assert_eq!(p.write(10, m, b"x"), Err(Errno::Again));
        assert_eq!(p.wake_mask(10, s), Ok(0));
        p.flush(10, s, 0).unwrap();
        assert_eq!(p.wake_mask(10, m).unwrap() & OUT, OUT);
        p.set_termios(10, s, Termios::DEFAULT, false, false)
            .unwrap();
        p.clear_wakes();
        p.write(10, m, &[b'x'; LINE]).unwrap();
        p.write(10, m, b"\n").unwrap();
        assert_eq!(p.wake_mask(10, s).unwrap() & IN, IN);
        p.clear_wakes();
        assert_eq!(p.read(10, s, &mut [0; 8]), Err(Errno::TooBig));
        assert_eq!(p.wake_mask(10, m).unwrap() & OUT, OUT);
    }

    #[test]
    fn canonical_incomplete_input_is_quiet_but_empty_eof_notifies() {
        use crate::epoll::IN;
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        p.write(10, m, b"old\n").unwrap();
        p.clear_wakes();
        p.write(10, m, b"new").unwrap();
        assert_ne!(p.poll(10, s).unwrap() & 1, 0);
        assert_eq!(p.wake_mask(10, s), Ok(0));
        p.write(10, m, b"\n").unwrap();
        assert_eq!(p.wake_mask(10, s), Ok(IN));
        p.flush(10, s, 2).unwrap();
        p.clear_wakes();
        p.write(10, m, &[Termios::DEFAULT.cc[4]]).unwrap();
        assert_eq!(p.pending(10, s), Ok(0));
        assert_ne!(p.poll(10, s).unwrap() & 1, 0);
        assert_eq!(p.wake_mask(10, s), Ok(IN));
        assert_eq!(p.read(10, s, &mut [0; 1]), Ok(0));
        assert_eq!(p.poll(10, s).unwrap() & 1, 0);
    }

    #[test]
    fn termios_capacity_change_notifies_only_after_valid_commit() {
        use crate::epoll::OUT;
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        p.write(10, s, &[b'x'; CAPACITY]).unwrap();
        assert_eq!(p.poll(10, m).unwrap() & 4, 0);
        let mut t = p.termios(10, s).unwrap();
        t.local &= !ECHO;
        p.clear_wakes();
        let mut bad = t;
        bad.cc[6] = 2;
        assert_eq!(p.set_termios(10, s, bad, false, false), Err(Errno::Inval));
        assert_eq!(p.wake_mask(10, m), Ok(0));
        p.set_termios(10, s, t, false, false).unwrap();
        assert_eq!(p.wake_mask(10, m), Ok(OUT));
        p.clear_wakes();
        p.set_termios(10, s, t, false, false).unwrap();
        assert_eq!(p.wake_mask(10, m), Ok(0));
    }
    #[test]
    fn canonical_edit_echo_line_boundaries_and_eof_are_real() {
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        let mut buf = [0; 64];
        assert_eq!(p.write(10, m, b"ab\x7fc"), Ok(4));
        assert_eq!(p.read(10, s, &mut buf), Err(Errno::Again));
        assert_eq!(p.write(10, m, b"\rsecond\n"), Ok(8));
        assert_eq!(p.read(10, s, &mut buf), Ok(3));
        assert_eq!(&buf[..3], b"ac\n");
        assert_eq!(p.read(10, s, &mut buf[..2]), Ok(2));
        assert_eq!(&buf[..2], b"se");
        assert_eq!(p.read(10, s, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"cond\n");
        let n = p.read(10, m, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ab\x08 \x08c\r\nsecond\r\n");
        p.write(10, m, b"partial\x04\x04").unwrap();
        assert_eq!(p.read(10, s, &mut buf), Ok(7));
        assert_eq!(&buf[..7], b"partial");
        assert_eq!(p.read(10, s, &mut buf), Ok(0));
        assert_eq!(p.read(10, s, &mut buf), Err(Errno::Again));
        p.write(10, m, b"discard\x15ok\n").unwrap();
        assert_eq!(p.read(10, s, &mut buf), Ok(3));
        assert_eq!(&buf[..3], b"ok\n");
    }
    #[test]
    fn raw_backpressure_wrap_output_transform_and_flush() {
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        let mut t = Termios::DEFAULT;
        t.local = 0;
        t.input = 0;
        t.output = 0;
        p.set_termios(10, s, t, false, false).unwrap();
        assert_eq!(p.write(10, m, &[42; CAPACITY]), Ok(CAPACITY));
        assert_eq!(p.write(10, m, &[1]), Err(Errno::Again));
        let mut buf = [0; CAPACITY];
        assert_eq!(p.read(10, s, &mut buf[..100]), Ok(100));
        assert_eq!(p.write(10, m, &[9; 101]), Ok(100));
        assert_eq!(p.read(10, s, &mut buf), Ok(CAPACITY));
        assert!(buf[..CAPACITY - 100].iter().all(|v| *v == 42));
        assert!(buf[CAPACITY - 100..].iter().all(|v| *v == 9));
        p.set_termios(10, s, Termios::DEFAULT, true, false).unwrap();
        assert_eq!(p.write(10, s, b"a\nb"), Ok(3));
        assert_eq!(p.set_termios(10, s, t, false, true), Err(Errno::Again));
        assert_eq!(p.read(10, m, &mut buf), Ok(4));
        assert_eq!(&buf[..4], b"a\r\nb");
        p.write(10, m, b"not committed").unwrap();
        assert_eq!(p.set_termios(10, s, t, false, false), Err(Errno::Again));
        p.set_termios(10, s, t, true, false).unwrap();
        assert_eq!(p.read(10, s, &mut buf), Err(Errno::Again));
    }
    #[test]
    fn sharing_lifetime_status_signals_and_stale_handle_isolation() {
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        assert_eq!(p.read(99, s, &mut [0; 1]), Err(Errno::Badf));
        p.share(10, s, 20).unwrap();
        p.close(10, s).unwrap();
        p.controlling(20, s).unwrap();
        p.set_flags(20, s, O_NONBLOCK).unwrap();
        assert_eq!(p.flags(20, s), Ok(O_RDWR | O_NONBLOCK));
        assert_eq!(p.controlling(10, m), Err(Errno::Notty));
        p.write(10, m, b"discard\x03").unwrap();
        assert_eq!(p.take_signal(), Some((20, 2)));
        assert_eq!(p.take_signal(), None);
        p.set_winsize(10, m, [30, 90, 0, 0]).unwrap();
        assert_eq!(p.take_signal(), Some((20, 28)));
        p.close(10, m).unwrap();
        assert_eq!(p.take_signal(), Some((20, 1)));
        assert_eq!(p.read(20, s, &mut [0; 2]), Ok(0));
        assert_eq!(p.poll(20, s).unwrap() & 16, 16);
        p.close_owner(20);
        assert_eq!(p.free(), PTYS);
        let next = p.open_master(10, 0).unwrap();
        assert_ne!(m, next);
        assert_eq!(p.write(10, m, b"x"), Err(Errno::Badf));
        p.close_owner(10);
        assert_eq!(p.free(), PTYS);
    }
    #[test]
    fn bounded_lines_records_flags_and_descriptors() {
        let mut p = Ptys::new();
        let (m, s) = pair(&mut p);
        let mut t = Termios::DEFAULT;
        t.local &= !ECHO;
        p.set_termios(10, s, t, false, false).unwrap();
        assert_eq!(p.write(10, m, &[b'a'; LINE - 1]), Ok(LINE - 1));
        assert_eq!(p.write(10, m, b"\n"), Ok(1));
        assert_eq!(p.read(10, s, &mut [0; LINE]), Ok(LINE));
        assert_eq!(p.write(10, m, &[b'a'; LINE + 100]), Ok(LINE + 100));
        assert_eq!(p.write(10, m, b"\nok\n"), Ok(4));
        assert_eq!(p.read(10, s, &mut [0; 1]), Err(Errno::TooBig));
        let mut next = [0; 4];
        assert_eq!(p.read(10, s, &mut next), Ok(3));
        assert_eq!(&next[..3], b"ok\n");
        p.write(10, m, &[b'a'; LINE + 1]).unwrap();
        p.write(10, m, &[4]).unwrap();
        assert_eq!(p.read(10, s, &mut next), Err(Errno::TooBig));
        p.write(10, m, &[b'a'; LINE + 1]).unwrap();
        p.write(10, m, b"\x15ok\n").unwrap();
        assert_eq!(p.read(10, s, &mut next), Ok(3));
        assert_eq!(&next[..3], b"ok\n");
        assert_eq!(p.write(10, m, &[4; RECORDS + 1]), Ok(RECORDS));
        assert_eq!(p.write(10, m, &[4]), Err(Errno::Again));
        p.flush(10, s, 0).unwrap();
        t.cc[5] = 1;
        assert_eq!(p.set_termios(10, s, t, false, false), Err(Errno::Inval));
        assert_eq!(p.lock(10, s, false), Err(Errno::Notty));
        assert_eq!(p.open_slave(10, 0, 0), Err(Errno::Exist));
        let objects = crate::OpenDescriptions::new();
        let mut process = crate::Process::new(&objects, 10).unwrap();
        let fd = process.install_pty(s, crate::O_CLOEXEC).unwrap();
        let alias = process.dup(fd).unwrap();
        assert!(!process.last_reference(fd).unwrap());
        let fs = cyxia_ai_fs::FileSystem::new();
        let child = process
            .spawn_descriptors(
                &fs,
                None,
                &[
                    crate::spawn::Mapping {
                        source: fd,
                        target: 0,
                    },
                    crate::spawn::Mapping {
                        source: alias,
                        target: 1,
                    },
                ],
                20,
            )
            .unwrap();
        assert_eq!(child.backend_owner(0), Ok(10));
        assert_eq!(child.pty(0), Ok(Some(s)));
        assert_eq!(child.pty(1), Ok(Some(s)));
        assert_eq!(child.fstat(&fs, 0).unwrap().mode & 0o170000, 0o020000);
    }
    #[test]
    fn exhausted_generations_retire_and_failed_claims_do_not_mutate() {
        let mut p = Ptys::new();
        p.entries[0].generation = GENERATION_MAX;
        assert_eq!(p.free(), PTYS - 1);
        let m = p.open_master(10, 0).unwrap();
        assert_eq!(p.number(10, m), Ok(1));
        p.lock(10, m, false).unwrap();
        let s = p.open_slave(10, 1, 0).unwrap();
        p.share(10, s, 20).unwrap();
        p.controlling(20, s).unwrap();
        assert_eq!(p.controlling(10, s), Err(Errno::Perm));
        assert_eq!(p.foreground(10, m), Ok(20));
        p.close_owner(20);
        assert_eq!(p.foreground(10, m), Ok(0));
        p.close_owner(10);
        assert_eq!(p.free(), PTYS - 1);
    }
}
