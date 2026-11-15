//! Complete Linux records in a bounded FIFO, with a reserved overflow record.
use super::{EVENTS, Errno, Q_OVERFLOW};
use cyxia_ai_fs::PATH_BYTES;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name_len: u16,
    name: [u8; PATH_BYTES],
}

impl Event {
    const EMPTY: Self = Self {
        wd: 0,
        mask: 0,
        cookie: 0,
        name_len: 0,
        name: [0; PATH_BYTES],
    };

    pub(super) fn new(wd: i32, mask: u32, cookie: u32, name: &str) -> Self {
        let mut event = Self {
            wd,
            mask,
            cookie,
            name_len: name.len() as u16,
            ..Self::EMPTY
        };
        // Names originate in the bounded VFS Path, never arbitrary user bytes.
        event.name[..name.len()].copy_from_slice(name.as_bytes());
        event
    }

    fn name_bytes(self) -> usize {
        if self.name_len == 0 {
            0
        } else {
            (usize::from(self.name_len) + 1 + 15) & !15
        }
    }

    fn bytes(self) -> usize {
        16 + self.name_bytes()
    }

    fn write(self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.wd.to_le_bytes());
        out[4..8].copy_from_slice(&self.mask.to_le_bytes());
        out[8..12].copy_from_slice(&self.cookie.to_le_bytes());
        out[12..16].copy_from_slice(&(self.name_bytes() as u32).to_le_bytes());
        out[16..self.bytes()].fill(0);
        out[16..16 + usize::from(self.name_len)]
            .copy_from_slice(&self.name[..usize::from(self.name_len)]);
    }
}

#[derive(Clone, Copy)]
pub(super) struct Queue {
    events: [Event; EVENTS + 1],
    start: usize,
    len: usize,
    overflowed: bool,
}

impl Queue {
    pub(super) const EMPTY: Self = Self {
        events: [Event::EMPTY; EVENTS + 1],
        start: 0,
        len: 0,
        overflowed: false,
    };
    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn bytes(&self) -> usize {
        (0..self.len)
            .map(|i| self.events[(self.start + i) % (EVENTS + 1)].bytes())
            .sum()
    }

    fn append(&mut self, event: Event) {
        self.events[(self.start + self.len) % (EVENTS + 1)] = event;
        self.len += 1;
    }

    pub(super) fn overflow(&mut self) -> bool {
        if self.overflowed {
            return false;
        }
        self.append(Event::new(-1, Q_OVERFLOW, 0, ""));
        self.overflowed = true;
        true
    }

    pub(super) fn push(&mut self, event: Event) -> bool {
        if self.len != 0 && self.events[(self.start + self.len - 1) % (EVENTS + 1)] == event {
            return false;
        }
        if self.len - usize::from(self.overflowed) == EVENTS {
            return self.overflow();
        }
        self.append(event);
        true
    }

    pub(super) fn read(&mut self, out: &mut [u8]) -> Result<usize, Errno> {
        if self.len == 0 {
            return Err(Errno::Again);
        }
        let mut written = 0;
        while self.len != 0 {
            let event = self.events[self.start];
            let size = event.bytes();
            if size > out.len() - written {
                return if written == 0 {
                    Err(Errno::Inval)
                } else {
                    Ok(written)
                };
            }
            event.write(&mut out[written..written + size]);
            if event.mask == Q_OVERFLOW {
                self.overflowed = false;
            }
            self.start = (self.start + 1) % (EVENTS + 1);
            self.len -= 1;
            written += size;
        }
        Ok(written)
    }
}
