//! Bounded merged input stream with explicit loss and key-state recovery.
//!
//! Source IDs are internal: callers receive eight-byte events without a source
//! field. Relative motion lost on overflow cannot be reconstructed. Read the
//! merged key bitmap after SYN_DROPPED followed by SYN_REPORT to resynchronize.
#![forbid(unsafe_code)]

use crate::{Error, InputEvent};

pub const CAPACITY: usize = 128;
pub const READ_LIMIT: usize = 32;
pub const KEY_BYTES: usize = 96;
pub const SOURCES: usize = 2;
const EMPTY: InputEvent = InputEvent {
    kind: 0,
    code: 0,
    value: 0,
};
pub const SYN_REPORT: InputEvent = EMPTY;
pub const SYN_DROPPED: InputEvent = InputEvent {
    kind: 0,
    code: 3,
    value: 0,
};

pub struct InputBuffer {
    events: [InputEvent; CAPACITY],
    head: usize,
    len: usize,
    keys: [[u8; KEY_BYTES]; SOURCES],
    discard_packet: [bool; SOURCES],
}

impl Default for InputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl InputBuffer {
    pub const fn new() -> Self {
        Self {
            events: [EMPTY; CAPACITY],
            head: 0,
            len: 0,
            keys: [[0; KEY_BYTES]; SOURCES],
            discard_packet: [false; SOURCES],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn append(&mut self, event: InputEvent) {
        self.events[(self.head + self.len) % CAPACITY] = event;
        self.len += 1;
    }

    fn report_loss(&mut self) {
        self.head = 0;
        self.len = 0;
        self.discard_packet.fill(true);
        // This terminates any partially delivered merged packet. It always
        // precedes subsequent normal records, including across short reads.
        self.append(SYN_DROPPED);
        self.append(SYN_REPORT);
    }

    /// Returns true when a fresh loss notification replaces queued records.
    /// State changes are retained even while a packet tail is being discarded.
    pub fn push(&mut self, source: usize, event: InputEvent) -> Result<bool, Error> {
        if source >= SOURCES {
            return Err(Error::Address);
        }
        if event.kind == 1 && usize::from(event.code) < KEY_BYTES * 8 {
            let byte = usize::from(event.code) / 8;
            let bit = 1 << (event.code % 8);
            match event.value {
                0 => self.keys[source][byte] &= !bit,
                1 => self.keys[source][byte] |= bit,
                _ => {} // Repeat does not change state; unknown values are raw events.
            }
        }
        if event.kind == SYN_DROPPED.kind && event.code == SYN_DROPPED.code {
            // Hardware-side loss cannot be reconstructed from this buffer.
            // Release that source's known keys rather than leave stale presses.
            self.keys[source].fill(0);
            self.report_loss();
            return Ok(true);
        }
        let report = event.kind == SYN_REPORT.kind && event.code == SYN_REPORT.code;
        if self.discard_packet[source] {
            if report {
                self.discard_packet[source] = false;
            }
            return Ok(false);
        }
        if self.len == CAPACITY {
            self.report_loss();
            self.discard_packet[source] = !report;
            return Ok(true);
        }
        self.append(event);
        Ok(false)
    }

    /// Device removal invalidates its keys and tells readers to resynchronize.
    pub fn disconnect(&mut self, source: usize) -> Result<(), Error> {
        if source >= SOURCES {
            return Err(Error::Address);
        }
        self.keys[source].fill(0);
        self.report_loss();
        Ok(())
    }

    /// Merged state of the two sources: releasing one does not release a key
    /// still held by the other. Codes 0..767 include keyboard and mouse buttons.
    pub fn key_state(&self, out: &mut [u8; KEY_BYTES]) {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self.keys[0][i] | self.keys[1][i];
        }
    }

    /// Nonblocking bounded read. Busy means no events, not device failure.
    pub fn read(&mut self, out: &mut [InputEvent]) -> Result<usize, Error> {
        if out.is_empty() {
            return Err(Error::Address);
        }
        if self.len == 0 {
            return Err(Error::Busy);
        }
        let count = out.len().min(READ_LIMIT).min(self.len);
        for event in &mut out[..count] {
            *event = self.events[self.head];
            self.head = (self.head + 1) % CAPACITY;
            self.len -= 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn event(kind: u16, code: u16, value: i32) -> InputEvent {
        InputEvent { kind, code, value }
    }

    #[test]
    fn records_are_eight_bytes_and_signed_motion_survives() {
        assert_eq!(core::mem::size_of::<InputEvent>(), 8);
        let mut queue = InputBuffer::new();
        for e in [event(1, 30, 1), SYN_REPORT, event(2, 0, -7), SYN_REPORT] {
            assert_eq!(queue.push(0, e), Ok(false));
        }
        let mut out = [EMPTY; 8];
        assert_eq!(queue.read(&mut out), Ok(4));
        assert_eq!(
            &out[..4],
            &[event(1, 30, 1), SYN_REPORT, event(2, 0, -7), SYN_REPORT]
        );
        assert_eq!(queue.read(&mut out), Err(Error::Busy));
        assert_eq!(queue.read(&mut []), Err(Error::Address));
    }

    #[test]
    fn read_is_bounded_and_ring_wrap_preserves_order() {
        let mut queue = InputBuffer::new();
        for i in 0..CAPACITY {
            queue.push(0, event(2, 0, i as i32)).unwrap();
        }
        let mut out = [EMPTY; 64];
        assert_eq!(queue.read(&mut out), Ok(READ_LIMIT));
        for (i, e) in out[..READ_LIMIT].iter().enumerate() {
            assert_eq!(e.value, i as i32);
        }
        for i in CAPACITY..CAPACITY + READ_LIMIT {
            queue.push(0, event(2, 0, i as i32)).unwrap();
        }
        for group in 1..5 {
            assert_eq!(queue.read(&mut out), Ok(READ_LIMIT));
            for (i, e) in out[..READ_LIMIT].iter().enumerate() {
                assert_eq!(e.value, (group * READ_LIMIT + i) as i32);
            }
        }
    }

    #[test]
    fn overflow_reports_loss_then_discards_each_sources_partial_packet() {
        let mut queue = InputBuffer::new();
        for _ in 0..CAPACITY {
            queue.push(0, event(2, 0, 1)).unwrap();
        }
        assert_eq!(queue.push(0, event(1, 30, 1)), Ok(true));
        // Both devices may have partly emitted packets. Neither tail is exposed.
        queue.push(1, event(2, 1, -1)).unwrap();
        queue.push(0, event(1, 30, 0)).unwrap();
        queue.push(0, SYN_REPORT).unwrap();
        queue.push(0, event(1, 31, 1)).unwrap();
        queue.push(0, SYN_REPORT).unwrap();
        queue.push(1, SYN_REPORT).unwrap();
        queue.push(1, event(2, 0, -9)).unwrap();
        queue.push(1, SYN_REPORT).unwrap();
        let mut out = [EMPTY; 32];
        assert_eq!(queue.read(&mut out), Ok(6));
        assert_eq!(
            &out[..6],
            &[
                SYN_DROPPED,
                SYN_REPORT,
                event(1, 31, 1),
                SYN_REPORT,
                event(2, 0, -9),
                SYN_REPORT
            ]
        );
        let mut keys = [0; KEY_BYTES];
        queue.key_state(&mut keys);
        assert_eq!(keys[3], 1 << 7); // Release during discarded packet was retained.
    }

    #[test]
    fn overflow_at_report_already_finishes_that_sources_packet() {
        let mut queue = InputBuffer::new();
        for _ in 0..CAPACITY {
            queue.push(0, event(2, 0, 1)).unwrap();
        }
        assert_eq!(queue.push(0, SYN_REPORT), Ok(true));
        queue.push(0, event(1, 1, 1)).unwrap();
        let mut out = [EMPTY; 8];
        assert_eq!(queue.read(&mut out), Ok(3));
        assert_eq!(&out[..3], &[SYN_DROPPED, SYN_REPORT, event(1, 1, 1)]);
    }

    #[test]
    fn merged_keys_repeat_bounds_and_disconnect_are_safe() {
        let mut queue = InputBuffer::new();
        for source in 0..2 {
            queue.push(source, event(1, 767, 1)).unwrap();
        }
        queue.push(0, event(1, 767, 0)).unwrap();
        queue.push(0, event(1, 7, 2)).unwrap(); // Repeat does not invent a press.
        queue.push(0, event(1, 768, 1)).unwrap();
        let mut keys = [0; KEY_BYTES];
        queue.key_state(&mut keys);
        assert_eq!(keys[95], 0x80);
        assert_eq!(keys[0], 0);
        queue.disconnect(1).unwrap();
        queue.key_state(&mut keys);
        assert_eq!(keys, [0; KEY_BYTES]);
        let mut out = [EMPTY; 4];
        assert_eq!(queue.read(&mut out), Ok(2));
        assert_eq!(&out[..2], &[SYN_DROPPED, SYN_REPORT]);
        assert_eq!(queue.push(2, event(1, 3, 1)), Err(Error::Address));
        assert_eq!(queue.disconnect(2), Err(Error::Address));
    }

    #[test]
    fn upstream_loss_is_not_silently_forwarded_with_stale_queued_events() {
        let mut queue = InputBuffer::new();
        queue.push(0, event(1, 30, 1)).unwrap();
        assert_eq!(queue.push(0, SYN_DROPPED), Ok(true));
        queue.push(0, event(1, 30, 0)).unwrap();
        queue.push(0, SYN_REPORT).unwrap();
        let mut out = [EMPTY; 4];
        assert_eq!(queue.read(&mut out), Ok(2));
        assert_eq!(&out[..2], &[SYN_DROPPED, SYN_REPORT]);
    }
}
