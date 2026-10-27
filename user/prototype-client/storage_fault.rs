//! Dedicated ordinary EL0 workload for native filesystem crash experiments.
//! Progress records consumed replies only; protected ABI delivery and the
//! independent disk decoder, never this page, establish native acceptance.
use super::{call, clock, file, file_call, get, handle, put, waiting};
use core::sync::atomic::{Ordering, fence};
#[path = "../../crates/prototype/src/a10_budget.rs"]
mod a10_budget;

const DATA: u64 = 0x50000;
const PROGRESS: u64 = 0x30000;
const BYTES: u64 = 4096;
const DATA_PAGES: u64 = 16;
const PRESSURE_CHUNK_BYTES: u64 = DATA_PAGES * 4096;
const PRESSURE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const PRESSURE_CHUNKS: u64 = PRESSURE_FILE_BYTES / PRESSURE_CHUNK_BYTES;
const VALUE: &str = "/a10/value";
const PRESSURE: [&str; 2] = ["/a10/pressure-a", "/a10/pressure-b"];
// At most MAX_POLL_REQUESTS polling requests per role, leaving room for both
// endpoints and finite work in the protected capture. This changes no policy
// budget and introduces no privileged I/O or acknowledgement shortcut.

// Public progress wire: stage 1 start, 2 opened, 3 fsync1 consumed, 4 fsync2
// consumed, 5 complete read + stable STAT verified, 6 epoch marker created or
// observed, 7 fsync3 consumed, 8 complete, 255 failed (word12 is the error).
// Local error codes: 201 launch, 202 authority, 203 map, 204 unmap, 205 timeout,
// 206 transport, 207 file reply, 208 object/handle identity, 209 metadata,
// 210 data/length, 211 fsync sequence, 212 marker, 213 request overflow.
type Result<T> = core::result::Result<T, u64>;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    id: u64,
    generation: u64,
}
impl Identity {
    fn object(frame: &file::Frame) -> Result<Self> {
        let key = Self {
            id: frame.u64(file::OFF_OBJECT_ID),
            generation: frame.u64(file::OFF_OBJECT_GENERATION),
        };
        if key.id == 0 || key.generation == 0 {
            Err(208)
        } else {
            Ok(key)
        }
    }
    fn matches(self, frame: &file::Frame) -> Result<()> {
        if Self::object(frame)? == self {
            Ok(())
        } else {
            Err(208)
        }
    }
}

struct Client {
    authority: file::Capability,
    mode: u64,
    role: u64,
    boot: u64,
    deadline: u64,
    poll_ns: u64,
    request: u64,
    progress_sequence: u64,
    object: Identity,
    consumed: u64,
    observed: u64,
    verified: u64,
}
impl Client {
    fn publish(&mut self, stage: u64, error: u64) {
        let sequence = self.progress_sequence + 2;
        put(PROGRESS, sequence - 1);
        fence(Ordering::SeqCst);
        for (index, value) in [
            0x4359_5841_3130_5553,
            1,
            self.mode,
            self.role,
            self.boot,
            stage,
            self.object.id,
            self.object.generation,
            self.consumed,
            self.observed,
            self.verified,
            error,
        ]
        .into_iter()
        .enumerate()
        {
            put(PROGRESS + (index as u64 + 1) * 8, value);
        }
        fence(Ordering::Release);
        put(PROGRESS, sequence);
        self.progress_sequence = sequence;
    }
    fn frame(&mut self, operation: u16) -> Result<file::Frame> {
        if clock() >= self.deadline {
            return Err(205);
        }
        self.request = self.request.checked_add(1).ok_or(213u64)?;
        Ok(file::Frame::new(operation, self.request, self.authority))
    }
    fn deliver(&self, frame: &mut file::Frame) -> Result<()> {
        if file_call(frame, self.deadline) {
            Ok(())
        } else {
            Err(206)
        }
    }
    fn success(&self, frame: &mut file::Frame) -> Result<()> {
        self.deliver(frame)?;
        if frame.result() == 0 {
            Ok(())
        } else {
            Err(207)
        }
    }
    fn path_frame(&mut self, operation: u16, path: &str) -> Result<file::Frame> {
        let mut frame = self.frame(operation)?;
        if !frame.set_path(path) {
            return Err(201);
        }
        Ok(frame)
    }
    fn wait_poll(&self) -> Result<()> {
        let next = clock().saturating_add(self.poll_ns).min(self.deadline);
        while clock() < next {
            if !waiting(self.deadline) {
                return Err(205);
            }
        }
        if clock() < self.deadline {
            Ok(())
        } else {
            Err(205)
        }
    }
    fn await_value(&mut self) -> Result<file::Frame> {
        loop {
            let mut frame = self.path_frame(file::STAT, VALUE)?;
            self.deliver(&mut frame)?;
            if frame.result() == 0 {
                Identity::object(&frame)?;
                let written = frame.u64(file::OFF_WRITE_SEQ);
                let durable = frame.u64(file::OFF_DURABLE_SEQ);
                if frame.u16(file::OFF_MODE) != 1 || durable > written {
                    return Err(209);
                }
                let allowed = if self.mode >= 3 {
                    matches!(durable, 2 | 3)
                } else {
                    durable == 2
                };
                if allowed && written == durable && frame.u64(file::OFF_COUNT) == BYTES {
                    return Ok(frame);
                }
                if self.mode >= 3 || written > 2 || durable > 2 {
                    return Err(209);
                }
            } else if !matches!(frame.result(), -2 | -11 | -16 | -19) {
                return Err(207);
            }
            self.wait_poll()?;
        }
    }
    fn open_path(&mut self, path: &str, mode: u16, object: Identity) -> Result<Identity> {
        let mut frame = self.path_frame(file::OPEN, path)?;
        frame.set_u16(file::OFF_MODE, mode);
        self.success(&mut frame)?;
        object.matches(&frame)?;
        let key = Identity {
            id: frame.u64(file::OFF_HANDLE_ID),
            generation: frame.u64(file::OFF_HANDLE_GENERATION),
        };
        if key.id == 0 || key.generation == 0 {
            return Err(208);
        }
        self.publish(2, 0);
        Ok(key)
    }
    fn open(&mut self, mode: u16) -> Result<Identity> {
        self.open_path(VALUE, mode, self.object)
    }
    fn close(&mut self, key: Identity) -> Result<()> {
        let mut frame = self.frame(file::CLOSE)?;
        handle(&mut frame, key.id, key.generation);
        self.success(&mut frame)
    }
    fn write_version(&mut self, key: Identity, version: u64) -> Result<()> {
        for word in 0..BYTES / 8 {
            put(DATA + word * 8, pattern(version, word));
        }
        let mut frame = self.frame(file::WRITE)?;
        handle(&mut frame, key.id, key.generation);
        frame.set_u64(file::OFF_DATA, DATA);
        frame.set_u32(file::OFF_DATA_LENGTH, BYTES as u32);
        self.success(&mut frame)?;
        self.object.matches(&frame)?;
        if frame.u64(file::OFF_COUNT) != BYTES {
            return Err(210);
        }
        let mut frame = self.frame(file::FSYNC)?;
        handle(&mut frame, key.id, key.generation);
        self.success(&mut frame)?;
        self.object.matches(&frame)?;
        if frame.u64(file::OFF_WRITE_SEQ) != version || frame.u64(file::OFF_DURABLE_SEQ) != version
        {
            return Err(211);
        }
        self.consumed = version;
        self.observed = version;
        self.publish(if version == 3 { 7 } else { version + 2 }, 0);
        Ok(())
    }
    fn await_marker(&mut self, path: &str) -> Result<()> {
        loop {
            let mut frame = self.path_frame(file::STAT, path)?;
            self.deliver(&mut frame)?;
            if frame.result() == 0 {
                Identity::object(&frame)?;
                if frame.u16(file::OFF_MODE) != 1
                    || frame.u64(file::OFF_COUNT) != 0
                    || frame.u64(file::OFF_WRITE_SEQ) != 0
                    || frame.u64(file::OFF_DURABLE_SEQ) != 0
                {
                    return Err(212);
                }
                self.publish(6, 0);
                return Ok(());
            }
            if !matches!(frame.result(), -2 | -11 | -16 | -19) {
                return Err(207);
            }
            self.wait_poll()?;
        }
    }
    fn writer(&mut self, marker: &str) -> Result<()> {
        if self.mode == 1 {
            let mut frame = self.path_frame(file::MKDIR, "/a10")?;
            self.success(&mut frame)?;
            let mut frame = self.path_frame(file::CREATE, VALUE)?;
            self.success(&mut frame)?;
            self.object = Identity::object(&frame)?;
        } else {
            let frame = self.await_value()?;
            self.object = Identity::object(&frame)?;
            self.observed = frame.u64(file::OFF_DURABLE_SEQ);
        }
        let key = self.open(file::MODE_WRITE)?;
        if self.mode == 1 {
            self.write_version(key, 1)?;
            self.write_version(key, 2)?;
        } else {
            self.await_marker(marker)?;
            self.write_version(key, 3)?;
        }
        self.close(key)
    }
    fn read_current(&mut self) -> Result<()> {
        let key = self.open(file::MODE_READ)?;
        for word in 0..BYTES / 8 {
            put(DATA + word * 8, 0);
        }
        let mut frame = self.frame(file::READ)?;
        handle(&mut frame, key.id, key.generation);
        frame.set_u64(file::OFF_DATA, DATA);
        frame.set_u32(file::OFF_DATA_LENGTH, BYTES as u32);
        self.success(&mut frame)?;
        self.object.matches(&frame)?;
        if frame.u64(file::OFF_COUNT) != BYTES {
            return Err(210);
        }
        for word in 0..BYTES / 8 {
            if get(DATA + word * 8) != pattern(self.observed, word) {
                return Err(210);
            }
        }
        self.close(key)?;
        let mut after = self.path_frame(file::STAT, VALUE)?;
        self.success(&mut after)?;
        self.object.matches(&after)?;
        if after.u16(file::OFF_MODE) != 1
            || after.u64(file::OFF_COUNT) != BYTES
            || after.u64(file::OFF_WRITE_SEQ) != self.observed
            || after.u64(file::OFF_DURABLE_SEQ) != self.observed
        {
            return Err(209);
        }
        self.verified = self.verified.checked_add(BYTES).ok_or(213u64)?;
        self.publish(5, 0);
        Ok(())
    }
    fn reader(&mut self, marker: &str) -> Result<()> {
        let before = self.await_value()?;
        self.object = Identity::object(&before)?;
        self.observed = before.u64(file::OFF_DURABLE_SEQ);
        self.read_current()?;
        if self.mode != 3 {
            let mut frame = self.path_frame(file::CREATE, marker)?;
            self.success(&mut frame)?;
            Identity::object(&frame)?;
            self.publish(6, 0);
        }
        Ok(())
    }
    fn write_pressure_file(&mut self, path: &str, file_index: u64) -> Result<()> {
        let mut frame = self.path_frame(file::CREATE, path)?;
        self.success(&mut frame)?;
        let object = Identity::object(&frame)?;
        let key = self.open_path(path, file::MODE_WRITE, object)?;
        for chunk in 0..PRESSURE_CHUNKS {
            let first_word = chunk * (PRESSURE_CHUNK_BYTES / 8);
            for word in 0..PRESSURE_CHUNK_BYTES / 8 {
                put(DATA + word * 8, pressure_pattern(file_index, first_word + word));
            }
            let mut frame = self.frame(file::WRITE)?;
            handle(&mut frame, key.id, key.generation);
            frame.set_u64(file::OFF_OFFSET, chunk * PRESSURE_CHUNK_BYTES);
            frame.set_u64(file::OFF_DATA, DATA);
            frame.set_u32(file::OFF_DATA_LENGTH, PRESSURE_CHUNK_BYTES as u32);
            self.success(&mut frame)?;
            object.matches(&frame)?;
            if frame.u64(file::OFF_COUNT) != PRESSURE_CHUNK_BYTES {
                return Err(210);
            }
        }
        let mut frame = self.frame(file::FSYNC)?;
        handle(&mut frame, key.id, key.generation);
        self.success(&mut frame)?;
        object.matches(&frame)?;
        if frame.u64(file::OFF_WRITE_SEQ) != PRESSURE_CHUNKS
            || frame.u64(file::OFF_DURABLE_SEQ) != PRESSURE_CHUNKS
        {
            return Err(211);
        }
        self.close(key)
    }
    fn cache_pressure(&mut self) -> Result<()> {
        let before = self.await_value()?;
        self.object = Identity::object(&before)?;
        self.observed = before.u64(file::OFF_DURABLE_SEQ);
        self.read_current()?;
        for (index, path) in PRESSURE.into_iter().enumerate() {
            self.write_pressure_file(path, index as u64 + 1)?;
        }
        self.publish(7, 0);
        let after = self.await_value()?;
        self.object.matches(&after)?;
        if after.u64(file::OFF_WRITE_SEQ) != self.observed
            || after.u64(file::OFF_DURABLE_SEQ) != self.observed
        {
            return Err(209);
        }
        self.read_current()
    }
}
fn pattern(version: u64, word: u64) -> u64 {
    0xa100_0000_0000_0000 | (version << 32) | word
}
fn pressure_pattern(file_index: u64, word: u64) -> u64 {
    0xa400_0000_0000_0000 | (file_index << 48) | word
}
fn marker(boot: u64) -> [u8; 26] {
    let mut bytes = *b"/a10/seen-0000000000000000";
    for digit in 0..16 {
        bytes[10 + digit] = b"0123456789abcdef"[((boot >> ((15 - digit) * 4)) & 15) as usize];
    }
    bytes
}

pub fn run(authority: file::Capability) -> u64 {
    let mode = get(0x21008);
    let deadline_ns = get(0x21020);
    let mut client = Client {
        authority,
        mode,
        role: get(0x21010),
        boot: get(0x21018),
        deadline: clock().saturating_add(deadline_ns),
        poll_ns: a10_budget::client_poll_ns(mode).unwrap_or(0),
        request: 0,
        progress_sequence: 0,
        object: Identity {
            id: 0,
            generation: 0,
        },
        consumed: 0,
        observed: 0,
        verified: 0,
    };
    client.publish(1, 0);
    let result = (|| {
        if get(0x20000) != 40
            || get(0x21000) != 1
            || !matches!(client.mode, 1..=4)
            || !matches!(client.role, 1 | 2)
            || client.boot == 0
            || a10_budget::client_deadline_ns(client.mode) != Some(deadline_ns)
            || client.poll_ns == 0
            || (client.mode >= 3 && client.role != 2)
        {
            return Err(201);
        }
        if authority.id == 0 || authority.generation == 0 {
            return Err(202);
        }
        let pages = if client.mode == 4 { DATA_PAGES } else { 1 };
        if call(14, DATA, pages, 1, 0, 0)[0] != 0 {
            return Err(203);
        }
        let bytes = marker(client.boot);
        let marker = core::str::from_utf8(&bytes).map_err(|_| 201u64)?;
        let work = if client.mode == 4 {
            client.cache_pressure()
        } else if client.role == 1 {
            client.writer(marker)
        } else {
            client.reader(marker)
        };
        let unmapped = call(15, DATA, pages, 0, 0, 0)[0] == 0;
        work?;
        if !unmapped {
            return Err(204);
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            client.publish(8, 0);
            0
        }
        Err(error) => {
            client.publish(255, error);
            error
        }
    }
}
