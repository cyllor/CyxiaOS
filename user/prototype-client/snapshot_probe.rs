//! Opt-in, fresh-volume native probe. The root supplies two different grants:
//! role 1 can create/list/read its historical prefix; role 2 is the explicitly
//! admitted recovery supervisor and has no ordinary write authority.
use super::{clock, file, file_call, get, waiting};
use file::snapshot as wire;

const BEFORE: &[u8; 16] = b"snapshot before!";
const AFTER: &[u8; 16] = b"changed after!!!";
const VALUE: &str = "/snapshot-probe/value";
const KEY_FILE: &str = "/snapshot-probe/key";
const READY: &str = "/snapshot-probe/ready";

struct Live {
    capability: file::Capability,
    sequence: u64,
    deadline: u64,
}
impl Live {
    fn frame(&mut self, operation: u16) -> Result<file::Frame, u64> {
        self.sequence = self.sequence.checked_add(1).ok_or(301u64)?;
        Ok(file::Frame::new(operation, self.sequence, self.capability))
    }
    fn execute(&mut self, frame: &mut file::Frame) -> Result<i64, u64> {
        if !file_call(frame, self.deadline) {
            return Err(302);
        }
        Ok(frame.result())
    }
    fn path(&mut self, operation: u16, path: &str) -> Result<i64, u64> {
        let mut frame = self.frame(operation)?;
        if !frame.set_path(path) {
            return Err(303);
        }
        self.execute(&mut frame)
    }
    fn open(&mut self, path: &str, mode: u16) -> Result<(u64, u64), u64> {
        let mut frame = self.frame(file::OPEN)?;
        if !frame.set_path(path) {
            return Err(304);
        }
        frame.set_u16(file::OFF_MODE, mode);
        if self.execute(&mut frame)? != 0 {
            return Err(305);
        }
        Ok((
            frame.u64(file::OFF_HANDLE_ID),
            frame.u64(file::OFF_HANDLE_GENERATION),
        ))
    }
    fn handle(&mut self, operation: u16, handle: (u64, u64)) -> Result<file::Frame, u64> {
        let mut frame = self.frame(operation)?;
        frame.set_u64(file::OFF_HANDLE_ID, handle.0);
        frame.set_u64(file::OFF_HANDLE_GENERATION, handle.1);
        Ok(frame)
    }
    fn write(&mut self, handle: (u64, u64), bytes: &[u8]) -> Result<(), u64> {
        let mut frame = self.handle(file::WRITE, handle)?;
        frame.set_u64(file::OFF_DATA, bytes.as_ptr() as u64);
        frame.set_u32(file::OFF_DATA_LENGTH, bytes.len() as u32);
        if self.execute(&mut frame)? != 0 || frame.u64(file::OFF_COUNT) != bytes.len() as u64 {
            return Err(306);
        }
        let mut sync = self.handle(file::FSYNC, handle)?;
        if self.execute(&mut sync)? != 0 {
            return Err(307);
        }
        Ok(())
    }
    fn read(&mut self, handle: (u64, u64), bytes: &mut [u8]) -> Result<i64, u64> {
        let mut frame = self.handle(file::READ, handle)?;
        frame.set_u64(file::OFF_DATA, bytes.as_mut_ptr() as u64);
        frame.set_u32(file::OFF_DATA_LENGTH, bytes.len() as u32);
        let status = self.execute(&mut frame)?;
        if status == 0 && frame.u64(file::OFF_COUNT) != bytes.len() as u64 {
            return Err(308);
        }
        Ok(status)
    }
    fn close(&mut self, handle: (u64, u64)) -> Result<(), u64> {
        let mut frame = self.handle(file::CLOSE, handle)?;
        if self.execute(&mut frame)? != 0 {
            return Err(309);
        }
        Ok(())
    }
}
struct Snapshot {
    capability: file::Capability,
    uuid: [u8; 16],
    client_slot: u32,
    sequence: u64,
    response: [u8; wire::MAX_RESPONSE],
}
impl Snapshot {
    fn key(&self, sequence: u64) -> [u8; 36] {
        let mut key = [0; 36];
        key[..16].copy_from_slice(&self.uuid);
        wire::put_u32(&mut key, 16, self.client_slot);
        wire::put_u64(&mut key, 20, 1);
        wire::put_u64(&mut key, 28, sequence);
        key
    }
    fn send(
        &mut self,
        operation: u16,
        key: [u8; 36],
        epoch: u64,
        payload: &[u8],
    ) -> Result<usize, u64> {
        let mut request =
            wire::RequestBuffer::new(operation, self.capability.id as u32, key, epoch);
        request.set_payload(payload).map_err(|_| 310u64)?;
        let reply = file::snapshot_client::invoke(self.capability, &request, &mut self.response)
            .map_err(|_| 311u64)?;
        if reply.status != 0 || (wire::persistent(operation) && reply.state != 2) {
            return Err(312);
        }
        Ok(reply.payload.len())
    }
    fn list(&mut self) -> Result<(u64, u64), u64> {
        let n = self.send(wire::SNAP_LIST, [0; 36], 0, &[])?;
        let data = &self.response[32..32 + n];
        if n < 48 + 128 || wire::u32_at(data, 0) == 0 {
            return Err(313);
        }
        self.uuid.copy_from_slice(&data[48..64]);
        Ok((wire::u64_at(data, 16), wire::u64_at(data, 24)))
    }
    fn mutate(&mut self, operation: u16, epoch: u64, payload: &[u8]) -> Result<[u8; 36], u64> {
        self.sequence = self.sequence.checked_add(1).ok_or(314u64)?;
        let key = self.key(self.sequence);
        self.send(operation, key, epoch, payload)?;
        Ok(key)
    }
    fn history_open(&mut self, key: &[u8; 40]) -> Result<u64, u64> {
        let mut payload = [0; 48 + VALUE.len()];
        payload[..40].copy_from_slice(key);
        wire::put_u16(&mut payload, 40, VALUE.len() as u16);
        payload[48..].copy_from_slice(VALUE.as_bytes());
        if self.send(wire::SNAP_OPEN, [0; 36], 0, &payload)? != 8 {
            return Err(315);
        }
        Ok(wire::u64_at(&self.response, 32))
    }
}
fn ordinary(live: &mut Live, snapshot: &mut Snapshot) -> Result<(), u64> {
    for (op, path) in [
        (file::MKDIR, "/snapshot-probe"),
        (file::CREATE, VALUE),
        (file::CREATE, KEY_FILE),
    ] {
        if live.path(op, path)? != 0 {
            return Err(320);
        }
    }
    let value = live.open(VALUE, file::MODE_READ_WRITE)?;
    live.write(value, BEFORE)?;
    let (epoch, _) = snapshot.list()?;
    let mut payload = [0; 16];
    wire::put_u64(&mut payload, 0, 3600);
    wire::put_u32(&mut payload, 8, 2);
    wire::put_u32(&mut payload, 12, 1);
    snapshot.mutate(wire::SNAP_CREATE, epoch, &payload)?;
    let mut key = [0; 40];
    key.copy_from_slice(&snapshot.response[32..72]);
    live.write(value, AFTER)?;
    let marker = live.open(KEY_FILE, file::MODE_WRITE)?;
    live.write(marker, &key)?;
    live.close(marker)?;
    let history = snapshot.history_open(&key)?;
    let mut historical = Live {
        capability: snapshot.capability,
        sequence: 0,
        deadline: live.deadline,
    };
    let mut bytes = [0; 16];
    if historical.read((history, 0), &mut bytes)? != 0 || &bytes != BEFORE {
        return Err(321);
    }
    // The empty ready name is published only after the key and last live
    // write have durable receipts, so the recovery actor cannot race fsync.
    if live.path(file::CREATE, READY)? != 0 {
        return Err(322);
    }
    while snapshot.list()?.0 == epoch {
        if !waiting(live.deadline) {
            return Err(323);
        }
    }
    if live.read(value, &mut bytes)? != -116 {
        return Err(324);
    }
    if historical.read((history, 0), &mut bytes)? != 0 || &bytes != BEFORE {
        return Err(325);
    }
    historical.close((history, 0))?;
    live.close(value)?;
    Ok(())
}
fn recover(live: &mut Live, snapshot: &mut Snapshot) -> Result<(), u64> {
    loop {
        match live.path(file::STAT, READY)? {
            0 => break,
            -2 => {
                if !waiting(live.deadline) {
                    return Err(330);
                }
            }
            _ => return Err(331),
        }
    }
    let marker = live.open(KEY_FILE, file::MODE_READ)?;
    let mut key = [0; 40];
    if live.read(marker, &mut key)? != 0 {
        return Err(332);
    }
    live.close(marker)?;
    let (epoch, _) = snapshot.list()?;
    let mut payload = [0; 48];
    payload[..40].copy_from_slice(&key);
    wire::put_u32(&mut payload, 40, 2);
    let restored = snapshot.mutate(wire::SNAP_RESTORE, epoch, &payload)?;
    let (new_epoch, protection) = snapshot.list()?;
    if new_epoch != epoch.checked_add(1).ok_or(333u64)? {
        return Err(334);
    }
    let value = live.open(VALUE, file::MODE_READ)?;
    let mut bytes = [0; 16];
    if live.read(value, &mut bytes)? != 0 || &bytes != BEFORE {
        return Err(335);
    }
    live.close(value)?;
    payload.fill(0);
    wire::put_u64(&mut payload, 0, protection);
    payload[8..44].copy_from_slice(&restored);
    snapshot.mutate(wire::OPEN_WRITES, new_epoch, &payload)?;
    Ok(())
}
pub fn run(files: file::Capability, snapshots: file::Capability) -> u64 {
    if get(0x20000) != 8 {
        return 300;
    }
    let role = get(0x21000);
    if !(1..=2).contains(&role) {
        return 300;
    }
    let Some(deadline) = clock().checked_add(50_000_000_000) else {
        return 300;
    };
    let mut live = Live {
        capability: files,
        sequence: 0,
        deadline,
    };
    let mut snapshot = Snapshot {
        capability: snapshots,
        uuid: [0; 16],
        client_slot: if role == 1 { 0 } else { 15 },
        // Trusted bootstrap used and ACKed recovery sequence 1 to open the
        // fresh business namespace after both periodic baselines were durable.
        sequence: if role == 1 { 0 } else { 1 },
        response: [0; wire::MAX_RESPONSE],
    };
    let result = if role == 1 {
        ordinary(&mut live, &mut snapshot)
    } else {
        recover(&mut live, &mut snapshot)
    };
    result.map_or_else(|code| code, |()| 0)
}
