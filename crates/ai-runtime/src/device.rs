use crate::{Error, model};
const REQUESTS: usize = 16;
const BYTES: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Uart,
    Timer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    Again,
    Failed,
}
impl From<cyxia_contracts::PlatformError> for IoError {
    fn from(error: cyxia_contracts::PlatformError) -> Self {
        match error {
            cyxia_contracts::PlatformError::Again => Self::Again,
            _ => Self::Failed,
        }
    }
}
/// Adapter must be bounded and nonblocking. A successful UART result is the exact
/// accepted prefix; Again accepts zero bytes. Failed can have unknown physical side effects
/// and is never retried. Completion is acceptance, not remote delivery.
pub trait DeviceIo {
    fn uart_write(&mut self, data: &[u8]) -> Result<usize, IoError>;
    fn timer_read(&mut self) -> Result<u64, IoError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    Queued,
    Complete,
    Failed,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestInfo {
    pub id: u64,
    pub owner: u32,
    pub device: Device,
    pub state: RequestState,
    pub done: usize,
    pub len: usize,
    pub result: u64,
    pub retries: u8,
    pub uncertain: bool,
}
#[derive(Clone, Copy)]
struct Request {
    info: RequestInfo,
    data: [u8; BYTES],
    priority: u8,
    submitted: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct DeviceInfo {
    pub device: Device,
    pub present: bool,
    pub enabled: bool,
    pub pending: usize,
}
pub(crate) struct Devices {
    requests: [Option<Request>; REQUESTS],
    present: [bool; 2],
    enabled: [bool; 2],
    next: u64,
    pub decisions: u64,
    pub failures: u64,
    pub guards: u64,
    pub mechanisms: u64,
}
fn index(d: Device) -> usize {
    match d {
        Device::Uart => 0,
        Device::Timer => 1,
    }
}
impl Devices {
    pub const fn new() -> Self {
        Self {
            requests: [None; REQUESTS],
            present: [false; 2],
            enabled: [false; 2],
            next: 1,
            decisions: 0,
            failures: 0,
            guards: 0,
            mechanisms: 0,
        }
    }
    pub fn bind(&mut self, uart: bool, timer: bool) {
        self.present = [uart, timer];
        self.enabled = [uart, timer];
    }
    pub fn info(&self, d: Device) -> DeviceInfo {
        DeviceInfo {
            device: d,
            present: self.present[index(d)],
            enabled: self.enabled[index(d)],
            pending: self
                .requests
                .iter()
                .flatten()
                .filter(|r| r.info.device == d && r.info.state == RequestState::Queued)
                .count(),
        }
    }
    pub fn enable(&mut self, d: Device, enabled: bool) -> Result<(), Error> {
        if !self.present[index(d)] {
            return Err(Error::Offline);
        }
        if self.info(d).pending > 0 {
            return Err(Error::Busy);
        }
        self.enabled[index(d)] = enabled;
        Ok(())
    }
    pub fn check_batch(&self, d: Device, count: usize) -> Result<(), Error> {
        if count == 0 || count > 8 {
            return Err(Error::Invalid);
        }
        if !self.present[index(d)] || !self.enabled[index(d)] {
            return Err(Error::Offline);
        }
        if self.requests.iter().filter(|r| r.is_none()).count() < count {
            return Err(Error::Capacity);
        }
        self.next
            .checked_add(count as u64)
            .ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn submit(
        &mut self,
        owner: u32,
        d: Device,
        data: &[u8],
        priority: u8,
        now: u64,
    ) -> Result<u64, Error> {
        if owner == 0
            || priority > 3
            || data.len() > BYTES
            || (d == Device::Uart && data.is_empty())
            || (d == Device::Timer && !data.is_empty())
        {
            return Err(Error::Invalid);
        }
        if !self.present[index(d)] || !self.enabled[index(d)] {
            return Err(Error::Offline);
        }
        let slot = self
            .requests
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let id = self.next;
        let mut bytes = [0; BYTES];
        bytes[..data.len()].copy_from_slice(data);
        self.requests[slot] = Some(Request {
            info: RequestInfo {
                id,
                owner,
                device: d,
                state: RequestState::Queued,
                done: 0,
                len: data.len(),
                result: 0,
                retries: 0,
                uncertain: false,
            },
            data: bytes,
            priority,
            submitted: now,
        });
        self.next = next;
        Ok(id)
    }
    pub fn get(&self, id: u64) -> Result<RequestInfo, Error> {
        self.requests
            .iter()
            .flatten()
            .find(|r| r.info.id == id)
            .map(|r| r.info)
            .ok_or(Error::Stale)
    }
    pub fn reap(&mut self, owner: u32, id: u64) -> Result<RequestInfo, Error> {
        let slot = self
            .requests
            .iter()
            .position(|r| r.is_some_and(|r| r.info.id == id))
            .ok_or(Error::Stale)?;
        let r = self.requests[slot].ok_or(Error::Invariant)?;
        if r.info.owner != owner {
            return Err(Error::Owner);
        }
        if r.info.state == RequestState::Queued {
            return Err(Error::Busy);
        }
        self.requests[slot] = None;
        Ok(r.info)
    }
    pub fn cancel_owner(&mut self, owner: u32) {
        for r in &mut self.requests {
            if r.is_some_and(|r| r.info.owner == owner) {
                *r = None;
            }
        }
    }
    pub fn cancel(&mut self, owner: u32, id: u64) -> Result<(), Error> {
        let r = self
            .requests
            .iter_mut()
            .flatten()
            .find(|r| r.info.id == id)
            .ok_or(Error::Stale)?;
        if r.info.owner != owner {
            return Err(Error::Owner);
        }
        if r.info.state != RequestState::Queued {
            return Err(Error::State);
        }
        r.info.state = RequestState::Cancelled;
        Ok(())
    }
    pub fn records(&self) -> impl Iterator<Item = RequestInfo> + '_ {
        self.requests.iter().flatten().map(|r| r.info)
    }
    pub fn step(
        &mut self,
        now: u64,
        io: &mut impl DeviceIo,
    ) -> Option<(u32, u64, cyxia_contracts::DecisionSource, usize)> {
        // No retry loop: at most one driver attempt per service tick.
        let candidates = self
            .requests
            .iter()
            .flatten()
            .filter(|r| r.info.state == RequestState::Queued)
            .count();
        let mut selected = None;
        for (i, r) in self.requests.iter().enumerate() {
            if let Some(r) = r
                && r.info.state == RequestState::Queued
            {
                let age = now.saturating_sub(r.submitted);
                if age >= 64 {
                    selected = Some(i);
                    break;
                }
                if selected.is_none_or(|j: usize| {
                    self.requests[j].is_some_and(|b| {
                        model::device(age, r.priority, r.info.retries)
                            > model::device(
                                now.saturating_sub(b.submitted),
                                b.priority,
                                b.info.retries,
                            )
                    })
                }) {
                    selected = Some(i);
                }
            }
        }
        let i = selected?;
        let r = self.requests[i].as_mut()?;
        let before = r.info.done;
        let expired = now.saturating_sub(r.submitted) >= 64;
        let source = if expired {
            cyxia_contracts::DecisionSource::SafetyGuard
        } else if candidates > 1 {
            cyxia_contracts::DecisionSource::AiDirect
        } else {
            cyxia_contracts::DecisionSource::Mechanism
        };
        if expired {
            r.info.state = RequestState::Failed;
            self.guards = self.guards.saturating_add(1);
        } else {
            if candidates > 1 {
                self.decisions = self.decisions.saturating_add(1);
            } else {
                self.mechanisms = self.mechanisms.saturating_add(1);
            }
            match r.info.device {
                Device::Uart => match io.uart_write(&r.data[r.info.done..r.info.len]) {
                    Ok(n) if n > 0 && n <= r.info.len - r.info.done => {
                        r.info.done += n;
                        if r.info.done == r.info.len {
                            r.info.state = RequestState::Complete;
                        }
                    }
                    Err(IoError::Again) | Ok(0) => {
                        r.info.retries += 1;
                        if r.info.retries >= 8 {
                            r.info.state = RequestState::Failed;
                        }
                    }
                    _ => {
                        r.info.state = RequestState::Failed;
                        r.info.uncertain = true;
                    }
                },
                Device::Timer => match io.timer_read() {
                    Ok(v) => {
                        r.info.result = v;
                        r.info.state = RequestState::Complete;
                    }
                    Err(IoError::Again) => {
                        r.info.retries += 1;
                        if r.info.retries >= 8 {
                            r.info.state = RequestState::Failed;
                        }
                    }
                    Err(IoError::Failed) => r.info.state = RequestState::Failed,
                },
            }
        }
        if r.info.state == RequestState::Failed {
            self.failures = self.failures.saturating_add(1);
        }
        Some((r.info.owner, r.info.id, source, r.info.done - before))
    }
}
