use super::memory::{Pages, copy_from, copy_to, fault_page, prepare};
use super::*;

pub(super) struct Mailbox<'a> {
    pub tasks: &'a [Task; TASKS],
    pub wake: &'a mut u64,
    pub received: &'a mut [u8],
    pub used: usize,
}
impl IpcBackend<IPC_BYTES> for Mailbox<'_> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        operation: IpcOperation,
    ) -> Result<(), Error> {
        let owner = self
            .tasks
            .iter()
            .find(|t| t.life != Life::Free && t.endpoint == endpoint)
            .ok_or(Error::Stale)?;
        match operation {
            IpcOperation::Receive if owner.key == actor => Ok(()),
            IpcOperation::Send if owner.closed => Err(Error::Auth),
            IpcOperation::Send if actor == KERNEL_CALLER && owner.recipe != 0 => Ok(()),
            IpcOperation::Send => {
                let sender = &self.tasks[task_index(self.tasks, actor)?];
                if sender.closed || sender.life == Life::Exiting {
                    return Err(Error::Auth);
                }
                if sender.key == owner.key || sender.caps.contains(&endpoint) {
                    Ok(())
                } else {
                    Err(Error::Auth)
                }
            }
            _ => Err(Error::Auth),
        }
    }
    fn notify(&mut self, actor: ObjectKey, _endpoint: ObjectKey) -> Result<(), Error> {
        let i = task_index(self.tasks, actor)?;
        *self.wake |= 1u64 << i;
        Ok(())
    }
    fn deliver(
        &mut self,
        receiver: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<IPC_BYTES>,
    ) -> Result<(), Error> {
        self.authorize(receiver, endpoint, IpcOperation::Receive)?;
        let end = self
            .used
            .checked_add(32 + message.len)
            .filter(|end| *end <= self.received.len())
            .ok_or(Error::Again)?;
        for (i, value) in [
            message.sequence,
            message.sender.id,
            message.sender.generation,
            message.len as u64,
        ]
        .into_iter()
        .enumerate()
        {
            self.received[self.used + i * 8..self.used + i * 8 + 8]
                .copy_from_slice(&value.to_le_bytes());
        }
        self.received[self.used + 32..end].copy_from_slice(&message.bytes[..message.len]);
        self.used = end;
        Ok(())
    }
}

/// Each dispatch places one copied vector into a real endpoint. The receiver
/// verifies the copied operation/object/generation before reading either service.
pub(super) struct Transport<'a> {
    pub tasks: &'a [Task; TASKS],
    pub validate: Option<ValidateFile>,
    pub stat: Option<StatFile>,
    pub ipc: &'a mut Ipc<IPC_BYTES>,
    pub task_endpoint: ObjectKey,
    pub file_endpoint: ObjectKey,
    pub sequence: &'a mut u64,
    pub lease: &'a mut VectorLease,
}
struct ServiceAuthority {
    service: ObjectKey,
    endpoint: ObjectKey,
}
impl IpcBackend<IPC_BYTES> for ServiceAuthority {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        _: IpcOperation,
    ) -> Result<(), Error> {
        if actor == self.service && endpoint == self.endpoint {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)
    }
    fn deliver(&mut self, _: ObjectKey, _: ObjectKey, _: &Message<IPC_BYTES>) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
/// PENDING vectors own real cells; no service effect occurs until the exact
/// bound grant version has received the root's execution acknowledgement.
pub(super) fn prepare_vector_leases(s: &mut State, i: usize) -> Result<bool, Error> {
    if s.vector_leases[i].ready {
        return Ok(true);
    }
    if now_ns() >= s.vector_leases[i].deadline {
        return Ok(true);
    }
    for j in 0..2 {
        if s.vector_leases[i].needed & (1 << j) == 0 {
            continue;
        }
        let (service, endpoint) = if j == 0 {
            (TASK_SERVICE, s.task_endpoint)
        } else {
            (FILE_SERVICE, s.file_endpoint)
        };
        let mut authority = ServiceAuthority { service, endpoint };
        if s.vector_leases[i].grants[j].is_none() {
            let request = s.service_sequence.checked_add(1).ok_or(Error::Overflow)?;
            s.service_sequence = request;
            let grant = s
                .ipc
                .reserve_send(service, endpoint, request, now_ns(), &mut authority)?;
            s.vector_leases[i].grants[j] = Some(grant);
            s.vector_leases[i].requests[j] = request;
        }
        s.ipc.validate_confirmed_send_grant(
            s.vector_leases[i].grants[j].ok_or(Error::NotReady)?,
            service,
            endpoint,
            &mut authority,
        )?;
    }
    s.vector_leases[i].ready = true;
    Ok(true)
}
pub(super) fn release_vector_leases(s: &mut State, i: usize) -> Result<(), Error> {
    for j in 0..2 {
        if let Some(grant) = s.vector_leases[i].grants[j] {
            match s.ipc.cancel_send(grant) {
                Ok(()) | Err(Error::Stale) => {}
                Err(e) => return Err(e),
            }
            s.vector_leases[i].grants[j] = None;
        }
    }
    s.vector_leases[i] = VectorLease::EMPTY;
    Ok(())
}
fn validate_object(
    tasks: &[Task; TASKS],
    validate: Option<ValidateFile>,
    object: ObjectKey,
    op: u16,
) -> Result<(), Error> {
    match op {
        TASK_QUERY_BY_CAP => {
            task_index(tasks, object)?;
            Ok(())
        }
        FILE_STAT_BY_CAP => validate.ok_or(Error::NotReady)?(object),
        _ => Err(Error::Unsupported),
    }
}
struct BatchDelivery<'a> {
    tasks: &'a [Task; TASKS],
    validate: Option<ValidateFile>,
    stat: Option<StatFile>,
    service: ObjectKey,
    endpoint: ObjectKey,
    request: u64,
    items: &'a [ResolvedItem],
    results: &'a mut [Option<Result<u64, Error>>],
    delivered: bool,
}
impl IpcBackend<IPC_BYTES> for BatchDelivery<'_> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        _: IpcOperation,
    ) -> Result<(), Error> {
        if actor == self.service && endpoint == self.endpoint {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)
    }
    fn deliver(
        &mut self,
        receiver: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<IPC_BYTES>,
    ) -> Result<(), Error> {
        self.authorize(receiver, endpoint, IpcOperation::Receive)?;
        if self.delivered
            || message.sender != self.service
            || message.request_id != self.request
            || message.len != self.items.len() * 32
        {
            return Err(Error::Conflict);
        }
        // Full transport decoding precedes the first service observation.
        for (i, item) in self.items.iter().enumerate() {
            let row = &message.bytes[i * 32..i * 32 + 32];
            for (offset, word) in [
                u64::from(item.op),
                item.object.id,
                item.object.generation,
                item.tag,
            ]
            .into_iter()
            .enumerate()
            {
                if row[offset * 8..offset * 8 + 8] != word.to_le_bytes() {
                    return Err(Error::Conflict);
                }
            }
        }
        for (i, item) in self.items.iter().enumerate() {
            self.results[i] = Some(
                validate_object(self.tasks, self.validate, item.object, item.op).and_then(|()| {
                    match item.op {
                        TASK_QUERY_BY_CAP => {
                            let t = &self.tasks[task_index(self.tasks, item.object)?];
                            Ok((t.life as u64) | ((t.exit_code & 0xffff_ffff) << 32))
                        }
                        FILE_STAT_BY_CAP => self.stat.ok_or(Error::NotReady)?(item.object),
                        _ => Err(Error::Unsupported),
                    }
                }),
            );
        }
        self.delivered = true;
        Ok(())
    }
}
impl ServiceBackend for Transport<'_> {
    fn validate_object(&mut self, object: ObjectKey, op: u16) -> Result<(), Error> {
        validate_object(self.tasks, self.validate, object, op)
    }
    fn call_batch(
        &mut self,
        service: ObjectKey,
        items: &[ResolvedItem],
        results: &mut [Option<Result<u64, Error>>],
    ) -> Result<(), Error> {
        if items.is_empty() || items.len() > 8 || results.len() != items.len() {
            return Err(Error::Format);
        }
        let endpoint = if service == TASK_SERVICE {
            self.task_endpoint
        } else if service == FILE_SERVICE {
            self.file_endpoint
        } else {
            return Err(Error::Auth);
        };
        if self.ipc.stats(endpoint)?.depth != 0 {
            return Err(Error::Busy);
        }
        let index = usize::from(service == FILE_SERVICE);
        let reserved = self.lease.grants[index];
        let next = if reserved.is_some() {
            self.lease.requests[index]
        } else {
            self.sequence.checked_add(1).ok_or(Error::Overflow)?
        };
        let mut bytes = [0u8; IPC_BYTES];
        for (i, item) in items.iter().enumerate() {
            if (service == TASK_SERVICE && item.op != TASK_QUERY_BY_CAP)
                || (service == FILE_SERVICE && item.op != FILE_STAT_BY_CAP)
            {
                return Err(Error::Auth);
            }
            for (j, value) in [
                u64::from(item.op),
                item.object.id,
                item.object.generation,
                item.tag,
            ]
            .into_iter()
            .enumerate()
            {
                bytes[i * 32 + j * 8..i * 32 + j * 8 + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        let mut backend = BatchDelivery {
            tasks: self.tasks,
            validate: self.validate,
            stat: self.stat,
            service,
            endpoint,
            request: next,
            items,
            results,
            delivered: false,
        };
        if let Some(grant) = reserved {
            self.ipc.send_reserved(
                grant,
                next,
                &bytes[..items.len() * 32],
                now_ns(),
                &mut backend,
            )?;
            self.lease.grants[index] = None;
        } else {
            self.ipc.send(
                service,
                endpoint,
                next,
                &bytes[..items.len() * 32],
                now_ns(),
                &mut backend,
            )?;
            *self.sequence = next;
        }
        self.ipc
            .receive_batch(service, endpoint, now_ns(), &mut backend)?;
        if backend.delivered {
            Ok(())
        } else {
            Err(Error::Again)
        }
    }
}

pub fn grant_file_cap(caller: ObjectKey, object: ObjectKey) -> Result<u64, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        task_index(&s.tasks, caller)?;
        s.validate_file.ok_or(Error::NotReady)?(object)?;
        s.services.grant(caller, object, FILE_SERVICE, 1)
    })
}
pub fn grant_endpoint(
    owner: ObjectKey,
    recipient: ObjectKey,
    endpoint: ObjectKey,
) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        if s.tasks[i].endpoint != endpoint || s.tasks[i].closed {
            return Err(Error::Auth);
        }
        s.ipc.stats(endpoint)?;
        let recipient = task_index(&s.tasks, recipient)?;
        if s.tasks[recipient].caps.contains(&endpoint) {
            return Ok(());
        }
        let cap = s.tasks[recipient]
            .caps
            .iter_mut()
            .find(|key| **key == ZERO)
            .ok_or(Error::Capacity)?;
        *cap = endpoint;
        Ok(())
    })
}
fn read(s: &mut State, owner: ObjectKey, address: u64, out: &mut [u8]) -> Result<(), Error> {
    prepare(
        &mut s.memory,
        &s.tasks,
        s.remote,
        owner,
        address,
        out.len(),
        false,
    )?;
    copy_from(&s.memory, &s.tasks, owner, address, out)
}
fn write(s: &mut State, owner: ObjectKey, address: u64, input: &[u8]) -> Result<(), Error> {
    prepare(
        &mut s.memory,
        &s.tasks,
        s.remote,
        owner,
        address,
        input.len(),
        true,
    )?;
    copy_to(&s.memory, owner, address, input)
}
fn spawn_result(context: &mut user::Context, state: SpawnState) {
    let (status, id, generation) = match state {
        SpawnState::Queued => (0, 0, 0),
        SpawnState::Created(key) => (1, key.id, key.generation),
        SpawnState::Failed(error) => (2, error_word(error), 0),
        SpawnState::Unknown => (3, 0, 0),
        SpawnState::Cancelled => (4, 0, 0),
    };
    context.regs[1] = status;
    context.regs[2] = id;
    context.regs[3] = generation;
}
fn waiter_result(context: &mut user::Context, result: WaitResult) {
    let (status, value) = match result {
        WaitResult::Pending => (0, 0),
        WaitResult::Sent(sequence) => (1, sequence),
        WaitResult::Cancelled => (2, 0),
        WaitResult::Failed(error) => (3, error_word(error)),
    };
    context.regs[1] = status;
    context.regs[2] = value;
}
fn copy_results(s: &mut State, i: usize) -> Result<(bool, usize), Error> {
    let vector = s.vectors[i].as_ref().ok_or(Error::NotFound)?;
    let mut bytes = [0u8; MAX_VECTOR * 24];
    for (j, result) in vector.results().iter().enumerate() {
        let (status, value) = match result.status {
            ItemStatus::Pending => (0, 0),
            ItemStatus::Value(value) => (1, value),
            ItemStatus::Error(error) => (2, error_word(error)),
            ItemStatus::Cancelled => (3, 0),
            ItemStatus::TimedOut => (4, 0),
        };
        for (k, value) in [result.tag, status, value].into_iter().enumerate() {
            bytes[j * 24 + k * 8..j * 24 + k * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    let count = vector.results().len();
    let complete = vector.complete();
    write(
        s,
        s.tasks[i].key,
        s.tasks[i].vector_output,
        &bytes[..count * 24],
    )?;
    Ok((complete, count))
}
pub(super) fn syscall_locked(
    s: &mut State,
    i: usize,
    context: &mut user::Context,
) -> Result<(), Error> {
    let task = s.tasks[i];
    let args = [
        context.regs[0],
        context.regs[1],
        context.regs[2],
        context.regs[3],
        context.regs[4],
    ];
    if task.closed
        && !matches!(
            context.regs[8],
            0 | 1 | 3 | 7 | 9 | 10 | 12 | 13 | 15 | 16 | 17 | 18
        )
    {
        return Err(Error::Auth);
    }
    match context.regs[8] {
        0 => {}
        1 => {
            s.tasks[i].exit_code = args[0];
            s.tasks[i].terminal_seen = true;
            s.tasks[i].life = Life::Exiting;
        }
        2 => {
            let len = usize::try_from(args[2]).map_err(|_| Error::Range)?;
            if len > 4096 {
                return Err(Error::Range);
            }
            let mut input = [0u8; 4096];
            read(s, task.key, args[1], &mut input[..len])?;
            let target_cpu = u16::try_from(args[3]).map_err(|_| Error::Range)?;
            let state = execution::submit_locked(
                s,
                task.key,
                args[0],
                task.group,
                &input[..len],
                target_cpu,
                args[4],
                false,
                0,
            )?;
            spawn_result(context, state);
        }
        3 => spawn_result(context, s.admission.query(task.key, args[0])?),
        4 => spawn_result(context, s.admission.cancel(task.key, args[0])?),
        5 => {
            let endpoint = if task.endpoint == ZERO {
                let endpoint = s.ipc.open(task.key, false)?;
                s.tasks[i].endpoint = endpoint;
                endpoint
            } else {
                task.endpoint
            };
            context.regs[1] = endpoint.id;
            context.regs[2] = endpoint.generation;
        }
        6 | 8 => {
            let endpoint = ObjectKey {
                id: args[0],
                generation: args[1],
            };
            let len = usize::try_from(args[4]).map_err(|_| Error::Range)?;
            if len > IPC_BYTES {
                return Err(Error::Range);
            }
            let mut bytes = [0u8; IPC_BYTES];
            read(s, task.key, args[3], &mut bytes[..len])?;
            let mut backend = Mailbox {
                tasks: &s.tasks,
                wake: &mut s.wake,
                received: &mut [],
                used: 0,
            };
            if context.regs[8] == 6 {
                context.regs[1] = s.ipc.send(
                    task.key,
                    endpoint,
                    args[2],
                    &bytes[..len],
                    now_ns(),
                    &mut backend,
                )?;
            } else {
                context.regs[1] = s
                    .ipc
                    .wait_send(
                        task.key,
                        endpoint,
                        args[2],
                        &bytes[..len],
                        now_ns(),
                        &mut backend,
                    )?
                    .id;
            }
        }
        7 => {
            let len = usize::try_from(args[1]).map_err(|_| Error::Range)?;
            if len > 8192 || len < 32 {
                return Err(Error::Range);
            }
            prepare(
                &mut s.memory,
                &s.tasks,
                s.remote,
                task.key,
                args[0],
                len,
                true,
            )?;
            let mut bytes = [0u8; 8192];
            let mut backend = Mailbox {
                tasks: &s.tasks,
                wake: &mut s.wake,
                received: &mut bytes[..len],
                used: 0,
            };
            let count = s
                .ipc
                .receive_batch(task.key, task.endpoint, now_ns(), &mut backend)?;
            let used = backend.used;
            if count == 0 {
                return Err(Error::Again);
            }
            copy_to(&s.memory, task.key, args[0], &bytes[..used])?;
            context.regs[1] = count as u64;
            context.regs[2] = used as u64;
        }
        9 | 10 => {
            let ticket = WaitTicket {
                id: args[0],
                endpoint: ObjectKey {
                    id: args[1],
                    generation: args[2],
                },
                sender: task.key,
            };
            let result = if context.regs[8] == 9 {
                s.ipc.wait_result(ticket)?
            } else {
                s.ipc.cancel(
                    ticket,
                    &mut Mailbox {
                        tasks: &s.tasks,
                        wake: &mut s.wake,
                        received: &mut [],
                        used: 0,
                    },
                )?
            };
            waiter_result(context, result);
        }
        11 => {
            let count = usize::try_from(args[1]).map_err(|_| Error::Range)?;
            if count == 0 || count > MAX_VECTOR {
                return Err(Error::Format);
            }
            if s.vectors[i].as_ref().is_some_and(|v| !v.complete()) {
                return Err(Error::Busy);
            }
            let mut encoded = [0u8; MAX_VECTOR * 32];
            read(s, task.key, args[0], &mut encoded[..count * 32])?;
            prepare(
                &mut s.memory,
                &s.tasks,
                s.remote,
                task.key,
                args[3],
                count * 24,
                true,
            )?;
            let mut items = [ServiceItem::default(); MAX_VECTOR];
            for (j, item) in items[..count].iter_mut().enumerate() {
                let row = &encoded[j * 32..j * 32 + 32];
                if row[4..8] != [0; 4] {
                    return Err(Error::Format);
                }
                *item = ServiceItem {
                    op: u16::from_le_bytes(row[..2].try_into().unwrap()),
                    flags: u16::from_le_bytes(row[2..4].try_into().unwrap()),
                    cap: u64::from_le_bytes(row[8..16].try_into().unwrap()),
                    object_gen: u64::from_le_bytes(row[16..24].try_into().unwrap()),
                    tag: u64::from_le_bytes(row[24..32].try_into().unwrap()),
                };
            }
            let id = s.vector_ids[i].checked_add(1).ok_or(Error::Overflow)?;
            s.services
                .preflight(task.key, &items[..count], args[2], now_ns())?;
            release_vector_leases(s, i)?;
            let vector = s
                .services
                .submit(task.key, &items[..count], args[2], now_ns())?;
            s.vectors[i] = Some(vector);
            s.vector_leases[i] = VectorLease {
                needed: items[..count].iter().fold(0, |mask, item| {
                    mask | if item.op == TASK_QUERY_BY_CAP { 1 } else { 2 }
                }),
                deadline: args[2],
                ..VectorLease::EMPTY
            };
            let _ = prepare_vector_leases(s, i);
            s.vector_ids[i] = id;
            s.tasks[i].vector_output = args[3];
            s.facts.vector_started[i] = now_ns();
            s.facts.vector_measured[i] = false;
            s.facts.vectors.add(now_ns(), 1);
            s.facts.last_vector_len = count as u64;
            context.regs[1] = id;
        }
        12 => {
            if args[0] != s.vector_ids[i] {
                return Err(Error::Stale);
            }
            let (complete, count) = copy_results(s, i)?;
            context.regs[1] = u64::from(complete);
            context.regs[2] = count as u64;
        }
        13 => {
            if args[0] != s.vector_ids[i] {
                return Err(Error::Stale);
            }
            s.vectors[i]
                .as_mut()
                .ok_or(Error::NotFound)?
                .cancel(args[1])?;
        }
        14 => {
            let pages = usize::try_from(args[1]).map_err(|_| Error::Range)?;
            if args[0] < 0x50000
                || pages == 0
                || pages > 64
                || args[2] > 1
                || task.region_count == task.regions.len()
                || args[0]
                    .checked_add(pages as u64 * 4096)
                    .is_none_or(|end| end > USER_LIMIT)
            {
                return Err(Error::Range);
            }
            s.memory.reserve(task.key, args[0], pages, args[2] != 0)?;
            s.tasks[i].regions[task.region_count] = args[0];
            s.tasks[i].region_count += 1;
        }
        15 => {
            if args[0] < 0x50000 {
                return Err(Error::Auth);
            }
            let region = task.regions[..task.region_count]
                .iter()
                .position(|base| *base == args[0])
                .ok_or(Error::NotFound)?;
            let result = s.memory.unmap_step(
                task.key,
                args[0],
                64,
                &mut Pages {
                    tasks: &s.tasks,
                    remote: s.remote,
                    load: None,
                },
            )?;
            if result.remaining != 0 {
                return Err(Error::Busy);
            }
            s.tasks[i]
                .regions
                .copy_within(region + 1..task.region_count, region);
            s.tasks[i].region_count -= 1;
            s.tasks[i].regions[task.region_count - 1] = 0;
        }
        16 => {
            context.regs[1] = task.own_query_cap;
            context.regs[2] = task.key.generation;
        }
        17 => {
            context.regs[1] = now_ns();
        }
        18 => {
            let child = ObjectKey {
                id: args[0],
                generation: args[1],
            };
            if let Some(record) = s
                .exits
                .iter()
                .flatten()
                .find(|record| record.key == child && record.parent == task.key)
            {
                context.regs[1] = 1;
                context.regs[2] = record.code;
                context.regs[3] = record.value;
            } else if s.tasks.iter().any(|child_task| {
                child_task.key == child
                    && child_task.parent == task.key
                    && child_task.life != Life::Free
            }) {
                context.regs[1] = 0;
                context.regs[2] = 0;
                context.regs[3] = 0;
            } else {
                return Err(Error::Auth);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    context.regs[0] = 0;
    Ok(())
}
pub(super) fn fault_locked(
    s: &mut State,
    owner: ObjectKey,
    context: &user::Context,
) -> Result<(), Error> {
    let esr = context.esr;
    let fsc = esr & 63;
    if context.kind != 8 || esr >> 26 != 0x24 || !(4..=7).contains(&fsc) || esr & (1 << 10) != 0 {
        return Err(Error::Auth);
    }
    fault_page(
        &mut s.memory,
        owner,
        context.far,
        esr & (1 << 6) != 0,
        &mut Pages {
            tasks: &s.tasks,
            remote: s.remote,
            load: None,
        },
    )?;
    Ok(())
}
pub fn fault(owner: ObjectKey, context: &user::Context) -> Result<(), Error> {
    locked(|s| {
        task_index(&s.tasks, owner)?;
        fault_locked(s, owner, context)
    })
}
pub fn syscall(owner: ObjectKey, context: &mut user::Context) -> Result<(), Error> {
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        syscall_locked(s, i, context)
    })
}

struct NetworkBackend<'a> {
    network: Network,
    send: Option<&'a mut dyn FnMut(&[u8]) -> Result<(), Error>>,
}
impl IpcBackend<IPC_BYTES> for NetworkBackend<'_> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        operation: IpcOperation,
    ) -> Result<(), Error> {
        let expected = match operation {
            IpcOperation::Send => self.network.caller(),
            IpcOperation::Receive => self.network.owner(),
        };
        if endpoint == self.network.endpoint && actor == expected {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)
    }
    fn deliver(
        &mut self,
        receiver: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<IPC_BYTES>,
    ) -> Result<(), Error> {
        self.authorize(receiver, endpoint, IpcOperation::Receive)?;
        if message.sender != self.network.caller() {
            return Err(Error::Auth);
        }
        self.send.as_mut().ok_or(Error::NotReady)?(&message.bytes[..message.len])
    }
}
pub fn open_network(epoch: u64) -> Result<ObjectKey, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        if let Some(network) = s.network {
            return if network.epoch == epoch {
                Ok(network.endpoint)
            } else {
                Err(Error::Busy)
            };
        }
        if epoch == 0 || epoch <= s.network_epoch {
            return Err(Error::Stale);
        }
        let owner = ObjectKey {
            id: NETWORK_SERVICE_ID,
            generation: epoch,
        };
        let endpoint = s.ipc.open(owner, false)?;
        s.network = Some(Network { epoch, endpoint });
        s.network_epoch = epoch;
        Ok(endpoint)
    })
}
pub fn close_network(epoch: u64) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let Some(network) = s.network else {
            return if epoch == s.network_epoch {
                Ok(())
            } else {
                Err(Error::Stale)
            };
        };
        if network.epoch != epoch {
            return Err(Error::Stale);
        }
        if let Some(pending) = s.network_send {
            s.ipc.cancel_send(pending.grant)?;
            s.network_send = None;
        }
        s.ipc.close(
            network.owner(),
            network.endpoint,
            &mut NetworkBackend {
                network,
                send: None,
            },
        )?;
        s.network = None;
        Ok(())
    })
}
pub fn network_write(epoch: u64, request_sequence: u64, bytes: &[u8]) -> Result<usize, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let network = s
            .network
            .filter(|network| network.epoch == epoch)
            .ok_or(Error::Stale)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let len = bytes.len().min(IPC_BYTES);
        if let Some(pending) = s.network_send
            && (pending.len != len || pending.bytes[..len] != bytes[..len])
        {
            // This prefix was never accepted or enqueued. Only a provable
            // cancellation permits a replacement; otherwise custody remains.
            s.ipc.cancel_send(pending.grant)?;
            s.network_send = None;
        }
        let mut backend = NetworkBackend {
            network,
            send: None,
        };
        if s.network_send.is_none() {
            let grant = s.ipc.reserve_send(
                network.caller(),
                network.endpoint,
                request_sequence,
                now_ns(),
                &mut backend,
            )?;
            let mut pending = NetworkSend {
                grant,
                request: request_sequence,
                bytes: [0; IPC_BYTES],
                len,
            };
            pending.bytes[..len].copy_from_slice(&bytes[..len]);
            s.network_send = Some(pending);
        }
        let pending = s.network_send.ok_or(Error::NotReady)?;
        // Same ciphertext prefix across SVC retries uses the same ticket and
        // original request identity even when the broker sequence advances.
        s.ipc.validate_confirmed_send_grant(
            pending.grant,
            network.caller(),
            network.endpoint,
            &mut backend,
        )?;
        s.ipc.send_reserved(
            pending.grant,
            pending.request,
            &pending.bytes[..pending.len],
            now_ns(),
            &mut backend,
        )?;
        s.network_send = None;
        Ok(len)
    })
}
pub fn network_key(epoch: u64) -> Result<ObjectKey, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let network = s.network.filter(|n| n.epoch == epoch).ok_or(Error::Stale)?;
        s.ipc.stats(network.endpoint)?;
        Ok(network.endpoint)
    })
}
pub fn network_pending(epoch: u64) -> Result<usize, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let network = s
            .network
            .filter(|network| network.epoch == epoch)
            .ok_or(Error::Stale)?;
        Ok(s.ipc.stats(network.endpoint)?.depth)
    })
}
/// The callback must be nonblocking and accept the entire copied message or
/// return an error without sending any prefix. Failed heads stay queued.
pub fn network_drain(
    epoch: u64,
    _now: u64,
    send: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<usize, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let network = s
            .network
            .filter(|network| network.epoch == epoch)
            .ok_or(Error::Stale)?;
        s.ipc.receive_batch(
            network.owner(),
            network.endpoint,
            now_ns(),
            &mut NetworkBackend {
                network,
                send: Some(send),
            },
        )
    })
}
