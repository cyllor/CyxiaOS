//! Real bounded IPC transport for the two read-only vector services.
use super::*;

/// Each dispatch places one copied vector into a real endpoint. The receiver
/// verifies the copied operation/object/generation before reading either service.
pub(crate) struct Transport<'a> {
    pub tasks: &'a [Task; TASKS],
    pub validate: Option<ValidateFile>,
    pub stat: Option<StatFile>,
    pub ipc: &'a mut Ipc<IPC_BYTES>,
    pub task_endpoint: ObjectKey,
    pub file_endpoint: ObjectKey,
    pub sequence: &'a mut u64,
    pub lease: &'a mut VectorLease,
}
pub(crate) struct ServiceAuthority {
    pub(crate) service: ObjectKey,
    pub(crate) endpoint: ObjectKey,
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
