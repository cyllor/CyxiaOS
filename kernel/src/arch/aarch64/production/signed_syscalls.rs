//! Object capabilities for the exact startup roster. All state and quotas
//! belong to the CPU0 foreground owner for the lifetime of this boot.

use super::{
    E_AUTH, EFAULT, NativeRole, ROLE_COUNT, copy_window::VerifiedSpan, now_ns, role_asid,
    role_loader::registered_role_abi, signed_resident::SignedCaller,
};
use cyxia_kernel_core::{
    control_plane::control_rpc_v1::Error,
    security::{
        Error as SecurityError,
        ipc_receive_v3::{DirectionalEndpoint, Endpoint, PAYLOAD_BYTES},
        syscall::{
            ITEM_BYTES, MAX_VECTOR, ObjectObservation, ReadOperation, Syscall, TASK_QUERY_BY_CAP,
            query_admission, validate_readonly_batch,
        },
        syscall_v3::{ABI_VERSION, ValidatedCall},
    },
};

const MAX_ROUTES: usize = 8;
const TASK_QUERY_CAP: u32 = 0x100;
const IPC_SEND_CAP: u32 = 0x200;
const IPC_RECV_CAP: u32 = 0x300;
const SYSTEM_GROUP: u32 = 0xffff;
const TASK_INFO_BYTES: usize = 48;
const RUNNING: u16 = 4;
const VECTOR_MAGIC: u32 = 0x4359_5656;
const VECTOR_ABI: u16 = 2;
const VECTOR_HEADER: usize = 16;
const VECTOR_RESULT: usize = 64;
const _: () = assert!(ROLE_COUNT == u8::BITS as usize);

/// Supplied only by the verified optional catalog. Bit positions are indices
/// in the fixed signed roster. `ipc_peers` indexes sender, then receiver.
#[derive(Clone, Copy)]
pub(super) struct ObjectGrant {
    pub task_query_mask: u8,
    pub ipc_peers: [u8; ROLE_COUNT],
}

struct Route {
    sender: usize,
    receiver: usize,
    queue: DirectionalEndpoint<1>,
    // This endpoint owns one dedicated completion credit. Reserve and ACK
    // mutate it in the same CPU0 turn that changes the receive slot.
    completion_held: bool,
}

impl Route {
    fn number(&self) -> u32 {
        route_number(self.sender, self.receiver)
    }
}

pub(super) struct Objects {
    epoch: u64,
    members: [NativeRole; ROLE_COUNT],
    task_query_mask: u8,
    revoked_task_query: [Option<u64>; ROLE_COUNT],
    routes: [Option<Route>; MAX_ROUTES],
}

impl Objects {
    pub(super) fn new(
        grant: Option<ObjectGrant>,
        members: &[NativeRole; ROLE_COUNT],
        boot_epoch: u64,
    ) -> Option<Self> {
        let grant = grant.unwrap_or(ObjectGrant {
            task_query_mask: 0,
            ipc_peers: [0; ROLE_COUNT],
        });
        let route_count: u32 = grant.ipc_peers.iter().map(|row| row.count_ones()).sum();
        if route_count as usize > MAX_ROUTES
            || (route_count != 0 || grant.task_query_mask != 0)
                && (boot_epoch == 0 || boot_epoch > u64::from(u32::MAX))
        {
            return None;
        }

        let mut routes = [const { None }; MAX_ROUTES];
        let mut slot = 0;
        for (sender, peers) in grant.ipc_peers.into_iter().enumerate() {
            if peers & role_bit(sender) != 0 {
                return None;
            }
            for receiver in 0..ROLE_COUNT {
                if peers & role_bit(receiver) == 0 {
                    continue;
                }
                let queue = DirectionalEndpoint::new(
                    Endpoint {
                        id: u64::from(IPC_SEND_CAP + route_number(sender, receiver)),
                        generation: boot_epoch,
                        receiver: members[receiver].actor,
                    },
                    members[sender].actor,
                )
                .ok()?;
                routes[slot] = Some(Route {
                    sender,
                    receiver,
                    queue,
                    completion_held: false,
                });
                slot += 1;
            }
        }

        Some(Self {
            epoch: boot_epoch,
            members: *members,
            task_query_mask: grant.task_query_mask,
            revoked_task_query: [None; ROLE_COUNT],
            routes,
        })
    }

    /// Resolve the holder's selector namespace before EL1 examines user
    /// buffers. Full capability and object generations are checked during
    /// dispatch before any copy or resource mutation.
    pub(super) fn permits(&self, index: usize, operation: Syscall, first: u64) -> bool {
        index < ROLE_COUNT
            && match operation {
                Syscall::QueryTask | Syscall::RevokeCap => self.has_task_cap(index, first),
                Syscall::SubmitReadVector => self.task_query_mask & role_bit(index) != 0,
                Syscall::IpcSend => self.route_slot(index, first, true).is_some(),
                Syscall::IpcRecv => self.route_slot(index, first, false).is_some(),
                _ => false,
            }
    }

    pub(super) fn dispatch(&mut self, caller: &SignedCaller, call: ValidatedCall, now: u64) -> i64 {
        let index = caller.index;
        if self.members.get(index) != Some(&caller.member)
            || !caller.registered()
            || !self.permits(index, call.operation, call.args[0])
        {
            return E_AUTH;
        }

        let result = match call.operation {
            Syscall::QueryTask => self.query(caller, call.args),
            Syscall::RevokeCap => self.revoke(index, call.args),
            Syscall::IpcSend => self.send(caller, call.args),
            Syscall::IpcRecv => self.receive(caller, call.args, now),
            Syscall::SubmitReadVector => self.vector(caller, call.args, now),
            _ => Err(E_AUTH),
        };
        result.unwrap_or_else(|errno| errno)
    }

    /// Retain queued messages and receive receipts in the closed endpoint.
    /// The lifecycle roster never replaces its old roots during this boot.
    pub(super) fn retire(&mut self, index: usize) {
        for route in self.routes.iter_mut().flatten() {
            if route.sender == index || route.receiver == index {
                route.queue.fence();
            }
        }
    }

    fn has_task_cap(&self, index: usize, capability: u64) -> bool {
        self.task_query_mask & role_bit(index) != 0 && (capability as u32) == task_slot(index)
    }

    fn check_task_cap(&self, index: usize, capability: u64) -> Result<(), i64> {
        if !self.has_task_cap(index, capability) {
            return Err(E_AUTH);
        }
        self.check_epoch(capability)
    }

    fn check_epoch(&self, capability: u64) -> Result<(), i64> {
        if (capability >> 32) != self.epoch {
            return Err(Error::Stale as i64);
        }
        Ok(())
    }

    fn task_info(
        &self,
        index: usize,
        member: NativeRole,
        capability: u64,
        generation: u64,
    ) -> Result<[u8; TASK_INFO_BYTES], i64> {
        self.check_task_cap(index, capability)?;
        if self.revoked_task_query[index].is_some() {
            return Err(Error::Stale as i64);
        }
        let actor = self.members[index].actor;
        query_admission(
            member.actor.id,
            member.actor.generation,
            generation,
            ObjectObservation::Present {
                holder: actor.id,
                holder_generation: actor.generation,
                object_generation: actor.generation,
            },
        )
        .map_err(|error| match error {
            SecurityError::Stale => Error::Stale as i64,
            _ => E_AUTH,
        })?;
        let mut row = [0; TASK_INFO_BYTES];
        row[..8].copy_from_slice(&capability.to_le_bytes());
        row[8..16].copy_from_slice(&actor.generation.to_le_bytes());
        row[16..20].copy_from_slice(&SYSTEM_GROUP.to_le_bytes());
        row[20..22].copy_from_slice(&RUNNING.to_le_bytes());
        // The task is the current caller on CPU0. It has no spawn request.
        Ok(row)
    }

    fn query(&self, caller: &SignedCaller, args: [u64; 6]) -> Result<i64, i64> {
        let row = self.task_info(caller.index, caller.member, args[0], args[1])?;
        let out = VerifiedSpan::verify_signed(caller, args[2], args[3] as usize, true)?;
        finish_output(&out, &row, 0)
    }

    fn revoke(&mut self, index: usize, args: [u64; 6]) -> Result<i64, i64> {
        self.check_task_cap(index, args[0])?;
        if args[1] != self.epoch {
            return Err(Error::Stale as i64);
        }
        let receipt = &mut self.revoked_task_query[index];
        match *receipt {
            Some(request) if request == args[2] => Ok(0),
            Some(_) => Err(Error::Stale as i64),
            None => {
                // The catalog grants a leaf. Nothing can derive from it;
                // this update is both the deny gate and the revoke receipt.
                *receipt = Some(args[2]);
                Ok(0)
            }
        }
    }

    fn route_slot(&self, index: usize, capability: u64, send: bool) -> Option<usize> {
        let base = if send { IPC_SEND_CAP } else { IPC_RECV_CAP };
        self.routes.iter().position(|route| {
            route.as_ref().is_some_and(|route| {
                (if send { route.sender } else { route.receiver }) == index
                    && (capability as u32) == base + route.number()
            })
        })
    }

    fn route(&mut self, index: usize, capability: u64, send: bool) -> Result<&mut Route, i64> {
        let slot = self.route_slot(index, capability, send).ok_or(E_AUTH)?;
        self.check_epoch(capability)?;
        let route = self.routes[slot].as_mut().ok_or(E_AUTH)?;
        let peer = if send { route.receiver } else { route.sender };
        let member = self.members[peer];
        let root = member.ttbr0_root | (u64::from(role_asid(peer)) << 48);
        if registered_role_abi(peer, member, root) != Some(ABI_VERSION) {
            route.queue.fence();
            return Err(Error::Stale as i64);
        }
        Ok(route)
    }

    fn send(&mut self, caller: &SignedCaller, args: [u64; 6]) -> Result<i64, i64> {
        let route = self.route(caller.index, args[0], true)?;
        if args[5] != 1 {
            return Err(Error::Unsupported as i64);
        }
        let mut buffer = [0; PAYLOAD_BYTES];
        let count = args[2] as usize;
        let payload = &mut buffer[..count];
        if count != 0 {
            VerifiedSpan::verify_signed(caller, args[1], count, false)?.copy_in(payload)?;
        }
        route
            .queue
            .send(
                caller.member.actor,
                route.queue.endpoint().generation,
                args[3],
                payload,
            )
            .map(|()| 0)
            .map_err(|error| error as i64)
    }

    fn receive(&mut self, caller: &SignedCaller, args: [u64; 6], now: u64) -> Result<i64, i64> {
        let route = self.route(caller.index, args[0], false)?;
        let generation = route.queue.endpoint().generation;
        let credit = &mut route.completion_held;
        if args[4] == 2 {
            return route
                .queue
                .ack(caller.member.actor, generation, args[5], || {
                    if !*credit {
                        return Err(Error::Conflict);
                    }
                    *credit = false;
                    Ok(())
                })
                .map(|()| 0)
                .map_err(|error| error as i64);
        }
        if args[4] != 1 {
            return Err(Error::Unsupported as i64);
        }

        let capacity = args[2] as usize;
        let out = VerifiedSpan::verify_signed(caller, args[1], capacity, true)?;
        let ticket = route
            .queue
            .reserve_receive(
                caller.member.actor,
                generation,
                args[5],
                capacity,
                true,
                0,
                now,
                || {
                    if *credit {
                        return Err(Error::Capacity);
                    }
                    *credit = true;
                    Ok(())
                },
            )
            .map_err(|error| error as i64)?;
        let exact = out
            .copy_out_and_check(ticket.message().bytes())
            .unwrap_or(false);
        route
            .queue
            .finish_copy(ticket, exact)
            .map(|len| len as i64)
            .map_err(|error| error as i64)
    }

    fn vector(&self, caller: &SignedCaller, args: [u64; 6], now: u64) -> Result<i64, i64> {
        let mut input = [0; VECTOR_HEADER + MAX_VECTOR * ITEM_BYTES];
        let input = &mut input[..args[1] as usize];
        let source = VerifiedSpan::verify_signed(caller, args[0], input.len(), false)?;
        let out = VerifiedSpan::verify_signed(caller, args[2], args[3] as usize, true)?;
        source.copy_in(input)?;

        let count = (input.len() - VECTOR_HEADER) / ITEM_BYTES;
        if input[..VECTOR_HEADER] != vector_header(count, input.len()) {
            return Err(Error::Format as i64);
        }
        validate_readonly_batch(count, |at| {
            let item = vector_item(input, at);
            (item.op, item.flags, item.tag)
        })
        .map_err(|_| Error::Format as i64)?;

        let until = args[4];
        let mut output = [0; VECTOR_HEADER + MAX_VECTOR * VECTOR_RESULT];
        let length = VECTOR_HEADER + count * VECTOR_RESULT;
        output[..VECTOR_HEADER].copy_from_slice(&vector_header(count, length));
        for (at, row) in output[VECTOR_HEADER..length]
            .chunks_exact_mut(VECTOR_RESULT)
            .enumerate()
        {
            let item = vector_item(input, at);
            row[..8].copy_from_slice(&item.tag.to_le_bytes());
            let result = match item.op {
                TASK_QUERY_BY_CAP => {
                    let task = self.task_info(
                        caller.index,
                        caller.member,
                        item.capability,
                        item.generation,
                    );
                    task.and_then(|value| {
                        if now >= until || now_ns() >= until {
                            Err(Error::Timeout as i64)
                        } else {
                            Ok(value)
                        }
                    })
                }
                _ => Err(E_AUTH), // No file capability in the signed object grant.
            };
            match result {
                Ok(value) => {
                    row[12..14].copy_from_slice(&TASK_QUERY_BY_CAP.to_le_bytes());
                    row[16..].copy_from_slice(&value);
                }
                Err(errno) => row[8..12].copy_from_slice(&(errno as i32).to_le_bytes()),
            }
        }
        finish_output(&out, &output[..length], 0)
    }
}

fn role_bit(index: usize) -> u8 {
    1 << index
}

fn task_slot(index: usize) -> u32 {
    TASK_QUERY_CAP + index as u32
}

fn route_number(sender: usize, receiver: usize) -> u32 {
    (sender * ROLE_COUNT + receiver) as u32
}

fn vector_header(count: usize, length: usize) -> [u8; VECTOR_HEADER] {
    let mut header = [0; VECTOR_HEADER];
    header[..4].copy_from_slice(&VECTOR_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&VECTOR_ABI.to_le_bytes());
    header[6..8].copy_from_slice(&(VECTOR_HEADER as u16).to_le_bytes());
    header[8..10].copy_from_slice(&(count as u16).to_le_bytes());
    header[12..16].copy_from_slice(&(length as u32).to_le_bytes());
    header
}

fn vector_item(vector: &[u8], index: usize) -> ReadOperation {
    let offset = VECTOR_HEADER + index * ITEM_BYTES;
    let item = &vector[offset..offset + ITEM_BYTES];
    ReadOperation {
        op: u16::from_le_bytes(item[..2].try_into().unwrap()),
        flags: u16::from_le_bytes(item[2..4].try_into().unwrap()),
        capability: u64::from_le_bytes(item[4..12].try_into().unwrap()),
        generation: u64::from_le_bytes(item[12..20].try_into().unwrap()),
        tag: u64::from_le_bytes(item[20..28].try_into().unwrap()),
    }
}

fn finish_output(out: &VerifiedSpan<'_>, bytes: &[u8], result: i64) -> Result<i64, i64> {
    if out.copy_out_and_check(bytes)? {
        Ok(result)
    } else {
        Err(EFAULT)
    }
}
