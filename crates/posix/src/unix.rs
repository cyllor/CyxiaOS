//! Bounded pathname/abstract AF_UNIX/SOCK_STREAM mechanism, with no host OS or allocator.
//!
//! The kernel serializes calls, authenticates owners, authorizes pathname access
//! and obtains AI admission before allocating endpoints, bindings or connections.
//! This module only enforces capacities and byte-stream semantics. Paths are
//! already resolved canonical absolute byte strings; this namespace is not a VFS.
//! No descriptor passing, dup or blocking waits are
//! implemented. Check/register/wake for poll must be serialized by the kernel.
use crate::{
    Errno,
    epoll::{HUP, IN, OUT, RDHUP},
};

#[cfg(not(feature = "large-memory"))]
pub const ENDPOINTS: usize = 16;
#[cfg(feature = "large-memory")]
pub const ENDPOINTS: usize = 64;
#[cfg(not(feature = "large-memory"))]
pub const CONNECTIONS: usize = 8;
#[cfg(feature = "large-memory")]
pub const CONNECTIONS: usize = 32;
pub const BUFFER_BYTES: usize = 4096;
pub const PATH_BYTES: usize = 108;
pub const BACKLOG_MAX: usize = 8;
/// Linux listen(2) consumes an int, then caps its unsigned representation.
/// Rust's UnixListener uses -1 to request the platform maximum. The native
/// mechanism stays bounded; this adapter never grows its pending queue.
pub fn linux_listen_backlog(raw: u64) -> usize {
    (raw as u32 as usize).clamp(1, BACKLOG_MAX)
}
const GENERATION_MAX: u64 = u64::MAX >> 8;

/// Opaque endpoint identity, not a Unix file descriptor. The low byte is a slot;
/// upper bits are a nonzero generation. Raw values are always revalidated with
/// the authenticated owner. A slot retires rather than wrapping its generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(u64);
impl Handle {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    fn slot(self) -> usize {
        (self.0 & 255) as usize
    }
    fn generation(self) -> u64 {
        self.0 >> 8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    pub free_endpoints: usize,
    pub free_connections: usize,
    pub free_bindings: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    /// Peer closed its write half (including close), independent of POLLHUP.
    pub read_hangup: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pathname {
    bytes: [u8; PATH_BYTES],
    len: usize,
}
impl Pathname {
    fn parse(bytes: &[u8]) -> Result<Self, Errno> {
        if bytes.is_empty() {
            return Err(Errno::Noent);
        }
        if bytes.len() > PATH_BYTES || (bytes[0] != 0 && bytes.len() == PATH_BYTES) {
            return Err(Errno::Nametoolong);
        }
        if bytes[0] != 0 && (bytes[0] != b'/' || bytes.contains(&0)) {
            return Err(Errno::Inval);
        }
        for component in bytes[1..]
            .split(|byte| *byte == b'/')
            .filter(|_| bytes[0] != 0)
        {
            if component.is_empty() || component == b"." || component == b".." {
                return Err(Errno::Inval);
            }
        }
        let mut path = Self {
            bytes: [0; PATH_BYTES],
            len: bytes.len(),
        };
        path.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(path)
    }
}

#[derive(Clone, Copy)]
struct Binding {
    path: Pathname,
    target: Option<Handle>,
}

#[derive(Clone, Copy)]
struct Pending {
    handles: [Option<Handle>; BACKLOG_MAX],
    len: usize,
    limit: usize,
}
impl Pending {
    const fn new(limit: usize) -> Self {
        Self {
            handles: [None; BACKLOG_MAX],
            len: 0,
            limit,
        }
    }
    fn push(&mut self, handle: Handle) -> Result<(), Errno> {
        if self.len >= self.limit {
            return Err(Errno::Again);
        }
        self.handles[self.len] = Some(handle);
        self.len += 1;
        Ok(())
    }
    fn pop(&mut self) -> Result<Handle, Errno> {
        let handle = self.handles[0].ok_or(Errno::Again)?;
        self.handles.copy_within(1..self.len, 0);
        self.len -= 1;
        self.handles[self.len] = None;
        Ok(handle)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Unconnected,
    Listening(Pending),
    Connected {
        connection: usize,
        side: usize,
    },
    /// Reserved by connect, owned by the listener, invisible until accept.
    PendingAccept {
        connection: usize,
        side: usize,
    },
}
#[derive(Clone, Copy)]
struct Endpoint {
    owner: u32,
    actor: u32,
    bound: bool,
    name: Option<Pathname>,
    kind: Kind,
}
struct Slot {
    generation: u64,
    endpoint: Option<Endpoint>,
    wakes: u32,
}
impl Slot {
    const fn new() -> Self {
        Self {
            generation: 0,
            endpoint: None,
            wakes: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct Marker {
    ticket: crate::ancillary::Ticket,
    start: u64,
    end: u64,
}
struct Stream {
    bytes: [u8; BUFFER_BYTES],
    head: usize,
    len: usize,
    sequence: u64,
    markers: [Option<Marker>; crate::ancillary::MESSAGES],
    marker_count: usize,
}
impl Stream {
    const fn new() -> Self {
        Self {
            bytes: [0; BUFFER_BYTES],
            head: 0,
            len: 0,
            sequence: 0,
            markers: [None; crate::ancillary::MESSAGES],
            marker_count: 0,
        }
    }
    fn read(
        &mut self,
        out: &mut [u8],
        peer_open: bool,
    ) -> Result<(usize, Option<crate::ancillary::Ticket>), Errno> {
        let mut count = out.len().min(self.len);
        if count == 0 && !out.is_empty() && peer_open {
            return Err(Errno::Again);
        }
        let mut ticket = None;
        if count != 0
            && let Some(marker) = self.markers[0]
            && self.sequence + count as u64 > marker.start
        {
            count = count.min((marker.end - self.sequence) as usize);
            ticket = Some(marker.ticket);
        }
        for (index, byte) in out[..count].iter_mut().enumerate() {
            let slot = (self.head + index) % BUFFER_BYTES;
            *byte = self.bytes[slot];
            self.bytes[slot] = 0;
        }
        self.head = (self.head + count) % BUFFER_BYTES;
        self.len -= count;
        self.sequence += count as u64;
        if ticket.is_some() {
            self.markers.copy_within(1..self.marker_count, 0);
            self.marker_count -= 1;
            self.markers[self.marker_count] = None;
        }
        if self.len == 0 {
            self.sequence = 0;
        }
        Ok((count, ticket))
    }
    fn write(
        &mut self,
        bytes: &[u8],
        ticket: Option<crate::ancillary::Ticket>,
    ) -> Result<usize, Errno> {
        if ticket.is_some() && bytes.is_empty() {
            return Err(Errno::Inval);
        }
        if ticket.is_some() && self.marker_count == self.markers.len() {
            return Err(Errno::Nobufs);
        }
        let count = bytes.len().min(BUFFER_BYTES - self.len);
        if count == 0 && !bytes.is_empty() {
            return Err(Errno::Again);
        }
        let start = self
            .sequence
            .checked_add(self.len as u64)
            .ok_or(Errno::Overflow)?;
        let end = start.checked_add(count as u64).ok_or(Errno::Overflow)?;
        for (index, byte) in bytes[..count].iter().enumerate() {
            self.bytes[(self.head + self.len + index) % BUFFER_BYTES] = *byte;
        }
        self.len += count;
        if let Some(ticket) = ticket {
            self.markers[self.marker_count] = Some(Marker { ticket, start, end });
            self.marker_count += 1;
        }
        Ok(count)
    }
    fn discard(&mut self, sink: &mut impl FnMut(crate::ancillary::Ticket)) {
        for marker in self.markers[..self.marker_count].iter().flatten() {
            sink(marker.ticket);
        }
        *self = Self::new();
    }
}
struct Connection {
    names: [Option<Pathname>; 2],
    owners: [u32; 2],
    open: [bool; 2],
    read_shutdown: [bool; 2],
    write_shutdown: [bool; 2],
    incoming: [Stream; 2],
}
impl Connection {
    const fn new(names: [Option<Pathname>; 2], owners: [u32; 2]) -> Self {
        Self {
            names,
            owners,
            open: [true; 2],
            read_shutdown: [false; 2],
            write_shutdown: [false; 2],
            incoming: [const { Stream::new() }; 2],
        }
    }
}

pub struct UnixSockets {
    endpoints: [Slot; ENDPOINTS],
    connections: [Option<Connection>; CONNECTIONS],
    bindings: [Option<Binding>; ENDPOINTS],
}
impl Default for UnixSockets {
    fn default() -> Self {
        Self::new()
    }
}
impl UnixSockets {
    pub const fn new() -> Self {
        Self {
            endpoints: [const { Slot::new() }; ENDPOINTS],
            connections: [const { None }; CONNECTIONS],
            bindings: [None; ENDPOINTS],
        }
    }
    pub fn capacity(&self) -> Capacity {
        Capacity {
            free_endpoints: self
                .endpoints
                .iter()
                .filter(|s| s.endpoint.is_none() && s.generation < GENERATION_MAX)
                .count(),
            free_connections: self.connections.iter().filter(|c| c.is_none()).count(),
            free_bindings: self.bindings.iter().filter(|b| b.is_none()).count(),
        }
    }
    fn free_endpoint(&self, excluded: Option<usize>) -> Result<usize, Errno> {
        self.endpoints
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                (Some(index) != excluded
                    && slot.endpoint.is_none()
                    && slot.generation < GENERATION_MAX)
                    .then_some(index)
            })
            .ok_or(Errno::Nospc)
    }
    fn free_connection(&self) -> Result<usize, Errno> {
        self.connections
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Nospc)
    }
    fn fresh_handle(&self, slot: usize) -> Result<Handle, Errno> {
        let generation = self.endpoints[slot]
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= GENERATION_MAX)
            .ok_or(Errno::Overflow)?;
        Ok(Handle((generation << 8) | slot as u64))
    }
    fn install(&mut self, handle: Handle, endpoint: Endpoint) {
        let slot = &mut self.endpoints[handle.slot()];
        slot.generation = handle.generation();
        slot.endpoint = Some(endpoint);
        slot.wakes = 0;
    }
    fn live(&self, handle: Handle) -> Result<Endpoint, Errno> {
        let slot = self.endpoints.get(handle.slot()).ok_or(Errno::Badf)?;
        if handle.generation() == 0 || slot.generation != handle.generation() {
            return Err(Errno::Badf);
        }
        slot.endpoint.ok_or(Errno::Badf)
    }
    fn owned(&self, owner: u32, handle: Handle) -> Result<Endpoint, Errno> {
        let endpoint = self.live(handle)?;
        if owner == 0
            || endpoint.owner != owner
            || matches!(endpoint.kind, Kind::PendingAccept { .. })
        {
            return Err(Errno::Badf);
        }
        Ok(endpoint)
    }
    fn stream(&self, owner: u32, handle: Handle) -> Result<(usize, usize), Errno> {
        match self.owned(owner, handle)?.kind {
            Kind::Connected { connection, side } => Ok((connection, side)),
            _ => Err(Errno::Notconn),
        }
    }
    /// The supervisor observes all weak watches before clearing this bounded,
    /// generation-owned notification mask. Poll alone never generates a wake.
    pub fn wake_mask(&self, owner: u32, handle: Handle) -> Result<u32, Errno> {
        self.owned(owner, handle)?;
        Ok(self.endpoints[handle.slot()].wakes)
    }
    pub fn clear_wakes(&mut self) {
        for slot in &mut self.endpoints {
            slot.wakes = 0;
        }
    }
    fn wake_connection(&mut self, connection: usize, side: usize, mask: u32) {
        for slot in &mut self.endpoints {
            if slot.endpoint.is_some_and(|endpoint| {
                matches!(
                    endpoint.kind,
                    Kind::Connected { connection: c, side: s }
                        | Kind::PendingAccept { connection: c, side: s }
                        if c == connection && s == side
                )
            }) {
                slot.wakes |= mask;
            }
        }
    }

    /// Allocate one unbound endpoint after the kernel's admission decision.
    pub fn socket(&mut self, owner: u32) -> Result<Handle, Errno> {
        if owner == 0 {
            return Err(Errno::Inval);
        }
        let slot = self.free_endpoint(None)?;
        let handle = self.fresh_handle(slot)?;
        self.install(
            handle,
            Endpoint {
                owner,
                actor: owner,
                bound: false,
                name: None,
                kind: Kind::Unconnected,
            },
        );
        Ok(handle)
    }

    /// Allocate two same-owner endpoints and a connection, or change nothing.
    pub fn socketpair(&mut self, owner: u32) -> Result<[Handle; 2], Errno> {
        if owner == 0 {
            return Err(Errno::Inval);
        }
        let a = self.free_endpoint(None)?;
        let b = self.free_endpoint(Some(a))?;
        let connection = self.free_connection()?;
        let handles = [self.fresh_handle(a)?, self.fresh_handle(b)?];
        self.connections[connection] = Some(Connection::new([None; 2], [owner; 2]));
        for (side, handle) in handles.iter().enumerate() {
            self.install(
                *handle,
                Endpoint {
                    owner,
                    actor: owner,
                    bound: false,
                    name: None,
                    kind: Kind::Connected { connection, side },
                },
            );
        }
        Ok(handles)
    }

    pub fn bind(&mut self, owner: u32, handle: Handle, path: &[u8]) -> Result<(), Errno> {
        let mut endpoint = self.owned(owner, handle)?;
        if endpoint.bound || !matches!(endpoint.kind, Kind::Unconnected) {
            return Err(Errno::Inval);
        }
        let path = Pathname::parse(path)?;
        if self
            .bindings
            .iter()
            .flatten()
            .any(|binding| binding.path == path)
        {
            return Err(Errno::Addrinuse);
        }
        let slot = self
            .bindings
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Nospc)?;
        self.bindings[slot] = Some(Binding {
            path,
            target: Some(handle),
        });
        endpoint.bound = true;
        endpoint.name = Some(path);
        self.endpoints[handle.slot()].endpoint = Some(endpoint);
        Ok(())
    }

    /// Backlog is explicit and bounded; shrinking below queued connections fails
    /// without dropping clients. A pathname bind is required in this first API.
    pub fn listen(&mut self, owner: u32, handle: Handle, backlog: usize) -> Result<(), Errno> {
        self.listen_for(owner, handle, backlog, owner)
    }
    /// Capability owner authenticates the OFD; actor is the actual calling PID.
    pub fn listen_for(
        &mut self,
        owner: u32,
        handle: Handle,
        backlog: usize,
        actor: u32,
    ) -> Result<(), Errno> {
        if actor == 0 {
            return Err(Errno::Inval);
        }
        let mut endpoint = self.owned(owner, handle)?;
        if !endpoint.bound || !(1..=BACKLOG_MAX).contains(&backlog) {
            return Err(Errno::Inval);
        }
        endpoint.kind = match endpoint.kind {
            Kind::Unconnected => Kind::Listening(Pending::new(backlog)),
            Kind::Listening(mut pending) => {
                if pending.len > backlog {
                    return Err(Errno::Busy);
                }
                pending.limit = backlog;
                Kind::Listening(pending)
            }
            _ => return Err(Errno::Inval),
        };
        endpoint.actor = actor;
        self.endpoints[handle.slot()].endpoint = Some(endpoint);
        Ok(())
    }

    /// Complete nonblocking connect by reserving the peer endpoint and both
    /// rings before publication. accept never allocates and cannot fail for space.
    /// Full backlog returns EAGAIN, leaving the original client unconnected.
    pub fn connect(&mut self, owner: u32, handle: Handle, path: &[u8]) -> Result<(), Errno> {
        self.connect_for(owner, handle, path, owner)
    }
    pub fn connect_for(
        &mut self,
        owner: u32,
        handle: Handle,
        path: &[u8],
        actor: u32,
    ) -> Result<(), Errno> {
        if actor == 0 {
            return Err(Errno::Inval);
        }
        let mut client = self.owned(owner, handle)?;
        match client.kind {
            Kind::Unconnected => {}
            Kind::Connected { .. } => return Err(Errno::Isconn),
            _ => return Err(Errno::Inval),
        }
        let path = Pathname::parse(path)?;
        let binding = self
            .bindings
            .iter()
            .flatten()
            .find(|binding| binding.path == path)
            .ok_or(Errno::Noent)?;
        let listener_handle = binding.target.ok_or(Errno::Connrefused)?;
        let mut listener = self.live(listener_handle).map_err(|_| Errno::Connrefused)?;
        let Kind::Listening(mut pending) = listener.kind else {
            return Err(Errno::Connrefused);
        };
        if pending.len >= pending.limit {
            return Err(Errno::Again);
        }
        let server_slot = self.free_endpoint(None)?;
        let server_handle = self.fresh_handle(server_slot)?;
        let connection = self.free_connection()?;
        pending.push(server_handle)?;
        client.kind = Kind::Connected {
            connection,
            side: 0,
        };
        listener.kind = Kind::Listening(pending);
        // All validation/admission-capacity failures precede this commit.
        self.connections[connection] = Some(Connection::new(
            [client.name, listener.name],
            [actor, listener.actor],
        ));
        self.install(
            server_handle,
            Endpoint {
                owner: listener.owner,
                actor: listener.actor,
                bound: false,
                name: listener.name,
                kind: Kind::PendingAccept {
                    connection,
                    side: 1,
                },
            },
        );
        self.endpoints[handle.slot()].endpoint = Some(client);
        self.endpoints[listener_handle.slot()].endpoint = Some(listener);
        self.endpoints[handle.slot()].wakes |= OUT;
        self.endpoints[listener_handle.slot()].wakes |= IN;
        Ok(())
    }

    pub fn accept(&mut self, owner: u32, handle: Handle) -> Result<Handle, Errno> {
        self.accept_for(owner, handle, owner)
    }
    pub fn accept_for(
        &mut self,
        owner: u32,
        handle: Handle,
        new_owner: u32,
    ) -> Result<Handle, Errno> {
        if new_owner == 0 {
            return Err(Errno::Inval);
        }
        let mut listener = self.owned(owner, handle)?;
        let Kind::Listening(mut pending) = listener.kind else {
            return Err(Errno::Inval);
        };
        let accepted = pending.pop()?;
        let mut endpoint = self.live(accepted)?;
        let Kind::PendingAccept { connection, side } = endpoint.kind else {
            return Err(Errno::Badf);
        };
        endpoint.kind = Kind::Connected { connection, side };
        endpoint.owner = new_owner;
        listener.kind = Kind::Listening(pending);
        self.endpoints[accepted.slot()].endpoint = Some(endpoint);
        self.endpoints[handle.slot()].endpoint = Some(listener);
        // Bytes may already have arrived while the endpoint was pending.
        // Delivery still intersects these hints with the current poll result.
        self.endpoints[accepted.slot()].wakes |= IN | OUT;
        Ok(accepted)
    }

    /// Return the actual Linux sockaddr_un wire address, including family.
    /// Connected names are snapshots and survive unlink/peer closure.
    pub fn socket_name(
        &self,
        owner: u32,
        handle: Handle,
        peer: bool,
    ) -> Result<([u8; 110], usize), Errno> {
        let endpoint = self.owned(owner, handle)?;
        let name = if peer {
            let (slot, side) = self.stream(owner, handle)?;
            self.connections[slot].as_ref().ok_or(Errno::Badf)?.names[side ^ 1]
        } else {
            endpoint.name
        };
        let mut wire = [0u8; 110];
        wire[0] = 1; // AF_UNIX, little endian.
        let len = if let Some(name) = name {
            wire[2..2 + name.len].copy_from_slice(&name.bytes[..name.len]);
            2 + name.len + usize::from(name.bytes[0] != 0)
        } else {
            2
        };
        Ok((wire, len))
    }
    pub fn peer_owner(&self, owner: u32, handle: Handle) -> Result<u32, Errno> {
        let (slot, side) = self.stream(owner, handle)?;
        Ok(self.connections[slot].as_ref().ok_or(Errno::Badf)?.owners[side ^ 1])
    }

    /// Legacy byte-only API refuses to discard attached references. Kernel
    /// callers use shutdown_with so every detached ticket has a release sink.
    pub fn shutdown(&mut self, owner: u32, handle: Handle, how: u64) -> Result<(), Errno> {
        let (slot, side) = self.stream(owner, handle)?;
        if self.connections[slot].as_ref().ok_or(Errno::Badf)?.incoming[side].marker_count != 0 {
            return Err(Errno::Busy);
        }
        self.shutdown_with(owner, handle, how, &mut |_| {})
    }
    pub fn shutdown_with(
        &mut self,
        owner: u32,
        handle: Handle,
        how: u64,
        sink: &mut impl FnMut(crate::ancillary::Ticket),
    ) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::Inval);
        }
        let (slot, side) = self.stream(owner, handle)?;
        let connection = self.connections[slot].as_mut().ok_or(Errno::Badf)?;
        let read_changed = how != 1 && !connection.read_shutdown[side];
        let write_changed = how != 0 && !connection.write_shutdown[side];
        if how != 1 {
            connection.read_shutdown[side] = true;
            connection.incoming[side].discard(sink);
        }
        if how != 0 {
            connection.write_shutdown[side] = true;
        }
        let hung_up = connection.read_shutdown[side] && connection.write_shutdown[side];
        if read_changed {
            self.wake_connection(slot, side, IN | RDHUP);
            self.wake_connection(slot, side ^ 1, OUT);
        }
        if write_changed {
            self.wake_connection(slot, side, OUT);
            self.wake_connection(slot, side ^ 1, IN | RDHUP);
        }
        if (read_changed || write_changed) && hung_up {
            self.wake_connection(slot, side, HUP);
        }
        Ok(())
    }
    pub fn read(&mut self, owner: u32, handle: Handle, out: &mut [u8]) -> Result<usize, Errno> {
        let (slot, side) = self.stream(owner, handle)?;
        if self.connections[slot].as_ref().ok_or(Errno::Badf)?.incoming[side].marker_count != 0 {
            return Err(Errno::Nosys);
        }
        self.read_message(owner, handle, out)
            .map(|(count, _)| count)
    }
    pub fn read_message(
        &mut self,
        owner: u32,
        handle: Handle,
        out: &mut [u8],
    ) -> Result<(usize, Option<crate::ancillary::Ticket>), Errno> {
        let (slot, side) = self.stream(owner, handle)?;
        let connection = self.connections[slot].as_mut().ok_or(Errno::Badf)?;
        if connection.read_shutdown[side] {
            return Ok((0, None));
        }
        let result = connection.incoming[side].read(
            out,
            connection.open[side ^ 1] && !connection.write_shutdown[side ^ 1],
        )?;
        if result.0 != 0 {
            self.wake_connection(slot, side ^ 1, OUT);
        }
        Ok(result)
    }
    pub fn write(&mut self, owner: u32, handle: Handle, bytes: &[u8]) -> Result<usize, Errno> {
        self.write_message(owner, handle, bytes, None)
    }
    /// A positive short write attaches exactly one ticket to the committed byte
    /// interval. Errors and zero byte operations do not acquire ticket ownership.
    pub fn write_message(
        &mut self,
        owner: u32,
        handle: Handle,
        bytes: &[u8],
        ticket: Option<crate::ancillary::Ticket>,
    ) -> Result<usize, Errno> {
        let (slot, side) = self.stream(owner, handle)?;
        let connection = self.connections[slot].as_mut().ok_or(Errno::Badf)?;
        if bytes.is_empty() {
            return if ticket.is_some() {
                Err(Errno::Inval)
            } else {
                Ok(0)
            };
        }
        if !connection.open[side ^ 1]
            || connection.write_shutdown[side]
            || connection.read_shutdown[side ^ 1]
        {
            return Err(Errno::Pipe);
        }
        let count = connection.incoming[side ^ 1].write(bytes, ticket)?;
        if count != 0 {
            self.wake_connection(slot, side ^ 1, IN);
        }
        Ok(count)
    }
    /// HUP is also readable/writable: EOF or EPIPE must be observed immediately
    /// rather than sleeping. A listener is readable when accept can proceed.
    pub fn poll(&self, owner: u32, handle: Handle) -> Result<Ready, Errno> {
        match self.owned(owner, handle)?.kind {
            Kind::Listening(pending) => Ok(Ready {
                readable: pending.len > 0,
                ..Ready::default()
            }),
            Kind::Connected { connection, side } => {
                let connection = self.connections[connection].as_ref().ok_or(Errno::Badf)?;
                let hangup = !connection.open[side ^ 1]
                    || (connection.read_shutdown[side] && connection.write_shutdown[side]);
                Ok(Ready {
                    readable: hangup
                        || connection.read_shutdown[side]
                        || connection.write_shutdown[side ^ 1]
                        || connection.incoming[side].len > 0,
                    writable: hangup
                        || connection.write_shutdown[side]
                        || connection.read_shutdown[side ^ 1]
                        || connection.incoming[side ^ 1].len < BUFFER_BYTES,
                    hangup,
                    read_hangup: !connection.open[side ^ 1]
                        || connection.write_shutdown[side ^ 1]
                        || connection.read_shutdown[side],
                })
            }
            _ => Err(Errno::Notconn),
        }
    }

    /// Remove only the directory entry; open sockets, pending accepts and live
    /// streams remain valid. Kernel pathname permissions must be checked first.
    pub fn unlink(&mut self, path: &[u8]) -> Result<(), Errno> {
        let path = Pathname::parse(path)?;
        if path.bytes[0] == 0 {
            return Err(Errno::Noent);
        }
        let slot = self
            .bindings
            .iter()
            .position(|binding| binding.is_some_and(|b| b.path == path))
            .ok_or(Errno::Noent)?;
        self.bindings[slot] = None;
        Ok(())
    }

    /// Closing a listener cancels only its unaccepted peers. Pathname entries
    /// persist until unlink; future connects to a closed binding are refused.
    pub fn close(&mut self, owner: u32, handle: Handle) -> Result<(), Errno> {
        self.owned(owner, handle)?;
        if self.has_rights() {
            return Err(Errno::Busy);
        }
        self.close_with(owner, handle, &mut |_| {})
    }
    pub fn close_with(
        &mut self,
        owner: u32,
        handle: Handle,
        sink: &mut impl FnMut(crate::ancillary::Ticket),
    ) -> Result<(), Errno> {
        self.owned(owner, handle)?;
        self.close_slot(handle.slot(), sink);
        Ok(())
    }
    fn has_rights(&self) -> bool {
        self.connections
            .iter()
            .flatten()
            .any(|c| c.incoming.iter().any(|s| s.marker_count != 0))
    }
    pub fn close_owner(&mut self, owner: u32) {
        // Byte-only compatibility API cannot silently lose strong references.
        if self.has_rights() {
            return;
        }
        for slot in 0..ENDPOINTS {
            if self.endpoints[slot].endpoint.is_some_and(|endpoint| {
                endpoint.owner == owner && !matches!(endpoint.kind, Kind::PendingAccept { .. })
            }) {
                self.close_slot(slot, &mut |_| {});
            }
        }
    }
    fn close_slot(&mut self, slot: usize, sink: &mut impl FnMut(crate::ancillary::Ticket)) {
        let Some(endpoint) = self.endpoints[slot].endpoint.take() else {
            return;
        };
        self.endpoints[slot].wakes = 0;
        let handle = Handle((self.endpoints[slot].generation << 8) | slot as u64);
        for entry in &mut self.bindings {
            if let Some(binding) = entry.as_mut()
                && binding.target == Some(handle)
            {
                if binding.path.bytes[0] == 0 {
                    *entry = None;
                } else {
                    binding.target = None;
                }
            }
        }
        match endpoint.kind {
            Kind::Listening(pending) => {
                // Queue entries are exclusively PendingAccept endpoints. Depth
                // is exactly one: accepted endpoints have already left the queue.
                for queued in pending.handles.into_iter().flatten() {
                    if self.live(queued).is_ok() {
                        self.close_slot(queued.slot(), sink);
                    }
                }
            }
            Kind::Connected { connection, side } | Kind::PendingAccept { connection, side } => {
                if let Some(stream) = self.connections[connection].as_mut() {
                    stream.open[side] = false;
                    // Discard bytes addressed to the closing endpoint. Already
                    // sent bytes in its peer's ring are preserved until drained.
                    stream.incoming[side].discard(sink);
                    if stream.open == [false, false] {
                        self.connections[connection] = None;
                    }
                }
                self.wake_connection(connection, side ^ 1, IN | OUT | HUP | RDHUP);
            }
            Kind::Unconnected => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_notifications_repeat_on_committed_io_without_level_transition() {
        use crate::epoll::{HUP, IN, OUT, RDHUP};
        let mut sockets = UnixSockets::new();
        let [a, b] = sockets.socketpair(1).unwrap();
        let [c, _] = sockets.socketpair(2).unwrap();
        sockets.write(1, a, b"a").unwrap();
        assert_eq!(sockets.wake_mask(1, b), Ok(IN));
        assert_eq!(sockets.wake_mask(2, c), Ok(0));
        sockets.clear_wakes();
        sockets.write(1, a, b"b").unwrap();
        assert_eq!(sockets.wake_mask(1, b), Ok(IN));
        assert!(sockets.poll(1, b).unwrap().readable);
        sockets.clear_wakes();
        sockets.read(1, b, &mut [0; 1]).unwrap();
        assert_eq!(sockets.wake_mask(1, a), Ok(OUT));
        sockets.clear_wakes();
        assert_eq!(sockets.write(1, a, &[]), Ok(0));
        assert_eq!(sockets.read(1, b, &mut []), Ok(0));
        assert_eq!(sockets.write(2, a, b"forged"), Err(Errno::Badf));
        assert_eq!(sockets.wake_mask(1, a), Ok(0));
        assert_eq!(sockets.wake_mask(1, b), Ok(0));
        assert_eq!(sockets.wake_mask(2, a), Err(Errno::Badf));
        sockets.shutdown(1, a, 1).unwrap();
        assert_eq!(sockets.wake_mask(1, b), Ok(IN | RDHUP));
        assert_eq!(sockets.wake_mask(1, a), Ok(OUT));
        sockets.clear_wakes();
        sockets.shutdown(1, a, 1).unwrap();
        assert_eq!(sockets.wake_mask(1, b), Ok(0));
        sockets.close(1, a).unwrap();
        assert_eq!(sockets.wake_mask(1, b), Ok(IN | OUT | HUP | RDHUP));
        sockets.close(1, b).unwrap();
        let [fresh, _] = sockets.socketpair(1).unwrap();
        assert_ne!(fresh, a);
        assert_eq!(sockets.wake_mask(1, a), Err(Errno::Badf));
        assert_eq!(sockets.wake_mask(1, fresh), Ok(0));
    }

    #[test]
    fn listener_wakes_each_connect_and_close_notifies_unaccepted_client() {
        use crate::epoll::{HUP, IN, OUT, RDHUP};
        let mut sockets = UnixSockets::new();
        let listener = sockets.socket(1).unwrap();
        sockets.bind(1, listener, b"/wake-listener").unwrap();
        sockets.listen(1, listener, 2).unwrap();
        let a = sockets.socket(2).unwrap();
        let b = sockets.socket(3).unwrap();
        sockets.connect(2, a, b"/wake-listener").unwrap();
        assert_eq!(sockets.wake_mask(1, listener), Ok(IN));
        assert_eq!(sockets.wake_mask(2, a), Ok(OUT));
        sockets.clear_wakes();
        sockets.connect(3, b, b"/wake-listener").unwrap();
        assert_eq!(sockets.wake_mask(1, listener), Ok(IN));
        sockets.clear_wakes();
        let accepted = sockets.accept(1, listener).unwrap();
        assert!(sockets.poll(1, listener).unwrap().readable);
        assert_eq!(sockets.wake_mask(1, accepted), Ok(IN | OUT));
        sockets.clear_wakes();
        sockets.close(1, listener).unwrap();
        assert_eq!(sockets.wake_mask(3, b), Ok(IN | OUT | HUP | RDHUP));
        assert_eq!(sockets.wake_mask(2, a), Ok(0));
    }

    #[test]
    fn exhausted_generation_retires_slot_without_aba_reuse() {
        let mut sockets = UnixSockets::new();
        sockets.endpoints[0].generation = GENERATION_MAX - 1;
        let last = sockets.socket(1).unwrap();
        assert_eq!(last.slot(), 0);
        assert_eq!(last.generation(), GENERATION_MAX);
        sockets.close(1, last).unwrap();
        let next = sockets.socket(1).unwrap();
        assert_eq!(next.slot(), 1);
        assert_eq!(sockets.poll(1, last), Err(Errno::Badf));
        assert_eq!(sockets.capacity().free_endpoints, ENDPOINTS - 2);
        sockets.close(1, next).unwrap();
        for slot in &mut sockets.endpoints {
            slot.generation = GENERATION_MAX;
        }
        assert_eq!(sockets.socket(1), Err(Errno::Nospc));
        assert_eq!(sockets.socketpair(1), Err(Errno::Nospc));
        assert_eq!(sockets.capacity().free_endpoints, 0);
    }
}
