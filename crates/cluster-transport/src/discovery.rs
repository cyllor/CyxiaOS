//! Bounded, unauthenticated paired-node discovery. A hint can select an IP/TCP
//! endpoint for a new pinned TLS handshake, never membership or resource rights.
//! Wire v1: CXD1, u16 version, u16 length, NodeID[32], u16 TCP port,
//! u16 zero, nonce[16]. Integers are little endian; no trailing fields.
pub const WIRE_BYTES: usize = 60;
pub const MAX_DATAGRAM: usize = 256;
pub const PORT: u16 = 8444;
pub const CACHE_CAPACITY: usize = 8;
pub const AUTH_CAPACITY: usize = 4;
pub const CANDIDATE_TTL_MS: u64 = 6600;
pub use smoltcp::socket::udp::PacketMetadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Packet,
    Clock,
    Nonce,
    NotDue,
    Capacity,
    NotFound,
    Busy,
    Stale,
    Expired,
    Overflow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub node: [u8; 32],
    pub port: u16,
    pub nonce: [u8; 16],
}
impl Message {
    pub fn encode(self) -> Result<[u8; WIRE_BYTES], Error> {
        if self.node == [0; 32] || self.port == 0 || self.nonce == [0; 16] {
            return Err(Error::Packet);
        }
        let mut bytes = [0; WIRE_BYTES];
        bytes[..8].copy_from_slice(b"CXD1\x01\0\x3c\0");
        bytes[8..40].copy_from_slice(&self.node);
        bytes[40..42].copy_from_slice(&self.port.to_le_bytes());
        bytes[44..].copy_from_slice(&self.nonce);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != WIRE_BYTES
            || bytes[..8] != *b"CXD1\x01\0\x3c\0"
            || bytes[42..44] != [0; 2]
        {
            return Err(Error::Packet);
        }
        let value = Self {
            node: bytes[8..40].try_into().map_err(|_| Error::Packet)?,
            port: u16::from_le_bytes(bytes[40..42].try_into().map_err(|_| Error::Packet)?),
            nonce: bytes[44..].try_into().map_err(|_| Error::Packet)?,
        };
        value.encode()?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub node: [u8; 32],
    pub ipv4: [u8; 4],
    pub port: u16,
    pub nonce: [u8; 16],
    pub received_ms: u64,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub node: [u8; 32],
    pub ipv4: [u8; 4],
    pub port: u16,
    pub nonce: [u8; 16],
    pub candidate_generation: u64,
    pub generation: u64,
    slot: u8,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub prepared: u64,
    pub received: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub max_auth: u64,
}
/// Public announcement pacing survives TCP reconstruction. This opaque token
/// contains no peer candidate, attempt, member, TLS or resource authority.
#[derive(Clone, Copy)]
pub struct AnnouncementSchedule {
    local: [u8; 32],
    peer: [u8; 32],
    ip: [u8; 4],
    prefix: u8,
    port: u16,
    next_ms: u64,
    last_ms: u64,
    last_nonce: Option<[u8; 16]>,
}
pub struct Discovery {
    local_node: [u8; 32],
    peer_node: [u8; 32],
    local_ip: [u8; 4],
    prefix: u8,
    port: u16,
    last_ms: u64,
    next_announcement: u64,
    last_nonce: Option<[u8; 16]>,
    candidates: [Option<Candidate>; CACHE_CAPACITY],
    attempts: [Option<Attempt>; AUTH_CAPACITY],
    candidate_generation: u64,
    attempt_generation: u64,
    pub counters: Counters,
}
fn unicast(ip: [u8; 4], prefix: u8) -> bool {
    let host = u32::from_be_bytes(ip) & (u32::MAX >> prefix);
    (1..=223).contains(&ip[0]) && ip[0] != 127 && host != 0 && host != u32::MAX >> prefix
}
impl Discovery {
    pub fn announcement_schedule(&self) -> AnnouncementSchedule {
        AnnouncementSchedule {
            local: self.local_node,
            peer: self.peer_node,
            ip: self.local_ip,
            prefix: self.prefix,
            port: self.port,
            next_ms: self.next_announcement,
            last_ms: self.last_ms,
            last_nonce: self.last_nonce,
        }
    }
    pub fn resume_announcements(
        &mut self,
        schedule: AnnouncementSchedule,
        now: u64,
    ) -> Result<(), Error> {
        if self.counters.prepared != 0
            || self.counters.received != 0
            || self.candidate_generation != 0
            || self.attempt_generation != 0
            || (
                schedule.local,
                schedule.peer,
                schedule.ip,
                schedule.prefix,
                schedule.port,
            ) != (
                self.local_node,
                self.peer_node,
                self.local_ip,
                self.prefix,
                self.port,
            )
        {
            return Err(Error::Configuration);
        }
        if now < schedule.last_ms {
            return Err(Error::Clock);
        }
        self.time(now)?;
        self.next_announcement = schedule.next_ms;
        self.last_nonce = schedule.last_nonce;
        Ok(())
    }
    pub fn new(
        local_node: [u8; 32],
        peer_node: [u8; 32],
        local_ip: [u8; 4],
        prefix: u8,
        port: u16,
        now_ms: u64,
    ) -> Result<Self, Error> {
        if local_node == [0; 32]
            || peer_node == [0; 32]
            || local_node == peer_node
            || !(1..=30).contains(&prefix)
            || !unicast(local_ip, prefix)
            || port == 0
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            local_node,
            peer_node,
            local_ip,
            prefix,
            port,
            last_ms: now_ms,
            next_announcement: now_ms,
            last_nonce: None,
            candidates: [None; CACHE_CAPACITY],
            attempts: [None; AUTH_CAPACITY],
            candidate_generation: 0,
            attempt_generation: 0,
            counters: Counters::default(),
        })
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_ms {
            return Err(Error::Clock);
        }
        self.last_ms = now;
        Ok(())
    }
    pub fn due(&mut self, now: u64) -> Result<bool, Error> {
        self.time(now)?;
        Ok(now >= self.next_announcement)
    }
    pub fn next_announcement_ms(&self) -> u64 {
        self.next_announcement
    }
    /// The caller supplies fresh guest CSPRNG bytes. No clock/NodeID/random-seed
    /// fallback is accepted, and backpressure must retain the returned packet.
    pub fn announce(&mut self, now: u64, nonce: [u8; 16]) -> Result<Message, Error> {
        if !self.due(now)? {
            return Err(Error::NotDue);
        }
        if nonce == [0; 16] || self.last_nonce == Some(nonce) {
            return Err(Error::Nonce);
        }
        let jitter = u16::from_le_bytes([nonce[0], nonce[1]]) as u64 % 401;
        let next = now.checked_add(1800 + jitter).ok_or(Error::Overflow)?;
        let prepared = self
            .counters
            .prepared
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.next_announcement = next;
        self.last_nonce = Some(nonce);
        self.counters.prepared = prepared;
        Ok(Message {
            node: self.local_node,
            port: self.port,
            nonce,
        })
    }
    pub fn receive(&mut self, source: [u8; 4], bytes: &[u8], now: u64) -> Result<(), Error> {
        self.time(now)?;
        self.counters.received = self
            .counters
            .received
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let result = self.receive_inner(source, bytes, now);
        if result.is_err() {
            self.counters.rejected = self
                .counters
                .rejected
                .checked_add(1)
                .ok_or(Error::Overflow)?;
        }
        result
    }
    fn receive_inner(&mut self, source: [u8; 4], bytes: &[u8], now: u64) -> Result<(), Error> {
        let mask = u32::MAX << (32 - self.prefix);
        if !unicast(source, self.prefix)
            || source == self.local_ip
            || u32::from_be_bytes(source) & mask != u32::from_be_bytes(self.local_ip) & mask
        {
            return Err(Error::Packet);
        }
        let message = Message::decode(bytes)?;
        if message.node == self.local_node {
            return Err(Error::Packet);
        }
        if self
            .candidates
            .iter()
            .flatten()
            .any(|c| c.node == message.node && c.nonce == message.nonce)
        {
            return Err(Error::Nonce);
        }
        // Slot zero is reserved for the configured peer hint. A spoofed-node
        // flood cannot evict it or acquire any authentication/member authority.
        let slot = if message.node == self.peer_node {
            0
        } else {
            (1..CACHE_CAPACITY)
                .find(|&i| self.candidates[i].is_some_and(|c| c.node == message.node))
                .or_else(|| {
                    (1..CACHE_CAPACITY).find(|&i| {
                        self.candidates[i]
                            .is_none_or(|c| now.saturating_sub(c.received_ms) >= CANDIDATE_TTL_MS)
                    })
                })
                .ok_or(Error::Capacity)?
        };
        let generation = self
            .candidate_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.counters.accepted = self
            .counters
            .accepted
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.candidates[slot] = Some(Candidate {
            node: message.node,
            ipv4: source,
            port: message.port,
            nonce: message.nonce,
            received_ms: now,
            generation,
        });
        self.candidate_generation = generation;
        Ok(())
    }
    pub fn candidates(&self) -> usize {
        self.candidates.iter().flatten().count()
    }
    pub fn selected_candidate(&self) -> Option<Candidate> {
        self.candidates[0]
    }
    pub fn pending_auth(&self) -> usize {
        self.attempts.iter().flatten().count()
    }
    pub fn begin_auth(&mut self, now: u64) -> Result<Attempt, Error> {
        self.time(now)?;
        let c = self.candidates[0].ok_or(Error::NotFound)?;
        if now.saturating_sub(c.received_ms) >= CANDIDATE_TTL_MS {
            return Err(Error::Expired);
        }
        if self.attempts.iter().flatten().any(|a| a.node == c.node) {
            return Err(Error::Busy);
        }
        let slot = self
            .attempts
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self
            .attempt_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let a = Attempt {
            node: c.node,
            ipv4: c.ipv4,
            port: c.port,
            nonce: c.nonce,
            candidate_generation: c.generation,
            generation,
            slot: slot as u8,
        };
        self.attempts[slot] = Some(a);
        self.attempt_generation = generation;
        self.counters.max_auth = self.counters.max_auth.max(self.pending_auth() as u64);
        Ok(a)
    }
    pub fn finish_auth(&mut self, attempt: Attempt) -> Result<(), Error> {
        let slot = self
            .attempts
            .get_mut(attempt.slot as usize)
            .ok_or(Error::Stale)?;
        if *slot != Some(attempt) {
            return Err(Error::Stale);
        }
        *slot = None;
        Ok(())
    }
}
