//! Measurements of packets accepted by the real device and acknowledgments
//! consumed by the real socket. No sample is invented for an idle stream.
use super::Config;
use crate::device::{Error, MTU, Port};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet, TcpPacket,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    /// bit 0: unambiguous RTT; bit 1: an actual segment denominator.
    pub valid: u64,
    pub sample_ms: u64,
    pub rtt_us: u64,
    pub retrans_milli: u64,
    pub queued_bytes: u64,
    pub active: u64,
}
#[derive(Clone, Copy)]
struct Segment {
    start: u32,
    end: u32,
    sent: u64,
    ambiguous: bool,
}
#[derive(Clone, Copy)]
struct Packet {
    seq: u32,
    end: u32,
    ack: Option<u32>,
}
pub(super) struct ObservedPort<P> {
    inner: P,
    config: Config,
    now: u64,
    outstanding: [Option<Segment>; 64],
    received_ack: Option<u32>,
    rtt: Option<(u64, u64)>,
    window_started: u64,
    sent: u64,
    retransmitted: u64,
    valid: bool,
}
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn packet(frame: &[u8], config: Config, outgoing: bool) -> Option<Packet> {
    let ethernet = EthernetFrame::new_checked(frame).ok()?;
    if ethernet.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
    let (source, destination, source_port, destination_port) = if outgoing {
        (
            config.local,
            config.peer,
            config.local_port,
            config.peer_port,
        )
    } else {
        (
            config.peer,
            config.local,
            config.peer_port,
            config.local_port,
        )
    };
    if ip.next_header() != IpProtocol::Tcp
        || ip.more_frags()
        || ip.frag_offset() != 0
        || ip.src_addr().octets() != source
        || ip.dst_addr().octets() != destination
        || !ip.verify_checksum()
    {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    if tcp.src_port() != source_port
        || tcp.dst_port() != destination_port
        || !tcp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
        )
    {
        return None;
    }
    let seq = tcp.seq_number().0 as u32;
    let length = tcp.payload().len() as u32 + u32::from(tcp.syn()) + u32::from(tcp.fin());
    Some(Packet {
        seq,
        end: seq.wrapping_add(length),
        ack: tcp.ack().then_some(tcp.ack_number().0 as u32),
    })
}
impl<P: Port> ObservedPort<P> {
    pub(super) fn new(inner: P, config: Config, now: u64) -> Self {
        Self {
            inner,
            config,
            now,
            outstanding: [None; 64],
            received_ack: None,
            rtt: None,
            window_started: now,
            sent: 0,
            retransmitted: 0,
            valid: true,
        }
    }
    pub(super) fn set_time(&mut self, now: u64) {
        self.now = now;
        if now.saturating_sub(self.window_started) >= 1000 {
            self.window_started = now;
            self.sent = 0;
            self.retransmitted = 0;
        }
    }
    pub(super) fn ingress_processed(&mut self, accepted_ack: bool) {
        let Some(ack) = self.received_ack.take().filter(|_| accepted_ack) else {
            return;
        };
        let mut newest = None;
        for slot in &mut self.outstanding {
            if let Some(segment) = *slot
                && !before(ack, segment.end)
            {
                if !segment.ambiguous && self.now >= segment.sent {
                    newest = Some(newest.map_or(segment.sent, |old: u64| old.max(segment.sent)));
                }
                *slot = None;
            }
        }
        if let Some(sent) = newest
            && let Some(us) = self.now.checked_sub(sent).and_then(|v| v.checked_mul(1000))
        {
            self.rtt = Some((self.now, us));
        }
    }
    pub(super) fn observation(&self, queued: usize, active: bool) -> Observation {
        let mut result = Observation {
            queued_bytes: queued as u64,
            active: u64::from(active),
            ..Observation::default()
        };
        if !self.valid {
            return result;
        }
        if let Some((ms, us)) = self
            .rtt
            .filter(|(ms, _)| self.now.saturating_sub(*ms) <= 1000)
        {
            result.valid |= 1;
            result.sample_ms = ms;
            result.rtt_us = us;
        }
        if self.sent != 0 {
            result.valid |= 2;
            result.retrans_milli =
                ((u128::from(self.retransmitted) * 1000) / u128::from(self.sent)) as u64;
        }
        result
    }
    fn sent_packet(&mut self, packet: Packet) {
        if packet.end == packet.seq {
            return;
        }
        let Some(sent) = self.sent.checked_add(1) else {
            self.valid = false;
            return;
        };
        self.sent = sent;
        let mut retransmission = false;
        for slot in self.outstanding.iter_mut().flatten() {
            if before(packet.seq, slot.end) && before(slot.start, packet.end) {
                retransmission = true;
                slot.ambiguous = true;
            }
        }
        if retransmission {
            if let Some(count) = self.retransmitted.checked_add(1) {
                self.retransmitted = count;
            } else {
                self.valid = false;
            }
            // Retain the original sequence range but never use its timestamp.
            return;
        }
        let Some(slot) = self.outstanding.iter_mut().find(|slot| slot.is_none()) else {
            self.valid = false;
            return;
        };
        *slot = Some(Segment {
            start: packet.seq,
            end: packet.end,
            sent: self.now,
            ambiguous: false,
        });
    }
}
impl<P: Port> Port for ObservedPort<P> {
    fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }
    fn burst_capacity(&self) -> usize {
        self.inner.burst_capacity()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.inner.send(frame)?;
        if let Some(packet) = packet(frame, self.config, true) {
            self.sent_packet(packet);
        }
        Ok(())
    }
    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, Error> {
        let received = self.inner.receive(frame)?;
        if let Some(length) = received {
            self.received_ack = frame
                .get(..length)
                .and_then(|frame| packet(frame, self.config, false))
                .and_then(|p| p.ack);
        }
        Ok(received)
    }
}
