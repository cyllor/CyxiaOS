//! Structural admission of a single Ethernet frame for a configured Echo
//! listener. No connection state, credentials or authority are passed in.
use crate::device::MTU;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr,
};

pub fn eligible(frame: &[u8], mac: [u8; 6], local: [u8; 4], peer: [u8; 4], port: u16) -> bool {
    if frame.len() > MTU {
        return false;
    }
    let Ok(frame) = EthernetFrame::new_checked(frame) else {
        return false;
    };
    let mac = EthernetAddress(mac);
    let local = Ipv4Address::from_octets(local);
    let peer = Ipv4Address::from_octets(peer);
    let destination = frame.dst_addr();
    match frame.ethertype() {
        EthernetProtocol::Arp if destination == mac || destination.is_broadcast() => {
            let Ok(arp) = ArpPacket::new_checked(frame.payload()) else {
                return false;
            };
            let Ok(ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            }) = ArpRepr::parse(&arp)
            else {
                return false;
            };
            source_hardware_addr == frame.src_addr()
                && source_hardware_addr.is_unicast()
                && source_protocol_addr == peer
                && target_protocol_addr == local
                && match operation {
                    ArpOperation::Request => true,
                    ArpOperation::Reply => destination == mac && target_hardware_addr == mac,
                    _ => false,
                }
        }
        EthernetProtocol::Ipv4 if destination == mac => {
            let checksums = ChecksumCapabilities::default();
            let Ok(ip) = Ipv4Packet::new_checked(frame.payload()) else {
                return false;
            };
            if ip.header_len() != 20
                || ip.more_frags()
                || ip.frag_offset() != 0
                || ip.src_addr() != peer
                || ip.dst_addr() != local
                || ip.next_header() != IpProtocol::Tcp
                || Ipv4Repr::parse(&ip, &checksums).is_err()
            {
                return false;
            }
            let tcp = TcpPacket::new_unchecked(ip.payload());
            TcpRepr::parse(
                &tcp,
                &IpAddress::Ipv4(peer),
                &IpAddress::Ipv4(local),
                &checksums,
            )
            .is_ok_and(|tcp| tcp.dst_port == port)
        }
        _ => false,
    }
}
