use cyxia_cluster_transport::{
    device::{Error as PortError, MTU, Port},
    discovery,
    tcp::{BUFFER_SIZE, Config, DiscoveryBuffers, DiscoveryConfig, State, Storage, Tcp},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
#[derive(Default)]
struct Link {
    queues: [VecDeque<Vec<u8>>; 2],
    frames: Vec<Vec<u8>>,
    drop_arp: bool,
}
struct TestPort(Rc<RefCell<Link>>, usize);
impl Port for TestPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), PortError> {
        let mut link = self.0.borrow_mut();
        link.frames.push(frame.to_vec());
        if link.drop_arp && frame.get(12..14) == Some(&[8, 6]) {
            return Ok(());
        }
        link.queues[1 - self.1].push_back(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, out: &mut [u8; MTU]) -> Result<Option<usize>, PortError> {
        let Some(frame) = self.0.borrow_mut().queues[self.1].pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
}
fn config(node: u8) -> Config {
    Config {
        mac: [2, 0, 0, 0, 0, node],
        local: [10, 42, 0, node],
        peer: [0; 4],
        prefix_len: 24,
        local_port: if node == 1 { 40001 } else { 8443 },
        peer_port: 0,
        random_seed: node as u64,
    }
}

#[test]
fn reconnect_preserves_boot_broadcast_deadline_and_requires_new_received_hint() {
    let link = Rc::new(RefCell::new(Link::default()));
    let old_next;
    let previous_schedule;
    {
        let (mut rx, mut tx) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE]);
        let mut storage = [Storage::EMPTY, Storage::EMPTY];
        let (mut rm, mut tm) = (
            [discovery::PacketMetadata::EMPTY; 4],
            [discovery::PacketMetadata::EMPTY; 4],
        );
        let (mut rd, mut td) = ([0; 1024], [0; 1024]);
        let mut tcp = Tcp::new_discovering(
            TestPort(link.clone(), 0),
            config(1),
            0,
            &mut rx,
            &mut tx,
            &mut storage,
            DiscoveryConfig {
                local_node: [1; 32],
                peer_node: [2; 32],
            },
            DiscoveryBuffers {
                rx_meta: &mut rm,
                tx_meta: &mut tm,
                rx: &mut rd,
                tx: &mut td,
            },
        )
        .unwrap();
        tcp.connect().unwrap();
        tcp.prepare_discovery(0, [7; 16]).unwrap();
        let peer = discovery::Message {
            node: [2; 32],
            port: 8443,
            nonce: [11; 16],
        }
        .encode()
        .unwrap();
        link.borrow_mut().queues[0].push_back(datagram([10, 42, 0, 2], 8444, &peer));
        for now in 0..10 {
            tcp.poll(now).unwrap();
            if tcp.discovery_snapshot().unwrap().sent == 1 {
                break;
            }
        }
        assert_eq!(tcp.discovery_snapshot().unwrap().sent, 1);
        assert_eq!(tcp.peer_ipv4(), Some([10, 42, 0, 2]));
        old_next = tcp.discovery_snapshot().unwrap().next_ms;
        previous_schedule = tcp.discovery_schedule().unwrap();
        assert!((1800..=2200).contains(&old_next));
    }
    link.borrow_mut().queues.iter_mut().for_each(|q| q.clear());
    let (mut rx, mut tx) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE]);
    let mut storage = [Storage::EMPTY, Storage::EMPTY];
    let (mut rm, mut tm) = (
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
    );
    let (mut rd, mut td) = ([0; 1024], [0; 1024]);
    let mut tcp = Tcp::new_discovering(
        TestPort(link.clone(), 0),
        config(1),
        1000,
        &mut rx,
        &mut tx,
        &mut storage,
        DiscoveryConfig {
            local_node: [1; 32],
            peer_node: [2; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm,
            tx_meta: &mut tm,
            rx: &mut rd,
            tx: &mut td,
        },
    )
    .unwrap();
    tcp.resume_discovery_schedule(previous_schedule, 1000)
        .unwrap();
    tcp.connect().unwrap();
    assert!(
        !tcp.discovery_due(1000).unwrap(),
        "TCP reconstruction reset the same boot's UDP rate limit"
    );
    assert_eq!(tcp.discovery_snapshot().unwrap().next_ms, old_next);
    assert_eq!(
        tcp.peer_ipv4(),
        None,
        "schedule preservation must not reuse a peer candidate"
    );
    assert!(tcp.prepare_discovery(1000, [9; 16]).is_err());
    tcp.poll(1000).unwrap();
    assert_eq!(
        link.borrow()
            .frames
            .iter()
            .filter(|f| f.get(23) == Some(&17))
            .count(),
        1,
        "no new UDP is allowed at the TCP reconnect boundary"
    );
    assert!(tcp.discovery_due(old_next).unwrap());
    assert!(
        tcp.prepare_discovery(old_next, [7; 16]).is_err(),
        "last nonce survives reconstruction"
    );
    tcp.prepare_discovery(old_next, [9; 16]).unwrap();
    tcp.poll(old_next).unwrap();
    assert_eq!(
        link.borrow()
            .frames
            .iter()
            .filter(|f| f.get(23) == Some(&17))
            .count(),
        2
    );
    assert_eq!(tcp.peer_ipv4(), None);
}
#[test]
fn actual_udp_discovery_is_required_before_tcp_and_selects_received_endpoint() {
    let link = Rc::new(RefCell::new(Link::default()));
    let (mut rx1, mut tx1, mut rx2, mut tx2) = (
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
    );
    let (mut st1, mut st2) = (
        [Storage::EMPTY, Storage::EMPTY],
        [Storage::EMPTY, Storage::EMPTY],
    );
    let (mut rm1, mut tm1, mut rm2, mut tm2) = (
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
    );
    let (mut rd1, mut td1, mut rd2, mut td2) = ([0; 1024], [0; 1024], [0; 1024], [0; 1024]);
    let mut a = Tcp::new_discovering(
        TestPort(link.clone(), 0),
        config(1),
        0,
        &mut rx1,
        &mut tx1,
        &mut st1,
        DiscoveryConfig {
            local_node: [1; 32],
            peer_node: [2; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm1,
            tx_meta: &mut tm1,
            rx: &mut rd1,
            tx: &mut td1,
        },
    )
    .unwrap();
    let mut b = Tcp::new_discovering(
        TestPort(link.clone(), 1),
        config(2),
        0,
        &mut rx2,
        &mut tx2,
        &mut st2,
        DiscoveryConfig {
            local_node: [2; 32],
            peer_node: [1; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm2,
            tx_meta: &mut tm2,
            rx: &mut rd2,
            tx: &mut td2,
        },
    )
    .unwrap();
    a.connect().unwrap();
    b.listen().unwrap();
    for t in 0..10 {
        a.poll(t).unwrap();
        b.poll(t).unwrap();
    }
    assert!(
        link.borrow().frames.is_empty(),
        "static IP bypass emitted packets before discovery"
    );
    assert_eq!(a.peer_ipv4(), None);
    a.prepare_discovery(10, [7; 16]).unwrap();
    b.prepare_discovery(10, [9; 16]).unwrap();
    for t in 10..1000 {
        a.poll(t).unwrap();
        b.poll(t).unwrap();
        if a.state() == Ok(State::Established) && b.state() == Ok(State::Established) {
            break;
        }
    }
    assert_eq!(a.state(), Ok(State::Established));
    assert_eq!(b.state(), Ok(State::Established));
    assert_eq!(a.peer_ipv4(), Some([10, 42, 0, 2]));
    assert_eq!(b.peer_ipv4(), Some([10, 42, 0, 1]));
    let frames = &link.borrow().frames;
    let discovery_at = frames.iter().position(|f| f.get(23) == Some(&17)).unwrap();
    let syn_at = frames.iter().position(|f| f.get(23) == Some(&6)).unwrap();
    assert!(discovery_at < syn_at);
    for f in frames.iter().filter(|f| f.get(23) == Some(&17)) {
        assert_eq!(f.len(), 14 + 20 + 8 + discovery::WIRE_BYTES);
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16)
    }
    !(sum as u16)
}
fn datagram(source: [u8; 4], port: u16, body: &[u8]) -> Vec<u8> {
    let mut udp = Vec::from(port.to_be_bytes());
    udp.extend(discovery::PORT.to_be_bytes());
    udp.extend(((8 + body.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(body);
    let mut pseudo = Vec::from(source);
    pseudo.extend([10, 42, 0, 255, 0, 17]);
    pseudo.extend((udp.len() as u16).to_be_bytes());
    pseudo.extend(&udp);
    let check = checksum(&pseudo);
    udp[6..8].copy_from_slice(&check.to_be_bytes());
    let mut ip = vec![0x45, 0];
    ip.extend(((20 + udp.len()) as u16).to_be_bytes());
    ip.extend([0, 0, 0x40, 0, 64, 17, 0, 0]);
    ip.extend(source);
    ip.extend([10, 42, 0, 255]);
    let check = checksum(&ip);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    let mut f = vec![255; 6];
    f.extend([2, 0, 0, 0, 0, 2, 8, 0]);
    f.extend(ip);
    f.extend(udp);
    f
}
#[test]
fn malformed_wrong_port_and_unconfigured_hints_never_open_a_tcp_stream() {
    let link = Rc::new(RefCell::new(Link::default()));
    let (mut rx, mut tx) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE]);
    let mut st = [Storage::EMPTY, Storage::EMPTY];
    let (mut rm, mut tm) = (
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
    );
    let (mut rd, mut td) = ([0; 1024], [0; 1024]);
    let mut a = Tcp::new_discovering(
        TestPort(link.clone(), 0),
        config(1),
        0,
        &mut rx,
        &mut tx,
        &mut st,
        DiscoveryConfig {
            local_node: [1; 32],
            peer_node: [2; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm,
            tx_meta: &mut tm,
            rx: &mut rd,
            tx: &mut td,
        },
    )
    .unwrap();
    a.connect().unwrap();
    let good = discovery::Message {
        node: [2; 32],
        port: 8443,
        nonce: [7; 16],
    }
    .encode()
    .unwrap();
    let mut malformed = good;
    malformed[42] = 1;
    let mut zero = good;
    zero[44..].fill(0);
    let unrelated = discovery::Message {
        node: [3; 32],
        port: 8443,
        nonce: [9; 16],
    }
    .encode()
    .unwrap();
    let mut oversized = good.to_vec();
    oversized.resize(257, 0);
    for (i, frame) in [
        datagram([10, 42, 0, 77], 8444, &malformed),
        datagram([10, 42, 0, 77], 8445, &good),
        datagram([10, 42, 0, 77], 8444, &zero),
        datagram([10, 42, 0, 77], 8444, &unrelated),
        datagram([10, 42, 0, 255], 8444, &good),
        datagram([10, 42, 0, 77], 8444, &oversized),
    ]
    .into_iter()
    .enumerate()
    {
        link.borrow_mut().queues[0].push_back(frame);
        a.poll(i as u64).unwrap();
        assert_eq!(a.peer_ipv4(), None);
        assert!(!link.borrow().frames.iter().any(|f| f.get(23) == Some(&6)));
    }
    link.borrow_mut().queues[0].push_back(datagram([10, 42, 0, 77], 8444, &good));
    a.poll(10).unwrap();
    assert_eq!(
        a.peer_ipv4(),
        Some([10, 42, 0, 77]),
        "source 77 must win over any conventional paired IP 2"
    );
}

#[test]
fn delayed_arp_across_announcements_keeps_the_original_selected_attempt() {
    let link = Rc::new(RefCell::new(Link {
        drop_arp: true,
        ..Default::default()
    }));
    let (mut rx1, mut tx1, mut rx2, mut tx2) = (
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
    );
    let (mut st1, mut st2) = (
        [Storage::EMPTY, Storage::EMPTY],
        [Storage::EMPTY, Storage::EMPTY],
    );
    let (mut rm1, mut tm1, mut rm2, mut tm2) = (
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
        [discovery::PacketMetadata::EMPTY; 4],
    );
    let (mut rd1, mut td1, mut rd2, mut td2) = ([0; 1024], [0; 1024], [0; 1024], [0; 1024]);
    let mut a = Tcp::new_discovering(
        TestPort(link.clone(), 0),
        config(1),
        0,
        &mut rx1,
        &mut tx1,
        &mut st1,
        DiscoveryConfig {
            local_node: [1; 32],
            peer_node: [2; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm1,
            tx_meta: &mut tm1,
            rx: &mut rd1,
            tx: &mut td1,
        },
    )
    .unwrap();
    let mut b = Tcp::new_discovering(
        TestPort(link.clone(), 1),
        config(2),
        0,
        &mut rx2,
        &mut tx2,
        &mut st2,
        DiscoveryConfig {
            local_node: [2; 32],
            peer_node: [1; 32],
        },
        DiscoveryBuffers {
            rx_meta: &mut rm2,
            tx_meta: &mut tm2,
            rx: &mut rd2,
            tx: &mut td2,
        },
    )
    .unwrap();
    a.connect().unwrap();
    b.listen().unwrap();
    a.prepare_discovery(0, [7; 16]).unwrap();
    b.prepare_discovery(0, [9; 16]).unwrap();
    for t in 0..7000 {
        if t == 2200 {
            a.prepare_discovery(t, [17; 16]).unwrap();
            b.prepare_discovery(t, [19; 16]).unwrap();
        }
        if t == 2300 {
            // An unauthenticated later hint advertises a different port. It
            // may update the cache, never the already selected TCP attempt.
            let body = discovery::Message {
                node: [2; 32],
                port: 9443,
                nonce: [29; 16],
            }
            .encode()
            .unwrap();
            let frame = datagram([10, 42, 0, 2], 8444, &body);
            let mut wire = link.borrow_mut();
            wire.frames.push(frame.clone());
            wire.queues[0].push_back(frame);
        }
        if t == 2400 {
            link.borrow_mut().drop_arp = false;
        }
        a.poll(t).unwrap();
        b.poll(t).unwrap();
        if a.state() == Ok(State::Established) && b.state() == Ok(State::Established) {
            break;
        }
    }
    assert_eq!(a.state(), Ok(State::Established));
    assert_eq!(b.state(), Ok(State::Established));
    let selected = a.discovery_snapshot().unwrap();
    assert_eq!(selected.selected.unwrap().nonce, [9; 16]);
    assert_eq!(
        selected.counters.accepted, 3,
        "both actual announcements and the untrusted changed hint reached ingress"
    );
    assert_eq!(selected.selected.unwrap().ipv4, [10, 42, 0, 2]);
    assert_eq!(
        selected.selected.unwrap().port,
        8443,
        "later hint must not mutate the selected endpoint"
    );
    let frames = &link.borrow().frames;
    let second = frames
        .iter()
        .position(|f| f.get(23) == Some(&17) && f.get(86..102) == Some(&[19; 16]))
        .unwrap();
    let syn = frames.iter().position(|f| f.get(23) == Some(&6)).unwrap();
    assert!(
        second < syn,
        "new advertisement must precede delayed first SYN"
    );
    // Optional test-only export lets the independent Python auditor consume
    // the exact production smoltcp frames, rather than invented packet bytes.
    if let Some(output) = std::env::var_os("CYXIA_DISCOVERY_TEST_PCAP") {
        use std::io::Write;
        let mut out = std::fs::File::create(output).unwrap();
        out.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ])
        .unwrap();
        for (i, f) in frames.iter().enumerate() {
            for word in [0u32, i as u32, f.len() as u32, f.len() as u32] {
                out.write_all(&word.to_le_bytes()).unwrap();
            }
            out.write_all(f).unwrap();
        }
    }
}
