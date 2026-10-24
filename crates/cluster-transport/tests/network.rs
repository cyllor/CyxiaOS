use cyxia_cluster_transport::{
    device::{Error as PortError, MTU, Port},
    tcp::{BUFFER_SIZE, Config, Error, Storage, Tcp},
    wire::{self, Decoder, Header, Kind, ReplayGate},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

#[derive(Default)]
struct Link {
    a: VecDeque<Vec<u8>>,
    b: VecDeque<Vec<u8>>,
    drop_one_ip: bool,
    seen_arp: bool,
    seen_ipv4: bool,
}
struct TestPort {
    link: Rc<RefCell<Link>>,
    a: bool,
}
impl Port for TestPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), PortError> {
        let mut link = self.link.borrow_mut();
        link.seen_arp |= frame[12..14] == [8, 6];
        link.seen_ipv4 |= frame[12..14] == [8, 0];
        if link.drop_one_ip && frame[12..14] == [8, 0] {
            link.drop_one_ip = false;
            return Ok(());
        }
        let queue = if self.a { &mut link.b } else { &mut link.a };
        if queue.len() == 2 {
            return Err(PortError::WouldBlock);
        }
        queue.push_back(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, out: &mut [u8; MTU]) -> Result<Option<usize>, PortError> {
        let mut link = self.link.borrow_mut();
        let queue = if self.a { &mut link.a } else { &mut link.b };
        let Some(frame) = queue.pop_front() else {
            return Ok(None);
        };
        out[..frame.len()].copy_from_slice(&frame);
        Ok(Some(frame.len()))
    }
}
fn config(a: bool) -> Config {
    Config {
        mac: [2, 0, 0, 0, 0, if a { 1 } else { 2 }],
        local: [10, 0, 0, if a { 1 } else { 2 }],
        peer: [10, 0, 0, if a { 2 } else { 1 }],
        prefix_len: 24,
        local_port: if a { 40001 } else { 8443 },
        peer_port: if a { 8443 } else { 40001 },
        random_seed: if a { 0xdeadbeef } else { 0xf00dcafe },
    }
}
fn tcp_roundtrip(drop_syn: bool) {
    let link = Rc::new(RefCell::new(Link {
        drop_one_ip: drop_syn,
        ..Default::default()
    }));
    let (mut arx, mut atx, mut brx, mut btx) = (
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
    );
    let mut a_storage = [Storage::EMPTY];
    let mut b_storage = [Storage::EMPTY];
    let mut a = Tcp::new(
        TestPort {
            link: link.clone(),
            a: true,
        },
        config(true),
        0,
        &mut arx,
        &mut atx,
        &mut a_storage,
    )
    .unwrap();
    let mut b = Tcp::new(
        TestPort {
            link: link.clone(),
            a: false,
        },
        config(false),
        0,
        &mut brx,
        &mut btx,
        &mut b_storage,
    )
    .unwrap();
    b.listen().unwrap();
    a.connect().unwrap();
    let payload: Vec<u8> = (0..65000).map(|i| (i * 17) as u8).collect();
    let mut sent = 0;
    let mut received = Vec::new();
    for ms in 0..20000 {
        a.poll(ms).unwrap();
        b.poll(ms).unwrap();
        if sent < payload.len()
            && let Ok(count) = a.send_tls(&payload[sent..])
        {
            sent += count;
        }
        let mut block = [0; 731];
        if let Ok(count) = b.receive_tls(&mut block) {
            received.extend_from_slice(&block[..count]);
        }
        if received.len() == payload.len() {
            break;
        }
    }
    assert_eq!(received, payload);
    let observed = a.observation();
    assert_eq!(observed.valid, 3);
    assert_eq!(observed.active, 1);
    assert!(observed.rtt_us < 1_000_000);
    assert!(link.borrow().seen_arp && link.borrow().seen_ipv4);
    assert_eq!(a.poll(0), Err(Error::Clock));
    assert_eq!(a.send_tls(b"stale"), Err(Error::Closed));
}

#[test]
fn reconnect_retains_backoff_and_entropy_gates_for_terminal_errors() {
    use cyxia_cluster_transport::tcp::{State, reconnect_due};
    for state in [
        Ok(State::Closed),
        Err(Error::Closed),
        Err(Error::Peer),
        Err(Error::Device),
        Err(Error::Clock),
        Err(Error::Socket),
    ] {
        assert!(!reconnect_due(state, 999, true));
        assert!(!reconnect_due(state, 1000, false));
        assert!(reconnect_due(state, 1000, true));
    }
    for state in [
        Ok(State::Established),
        Ok(State::SynSent),
        Err(Error::Configuration),
        Err(Error::WouldBlock),
    ] {
        assert!(!reconnect_due(state, 5000, true));
    }
}

#[test]
fn exact_send_backpressure_does_not_enqueue_any_prefix() {
    let link = Rc::new(RefCell::new(Link::default()));
    let (mut arx, mut atx, mut brx, mut btx) = (
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
        [0; BUFFER_SIZE],
    );
    let (mut sa, mut sb) = ([Storage::EMPTY], [Storage::EMPTY]);
    let mut a = Tcp::new(
        TestPort {
            link: link.clone(),
            a: true,
        },
        config(true),
        0,
        &mut arx,
        &mut atx,
        &mut sa,
    )
    .unwrap();
    let mut b = Tcp::new(
        TestPort { link, a: false },
        config(false),
        0,
        &mut brx,
        &mut btx,
        &mut sb,
    )
    .unwrap();
    assert_eq!(a.observation().valid, 0);
    b.listen().unwrap();
    a.connect().unwrap();
    for ms in 0..20 {
        a.poll(ms).unwrap();
        b.poll(ms).unwrap();
    }
    let payload = [7; BUFFER_SIZE - 2];
    a.send_exact(&payload).unwrap();
    let depth = a.observation().queued_bytes;
    assert_eq!(a.send_exact(&[1, 2, 3]), Err(Error::WouldBlock));
    assert_eq!(a.observation().queued_bytes, depth);
    a.send_exact(&[8, 9]).unwrap();
    assert_eq!(a.observation().queued_bytes, BUFFER_SIZE as u64);
    let mut output = Vec::new();
    for ms in 20..2000 {
        a.poll(ms).unwrap();
        b.poll(ms).unwrap();
        let mut bytes = [0; 4096];
        if let Ok(n) = b.receive_tls(&mut bytes) {
            output.extend_from_slice(&bytes[..n]);
        }
        if output.len() == BUFFER_SIZE {
            break;
        }
    }
    assert_eq!(output.len(), BUFFER_SIZE);
    assert!(output[..BUFFER_SIZE - 2].iter().all(|b| *b == 7));
    assert_eq!(&output[BUFFER_SIZE - 2..], &[8, 9]);
}
#[test]
fn native_stack_arp_tcp_fragmentation_and_backpressure() {
    tcp_roundtrip(false);
}
#[test]
fn tcp_retransmits_a_dropped_syn() {
    tcp_roundtrip(true);
}

#[test]
fn malformed_network_configuration_is_rejected_before_interface_creation() {
    for mutate in 0..8 {
        let mut cfg = config(true);
        match mutate {
            0 => cfg.random_seed = 0,
            1 => cfg.mac = [0; 6],
            2 => cfg.mac[0] = 3,
            3 => cfg.local[0] = 0,
            4 => cfg.peer[0] = 224,
            5 => cfg.peer = cfg.local,
            6 => cfg.peer[3] = 255,
            _ => cfg.prefix_len = 33,
        }
        let mut rx = [0; BUFFER_SIZE];
        let mut tx = [0; BUFFER_SIZE];
        let mut storage = [Storage::EMPTY];
        assert!(matches!(
            Tcp::new(
                TestPort {
                    link: Rc::default(),
                    a: true
                },
                cfg,
                0,
                &mut rx,
                &mut tx,
                &mut storage
            ),
            Err(Error::Configuration)
        ));
    }
}
fn header() -> Header {
    Header {
        kind: Kind::Prepare,
        response: false,
        body_len: 3,
        session_seq: 0x0102_0304_0506_0708,
        request_id: [0x11; 16],
        cluster_id: [0x22; 32],
        config_epoch: 7,
        sender_boot: 9,
        receiver_boot: 11,
    }
}
#[test]
fn rpc_header_exact_offsets_and_response_bit() {
    let mut out = [0xaa; 96];
    let h = header();
    h.encode(&mut out).unwrap();
    assert_eq!(
        &out[..24],
        &[
            0x31, 0x43, 0x58, 0x43, 1, 0, 17, 0, 96, 0, 0, 0, 3, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1
        ]
    );
    assert_eq!(&out[24..40], &[0x11; 16]);
    assert_eq!(&out[40..72], &[0x22; 32]);
    assert_eq!(
        &out[72..96],
        &[
            7, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(Header::decode(&out), Ok(h));
    let response = Header {
        response: true,
        ..h
    };
    response.encode(&mut out).unwrap();
    assert_eq!(out[7], 0x80);
    assert_eq!(Header::decode(&out), Ok(response));
}
#[test]
fn fragmented_rpc_consumes_one_message_and_retains_suffix() {
    let mut buffer = Box::new([0; wire::MAX_FRAME]);
    let mut decoder = Decoder::new(&mut buffer);
    let mut frame = [0; 101];
    header().encode(&mut frame[..96]).unwrap();
    frame[96..].copy_from_slice(b"abcXY");
    for byte in &frame[..95] {
        assert_eq!(decoder.feed(&[*byte]).unwrap(), 1);
        assert!(decoder.message().is_none());
    }
    assert_eq!(decoder.feed(&frame[95..]).unwrap(), 4);
    assert_eq!(decoder.message().unwrap(), (header(), &b"abc"[..]));
    assert_eq!(decoder.feed(b"XY").unwrap(), 0);
    decoder.consume().unwrap();
    assert!(decoder.message().is_none());
}
#[test]
fn invalid_headers_poison_stream_and_never_allocate_body() {
    for byte in [0, 4, 8, 10, 14, 15] {
        let mut frame = [0; 96];
        header().encode(&mut frame).unwrap();
        frame[byte] = 0xff;
        let mut buffer = Box::new([0; wire::MAX_FRAME]);
        let mut decoder = Decoder::new(&mut buffer);
        assert!(decoder.feed(&frame).is_err());
        assert_eq!(decoder.feed(b"x"), Err(wire::Error::Poisoned));
        assert!(decoder.message().is_none());
    }
    for len in 0..96 {
        assert_eq!(Header::decode(&[0; 96][..len]), Err(wire::Error::Length));
    }
}
#[test]
fn replay_gate_checks_epochs_before_consuming_sequence() {
    let mut gate = ReplayGate::new(11, 9).unwrap();
    let h = Header {
        session_seq: 1,
        ..header()
    };
    assert_eq!(
        gate.accept(&Header {
            sender_boot: 10,
            session_seq: 100,
            ..h
        }),
        Err(wire::Error::Boot)
    );
    gate.accept(&h).unwrap();
    assert_eq!(gate.accept(&h), Err(wire::Error::Sequence));
    assert_eq!(
        gate.accept(&Header {
            kind: Kind::Hello,
            receiver_boot: 0,
            session_seq: 2,
            ..h
        }),
        Err(wire::Error::Boot)
    );
    gate.accept(&Header {
        session_seq: u64::MAX,
        ..h
    })
    .unwrap();
    assert_eq!(
        gate.accept(&Header {
            session_seq: 1,
            ..h
        }),
        Err(wire::Error::Sequence)
    );
}
#[test]
fn only_first_hello_may_omit_receiver_boot() {
    let mut gate = ReplayGate::new(11, 9).unwrap();
    let h = Header {
        kind: Kind::Hello,
        receiver_boot: 0,
        session_seq: 1,
        ..header()
    };
    gate.accept(&h).unwrap();
    assert_eq!(
        gate.accept(&Header {
            session_seq: 2,
            ..h
        }),
        Err(wire::Error::Boot)
    );
}
