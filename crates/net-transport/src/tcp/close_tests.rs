extern crate std;
use super::*;
use crate::device::{self, MTU};
use std::{cell::RefCell, collections::VecDeque, rc::Rc, vec::Vec};

type Frames = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Wire {
    input: Frames,
    output: Frames,
    tx_done: bool,
}
impl Port for Wire {
    fn send(&mut self, frame: &[u8]) -> Result<(), device::Error> {
        self.output.borrow_mut().push_back(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, buf: &mut [u8; MTU]) -> Result<Option<usize>, device::Error> {
        Ok(self.input.borrow_mut().pop_front().map(|frame| {
            buf[..frame.len()].copy_from_slice(&frame);
            frame.len()
        }))
    }
    fn tx_quiescent(&self) -> bool {
        self.tx_done
    }
}

#[derive(PartialEq, Eq)]
enum End {
    FinAck,
    Reset,
    Timeout,
    Rejected,
}

fn exercise(end: End) {
    let a = Config {
        mac: [2, 0, 0, 0, 0, 1],
        local: [10, 0, 0, 1],
        peer: [10, 0, 0, 2],
        prefix_len: 24,
        local_port: 7,
        peer_port: 2001,
        random_seed: 3,
    };
    let b = Config {
        mac: [2, 0, 0, 0, 0, 2],
        local: a.peer,
        peer: a.local,
        local_port: a.peer_port,
        peer_port: a.local_port,
        random_seed: 4,
        ..a
    };
    let (ab, ba) = (Frames::default(), Frames::default());
    let server_port = Wire {
        input: ba.clone(),
        output: ab.clone(),
        tx_done: false,
    };
    let client_port = Wire {
        input: ab,
        output: ba,
        tx_done: true,
    };
    let (mut ar, mut at, mut sa) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE], [Storage::EMPTY]);
    let (mut br, mut bt, mut sb) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE], [Storage::EMPTY]);
    let mut server = Tcp::new(server_port, a, 0, &mut ar, &mut at, &mut sa).unwrap();
    let mut client = Tcp::new(client_port, b, 0, &mut br, &mut bt, &mut sb).unwrap();
    server.listen().unwrap();
    client.connect().unwrap();
    for ms in 0..20 {
        client.poll(ms).unwrap();
        server.poll(ms).unwrap();
    }
    assert_eq!(server.state(), Ok(State::Established));
    if end == End::Rejected {
        server.abort_rejected().unwrap();
        assert!(!server.relisten_open_after_rejection().unwrap());
        for ms in 20..30 {
            server.poll(ms).unwrap();
            client.poll(ms).unwrap();
        }
        assert_eq!(client.state(), Ok(State::Closed));
        assert!(!server.relisten_open_after_rejection().unwrap());
        server.port_mut().tx_done = true;
        assert!(server.relisten_open_after_rejection().unwrap());
        assert_eq!(server.state(), Ok(State::Listen));
        return;
    }
    client.sockets.get_mut::<Socket>(client.socket).close();
    client.poll(20).unwrap();
    assert_eq!(server.poll_passive_close(20), Ok(false));
    assert_eq!(server.state(), Ok(State::LastAck));
    match end {
        End::Reset => {
            client.close(21);
            assert_eq!(server.poll_passive_close(21), Err(Error::Closed));
            assert!(server.relisten_open_after_close().is_err());
        }
        End::Timeout => {
            assert_eq!(server.poll_passive_close(100_000), Err(Error::Closed));
            assert!(server.relisten_open_after_close().is_err());
        }
        End::FinAck => {
            for ms in 21..40 {
                client.poll(ms).unwrap();
                assert_eq!(server.poll_passive_close(ms), Ok(false));
            }
            assert_eq!(server.state(), Ok(State::Closed));
            assert_eq!(server.relisten_open_after_close(), Err(Error::WouldBlock));
            server.port_mut().tx_done = true;
            assert_eq!(server.poll_passive_close(40), Ok(true));
            assert_eq!(server.relisten_open_after_close(), Ok(()));
            assert_eq!(server.state(), Ok(State::Listen));
            assert_eq!(server.peer_ipv4(), None);
            assert!(server.relisten_open_after_close().is_err());
        }
        End::Rejected => unreachable!(),
    }
}

#[test]
fn passive_close_requires_a_fin_ack_and_empty_native_tx() {
    exercise(End::FinAck)
}
#[test]
fn passive_close_refuses_peer_reset_in_last_ack() {
    exercise(End::Reset)
}
#[test]
fn passive_close_refuses_socket_timeout_in_last_ack() {
    exercise(End::Timeout)
}

#[test]
fn pending_rejection_drains_local_reset_and_native_tx_before_relisten() {
    exercise(End::Rejected)
}
