//! Exercise the complete Tcp -> observation -> Ethernet -> Port path.
//! Component-only NIC tests cannot detect a wrapper swallowing safe points.
use cyxia_cluster_transport::{
    device::{Error as PortError, MTU, Port},
    tcp::{BUFFER_SIZE, Config, Error, Storage, Tcp},
};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    LegacyReceive,
    ReceiveBegin,
    Checkpoint,
    ReceiveEnd,
}
struct CheckpointPort {
    events: Rc<RefCell<Vec<Event>>>,
    fail: bool,
}
impl Port for CheckpointPort {
    fn send(&mut self, _: &[u8]) -> Result<(), PortError> {
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; MTU]) -> Result<Option<usize>, PortError> {
        self.events.borrow_mut().push(Event::LegacyReceive);
        if self.fail {
            Err(PortError::Device)
        } else {
            Ok(None)
        }
    }
    fn receive_with_checkpoint(
        &mut self,
        _: &mut [u8; MTU],
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, PortError> {
        self.events.borrow_mut().push(Event::ReceiveBegin);
        checkpoint();
        self.events.borrow_mut().push(Event::ReceiveEnd);
        if self.fail {
            Err(PortError::Device)
        } else {
            Ok(None)
        }
    }
    fn burst_capacity(&self) -> usize {
        8
    }
}
fn run(
    fail: bool,
) -> (
    Result<cyxia_cluster_transport::tcp::State, Error>,
    Vec<Event>,
) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let (mut rx, mut tx) = ([0; BUFFER_SIZE], [0; BUFFER_SIZE]);
    let mut storage = [Storage::EMPTY];
    let config = Config {
        mac: [2, 0, 0, 0, 0, 2],
        local: [10, 0, 0, 2],
        peer: [10, 0, 0, 1],
        prefix_len: 24,
        local_port: 8443,
        peer_port: 40001,
        random_seed: 0xf00dcafe,
    };
    let mut tcp = Tcp::new(
        CheckpointPort {
            events: events.clone(),
            fail,
        },
        config,
        0,
        &mut rx,
        &mut tx,
        &mut storage,
    )
    .unwrap();
    tcp.listen().unwrap();
    let result = tcp.poll_with_checkpoints(1, &mut || events.borrow_mut().push(Event::Checkpoint));
    if fail {
        assert_eq!(
            tcp.poll_with_checkpoints(2, &mut || panic!("failed stream resumed")),
            Err(Error::Closed)
        );
    }
    let events = events.borrow().clone();
    (result, events)
}
fn assert_forwarded(events: &[Event]) {
    assert!(
        !events.contains(&Event::LegacyReceive),
        "observation wrapper swallowed RX checkpoints: {events:?}"
    );
    let mut receives = 0;
    for (i, event) in events.iter().enumerate() {
        if *event == Event::ReceiveBegin {
            assert_eq!(
                events.get(i + 1..i + 3),
                Some(&[Event::Checkpoint, Event::ReceiveEnd][..])
            );
            receives += 1;
        }
    }
    assert!(receives > 0, "no real receive boundary exercised");
}
#[test]
fn tcp_observation_preserves_each_inner_receive_checkpoint() {
    let (result, events) = run(false);
    assert!(result.is_ok());
    assert_forwarded(&events);
}
#[test]
fn receive_error_preserves_checkpoints_and_poisoning_without_retry() {
    let (result, events) = run(true);
    assert_eq!(result, Err(Error::Device));
    assert_forwarded(&events);
    assert_eq!(
        events.iter().filter(|v| **v == Event::ReceiveBegin).count(),
        1
    );
}
