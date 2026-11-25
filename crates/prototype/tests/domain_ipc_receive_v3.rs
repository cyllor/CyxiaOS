use cyxia_prototype::domains::{Error, ObjectKey, tasks::*};
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
#[derive(Default)]
struct Backend {
    deny: bool,
}
impl<const B: usize> IpcBackend<B> for Backend {
    fn authorize(&mut self, _: ObjectKey, _: ObjectKey, _: IpcOperation) -> Result<(), Error> {
        if self.deny { Err(Error::Auth) } else { Ok(()) }
    }
    fn notify(&mut self, _: ObjectKey, _: ObjectKey) -> Result<(), Error> {
        Ok(())
    }
    fn deliver(&mut self, _: ObjectKey, _: ObjectKey, _: &Message<B>) -> Result<(), Error> {
        panic!("v3 must never use the legacy direct delivery path")
    }
}
fn enqueue(q: &mut IpcV3<8>, ep: ObjectKey, seq: u64, bytes: &[u8], b: &mut Backend) {
    let g = q.reserve_send(key(2), ep, seq, 0, b).unwrap();
    q.send_reserved(g, seq, bytes, 0, b).unwrap();
}
#[test]
fn actual_fifo_copy_fault_and_lost_return_never_dequeue_twice() {
    let mut q = Box::new(IpcV3::<8>::new());
    let mut b = Backend::default();
    let ep = q.open(key(1)).unwrap();
    assert_eq!(
        q.prepare(key(1), ep, 1, 552, 0, &mut b, || panic!(
            "empty head reserved credit"
        )),
        Err(Error::Again)
    );
    enqueue(&mut q, ep, 1, b"first", &mut b);
    enqueue(&mut q, ep, 2, b"second", &mut b);
    assert_eq!(
        q.prepare(key(1), ep, 2, 552, 0, &mut b, || panic!("sequence gap")),
        Err(Error::Again)
    );
    assert_eq!(
        q.prepare(key(3), ep, 1, 552, 0, &mut b, || panic!("wrong holder")),
        Err(Error::Auth)
    );
    assert_eq!(
        q.prepare(key(1), ep, 1, 551, 0, &mut b, || panic!("short output")),
        Err(Error::Range)
    );
    assert_eq!(
        q.prepare(key(1), ep, 1, 552, 0, &mut b, || Err(Error::Capacity)),
        Err(Error::Capacity)
    );
    let ticket = q
        .prepare(key(1), ep, 1, 552, 0, &mut b, || Ok(7))
        .unwrap()
        .ticket();
    let mut frame = [0; 552];
    let first_copy = q.stage(ticket, &mut frame, &mut b).unwrap();
    let length = first_copy.len();
    assert_eq!(q.stage(ticket, &mut [0; 552], &mut b), Err(Error::Busy));
    assert_eq!(length, 45);
    assert_eq!(&frame[40..45], b"first");
    assert_eq!(u64::from_le_bytes(frame[0..8].try_into().unwrap()), 2);
    assert_eq!(
        u64::from_le_bytes(frame[24..32].try_into().unwrap()),
        ep.generation
    );
    assert_eq!(
        q.commit_copied(first_copy, length - 1, 0, &mut b),
        Err(Error::Range)
    );
    assert_eq!(q.stats(ep).unwrap().depth, 2);
    assert_eq!(
        q.ack(key(1), ep, 1, &mut b, |_| panic!("not DONE")),
        Err(Error::Busy)
    );
    assert_eq!(
        q.prepare(key(1), ep, 1, 552, 0, &mut b, || panic!("duplicate credit")),
        Ok(ReceivePrepared::Existing(ticket))
    );
    b.deny = true;
    assert_eq!(
        q.commit_copied(first_copy, length, 0, &mut b),
        Err(Error::Auth)
    );
    b.deny = false;
    q.abort_copy(first_copy).unwrap();
    assert_eq!(q.abort_copy(first_copy), Err(Error::Stale));
    let mut retry = [0; 552];
    let second_copy = q.stage(ticket, &mut retry, &mut b).unwrap();
    assert_ne!(first_copy, second_copy);
    assert_eq!(retry, frame);
    assert_eq!(
        q.commit_copied(first_copy, length, 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(q.commit_copied(second_copy, length, 0, &mut b), Ok(length));
    // A lost return replays the retained DONE bytes under a new lease.
    let replay = q.stage(ticket, &mut retry, &mut b).unwrap();
    assert_eq!(retry, frame);
    assert_eq!(
        q.ack(key(1), ep, 1, &mut b, |_| panic!("copy still active")),
        Err(Error::Busy)
    );
    assert_eq!(q.commit_copied(replay, length, 0, &mut b), Ok(length));
    assert_eq!(
        q.commit_copied(replay, length, 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(q.stats(ep).unwrap().depth, 1);
    assert_eq!(
        q.prepare(key(1), ep, 2, 552, 0, &mut b, || panic!("unacked")),
        Err(Error::Busy)
    );
    assert_eq!(
        q.ack(key(1), ep, 1, &mut b, |_| Err(Error::Busy)),
        Err(Error::Busy)
    );
    q.ack(key(1), ep, 1, &mut b, |credit| {
        assert_eq!(credit, 7);
        Ok(())
    })
    .unwrap();
    q.ack(key(1), ep, 1, &mut b, |_| panic!("duplicate release"))
        .unwrap();
    assert_eq!(
        q.prepare(key(1), ep, 1, 552, 0, &mut b, || panic!("old seq")),
        Err(Error::Stale)
    );
    let second = q
        .prepare(key(1), ep, 2, 552, 0, &mut b, || Ok(8))
        .unwrap()
        .ticket();
    let copy = q.stage(second, &mut retry, &mut b).unwrap();
    assert_eq!(copy.len(), 46);
    assert_eq!(&retry[40..46], b"second");
    q.commit_copied(copy, 46, 0, &mut b).unwrap();
    q.ack(key(1), ep, 2, &mut b, |credit| {
        assert_eq!(credit, 8);
        Ok(())
    })
    .unwrap();
    assert_eq!(q.stats(ep).unwrap().delivered, 2);
}
#[test]
fn closed_holder_cannot_erase_reserved_or_done_custody() {
    for done in [false, true] {
        let mut q = Box::new(IpcV3::<8>::new());
        let mut b = Backend::default();
        let ep = q.open(key(1)).unwrap();
        enqueue(&mut q, ep, 1, b"x", &mut b);
        let t = q
            .prepare(key(1), ep, 1, 552, 0, &mut b, || Ok(9))
            .unwrap()
            .ticket();
        let copy = q.stage(t, &mut [0; 552], &mut b).unwrap();
        if done {
            q.commit_copied(copy, 41, 0, &mut b).unwrap();
        }
        let active = if done {
            q.stage(t, &mut [0; 552], &mut b).unwrap()
        } else {
            copy
        };
        q.close_admission(key(1), ep).unwrap();
        assert_eq!(q.stage(t, &mut [0; 552], &mut b), Err(Error::Stale));
        assert_eq!(q.reserve_send(key(2), ep, 2, 0, &mut b), Err(Error::Stale));
        assert_eq!(q.close_empty(key(1), ep, &mut b), Err(Error::Busy));
        assert_eq!(
            q.retire_closed(ep, false, true, |_| panic!("not stopped")),
            Err(Error::Busy)
        );
        assert_eq!(
            q.retire_closed(ep, true, true, |_| panic!("copy not joined")),
            Err(Error::Busy)
        );
        assert_eq!(q.commit_copied(active, 41, 0, &mut b), Err(Error::Stale));
        q.abort_copy(active).unwrap();
        if done {
            assert_eq!(
                q.retire_closed(ep, true, false, |_| panic!("not audited")),
                Err(Error::Busy)
            );
        }
        q.retire_closed(ep, true, done, |credit| {
            assert_eq!(credit, 9);
            Ok(())
        })
        .unwrap();
        assert_eq!(q.stats(ep).unwrap().depth, usize::from(!done));
        if done {
            q.close_empty(key(1), ep, &mut b).unwrap();
            let next = q.open(key(3)).unwrap();
            assert_eq!(next.id, ep.id);
            assert_ne!(next.generation, ep.generation);
            assert_eq!(q.stage(t, &mut [0; 552], &mut b), Err(Error::Stale));
        } else {
            assert_eq!(q.close_empty(key(1), ep, &mut b), Err(Error::Busy));
        }
    }
}
