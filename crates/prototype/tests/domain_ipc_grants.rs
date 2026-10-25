use cyxia_prototype::domains::{
    Error, ObjectKey, POLICY_NS, PolicyStamp,
    tasks::{Ipc, IpcBackend, IpcOperation, Message, WaitResult},
};
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn stamp(version: u64, now: u64) -> PolicyStamp {
    PolicyStamp::new(version, now, now).unwrap()
}
#[derive(Default)]
struct Backend {
    denied: bool,
    fail_notify: bool,
    fail_deliver: bool,
    notices: usize,
    messages: Vec<(u64, u64, Vec<u8>)>,
}
impl<const B: usize> IpcBackend<B> for Backend {
    fn authorize(&mut self, _: ObjectKey, _: ObjectKey, _: IpcOperation) -> Result<(), Error> {
        if self.denied {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }
    fn notify(&mut self, _: ObjectKey, _: ObjectKey) -> Result<(), Error> {
        self.notices += 1;
        if self.fail_notify {
            Err(Error::Again)
        } else {
            Ok(())
        }
    }
    fn deliver(&mut self, _: ObjectKey, _: ObjectKey, m: &Message<B>) -> Result<(), Error> {
        if self.fail_deliver {
            return Err(Error::Io);
        }
        self.messages
            .push((m.sequence, m.request_id, m.bytes[..m.len].to_vec()));
        Ok(())
    }
}

#[test]
fn grant_occupies_backed_cell_without_manufacturing_a_message() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let endpoint = ipc.open(key(1), false).unwrap();
    ipc.install(endpoint, 8, 1, stamp(1, 0), 0).unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(0));
    let a = ipc.reserve_send(key(2), endpoint, 1, 0, &mut b).unwrap();
    let c = ipc.reserve_send(key(2), endpoint, 2, 0, &mut b).unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(1));
    let stats = ipc.stats(endpoint).unwrap();
    assert_eq!(
        (stats.depth, stats.reserved, stats.admitted, stats.delivered),
        (0, 2, 0, 0)
    );
    assert_eq!(b.notices, 0);
    for id in 3..=8 {
        ipc.send(key(3), endpoint, id, &[id as u8], 0, &mut b)
            .unwrap();
    }
    assert_eq!(
        ipc.send(key(3), endpoint, 9, b"x", 0, &mut b),
        Err(Error::Again)
    );
    assert_eq!(
        ipc.reserve_send(key(3), endpoint, 9, 0, &mut b),
        Err(Error::Again)
    );
    // The held physical cells precede the normal cells in backing storage;
    // FIFO delivery follows successful enqueue order, not physical cell order.
    assert_eq!(ipc.send_reserved(a, 1, b"first", 0, &mut b), Ok(7));
    assert_eq!(ipc.send_reserved(c, 2, b"second", 0, &mut b), Ok(8));
    assert_eq!(
        (
            ipc.stats(endpoint).unwrap().depth,
            ipc.stats(endpoint).unwrap().reserved
        ),
        (8, 0)
    );
    for _ in 0..8 {
        assert_eq!(ipc.receive_batch(key(1), endpoint, 1, &mut b), Ok(1));
    }
    assert_eq!(
        b.messages.iter().map(|m| m.1).collect::<Vec<_>>(),
        vec![3, 4, 5, 6, 7, 8, 1, 2]
    );
    assert_eq!(&b.messages[6].2, b"first");
    assert_eq!(&b.messages[7].2, b"second");
}

#[test]
fn reservation_identity_never_reallocates_a_consumed_or_cancelled_ticket() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    let a = ipc.reserve_send(key(2), ep, 10, 0, &mut b).unwrap();
    assert_eq!(ipc.reserve_send(key(2), ep, 10, 0, &mut b), Ok(a));
    assert_eq!(ipc.stats(ep).unwrap().reserved, 1);
    assert_eq!(
        ipc.send(key(2), ep, 10, b"x", 0, &mut b),
        Err(Error::Conflict)
    );
    assert_eq!(
        ipc.wait_send(key(2), ep, 10, b"x", 0, &mut b),
        Err(Error::Conflict)
    );
    ipc.cancel_send(a).unwrap();
    assert_eq!(ipc.cancel_send(a), Err(Error::Stale));
    assert_eq!(
        ipc.reserve_send(key(2), ep, 10, 0, &mut b),
        Err(Error::Stale)
    );
    let next = ipc.reserve_send(key(2), ep, 11, 0, &mut b).unwrap();
    assert_ne!(a, next);
    assert_eq!(
        ipc.send_reserved(a, 10, b"stale", 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(ipc.send_reserved(next, 11, b"once", 0, &mut b), Ok(1));
    assert_eq!(
        ipc.send_reserved(next, 11, b"twice", 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(ipc.cancel_send(next), Err(Error::Stale));
    assert_eq!(
        ipc.reserve_send(key(2), ep, 11, 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(ipc.stats(ep).unwrap().depth, 1);
    ipc.receive_batch(key(1), ep, 0, &mut b).unwrap();
    assert_eq!(b.messages, vec![(1, 11, b"once".to_vec())]);
}

#[test]
fn shrink_and_expiry_do_not_confiscate_128_reserved_cells() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 128, 16, stamp(1, 0), 0).unwrap();
    let grants: Vec<_> = (1..=128)
        .map(|id| ipc.reserve_send(key(2), ep, id, 0, &mut b).unwrap())
        .collect();
    ipc.install(ep, 8, 1, stamp(2, 1), 1).unwrap();
    assert_eq!(ipc.policy_receipt(ep), Ok(1));
    assert_eq!(
        ipc.reserve_send(key(2), ep, 129, 1, &mut b),
        Err(Error::Again)
    );
    let expired = POLICY_NS + 1;
    for (i, grant) in grants.into_iter().enumerate() {
        assert_eq!(
            ipc.send_reserved(grant, i as u64 + 1, &[i as u8], expired, &mut b),
            Ok(i as u64 + 1)
        );
    }
    assert_eq!(ipc.stats(ep).unwrap().depth, 128);
    assert_eq!(ipc.stats(ep).unwrap().reserved, 0);
    assert_eq!(ipc.policy_receipt(ep), Ok(1));
    assert_eq!(
        ipc.send(key(3), ep, 1, b"new", expired, &mut b),
        Err(Error::Again)
    );
    while ipc.stats(ep).unwrap().depth != 0 {
        ipc.receive_batch(key(1), ep, expired, &mut b).unwrap();
    }
    assert_eq!(b.messages.len(), 128);
    assert!(
        b.messages
            .iter()
            .enumerate()
            .all(|(i, m)| m.0 == i as u64 + 1 && m.2 == [i as u8])
    );
}

#[test]
fn validation_failures_retain_the_grant_and_notice_failure_retains_the_message() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    let grant = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    assert_eq!(
        ipc.send_reserved(grant, 2, b"x", 0, &mut b),
        Err(Error::Conflict)
    );
    assert_eq!(
        ipc.send_reserved(grant, 1, &[0; 9], 0, &mut b),
        Err(Error::Range)
    );
    b.denied = true;
    assert_eq!(
        ipc.send_reserved(grant, 1, b"x", 0, &mut b),
        Err(Error::Auth)
    );
    assert_eq!(ipc.stats(ep).unwrap().reserved, 1);
    b.denied = false;
    b.fail_notify = true;
    assert_eq!(ipc.send_reserved(grant, 1, b"x", 0, &mut b), Ok(1));
    assert_eq!(ipc.stats(ep).unwrap().notifications, 0);
    b.fail_deliver = true;
    assert_eq!(ipc.receive_batch(key(1), ep, 1, &mut b), Err(Error::Io));
    assert_eq!(ipc.stats(ep).unwrap().depth, 1);
    assert_eq!(ipc.cancel_send(grant), Err(Error::Stale));
    b.fail_deliver = false;
    b.fail_notify = false;
    ipc.flush_notifications(&mut b);
    assert_eq!(ipc.stats(ep).unwrap().notifications, 1);
    assert_eq!(ipc.receive_batch(key(1), ep, 2, &mut b), Ok(1));
}

#[test]
fn older_grant_cannot_credit_or_erase_a_newer_policy_version() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 8, 1, stamp(1, 0), 0).unwrap();
    let a = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    ipc.install(ep, 32, 4, stamp(2, 1), 1).unwrap();
    assert_eq!(ipc.reserve_send(key(2), ep, 1, 1, &mut b), Ok(a));
    assert_eq!(ipc.policy_receipt(ep), Ok(1));
    let next = ipc.reserve_send(key(2), ep, 2, 1, &mut b).unwrap();
    assert_eq!(ipc.policy_receipt(ep), Ok(2));
    ipc.send_reserved(a, 1, b"old", 2, &mut b).unwrap();
    assert_eq!(ipc.policy_receipt(ep), Ok(2));
    ipc.cancel_send(next).unwrap();
    assert_eq!(ipc.stats(ep).unwrap().reserved, 0);
}

#[test]
fn endpoint_and_actor_retirement_release_only_their_unconsumed_cells() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    let own = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    let peer = ipc.reserve_send(key(3), ep, 1, 0, &mut b).unwrap();
    ipc.exit(key(2), &mut b);
    assert_eq!(ipc.stats(ep).unwrap().reserved, 1);
    assert_eq!(
        ipc.send_reserved(own, 1, b"x", 0, &mut b),
        Err(Error::Stale)
    );
    ipc.send_reserved(peer, 1, b"peer", 0, &mut b).unwrap();
    let held = ipc.reserve_send(key(3), ep, 2, 0, &mut b).unwrap();
    ipc.close(key(1), ep, &mut b).unwrap();
    let replacement = ipc.open(key(4), false).unwrap();
    assert_eq!(replacement.id, ep.id);
    assert_ne!(replacement.generation, ep.generation);
    assert_eq!(
        ipc.send_reserved(held, 2, b"x", 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(ipc.receive_batch(key(4), replacement, 0, &mut b), Ok(0));
    assert!(b.messages.is_empty());
}

#[test]
fn pending_waiters_use_only_unreserved_capacity() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 8, 1, stamp(1, 0), 0).unwrap();
    let a = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    let second = ipc.reserve_send(key(2), ep, 2, 0, &mut b).unwrap();
    for id in 3..=8 {
        ipc.send(key(3), ep, id, b"sent", 0, &mut b).unwrap();
    }
    let wait = ipc.wait_send(key(3), ep, 9, b"wait", 0, &mut b).unwrap();
    assert_eq!(ipc.wait_result(wait), Ok(WaitResult::Pending));
    assert_eq!(
        ipc.reserve_send(key(4), ep, 1, 0, &mut b),
        Err(Error::Again)
    );
    ipc.receive_batch(key(1), ep, 1, &mut b).unwrap();
    assert_eq!(ipc.wait_result(wait), Ok(WaitResult::Sent(7)));
    assert_eq!(ipc.stats(ep).unwrap().reserved, 2);
    assert_eq!(ipc.send_reserved(a, 1, b"held1", 1, &mut b), Ok(8));
    assert_eq!(ipc.send_reserved(second, 2, b"held2", 1, &mut b), Ok(9));
    assert_eq!(ipc.stats(ep).unwrap().depth, 8);
}

#[test]
fn grant_pool_capacity_is_explicit_and_reclaimed_without_aba() {
    let mut ipc = Box::new(Ipc::<1>::new());
    let mut b = Backend::default();
    let endpoints: Vec<_> = (1..=5)
        .map(|id| ipc.open(key(id), false).unwrap())
        .collect();
    let mut grants = Vec::new();
    for ep in &endpoints[..4] {
        for id in 1..=32 {
            grants.push(ipc.reserve_send(key(20), *ep, id, 0, &mut b).unwrap());
        }
    }
    assert_eq!(
        ipc.reserve_send(key(20), endpoints[4], 1, 0, &mut b),
        Err(Error::Capacity)
    );
    let old = grants[0];
    ipc.cancel_send(old).unwrap();
    let new = ipc
        .reserve_send(key(20), endpoints[4], 1, 0, &mut b)
        .unwrap();
    assert_ne!(old, new);
    assert_eq!(
        ipc.send_reserved(old, 1, &[1], 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(ipc.send_reserved(new, 1, &[2], 0, &mut b), Ok(1));
}

#[test]
fn bound_validation_requires_a_live_cell_and_current_authority_not_current_policy() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    let baseline = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    assert_eq!(baseline.policy_version(), 0);
    assert_eq!(ipc.validate_send_grant(baseline, key(2), ep, &mut b), Ok(0));
    ipc.cancel_send(baseline).unwrap();
    assert_eq!(
        ipc.validate_send_grant(baseline, key(2), ep, &mut b),
        Err(Error::Stale)
    );
    ipc.install(ep, 128, 16, stamp(1, 1), 1).unwrap();
    let held = ipc.reserve_send(key(2), ep, 2, 1, &mut b).unwrap();
    assert_eq!(held.policy_version(), 1);
    ipc.install(ep, 8, 1, stamp(2, 2), 2).unwrap();
    assert_eq!(ipc.validate_send_grant(held, key(2), ep, &mut b), Ok(1));
    assert_eq!(
        ipc.validate_send_grant(held, key(3), ep, &mut b),
        Err(Error::Auth)
    );
    let other = ipc.open(key(4), false).unwrap();
    assert_eq!(
        ipc.validate_send_grant(held, key(2), other, &mut b),
        Err(Error::Auth)
    );
    b.denied = true;
    assert_eq!(
        ipc.validate_send_grant(held, key(2), ep, &mut b),
        Err(Error::Auth)
    );
    b.denied = false;
    assert_eq!(
        ipc.send_reserved(held, 2, b"old", POLICY_NS + 2, &mut b),
        Ok(1)
    );
    assert_eq!(
        ipc.validate_send_grant(held, key(2), ep, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(held.policy_version(), 1); // historical data is not a live permit
}

#[test]
fn exact_root_confirmation_survives_new_pending_without_acknowledging_it() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    let baseline = ipc.reserve_send(key(2), ep, 1, 0, &mut b).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(baseline, key(2), ep, &mut b),
        Ok(0)
    );
    ipc.install(ep, 8, 1, stamp(1, 1), 1).unwrap();
    assert_eq!(ipc.confirm_policy_version(ep, 1), Err(Error::NotReady));
    let first = ipc.reserve_send(key(2), ep, 2, 1, &mut b).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(first, key(2), ep, &mut b),
        Err(Error::NotReady)
    );
    assert_eq!(ipc.policy_receipt(ep), Ok(1));
    ipc.confirm_policy_version(ep, 1).unwrap();
    ipc.confirm_policy_version(ep, 1).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(first, key(2), ep, &mut b),
        Ok(1)
    );
    let inherited = ipc.reserve_send(key(2), ep, 3, 1, &mut b).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(inherited, key(2), ep, &mut b),
        Ok(1)
    );
    ipc.install(ep, 32, 4, stamp(2, 2), 2).unwrap();
    let pending = ipc.reserve_send(key(2), ep, 4, 2, &mut b).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(pending, key(2), ep, &mut b),
        Err(Error::NotReady)
    );
    assert_eq!(
        ipc.validate_confirmed_send_grant(first, key(2), ep, &mut b),
        Ok(1)
    );
    assert_eq!(
        ipc.validate_confirmed_send_grant(baseline, key(2), ep, &mut b),
        Ok(0)
    );
    ipc.send_reserved(first, 2, b"old", POLICY_NS + 2, &mut b)
        .unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(first, key(2), ep, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(
        ipc.validate_confirmed_send_grant(inherited, key(2), ep, &mut b),
        Ok(1)
    );
    ipc.cancel_send(inherited).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(inherited, key(2), ep, &mut b),
        Err(Error::Stale)
    );
}

#[test]
fn a_higher_execution_does_not_confirm_an_unexecuted_version_hole() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 8, 1, stamp(1, 1), 1).unwrap();
    let old = ipc.reserve_send(key(2), ep, 1, 1, &mut b).unwrap();
    ipc.install(ep, 32, 4, stamp(2, 2), 2).unwrap();
    ipc.install(ep, 64, 8, stamp(3, 3), 3).unwrap();
    let newer = ipc.reserve_send(key(2), ep, 2, 3, &mut b).unwrap();
    assert_eq!(ipc.policy_receipt(ep), Ok(3));
    assert_eq!(ipc.confirm_policy_version(ep, 2), Err(Error::NotReady));
    ipc.confirm_policy_version(ep, 3).unwrap();
    ipc.confirm_policy_version(ep, 1).unwrap(); // exact old custody is still present
    assert_eq!(
        ipc.validate_confirmed_send_grant(old, key(2), ep, &mut b),
        Ok(1)
    );
    assert_eq!(
        ipc.validate_confirmed_send_grant(newer, key(2), ep, &mut b),
        Ok(3)
    );
    let inherited = ipc.reserve_send(key(2), ep, 3, 3, &mut b).unwrap();
    assert_eq!(
        ipc.validate_confirmed_send_grant(inherited, key(2), ep, &mut b),
        Ok(3)
    );
}

#[test]
fn cancelling_a_reserved_only_queue_releases_waiters_without_a_policy_or_receive_event() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Backend::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 8, 1, stamp(1, 0), 0).unwrap();
    let mut held = Vec::new();
    for request in 1..=8 {
        held.push(ipc.reserve_send(key(2), ep, request, 0, &mut b).unwrap());
    }
    let waiter = ipc.wait_send(key(3), ep, 1, b"ready", 0, &mut b).unwrap();
    assert_eq!(ipc.wait_result(waiter), Ok(WaitResult::Pending));
    assert_eq!(ipc.stats(ep).unwrap().depth, 0);
    ipc.cancel_send(held[0]).unwrap();
    // The native owner calls this from its bounded independent service pump,
    // including when no receiver/message/model event exists to drive progress.
    ipc.service_waiters(ep, 1, &mut b).unwrap();
    assert_eq!(ipc.wait_result(waiter), Ok(WaitResult::Sent(1)));
    assert_eq!(ipc.stats(ep).unwrap().reserved, 7);
    assert_eq!(ipc.stats(ep).unwrap().depth, 1);
    assert_eq!(ipc.receive_batch(key(1), ep, 1, &mut b), Ok(1));
    assert_eq!(b.messages, vec![(1, 1, b"ready".to_vec())]);
}
