use cyxia_prototype::domains::{
    Action, Error, ObjectKey, PolicyStamp,
    io::{Class, ORDINARY_BYTES, Request, Scheduler, Submission},
};

fn request(class: Class) -> Request {
    Request {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        class,
        bytes: 4096,
        pages: 1,
        descriptors: 1,
    }
}
fn scheduled(share: u16) -> Scheduler {
    let mut scheduler = Scheduler::new(32, 32);
    scheduler
        .apply(
            Action::IoShare(share),
            PolicyStamp::new(1, 0, 0).unwrap(),
            0,
        )
        .unwrap();
    scheduler.set_upstream_demand(true, true);
    scheduler
}
fn transfer(s: &mut Scheduler, class: Class) -> bool {
    let ticket = s.enqueue(request(class), 2).unwrap();
    let mut submitted = 0;
    let actual = s
        .dispatch(
            2,
            |_, _| true,
            |t, r| {
                assert_eq!(t, ticket);
                assert_eq!(r.class, class);
                submitted += 1;
                Submission::Accepted
            },
        )
        .unwrap();
    if actual.is_none() {
        assert_eq!(submitted, 0);
        s.cancel(ticket).unwrap();
        return false;
    }
    assert_eq!(submitted, 1);
    s.complete(ticket, Ok(()), 2).unwrap();
    let receipt = s.acknowledge(ticket).unwrap();
    assert_eq!(
        receipt.policy_version,
        if class == Class::Recovery { 0 } else { 1 }
    );
    true
}
fn transfer_until_blocked(s: &mut Scheduler, class: Class) -> u64 {
    let mut bytes = 0;
    // Only one class is in the DMA queue at a time, as in the native broker.
    while transfer(s, class) {
        bytes += 4096;
        assert!(bytes <= ORDINARY_BYTES);
    }
    bytes
}

#[test]
fn sequential_native_style_queues_respect_actual_opposite_backlogs() {
    for share in [250, 750] {
        let mut io = scheduled(share);
        let background = ORDINARY_BYTES * u64::from(share) / 1000;
        assert_eq!(
            transfer_until_blocked(&mut io, Class::Foreground),
            ORDINARY_BYTES - background
        );
        assert_eq!(
            transfer_until_blocked(&mut io, Class::Background),
            background
        );
        assert_eq!(io.usage().borrowed_foreground_bytes, 0);
        assert_eq!(io.usage().borrowed_background_bytes, 0);
        assert!(transfer(&mut io, Class::Recovery));
        assert_eq!(io.usage().recovery_bytes, 4096);
        assert_eq!(io.usage().ordinary_credits, 0);
    }
}

#[test]
fn only_proved_idle_opposite_upstream_allows_new_byte_borrowing() {
    let mut io = scheduled(250);
    assert_eq!(
        transfer_until_blocked(&mut io, Class::Foreground),
        ORDINARY_BYTES * 3 / 4
    );
    io.set_upstream_demand(true, false);
    assert_eq!(
        transfer_until_blocked(&mut io, Class::Foreground),
        ORDINARY_BYTES / 4
    );
    assert_eq!(io.usage().borrowed_foreground_bytes, ORDINARY_BYTES / 4);
    io.set_upstream_demand(false, false);
    assert!(!transfer(&mut io, Class::Background)); // Demand never resets spent bytes.
}

#[test]
fn transaction_reservation_sees_upstream_before_any_descriptor_exists() {
    let mut io = scheduled(250);
    assert_eq!(
        io.reserve_transaction(Class::Background, ORDINARY_BYTES / 2, 1),
        Err(Error::Budget)
    );
    assert_eq!(io.reserved_bytes(), 0);
    assert_eq!(io.usage().pages, 0);
    io.set_upstream_demand(false, true);
    let grant = io
        .reserve_admission(request(Class::Background), ORDINARY_BYTES / 2, 1, 1)
        .unwrap();
    assert_eq!(io.usage().ordinary_credits, 1);
    assert_eq!(io.stats().submitted, 0);
    // A later foreground arrival cannot confiscate this granted transaction.
    io.set_upstream_demand(true, true);
    io.begin_admission(grant, 4096).unwrap();
    let ticket = io
        .activate_admission(grant, request(Class::Background), 1)
        .unwrap();
    assert_eq!(
        io.dispatch(1, |_, _| true, |_, _| Submission::Unknown)
            .unwrap(),
        Some(ticket)
    );
    let held = io.usage();
    io.set_upstream_demand(false, false);
    assert_eq!(io.cancel_admission(grant), Err(Error::Busy));
    assert_eq!(io.finish_transaction(grant.permit), Err(Error::Busy));
    assert_eq!(io.usage(), held);
    io.complete(ticket, Ok(()), 2).unwrap();
    assert_eq!(io.acknowledge(ticket).unwrap().policy_version, 1);
    io.finish_transaction(grant.permit).unwrap();
    assert_eq!(io.usage().ordinary_credits, 0);
}

#[test]
fn an_empty_upstream_signal_cannot_hide_an_actual_queued_competitor() {
    let mut io = scheduled(250);
    assert_eq!(
        transfer_until_blocked(&mut io, Class::Foreground),
        ORDINARY_BYTES * 3 / 4
    );
    io.set_upstream_demand(false, false);
    let foreground = io.enqueue(request(Class::Foreground), 2).unwrap();
    let background = io.enqueue(request(Class::Background), 2).unwrap();
    assert_eq!(
        io.dispatch(2, |_, _| true, |_, _| Submission::Accepted)
            .unwrap(),
        Some(background)
    );
    io.complete(background, Ok(()), 2).unwrap();
    io.acknowledge(background).unwrap();
    io.cancel(foreground).unwrap();
}
