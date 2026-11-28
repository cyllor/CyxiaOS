use cyxia_prototype::domains::{
    Error, ObjectKey,
    io::{COMPLETION_CREDITS, Class, Request, Scheduler, Submission},
};
use std::{
    sync::{Barrier, Mutex},
    thread,
};

#[test]
fn ordinary_saturation_preserves_recovery_io_and_terminal_custody() {
    let credits = u32::from(COMPLETION_CREDITS);
    let capacity = credits * 4;
    let io = Mutex::new(Scheduler::new(capacity, capacity));
    let ordinary = Request {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        class: Class::Foreground,
        bytes: 3 * 4096,
        pages: 3,
        descriptors: 3,
    };
    let recovery = Request {
        class: Class::Recovery,
        bytes: 4096,
        pages: 1,
        descriptors: 1,
        ..ordinary
    };
    let normal_tickets: Vec<_> = {
        let mut io = io.lock().unwrap();
        let mut tickets: Vec<_> = (0..credits - 1)
            .map(|_| io.enqueue(ordinary, 0).unwrap())
            .collect();
        let usage = io.usage();
        assert_eq!(usage.ordinary_credits, COMPLETION_CREDITS - 1);
        let crosses_dma_reserve = Request {
            bytes: 4 * 4096,
            pages: 4,
            ..ordinary
        };
        let crosses_descriptor_reserve = Request {
            descriptors: 4,
            ..ordinary
        };
        assert_eq!(io.enqueue(crosses_dma_reserve, 0), Err(Error::Again));
        assert_eq!(io.enqueue(crosses_descriptor_reserve, 0), Err(Error::Again));
        assert_eq!(io.usage(), usage);
        tickets.push(io.enqueue(ordinary, 0).unwrap());
        // Keep ordinary queued, pending, unknown and completed work in the
        // owner together. Each state must continue to hold completion credit.
        for (offset, &ticket) in tickets.iter().take(tickets.len() * 3 / 4).enumerate() {
            let submission = if offset % 3 == 0 {
                Submission::Unknown
            } else {
                Submission::Accepted
            };
            assert_eq!(
                io.dispatch(1, |_, _| true, |_, _| submission).unwrap(),
                Some(ticket)
            );
            if offset % 3 == 1 {
                io.complete(ticket, Ok(()), 1).unwrap();
            }
        }
        let usage = io.usage();
        assert_eq!(usage.ordinary_credits, COMPLETION_CREDITS);
        assert_eq!(usage.queued, COMPLETION_CREDITS / 4);
        assert_eq!(usage.completed, COMPLETION_CREDITS / 4);
        assert_eq!(usage.inflight, COMPLETION_CREDITS / 2);
        assert_eq!((usage.pages, usage.descriptors), (3 * credits, 3 * credits));
        tickets
    };

    let start = Barrier::new(2);
    let recovery_tickets = thread::scope(|scope| {
        let ordinary_producer = scope.spawn(|| {
            start.wait();
            for _ in 0..credits {
                let mut io = io.lock().unwrap();
                assert_eq!(io.enqueue(ordinary, 1), Err(Error::Again));
                assert_eq!(io.acknowledge(normal_tickets[0]), Err(Error::Busy));
            }
        });
        let recovery_producer = scope.spawn(|| {
            start.wait();
            (0..credits)
                .map(|_| {
                    let mut io = io.lock().unwrap();
                    let ticket = io.enqueue(recovery, 1).unwrap();
                    assert_eq!(
                        io.dispatch(1, |_, _| true, |_, _| Submission::Accepted)
                            .unwrap(),
                        Some(ticket)
                    );
                    io.complete(ticket, Ok(()), 1).unwrap();
                    ticket
                })
                .collect::<Vec<_>>()
        });
        ordinary_producer.join().unwrap();
        recovery_producer.join().unwrap()
    });

    let mut io = io.into_inner().unwrap();
    let usage = io.usage();
    assert_eq!(usage.ordinary_credits, COMPLETION_CREDITS);
    assert_eq!(usage.recovery_credits, COMPLETION_CREDITS);
    assert_eq!((usage.pages, usage.descriptors), (capacity, capacity));
    assert_eq!(io.enqueue(recovery, 1), Err(Error::Again));
    assert_eq!(io.usage(), usage);
    let acknowledged = recovery_tickets[0];
    assert_eq!(io.acknowledge(acknowledged).unwrap().result, Ok(()));
    assert_eq!(io.enqueue(ordinary, 1), Err(Error::Again));
    let replacement = io.enqueue(recovery, 1).unwrap();
    assert_eq!(replacement.slot, acknowledged.slot);
    assert!(replacement.generation > acknowledged.generation);
    assert_eq!(io.acknowledge(acknowledged), Err(Error::Stale));
    assert_eq!(io.usage().ordinary_credits, COMPLETION_CREDITS);
    assert_eq!(io.usage().recovery_credits, COMPLETION_CREDITS);
    assert_eq!(
        io.completion(normal_tickets[1]).unwrap().unwrap().result,
        Ok(())
    );
    for ticket in recovery_tickets.into_iter().skip(1) {
        assert_eq!(io.acknowledge(ticket).unwrap().result, Ok(()));
    }
    io.cancel(replacement).unwrap();
    assert_eq!(io.usage().recovery_credits, 0);
    assert_eq!(io.usage().ordinary_credits, COMPLETION_CREDITS);
}
