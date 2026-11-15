use cyxia_arch_x86_64::dispatch::{Error, Handoff};
use std::sync::{Arc, mpsc};

// A producer must never recover or overwrite a context before the AP exits.
#[test]
fn ownership_is_returned_only_after_the_worker_finishes() {
    let handoff = Handoff::<Vec<u64>, u64>::new();
    let ticket = unsafe { handoff.publish(vec![11, 23]) }.unwrap();
    assert_eq!(unsafe { handoff.try_collect(ticket) }, Ok(None));
    let (error, rejected) = unsafe { handoff.publish(vec![91]) }.unwrap_err();
    assert_eq!(error, Error::Busy);
    assert_eq!(rejected, [91]);
    assert!(unsafe {
        handoff.run(|job, cancel| {
            assert!(!cancel.is_requested());
            job[0] += 7;
            job[1] * 2
        })
    });
    let (job, result) = unsafe { handoff.try_collect(ticket) }.unwrap().unwrap();
    assert_eq!(job, [18, 23]);
    assert_eq!(result, 46);
    assert_eq!(unsafe { handoff.try_collect(ticket) }, Err(Error::Stale));
    assert!(!unsafe { handoff.run(|_, _| 0) });
}

// Reusing a CPU slot cannot let a delayed stop or completion affect a new PID.
#[test]
fn generations_reject_stale_stop_and_collection_without_cancelling_reuse() {
    let handoff = Handoff::<u64, bool>::new();
    let old = unsafe { handoff.publish(17) }.unwrap();
    assert_eq!(unsafe { handoff.request_stop(old) }, Ok(true));
    unsafe { handoff.run(|_, cancel| cancel.is_requested()) };
    assert_eq!(unsafe { handoff.try_collect(old) }, Ok(Some((17, true))));
    let next = unsafe { handoff.publish(29) }.unwrap();
    assert_ne!(next, old);
    assert_eq!(unsafe { handoff.request_stop(old) }, Err(Error::Stale));
    assert_eq!(unsafe { handoff.try_collect(old) }, Err(Error::Stale));
    unsafe { handoff.run(|_, cancel| cancel.is_requested()) };
    assert_eq!(unsafe { handoff.request_stop(next) }, Ok(false));
    assert_eq!(unsafe { handoff.try_collect(next) }, Ok(Some((29, false))));
}

// Exercise the actual Release/Acquire payload transfer with distinct threads;
// collecting RUNNING early would expose the context while the worker mutates it.
#[test]
fn another_cpu_observes_job_and_publishes_all_changes_before_completion() {
    let handoff = Arc::new(Handoff::<[u64; 4], bool>::new());
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let remote = handoff.clone();
    let worker = std::thread::spawn(move || {
        while !unsafe {
            remote.run(|job, cancel| {
                assert_eq!(*job, [19, 31, 47, 61]);
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                *job = [71, 83, 97, 109];
                cancel.is_requested()
            })
        } {
            std::thread::yield_now();
        }
    });
    let ticket = unsafe { handoff.publish([19, 31, 47, 61]) }.unwrap();
    started_rx.recv().unwrap();
    assert_eq!(unsafe { handoff.try_collect(ticket) }, Ok(None));
    assert_eq!(unsafe { handoff.request_stop(ticket) }, Ok(true));
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(
        unsafe { handoff.try_collect(ticket) },
        Ok(Some(([71, 83, 97, 109], true)))
    );
}
