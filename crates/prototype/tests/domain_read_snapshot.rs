#[path = "../../../kernel/src/domain_platform/read_snapshot.rs"]
mod read_snapshot;
use read_snapshot::ReadSnapshot;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn published_owner_snapshot_is_consistent_across_actual_concurrent_readers() {
    let view = Arc::new(ReadSnapshot::<[u64; 256]>::new());
    assert_eq!(view.read().unwrap(), None);
    let finished = Arc::new(AtomicBool::new(false));
    let start = Arc::new(std::sync::Barrier::new(4));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let view = Arc::clone(&view);
        let finished = Arc::clone(&finished);
        let start = Arc::clone(&start);
        readers.push(std::thread::spawn(move || {
            start.wait();
            let mut seen = 0;
            loop {
                if let Ok(Some(words)) = view.read() {
                    assert!(words.iter().all(|v| *v == words[0]));
                    seen += 1;
                    if finished.load(Ordering::Acquire) {
                        break;
                    }
                } else {
                    std::thread::yield_now();
                }
            }
            seen
        }));
    }
    start.wait();
    for generation in 1..5000 {
        while view.publish([generation; 256]).is_err() {
            std::thread::yield_now();
        }
    }
    finished.store(true, Ordering::Release);
    for reader in readers {
        assert!(reader.join().unwrap() > 0);
    }
    assert_eq!(view.read().unwrap(), Some([4999; 256]));
}

#[test]
fn absent_snapshot_does_not_invoke_a_projection() {
    let view = ReadSnapshot::<[u64; 1024]>::new();
    let mut called = false;
    assert_eq!(
        view.inspect(|_| {
            called = true;
            7
        })
        .unwrap(),
        None
    );
    assert!(!called);
}

#[test]
fn projection_holds_one_nonblocking_gate_until_its_small_result_is_copied() {
    let view = ReadSnapshot::<[u64; 1024]>::new();
    view.publish([11; 1024]).unwrap();
    let pair = view
        .inspect(|words| {
            assert!(view.read().is_err());
            assert!(view.inspect(|_| 0).is_err());
            assert!(view.publish([29; 1024]).is_err());
            (words[0], words[1023])
        })
        .unwrap();
    assert_eq!(pair, Some((11, 11)));
    view.publish([29; 1024]).unwrap();
    assert_eq!(
        view.inspect(|words| (words[0], words[1023])).unwrap(),
        Some((29, 29))
    );
}

#[test]
fn projected_fields_are_from_one_owner_publication_under_concurrent_updates() {
    let view = Arc::new(ReadSnapshot::<[u64; 1024]>::new());
    view.publish([0; 1024]).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let start = Arc::new(std::sync::Barrier::new(4));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let view = Arc::clone(&view);
        let finished = Arc::clone(&finished);
        let start = Arc::clone(&start);
        readers.push(std::thread::spawn(move || {
            start.wait();
            let mut seen = 0;
            loop {
                if let Ok(Some((first, middle, last))) =
                    view.inspect(|words| (words[0], words[511], words[1023]))
                {
                    assert_eq!(first, middle);
                    assert_eq!(first, last);
                    seen += 1;
                    if finished.load(Ordering::Acquire) {
                        break;
                    }
                }
            }
            seen
        }));
    }
    start.wait();
    for generation in 1..5000 {
        while view.publish([generation; 1024]).is_err() {
            std::thread::yield_now();
        }
    }
    finished.store(true, Ordering::Release);
    for reader in readers {
        assert!(reader.join().unwrap() > 0);
    }
    assert_eq!(
        view.inspect(|words| (words[0], words[1023])).unwrap(),
        Some((4999, 4999))
    );
}
