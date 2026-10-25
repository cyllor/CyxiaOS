use cyxia_prototype::learning::{
    Error,
    capture::{Capture, CaptureInit, InitValue},
};

/// This is the same typed write boundary used by a protected pool owner. The
/// allocation is uninitialized; no Capture reference exists until completion.
fn initialize<const I: usize, const R: usize>() -> Box<Capture<I, R>> {
    let mut storage = Box::<Capture<I, R>>::new_uninit();
    let base = storage.as_mut_ptr().cast::<u8>();
    let mut init = CaptureInit::<I, R>::new().unwrap();
    let mut occupied = vec![false; init.bytes()];
    assert_eq!(base as usize % init.alignment(), 0);
    while let Some(piece) = init.peek() {
        assert!(piece.value.byte_len() <= 256);
        assert_eq!(piece.offset % piece.value.alignment(), 0);
        assert!(piece.offset + piece.value.byte_len() <= init.bytes());
        for byte in &mut occupied[piece.offset..piece.offset + piece.value.byte_len()] {
            assert!(!*byte, "initializer wrote a field twice");
            *byte = true;
        }
        // Each enum variant is a valid value of the exact destination field.
        // The recipe computes offsets with offset_of!, not a copied C layout.
        unsafe {
            let destination = base.add(piece.offset);
            macro_rules! write {
                ($v:expr) => {
                    core::ptr::write(destination.cast(), $v)
                };
            }
            match piece.value {
                InitValue::Config(v) => write!(v),
                InitValue::U64(v) => write!(v),
                InitValue::Usize(v) => write!(v),
                InitValue::Raw(v) => write!(v),
                InitValue::Source(v) => write!(v),
                InitValue::Open(v) => write!(v),
                InitValue::Cpu(v) => write!(v),
                InitValue::Request(v) => write!(v),
                InitValue::Work(v) => write!(v),
                InitValue::Fault(v) => write!(v),
                InitValue::Hash(v) => write!(v),
                InitValue::Seal(v) => write!(v),
            }
        }
        init.commit(piece.sequence).unwrap();
    }
    let complete = init.finish().unwrap();
    assert_eq!(complete.bytes(), core::mem::size_of::<Capture<I, R>>());
    // Every field has been written and the allocation has remained exclusive.
    unsafe { storage.assume_init() }
}

#[test]
fn full_native_capacity_initializes_without_a_whole_object_stack_temporary() {
    let capture = initialize::<8192, 4096>();
    let status = capture.status();
    assert_eq!(status.key, None);
    assert_eq!(status.intervals, 0);
    assert_eq!(status.requests, 0);
    assert_eq!(status.raw_tagged_ns, [0; 4]);
    assert_eq!(status.missing_events, 0);
    assert_eq!(status.fault, None);
}

#[test]
fn missing_or_reordered_writes_cannot_finish_the_recipe() {
    assert!(matches!(CaptureInit::<0, 100>::new(), Err(Error::Capacity)));
    assert!(matches!(
        CaptureInit::<1, 100>::new().unwrap().finish(),
        Err(Error::State)
    ));
    let mut init = CaptureInit::<2, 100>::new().unwrap();
    assert_eq!(init.commit(1), Err(Error::Order));
    assert_eq!(init.completed_pieces(), 0);
    assert_eq!(init.peek().unwrap().sequence, 0);
    init.commit(0).unwrap();
    assert_eq!(init.commit(0), Err(Error::Order));
    assert_eq!(init.completed_pieces(), 1);
}
