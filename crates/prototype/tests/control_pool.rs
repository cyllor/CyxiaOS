#[path = "../../../kernel/src/control_pool/ledger.rs"]
mod ledger;
use cyxia_prototype::domains::{Error, ObjectKey};
use ledger::Ledger;
fn owner(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
#[test]
fn actual_pool_capacity_is_nonoverlapping_and_never_reclaimed_from_unknown_pins() {
    let mut pool = Ledger::new();
    let model = pool.allocate(owner(1), 1).unwrap();
    let workspace = pool.allocate(owner(2), 256).unwrap();
    let remaining = pool.allocate(owner(3), 1791).unwrap();
    assert_eq!(
        (model.first(), workspace.first(), remaining.first()),
        (0, 1, 257)
    );
    assert_eq!(pool.usage().0, 2048);
    let pin = pool.pin(workspace).unwrap();
    assert_eq!(pool.allocate(owner(4), 1), Err(Error::Capacity));
    assert_eq!(pool.writable(workspace), Err(Error::Busy));
    pool.unpin(&pin).unwrap();
    assert_eq!(pool.allocate(owner(4), 1), Err(Error::Capacity));
    assert_eq!(pool.unpin(&pin), Err(Error::Stale));
}
#[test]
fn sealed_model_can_be_read_but_not_rewritten_until_all_exact_readers_stop() {
    let mut pool = Ledger::new();
    let model = pool.allocate(owner(1), 1).unwrap();
    pool.seal(model, true).unwrap();
    let first = pool.pin(model).unwrap();
    let second = pool.pin(model).unwrap();
    assert_eq!(pool.readable(model), Ok(()));
    assert_eq!(pool.writable(model), Err(Error::Auth));
    assert_eq!(pool.seal(model, false), Err(Error::Busy));
    pool.unpin(&first).unwrap();
    assert_eq!(pool.seal(model, false), Err(Error::Busy));
    pool.unpin(&second).unwrap();
    pool.seal(model, false).unwrap();
    assert_eq!(pool.writable(model), Ok(()));
}
#[test]
fn generation_and_bounded_allocation_table_fail_before_any_new_page_is_owned() {
    let mut pool = Ledger::new();
    assert_eq!(pool.allocate(owner(0), 1), Err(Error::Auth));
    assert_eq!(pool.allocate(owner(1), 0), Err(Error::Capacity));
    let a = pool.allocate(owner(1), 1).unwrap();
    assert_eq!(
        pool.find(ObjectKey {
            id: a.key().id,
            generation: 2
        }),
        Err(Error::Stale)
    );
    for id in 2..=64 {
        pool.allocate(owner(id), 1).unwrap();
    }
    assert_eq!(pool.allocate(owner(65), 1), Err(Error::Capacity));
    assert_eq!(pool.usage(), (64, 64, 0));
}
#[test]
fn pin_exhaustion_does_not_make_an_executing_mutable_buffer_readable() {
    let mut pool = Ledger::new();
    let a = pool.allocate(owner(1), 1).unwrap();
    let pins: Vec<_> = (0..128).map(|_| pool.pin(a).unwrap()).collect();
    assert!(matches!(pool.pin(a), Err(Error::Capacity)));
    assert_eq!(pool.readable(a), Err(Error::Busy));
    for p in &pins {
        pool.unpin(p).unwrap();
    }
    assert_eq!(pool.readable(a), Ok(()));
    assert_eq!(pool.usage().2, 0);
}
