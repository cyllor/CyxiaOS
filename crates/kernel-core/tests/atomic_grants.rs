use cyxia_contracts::{Generation, PageCount, RedemptionId, TaskId};
use cyxia_kernel_core::grants::{
    AuthorizedGrantRequest, BoundedGrantLedger, GrantError, GrantLedger, Owner, ReleaseReceipt,
};

fn owner(task: u32, generation: u64) -> Owner {
    Owner {
        task: TaskId::new(task).unwrap(),
        generation: Generation::new(generation).unwrap(),
    }
}

fn request(owner: Owner, pages: u32) -> AuthorizedGrantRequest {
    // The test is the trusted admission authority; no application supplies this.
    unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(pages)) }
}

fn receipt(id: RedemptionId, owner: Owner, pages: u32) -> ReleaseReceipt {
    // These capacity-only tests never publish CPU or DMA mappings.
    unsafe { ReleaseReceipt::after_revoke(id, owner, PageCount(pages)) }
}

#[test]
fn fragmented_desktop_heap_keeps_page_and_metadata_limits_independent() {
    let owner = owner(1, 1);
    let mut ledger = BoundedGrantLedger::<512>::new(PageCount(2048));
    let mut ids = Vec::new();
    for _ in 0..512 {
        ids.push(ledger.commit_and_redeem(request(owner, 1)).unwrap());
    }
    let before = ledger.snapshot();
    assert_eq!(before.free, 1536);
    assert_eq!(
        ledger.commit_and_redeem(request(owner, 1)),
        Err(GrantError::Metadata)
    );
    assert_eq!(ledger.snapshot(), before);
    // Recycle a middle record, not just the first-fit tail. A single larger
    // region consumes that record while retaining the exact page accounting.
    ledger
        .release_completed(receipt(ids.remove(255), owner, 1))
        .unwrap();
    let large = ledger.commit_and_redeem(request(owner, 1000)).unwrap();
    assert_eq!(ledger.snapshot().free, 537);
    ledger
        .release_completed(receipt(large, owner, 1000))
        .unwrap();
    for id in ids {
        ledger.release_completed(receipt(id, owner, 1)).unwrap();
    }
    assert_eq!(ledger.snapshot().free, 2048);
}

#[test]
fn failed_atomic_admission_preserves_next_identity_as_well_as_capacity() {
    let owner = owner(1, 1);
    let mut checked = GrantLedger::new(PageCount(2048));
    let mut control = GrantLedger::new(PageCount(2048));
    let before = checked.snapshot();
    assert_eq!(
        checked.commit_and_redeem(request(owner, 0)),
        Err(GrantError::Invalid)
    );
    assert_eq!(
        checked.commit_and_redeem(request(owner, 2049)),
        Err(GrantError::Capacity)
    );
    assert_eq!(checked.snapshot(), before);
    let actual = checked.commit_and_redeem(request(owner, 1024)).unwrap();
    let expected = control.commit_and_redeem(request(owner, 1024)).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(checked.snapshot(), control.snapshot());
}

#[test]
fn atomic_regions_cannot_consume_metadata_promised_to_existing_grants() {
    let owner = owner(1, 1);
    let mut ledger = GrantLedger::new(PageCount(4096));
    let promised = ledger.commit(request(owner, 128)).unwrap();
    let before = ledger.snapshot();
    assert_eq!(
        ledger.commit_and_redeem(request(owner, 1024)),
        Err(GrantError::Metadata)
    );
    assert_eq!(ledger.snapshot(), before);

    // Releasing one completed page frees precisely one record; the atomic
    // region may take it without preventing any of the other 127 redemptions.
    let first = ledger.redeem(promised, owner, PageCount(1)).unwrap();
    ledger.release_completed(receipt(first, owner, 1)).unwrap();
    let region = ledger.commit_and_redeem(request(owner, 1024)).unwrap();
    let pages: Vec<_> = (0..127)
        .map(|_| ledger.redeem(promised, owner, PageCount(1)).unwrap())
        .collect();
    assert_eq!(ledger.snapshot().reserved_unredeemed, 0);
    assert_eq!(ledger.snapshot().in_use, 1024 + 127);
    for page in pages {
        ledger.release_completed(receipt(page, owner, 1)).unwrap();
    }
    ledger
        .release_completed(receipt(region, owner, 1024))
        .unwrap();
    assert_eq!(ledger.snapshot().free, 4096);
}

#[test]
fn large_atomic_region_uses_one_record_when_followed_by_promised_pages() {
    let owner = owner(1, 1);
    let mut ledger = GrantLedger::new(PageCount(4096));
    let region = ledger.commit_and_redeem(request(owner, 3072)).unwrap();
    let promised = ledger.commit(request(owner, 127)).unwrap();
    let before = ledger.snapshot();
    assert_eq!(ledger.commit(request(owner, 1)), Err(GrantError::Metadata));
    assert_eq!(ledger.snapshot(), before);
    let pages: Vec<_> = (0..127)
        .map(|_| ledger.redeem(promised, owner, PageCount(1)).unwrap())
        .collect();
    ledger
        .release_completed(receipt(region, owner, 3072))
        .unwrap();
    for page in pages {
        ledger.release_completed(receipt(page, owner, 1)).unwrap();
    }
    assert_eq!(ledger.snapshot().free, 4096);
}

#[test]
fn full_grant_table_refuses_atomically_and_reuses_completed_slots() {
    let owner = owner(1, 1);
    let mut checked = GrantLedger::new(PageCount(4096));
    let mut control = GrantLedger::new(PageCount(4096));
    let mut checked_ids = Vec::new();
    let mut control_ids = Vec::new();
    for _ in 0..128 {
        checked_ids.push(checked.commit_and_redeem(request(owner, 16)).unwrap());
        control_ids.push(control.commit_and_redeem(request(owner, 16)).unwrap());
    }
    let before = checked.snapshot();
    assert_eq!(before.free, 2048);
    assert_eq!(
        checked.commit_and_redeem(request(owner, 1)),
        Err(GrantError::Metadata)
    );
    assert_eq!(checked.snapshot(), before);
    let stale = receipt(checked_ids.remove(0), owner, 16);
    checked.release_completed(stale).unwrap();
    control
        .release_completed(receipt(control_ids.remove(0), owner, 16))
        .unwrap();
    let replacement = checked.commit_and_redeem(request(owner, 64)).unwrap();
    assert_eq!(
        replacement,
        control.commit_and_redeem(request(owner, 64)).unwrap()
    );
    let before_replay = checked.snapshot();
    assert_eq!(checked.release_completed(stale), Err(GrantError::Stale));
    assert_eq!(checked.snapshot(), before_replay);
    checked
        .release_completed(receipt(replacement, owner, 64))
        .unwrap();
    for id in checked_ids {
        checked.release_completed(receipt(id, owner, 16)).unwrap();
    }
    assert_eq!(checked.snapshot().free, 4096);
}

#[test]
fn atomic_release_rejects_wrong_task_generation_or_extent_without_mutation() {
    let rightful = owner(1, 1);
    let mut ledger = GrantLedger::new(PageCount(4096));
    let id = ledger.commit_and_redeem(request(rightful, 1024)).unwrap();
    let before = ledger.snapshot();
    for (identity, pages) in [
        (owner(2, 1), 1024),
        (owner(1, 2), 1024),
        (rightful, 0),
        (rightful, 1023),
        (rightful, 1025),
    ] {
        assert_eq!(
            ledger.release_completed(receipt(id, identity, pages)),
            Err(GrantError::Invalid)
        );
        assert_eq!(ledger.snapshot(), before);
    }
    ledger
        .release_completed(receipt(id, rightful, 1024))
        .unwrap();
    assert_eq!(ledger.snapshot().free, 4096);
}

#[test]
fn repeated_region_reuse_never_revives_an_old_release_receipt() {
    let mut ledger = GrantLedger::new(PageCount(1024));
    let first_owner = owner(1, 1);
    let first = ledger
        .commit_and_redeem(request(first_owner, 1024))
        .unwrap();
    let stale = receipt(first, first_owner, 1024);
    ledger.release_completed(stale).unwrap();
    for generation in 2..258 {
        let next_owner = owner(1, generation);
        let id = ledger.commit_and_redeem(request(next_owner, 1024)).unwrap();
        assert_ne!(id, first);
        let before = ledger.snapshot();
        assert_eq!(ledger.release_completed(stale), Err(GrantError::Stale));
        assert_eq!(ledger.snapshot(), before);
        ledger
            .release_completed(receipt(id, next_owner, 1024))
            .unwrap();
        assert_eq!(ledger.snapshot().free, 1024);
    }
}

#[test]
fn full_u32_capacity_can_be_admitted_and_released_without_overflow() {
    let owner = owner(1, 1);
    let mut ledger = GrantLedger::new(PageCount(u32::MAX));
    let id = ledger.commit_and_redeem(request(owner, u32::MAX)).unwrap();
    assert_eq!(ledger.snapshot().free, 0);
    assert_eq!(ledger.snapshot().in_use, u32::MAX);
    let before = ledger.snapshot();
    assert_eq!(
        ledger.commit_and_redeem(request(owner, 1)),
        Err(GrantError::Capacity)
    );
    assert_eq!(ledger.snapshot(), before);
    ledger
        .release_completed(receipt(id, owner, u32::MAX))
        .unwrap();
    assert_eq!(ledger.snapshot().free, u32::MAX);
}
