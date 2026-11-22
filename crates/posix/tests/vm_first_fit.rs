use cyxia_posix::{
    Errno,
    vm::{BASE, PAGE_COUNT, PAGE_SIZE, PageBatch, Vm},
};

fn address(page: usize) -> u64 {
    BASE + (page * PAGE_SIZE) as u64
}

#[test]
fn first_fit_joins_a_hole_across_the_middle_of_the_window() {
    let mut vm = Vm::new();
    let mut batch = PageBatch::new();
    vm.allocate_into(PAGE_COUNT, &mut batch).unwrap();
    let cross = PAGE_COUNT / 2 - 2;
    vm.unmap_into(address(2), 3, &mut batch).unwrap();
    vm.unmap_into(address(cross), 7, &mut batch).unwrap();

    assert_eq!(vm.free(), 10);
    assert_eq!(vm.largest_free_run(), 7);
    assert_eq!(vm.allocate_into(8, &mut batch), Err(Errno::Nomem));
    assert_eq!(batch.page_count(), 0);

    vm.allocate_into(4, &mut batch).unwrap();
    assert_eq!(batch.start(), address(cross));
    assert_eq!(
        batch.iter().map(|page| page.slot).collect::<Vec<_>>(),
        [2, 3, 4, cross]
    );
    vm.protect(address(cross), 4 * PAGE_SIZE, 0).unwrap();
    assert_eq!(vm.largest_free_run(), 3);
    assert_eq!(
        vm.unmap_into(address(cross), 5, &mut batch),
        Err(Errno::Fault)
    );
    assert_eq!(batch.page_count(), 0);
    assert_eq!(vm.permissions(address(cross + 3)), Ok(0));
    assert_eq!(vm.largest_free_run(), 3);
    vm.unmap_into(address(cross), 4, &mut batch).unwrap();
    assert_eq!(vm.largest_free_run(), 7);
}

#[test]
fn fragmented_transactions_match_a_flat_first_fit_model() {
    let mut vm = Vm::new();
    let mut batch = PageBatch::new();
    vm.allocate_into(PAGE_COUNT, &mut batch).unwrap();
    let mut virtual_slots: Vec<Option<usize>> = (0..PAGE_COUNT).map(Some).collect();
    let mut physical_slots = vec![true; PAGE_COUNT];
    let choices = [1, 3, 31, 63, 64, 65, 127, 128, 129, 257];
    let mut seed = 0xb19c_723d_58e2_6fa1u64;
    for iteration in 0..1536 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let pages = choices[((seed >> 32) as usize) % choices.len()];
        if iteration % 3 == 0 {
            let start = (seed as usize) % (PAGE_COUNT - pages + 1);
            let range = &mut virtual_slots[start..start + pages];
            let result = vm.unmap_into(address(start), pages, &mut batch);
            if range.iter().all(Option::is_some) {
                result.unwrap();
                assert_eq!(batch.start(), address(start));
                assert_eq!(batch.page_count(), pages);
                for (removed, expected) in batch.iter().zip(range) {
                    let slot = expected.take().unwrap();
                    assert_eq!(removed.slot, slot);
                    physical_slots[slot] = false;
                }
            } else {
                assert_eq!(result, Err(Errno::Fault));
                assert_eq!(batch.page_count(), 0);
            }
        } else {
            let mut offset = 0;
            let mut first = None;
            for hole in virtual_slots.split(Option::is_some) {
                if hole.len() >= pages {
                    first = Some(offset);
                    break;
                }
                offset += hole.len() + 1;
            }
            let result = vm.allocate_into(pages, &mut batch);
            if let Some(start) = first {
                result.unwrap();
                assert_eq!(batch.start(), address(start));
                assert_eq!(batch.page_count(), pages);
                let available: Vec<_> = (0..PAGE_COUNT)
                    .filter(|&slot| !physical_slots[slot])
                    .take(pages)
                    .collect();
                assert_eq!(available.len(), pages);
                for (index, (page, expected)) in batch.iter().zip(available).enumerate() {
                    assert_eq!(page.slot, expected);
                    physical_slots[expected] = true;
                    virtual_slots[start + index] = Some(expected);
                }
            } else {
                assert_eq!(result, Err(Errno::Nomem));
                assert_eq!(batch.page_count(), 0);
            }
        }
        let largest = virtual_slots
            .split(Option::is_some)
            .map(<[_]>::len)
            .max()
            .unwrap();
        assert_eq!(vm.largest_free_run(), largest);
        assert_eq!(vm.used(), virtual_slots.iter().flatten().count());
    }
}
