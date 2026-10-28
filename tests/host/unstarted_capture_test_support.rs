// Appended only to a temporary copy of the production module. Corrupt and
// restore the retained identity to pressure-test its real retirement checks.
pub(super) fn check_binding_corruption(slot: usize) {
    let original = cell(slot).as_ref().unwrap().binding;
    for field in 0..3 {
        let binding = &mut cell(slot).as_mut().unwrap().binding;
        match field {
            0 => binding.sequence += 1,
            1 => binding.thread.generation += 1,
            _ => binding.cpu ^= 1,
        }
        assert!(!retire(slot), "mismatched cancellation identity retired another dispatch");
        assert!(!available(slot));
        cell(slot).as_mut().unwrap().binding = original;
    }
}
