from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeInputPage(unittest.TestCase):
    def test_paid_preparation_encodes_directly_into_private_input_page(self):
        source = (ROOT / "kernel/src/prototype_runtime/native.rs").read_text()

        self.assertIn("let input = unsafe { &mut (*input_ptr(slot)).0 };", source)
        self.assertNotIn("let mut input = [0; 512];", source)
        self.assertNotIn("(*page).0.copy_from_slice(&input);", source)
        self.assertIn('core::arch::asm!("dsb ish", options(nostack));', source)

        encoder = (ROOT / "kernel/src/domain_control.rs").read_text()
        self.assertIn("input.fill(0);", encoder)

    def test_failed_target_lookup_retains_attributable_context(self):
        source = (ROOT / "kernel/src/domain_control.rs").read_text()
        target = source.index("let target_result = read_target_batch")
        checked = source.index("if let Err(error) = target_result", target)
        lookup = source.index("preparation_lookup(index, f, ordinal, wall_started);", checked)

        self.assertLess(target, checked)
        self.assertLess(checked, lookup)
        self.assertIn("descriptor.target_source", source)

    def test_preparation_diagnostics_use_zero_terminated_rows(self):
        source = (ROOT / "kernel/src/domain_control.rs").read_text()

        self.assertIn("row.store(phase + 1, 0)", source)
        self.assertIn("row.store(phase, timer::cpu_ticks())", source)
        self.assertIn("row.store(phase, now())", source)
        self.assertIn("size_of::<PreparationEvidence>() == 128", source)
        self.assertIn("size_of::<PreparationDetail>() == 256", source)
        self.assertIn("size_of::<PreparationPrefixDetail>() == 128", source)
        self.assertIn("preparation_prefix_detail(6)", source)
        self.assertIn("struct PreparationContextRow", source)
        self.assertIn("published: AtomicU64", source)
        self.assertIn(".write_volatile(value)", source)
        self.assertIn(".published\n        .store(0, Ordering::Release)", source)

    def test_task_target_projection_does_not_reborrow_mutable_owner(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()
        start = source.index("pub(crate) fn queued_targets(")
        end = source.index("pub fn current_action", start)
        projection = source[start:end]

        self.assertIn("if !READY.load(Ordering::Acquire)", projection)
        self.assertIn("projected_target(q.domain, q.ordinal)", projection)
        self.assertNotIn("locked(", projection)
        self.assertLess(
            source.index("word.store(value, Ordering::Relaxed)"),
            source.index("READY.store(true, Ordering::Release)"),
        )

    def test_first_scope_hash_uses_verified_arch_acceleration_with_fallback(self):
        source = (ROOT / "kernel/src/learning_replay/owner.rs").read_text()
        start = source.index("fn scope_hash(")
        end = source.index("fn on_first", start)
        hashing = source[start:end]

        self.assertIn("SCOPE_HASH_CAPACITY", source)
        self.assertIn("cyxia_arch_aarch64::sha256::digest(input)", hashing)
        self.assertIn("Sha256::digest(input)", hashing)
        self.assertIn('append(b"CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\\0")', hashing)

    def test_peer_ledger_avoids_zero_value_rmw_on_every_measurement(self):
        source = (ROOT / "kernel/src/peer_replay/owner.rs").read_text()
        start = source.index("fn ledger_with<T>(")
        end = source.index("fn now()", start)
        ledger_with = source[start:end]

        self.assertIn("counter.load(Ordering::Acquire) == 0", ledger_with)
        self.assertIn("counter.swap(0, Ordering::AcqRel)", ledger_with)
        self.assertNotIn("DROPPED.swap", ledger_with)
        self.assertNotIn("DROPPED_OPEN.swap", ledger_with)

    def test_batched_completion_uses_wide_volatile_copy_with_exact_tail(self):
        page = (ROOT / "crates/driver-virtio/src/lib.rs").read_text()
        queue = (ROOT / "crates/driver-virtio/src/queue.rs").read_text()

        self.assertIn("fn copy_prefix_to(&self, out: &mut [u8], bytes: usize)", page)
        self.assertIn("read_volatile((self.address() + offset) as *const u64)", page)
        self.assertIn("core::ptr::write_unaligned", page)
        self.assertIn("out[wide..bytes]", page)
        self.assertIn("copy_prefix_to(out, len as usize)", queue)


if __name__ == "__main__":
    unittest.main()
