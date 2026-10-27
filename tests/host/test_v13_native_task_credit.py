from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeTaskCredit(unittest.TestCase):
    def test_builtin_workers_do_not_run_on_tail_credit_below_one_full_turn(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()

        self.assertIn("const BUILTIN_MIN_GRANT_NS: u64 = 10_000_000;", source)
        self.assertIn("if d.thread == builtin(slot)", source)
        self.assertIn("BUILTIN_MIN_GRANT_NS", source[source.index("let safety ="):])
        self.assertIn("pub fn builtin_selected", source)

    def test_dynamic_el0_workers_require_their_declared_full_envelope(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()

        self.assertIn("const DYNAMIC_EL0_MIN_GRANT_NS: u64 = 10_000_000;", source)
        admission = source[source.index("let safety ="):source.index("let optional =")]
        self.assertIn("d.thread.id >= 0x1000", admission)
        self.assertIn("DYNAMIC_EL0_MIN_GRANT_NS", admission)
        execution = (ROOT / "kernel/src/domain_tasks/execution.rs").read_text()
        self.assertIn("minimum_ns: if local { 10_000_000 } else { 0 }", execution)

    def test_cpu0_service_owners_have_separate_credits_and_single_writer_detail(self):
        source = (ROOT / "kernel/src/domain_services.rs").read_text()

        self.assertIn("static DOMAIN_SERVICE_DETAIL: ServiceDetail", source)
        self.assertIn("size_of::<ServiceDetail>() == 128", source)
        service = source[source.index("pub fn service(now:"):source.index("mod target_projection")]
        self.assertGreaterEqual(service.count("progress();"), 2)
        self.assertIn("crate::domain_platform::poll(now)?;", service)
        self.assertIn("service_detail(6);\n    // with() has released", service)

    def test_batched_rx_custody_transitions_are_independently_settleable(self):
        driver = (ROOT / "crates/driver-virtio/src/net/batched.rs").read_text()
        transport = (ROOT / "crates/cluster-transport/src/device.rs").read_text()

        receive = driver[driver.index("pub fn receive_with_checkpoint"):]
        self.assertIn("self.poll_rx_with_checkpoint(p, checkpoint)?;\n        checkpoint();", receive)
        self.assertIn("copy_from_slice", receive)
        self.assertIn("checkpoint();\n        self.rx.release(token)?;", receive)
        self.assertIn("receive_frame_with_checkpoint", transport)
        self.assertIn("receive_with_checkpoint(&mut self.rx.bytes, checkpoint)", transport)

    def test_builtin_boundary_has_single_writer_phase_detail(self):
        runtime = (ROOT / "kernel/src/smp.rs").read_text()

        self.assertIn("static BUILTIN_TASK_DETAIL: BuiltinDetail", runtime)
        self.assertIn("size_of::<BuiltinDetail>() == 256", runtime)
        fixture = runtime[runtime.index("let builtin_selected ="):]
        for phase in range(7):
            self.assertIn(f"builtin_detail(slot, {phase});", fixture)

    def test_builtin_fixture_yields_after_a_fixed_batch_with_timer_backstop(self):
        assembly = (ROOT / "kernel/src/smp_user.S").read_text()
        runtime = (ROOT / "kernel/src/smp.rs").read_text()

        self.assertIn("mov x12, #16", assembly)
        self.assertIn("subs x12, x12, #1", assembly)
        self.assertIn("svc #4", assembly)
        self.assertIn("cbz x2, smp_busy", assembly)
        self.assertIn("cmp x2, #4", assembly)
        self.assertIn("b.eq smp_bounded", assembly)
        self.assertIn("ctx.regs[2] = 4;", runtime)
        self.assertIn("prepare_builtin_capture(slot, i)", runtime)
        self.assertIn("builtin_capture_index(cpu::slot())", runtime)
        tasks = (ROOT / "kernel/src/domain_tasks/execution.rs").read_text()
        self.assertIn("if !s.tasks[i].capture_ready", tasks)
        self.assertIn("crate::a02_capture::prepare(task)", tasks)
        self.assertIn("s.tasks[i].capture_index = capture_index", tasks)
        self.assertIn("enter_builtin_service(\n            ctx", runtime)
        self.assertIn(
            "            builtin_capture_index(cpu::slot()),\n            true,\n            false,\n        );",
            runtime,
        )
        entry = runtime[runtime.index("pub(crate) unsafe fn enter_service"):]
        self.assertNotIn(
            "RECORD_SLICE_EXCEPTION[slot].store(record_slice_evidence",
            entry,
        )
        self.assertIn(
            "if record_slice_evidence {\n            RECORD_SLICE_EXCEPTION[slot].store(true",
            entry,
        )
        self.assertIn("fn fixture_yielded", runtime)
        self.assertIn("ctx.kind == 9", runtime[runtime.index("fn fixture_yielded"):])
        self.assertIn(
            '#[cfg(feature = "unified-runtime")]',
            runtime[runtime.index("fn fixture_yielded"):],
        )
        self.assertIn("ctx.esr & 0xffff == 4", runtime[runtime.index("fn fixture_yielded"):])

    def test_builtin_immutable_root_keeps_full_context_without_global_tlbi(self):
        runtime = (ROOT / "kernel/src/smp.rs").read_text()
        arch = (ROOT / "crates/arch-aarch64/src/user.rs").read_text()
        assembly = (ROOT / "crates/arch-aarch64/src/user.S").read_text()

        self.assertIn("unsafe fn enter_builtin_service", runtime)
        self.assertIn("fn builtin_asid(root: u64) -> u8", runtime)
        self.assertIn("index < (C * 2) as u64", runtime)
        self.assertIn("0x90 + u8::try_from(index)", runtime)
        self.assertIn("user::enter_immutable(context, root, builtin_asid(root));", runtime)
        self.assertIn("pub unsafe fn enter_immutable", arch)
        self.assertIn("u64::from(asid) << 48", arch)
        self.assertIn("true, false", arch)
        self.assertIn("str x2, [sp, #136]", assembly)
        self.assertIn("ldr x11, [sp, #136]", assembly)
        self.assertIn("cbz x11, .Luser_low_walks_revoked", assembly)

    def test_cpu0_service_completion_scan_uses_owned_layout_only(self):
        runtime = (ROOT / "kernel/src/unified.rs").read_text()
        execution = (ROOT / "kernel/src/domain_tasks/execution.rs").read_text()
        start = execution.index("pub fn service(_now:")
        end = execution.index("fn lifecycle_piece", start)
        service = execution[start:end]

        self.assertIn("pub(crate) fn service_stage", runtime)
        self.assertIn("crate::unified::service_stage(10 + phase as u64)", service)
        self.assertIn("let mut owned = s.layout.healthy_mask", service)
        self.assertIn("owned.trailing_zeros()", service)
        self.assertNotIn("for slot in 0..64", service)


if __name__ == "__main__":
    unittest.main()
