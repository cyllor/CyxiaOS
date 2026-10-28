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
        queue = (ROOT / "crates/driver-virtio/src/queue.rs").read_text()
        transport = (ROOT / "crates/cluster-transport/src/device.rs").read_text()

        receive = driver[driver.index("pub fn receive_with_checkpoint"):]
        self.assertIn("self.poll_rx_with_checkpoint(p, checkpoint)?;\n        checkpoint();", receive)
        self.assertIn("copy_from_slice", receive)
        self.assertIn("checkpoint();\n        self.rx.release(token)?;", receive)
        self.assertIn("receive_frame_with_checkpoint", transport)
        self.assertIn("receive_with_checkpoint(&mut self.rx.bytes, checkpoint)", transport)
        record = queue[queue.index("let at = 4 + usize::from(self.used % self.size) * 8;") :]
        self.assertLess(record.index("p.sync("), record.index("checkpoint();"))
        self.assertLess(record.index("checkpoint();"), record.index("let id ="))
        response = record[record.index("if len != 0 {") :]
        self.assertIn("p.barrier();\n        }\n        // DMA cache acquisition", response)
        self.assertLess(response.index("// DMA cache acquisition"),
                        response.index("checkpoint();"))
        self.assertLess(response.index("checkpoint();"),
                        response.index("copy_prefix_to"))
        published = response[response.index("copy_prefix_to") :]
        self.assertLess(published.index("last_completed_version"),
                        published.index("checkpoint();"))
        self.assertLess(published.index("checkpoint();"), published.index("let irq"))

    def test_native_tcp_ingress_and_handshake_have_separate_bounded_credits(self):
        tcp = (ROOT / "crates/cluster-transport/src/tcp.rs").read_text()
        tls = (ROOT / "crates/cluster-transport/src/tls.rs").read_text()

        self.assertIn("pub const IDLE_TIMEOUT_SECS: u64 = 60;", tcp)
        ingress = tcp[tcp.index("let queued = before.send_queue();"):
                      tcp.index("// A hardware multichain port")]
        self.assertIn("checkpoint();\n        let ingress = self", ingress)
        self.assertIn("poll_ingress_single(now, &mut self.device, &mut self.sockets);\n        checkpoint();", ingress)
        self.assertIn("pub const HANDSHAKE_TIMEOUT_MS: u64 = 30_000;", tls)
        self.assertIn("HANDSHAKE_TIMEOUT_MS < IDLE_TIMEOUT_SECS * 1000", tls)
        self.assertIn("checked_add(HANDSHAKE_TIMEOUT_MS)", tls)

    def test_network_stage_diagnostic_is_outside_next_service_debit(self):
        runtime = (ROOT / "kernel/src/unified.rs").read_text()
        turn = runtime[runtime.index("fn network_turn(") : runtime.index("fn progress(")]

        self.assertLess(
            turn.index("service_stage(network_stage);"),
            turn.index("let mut started = timer::cpu_ticks();"),
        )
        resume = turn[turn.index("resume_network_service(coordinator);") :]
        self.assertLess(
            resume.index("service_stage(network_stage);"),
            resume.index("started = timer::cpu_ticks();"),
        )

    def test_builtin_boundary_has_single_writer_phase_detail(self):
        runtime = (ROOT / "kernel/src/smp.rs").read_text()

        self.assertIn("static BUILTIN_TASK_DETAIL: BuiltinDetail", runtime)
        self.assertIn("size_of::<BuiltinDetail>() == 256", runtime)
        fixture = runtime[runtime.index("let builtin_selected ="):]
        for phase in range(8):
            self.assertIn(f"builtin_detail(slot, {phase});", fixture)
        self.assertLess(
            runtime.index("builtin_detail(slot, 5);"),
            runtime.index("user::enter_immutable(context, root, builtin_asid(root));"),
        )
        self.assertGreater(
            runtime.index("builtin_detail(slot, 6);"),
            runtime.index("user::enter_immutable(context, root, builtin_asid(root));"),
        )
        self.assertGreater(
            runtime.index("builtin_detail(slot, 7);"),
            runtime.index("crate::a02_capture::returned_prepared(index);"),
        )

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
        validator = runtime[
            runtime.index("fn fixture_context_valid") : runtime.index(
                '#[cfg(not(feature = "unified-runtime"))]\nfn fixture_yielded'
            )
        ]
        self.assertIn('"ldp x10, x11, [{simd}], #16"', validator)
        self.assertIn('"cmp x9, #32"', validator)
        unified_loop = runtime[runtime.index("let ctx = &mut contexts[role]") :]
        self.assertIn("fixture_context_valid(ctx, i)", unified_loop)

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

    def test_cpu0_service_pumps_publish_stopped_snapshot_boundaries(self):
        execution = (ROOT / "kernel/src/domain_tasks/execution.rs").read_text()
        start = execution.index("pub fn service(_now:")
        end = execution.index("fn lifecycle_piece", start)
        service = execution[start:end]

        for stage in range(70, 75):
            self.assertIn(f"diagnostic_service_stage({stage});", service)
        helper = execution[execution.index("fn diagnostic_service_stage") : start]
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[9].store(stage", helper)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[10]", helper)
        self.assertIn("CREDIT_KIND[0].load", helper)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[11]", helper)
        self.assertIn("COMPLETE_READY[0].load", helper)
        self.assertLess(service.index("diagnostic_service_stage(70);"),
                        service.index("let _ = service_segment"))
        self.assertLess(service.index("diagnostic_service_stage(71);"),
                        service.index("service_file(progress);"))
        self.assertLess(service.index("diagnostic_service_stage(72);"),
                        service.index("crate::learning_workload::service_io(progress);"))
        self.assertLess(service.index("diagnostic_service_stage(73);"),
                        service.index("crate::learning_replay::service_io(progress);"))

    def test_storage_profile_records_unsettled_cpu0_credit_error(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()
        start = source.index("fn complete_locked")
        end = source.index("pub fn complete_builtin", start)
        completion = source[start:end]

        self.assertIn("storage_fault_capture::PROFILE", completion)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[12]", completion)
        self.assertIn("error as u64 + 1", completion)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[13]", completion)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[14]", completion)
        self.assertIn("DOMAIN_TASK_EVIDENCE.words[15]", completion)
        self.assertIn("active.dispatch.started_ns", completion)

    def test_a10_consumption_snapshot_retries_transient_task_lock_before_effect(self):
        capture = (ROOT / "kernel/src/storage_fault_capture.rs").read_text()
        file_abi = (ROOT / "kernel/src/domain_file_abi.rs").read_text()

        self.assertIn("pub fn entered(owner: ObjectKey, frame: &[u8; 640]) -> Result<(), Error>",
                      capture)
        self.assertIn("Err(Error::Busy) => return Err(Error::Busy)", capture)
        self.assertIn("authorize(owner, &input).is_ok()", file_abi)
        self.assertIn("storage_fault_capture::entered(owner, &input.bytes)", file_abi)
        self.assertIn("context.regs[0] = (-11i64) as u64", file_abi)
        self.assertLess(file_abi.index("storage_fault_capture::entered(owner, &input.bytes)"),
                        file_abi.index("let result = (||"))

    def test_a10_delivery_retains_operation_completion_io_snapshot(self):
        capture = (ROOT / "kernel/src/storage_fault_capture.rs").read_text()
        file_abi = (ROOT / "kernel/src/domain_file_abi.rs").read_text()

        self.assertIn("pub fn snapshot() -> Option<[u64; 4]>", capture)
        self.assertIn("io: [u64; 4]", capture)
        self.assertIn("capture_io: Option<[u64; 4]>", file_abi)
        snapshot = "crate::storage_fault_capture::snapshot()"
        self.assertIn(snapshot, file_abi)
        self.assertLess(file_abi.index(snapshot),
                        file_abi.index("*core::ptr::addr_of_mut!(PENDING) = Some(Delivery"))
        self.assertIn("pending.capture_io", file_abi)

    def test_a10_cache_client_uses_its_source_bound_private_page_quota(self):
        execution = (ROOT / "kernel/src/domain_tasks/execution.rs").read_text()

        self.assertIn("a10_budget::client_memory_pages", execution)
        self.assertNotIn("register_owner(key, if client || local { 16 }", execution)


if __name__ == "__main__":
    unittest.main()
