"""Source-level regression checks for V0.19 native security wiring.

Not an AArch64 runtime, QEMU, DMA or TLB proof. Every assertion is a structural
guard that requires subsequent native integration/negative-test evidence.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates/kernel-core/src/security"
ARM = ROOT / "kernel/src/runtime/tasks/domain_tasks"


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class NativeSecurityWiring(unittest.TestCase):
    def test_process_spawn_has_independent_business_core_gate(self):
        src = source(ARM / "execution.rs")
        self.assertGreaterEqual(src.count("security::process::authorize_business_core("), 2)
        self.assertIn("self.layout.business_mask", src)
        self.assertIn("self.layout.healthy_mask", src)
        self.assertIn("self.layout.generation", src)
        self.assertGreaterEqual(src.count("self.scheduler.quarantine_mask()"), 2)
        self.assertRegex(src, r"self\s*\.\s*scheduler\s*\.\s*prepare_admission\(")

    def test_data_pte_mapping_and_revoke_reject_protected_frame_slots(self):
        src = source(ARM / "memory.rs")
        self.assertGreaterEqual(src.count("security::memory::authorize_data_frame_slot("), 2)
        self.assertIn("TABLE_PAGES + CODE_PAGES", src)
        self.assertIn("mmu::encode_user_leaf(", src)
        self.assertIn("tlbi vmalle1is", src)

    def test_native_vector_checks_stable_input_before_submit(self):
        src = source(ARM / "abi.rs")
        preflight = src.find("security::syscall::validate_readonly_batch(")
        submit = src.find("s.services\n                .preflight(")
        self.assertGreaterEqual(preflight, 0)
        self.assertGreater(submit, preflight)

    def test_legacy_remote_syscalls_are_closed(self):
        src = source(ARM / "abi.rs")
        self.assertIn("19 | 20 =>", src)
        self.assertIn("return Err(Error::Unsupported);", src)
        self.assertNotIn("domain_network::submit_placement_request(", src)
        self.assertNotIn("domain_network::placement_request_status(", src)

    def test_file_service_checks_stable_path_before_side_effect(self):
        src = source(ROOT / "kernel/src/runtime/files/domain_file_abi.rs")
        guard = src.find("security::file::validate_absolute_path(")
        stable = src.find("memory.copyin(address, &mut f.bytes)?;")
        run = src.find("let result = run(owner, &input, &mut output, data, progress);")
        self.assertGreater(guard, 0)
        self.assertGreater(stable, 0)
        self.assertGreater(run, guard)
        self.assertIn("validate_shape(address, f)?;", src)

    def test_block_completion_retains_dma_until_exact_ack(self):
        src = source(ROOT / "crates/driver-virtio/src/block/batched.rs")
        self.assertIn("COMPLETED_RETAINED", src)
        self.assertIn("self.queue.release(token)?;", src)
        self.assertIn("self.pending[at] = None;", src)
        self.assertIn("native_sec_d06_completion_keeps_exact_token_until_valid_ack", src)

    def test_internal_filesystem_path_cannot_normalize_empty_components(self):
        src = source(ROOT / "crates/prototype/src/domains/filesystem.rs")
        self.assertIn("for part in path[1..].split('/')", src)
        self.assertIn("part.is_empty()", src)
        self.assertNotIn("path.split('/').filter(|s| !s.is_empty())", src)

    def test_real_journal_power_cut_matrix_is_in_ci_scope(self):
        workflow = source(ROOT / ".github/workflows/v19-advisory-smoke.yml")
        self.assertIn("--test journal", workflow)
        journal = source(ROOT / "crates/prototype/tests/journal.rs")
        self.assertIn("every_recovery_write_and_flush_boundary_preserves_acknowledged_fsync_sequence", journal)
        self.assertIn("v019_sec_f01_direct_filesystem_rejects_ambiguous_path_without_disk_effect", journal)

    def test_local_echo_tls_is_protocol_isolated_from_cluster_rpc(self):
        source = (ROOT / "crates/net-transport/src/tls.rs").read_text(encoding="utf-8")
        echo = (ROOT / "crates/net-transport/src/echo.rs").read_text(encoding="utf-8")
        legacy = (ROOT / "crates/cluster-transport/src/tls.rs").read_text(encoding="utf-8")
        assert "cyxia-echo/1" in source and "cyxia-cluster/1" in source
        assert "new_local_echo" in source and "accept_local_echo" in source
        assert "authenticated_peer().is_none()" in source
        assert "READONLY_ECHO: u16 = 1" in echo
        assert "MAX_PAYLOAD: usize = 4096" in echo
        assert "cyxia_net_transport::tls::*" in legacy
        # Comments may describe forbidden remote operations. Check the
        # executable wire surface, not prose words in a security warning.
        assert "pub enum Kind" not in echo and "ClusterId" not in echo
        assert "pub const READONLY_ECHO: u16 = 1" in echo

    def test_v019_cpu1_fixed_and_two_brains_have_no_runtime_scale_path(self):
        native = source(ROOT / "kernel/src/runtime/control/prototype_runtime.rs")
        model = source(ROOT / "user/prototype-runtime/main.rs")
        role = source(ROOT / "crates/kernel-core/src/control_plane/fixed.rs")
        cores = source(ROOT / "crates/prototype/src/cores.rs")
        manager = source(ROOT / "crates/kernel-core/src/control_plane/manager.rs")
        self.assertIn("Cores::new_fixed(CoreSet::from_bits(15))", native)
        self.assertNotIn("self.poll_handoff(now);", native)
        self.assertNotIn("self.poll_secondary(now);", native)
        self.assertNotIn("self.propose(target, accepted_at);", native)
        self.assertNotIn("core_candidates(input[15])", model)
        self.assertIn("const CONTROL_CPU: usize = 1;", role)
        self.assertIn("pub fn review", role)
        self.assertIn("pub fn new_fixed(online: CoreSet)", cores)
        self.assertIn("if self.fixed_control { return Err(Error::Invalid); }", cores)
        self.assertIn("fn review_brains", manager)

    def test_v019_native_domain_never_publishes_moved_control_cpu(self):
        native = source(ROOT / "kernel/src/runtime/control/domain_control.rs")
        self.assertIn("context.control_mask != 0b10", native)
        self.assertIn("Action::ControlSet(mask) if mask != 0b10", native)
        self.assertIn("self.provenance.at(submission::Stage::Stamp)", native)

    def test_sec_n_source_bound_active_credits_and_bounded_idle_eviction(self):
        network = source(CORE / "network.rs")
        self.assertIn("pub fn close_active_from(&mut self, ip: u32)", network)
        self.assertIn("entry.active != 0", network)
        self.assertIn("if self.active >= MAX_ACTIVE { return Err(Error::Capacity); }", network)
        self.assertIn("source.inflight -= 1;", network)
        self.assertIn("source.active -= 1;", network)
        self.assertNotIn("pub fn close_active(&mut self)", network)

    def test_sec_n_handshake_and_tls_echo_use_generation_bound_credits(self):
        gate = source(ROOT / "crates/net-transport/src/admission.rs")
        tls = source(ROOT / "crates/net-transport/src/tls.rs")
        self.assertIn("pub struct PendingTicket", gate)
        self.assertIn("pub struct ActiveTicket", gate)
        self.assertIn("self.pending_entry(ticket)?", gate)
        self.assertIn("tls.local_echo_proof()", gate)
        self.assertIn("row.proof==proof", gate)
        self.assertIn("tls.accept_local_echo(tls.plaintext())", gate)
        self.assertIn("pub fn begin_restart(&mut self)", gate)
        self.assertIn("self.active_count()!=0", gate)
        self.assertIn("static NEXT_SESSION: AtomicU64", tls)
        self.assertIn("pub fn local_echo_proof(&self)", tls)

    def test_sec_n_tls_echo_dispatch_retains_egress_credit_until_drained(self):
        gate = source(ROOT / "crates/net-transport/src/admission.rs")
        tls = source(ROOT / "crates/net-transport/src/tls.rs")
        self.assertIn("pub fn dispatch_echo(", gate)
        self.assertIn("tls.send_plaintext(&response[..encoded])", gate)
        self.assertIn("tls.consume_plaintext(consumed)", gate)
        self.assertIn("tls_egress_pending", gate)
        self.assertIn("pub fn confirm_tls_output_drained(", gate)
        self.assertIn("tls.has_pending_plaintext() || !tls.pending_tls().is_empty()", gate)
        self.assertIn("row.state!=State::Draining || row.tls_egress_pending", gate)
        self.assertIn("pub(crate) fn reply(", gate)
        self.assertIn("pub fn local_echo_proof(&self)", tls)

    def test_v019_other_five_tracks_fail_closed_with_fixed_control_roles(self):
        process = source(CORE / "process.rs")
        file = source(CORE / "file.rs")
        memory = source(CORE / "memory.rs")
        device = source(CORE / "device.rs")
        syscall = source(CORE / "syscall.rs")
        manager = source(ROOT / "crates/kernel-core/src/control_plane/manager.rs")
        self.assertIn("if cpu < 2 { return Err(Error::Unauthorized); }", process)
        self.assertIn("request.cpu >= 2", process)
        self.assertIn("if target_cpu == 1 || kind != IrqKind::VirtioSpi", device)
        self.assertIn("protected_inode: u16, protected_generation: u64", file)
        self.assertIn("frame.owner == 0", memory)
        self.assertIn("total.checked_add(usize::from(lease.descriptors))", device)
        self.assertIn("pub fn can_publish_fixed(", syscall)
        self.assertIn("security::syscall::can_publish_fixed(", manager)

    def test_sec_n_native_tcp_uses_strict_echo_stream_framing(self):
        echo=source(ROOT / "crates/net-transport/src/echo.rs")
        tls=source(ROOT / "crates/net-transport/src/tls.rs")
        ingress=source(ROOT / "crates/net-transport/src/native_tcp.rs")
        device=source(ROOT / "crates/cluster-transport/src/local_echo_tcp.rs")
        admission=source(ROOT / "crates/net-transport/src/admission.rs")
        self.assertIn("pub(crate) fn next_frame_len(",echo)
        self.assertIn("next_frame_len(tls.plaintext())",admission)
        self.assertIn("let accepted = self.received;",tls)
        self.assertIn("self.buffers.received[accepted..]",tls)
        self.assertIn("tls.receive_tls(&scratch[..n])",ingress)
        self.assertIn("tls.consume_tls(queued)",ingress)
        self.assertIn("impl<P: Port> NativeSocket for Tcp<'_, P>",device)
        self.assertNotIn("member_rpc(",ingress)
        self.assertNotIn("remote_placement",device)

    def test_sec_d_native_net_tx_receipts_retain_exact_generation_until_ack(self):
        driver=source(ROOT / "crates/driver-virtio/src/net/batched.rs")
        self.assertIn("pub fn poll_tx_receipt(",driver)
        self.assertIn("pub fn acknowledge_tx(",driver)
        self.assertIn("self.completed_tx != Some(receipt)",driver)
        self.assertIn("self.tx.release(receipt.token)?",driver)
        self.assertIn("v019_sec_d_tx_completion_retains_dma_until_exact_generation_ack",driver)

    def test_ai_proposals_are_not_capabilities(self):
        src = source(CORE / "process.rs")
        self.assertIn("pub fn authorize_business_core(", src)
        src = source(CORE / "memory.rs")
        self.assertIn("pub fn authorize_data_frame_slot(", src)
        src = source(CORE / "syscall.rs")
        self.assertIn("fn from_kernel(", src)


if __name__ == "__main__":
    unittest.main()
