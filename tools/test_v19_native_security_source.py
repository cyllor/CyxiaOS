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
        assert "cluster_id" not in echo and "remote" not in echo

    def test_ai_proposals_are_not_capabilities(self):
        src = source(CORE / "process.rs")
        self.assertIn("pub fn authorize_business_core(", src)
        src = source(CORE / "memory.rs")
        self.assertIn("pub fn authorize_data_frame_slot(", src)
        src = source(CORE / "syscall.rs")
        self.assertIn("fn from_kernel(", src)


if __name__ == "__main__":
    unittest.main()
