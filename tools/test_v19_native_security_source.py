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

    def test_v020_cpu0_fixed_and_two_brains_have_no_runtime_scale_path(self):
        native = source(ROOT / "kernel/src/runtime/control/prototype_runtime.rs")
        model = source(ROOT / "user/prototype-runtime/main.rs")
        role = source(ROOT / "crates/kernel-core/src/control_plane/fixed.rs")
        contract = source(ROOT / "crates/kernel-core/src/control_plane/cpu0_v0199.rs")
        cores = source(ROOT / "crates/prototype/src/cores.rs")
        manager = source(ROOT / "crates/kernel-core/src/control_plane/manager.rs")
        self.assertIn("Cores::new_fixed(CoreSet::from_bits(15))", native)
        self.assertNotIn("self.poll_handoff(now);", native)
        self.assertNotIn("self.poll_secondary(now);", native)
        self.assertNotIn("self.propose(target, accepted_at);", native)
        self.assertNotIn("core_candidates(input[15])", model)
        # Single authoritative topology: the cpu0_v0199 contract fixes C={CPU0},
        # B={CPU1,CPU2,CPU3}, and fixed.rs re-exports it (no dual truth).
        self.assertIn("pub const CONTROL_CPU: usize = 0;", contract)
        self.assertIn("pub const BUSINESS_MASK: u64 = 0b1110;", contract)
        self.assertIn("pub const CONTROL_CPU: usize = super::cpu0_v0199::CONTROL_CPU;", role)
        self.assertIn("pub const CONTROL_MASK: u64 = super::cpu0_v0199::CONTROL_MASK;", role)
        self.assertIn("pub fn review", role)
        self.assertIn("pub fn new_fixed(online: CoreSet)", cores)
        self.assertIn("CoreSet::from_bits(0b0001)", cores)
        self.assertIn("if self.fixed_control {\n            return Err(Error::Invalid);\n        }", cores)
        self.assertIn("fn review_brains", manager)

    def test_v020_native_domain_never_publishes_moved_control_cpu(self):
        native = source(ROOT / "kernel/src/runtime/control/domain_control.rs")
        self.assertIn("context.control_mask != 0b0001", native)
        self.assertIn("Action::ControlSet(mask) if mask != 0b0001", native)
        self.assertIn("self.provenance.at(submission::Stage::Stamp)", native)

    def test_sec_n_source_bound_active_credits_and_bounded_idle_eviction(self):
        network = source(CORE / "network.rs")
        self.assertIn("pub fn close_active_from(&mut self, ip: u32)", network)
        self.assertIn("entry.active != 0", network)
        self.assertIn("if self.active >= MAX_ACTIVE {\n                return Err(Error::Capacity);\n            }", network)
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
        self.assertIn("row.proof == proof", gate)
        self.assertIn(".accept_local_echo(&bytes[..length])", gate)
        self.assertIn("pub fn begin_restart(&mut self)", gate)
        self.assertIn("self.active_count() != 0", gate)
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
        self.assertIn("row.state != State::Draining || row.tls_egress_pending", gate)
        self.assertIn("pub(crate) fn reply(", gate)
        self.assertIn("pub fn local_echo_proof(&self)", tls)

    def test_sec_n_single_authoritative_admission_ledger(self):
        # 2026-11-25 designation (six-tracks "生产级接线门槛"): Admission is
        # the sole authoritative production connection-credit ledger; the
        # kernel-core RateLimiter stays a legacy host-contract model and is
        # never referenced by the native transport or the EL0 Echo guest.
        legacy = source(CORE / "network.rs")
        self.assertIn("Legacy host-contract rate limiter", legacy)
        self.assertIn("NOT the production admission ledger", legacy)
        self.assertIn("cyxia_net_transport::admission::Admission", legacy)
        self.assertIn("sole authoritative connection-credit ledger", legacy)
        self.assertIn("Never wire both ledgers on one production connection", legacy)
        self.assertIn("生产级接线门槛", legacy)
        gate = source(ROOT / "crates/net-transport/src/admission.rs")
        self.assertIn("Designated sole authoritative production connection-credit ledger", gate)
        self.assertIn("single-machine native EL0 Echo service", gate)
        self.assertIn("real TCP/VirtIO/TLS completion evidence", gate)
        self.assertIn("生产级接线门槛", gate)
        for directory in (ROOT / "crates/net-transport/src", ROOT / "user/local-echo/src"):
            for path in sorted(directory.rglob("*.rs")):
                self.assertNotIn("RateLimiter", source(path), str(path))

    def test_v020_other_five_tracks_fail_closed_with_fixed_control_roles(self):
        process = source(CORE / "process.rs")
        file = source(CORE / "file.rs")
        memory = source(CORE / "memory.rs")
        device = source(CORE / "device.rs")
        syscall = source(CORE / "syscall.rs")
        manager = source(ROOT / "crates/kernel-core/src/control_plane/manager.rs")
        # CPU0 is the only control core; CPU1-3 are the business cores. The
        # legacy SEC-P gate delegates to the single authoritative cpu0_v0199
        # business boundary instead of the old CPU0+CPU1 rejection.
        self.assertIn("if cpu == 0 {\n        return Err(Error::Unauthorized);\n    }", process)
        self.assertIn("authorize_business_core_v0199(", process)
        self.assertIn("cpu0_v0199::permits_business(", process)
        self.assertNotIn("request.cpu >= 2", process)
        self.assertIn("if target_cpu == 0\n        || kind != IrqKind::VirtioSpi", device)
        self.assertIn("protected_inode: u16,\n        protected_generation: u64,", file)
        self.assertIn("frame.owner == 0", memory)
        self.assertIn("total.checked_add(usize::from(lease.descriptors))", device)
        self.assertIn("pub fn can_publish_fixed(", syscall)
        self.assertIn("executing_cpu != crate::control_plane::fixed::CONTROL_CPU", syscall)
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

    def test_sec_n_d_native_device_evidence_gates_connection_retirement(self):
        driver=source(ROOT / "crates/driver-virtio/src/net/batched.rs")
        single=source(ROOT / "crates/driver-virtio/src/net.rs")
        port=source(ROOT / "crates/cluster-transport/src/device.rs")
        tcp=source(ROOT / "crates/cluster-transport/src/tcp.rs")
        adapter=source(ROOT / "crates/cluster-transport/src/local_echo_tcp.rs")
        native=source(ROOT / "crates/net-transport/src/native_tcp.rs")
        ledger=source(ROOT / "crates/net-transport/src/admission.rs")
        self.assertIn("self.completed_tx.is_none() && self.tx.is_quiescent()",driver)
        self.assertIn("!self.failed && !self.tx.pending",single)
        self.assertIn("fn tx_quiescent(&self) -> bool {\n        false\n    }",port)
        self.assertIn("self.device.port().tx_quiescent()",tcp)
        self.assertIn("impl<P: Port> NativeSocket for Tcp<'_, P>",adapter)
        self.assertIn("fn terminal_tx_quiescent(&self) -> bool",native)
        self.assertIn("pub fn finish_session<S: NativeSocket>",native)
        self.assertIn(".verify_session(key, tls)",native)
        self.assertIn("pub(crate) fn finish_drain(",ledger)
        self.assertNotIn("pub fn finish_drain(",ledger)

    def test_v019_local_echo_el0_guest_has_only_network_broker_rights(self):
        manifest = source(ROOT / "user/local-echo/Cargo.toml")
        surface = source(ROOT / "user/local-echo/src/lib.rs")
        guest = source(ROOT / "user/local-echo/src/runtime.rs")
        broker = source(ROOT / "user/local-echo/src/broker.rs")
        build = source(ROOT / "user/local-echo/build.rs")
        self.assertIn("cyxia-net-transport", manifest)
        self.assertNotIn("cyxia-cluster-transport", manifest)
        self.assertNotIn("cyxia-prototype-cluster", manifest)
        self.assertIn("pub const DIRECT_TLS_CIPHERTEXT: u64 = 1", surface)
        self.assertIn("match op {", surface)
        self.assertIn("allowed::allowed(op, len, arg0)", broker)
        self.assertIn("native_tcp::turn(", guest)
        self.assertIn("gate.begin_restart();", guest)
        self.assertIn("fn terminal_tx_quiescent(&self) -> bool {\n        false\n    }", guest)
        self.assertIn("CYXIA_LOCAL_ECHO_IDENTITY", build)
        abi=source(ROOT / "user/local-echo/src/abi.rs")
        main=source(ROOT / "user/local-echo/src/main.rs")
        self.assertIn("pub struct DomainSourceView", abi)
        self.assertIn("offset_of!(Shared, payload) == 2696",abi)
        self.assertNotIn("cyxia_prototype",abi)
        self.assertNotIn("prototype-cluster/src/abi.rs",main)
        fixture=source(ROOT / "user/local-echo/tests/native_shared_layout.rs")
        self.assertIn("native_local_echo_shared_page_matches_kernel_broker_offsets",fixture)
        self.assertIn("cargo check --release --locked --offline -p cyxia-local-echo --features guest", source(ROOT / ".github/workflows/v19-advisory-smoke.yml"))

    def test_v019_freestanding_ring_uses_existing_native_crypto_patch(self):
        manifest = source(ROOT / "Cargo.toml")
        lock = source(ROOT / "Cargo.lock")
        self.assertIn('ring = { path = "user/prototype-cluster/vendor/ring" }', manifest)
        self.assertIn('name = "ring"\nversion = "0.17.14"\ndependencies', lock)
        self.assertNotIn('name = "ring"\nversion = "0.17.14"\nsource = "registry+', lock)

    def test_v020_wave_structural_pins_kernel_core_cluster_isolation(self):
        # Wave 1: the historical dual-node security core stays compiled out of
        # the single-machine default build; its test target needs the feature.
        lib = source(ROOT / "crates/kernel-core/src/lib.rs")
        manifest = source(ROOT / "crates/kernel-core/Cargo.toml")
        self.assertIn('#[cfg(feature = "legacy-cluster")]\npub mod cluster;', lib)
        self.assertIn("legacy-cluster = []", manifest)
        self.assertIn('[[test]]\nname = "cluster"\nrequired-features = ["legacy-cluster"]', manifest)

    def test_v020_wave_structural_pins_prototype_wire_isolation(self):
        # Wave 2: the cluster wire codec is legacy-only and the engine feature
        # implies it, so no default build can reach the historical wire path.
        cluster = source(ROOT / "crates/prototype/src/cluster/mod.rs")
        manifest = source(ROOT / "crates/prototype/Cargo.toml")
        self.assertIn('#[cfg(feature = "legacy-cluster")]\npub mod wire;', cluster)
        self.assertIn("legacy-cluster = []", manifest)
        self.assertIn('cluster-engine = ["legacy-cluster"]', manifest)
        self.assertIn('[[test]]\nname = "cluster_wire"\nrequired-features = ["legacy-cluster"]', manifest)

    def test_v020_wave_structural_pins_local_volume_relocation(self):
        # Wave 3: reserved-volume storage left the cluster module; the local
        # module keeps the exact MAX_EFFECT bound under both cfg branches.
        lib = source(ROOT / "crates/prototype/src/lib.rs")
        cluster = source(ROOT / "crates/prototype/src/cluster/mod.rs")
        self.assertIn("pub mod local_volume;", lib)
        self.assertNotIn("pub mod volume;", lib)
        self.assertNotIn("pub mod volume;", cluster)
        volume_path = ROOT / "crates/prototype/src/local_volume.rs"
        self.assertTrue(volume_path.is_file())
        volume = source(volume_path)
        self.assertIn('#[cfg(feature = "cluster-engine")]\npub use crate::cluster::engine::MAX_EFFECT;', volume)
        self.assertIn('#[cfg(not(feature = "cluster-engine"))]\npub const MAX_EFFECT: usize = 33_200;', volume)

    def test_v020_wave_structural_pins_admit_v3_contract(self):
        # Wave 2: FILE_AUTH ADMIT v3 / COMPLETE v1 contract layer pins the
        # frozen baseline magics, versions and frame sizes. Contract layer
        # only; native EL1 wiring is a later gate and is not claimed here.
        contract_path = CORE / "file_auth_v3.rs"
        self.assertTrue(contract_path.is_file())
        contract = source(contract_path)
        self.assertIn("pub const ADMIT_REQUEST_MAGIC: u32 = 0x4359_5646;", contract)
        self.assertIn("pub const ADMIT_REPLY_MAGIC: u32 = 0x4359_5652;", contract)
        self.assertIn("pub const COMPLETE_REQUEST_MAGIC: u32 = 0x4359_4643;", contract)
        self.assertIn("pub const ADMIT_REQUEST_VERSION: u16 = 3;", contract)
        self.assertIn("pub const ADMIT_REPLY_VERSION: u16 = 3;", contract)
        self.assertIn("pub const COMPLETE_REQUEST_VERSION: u16 = 1;", contract)
        self.assertIn("pub const ADMIT_REQUEST_BYTES: usize = 128;", contract)
        self.assertIn("pub const ADMIT_REPLY_BYTES: usize = 48;", contract)
        self.assertIn("pub const COMPLETE_REQUEST_BYTES: usize = 56;", contract)
        self.assertIn("pub const COMPLETE_REPLY_BYTES: usize = 8;", contract)
        self.assertIn("pub const FILE_AUTH_ADMIT: u16 = 1;", contract)
        self.assertIn("pub const FILE_AUTH_COMPLETE: u16 = 2;", contract)
        self.assertIn('pub const OPERATION_DOMAIN: &[u8] = b"CYX/FILE-ADMIT/v3";', contract)
        self.assertIn("pub mod file_auth_v3;", source(CORE / "mod.rs"))

    def test_v020_wave_structural_pins_legacy_coreset_gate(self):
        # Wave 2: the default smp-selftest fixture is fixed CPU0; the retired
        # dynamic C/B/T/Q transition fixture only compiles under legacy-coreset.
        manifest = source(ROOT / "kernel/Cargo.toml")
        smp = source(ROOT / "kernel/src/arch/aarch64/smp.rs")
        self.assertIn("legacy-coreset = []", manifest)
        self.assertIn('        feature = "legacy-coreset"\n    )))]\n    fixed_cpu0_fixture()', smp)
        self.assertIn('    feature = "legacy-coreset"\n)))]\nfn fixed_cpu0_fixture() -> ! {', smp)
        self.assertIn('#[cfg(feature = "legacy-coreset")]\nfn fixture(mut ownership: Ownership<C>) -> ! {', smp)
        self.assertIn("        fixture(ownership)\n    }", smp)

    def test_v020_wave_structural_pins_smp_verifier_contract(self):
        # Wave 2: the host verifier's default validate() pins the fixed-CPU0
        # evidence; the retired contract is reachable only via --legacy-coreset,
        # and CI keeps a dedicated build+run lane for that opt-in profile.
        verifier = source(ROOT / "tools/verify_smp.py")
        smp = source(ROOT / "kernel/src/arch/aarch64/smp.rs")
        workflow = source(ROOT / ".github/workflows/smp-native.yml")
        self.assertIn("def validate(serial: bytes, page: bytes, cpu_count: int) -> dict:", verifier)
        self.assertIn("def validate_legacy(serial: bytes, page: bytes, cpu_count: int) -> dict:", verifier)
        self.assertIn("parser.add_argument('--legacy-coreset', action='store_true',", verifier)
        self.assertIn("require(rows('SMP_FIXED_CPU0') == [(words[5], words[6], 1)],", verifier)
        self.assertIn("scope = 'SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false'", verifier)
        self.assertIn("validator = (validate_legacy if legacy else validate) if acceptance is None else acceptance.validate", verifier)
        self.assertIn("report['fixture_contract'] = 'legacy-coreset' if legacy else 'fixed-cpu0'", verifier)
        self.assertIn("SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false", smp)
        self.assertIn("--features smp-selftest,legacy-coreset", workflow)
        self.assertIn("python3 tools/verify_smp.py --legacy-coreset --elf", workflow)
        self.assertIn("Build and boot retired legacy CoreSet profile", workflow)

    def test_v020_wave_structural_pins_irq_maintenance_reserve(self):
        # Wave 1: each 100 ms business window hard-commits at most 90 ms; the
        # explicit 10 ms IRQ/maintenance reserve is compile-time accounted.
        scheduler = source(ROOT / "crates/prototype/src/domains/tasks/scheduler.rs")
        self.assertIn("pub const IRQ_MAINTENANCE_RESERVE_NS: u64 = WINDOW_NS / 10;", scheduler)
        self.assertIn("pub const CPU_BUDGET_NS: u64 = WINDOW_NS - IRQ_MAINTENANCE_RESERVE_NS;", scheduler)
        self.assertIn("const _: () = assert!(CPU_BUDGET_NS + IRQ_MAINTENANCE_RESERVE_NS == WINDOW_NS);", scheduler)

    def test_ai_proposals_are_not_capabilities(self):
        src = source(CORE / "process.rs")
        self.assertIn("pub fn authorize_business_core(", src)
        src = source(CORE / "memory.rs")
        self.assertIn("pub fn authorize_data_frame_slot(", src)
        src = source(CORE / "syscall.rs")
        self.assertIn("fn from_kernel(", src)


if __name__ == "__main__":
    unittest.main()
