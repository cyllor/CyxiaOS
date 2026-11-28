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

    def test_native_user_copies_share_the_window_and_release_pins_after_copy(self):
        task_memory = source(ARM / "memory.rs")
        self.assertIn("    fn transfer(", task_memory)
        transfer = task_memory.split("    fn transfer(", 1)[1].split("\n    }", 1)[0]
        copied = transfer.index("let transferred = copy(physical")
        self.assertLess(transfer.index(".pin("), copied)
        self.assertLess(copied, transfer.index(".unpin("))
        self.assertNotIn("frame_ptr(", transfer)
        self.assertIn("copy_window::copy_in(", task_memory)
        self.assertIn("copy_window::copy_out(", task_memory)
        task_abi = source(ARM / "abi.rs")
        self.assertIn("s.user_memory(owner)?.copyin(address, out)", task_abi)
        self.assertIn("s.user_memory(owner)?.copyout(address, input)", task_abi)

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
        device=source(ROOT / "crates/net-transport/src/local_echo_tcp.rs")
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
        port=source(ROOT / "crates/net-transport/src/device.rs")
        tcp=source(ROOT / "crates/net-transport/src/tcp.rs")
        adapter=source(ROOT / "crates/net-transport/src/local_echo_tcp.rs")
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
        self.assertIn("fn terminal_tx_quiescent(&self) -> bool {\n        self.terminal\n    }", guest)
        retirement = guest.split("if session.normal_close_complete() {", 1)[1]
        self.assertRegex(retirement, r"(?s)poll_normal_close\(generation, source\).*socket\.terminal = true;.*native_tcp::finish_session\(")
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
        self.assertIn('ring = { path = "vendor/ring" }', manifest)
        self.assertIn('name = "ring"\nversion = "0.17.14"\ndependencies', lock)
        self.assertNotIn('name = "ring"\nversion = "0.17.14"\nsource = "registry+', lock)

    def test_v020_wave_structural_pins_kernel_core_cluster_isolation(self):
        # Ledger #26 phase 0: the gated dual-node security core had zero active
        # consumers and was deleted outright (module, tests and feature). The
        # protective intent is unchanged: cluster code stays out of kernel-core.
        # prototype::cluster (wire/engine) remains gated pending phase 1, while
        # the kernel unified-runtime facade still references it.
        lib = source(ROOT / "crates/kernel-core/src/lib.rs")
        manifest = source(ROOT / "crates/kernel-core/Cargo.toml")
        self.assertNotIn("pub mod cluster;", lib)
        self.assertNotIn("legacy-cluster", manifest)
        self.assertNotIn('name = "cluster"', manifest)
        self.assertFalse((ROOT / "crates/kernel-core/src/cluster").exists())
        self.assertFalse((ROOT / "crates/kernel-core/tests/cluster.rs").exists())

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

    def test_v020_wave6_structural_pins_policy_lock_budget_baseline(self):
        # Wave 6: the G1 lock-chain scaffold keeps the frozen baseline budget
        # split (45us effective work + 5us acquisition <= 50us IRQ-off total).
        # Only the baseline constants are pinned; the metering counters are
        # still being hardened this wave and are deliberately not pinned.
        lock_path = ROOT / "crates/kernel-core/src/control_plane/policy_lock_v0199.rs"
        self.assertTrue(lock_path.is_file())
        lock = source(lock_path)
        self.assertIn("pub mod policy_lock_v0199;", source(ROOT / "crates/kernel-core/src/control_plane/mod.rs"))
        self.assertIn("pub const WORK_BUDGET_NS: u64 = 45_000;", lock)
        self.assertIn("pub const IRQ_OFF_BUDGET_NS: u64 = 50_000;", lock)
        self.assertIn("pub const ACQUISITION_BUDGET_NS: u64 = 5_000;", lock)

    def test_v020_wave6_structural_pins_frame_meta_static_region_path(self):
        # Wave 6: the bounded static FrameMeta path exists as structure only;
        # the frames bridge wiring is still being rewritten this wave and is
        # deliberately not pinned here.
        meta_path = ROOT / "crates/kernel-core/src/frame_meta_v0199.rs"
        self.assertTrue(meta_path.is_file())
        meta = source(meta_path)
        self.assertIn("pub fn initialize_static(", meta)
        self.assertIn("regions: &[StaticRegion],", meta)
        self.assertIn("pub struct StaticRegion {", meta)
        self.assertIn("pub enum StaticClass {", meta)

    def test_v020_wave6_structural_pins_advice_e2e_fixture_scope(self):
        # Wave 6: the advice-chain E2E stays a fixture-scoped opt-in feature;
        # production in-vector wiring is explicitly not claimed. The sec-n
        # feature set in kernel/Cargo.toml is still being rewritten this wave
        # and is deliberately not pinned here.
        manifest = source(ROOT / "kernel/Cargo.toml")
        self.assertIn('v0199-advice-e2e-selftest = ["smp-selftest", "dep:sha2"]', manifest)
        fixture_path = ROOT / "kernel/src/arch/aarch64/v0199_advice_e2e.rs"
        self.assertTrue(fixture_path.is_file())
        fixture = source(fixture_path)
        self.assertIn("V0199_ADVICE_E2E_SCOPE production_wiring=false real_services=false fixture_executor=true", fixture)
        self.assertTrue((ROOT / "tools/verify_v0199_advice_e2e.py").is_file())

    def test_v020_wave6_structural_pins_net_transport_adapter_relocation(self):
        # Wave 6: the SEC-N NativeSocket adapter lives in the active
        # single-machine net-transport crate; cluster-transport is only a
        # re-export facade and must not own a second adapter implementation.
        adapter_path = ROOT / "crates/net-transport/src/local_echo_tcp.rs"
        self.assertTrue(adapter_path.is_file())
        adapter = source(adapter_path)
        self.assertIn("Relocated from the excluded legacy cluster crate", adapter)
        self.assertIn("impl<P: Port> NativeSocket for Tcp<'_, P>", adapter)
        facade = source(ROOT / "crates/cluster-transport/src/lib.rs")
        self.assertIn("pub use cyxia_net_transport", facade)
        self.assertIn("pub use cyxia_net_transport::local_echo_tcp;", facade)
        self.assertNotIn("impl<P: Port> NativeSocket", facade)

    def test_v020_wave6_structural_pins_legacy_d16_decode_gate(self):
        # Wave 6: the legacy D16 (OfferCpu/Placement) decode arms are opt-in
        # only; the default decode rejects domain 16. The wire module lives at
        # crates/prototype/src/policy_wire.rs (not under domains/).
        manifest = source(ROOT / "crates/prototype/Cargo.toml")
        self.assertIn("legacy-d16-decode = []", manifest)
        wire = source(ROOT / "crates/prototype/src/policy_wire.rs")
        self.assertIn('#[cfg(feature = "legacy-d16-decode")]\n        (16, 1) => Action::OfferCpu(u16_at(b, 2)?),', wire)
        self.assertIn('#[cfg(feature = "legacy-d16-decode")]\n        (16, 2) => Action::Placement(u16_at(b, 2)?),', wire)
        self.assertIn("_ => return Err(Error::Unsupported),", wire)

    def test_v020_wave6_structural_pins_task_admission_legacy_scope_rename(self):
        # Wave 6: the custody key's remote-task scope field is source-only
        # legacy naming; the positional wire ABI is unchanged and the native
        # single-machine profile carries no cluster runtime.
        admission = source(ROOT / "crates/kernel-core/src/control_plane/task_admission.rs")
        self.assertIn("pub legacy_remote_scope: [u8; 32],", admission)
        self.assertIn("key.legacy_remote_scope == [0; 32]", admission)
        self.assertNotIn("pub cluster:", admission)

    # Wave 7 pin deferrals (2026-11-25): frames.rs (FrameRecorder trait),
    # frame_meta_v0199.rs initialize_pool, and net-transport service.rs /
    # discovery.rs all exist at HEAD but are being rewritten by concurrent
    # wave tasks; they are deliberately not pinned until those rewrites
    # land. The vendor/ring neutral path is already pinned by
    # test_v019_freestanding_ring_uses_existing_native_crypto_patch.

    def test_v020_wave7_structural_pins_ai_control_retirement_replay_lane(self):
        # Wave 7: ai-control-selftest / model-v13-selftest are retired
        # pre-cutover CPU1-control history; a standalone build emits
        # compile_error by design (kernel/src/arch/aarch64/smp.rs retirement
        # marker, not pinned here while smp.rs gains its new fixture). The
        # native CI lane survives only as an explicit legacy-coreset replay,
        # mirroring the retired-profile lane in smp-native.yml.
        workflow = source(ROOT / ".github/workflows/ai-control-native.yml")
        umbrella = "--features smp-selftest,ai-control-selftest,legacy-coreset"
        # All three build sites (clippy, debug/release profile builds, fault
        # builds) use the retirement umbrella; no standalone feature flag
        # may remain (comment prose is not a feature flag).
        self.assertEqual(workflow.count(umbrella), 3)
        self.assertNotRegex(workflow, r"--features\s+ai-control-selftest(?![\w,-])")
        self.assertIn("Retired pre-cutover CPU1-control history", workflow)

    def test_v020_wave7_structural_pins_file_auth_context_contract_layer(self):
        # Wave 6/7: the EL1-internal AuthContext identity + admission-ledger
        # contract layer exists and is declared. Contract layer only; native
        # EL1 wiring is a later gate and is not claimed here. The frozen
        # baseline bounds (16 principals, 16 ledger records) are pinned;
        # ledger state rules stay host-test territory.
        context_path = CORE / "file_auth_context_v1.rs"
        self.assertTrue(context_path.is_file())
        self.assertIn("pub mod file_auth_context_v1;", source(CORE / "mod.rs"))
        context = source(context_path)
        self.assertIn("pub struct AuthContextV1 {", context)
        self.assertIn("pub const MAX_AUTH_PRINCIPALS: usize = 16;", context)
        self.assertIn("pub const ADMISSION_LEDGER_CAPACITY: usize = 16;", context)

    # Wave 10 pin deferrals (2026-11-25, T6 sync time, HEAD defeae7): the
    # v020-production feature declaration (kernel/Cargo.toml), the
    # file_media_unified_v1 module, T1's production verifier (expected path
    # tools/verify_v020_production.py), T3's FrameMeta allocator skeleton,
    # T4's real VirtIO-net SEC-N adapter and T5's BootEpoch/Recovery native
    # APIs are concurrent in-progress wave-10 outputs with no committed
    # artifact in this checkout (verified by reading; T3/T5 edits appeared
    # uncommitted during T6 execution). They are deliberately not pinned
    # until they land; pin only the stable T6 skeleton lane below.

    def test_v020_wave10_structural_pins_production_skeleton_lane(self):
        # Wave 10 (T6, wired centrally after T1 landed): the production-wiring
        # CI lane is an honest skeleton, NOT G4 acceptance. The v020-production
        # profile build command and production-skeleton scope labels are pinned;
        # the run step now invokes T1's frozen verifier CLI (pinned QEMU on PATH,
        # provenance hash gates) and exits non-zero on FAIL. A skeleton-lane green
        # is never production run evidence.
        workflow_path = ROOT / ".github/workflows/v020-production.yml"
        self.assertTrue(workflow_path.is_file())
        workflow = source(workflow_path)
        self.assertIn(
            "cargo build --locked --offline -p cyxia-kernel --target aarch64-unknown-none-softfloat --features v020-production-diagnostic",
            workflow,
        )
        self.assertIn("name: V0.20 production-wiring skeleton (NOT G4 acceptance)", workflow)
        self.assertIn('"lane_scope": "production-skeleton"', workflow)
        self.assertRegex(workflow, r"(?m)^    branches: \[CyxiaOS-V0\.20(?:,|\])")
        self.assertIn("- 'kernel/**'", workflow)
        self.assertIn("RUSTUP_TOOLCHAIN: '1.95.0'", workflow)
        self.assertIn("f8ed81651e61d9c2166df6121ce2af0f44f06b3e", workflow)
        self.assertIn("tools/qemu/cyxia-per-vcpu-pmu.patch", workflow)
        self.assertIn("python3 -B tools/verify_v020_production.py", workflow)
        self.assertIn("--elf artifacts/v020-production/kernel.elf", workflow)
        self.assertIn("python3 -B tools/verify_v020_resident.py", workflow)
        self.assertIn("--elf artifacts/v020-production/kernel-resident.elf", workflow)

    def test_v020_default_production_keeps_fixture_builds_isolated(self):
        # Default production must not silently change a historical fixture.
        manifest = source(ROOT / "kernel/Cargo.toml")
        self.assertIn('default = ["v0199-local-native", "v020-production"]', manifest)
        cases = (
            ("ai-control-native", 3),
            ("smp-native", 4),
            ("v20-cpu0-role-native", 1),
            ("v20-cpu0-role-replay", 1),
            ("v20-native-eight-role-bringup", 2),
            ("v20-native-hardening", 1),
            ("v20-native-mechanism", 2),
            ("validate-current", 1),
        )
        for name, expected in cases:
            with self.subTest(workflow=name):
                workflow = source(ROOT / ".github/workflows" / (name + ".yml"))
                commands = [
                    line for line in workflow.splitlines()
                    if ("cargo build " in line or "cargo clippy " in line)
                    and "--target aarch64-unknown-none-softfloat" in line
                ]
                self.assertEqual(len(commands), expected)
                for command in commands:
                    self.assertIn("--no-default-features", command)
                    self.assertNotIn("--features v020-production", command)
        for name in ("v20-native-eight-role-bringup", "v20-native-hardening",
                     "v20-native-mechanism"):
            workflow = source(ROOT / ".github/workflows" / (name + ".yml"))
            self.assertIn("work/v020-integrated-eleven-gate-custody", workflow)

    def test_v020_wave10_structural_pins_t1_production_skeleton(self):
        # The default resident has no fixture dependencies. The explicit
        # diagnostic build retains the SvcV3Bridge exception-vector coverage.
        manifest = source(ROOT / "kernel/Cargo.toml")
        startup_features = next(line for line in manifest.splitlines() if line.startswith("v020-production = "))
        self.assertIn('"smp-selftest"', startup_features)
        self.assertIn('"dep:sha2"', startup_features)
        self.assertNotIn("diagnostic", startup_features)
        self.assertIn('v020-production-diagnostic = ["v020-production", "dep:sha2", "sec-n-native"]', manifest)
        boot = source(ROOT / "kernel/src/arch/aarch64/boot.rs")
        self.assertIn('feature = "v020-production"))]\n    smp::production::run(&info);', boot)
        exceptions = source(ROOT / "kernel/src/arch/aarch64/exceptions.rs")
        self.assertIn("smp::production::exception(f, kind);", exceptions)
        prod_path = ROOT / "kernel/src/arch/aarch64/production.rs"
        self.assertTrue(prod_path.is_file())
        prod = source(prod_path)
        # Honest scope: skeleton only, never full authority or real models.
        self.assertIn(
            "V020_PROD_SCOPE production_skeleton=true full_authority=false real_models=false",
            prod,
        )
        self.assertIn("production_skeleton=true, full_authority=false, real_models=false", prod)
        # In-vector dispatch reuses the SAME kernel-core bridge APIs as the
        # advice-e2e fixture (no reinvented chain).
        self.assertIn("decode_aarch64_svc_v3(ABI_VERSION, f.esr, &f.regs)", prod)
        self.assertIn("return Some(preflight_errno(error) as u64)", prod)
        self.assertNotIn('expect("actual ABI3 role trap")', prod)
        self.assertIn("bridge.register_assisted_one(", prod)
        self.assertIn("bridge.publish_assisted_one(", prod)
        self.assertIn(".claim_apply_work(", prod)
        self.assertIn(".settle_verified_apply_reports_with_feedback(", prod)
        # The production profile owns CPU0 and must not mix with other fixtures.
        smp = source(ROOT / "kernel/src/arch/aarch64/smp.rs")
        self.assertIn('compile_error!("v020-production requires the plain smp-selftest profile");', smp)
        self.assertIn('#[cfg(feature = "v020-production-diagnostic")]\n#[path = "production.rs"]', smp)
        self.assertIn('#[path = "production/resident.rs"]', smp)
        self.assertIn('#[cfg(cyxia_startup_catalog)]\n#[path = "production/authorized.rs"]', smp)
        authorized = source(ROOT / "kernel/src/arch/aarch64/production/authorized.rs")
        self.assertIn("signed_resident::run(info)", authorized)
        # The role catalog is built for the diagnostic feature.
        build = source(ROOT / "kernel/build/aarch64.rs")
        self.assertIn('env::var_os("CARGO_FEATURE_V020_PRODUCTION_DIAGNOSTIC").is_some()', build)
        self.assertTrue((ROOT / "tools/verify_v020_production.py").is_file())

    def test_v020_wave11_feature_gating(self):
        manifest = source(ROOT / "kernel/Cargo.toml")
        self.assertRegex(manifest, r'(?m)^v020-production-diagnostic = \[[^\]]*"sec-n-native"[^\]]*\]')
        self.assertRegex(
            manifest,
            r'(?m)^v020-production-media-staging = \[[^\]]*"v020-production-diagnostic"[^\]]*\]',
        )
        comp = source(ROOT / "kernel/src/composition/aarch64.rs")
        gate = comp.split('mod virtio_platform;')[0].rsplit("#[cfg(any(", 1)[1]
        self.assertIn('feature = "v020-production-diagnostic"', gate)
        near = comp.split("mod net_device;")[0][-700:]
        self.assertNotIn("allow(dead_code)", near)
        self.assertNotIn("not yet wired by default", near)

    def test_v020_wave11_sec_n_production_pins(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        net = source(arm / "production/net.rs")
        self.assertIn("net_device::with_device(", net)
        self.assertIn("net_device::terminal_custody(identity.boot_epoch())", net)
        self.assertNotIn("LoopbackPort", net)
        self.assertNotIn("RateLimiter", net)
        self.assertIn("evidence::W11_TLS_ECHO_TURN_VERIFIED, 0", net)
        fixture = source(arm / "v0199_sec_n_fixture.rs")
        self.assertIn("sec_n_broker::", fixture)
        self.assertNotIn("fn broker(", fixture)
        self.assertNotIn("fn run_until_park(", fixture)
        broker = source(arm / "sec_n_broker.rs")
        dispatch = broker.split("fn broker<P: Port>(", 1)[1].split("fn reply(", 1)[0]
        self.assertIn("OP_TLS_CERTIFICATE_VERIFY => broker_certificate_verify(signer)", dispatch)
        guest = broker.split("pub(crate) fn run_guest<P: Port>(", 1)[1]
        self.assertLess(guest.index("if iss != 0x43"), guest.index("broker("))
        self.assertIn("signer.as_deref_mut()", guest)
        self.assertIn("pub(crate) fn run_until_park<P: Port>(", broker)
        self.assertIn('link_section = ".bss.sec_n', broker)

    def test_v020_wave12_modes_are_explicit(self):
        manifest = source(ROOT / "kernel/Cargo.toml")
        self.assertIn('v020-production-authenticated-net = ["v020-production-diagnostic", "dep:zeroize"]', manifest)
        self.assertIn('v020-production-live-control = ["v020-production-diagnostic"]', manifest)
        self.assertIn('v020-production-media-reopen = ["v020-production-media-staging"]', manifest)
        self.assertIn('v020-production-media-signed = ["v020-production-media-staging"]', manifest)
        self.assertIn('v020-production-media-envelopes = ["v020-production-media-staging"]', manifest)
        self.assertIn('v020-production-media-unified = ["v020-production-media-envelopes"]', manifest)
        self.assertIn('v020-production-snapshot-catalog = ["v020-production-media-unified", "v020-production-media-signed", "v020-production-live-control"]',
                      manifest)
        self.assertIn('v020-production-file-read = ["v020-production-media-unified", "v020-production-media-signed", "v020-production-live-control"]',
                      manifest)
        self.assertIn('v020-production-snapshot-read = ["v020-production-snapshot-catalog", "v020-production-file-read"]',
                      manifest)
        self.assertIn('v020-production-file-sessions = ["v020-production-file-read"]', manifest)
        self.assertIn('v020-production-frame-pool = ["v020-production-diagnostic"]', manifest)
        for base in ("default", "v020-production", "v020-production-media-staging"):
            line = next(line for line in manifest.splitlines() if line.startswith(base + " = "))
            for feature in ("authenticated-net", "live-control", "media-reopen", "media-signed",
                            "media-envelopes", "media-unified", "snapshot-catalog", "file-read",
                            "snapshot-read", "file-sessions", "fsync-scratch", "frame-pool"):
                self.assertNotIn(feature, line)

    def test_v020_wave11_media_staging_is_opt_in(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        staging = 'feature = "v020-production-media-staging"'
        prod = source(arm / "production.rs")
        # The module is mounted only under the opt-in staging feature.
        self.assertEqual(prod.count("mod media_staging;"), 1)
        before = prod.split("mod media_staging;")[0].splitlines()[-2:]
        self.assertEqual(before[0].strip(), f"#[cfg({staging})]")
        self.assertEqual(before[1].strip(), '#[path = "production/media_staging.rs"]')
        media = source(arm / "production/media_staging.rs")
        signature = media.split("pub(super) fn stage(", 1)[1].split(") -> StagingOutcome", 1)[0]
        self.assertIn("info: &BootInfo", signature)
        self.assertIn('feature = "v020-production-fsync-scratch"', signature)
        self.assertIn("file_client: Option<super::file_durable::Client<'_>>", signature)
        self.assertIn("golden_vector_pending=1", media)
        # Outside staging the in-vector 0x40 branch still answers EAGAIN.
        arm40 = prod.split("0x40 => {", 1)[1].split("0x50 if", 1)[0]
        self.assertIn(f"#[cfg(not({staging}))]", arm40)
        self.assertRegex(arm40, r"#\[cfg\(not\(" + staging.replace('"', '\\"').replace("(", r"\(")
                         + r"\)\)\]\s*\{?\s*EAGAIN as u64")
        self.assertIn(f"#[cfg({staging})]", arm40)
        self.assertIn("media_staging::snapshot_0x40(", arm40)
        # v020-production must not imply the staging feature.
        manifest = source(ROOT / "kernel/Cargo.toml")
        line = [l for l in manifest.splitlines() if l.startswith("v020-production = ")][0]
        self.assertNotIn("media-staging", line)
        self.assertNotIn("prototype-memory", line)

    def test_v020_wave11_verifier_lanes_pinned(self):
        # Wave 11 (T7): the G-A lane boots a real modern virtio-net device, keeps
        # the no-NIC negative control and the opt-in staging lane, and checks the
        # W11 segment up to word 160 with honest labels.
        verifier = source(ROOT / "tools/verify_v020_production.py")
        qemu = source(ROOT / "tools/v020_production_qemu.py")
        self.assertIn('f"virtio-net-device,netdev=n0,mac={NATIVE_MAC}"', qemu)
        self.assertIn('NATIVE_MAC = "52:54:00:12:34:56"', qemu)
        self.assertIn('"virtio-mmio.force-legacy=false"', qemu)
        self.assertIn('"virtio-rng-device,rng=rng0"', qemu)
        self.assertIn("W11_END = 160", verifier)
        self.assertIn('words[W21_END:]', verifier)
        self.assertIn('"kernel/src/arch/aarch64/production/file_read/sessions.rs"', verifier)
        self.assertIn('"kernel/src/arch/aarch64/production/file_read/volatile_write.rs"', verifier)
        self.assertIn('"tls_echo_turn_verified": False', verifier)
        self.assertIn('"policy_lock_budget_verified": False', verifier)
        self.assertIn('"golden_vector_pending": True', verifier)
        self.assertIn("if NET_ABSENT in serial", verifier)
        workflow = source(ROOT / ".github/workflows/v020-production.yml")
        self.assertIn("s.build_guest(isolated_signer=True)", workflow)
        self.assertIn("signer.sha256", workflow)
        self.assertIn("--no-nic; then", workflow)
        self.assertIn('ValueError: guest reported V020_W11_NET_ABSENT:', workflow)
        self.assertIn('--no-peer; then', workflow)
        self.assertIn('ValueError: V020_W11_NET_NO_PEER:', workflow)
        self.assertIn("--timeout 240 --media-staging", workflow)
        self.assertIn("tools/test_verify_v020_production.py", workflow)
        evidence = source(ROOT / "kernel/src/arch/aarch64/production/evidence.rs")
        self.assertNotIn("allow(dead_code)", evidence)
        self.assertIn("pub fn log_completion()", evidence)
        prod = source(ROOT / "kernel/src/arch/aarch64/production.rs")
        self.assertIn("evidence::log_completion();", prod)

    def test_v020_wave11_ga_call_sites_pinned(self):
        # Spec §5 (final-review I4): every G-A item keeps a live production call
        # site, so none can silently regress to dead code.
        arm = ROOT / "kernel/src/arch/aarch64"
        prod = source(arm / "production.rs")
        run = prod.split("pub(crate) fn run(info: &BootInfo) -> ! {", 1)[1]
        # FrameMeta registration and recovery init run first in run(), in order.
        self.assertIn("frames::register_or_fatal();", run)
        self.assertLess(run.index("frames::register_or_fatal();"),
                        run.index("recovery::init_or_fatal();"))
        self.assertIn("recovery::publish_probe(", run)
        self.assertLess(run.index("STOPPED.load(Ordering::Acquire) == 14"),
                        run.index("recovery::takeover_stopped();"))
        # SEC-N serve runs in run() and its outcome is sealed.
        self.assertIn("let net_outcome = net::serve(info, super::sec_n_broker::BootIdentity::FIXTURE);", run)
        self.assertLess(run.index("let staging_outcome = media_staging::stage("),
                        run.index("match staging_outcome.network_boot()"))
        self.assertIn("Some(identity) => net::serve(info, identity),", run)
        self.assertIn("net::publish(&net_outcome);", run)
        # 0x41: the recovery gate refuses BEFORE the metered bridge call.
        arm41 = prod.split("        0x41 => {", 1)[1].split("\n        _ => 0,", 1)[0]
        self.assertIn("if !recovery::publish_allowed() {", arm41)
        self.assertIn("return E_AUTH as u64;", arm41)
        self.assertLess(arm41.index("recovery::publish_allowed()"),
                        arm41.index("meter::metered("))
        self.assertLess(arm41.index("meter::metered("),
                        arm41.index("bridge.publish_assisted_one("))
        # 0x50 register: the bridge call is metered too; exactly these two.
        arm50 = prod.split("        0x50 if args[2] == (DECISION_BYTES", 1)[1].split(
            "        0x41 => {", 1)[0]
        self.assertLess(arm50.index("meter::metered("),
                        arm50.index("bridge.register_assisted_one("))
        self.assertEqual(prod.count("meter::metered("), 2)
        # EL0 aborts feed the faulting CPU's accumulator in the vector.
        exc = source(arm / "exceptions.rs")
        prod_block = exc.split('feature = "v020-production-diagnostic",', 1)[1].split(
            '#[cfg(feature = "v020-production")]', 1)[0]
        self.assertIn("smp::production::recovery::record_fault(", prod_block)
        self.assertIn('not(feature = "v020-production-signed-resident")', prod_block)
        # The callees are the real implementations, not stubs.
        frames = source(arm / "production/frames.rs")
        self.assertRegex(frames, r"fn register_or_fatal\(\) \{\s*match register_production_statics\(\)")
        self.assertIn("RegisteredDecisionGate::with_pool(", prod)
        self.assertIn("region(addr_of!(PLAN_POOL) as u64, PLAN_POOL_BYTES, Control)?", frames)
        recovery = source(arm / "production/recovery.rs")
        self.assertIn("with_gate(|staged| staged.gate.raise(&staged.pair))", recovery)
        self.assertIn("acc.takeover_stopped_writer(", recovery)
        self.assertIn("acc.record(&ev)", recovery)
        meter = source(arm / "production/meter.rs")
        # Keep both live call sites pinned above, and pin the complete interval
        # observer instead of the retired diagnostic-only begin/end latch.
        self.assertIn("static mut OBSERVATIONS: CompletedSectionObservations", meter)
        scope = meter.split(
            "pub(super) fn metered<T>(f: impl FnOnce() -> T) -> T {", 1
        )[1].split("\n}", 1)[0]
        start = scope.index("let start_ns = now_ns();")
        call = scope.index("let out = f();")
        end = scope.index("let end_ns = now_ns();")
        record = scope.index("m.record(SectionKind::EffectiveWork, start_ns, end_ns)")
        self.assertLess(start, call)
        self.assertLess(call, end)
        self.assertLess(end, record)
        self.assertEqual(scope.count("f()"), 1)
        self.assertTrue(scope.rstrip().endswith("\n    out"))
        net = source(arm / "production/net.rs")
        self.assertIn("pub(super) fn serve(info: &BootInfo, identity: sec_n_broker::BootIdentity<'_>) -> NetOutcome", net)

    def test_v020_wave11_production_parks_halted_cpus_with_wfi(self):
        # Final fix wave I1: under TCG a WFE park spins a host core per halted
        # vCPU and starved the scratch virtio-blk completions (staging flake).
        console = source(ROOT / "kernel/src/arch/aarch64/console.rs")
        halt = console.split("pub(crate) fn halt() -> ! {", 1)[1].split("\n}\n", 1)[0]
        prod = halt.split('#[cfg(feature = "v020-production")]', 1)[1].split(
            '#[cfg(not(feature = "v020-production"))]', 1)[0]
        self.assertIn('"msr daifset, #15", "wfi"', prod)
        self.assertNotIn("wfe", prod)
        verifier = source(ROOT / "tools/verify_v020_production.py")
        self.assertIn('"kernel/src/arch/aarch64/console.rs",', verifier)

    def test_signed_lifecycle_dispatch_consumes_the_verified_package_abi_and_return(self):
        arm = ROOT / "kernel/src/arch/aarch64/production"
        signed = source(arm / "signed_resident.rs")
        loader = source(arm / "role_loader.rs")
        self.assertIn("let syscall_abi = verified.syscall_abi();", loader)
        self.assertIn("PIE_SYSCALL_ABI[index].store(syscall_abi, Ordering::Release);", loader)
        self.assertIn("decode_aarch64_lifecycle_svc_v3(syscall_abi, ctx.esr, &ctx.regs)", signed)
        adapter = signed.split("impl Task {", 1)[1].split("fn reservation(", 1)[0]
        self.assertLess(adapter.index("registered_role_abi(index, member, captured_ttbr0)"),
                        adapter.index("decode_aarch64_authorized_svc_v3("))
        self.assertLess(adapter.index("services.permits(&caller, operation, first)"),
                        adapter.index("services.dispatch(&caller, call, policy)"))
        self.assertIn("captured | CAPTURED", signed)
        self.assertNotIn("trapped_ttbr0()", adapter)
        quantum = signed.split("fn run_quantum(", 1)[1].split("fn run_tasks(", 1)[0]
        self.assertLess(quantum.index("registered_role_abi(index, member, ttbr0)"),
                        quantum.index("user::enter_pinned_until_retired("))
        self.assertLess(quantum.index("ACTIVE_ROLE_TTBR0.swap(0, Ordering::AcqRel)"),
                        quantum.index("let captured_ttbr0 = capture & !CAPTURED"))
        self.assertLess(quantum.index("let captured_ttbr0 = capture & !CAPTURED"),
                        quantum.index("execution.handle_return(&mut task.context)"))
        self.assertLess(quantum.index("execution.handle_return(&mut task.context)"),
                        quantum.index("task.syscall(syscall_abi,"))

        window = source(arm / "copy_window.rs")
        self.assertIn("Signed(&'call SignedCaller)", window)
        self.assertIn("Self::Vector(_) => trapped_ttbr0() == root_asid", window)
        self.assertIn("Self::Signed(caller) => caller.root_asid() == root_asid && caller.registered()",
                      window)

    def test_signed_lifecycle_uses_the_sec_p_execution_trap_contract(self):
        arm = ROOT / "kernel/src/arch/aarch64/production"
        traps = source(arm / "signed_exec_trap.rs")
        self.assertIn("const TRAPPING_BITS: u64 = (1 << 15) | (1 << 16) | (1 << 18);", traps)
        self.assertIn("observed & TRAPPING_BITS == 0", traps)
        self.assertIn("TrapSource::LowerElAarch64", traps)
        self.assertIn("decide_trap(", traps)
        self.assertIn("resume_frame(", traps)

    def test_authorized_network_is_published_after_confirmed_boot_on_business_cpu(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        signed = source(arm / "production/signed_resident.rs")
        startup = signed.split("pub(super) fn run(info:", 1)[1]
        self.assertLess(startup.index("boot.policy()"), startup.index("stage_resident_network("))
        worker = source(arm / "production/network_worker.rs")
        self.assertIn("pub(crate) const CPU: usize = 1;", worker)
        self.assertIn("Plane::Business", worker)
        self.assertIn("authorize_business_core(", worker)
        self.assertIn("network_worker::worker(slot)", source(arm / "smp.rs"))

    def test_resident_ingress_retains_one_frame_across_preemption(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        parser = source(arm / "sec_n_broker/ingress.rs")
        poll = parser.split("pub(crate) fn poll_frame(", 1)[1].split("pub(crate) fn discard_frame(", 1)[0]
        self.assertIn("&mut pending.context", poll)
        self.assertIn("timer::cpu_elapsed_ns(started)", poll)
        self.assertLess(poll.index("return Ok(None);\n        }\n        let pending"),
                        poll.index("self.pending.take()"))
        self.assertLess(poll.index("if matches!(verdict, Ok(true))"),
                        poll.index(".copy_to_nonoverlapping("))
        port = source(arm / "production/net_resident.rs")
        self.assertLess(port.index("if !self.parser.has_pending()"),
                        port.index("self.nic.receive(frame)?"))

    def test_signed_lifecycle_exit_retires_the_root_with_prepaid_recovery(self):
        arm = ROOT / "kernel/src/arch/aarch64/production"
        signed = source(arm / "signed_resident.rs")
        turn = signed.split("fn turn(", 1)[1].split("fn stopped_evidence(", 1)[0]
        settled = turn.index("budget.settle(grant, start, returned)?")
        stopped = turn.index("if let Some(stop) = result?")
        self.assertLess(settled, stopped)
        local, terminal = turn[stopped:].split("budget.ledger.close_ordinary()", 1)
        self.assertLess(local.index(".retire(index, member)"),
                        local.index("task.recovery = RoleRecovery::Stopped"))
        ordered = [
            "budget.reserve_recovery()?",
            "retire_stopped_role(index, member)?",
            "task.context = user::Context::empty()",
            "budget.settle(recovery_grant, recovery_start, 0)?",
            "retirement?;",
            "return Err(Fault::RoleStopped",
        ]
        positions = [terminal.index(step) for step in ordered]
        self.assertEqual(positions, sorted(positions))
        recovery = signed.split("fn recover_one_role(", 1)[1].split("fn run_quantum(", 1)[0]
        self.assertLess(recovery.index("Class::Recovery"), recovery.index("recover_role_step("))
        self.assertLess(recovery.index("recover_role_step("), recovery.index("budget.settle(grant"))
        step = signed.split("fn recover_role_step(", 1)[1].split("fn recover_one_role(", 1)[0]
        self.assertLess(step.index("ACTIVE_ROLE_TTBR0.load"), step.index("retire_stopped_role("))
        loader = source(arm / "role_loader.rs")
        retire = loader.split("pub(super) fn retire_stopped_role(", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(retire.index("registration(index).write(Registration::Retired"),
                        retire.index("root.write_volatile(0)"))
        self.assertLess(retire.index("root.write_volatile(0)"), retire.index("tlbi();"))
        self.assertLess(retire.index("tlbi();"), retire.index("PIE_SYSCALL_ABI[index].store(0"))

    def test_v020_live_pie_dispatch_checks_trapped_identity(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        prod = source(arm / "production.rs")
        dispatch = prod.split("fn pie_dispatch(", 1)[1].split("fn advice_dispatch(", 1)[0]
        self.assertIn("trapped_pie_cap(index, member)", dispatch)
        self.assertLess(dispatch.index("trapped_pie_cap("), dispatch.index("match x8"))
        observations = source(arm / "production/observations.rs")
        snap = observations.split("pub(super) fn snapshot(", 1)[1].split(
            "pub(super) fn audit(", 1
        )[0]
        self.assertIn("trapped_pie_cap(index, m)", snap)
        self.assertIn("endpoint_cap: cap", snap)
        audit = source(arm / "production/observations/audit_rpc.rs")
        self.assertIn("table.admit_live(", audit)
        self.assertIn("trapped_pie_cap(index, m)", audit)
        self.assertNotIn("table.admit(", audit)

    def test_v020_syscall_payloads_use_checked_copy_windows(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        prod = source(arm / "production.rs")
        advice = prod.split("fn advice_dispatch(", 1)[1].split("fn with_bundle(", 1)[0]
        self.assertIn("trapped_ttbr0() != expected", advice)
        self.assertIn("copy_in(&mut plan_copy)", advice)
        self.assertIn("copy_in(&mut side_copy)", advice)
        self.assertNotIn("read_bytes(", advice)
        self.assertIn("StackSpan::from_syscall_static(", prod)

        observations = source(arm / "production/observations.rs")
        snapshot = observations.split("pub(super) fn snapshot(", 1)[1].split(
            "pub(super) fn audit(", 1
        )[0]
        self.assertIn("StackSpan::verify_syscall(", snapshot)
        self.assertLess(snapshot.index("trapped_pie_cap("), snapshot.index("verify_syscall("))
        self.assertLess(snapshot.index("copy_out_and_check("), snapshot.index("SNAP_SEQ.store("))
        self.assertNotIn("copy_reply(", observations)

    def test_v020_combined_mount_gates_both_native_services(self):
        arm = ROOT / "kernel/src/arch/aarch64"
        prod = source(arm / "production.rs")
        normalized = " ".join(prod.split())
        self.assertIn("staging_outcome.services_ready() && let Some(view) = staging_outcome.file_read",
                      normalized)
        self.assertIn("staging_outcome.services_ready() && let Some(view) = staging_outcome.snapshot_catalog",
                      normalized)
        staging = source(arm / "production/media_staging.rs")
        self.assertIn("out.chain_complete = run_chain(&mut disk, &mut out).is_some()", staging)
        self.assertIn("authority::verified_pair_state(disk, checkpoint, config)", staging)
        self.assertRegex(
            staging,
            r"volume::confirmed_receipt_query_digest\(\s*&mounted,\s*&committed,\s*&verified,"
            r"\s*&mut \|\| disk\.checkpoint\(\)",
        )

    def test_ai_proposals_are_not_capabilities(self):
        src = source(CORE / "process.rs")
        self.assertIn("pub fn authorize_business_core(", src)
        src = source(CORE / "memory.rs")
        self.assertIn("pub fn authorize_data_frame_slot(", src)
        src = source(CORE / "syscall.rs")
        self.assertIn("fn from_kernel(", src)


if __name__ == "__main__":
    unittest.main()
