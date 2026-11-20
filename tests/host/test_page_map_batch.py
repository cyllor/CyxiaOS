"""Run actual page-table batching and alias ownership algorithms on host memory.

The ordinary host arch build omits runtime alias hooks. This harness explicitly
selects space.rs's runtime branches on the host and the x86 staging type, enables
feature runtime, and records that adaptation. Runtime guard, phase/count core and batch
FFI bodies, PageTable, ProcessSpace.map_pages, and the permission state helper all
come from this checkout. The real bounded entry-error formatter writes to an
explicit host-only byte sink. CPU identity, physical backing/link addresses and
PTE/TLB effects are fixtures. RX pre-publication executes the actual production
wrapper and permission transaction. This is not a guest, TLB/IPI test, or proof
of hardware retirement completion.

The cases check real alias changes, prefixes, failures, ownership and
RX ranges through actual publish_code and permission transaction functions.
Staging mutation tests inspect actual translations and retirement; a private
child-module test observes checked RX ranges before invalid physical metadata
reaches the unchanged publication-address boundary. The
atomic gate fixture forwards operations to a real std::AtomicBool and only adds
observations. A wrong CPU or failed guard cannot clear another owner's gate.

Run with this repository's Rust toolchain on PATH. CYXIA_NATIVE_LOCK may select
the shared native lease; the default matches the notification runtime workflow.
"""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from doctor import env
from native_session import idle_native_host, native_lease
from test_governance_billing_priority import function

LOCK = Path(os.environ.get("CYXIA_NATIVE_LOCK", str(
    ROOT / "artifacts/v017-cosmic-completion-20261116/native-session.lock"))).expanduser().resolve()


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def runtime_declaration(source, symbol):
    starts = list(re.finditer(r"(?m)^(?:const|static) " + re.escape(symbol) + r": ", source))
    if len(starts) != 1:
        raise ValueError("Ambiguous runtime fixture declaration: " + symbol)
    start = starts[0].start()
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        depth += (char in "([{") - (char in ")]}")
        if char == ";" and depth == 0:
            return source[start:index + 1]
    raise ValueError("Unterminated runtime fixture declaration: " + symbol)


def production_files(address_source=None, *, source_root=None):
    """Pure source extraction; no subprocess, compiler, lease or guest access."""
    names = ("crates/arch-x86_64/src/space.rs", "kernel/src/arch/x86_64/runtime.rs",
             "kernel/src/desktop/address_space.rs", "kernel/src/desktop/process_arch.rs")
    selected_root = Path(source_root) if source_root is not None else ROOT
    sources = {name: (selected_root / name).read_text() for name in names}
    # Private candidates may explicitly select their address_space source;
    # installed portable tests always read the production checkout by default.
    if address_source is not None:
        sources["kernel/src/desktop/address_space.rs"] = Path(address_source).read_text()
    space, runtime, address, arch = (sources[name] for name in names)
    selector = 'all(feature = "runtime", target_arch = "x86_64", target_os = "none")'
    adapted = space.replace(selector, 'feature = "runtime"')
    if adapted == space:
        raise ValueError("Runtime platform selector missing; do not test no-op alias hooks")
    adapted += '\n#[cfg(test)]\n#[path = "cases.rs"]\nmod batch_tests;\n'
    files = {
        "space-runtime-enabled.rs": adapted,
        "space-cfg-adaptation.patch": "".join(difflib.unified_diff(
            space.splitlines(True), adapted.splitlines(True),
            fromfile="candidate/space.rs", tofile="host-tests/space-runtime-enabled.rs")),
    }
    guard = runtime[runtime.index("struct AliasGuard;"):runtime.index('unsafe extern "C" {')]
    signatures = [
        "fn code_phase(", 'extern "C" fn x86_runtime_code_sealed(',
        'extern "C" fn x86_runtime_mapping_change(', "fn mapping_change_locked(",
        'extern "C" fn x86_runtime_mapping_batch_begin(', "fn mapping_batch_owned(",
        'extern "C" fn x86_runtime_mapping_batch_change(',
        'extern "C" fn x86_runtime_mapping_batch_end(',
    ]
    if 'extern "C" fn x86_runtime_mapping_batch_run(' in runtime:
        signatures.append('extern "C" fn x86_runtime_mapping_batch_run(')
    parts = [guard]
    extracted = {"alias_guard_and_drop": guard}
    for signature in signatures:
        body = function(runtime, signature)
        extracted[signature] = body
        parts.append(('#[unsafe(no_mangle)]\n' if signature.startswith("extern") else "") + body)
    code_runtime = []
    for signature in ("pub fn is_user_code_writable(", "impl Backend for CodePermissions {",
                      "pub unsafe fn seal_user_code(", "pub unsafe fn unseal_user_code("):
        body = function(runtime, signature)
        extracted[signature] = body
        code_runtime.append(body)
    code_runtime.insert(1, "struct CodePermissions;")
    wrappers = "\n".join(function(arch, signature) for signature in (
        "pub fn make_writable(", "pub fn publish_code("))
    wrappers = wrappers.replace('target_arch = "aarch64"', 'any()').replace('target_arch = "x86_64"', 'all()')
    extracted["permission_wrappers"] = wrappers
    fixture = (HERE / "page_map_batch_runtime_fixture.rs").read_text()
    substitutions = {"@PRODUCTION_ALIAS_RUNTIME@": "\n".join(parts),
                     "@PRODUCTION_CODE_RUNTIME@": "\n".join(code_runtime)}
    for symbol in ("RAM", "CODE_PHASES", "USER_ALIASES", "ALIAS_GATE", "ALIAS_BATCH_OWNER"):
        declaration = runtime_declaration(runtime, symbol)
        substitutions["@" + symbol + "@"] = ("pub " if symbol == "RAM" else "") + declaration
    for marker, value in substitutions.items():
        if fixture.count(marker) != 1:
            raise ValueError("Ambiguous fixture marker: " + marker)
        fixture = fixture.replace(marker, value)
    files["runtime-fixture.rs"] = fixture
    if 'extern "C" fn x86_runtime_mapping_batch_run(' in runtime:
        files['runtime-fixture.rs'] += '''
pub fn run(owner: u64, physical: u64, pages: u64, old: u64, new: u64) -> u64 {
    x86_runtime_mapping_batch_run(owner, physical, pages, old, new)
}
'''
    table = address[address.index('#[cfg(target_arch = "aarch64")]'):
                    address.index('#[cfg(target_arch = "x86_64")]\npub const TABLE_PAGES_PER_PROCESS')]
    # Exercise x86 staging metadata on ARM/macOS hosts as well as x86/Linux.
    table = table.replace('target_arch = "aarch64"', 'any()').replace('target_arch = "x86_64"', 'all()')
    map_pages = function(address, "    pub fn map_pages(")
    extra_maps = function(address, "    pub fn map_table_run(") if "    pub fn map_table_run(" in address else ""
    diagnostic = function(arch, "pub fn trace_entry_error(")
    files["staging.rs"] = (
        "use crate::Errno;\n" + table
        + "pub struct ProcessSpace { pub current: Option<crate::space::AddressSpace<'static>>, pub pid: u32 }\n"
        + "impl ProcessSpace {\n" + map_pages + "\n" + extra_maps + "\n}\n"
        + '#[cfg(test)]\n#[path = "staging-cases.rs"]\nmod staging_tests;\n')
    files["staging-cases.rs"] = (HERE / "page_map_staging_cases.rs").read_text()
    helper = selected_root / "crates/arch-x86_64/src/code_permissions.rs"
    if not helper.is_file():
        helper = ROOT / "crates/arch-x86_64/src/code_permissions.rs"
    files['code-permissions.rs'] = helper.read_text()
    files["transactions.rs"] = '''#![allow(dead_code)]
extern crate self as cyxia_arch_x86_64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno { Inval, Nodev, Io, Fault }
pub const HIGH: u64 = 0xffff800000000000;
// Host-only output capture. This does not emulate UART or AP ownership.
std::thread_local! {
    static HOST_DIAGNOSTICS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn log(payload: &[u8]) {
    HOST_DIAGNOSTICS.with(|bytes| bytes.borrow_mut().extend_from_slice(payload));
}
#[path = "space-runtime-enabled.rs"]
pub mod space;
#[path = "code-permissions.rs"]
pub mod code_permissions;
#[path = "runtime-fixture.rs"]
mod runtime_fixture;
#[path = "staging.rs"]
mod staging;
mod process_arch {
    pub fn publish_code(address: u64, length: usize) -> Result<(), crate::Errno> {
        crate::runtime_fixture::publish_code_fixture(address, length)
    }
''' + diagnostic + '''
}
mod machine {
    pub mod runtime {
        pub use crate::runtime_fixture::{is_user_code_writable, seal_user_code, unseal_user_code};
    }
}
mod production_process_arch {
    use crate::Errno;
    use crate::process_arch::trace_entry_error;
''' + wrappers + '''
}
'''
    files["cases.rs"] = (HERE / "page_map_batch_cases.rs").read_text()
    if 'pub fn map_table_run(' in space:
        files['cases.rs'] += '\n' + (HERE / 'page_map_run_cases.rs').read_text()
    files['cases.rs'] += '\n' + (HERE / 'page_retire_cases.rs').read_text()
    files['cases.rs'] += '\n' + (HERE / 'page_alias_counter_cases.rs').read_text()
    identity = {
        "source_sha256": {name: digest(text) for name, text in sources.items()},
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "helper_source_path": str(helper),
        "extracted_sha256": {name: digest(text) for name, text in extracted.items()},
        "staging_sha256": {"PageTable": digest(table), "ProcessSpace.map_pages": digest(map_pages)},
        "diagnostic_sha256": digest(diagnostic),
        "diagnostic_sink": "host-only thread-local bytes; no UART or AP ownership emulation",
        "generated_sha256": {name: digest(text) for name, text in files.items()},
        "platform_adaptation": "space.rs runtime selector -> feature runtime; x86 staging cfg selected on host",
        "runtime_branches_enabled": True,
        "hardware_tlb_exercised": False,
        "guest_execution": False,
    }
    return files, identity


def bounded(command, environment):
    process = subprocess.Popen(command, cwd=ROOT, env=environment, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        output, _ = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate(timeout=5)
        raise AssertionError("Host harness exceeded 30 seconds: " + output)
    return process.returncode, output


class PageMapBatchTransactions(unittest.TestCase):
    def test_actual_runtime_alias_batches_and_partial_failures(self):
        files, identity = production_files()
        environment = env()
        compiler = shutil.which("rustc", path=environment["PATH"])
        self.assertIsNotNone(compiler, "Repository Rust toolchain is required on PATH")
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cyxia-map-batch-") as temporary, native_lease(LOCK):
            idle_native_host()
            temporary = Path(temporary)
            for name, content in files.items():
                (temporary / name).write_text(content)
            (temporary / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
            binary = temporary / "batch-tests"
            compiled, output = bounded(
                [compiler, "--edition=2024", "--test", "--cfg", 'feature="runtime"',
                 "-Dwarnings", str(temporary / "transactions.rs"), "-o", str(binary)], environment)
            self.assertEqual(compiled, 0, output)
            # The helper's nine embedded tests are covered by its own suite.
            ran, output = bounded([str(binary), "runtime_batch_", "--test-threads=1"], environment)
            self.assertEqual(ran, 0, output)
            expected = files['cases.rs'].count('fn runtime_batch_') + files['staging-cases.rs'].count('fn runtime_batch_')
            self.assertGreaterEqual(expected, 32)
            self.assertIn(f"{expected} passed; 0 failed", output)


if __name__ == "__main__":
    unittest.main()
