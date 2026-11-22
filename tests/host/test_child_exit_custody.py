"""Execute production Runner reuse, child publication and wait delivery bodies.

Hardware/ELF/filesystem operations are explicit facades; POSIX signals/statuses,
admission policy and kernel AI counters are real. Negative controls remove each
publication boundary and must fail the semantic witness that requires it.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


def production_program():
    user = (ROOT / "kernel/src/desktop/user.rs").read_text()
    spawn = (ROOT / "kernel/src/desktop/user/spawn.rs").read_text()
    threads = (ROOT / "kernel/src/desktop/user/threads.rs").read_text()
    launch = function(user, "fn launch_accounted(")
    admit = function(spawn, "fn spawn_image_accounted(")
    template = (ROOT / "tests/host/child_exit_custody_harness.rs").read_text()
    template = template.replace("// AI_SOURCE", "#[path=" + json.dumps(
        str(ROOT / "kernel/src/desktop/user/ai.rs")) + "] pub mod ai;")
    types = [
        "#[derive(Clone, Copy)]\n" + function(spawn, "pub(super) struct Request"),
        "#[derive(Clone, Copy)]\n" + function(spawn, "struct Receipt"),
        function(spawn, "pub(super) struct Children"),
        function(spawn, "impl Children"),
    ]
    template = template.replace("// RECEIPT_TYPES", "\n".join(types))
    template = template.replace("// THREAD_SLOTS", function(threads, "fn thread_slots("))
    template = template.replace("// PARKED_SLOTS", function(threads, "fn parked_slots("))
    runner = [function(user, "fn finish("), function(user, "fn block("),
              function(spawn, "pub(super) fn request_wait("),
              function(spawn, "pub(super) fn supervisor_result("),
              function(threads, "pub(super) fn refresh_thread_state("),
              function(threads, "pub(super) fn has_runnable_thread(")]
    template = template.replace("// RUNNER_METHODS", "\n".join(runner))
    supervisor = [
        function(user, "fn launch(&mut self,"), launch,
        function(user, "fn kill_runner("),
        function(user, "fn pair(&mut self,"),
        function(spawn, "fn spawn_image("), admit,
        function(spawn, "pub(super) fn service_spawn("),
        function(spawn, "pub(super) fn publish_child_exits("),
        function(spawn, "pub(super) fn collect_children("),
    ]
    return template.replace("// SUPERVISOR_METHODS", "\n".join(supervisor)), launch, admit


class ChildExitCustody(unittest.TestCase):
    def test_actual_reuse_and_collection_keep_status_signal_and_accounting(self):
        program, launch, admit = production_program()
        with tempfile.TemporaryDirectory(prefix="cyxia-child-custody-") as temporary:
            directory = Path(temporary)
            source = directory / "harness.rs"
            (directory / "Cargo.toml").write_text(
                '[package]\nname="child-exit-custody"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[features]\ndefault=["ported"]\nported=[]\nfull-os=[]\ncosmic-session=["full-os"]\n'
                '[dependencies]\ncyxia-posix={path=' + json.dumps(str(ROOT / "crates/posix"))
                + '}\ncyxia-ai-runtime={path=' + json.dumps(str(ROOT / "crates/ai-runtime"))
                + '}\n[workspace]\n')
            target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target/host-child-exit-custody"))
            command = [str(RUST_BIN / "cargo"), "test", "--offline", "--manifest-path",
                       str(directory / "Cargo.toml"), "--target-dir", str(target), "--lib"]
            hook = "        self.publish_child_exits();\n"
            controls = [
                (program.replace(launch, launch.replace(hook, "", 1), 1),
                 "launch_modes_publish_before_overwrite_and_wait_once",
                 "terminal receipt was overwritten at the shared launch boundary"),
                (program.replace(admit, admit.replace(hook, "", 1), 1),
                 "spawn_admission_reclaims_auto_receipts_before_evaluating_capacity",
                 "auto-reaped receipts did not reach admission"),
            ]
            for changed, selection, failure in controls:
                self.assertNotEqual(changed, program)
                source.write_text(changed)
                result = subprocess.run(command + [selection, "--", "--test-threads=1"],
                                        cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(failure, output)
            source.write_text(program)
            result = subprocess.run(command + ["--", "--test-threads=1"],
                                    cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("12 passed; 0 failed", output)

    def test_actual_ai_status_compiles_and_runs_with_and_without_ported(self):
        user = (ROOT / "kernel/src/desktop/user.rs").read_text()
        status = function(user, "pub fn ai_status(")
        template = r'''
use std::fmt::Write;
fn mark(out: &mut impl Write, name: &str) { write!(out, "{name} ").unwrap(); }
mod ai { pub fn status(out: &mut impl std::fmt::Write) { super::mark(out, "ai"); } }
#[cfg(feature = "ported")]
mod pipes { pub fn status(out: &mut impl std::fmt::Write) { super::mark(out, "pipes"); } }
#[cfg(feature = "ported")]
mod unix { pub fn status(out: &mut impl std::fmt::Write) { super::mark(out, "unix"); } }
mod parallel { pub fn status(out: &mut impl std::fmt::Write) { super::mark(out, "parallel"); } }
#[cfg(feature = "ported")]
mod shared_memory { pub fn status(out: &mut impl std::fmt::Write) { super::mark(out, "shared"); } }
fn object_status(out: &mut impl Write) { mark(out, "objects"); }
// AI_STATUS
#[test]
fn actual_status_uses_only_built_domains() {
    let mut output = String::new();
    ai_status(&mut output);
    assert!(output.contains("ai ") && output.contains("objects "));
    assert_eq!(output.contains("pipes "), cfg!(feature = "ported"));
    assert_eq!(output.contains("unix "), cfg!(feature = "ported"));
    assert_eq!(output.contains("shared "), cfg!(feature = "ported"));
}
'''
        with tempfile.TemporaryDirectory(prefix="cyxia-ai-status-cfg-") as temporary:
            directory = Path(temporary)
            source = directory / "status.rs"
            source.write_text(template.replace("// AI_STATUS", status))
            for ported in (False, True):
                binary = directory / ("ported" if ported else "native")
                command = [str(RUST_BIN / "rustc"), "--edition=2024", "--test",
                           str(source), "-o", str(binary)]
                if ported:
                    command += ["--cfg", 'feature="ported"']
                compiled = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                          text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                run = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn("1 passed; 0 failed", run.stdout)


if __name__ == "__main__":
    unittest.main()
