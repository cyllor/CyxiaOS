"""Actual patch-stack integrity and optional leased native ABI/selection tests.

Python-only by default. --rust-tests executes the actual patched modules, not
an independent backend implementation. Neither mode links or runs COSMIC.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
PORT = ROOT / "ports/cosmic/native-comp"
SOURCE = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch"
PATCH = ROOT / "ports/cosmic/patches/cosmic-comp-native-backend.patch"
RUST_TESTS = "--rust-tests" in sys.argv
if RUST_TESTS:
    sys.argv.remove("--rust-tests")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


class NativeBackendPatchTests(unittest.TestCase):
    def test_apply_exact_stack_and_verify_transitive_hashes(self):
        binding = json.loads((PORT / "backend-patch.json").read_text())
        series = json.loads((PORT / "series.json").read_text())
        self.assertEqual(sha(PATCH), binding["patch_sha256"])
        self.assertEqual(sha(SOURCE / "Cargo.lock"), binding["source_lock_sha256"])
        self.assertEqual(subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip(), binding["commit"])
        with tempfile.TemporaryDirectory(prefix="cosmic-cyxia-backend-") as temp:
            work = Path(temp) / "source"
            shutil.copytree(SOURCE, work, ignore=shutil.ignore_patterns(".git", "target"))
            previous_sha = None
            for entry in series["patches"]:
                if entry["patch"] == str(PATCH.relative_to(ROOT)):
                    self.assertEqual(sha(ROOT / entry["manifest"]), entry["manifest_sha256"])
                    break
                manifest = json.loads((ROOT / entry["manifest"]).read_text())
                self.assertEqual(sha(ROOT / entry["manifest"]), entry["manifest_sha256"])
                self.assertEqual(sha(ROOT / entry["patch"]), manifest["patch_sha256"])
                subprocess.run(["git", "apply", str(ROOT / entry["patch"])], cwd=work, check=True)
                previous_sha = manifest["patch_sha256"]
            self.assertEqual(previous_sha, binding["base_patch_sha256"])
            for name, expected in binding["before"].items():
                self.assertEqual(sha(work / name), expected, name)
            subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=work, check=True)
            subprocess.run(["git", "apply", str(PATCH)], cwd=work, check=True)
            for name, expected in binding["after"].items():
                self.assertEqual(sha(work / name), expected, name)
            session = (work / "src/wayland/handlers/session_lock.rs").read_text()
            self.assertIn("if !locker.ext_session_lock().is_alive()", session)
            self.assertEqual(session.count("session_lock.ext_session_lock.is_alive()"), 2)
            self.assertIn("session_lock.ext_session_lock == *lock_surface.ext_session_lock()", session)
            focus = (work / "src/shell/focus/mod.rs").read_text()
            set_focus = focus[focus.index("    pub fn set_focus("):focus.index("    // We suppress Element(")]
            self.assertLess(set_focus.index("cyxia_lock_allows_focus("), set_focus.index("append_focus_stack("))
            update = focus[focus.index("fn update_focus_state("):focus.index("fn focus_target_is_valid(")]
            self.assertLess(update.index("cyxia_lock_allows_focus("), update.index("keyboard.set_focus("))
            self.assertIn("surface.ext_session_lock().is_alive()", focus)
            self.assertIn("lock.surfaces.values().any(|registered| registered == surface)", focus)
            popup = (work / "src/wayland/handlers/xdg_shell/mod.rs").read_text()
            grab = popup[popup.index("    fn grab("):popup.index("    fn reposition_request(")]
            self.assertLess(grab.index("cyxia_lock_allows_focus("), grab.index(".grab_popup("))
            for path in [*(PORT / "backend").glob("*.rs"), *(PORT / "backend/native").glob("*.rs")]:
                self.assertEqual(path.read_bytes(), (work / "src/backend/cyxia" / path.relative_to(PORT / "backend")).read_bytes())
            # Existing native ABI tests and actual upstream selector are isolated
            # from COSMIC dependencies; the full native-feature check is separate.
            if RUST_TESTS:
                sys.path.insert(0, str(ROOT / "tools"))
                from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
                rustc = os.environ.get("RUSTC") or shutil.which("rustc") or str(Path.home() / ".cargo/bin/rustc")
                with native_lease(DEFAULT_NATIVE_LOCK):
                    idle_native_host()
                    binary = Path(temp) / "abi-tests"
                    abi_wrapper = Path(temp) / "abi-tests.rs"
                    abi_wrapper.write_text("".join(f'#[path = {json.dumps(str(work / "src/backend/cyxia" / (module + ".rs")))}] mod {module};\n' for module in ("native", "delivery", "scheduling", "locking")))
                    subprocess.run([rustc, "--edition", "2024", "--test", str(abi_wrapper), "-o", str(binary)], check=True)
                    subprocess.run([str(binary)], check=True)
                    wrapper = Path(temp) / "selection-tests.rs"
                    wrapper.write_text(f'#[path = {json.dumps(str(work / "src/backend/selection.rs"))}] mod selection;\n' + (PORT / "backend/tests/selection.rs").read_text())
                    for features in [("cyxia",), ("kms",), ("winit",), ("kms", "winit", "x11", "cyxia")]:
                        binary = Path(temp) / ("selection-" + "-".join(features))
                        command = [rustc, "--edition", "2024", "--test", str(wrapper), "-o", str(binary)]
                        for feature in features:
                            command.extend(["--cfg", f'feature="backend-{feature}"'])
                        subprocess.run(command, check=True)
                        subprocess.run([str(binary)], check=True)

    def test_reuses_existing_validated_native_abi_exactly(self):
        self.assertEqual((PORT / "backend/linux_syscall.rs").read_bytes(), (ROOT / "ports/cosmic/smithay-wayland/linux_syscall.rs").read_bytes())
        original = (ROOT / "ports/cosmic/smithay-wayland/native.rs").read_bytes()
        extended = (PORT / "backend/native.rs").read_bytes()
        self.assertTrue(extended.startswith(original))
        self.assertEqual(extended[len(original):], b'\n// COSMIC extension: resumable native submission; the ABI adapter above is unchanged.\n#[path = "native/presentation.rs"]\npub mod presentation;\n')

    def test_native_completion_order_supplements_smithay_primary_output_regression(self):
        source = (PORT / "backend/mod.rs").read_text()
        advance = source[source.index("    fn advance_presentation("):source.index("    fn complete_frame(")]
        completion = source[source.index("    fn complete_frame("):source.index("\nfn dispatch_actions")]
        self.assertNotIn("present_rgba(", source)
        self.assertLess(advance.index(".advance("), advance.index("self.complete_frame("))
        self.assertLess(completion.index("common.update_primary_output("), completion.index("common.send_frames("))
        self.assertNotIn("schedule.begin()", completion)



if __name__ == "__main__":
    unittest.main()
