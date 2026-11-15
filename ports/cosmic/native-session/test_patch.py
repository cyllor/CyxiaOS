"""Hash-bound patch reproduction/application checks. Root runs under native lease.

Actual process and manager behavior is verified by probe.rs in the guest, through
the public API. These checks only establish the source artifact's integrity.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

PORT = Path(__file__).resolve().parent
ROOT = PORT.parents[2]
SPEC = importlib.util.spec_from_file_location("session_patch", PORT / "build_patch.py")
PATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCH)


class NativeSessionPatchTests(unittest.TestCase):
    def test_reproduces_exact_patch_and_applies_bound_preimages(self):
        record = json.loads((PORT / "native-patch.json").read_text())
        patch = ROOT / record["patch"]
        self.assertEqual(PATCH.sha(patch), record["patch_sha256"])
        for name, expected in record["support_inputs"].items():
            self.assertEqual(PATCH.sha(ROOT / name), expected, name)
        session = ROOT / record["source_inputs"]["session"]["path"]
        launch = ROOT / record["source_inputs"]["launch_pad"]["path"]
        for name, source in [("session", session), ("launch_pad", launch)]:
            original = record["source_inputs"][name]
            actual, _, _ = PATCH.snapshot(source, original["commit"], original["git_tree"])
            self.assertEqual(actual, original)
        with tempfile.TemporaryDirectory(prefix="cyxia-native-session-patch-") as directory:
            temporary = Path(directory)
            replay = PATCH.build(session, launch, temporary / "export", temporary / "replay.patch", temporary / "replay.json")
            self.assertEqual((temporary / "replay.patch").read_bytes(), patch.read_bytes())
            self.assertEqual(replay["before"], record["before"])
            self.assertEqual(replay["after"], record["after"])
            self.assertEqual(replay["effective_lock_sha256"], record["effective_lock_sha256"])
            base = temporary / "export/base"
            initial = {str(path.relative_to(base)): PATCH.sha(path) for path in base.rglob("*") if path.is_file()}
            for name, expected in record["before"].items():
                self.assertEqual(PATCH.sha(base / name), expected, name)
            subprocess.run(["git", "apply", "--check", str(patch)], cwd=base, check=True)
            subprocess.run(["git", "apply", str(patch)], cwd=base, check=True)
            final = {str(path.relative_to(base)): PATCH.sha(path) for path in base.rglob("*") if path.is_file()}
            for name, expected in record["after"].items():
                self.assertEqual(PATCH.sha(base / name), expected, name)
            changed = {name for name in initial.keys() | final.keys() if initial.get(name) != final.get(name)}
            self.assertEqual(changed, set(record["before"]))
            self.assertEqual((base / "native-deps/launch-pad/src/native_child.rs").read_bytes(), (PORT / "native_child.rs").read_bytes())
            self.assertEqual((base / "native-deps/launch-pad/LICENSE.md").read_bytes(), (launch / "LICENSE.md").read_bytes())
            self.assertEqual((base / "Cargo.lock").read_text(), (session / "Cargo.lock").read_text().replace(
                f'source = "git+https://github.com/pop-os/launch-pad#{PATCH.LAUNCH_COMMIT}"\n', ""))


if __name__ == "__main__":
    unittest.main()
