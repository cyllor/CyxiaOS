"""Apply the real patch stack, then compile and test its device selection policy.

This is a pure policy/patch check, not a cosmic-comp build or guest proof.
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

ROOT = Path(__file__).resolve().parents[4]
PORT = ROOT / "ports/cosmic/native-comp"
PATCH = ROOT / "ports/cosmic/patches/cosmic-comp-native-offscreen.patch"
BASE_PATCH = ROOT / "ports/cosmic/patches/cosmic-comp-41497b42-cyxia-nested.patch"
SOURCE = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch"
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc") or str(Path.home() / ".cargo/bin/rustc")
sys.path.insert(0, str(ROOT / "tools"))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OffscreenPatchTests(unittest.TestCase):
    def test_patch_preserves_real_offscreen_device_choices(self):
        self.assertTrue(PATCH.is_file(), "native offscreen separation patch is missing")
        binding = json.loads((PORT / "offscreen-patch.json").read_text())
        self.assertEqual(sha256(PATCH), binding["patch_sha256"])
        self.assertEqual(sha256(BASE_PATCH), binding["base_patch_sha256"])
        head = subprocess.check_output(
            ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
        ).strip()
        self.assertEqual(head, binding["commit"])
        self.assertEqual(sha256(SOURCE / "Cargo.lock"), binding["source_lock_sha256"])
        with tempfile.TemporaryDirectory(prefix="cosmic-native-offscreen-") as directory:
            source = Path(directory) / "source"
            shutil.copytree(SOURCE, source, ignore=shutil.ignore_patterns(".git", "target"))
            subprocess.run(["git", "apply", str(BASE_PATCH)], cwd=source, check=True)
            for path, expected in binding["before"].items():
                actual = sha256(source / path) if (source / path).exists() else None
                self.assertEqual(actual, expected, path)
            subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=source, check=True)
            subprocess.run(["git", "apply", str(PATCH)], cwd=source, check=True)
            for path, expected in binding["after"].items():
                self.assertEqual(sha256(source / path), expected, path)
            policy = source / "src/backend/kms/offscreen_policy.rs"
            wrapper = Path(directory) / "policy_tests.rs"
            wrapper.write_text(
                f'#[path = {json.dumps(str(policy))}] mod policy;\n'
                + (PORT / "tests/offscreen_policy.rs").read_text()
            )
            binary = Path(directory) / "policy_tests"
            with native_lease(DEFAULT_NATIVE_LOCK):
                idle_native_host()
                subprocess.run(
                    [RUSTC, "--edition", "2024", "--test", str(wrapper), "-o", str(binary)],
                    check=True,
                )
                subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
