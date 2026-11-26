"""Execute the real x86 build-profile guard; no native x86 boot claim."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
FEATURES = tomllib.loads((ROOT / "kernel/Cargo.toml").read_text())["features"]


def feature_environment(selected):
    """Expand the kernel's actual Cargo feature graph, excluding dependency flags."""
    enabled = set()
    pending = list(selected)
    while pending:
        name = pending.pop()
        if name in enabled:
            continue
        enabled.add(name)
        pending.extend(child for child in FEATURES[name] if child in FEATURES)
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("CARGO_FEATURE_")
        and key not in ("CYXIA_A03_DEMAND", "CYXIA_LEARNING_COLLECTION")
    }
    environment["CARGO_MANIFEST_DIR"] = str(ROOT / "kernel")
    for name in enabled:
        environment["CARGO_FEATURE_" + name.upper().replace("-", "_")] = "1"
    return environment


class X86ProfileGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rustc = shutil.which("rustc")
        if rustc is None:
            raise RuntimeError("rustc is required to exercise the real build-profile guard")
        cls.temporary = tempfile.TemporaryDirectory(prefix="cyxia-x86-profile-guard-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        harness = directory / "profile_guard.rs"
        harness.write_text(
            "mod os { pub fn build() { println!(\"X86_RUNTIME_BUILD_SELECTED\"); } }\n"
            + "#[path = " + json.dumps(str(ROOT / "kernel/build/x86_64.rs")) + "]\n"
            + "mod x86_64;\nfn main() { x86_64::build(); }\n"
        )
        cls.binary = directory / "profile_guard"
        subprocess.run(
            [rustc, "--edition=2024", str(harness), "-o", str(cls.binary)],
            check=True, capture_output=True, text=True, timeout=60,
        )

    def run_guard(self, features):
        return subprocess.run(
            [str(self.binary)], env=feature_environment(features),
            capture_output=True, text=True, timeout=10,
        )

    def test_explicit_x86_profiles_still_select_their_existing_builder(self):
        for features, runtime in (
            ([], False),
            (["selftest"], False),
            (["smp-selftest"], False),
            (["os-runtime"], True),
            (["full-os"], True),
            (["cosmic-desktop"], True),
        ):
            with self.subTest(features=features):
                result = self.run_guard(features)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("X86_RUNTIME_BUILD_SELECTED" in result.stdout, runtime)

    def test_arm_default_is_rejected_with_or_without_x86_runtime(self):
        for features in (["default"], ["default", "os-runtime"]):
            with self.subTest(features=features):
                result = self.run_guard(features)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("X86_RUNTIME_BUILD_SELECTED", result.stdout)

    def test_runtime_cannot_hide_any_arm_production_profile(self):
        production = sorted(name for name in FEATURES if name.startswith("v020-production"))
        self.assertTrue(production)
        for profile in production:
            with self.subTest(profile=profile):
                result = self.run_guard(["os-runtime", profile])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("V0.20 production profiles require AArch64", result.stderr)
                self.assertNotIn("X86_RUNTIME_BUILD_SELECTED", result.stdout)


if __name__ == "__main__":
    unittest.main()
