import copy
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_smithay_probe as builder
import verify_smithay as verifier


class SmithayPortTests(unittest.TestCase):
    def test_incomplete_damaged_or_inflated_runtime_claims_cannot_pass(self):
        rows = [f"SMITHAY CHECK name={name} result=PASS" for name in verifier.CHECKS]
        rows.append(verifier.SUCCESS)
        valid = ("\n".join(rows) + "\n").encode()
        self.assertEqual(len(verifier.validate(valid)), 14)
        bad = [
            b"\n".join(valid.splitlines()[1:]),
            valid + rows[0].encode() + b"\n",
            valid.replace(b"result=PASS", b"result=FAIL", 1),
            valid.replace(b"real-softpipe", b"fake-renderer"),
            valid.replace(b"cosmic=0", b"cosmic=1"),
            valid.replace(b"pixels=1087", b"pixels=0"),
            valid + b"noise SMITHAY FAIL interleaved\n",
        ]
        for data in bad:
            with self.subTest(data=data[-80:]):
                with self.assertRaises(AssertionError):
                    verifier.validate(data)

    def fixture(self):
        return (
            '[package]\nname="smithay"\nversion="0.7.0"\nedition="2024"\n'
            '[dependencies]\nlibc="0.2"\n'
            'libloading={version="0.8",optional=true}\n'
            'unused={version="1",optional=true}\n'
            '[build-dependencies]\ngl_generator={version="0.14",optional=true}\n'
            '[features]\nbackend_egl=["gl_generator","libloading"]\n'
            'backend_egl_static=["backend_egl"]\nrenderer_gl=["backend_egl"]\n'
        )

    def packages(self):
        return [
            dict(name="smithay", version="0.7.0",
                 dependencies=["libc", "libloading", "gl_generator"]),
            dict(name="libc", version="0.2.182"),
            dict(name="libloading", version="0.8.9"),
            dict(name="gl_generator", version="0.14.0"),
        ]

    def test_manifest_projection_cannot_remove_mandatory_upstream_code_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(self.fixture())
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "mandatory"):
                builder.project_manifest(path, {"projected_dependencies": []}, self.packages())
            self.assertEqual(path.read_bytes(), before)

    def test_projection_retains_original_options_and_pins_selected_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(self.fixture())
            result = builder.project_manifest(
                path, {"projected_dependencies": ["libc", "libloading", "gl_generator"]},
                self.packages())
            parsed = tomllib.loads(path.read_text())
            self.assertEqual(result["omitted_optional_dependencies"], ["unused"])
            self.assertEqual(parsed["dependencies"]["libc"]["version"], "=0.2.182")
            self.assertTrue(parsed["dependencies"]["libloading"]["optional"])
            self.assertEqual(parsed["features"]["backend_egl_static"], ["backend_egl"])

    def test_ambiguous_lock_selection_is_rejected_without_modifying_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(self.fixture())
            before = path.read_bytes()
            packages = copy.deepcopy(self.packages())
            packages.append(dict(name="libc", version="0.2.181"))
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                builder.project_manifest(path, {"projected_dependencies": ["libc"]}, packages)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
