"""Negative evidence/source checks for the bounded native Rust EGL bridge."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_rust_egl_probe as build
import verify_rust_egl as verify


class RustEglPortTests(unittest.TestCase):
    def test_missing_failed_duplicate_and_wrong_renderer_never_pass(self):
        lines = ["RUST_EGL CHECK name=" + name + " result=PASS" for name in verify.CHECKS]
        lines.insert(10, "RUST_EGL RENDERER softpipe")
        lines.append(verify.SUCCESS)
        good = ("\n".join(lines) + "\n").encode()
        self.assertEqual(len(verify.validate(good)), 18)
        for bad in (
            good.replace(b"name=shader-readback-16-pixels result=PASS",
                         b"name=shader-readback-16-pixels result=FAIL"),
            good.replace(b"RUST_EGL CHECK name=egl-cleanup result=PASS\n", b""),
            good.replace(b"RUST_EGL RENDERER softpipe\n", b"RUST_EGL RENDERER llvmpipe\n"),
            good.replace(b"name=real-softpipe result=PASS", b"name=real-softpipe result=PA\nnoise\nSS"),
            good + b"RUST_EGL CHECK name=egl-cleanup result=PASS\n",
            good.replace(b"high_level_smithay=0", b"high_level_smithay=1"),
        ):
            with self.subTest(data=bad[-100:]), self.assertRaises(AssertionError):
                verify.validate(bad)

    def test_changed_cached_source_is_rejected_without_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = b"verified"
            item = {"bytes": len(original), "sha256": hashlib.sha256(original).hexdigest(),
                    "url": "https://example.invalid/source"}
            (root / "source.rs").write_bytes(original)
            self.assertEqual(build.source_input(root, item, "source.rs", False), root / "source.rs")
            (root / "source.rs").write_bytes(b"tampered")
            with patch("urllib.request.urlopen") as network:
                with self.assertRaises(ValueError):
                    build.source_input(root, item, "source.rs", True)
                network.assert_not_called()
            self.assertEqual((root / "source.rs").read_bytes(), b"tampered")

    def test_source_path_and_link_cannot_escape_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            (root / "outside").write_bytes(b"x")
            (cache / "link").symlink_to(root / "outside")
            item = {"bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
            for name in ("../outside", str(root / "outside"), "link"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    build.source_input(cache, item, name, False)

    def test_oversize_traversal_and_links_are_rejected_before_extract(self):
        for name, link, budget in (
            ("crate/../escape", None, 100),
            ("other/file", None, 100),
            ("crate/link", "../outside", 100),
            ("crate/file", None, 3),
        ):
            with self.subTest(name=name, budget=budget), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.crate"
                with tarfile.open(archive, "w") as bundle:
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type, entry.linkname = tarfile.SYMTYPE, link
                        bundle.addfile(entry)
                    else:
                        entry.size = 5
                        bundle.addfile(entry, io.BytesIO(b"hello"))
                target = root / "unpack"
                target.mkdir()
                with self.assertRaises(ValueError):
                    build.extract(archive, target, "crate", budget)
                self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
