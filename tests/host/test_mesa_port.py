"""Mesa source containment and evidence-negative tests; no network or builds."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_mesa as build
import verify_egl


def successful_probe_log():
    lines = ["EGL_PROBE START mode=offscreen",
             "EGL_PROBE GL version=OpenGL ES 3.1 Mesa 26.2.3 renderer=softpipe"]
    lines.extend("EGL_PROBE CHECK name=" + name + " result=PASS" for name in verify_egl.OFFSCREEN_CHECKS)
    lines.extend(f"EGL_PROBE COMPUTE_OOM_ATTEMPT cycle={cycle} local=8x8 grid=8x8"
                 for cycle in range(1, 4))
    lines.append("EGL_PROBE RESULT PASS mode=offscreen failures=0")
    return ("\n".join(lines) + "\n").encode()


class MesaPortTests(unittest.TestCase):
    def test_missing_failed_duplicate_and_interleaved_checks_cannot_pass(self):
        baseline = successful_probe_log()
        self.assertTrue(verify_egl.validate_offscreen(baseline))
        variants = [
            baseline.replace(b"name=rgba8-fbo result=PASS", b"name=rgba8-fbo result=FAIL"),
            baseline.replace(b"EGL_PROBE CHECK name=swap result=PASS\n", b""),
            baseline.replace(b"name=swap result=PASS", b"name=swap result=PA\nkernel log\nSS"),
            baseline.replace(b"EGL_PROBE RESULT PASS", b"EGL_PROBE RESULT FAIL"),
            baseline.replace(b"renderer=softpipe", b"renderer=host-accelerated"),
            baseline.replace(b"mode=offscreen", b"mode=x11"),
            baseline.replace(b"EGL_PROBE CHECK name=swap result=PASS\n",
                             b"EGL_PROBE CHECK name=swap result=PASS\n" * 2),
        ]
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                verify_egl.validate_offscreen(value)

    def test_compute_oom_requires_each_error_atomicity_and_recovery_observation(self):
        baseline = successful_probe_log()
        for name in verify_egl.COMPUTE_OOM_CHECKS:
            marker = f"EGL_PROBE CHECK name={name} result=PASS\n".encode()
            for value in (baseline.replace(marker, b""),
                          baseline.replace(marker, marker.replace(b"PASS", b"FAIL")),
                          baseline.replace(marker, marker * 2)):
                with self.subTest(name=name), self.assertRaises(AssertionError):
                    verify_egl.validate_offscreen(value)
        for cycle in range(1, 4):
            marker = f"EGL_PROBE COMPUTE_OOM_ATTEMPT cycle={cycle} local=8x8 grid=8x8\n".encode()
            for value in (baseline.replace(marker, b""),
                          baseline.replace(marker, marker * 2),
                          baseline.replace(marker, marker.replace(b"local=8x8", b"local=4x1"))):
                with self.subTest(cycle=cycle), self.assertRaises(AssertionError):
                    verify_egl.validate_offscreen(value)

    def test_x11_mode_requires_its_actual_display_and_visual_checks(self):
        lines = ["EGL_PROBE START mode=x11",
                 "EGL_PROBE GL version=OpenGL ES 3.1 Mesa 26.2.3 renderer=softpipe"]
        lines.extend("EGL_PROBE CHECK name=" + name + " result=PASS"
                     for name in verify_egl.X11_CHECKS)
        lines.extend(f"EGL_PROBE COMPUTE_OOM_ATTEMPT cycle={cycle} local=8x8 grid=8x8"
                     for cycle in range(1, 4))
        lines.append("EGL_PROBE RESULT PASS mode=x11 failures=0")
        data = ("\n".join(lines) + "\n").encode()
        self.assertTrue(verify_egl.validate_offscreen(data, "x11"))
        with self.assertRaises(AssertionError):
            verify_egl.validate_offscreen(data)
        with self.assertRaises(AssertionError):
            verify_egl.validate_offscreen(data.replace(b"name=x11-visual", b"name=platform-proc"), "x11")

    def test_scanout_checks_all_window_pixels_and_gl_vertical_orientation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "frame.ppm"
            pixels = bytearray(1024 * 768 * 3)
            colors = ((0, 0, 255), (255, 255, 0), (255, 0, 0), (0, 255, 0))
            for y in range(64):
                for x in range(64):
                    offset = ((y + 100) * 1024 + x + 120) * 3
                    pixels[offset:offset + 3] = bytes(colors[(x >= 32) + 2 * (y >= 32)])
            header = b"P6\n1024 768\n255\n"
            path.write_bytes(header + pixels)
            self.assertTrue(verify_egl.presented_pixels(path))
            pixels[(131 * 1024 + 151) * 3] ^= 1
            path.write_bytes(header + pixels)
            with self.assertRaises(AssertionError):
                verify_egl.presented_pixels(path)

    def test_tree_fingerprint_detects_content_and_link_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source.c"
            source.write_text("upstream")
            initial = build.tree_digest(directory)
            source.write_text("locally changed")
            self.assertNotEqual(initial, build.tree_digest(directory))
            source.write_text("upstream")
            self.assertEqual(initial, build.tree_digest(directory))
            (directory / "link").symlink_to("source.c")
            self.assertNotEqual(initial, build.tree_digest(directory))

    def test_archive_escape_and_oversize_are_rejected_before_extraction(self):
        cases = [("mesa-fixture/../escaped", None, 10),
                 ("mesa-fixture/link", "../../escaped", 10),
                 ("mesa-fixture/license", None, 2)]
        for name, target, maximum in cases:
            with self.subTest(name=name, target=target), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                archive = work / "source.archive"
                with tarfile.open(archive, "w") as bundle:
                    entry = tarfile.TarInfo(name)
                    if target:
                        entry.type, entry.linkname = tarfile.SYMTYPE, target
                        bundle.addfile(entry)
                    else:
                        entry.size = 5
                        bundle.addfile(entry, io.BytesIO(b"hello"))
                package = {"expected_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                           "expanded_max_bytes": maximum, "archive_root": "mesa-fixture",
                           "license_file": "license"}
                with patch.object(build, "WORK", work), self.assertRaises(build.BuildError):
                    build.unpack_mesa(package, {"directory": str(work)}, work / "source")
                self.assertFalse((work / "escaped").exists())
                self.assertFalse((work / "source").exists())

    def test_changed_archive_is_not_trusted_from_old_verification_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "source.archive").write_bytes(b"tampered")
            with patch.object(build, "WORK", work), self.assertRaisesRegex(build.BuildError, "changed"):
                build.unpack_mesa({"expected_sha256": "0" * 64}, {"directory": str(work)}, work / "source")


if __name__ == "__main__":
    unittest.main()
