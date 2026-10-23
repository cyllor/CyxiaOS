"""Source isolation and executable contract tests; never execute target code."""
import copy
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import build_sysroot as build


def executable():
    data = bytearray(8192)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 2, 183, 1,
                     build.BASE + 4096, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    headers = [(6, 4, 64, build.BASE + 64, 0, 168, 168, 8),
               (1, 4, 0, build.BASE, 0, 4096, 4096, 4096),
               (1, 5, 4096, build.BASE + 4096, 0, 4096, 4096, 4096)]
    for index, header in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *header)
    return data


class ElfTests(unittest.TestCase):
    def inspect(self, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "probe.elf"
            path.write_bytes(data)
            return build.inspect_elf(path)

    def test_valid_static_contract(self):
        result = self.inspect(executable())
        self.assertEqual(result["entry"], build.BASE + 4096)
        self.assertEqual(result["at_phdr"], build.BASE + 64)

    def test_reject_pie_foreign_machine_and_truncation(self):
        for offset, value in ((16, 3), (18, 62)):
            data = executable()
            struct.pack_into("<H", data, offset, value)
            with self.assertRaises(build.BuildError):
                self.inspect(data)
        with self.assertRaises(build.BuildError):
            self.inspect(executable()[:100])

    def test_reject_out_of_window_writable_code_and_file_overrun(self):
        for offset, fmt, value in ((64 + 112 + 16, "Q", build.LIMIT),
                                   (64 + 112 + 4, "I", 7),
                                   (64 + 112 + 32, "Q", 99999)):
            data = executable()
            struct.pack_into("<" + fmt, data, offset, value)
            with self.assertRaises(build.BuildError):
                self.inspect(data)

    def test_reject_interpreter_and_unmapped_phdr(self):
        for offset, fmt, value in ((64, "I", 3), (64 + 16, "Q", build.LIMIT)):
            data = executable()
            struct.pack_into("<" + fmt, data, offset, value)
            with self.assertRaises(build.BuildError):
                self.inspect(data)

    def test_reject_page_overlap(self):
        data = executable()
        struct.pack_into("<Q", data, 64 + 112 + 16, build.BASE)
        with self.assertRaises(build.BuildError):
            self.inspect(data)

    def test_undefined_global_rejected_local_and_weak_allowed(self):
        for binding in (0, 1, 2):
            data = executable()
            struct.pack_into("<Q", data, 40, 7000)
            struct.pack_into("<H", data, 60, 1)
            struct.pack_into("<IIQQQQIIQQ", data, 7000, 0, 2, 0, 0, 7100, 24, 0, 0, 8, 24)
            struct.pack_into("<IBBHQQ", data, 7100, 0, binding << 4, 0, 0, 0, 0)
            if binding == 1:
                with self.assertRaises(build.BuildError):
                    self.inspect(data)
            else:
                self.inspect(data)


class SourceTests(unittest.TestCase):
    def test_manifest_requires_pins_and_simple_paths(self):
        baseline = build.load_manifest()
        for field, value in (("expected_sha256", ""), ("archive_root", "../musl"),
                             ("license_file", "/etc/passwd")):
            data = copy.deepcopy(baseline)
            data["packages"][0][field] = value
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "manifest.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError if field == "expected_sha256" else build.BuildError):
                    build.load_manifest(path)

    def test_unpack_rejects_archive_escape_and_symlinks(self):
        for member_name, link in (("../outside", False), ("pkg/link", True)):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = root / "source.archive"
                with tarfile.open(archive, "w") as bundle:
                    member = tarfile.TarInfo(member_name)
                    if link:
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    bundle.addfile(member, io.BytesIO())
                package = {"archive_root": "pkg", "license_file": "COPYING",
                           "expected_sha256": build.digest(archive)}
                with self.assertRaises(build.BuildError):
                    build.unpack(package, {"directory": str(root)}, root)
                self.assertFalse((root / "pkg").exists())

    def test_unpack_rechecks_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source.archive").write_bytes(b"corrupt")
            with self.assertRaises(build.BuildError):
                build.unpack({"expected_sha256": "0" * 64}, {"directory": str(root)}, root)

    def test_unpack_preserves_safe_internal_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "source.archive"
            with tarfile.open(archive, "w") as bundle:
                license_file = tarfile.TarInfo("pkg/COPYING")
                license_file.size = 3
                bundle.addfile(license_file, io.BytesIO(b"MIT"))
                link = tarfile.TarInfo("pkg/notice")
                link.type, link.linkname = tarfile.SYMTYPE, "COPYING"
                bundle.addfile(link)
            package = {"archive_root": "pkg", "license_file": "COPYING",
                       "expected_sha256": build.digest(archive)}
            source = build.unpack(package, {"directory": str(root)}, root)
            self.assertEqual((source / "notice").read_text(), "MIT")

    def test_server_manifest_has_pinned_runtime_sources(self):
        packages = build.server_manifest()["packages"]
        self.assertEqual(packages[-1]["name"], "xorg-server")
        self.assertEqual(packages[-1]["version"], "21.1.25")
        self.assertTrue(all(len(p["expected_sha256"]) == 64 for p in packages))

    def test_environment_strips_host_search_paths(self):
        with patch.dict("os.environ", {"CPATH": "/host/include", "SDKROOT": "/host/sdk", "CC": "wrong"}):
            env = build.clean_env()
        self.assertNotIn("CPATH", env)
        self.assertNotIn("SDKROOT", env)
        self.assertNotIn("CC", env)


if __name__ == "__main__":
    unittest.main()
