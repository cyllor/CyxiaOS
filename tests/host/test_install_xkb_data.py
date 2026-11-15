"""Offline staging policy tests; no keyboard generator or target code runs."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import install_xkb_data as build


class XkbDataTests(unittest.TestCase):
    def test_existing_output_and_symlink_refused_before_source_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            occupied = root / "occupied"
            occupied.mkdir()
            sentinel = occupied / "sentinel"
            sentinel.write_bytes(b"preserve")
            link = root / "link"
            link.symlink_to(occupied, target_is_directory=True)
            with patch.object(build.desktop_ports, "verify") as verify:
                for output in (occupied, link):
                    with self.assertRaises(build.BuildError):
                        build.install(output, root / "cache")
                verify.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_archive_pin_and_recipe_version_are_required(self):
        baseline = json.loads(build.MANIFEST.read_text())
        for field, value in (("expected_sha256", None), ("version", "2.43"),
                             ("archive_root", "../outside")):
            manifest = copy.deepcopy(baseline)
            manifest["packages"][-1][field] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(manifest))
                with self.assertRaises((build.BuildError, build.desktop_ports.PortError)):
                    build.load_package(path)

    def test_selected_files_retain_whole_bytes_and_refuse_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            original = source / "us"
            original.write_bytes(b"first section\n\x00whole second section\xff")
            target = root / "rootfs" / "symbols" / "us"
            record = build.copy_asset(source, "us", target, "/symbols/us")
            self.assertEqual(target.read_bytes(), original.read_bytes())
            self.assertEqual(record["sha256"], build.digest(original))
            self.assertEqual(record["bytes"], original.stat().st_size)
            with self.assertRaises(FileExistsError):
                build.copy_asset(source, "us", target, "/symbols/us")
            alias = source / "alias"
            alias.symlink_to(original)
            with self.assertRaises(build.BuildError):
                build.copy_asset(source, "alias", root / "bad", "/bad")
            nested = source / "nested"
            nested.symlink_to(source, target_is_directory=True)
            with self.assertRaises(build.BuildError):
                build.copy_asset(source, "nested/us", root / "bad", "/bad")

    def test_catalog_rejects_count_path_and_directory_overflow(self):
        paths = [target for _, target in build.ASSETS] + [build.RULE_TARGET]
        counts = build.catalog_bounds(paths)
        self.assertEqual(counts["asset_files"], 30)
        self.assertEqual(counts["directory_nodes"], 13)
        self.assertLess(counts["max_path_bytes"], 96)
        for invalid in ([f"/file{i}" for i in range(121)], ["/" + "x" * 95],
                        [f"/d{i}/file" for i in range(64)], ["/a/../b"], ["relative"]):
            with self.assertRaises(build.BuildError):
                build.catalog_bounds(invalid)

    def test_generation_failure_never_publishes_rootfs_or_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            with patch.object(build.desktop_ports, "verify", return_value={}), \
                    patch.object(build.build_sysroot, "unpack", return_value=root), \
                    patch.object(build, "generate_evdev", side_effect=build.BuildError("generator failed")):
                with self.assertRaisesRegex(build.BuildError, "generator failed"):
                    build.install(output, root / "cache")
            self.assertFalse((output / "rootfs").exists())
            self.assertFalse((output / "report.json").exists())

    def test_nonidentical_generation_rejected_with_isolated_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source", root / "output"
            output.mkdir()
            for name in build.GENERATORS + tuple("rules/" + name for name in build.RULE_PARTS):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"test input, never executed\n")

            def generated(command, *, stdout, stderr, cwd, env, timeout, check):
                self.assertEqual(command[1], "-I")
                self.assertTrue(Path(command[2]).is_relative_to(source))
                self.assertNotIn("PYTHONPATH", env)
                self.assertNotIn("XKB_CONFIG_ROOT", env)
                target = Path(stdout.name)
                data = target.name.encode()
                if target.parent.name == "generation-2" and target.name == "evdev":
                    data += b"different"
                stdout.write(data)
                return SimpleNamespace(returncode=0)

            with patch.object(build.subprocess, "run", side_effect=generated), \
                    patch.dict("os.environ", {"PYTHONPATH": "/ambient", "XKB_CONFIG_ROOT": "/ambient"}):
                with self.assertRaisesRegex(build.BuildError, "Repeated upstream generation differs: evdev"):
                    build.generate_evdev(source, output)


if __name__ == "__main__":
    unittest.main()
