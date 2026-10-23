"""Host XKB source and build-environment isolation; never downloads or builds."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import build_xkb as build


class XkbBuildTests(unittest.TestCase):
    def test_unpinned_or_unknown_dependency_rejected_before_execution(self):
        baseline = build.load_manifest()
        for field, value in (("expected_sha256", None), ("depends_on", ["host-unpinned-lib"]),
                             ("archive_root", "../outside")):
            manifest = copy.deepcopy(baseline)
            manifest["packages"][-1][field] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(manifest))
                with self.assertRaises((build.BuildError, build.desktop_ports.PortError)):
                    build.load_manifest(path)

    def test_host_environment_cannot_select_target_or_system_x11(self):
        incoming = {"PKG_CONFIG_SYSROOT_DIR": "/target", "PKG_CONFIG_PATH": "/system/x11",
                    "PKG_CONFIG_LIBDIR": "/target/lib", "CPATH": "/target/include",
                    "CC": "cross-cc", "DISPLAY": ":0", "PYTHONPATH": "/foreign-python",
                    "CONFIG_SITE": "/foreign-config", "DYLD_LIBRARY_PATH": "/system/x11",
                    "XKBCOMP_LIBS": "-lforeign-x11", "LIBS": "-lforeign", "ac_cv_func_fake": "yes"}
        with patch.dict("os.environ", incoming):
            env = build.host_env(Path("/isolated/host"))
        self.assertEqual(env["PKG_CONFIG_LIBDIR"],
                         "/isolated/host/lib/pkgconfig:/isolated/host/share/pkgconfig")
        self.assertEqual(env["PKG_CONFIG_PATH"], "")
        self.assertEqual(env["CONFIG_SITE"], "/dev/null")
        self.assertNotEqual(env["CC"], "cross-cc")
        for name in ("PKG_CONFIG_SYSROOT_DIR", "CPATH", "DISPLAY", "PYTHONPATH", "DYLD_LIBRARY_PATH",
                     "XKBCOMP_LIBS", "LIBS", "ac_cv_func_fake"):
            self.assertNotIn(name, env)

    def test_patch_cannot_escape_sources_or_omit_integrity_pin(self):
        for field, value in (("file", "../../outside.patch"), ("original_file", "/tmp/outside.c"),
                             ("original_file", "../outside.c"), ("sha256", "")):
            manifest = copy.deepcopy(build.load_manifest())
            manifest["host_patches"][0][field] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(manifest))
                with self.assertRaises(build.BuildError):
                    build.load_manifest(path)


if __name__ == "__main__":
    unittest.main()
