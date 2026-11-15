"""API-contract regressions; no live network, package download or compiler."""
from pathlib import Path
import sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_mesa as build
class StopAfterFetch(Exception): pass
class FetchModeTests(unittest.TestCase):
    def test_generators_skip_python_too_new_for_pinned_binary_wheels(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            candidates = []
            for minor in (15, 14):
                executable = root / ('python3.' + str(minor))
                executable.write_text('#!/bin/sh\nprintf "[3, ' + str(minor) + ', 3]\\n"\n')
                executable.chmod(0o755)
                candidates.append(executable)
            result = build.select_host_python(candidates)
            self.assertEqual(Path(result['executable']), candidates[1].resolve())
            self.assertEqual(result['version'], [3, 14, 3])
            with self.assertRaisesRegex(build.BuildError, 'Python 3.9'):
                build.select_host_python(candidates[:1])

    def test_audit_cxx_fetch_passes_explicit_network_consent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            item = dict(name="libcxx", archive_root="libcxx-fixture", source_max_bytes=20)
            def fetch(package, cache, **kwargs):
                self.assertIs(kwargs.get("online"), True)
                self.assertIsNone(kwargs.get("offline_file"))
                raise StopAfterFetch
            with patch.object(build, "DEFAULT_OUTPUT", root), \
                 patch.object(build.desktop_ports, "destination", return_value=root/"absent"), \
                 patch.object(build.desktop_ports, "fetch", side_effect=fetch):
                with self.assertRaises(StopAfterFetch):
                    build.target_cxx(None, {"target_cxx":{"packages":[item]}}, True)
    def test_audit_cxx_no_fetch_does_not_enable_network(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            item=dict(name="libcxx", archive_root="libcxx-fixture", source_max_bytes=20)
            with patch.object(build,"DEFAULT_OUTPUT",root), \
                 patch.object(build.desktop_ports,"destination",return_value=root/"absent"), \
                 patch.object(build.desktop_ports,"fetch") as fetch:
                with self.assertRaises(build.BuildError):
                    build.target_cxx(None,{"target_cxx":{"packages":[item]}},False)
                fetch.assert_not_called()
