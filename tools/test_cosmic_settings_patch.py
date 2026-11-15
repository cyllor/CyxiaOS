"""Apply generated patches to verify byte preservation at file boundaries."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'settings_patch', ROOT / 'ports/cosmic/native-settings/build_patch.py')
PORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORT)


class PatchBoundaries(unittest.TestCase):
    def test_added_and_changed_files_preserve_missing_final_newlines(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new, applied = (root / p for p in ('old', 'new', 'applied'))
            for directory in (old, new, applied):
                directory.mkdir()
            original = {'changed.json': b'{"old": true}', 'keep.txt': b'old\nlast'}
            expected = {'added.json': b'{"new": true}', 'changed.json': b'{"old": false}',
                        'keep.txt': b'new\nlast', 'last.txt': b'last\n'}
            for name, data in original.items():
                (old / name).write_bytes(data)
                (applied / name).write_bytes(data)
            patch = []
            for name, data in expected.items():
                (new / name).write_bytes(data)
                patch.append(f'diff --git a/{name} b/{name}\n')
                if name not in original:
                    patch.append('new file mode 100644\n')
                patch.extend(PORT.file_diff(old / name, new / name, name))
            result = subprocess.run(['git', 'apply', '--unsafe-paths', '-'],
                                    input=''.join(patch).encode(), cwd=applied,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({p.name: p.read_bytes() for p in applied.iterdir()}, expected)


if __name__ == '__main__':
    unittest.main()
