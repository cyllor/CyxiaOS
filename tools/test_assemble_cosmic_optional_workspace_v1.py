"""Byte fixtures test optional configuration preservation, not guest execution."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import assemble_cosmic_optional_workspace_v1 as subject


class OptionalConfiguration(unittest.TestCase):
    def test_only_appends_user_entry_and_preserves_every_original_byte(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
            root = Path(directory); parent = root / 'parent'; parent.mkdir()
            path = parent / subject.DEFAULT; path.parent.mkdir(parents=True)
            path.write_text('Some((["com.system76.CosmicPanelWorkspacesButton", "com.system76.CosmicPanelAppButton"],["com.system76.CosmicAppletTiling"]))\n')
            (parent / 'probe.elf').write_bytes(b'nonexecutable fixture')
            before = subject.os_x86.catalog_inputs(parent)
            (parent / 'cosmic-workspace-applets-origin.json').write_text(json.dumps(dict(
                status='WORKSPACE_APPLETS_INSTALLED_NOT_RUN', files=before)))
            output = root / 'optional'
            with patch.object(subject, 'DEFAULT_SHA', subject.pc.sha(path)), patch.object(subject.objects, 'validate'):
                result = subject.assemble(parent, output)
                self.assertEqual(set(result['added']), {subject.USER})
                self.assertEqual(subject.os_x86.catalog_inputs(parent), before)
                for name, digest in before.items():
                    self.assertEqual(subject.pc.sha(output / name), digest)
                self.assertIn('CosmicAppletWorkspaces', (output / subject.USER).read_text())
                self.assertFalse(result['cosmic_session_verified'])
                with self.assertRaises(ValueError): subject.assemble(parent, output)
                user = parent / subject.USER; user.parent.mkdir(parents=True); user.write_text('user configuration')
                before[subject.USER] = subject.pc.sha(user)
                (parent / 'cosmic-workspace-applets-origin.json').write_text(json.dumps(dict(
                    status='WORKSPACE_APPLETS_INSTALLED_NOT_RUN', files=before)))
                with self.assertRaises(ValueError): subject.assemble(parent, root / 'refused')
                self.assertEqual(user.read_text(), 'user configuration')
                self.assertFalse((root / 'refused').exists())


if __name__ == '__main__': unittest.main()
