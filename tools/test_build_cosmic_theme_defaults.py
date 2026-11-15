"""Exporter publication contracts; fixtures never compile or run a guest."""
import contextlib
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import build_cosmic_theme_defaults as b


def elf_bytes():
    data = bytearray(4096)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0,
                     b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
                     0x1000100, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x1000040, 0x1000040, 112, 112, 8)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 5, 0, 0x1000000, 0x1000000, 4096, 4096, 4096)
    return bytes(data)


class ThemeDefaultsBuildTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            cosmic, sdk, settings = [artifacts / name for name in ('cosmic', 'sdk', 'settings')]
            for directory in (cosmic, sdk, settings):
                directory.mkdir()
            source = root / 'client.rs'
            source.write_text('source fixture')
            inputs = {'cosmic_build': str(cosmic), 'sdk': str(sdk),
                      'settings_prefix': str(settings), 'rustc': str(root / 'rustc'),
                      'toolchain_root': str(root / 'toolchain'), 'source': b.common.file_identity(source),
                      'externs': {name: {'path': str(cosmic / ('lib' + name + '.rlib'))}
                                  for name in b.EXTERNS}}
            with patch.object(b, 'ARTIFACTS', artifacts), patch.object(b, 'SOURCE', source), \
                 patch.object(b, 'DEFAULT_BUILD', cosmic), patch.object(b, 'SDK', sdk), \
                 patch.object(b, 'idle_native_host'), patch.object(b, 'resource_check'):
                yield artifacts, settings, source, inputs

    def fake_run(self, command, cwd, env, log, timeout, min_free, max_bytes, **kwargs):
        self.assertEqual((timeout, min_free, max_bytes), (120, 1024 ** 3, 256 * 1024 ** 2))
        self.assertEqual(kwargs['budget_root'], Path(log).parent)
        Path(log).write_text('fixture rustc log\n')
        Path(command[command.index('-o') + 1]).write_bytes(elf_bytes())

    def test_target_rlibs_must_be_unique_regular_files(self):
        with self.fixture() as (_, _, _, inputs):
            root = Path(inputs['cosmic_build'])
            directory = root / b.SEARCH_ROOTS[0]
            directory.mkdir(parents=True)
            for name in b.EXTERNS:
                (directory / ('lib' + name + '-123.rlib')).write_bytes(b'library fixture')
            self.assertEqual(set(b.resolve_externs(root)), set(b.EXTERNS))
            duplicate = directory / 'libcosmic_theme-456.rlib'
            duplicate.write_bytes(b'extra')
            with self.assertRaisesRegex(b.BuildError, 'ambiguous'):
                b.resolve_externs(root)
            duplicate.unlink()
            selected = directory / 'libcosmic_theme-123.rlib'
            selected.unlink()
            with self.assertRaisesRegex(b.BuildError, 'Missing'):
                b.resolve_externs(root)
            selected.symlink_to(directory / 'libcosmic_config-123.rlib')
            with self.assertRaisesRegex(b.BuildError, 'Symlink'):
                b.resolve_externs(root)

    def test_destinations_are_fresh_confined_and_do_not_overlap_inputs(self):
        with self.fixture() as (artifacts, settings, _, inputs):
            output, prefix = artifacts / 'output', artifacts / 'prefix'
            self.assertEqual(b.destinations(output, prefix, settings), (output, prefix))
            for bad in (artifacts.parent / 'outside', Path(inputs['sdk']) / 'new', output / 'prefix'):
                with self.assertRaises(b.BuildError):
                    b.destinations(output, bad, settings)
            prefix.mkdir()
            (prefix / 'preserve').write_text('existing')
            with self.assertRaisesRegex(b.BuildError, 'fresh'):
                b.destinations(output, prefix, settings)
            self.assertEqual((prefix / 'preserve').read_text(), 'existing')

    def test_success_publishes_only_admitted_elf_with_exact_source_and_receipt(self):
        with self.fixture() as (artifacts, settings, source, inputs), \
             patch.object(b, 'capture_inputs', return_value=inputs), \
             patch.object(b, 'run_bounded', side_effect=self.fake_run):
            output, prefix = artifacts / 'output', artifacts / 'prefix'
            report = b.build(output, prefix, settings)
            self.assertEqual(report['status'], 'cross-built')
            self.assertFalse(report['generated_assets_verified'])
            self.assertEqual((output / 'client.rs').read_bytes(), source.read_bytes())
            self.assertEqual((prefix / b.EXECUTABLE).read_bytes(), elf_bytes())
            self.assertEqual((prefix / b.RECEIPT).read_bytes(), (output / b.RECEIPT).read_bytes())
            self.assertEqual(b.validate_inputs(prefix)['status'], 'VALIDATED_NOT_RUN')
            self.assertEqual(report['command'].count('--extern'), 2)
            self.assertEqual(report['command'][0], inputs['rustc'])
            self.assertIn('link-self-contained=no', report['command'])
            self.assertIn('target-feature=+crt-static', report['command'])

    def test_input_change_and_native_failure_never_publish_prefix(self):
        for failure in ('input-change', 'native-failure', 'copied-source-change'):
            with self.subTest(failure=failure), self.fixture() as (artifacts, settings, _, inputs):
                changed = copy.deepcopy(inputs)
                changed['changed'] = True
                captures = [inputs, changed] if failure == 'input-change' else [inputs, inputs]

                def run(*args, **kwargs):
                    if failure == 'native-failure':
                        raise b.CosmicBuildError('fixture compiler failed')
                    self.fake_run(*args, **kwargs)
                    if failure == 'copied-source-change':
                        (Path(args[3]).parent / 'client.rs').write_text('changed source')

                with patch.object(b, 'capture_inputs', side_effect=captures), \
                     patch.object(b, 'run_bounded', side_effect=run):
                    with self.assertRaises((b.BuildError, b.CosmicBuildError)):
                        b.build(artifacts / 'output', artifacts / 'prefix', settings)
                self.assertFalse((artifacts / 'prefix').exists())
                self.assertFalse((artifacts / 'output' / b.EXECUTABLE).exists())
                report = json.loads((artifacts / 'output' / b.RECEIPT).read_text())
                self.assertEqual(report['status'], 'failed')

    def test_validation_rejects_receipt_payload_and_input_mutations(self):
        with self.fixture() as (artifacts, settings, _, inputs), \
             patch.object(b, 'capture_inputs', return_value=inputs), \
             patch.object(b, 'run_bounded', side_effect=self.fake_run):
            output, prefix = artifacts / 'output', artifacts / 'prefix'
            report = b.build(output, prefix, settings)
            for key, value in [('limits', {}), ('command', []), ('environment', {}),
                               ('input_preserved', False), ('generated_assets_verified', True),
                               ('inputs_after', {})]:
                changed = {**report, key: value}
                for directory in (output, prefix):
                    (directory / b.RECEIPT).write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(b.BuildError):
                    b.validate_inputs(prefix)
            for directory in (output, prefix):
                (directory / b.RECEIPT).write_text(json.dumps(report))
            (prefix / b.EXECUTABLE).write_bytes(elf_bytes() + b'changed')
            with self.assertRaisesRegex(b.BuildError, 'ELF differs'):
                b.validate_inputs(prefix)
            (prefix / b.EXECUTABLE).write_bytes(elf_bytes())
            with patch.object(b, 'capture_inputs', return_value={**inputs, 'changed': True}):
                with self.assertRaisesRegex(b.BuildError, 'inputs changed'):
                    b.validate_inputs(prefix)


if __name__ == '__main__':
    unittest.main()
