"""Bundle admission boundaries; fixtures are separate from real ELF/guest proof."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import cosmic_workspace_applets_v1 as subject


class WorkspaceAppletContract(unittest.TestCase):
    def test_additional_sdk_rejects_tampered_receipts_archives_and_wrong_isa(self):
        # Deliberately synthetic ELF headers/archive members; no executable or
        # native build proof is claimed by this isolated admission fixture.
        with tempfile.TemporaryDirectory(prefix='cyxia-input-admission-') as temporary:
            sdk = Path(temporary).resolve()
            def elf_header(kind, machine=62):
                raw = bytearray(64); raw[:7] = b'\x7fELF\x02\x01\x01'
                struct.pack_into('<HH', raw, 16, kind, machine)
                return bytes(raw)
            body = elf_header(1)
            archive = b'!<arch>\n' + b'fixture.o/'.ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) * 2
            archive += b'644'.ljust(8) + str(len(body)).encode().ljust(10) + b'`\n' + body
            recipe = dict(native_inputs=[], additional_native_inputs=[], additional_native_licenses=[])
            for relative in subject.INPUT_LIBRARIES:
                path = sdk / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(archive)
                recipe['additional_native_inputs'].append(dict(path=relative, sha256=subject.base.digest(path), bytes=len(archive)))
            compiler = sdk / 'bin/x86_64-linux-musl-cc'; compiler.parent.mkdir(); compiler.write_text('compiler fixture')
            smoke = sdk / 'native-input-port/static-link.elf'; smoke.parent.mkdir(); smoke.write_bytes(elf_header(2))
            producers = {}
            for relative in ('tools/build_cosmic_input_sdk_v1.py', 'ports/cosmic/native-input-sdk-v1/sources.json'):
                path = sdk / 'producer-sources' / relative
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text('archived fixture')
                producers[relative] = subject.base.digest(path)
            receipt = dict(status='NATIVE_INPUT_SDK_BUILT_NOT_RUN', target=subject.parent.TARGET,
                libraries={row['path']: {k: row[k] for k in ('sha256', 'bytes')} for row in recipe['additional_native_inputs']},
                sources=subject.base.load_json(subject.base.ROOT / 'ports/cosmic/native-input-sdk-v1/sources.json'),
                original_native_inputs={}, compiler_sha256=subject.base.digest(compiler), original_inputs_preserved=True,
                device_runtime_verified=False, guest_execution=False, producers=producers,
                producer_sha256=producers['tools/build_cosmic_input_sdk_v1.py'],
                source_manifest_sha256=producers['ports/cosmic/native-input-sdk-v1/sources.json'],
                static_link_probe=dict(sha256=subject.base.digest(smoke), bytes=64, executed=False))
            origin = sdk / 'native-input-sdk-origin.json'
            def bind(value):
                origin.write_text(json.dumps(value))
                recipe['native_sdk_extension'] = dict(path=origin.name, sha256=subject.base.digest(origin))
            bind(receipt)
            subject.additional_link_inputs(sdk, recipe)
            for change in (dict(status='FAILED'), dict(guest_execution=True), dict(libraries={})):
                bind({**receipt, **change})
                with self.assertRaises(subject.base.CosmicBuildError):
                    subject.additional_link_inputs(sdk, recipe)
            bind(receipt)
            victim = sdk / subject.INPUT_LIBRARIES[0]; pristine = victim.read_bytes(); victim.write_bytes(b'changed')
            with self.assertRaises(subject.base.CosmicBuildError):
                subject.additional_link_inputs(sdk, recipe)
            victim.write_bytes(pristine)
            smoke.write_bytes(elf_header(2, 183))
            changed = copy.deepcopy(receipt); changed['static_link_probe']['sha256'] = subject.base.digest(smoke); bind(changed)
            with self.assertRaises(subject.cosmic_ports.PortError):
                subject.additional_link_inputs(sdk, recipe)

    def test_export_checks_real_modes_without_assuming_digest_records_have_modes(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-applets-source-') as temporary:
            root = Path(temporary).resolve(); stage = root / 'stage'; native = root / 'native'
            stage.mkdir(); native.mkdir()
            (stage / 'Cargo.lock').write_text('locked\n')
            (native / 'lib.rs').write_text('genuine binding\n')
            target = stage / 'native-deps/binding/lib.rs'
            target.parent.mkdir(parents=True); target.write_bytes((native / 'lib.rs').read_bytes())
            for path in (stage / 'Cargo.lock', native / 'lib.rs', target):
                path.chmod(0o644)
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            inputs = {'originals': {'applets': {'files': {'Cargo.lock': {
                'sha256': digest(stage / 'Cargo.lock'), 'mode': '100644'}}}},
                'native_bindings': {'binding': {'path': str(native), 'files': {
                    'lib.rs': {'sha256': digest(native / 'lib.rs')}}}}}
            with patch.object(subject, 'contract', return_value=({'after': {}}, None, None, None, None)), \
                 patch.object(subject.parent, 'contract', return_value=({'after': {}}, None, None, None, None)):
                subject.verify_export(stage, inputs)
                target.chmod(0o600)
                with self.assertRaises(subject.base.CosmicBuildError):
                    subject.verify_export(stage, inputs)
                target.chmod(0o644); target.write_text('modified\n')
                with self.assertRaises(subject.base.CosmicBuildError):
                    subject.verify_export(stage, inputs)

    def test_locked_offline_commands_select_both_original_roots_and_complete_features(self):
        _, recipe, _, _, _ = subject.contract()
        programs = {name: 'path+file:///fixture/source/' + name + '#1.10.0' for name in subject.PROGRAMS}
        metadata, command = subject.commands('/tool/cargo', Path('/fixture/source'), recipe, 2, programs)
        for argv, features in ((metadata, subject.METADATA_FEATURES), (command, subject.FEATURES)):
            self.assertIn('--locked', argv)
            self.assertIn('--offline', argv)
            self.assertEqual(argv[argv.index('--features') + 1], ','.join(features))
            self.assertNotIn('--no-default-features', argv)
        self.assertEqual(command.count('--package'), 2)
        self.assertIn('--bins', command)
        selected_features = command[command.index('--features') + 1].split(',')
        self.assertTrue(all(feature.split('/')[0] in subject.PROGRAMS for feature in selected_features),
                        'Cargo rejects features of workspace roots not selected for this build')
        for identifier in programs.values():
            self.assertIn(identifier, command)

    def test_binary_subset_or_extra_program_cannot_be_published(self):
        _, recipe, _, _, _ = subject.contract()
        for programs in ({}, {subject.PROGRAMS[0]: 'first'},
                         {name: name for name in (*subject.PROGRAMS, 'replacement')}):
            with self.subTest(programs=programs), self.assertRaises(subject.base.CosmicBuildError):
                subject.commands('/cargo', Path('/fixture/source'), recipe, 2, programs)

    def test_contract_rejects_different_defaults_sdk_binary_or_capacity(self):
        original = subject.base.load_json
        cases = [
            ('native-recipe.json', lambda r: r.update(default_features=False)),
            ('native-recipe.json', lambda r: r.update(binaries=[subject.PROGRAMS[0]])),
            ('native-recipe.json', lambda r: r.update(binary='cosmic-applet-time')),
            ('native-recipe.json', lambda r: r.update(features=subject.FEATURES[:-1])),
            ('native-recipe.json', lambda r: r['native_inputs'][0].update(sha256='0' * 64)),
            ('resource-profile.json', lambda r: r.update(image_bytes=r['image_bytes'] * 2)),
            ('source-policy.json', lambda r: r['after'].update({'unreviewed.rs': '0' * 64})),
        ]
        for filename, change in cases:
            def read(path):
                data = original(path)
                if Path(path) == subject.PORT / filename:
                    data = copy.deepcopy(data)
                    change(data)
                return data
            with self.subTest(filename=filename), patch.object(subject.base, 'load_json', side_effect=read):
                with self.assertRaises(subject.base.CosmicBuildError):
                    subject.contract()


if __name__ == '__main__':
    unittest.main()
