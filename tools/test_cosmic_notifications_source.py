"""Pure source-policy/archive boundary checks; never Cargo, Git or native tools."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import cosmic_notifications_source as subject


class NotificationSourcePolicy(unittest.TestCase):
    def setUp(self):
        self.source = {'name': 'cosmic-notifications', 'repository': 'https://github.com/pop-os/cosmic-notifications',
                       'commit': '1' * 40}
        self.recipe = {'component': self.source['name'], 'commit': self.source['commit'],
                       'source_lock_sha256': '2' * 64,
                       'reviewed_rust_flags': list(subject.FLAGS),
                       'reviewed_rustdoc_flags': list(subject.FLAGS)}
        self.policy = {'schema_version': 1, 'component': self.source['name'],
                       'repository': self.source['repository'], 'commit': self.source['commit'],
                       'source_lock_sha256': self.recipe['source_lock_sha256'],
                       'before': {'.cargo/config.toml': subject.CONFIG_SHA256},
                       'after': {'.cargo/config.toml': None},
                       'rust_flags': list(subject.FLAGS), 'rustdoc_flags': list(subject.FLAGS)}

    def test_exact_reviewed_policy_and_static_flags_are_preserved(self):
        self.assertEqual(subject.validate_policy(self.policy, self.source, self.recipe), self.policy)
        env = {'CARGO_ENCODED_RUSTFLAGS': '-C\x1flink-self-contained=no'}
        result = subject.cargo_environment(env, self.policy)
        self.assertEqual(result['CARGO_ENCODED_RUSTFLAGS'],
                         '-C\x1flink-self-contained=no\x1f--cfg\x1ftokio_unstable')
        self.assertEqual(result['CARGO_ENCODED_RUSTDOCFLAGS'], '--cfg\x1ftokio_unstable')
        self.assertEqual(env, {'CARGO_ENCODED_RUSTFLAGS': '-C\x1flink-self-contained=no'})

    def test_unknown_flags_paths_postimages_and_identities_fail_closed(self):
        changes = [{'rust_flags': ['--cfg', 'different']}, {'rustdoc_flags': []},
                   {'before': {'../config.toml': subject.CONFIG_SHA256}},
                   {'before': {'.cargo/config.toml': '0' * 64}},
                   {'after': {'.cargo/config.toml': subject.CONFIG_SHA256}},
                   {'commit': '0' * 40}, {'unchecked': True}, {'schema_version': True}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.validate_policy({**self.policy, **change}, self.source, self.recipe)
        bad_recipe = copy.deepcopy(self.recipe)
        bad_recipe['reviewed_rust_flags'].append('-Zunstable-options')
        with self.assertRaises(ValueError):
            subject.validate_policy(self.policy, self.source, bad_recipe)
        for key in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.cargo_environment({key: ''}, self.policy)

    def archive(self, entries):
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode='w') as packed:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                if isinstance(data, bytes):
                    info.size = len(data)
                    packed.addfile(info, io.BytesIO(data))
                else:
                    info.type, info.linkname = tarfile.SYMTYPE, data
                    packed.addfile(info)
        memory.seek(0)
        return tarfile.open(fileobj=memory)

    def test_archive_accepts_only_exact_known_config(self):
        with self.archive([('.cargo/config.toml', subject.CONFIG),
                           ('.cargo/config.default', subject.CONFIG), ('src/main.rs', b'fn main() {}')]) as packed:
            self.assertEqual(len(subject.archive_members(packed)), 3)

    def test_archive_tamper_new_configs_and_escaping_exports_are_rejected(self):
        cases = [[('.cargo/config.toml', subject.CONFIG + b'\n[target]\n')],
                 [('src/main.rs', b'fn main() {}')],
                 [('.cargo/config.toml', subject.CONFIG), ('sub/.cargo/config', subject.CONFIG)],
                 [('.cargo/config.toml', subject.CONFIG), ('../outside', b'x')],
                 [('.cargo/config.toml', subject.CONFIG), ('/outside', b'x')],
                 [('.cargo/config.toml', subject.CONFIG), ('a\\outside', b'x')],
                 [('.cargo/config.toml', subject.CONFIG), ('link', '../../outside')],
                 [('.cargo/config.toml', subject.CONFIG), ('.cargo/config.toml', subject.CONFIG)]]
        for entries in cases:
            with self.subTest(entries=entries), self.archive(entries) as packed, self.assertRaises(ValueError):
                subject.archive_members(packed)
        with self.archive([('.cargo/config.toml', subject.CONFIG)]) as packed, self.assertRaises(ValueError):
            subject.archive_members(packed, max_bytes=1)

    def test_policy_file_tamper_escape_and_symlink_rejected_without_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                subject.subprocess, 'run', side_effect=AssertionError('native subprocess forbidden')):
            root = Path(temporary).resolve()
            policy_path = root / 'policy.json'
            policy_path.write_text(json.dumps(self.policy))
            recipe = {**self.recipe, 'source_export_policy':
                      {'path': 'policy.json', 'sha256': subject.build.digest(policy_path)}}
            self.assertEqual(subject.load_policy(recipe, root / 'recipe.json', self.source), self.policy)
            policy_path.write_text(json.dumps({**self.policy, 'rust_flags': ['--cfg', 'injected']}))
            with self.assertRaises(ValueError):
                subject.load_policy(recipe, root / 'recipe.json', self.source)
            for value in ('../policy.json', '/policy.json'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    subject.load_policy({**recipe, 'source_export_policy':
                                        {'path': value, 'sha256': '0' * 64}}, root / 'recipe.json', self.source)
            policy_path.unlink()
            policy_path.symlink_to(root / 'outside')
            with self.assertRaises(ValueError):
                subject.load_policy(recipe, root / 'recipe.json', self.source)


if __name__ == '__main__':
    unittest.main()
