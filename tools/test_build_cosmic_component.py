"""Public Cargo metadata selection; fixtures are not target execution evidence."""
import copy
from pathlib import Path
import unittest

from tools.build_cosmic_component import local_package


class PackageSelection(unittest.TestCase):
    def setUp(self):
        self.source = Path('/cyxia-fixture/source')
        self.recipe = {'package': 'cosmic-settings-daemon', 'binary': 'cosmic-settings-daemon'}
        self.local = {'name': 'cosmic-settings-daemon', 'source': None,
                      'id': 'path+file:///cyxia-fixture/source#cosmic-settings-daemon@1.10.0',
                      'manifest_path': '/cyxia-fixture/source/Cargo.toml',
                      'targets': [{'name': 'cosmic-settings-daemon', 'kind': ['bin']}]}
        self.remote = {**self.local, 'source': 'git+https://github.com/pop-os/cosmic-settings-daemon#abc',
                       'id': 'git+https://github.com/pop-os/cosmic-settings-daemon#cosmic-settings-daemon@0.1.0',
                       'manifest_path': '/cyxia-fixture/cargo-cache/daemon/Cargo.toml'}

    def test_same_name_remote_library_does_not_make_local_binary_ambiguous(self):
        for packages in ([self.local, self.remote], [self.remote, self.local]):
            self.assertEqual(local_package({'packages': packages}, self.source, self.recipe),
                             'path+file:///cyxia-fixture/source#cosmic-settings-daemon@1.10.0')

    def test_root_binary_and_local_identity_are_required(self):
        cases = [[], [self.remote], [self.local, copy.deepcopy(self.local)],
                 [{**self.local, 'targets': [{'name': 'different', 'kind': ['bin']}]}],
                 [{**self.local, 'id': self.remote['id']}],
                 [{**self.local, 'manifest_path': '/cyxia-fixture/source/subcrate/Cargo.toml'}]]
        for packages in cases:
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                local_package({'packages': packages}, self.source, self.recipe)


if __name__ == '__main__':
    unittest.main()
