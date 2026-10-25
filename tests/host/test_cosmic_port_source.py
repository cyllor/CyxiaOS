import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import cosmic_port_source as prep


class CosmicPortSourceTests(unittest.TestCase):
    def metadata(self, root):
        source = root / 'source'
        source.mkdir()
        manifest = source / 'Cargo.toml'
        manifest.write_text('[package]\nname="fixture"\nversion="1.0.0"\n')
        doc = {'version': 1, 'packages': [{'id': 'fixture', 'name': 'fixture',
                'source': None, 'manifest_path': str(manifest)}],
                'resolve': {'nodes': [{'id': 'fixture', 'dependencies': []}]}}
        path = root / 'metadata.json'
        path.write_text(json.dumps(doc))
        return source, path, doc

    def test_resolved_sources_are_availability_not_guest_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, path, _ = self.metadata(Path(tmp))
            result = prep.summarize_metadata(path, source)
            self.assertEqual(result['package_count'], 1)
            self.assertEqual(result['root_packages'], ['fixture'])
            self.assertNotIn('guest_tested', result)

    def test_incomplete_graph_or_missing_sources_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, path, doc = self.metadata(Path(tmp))
            doc['resolve']['nodes'][0]['dependencies'] = ['absent']
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                prep.summarize_metadata(path, source)
            doc['resolve']['nodes'][0]['dependencies'] = []
            path.write_text(json.dumps(doc))
            (source / 'Cargo.toml').unlink()
            with self.assertRaisesRegex(ValueError, 'absent'):
                prep.summarize_metadata(path, source)

    def test_escaping_path_dependencies_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, path, doc = self.metadata(Path(tmp))
            outside = Path(tmp) / 'Cargo.toml'
            outside.write_text('')
            doc['packages'][0]['manifest_path'] = str(outside)
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'escapes'):
                prep.summarize_metadata(path, source)

    def test_failure_preserves_report_and_does_not_claim_availability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = {'name': 'fixture', 'commit': 'a' * 40}
            with patch.object(prep.ports, 'load_manifest', return_value={'components': [source]}), \
                 patch.object(prep.build, 'inspect_source', return_value={'path': str(root)}), \
                 patch.object(prep.build, 'resource_check', side_effect=ValueError('reserve exhausted')):
                with self.assertRaisesRegex(ValueError, 'reserve'):
                    prep.prepare('fixture', root / 'out', cache=root / 'cache')
            report = json.loads((root / 'out/preparation.json').read_text())
            self.assertEqual(report['status'], 'FAILED')
            self.assertFalse(report['built'])
            self.assertFalse(report['guest_tested'])
            self.assertFalse(report['native_dependency_closure_verified'])

    def test_invalid_resource_bounds_are_rejected_before_io(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'positive integers'):
                prep.prepare('fixture', Path('/uncreated'), timeout=value)

    def test_prepare_binds_export_and_rejects_cargo_source_mutation(self):
        for mutate in (False, True):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                source = {'name': 'fixture', 'commit': 'a' * 40}
                cargo = root / 'cargo'
                cargo.write_text('fixture tool')
                commands = []

                def export(_, destination):
                    destination.mkdir()
                    (destination / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="1.0.0"\n')
                    (destination / 'Cargo.lock').write_text('version = 4\n[[package]]\nname="fixture"\nversion="1.0.0"\n')

                def run(command, cwd, env, log, *args, **kwargs):
                    commands.append(command)
                    if command[1] == 'metadata':
                        Path(log).write_text(json.dumps({'version': 1, 'packages': [
                            {'id': 'fixture', 'name': 'fixture', 'source': None,
                             'manifest_path': str(cwd / 'Cargo.toml')}],
                            'resolve': {'nodes': [{'id': 'fixture', 'dependencies': []}]}}))
                        if mutate:
                            (cwd / 'Cargo.lock').write_text('changed')

                with patch.object(prep.ports, 'load_manifest', return_value={'components': [source]}), \
                     patch.object(prep.build, 'inspect_source', return_value={'path': str(root)}), \
                     patch.object(prep.build, 'resource_check'), \
                     patch.object(prep.build, 'export_source', side_effect=export), \
                     patch.object(prep, 'acquisition_environment', return_value=(cargo, {})), \
                     patch.object(prep.build, 'run_bounded', side_effect=run):
                    if mutate:
                        with self.assertRaisesRegex(ValueError, 'changed the immutable'):
                            prep.prepare('fixture', root / 'out', cache=root / 'cache')
                    else:
                        report = prep.prepare('fixture', root / 'out', cache=root / 'cache')
                        self.assertEqual(report['status'], 'CARGO_SOURCES_AVAILABLE')
                        self.assertFalse(report['native_dependency_closure_verified'])
                self.assertEqual(commands[0][1:], ['fetch', '--locked'])
                self.assertIn('--offline', commands[1])
                self.assertIn('--filter-platform', commands[1])

    @unittest.skipUnless((Path.home() / '.cargo/bin/rustc').exists(), 'Rust toolchain unavailable')
    def test_real_cargo_standalone_package_ignores_output_ancestor_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            source = {'name': 'fixture', 'commit': 'a' * 40}

            def export(_, destination):
                (destination / 'src').mkdir(parents=True)
                (destination / 'src/main.rs').write_text('fn main() {}\n')
                (destination / 'Cargo.toml').write_text(
                    '[package]\nname="fixture"\nversion="1.0.0"\nedition="2021"\n')
                (destination / 'Cargo.lock').write_text(
                    'version = 4\n[[package]]\nname="fixture"\nversion="1.0.0"\n')

            with patch.object(prep.ports, 'load_manifest', return_value={'components': [source]}), \
                 patch.object(prep.build, 'inspect_source', return_value={'path': str(root)}), \
                 patch.object(prep.build, 'export_source', side_effect=export):
                report = prep.prepare('fixture', root / 'out', cache=root / 'cache',
                                      min_free=1024**2, max_bytes=16*1024**2)
            self.assertEqual(report['status'], 'CARGO_SOURCES_AVAILABLE')
            self.assertEqual(report['resolved']['package_count'], 1)
            self.assertTrue((root / 'out/source/src/main.rs').is_file())
            self.assertEqual((root / 'Cargo.toml').read_text(), '[workspace]\nmembers=[]\n')


if __name__ == '__main__':
    unittest.main()
