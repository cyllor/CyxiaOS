"""Host regressions for the new compositor source and admission boundaries."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools import build_cosmic_comp_linux as producer


class Contracts(unittest.TestCase):
    def setUp(self):
        self.recipe = json.loads((producer.ROOT / 'ports/cosmic/native-comp/native-recipe.json').read_text())

    def test_preserved_native_series_and_features(self):
        producer.contract(self.recipe)
        for field, value in [('commit', '0' * 40), ('features', ['backend-winit']),
                             ('default_features', True), ('effective_lock_sha256', '0' * 64),
                             ('source_series', {'path':'elsewhere', 'sha256':producer.SERIES_SHA256})]:
            with self.subTest(field=field), self.assertRaises(producer.base.CosmicBuildError):
                producer.contract({**self.recipe, field:value})

    def test_full_os_budget_is_fixed(self):
        self.recipe['resource_profile'] = producer.PROFILE
        profile = dict(target_runtime_validated=False, jobs_max=2, min_free_bytes=1024**3,
                       max_build_bytes=3*1024**3, timeout_seconds=3600,
                       max_elf_bytes=64*1024**2, image_bytes=64*1024**2, stack_bytes=2*1024**2)
        document = dict(schema_version=1, target='x86_64-unknown-linux-musl',
                        build_profiles={producer.PROFILE:profile})
        self.assertEqual(producer.full_os_profile(document, self.recipe, 2), profile)
        for field, value in [('target_runtime_validated', True), ('image_bytes', 128*1024**2),
                             ('stack_bytes', 4096), ('timeout_seconds', 3601), ('jobs_max', 3)]:
            changed = deepcopy(document)
            changed['build_profiles'][producer.PROFILE][field] = value
            with self.subTest(field=field), self.assertRaises(producer.base.CosmicBuildError):
                producer.full_os_profile(changed, self.recipe, 2)
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.full_os_profile(document, self.recipe, 3)


class GitAndMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.stage = self.root / 'source'
        self.stage.mkdir()
        (self.stage / 'Cargo.toml').write_text('[package]\nname="cosmic-comp"\nversion="1.0.0"\n')
        self.cache = self.root / 'cache'
        self.checkout = self.cache / 'git/checkouts/dependency-fixed/commit'
        self.checkout.mkdir(parents=True)
        self.git('init', '--quiet')
        (self.checkout / 'LICENSE').write_text('tracked license\n')
        (self.checkout / 'pkg').mkdir()
        (self.checkout / 'pkg/Cargo.toml').write_text('[package]\nname="dep"\nversion="1.0.0"\n')
        (self.checkout / 'pkg/LICENSE').symlink_to('../LICENSE')
        self.commit = self.commit_all()
        self.spec = 'git+https://example.invalid/pinned#' + self.commit
        self.recipe = {'package':'cosmic-comp', 'binary':'cosmic-comp'}
        self.write_lock()
        self.metadata = {'version':1, 'packages':[
            {'id':'root', 'name':'cosmic-comp', 'version':'1.0.0', 'source':None,
             'manifest_path':str(self.stage/'Cargo.toml'),
             'targets':[{'name':'cosmic-comp','kind':['bin']}]},
            {'id':'dep', 'name':'dep', 'version':'1.0.0', 'source':self.spec,
             'manifest_path':str(self.checkout/'pkg/Cargo.toml'), 'targets':[]}],
             'resolve':{'nodes':[{'id':'root','dependencies':['dep']},{'id':'dep','dependencies':[]}]}}

    def git(self, *arguments):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.run(['/usr/bin/git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                               '-C',str(self.checkout),*arguments],env=env,capture_output=True,text=True,check=True).stdout.strip()

    def commit_all(self):
        self.git('add', '--all')
        self.git('commit','--quiet','-m','fixture')
        return self.git('rev-parse','HEAD')

    def write_lock(self):
        (self.stage/'Cargo.lock').write_text('version = 4\n[[package]]\nname="cosmic-comp"\nversion="1.0.0"\n'
            '[[package]]\nname="dep"\nversion="1.0.0"\nsource='+json.dumps(self.spec)+'\n')

    def validate(self):
        return producer.metadata_identity(self.metadata, self.stage, self.cache, self.recipe)

    def test_actual_tracked_cross_package_link_is_accepted(self):
        records = self.validate()
        self.assertEqual(records[1]['git_checkout']['commit'],self.commit)
        self.assertEqual(records[1]['git_checkout']['files']['pkg/LICENSE']['symlink'],'../LICENSE')

    def test_changed_git_blob_is_rejected(self):
        (self.checkout/'LICENSE').write_text('edited after acquisition\n')
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_untracked_checkout_content_is_rejected(self):
        (self.checkout/'untracked').write_text('unexpected\n')
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_tracked_link_cannot_escape_checkout(self):
        outside = self.checkout.parent/'outside'
        outside.write_text('outside\n')
        (self.checkout/'pkg/LICENSE').unlink()
        (self.checkout/'pkg/LICENSE').symlink_to('../../outside')
        commit = self.commit_all()
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.git_identity(self.checkout,commit)

    def test_real_git_replacement_cannot_hide_changed_tree(self):
        (self.checkout/'LICENSE').write_text('replacement commit\n')
        replacement = self.commit_all()
        self.git('replace',self.commit,replacement)
        self.git('checkout','--quiet','--detach',self.commit)
        self.assertEqual(self.git('rev-parse','HEAD'),self.commit)
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_export_uses_canonical_worktree_despite_replacement_ref(self):
        (self.checkout/'LICENSE').write_text('replacement export would be wrong\n')
        replacement = self.commit_all()
        self.git('--no-replace-objects','checkout','--quiet','--force','--detach',self.commit)
        self.git('replace',self.commit,replacement)
        # Git archive HEAD would follow the replacement even though the actual
        # checkout still contains every pinned original blob.
        destination=self.root/'canonical-export'
        producer.export_canonical(self.checkout,destination,self.commit)
        self.assertEqual((destination/'LICENSE').read_text(),'tracked license\n')
        self.assertTrue((destination/'pkg/LICENSE').is_symlink())

    def test_export_rejects_unreviewed_cargo_configuration(self):
        (self.checkout/'.cargo').mkdir()
        (self.checkout/'.cargo/config.toml').write_text('[build]\nrustflags=["--cfg","unreviewed"]\n')
        commit=self.commit_all()
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.export_canonical(self.checkout,self.root/'rejected-export',commit)

    def test_metadata_must_match_locked_git_commit(self):
        self.metadata['packages'][1]['source'] = self.spec[:-40] + '0'*40
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_cargo_git_branch_query_percent_escape_is_semantically_equal(self):
        self.spec='git+https://example.invalid/pinned?branch=feature%2Fcopy_clone#'+self.commit
        self.write_lock()
        self.metadata['packages'][1]['source']=self.spec.replace('%2F','/')
        self.assertEqual(self.validate()[1]['git_checkout']['commit'],self.commit)

    def test_query_normalization_does_not_accept_a_different_branch(self):
        self.spec='git+https://example.invalid/pinned?branch=feature%2Fcopy_clone#'+self.commit
        self.write_lock()
        self.metadata['packages'][1]['source']=self.spec.replace('%2Fcopy_clone','/different')
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_duplicate_or_unknown_git_revision_query_is_rejected(self):
        for query in ('branch=main&branch=other','revision=main','branch=bad%2G'):
            with self.subTest(query=query), self.assertRaises(producer.base.CosmicBuildError):
                producer.source_key('git+https://example.invalid/pinned?'+query+'#'+self.commit)

    def test_metadata_cannot_use_external_local_package(self):
        self.metadata['packages'][0]['manifest_path'] = str(self.checkout/'pkg/Cargo.toml')
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()

    def test_dependency_graph_cannot_reference_missing_package(self):
        self.metadata['resolve']['nodes'][0]['dependencies'].append('absent')
        with self.assertRaises(producer.base.CosmicBuildError):
            self.validate()


class SharedDeadline(unittest.TestCase):
    def exercise(self, metadata_seconds):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output, sdk = root/'source', root/'output', root/'sdk'
            source.mkdir(); output.mkdir(); (sdk/'sysroot').mkdir(parents=True)
            current = [100.0]
            observed = []
            recipe = {'target':'x86_64-unknown-linux-musl','native_inputs':[]}
            report = {'jobs':2,'link_completed':False,
                      'sysroot_before':producer.base.tree_identity(sdk/'sysroot')}

            def run(command, cwd, env, log, timeout, min_free, max_bytes, **kwargs):
                observed.append((command[1], timeout))
                if command[1] == 'metadata':
                    Path(log).write_text('{}')
                    current[0] += metadata_seconds
                else:
                    linked=output/'target'/recipe['target']/'release/cosmic-comp'
                    linked.parent.mkdir(parents=True)
                    linked.write_bytes(b'host-unit-fixture; never inspected or executed as ELF')
                    current[0] += 1

            with patch.object(producer.time,'monotonic',side_effect=lambda:current[0]), \
                    patch.object(producer.base,'run_bounded',side_effect=run), \
                    patch.object(producer,'metadata_identity',return_value=[]):
                try:
                    producer.compile_selected(report,Path('/fixture/cargo'),{},root,source,output,[],[],
                        (3600,1024,1024**2),{},recipe,root,{},sdk,1100.0)
                except producer.base.CosmicBuildError as error:
                    return observed, report, str(error)
            return observed, report, None

    def test_metadata_consumes_builds_remaining_deadline(self):
        calls, report, error = self.exercise(700)
        self.assertIsNone(error)
        self.assertEqual(calls,[('metadata',1000.0),('build',300.0)])
        self.assertTrue(report['link_completed'])

    def test_expired_metadata_prevents_compiler_launch(self):
        calls, report, error = self.exercise(1000)
        self.assertEqual(calls,[('metadata',1000.0)])
        self.assertIn('deadline exceeded',error)
        self.assertFalse(report['link_completed'])


if __name__ == '__main__':
    unittest.main()
