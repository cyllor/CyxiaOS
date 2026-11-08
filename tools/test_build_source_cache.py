"""Actual Cargo cache witnesses; no mocked compiler or native acceptance."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import build_unified as builder


class SourceBoundBuildCache(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cyx-source-cache-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cargo = shutil.which('cargo')
        self.assertIsNotNone(self.cargo, 'real Cargo is required')
        self.environment = dict(os.environ, CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0')
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
            self.environment.pop(name, None)

    def crate(self, name, code):
        root = self.root / name
        (root / 'src').mkdir(parents=True)
        (root / 'Cargo.toml').write_text('[package]\nname="cache-witness"\nversion="0.1.0"\nedition="2021"\n[workspace]\n')
        (root / 'src/main.rs').write_text(code)
        subprocess.run([self.cargo, 'generate-lockfile', '--offline', '--quiet'],
            cwd=root, env=self.environment, check=True, capture_output=True, timeout=30)
        return root

    def sources(self, root):
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in ('Cargo.toml', 'Cargo.lock', 'src/main.rs')}

    def build_and_run(self, root, base):
        context = builder.build_cache_context(base, root, self.sources(root))
        target = Path(context['effective'])
        subprocess.run([self.cargo, 'build', '--offline', '--quiet', '--target-dir', str(target)],
            cwd=root, env=self.environment, check=True, capture_output=True, timeout=30)
        result = subprocess.check_output([str(target / 'debug/cache-witness')], text=True, timeout=10)
        return context, result.strip()

    def test_changed_source_with_restored_mtime_executes_new_bytes(self):
        root = self.crate('checkout', 'fn main() { println!("A"); }\n')
        source = root / 'src/main.rs'
        original = source.stat()
        first, output = self.build_and_run(root, self.root / 'shared-cache')
        self.assertEqual(output, 'A')
        source.write_text('fn main() { println!("B"); }\n')
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        second, output = self.build_and_run(root, self.root / 'shared-cache')
        self.assertEqual(output, 'B', 'Cargo reused an artifact for different backdated source bytes')
        self.assertNotEqual(first['effective'], second['effective'])

    def test_same_bytes_in_different_checkouts_have_separate_real_artifacts(self):
        code = 'fn main() { println!("{}", env!("CARGO_MANIFEST_DIR")); }\n'
        a, b = self.crate('checkout-a', code), self.crate('checkout-b', code)
        first, printed_a = self.build_and_run(a, self.root / 'shared-cache')
        second, printed_b = self.build_and_run(b, self.root / 'shared-cache')
        self.assertEqual(printed_a, str(a.resolve()))
        self.assertEqual(printed_b, str(b.resolve()))
        self.assertNotEqual(first['effective'], second['effective'])

    def test_context_is_deterministic_and_stays_under_explicit_cache_base(self):
        root = self.crate('checkout', 'fn main() {}\n')
        sources = self.sources(root)
        a = builder.build_cache_context(self.root / 'cache', root, sources)
        b = builder.build_cache_context(self.root / 'cache', root, dict(reversed(list(sources.items()))))
        self.assertEqual(a, b)
        self.assertEqual(Path(a['effective']).parent, Path(a['base']))
        self.assertEqual(a['source_root'], str(root.resolve()))

    def test_existing_namespace_symlink_is_rejected(self):
        root = self.crate('checkout', 'fn main() {}\n')
        base = self.root / 'cache'
        base.mkdir()
        context = builder.build_cache_context(base, root, self.sources(root))
        target = Path(context['effective'])
        self.assertNotEqual(target, base)
        outside = self.root / 'outside'
        outside.mkdir()
        target.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'cache namespace'):
            builder.build_cache_context(base, root, self.sources(root))

    def test_returned_artifacts_must_stay_in_selected_namespace(self):
        root = self.crate('checkout', 'fn main() {}\n')
        context = builder.build_cache_context(self.root / 'cache', root, self.sources(root))
        target = Path(context['effective'])
        target.mkdir(parents=True)
        artifact = target / 'kernel.elf'
        artifact.write_bytes(b'actual-artifact')
        self.assertEqual(builder.cache_artifact(artifact, target), artifact)
        outside = self.root / 'other-cache.elf'
        outside.write_bytes(b'stale-artifact')
        with self.assertRaisesRegex(ValueError, 'outside selected build cache namespace'):
            builder.cache_artifact(outside, target)
        link = target / 'redirect.elf'
        link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'outside selected build cache namespace'):
            builder.cache_artifact(link, target)
