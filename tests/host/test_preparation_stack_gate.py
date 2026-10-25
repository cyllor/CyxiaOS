from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import build_unified as build
import check_v13_preparation_stack as stack
from test_check_v13_preparation_stack import chain


class PreparationStackGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.objdump = self.root / 'lib/rustlib/aarch64-test/bin/llvm-objdump'
        self.objdump.parent.mkdir(parents=True)
        self.objdump.write_bytes(b'pinned LLVM binary')
        self.objdump.chmod(0o700)
        self.images = {node: self.root / f'node-{node}.elf' for node in ('a', 'b')}
        for node, image in self.images.items():
            image.write_bytes(b'actual ELF fixture ' + node.encode())
        self.tool = dict(path=str(self.objdump), sha256=build.sha(self.objdump),
                         version='LLVM version 22', source='rustc-sysroot',
                         sysroot=str(self.root), host='aarch64-test', rustc='rustc 1.95.0')

    def command(self, argv, **kwargs):
        if argv[-2:] == ['--print', 'sysroot']:
            output = str(self.root)
        elif argv[-2:] == ['--version', '--verbose']:
            output = 'rustc 1.95.0\nhost: aarch64-test\n'
        elif argv[-1] == '--version':
            output = 'LLVM version 22\n'
        else:
            output = chain(False)
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr='')

    def test_resolves_objdump_only_from_the_selected_rustc_sysroot(self):
        with patch.object(stack.subprocess, 'run', side_effect=self.command) as run:
            tool = stack.toolchain_objdump(dict(os.environ, RUSTC='/selected/rustc'))
        self.assertEqual(tool['path'], str(self.objdump))
        self.assertEqual(tool['sha256'], build.sha(self.objdump))
        self.assertEqual(tool['source'], 'rustc-sysroot')
        self.assertEqual(tool['host'], 'aarch64-test')
        self.assertTrue(any(call.args[0][0] == '/selected/rustc' for call in run.call_args_list))

    def test_missing_tool_component_fails_closed(self):
        self.objdump.unlink()
        with patch.object(stack.subprocess, 'run', side_effect=self.command):
            with self.assertRaisesRegex(ValueError, 'llvm-tools-preview'):
                stack.toolchain_objdump(os.environ)

    def test_both_actual_images_are_recomputed_and_provenance_is_retained(self):
        for node in self.images:
            (self.root / f'node-{node}-stack.json').write_text('{"passed": false}')
        with patch.object(stack.subprocess, 'run', side_effect=self.command) as run:
            result = build.preparation_stack_gate(self.images, self.root, self.tool, os.environ)
        self.assertEqual(set(result['nodes']), {'a', 'b'})
        self.assertEqual((result['stack_bytes'], result['exception_reserve_bytes']), (65536, 4096))
        self.assertEqual(result['checker_sha256'], build.sha(Path(stack.__file__)))
        calls = [call.args[0] for call in run.call_args_list if '-d' in call.args[0]]
        self.assertEqual([Path(call[-1]) for call in calls], list(self.images.values()))
        for node, image in self.images.items():
            report = json.loads((self.root / f'node-{node}-stack.json').read_text())
            self.assertTrue(report['passed'])
            self.assertEqual(report['elf_sha256'], build.sha(image))
            self.assertEqual(report['objdump']['sha256'], build.sha(self.objdump))
            self.assertEqual(report['objdump']['version'], 'LLVM version 22')

    def test_bad_second_image_overwrites_forged_pass_and_blocks_build(self):
        def command(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if '-d' in argv and Path(argv[-1]) == self.images['b']:
                result.stdout = chain(True)
            return result
        (self.root / 'node-b-stack.json').write_text('{"passed": true}')
        with patch.object(stack.subprocess, 'run', side_effect=command):
            with self.assertRaisesRegex(ValueError, 'preparation stack.*b'):
                build.preparation_stack_gate(self.images, self.root, self.tool, os.environ)
        self.assertTrue(json.loads((self.root / 'node-a-stack.json').read_text())['passed'])
        self.assertFalse(json.loads((self.root / 'node-b-stack.json').read_text())['passed'])

    def test_unrecognized_disassembly_retains_failure_and_rejects(self):
        def command(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if '-d' in argv:
                result.stdout = 'unrecognized compiler output'
            return result
        with patch.object(stack.subprocess, 'run', side_effect=command):
            with self.assertRaisesRegex(ValueError, 'preparation stack'):
                build.preparation_stack_gate(self.images, self.root, self.tool, os.environ)
        report = json.loads((self.root / 'node-a-stack.json').read_text())
        self.assertFalse(report['passed'])
        self.assertIn('missing function', report['error'])

    def test_changed_tool_or_elf_cannot_reuse_inspection(self):
        self.objdump.write_bytes(b'changed binary')
        with self.assertRaisesRegex(ValueError, 'objdump changed'):
            stack.inspect_elf(self.images['a'], self.tool, os.environ)
        self.tool['sha256'] = build.sha(self.objdump)
        def command(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if '-d' in argv:
                self.images['a'].write_bytes(b'changed while disassembling')
            return result
        with patch.object(stack.subprocess, 'run', side_effect=command):
            with self.assertRaisesRegex(ValueError, 'ELF changed'):
                stack.inspect_elf(self.images['a'], self.tool, os.environ)


if __name__ == '__main__':
    unittest.main()
