"""Actual launch-expression/parser seams; syntax evidence is separate, no native PASS."""
import ast
import copy
import inspect
from pathlib import Path
from types import SimpleNamespace
import unittest

import run_v13_a10 as runner
import verify_v13_a10_native_receipt as native

NODE = 'cyxia-a10-disk'


def capture_drive_option(endpoint):
    # Evaluate only the drive-option expression in the reviewed local capture
    # implementation, as other host fixtures extract production function bodies.
    # No receipt/archive code or node-name is evaluated or selected here.
    tree = ast.parse(Path(inspect.getfile(runner)).read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
    argv = next(n.value for n in ast.walk(function) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'argv' for t in n.targets))
    at = next(i for i, value in enumerate(argv.elts)
              if isinstance(value, ast.Constant) and value.value == '-drive')
    expression = ast.Expression(argv.elts[at + 1])
    return eval(compile(expression, inspect.getfile(runner), 'eval'), {'__builtins__': {}},
                {'server': SimpleNamespace(path=endpoint),
                 'A10_DISK_NODE_NAME': getattr(runner, 'A10_DISK_NODE_NAME', None)})


def launch(private='/tmp/synthetic', root='/capture', binary='/trusted/qemu', port=1234):
    context = dict(binary=binary, private_dir=private, private_mode=0o700,
        capture_root=root, network_port=port,
        endpoints=dict(qmp=private+'/q.sock', gdb=private+'/g.sock', nbd=private+'/disk.sock'))
    inputs = dict(mode=2, cut=216)
    # Independent literal launch grammar. It does not obtain the expected node
    # identity from the capture implementation or any producer/receipt field.
    argv = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
        '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
        '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
        '-drive', f'if=none,id=disk0,node-name=cyxia-a10-disk,file=nbd:unix:{private}/disk.sock,format=raw,cache=writeback',
        '-device', 'virtio-blk-device,drive=disk0,request-merging=off',
        '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
        '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
        '-object', 'rng-random,id=rng0,filename=/dev/urandom', '-device', 'virtio-rng-device,rng=rng0',
        '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
        '-qmp', f'unix:{private}/q.sock,server=on,wait=off',
        '-gdb', f'unix:{private}/g.sock,server=on,wait=off',
        '-kernel', root+'/node-a.elf', '-no-reboot']
    return context, inputs, argv


def protocol(node=NODE):
    greeting = {'direction': 'receive', 'message': {'QMP': {'version': {
        'qemu': {'major': 10, 'minor': 2, 'micro': 2}, 'package': 'v10.2.2-dirty'}, 'capabilities': ['oob']}}}
    event = dict(event='BLOCK_IO_ERROR', timestamp=dict(seconds=1, microseconds=2),
        data={'device': 'disk0', 'node-name': node, 'nospace': False,
              'qom-path': '/machine/peripheral-anon/device[0]', 'operation': 'write',
              'action': 'report', 'reason': 'Input/output error'})
    return [greeting, dict(direction='send', message=dict(execute='cont', id=1)),
        dict(direction='receive', message=dict(event='RESUME', timestamp=dict(seconds=1, microseconds=1))),
        dict(direction='receive', message={'id': 1, 'return': {}}),
        dict(direction='send', message=dict(execute='ringbuf-read', id=2)),
        dict(direction='receive', message=event), dict(direction='receive', message={'id': 2, 'return': ''})]


class FixedNodeIdentity(unittest.TestCase):
    def test_actual_capture_option_names_the_unique_raw_node(self):
        context, inputs, argv = launch()
        option = capture_drive_option('/tmp/synthetic/disk.sock')
        self.assertEqual(option, argv[argv.index('-drive') + 1])
        argv[argv.index('-drive') + 1] = option
        native.validate_launch(argv, context, inputs)

    def test_fixed_node_launch_is_accepted_without_a_native_verdict(self):
        context, inputs, argv = launch()
        self.assertIsNone(native.validate_launch(argv, context, inputs))
        self.assertIn('-S', argv)
        self.assertNotIn('cont', argv)

    def test_missing_renamed_duplicate_or_differently_attached_nodes_are_rejected(self):
        context, inputs, argv = launch()
        for mutation in ('missing', 'other-name', 'auto101', 'auto131', 'duplicate-node',
                         'duplicate-drive', 'wrong-drive-id', 'wrong-device-binding'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(argv)
                at = changed.index('-drive') + 1
                if mutation == 'missing': changed[at] = changed[at].replace('node-name=cyxia-a10-disk,', '')
                elif mutation in ('other-name', 'auto101', 'auto131'):
                    name = {'other-name': 'unreviewed-node', 'auto101': '#block101', 'auto131': '#block131'}[mutation]
                    changed[at] = changed[at].replace('node-name=cyxia-a10-disk', 'node-name='+name)
                elif mutation == 'duplicate-node': changed[at] += ',node-name=cyxia-a10-disk'
                elif mutation == 'duplicate-drive': changed += ['-drive', changed[at]]
                elif mutation == 'wrong-drive-id': changed[at] = changed[at].replace('id=disk0', 'id=other')
                elif mutation == 'wrong-device-binding':
                    changed[changed.index('virtio-blk-device,drive=disk0,request-merging=off')] = 'virtio-blk-device,drive=other,request-merging=off'
                with self.assertRaisesRegex(ValueError, 'native launch'):
                    native.validate_launch(changed, context, inputs)

    def test_real_fault_parser_collects_only_the_explicit_node(self):
        candidates = []
        pairs = list(native.transactions(protocol(), 20, [], fault_events=candidates))
        self.assertEqual(len(pairs), 2)
        self.assertEqual(len(candidates), 1)
        self.assertNotIn('native_execution_verified', candidates[0])

    def test_old_auto_nodes_are_never_compatibility_aliases_and_default_remains_deny(self):
        for node in ('#block101', '#block131', '#block999', 'cyxia-a10-other', ''):
            with self.subTest(node=node), self.assertRaises(ValueError):
                list(native.transactions(protocol(node), 20, [], fault_events=[]))
        with self.assertRaisesRegex(ValueError, 'unaccounted QMP asynchronous event'):
            list(native.transactions(protocol(), 20, []))


if __name__ == '__main__': unittest.main()
