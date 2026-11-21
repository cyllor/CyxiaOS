"""Synthetic input identities exercise the actual versioned catalog gate."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import cosmic_applet_object_profile_v1 as subject


class NativeHostContract(unittest.TestCase):
    def test_resource_or_host_drift_is_rejected(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temporary:
            root = Path(temporary); path = root / subject.CONTRACT; path.parent.mkdir(parents=True)
            inputs = {'cosmic-session.elf': '1' * 64, 'cosmic-panel.elf': '2' * 64}
            value = dict(subject.FIELDS, hosts=dict(inputs),
                session_bus_sha256=hashlib.sha256(subject.BUS_SOURCE.read_bytes()).hexdigest(),
                panel_popup_source_policy_sha256=hashlib.sha256(subject.POPUP_POLICY.read_bytes()).hexdigest(),
                host_source_policy_sha256=hashlib.sha256((subject.ROOT / 'ports/cosmic/native-applet-hosts-v1/source-policy.json').read_bytes()).hexdigest())
            inputs[subject.BUS] = value['session_bus_sha256']
            path.write_text(json.dumps(value)); subject.validate(root, inputs)
            with self.assertRaises(ValueError):
                subject.validate(root, inputs, notifications=True)
            notification_profile = {**value, **subject.NOTIFICATIONS_FIELDS}
            path.write_text(json.dumps(notification_profile))
            self.assertEqual(subject.validate(root, inputs, notifications=True)['shared_objects'], 48)
            with self.assertRaises(ValueError):
                subject.validate(root, inputs)
            for change in (dict(fds_per_process=64), dict(shared_objects=16), dict(shared_mappings_per_process=16),
                           dict(session_bus_sha256='0' * 64), dict(session_bus_connections=16),
                           dict(panel_popup_source_policy_sha256='0' * 64),
                           dict(host_source_policy_sha256='0' * 64), dict(fds_per_process=True)):
                path.write_text(json.dumps({**value, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError): subject.validate(root, inputs)
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): subject.validate(root, {**inputs, 'cosmic-panel.elf': '3' * 64})
            changed = copy.deepcopy(value); changed['hosts'].pop('cosmic-session.elf')
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError): subject.validate(root, inputs)
            path.unlink()
            with self.assertRaises(ValueError): subject.validate(root, inputs)


if __name__ == '__main__': unittest.main()
