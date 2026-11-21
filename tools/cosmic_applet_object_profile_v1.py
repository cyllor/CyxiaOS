"""Bind the opt-in object envelope to the actual paired native host images."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'rootfs/usr/share/cyxia/cosmic-applets-v1.json'
BUS = 'rootfs/etc/dbus-1/session.conf'
BUS_SOURCE = ROOT / 'ports/cosmic/native-workspace-applets-v1/session-bus.conf'
POPUP_POLICY = ROOT / 'ports/cosmic/native-popup-input-v1/source-policy.json'
FIELDS = dict(profile='cosmic-applets-objects-v1', fds_per_process=128,
    open_descriptions=512, unix_endpoints=128, unix_connections=64, shared_objects=32, shared_mappings_per_process=32,
    session_bus_connections=32, panel_popup_input='cosmic-panel-popup-input-v1')


def validate(prefix, inputs):
    path = Path(prefix) / CONTRACT
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError('missing bounded COSMIC applet object contract')
    value = json.loads(path.read_text())
    if (set(value) != {*FIELDS, 'hosts', 'host_source_policy_sha256', 'session_bus_sha256', 'panel_popup_source_policy_sha256'}
            or any(type(value[k]) is not type(v) or value[k] != v for k, v in FIELDS.items())
            or set(value['hosts']) != {'cosmic-session.elf', 'cosmic-panel.elf'}):
        raise ValueError('COSMIC applet object contract mismatch')
    expected = hashlib.sha256((ROOT / 'ports/cosmic/native-applet-hosts-v1/source-policy.json').read_bytes()).hexdigest()
    if value['host_source_policy_sha256'] != expected:
        raise ValueError('COSMIC applet host source contract changed')
    bus_sha = hashlib.sha256(BUS_SOURCE.read_bytes()).hexdigest()
    if value['session_bus_sha256'] != bus_sha or inputs.get(BUS) != bus_sha:
        raise ValueError('COSMIC applet session bus contract changed')
    if value['panel_popup_source_policy_sha256'] != hashlib.sha256(POPUP_POLICY.read_bytes()).hexdigest():
        raise ValueError('COSMIC panel popup source contract changed')
    for name, digest in value['hosts'].items():
        if name not in inputs or inputs[name] != digest:
            raise ValueError('COSMIC applet host image differs: ' + name)
    return value
