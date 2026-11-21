#!/usr/bin/env python3
"""Append the original optional workspace applet without editing defaults."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import cosmic_applet_object_profile_v1 as objects
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

pc = os_x86.pc
DEFAULT = 'rootfs/usr/share/cosmic/com.system76.CosmicPanel.Panel/v1/plugins_wings'
USER = 'rootfs/.config/cosmic/com.system76.CosmicPanel.Panel/v1/plugins_wings'
DEFAULT_SHA = '21088e8f37cadd744fd28f3db99baabaebcc99fdd45693eea8ed6b312d414166'


def assemble(parent, output):
    parent, output = Path(parent).resolve(strict=True), Path(output).absolute()
    pc.require(not output.exists() and output.parent.is_dir(), 'Preserving optional catalog output')
    original = os_x86.catalog_inputs(parent)
    receipt = json.loads((parent / 'cosmic-workspace-applets-origin.json').read_text())
    pc.require(receipt['status'] == 'WORKSPACE_APPLETS_INSTALLED_NOT_RUN' and receipt['files'] == original,
               'Complete paired workspace applet catalog required')
    objects.validate(parent, original)
    pc.require(pc.sha(parent / DEFAULT) == DEFAULT_SHA and USER not in original,
               'Original panel defaults required; preserve existing user configuration')
    source = (parent / DEFAULT).read_text()
    anchor = '"com.system76.CosmicPanelAppButton"]'
    pc.require(source.count(anchor) == 1, 'Unexpected panel default syntax')
    content = source.replace(anchor, '"com.system76.CosmicPanelAppButton", "com.system76.CosmicAppletWorkspaces"]')
    producers = os_x86.producer_sources(__file__)
    with tempfile.TemporaryDirectory(prefix='.optional-workspaces-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'catalog'
        subprocess.run(['/bin/cp', '-cRp', str(parent), str(stage)], check=True, timeout=60)
        target = stage / USER; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content); target.chmod(0o644)
        current = os_x86.catalog_inputs(stage)
        pc.require(current == {**original, USER: pc.sha(target)}, 'Unrelated optional catalog delta')
        result = dict(status='OPTIONAL_USER_CONFIGURATION_NOT_RUN', parent=str(parent),
            parent_receipt_sha256=pc.sha(parent / 'cosmic-workspace-applets-origin.json'),
            default_sha256=DEFAULT_SHA, added={USER: pc.sha(target)}, files=current,
            scope='append optional workspace list; all original default identities unchanged',
            producers=producers, full_os_verified=False, cosmic_session_verified=False)
        pc.write_json(stage / 'optional-workspace-user-config-origin.json', result)
        pc.require(os_x86.catalog_inputs(parent) == original and os_x86.producer_sources(__file__) == producers,
                   'Optional catalog inputs changed during assembly')
        pc.require(not output.exists(), 'Optional catalog output appeared')
        stage.rename(output)
    return result


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host(); result = assemble(args.parent, args.output)
    print(result['status'])


if __name__ == '__main__':
    main()
