#!/usr/bin/env python3
"""Prepare the narrowly scoped native FD adapter patch from verified exports."""
import difflib
import json
from pathlib import Path
import tempfile

import cosmic_applet_hosts_v1 as hosts


def main():
    hosts.PORT.mkdir(exist_ok=True)
    policy = dict(kind='cosmic-applet-hosts-v1', fd_limit=128, components={})
    for kind in hosts.NAMES:
        with tempfile.TemporaryDirectory(prefix='cyxia-host-policy-', dir='/private/tmp') as temporary:
            stage = Path(temporary) / 'source'
            hosts.original_export(kind, stage)
            source = 'native-deps/launch-pad/src/native_child.rs'
            path = stage / source; original = path.read_text()
            marker = 'const MAX_FDS: usize = 64;'
            hosts.require(original.count(marker) == 1, 'Native descriptor ABI preimage changed')
            record = dict(commit=hosts.parent_contract(kind)[2]['commit'],
                recipe_sha256=hosts.canonical(hosts.parent_contract(kind)[1]), source_path=source,
                before_tree_sha256=hosts.base.tree_identity(stage)['sha256'], before=hosts.base.digest(path),
                mode_sha256=hosts.canonical(hosts.modes(stage)))
            changed = original.replace(marker, 'const MAX_FDS: usize = 128;')
            patch = ''.join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True),
                fromfile='a/' + source, tofile='b/' + source))
            patch_path = hosts.PORT / (kind + '.patch'); patch_path.write_text(patch)
            path.write_text(changed)
            record.update(after_tree_sha256=hosts.base.tree_identity(stage)['sha256'],
                after=hosts.base.digest(path), patch_sha256=hosts.base.digest(patch_path))
            policy['components'][kind] = record
    (hosts.PORT / 'source-policy.json').write_text(json.dumps(policy, indent=2) + '\n')
    print('Prepared two genuine complete sources; only native descriptor bounds changed')


if __name__ == '__main__': main()
