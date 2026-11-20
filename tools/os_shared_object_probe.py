#!/usr/bin/env python3
"""Verify real memfd metadata admission, unchanged page bounds and slot reuse."""
import argparse
from pathlib import Path
import re
from os_signal_restart import run_probe, rights_snapshot
import x86_64 as pc


def observe_reclamation(console):
    start = len(console.raw)
    ofds = rights_snapshot(console)['objects']
    matches = re.findall(rb'^SHARED_OBJECTS ([^\r\n]+)', console.raw[start:], re.MULTILINE)
    pc.require(len(matches) == 1, 'Missing actual shared-object reclamation receipt')
    values = {key.decode(): int(value) for key, value in re.findall(rb'(\w+)=(\d+)', matches[0])}
    pc.require(all(values[key] == 0 for key in ('objects', 'pages', 'mappings', 'description_refs',
               'mapping_refs', 'grant_reserved', 'grant_used'))
               and values['metadata_capacity'] == 16 and values['page_capacity'] == values['free_pages'] == 4096
               and ofds['live'] == ofds['references'] == 0,
               'Shared objects/pages/OFDs were not reclaimed within the unchanged bounds')
    return dict(shared_objects=values, ofds=ofds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'notifications-peer-probe', 'SHARED_OBJECT_PROBE',
        ('CREATE_16', 'REJECT_17', 'PAGE_BOUNDS', 'REUSE', 'CLEANUP'), producer_entry=__file__,
        observe_exit=observe_reclamation)


if __name__ == '__main__':
    raise SystemExit(main())
