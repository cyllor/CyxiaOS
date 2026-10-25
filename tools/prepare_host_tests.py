#!/usr/bin/env python3
"""Prepare pinned upstream inputs for host tests; network requires --fetch.

Run before unittest discovery in a fresh checkout. Existing modified inputs
are rejected and preserved. This does not build or run the COSMIC desktop.
"""
import argparse
import json

from build_rust_egl_probe import source_input
from cosmic_ports import ROOT, PortError, fetch_source, inspect_source, load_manifest


def prepare(*, fetch=False):
    pins = [json.loads((ROOT / f'ports/cosmic/smithay-{name}-client-source.json').read_text())['crate']
            for name in ('dynamic', 'interactive', 'multi', 'resize', 'xdg')]
    if any(pin != pins[0] for pin in pins):
        raise ValueError('Client protocol archive pins disagree')
    smithay = json.loads((ROOT / 'ports/cosmic/smithay-source.json').read_text())
    cosmic = next(item for item in load_manifest()['components'] if item['name'] == 'cosmic-comp')
    if cosmic['commit'] != smithay['cosmic_comp_commit']:
        raise ValueError('COSMIC source pins disagree')
    sources = [
        (cosmic, ROOT / 'artifacts/cosmic-sources'),
        ({'name': 'smithay', 'repository': 'https://github.com/Smithay/smithay',
          'commit': smithay['smithay_commit'],
          'directory': 'smithay-' + smithay['smithay_commit']}, ROOT / 'artifacts/smithay-research'),
    ]
    for source, cache in sources:
        record = fetch_source(source, cache) if fetch else inspect_source(cache, source)
        if not record['verified']:
            raise PortError('Missing verified host source; run with --fetch: ' + source['name'])
    archive = source_input(ROOT / 'artifacts/smithay-wayland-research', pins[0],
                           'wayland-protocols-0.32.13.crate', fetch)
    return {'status': 'verified', 'protocol_archive': str(archive),
            'sources': [source['commit'] for source, _ in sources]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', help='allow fetching exact pinned inputs')
    args = parser.parse_args()
    print(json.dumps(prepare(fetch=args.fetch), indent=2))


if __name__ == '__main__':
    main()
