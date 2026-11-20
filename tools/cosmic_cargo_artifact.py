"""Find an rlib by traversing the actual linked binary's Cargo fingerprints."""
from pathlib import Path
import json

import build_cosmic as base


def selected_rlib(build, report, crate):
    dependencies = Path(build) / 'target' / report['recipe']['target'] / 'release/deps'
    fingerprints = dependencies.parent / '.fingerprint'
    roots = [p for p in dependencies.iterdir() if p.is_file() and not p.suffix
             and base.digest(p) == report['linked_binary']['sha256']]
    if len(roots) != 1:
        raise ValueError('Ambiguous actual linked Cargo binary')
    tag = roots[0].name.rsplit('-', 1)[1]
    starts = list((fingerprints / (report['recipe']['package'] + '-' + tag)).glob('bin-*.json'))
    if len(starts) != 1:
        raise ValueError('Missing actual binary fingerprint')
    index = {}
    for path in fingerprints.glob('*/lib-*'):
        if path.suffix or not path.with_name(path.name + '.json').is_file():
            continue
        value = int.from_bytes(bytes.fromhex(path.read_text().strip()), 'little')
        index.setdefault((path.name.removeprefix('lib-'), value), []).append(path)
    pending, seen, found = starts[:], set(), set()
    while pending:
        record = pending.pop()
        if record in seen:
            continue
        seen.add(record)
        for dependency in json.loads(record.read_text())['deps']:
            name, fingerprint = dependency[1], dependency[3]
            candidates = index.get((name, fingerprint), [])
            if name == crate:
                if len(candidates) != 1:
                    raise ValueError('Ambiguous actual crate fingerprint: ' + name)
                selected = candidates[0]
                suffix = selected.parent.name.rsplit('-', 1)[1]
                found.add(dependencies / ('lib' + name + '-' + suffix + '.rlib'))
            pending.extend(p.with_name(p.name + '.json') for p in candidates)
    if len(found) != 1 or not next(iter(found)).is_file():
        raise ValueError('Missing unique actual rlib: ' + crate)
    return next(iter(found))
