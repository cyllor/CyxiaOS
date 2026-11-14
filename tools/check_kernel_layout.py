#!/usr/bin/env python3
"""Check kernel ownership directories and literal source/linker references."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LAYERS = {'arch', 'composition', 'platform', 'runtime', 'desktop', 'diagnostics', 'selftest'}


def check(root=ROOT):
    root = Path(root).resolve(strict=True)
    source = root / 'kernel/src'
    errors = []
    for path in source.iterdir():
        if path.is_file() and path.name != 'main.rs':
            errors.append('unowned root source: ' + str(path.relative_to(root)))
        elif path.is_dir() and path.name not in LAYERS:
            errors.append('unknown kernel layer: ' + path.name)
    files = sorted(source.rglob('*.rs'))
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            errors.append('linked/escaping source: ' + str(path))
            continue
        for attribute, include in re.findall(
                r'#\[path\s*=\s*"([^"]+)"\]|include(?:_str|_bytes)?!\(\s*"([^"]+)"', path.read_text()):
            target = (path.parent / (attribute or include)).resolve()
            if not target.is_file() or not target.is_relative_to(root):
                errors.append(str(path.relative_to(root)) + ': missing/escaping ' + (attribute or include))
        text = path.read_text()
        for declaration in re.finditer(r'^(?:pub(?:\([^\n]+\))? )?mod (\w+);', text, re.M):
            child = path.parent / path.stem / (declaration[1] + '.rs')
            if not child.is_file():
                continue
            attributes = []
            for line in reversed(text[:declaration.start()].rstrip().splitlines()):
                if not line.startswith('#['):
                    break
                attributes.append(line)
            if not any('#[path' in line for line in attributes):
                errors.append(str(path.relative_to(root)) + ': implicit child path ' + declaration[1])
    for path in sorted((root / 'kernel/build').glob('*.rs')):
        for literal in re.findall(r'"(kernel/(?:src|linker)/[^"]+)"', path.read_text()):
            if not (root / literal).exists():
                errors.append(str(path.relative_to(root)) + ': missing build input ' + literal)
    migration = json.loads((root / 'kernel/layout-migration.json').read_text())
    for old, new in migration['moves'].items():
        if (root / old).exists() or not (root / new).is_file():
            errors.append('incomplete move: ' + old + ' -> ' + new)
    for arch in ('aarch64', 'x86_64'):
        if not (root / 'kernel/linker' / (arch + '.ld')).is_file():
            errors.append('missing linker script: ' + arch)
    if errors:
        raise ValueError('\n'.join(errors))
    return dict(status='PASS', rust_files=len(files), moves=len(migration['moves']), layers=sorted(LAYERS))


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
