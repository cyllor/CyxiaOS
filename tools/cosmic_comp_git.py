"""Read-only canonical Git identity for a compositor dependency checkout.

A gitlink is a required recursively verified checkout, never an ignored path.
Only each verified repository's own real .git directory and untracked regular
.cargo-ok marker are excluded from the flattened source inventory. File/total
bounds apply to the entire parent checkout, including every nested submodule.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

try:
    from . import build_cosmic as build
    from . import cosmic_notifications_dependencies as objects
except ImportError:
    import build_cosmic as build
    import cosmic_notifications_dependencies as objects

MAX_FILE_BYTES = 16 * 1024**2
MAX_TREE_BYTES = 64 * 1024**2
MAX_REPOSITORIES = 64
MAX_DEPTH = 8
MAX_FILES = 100_000


def require(condition, message):
    if not condition:
        raise build.CosmicBuildError(message)


def parse_tree(text):
    """Keep blobs and gitlinks distinct; reject unknown modes and duplicates."""
    files, gitlinks = {}, {}
    for row in text.split('\0'):
        if not row:
            continue
        try:
            header, name = row.split('\t', 1)
            mode, kind, oid = header.split()
        except ValueError as error:
            raise build.CosmicBuildError('Malformed canonical Git tree entry') from error
        relative = build.dependencies.relative_path(name)
        require(relative.parts and '.git' not in relative.parts,
                'Git tree overlaps repository control metadata')
        require(name not in files and name not in gitlinks and re.fullmatch('[0-9a-f]{40}', oid),
                'Duplicate or invalid canonical Git tree entry')
        if mode == '160000' and kind == 'commit':
            gitlinks[name] = oid
        else:
            require(kind == 'blob' and mode in ('100644', '100755', '120000'),
                    'Unsupported canonical Git tree entry')
            files[name] = {'mode': mode, 'blob': oid}
    require(files or gitlinks, 'Empty pinned Git checkout tree')
    return files, gitlinks


def repository(root, expected_commit):
    """Require the actual independent Cargo checkout, not a parent Git fallback."""
    require(re.fullmatch('[0-9a-f]{40}', expected_commit or ''), 'Invalid pinned Git commit')
    root = build.no_symlink_path(root)
    require(root.is_dir() and (root / '.git').is_dir() and not (root / '.git').is_symlink(),
            'Missing initialized independent Git checkout: ' + str(root))
    require(Path(objects.pinned_git(root, 'rev-parse', '--show-toplevel')) == root,
            'Git checkout root differs from gitlink path: ' + str(root))
    require(Path(objects.pinned_git(root, 'rev-parse', '--absolute-git-dir')) == root / '.git',
            'Git metadata differs from initialized checkout')
    common = Path(objects.pinned_git(root, 'rev-parse', '--git-common-dir'))
    require((root / common).resolve() == root / '.git',
            'Shared or external Git metadata is unsupported')
    require(objects.pinned_git(root, 'rev-parse', 'HEAD') == expected_commit,
            'Git checkout HEAD differs from pinned gitlink commit: ' + str(root))
    tree = objects.pinned_git(root, 'rev-parse', expected_commit + '^{tree}')
    require(re.fullmatch('[0-9a-f]{40}', tree), 'Invalid canonical Git tree identity')
    # The immutable expected object, not a mutable HEAD expression, drives this
    # traversal. Every object read also disables Git replacement references.
    files, gitlinks = parse_tree(objects.pinned_git(root, 'ls-tree', '-rz', expected_commit))
    return root, tree, files, gitlinks


def git_identity(root, expected_commit):
    """Return canonical flat files plus every verified submodule pointer/tree."""
    root = build.no_symlink_path(root)
    pending = [(root, expected_commit, 0)]
    nodes, declared, submodules = {}, {}, {}
    top_tree = None
    while pending:
        selected, commit, depth = pending.pop()
        require(depth <= MAX_DEPTH and len(nodes) < MAX_REPOSITORIES,
                'Pinned submodule recursion exceeds bounds')
        require(selected.is_relative_to(root) and selected not in nodes,
                'Cyclic, aliased or escaping pinned submodule')
        selected, tree, files, links = repository(selected, commit)
        nodes[selected] = {'commit': commit, 'git_tree': tree}
        if selected == root:
            top_tree = tree
        else:
            submodules[selected.relative_to(root).as_posix()] = {'commit': commit, 'git_tree': tree}
        for name, item in files.items():
            full = (selected / name).relative_to(root).as_posix()
            require(full not in declared, 'Overlapping pinned source paths')
            declared[full] = item
            require(len(declared) <= MAX_FILES, 'Pinned source file count exceeds bound')
        for name, child_commit in sorted(links.items(), reverse=True):
            child = selected / name
            require(not child.is_symlink() and child.is_dir(),
                    'Missing or aliased gitlink checkout: ' + str(child))
            pending.append((child, child_commit, depth + 1))

    def inventory_error(error):
        raise build.CosmicBuildError('Cannot enumerate complete pinned Git checkout') from error

    observed = set()
    for directory, directories, files in os.walk(root, followlinks=False, onerror=inventory_error):
        parent = Path(directory)
        for name in list(directories):
            selected = parent / name
            if name == '.git':
                require(parent in nodes and not selected.is_symlink(),
                        'Unverified or aliased repository control metadata')
                directories.remove(name)
            elif parent in nodes and name == '.cargo-ok':
                raise build.CosmicBuildError('Cargo cache marker is not a regular file')
            elif selected.is_symlink():
                observed.add(selected.relative_to(root).as_posix())
                directories.remove(name)
        for name in files:
            selected = parent / name
            relative = selected.relative_to(root).as_posix()
            if parent in nodes and name == '.cargo-ok' and relative not in declared:
                require(stat.S_ISREG(selected.lstat().st_mode), 'Aliased Cargo cache marker')
                continue
            observed.add(relative)
    require(observed == set(declared), 'Pinned recursive Git checkout file inventory changed')

    result, link_files, total = {}, {}, 0
    for name, item in sorted(declared.items()):
        selected = root / name
        info = selected.lstat()
        if item['mode'] == '120000':
            require(stat.S_ISLNK(info.st_mode), 'Tracked Git symlink was replaced: ' + name)
            target = os.readlink(selected)
            raw = os.fsencode(target)
            require(not Path(target).is_absolute(), 'Absolute tracked Git symlink: ' + name)
            lexical = Path(os.path.normpath(selected.parent / target))
            require(lexical.is_relative_to(root), 'Git symlink escapes parent checkout: ' + name)
            try:
                resolved = selected.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise build.CosmicBuildError('Broken or cyclic pinned Git symlink: ' + name) from error
            require(resolved.is_relative_to(root), 'Git symlink resolves outside parent checkout: ' + name)
            target_name = resolved.relative_to(root).as_posix()
            if resolved.is_file():
                require(target_name in declared and declared[target_name]['mode'] in ('100644', '100755'),
                        'Git symlink target is not a pinned regular file: ' + name)
                # Fill this only from a successfully bounded, canonical blob
                # read below, rather than performing an unbounded target read.
                link_files[name] = target_name
                target_identity = None
            else:
                entries = {key: value for key, value in declared.items() if key.startswith(target_name + '/')}
                require(resolved.is_dir() and entries, 'Git symlink target is not a pinned directory: ' + name)
                target_identity = {'git_entries_sha256': objects.canonical_hash(entries)}
            record = {'mode': item['mode'], 'git_blob': item['blob'], 'symlink': target,
                      'resolved_path': target_name, 'resolved_identity': target_identity}
        else:
            require(stat.S_ISREG(info.st_mode), 'Tracked Git file is not regular: ' + name)
            require(bool(info.st_mode & 0o111) == (item['mode'] == '100755'),
                    'Pinned Git executable mode changed: ' + name)
            require(info.st_size <= MAX_FILE_BYTES, 'Pinned Git blob exceeds size bound')
            descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                require(stat.S_ISREG(opened.st_mode)
                        and bool(opened.st_mode & 0o111) == (item['mode'] == '100755')
                        and opened.st_size <= MAX_FILE_BYTES,
                        'Pinned Git file changed during open: ' + name)
                raw = stream.read(MAX_FILE_BYTES + 1)
            record = {'mode': item['mode'], 'git_blob': item['blob'],
                      'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        require(len(raw) <= MAX_FILE_BYTES, 'Pinned Git blob exceeds size bound')
        total += len(raw)
        require(total <= MAX_TREE_BYTES, 'Entire pinned checkout exceeds size bound')
        require(objects.git_blob(raw) == item['blob'], 'Pinned Git blob bytes changed: ' + name)
        result[name] = record
    for name, target_name in link_files.items():
        target = result[target_name]
        result[name]['resolved_identity'] = {'bytes': target['bytes'], 'sha256': target['sha256']}
    # Recheck the repository boundaries as well as the immutable content. This
    # catches parent/submodule HEAD changes during the flat filesystem pass.
    for selected, identity in nodes.items():
        require(not (selected / '.git').is_symlink() and (selected / '.git').is_dir()
                and objects.pinned_git(selected, 'rev-parse', 'HEAD') == identity['commit']
                and Path(objects.pinned_git(selected, 'rev-parse', '--show-toplevel')) == selected,
                'Pinned repository identity changed during validation')
    submodules = dict(sorted(submodules.items()))
    return {'commit': expected_commit, 'git_tree': top_tree,
            'sha256': objects.canonical_hash({'files': result, 'submodules': submodules}),
            'files': result, 'submodules': submodules, 'total_bytes': total}
