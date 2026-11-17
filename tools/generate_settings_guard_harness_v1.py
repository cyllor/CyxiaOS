"""Generate the six-case settings guard regression from two exact source exports.

Required arguments select the complete Linux-v2 baseline and Linux-v3 candidate
src/main.rs files, plus a fresh output directory outside their source trees.
The template is repository-relative. This tool never invokes a compiler or runs
the resulting harness; the source report records generation only.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'fixtures/settings_guard_main_fut_v1.rs.in'
MAX_SOURCE_BYTES = 128 * 1024
BASELINE_SHA256 = '5a82e73fc6462b5fa6ee23bf1f3085583e433aa90f70890f9629d86de0d42a42'
CANDIDATE_SHA256 = 'd8009a37196df8d3591c1241d792f3c8d9da026b632f65018bfae38a5e84dbbe'
TEMPLATE_SHA256 = 'e557661d1fe2cf3f5c1a91a3e5494384364b2dd962d52cb7a7fb29adad5c7dfb'
HARNESS_SHA256 = 'cbdbca97a9a581a678f0e57ff0e07dc777676dbdbd3398d3dbf89d04bb9779a0'
BODY_SHA256 = {
    'original': '65a7f4889fdee87b41222b4394b4dac76fbd1d5ceb639780e21a7f5394c74bda',
    'candidate': '3317c70dbf8e96cfa6486ec5473b22201deeac80ee6c2e188144e9dea8a65163',
}
TEST_CASES = [
    'original_source_holds_interface_read_guard_while_theme_send_is_blocked',
    'candidate_source_releases_interface_before_the_same_blocked_send',
    'newly_registered_config_and_state_watchers_are_visible_through_the_same_arcs',
    'failed_interface_lookup_still_skips_that_batch_and_processes_the_next_one',
    'mixed_config_state_theme_and_xkb_effect_order_remains_exact',
    'capacity_ten_backpressure_retains_all_thirteen_updates_and_signal_order',
]
BEGIN = '            let main_fut = std::pin::pin!(async move {\n'
END = '            });\n\n            futures::future::join(theme_watcher_fut, async move {'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plain(value):
    path = Path(value).absolute()
    require('..' not in path.parts
            and not any(part.is_symlink() for part in (path, *path.parents)),
            'Source and output paths must not contain parent traversal or symbolic links')
    return path


def read(path):
    path = plain(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_SOURCE_BYTES,
                'Harness source must be a bounded regular file')
        raw = stream.read(MAX_SOURCE_BYTES + 1)
        key = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_size,
                           row.st_mtime_ns, row.st_ctime_ns)
        require(len(raw) == before.st_size and key(before) == key(os.fstat(stream.fileno()))
                == key(path.stat(follow_symlinks=False)), 'Harness source changed during read')
    return raw


def identity(path, raw=None):
    path = plain(path)
    raw = read(path) if raw is None else raw
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def extract(source):
    require(source.count(BEGIN) == 1 and source.count(END) == 1, 'Ambiguous actual main_fut delimiters')
    start = source.index(BEGIN) + len(BEGIN)
    finish = source.index(END, start)
    body = source[start:finish]
    require(body.count('while let Some(changes) = rx.recv().await {') == 1,
            'The actual outer event receive loop is missing')
    require(body.count('for c in changes {') == 1, 'The actual ordered changes loop is missing')
    require(body.count('theme_tx.send(') == 4 and body.count('xkb_tx.send(') == 1,
            'The actual bounded sends changed')
    require(body.count('Config::changed(') == 2, 'The actual config/state Changed calls changed')
    capacity = re.findall(r'let \(theme_tx, mut theme_rx\) = tokio::sync::mpsc::channel\((\d+)\);', source)
    require(capacity == ['10'], 'The original capacity-ten theme channel changed')
    return body, int(capacity[0])


def generate(baseline_main, candidate_main, output):
    baseline, candidate_path, output = map(plain, (baseline_main, candidate_main, output))
    require(not output.exists(), 'Generated output must be fresh')
    # Both arguments select src/main.rs within retained source exports. Keep
    # output outside the corresponding source trees and the generator directory.
    protected = [baseline.parent.parent, candidate_path.parent.parent, HERE]
    require(all(output != path and not output.is_relative_to(path) and not path.is_relative_to(output)
                for path in protected), 'Generated output overlaps a source tree or tools directory')
    paths = {'baseline': baseline, 'candidate': candidate_path, 'template': plain(TEMPLATE),
             'generator': plain(__file__)}
    sources = {name: read(path) for name, path in paths.items()}
    before = {name: identity(paths[name], raw) for name, raw in sources.items()}
    for name, checksum in [('baseline', BASELINE_SHA256), ('candidate', CANDIDATE_SHA256),
                           ('template', TEMPLATE_SHA256)]:
        require(before[name]['sha256'] == checksum, 'Pinned harness input changed: ' + name)
    original, capacity = extract(sources['baseline'].decode('utf-8'))
    candidate, new_capacity = extract(sources['candidate'].decode('utf-8'))
    require(new_capacity == capacity == 10, 'Channel capacity differs between old/new sources')
    for name, body in [('original', original), ('candidate', candidate)]:
        require(hashlib.sha256(body.encode('utf-8')).hexdigest() == BODY_SHA256[name],
                'Complete extracted main_fut body changed: ' + name)
    template = sources['template'].decode('utf-8')
    for marker in ('@@ORIGINAL_MAIN_FUT_BODY@@', '@@CANDIDATE_MAIN_FUT_BODY@@', '@@SOURCE_THEME_CAPACITY@@'):
        require(template.count(marker) == 1, 'Ambiguous harness insertion point')
    generated = template.replace('@@ORIGINAL_MAIN_FUT_BODY@@', original).replace(
        '@@CANDIDATE_MAIN_FUT_BODY@@', candidate).replace('@@SOURCE_THEME_CAPACITY@@', str(capacity))
    require('@@' not in generated, 'An unresolved source insertion marker remains')
    # Both function bodies are inserted verbatim, with no normalization,
    # AST rewriting, hand-translated guard sequence, or omitted await branch.
    require(original in generated and candidate in generated, 'Production body bytes were not retained')
    require(hashlib.sha256(generated.encode('utf-8')).hexdigest() == HARNESS_SHA256,
            'Generated harness differs from the exact six-case source that was host-tested')
    cases = re.findall(r'#\[test\]\nfn ([a-z0-9_]+)\(', generated)
    require(cases == TEST_CASES, 'The complete six-case regression changed')
    output.mkdir()
    for name, text in [('harness.rs', generated), ('original-main-fut.rs.txt', original),
                       ('candidate-main-fut.rs.txt', candidate)]:
        with (output / name).open('xb') as stream:
            stream.write(text.encode('utf-8'))
    after = {name: identity(path) for name, path in paths.items()}
    require(after == before, 'A source input changed during generation')
    report = {
        'status': 'ACTUAL_SOURCE_HARNESS_GENERATED_NOT_COMPILED',
        'source_inputs_before': before, 'source_inputs_after': after, 'sources_preserved': True,
        'generated': {name: identity(output / name) for name in
                      ('harness.rs', 'original-main-fut.rs.txt', 'candidate-main-fut.rs.txt')},
        'baseline_main_fut_bytes': len(original.encode('utf-8')),
        'candidate_main_fut_bytes': len(candidate.encode('utf-8')),
        'inserted_source_verbatim': True, 'theme_capacity': capacity, 'test_cases': cases,
        'host_tested_harness_sha256': HARNESS_SHA256, 'matches_host_tested_harness_bytes': True,
        'external_processes': 0, 'compiler_executed': False, 'guest_execution': False,
        'scope': 'Actual Rust production control flow with real std read/write guards and deterministic bounded future adapters; not the real Tokio/zbus executor or a guest.',
        'cause_proven': False,
    }
    with (output / 'source-report.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-main', type=Path, required=True)
    parser.add_argument('--candidate-main', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    generate(args.baseline_main, args.candidate_main, args.output)
    print(json.dumps(identity(plain(args.output) / 'source-report.json')))


if __name__ == '__main__':
    main()
