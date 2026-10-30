"""Apply exactly the reviewed A01 candidate; refuse unrelated source drift."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import zlib

BASE = '3af89206879ea990c5bce0b5e1ce17c7f381b473'
PATCH_SHA = 'bd3ffdd02e03b798d27d5221556326caf22d7f15560154aa1323475e23af0a53'
STAGING = '.github/v13-boot-candidate/'
WORKFLOW = '.github/workflows/v13-boot-candidate.yml'
ALLOWED = '''crates/prototype/src/lib.rs
crates/prototype/src/boot_model.rs
crates/prototype/tests/boot_model.rs
kernel/build.rs
kernel/src/domain_control.rs
kernel/src/main.rs
kernel/src/prototype_runtime.rs
kernel/src/prototype_runtime/boot_model.rs
kernel/src/prototype_storage.rs
kernel/src/boot_recovery.rs
kernel/src/smp.rs
kernel/src/unified.rs
user/prototype-runtime/main.rs
tools/run_v13_boot_recovery.py
tools/verify_v13_boot_recovery.py
tools/test_verify_v13_boot_recovery.py'''.splitlines()


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


if git('status', '--porcelain'):
    raise SystemExit('Refuse a dirty candidate checkout')
subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD'], check=True)
changed = git('diff', '--name-only', BASE, 'HEAD').splitlines()
if any(not (p.startswith(STAGING) or p == WORKFLOW) for p in changed):
    raise SystemExit('Source moved beyond the reviewed candidate base')
encoded = b''.join((Path(STAGING)/f'{i:02}.part').read_bytes() for i in range(13))
patch = zlib.decompress(encoded)
if len(patch) != 48135 or hashlib.sha256(patch).hexdigest() != PATCH_SHA:
    raise SystemExit('Candidate transport identity mismatch')
with tempfile.NamedTemporaryFile(suffix='.patch') as f:
    f.write(patch)
    f.flush()
    subprocess.run(['git', 'apply', '--check', '--index', f.name], check=True)
    subprocess.run(['git', 'apply', '--index', f.name], check=True)
subprocess.run(['cargo', 'fmt', '--all'], check=True)
changed = set(git('diff', 'HEAD', '--name-only').splitlines())
if changed != set(ALLOWED):
    raise SystemExit('Unexpected candidate/formatter changed paths: ' + repr(sorted(changed)))
subprocess.run(['git', 'add', '--', *ALLOWED], check=True)
subprocess.run(['git', 'diff', '--cached', '--check'], check=True)
tree = git('write-tree')
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write('tree=' + tree + '\n')
print('Exact candidate tree:', tree)
