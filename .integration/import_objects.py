"""One-time, data-only import of a locally validated source patch.
Creates Git blobs/tree only. Does not execute candidate code or change refs.
"""
from __future__ import annotations
import base64
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

REPO = 'cyllor/CyxiaOS'
BASE = '8c295c814068299010ec39bbe18e2fe8a3c21ea3'
BASE_TREE = '838b6931f370f5feb779de227e71176c4337efb7'
TARGET = 'af767e071a51d668d681a61bb1dcc899115ae2be'
XZ_HASH = 'e363f043d101f4a8a63eb02560d5f64fd7fbd1ba7ff73a9baa6b3618afab633e'
PATCH_HASH = '579d16817d892427f306377aa7db00ff4f53292d518fe51ee2782aaec35bdf0d'

def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)

def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(['git', *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=60).stdout

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('API redirects forbidden')

def post(endpoint: str, payload: dict) -> dict:
    require(endpoint in ('blobs', 'trees'), 'Only immutable Git objects may be created')
    request = urllib.request.Request(
        'https://api.github.com/repos/' + REPO + '/git/' + endpoint,
        data=json.dumps(payload).encode(), method='POST',
        headers={'Accept': 'application/vnd.github+json',
                 'Authorization': 'Bearer ' + os.environ['IMPORT_TOKEN'],
                 'X-GitHub-Api-Version': '2022-11-28',
                 'Content-Type': 'application/json', 'User-Agent': 'CyxiaOS-source-object-import'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            require(response.status == 201, 'Git object was not created')
            return json.loads(response.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as error:
        # Never dump request headers, the token or an arbitrary error body.
        raise RuntimeError('Git object API returned HTTP ' + str(error.code)) from None

def main() -> None:
    require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Unexpected repository')
    transport = Path(os.environ['RUNNER_TEMP']) / 'cyxia-import'
    pieces = [transport / ('part-%02d.xz' % i) for i in range(8)]
    require(all(p.is_file() and not p.is_symlink() for p in pieces), 'Missing transport piece')
    data = b''.join(p.read_bytes() for p in pieces)
    require(len(data) == 78100 and hashlib.sha256(data).hexdigest() == XZ_HASH,
            'Compressed patch identity mismatch')
    decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
    patch = decoder.decompress(data, max_length=342418)
    require(decoder.eof and not decoder.unused_data and len(patch) == 342417
            and hashlib.sha256(patch).hexdigest() == PATCH_HASH, 'Patch identity mismatch')
    # This runner is ephemeral. Copy transport before checkout; no user working
    # directory or mutable persistent state is touched by this import.
    git('checkout', '--detach', BASE)
    require(git('rev-parse', 'HEAD^{tree}').decode().strip() == BASE_TREE, 'Base tree changed')
    require(not git('status', '--porcelain'), 'Base checkout is not clean')
    git('apply', '--check', '--index', '-', data=patch)
    git('apply', '--index', '-', data=patch)
    actual = git('write-tree').decode().strip()
    require(actual == TARGET, 'Candidate differs from locally tested tree')
    changed = git('diff', '--cached', '--name-only', '-z').split(b'\0')[:-1]
    require(len(changed) == 71 and len(set(changed)) == 71, 'Unexpected changed-file set')
    index = {}
    for record in git('ls-files', '--stage', '-z').split(b'\0'):
        if not record:
            continue
        meta, path = record.split(b'\t', 1)
        mode, sha, stage = meta.decode().split()
        index[path] = (mode, sha, stage)
    entries = []
    identities = []
    for raw in changed:
        path = raw.decode('utf-8')
        require(not path.startswith(('/', '.integration/')) and '..' not in Path(path).parts,
                'Unexpected source path')
        mode, sha, stage = index[raw]
        require(mode in ('100644', '100755') and stage == '0', 'Unsupported file mode')
        content = git('cat-file', 'blob', sha)
        uploaded = post('blobs', {'encoding': 'base64',
                                 'content': base64.b64encode(content).decode('ascii')})
        require(uploaded.get('sha') == sha, 'Uploaded blob differs from source')
        entries.append({'path': path, 'mode': mode, 'type': 'blob', 'sha': sha})
        identities.append({'path': path, 'blob': sha, 'sha256': hashlib.sha256(content).hexdigest()})
        print('Verified source blob: ' + path, flush=True)
    tree = post('trees', {'base_tree': BASE_TREE, 'tree': entries})
    require(tree.get('sha') == TARGET, 'Remote tree differs from tested source')
    receipt = {'status': 'PASS', 'operation': 'immutable-object-import-only', 'base': BASE,
               'base_tree': BASE_TREE, 'tree': TARGET, 'changed_files': len(entries),
               'patch_sha256': PATCH_HASH, 'files': identities,
               'refs_modified': False, 'candidate_code_executed': False}
    (transport / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('IMPORT_PASS tree=' + TARGET + ' files=71 refs_modified=false', flush=True)

if __name__ == '__main__':
    main()
