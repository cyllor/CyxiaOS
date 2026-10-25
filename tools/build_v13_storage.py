#!/usr/bin/env python3
"""Build the pinned native storage-only profile with a source/ELF manifest."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from build_unified import code_source_map
from check_elf import inspect_elf, boot_profile, symbol
from doctor import ROOT, env, inspect
from verify_smp import require, sha


def build(output: Path):
    output = output.resolve()
    require(not output.exists(), 'refuse to overwrite a storage build')
    require(inspect()['ready'], 'pinned native environment unavailable')
    output.mkdir(parents=True)
    source = code_source_map()
    command = ['cargo', 'build', '--locked', '--offline', '--release', '-p', 'cyxia-kernel',
               '--target', 'aarch64-unknown-none-softfloat', '--no-default-features',
               '--features', 'storage-v13-selftest', '--message-format=json-render-diagnostics']
    result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True, text=True, timeout=600)
    (output/'build.log').write_text(result.stdout+result.stderr)
    require(result.returncode == 0, 'storage build failed; inspect build.log')
    executables = [message['executable'] for line in result.stdout.splitlines()
                   if (message := json.loads(line)).get('reason') == 'compiler-artifact'
                   and message.get('target', {}).get('name') == 'cyxia-kernel' and message.get('executable')]
    require(len(executables) == 1 and code_source_map() == source, 'ambiguous image or source changed during build')
    elf = output/'storage.elf'; shutil.copyfile(executables[0], elf)
    data = elf.read_bytes(); inspect_elf(data)
    require(boot_profile(data)['ram_mib'] == 1024 and symbol(data, 'STORAGE_V13_EVIDENCE')['size'] == 4096,
            'wrong native storage profile')
    report = dict(version=1, profile='storage-v13-selftest', elf_sha256=sha(elf),
                  code_source_map=source, command=command, build_log_sha256=sha(output/'build.log'),
                  builder_sha256=sha(Path(__file__)), environment=inspect())
    (output/'build-manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return elf


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(build(parser.parse_args().output))
