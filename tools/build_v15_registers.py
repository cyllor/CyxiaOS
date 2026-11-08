#!/usr/bin/env python3
"""Build only the independent architectural register profile, with source binding."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from doctor import ROOT, RUST_BIN, TARGET, env
from build_unified import (build_cache_context, cache_artifact, code_source_map,
                           parse_cargo_build_messages, sha, tool_version)
from check_elf import inspect_elf


def build(output):
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    before=code_source_map(ROOT);environment=env()
    cache=build_cache_context(environment.get('CARGO_TARGET_DIR',ROOT/'target'),ROOT,before)
    environment['CARGO_TARGET_DIR']=cache['effective']
    command=[str(RUST_BIN/'cargo'),'build','--locked','--offline','--release','-p',
             'cyxia-kernel','--target',TARGET,'--no-default-features','--features',
             'register-v15-selftest','--message-format=json-render-diagnostics']
    result=subprocess.run(command,cwd=ROOT,env=environment,capture_output=True,timeout=600)
    (output/'build.log').write_bytes(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('build failed; retained build.log')
    image,_=parse_cargo_build_messages(result.stdout.decode())
    image=cache_artifact(image,cache['effective'])
    inspect_elf(image.read_bytes());shutil.copyfile(image,output/'registers.elf')
    if before!=code_source_map(ROOT):raise ValueError('source changed during build')
    manifest=dict(schema=1,profile='register-v15-selftest',code_source_map=before,
                  image_sha256=sha(output/'registers.elf'),command=command,
                  builder_sha256=sha(Path(__file__)),build_cache=cache,
                  rustc=tool_version([str(RUST_BIN/'rustc'),'--version','--verbose'],environment),
                  cargo=tool_version([str(RUST_BIN/'cargo'),'--version'],environment),
                  build_log_sha256=sha(output/'build.log'))
    (output/'build-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    print(json.dumps(build(p.parse_args().output),indent=2))
