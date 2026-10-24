#!/usr/bin/env python3
"""Build native per-node images; identities remain external and keys stay private.

Example: python3 tools/build_unified.py --identity-a /private/pair/a
 --identity-b /private/pair/b --output artifacts/unified-build --fault normal
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from doctor import ROOT,env
from verify_smp import manifest,require


CODE_ROOTS={'kernel','crates','user','.cargo'}
ROOT_BUILD_FILES={'Cargo.toml','Cargo.lock','rust-toolchain.toml','rust-toolchain'}
EXCLUDED_COMPONENTS={'tests','docs','target','__pycache__','.git'}


def code_source_map():
    # Bind every potentially included source/asset, not an extension allowlist:
    # ring includes .inl, and models/packages can have arbitrary suffixes.
    return {name:digest for name,digest in manifest().items()
            if (name in ROOT_BUILD_FILES or Path(name).parts[0] in CODE_ROOTS)
            and not any(part in EXCLUDED_COMPONENTS for part in Path(name).parts)}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity_metadata(directory):
    directory=Path(directory)
    public=(directory/'own.pub').read_bytes();peer=(directory/'peer.pub').read_bytes()
    local=(directory/'local.pin').read_bytes();pin=(directory/'peer.pin').read_bytes()
    require(len(public)==len(peer)==len(local)==len(pin)==32,'identity public keys and pins must be 32 bytes')
    require(hashlib.sha256(public).digest()==local and hashlib.sha256(peer).digest()==pin and local!=pin,'identity public key/NodeID pin mismatch')
    require((directory/'key.der').is_file() and (directory/'key.der').stat().st_size>0,'own identity key is missing')
    return dict(node_id=local.hex(),peer_node_id=pin.hex(),public_hex=public.hex(),public_sha256=hashlib.sha256(public).hexdigest(),certificate_sha256=sha(directory/'cert.der'))


def parse_cargo_build_messages(text):
    executable,out_dir=None,None
    for line in text.splitlines():
        try:message=json.loads(line)
        except json.JSONDecodeError:continue
        if message.get('reason')=='build-script-executed' and 'cyxia-kernel' in message.get('package_id',''):
            out_dir=Path(message['out_dir'])
        if message.get('reason')=='compiler-artifact' and message.get('target',{}).get('name')=='cyxia-kernel' and message.get('executable'):
            executable=Path(message['executable'])
    require(executable is not None and out_dir is not None,'Cargo did not report the kernel executable and actual build output directory')
    return executable,out_dir


def run_logged(argv,environment,log):
    result=subprocess.run(argv,cwd=ROOT,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
    require(len(result.stdout)<=4*1024*1024,'build log exceeded budget')
    log.write_bytes(result.stdout);log.chmod(0o600)
    require(result.returncode==0,f'build failed; inspect {log}')
    return result.stdout.decode('utf-8','replace')


def tool_version(argv,environment):
    result=subprocess.run(argv,cwd=ROOT,env=environment,capture_output=True,text=True,timeout=15)
    require(result.returncode==0,'cannot obtain build tool version: '+argv[0])
    return result.stdout.strip()


def build(identity_a,identity_b,output,*,fault='normal',leave=False,unix_seconds=1792800000):
    require(fault in ('normal','hang-once','no-stop-ack'),'unknown runtime fault')
    require(0<unix_seconds<(1<<63),'invalid provisioned UTC epoch')
    identities=[Path(identity_a).resolve(strict=True),Path(identity_b).resolve(strict=True)]
    require(all(not p.is_relative_to(ROOT) for p in identities),'private identities must be outside the source checkout')
    metadata=[identity_metadata(p) for p in identities]
    require(metadata[0]['node_id']!=metadata[1]['node_id'],'nodes must have distinct own private identities')
    output=Path(output).resolve()
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),'refuse to overwrite an existing build/evidence directory')
    output.mkdir(parents=True,mode=0o700,exist_ok=True);output.chmod(0o700)
    before=code_source_map()
    environment=env();environment['CARGO_TARGET_DIR']=str(ROOT/'target')
    environment['CARGO_NET_OFFLINE']='true'
    environment.pop('RUSTFLAGS',None);environment.pop('CARGO_ENCODED_RUSTFLAGS',None)
    versions={name:tool_version(argv,environment) for name,argv in {
        'cargo':['cargo','--version'],'rustc':['rustc','--version','--verbose'],
        'clang':['clang','--version'],'openssl':['openssl','version'],
        'installed_targets':['rustup','target','list','--installed']}.items()}
    require('aarch64-unknown-none\n' in versions['installed_targets']+'\n' and 'aarch64-unknown-none-softfloat' in versions['installed_targets'],'install both standard EL0 and softfloat EL1 Rust targets before building')
    keys=[(p/'key.der').read_bytes() for p in identities]
    artifacts={};commands=[];task_hash=None
    for index,name in enumerate(('a','b')):
        per_node=dict(environment,CYXIA_CLUSTER_IDENTITY=str(identities[index]),CYXIA_CLUSTER_LEAVE='1' if leave else '0',CYXIA_CLUSTER_UNIX_SECONDS=str(unix_seconds),CYXIA_RUNTIME_FAULT='none' if fault=='normal' else fault)
        service_command=[str(ROOT/'user/prototype-cluster/tools/build.sh')]
        commands.append(dict(node=name,stage='service',argv=service_command))
        print(f'Building node {name} EL0 service',flush=True)
        run_logged(service_command,per_node,output/f'service-{name}.log')
        service=output/f'service-{name}.elf'
        shutil.copyfile(ROOT/'target/aarch64-unknown-none/release/cyxia-prototype-cluster',service);service.chmod(0o600)
        per_node['CYXIA_CLUSTER_SERVICE_ELF']=str(service)
        kernel_command=['cargo','build','--locked','--offline','--release','-p','cyxia-kernel','--target','aarch64-unknown-none-softfloat','--no-default-features','--features','unified-runtime','--message-format=json-render-diagnostics']
        commands.append(dict(node=name,stage='kernel',argv=kernel_command))
        print(f'Building node {name} EL1 kernel',flush=True)
        text=run_logged(kernel_command,per_node,output/f'kernel-{name}.log')
        kernel,actual_out=parse_cargo_build_messages(text)
        image=output/f'node-{name}.elf';shutil.copyfile(kernel,image);image.chmod(0o600)
        package=actual_out/'prototype-task.elf'
        found_hash=sha(package)
        require(task_hash is None or found_hash==task_hash,'nodes contain different pure-task packages')
        if task_hash is None:shutil.copyfile(package,output/'task.elf');(output/'task.elf').chmod(0o600)
        task_hash=found_hash
        public=output/f'node-{name}.pub';public.write_bytes((identities[index]/'own.pub').read_bytes());public.chmod(0o600)
        for binary in (service,image):
            data=binary.read_bytes()
            require(keys[index] in data and keys[1-index] not in data,'image own-private-key-only audit failed')
    require([identity_metadata(p) for p in identities]==metadata and all((p/'key.der').read_bytes()==keys[i] for i,p in enumerate(identities)),'external identity changed during the build')
    require(code_source_map()==before,'code changed while building; preserve this failed build and rebuild from a source freeze')
    for path in sorted(output.iterdir()):
        if path.is_file():artifacts[path.name]=dict(sha256=sha(path),bytes=path.stat().st_size)
    report=dict(schema_version=1,status='BUILT_NOT_RUN',profiles=dict(fault=fault,leave=bool(leave),unix_seconds=unix_seconds),code_source_map=before,code_source_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),builder_sha256=sha(Path(__file__)),tools=versions,nodes=dict(zip(('a','b'),metadata)),artifacts=artifacts,commands=commands,own_private_key_only_verified=True,scope='Reproducible source/image binding and separate private identities; native execution and acceptance require the independent runner.')
    (output/'build-manifest.json').write_text(json.dumps(report,indent=2)+'\n');(output/'build-manifest.json').chmod(0o600)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity-a',type=Path,required=True)
    parser.add_argument('--identity-b',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--fault',choices=('normal','hang-once','no-stop-ack'),default='normal')
    parser.add_argument('--leave',action='store_true')
    parser.add_argument('--unix-seconds',type=int,default=int(os.environ.get('SOURCE_DATE_EPOCH','1792800000')))
    args=parser.parse_args()
    build(args.identity_a,args.identity_b,args.output,fault=args.fault,leave=args.leave,unix_seconds=args.unix_seconds)
    print(args.output/'build-manifest.json')


if __name__=='__main__':main()
