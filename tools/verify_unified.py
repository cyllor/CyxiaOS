#!/usr/bin/env python3
"""Joint native evidence runner. Development observations cannot certify completion."""
from __future__ import annotations
import argparse,base64,json,re,secrets,shutil,socket,struct,subprocess,tempfile,time
from contextlib import ExitStack
from pathlib import Path
from doctor import ROOT
from check_elf import boot_profile,inspect_elf,symbol
from check_v13_disk import inspect as inspect_disk
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest,require,sha
from verify_unified_capture import validate_capture
from verify_unified_disk import verify_pair
from verify_domains import (CONTROL_MAGIC, CONTROL_WORDS, active_control_records,
                            diagnostics as decode_domain_diagnostics, parse_control,
                            progress_diagnostics as decode_progress_diagnostics,
                            retained_observation)
import hashlib
from build_unified import code_source_map

PINNED_QEMU_COMMIT='f8ed81651e61d9c2166df6121ce2af0f44f06b3e'
PINNED_QEMU_PATCH_SHA256='b92d2ce14bca13cae43338729de3226c1ad9f469dc9947e1bd5c465d753876fd'
PATCHED_QEMU_SOURCE_SHA256={
    'include/hw/core/cpu.h':'4696335a01617de2504f2ab09dd10dc8c86ec854fecf244aa24e31469d60ced1',
    'cpu-common.c':'5a309695dd5c559b93ce7cf13171b3bdfc4b526092b42e49bbbcabeee22fdf13',
    'accel/tcg/cpu-exec.c':'d49ac54fba75a2ee3fe58792e8bbcd0e4ca8ada5775d5facbccdfcb9bc990b2b',
    'target/arm/cpregs-pmu.c':'f09a95b22f4b67e0d22bffa2523b3055cabe8d2bf943cfb313e5d4fc16364556',
}

CAPTURE_SYMBOLS = (
    ('UNIFIED_EVIDENCE', 4096),
    ('DYNAMIC_V13_EVIDENCE', 4096),
    ('RUNTIME_V13_EVIDENCE', 8192),
    ('UNIFIED_SERVICE_STAGE', 8),
    ('DOMAIN_TASK_EVIDENCE', 256),
    ('TASK_OVERRUN_EVIDENCE', 256),
    ('NETWORK_PIECE_EVIDENCE', 512),
    ('NETWORK_SETTLEMENT_EVIDENCE', 512),
    ('FILE_SERVICE_EVIDENCE', 512),
    ('TASK_VECTOR_EVIDENCE', 512),
    ('RUNTIME_LOOP_EVIDENCE', 512),
    ('DOMAIN_PUBLICATION_COST', 1024),
    ('DOMAIN_CONTROL_EVIDENCE', CONTROL_WORDS * 8),
    ('REPLAY_V13_EVIDENCE', 512),
    ('DOMAIN_PREPARATION_CONTEXT', 128),
    ('DOMAIN_PREPARATION_DETAIL', 256),
    ('DOMAIN_PREPARATION_PREFIX_DETAIL', 128),
    ('DOMAIN_PREPARATION_ENTRY_DETAIL', 128),
    ('DOMAIN_PREPARATION_REJECTIONS', 5184),
    ('DOMAIN_PREPARATION_SKIP_EVIDENCE', 2048),
)

FINAL_DIAGNOSTIC_FIELDS = (
    'service_stage_word', 'task_evidence', 'tasks', 'overrun_evidence',
    'network_piece_evidence', 'network_settlement_evidence',
    'file_service_evidence', 'task_vector_evidence',
    'runtime_loop', 'runtime_loop_evidence',
    'publication_cost', 'publication_cost_evidence',
    'control', 'replay', 'replay_evidence',
    'preparation_context', 'preparation_detail',
    'preparation_prefix_detail', 'preparation_entry_detail',
    'preparation_rejections', 'rejected_preparations',
    'preparation_skip_evidence', 'preparation_skips',
    'diagnostic_errors', 'final_parse_error',
)

LIVE_CAPTURE_SYMBOLS = frozenset((
    'UNIFIED_EVIDENCE', 'DYNAMIC_V13_EVIDENCE', 'RUNTIME_V13_EVIDENCE',
))

D8_DIAGNOSTIC_FILE = 'd8-service-batch-diagnostic.json'
D8_CONTROL_RECORD_WORDS = 640
D8_CONTROL_HEADER_WORDS = 512

def d8_control_location(data):
    """Resolve the optional diagnostic page without changing acceptance capture."""
    location = symbol(data, 'DOMAIN_CONTROL_EVIDENCE')
    require(location['size'] == CONTROL_WORDS * 8,
            'DOMAIN_CONTROL_EVIDENCE size differs')
    return location

def _service_batch(input_words, selected):
    """Decode the canonical D8 ABI3 payload selected by the native runtime."""
    if input_words[8:10] != (8, 1) or not 0 <= selected < input_words[15] <= 32:
        raise ValueError('invalid D8 native input identity')
    at = 64 + selected * 10
    length = input_words[at]
    payload = (input_words[at + 1].to_bytes(8, 'little')
               + input_words[at + 2].to_bytes(8, 'little'))
    if length != 3 or any(payload[length:]) \
            or int.from_bytes(payload[:2], 'little') != selected \
            or payload[2] not in (1, 2, 4, 8):
        raise ValueError('invalid D8 ServiceBatch candidate payload')
    return payload[2]

def stable_d8_records(first, second):
    """Return only identical, independently stable D8 records from two live reads."""
    expected = CONTROL_WORDS * 8
    require(len(first) == len(second) == expected,
            'live D8 control snapshot size differs')
    a = struct.unpack(f'<{CONTROL_WORDS}Q', first)
    b = struct.unpack(f'<{CONTROL_WORDS}Q', second)
    require(a[0] == b[0] == CONTROL_MAGIC and a[1] == b[1] == 1
            and a[2] == b[2] and a[2] > 0,
            'live D8 control snapshot identity differs')
    # Reuse the ordinary decoder's bounded slot filtering, then impose the
    # stronger double-read/identity/completion requirements needed here.
    active_a = {row['slot']: row for row in active_control_records(first)}
    active_b = {row['slot']: row for row in active_control_records(second)}
    rows = []
    states = {1: 'pending', 2: 'applied', 3: 'failed', 4: 'unknown'}
    for slot in sorted(active_a.keys() & active_b.keys()):
        at = D8_CONTROL_HEADER_WORDS + slot * D8_CONTROL_RECORD_WORDS
        ra = a[at:at + D8_CONTROL_RECORD_WORDS]
        rb = b[at:at + D8_CONTROL_RECORD_WORDS]
        if ra != rb or ra[639] & 1 or ra[0] == 0 or ra[0] != ra[1] \
                or ra[2:4] != (8, 1) or ra[7] != a[2] or ra[30] != 1 \
                or ra[14] not in states:
            continue
        if ra[14] == 2 and not (ra[13] > 0 and ra[19] == 1 and ra[15] == 0
                                and ra[28] >= ra[9] >= ra[8]):
            continue
        selected = ra[17]
        native_input = ra[32:544]
        try:
            batch = _service_batch(native_input, selected)
        except (IndexError, OverflowError, ValueError):
            continue
        rows.append({
            'slot': slot,
            'sequence': ra[0],
            'boot_epoch': ra[7],
            'target': [ra[4], ra[5]],
            'approved_version': ra[13],
            'executor_state': states[ra[14]],
            'executor_error': ra[15],
            'selected_candidate': selected,
            'service_batch': batch,
            'completed_ns': ra[28],
        })
    return rows

def _stable_d8_counters(first, second):
    """Reuse the full control decoder when both live headers agree."""
    try:
        a = parse_control(first)
        b = parse_control(second)
    except ValueError:
        return None
    if a is None or b is None or a['boot_epoch'] != b['boot_epoch']:
        return None
    counters = {
        'boot_epoch': a['boot_epoch'],
        'jobs': a['family_jobs'][8],
        'applied': a['family_applied'][8],
        'family_jobs': a['family_jobs'],
        'family_applied': a['family_applied'],
    }
    return counters if counters == {
        'boot_epoch': b['boot_epoch'],
        'jobs': b['family_jobs'][8],
        'applied': b['family_applied'][8],
        'family_jobs': b['family_jobs'],
        'family_applied': b['family_applied'],
    } else None

class D8ControlDiagnostics:
    """Best-effort development diagnostic with synchronous QMP perturbation."""
    def __init__(self, output, *, interval_seconds):
        require(0.1 <= interval_seconds <= 60,
                'D8 diagnostic interval must be between 0.1 and 60 seconds')
        self.output = Path(output)
        self.interval_seconds = float(interval_seconds)
        self.samples = 0
        self.nodes = []
        self.initialization_errors = []
        self.enabled = True

    def disable(self, error):
        self.enabled = False
        self.initialization_errors.append(type(error).__name__ + ': ' + str(error))

    def next_sample_at(self, completed_monotonic):
        return completed_monotonic + self.interval_seconds

    def _node(self, index):
        while len(self.nodes) <= index:
            self.nodes.append({'node': len(self.nodes) + 1, 'records': {},
                               'counters': [], 'errors': []})
        return self.nodes[index]

    def sample(self, guests, locations, *, elapsed_seconds):
        require(len(guests) == len(locations), 'D8 diagnostic guest/location mismatch')
        self.samples += 1
        for index, (guest, location) in enumerate(zip(guests, locations)):
            node = self._node(index)
            paths = [guest['folder'] / f'.d8-control-{self.samples:04d}-{part}.bin'
                     for part in ('a', 'b')]
            try:
                require(location['size'] == CONTROL_WORDS * 8,
                        'DOMAIN_CONTROL_EVIDENCE size differs')
                pages = []
                for path in paths:
                    guest['qmp'].execute('pmemsave', {
                        'val': location['pa'], 'size': location['size'],
                        'filename': str(path),
                    })
                    pages.append(path.read_bytes())
                counters = _stable_d8_counters(*pages)
                if counters is not None:
                    node['counters'].append({
                        'sample': self.samples,
                        'elapsed_seconds': elapsed_seconds,
                        **counters,
                    })
                for row in stable_d8_records(*pages):
                    key = str(row['sequence'])
                    old = node['records'].get(key)
                    row['first_observed_seconds'] = (old or {}).get(
                        'first_observed_seconds', elapsed_seconds)
                    row['last_observed_seconds'] = elapsed_seconds
                    row['stable_samples'] = (old or {}).get('stable_samples', 0) + 1
                    node['records'][key] = row
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
                node['errors'].append({
                    'sample': self.samples,
                    'elapsed_seconds': elapsed_seconds,
                    'error': type(error).__name__ + ': ' + str(error),
                })
            finally:
                for path in paths:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass

    def document(self):
        nodes = []
        for node in self.nodes:
            nodes.append({
                'node': node['node'],
                'records': [node['records'][key]
                            for key in sorted(node['records'], key=int)],
                'counters': node['counters'],
                'errors': node['errors'],
            })
        return {
            'schema_version': 1,
            'kind': 'live-d8-service-batch-diagnostic',
            'acceptance_evidence': False,
            'development_only': True,
            'warning': ('Development-only synchronous QMP memory reads perturb host timing. '
                        'This file is not acceptance or physical-realtime evidence.'),
            'initialization_errors': self.initialization_errors,
            'sampling': {
                'enabled': self.enabled,
                'interval_seconds': self.interval_seconds,
                'samples': self.samples,
                'stops_vcpus': False,
                'reads_per_node_per_sample': 2,
            },
            'nodes': nodes,
        }

    def write(self):
        document = self.document()
        try:
            encoded = json.dumps(document, indent=2, allow_nan=False) + '\n'
        except (TypeError, ValueError, OverflowError) as error:
            document = {
                'schema_version': 1,
                'kind': 'live-d8-service-batch-diagnostic',
                'acceptance_evidence': False,
                'development_only': True,
                'warning': ('Development-only synchronous QMP memory reads perturb host timing. '
                            'This file is not acceptance or physical-realtime evidence.'),
                'initialization_errors': list(self.initialization_errors),
                'serialization_error': type(error).__name__ + ': ' + str(error),
                'sampling': {
                    'enabled': False,
                    'interval_seconds': self.interval_seconds,
                    'samples': self.samples,
                    'stops_vcpus': False,
                    'reads_per_node_per_sample': 2,
                },
                'nodes': [],
            }
            encoded = json.dumps(document, indent=2, allow_nan=False) + '\n'
        (self.output / D8_DIAGNOSTIC_FILE).write_text(encoded)
        return document

def initialize_d8_locations(diagnostic, image_data):
    """Best-effort opt-in setup; diagnostic symbol failures never fail the run."""
    try:
        return [d8_control_location(data) for data in image_data]
    except (ValueError, KeyError, TypeError) as error:
        diagnostic.disable(error)
        return None

def attest_qemu(binary,source=None):
    binary=Path(binary).resolve(strict=True)
    require(binary.is_file(),'qemu-system-aarch64 is missing')
    version=subprocess.check_output([str(binary),'--version'],timeout=10,text=True)
    first=version.splitlines()[0] if version.splitlines() else ''
    clean=('QEMU emulator version 10.2.2','QEMU emulator version 10.2.2 (v10.2.2)')
    if first in clean:
        return {'qemu_version':version,'qemu_sha256':sha(binary),'qemu_pmu_patch_attested':False}
    require(first=='QEMU emulator version 10.2.2 (v10.2.2-dirty)' and source is not None,
            'unverified QEMU version; patched builds require exact source attestation')
    source=Path(source).resolve(strict=True)
    built=(source/'build/qemu-system-aarch64').resolve(strict=True)
    require(sha(binary)==sha(built),'patched QEMU binary is not the attested source build')
    commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],timeout=10,text=True).strip()
    require(commit==PINNED_QEMU_COMMIT,'patched QEMU source commit differs')
    status=subprocess.run(['git','-C',str(source),'status','--short','--untracked-files=no'],
                          check=True,capture_output=True,text=True,timeout=10).stdout
    changed={line[3:] for line in status.splitlines() if len(line)>=4 and line[:2]==' M'}
    require(changed==set(PATCHED_QEMU_SOURCE_SHA256) and len(status.splitlines())==len(changed),
            'patched QEMU tracked changes differ')
    subprocess.run(['git','-C',str(source),'diff','--check'],check=True,capture_output=True,timeout=10)
    subprocess.run(['git','-C',str(source),'apply','--reverse','--check',
                    str(ROOT/'tools/qemu/cyxia-per-vcpu-pmu.patch')],
                   check=True,capture_output=True,timeout=10)
    require(sha(ROOT/'tools/qemu/cyxia-per-vcpu-pmu.patch')==PINNED_QEMU_PATCH_SHA256,
            'pinned QEMU patch differs')
    require(all(sha(source/name)==digest for name,digest in PATCHED_QEMU_SOURCE_SHA256.items()),
            'patched QEMU source differs')
    return {'qemu_version':version,'qemu_sha256':sha(binary),'qemu_pmu_patch_attested':True,
            'qemu_source_commit':commit,'qemu_patch_sha256':PINNED_QEMU_PATCH_SHA256,
            'qemu_source_sha256':PATCHED_QEMU_SOURCE_SHA256}

def bind_build(path,elf,peer_elf,publics,package,expect):
    require(path is not None,'final acceptance requires --build-manifest')
    build=json.loads(path.read_text())
    require(build.get('schema_version')==1 and build.get('status')=='BUILT_NOT_RUN','invalid build manifest')
    require(build['code_source_map']==code_source_map(),'images were built from different source')
    require(build['builder_sha256']==sha(ROOT/'tools/build_unified.py'),'builder changed after image build')
    expected_fault=expect if expect in ('hang-once','no-stop-ack') else 'normal'
    require(build['profiles']['fault']==expected_fault and build['profiles']['leave']==(expect=='leave'),'build fault/profile differs from acceptance')
    expected_service_fault={
        'service-restart':'after-ready','service-restart-ready':'after-ready',
        'service-restart-reserve':'after-reserve','service-restart-start':'after-start',
        'service-restart-completion':'after-completion',
        'service-restart-result':'after-result-record',
    }.get(expect,'none')
    require(build['profiles'].get('service_fault','none')==expected_service_fault,'build service-fault profile differs from acceptance')
    expected_service_fault_nodes = (
        {'a': expected_service_fault, 'b': 'none'}
        if expected_service_fault != 'none' else {'a': 'none', 'b': 'none'}
    )
    require(build['profiles'].get('service_fault_nodes')==expected_service_fault_nodes,
            'build service-fault node scope differs from acceptance')
    require(build.get('own_private_key_only_verified') is True,'per-node key audit missing')
    require(publics is not None and len(publics)==2 and package is not None,'two public keys and task package required')
    for name,file in zip(('node-a.elf','node-b.elf','node-a.pub','node-b.pub','task.elf'),(elf,peer_elf,*publics,package)):
        require(build['artifacts'][name]['sha256']==sha(file) and build['artifacts'][name]['bytes']==file.stat().st_size,'build artifact differs: '+name)
    for i,name in enumerate(('a','b')):
        require(hashlib.sha256(publics[i].read_bytes()).hexdigest()==build['nodes'][name]['node_id'],'public key differs from built identity')
    if expect!='wrong-pin':
        require(build['nodes']['a']['peer_node_id']==build['nodes']['b']['node_id'] and build['nodes']['b']['peer_node_id']==build['nodes']['a']['node_id'],'build identities are not mutually pinned')
    return {'sha256':sha(path),'code_source_sha256':build['code_source_sha256'],'profiles':build['profiles']}

def profile(data):
    inspect_elf(data)
    require(boot_profile(data)['ram_mib']==1024,'unified image requires 1 GiB')
    locations={}
    for name,size in CAPTURE_SYMBOLS:
        location=symbol(data,name)
        require(location['size']==size,f'{name} size differs')
        locations[name]=location
    return locations

def decode_final_diagnostics(bundle):
    """Decode a stopped snapshot without replacing its functional failure."""
    snapshot={}
    try:
        decode_domain_diagnostics(snapshot,bundle)
    except ValueError as error:
        snapshot['final_parse_error']=str(error)
    progress_errors=decode_progress_diagnostics(snapshot,bundle)
    if progress_errors:
        snapshot.setdefault('final_parse_error',str(progress_errors[0]))
    snapshot['control'] = None
    if 'DOMAIN_CONTROL_EVIDENCE' in bundle:
        try:
            unified = snapshot.get('unified_words') or []
            boot_epoch = unified[1] if len(unified) > 1 else None
            snapshot['control'] = parse_control(
                bundle['DOMAIN_CONTROL_EVIDENCE'], boot_epoch)
        except ValueError as error:
            snapshot.setdefault('diagnostic_errors', []).append({
                'field': 'control', 'error': str(error),
            })
            snapshot.setdefault('final_parse_error', str(error))
    retained=retained_observation(snapshot)
    return {key:retained.get(key) for key in FINAL_DIAGNOSTIC_FIELDS}

def record_final_diagnostics(output,bundles):
    decoded=[decode_final_diagnostics(bundle) for bundle in bundles]
    (output/'final-diagnostics.json').write_text(json.dumps(decoded,indent=2)+'\n')
    return decoded

def validate(serial,pages,cpu_counts,*,recover=False,expect='normal'):
    require(cpu_counts==[4,4],'four native cores per node required')
    service_restart = expect.startswith('service-restart')
    restart_boundary = {
        'service-restart':(11,0x212),'service-restart-ready':(11,0x212),
        'service-restart-reserve':(10,31),'service-restart-start':(10,2),
        'service-restart-completion':(10,3),'service-restart-result':(11,0x216),
    }.get(expect)
    observations=[]
    for text,bundle in zip(serial,pages):
        u=struct.unpack('<512Q',bundle['UNIFIED_EVIDENCE']);d=struct.unpack('<512Q',bundle['DYNAMIC_V13_EVIDENCE']);r=struct.unpack('<1024Q',bundle['RUNTIME_V13_EVIDENCE'])
        require(u[0]==0x435958554e493031 and u[1]>0 and u[15]==0 and 0<u[6]<=200,'invalid or truncated unified evidence')
        require(u[30]>0 and u[30]==u[31]+1,'invalid service generation/restart evidence')
        require(r[0]==0x43595852554e3133 and r[2]>0 and r[2]%2==0 and r[32]==u[1],'incomplete runtime publication or boot mismatch')
        require(u[2]>0 and u[4]>0 and u[5]>0,'EL0 and encrypted transport must execute')
        require(expect=='no-stop-ack' or (d[0]==0x43595844594e3133 and 2<=d[1]<=16),'missing dynamic 1→2→1')
        transitions=[d[16+i*16:32+i*16] for i in range(d[1])]
        if expect=='no-stop-ack':
            require(not transitions and re.search(rb'DYNAMIC_V13_RECONCILE a=\d+ b=4 c=\d+',text) is not None and r[6:8]==(2,13),'missing stop ACK must preserve old ownership and mark CPU2 suspect')
            require(r[46]>0 and r[47]<r[46],'fault did not withhold native stop ACK')
        else:require([t[4] for t in transitions[:2]]==[6,2],'wrong core allocation sequence')
        for i,t in enumerate(transitions):
            require(t[5]==t[4] and t[6]==15^t[5] and t[9]==63 and t[15]==u[1],'bad ownership/stop domains/boot binding')
            require(t[2]<=t[3]<=t[2]+200,'handoff deadline exceeded')
            if i: require(t[2]>=transitions[i-1][2]+1000,'core transition rate exceeded')
        require(r[28]>=4 and (r[19]>0 or expect=='no-stop-ack') and r[20]>0 and r[14]>0,'AI/business/isolation did not execute')
        require(r[17]==r[18]==r[38]==0,'runtime rejection or budget violation')
        require(r[4]>=1000 and all(v<=r[4]//100 for v in r[39:42]) and r[35]<=700 and all(v<=900 and v%100==0 for v in r[23:25]),'raw runtime cost exceeds prepaid capacity')
        expected_runtime_fault={'hang-once':1,'no-stop-ack':2}.get(expect,0)
        require(r[29]==expected_runtime_fault,'wrong runtime fault image')
        require(r[15]==int(expect=='hang-once'),'model fault was not contained exactly once')
        require(u[10]%100==0 and u[11]<=u[10]*r[4]//10000 and u[12]<=r[4]//100,'remote CPU execution exceeds predebit')
        events=[u[32+2*i] for i in range(min(u[6],200))]
        require(all(event in events for event in ((1,2,3,0x212) if recover else (1,2,3,0x211,0x212,0x219))),'missing TLS/BOUND/READY/close')
        require(not any(0xfe<=event<=0x108 or event>=0xf000 for event in events),'service reported failure')
        if expect=='leave':require(0x221 in events,'missing two-signature durable leave')
        restarted = u[30:32] == (2,1)
        if service_restart:
            restart=re.search(rb'(?m)^UNIFIED_SERVICE_RESTART boot=(\d+) generation=2\r?$',text)
            fault=(f'UNIFIED_EL0_FAULT generation=1 last_op={restart_boundary[0]} last_arg0={restart_boundary[1]} ').encode()
            if restarted:
                require(restart is not None and int(restart.group(1))==u[1],
                        'same-boot service restart evidence missing')
                require(u[13:15]==restart_boundary and u[22]==1 and fault in text[:restart.start()],
                        'real generation-1 EL0 fault boundary missing')
                # Counts span the complete boot, including earlier reconnects.
                # Only events after this generation's restart can certify its
                # new service entry, TLS authentication and peer READY.
                pending=iter((1,2,3,0x212));next_event=next(pending)
                for event in re.finditer(rb'(?m)^UNIFIED_SERVICE event=(\d+) arg1=\d+ arg2=\d+ ms=\d+\r?$',text[restart.end():]):
                    if int(event.group(1))==next_event:
                        next_event=next(pending,None)
                        if next_event is None:break
                require(next_event is None,'post-restart service did not authenticate and reconcile to READY')
            else:
                require(u[30:32]==(1,0) and restart is None and u[13:15]==(0,0) and u[22]==0
                        and b'UNIFIED_EL0_FAULT generation=' not in text,
                        'healthy peer unexpectedly faulted or restarted')
            require(all(events.count(event)>=(2 if restarted else 1) for event in (1,2))
                    and all(events.count(event)>=2 for event in (3,0x212)),
                    'service restart pair did not reconcile to READY')
        else:require(u[30:32]==(1,0),'unexpected service restart in this scenario')
        observations.append(dict(boot_epoch=u[1],service_generation=u[30],service_restarts=u[31],service_restarted=restarted,task_starts=u[8],task_finishes=u[9],events=events,transitions=[list(t) for t in transitions],business=list(r[19:23]),inferences=r[14]))
    if service_restart:
        require([o['service_restarted'] for o in observations]==[True,False],
                'service restart must fault node a exactly once while node b remains healthy')
    require(sorted(o['task_starts'] for o in observations)==([0,0] if recover else [0,1]) and sorted(o['task_finishes'] for o in observations)==([0,0] if recover else [0,1]),'pure task not uniquely executed')
    return observations

def validate_rejection(serial,pages,cpu_counts,expect):
    require(cpu_counts==[4,4],'four native cores per node required')
    observations=[]
    for text,bundle in zip(serial,pages):
        u=struct.unpack('<512Q',bundle['UNIFIED_EVIDENCE']);r=struct.unpack('<1024Q',bundle['RUNTIME_V13_EVIDENCE'])
        events=[u[32+2*i] for i in range(min(u[6],200))]
        require(u[0]==0x435958554e493031 and u[1]>0 and u[2]>0 and 0<u[6]<=200,'guest service did not run or trace truncated')
        require(u[15]==(4 if expect=='no-entropy' else 0) and set(events)<=({1,2} if expect=='no-entropy' else {1,2,4}) and {1,2}<=set(events),'unrelated service failure or uninitialized custody cannot prove intended rejection')
        require(all(v==0 for v in u[8:13]) and all(e not in events for e in (3,0x210,0x211,0x212,0x213,0x214)),'rejected peer acquired cluster/task authority')
        require(r[0]==0x43595852554e3133 and r[2]>0 and r[2]%2==0 and r[32]==u[1],'incomplete runtime publication or boot mismatch')
        require(r[14]>0 and r[20]>0 and r[15]==r[17]==r[18]==r[29]==r[38]==0,'local work did not survive network rejection')
        require(r[4]>=1000 and all(v<=r[4]//100 for v in r[39:42]) and r[35]<=700 and all(v<=900 and v%100==0 for v in r[23:25]),'raw runtime cost exceeds prepaid capacity')
        if expect=='no-entropy':require(b'UNIFIED_ISOLATED code=4' in text and u[4]==u[5]==0,'entropy failure did not isolate transport')
        else:require((u[4]>0 or u[5]>0) and 4 in events,'wrong-pin test never attempted and aborted TLS')
        observations.append(dict(boot_epoch=u[1],events=events,inferences=r[14],business_cpu3=r[20],task_starts=u[8]))
    return observations

def capture(guests,locations,label='',resume=False):
    if resume:
        # Mid-run progress observation must not pause/resume vCPUs. Only the
        # runtime page has a publication seqlock; U/D are diagnostic live reads.
        bundles=[]
        for guest,source in zip(guests,locations):
            location=source['RUNTIME_V13_EVIDENCE'];bundle={}
            def read(name,pa,size):
                path=guest['folder']/(label+name+'.bin')
                guest['qmp'].execute('pmemsave',{'val':pa,'size':size,'filename':str(path)})
                return path.read_bytes()
            for _ in range(50):
                a=struct.unpack('<Q',read('runtime-seq-before',location['pa']+16,8))[0]
                page=read('RUNTIME_V13_EVIDENCE',location['pa'],location['size'])
                b=struct.unpack('<Q',read('runtime-seq-after',location['pa']+16,8))[0]
                if a==b==struct.unpack_from('<Q',page,16)[0] and a>0 and a%2==0:
                    bundle['RUNTIME_V13_EVIDENCE']=page;break
                time.sleep(.001)
            else:raise ValueError('live runtime publication did not stabilize')
            for name,location in source.items():
                if name in LIVE_CAPTURE_SYMBOLS and name!='RUNTIME_V13_EVIDENCE':
                    bundle[name]=read(name,location['pa'],location['size'])
            bundles.append(bundle)
        return bundles
    bundles=[]
    for guest in guests:guest['qmp'].execute('stop')
    try:
        for guest,source in zip(guests,locations):
            bundle={}
            for name,location in source.items():
                path=guest['folder']/(label+name+'.bin')
                guest['qmp'].execute('pmemsave',{'val':location['pa'],'size':location['size'],'filename':str(path)})
                bundle[name]=path.read_bytes()
            bundles.append(bundle)
    finally:
        if resume:
            for guest in guests:guest['qmp'].execute('cont')
    return bundles

def clone_sparse(source,target):
    # Preserve prior evidence and disk identity without allocating another full
    # 512MiB on the development machine. Target creation is exclusive.
    with source.open('rb') as r,target.open('xb') as w:
        while data:=r.read(1024*1024):
            if any(data):w.write(data)
            else:w.seek(len(data),1)
        w.truncate(r.tell())

def validate_offline_custody(before,after,publics,package_hash):
    require(len(before)==len(after)==2,'two offline custody disks required')
    for old,new in zip(before,after):
        require(new['uuid']==old['uuid'] and new['boot_epoch']==old['boot_epoch']+1,'offline custody reboot identity mismatch')
        require(new['cluster_records']==old['cluster_records'],'rejected network changed durable cluster history')
    proof=verify_pair(after,publics,package_hash=package_hash)
    require(proof['pure_task_done_verified'],'offline custody lost completed task result')
    return proof

def run(elf: Path, output: Path, timeout: float = 60, *, linked: bool = True, entropy: bool = True, formatter: Path | None = None, peer_elf: Path, development: bool = False, existing_disks=None, reconnect=False, publics=None, package=None,expect='normal',clock_profile='wallclock',build_manifest=None,icount_shift=0,tcg_threads='multi',qemu=None,qemu_source=None,d8_diagnostic_interval=None) -> dict:
    require(1 <= timeout <= 180, 'invalid execution deadline')
    require(d8_diagnostic_interval is None or development,
            'live D8 diagnostics require --development')
    elf = elf.resolve(strict=True)
    peer_elf = peer_elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), 'refuse to reuse evidence output')
    output.mkdir(parents=True)
    d8_diagnostic = (D8ControlDiagnostics(output, interval_seconds=d8_diagnostic_interval)
                     if d8_diagnostic_interval is not None else None)
    before = manifest()
    (output / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    rejection=expect in ('no-entropy','wrong-pin')
    report = {'status': 'FAIL', 'clock_profile':clock_profile,'tcg_threads':'single' if clock_profile=='icount' else tcg_threads,'icount_shift':icount_shift if clock_profile=='icount' else None,'physical_realtime_verified':False,'expect':expect,'reconnect': reconnect, 'recover': bool(existing_disks), 'scope': 'unified-native-integration', 'nodes': 2,
              'intermediate_sampling':'live sequence-page-sequence runtime only; U/D diagnostic; final stopped snapshot',
              'native_tcp_verified': False, 'native_cluster_verified': False,
              'tls_verified': False, 'production_isolation_verified': False,
              'runtime_truth_attested': False, 'linked': linked, 'entropy_device': entropy,
              'elf_sha256': sha(elf), 'peer_elf_sha256': sha(peer_elf), 'development': development, 'source_manifest_sha256': sha(output / 'source-manifest.json')}
    guests = [];prior_disks=[]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-tcp-') as td, ExitStack() as stack:
        try:
            if not development or build_manifest is not None:
                report['build_binding']=bind_build(build_manifest,elf,peer_elf,publics,package,expect)
                shutil.copyfile(build_manifest,output/'build-manifest.json')
            image_data = [p.read_bytes() for p in (elf, peer_elf)]
            locations = [profile(data) for data in image_data]
            d8_locations = (initialize_d8_locations(d8_diagnostic, image_data)
                            if d8_diagnostic is not None else None)
            formatter = (formatter or ROOT / 'target/debug/examples/prototype-disk').resolve(strict=True)
            report['formatter_sha256'] = sha(formatter)
            binary = qemu or shutil.which('qemu-system-aarch64')
            require(binary is not None, 'qemu-system-aarch64 is missing')
            qemu_proof=attest_qemu(binary,qemu_source)
            if qemu_proof['qemu_pmu_patch_attested']:
                require(clock_profile=='wallclock' and tcg_threads=='multi',
                        'patched per-vCPU PMU requires wallclock multi-thread TCG')
            report.update(qemu_proof)
            binary=str(Path(binary).resolve(strict=True))
            # Reserving then releasing the loopback port can race with another
            # process. QEMU startup failure is fatal; it cannot yield PASS.
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            end = started + timeout
            link_phase=0; link_at=0; before_link=None;rejection_started=None
            for node in (1, 2):
                folder = output / f'node-{node}'
                folder.mkdir()
                disk = folder / 'disk.raw'
                if existing_disks:
                    source=existing_disks[node-1].resolve(strict=True)
                    before_disk=inspect_disk(source);clone_sparse(source,disk);uuid=before_disk['uuid']
                    prior_disks.append(before_disk)
                    (folder/'clone-source.json').write_text(json.dumps({'path':str(source),'sha256':sha(source)}))
                else:
                    uuid=secrets.token_hex(16)
                    result=subprocess.run([str(formatter),str(disk),uuid],check=True,capture_output=True,timeout=30)
                    (folder/'format.log').write_bytes(result.stdout+result.stderr)
                    before_disk={'boot_epoch':0}
                require(disk.stat().st_size==512*1024*1024,'disk must be512MiB')
                (folder/'disk-before.json').write_text(json.dumps({'uuid':uuid,'boot_epoch':before_disk['boot_epoch'],'sha256':sha(disk)})+'\n')
                path = str(Path(td) / f'q{node}.sock')
                link = f'socket,id=net0,{"listen" if node == 1 else "connect"}=127.0.0.1:{port}'
                args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                        '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread='+('single' if clock_profile=='icount' else tcg_threads),
                        '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                        '-drive', f'if=none,id=disk0,format=raw,file={disk},cache=writeback', '-device', 'virtio-blk-device,drive=disk0',
                        '-netdev', link, '-device', f'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{node}',
                        '-object', f'filter-dump,id=capture,netdev=net0,file={folder / "ethernet.pcap"}',
                        '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                        '-qmp', f'unix:{path},server=on,wait=off', '-kernel', str(elf if node == 1 else peer_elf), '-no-reboot']
                if entropy:
                    args.extend(['-object', 'rng-random,id=rng0,filename=/dev/urandom', '-device', 'virtio-rng-device,rng=rng0'])
                if clock_profile=='icount':args.extend(['-icount',f'shift={icount_shift},align=on,sleep=on','-rtc','clock=vm'])
                guest = {'folder': folder, 'argv': args, 'raw': bytearray(), 'serial': bytearray(),
                         'decoder': FrameDecoder(), 'proc': None, 'sock': None, 'qmp': None}
                guests.append(guest)
                err = stack.enter_context((folder / 'qemu-stderr.log').open('wb'))
                guest['proc'] = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                guest['sock'] = sock
                while True:
                    require(guest['proc'].poll() is None, f'node {node}: QEMU exited before handshake')
                    if time.monotonic() >= end:
                        raise TimeoutError('QMP handshake deadline')
                    try:
                        sock.connect(path)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(.01)
                qmp = Qmp(sock)
                guest['qmp'] = qmp
                require('QMP' in qmp.receive(end), 'invalid QMP greeting')
                qmp.execute('qmp_capabilities')
                guest['cpus'] = qmp.execute('query-cpus-fast')
                guest['memory'] = qmp.execute('query-memory-size-summary')
                require(guest['memory']['base-memory'] == 1024 * 1024 * 1024, 'wrong QEMU RAM size')
            for guest in guests:
                if not linked:
                    guest['qmp'].execute('set_link', {'name': 'eth0', 'up': False})
                guest['qmp'].execute('cont')
            next_d8_diagnostic = (d8_diagnostic.next_sample_at(time.monotonic())
                                  if d8_diagnostic is not None
                                  and d8_locations is not None else None)
            while time.monotonic() < end:
                for guest in guests:
                    require(guest['proc'].poll() is None, 'QEMU exited before acceptance')
                    value = guest['qmp'].execute('ringbuf-read', {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'})
                    data = base64.b64decode(value, validate=True)
                    guest['raw'].extend(data)
                    require(len(guest['raw']) <= 2 * 1024 * 1024, 'serial budget exceeded')
                    for frame in guest['decoder'].feed(data):
                        guest['serial'].extend(frame)
                    if data:(guest['folder']/'serial-live.txt').write_bytes(guest['serial'])
                    require(not any(word in guest['serial'] for word in (b'FAIL', b'SMP_ERROR', b'PANIC')),
                            'guest reported failure')
                final_event=545 if expect=='leave' else 530 if existing_disks else 537
                complete=all(f'UNIFIED_SERVICE event={final_event} '.encode() in g['serial'] and (b'DYNAMIC_V13_RECONCILE' if expect=='no-stop-ack' else b' b=2 c=2') in g['serial'] for g in guests)
                if rejection and all(b'UNIFIED_START' in g['serial'] for g in guests):
                    if rejection_started is None:
                        rejection_started=time.monotonic();before_link=capture(guests,locations,'before-rejection-',resume=True)
                    complete=time.monotonic()-rejection_started>=5
                if complete and reconnect and link_phase==0:
                    before_link=capture(guests,locations,'before-link-',resume=True)
                    for g in guests:g['qmp'].execute('set_link',{'name':'eth0','up':False})
                    link_phase=1;link_at=time.monotonic();continue
                if link_phase==1 and time.monotonic()-link_at>=2:
                    during=capture(guests,locations,'during-link-',resume=True)
                    progress=[]
                    for a,b in zip(before_link,during):
                        x=struct.unpack('<1024Q',a['RUNTIME_V13_EVIDENCE']);y=struct.unpack('<1024Q',b['RUNTIME_V13_EVIDENCE'])
                        require(y[14]>x[14] and y[20]>x[20],'local AI/business stopped during link loss')
                        progress.append({'inferences':y[14]-x[14],'business_cpu3':y[20]-x[20]})
                    report['link_loss_progress']=progress
                    for g in guests:g['qmp'].execute('set_link',{'name':'eth0','up':True})
                    link_phase=2
                if reconnect:complete &= link_phase==2 and all(g['serial'].count(b'UNIFIED_SERVICE event=3 ')>=2 and g['serial'].count(b'UNIFIED_SERVICE event=530 ')>=2 for g in guests)
                if complete:
                    if development:
                        capture(guests,locations,'pre-stop-',resume=True)
                    pages=capture(guests,locations)
                    for guest in guests:
                        decoder=guest['decoder'];require(decoder.loss==decoder.corrupt==0 and not decoder.buffer,'corrupt UART transport')
                    observations = (validate_rejection([bytes(g['serial']) for g in guests],pages,[len(g['cpus']) for g in guests],expect) if rejection else validate([bytes(g['serial']) for g in guests], pages,[len(g['cpus']) for g in guests],recover=bool(existing_disks),expect=expect))
                    if rejection:
                        for old,new in zip(before_link,pages):
                            x=struct.unpack('<1024Q',old['RUNTIME_V13_EVIDENCE']);y=struct.unpack('<1024Q',new['RUNTIME_V13_EVIDENCE'])
                            require(y[14]>x[14] and y[20]>x[20],'local work stopped during rejected network operation')
                    require(sha(elf)==report['elf_sha256'] and sha(peer_elf)==report['peer_elf_sha256'],'ELF changed during guest run')
                    if build_manifest is not None:require(bind_build(build_manifest,elf,peer_elf,publics,package,expect)==report['build_binding'],'build inputs changed during guest run')
                    require(development or before == manifest(), 'source changed during guest run')
                    report.update(status='OBSERVED' if development else 'PASS', native_tcp_verified=not rejection, observations=observations)
                    break
                now = time.monotonic()
                if d8_diagnostic is not None and d8_locations is not None \
                        and now >= next_d8_diagnostic:
                    d8_diagnostic.sample(
                        guests, d8_locations,
                        elapsed_seconds=round(now - started, 6),
                    )
                    next_d8_diagnostic = d8_diagnostic.next_sample_at(time.monotonic())
                time.sleep(.01)
            else:
                raise TimeoutError('two-guest TCP execution deadline')
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
            report['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            if len(guests)==2 and all(g.get('qmp') and g['proc'].poll() is None for g in guests):
                try:
                    final_pages=capture(guests,locations,'final-')
                    report['final_diagnostics']=record_final_diagnostics(output,final_pages)
                except (OSError,ValueError,RuntimeError) as error:
                    report['final_diagnostics_error']=type(error).__name__+': '+str(error)
            for guest in guests:
                proc, qmp = guest['proc'], guest['qmp']
                if proc is not None and proc.poll() is None:
                    try:
                        if qmp:
                            qmp.execute('quit')
                    except (OSError, ValueError, RuntimeError):
                        pass
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=2)
                if guest['sock']:
                    guest['sock'].close()
                folder = guest['folder']
                (folder / 'serial.bin').write_bytes(guest['raw'])
                (folder / 'serial.txt').write_bytes(guest['serial'])
                if qmp:
                    (folder / 'qmp.jsonl').write_text(''.join(json.dumps(m) + '\n' for m in qmp.transcript))
                decoder = guest['decoder']
                (folder / 'launch.json').write_text(json.dumps({'argv': guest['argv'],
                    'cpus': guest.get('cpus'), 'memory': guest.get('memory'),
                    'exit': proc.returncode if proc is not None else None,
                    'transport': {'frames': decoder.frames, 'lost': decoder.loss, 'corrupt': decoder.corrupt}}, indent=2) + '\n')
    if d8_diagnostic is not None:
        try:
            document = d8_diagnostic.write()
            report['d8_service_batch_diagnostic'] = {
                'file': D8_DIAGNOSTIC_FILE,
                'acceptance_evidence': False,
                'samples': document['sampling']['samples'],
            }
        except (OSError, TypeError, ValueError, OverflowError) as error:
            report['d8_service_batch_diagnostic_error'] = type(error).__name__ + ': ' + str(error)
    if report['status'] in ('PASS','OBSERVED'):
        try:
            captures = [] if rejection else [validate_capture((guest['folder'] / 'ethernet.pcap').read_bytes()) for guest in guests]
            disks = [inspect_disk(guest['folder'] / 'disk.raw') for guest in guests]
            provisioned = [json.loads((guest['folder'] / 'disk-before.json').read_text()) for guest in guests]
            require(len({d['uuid'] for d in disks}) == 2, 'cloned disks')
            for d,p in zip(disks,provisioned): require(d['uuid']==p['uuid'] and d['boot_epoch']==p['boot_epoch']+1,'provisioned disk/BootEpoch changed')
            require(publics is not None and package is not None,'public keys and actual task package are required for joint verification')
            if rejection:
                if existing_disks:
                    require(expect=='no-entropy','only no-entropy supports offline custody reboot')
                    report['offline_custody']=validate_offline_custody(prior_disks,disks,[p.read_bytes() for p in publics],hashlib.sha256(package.read_bytes()).digest())
                    report['offline_custody_verified']=not development
                else:require(all(len(d.get('cluster_records',[]))<=1 for d in disks),'rejected network wrote membership/contract authority')
                report['rejection_verified']=not development
            else:
                report['durable_protocol']=verify_pair(disks,[p.read_bytes() for p in publics],package_hash=hashlib.sha256(package.read_bytes()).digest())
                require(report['durable_protocol']['pure_task_done_verified'],'pure computation terminal result unverified')
                require(all(n['member']==('standalone' if expect=='leave' else 'bound') for n in report['durable_protocol']['nodes']),'unexpected durable membership')
                report.update(joint_native_verified=not development,native_cluster_verified=not development,tls_verified=not development)
            report['captures'] = captures
            report['durable_disks'] = disks
        except (OSError, ValueError) as error:
            report.update(status='FAIL', native_tcp_verified=False,
                          error=type(error).__name__ + ': ' + str(error))
            report['joint_native_verified'] = False
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['evidence_sha256'] = {str(p.relative_to(output)): sha(p)
        for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('elf','peer-elf','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--public',type=Path,action='append',required=True);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--disk',type=Path,action='append');p.add_argument('--reconnect',action='store_true')
    p.add_argument('--expect',choices=('normal','leave','service-restart','service-restart-ready','service-restart-reserve','service-restart-start','service-restart-completion','service-restart-result','hang-once','no-stop-ack','wrong-pin','no-entropy'),default='normal')
    p.add_argument('--clock-profile',choices=('icount','wallclock'),default='wallclock',help='icount is an experimental guest clock; neither profile certifies physical realtime')
    p.add_argument('--icount-shift',choices=(0,4),type=int,default=0)
    p.add_argument('--tcg-threads',choices=('single','multi'),default='multi')
    p.add_argument('--qemu',type=Path,help='explicit qemu-system-aarch64 binary')
    p.add_argument('--qemu-source',type=Path,help='exact pinned source tree for a patched QEMU build')
    p.add_argument('--build-manifest',type=Path)
    p.add_argument('--d8-diagnostic-interval',type=float,metavar='SECONDS',
                   help='development-only synchronous-QMP D8 diagnostic interval; '
                        'recommended 2-3 seconds; perturbs host timing')
    p.add_argument('--timeout',type=float,default=90);p.add_argument('--development',action='store_true');p.add_argument('--disconnected',action='store_true');p.add_argument('--without-entropy',action='store_true');p.add_argument('--formatter',type=Path)
    a=p.parse_args();require(len(a.public)==2 and (a.disk is None or len(a.disk)==2),'two keys/disks required')
    r=run(a.elf,a.output,a.timeout,peer_elf=a.peer_elf,development=a.development,linked=not a.disconnected,entropy=not a.without_entropy,formatter=a.formatter,existing_disks=a.disk,reconnect=a.reconnect,publics=a.public,package=a.package,expect=a.expect,clock_profile=a.clock_profile,build_manifest=a.build_manifest,icount_shift=a.icount_shift,tcg_threads=a.tcg_threads,qemu=a.qemu,qemu_source=a.qemu_source,d8_diagnostic_interval=a.d8_diagnostic_interval)
    print(json.dumps(r,indent=2));return 0 if r['status'] in ('PASS','OBSERVED') else 1
if __name__=='__main__':raise SystemExit(main())
