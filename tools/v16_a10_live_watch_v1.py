"""Opt-in operator stop from existing live files; never native acceptance.

The unchanged collector alone samples QMP and owns QEMU. This observer reads
only its existing task-bank file and NBD event-file metadata. Two distinct
collector file revisions are hints, not stopped snapshots or an I/O proof.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import time

from check_prototype_evidence import read_json, require

MAGIC = 0x43595441534B0001


class OperatorDiagnosticStop(RuntimeError):
    def __init__(self, diagnostics):
        self.diagnostics = Path(diagnostics)
        super().__init__('operator stopped cache experiment from repeated live hints: '+str(diagnostics))


def _stat(path):
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1,'live-watch requires unlinked regular files')
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def live_hint(capture):
    """Stable host reads only. No added QMP commands and no guest-state verdict."""
    capture=Path(capture);bank=capture/'pending-domain-task.bin'
    try:
        before=_stat(bank)
        if before[2] != 256:return None
        raw=bank.read_bytes();after=_stat(bank)
        if before != after or len(raw) != 256:return None
        w=struct.unpack('<32Q',raw)
        if w[0] != MAGIC or not w[1]:return None
        candidates=[p for p in (capture/'nbd/events.jsonl',capture/'nbd/events.jsonl.gz') if p.exists()]
        if len(candidates) != 1:return None
        event=candidates[0];nbd=_stat(event)
        return dict(revision=list(after),guest_publication_ns=w[1],quarantine_mask=w[2],overruns=w[3],
                    bank_sha256=hashlib.sha256(raw).hexdigest(),
                    nbd_revision=[event.name,*nbd],live_hint_only=True)
    except (OSError,ValueError):
        return None


class RepeatedStall:
    def __init__(self):
        self.previous=None;self.revision=None
    def observe(self,hint):
        if hint is None or hint['revision'] == self.revision:return None
        self.revision=hint['revision']
        if hint['quarantine_mask'] & 1 == 0 or hint['overruns'] == 0:
            self.previous=None;return None
        old=self.previous;self.previous=hint
        if old is not None and old['nbd_revision'] == hint['nbd_revision'] \
                and hint['guest_publication_ns'] >= old['guest_publication_ns']:
            return [old,hint]
        return None


def process_identity(pid):
    """Birth time plus private process-group membership prevents PID-only kill."""
    if type(pid) is not int or pid <= 0:return None
    result=subprocess.run(['ps','-p',str(pid),'-o','pid=,ppid=,pgid=,lstart=,stat=,comm='],
                          capture_output=True,text=True,env=dict(os.environ,LC_ALL='C'),timeout=5)
    if result.returncode != 0:return None
    fields=result.stdout.strip().split(None,9)
    if len(fields) != 10:return None
    try:
        return dict(pid=int(fields[0]),ppid=int(fields[1]),pgid=int(fields[2]),
                    birth=' '.join(fields[3:8]),state=fields[8],binary=str(Path(fields[9]).resolve()))
    except ValueError:
        return None


def _same(old,new):
    return old is not None and new is not None and all(old[k] == new[k] for k in ('pid','pgid','birth','binary'))


def _qemu(capture,proc,binary):
    path=Path(capture)/'native-context.json'
    try:
        if _stat(path)[2] > 65536:return None
        c=read_json(path)
        if c.get('capture_root') != str(capture) or c.get('binary') != str(binary):return None
        found=process_identity(c.get('pid'))
        if found and found['ppid'] == proc.pid and found['pgid'] == proc.pid \
                and found['binary'] == str(Path(binary).resolve()):
            return found
    except (OSError,ValueError,KeyError):
        pass
    return None


def stop_owned(proc,identity,*,capture,qemu_binary,grace=15):
    """SIGINT the owned collector first; its original finally owns device loss."""
    report=dict(child_pid=proc.pid,signals=[],cleanup_errors=[])
    qemu=_qemu(capture,proc,qemu_binary) if proc.poll() is None else None
    report['qemu_before']=qemu
    def signal_owned(pid,old,sig,*,direct_child=False):
        try:current=process_identity(pid)
        except (OSError,subprocess.SubprocessError):current=None
        if direct_child:
            # This exact unreaped Popen is kernel direct-child custody; unlike
            # an archive PID it cannot be reused before our wait/poll reaps it.
            if proc.poll() is not None:return
            require(current is None or current['pid'] == current['pgid'] == proc.pid
                    and current['ppid'] == os.getpid() and (old is None
                    or all(old[k] == current[k] for k in ('pid','pgid','birth'))),
                    'live-watch changed direct-child identity')
            proc.send_signal(sig)
        else:
            require(_same(old,current) and current['pgid'] == proc.pid,
                    'live-watch refuses signal to changed/non-owned process')
            if current['state'].startswith('Z'):return
            os.kill(pid,sig)
        report['signals'].append(dict(pid=pid,signal=sig))
    def wait(seconds):
        try:proc.wait(timeout=seconds);return True
        except subprocess.TimeoutExpired:return False
    try:
        if proc.poll() is None:
            signal_owned(proc.pid,identity,signal.SIGINT,direct_child=True)
        if not wait(grace):
            # Only a QEMU whose direct-child lineage and private group were
            # observed above can be cleaned after collector cleanup stalls.
            if qemu is not None and _same(qemu,process_identity(qemu['pid'])):
                signal_owned(qemu['pid'],qemu,signal.SIGKILL)
            if not wait(5):
                signal_owned(proc.pid,identity,signal.SIGKILL,direct_child=True)
                wait(5)
        if qemu is not None and _same(qemu,process_identity(qemu['pid'])):
            signal_owned(qemu['pid'],qemu,signal.SIGKILL)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        report['cleanup_errors'].append(type(error).__name__+': '+str(error))
    report['child_returncode']=proc.poll()
    report['qemu_after']=process_identity(qemu['pid']) if qemu else None
    return report


def _save(path,document):
    with Path(path).open('x') as stream:
        json.dump(document,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')


def run_monitored_clean(argv,*,cwd,environment,capture,diagnostics,qemu_binary,
                        poll_seconds=.25,cleanup_grace=15):
    """Return the unchanged original summary, or an explicit operator stop.

    Caller supplies the reviewed original producer argv. This function never
    edits a child summary, native bank, timeout, quarantine flag or verdict.
    """
    capture=Path(capture);diagnostics=Path(diagnostics)
    require(capture.is_absolute() and not capture.exists(),'live-watch refuses existing/nonabsolute child')
    require(not diagnostics.exists() and not diagnostics.is_relative_to(capture)
            and not capture.is_relative_to(diagnostics),'live-watch diagnostics must be new and outside child')
    require(type(poll_seconds) in (int,float) and .01 <= poll_seconds <= 1
            and type(cleanup_grace) in (int,float) and .1 <= cleanup_grace <= 15,
            'live-watch polling/cleanup bound')
    require(process_identity(os.getpid()) is not None,'live-watch process inspection unavailable before launch')
    diagnostics.mkdir(parents=True,mode=0o700)
    detector=RepeatedStall();hints=None;cleanup=None;identity=None
    with (diagnostics/'stdout.log').open('xb') as stdout, (diagnostics/'stderr.log').open('xb') as stderr:
        proc=subprocess.Popen(argv,cwd=cwd,env=environment,stdout=stdout,stderr=stderr,start_new_session=True)
        try:
            identity=process_identity(proc.pid)
            _save(diagnostics/'launch.json',dict(argv=argv,cwd=str(cwd),child=identity,
                live_hint_only=True,scope='operator observation, never native acceptance'))
            while proc.poll() is None:
                hints=detector.observe(live_hint(capture))
                if hints is not None:
                    cleanup=stop_owned(proc,identity,capture=capture,qemu_binary=qemu_binary,grace=cleanup_grace)
                    require(proc.poll() is not None,'owned collector cleanup incomplete; inspect '+str(diagnostics))
                    if not any(s['pid'] == proc.pid and s['signal'] == signal.SIGINT for s in cleanup['signals']):
                        hints=None  # natural completion won the race; preserve its original result
                    break
                time.sleep(poll_seconds)
            returncode=proc.wait()
        except BaseException:
            if proc.poll() is None:
                cleanup=stop_owned(proc,identity,capture=capture,qemu_binary=qemu_binary,grace=cleanup_grace)
            _save(diagnostics/'observer-interruption.json',dict(live_hint_only=True,cleanup=cleanup))
            raise
    _save(diagnostics/'observation.json',dict(live_hint_only=True,operator_stopped=hints is not None,
        repeated_hints=hints,cleanup=cleanup,child_returncode=returncode,
        native_acceptance_status='NOT_RUN',cache_eviction_verified=False,
        scope='two collector file revisions and unchanged NBD file metadata; no native failure or completion inferred'))
    if hints is not None:
        raise OperatorDiagnosticStop(diagnostics/'observation.json')
    result=read_json(capture/'summary.json')
    require(returncode == 0 or returncode == 1 and result.get('status') == 'FAIL',
            'original clean producer exited '+str(returncode)+'; logs: '+str(diagnostics))
    return result
