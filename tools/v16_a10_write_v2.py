"""A10 v2 transport observations: one NBD close owner and QMP through EOF.

These primitives confer no native verdict. In particular, an event count or
an idle socket cannot replace normal owned-process quit/EOF/wait custody.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import struct
import sys
import threading
import time

from v13_a10_native_capture import Witness
from v13_fault_disk import Server as BaseServer
from verify_smp import require

VERSION = 'a10-write-native-v2'
MAX_ERRORS = 32  # resource bound; every other proof remains mandatory
MAX_WIRE = 20 * 1024**2


def canonical(message):
    return hashlib.sha256(json.dumps(message,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def peer_pid(connection):
    if sys.platform == 'darwin':
        return connection.getsockopt(0,2)
    require(sys.platform == 'linux','v2 needs kernel Unix peer PID')
    return struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]


def typed_error(message):
    if type(message) is not dict or set(message) != {'event','timestamp','data'}:
        return False
    t,d=message['timestamp'],message['data']
    return (message['event']=='BLOCK_IO_ERROR' and type(t) is dict
        and set(t)=={'seconds','microseconds'} and all(type(x) is int and x>=0 for x in t.values())
        and t['microseconds']<1000000 and type(d) is dict
        and d=={'device':'disk0','node-name':'cyxia-a10-disk',
            'qom-path':'/machine/peripheral-anon/device[0]','operation':'write',
            'action':'report','nospace':False,'reason':'Input/output error'}
        and type(d['nospace']) is bool)


class CloseOwner:
    def __init__(self,connection,witness,*,run_id,endpoint):
        require(isinstance(connection,socket.socket) and connection.fileno()>=0,'live accepted socket required')
        connection.getpeername()
        self.connection,self.witness=connection,witness
        self.identity=dict(run_id=run_id,endpoint=str(endpoint),peer_pid=peer_pid(connection))
        require(type(self.identity['peer_pid']) is int and self.identity['peer_pid']>0,'missing kernel peer PID')
        self.lock=threading.Lock();self.result=None;self.observation_error=None

    def close(self):
        with self.lock:
            if self.result is not None:
                if self.observation_error is not None:raise self.observation_error
                return self.result
            fd=self.connection.fileno()
            require(fd>=0,'accepted socket closed outside v2 owner')
            shutdown_errno=close_errno=None
            # Actual syscall timestamps remain separate from serialized record
            # timestamps. Receivers sample their return/parse BEFORE this lock.
            with self.witness.lock:
                try:self.witness.record('nbd-close-intent',fd=fd,**self.identity)
                except Exception as error:self.observation_error=error
                begin=time.monotonic_ns()
                try:self.connection.shutdown(socket.SHUT_RDWR)
                except OSError as error:shutdown_errno=error.errno
                finally:
                    end=time.monotonic_ns()
                    close_begin=time.monotonic_ns()
                    try:self.connection.close()
                    except OSError as error:close_errno=error.errno
                    finally:close_end=time.monotonic_ns()
                self.result=dict(fd=fd,fd_after=self.connection.fileno(),shutdown_begin_ns=begin,
                    shutdown_end_ns=end,close_begin_ns=close_begin,close_end_ns=close_end,
                    shutdown_errno=shutdown_errno,close_errno=close_errno,**self.identity)
                try:self.witness.record('nbd-close-complete',**self.result)
                except Exception as error:
                    if self.observation_error is None:self.observation_error=error
                if self.observation_error is not None:raise self.observation_error
            return self.result


class Server(BaseServer):
    """No context-manager/cleanup path may silently close the accepted fd."""
    def __init__(self,backend,path):
        self.state_lock=threading.Lock();self.owner=None;self.closing=False
        self.completed=threading.Event();self.close_origin=None
        try:super().__init__(backend,path)
        except BaseException:
            if hasattr(self,'listener'):self.listener.close()
            raise

    def run(self):
        connection=None
        try:
            connection,_=self.listener.accept()
            witness=getattr(self.backend.witness,'__self__',None)
            require(witness is not None and hasattr(witness,'lock'),'actual shared witness required')
            with self.state_lock:
                self.connection=connection
                self.owner=CloseOwner(connection,witness,run_id=self.backend.meta['run_id'],endpoint=self.path)
                closing=self.closing
            self.backend.witness('endpoint-connected',**self.owner.identity,peer_identity='kernel-pid')
            if not closing:
                self.backend.serve(connection)
                # Backend.serve has exited its actual file/event/wire contexts
                # before this observation, and before the accepted fd close.
                self.backend.witness('nbd-backend-return',run_id=self.backend.meta['run_id'],
                    disk_closed=self.backend.disk.closed,events_closed=self.backend.events.closed,
                    wire_closed=self.backend.wire.closed,requests=self.backend.requests,acks=self.backend.acks)
        except (OSError,ValueError,RuntimeError) as error:self.error=error
        finally:
            try:
                self.close_connection('cut-return' if self.backend.cut_event.is_set() else 'non-cut-return')
            except (OSError,ValueError,RuntimeError) as error:self.error=error
            if connection is not None and self.owner is None:connection.close()
            self.completed.set()

    def close_connection(self,origin):
        with self.state_lock:
            owner=self.owner
            if owner is not None and self.close_origin is None:self.close_origin=origin
        if owner is not None:return owner.close()

    def close(self):
        with self.state_lock:self.closing=True
        error=None
        try:self.close_connection('main-cleanup')
        except Exception as failure:error=failure
        finally:
            try:self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.listener.close()
        self.thread.join(6)
        require(not self.thread.is_alive(),'v2 NBD worker did not end')
        if error is not None:raise error


class Qmp:
    def __init__(self,sock,witness,*,journal_path,byte_limit,command_limit):
        self.sock,self.witness=sock,witness
        self.stream=Path(journal_path).open('xb')
        self.wire=Path(journal_path).with_name('qmp-wire.bin').open('xb')
        self.byte_limit,self.command_limit=byte_limit,command_limit
        self.seq=self.rows=self.bytes=self.wire_bytes=self.errors=0
        self.buffer=b'';self.pending=[];self.wire_hash=hashlib.sha256()
        self.eof=False;self.eof_ns=None;self.lifecycle=[]
        self.peer_pid=peer_pid(sock)
        witness.record('qmp-connected',peer_pid=self.peer_pid,endpoint=sock.getpeername(),fd=sock.fileno())

    def append(self,direction,message,*,recv_return_ns=None,parse_complete_ns=None):
        entry=time.monotonic_ns()
        with self.witness.lock:
            row=dict(direction=direction,message=message)
            raw=(json.dumps(row,separators=(',',':'),allow_nan=False)+'\n').encode()
            require(len(raw)<=4*1024**2 and self.bytes+len(raw)<=self.byte_limit,'v2 transcript byte bound')
            self.stream.write(raw);self.stream.flush();self.rows+=1;self.bytes+=len(raw)
            self.witness.record('qmp-observed',direction=direction,qmp_row=self.rows,sha256=canonical(message),
                append_entry_ns=entry,recv_return_ns=recv_return_ns,parse_complete_ns=parse_complete_ns)
            if direction=='send' and message['execute'] in ('cont','stop','quit'):
                self.lifecycle.append(row)
            if direction=='receive' and message.get('event')=='BLOCK_IO_ERROR':
                self.errors+=1
                require(typed_error(message) and self.errors<=MAX_ERRORS,'v2 unknown/overflow block event')

    def receive(self,deadline):
        while not self.pending:
            require(not self.eof,'QMP receive after EOF')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('v2 QMP deadline before EOF/response')
            self.sock.settimeout(min(1,remaining))
            begin=time.monotonic_ns()
            try:data=self.sock.recv(65536)
            except socket.timeout:continue
            returned=time.monotonic_ns()
            if not data:
                self.eof=True;self.eof_ns=returned
                self.witness.record('qmp-eof',peer_pid=self.peer_pid,recv_begin_ns=begin,
                    recv_return_ns=returned,wire_bytes=self.wire_bytes,wire_sha256=self.wire_hash.hexdigest(),
                    buffer_bytes=len(self.buffer),fd=self.sock.fileno())
                require(not self.buffer,'partial QMP JSON at EOF')
                return None
            require(self.wire_bytes+len(data)<=MAX_WIRE,'v2 QMP raw-wire bound')
            offset=self.wire_bytes
            self.wire.write(data);self.wire.flush();self.wire_hash.update(data);self.wire_bytes+=len(data)
            self.witness.record('qmp-recv-chunk',offset=offset,length=len(data),
                sha256=hashlib.sha256(data).hexdigest(),recv_begin_ns=begin,recv_return_ns=returned)
            self.buffer+=data
            require(len(self.buffer)<=4*1024**2,'v2 QMP frame bound')
            while b'\n' in self.buffer:
                line,self.buffer=self.buffer.split(b'\n',1)
                if not line.strip():continue
                message=json.loads(line)
                require(type(message) is dict,'v2 QMP JSON object required')
                parsed=time.monotonic_ns()
                self.append('receive',message,recv_return_ns=returned,parse_complete_ns=parsed)
                self.pending.append(message)
        return self.pending.pop(0)

    def execute(self,command,args=None):
        require(not self.eof and self.seq<self.command_limit,'v2 command after EOF/bound')
        self.seq+=1;message=dict(execute=command,id=self.seq)
        if args is not None:message['arguments']=args
        self.witness.record('qmp-request',id=self.seq)
        self.append('send',message)
        self.sock.sendall(json.dumps(message).encode()+b'\n')
        deadline=time.monotonic()+5
        while True:
            response=self.receive(deadline)
            require(response is not None,'v2 EOF before command response')
            if 'event' in response:continue
            require(response.get('id')==self.seq,'v2 orphan/out-of-order response')
            require('error' not in response and 'return' in response,'v2 QMP command failed')
            self.witness.record('qmp-response',id=self.seq)
            return response['return']

    @property
    def capture_commands(self):return self.lifecycle

    def until_eof(self,deadline):
        while not self.eof:
            message=self.receive(deadline)
            if message is not None:require('event' in message,'v2 non-event after quit response')

    def close_journal(self):
        try:self.stream.close()
        finally:self.wire.close()


def close_capture(proc,sock,server,qmp,backend,witness,report):
    """Normal quit is safe only AFTER this NBD backing connection is dead."""
    def failure(label,error):
        previous=report.get('error')
        report['error']=(previous+'; ' if previous else '')+label+': '+str(error)
    def attempt(label,body):
        try:return body()
        except Exception as error:failure(label,error)
    def record(event,**fields):
        attempt('v2 cleanup witness',lambda:witness.record(event,**fields))
    try:
        require(proc is not None and proc.poll() is None and qmp is not None,'v2 missing live own process/QMP')
        require(report.get('cut_observed') is True and backend.cut_event.is_set()
            and server.completed.wait(5) and server.error is None and server.close_origin=='cut-return',
            'v2 backend cut/close did not complete')
        closed=server.owner.result
        require(closed and closed['fd_after']==-1 and closed['shutdown_errno'] is None
            and closed['close_errno'] is None and closed['peer_pid']==proc.pid==qmp.peer_pid,
            'v2 actual owned shutdown/PID not proved')
        qmp.execute('quit')
        qmp.until_eof(time.monotonic()+5)
        started=time.monotonic_ns();returncode=proc.wait(timeout=5);finished=time.monotonic_ns()
        witness.record('wait-observed',pid=proc.pid,begin_ns=started,return_ns=finished)
        witness.record('wait',pid=proc.pid,returncode=returncode)
        require(returncode==0,'v2 nonzero owned normal exit')
    except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.SubprocessError) as error:
        failure('v2 normal quit/EOF',error)
    finally:
        if proc is not None and proc.poll() is None:
            record('kill',pid=proc.pid,signal=9)
            attempt('v2 own-process kill',proc.kill)
            attempt('v2 own-process wait',lambda:proc.wait(timeout=5))
            record('wait',pid=proc.pid,returncode=proc.returncode)
        if sock:attempt('v2 QMP close',sock.close)
        if server:
            attempt('v2 backend cleanup',server.close)
            record('backend-close',run_id=backend.meta['run_id'])
        if qmp:attempt('v2 journal close',qmp.close_journal)


def validate_capture_commands(rows,*,cut_observed):
    names=[r['message']['execute'] for r in rows]
    require(cut_observed and names==['cont','stop','quit'],'v2 needs single cont/stop/quit')
