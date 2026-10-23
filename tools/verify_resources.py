"""Production ARM resource-manager tests over the actual UART console."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from shell import Guest
from doctor import ROOT, llvm_dir, env
from check_elf import inspect_elf
from verify_m1 import inspect_instructions


def verify(elf, output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    report=dict(status='FAIL',elf_sha256=hashlib.sha256(Path(elf).read_bytes()).hexdigest(),checks=[])
    try:
        layout=inspect_elf(Path(elf).read_bytes())
        report['kernel_bytes']=max(x['pa']+x['mem'] for x in layout['loads'])-0x40200000
        disassembly=subprocess.run([str(llvm_dir()/'llvm-objdump'),'--disassemble','--no-show-raw-insn',str(elf)],env=env(),capture_output=True,text=True,check=True,timeout=30).stdout
        report['inspected_instructions']=inspect_instructions(disassembly, allow_user_context=True)
        with Guest(elf,output/'session') as guest:
            guest.until(b'cyxia:/> ')
            def check(command,expected=b'',error=False):
                reply=guest.command(command)
                if expected not in reply or (not error and b'error:' in reply):raise AssertionError((command,expected,reply))
                report['checks'].append(command)
                return reply
            def task(pid):
                reply=check('ps')
                match=re.search(rb'pid='+str(pid).encode()+rb' .*?\r\n',reply)
                if not match:raise AssertionError(('missing pid',pid,reply))
                return match.group()
            def wait_task(pid,state):
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    line=task(pid)
                    if state in line:return line
                    time.sleep(.02)
                raise TimeoutError(('task state',pid,state,line))
            def spawn(kind,work,priority=1,pages=1):
                reply=check(f'proc spawn {kind} {work} {priority} {pages}',b'spawned pid=')
                return int(re.search(rb'spawned pid=(\d+)',reply).group(1))
            check('mem status',b'total=32 free=32 used=0')
            check('mem alloc 2',b'allocated id=1')
            check('mem poke 1 4096 173',b'written')
            check('mem peek 1 4096',b'byte=173')
            check('mem peek 1 8192',b'error: Bounds',True)
            check('mem free 1',b'freed id=1')
            check('mem peek 1 0',b'error: Stale',True)
            check('mem alloc 2',b'allocated id=2')
            check('mem peek 2 4096',b'byte=0')
            check('mem free 2')
            a=spawn('compute',4000,1,1);b=spawn('memory',9000,2,3)
            for pid in [a,b]:
                line=wait_task(pid,b'Exited')
                if b'checksum=0 ' in line or b'pages=0 ' not in line:raise AssertionError(line)
                check(f'proc reap {pid}')
            check('mem status',b'free=32 used=0')
            slow=spawn('compute',1000000,0,2)
            check(f'proc pause {slow}')
            before=task(slow);time.sleep(.05);after=task(slow)
            if re.search(rb'work=(\d+)/',before).group(1)!=re.search(rb'work=(\d+)/',after).group(1):raise AssertionError('paused task progressed')
            check(f'proc resume {slow}');time.sleep(.05)
            if re.search(rb'work=(\d+)/',after).group(1)==re.search(rb'work=(\d+)/',task(slow)).group(1):raise AssertionError('resumed task did not progress')
            check(f'proc kill {slow}');wait_task(slow,b'Killed');check(f'proc reap {slow}')
            check('dev list',b'Timer present=true')
            reply=check('dev read timer',b'queued request=');request=int(re.search(rb'queued request=(\d+)',reply).group(1))
            reply=check('dev requests',b'Timer Complete')
            if not re.search(rb'result=[1-9]\d*',reply):raise AssertionError('timer did not return actual counter')
            check(f'dev reap {request}')
            check('dev write [AI-DEVICE-TEST]',b'queued request=')
            check('dev requests',b'Uart Complete')
            if b'[AI-DEVICE-TEST]\r\n' not in guest.text and guest.text.count(b'[AI-DEVICE-TEST]')<2:raise AssertionError('UART output not observed beyond command echo')
            uart=spawn('uart',2,1,1);wait_task(uart,b'Exited');check(f'proc reap {uart}')
            if guest.text.count(b'[CyxiaOS AI task UART]')!=2:raise AssertionError('UART task output wrong count')
            check('dev disable uart',b'kernel console/timer reserved')
            check('dev write denied',b'error: Offline',True)
            failed=spawn('uart',1);line=wait_task(failed,b'Failed')
            if b'error=Some(Offline)' not in line:raise AssertionError(line)
            check(f'proc reap {failed}');check('dev enable uart')
            check('mem status',b'free=32 used=0')
            check('dev batch 4',b'count=4')
            check('dev requests',b'Timer Complete')
            for _ in range(3):check('mem alloc 8',b'source=AI_DIRECT')
            check('mem alloc 8',b'error: AiDenied',True)
            check('mem status',b'free=8 used=24')
            check('ai resources',b'EL1 cooperative tasks')
            audit=check('ai audit',b'Memory AiDirect')
            if b'Device AiDirect' not in audit:raise AssertionError('missing device model decisions')
            check('write /regression still-working')
            check('cat /regression',b'still-working\r\n')
            report['frames']=guest.decoder.frames
        report['status']='PASS'
    except Exception as error:report['error']=repr(error)
    (output/'summary.json').write_text(json.dumps(report,indent=2))
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--elf',required=True);p.add_argument('--output',default=str(ROOT/'artifacts/resource-verification'));a=p.parse_args()
    result=verify(a.elf,a.output);print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='PASS' else 1)
