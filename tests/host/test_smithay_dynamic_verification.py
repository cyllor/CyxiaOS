"""Reject false independent admission, stale identities and premature disconnect claims."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_smithay_dynamic as gate
from test_smithay_xdg_verification import snapshots


def valid_log():
    lines=[];config_numbers={1:0,2:0,3:0};native_serial=1000
    def launch(pid):lines.append(f"ELF pid={pid} started; ABI=Linux-AArch64-subset image AI_DIRECT model=8195 pages={3970 if pid==1 else 165}")
    def environment(identity):
        lines.extend((f"DYN_CLIENT ENV id={identity} ws=0 fd3=closed",f"DYN_CLIENT PATH id={identity} /tmp/cyxia-wayland-0",
                      f"DYN_CLIENT START id={identity} pid={gate.PIDS[identity]} fd=3",f"DYN_CLIENT PEER id={identity} pid=1 uid=0 gid=0"))
    def configure(identity):
        index=config_numbers[identity];config_numbers[identity]+=1;s=100*identity+index+1;a=gate.CONFIGS[identity][index]
        lines.extend((f"SMITHAY_DYN CONFIG id={identity} n={index} s={s} w=64 h=48 a={a}",
                      f"DYN_CLIENT CFG id={identity} n={index} s={s} w=64 h=48 a={a}",
                      f"DYN_CLIENT ACK id={identity} n={index} s={s}",f"SMITHAY_DYN ACK id={identity} n={index} s={s}"))
    def admit(identity):
        launch(gate.PIDS[identity]);environment(identity)
        lines.extend((f"SMITHAY_DYN ACCEPT id={identity} slot={0 if identity==1 else 1} gen={2 if identity==3 else 1} pid={gate.PIDS[identity]}",
                      f"SMITHAY_DYN PEER id={identity} uid=0 gid=0"))
        if identity==3:lines.append("SMITHAY_DYN STALE old=2 slot=1 gen=1 rejected=1")
        lines.append(f"DYN_CLIENT KEYMAP id={identity} bytes=23019");configure(identity)
    def commit(identity,frame):lines.append(f"SMITHAY_DYN COMMIT id={identity} frame={frame} seed={gate.SEEDS[identity][frame]}")
    def focus(previous,current,reason):lines.append(f"SMITHAY_DYN FOCUS previous={previous} current={current} reason={reason}")
    def scene(n):
        lines.extend(gate.geometry(n,w) for w in reversed(gate.SCENES[n]));lines.append(gate.scene_ready(n))
    def frame(identity,f):
        lines.extend((f"DYN_CLIENT CALLBACK id={identity} f={f} time={gate.FRAME_SCENES[identity][f]}",gate.frame_ready(identity,f)))
        if identity!=3 or f==0:lines.append(f"DYN_CLIENT RELEASE id={identity} f={f}")
    def key(n,identity,f,code):
        nonlocal native_serial
        sym={32:100,16:113,45:120}[code]
        for state in (1,0):
            lines.extend((f"SMITHAY_DYN KEY n={n} id={identity} code={code} state={state} s={native_serial}",
                          f"DYN_CLIENT KEY id={identity} f={f} s={native_serial} c={code} v={state} sym={sym}"));native_serial+=1
        lines.append(f"SMITHAY_DYN INPUT n={n} kind=key code={code}")
    def close(identity):lines.extend((f"SMITHAY_DYN CLOSE id={identity}",f"DYN_CLIENT CLOSE id={identity} n=1"))
    def normal_done(identity):
        lines.extend((f"DYN_CLIENT K_LEAVE id={identity} n=0 closing=1",gate.client_counts(identity),
                      f"DYN_CLIENT FOCUS id={identity} ke={3 if identity==1 else 1} kl={2 if identity==1 else 0}",gate.client_done(identity),
                      f"SMITHAY_DYN RETIRED id={identity} why=graceful"))
    def exit_pid(pid,free):lines.append(f"EL0 pid={pid} Exited code=0 free_pages={free} esr=0x0 far=0x0")
    launch(1);lines.extend((gate.LISTEN,gate.READY,gate.CANVAS));scene(0)
    admit(1);commit(1,0);focus(0,1,"map");lines.append("DYN_CLIENT K_ENTER id=1 n=0");scene(1);frame(1,0)
    key(1,1,0,32);commit(1,1);scene(2);frame(1,1)
    admit(2);commit(2,0);configure(1);focus(1,2,"map");lines.extend(("DYN_CLIENT K_LEAVE id=1 n=0 closing=0","DYN_CLIENT K_ENTER id=2 n=0"));scene(3);frame(2,0)
    key(3,2,0,32);commit(2,1);scene(4);frame(2,1)
    launch(4);environment(0);lines.extend(("SMITHAY_DYN REJECT why=full pid=4 uid=0 gid=0","DYN_CLIENT PROBE id=0 eof=1 bytes=0","DYN_CLIENT RESULT PASS id=0 eof=1"));exit_pid(4,40)
    key(4,2,1,16);close(2);configure(1);focus(2,1,"unmap");lines.extend(("SMITHAY_DYN UNMAP id=2","DYN_CLIENT K_ENTER id=1 n=1"));normal_done(2);exit_pid(3,48);scene(5)
    key(5,1,1,32);commit(1,2);scene(6);frame(1,2)
    admit(3);commit(3,0);configure(1);focus(1,3,"map");lines.extend(("DYN_CLIENT K_LEAVE id=1 n=1 closing=0","DYN_CLIENT K_ENTER id=3 n=0"));scene(7);frame(3,0)
    key(7,3,0,32);commit(3,1);scene(8);frame(3,1)
    key(8,3,1,45);lines.extend(("DYN_CLIENT ABORT id=3 f=2 cb=2 rel=1 keys=4","DYN_CLIENT DISCONNECT id=3 mode=abrupt","SMITHAY_DYN REMOVE id=3 why=disconnect"));configure(1);focus(3,1,"disconnect");lines.extend(("SMITHAY_DYN RETIRED id=3 why=abrupt","DYN_CLIENT K_ENTER id=1 n=2"));exit_pid(5,48);scene(9)
    key(9,1,2,32);commit(1,3);scene(10);frame(1,3)
    key(10,1,3,16);close(1);focus(1,0,"unmap");lines.append("SMITHAY_DYN UNMAP id=1");normal_done(1);exit_pid(2,56);scene(11)
    lines.extend(("SMITHAY_DYN REBIND PASS","SMITHAY_DYN SOCKET CLEAN",gate.TOTAL,gate.SUCCESS));exit_pid(1,64)
    return ("\r\n".join(lines)+"\r\n").encode()


def move_record(data,prefix,anchor,after=False):
    record=next(line for line in data.splitlines(keepends=True) if line.startswith(prefix));at=next(line for line in data.splitlines(keepends=True) if line.startswith(anchor))
    return data.replace(record,b"").replace(at,at+record if after else record+at)


def qmp_fixture():
    transcript=[];witnesses=[];capacity=None
    def command(name,args):
        n=sum(row["direction"]=="send" for row in transcript)+1
        transcript.extend((dict(direction="send",message=dict(execute=name,arguments=args,id=n)),dict(direction="receive",message={"return":{},"id":n})));return n
    def capture(scene,suffix=""):
        path=str(Path(f"scene-{scene}{suffix}.ppm").resolve());n=command("screendump",{"filename":path})
        return dict(scene=scene,path=path,capture_attempts=1,capture_qmp_id=n,captured_at=n,canvas_sha256=f"canvas-{scene}")
    command("qmp_capabilities",{})
    for scene in range(12):
        witness=capture(scene);witnesses.append(witness)
        if scene==4:capacity=capture(4,"-after-capacity")
        events=gate.input_events(scene)
        if events:
            witness.update(input_started_at=transcript[-1]["message"]["id"]+.1,input_first_qmp_id=transcript[-1]["message"]["id"]+1)
            for batch in events:witness["input_last_qmp_id"]=command("input-send-event",{"events":batch})
            witness["input_finished_at"]=witness["input_last_qmp_id"]+.1
    command("quit",{});return transcript,witnesses,capacity


def resource_fixture():
    before,after,old_processes=snapshots()
    after["ai"]["display"].update(admitted=36,submitted=36,completed=36,ai_admitted=36)
    after["ai"]["spawn_receipt"]=copy.deepcopy(before["ai"]["spawn_receipt"])
    for field in ("requests","committed","ai","proposals","approved"):after["ai"]["process"][field]=before["ai"]["process"][field]+5
    sample=next(iter(old_processes.values()));processes={}
    for pid in (1,2,4,5):
        row=copy.deepcopy(sample);row.update(pid=pid,parent_pid=0,guard_selections=0,thread_guard_selections=0);processes[pid]=row
    return before,after,processes


class SmithayDynamicVerificationTests(unittest.TestCase):
    def test_real_independent_admission_lifecycle(self):
        result=gate.validate(valid_log());self.assertEqual((result["scenes"],result["commits"],result["configures"]),(12,8,7))
        self.assertEqual((result["admitted_clients"],result["capacity_rejections"],result["reused_slots"]),(3,1,1))
        self.assertEqual(set(result["launches"]),{"1","2","3","4","5"})

    def test_every_actual_lifecycle_record_is_required_once(self):
        good=valid_log()
        for line in good.splitlines():
            for bad in (good.replace(line+b"\r\n",b""),good.replace(line+b"\r\n",(line+b"\r\n")*2)):
                with self.subTest(line=line),self.assertRaises(AssertionError):gate.validate(bad)
        with self.assertRaises(AssertionError):gate.validate(good+b"noise DYN_CLIENT RESULT PASS\n")

    def test_actual_peer_credentials_and_generation_cannot_be_labels(self):
        good=valid_log()
        for old,new in ((b"gen=2 pid=5",b"gen=1 pid=5"),(b"slot=1 gen=2",b"slot=0 gen=2"),
                        (b"gen=1 pid=3",b"gen=1 pid=2"),(b"PEER id=3 pid=1",b"PEER id=3 pid=2"),
                        (b"uid=0 gid=0",b"uid=1 gid=0"),(b"old=2 slot=1 gen=1 rejected=1",b"old=2 slot=1 gen=2 rejected=1"),
                        (b"ws=0 fd3=closed",b"ws=1 fd3=open"),(b"/tmp/cyxia-wayland-0",b"/tmp/forged-display")):
            with self.subTest(old=old),self.assertRaises(AssertionError):gate.validate(good.replace(old,new,1))

    def test_capacity_requires_real_zero_byte_eof_and_no_registration(self):
        good=valid_log()
        for old,new in ((b"eof=1 bytes=0",b"eof=0 bytes=0"),(b"eof=1 bytes=0",b"eof=1 bytes=1"),
                        (b"why=full pid=4",b"why=full pid=5"),(b"why=full",b"why=protocol")):
            with self.subTest(old=old),self.assertRaises(AssertionError):gate.validate(good.replace(old,new,1))
        for line in ("SMITHAY_DYN ACCEPT id=4 slot=2 gen=1 pid=4","DYN_CLIENT KEYMAP id=0 bytes=23019","SMITHAY_DYN CONFIG id=0 n=0 s=900 w=64 h=48 a=1"):
            with self.subTest(line=line),self.assertRaises(AssertionError):gate.validate(good+(line+"\r\n").encode())
        with self.assertRaises(AssertionError):gate.validate(move_record(good,b"DYN_CLIENT PROBE",b"SMITHAY_DYN REJECT"))

    def test_abrupt_client_keeps_live_last_buffer_and_has_no_graceful_teardown(self):
        good=valid_log()
        for line in ("DYN_CLIENT RELEASE id=3 f=1","DYN_CLIENT CLOSE id=3 n=1","SMITHAY_DYN UNMAP id=3",
                     "DYN_CLIENT K_LEAVE id=3 n=0 closing=1","DYN_CLIENT COUNTS id=3 f=2 cb=2 rel=2 keys=4"):
            with self.subTest(line=line),self.assertRaises(AssertionError):gate.validate(good+(line+"\r\n").encode())
        for old,new in ((b"f=2 cb=2 rel=1 keys=4",b"f=2 cb=2 rel=2 keys=4"),(b"why=abrupt",b"why=graceful")):
            with self.assertRaises(AssertionError):gate.validate(good.replace(old,new,1))
        with self.assertRaises(AssertionError):gate.validate(move_record(good,b"SMITHAY_DYN REMOVE",b"DYN_CLIENT ABORT"))
        # Actual close wakes the server before the client emits its completion.
        reordered=move_record(good,b"DYN_CLIENT DISCONNECT",b"SMITHAY_DYN RETIRED id=3",True)
        self.assertEqual(gate.validate(reordered)["abrupt_disconnects"],1)

    def test_client_start_and_server_accept_are_independently_scheduled(self):
        good=valid_log()
        for identity in (1,2,3):
            accepted=f"SMITHAY_DYN ACCEPT id={identity} ".encode()
            changed=move_record(good,accepted,f"DYN_CLIENT START id={identity} ".encode())
            self.assertEqual(gate.validate(changed)["admitted_clients"],3)
        changed=move_record(good,b"SMITHAY_DYN REJECT",b"DYN_CLIENT START id=0 ")
        self.assertEqual(gate.validate(changed)["capacity_rejections"],1)

    def test_dispatch_and_survivor_focus_require_receipts_before_next_native_input(self):
        good=valid_log()
        for prefix,anchor,after in ((b"DYN_CLIENT FRAME id=1 f=1 ",b"SMITHAY_DYN ACCEPT id=2 ",True),
                                    (b"DYN_CLIENT FRAME id=3 f=1 ",b"SMITHAY_DYN KEY n=8 ",True),
                                    (b"DYN_CLIENT K_ENTER id=1 n=2",b"SMITHAY_DYN FOCUS previous=3 ",False),
                                    (b"SMITHAY_DYN RETIRED id=2 ",b"SMITHAY_DYN ACCEPT id=3 ",True),
                                    (b"DYN_CLIENT RELEASE id=2 f=1",gate.client_counts(2).encode(),True),
                                    (b"DYN_CLIENT K_LEAVE id=1 n=0 closing=1",gate.client_counts(1).encode(),True)):
            with self.subTest(prefix=prefix),self.assertRaises(AssertionError):gate.validate(move_record(good,prefix,anchor,after))

    def test_native_serials_are_real_unique_and_global(self):
        good=valid_log()
        for old,new in ((b"s=1000",b"s=101"),(b"s=1000",b"s=0"),(b"s=1000",b"s=4294967296"),(b"s=1002",b"s=1000")):
            with self.subTest(old=old),self.assertRaises(AssertionError):gate.validate(good.replace(old,new))
        with self.assertRaises(AssertionError):gate.validate(good.replace(b"f=0 s=1000",b"f=0 s=9000"))

    def test_kernel_exit_ledger_precedes_survivor_input_and_preserves_overwritten_b(self):
        good=valid_log()
        for old,new in ((b"pid=4 Exited code=0 free_pages=40",b"pid=4 Exited code=0 free_pages=48"),
                        (b"pid=3 Exited code=0",b"pid=3 Exited code=1"),(b"pid=5 Exited code=0 free_pages=48",b"pid=5 Exited code=0 free_pages=56")):
            with self.assertRaises(AssertionError):gate.validate(good.replace(old,new))
        for prefix,anchor in ((b"EL0 pid=4 ",b"SMITHAY_DYN KEY n=4 "),(b"EL0 pid=3 ",b"SMITHAY_DYN KEY n=5 "),(b"EL0 pid=5 ",b"SMITHAY_DYN KEY n=9 ")):
            with self.assertRaises(AssertionError):gate.validate(move_record(good,prefix,anchor,True))
        # The server cannot waitpid independent children; either final exit order is legal.
        changed=move_record(good,b"EL0 pid=2 ",b"EL0 pid=1 ",True).replace(b"pid=1 Exited code=0 free_pages=64",b"pid=1 Exited code=0 free_pages=56").replace(b"pid=2 Exited code=0 free_pages=56",b"pid=2 Exited code=0 free_pages=64")
        self.assertEqual(gate.validate(changed)["independently_launched_processes"],5)

    def test_qmp_capacity_witness_precedes_close_and_all_operations_complete(self):
        transcript,witnesses,capacity=qmp_fixture()
        self.assertEqual(gate.validate_qmp(transcript,witnesses,capacity),dict(scanouts=12,capacity_scanouts=1,input_commands=16,qmp_commands=31))
        for change in ("key","late_reply","missing_reply","extra_input","wrong_capture","no_quit"):
            bad=copy.deepcopy(transcript)
            if change=="key":next(r for r in bad if r["direction"]=="send" and r["message"]["execute"]=="input-send-event")["message"]["arguments"]["events"][0]["data"]["key"]["data"]="a"
            elif change=="late_reply":bad.insert(5,bad.pop(3))
            elif change=="missing_reply":del bad[3]
            elif change=="extra_input":bad.append(copy.deepcopy(bad[8]))
            elif change=="wrong_capture":next(r for r in bad if r["direction"]=="send" and r["message"]["id"]==capacity["capture_qmp_id"])["message"]["arguments"]["filename"]="/wrong.ppm"
            else:del bad[-2:]
            with self.subTest(change=change),self.assertRaises(AssertionError):gate.validate_qmp(bad,witnesses,capacity)
        bad=copy.deepcopy(capacity);bad["canvas_sha256"]="changed"
        with self.assertRaises(AssertionError):gate.validate_qmp(transcript,witnesses,bad)

    def test_pixels_include_distinct_c_origin_and_unchanged_survivor(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"scene.ppm";header=b"P6\n1024 768\n255\n"
            for scene in range(12):
                pixels=bytearray(1024*768*3)
                for y in range(96):
                    for x in range(128):
                        at=((gate.Y+y)*1024+gate.X+x)*3;pixels[at:at+3]=gate.expected_pixel(scene,x,y)
                path.write_bytes(header+pixels);self.assertEqual(gate.scanout(path,scene)["pixels"],12288)
                at=((gate.Y+16)*1024+gate.X+48)*3;pixels[at]^=1;path.write_bytes(header+pixels)
                with self.assertRaises(AssertionError):gate.scanout(path,scene)
        self.assertNotEqual(gate.expected_pixel(7,48,16),gate.expected_pixel(6,48,16))
        self.assertEqual(gate.expected_pixel(8,111,16),gate.expected_pixel(8,111,16))
        for y in range(96):
            for x in range(128):self.assertEqual(gate.expected_pixel(6,x,y),gate.expected_pixel(9,x,y))

    def test_ai_accounting_rejects_spawn_substitution_and_guard_fallback(self):
        before,after,processes=resource_fixture();gate.validate_resources(before,after,processes,4096)
        for domain,field,value in (("spawn_receipt","requests",1),("process","committed",4),("display","completed",35),
                                   ("display","guard_admitted",1),("anonymous","release_units",0)):
            bad=copy.deepcopy(after);bad["ai"][domain][field]=value
            with self.subTest(domain=domain),self.assertRaises(AssertionError):gate.validate_resources(before,bad,processes,4096)
        for field,value in (("parent_pid",1),("guard_selections",1),("state","Running")):
            bad=copy.deepcopy(processes);bad[2][field]=value
            with self.assertRaises(AssertionError):gate.validate_resources(before,after,bad,4096)

    def test_live_process_snapshots_preserve_b_cleanup_before_slot_reuse(self):
        _,_,sample=resource_fixture()
        for phase,(alive,dead,_) in gate.PHASES.items():
            processes={}
            for pid in alive|dead:
                row=copy.deepcopy(sample[1]);row.update(pid=pid,free_pages=64-8*len(alive))
                if pid in alive:row.update(state="Waiting",image_pages=100,heap_pages=5,thread_count=1)
                processes[pid]=row
            gate.validate_process_phase(processes,phase,4096)
            for pid in processes:
                bad=copy.deepcopy(processes);bad[pid]["parent_pid"]=1
                with self.assertRaises(AssertionError):gate.validate_process_phase(bad,phase,4096)
            bad=copy.deepcopy(processes);bad[99]=copy.deepcopy(next(iter(processes.values())))
            with self.assertRaises(AssertionError):gate.validate_process_phase(bad,phase,4096)

    def test_dispatch_barrier_and_no_admission_before_shell_launch(self):
        guest=SimpleNamespace(text=(gate.scene_ready(2)+"\nDYN_CLIENT CALLBACK id=1 f=1 time=2\n").encode(),poll=lambda:None)
        with patch.object(gate.time,"monotonic",side_effect=[0,0,2]),patch.object(gate.time,"sleep"),self.assertRaises(TimeoutError):gate.wait_input_target(guest,0,2,timeout=1)
        guest.text+=(gate.frame_ready(1,1)+"\n").encode();gate.wait_input_target(guest,0,2)
        for scene,identity in ((0,1),(2,2),(6,3)):
            data=(gate.scene_ready(scene)+"\n").encode();gate.scene_waiting(data,scene)
            with self.assertRaises(AssertionError):gate.scene_waiting(data+f"SMITHAY_DYN ACCEPT id={identity} slot=0 gen=1 pid=99\n".encode(),scene)


if __name__=="__main__":unittest.main()
