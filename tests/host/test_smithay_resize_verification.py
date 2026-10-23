"""Reject fake anchors, premature commits and incomplete physical release drain."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_smithay_resize as gate
from test_smithay_xdg_verification import snapshots


def valid_log():
    lines, config_numbers = [gate.READY, gate.CANVAS], {1: 0, 2: 0}

    def configure(identity):
        index = config_numbers[identity]
        config_numbers[identity] += 1
        width, height, active, resizing = gate.CONFIGS[identity][index]
        number = 100*identity+index+1
        lines.extend((f"SMITHAY_RS CONFIG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}",
                      f"RS_CLIENT CFG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}",
                      f"RS_CLIENT ACK id={identity} n={index} s={number}",
                      f"SMITHAY_RS ACK id={identity} n={index} s={number}"))

    def request(number, serial, edge):
        lines.extend((f"RS_CLIENT REQ id=1 n={number} kind=resize s={serial} edge={edge}",
                      f"SMITHAY_RS REQUEST id=1 n={number} kind=resize s={serial} edge={edge}",
                      f"SMITHAY_RS AUTH id=1 n={number} s={serial} held={serial} owner=1"))
        configure(1)
        lines.extend((f"SMITHAY_RS GRAB id=1 kind=resize s={serial}",
                      f"RS_CLIENT P_LEAVE id=1 n={number} closing=0"))

    def scene(number):
        lines.extend(gate.geometry(number, window) for window in reversed(gate.SCENES[number]))
        lines.append(gate.scene_ready(number))

    def frame(identity, number):
        lines.extend((f"RS_CLIENT CALLBACK id={identity} f={number} time={gate.FRAME_SCENES[identity][number]}",
                      gate.frame_ready(identity, number), f"RS_CLIENT RELEASE id={identity} f={number}"))

    def commit(identity, number):
        index = {1: (0, 2, 3, 4, 5, None, 6, 7), 2: (0, 2)}[identity][number]
        serial = 0 if index is None else 100*identity+index+1
        window = next(w for w in gate.SCENES[gate.FRAME_SCENES[identity][number]] if w[0] == identity)
        anchor = int(identity == 1 and number in (1, 2, 3, 4, 6, 7))
        lines.extend((f"SMITHAY_RS APPLY id={identity} s={serial} anchor={anchor} x={window[2]} y={window[3]}",
                      f"SMITHAY_RS COMMIT id={identity} frame={number} seed={gate.SEEDS[identity][number]}"))

    def key(scene_number, identity, frame_number, code, serial):
        symbol = 100 if code == 32 else 113
        for index, state in enumerate((1, 0)):
            lines.extend((f"SMITHAY_RS KEY n={scene_number} id={identity} code={code} state={state} s={serial+index}",
                          f"RS_CLIENT KEY id={identity} f={frame_number} code={code} state={state} sym={symbol}"))
        lines.append(f"SMITHAY_RS INPUT n={scene_number} kind=key code={code}")

    def close(identity):
        lines.extend((f"SMITHAY_RS CLOSE id={identity}", f"RS_CLIENT CLOSE id={identity} n=1"))

    def exit_client(identity):
        focus = "ke=1 kl=0 pe=2 pl=2" if identity == 1 else "ke=2 kl=1 pe=0 pl=0"
        lines.extend((gate.client_counts(identity), f"RS_CLIENT FOCUS id={identity} {focus}", gate.client_done(identity),
                      f"EL0 pid={identity+1} Exited code=0 free_pages={48 if identity == 1 else 56} esr=0x0 far=0x0",
                      f"SMITHAY_RS EXIT id={identity} child={identity+1} status=0"))

    for identity in (1, 2):
        lines.extend((f"SMITHAY_RS SPAWN id={identity} child={identity+1}",
                      f"RS_CLIENT START id={identity} pid={identity+1} fd=3",
                      f"RS_CLIENT KEYMAP id={identity} bytes=23019"))
        configure(identity)
        commit(identity, 0)
    lines.append("SMITHAY_RS FOCUS previous=0 current=2 reason=initial")
    scene(0)
    lines.extend(("RS_CLIENT K_ENTER id=2 n=0", "RS_CLIENT P_ENTER id=1 n=0 x=2048 y=2048"))
    frame(1, 0)
    frame(2, 0)
    configure(2)
    configure(1)
    lines.extend(("SMITHAY_RS FOCUS previous=2 current=1 reason=click",
                  "RS_CLIENT K_LEAVE id=2 n=0 closing=0", "RS_CLIENT K_ENTER id=1 n=0",
                  "SMITHAY_RS BUTTON n=0 id=1 code=272 state=1 s=1000",
                  "SMITHAY_RS INPUT n=0 kind=button code=272 state=1",
                  "RS_CLIENT BUTTON id=1 n=0 s=1000 code=272 state=1"))
    request(0, 1000, 5)
    commit(1, 1)
    scene(1)
    frame(1, 1)
    for number, dx, dy, x, y, width, height in ((1, -8, -4, 16, 12, 72, 52),
                                               (2, 12, 8, 28, 20, 60, 44)):
        lines.append(f"SMITHAY_RS MOTION n={number} dx={dx} dy={dy}")
        configure(1)
        lines.extend((f"SMITHAY_RS DRAG id=1 kind=resize n={number} x={x} y={y} w={width} h={height}",
                      f"SMITHAY_RS INPUT n={number} kind=motion dx={dx} dy={dy}"))
        commit(1, number+1)
        scene(number+1)
        frame(1, number+1)
    lines.append("SMITHAY_RS BUTTON n=3 id=1 code=272 state=0 s=1001")
    configure(1)
    lines.extend(("SMITHAY_RS END id=1 kind=resize s=1001", "SMITHAY_RS INPUT n=3 kind=button code=272 state=0",
                  "RS_CLIENT P_ENTER id=1 n=1 x=2048 y=2048"))
    commit(1, 4)
    scene(4)
    frame(1, 4)
    key(4, 1, 4, 32, 1002)
    commit(1, 5)
    scene(5)
    frame(1, 5)
    lines.extend(("SMITHAY_RS BUTTON n=5 id=1 code=273 state=1 s=1004",
                  "SMITHAY_RS INPUT n=5 kind=button code=273 state=1",
                  "RS_CLIENT BUTTON id=1 n=1 s=1004 code=273 state=1"))
    request(1, 1004, 4)
    commit(1, 6)
    scene(6)
    frame(1, 6)
    lines.append("SMITHAY_RS MOTION n=6 dx=-16 dy=0")
    configure(1)
    lines.extend(("SMITHAY_RS DRAG id=1 kind=resize n=6 x=12 y=20 w=76 h=44",
                  "SMITHAY_RS INPUT n=6 kind=motion dx=-16 dy=0"))
    commit(1, 7)
    scene(7)
    frame(1, 7)
    key(7, 1, 7, 16, 1005)
    close(1)
    lines.extend(("SMITHAY_RS CANCEL id=1 reason=unmap", "SMITHAY_RS POINTER n=8 grabbed=1 held=1 focus=0"))
    configure(2)
    lines.extend(("SMITHAY_RS FOCUS previous=1 current=2 reason=unmap", "SMITHAY_RS UNMAP id=1",
                  "RS_CLIENT K_ENTER id=2 n=1"))
    exit_client(1)
    scene(8)
    lines.extend(("SMITHAY_RS BUTTON n=8 id=0 code=273 state=0 s=1007",
                  "SMITHAY_RS POINTER n=9 grabbed=0 held=0 focus=0",
                  "SMITHAY_RS INPUT n=8 kind=button code=273 state=0"))
    scene(9)
    key(9, 2, 0, 32, 1008)
    commit(2, 1)
    scene(10)
    frame(2, 1)
    key(10, 2, 1, 16, 1010)
    close(2)
    lines.extend(("SMITHAY_RS FOCUS previous=2 current=0 reason=unmap", "SMITHAY_RS UNMAP id=2"))
    exit_client(2)
    scene(11)
    lines.extend((gate.TOTAL, gate.SUCCESS, "EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0"))
    return ("\r\n".join(lines)+"\r\n").encode()


def qmp_fixture():
    transcript, witnesses = [], []

    def command(name, arguments):
        number = sum(row["direction"] == "send" for row in transcript)+1
        transcript.append(dict(direction="send", message=dict(execute=name, arguments=arguments, id=number)))
        transcript.append(dict(direction="receive", message={"return": {}, "id": number}))
        return number

    command("qmp_capabilities", {})
    for scene in range(12):
        path = str(Path(f"scene-{scene}.ppm").resolve())
        capture_id = command("screendump", {"filename": path})
        witness = dict(scene=scene, path=path, capture_attempts=1, capture_qmp_id=capture_id, captured_at=1)
        events = gate.input_events(scene)
        if events:
            witness.update(input_first_qmp_id=capture_id+1, input_started_at=2, input_finished_at=3)
            for batch in events:
                witness["input_last_qmp_id"] = command("input-send-event", {"events": batch})
        witnesses.append(witness)
    command("quit", {})
    return transcript, witnesses


def move_record(data, prefix, anchor, after=False):
    record = next(line for line in data.splitlines(keepends=True) if line.startswith(prefix))
    at = next(line for line in data.splitlines(keepends=True) if line.startswith(anchor))
    return data.replace(record, b"").replace(at, at+record if after else record+at)


class SmithayResizeVerificationTests(unittest.TestCase):
    def test_real_anchored_resize_and_owner_cancellation_contract(self):
        result = gate.validate(valid_log())
        self.assertEqual((result["scenes"], result["commits"], result["configures"]), (12, 10, 11))
        self.assertEqual((result["accepted_grabs"], result["cancelled_grabs"], result["drained_releases"]), (2, 1, 1))
        self.assertEqual(result["resize_serials"], [1000, 1004])
        self.assertEqual(result["resize_edges"], [5, 4])

    def test_every_anchor_lifecycle_and_input_receipt_is_required_exactly_once(self):
        good = valid_log()
        for line in good.splitlines():
            for bad in (good.replace(line+b"\r\n", b""), good.replace(line+b"\r\n", (line+b"\r\n")*2)):
                with self.subTest(line=line), self.assertRaises(AssertionError):
                    gate.validate(bad)
        with self.assertRaises(AssertionError):
            gate.validate(good+b"noise RS_CLIENT RESULT PASS\n")

    def test_authorized_edges_and_global_serials_cannot_be_forged(self):
        good = valid_log()
        for old, new in ((b"edge=5", b"edge=10"), (b"edge=4", b"edge=6"),
                         (b"held=1000 owner=1", b"held=1000 owner=2"), (b"held=1004 owner=1", b"held=0 owner=0"),
                         (b"s=1004", b"s=4294967296"), (b"kind=resize s=1001", b"kind=resize s=1000"),
                         (b"n=3 s=104", b"n=3 s=103"), (b"n=3 s=104", b"n=3 s=0")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        with self.assertRaisesRegex(AssertionError, "Configure/input serial collision"):
            gate.validate(good.replace(b"s=1000", b"s=101").replace(b"held=1000", b"held=101"))

    def test_anchored_commit_consumes_exact_ack_and_preserves_ordinary_repaint_origin(self):
        good = valid_log()
        for old, new in ((b"s=104 anchor=1 x=16 y=12", b"s=104 anchor=1 x=24 y=16"),
                         (b"s=104 anchor=1", b"s=103 anchor=1"), (b"s=104 anchor=1", b"s=104 anchor=0"),
                         (b"s=0 anchor=0 x=28 y=20", b"s=106 anchor=1 x=28 y=20"),
                         (b"s=0 anchor=0 x=28 y=20", b"s=0 anchor=0 x=24 y=16"),
                         (b"GEOM n=7 id=1 x=12 y=20", b"GEOM n=7 id=1 x=28 y=20"),
                         (b"w=76 h=44", b"w=76 h=48"), (b"w=60 h=44 a=1 r=0", b"w=60 h=44 a=1 r=1")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        for prefix, anchor in ((b"SMITHAY_RS APPLY id=1 s=104", b"SMITHAY_RS ACK id=1 n=3"),
                               (b"SMITHAY_RS APPLY id=1 s=0 ", b"RS_CLIENT KEY id=1 f=4 code=32 state=0")):
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(move_record(good, prefix, anchor))

    def test_cancellation_requires_owner_close_held_quarantine_and_real_release_drain(self):
        good = valid_log()
        for old, new in ((b"CANCEL id=1", b"CANCEL id=2"), (b"reason=unmap", b"reason=release"),
                         (b"n=8 grabbed=1 held=1 focus=0", b"n=8 grabbed=0 held=0 focus=0"),
                         (b"n=8 grabbed=1 held=1 focus=0", b"n=8 grabbed=1 held=1 focus=1"),
                         (b"n=9 grabbed=0 held=0 focus=0", b"n=9 grabbed=1 held=1 focus=0"),
                         (b"BUTTON n=8 id=0", b"BUTTON n=8 id=2"),
                         (b"SCENE n=8 top=B focus=B win=1 grab=none", b"SCENE n=8 top=B focus=B win=1 grab=resize")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        for prefix, anchor in ((b"SMITHAY_RS CANCEL", b"RS_CLIENT CLOSE id=1"),
                               (b"SMITHAY_RS POINTER n=9", b"SMITHAY_RS BUTTON n=8")):
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(move_record(good, prefix, anchor))

    def test_no_stale_owner_enter_or_orphan_survivor_release(self):
        good = valid_log()
        for line in (b"RS_CLIENT P_ENTER id=1 n=2 x=2048 y=2048\r\n",
                     b"RS_CLIENT P_LEAVE id=1 n=0 closing=1\r\n",
                     b"RS_CLIENT P_ENTER id=2 n=0 x=2048 y=2048\r\n",
                     b"RS_CLIENT BUTTON id=2 n=0 s=1007 code=273 state=0\r\n",
                     b"RS_CLIENT MOTION id=1 x=4096 y=3072\r\n"):
            with self.subTest(line=line), self.assertRaises(AssertionError):
                gate.validate(good+line)

    def test_dispatch_spawn_and_focus_receipts_follow_real_authority(self):
        good = valid_log()
        for prefix, anchor, after in (
            (b"RS_CLIENT FRAME id=1 f=1 ", b"SMITHAY_RS MOTION n=1 ", True),
            (b"RS_CLIENT FRAME id=1 f=3 ", b"SMITHAY_RS BUTTON n=3 ", True),
            (b"RS_CLIENT FRAME id=1 f=7 ", b"SMITHAY_RS KEY n=7 ", True),
            (b"RS_CLIENT K_ENTER id=2 n=0", b"RS_CLIENT START id=2 ", False),
            (b"RS_CLIENT K_ENTER id=1 n=0", b"SMITHAY_RS FOCUS previous=2 current=1 ", False),
            (b"SMITHAY_RS SPAWN id=1 ", b"SMITHAY_RS EXIT id=1 ", True)):
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(move_record(good, prefix, anchor, after))

    def test_all_buffer_releases_and_optional_keyboard_leaves_precede_counts(self):
        good = valid_log()
        release = b"RS_CLIENT RELEASE id=1 f=3\r\n"
        ready = gate.scene_ready(3).encode()
        self.assertEqual(gate.validate(good.replace(release, b"").replace(ready, release+ready))["commits"], 10)
        for anchor in (b"SMITHAY_RS COMMIT id=1 frame=3", gate.client_done(1).encode()):
            with self.assertRaises(AssertionError):
                gate.validate(good.replace(release, b"").replace(anchor, release+anchor))
        for identity in (1, 2):
            leave = f"RS_CLIENT K_LEAVE id={identity} n=0 closing=1\r\n".encode()
            counts = gate.client_counts(identity).encode()
            self.assertEqual(gate.validate(good.replace(counts, leave+counts))["closes"], 2)
            with self.assertRaises(AssertionError):
                gate.validate(good.replace(gate.client_done(identity).encode(), leave+gate.client_done(identity).encode()))

    def test_client_dispatch_barrier_waits_for_real_frame_not_just_callback(self):
        guest = SimpleNamespace(text=(gate.scene_ready(6)+"\nRS_CLIENT CALLBACK id=1 f=6 time=6\n").encode(), poll=lambda: None)
        with patch.object(gate.time, "monotonic", side_effect=[0, 0, 2]), patch.object(gate.time, "sleep"), self.assertRaises(TimeoutError):
            gate.wait_input_target(guest, 0, 6, timeout=1)
        guest.text += (gate.frame_ready(1, 6)+"\nRS_CLIENT P_LEAVE id=1 n=1 closing=0\n").encode()
        gate.wait_input_target(guest, 0, 6)
        gate.wait_input_target(SimpleNamespace(), 0, 11)

    def test_qmp_requires_capture_completion_and_exact_physical_input(self):
        transcript, witnesses = qmp_fixture()
        self.assertEqual(gate.validate_qmp(transcript, witnesses), dict(scanouts=12, input_commands=15, qmp_commands=29))
        for change in ("early_release", "wrong_button", "wrong_delta", "extra_input", "wrong_path",
                       "missing_reply", "late_reply", "error_reply", "duplicate_reply", "duplicate_id", "no_quit"):
            bad = copy.deepcopy(transcript)
            if change == "early_release": bad[4]["message"]["arguments"]["events"][0]["data"]["down"] = False
            elif change == "wrong_button": bad[4]["message"]["arguments"]["events"][0]["data"]["button"] = "right"
            elif change == "wrong_delta":
                move = next(row for row in bad if row["direction"] == "send" and row["message"].get("arguments", {}).get("events", [{}])[0].get("type") == "rel")
                move["message"]["arguments"]["events"][0]["data"]["value"] = 9
            elif change == "extra_input": bad.append(copy.deepcopy(bad[4]))
            elif change == "wrong_path": bad[2]["message"]["arguments"]["filename"] = "/synthetic.ppm"
            elif change == "missing_reply": del bad[3]
            elif change == "late_reply": bad.insert(5, bad.pop(3))
            elif change == "error_reply": bad[3]["message"] = {"error": {"class": "GenericError"}, "id": 2}
            elif change == "duplicate_reply": bad.append(copy.deepcopy(bad[3]))
            elif change == "duplicate_id": bad[4]["message"]["id"] = 2
            else: del bad[-2:]
            with self.subTest(change=change), self.assertRaises(AssertionError):
                gate.validate_qmp(bad, witnesses)

    def test_full_pixel_oracle_covers_both_anchors_and_unchanged_release_canvas(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"capture.ppm"
            header = b"P6\n1024 768\n255\n"
            for scene in range(12):
                pixels = bytearray(1024*768*3)
                for y in range(gate.HEIGHT):
                    for x in range(gate.WIDTH):
                        at = ((gate.Y+y)*1024+gate.X+x)*3
                        pixels[at:at+3] = gate.expected_pixel(scene, x, y)
                path.write_bytes(header+pixels)
                self.assertEqual(gate.scanout(path, scene)["pixels"], 12288)
                for x, y in ((12, 20), (16, 12), (28, 20), (48, 32), (87, 63), (127, 95)):
                    bad = pixels.copy();bad[((gate.Y+y)*1024+gate.X+x)*3] ^= 1
                    path.write_bytes(header+bad)
                    with self.subTest(scene=scene, point=(x, y)), self.assertRaises(AssertionError): gate.scanout(path, scene)
            self.assertNotEqual(gate.expected_pixel(2, 16, 12), bytes(3))
            self.assertEqual(gate.expected_pixel(3, 16, 12), bytes(3))
            self.assertNotEqual(gate.expected_pixel(7, 12, 20), bytes(3))
            for y in range(96):
                for x in range(128): self.assertEqual(gate.expected_pixel(8, x, y), gate.expected_pixel(9, x, y))
            self.assertEqual(gate.expected_pixel(11, 48, 32), bytes(3))

    def test_native_transition_requires_host_injection(self):
        for scene in range(11):
            waiting = (gate.scene_ready(scene)+"\n").encode();gate.scene_waiting(waiting, scene)
            kind = "BUTTON" if scene in (0, 3, 5, 8) else ("MOTION" if scene in (1, 2, 6) else "KEY")
            for line in (f"SMITHAY_RS {kind} n={scene} premature=1", gate.scene_ready(scene+1)):
                with self.subTest(scene=scene), self.assertRaises(AssertionError): gate.scene_waiting(waiting+(line+"\n").encode(), scene)

    def test_refresh_retry_never_changes_guest_input_state(self):
        guest = SimpleNamespace(text=(gate.scene_ready(0)+"\n").encode(), poll=lambda: None);calls=[]
        guest.qmp = SimpleNamespace(execute=lambda name, args: calls.append((name, args)))
        with tempfile.TemporaryDirectory() as directory, patch.object(gate.time, "sleep"), patch.object(gate, "scanout", side_effect=[AssertionError("pending refresh"), {"pixels": 12288}]):
            witness = gate.capture(guest, 0, Path(directory)/"real.ppm", 0)
        self.assertEqual(witness["capture_attempts"], 2)
        self.assertEqual([name for name, _ in calls], ["screendump", "screendump"])

    def test_all_ai_display_completions_and_allocations_are_reclaimed(self):
        before, after, processes = snapshots();processes[1].update(guard_selections=0, thread_guard_selections=0)
        after["ai"]["display"].update(admitted=36, submitted=36, completed=36, ai_admitted=36)
        gate.validate_resources(before, after, processes, 4096)
        for domain, field, value in (("display", "completed", 35), ("display", "guard_admitted", 1),
                                     ("display", "ai_admitted", 35), ("anonymous", "release_units", 0), ("shared_pages", "ai", 0)):
            bad=copy.deepcopy(after);bad["ai"][domain][field]=value
            with self.subTest(field=field), self.assertRaises(AssertionError): gate.validate_resources(before,bad,processes,4096)


if __name__ == "__main__":
    unittest.main()
