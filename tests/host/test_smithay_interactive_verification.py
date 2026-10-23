"""Reject fabricated grabs, unauthorized serials and synthetic interactive scanout."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_smithay_interactive as gate
from test_smithay_xdg_verification import snapshots


def valid_log():
    lines, config_numbers = [gate.READY, gate.CANVAS], {1: 0, 2: 0}

    def configure(identity):
        index = config_numbers[identity]
        config_numbers[identity] += 1
        width, height, active, resizing = gate.CONFIGS[identity][index]
        number = 100*identity+index+1
        lines.extend((f"SMITHAY_INT CONFIG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}",
                      f"INT_CLIENT CFG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}",
                      f"INT_CLIENT ACK id={identity} n={index} s={number}",
                      f"SMITHAY_INT ACK id={identity} n={index} s={number}"))

    def request(identity, number, kind, serial, held, owner, reason=None, defer_grab=False):
        edge = 10 if kind == "resize" else 0
        lines.extend((f"INT_CLIENT REQ id={identity} n={number} kind={kind} s={serial}"+(" edge=10" if edge else ""),
                      f"SMITHAY_INT REQUEST id={identity} n={number} kind={kind} s={serial} edge={edge}",
                      f"SMITHAY_INT AUTH id={identity} n={number} s={serial} held={held} owner={owner}"))
        if reason:
            lines.append(f"SMITHAY_INT REJECT id={identity} n={number} why={reason}")
        elif not defer_grab:
            lines.append(f"SMITHAY_INT GRAB id={identity} kind={kind} s={serial}")

    def scene(number):
        lines.extend(gate.geometry(number, window) for window in reversed(gate.SCENES[number]))
        lines.append(gate.scene_ready(number))

    def frame(identity, number):
        lines.extend((f"INT_CLIENT CALLBACK id={identity} f={number} time={gate.FRAME_SCENES[identity][number]}",
                      gate.frame_ready(identity, number), f"INT_CLIENT RELEASE id={identity} f={number}"))

    def commit(identity, number):
        lines.append(f"SMITHAY_INT COMMIT id={identity} frame={number} seed={gate.SEEDS[identity][number]}")

    def key(scene_number, identity, frame_number, code, serial):
        symbol = 100 if code == 32 else 113
        for index, state in enumerate((1, 0)):
            lines.extend((f"SMITHAY_INT KEY n={scene_number} id={identity} code={code} state={state} s={serial+index}",
                          f"INT_CLIENT KEY id={identity} f={frame_number} code={code} state={state} sym={symbol}"))
        lines.append(f"SMITHAY_INT INPUT n={scene_number} kind=key code={code}")

    def close(identity):
        lines.extend((f"SMITHAY_INT CLOSE id={identity}", f"INT_CLIENT CLOSE id={identity} n=1"))

    def exit_client(identity):
        focus = "ke=1 kl=0 pe=3 pl=2" if identity == 1 else "ke=2 kl=1 pe=0 pl=0"
        lines.extend((gate.client_counts(identity), f"INT_CLIENT FOCUS id={identity} {focus}", gate.client_done(identity),
                      f"EL0 pid={identity+1} Exited code=0 free_pages={48 if identity == 1 else 56} esr=0x0 far=0x0",
                      f"SMITHAY_INT EXIT id={identity} child={identity+1} status=0"))

    for identity in (1, 2):
        lines.extend((f"SMITHAY_INT SPAWN id={identity} child={identity+1}",
                      f"INT_CLIENT START id={identity} pid={identity+1} fd=3 peer=4",
                      f"INT_CLIENT KEYMAP id={identity} bytes=23019"))
        configure(identity)
        commit(identity, 0)
        if identity == 1:
            request(1, 0, "move", 0, 0, 0, "serial")
    lines.append("SMITHAY_INT FOCUS previous=0 current=2 reason=initial")
    scene(0)
    lines.extend(("INT_CLIENT K_ENTER id=2 n=0", "INT_CLIENT P_ENTER id=1 n=0 x=2048 y=2048"))
    frame(1, 0)
    frame(2, 0)
    configure(2)
    configure(1)
    lines.extend(("SMITHAY_INT FOCUS previous=2 current=1 reason=click",
                  "INT_CLIENT K_LEAVE id=2 n=0 closing=0", "INT_CLIENT K_ENTER id=1 n=0",
                  "SMITHAY_INT BUTTON n=0 id=1 code=272 state=1 s=1000",
                  "SMITHAY_INT INPUT n=0 kind=button code=272 state=1",
                  "INT_CLIENT BUTTON id=1 n=0 s=1000 code=272 state=1",
                  "INT_CLIENT PEER id=1 op=send s=1000", "INT_CLIENT PEER id=2 op=recv s=1000"))
    request(2, 0, "move", 1000, 1000, 1, "owner")
    lines.extend(("INT_CLIENT PEER id=2 op=sync s=1000", "INT_CLIENT PEER id=2 op=send s=1000",
                  "INT_CLIENT PEER id=2 op=close s=1000", "INT_CLIENT PEER id=1 op=recv s=1000",
                  "INT_CLIENT PEER id=1 op=close s=1000"))
    request(1, 1, "move", 1000, 1000, 1)
    lines.append("INT_CLIENT P_LEAVE id=1 n=0 closing=0")
    scene(1)
    for number, x, y in ((1, 16, 12), (2, 24, 16)):
        lines.extend((f"SMITHAY_INT MOTION n={number} dx=8 dy=4",
                      f"SMITHAY_INT DRAG id=1 kind=move n={number} x={x} y={y} w=64 h=48",
                      f"SMITHAY_INT INPUT n={number} kind=motion dx=8 dy=4"))
        scene(number+1)
    lines.extend(("SMITHAY_INT BUTTON n=3 id=1 code=272 state=0 s=1001",
                  "SMITHAY_INT END id=1 kind=move s=1001",
                  "SMITHAY_INT INPUT n=3 kind=button code=272 state=0",
                  "INT_CLIENT P_ENTER id=1 n=1 x=2048 y=2048"))
    request(1, 2, "move", 1000, 0, 0, "serial")
    lines.append("INT_CLIENT STALE_SYNC id=1 s=1000")
    commit(1, 1)
    scene(4)
    frame(1, 1)
    lines.extend(("SMITHAY_INT BUTTON n=4 id=1 code=273 state=1 s=1002",
                  "SMITHAY_INT INPUT n=4 kind=button code=273 state=1",
                  "INT_CLIENT BUTTON id=1 n=1 s=1002 code=273 state=1"))
    request(1, 3, "resize", 1002, 1002, 1, defer_grab=True)
    configure(1)
    lines.extend(("SMITHAY_INT GRAB id=1 kind=resize s=1002", "INT_CLIENT P_LEAVE id=1 n=1 closing=0"))
    commit(1, 2)
    scene(5)
    frame(1, 2)
    for number, dx, width, height, frame_number in ((5, 8, 72, 52, 3), (6, -4, 68, 56, 4)):
        lines.append(f"SMITHAY_INT MOTION n={number} dx={dx} dy=4")
        configure(1)
        lines.extend((f"SMITHAY_INT DRAG id=1 kind=resize n={number} x=24 y=16 w={width} h={height}",
                      f"SMITHAY_INT INPUT n={number} kind=motion dx={dx} dy=4"))
        commit(1, frame_number)
        scene(number+1)
        frame(1, frame_number)
    lines.append("SMITHAY_INT BUTTON n=7 id=1 code=273 state=0 s=1003")
    configure(1)
    lines.extend(("SMITHAY_INT END id=1 kind=resize s=1003", "SMITHAY_INT INPUT n=7 kind=button code=273 state=0",
                  "INT_CLIENT P_ENTER id=1 n=2 x=3072 y=4096"))
    commit(1, 5)
    scene(8)
    frame(1, 5)
    key(8, 1, 5, 16, 1004)
    close(1)
    configure(2)
    lines.extend(("SMITHAY_INT FOCUS previous=1 current=2 reason=unmap", "SMITHAY_INT UNMAP id=1",
                  "INT_CLIENT K_ENTER id=2 n=1"))
    exit_client(1)
    scene(9)
    key(9, 2, 0, 32, 1006)
    commit(2, 1)
    scene(10)
    frame(2, 1)
    key(10, 2, 1, 16, 1008)
    close(2)
    lines.extend(("SMITHAY_INT FOCUS previous=2 current=0 reason=unmap", "SMITHAY_INT UNMAP id=2"))
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
            for batch in events:
                last_id = command("input-send-event", {"events": batch})
            witness.update(input_first_qmp_id=capture_id+1, input_last_qmp_id=last_id,
                           input_started_at=2, input_finished_at=3)
        witnesses.append(witness)
    command("quit", {})
    return transcript, witnesses


class SmithayInteractiveVerificationTests(unittest.TestCase):
    def test_complete_genuine_grab_resize_and_recovery_contract(self):
        result = gate.validate(valid_log())
        self.assertEqual((result["scenes"], result["commits"], result["pixels"]), (12, 8, 147456))
        self.assertEqual((result["move_serial"], result["resize_serial"]), (1000, 1002))

    def test_every_exact_auth_lifecycle_and_input_receipt_is_required(self):
        good = valid_log()
        for line in good.splitlines():
            if line.startswith((b"SMITHAY_INT", b"INT_CLIENT", b"EL0 pid=")):
                for bad in (good.replace(line+b"\r\n", b""),
                            good.replace(line+b"\r\n", (line+b"\r\n")*2)):
                    with self.subTest(line=line), self.assertRaises(AssertionError):
                        gate.validate(bad)
        with self.assertRaises(AssertionError):
            gate.validate(good+b"noise INT_CLIENT RESULT PASS\n")

    def test_current_serial_foreign_owner_and_stale_authority_are_distinct(self):
        good = valid_log()
        for old, new in ((b"id=2 n=0 s=1000 held=1000 owner=1", b"id=2 n=0 s=1000 held=0 owner=0"),
                         (b"id=2 n=0 why=owner", b"id=2 n=0 why=serial"),
                         (b"id=1 n=2 s=1000 held=0 owner=0", b"id=1 n=2 s=1000 held=1000 owner=1"),
                         (b"id=1 n=0 s=0 held=0 owner=0", b"id=1 n=0 s=1 held=0 owner=0"),
                         (b"id=1 n=3 kind=resize s=1002 edge=10", b"id=1 n=3 kind=resize s=1000 edge=10"),
                         (b"kind=resize s=1002", b"kind=resize s=1001"),
                         (b"kind=move s=1001", b"kind=move s=1000"),
                         (b"s=1002", b"s=4294967296"),
                         (b"kind=resize s=1002 edge=10", b"kind=resize s=1002 edge=0")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))

    def test_owner_rejection_roundtrip_and_stale_roundtrip_precede_success(self):
        good = valid_log()
        for prefix, anchor in (
            (b"INT_CLIENT PEER id=2 op=sync", b"SMITHAY_INT REJECT id=2 n=0"),
            (b"INT_CLIENT REQ id=1 n=1", b"SMITHAY_INT REJECT id=2 n=0"),
            (b"INT_CLIENT STALE_SYNC", b"SMITHAY_INT REJECT id=1 n=2"),
            (b"SMITHAY_INT COMMIT id=1 frame=1", b"INT_CLIENT STALE_SYNC"),
        ):
            row = next(line for line in good.splitlines(keepends=True) if line.startswith(prefix))
            bad = good.replace(row, b"").replace(anchor, row+anchor)
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(bad)

    def test_peer_receiver_can_run_before_sender_logs_successful_write(self):
        good = valid_log()
        for sender, receiver in ((1, 2), (2, 1)):
            sent = f"INT_CLIENT PEER id={sender} op=send s=1000\r\n".encode()
            received = f"INT_CLIENT PEER id={receiver} op=recv s=1000\r\n".encode()
            closed = b"INT_CLIENT PEER id=2 op=close s=1000\r\n" if sender == 2 else b""
            moved = sent+closed
            good = good.replace(moved, b"").replace(received, received+moved)
        self.assertEqual(gate.validate(good)["accepted_grabs"], 2)

    def test_real_dispatch_and_focus_receipts_cannot_precede_authority(self):
        good = valid_log()
        for prefix, anchor, after in (
            (b"INT_CLIENT FRAME id=1 f=2 ", b"SMITHAY_INT MOTION n=5 ", True),
            (b"INT_CLIENT FRAME id=1 f=4 ", b"SMITHAY_INT BUTTON n=7 ", True),
            (b"INT_CLIENT FRAME id=2 f=1 ", b"SMITHAY_INT KEY n=10 ", True),
            (b"INT_CLIENT K_ENTER id=2 n=0", b"INT_CLIENT START id=2 ", False),
            (b"INT_CLIENT K_ENTER id=1 n=0", b"SMITHAY_INT FOCUS previous=2 current=1 ", False),
            (b"SMITHAY_INT SPAWN id=1 ", b"SMITHAY_INT EXIT id=1 ", True),
        ):
            row = next(line for line in good.splitlines(keepends=True) if line.startswith(prefix))
            at = next(line for line in good.splitlines(keepends=True) if line.startswith(anchor))
            bad = good.replace(row, b"").replace(at, at+row if after else row+at)
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(bad)

    def test_global_serial_counter_does_not_collide_with_configure(self):
        good = valid_log()
        # Keep every occurrence of the authentic pointer press consistent: the
        # defect is sharing a serial with initial configure, not a broken receipt.
        bad = good.replace(b"s=1000", b"s=101").replace(b"held=1000", b"held=101")
        with self.assertRaisesRegex(AssertionError, "Configure/input serial collision"):
            gate.validate(bad)

    def test_resize_ack_state_geometry_and_ordinary_post_move_repaint(self):
        good = valid_log()
        for old, new in ((b"w=72 h=52", b"w=64 h=48"), (b"w=68 h=56 a=1 r=0", b"w=68 h=56 a=1 r=1"),
                         (b"GEOM n=4 id=1 x=24 y=16", b"GEOM n=4 id=1 x=8 y=8"),
                         (b"GEOM n=7 id=1 x=24 y=16", b"GEOM n=7 id=1 x=28 y=16"),
                         (b"frame=1 seed=272", b"frame=1 seed=0"),
                         (b"n=3 s=104", b"n=3 s=103"), (b"n=3 s=104", b"n=3 s=0"),
                         (b"grab=none", b"grab=move"), (b"time=4", b"time=3")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        ack = b"SMITHAY_INT ACK id=1 n=3 s=104\r\n"
        ready = gate.scene_ready(6).encode()+b"\r\n"
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(ack, b"").replace(ready, ready+ack))

    def test_grab_focus_must_clear_restore_and_not_leak_motion_or_release(self):
        good = valid_log()
        for line in (b"INT_CLIENT MOTION id=1 x=4096 y=3072\r\n",
                     b"INT_CLIENT BUTTON id=1 n=0 s=1001 code=272 state=0\r\n",
                     b"INT_CLIENT P_ENTER id=2 n=0 x=2048 y=2048\r\n"):
            with self.assertRaises(AssertionError):
                gate.validate(good+line)
        for old, new in ((b"n=2 x=3072 y=4096", b"n=2 x=2048 y=2048"),
                         (b"id=1 n=1 closing=0", b"id=1 n=0 closing=0"),
                         (b"id=2 code=32", b"id=1 code=32")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))

    def test_buffer_releases_and_own_close_leaves_must_precede_final_counts(self):
        good = valid_log()
        release = b"INT_CLIENT RELEASE id=1 f=3\r\n"
        commit = b"SMITHAY_INT COMMIT id=1 frame=3 seed=273"
        ready = gate.scene_ready(6).encode()
        self.assertEqual(gate.validate(good.replace(release, b"").replace(ready, release+ready))["commits"], 8)
        for anchor in (commit, gate.client_done(1).encode()):
            with self.assertRaises(AssertionError):
                gate.validate(good.replace(release, b"").replace(anchor, release+anchor))
        for identity, device in ((1, "P"), (1, "K"), (2, "K")):
            leave = f"INT_CLIENT {device}_LEAVE id={identity} n=0 closing=1\r\n".encode()
            counts = gate.client_counts(identity).encode()
            self.assertEqual(gate.validate(good.replace(counts, leave+counts))["closes"], 2)
            with self.assertRaises(AssertionError):
                gate.validate(good.replace(gate.client_done(identity).encode(), leave+gate.client_done(identity).encode()))
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(gate.client_counts(2).encode(),
                                       b"INT_CLIENT P_LEAVE id=2 n=0 closing=1\r\n"+gate.client_counts(2).encode()))

    def test_client_dispatch_receipts_are_required_before_next_native_action(self):
        incomplete = (gate.scene_ready(6)+"\nINT_CLIENT CALLBACK id=1 f=3 time=6\n").encode()
        guest = SimpleNamespace(text=incomplete, poll=lambda: None)
        with patch.object(gate.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(gate.time, "sleep"), self.assertRaises(TimeoutError):
            gate.wait_input_target(guest, 0, 6, timeout=1)
        guest.text += (gate.frame_ready(1, 3)+"\n").encode()
        gate.wait_input_target(guest, 0, 6)
        gate.wait_input_target(SimpleNamespace(), 0, 2)
        gate.wait_input_target(SimpleNamespace(), 0, 11)
    def test_qmp_requires_press_drag_release_and_each_actual_scanout(self):
        transcript, witnesses = qmp_fixture()
        self.assertEqual(gate.validate_qmp(transcript, witnesses),
                         dict(scanouts=12, input_commands=14, qmp_commands=28))
        for change in ("early_release", "wrong_button", "wrong_delta", "extra_input", "wrong_path",
                       "missing_reply", "late_reply", "error_reply", "duplicate_reply", "duplicate_id", "no_quit"):
            bad = copy.deepcopy(transcript)
            if change == "early_release":
                bad[4]["message"]["arguments"]["events"][0]["data"]["down"] = False
            elif change == "wrong_button":
                bad[4]["message"]["arguments"]["events"][0]["data"]["button"] = "right"
            elif change == "wrong_delta":
                move = next(row for row in bad if row["direction"] == "send" and
                            row["message"].get("arguments", {}).get("events", [{}])[0].get("type") == "rel")
                move["message"]["arguments"]["events"][0]["data"]["value"] = 9
            elif change == "extra_input":
                bad.append(copy.deepcopy(bad[4]))
            elif change == "wrong_path":
                bad[2]["message"]["arguments"]["filename"] = "/synthetic.ppm"
            elif change == "missing_reply":
                del bad[3]
            elif change == "late_reply":
                bad.insert(5, bad.pop(3))
            elif change == "error_reply":
                bad[3]["message"] = {"error": {"class": "GenericError"}, "id": 2}
            elif change == "duplicate_reply":
                bad.append(copy.deepcopy(bad[3]))
            elif change == "duplicate_id":
                bad[4]["message"]["id"] = 2
            else:
                del bad[-2:]
            with self.subTest(change=change), self.assertRaises(AssertionError):
                gate.validate_qmp(bad, witnesses)

    def test_real_pixels_cover_move_damage_resize_growth_shrink_and_survivor(self):
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
                for x, y in ((8, 8), (24, 16), (48, 32), (94, 20), (91, 71), (127, 95)):
                    bad = pixels.copy()
                    bad[((gate.Y+y)*1024+gate.X+x)*3] ^= 1
                    path.write_bytes(header+bad)
                    with self.subTest(scene=scene, point=(x, y)), self.assertRaises(AssertionError):
                        gate.scanout(path, scene)
            self.assertNotEqual(gate.expected_pixel(0, 48, 32), gate.expected_pixel(1, 48, 32))
            self.assertEqual(gate.expected_pixel(3, 8, 8), bytes(3))
            self.assertNotEqual(gate.expected_pixel(6, 94, 20), bytes(3))
            self.assertEqual(gate.expected_pixel(7, 94, 20), bytes(3))
            self.assertNotEqual(gate.expected_pixel(9, 48, 32), bytes(3))
            self.assertEqual(gate.expected_pixel(11, 48, 32), bytes(3))

    def test_native_button_motion_and_key_require_host_injection(self):
        for scene in range(11):
            waiting = (gate.scene_ready(scene)+"\n").encode()
            gate.scene_waiting(waiting, scene)
            kind = "BUTTON" if scene in (0, 3, 4, 7) else ("MOTION" if scene in (1, 2, 5, 6) else "KEY")
            for line in (f"SMITHAY_INT {kind} n={scene} premature=1", gate.scene_ready(scene+1)):
                with self.subTest(scene=scene), self.assertRaises(AssertionError):
                    gate.scene_waiting(waiting+(line+"\n").encode(), scene)

    def test_refresh_retry_never_moves_pointer_or_changes_guest_state(self):
        guest = SimpleNamespace(text=(gate.scene_ready(0)+"\n").encode(), poll=lambda: None)
        calls = []
        guest.qmp = SimpleNamespace(execute=lambda name, args: calls.append((name, args)))
        with tempfile.TemporaryDirectory() as directory, patch.object(gate.time, "sleep"), \
                patch.object(gate, "scanout", side_effect=[AssertionError("pending refresh"), {"pixels": 12288}]):
            witness = gate.capture(guest, 0, Path(directory)/"real.ppm", 0)
        self.assertEqual(witness["capture_attempts"], 2)
        self.assertEqual([name for name, _ in calls], ["screendump", "screendump"])

    def test_all_thirty_six_ai_display_submissions_complete_without_guards(self):
        before, after, processes = snapshots()
        processes[1].update(guard_selections=0, thread_guard_selections=0)
        after["ai"]["display"].update(admitted=36, submitted=36, completed=36, ai_admitted=36)
        gate.validate_resources(before, after, processes, 4096)
        for domain, field, value in (("display", "completed", 35), ("display", "guard_admitted", 1),
                                     ("display", "ai_admitted", 35), ("anonymous", "release_units", 0),
                                     ("shared_pages", "ai", 0)):
            bad = copy.deepcopy(after)
            bad["ai"][domain][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate.validate_resources(before, bad, processes, 4096)


if __name__ == "__main__":
    unittest.main()
