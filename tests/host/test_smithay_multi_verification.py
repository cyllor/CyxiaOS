"""Negative tests for real two-client composition and physical focus evidence."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_smithay_multi as gate
from test_smithay_xdg_verification import snapshots


def valid_log():
    lines = [gate.READY, gate.CANVAS]
    sequences = {1: 0, 2: 0}

    def configure(identity, active):
        sequence = sequences[identity]
        sequences[identity] += 1
        serial = 100*identity+sequence+1
        lines.extend((f"SMITHAY_MULTI CONFIGURE id={identity} sequence={sequence} serial={serial} width=64 height=48 activated={active}",
                      f"MULTI_CLIENT CONFIGURE id={identity} index={sequence} serial={serial} width=64 height=48 activated={active}",
                      f"MULTI_CLIENT ACK id={identity} index={sequence} serial={serial}",
                      f"SMITHAY_MULTI ACK id={identity} sequence={sequence} serial={serial}"))

    def finish_frame(identity, frame, scene):
        lines.extend((f"MULTI_CLIENT CALLBACK id={identity} frame={frame} time={scene}",
                      f"MULTI_CLIENT FRAME PASS id={identity} frame={frame} width=64 height=48 seed={gate.SEEDS[identity][frame]} callback=1 after_import_write=1",
                      f"MULTI_CLIENT RELEASE id={identity} frame={frame} count=1"))

    for identity in (1, 2):
        lines.extend((f"SMITHAY_MULTI SPAWN id={identity} child={identity+1}",
                      f"MULTI_CLIENT START id={identity} pid={identity+1} fd=3 libwayland=1.24.0 xdg_shell=1",
                      f"MULTI_CLIENT KEYMAP PASS id={identity} bytes=23019"))
        configure(identity, int(identity == 2))
        lines.append(f"SMITHAY_MULTI COMMIT id={identity} frame=0 seed=0")
    lines.extend(("SMITHAY_MULTI FOCUS previous=0 current=2 reason=initial", gate.scene_ready(0),
                  "MULTI_CLIENT KEYBOARD_ENTER id=2 index=0",
                  "MULTI_CLIENT POINTER_ENTER id=2 index=0 x_fixed=2048 y_fixed=2048"))
    finish_frame(1, 0, 0)
    finish_frame(2, 0, 0)
    for scene, (identity, frame, kind, code) in enumerate(gate.TRANSITIONS):
        if scene in (1, 4):
            old = 3-identity
            configure(old, 0)
            configure(identity, 1)
            lines.extend((f"SMITHAY_MULTI FOCUS previous={old} current={identity} reason=click",
                          f"MULTI_CLIENT KEYBOARD_LEAVE id={old} index=0 closing=0",
                          f"MULTI_CLIENT KEYBOARD_ENTER id={identity} index={0 if identity == 1 else 1}",
                          f"MULTI_CLIENT POINTER_LEAVE id={old} index=0 closing=0"))
            lines.append("MULTI_CLIENT POINTER_ENTER id=1 index=0 x_fixed=2048 y_fixed=2048" if scene == 1
                         else "MULTI_CLIENT POINTER_ENTER id=2 index=1 x_fixed=14336 y_fixed=10240")
        if scene == 3:
            lines.append("MULTI_CLIENT MOTION id=1 frame=2 x_fixed=12288 y_fixed=8192")
        for state in (1, 0):
            if kind == "key":
                symbol = {30: 97, 48: 98, 46: 99, 32: 100, 16: 113}[code]
                lines.append(f"MULTI_CLIENT KEY id={identity} frame={frame} code={code} state={state} keysym={symbol}")
            else:
                x, y = (8, 8) if scene == 1 else ((48, 32) if scene == 3 else (56, 40))
                lines.append(f"MULTI_CLIENT BUTTON id={identity} frame={frame} code={code} state={state} x_fixed={x*256} y_fixed={y*256}")
        lines.append(f"SMITHAY_MULTI INPUT_FORWARDED scene={scene} target={identity} kind={kind} code={code}")
        if scene in (6, 8):
            lines.extend((f"SMITHAY_MULTI CLOSE id={identity}", f"MULTI_CLIENT CLOSE id={identity} count=1"))
            if scene == 6:
                configure(1, 1)
            lines.extend((f"SMITHAY_MULTI FOCUS previous={identity} current={1 if scene == 6 else 0} reason=unmap",
                          f"SMITHAY_MULTI UNMAP id={identity}"))
            if scene == 6:
                lines.append("MULTI_CLIENT KEYBOARD_ENTER id=1 index=1")
            count, events, pointers = (5, 10, 1) if identity == 1 else (4, 8, 2)
            lines.extend((f"MULTI_CLIENT COUNTS id={identity} f={count} cb={count} rel={count} ev={events}",
                          f"MULTI_CLIENT FOCUS id={identity} ke=2 kl=1 pe={pointers} pl=1",
                          gate.client_done(identity),
                          f"EL0 pid={identity+1} Exited code=0 free_pages={48 if identity == 2 else 56} esr=0x0 far=0x0",
                          f"SMITHAY_MULTI EXIT id={identity} child={identity+1} status=0", gate.scene_ready(scene+1)))
        else:
            lines.extend((f"SMITHAY_MULTI COMMIT id={identity} frame={frame+1} seed={gate.SEEDS[identity][frame+1]}",
                          gate.scene_ready(scene+1)))
            finish_frame(identity, frame+1, scene+1)
    lines.extend((gate.TOTAL, gate.SUCCESS, "EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0"))
    return ("\r\n".join(gate.wire(line) for line in lines)+"\r\n").encode()


def qmp_fixture():
    transcript, witnesses = [], []

    def command(name, arguments):
        identity = sum(row["direction"] == "send" for row in transcript)+1
        transcript.append(dict(direction="send", message=dict(execute=name, arguments=arguments, id=identity)))
        transcript.append(dict(direction="receive", message={"return": {}, "id": identity}))
        return identity

    command("qmp_capabilities", {})
    for scene in range(10):
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


class SmithayMultiVerificationTests(unittest.TestCase):
    def test_complete_concurrent_lifecycle(self):
        result = gate.validate(valid_log())
        self.assertEqual((result["scenes"], result["commits"], result["pixels"]), (10, 9, 122880))
        self.assertEqual(result["configure_serials"], [101, 102, 103, 104, 201, 202, 203])

    def test_missing_duplicated_and_interleaved_markers_are_rejected(self):
        good = valid_log()
        for row in good.splitlines():
            if row.startswith((b"SMITHAY_MULTI", b"MULTI_CLIENT", b"EL0 pid=")):
                for bad in (good.replace(row+b"\r\n", b""),
                            good.replace(row+b"\r\n", (row+b"\r\n")*2)):
                    with self.subTest(row=row), self.assertRaises(AssertionError):
                        gate.validate(bad)
        with self.assertRaises(AssertionError):
            gate.validate(good+b"noise MULTI_CLIENT RESULT PASS\n")

    def test_wrong_window_input_activation_configure_and_callback_are_rejected(self):
        good = valid_log()
        for old, new in ((b"scene=3 target=1", b"scene=3 target=2"),
                         (b"code=273", b"code=272"), (b"sym=98", b"sym=97"),
                         (b"x=12288", b"x=10240"),
                         (b"a=0", b"a=1"), (b"serial=203", b"serial=102"),
                         (b"serial=102", b"serial=0"), (b"serial=102", b"serial=4294967296"),
                         (b"time=8", b"time=7"), (b"bytes=23019", b"bytes=0"),
                         (b"top=A focus=A", b"top=B focus=A"), (b"windows=0", b"windows=1"),
                         (b"pid=3 fd=3", b"pid=2 fd=3"), (b"cosmic=0", b"cosmic=1")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))

    def test_frame_input_ack_and_close_causality(self):
        good = valid_log()
        for prefix, anchor in (
            (b"MULTI_CLIENT KEY id=2 frame=0 code=30 state=1", gate.scene_ready(0).encode()),
            (b"SMITHAY_MULTI ACK id=1 sequence=1", gate.scene_ready(3).encode()),
            (b"MULTI_CLIENT CALLBACK id=1 frame=1", gate.scene_ready(2).encode()),
            (b"SMITHAY_MULTI CLOSE id=2", gate.scene_ready(6).encode()),
            (b"SMITHAY_MULTI EXIT id=2", gate.scene_ready(8).encode()),
            (b"MULTI_CLIENT KEYBOARD_ENTER id=1 index=1", gate.scene_ready(9).encode()),
        ):
            prefix = gate.wire(prefix.decode()).encode()
            line = next(row for row in good.splitlines(keepends=True) if row.startswith(prefix))
            bad = good.replace(line, b"").replace(anchor, line+anchor)
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(bad)

    def test_early_real_release_valid_but_never_before_commit(self):
        good = valid_log()
        release = b"MULTI_CLIENT RELEASE id=1 f=1\r\n"
        ready = gate.scene_ready(2).encode()
        self.assertEqual(gate.validate(good.replace(release, b"").replace(ready, release+ready))["commits"], 9)
        commit = b"SMITHAY_MULTI COMMIT id=1 frame=1 seed=272"
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(release, b"").replace(commit, release+commit))
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(release, b"").replace(gate.client_done(1).encode(),
                                                            release+gate.client_done(1).encode()))

    def test_optional_own_close_leaves_must_follow_close_and_be_unique(self):
        good = valid_log()
        leave = b"MULTI_CLIENT K_LEAVE id=2 n=0 closing=1\r\n"
        anchor = gate.client_counts(2).encode()
        self.assertEqual(gate.validate(good.replace(anchor, leave+anchor))["closes"], 2)
        for bad in (good.replace(anchor, leave*2+anchor),
                    good.replace(gate.scene_ready(6).encode(), leave+gate.scene_ready(6).encode()),
                    good.replace(anchor, leave.replace(b"n=0", b"n=1")+anchor),
                    good.replace(gate.client_done(2).encode(), leave+gate.client_done(2).encode())):
            with self.assertRaises(AssertionError):
                gate.validate(bad)
        # A's pointer left when B was raised and never re-entered A.
        closing_a = b"MULTI_CLIENT P_LEAVE id=1 n=0 closing=1\r\n"
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(gate.client_done(1).encode(), closing_a+gate.client_done(1).encode()))

    def test_two_independent_live_children_required_before_first_input(self):
        processes = {pid: dict(pid=pid, parent_pid=0 if pid == 1 else 1, state="Waiting", code=0,
                              exit_signal=0, esr=0, far=0, image_pages=100, heap_pages=10,
                              ai_selections=1, syscalls=1, rank_model=12289, cpu_model=12290,
                              guard_selections=0, thread_guard_selections=0)
                     for pid in (1, 2, 3)}
        gate.validate_live(processes)
        for field, value in (("state", "Exited"), ("parent_pid", 0), ("image_pages", 0),
                             ("heap_pages", 0), ("syscalls", 0), ("cpu_model", 0),
                             ("guard_selections", 1), ("thread_guard_selections", 1)):
            bad = copy.deepcopy(processes)
            bad[3][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate.validate_live(bad)
        with self.assertRaises(AssertionError):
            gate.validate_live({1: processes[1], 2: processes[2]})

    def test_input_wait_barrier_allows_callbacks_but_never_next_input(self):
        for scene, (identity, frame, kind, code) in enumerate(gate.TRANSITIONS):
            waiting = (gate.scene_ready(scene)+"\n").encode()
            gate.scene_waiting(waiting, scene)
            for extra in (f"SMITHAY_MULTI INPUT_FORWARDED scene={scene} target={identity} kind={kind} code={code}",
                          f"MULTI_CLIENT {kind.upper()} id={identity} frame={frame} code={code} state=1",
                          gate.scene_ready(scene+1)):
                with self.subTest(scene=scene), self.assertRaises(AssertionError):
                    gate.scene_waiting(waiting+(gate.wire(extra)+"\n").encode(), scene)
        waiting = (gate.scene_ready(0)+"\nMULTI_CLIENT CALLBACK id=1 f=0 time=0\n").encode()
        gate.scene_waiting(waiting, 0)
        for scene, extra in ((1, "MULTI_CLIENT POINTER_ENTER id=1 index=0 x_fixed=2048 y_fixed=2048"),
                             (3, "MULTI_CLIENT MOTION id=1 frame=2 x_fixed=12288 y_fixed=8192"),
                             (4, "MULTI_CLIENT POINTER_ENTER id=2 index=1 x_fixed=14336 y_fixed=10240"),
                             (1, "SMITHAY_MULTI CONFIGURE id=1 sequence=1 serial=7 width=64 height=48 activated=1")):
            with self.subTest(scene=scene), self.assertRaises(AssertionError):
                gate.scene_waiting((gate.scene_ready(scene)+"\n"+gate.wire(extra)+"\n").encode(), scene)

    def test_scanout_polling_never_injects_input(self):
        guest = SimpleNamespace(text=(gate.scene_ready(0)+"\n").encode(), poll=lambda: None)
        calls = []
        guest.qmp = SimpleNamespace(execute=lambda command, args: calls.append((command, args)))
        with tempfile.TemporaryDirectory() as directory, patch.object(gate.time, "sleep"), \
                patch.object(gate, "scanout", side_effect=[AssertionError("refresh pending"), {"pixels": 12288}]):
            result = gate.capture(guest, 0, Path(directory)/"capture.ppm", 0)
        self.assertEqual(result["capture_attempts"], 2)
        self.assertEqual([command for command, _ in calls], ["screendump", "screendump"])

    def test_server_present_and_callback_do_not_replace_client_input_readiness(self):
        partial = (gate.scene_ready(2)+"\nMULTI_CLIENT CALLBACK id=1 f=1 time=2\n").encode()
        guest = SimpleNamespace(text=partial, poll=lambda: None)
        with patch.object(gate.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(gate.time, "sleep"), self.assertRaises(TimeoutError):
            gate.wait_input_target(guest, 0, 2, timeout=1)
        guest.text += b"MULTI_CLIENT FRAME id=1 f=1 w=64 h=48 seed=272\n"
        gate.wait_input_target(guest, 0, 2)
        # Closing B retains A's last displayed frame; no new callback is forged.
        guest.text = b"MULTI_CLIENT FRAME id=1 f=3 w=64 h=48 seed=273\n"
        gate.wait_input_target(guest, 0, 7)
        gate.wait_input_target(SimpleNamespace(), 0, 9)

    def test_exact_scanouts_before_physical_input_and_none_after_blank_scene(self):
        transcript, witnesses = qmp_fixture()
        self.assertEqual(gate.validate_qmp(transcript, witnesses)["input_commands"], 21)
        for change in ("early", "wrong_key", "wrong_button", "extra_input", "wrong_path",
                       "missing_reply", "error_reply", "duplicate_reply", "duplicate_id", "no_quit"):
            bad = copy.deepcopy(transcript)
            if change == "early":
                bad[2], bad[4] = bad[4], bad[2]
            elif change == "wrong_key":
                bad[4]["message"]["arguments"]["events"][0]["data"]["key"]["data"] = "q"
            elif change == "wrong_button":
                target = next(row for row in bad if row["direction"] == "send" and
                              row["message"].get("arguments", {}).get("events", [{}])[0].get("data", {}).get("button") == "right")
                target["message"]["arguments"]["events"][0]["data"]["button"] = "left"
            elif change == "extra_input":
                bad.append(copy.deepcopy(bad[4]))
            elif change == "wrong_path":
                bad[2]["message"]["arguments"]["filename"] = "/synthetic.ppm"
            elif change == "missing_reply":
                del bad[3]
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

    def test_oracle_covers_overlap_exclusive_regions_close_and_black_background(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"capture.ppm"
            header = b"P6\n1024 768\n255\n"
            for scene in (0, 2, 5, 7, 9):
                pixels = bytearray(1024*768*3)
                for y in range(gate.HEIGHT):
                    for x in range(gate.WIDTH):
                        at = ((gate.Y+y)*1024+gate.X+x)*3
                        pixels[at:at+3] = gate.expected_pixel(scene, x, y)
                path.write_bytes(header+pixels)
                self.assertEqual(gate.scanout(path, scene)["pixels"], 12288)
                for x, y in ((10, 10), (48, 32), (96, 64), (127, 95)):
                    bad = pixels.copy()
                    bad[((gate.Y+y)*1024+gate.X+x)*3] ^= 1
                    path.write_bytes(header+bad)
                    with self.subTest(scene=scene, point=(x, y)), self.assertRaises(AssertionError):
                        gate.scanout(path, scene)
            self.assertNotEqual(gate.expected_pixel(1, 48, 32), gate.expected_pixel(2, 48, 32))
            self.assertEqual(gate.expected_pixel(7, 96, 64), bytes(3))

    def test_all_native_display_submissions_and_resources_reclaimed(self):
        before, after, processes = snapshots()
        processes[1].update(guard_selections=0, thread_guard_selections=0)
        after["ai"]["display"].update(admitted=30, submitted=30, completed=30, ai_admitted=30)
        gate.validate_resources(before, after, processes, 4096)
        for domain, field, value in (("display", "completed", 29), ("display", "guard_admitted", 1),
                                     ("display", "ai_admitted", 29), ("anonymous", "release_units", 0),
                                     ("shared_pages", "ai", 0)):
            bad = copy.deepcopy(after)
            bad["ai"][domain][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gate.validate_resources(before, bad, processes, 4096)

    def test_strict_line_wait_failure_detection_and_artifact_preservation(self):
        marker = gate.scene_ready(0).encode()
        for ending in (b"\n", b"\r\n"):
            guest = SimpleNamespace(text=marker+ending, poll=lambda: None)
            self.assertEqual(gate.wait_marker(guest, 0, marker), guest.text)
        for data in (marker, marker+b"\r", b"prefix "+marker+b"\n", marker+b" suffix\n"):
            guest = SimpleNamespace(text=data, poll=lambda: None)
            with patch.object(gate.time, "monotonic", side_effect=[0, 0, 2]), \
                    patch.object(gate.time, "sleep"), self.assertRaises(TimeoutError):
                gate.wait_marker(guest, 0, marker, timeout=1)
        with self.assertRaises(AssertionError):
            gate.check_console(b"ELF start failed: Nomem\n")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            path = output/"summary.json"
            path.write_text("original failure")
            with self.assertRaises(FileExistsError):
                gate.verify(output/"kernel", output/"server", output/"client", output)
            self.assertEqual(path.read_text(), "original failure")


if __name__ == "__main__":
    unittest.main()
