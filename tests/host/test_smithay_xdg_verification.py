"""Reject partial, reordered or synthetic Smithay xdg-shell acceptance evidence."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_smithay_xdg as gate


def valid_log():
    lines = ["SMITHAY_XDG READY frontend=upstream renderer=upstream native=1 xdg=1",
             "SMITHAY_XDG SPAWN round=0 child=2",
             "XDG_CLIENT START round=0 pid=2 fd=3 libwayland=1.24.0 xdg_shell=1",
             "XDG_CLIENT NEGATIVE PASS round=0 error=3 object=9 interface=xdg_surface disconnected=1",
             "EL0 pid=2 Exited code=0 free_pages=56 esr=0x0 far=0x0",
             "SMITHAY_XDG NEGATIVE_PASS round=0 interface=xdg_surface code=3 object=9 surfaces=0"]
    for round_number in (1, 2):
        serial = round_number*100+1
        lines += [f"SMITHAY_XDG SPAWN round={round_number} child={round_number+2}",
                  f"XDG_CLIENT START round={round_number} pid={round_number+2} fd=3 libwayland=1.24.0 xdg_shell=1",
                  f"XDG_CLIENT KEYMAP PASS round={round_number} bytes=60909",
                  f"SMITHAY_XDG CONFIGURE round={round_number} phase=initial serial={serial} width=64 height=48 activated=1",
                  f"XDG_CLIENT CONFIGURE round={round_number} index=0 serial={serial} width=64 height=48 activated=1",
                  f"XDG_CLIENT ACK round={round_number} index=0 serial={serial}",
                  f"SMITHAY_XDG ACK round={round_number} phase=initial serial={serial}"]
        for frame in range(3):
            lines.append(gate.frame_ready(round_number, frame))
            if frame == 1:
                lines.append(f"XDG_CLIENT MOTION round={round_number} frame=1 x_fixed=5120 y_fixed=4864 dx=4 dy=3")
                lines += [f"XDG_CLIENT BUTTON round={round_number} frame=1 code=272 state={state}"
                          for state in (1, 0)]
            else:
                code, keysym = (30, 97) if frame == 0 else (16, 113)
                lines += [f"XDG_CLIENT KEY round={round_number} frame={frame} code={code} state={state} keysym={keysym}"
                          for state in (1, 0)]
            lines += [f"SMITHAY_XDG INPUT_FORWARDED round={round_number} frame={frame}"]
            if frame == 1:
                lines += [f"SMITHAY_XDG CONFIGURE round={round_number} phase=resize serial={serial+1} width=96 height=64 activated=1",
                          f"XDG_CLIENT CONFIGURE round={round_number} index=1 serial={serial+1} width=96 height=64 activated=1",
                          f"XDG_CLIENT ACK round={round_number} index=1 serial={serial+1}"]
            elif frame == 2:
                lines += [f"SMITHAY_XDG CLOSE round={round_number}",
                          f"XDG_CLIENT CLOSE round={round_number} count=1"]
            lines += [f"XDG_CLIENT CALLBACK round={round_number} frame={frame} time={round_number*100+frame}",
                      f"XDG_CLIENT FRAME PASS round={round_number} frame={frame} width={96 if frame == 2 else 64} "
                      f"height={64 if frame == 2 else 48} seed={[0,30,272][frame]} callback=1 after_import_write=1",
                      f"XDG_CLIENT RELEASE round={round_number} frame={frame} count=1"]
            if frame == 1:
                lines += [f"SMITHAY_XDG ACK round={round_number} phase=resize serial={serial+1}"]
        lines += [gate.client_done(round_number),
                  f"EL0 pid={round_number+2} Exited code=0 free_pages=56 esr=0x0 far=0x0",
                  gate.round_done(round_number)]
    lines += [gate.SUCCESS, "EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0"]
    return ("\r\n".join(lines)+"\r\n").encode()


def snapshots():
    before = {
        "ai": {},
        "OFD_OBJECTS": dict.fromkeys(("live", "references", "epolls", "watches", "fd_refs",
                                     "staged_refs", "inflight_refs", "staged_messages", "inflight_messages"), 0),
        "ANCILLARY_OBJECTS": dict.fromkeys(("messages", "references", "staged_messages",
                                          "inflight_messages", "staged_refs", "inflight_refs"), 0),
        "SHARED_OBJECTS": dict.fromkeys(("objects", "pages", "mappings", "description_refs",
                                       "mapping_refs", "grant_reserved", "grant_used"), 0),
    }
    before["SHARED_OBJECTS"].update(available="true", free_pages=4096, page_capacity=4096)
    after = copy.deepcopy(before)
    for domain in gate.DOMAINS:
        before["ai"][domain] = dict(requests=0, committed=0, denied=0, capacity=0, invalid=0,
                                   failed=0, ai=0, approved=0, proposals=0, grant_units=0, release_units=0)
        after["ai"][domain] = dict(requests=1, committed=1, denied=0, capacity=0, invalid=0,
                                  failed=0, ai=1, approved=1, proposals=1, grant_units=1, release_units=1)
    before["ai"]["display"] = dict(available="true", model=24577, phase="Idle", failed=0,
                                   admitted=0, submitted=0, completed=0, ai_admitted=0, guard_admitted=0)
    after["ai"]["display"] = dict(before["ai"]["display"], admitted=18, submitted=18, completed=18, ai_admitted=18)
    process = dict(parent_pid=0, state="Exited", code=0, exit_signal=0, esr=0, far=0, free_pages=64,
                   heap_pages=0, heap_free=4096, image_pages=0, image_free=4096, thread_count=0,
                   thread_peak=1, thread_admissions=0, rank_model=12289, cpu_model=12290,
                   ai_selections=1, syscalls=1)
    return before, after, {1: process}


class SmithayXdgVerificationTests(unittest.TestCase):
    def test_actual_elf_ai_rejection_is_fatal_before_waiting_for_frame_timeout(self):
        with self.assertRaises(AssertionError):
            gate.check_console(b"posix exec smithay-xdg-probe\r\nELF start failed: Nomem\r\n")

    def test_configure_requires_same_fresh_serial_and_exact_acked_state(self):
        good = valid_log()
        self.assertEqual(gate.validate(good)["configure_serials"], [101, 102, 201, 202])
        for old, new in (
            (b"index=0 serial=101", b"index=0 serial=100"),
            (b"phase=resize serial=102", b"phase=resize serial=101"),
            (b"serial=201", b"serial=101"),
            (b"serial=102", b"serial=0"),
            (b"serial=102", b"serial=4294967296"),
            (b"width=96 height=64 activated=1", b"width=64 height=48 activated=1"),
            (b"activated=1", b"activated=0"),
        ):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new))
        ack = b"SMITHAY_XDG ACK round=1 phase=initial serial=101\r\n"
        ready = gate.frame_ready(1, 0).encode()+b"\r\n"
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(ack, b"").replace(ready, ready+ack))

    def test_close_and_resize_events_cannot_precede_triggering_native_input(self):
        good = valid_log()
        for prefix, anchor in (
            (b"SMITHAY_XDG CONFIGURE round=1 phase=resize ", gate.frame_ready(1, 1).encode()),
            (b"XDG_CLIENT CLOSE round=1 ", gate.frame_ready(1, 2).encode()),
        ):
            line = next(row for row in good.splitlines(keepends=True) if row.startswith(prefix))
            with self.subTest(prefix=prefix), self.assertRaises(AssertionError):
                gate.validate(good.replace(line, b"").replace(anchor, line+anchor))

    def test_negative_connection_must_decode_same_object_error_then_recover(self):
        good = valid_log()
        self.assertEqual(gate.validate(good)["rejected_object"], 9)
        for old, new in (
            (b"error=3 object=9", b"error=3 object=10"),
            (b"code=3 object=9", b"code=2 object=9"),
            (b"object=9", b"object=0"),
            (b"interface=xdg_surface", b"interface=wl_display"),
            (b"disconnected=1", b"disconnected=0"),
            (b"START round=1 pid=3", b"START round=1 pid=2"),
        ):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new))

    def test_release_can_be_early_after_import_but_never_before_buffer_creation(self):
        good = valid_log()
        release = b"XDG_CLIENT RELEASE round=1 frame=0 count=1\r\n"
        ready = gate.frame_ready(1, 0).encode()
        early = good.replace(release, b"").replace(ready, release+ready)
        self.assertEqual(gate.validate(early)["frames"], 6)
        too_early = good.replace(release, b"").replace(b"XDG_CLIENT KEYMAP PASS round=1 ",
                                                     release+b"XDG_CLIENT KEYMAP PASS round=1 ")
        with self.assertRaises(AssertionError):
            gate.validate(too_early)

    def test_conflicting_build_input_hash_cannot_be_overwritten_by_current_file(self):
        path = Path("builder.py")
        inputs = {path: "frozen-build-hash"}
        gate.bind_inputs(inputs, {path: "frozen-build-hash"})
        with self.assertRaises(AssertionError):
            gate.bind_inputs(inputs, {path: "changed-current-hash"})
        self.assertEqual(inputs[path], "frozen-build-hash")

    def test_all_independent_protocol_observations_required(self):
        good = valid_log()
        self.assertEqual(gate.validate(good)["pixels"], 73728)
        for row in good.splitlines():
            if row.startswith((b"SMITHAY", b"XDG_CLIENT")):
                for bad in (good.replace(row+b"\r\n", b""),
                            good.replace(row+b"\r\n", (row+b"\r\n")*2)):
                    with self.subTest(row=row), self.assertRaises(AssertionError):
                        gate.validate(bad)
        for old, new in ((b"releases=3", b"releases=0"), (b"seed=30", b"seed=0"),
                         (b"keysym=97", b"keysym=113"), (b"cosmic=0", b"cosmic=1"),
                         (b"x_fixed=5120", b"x_fixed=4096"), (b"state=0", b"state=1"),
                         (b"callback=1", b"callback=2"), (b"bytes=60909", b"bytes=0")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        with self.assertRaises(AssertionError):
            gate.validate(good+b"noise XDG_CLIENT RESULT PASS\r\n")

    def test_input_must_follow_present_barrier_and_actual_child_exit(self):
        good = valid_log()
        row = b"XDG_CLIENT KEY round=1 frame=0 code=30 state=1 keysym=97\r\n"
        moved = good.replace(row, b"").replace(gate.frame_ready(1, 0).encode(), row+gate.frame_ready(1, 0).encode())
        with self.assertRaises(AssertionError):
            gate.validate(moved)
        for old, new in ((b"code=0 free_pages=56", b"code=139 free_pages=56"),
                         (b"esr=0x0", b"esr=0x96000004"), (b"far=0x0", b"far=0x18"),
                         (b"free_pages=64", b"free_pages=63")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                gate.validate(good.replace(old, new, 1))
        with self.assertRaises(AssertionError):
            gate.validate(good.replace(b"EL0 pid=3 Exited code=0 free_pages=56 esr=0x0 far=0x0\r\n", b""))
        frame_done = next(row for row in good.splitlines(keepends=True) if
                          row.startswith(b"XDG_CLIENT FRAME PASS round=1 frame=0"))
        late_done = good.replace(frame_done, b"").replace(
            gate.frame_ready(1, 1).encode()+b"\r\n", gate.frame_ready(1, 1).encode()+b"\r\n"+frame_done)
        with self.assertRaises(AssertionError):
            gate.validate(late_done)

    def test_wait_requires_one_complete_lf_or_crlf_line(self):
        marker = gate.frame_ready(1, 0).encode()
        for ending in (b"\n", b"\r\n"):
            guest = SimpleNamespace(text=marker+ending, poll=lambda: None)
            self.assertEqual(gate.wait_marker(guest, 0, marker), guest.text)
        for data in (b"prefix "+marker+b"\n", marker+b" suffix\n", marker, marker+b"\r"):
            guest = SimpleNamespace(text=data, poll=lambda: None)
            with self.subTest(data=data), patch.object(gate.time, "monotonic", side_effect=[0, 0, 2]), \
                    patch.object(gate.time, "sleep"), self.assertRaises(TimeoutError):
                gate.wait_marker(guest, 0, marker, timeout=1)

    def test_scanout_polling_never_advances_input_and_rejects_premature_callbacks(self):
        waiting = (gate.frame_ready(1, 0)+"\n").encode()
        guest = SimpleNamespace(text=waiting, poll=lambda: None)
        calls = []
        guest.qmp = SimpleNamespace(execute=lambda command, args: calls.append((command, args)))
        with tempfile.TemporaryDirectory() as directory, patch.object(gate.time, "sleep"), \
                patch.object(gate, "scanout", side_effect=[AssertionError("refresh pending"), {"pixels": 12288}]):
            result = gate.capture(guest, 0, Path(directory)/"capture.ppm", 1, 0)
        self.assertEqual(result["capture_attempts"], 2)
        self.assertEqual([row[0] for row in calls], ["screendump", "screendump"])
        for kind in ("KEY", "BUTTON", "MOTION", "CALLBACK", "FRAME PASS"):
            guest.text = waiting + f"XDG_CLIENT {kind} round=1 frame=0 unexpected=1\n".encode()
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                gate.frame_waiting(guest.text, 1, 0)
        guest.text = waiting+b"SMITHAY_XDG INPUT_FORWARDED round=1 frame=0\n"
        with self.assertRaises(AssertionError):
            gate.frame_waiting(guest.text, 1, 0)

    def test_qmp_requires_each_actual_scanout_before_exact_physical_input(self):
        transcript, witnesses = [], []

        def command(name, arguments):
            identity = sum(row["direction"] == "send" for row in transcript)+1
            transcript.append(dict(direction="send", message=dict(
                execute=name, arguments=arguments, id=identity)))
            transcript.append(dict(direction="receive", message={"return": {}, "id": identity}))
            return identity

        command("qmp_capabilities", {})
        for round_number in (1, 2):
            for frame in range(3):
                path = str(Path(f"round-{round_number}-frame-{frame}.ppm").resolve())
                capture_id = command("screendump", {"filename": path})
                first_input = capture_id+1
                for events in gate.input_events(frame):
                    last_input = command("input-send-event", {"events": events})
                witnesses.append(dict(round=round_number, frame=frame, path=path,
                                      capture_attempts=1, capture_qmp_id=capture_id,
                                      input_first_qmp_id=first_input, input_last_qmp_id=last_input,
                                      captured_at=1, input_started_at=2, input_finished_at=3))
        command("quit", {})
        self.assertEqual(gate.validate_qmp(transcript, witnesses)["input_commands"], 14)
        for change in ("missing", "early", "wrong_key", "extra_input", "wrong_path",
                       "missing_reply", "error_reply", "duplicate_reply", "duplicate_id", "no_quit"):
            bad = copy.deepcopy(transcript)
            if change == "missing":
                del bad[2]
            elif change == "early":
                bad[2], bad[4] = bad[4], bad[2]
            elif change == "wrong_key":
                bad[4]["message"]["arguments"]["events"][0]["data"]["key"]["data"] = "q"
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

    def test_real_scanout_checks_surface_channels_background_and_dimensions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.ppm"
            header = b"P6\n1024 768\n255\n"
            pixels = bytearray(1024*768*3)
            for y in range(gate.HEIGHT):
                for x in range(gate.WIDTH):
                    at = ((gate.Y+y)*1024+gate.X+x)*3
                    pixels[at:at+3] = gate.expected_pixel(2, 1, x, y)
            path.write_bytes(header+pixels)
            self.assertEqual(gate.scanout(path, 2, 1)["pixels"], 12288)
            for x, y in ((3, 4), (127, 95), (64, 0)):
                bad = pixels.copy()
                bad[((gate.Y+y)*1024+gate.X+x)*3] ^= 1
                path.write_bytes(header+bad)
                with self.assertRaises(AssertionError):
                    gate.scanout(path, 2, 1)
            path.write_bytes(header+pixels)
            with self.assertRaises(AssertionError):
                gate.scanout(path, 2, 0)
            path.write_bytes(header.replace(b"1024 768", b"128 96")+pixels)
            with self.assertRaises(AssertionError):
                gate.scanout(path, 2, 1)

    def test_grants_objects_faults_and_gpu_fences_cannot_be_left_live(self):
        before, after, processes = snapshots()
        # Unix sockets use an existing fixed pool; admission carries no page grant.
        after["ai"]["unix"].update(grant_units=0, release_units=0)
        gate.validate_resources(before, after, processes, 4096)
        for section, field, value in (("OFD_OBJECTS", "watches", 1),
                                      ("ANCILLARY_OBJECTS", "references", 1),
                                      ("SHARED_OBJECTS", "pages", 1)):
            bad = copy.deepcopy(after)
            bad[section][field] = value
            with self.assertRaises(AssertionError):
                gate.validate_resources(before, bad, processes, 4096)
        for domain, field, value in (("anonymous", "release_units", 0),
                                      ("shared_mappings", "ai", 0),
                                      ("display", "completed", 17), ("display", "failed", 1),
                                      ("display", "phase", "Pending"), ("display", "ai_admitted", 0)):
            bad = copy.deepcopy(after)
            bad["ai"][domain][field] = value
            with self.assertRaises(AssertionError):
                gate.validate_resources(before, bad, processes, 4096)
        bad = copy.deepcopy(after)
        bad["ai"]["anonymous"].update(requests=2, denied=1)
        with self.assertRaises(AssertionError):
            gate.validate_resources(before, bad, processes, 4096)
        bad = copy.deepcopy(after)
        bad["ai"]["display"].update(ai_admitted=17, guard_admitted=1)
        with self.assertRaises(AssertionError):
            gate.validate_resources(before, bad, processes, 4096)
        bad = copy.deepcopy(processes)
        bad[1]["exit_signal"] = 11
        with self.assertRaises(AssertionError):
            gate.validate_resources(before, after, bad, 4096)

    def test_preserve_prior_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            path = output / "summary.json"
            path.write_text("original failure")
            with self.assertRaises(FileExistsError):
                gate.verify(output/"kernel", output/"server", output/"client", output)
            self.assertEqual(path.read_text(), "original failure")


if __name__ == "__main__":
    unittest.main()
