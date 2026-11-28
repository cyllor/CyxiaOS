"""Independent byte reference for the G1 snapshot v4 endpoint and request store."""

from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
from struct import pack, pack_into, unpack, unpack_from


FIXTURE = Path(__file__).parent / "fixtures/v020-g1-snapshot-wire.tsv"
UUID = b"CYX-D7-WIRE-0001"
DURABLE = {0x20, 0x21, 0x22, 0x23, 0x27, 0x28, 0x29}
VIEW = {0x20, 0x23, 0x29}
OUT = {0x20: 72, 0x21: 64, 0x22: 56, 0x23: 96, 0x27: 16, 0x28: 16, 0x29: 16}
ROW_STATES = {1: 2, 2: 3, 3: 6, 4: 4, 5: 5}


def check(condition, reason="invalid"):
    if not condition:
        raise ValueError(reason)


def integer(raw, offset, code="Q"):
    return unpack_from("<" + code, raw, offset)[0]


def sealed(raw, offset):
    """Bitwise reflected Castagnoli, independent of the Rust table implementation."""
    result = bytearray(raw)
    result[offset:offset + 4] = bytes(4)
    crc = 0xFFFFFFFF
    for byte in result:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    pack_into("<I", result, offset, crc ^ 0xFFFFFFFF)
    return bytes(result)


def file_key(slot, generation, seq):
    return pack("<16sIQQ", UUID, slot, generation, seq)


def read_file_key(raw):
    uuid, slot, generation, seq = unpack("<16sIQQ", raw)
    check(any(uuid) and slot < 16 and generation and seq)
    return uuid, slot, generation, seq


def read_snapshot_key(raw):
    uuid, snapshot_id, slot, reserved, generation = unpack("<16sQIIQ", raw)
    check(any(uuid) and snapshot_id and slot < 8 and reserved == 0 and generation)
    return uuid, snapshot_id, slot, generation


def frame(op, req_id, body=b"", key=b"", epoch=0, context=0, version=4, magic=0x43594651):
    prefix = key + (pack("<Q", epoch) if op in VIEW else b"")
    return pack("<IHHHHIQQ", magic, version, 32, op, 0, len(prefix + body), req_id, context) + prefix + body


def body_fields(op, body):
    if op == 0x20:
        duration, slot_class, count = unpack("<QII", body)
        check(duration and slot_class in (1, 2) and count == 1)
    elif op in (0x21, 0x23):
        check(len(body) == 48)
        read_snapshot_key(body[:40])
        if op == 0x21:
            check(integer(body, 40))
        else:
            mode, reserved = unpack("<II", body[40:])
            check(mode in (1, 2) and reserved == 0)
    elif op in (0x22, 0x25):
        read_snapshot_key(body)
    elif op == 0x24:
        check(not body)
    elif op == 0x26:
        read_snapshot_key(body[:40])
        length, reserved = unpack("<H6s", body[40:48])
        path = body[48:]
        path.decode("utf-8")
        check(length == len(path) and 0 < length <= 512 and not any(reserved))
        check(path.startswith(b"/") and b"\0" not in path)
        check(path == b"/" or all(
            0 < len(part) <= 63 and part not in (b".", b"..") for part in path[1:].split(b"/")
        ))
    elif op == 0x27:
        gen, _, reserved = unpack("<QII", body)
        check(gen and reserved == 0)
    elif op == 0x28:
        check(unpack("<Q", body)[0])
    elif op == 0x29:
        check(len(body) == 48 and integer(body, 0) and not any(body[44:]))
        read_file_key(body[8:44])
    elif op == 0x2A:
        read_file_key(body)
    elif op == 0x2B:
        check(len(body) == 68 and any(body[36:]))
        read_file_key(body[:36])
    else:
        raise ValueError("invalid")


def read_request(raw, selector):
    check(32 <= len(raw) <= 1024)
    magic, version, header, op, flags, length, req_id, context = unpack_from("<IHHHHIQQ", raw)
    check(magic != 0x43594632, "schema")
    check(magic == 0x43594651)
    check(version == 4, "schema")
    check(header == 32 and flags == 0 and length == len(raw) - 32 and req_id and context == 0)
    check(0x20 <= op <= 0x2B)
    check(bool(selector) == (op <= 0x29), "selector")
    body = raw[32:]
    key = b""
    epoch = 0
    if op in DURABLE:
        key, body = body[:36], body[36:]
        check(read_file_key(key)[3] == req_id)
    if op in VIEW:
        epoch, body = integer(body, 0), body[8:]
        check(epoch)
    body_fields(op, body)
    if op in (0x2A, 0x2B):
        check(read_file_key(body[:36])[3] == req_id)
    if op in (0x21, 0x22, 0x23):
        check(body[:16] == key[:16])
    if op == 0x29:
        check(body[8:24] == key[:16] and body[8:44] != key)
    return op, req_id, key, epoch, body


def mutation_digest(op, key, epoch, body):
    return sha256(b"CYXIA-SNAP-REQ-V1" + pack("<HH", 4, op) + key + pack("<QI", epoch, len(body)) + body).digest()


def record(req, *, state, snapshot=b"", new_view=0, log=0, txid=0, code=0, payload=None, lsn=0):
    op, _, key, epoch, body = req
    data = body if payload is None else payload
    mode = integer(body, 40, "I") if op == 0x23 else 0
    raw = bytearray(512)
    pack_into("<IHHIH", raw, 0, 0x43594652, 1, 512, state, op)
    raw[16:52] = key
    raw[52:84] = mutation_digest(op, key, epoch, body)
    if snapshot:
        raw[88:128] = snapshot
    pack_into("<QQ16sQQiI", raw, 128, epoch, new_view, key[:16] if log else bytes(16), log, txid, code, mode)
    pack_into("<I", raw, 216, len(data))
    raw[220:220 + len(data)] = data
    pack_into("<Q", raw, 348, lsn)
    if state in (2, 3, 4):
        raw[184:216] = sha256(raw).digest()
    return sealed(raw, 508)


def verify_outcome(op, data, snapshot, lsn, log, tx, old, new):
    check(len(data) == OUT[op])
    if op in (0x27, 0x28, 0x29):
        gen, freeze, gate = unpack("<QII", data)
        check(gen and freeze in (0, 1) and gate in (0, 1))
        check(op != 0x27 or (freeze, gate) == (1, 1))
        check(op != 0x28 or freeze == 0)
        check(op != 0x29 or gate == 0)
        if old is not None:
            check(new == (old if op == 0x29 else 0))
        return
    read_snapshot_key(data[:40])
    check(snapshot is None or data[:40] == snapshot)
    if op == 0x20:
        view, capture, created, limit = unpack("<QQQQ", data[40:])
        check(view and capture < lsn and created < limit)
        check(old is None or old == new == view)
    elif op == 0x21:
        previous, limit, age = unpack("<QQQ", data[40:])
        check(previous and limit > max(previous, age))
    elif op == 0x22:
        drop, phase, reserved = unpack("<QII", data[40:])
        check(drop == lsn and phase == 1 and reserved == 0)
    elif op == 0x23:
        before, after, uuid, epoch, txn, gate, reserved = unpack("<QQ16sQQII", data[40:])
        check(before and after == before + 1 and uuid == data[:16])
        check(epoch == log and txn == tx and gate == 1 and reserved == 0)
        check(old is None or (old, new) == (before, after))


def read_record(raw):
    check(len(raw) == 512 and sealed(raw, 508) == raw)
    magic, version, length, state, op, reserved = unpack_from("<IHHIHH", raw)
    check((magic, version, length, reserved) == (0x43594652, 1, 512, 0))
    check(state in ROW_STATES and op in DURABLE and not any(raw[84:88]) and not any(raw[356:508]))
    key = read_file_key(raw[16:52])
    snapshot = raw[88:128]
    if any(snapshot):
        check(read_snapshot_key(snapshot)[0] == key[0])
    before, after, tx_uuid, log, txid, code, mode = unpack_from("<QQ16sQQiI", raw, 128)
    lsn = integer(raw, 348)
    check(len(raw) == 512 and any(raw[52:84]) and bool(log) == bool(txid))
    check(tx_uuid == (key[0] if log else bytes(16)))
    check(bool(before) == (op in VIEW) and (mode in (1, 2) if op == 0x23 else mode == 0))
    n = integer(raw, 216, "I")
    check(n <= 128 and not any(raw[220 + n:348]))
    data = raw[220:220 + n]
    if state in (1, 5):
        check(lsn == after == 0 and not any(raw[184:216]))
        check((log == 0 and code == 0) if state == 1 else code < 0)
        body_fields(op, data)
        check(snapshot == (data[:40] if op in (0x21, 0x22, 0x23) else bytes(40)))
        check(op != 0x23 or mode == integer(data, 40, "I"))
        check(op != 0x29 or (data[8:24] == key[0] and data[8:44] != raw[16:52]))
        check(raw[52:84] == mutation_digest(op, raw[16:52], before, data))
    else:
        check(log and lsn)
        check(raw[184:216] == sha256(raw[:184] + bytes(32) + raw[216:508] + bytes(4)).digest())
        if state == 2:
            check(code == 0 and bool(any(snapshot)) == (0x20 <= op <= 0x23))
            verify_outcome(op, data, snapshot if any(snapshot) else None, lsn, log, txid, before, after)
            check(op in VIEW or after == 0)
        else:
            check(code < 0 and after == 0 and n == 0)
    return key, state, code, log, txid, lsn, after, raw[184:216]


def header(marks, uuid=UUID, generation=9):
    raw = bytearray(4096)
    pack_into("<IHH16sQ", raw, 0, 0x43595152, 1, 40, uuid, generation)
    pack_into("<8H", raw, 40, 1, 128, 512, 64, 16, 48, 8, 8)
    for slot in range(16):
        client_generation, seq = marks.get(slot, (0, 0))
        row = bytearray(128)
        pack_into("<IHHIIQQ", row, 0, 0x4359574D, 1, 128, slot, 0, client_generation, seq)
        raw[512 + 128 * slot:640 + 128 * slot] = sealed(row, 124)
    return sealed(raw, 32)


def read_header(raw):
    check(len(raw) == 4096 and sealed(raw, 32) == raw)
    magic, version, length, uuid, gen, _, reserved = unpack_from("<IHH16sQII", raw)
    check((magic, version, length, reserved) == (0x43595152, 1, 40, 0) and any(uuid) and gen)
    if not any(raw[40:]):
        return uuid, gen, ()
    check(unpack_from("<8H", raw, 40) == (1, 128, 512, 64, 16, 48, 8, 8))
    check(not any(raw[56:512]) and not any(raw[2560:]))
    marks = []
    for slot in range(16):
        row = raw[512 + 128 * slot:640 + 128 * slot]
        check(sealed(row, 124) == row)
        magic, vers, length, row_slot, reserved, generation, seq = unpack_from("<IHHIIQQ", row)
        check((magic, vers, length, row_slot, reserved) == (0x4359574D, 1, 128, slot, 0))
        check(not any(row[32:124]) and (generation or seq == 0))
        marks.append((generation, seq))
    return uuid, gen, marks


def reply(req_id, output=b"", *, state=0, code=0, lsn=0, log=0, txid=0, target=0, digest=bytes(32)):
    return pack("<IHHQQHHiII5Q32sQQ",
                0x43594652, 3, 128, req_id, 7, state, 0, code, 0, len(output),
                lsn, log, txid, 0, target, digest, req_id if state else 0, 0) + output


def read_reply(raw, request):
    op, req_id, key, view_epoch, body = request
    check(128 <= len(raw) <= 2048)
    magic, ver, head, rid, service, state, flags, code, prefix, length, lsn, log, txid, cap, target, digest, ref, write = unpack_from(
        "<IHHQQHHiII5Q32sQQ", raw
    )
    output = raw[128:]
    check((magic, ver, head, rid) == (0x43594652, 3, 128, req_id) and service and code <= 0)
    check(flags == prefix == cap == write == 0 and length == len(output))
    if state:
        check(op in DURABLE or op == 0x2A)
        check(ref == rid and state in ROW_STATES.values() and (state == 3) == (code == 0))
        terminal = state in (3, 4, 6)
        check(all(bool(value) == terminal for value in (any(digest), lsn, log, txid)))
        if op == 0x2A:
            key, row_state, row_code, row_log, row_tx, row_lsn, row_view, row_digest = read_record(output)
            check(key == read_file_key(body) and state == ROW_STATES[row_state])
            check((code, lsn, target, digest) == (-11 if row_state == 1 else row_code, row_lsn, row_view, row_digest))
            check((log, txid) == ((row_log, row_tx) if terminal else (0, 0)))
        elif state == 3:
            snapshot = body[:40] if op in (0x21, 0x22, 0x23) else None
            verify_outcome(op, output, snapshot, lsn, log, txid, None, None)
            check(op not in range(0x20, 0x24) or output[:16] == key[:16])
            check(op not in (0x20, 0x23) or integer(output, 40) == view_epoch)
            check(op not in (0x27, 0x28, 0x29) or integer(output, 0) == integer(body, 0) + 1)
            check(target == (integer(output, 48) if op == 0x23 else view_epoch))
        else:
            check(not output and target == 0)
    else:
        check(ref == lsn == log == txid == 0 and not any(digest))
        if code < 0:
            check(not output)
        elif op in (0x24, 0x25):
            count, freeze, age, view, pgen, gate, phase, reserved = unpack_from("<II3QII8s", output)
            check(len(output) == 48 + 128 * count and count <= 8 and view and pgen)
            check(op != 0x25 or count == 1)
            check(freeze in (0, 1) and gate in (0, 1) and phase <= 2 and (gate or phase == 0))
            check(not any(reserved))
            previous = None
            for index in range(count):
                row = output[48 + 128 * index:176 + 128 * index]
                key = read_snapshot_key(row[:40])
                slot = key[2]
                slot_class, entry_state, captured_view, capture_lsn, born, deadline, retain_gen, drop, metadata, refs = unpack_from("<II6QII", row, 40)
                check(op != 0x25 or row[:40] == body)
                check(previous is None or (previous[0] == key[0] and previous[2] < slot))
                check(slot_class == (1 if slot < 6 else 2) and captured_view and retain_gen)
                check(born < deadline and metadata == 1 and not any(row[104:]))
                check((entry_state == 1 and drop == 0) or (entry_state == 2 and drop > capture_lsn))
                previous = key
        elif op == 0x26:
            check(unpack("<Q", output)[0])
        else:
            check(op == 0x2B and not output)


def changed(raw, offset, data):
    return raw[:offset] + data + raw[offset + len(data):]


def vectors():
    from struct import error

    cases = []
    requests = {}

    def add(name, kind, context, verdict, raw):
        try:
            if kind == "request":
                parsed = read_request(raw, int(context))
                if verdict == "accept":
                    requests[name] = parsed
            elif kind == "record":
                read_record(raw)
            elif kind == "header":
                read_header(raw)
            elif kind == "reply":
                read_reply(raw, requests[context])
        except (ValueError, error) as exc:
            actual = str(exc) if str(exc) in ("schema", "selector") else "invalid"
        else:
            actual = "accept"
        check(actual == verdict, f"{name}: expected {verdict}; reference verdict {actual}")
        cases.append((name, kind, context, verdict, raw))

    snapshot = pack("<16sQIIQ", UUID, 71, 6, 0, 12)
    ordinary = file_key(1, 4, 1)
    restored = file_key(15, 3, 4)
    opened = file_key(15, 3, 5)
    path = "/团队/报告.txt".encode()
    req_specs = [
        ("create", 0x20, 1, pack("<QII", 3600_000_000_000, 2, 1), ordinary, 2),
        ("extend", 0x21, 2, snapshot + pack("<Q", 7200_000_000_000), file_key(1, 4, 2), 0),
        ("delete", 0x22, 3, snapshot, file_key(1, 4, 3), 0),
        ("restore", 0x23, 4, snapshot + pack("<II", 2, 0), restored, 2),
        ("list", 0x24, 9, b"", b"", 0),
        ("query", 0x25, 10, snapshot, b"", 0),
        ("history", 0x26, 11, snapshot + pack("<H6x", len(path)) + path, b"", 0),
        ("freeze", 0x27, 6, pack("<QII", 7, 1, 0), file_key(15, 3, 6), 0),
        ("clear", 0x28, 7, pack("<Q", 8), file_key(15, 3, 7), 0),
        ("open", 0x29, 5, pack("<Q", 9) + restored + bytes(4), opened, 3),
        ("request-query", 0x2A, 4, restored, b"", 0),
        ("unknown-query", 0x2A, 2, file_key(1, 4, 2), b"", 0),
        ("ack", 0x2B, 4, restored + bytes(range(32)), b"", 0),
    ]
    raw_reqs = {}
    for name, op, req_id, body, key, epoch in req_specs:
        raw = frame(op, req_id, body, key, epoch)
        add(name, "request", 73 if op <= 0x29 else 0, "accept", raw)
        raw_reqs[name] = raw
    wrong = (
        ("old-abi", "schema", changed(raw_reqs["list"], 4, pack("<H", 2)), 73),
        ("old-magic", "schema", changed(raw_reqs["list"], 0, pack("<I", 0x43594632)), 73),
        ("internal-context", "invalid", changed(raw_reqs["create"], 24, pack("<Q", 1)), 73),
        ("wrong-id", "invalid", changed(raw_reqs["open"], 16, pack("<Q", 4)), 73),
        ("missing-view", "invalid", changed(raw_reqs["restore"], 68, bytes(8)), 73),
        ("foreign-restore", "invalid", changed(raw_reqs["open"], 84, bytes(range(16))), 73),
        ("self-restore-proof", "invalid", changed(raw_reqs["open"], 84, opened), 73),
        ("reserved-create", "invalid", changed(raw_reqs["create"], 88, pack("<I", 0)), 73),
        ("history-parent", "invalid", frame(0x26, 11, snapshot + pack("<H6x", 5) + b"/a/.."), 73),
        ("no-selector", "selector", raw_reqs["query"], 0),
        ("ack-selector", "selector", raw_reqs["ack"], 73),
        ("empty-ack-digest", "invalid", changed(raw_reqs["ack"], 68, bytes(32)), 0),
        ("wrong-key-id", "invalid", changed(raw_reqs["request-query"], 16, pack("<Q", 5)), 0),
        ("long-rest", "invalid", raw_reqs["restore"] + b"\0", 73),
    )
    for name, verdict, raw, selector in wrong:
        add(name, "request", selector, verdict, raw)

    pending = record(requests["create"], state=1)
    uncertain = record(requests["extend"], state=5, snapshot=snapshot, log=7, txid=12, code=-6)
    restore_out = snapshot + pack("<QQ16sQQII", 2, 3, UUID, 8, 15, 1, 0)
    terminal = record(requests["restore"], state=2, snapshot=snapshot, new_view=3,
                      log=8, txid=15, payload=restore_out, lsn=101)
    opening = record(requests["open"], state=2, new_view=3, log=8, txid=16,
                     payload=pack("<QII", 10, 1, 0), lsn=107)
    failed = record(requests["delete"], state=3, snapshot=snapshot, code=-10,
                    payload=b"", log=8, txid=17, lsn=110)
    incomplete = record(requests["restore"], state=4, snapshot=snapshot, code=-6,
                        payload=b"", log=8, txid=18, lsn=113)
    for name, raw in (("pending", pending), ("unknown", uncertain), ("restored", terminal),
                      ("opened", opening), ("failed", failed), ("incomplete", incomplete)):
        add(name, "record", "-", "accept", raw)
    add("torn-record", "record", "-", "invalid", changed(terminal, 508, bytes(4)))
    add("bad-result-digest", "record", "-", "invalid", sealed(changed(terminal, 184, bytes(32)), 508))
    add("unknown-success", "record", "-", "invalid", sealed(changed(uncertain, 176, bytes(4)), 508))
    add("pending-bad-digest", "record", "-", "invalid", sealed(changed(pending, 52, bytes(range(32))), 508))
    head = header({1: (4, 3), 15: (3, 5)})
    empty = sealed(pack("<IHH16sQ", 0x43595152, 1, 40, UUID, 1) + bytes(4064), 32)
    add("header", "header", "-", "accept", head)
    add("genesis-header", "header", "-", "accept", empty)
    add("aliased-ordinary-reserve", "header", "-", "invalid", sealed(changed(head, 50, pack("<H", 56)), 32))
    add("invalid-watermark-crc", "header", "-", "invalid", sealed(changed(head, 512 + 128 + 124, bytes(4)), 32))

    status = pack("<IIQQQII8x", 1, 1, 37, 3, 10, 1, 2)
    summary = snapshot + pack("<II6QII24x", 2, 1, 2, 13, 9, 8100, 3, 0, 1, 4)
    # All seven successful mutation reply bodies use independent fixed bytes.
    successes = (
        ("create", snapshot + pack("<4Q", 2, 19, 6, 100), snapshot, 2, 41),
        ("extend", snapshot + pack("<3Q", 100, 110, 8), snapshot, 0, 45),
        ("delete", snapshot + pack("<QII", 49, 1, 0), snapshot, 0, 49),
        ("freeze", pack("<QII", 8, 1, 1), b"", 0, 57),
        ("clear", pack("<QII", 9, 0, 1), b"", 0, 61),
        ("open", pack("<QII", 10, 1, 0), b"", 3, 107),
    )
    for context, output, selected, target, lsn in successes:
        _, rid, _, _, _ = requests[context]
        durable = record(requests[context], state=2, snapshot=selected, new_view=target,
                         log=8, txid=16, payload=output, lsn=lsn)
        add(context + "-result", "reply", context, "accept",
            reply(rid, output, state=3, lsn=lsn, log=8, txid=16, target=target, digest=durable[184:216]))
    for name, context, raw in (
        ("list-result", "list", reply(9, status + summary, target=4)),
        ("query-result", "query", reply(10, status + summary, target=4)),
        ("history-result", "history", reply(11, pack("<Q", 987654321))),
        ("restore-result", "restore", reply(4, restore_out, state=3, lsn=101, log=8, txid=15, target=3, digest=terminal[184:216])),
        ("durable-result", "request-query", reply(4, terminal, state=3, lsn=101, log=8, txid=15, target=3, digest=terminal[184:216])),
        ("durable-unknown", "unknown-query", reply(2, uncertain, state=5, code=-6)),
        ("ack-result", "ack", reply(4)),
    ):
        add(name, "reply", context, "accept", raw)
    add("bad-reply-count", "reply", "list", "invalid", reply(9, pack("<I", 2) + status[4:] + summary))
    add("bogus-open-phase", "reply", "list", "invalid", reply(9, changed(status, 32, bytes(4)) + summary))
    add("unproved-success", "reply", "restore", "invalid", reply(4))
    add("wrong-restored-target", "reply", "restore", "invalid",
        reply(4, restore_out, state=3, lsn=101, log=8, txid=15, target=4, digest=terminal[184:216]))
    add("freeze-open", "reply", "freeze", "invalid",
        reply(6, pack("<QII", 8, 1, 0), state=3, lsn=57, log=8, txid=16, digest=terminal[184:216]))
    add("unknown-success-reply", "reply", "unknown-query", "invalid", reply(2, uncertain, state=5))
    add("uncorrelated-query-key", "reply", "request-query", "invalid", reply(4, uncertain, state=5, code=-6))
    return cases


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print the canonical TSV")
    args = parser.parse_args()
    cases = vectors()
    expected = "# name\tkind\tcontext\tverdict\thex\n" + "".join(
        f"{name}\t{kind}\t{context}\t{verdict}\t{raw.hex()}\n"
        for name, kind, context, verdict, raw in cases
    )
    if args.emit:
        print(expected, end="")
    elif FIXTURE.read_text(encoding="ascii") != expected:
        raise SystemExit(f"G1 snapshot wire vectors differ from {FIXTURE}")
    else:
        print(f"{len(cases)} independent G1 snapshot requests, replies and store vectors match")
