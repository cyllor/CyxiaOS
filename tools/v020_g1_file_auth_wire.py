"""Independent V0.19.9 §9.6.1 FILE_AUTH codec and digest vectors."""

from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
from struct import Struct, pack


FIXTURE = Path(__file__).parent / "fixtures/v020-g1-file-auth-wire.tsv"
ADMIT = "admit-request"
ADMIT_REPLY = "admit-reply"
COMPLETE = "complete-request"
COMPLETE_REPLY = "complete-reply"
CODECS = {
    ADMIT: Struct("<IHH7Q32s32s"),
    ADMIT_REPLY: Struct("<IHHQH6s3Q"),
    COMPLETE: Struct("<IHHQH6s32s"),
    COMPLETE_REPLY: Struct("<iI"),
}
HEADERS = {
    ADMIT: (0x43595646, 3, 128),
    ADMIT_REPLY: (0x43595652, 3, 48),
    COMPLETE: (0x43594643, 1, 56),
}
FILE_REQUEST_HEADER = Struct("<IHHHHIQQ")
BOOT = 0x0102030405060708
CONTEXT = 0x1122334455667788
ADMISSION = 0xFEDCBA9876543210
SEQUENCE = 0x0100000000000029


def require(condition):
    if not condition:
        raise ValueError("invalid FILE_AUTH wire")


def matches_header(kind, raw):
    return (
        len(raw) == CODECS[kind].size
        and raw[:8] == pack("<IHH", *HEADERS[kind])
    )


def decode(kind, raw):
    codec = CODECS[kind]
    require(len(raw) == codec.size)
    if kind in HEADERS:
        require(matches_header(kind, raw))
    fields = codec.unpack(raw)
    if kind == ADMIT_REPLY:
        _, _, _, _, verdict, reserved, _, admission, accepted = fields
        require(not any(reserved) and verdict in range(5))
        require(admission != 0 if verdict == 1 else admission == accepted == 0)
    elif kind == COMPLETE:
        _, _, _, admission, state, reserved, evidence = fields
        require(admission and not any(reserved) and state in range(1, 5))
        require(state == 3 or any(evidence))
    elif kind == COMPLETE_REPLY:
        require(fields[1] == 0)
    return fields


def frozen_digest(data):
    return sha256(data).digest() if data else bytes(32)


def operation_digest(boot, original, proposal):
    require(len(original) >= 32)
    magic, version, header, _, _, size, _, _ = FILE_REQUEST_HEADER.unpack_from(original)
    require((magic, version, header) == (0x43594651, 4, 32) and len(original) == header + size)
    # The caller has already validated the FileServiceRequest operation and payload.
    original_digest = sha256(original[:24] + bytes(8) + original[32:]).digest()
    return sha256(
        b"CYX/FILE-ADMIT/v3" + pack("<Q", boot) + proposal[8:16]
        + original_digest + proposal[16:96]
    ).digest()


def replaced(raw, offset, content):
    return raw[:offset] + content + raw[offset + len(content):]


def vectors():
    rows = []

    def add(name, kind, raw, expect="accept", context="-", output=b""):
        rows.append((name, kind, str(context), expect, raw, output))

    frozen = b"\x00Cyxia FSYNC snapshot\xff\x01"
    payload = pack("<Q", 0x0102030405060709)
    original = FILE_REQUEST_HEADER.pack(0x43594651, 4, 32, 5, 0, len(payload), SEQUENCE, 0) + payload
    proposal_fields = (CONTEXT, 127, 0x100000203, 0x2000, SEQUENCE, 0x8877665544332211, 0x40805)

    def admit(data):
        prefix = pack("<IHH7Q32s", *HEADERS[ADMIT], *proposal_fields, frozen_digest(data))
        return prefix + operation_digest(BOOT, original, prefix)

    proposal = admit(frozen)
    no_data = admit(b"")
    changed_claim = replaced(proposal, 127, bytes([proposal[127] ^ 1]))
    add("admit-frozen", ADMIT, proposal)
    add("admit-no-data", ADMIT, no_data)
    add("admit-unverified-digest", ADMIT, changed_claim)
    add("admit-truncated", ADMIT, proposal[:-1], "schema")
    add("admit-trailing", ADMIT, proposal + b"\0", "schema")
    add("admit-legacy-48b", ADMIT, pack("<IHH", 0x43595646, 2, 48) + proposal[8:48], "schema")
    add("admit-wrong-magic", ADMIT, replaced(proposal, 0, b"BAD!"), "schema")
    add("admit-wrong-declared-length", ADMIT, replaced(proposal, 6, pack("<H", 127)), "schema")

    for verdict, name in enumerate(("deny", "admitted", "revoked", "stale", "retry")):
        granted = (ADMISSION, 0x123456789) if verdict == 1 else (0, 0)
        raw = CODECS[ADMIT_REPLY].pack(*HEADERS[ADMIT_REPLY], CONTEXT, verdict, bytes(6), 0x10005, *granted)
        add(name, ADMIT_REPLY, raw, context=verdict)
        if verdict == 0:
            denied = raw
        elif verdict == 1:
            admitted = raw
    add("admitted-missing-id", ADMIT_REPLY, replaced(admitted, 32, bytes(8)), "invalid")
    add("deny-with-admission", ADMIT_REPLY, replaced(denied, 32, pack("<Q", ADMISSION)), "invalid")
    add("deny-with-timestamp", ADMIT_REPLY, replaced(denied, 40, pack("<Q", 1)), "invalid")
    add("unknown-verdict", ADMIT_REPLY, replaced(admitted, 16, pack("<H", 5)), "invalid")
    add("admit-reply-reserved", ADMIT_REPLY, replaced(admitted, 23, b"\x01"), "invalid")
    add("admit-reply-wrong-version", ADMIT_REPLY, replaced(admitted, 4, pack("<H", 1)), "schema")
    add("admit-reply-trailing", ADMIT_REPLY, admitted + b"\0", "schema")

    for state, name in enumerate(("done", "partial", "unknown", "no-effect"), 1):
        evidence = bytes(32) if state == 3 else sha256(name.encode("ascii")).digest()
        raw = CODECS[COMPLETE].pack(*HEADERS[COMPLETE], ADMISSION, state, bytes(6), evidence)
        add(name, COMPLETE, raw, context=state)
        if state == 3:
            add("unknown-with-evidence", COMPLETE, replaced(raw, 24, sha256(b"reconcile").digest()), context=3)
        else:
            add(name + "-missing-evidence", COMPLETE, replaced(raw, 24, bytes(32)), "invalid")
        if state == 1:
            done = raw
    add("complete-missing-id", COMPLETE, replaced(done, 8, bytes(8)), "invalid")
    add("unknown-terminal-state", COMPLETE, replaced(done, 16, pack("<H", 5)), "invalid")
    add("complete-reserved", COMPLETE, replaced(done, 18, b"\x01"), "invalid")
    add("complete-wrong-version", COMPLETE, replaced(done, 4, pack("<H", 3)), "schema")
    add("complete-trailing", COMPLETE, done + b"\0", "schema")

    for result in (0, -1, -3, -4, -5, -(1 << 31)):
        add(f"complete-result-{result}", COMPLETE_REPLY, pack("<iI", result, 0), context=result)
    add("complete-reply-reserved", COMPLETE_REPLY, pack("<iI", 0, 1), "invalid")
    add("complete-reply-truncated", COMPLETE_REPLY, bytes(7), "schema")

    add("frozen-data-digest", "frozen", frozen, output=frozen_digest(frozen))
    add("empty-data-digest", "frozen", b"", output=bytes(32))

    def binding(name, raw, carried, ref, boot=BOOT, expect="accept"):
        output = operation_digest(boot, raw, carried) if expect != "invalid" else b""
        add(name, "binding", raw, expect, f"{boot}:{ref}", output)

    binding("binding-frozen", original, proposal, "admit-frozen")
    binding("binding-no-data", original, no_data, "admit-no-data")
    binding("binding-interior-context-zeroed", replaced(original, 24, pack("<Q", 0x123ABC)), proposal, "admit-frozen")
    binding("binding-boot-changed", original, proposal, "admit-frozen", boot=BOOT + 1, expect="mismatch")
    binding("binding-file-request-changed", replaced(original, 32, b"\x0a"), proposal, "admit-frozen", expect="mismatch")
    binding("binding-claim-changed", original, changed_claim, "admit-unverified-digest", expect="mismatch")
    binding("binding-wrong-file-version", replaced(original, 4, pack("<H", 3)), proposal, "admit-frozen", expect="invalid")
    binding("binding-wrong-file-header", replaced(original, 6, pack("<H", 24)), proposal, "admit-frozen", expect="invalid")
    binding("binding-short-file-header", original[:31], proposal, "admit-frozen", expect="invalid")
    binding("binding-trailing-file-data", original + b"\0", proposal, "admit-frozen", expect="invalid")
    return rows


def verify(rows):
    named = {name: raw for name, _, _, _, raw, _ in rows}
    require(len(named) == len(rows))
    for name, kind, context, expect, raw, output in rows:
        if kind == "frozen":
            require(output == frozen_digest(raw))
            continue
        if kind == "binding":
            boot, ref = context.split(":")
            proposal = named[ref]
            decode(ADMIT, proposal)
            try:
                digest = operation_digest(int(boot), raw, proposal)
            except ValueError as exc:
                if expect != "invalid":
                    raise ValueError(name) from exc
            else:
                require(expect != "invalid" and digest == output)
                require((digest == proposal[96:]) == (expect == "accept"))
            continue
        if kind in (ADMIT, COMPLETE):
            require(matches_header(kind, raw) == (expect != "schema"))
        try:
            fields = decode(kind, raw)
        except ValueError as exc:
            if expect == "accept":
                raise ValueError(name) from exc
        else:
            require(expect == "accept" and CODECS[kind].pack(*fields) == raw)
            if kind in (ADMIT_REPLY, COMPLETE):
                require(fields[4] == int(context))
            elif kind == COMPLETE_REPLY:
                require(fields[0] == int(context))


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print the canonical TSV")
    args = parser.parse_args()
    cases = vectors()
    verify(cases)
    expected = "# name\tkind\tcontext\texpect\tinput_hex\toutput_hex\n" + "".join(
        f"{name}\t{kind}\t{context}\t{expect}\t{raw.hex() or '-'}\t{output.hex() or '-'}\n"
        for name, kind, context, expect, raw, output in cases
    )
    if args.emit:
        print(expected, end="")
    elif FIXTURE.read_text(encoding="ascii") != expected:
        raise SystemExit(f"G1 FILE_AUTH vectors differ from {FIXTURE}")
    else:
        print(f"{len(cases)} independent G1 FILE_AUTH vectors match")
