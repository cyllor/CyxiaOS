"""Two-boot fixture and independent disk checks for V0.20 scratch media."""
from dataclasses import replace
import json
from pathlib import Path
import struct
import tempfile

from v020_production_modes import (
    FILE_READ, STAGED_FILE_WRITE_RIGHTS, Modes, file_sessions_evidence,
    file_volatile_write_evidence, rows, snapshot_read_evidence,
)
from v020_production_qemu import create_scratch
from v020_snapshot_envelopes import (
    BITMAP_START, DATA_START, ENVELOPE_HEAD_BLOCKS, SLOT_TAIL_BLOCK, STAGED_FILE_BLOCK, STAGED_FILE_DATA,
    crc32c_zeroed,
)
from verify_smp import require


SIGNED_POLICY_SHA256 = "ffff2c6b9fde3b5311c4df1c871ff6b3830817fd1d76e0a1fb4bc07aaa369bcf"
BLOCK_BYTES = 4096
STAGING_UUID = b"CYX-W11-STAGING!"
SECURITY_HOME = 4130
SECURITY_REDO = 3
REDO_HEADER_BYTES = 64
MOUNT_INVALID = 0
MOUNT_UNAUTHORIZED = 1
MOUNT_CONFLICT = 3


def verify_signed_disk(path: Path, epoch: int) -> str:
    """Check the frozen SecurityState header at home and in the appended redo."""
    with path.open("rb") as disk:
        for offset, expected_epoch in (
            (SECURITY_HOME * BLOCK_BYTES, epoch - 1),
            (SECURITY_REDO * BLOCK_BYTES + REDO_HEADER_BYTES, epoch),
        ):
            disk.seek(offset)
            state = disk.read(120)
            require(len(state) == 120 and state[:4] == b"SSYC" and state[8:24] == STAGING_UUID
                    and int.from_bytes(state[64:72], "little") == expected_epoch
                    and int.from_bytes(state[80:88], "little") == 1
                    and state[88:120].hex() == SIGNED_POLICY_SHA256,
                    "signed policy digest or epoch in the scratch disk differs from the fixture")
    return SIGNED_POLICY_SHA256


def require_read_only_refusal(report: dict, lines: list, output: Path, step: int) -> tuple:
    io = rows(lines, "V020_W11_MEDIA_IO")
    require(report["status"] == "FAIL"
            and report["error"] == "ValueError: guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed"
            and lines.count(f"V020_W11_MEDIA_STAGING_INCOMPLETE step={step}") == 1
            and len(io) == 1 and io[0][0] > 0 and io[0][1:] == (0, 0)
            and report["scratch_before_sha256"] == report["scratch_disk"]["scratch_after_sha256"],
            f"reopen must refuse the disk at step {step} without writing or flushing it")
    page = (output / "native-page.bin").read_bytes()
    require(len(page) == BLOCK_BYTES, "short native-owned evidence page on rejected media")
    words = struct.unpack("<512Q", page)
    file_sessions_evidence(words, lines, False)
    file_volatile_write_evidence(words, lines, False)
    return words


def verify_unsigned_rejection(boot, unsigned_fresh: Path, reopen: Path, output: Path,
                              timeout: float, modes: Modes) -> None:
    with tempfile.TemporaryDirectory(prefix="cyx-v020-unsigned-") as temp:
        scratch = Path(temp) / "unsigned.raw"
        create_scratch(scratch)
        prepared = boot(unsigned_fresh, output / "unsigned-fixture", timeout, staging=True,
                        modes=modes.unsigned_fixture(),
                        boot_disk=scratch)
        require(prepared["status"] == "PASS", f"unsigned fixture failed: {prepared.get('error')}")
        rejected = boot(reopen, output / "reopen-unsigned", timeout, staging=True, modes=modes,
                        boot_disk=scratch)
    rejected_output = output / "reopen-unsigned"
    lines = (rejected_output / "serial.txt").read_text().splitlines()
    words = require_read_only_refusal(rejected, lines, rejected_output, 2)
    require(prepared["scratch_disk"]["scratch_after_sha256"] == rejected["scratch_before_sha256"],
            "signed reopen must examine the completed unsigned fixture")
    require(rows(lines, "V020_W13_SIGNED_SCRATCH") == [(0, 0, 0)],
            "mismatched signed policy must yield no BootEpoch or config verdict")
    if modes.snapshot_envelopes:
        require_no_envelope_proof(words, lines, modes)


def require_no_envelope_proof(words: tuple, lines: list, modes: Modes) -> None:
    require(rows(lines, "V020_W14_SNAPSHOT_ENVELOPES") == [(0, 0, 0)]
            and words[196:199] == (0, 0, 0) and words[148] == 0,
            "rejected media must yield no snapshot envelope proof or BootEpoch")
    if modes.media_unified:
        require(rows(lines, "V020_W15_UNIFIED_MOUNT") == [(0, 0, 0)]
                and words[208:211] == (0, 0, 0),
                "rejected media must yield no unified mount proof")
    if modes.snapshot_catalog:
        require(not any(words[224:236])
                and not rows(lines, "V020_W16_CATALOG")
                and not rows(lines, "V020_W16_CATALOG_CHECKS")
                and not rows(lines, "V020_W16_CATALOG_BINDING"),
                "rejected media must yield no snapshot catalog proof")
    if modes.file_read:
        require(not any(words[240:252])
                and not rows(lines, "V020_W18_FILE_READ")
                and not rows(lines, "V020_W18_FILE_CHECKS")
                and not rows(lines, "V020_W18_FILE_OWNER"),
                "rejected media must yield no staged file grant or read evidence")
    snapshot_read_evidence(words, lines, False)


def verify_staging_refusal(boot, reopen: Path, case: Path, timeout: float,
                           modes: Modes, scratch: Path, error_code: int) -> None:
    result = boot(reopen, case, timeout, staging=True, modes=modes, boot_disk=scratch)
    lines = (case / "serial.txt").read_text().splitlines()
    words = require_read_only_refusal(result, lines, case, 2)
    require([row for row in rows(lines, "V020_W11_MEDIA_STEP") if row[0] == 2] == [(2, 0, error_code)],
            f"{case.name} must be refused for the expected mount error")
    require_no_envelope_proof(words, lines, modes)


def verify_envelope_rejections(boot, reopen: Path, output: Path, timeout: float,
                               modes: Modes, scratch: Path) -> None:
    # Both refusals use the same newly formatted disk that will subsequently
    # reopen successfully after restoration of its four original heads.
    offsets = [block * BLOCK_BYTES for block in ENVELOPE_HEAD_BLOCKS]
    originals = []
    with scratch.open("r+b") as disk:
        for offset in offsets:
            disk.seek(offset)
            originals.append(disk.read(BLOCK_BYTES))
        require(all(len(head) == BLOCK_BYTES for head in originals),
                "snapshot envelope is outside the scratch disk")
    for name in ("reopen-envelope-crc", "reopen-envelope-legacy"):
        with scratch.open("r+b") as disk:
            if name == "reopen-envelope-crc":
                disk.seek(offsets[0] + 32)
                disk.write(bytes([originals[0][32] ^ 1]))
            else:
                for offset in offsets:
                    disk.seek(offset)
                    disk.write(bytes(BLOCK_BYTES))
        verify_staging_refusal(boot, reopen, output / name, timeout, modes, scratch, MOUNT_INVALID)
    with scratch.open("r+b") as disk:
        for offset, head in zip(offsets, originals, strict=True):
            disk.seek(offset)
            disk.write(head)


def verify_unified_rejections(boot, reopen: Path, output: Path, timeout: float,
                              modes: Modes, scratch: Path) -> None:
    catalog = ENVELOPE_HEAD_BLOCKS[0]
    bit = 1 << (catalog % 8)
    bitmap_offset = BITMAP_START * BLOCK_BYTES + catalog // 8
    acl_offset = 4126 * BLOCK_BYTES + 224 * 64
    with scratch.open("rb") as disk:
        disk.seek(bitmap_offset)
        bitmap = disk.read(1)
        disk.seek(acl_offset)
        acl = disk.read(64)
    require(len(bitmap) == 1 and bitmap[0] & bit and len(acl) == 64
            and struct.unpack_from("<I", acl, 32) == (0,),
            "unified scratch test requires a live catalog with no ordinary owner rights")
    exposed = bytearray(acl)
    struct.pack_into("<I", exposed, 32, 1 << 8)
    struct.pack_into("<I", exposed, 60, crc32c_zeroed(exposed, 60))
    cases = (
        ("reopen-unified-bitmap", bitmap_offset, bitmap, bytes([bitmap[0] & ~bit]), MOUNT_CONFLICT),
        ("reopen-unified-acl", acl_offset, acl, exposed, MOUNT_UNAUTHORIZED),
    )
    for name, offset, original, replacement, expected in cases:
        # Mutate one metadata field on the known scratch preimage. The same
        # image must reopen after both controls restore its original bytes.
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(replacement)
        verify_staging_refusal(boot, reopen, output / name, timeout, modes, scratch, expected)
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(original)


def verify_file_rejection(boot, reopen: Path, output: Path, timeout: float,
                          modes: Modes, scratch: Path) -> None:
    offset = STAGED_FILE_BLOCK * BLOCK_BYTES
    with scratch.open("r+b") as disk:
        disk.seek(offset)
        original = disk.read(len(STAGED_FILE_DATA))
        require(original == STAGED_FILE_DATA, "corruption probe requires the sealed staged file")
        disk.seek(offset)
        disk.write(bytes([original[0] ^ 1]))
    try:
        verify_staging_refusal(boot, reopen, output / "reopen-file-content", timeout,
                                modes, scratch, MOUNT_CONFLICT)
    finally:
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(original)


def verify_file_acl_rejection(boot, reopen: Path, output: Path, timeout: float,
                              modes: Modes, scratch: Path) -> None:
    # Inode 1 holds the staged file and occupies the second ACL record.
    offset = (DATA_START + 8) * BLOCK_BYTES + 64
    with scratch.open("rb") as disk:
        disk.seek(offset)
        original = disk.read(64)
    require(len(original) == 64 and struct.unpack_from("<I", original, 0) == (1,)
            and struct.unpack_from("<I", original, 32) == (STAGED_FILE_WRITE_RIGHTS,)
            and struct.unpack_from("<I", original, 60) == (crc32c_zeroed(original, 60),),
            "volatile write ACL probe requires the valid staged file's read and write owner rights")
    readonly = bytearray(original)
    struct.pack_into("<I", readonly, 32, FILE_READ)
    struct.pack_into("<I", readonly, 60, crc32c_zeroed(readonly, 60))
    try:
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(readonly)
        verify_staging_refusal(boot, reopen, output / "reopen-file-acl-mode", timeout,
                               modes, scratch, MOUNT_UNAUTHORIZED)
    finally:
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(original)


def verify_snapshot_slot_rejection(boot, reopen: Path, output: Path, timeout: float,
                                    modes: Modes, scratch: Path) -> None:
    offset = (SLOT_TAIL_BLOCK + 1) * BLOCK_BYTES - 1
    with scratch.open("r+b") as disk:
        disk.seek(offset)
        original = disk.read(1)
        require(original == b"\0", "SlotStore corruption probe requires a clean tail block")
        disk.seek(offset)
        disk.write(b"\x01")
    try:
        verify_staging_refusal(boot, reopen, output / "reopen-snapshot-slot-tail", timeout,
                               modes, scratch, MOUNT_CONFLICT)
    finally:
        with scratch.open("r+b") as disk:
            disk.seek(offset)
            disk.write(original)


def run_media_reopen(boot, fresh: Path, reopen: Path, output: Path, timeout: float, modes: Modes,
                     unsigned_fresh: Path | None = None) -> dict:
    """Use one temporary disk across boots, then run independent refusal cases."""
    output.mkdir(parents=True)
    report = {"status": "FAIL", "scope": "native-v020-staging-two-boot-reopen",
              "golden_vector_pending": True, "signed_media_mode": modes.signed_media,
              "media_envelopes_mode": modes.snapshot_envelopes,
              "media_unified_mode": modes.media_unified,
              "snapshot_catalog_mode": modes.snapshot_catalog, "file_read_mode": modes.file_read,
              "snapshot_read_mode": modes.snapshot_read, "file_sessions_mode": modes.file_sessions,
              "file_volatile_write_mode": modes.file_volatile_write}
    try:
        require(not modes.signed_media or unsigned_fresh is not None,
                "signed reopen requires a separate unsigned fixture ELF")
        with tempfile.TemporaryDirectory(prefix="cyx-v020-reopen-") as temp:
            scratch = Path(temp) / "reopen.raw"
            create_scratch(scratch)
            first = boot(fresh, output / "boot-1", timeout, staging=True,
                         modes=replace(modes, media_reopen=False), boot_disk=scratch)
            require(first["status"] == "PASS", f"staging boot 1 failed: {first.get('error')}")
            if modes.snapshot_envelopes:
                verify_envelope_rejections(boot, reopen, output, timeout, modes, scratch)
                report["bad_envelope_crc_refused_without_write"] = True
                report["legacy_empty_envelopes_refused_without_write"] = True
            if modes.media_unified:
                verify_unified_rejections(boot, reopen, output, timeout, modes, scratch)
                report["missing_bitmap_allocation_refused_without_write"] = True
                report["snapshot_owner_rights_refused_without_write"] = True
            if modes.file_read:
                verify_file_rejection(boot, reopen, output, timeout, modes, scratch)
                report["changed_file_content_refused_without_write"] = True
            if modes.file_volatile_write:
                verify_file_acl_rejection(boot, reopen, output, timeout, modes, scratch)
                report["file_volatile_write_acl_mismatch_refused_without_write"] = True
            if modes.snapshot_read:
                verify_snapshot_slot_rejection(boot, reopen, output, timeout, modes, scratch)
                report["snapshot_read_slot_tail_refused_without_write"] = True
            second = boot(reopen, output / "boot-2", timeout, staging=True, modes=modes,
                          boot_disk=scratch)
            require(second["status"] == "PASS", f"staging boot 2 failed: {second.get('error')}")
            require(first["scratch_disk"]["scratch_after_sha256"] == second["scratch_before_sha256"],
                    "the staged disk at boot 2 must exactly match boot 1's output")
            require(second["scratch_before_sha256"] != second["scratch_disk"]["scratch_after_sha256"],
                    "reopen must checkpoint and allocate on the same disk")
            if modes.snapshot_envelopes:
                require(first["snapshot_envelope_disk"]["objects"] == second["snapshot_envelope_disk"]["objects"],
                        "empty snapshot envelope bytes must be stable across reopen")
            if modes.file_read:
                for key in ("file_read_sha256", "file_read_dirent_sha256"):
                    require(first["snapshot_envelope_disk"][key] == second["snapshot_envelope_disk"][key],
                            "staged file bytes must be stable across reopen")
        blank_path = output / "reopen-blank"
        blank = boot(reopen, blank_path, timeout, staging=True, modes=modes)
        blank_lines = (blank_path / "serial.txt").read_text().splitlines()
        blank_words = require_read_only_refusal(blank, blank_lines, blank_path, 1)
        if modes.snapshot_envelopes:
            require_no_envelope_proof(blank_words, blank_lines, modes)
        if modes.signed_media:
            verify_unsigned_rejection(boot, unsigned_fresh, reopen, output, timeout, modes)
            report["unsigned_disk_refused_without_write"] = True
        report.update({
            "epochs": [first["observations"]["staging_confirmed_epoch"],
                       second["observations"]["staging_confirmed_epoch"]],
            "signed_config": modes.signed_media,
            "reopened_same_disk": True,
            "blank_disk_refused_without_write": True,
        })
        if modes.snapshot_envelopes:
            report["snapshot_envelope_blocks_verified"] = second["snapshot_envelope_disk"]["snapshot_blocks"]
        if modes.media_unified:
            report["unified_system_inodes_verified"] = second["snapshot_envelope_disk"]["system_inodes"]
        if modes.snapshot_catalog:
            report["snapshot_catalog_lists_per_boot"] = [
                boot["observations"]["snapshot_catalog_lists"] for boot in (first, second)
            ]
        if modes.file_read:
            report["file_read_calls_per_boot"] = [
                boot["observations"]["file_read_calls"] for boot in (first, second)
            ]
            report["file_read_sha256"] = second["snapshot_envelope_disk"]["file_read_sha256"]
        if modes.snapshot_read:
            for operation in ("query", "history"):
                key = f"snapshot_read_{operation}_missing"
                report[f"{key}_per_boot"] = [boot["observations"][key] for boot in (first, second)]
            report["snapshot_read_slot_sha256"] = second["snapshot_envelope_disk"]["objects"]["slot"]["extent_sha256"]
        if modes.file_sessions:
            for field in ("boot_epoch", "peak_handles", "opens", "reads", "closes", "replays",
                          "acks", "denials_mask", "revoked_mask"):
                key = f"file_session_{field}"
                report[f"{key}_per_boot"] = [boot["observations"][key] for boot in (first, second)]
            report["file_session_acks_total"] = sum(report["file_session_acks_per_boot"])
        if modes.file_volatile_write:
            for field in ("boot_epoch", "owner_rights", "writes", "last_write_seq", "reads", "replays",
                          "acks", "denials_mask"):
                key = f"file_volatile_write_{field}"
                report[f"{key}_per_boot"] = [boot["observations"][key] for boot in (first, second)]
            report["file_volatile_write_acks_total"] = sum(report["file_volatile_write_acks_per_boot"])
        report["status"] = "PASS"
    except (OSError, ValueError, KeyError) as error:
        report["error"] = str(error)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
