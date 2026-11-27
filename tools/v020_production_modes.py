"""Select and verify the opt-in V0.20 native integration paths."""
from dataclasses import dataclass, replace
import hashlib
import re
import struct

import v020_tls_peer
from verify_smp import require
from v020_snapshot_envelopes import STAGED_FILE_DATA


W12_END = 176
W13_END = 192
W14_END = 208
W15_END = 224
W16_END = 240
W18_END = 256
W19_END = 272
W20_END = 288
W21_END = 304
QEMU_GATEWAY_IPV4 = 0x0a000202
FILE_READ = 1 << 8
STAGED_FILE_WRITE_RIGHTS = FILE_READ | (1 << 9)


@dataclass(frozen=True)
class Modes:
    authenticated_net: bool = False
    live_control: bool = False
    media_reopen: bool = False
    signed_media: bool = False
    orderly_close: bool = True
    frame_pool: bool = False
    media_envelopes: bool = False
    media_unified: bool = False
    snapshot_catalog: bool = False
    file_read: bool = False
    snapshot_read: bool = False
    file_sessions: bool = False
    file_volatile_write: bool = False
    fsync_scratch: bool = False
    fsync_bound: bool = False

    def __post_init__(self) -> None:
        require(not self.fsync_bound or self.fsync_scratch, "BOUND receipt proof requires FSYNC scratch")
        if self.fsync_scratch:
            object.__setattr__(self, "signed_media", True)
        if self.file_volatile_write:
            for dependency in ("file_read", "media_unified", "signed_media", "live_control"):
                object.__setattr__(self, dependency, True)

    @property
    def snapshot_envelopes(self) -> bool:
        return self.media_envelopes or self.media_unified

    def unsigned_fixture(self) -> "Modes":
        return replace(self, media_reopen=False, signed_media=False, snapshot_catalog=False,
                       file_read=False, snapshot_read=False, file_sessions=False,
                       file_volatile_write=False, fsync_scratch=False, fsync_bound=False)

    def features(self, staging: bool) -> str:
        require(not self.file_volatile_write or staging or self.media_reopen,
                "file volatile write requires a staging or reopen run")
        if self.media_reopen:
            base = "v020-production-media-reopen"
        else:
            base = "v020-production-media-staging" if staging else "v020-production-diagnostic"
        features = [base]
        if self.authenticated_net:
            features.append("v020-production-authenticated-net")
        if self.live_control:
            features.append("v020-production-live-control")
        if self.signed_media:
            features.append("v020-production-media-signed")
        if self.fsync_scratch:
            features.append("v020-production-fsync-scratch")
        if self.frame_pool:
            features.append("v020-production-frame-pool")
        if self.media_unified:
            features.append("v020-production-media-unified")
        elif self.media_envelopes:
            features.append("v020-production-media-envelopes")
        if self.snapshot_catalog:
            features.append("v020-production-snapshot-catalog")
        if self.file_read:
            features.append("v020-production-file-read")
        if self.snapshot_read:
            features.append("v020-production-snapshot-read")
        if self.file_sessions:
            features.append("v020-production-file-sessions")
        if self.file_volatile_write:
            features.append("v020-production-file-volatile-write")
        return ",".join(features)


def rows(lines: list, name: str) -> list:
    pattern = re.compile(re.escape(name) + r" a=(\d+) b=(\d+) c=(\d+)")
    matched = []
    for line in lines:
        if line.startswith(name + " "):
            found = pattern.fullmatch(line)
            require(found is not None, "malformed " + name)
            matched.append(tuple(map(int, found.groups())))
    return matched


def net_entropy(words: tuple, lines: list, enabled: bool) -> dict:
    count = words[160]
    unavailable = rows(lines, "V020_W12_NET_ENTROPY_UNAVAILABLE")
    supplied = rows(lines, "V020_W12_NET_ENTROPY")
    generated = rows(lines, "V020_SEC_N_DRBG")
    if not enabled:
        require(count == 0 and not (unavailable or supplied or generated),
                "unexpected authenticated RNG evidence")
        return {}
    if unavailable:
        require(len(unavailable) == 1 and not (supplied or generated or count)
                and words[138] == 1 and not any(words[139:143])
                and not rows(lines, "V020_W11_NET_LISTEN"),
                "inconsistent refusal of the authenticated network without entropy")
        raise ValueError("V020_W12_NET_ENTROPY_UNAVAILABLE: authenticated relay stopped before listen")
    require(count >= 32 and supplied == [(8, count, 0)],
            "authenticated relay requires matching VirtIO RNG evidence")
    require(len(generated) == 1 and generated[0][0] > 0
            and generated[0][1:] == (1024 * generated[0][0], count),
            "authenticated relay requires seeded DRBG evidence")
    key_epoch, samples, _ = generated[0]
    return {"tls_drbg_guest_bytes": count, "tls_drbg_key_epoch": key_epoch,
            "virtio_rng_health_samples": samples}


def net_signer(lines: list, enabled: bool, signed_boot_epoch: int | None) -> dict:
    spaces = rows(lines, "V020_SEC_N_SIGNER_SPACE")
    replies = rows(lines, "V020_SEC_N_SIGNER_REPLY")
    authenticated = rows(lines, "V020_SEC_N_VERIFIER_AUTHENTICATED")
    identities = rows(lines, "V020_SEC_N_SIGNER_IDENTITY")
    if not enabled:
        require(not (spaces or replies or authenticated or identities), "unexpected isolated signer evidence")
        return {}
    if signed_boot_epoch is not None or identities:
        require(identities == [(signed_boot_epoch or 1, 1, 1)],
                "Signer identity differs from the selected scratch BootEpoch or generation")
    require(len(spaces) == 1 and spaces[0][0] == 0x41
            and 0 < spaces[0][1] <= 64 and spaces[0][2] == 0,
            "missing bounded independent Signer address space")
    grants = rows(lines, "V020_W11_NET_ADMISSION")
    require(grants == [(1, QEMU_GATEWAY_IPV4, 1)] and replies == [(grants[0][0], 1, 1)],
            "missing connection-bound CertificateVerify signer reply")
    require(authenticated == grants, "missing connection-bound TLS verifier completion")
    sign_at = lines.index("V020_SEC_N_SIGNER_REPLY a=1 b=1 c=1")
    auth_at = lines.index(f"V020_SEC_N_VERIFIER_AUTHENTICATED a=1 b={QEMU_GATEWAY_IPV4} c=1")
    require(sign_at < auth_at, "TLS verifier completed before its signer reply")
    return {"native_signer_asid": spaces[0][0], "native_signer_certificate_verifies": len(replies),
            "native_verifier_authenticated_connections": len(authenticated)}


def net_reset_proofs(lines: list, *, boot_epoch: int = 1) -> dict:
    prefix = "V020_SEC_D_NET_RESET_PROOF "
    encoded = [line.removeprefix(prefix) for line in lines if line.startswith(prefix)]
    unconfirmed = rows(lines, "V020_SEC_D_NET_RESET_UNCONFIRMED")
    require(len(encoded) == 2 and not unconfirmed, "native net reset proof is incomplete")
    observations = []
    for queue_id, value in enumerate(encoded):
        require(re.fullmatch("[0-9a-f]{128}", value), "malformed ResetProof v1 bytes")
        fields = struct.unpack("<IHHQIHHQQQIIQ", bytes.fromhex(value))
        require(fields[:-1] == (0x43595250, 1, 64, boot_epoch, 1, queue_id, 0, 1, 1, 1, 0, 0)
                and fields[-1] > 0, "native net ResetProof v1 has the wrong generation or readback")
        observations.append(fields[-1])
    require(observations[0] == observations[1], "net queues were not proved in one device reset")
    custody = rows(lines, "V020_SEC_D_NET_RESET_CUSTODY")
    require(len(custody) == 1 and custody[0][0] == boot_epoch,
            "native net terminal custody is absent or belongs to another boot")
    _, receive_count, transmit_count = custody[0]
    seen = set()
    retained = []
    counts = [0, 0]
    for state in ("private", "published", "complete"):
        for queue, slot, generation in rows(lines, "V020_SEC_D_NET_RESET_CHAIN_" + state.upper()):
            require(queue in (0, 1) and slot < 8 and generation > 0 and (queue, slot) not in seen,
                    "native net retained chain identity is invalid")
            seen.add((queue, slot))
            counts[queue] += 1
            retained.append({"queue_id": queue, "slot": slot, "generation": generation, "state": state})
    require(counts == [receive_count, transmit_count] and receive_count > 0,
            "native net retained chain counts differ")
    return {"native_net_reset_queue_ids": [0, 1], "native_net_reset_boot_epoch": boot_epoch,
            "native_net_reset_observed_ns": observations[0],
            "native_net_retained_chains": sorted(retained, key=lambda entry: (entry["queue_id"], entry["slot"]))}


def control_observations(words: tuple, lines: list, enabled: bool) -> dict:
    roles, sequence, audit, early = words[164:168]
    snapshot_rows = rows(lines, "V020_W12_LIVE_SNAPSHOT")
    audit_rows = rows(lines, "V020_W12_VOLATILE_AUDIT")
    early_rows = rows(lines, "V020_W12_CONTROL_UNREADY")
    if not enabled:
        require(not any((roles, sequence, audit, early)) and not (snapshot_rows or audit_rows or early_rows),
                "unexpected live control evidence")
        return {}
    require(roles == 5 and sequence > 0 and snapshot_rows == [(roles, sequence, 17)],
            "missing authorized D01 snapshot readbacks")
    require(audit == 1 and audit_rows == [(11, audit, 1)], "missing supervisor volatile audit readback")
    require(early == 3 and early_rows == [(early, 0, 0)], "unready snapshot/audit refusal missing")
    return {
        "live_d01_snapshot_role_mask": roles,
        "live_d01_snapshot_sequence": sequence,
        "volatile_audit_sequence": audit,
        "early_control_refusal_mask": early,
    }


def validate_extensions(words: tuple, lines: list, modes: Modes) -> dict:
    require(words[161] == 0 and not any(words[168:W12_END]), "nonzero reserved evidence words")
    require(words[177] == 0 and not any(words[188:W13_END]), "nonzero reserved evidence words")
    require(words[195] == 0 and not any(words[199:W14_END]), "nonzero reserved evidence words")
    require(not any(words[211:W15_END]), "nonzero reserved evidence words")
    require(words[231] == 0 and not any(words[236:W16_END]), "nonzero reserved evidence words")
    require(not any(words[252:W18_END]), "nonzero reserved file read evidence words")
    if not modes.media_reopen:
        require(not any(words[162:164]), "unexpected media reopen evidence")
    return {
        **net_entropy(words, lines, modes.authenticated_net),
        **net_signer(lines, modes.authenticated_net, words[148] if modes.signed_media else None),
        **control_observations(words, lines, modes.live_control),
        **net_retirement(words, lines, modes),
        **audit_session(words, lines, modes.live_control),
        **frame_pool_evidence(words, lines, modes.frame_pool),
    }


def net_retirement(words: tuple, lines: list, modes: Modes) -> dict:
    count = words[176]
    retirements = rows(lines, "V020_W13_NET_RETIRE")
    if not modes.authenticated_net:
        require(count == 0 and not retirements, "unexpected authenticated retirement evidence")
        return {}
    expected = int(modes.orderly_close)
    require(count == expected and retirements == ([(1, QEMU_GATEWAY_IPV4, 1)] if expected else []),
            "native Admission retirement proof disagrees with the close mode")
    end = rows(lines, "V020_W11_NET_GUEST_END")
    require(end == [(0, 1 - expected, 0)], "guest stop or EOF disagrees with TCP retirement")
    return {"native_admission_retirements": count}


def audit_session(words: tuple, lines: list, enabled: bool) -> dict:
    audited = words[178:181]
    session = rows(lines, "V020_W13_AUDIT_SESSION")
    if not enabled:
        require(not any(audited) and not session, "unexpected Supervisor audit session evidence")
        return {}
    require(audited == (3, 3, 1) and session == [audited],
            "Supervisor must consume and acknowledge three records with one exact replay")
    return dict(zip(("audit_el0_sequence", "volatile_audit_released", "audit_exact_replays"), audited))


def signed_media_authority(words: tuple, lines: list, modes: Modes) -> dict:
    verified, epoch = words[181:183]
    marker = rows(lines, "V020_W13_SIGNED_SCRATCH")
    receipt_epoch = words[183]
    receipt_words = words[184:188]
    receipt_marker = rows(lines, "V020_W23_RECEIPT_VIEW")
    if not modes.signed_media:
        require(verified == epoch == receipt_epoch == 0 and not any(receipt_words)
                and not marker and not receipt_marker, "unexpected signed scratch authority")
        return {}
    require(verified == 1 and epoch == words[148]
            and marker == [(1, epoch, words[163])],
            "signed scratch verdict and BootEpoch must agree with mounted evidence")
    require(lines.count("V020_W13_MEDIA_SCOPE test_key=true format_golden=false signed_config=true") == 1,
            "expected signed scratch test scope")
    require(receipt_epoch == epoch and any(receipt_words)
            and receipt_marker == [(epoch, 7, receipt_words[0])],
            "signed receipt view must bind the confirmed BootEpoch and all seven blocks")
    digest = b"".join(word.to_bytes(8, "little") for word in receipt_words).hex()
    return {"signed_test_config_verified": True, "signed_config_bound_boot_epoch": epoch,
            "signed_receipt_view_sha256": digest}


def frame_pool_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    lifecycle = words[192:195]
    serial = rows(lines, "V020_W14_FRAME_POOL")
    if not enabled:
        require(not any(lifecycle) and not serial, "unexpected FrameMeta pool evidence")
        return {}
    require(lifecycle == (1, 4, 4) and serial == [lifecycle],
            "native FrameMeta pool requires a completed lifecycle and four conserved free pages")
    return {"native_frame_pool_lifecycle": True, "frame_pool_pages": lifecycle[1],
            "frame_pool_free_after_revoke": lifecycle[2]}


def snapshot_envelope_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    verified = words[196:199]
    serial = rows(lines, "V020_W14_SNAPSHOT_ENVELOPES")
    if not enabled:
        require(not any(verified) and not serial, "unexpected snapshot envelope evidence")
        return {}
    require(verified == (4, 1, 1) and serial == [verified],
            "snapshot envelope evidence must cover four pristine generation-1 objects")
    return {"snapshot_envelopes_verified": verified[0], "snapshot_envelope_generation": verified[1]}


def unified_mount_evidence(words: tuple, lines: list, enabled: bool, *, file_read: bool = False) -> dict:
    layout = words[208:211]
    serial = rows(lines, "V020_W15_UNIFIED_MOUNT")
    if not enabled:
        require(not any(layout) and not serial, "unexpected unified mount evidence")
        return {}
    require(layout == (8, 151, 152 + int(file_read)) and serial == [layout],
            "unified mount requires eight system inodes and conserved block counts")
    return {"unified_mount_system_inodes": layout[0], "unified_mount_system_blocks": layout[1],
            "unified_mount_data_blocks": layout[2]}


def file_read_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    boot, owner, generation, reads, ops, replays, refusals, acks = words[240:248]
    digest = struct.pack("<4Q", *words[248:252])
    service_rows = rows(lines, "V020_W18_FILE_READ")
    check_rows = rows(lines, "V020_W18_FILE_CHECKS")
    owner_rows = rows(lines, "V020_W18_FILE_OWNER")
    if not enabled:
        require(not any(words[240:252]) and not (service_rows or check_rows or owner_rows),
                "unexpected staged file read evidence")
        return {}
    expected_ops = sum(1 << op for op in (2, 3, 6, 8, 14, 15))
    require(boot != 0 and boot == words[148] and (reads, ops) == (3, expected_ops)
            and service_rows == [(boot, reads, ops)], "missing staged file operation evidence")
    require((owner, generation) == (1, 1) and owner_rows == [(owner, generation, 11)],
            "staged file read owner is not the signed Supervisor grant")
    require((refusals, replays, acks) == (255, 1, 3) and check_rows == [(refusals, replays, acks)],
            "missing staged file replay, ACK, or refusal evidence")
    require(digest == hashlib.sha256(STAGED_FILE_DATA).digest(), "staged file witness digest differs")
    return {
        "file_read_boot_epoch": boot,
        "file_read_calls": reads,
        "file_read_operations": [2, 3, 6, 8, 14, 15],
        "file_read_replays": replays,
        "file_read_acks": acks,
        "file_read_refusals": refusals.bit_count(),
        "file_read_sha256": digest.hex(),
    }


def snapshot_catalog_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    catalog, checks = words[224:227], words[227:230]
    service_generation = words[230]
    digest = words[232:236]
    catalog_rows = rows(lines, "V020_W16_CATALOG")
    check_rows = rows(lines, "V020_W16_CATALOG_CHECKS")
    binding_rows = rows(lines, "V020_W16_CATALOG_BINDING")
    if not enabled:
        require(not any(catalog + checks + digest) and not service_generation
                and not (catalog_rows or check_rows or binding_rows),
                "unexpected snapshot catalog evidence")
        return {}
    require(words[148] > 0 and catalog == (words[148], 1, 2) and catalog_rows == [catalog]
            and checks == (1, 7, 1) and check_rows == [checks] and any(digest)
            and service_generation == 3 and binding_rows == [(service_generation, 1, catalog[0])],
            "snapshot catalog requires the mounted BootEpoch, two LIST reads and all denial checks")
    return {
        "snapshot_catalog_boot_epoch": catalog[0],
        "snapshot_catalog_generation": catalog[1],
        "snapshot_catalog_lists": catalog[2],
        "snapshot_catalog_unready_checks": checks[0],
        "snapshot_catalog_denials": checks[1],
        "snapshot_catalog_retired_checks": checks[2],
        "snapshot_catalog_service_generation": service_generation,
        "snapshot_catalog_sha256": struct.pack("<4Q", *digest).hex(),
    }


def snapshot_read_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    require(not any(words[261:264]) and not any(words[268:W19_END]),
            "nonzero reserved snapshot read evidence words")
    if not enabled:
        require(not any(words[W18_END:W19_END])
                and not any(line.startswith("V020_W19_") for line in lines),
                "unexpected snapshot read evidence")
        return {}
    boot, query, history, denials, stale = words[W18_END:261]
    digest = words[264:268]
    read_rows = rows(lines, "V020_W19_SNAPSHOT_READ")
    check_rows = rows(lines, "V020_W19_SNAPSHOT_CHECKS")
    require(boot > 0 and boot == words[148] == words[224] == words[240],
            "snapshot read requires the mounted, catalog and file read BootEpochs to agree")
    require((query, history) == (1, 1) and read_rows == [(boot, query, history)],
            "snapshot read requires one missing QUERY and one missing HISTORY_OPEN")
    require((denials, stale) == (31, 1) and check_rows == [(denials, stale, 0)],
            "snapshot read requires all denial checks and a stale HISTORY_OPEN")
    require(any(digest), "snapshot read is missing the SlotStore digest")
    return {
        "snapshot_read_boot_epoch": boot,
        "snapshot_read_query_missing": query,
        "snapshot_read_history_missing": history,
        "snapshot_read_denials_mask": denials,
        "snapshot_read_stale_checks": stale,
        "snapshot_read_slot_sha256": struct.pack("<4Q", *digest).hex(),
    }


def file_sessions_evidence(words: tuple, lines: list, enabled: bool, *,
                           file_volatile_write: bool = False) -> dict:
    require(not any(words[281:W20_END]), "nonzero reserved file session evidence words")
    session_words = words[W19_END:281]
    serial = [line for line in lines if line.startswith("V020_W20_")]
    if not enabled:
        require(not any(session_words) and not serial, "unexpected file session evidence")
        return {}
    boot, peak, opens, reads, closes, replays, acks, denials, revoked = session_words
    require(boot > 0 and boot == words[148] == words[240],
            "file session requires matching confirmed and file read BootEpochs")
    expected_acks = 9 if file_volatile_write else 12
    require((peak, opens, reads, closes, replays, acks, denials, revoked) ==
            (4, 5, 3, 1, 2, expected_acks, 127, 15),
            "file session counts, denials or revocations differ from the sealed fixture")
    require(sorted(serial) == sorted((
        f"V020_W20_FILE_HANDLES a={boot} b={peak} c={opens}",
        f"V020_W20_FILE_IO a={reads} b={closes} c={replays}",
        f"V020_W20_FILE_CHECKS a={acks} b={denials} c={revoked}",
    )), "file session serial rows disagree with the sealed evidence")
    return {
        "file_session_boot_epoch": boot,
        "file_session_peak_handles": peak,
        "file_session_opens": opens,
        "file_session_reads": reads,
        "file_session_closes": closes,
        "file_session_replays": replays,
        "file_session_acks": acks,
        "file_session_denials_mask": denials,
        "file_session_revoked_mask": revoked,
    }


def file_volatile_write_evidence(words: tuple, lines: list, enabled: bool) -> dict:
    require(not any(words[296:W21_END]), "nonzero reserved file volatile write evidence words")
    write_words = words[W20_END:296]
    serial = [line for line in lines if line.startswith("V020_W21_")]
    if not enabled:
        require(not any(write_words) and not serial, "unexpected file volatile write evidence")
        return {}
    boot, rights, writes, write_seq, reads, replays, denials, acks = write_words
    require(boot > 0 and boot == words[148] == words[240],
            "file volatile write requires matching confirmed and file read BootEpochs")
    require(rights == STAGED_FILE_WRITE_RIGHTS, "file volatile write requires read and write owner rights")
    require((writes, write_seq, reads, replays, denials, acks) == (2, 2, 2, 1, 15, 9),
            "file volatile write counts, sequence or denials differ from the sealed fixture")
    require(sorted(serial) == sorted((
        f"V020_W21_WRITE a={boot} b={rights} c={writes}",
        f"V020_W21_WRITE_READBACK a={reads} b={write_seq} c={replays}",
        f"V020_W21_WRITE_CHECKS a={acks} b={denials} c=0",
    )), "file volatile write serial rows disagree with the sealed evidence")
    return {
        "file_volatile_write_boot_epoch": boot,
        "file_volatile_write_owner_rights": rights,
        "file_volatile_write_writes": writes,
        "file_volatile_write_last_write_seq": write_seq,
        "file_volatile_write_reads": reads,
        "file_volatile_write_replays": replays,
        "file_volatile_write_denials_mask": denials,
        "file_volatile_write_acks": acks,
    }


def authenticated_echo(proof: dict, relay_bytes: int, orderly_close: bool) -> None:
    digests = {
        role: hashlib.sha256((v020_tls_peer.FIXTURES / name).read_bytes()).hexdigest()
        for role, name in (("client", "a-test-cert.der"), ("server", "b-test-cert.der"))
    }
    require(proof.get("tls_version") == "TLSv1.3" and proof.get("alpn") == v020_tls_peer.ALPN
            and proof.get("client_certificate_verify") is True,
            f"authenticated TLS peer failed: {proof.get('error', 'incomplete transcript')}")
    require(all(proof.get(f"{role}_certificate_sha256") == digest for role, digest in digests.items()),
            "authenticated TLS peer fixture identities do not match")
    require(proof.get("sent") == proof.get("received") == v020_tls_peer.FRAME_BYTES < relay_bytes
            and re.fullmatch(r"[0-9a-f]{64}", proof.get("request_sha256", "")) is not None
            and proof["request_sha256"] == proof.get("reply_sha256"),
            "authenticated TLS Echo bytes or challenge digest do not match")
    require(proof.get("tls_close_notify_verified") is orderly_close
            and proof.get("tcp_orderly_eof") is orderly_close,
            "host TLS close_notify and TCP EOF disagree with the close mode")
