"""Independent, non-authoritative bounded session-exit decoder."""
import argparse
import json
import pathlib
import struct

REASONS = ('connection_lost', 'clock_unavailable', 'domain_tick', 'tcp_read',
           'tls_receive', 'tls_pump', 'handshake_ticket', 'handshake_finish',
           'enter_authenticated', 'plaintext_ingest', 'plaintext_consume',
           'driver_tick', 'replay_reconnect', 'tls_egress', 'ingress_begin', 'tls_create')
ORIGINS = ('connect', 'ingest_decode', 'handle', 'ready_binding', 'idle_timeout',
           'tick', 'domain_tick', 'runtime')
RESULTS = {0: 'local_lifecycle', 0x4000: 'driver_unit_error',
           0x4001: 'driver_idle_timeout', 0x4002: 'ready_binding_mismatch',
           0x4003: 'partial_tls_receive', 0x4004: 'connection_epoch_changed',
           0x4005: 'transport_disconnected', 0x4101: 'wire_invalid'}
for base, prefix, names in (
        (0x1001, 'tls_', ('identity', 'entropy', 'time', 'clock', 'timeout', 'protocol', 'buffer', 'would_block', 'handshake', 'closed', 'direction')),
        (0x2001, 'domain_', ('format', 'auth', 'schema', 'stale', 'capacity', 'budget', 'conflict', 'expired', 'unsupported', 'busy', 'again', 'not_found', 'exists', 'not_directory', 'is_directory', 'not_empty', 'range', 'io', 'overflow', 'not_ready')),
        (0x3000, 'broker_', ('ok', 'again', 'eof', 'failed', 'not_found', 'rejected')),
        (0x5001, 'engine_', ('invalid', 'conflict', 'state', 'isolated', 'busy', 'unknown_io', 'capacity', 'expired', 'replay', 'counter', 'not_found'))):
    RESULTS.update((base + i, prefix + name) for i, name in enumerate(names))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_session_exits(data, *, boot, service_generation):
    """Decode one stopped UNIFIED_EVIDENCE snapshot, bound to caller identity.

    The three retained slots span service generations of this boot. The caller
    supplies the *current* captured service generation, not a retained slot's
    generation. No diagnostic can establish READY, custody or native PASS.
    """
    require(len(data) == 4096, 'session exits require an exact 4096-byte snapshot')
    words = struct.unpack('<512Q', data)
    require(boot > 0 and service_generation > 0 and words[0] == 0x435958554e493031
            and words[1] == boot and words[30] == service_generation,
            'snapshot boot/service generation mismatch')
    bank = words[432:]
    sequence, magic, version, unauth, auth, first_generation, last_generation, reserved = bank[:8]
    require(sequence > 0 and sequence % 2 == 0 and magic == 0x4359584558495431
            and version == 1 and reserved == 0, 'missing, malformed or interrupted session-exit bank')
    require(sequence == 2 * (unauth + auth) and 0 < first_generation <= last_generation <= service_generation,
            'invalid session-exit publication/count/generation')

    def decode_record(record, expected_auth, present):
        if not present:
            require(not any(record), 'nonempty absent session-exit slot')
            return None
        r = record
        require(r[0] == 1 and r[1] == boot and first_generation <= r[2] <= last_generation
                and r[3] > 0, 'record boot/service/session identity mismatch')
        require(1 <= r[5] <= 16 and r[6] in RESULTS and 1 <= r[7] <= 8
                and r[8] <= 3 and r[9] <= 15 and bool(r[9] & 1) == expected_auth
                and (r[10] <= r[4] or r[6] == 0x1004) and r[12] <= 65535
                and r[16] <= 65536 and r[17] <= 65535 and r[23] == 0,
                'malformed session-exit record')
        return dict(boot=r[1], service_generation=r[2], connection_epoch=r[3], ms=r[4],
                    reason=REASONS[r[5] - 1], result=RESULTS[r[6]], original_result_code=r[6],
                    origin=ORIGINS[r[7] - 1], membership=r[8], state_flags=r[9], last_rx_ms=r[10],
                    peer_boot=r[11], last_message=dict(kind=r[12], sequence=r[13],
                    sender_boot=r[14], receiver_boot=r[15], body_bytes=r[16]),
                    last_tx_kind=r[17], last_tx_sequence=r[18],
                    session_fingerprint=struct.pack('<4Q', *r[19:23]).hex())

    first_unauth = decode_record(bank[8:32], False, unauth)
    first_auth = decode_record(bank[32:56], True, auth)
    latest_auth = decode_record(bank[56:80], True, auth)
    present = [r for r in (first_unauth, first_auth, latest_auth) if r]
    require(min(r['service_generation'] for r in present) == first_generation,
            'first retained generation does not match bank')
    if auth:
        # Retention follows publication order. Guest time is diagnostic data
        # and may regress in the very TLS Clock failure being retained.
        require(first_auth['service_generation'] <= latest_auth['service_generation'],
                'authenticated slot order mismatch')
        require(auth != 1 or first_auth == latest_auth, 'single authenticated exit differs between slots')
    return dict(scope='first_unauthenticated_first_authenticated_latest_authenticated_per_boot',
                counts=dict(unauthenticated=unauth, authenticated=auth),
                first_unauthenticated=first_unauth, first_authenticated=first_auth,
                latest_authenticated=latest_auth, ordinary_events_complete=words[6] <= 200,
                complete_session_history=False, native_pass=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=pathlib.Path)
    parser.add_argument('--boot', type=int, required=True)
    parser.add_argument('--service-generation', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(decode_session_exits(args.snapshot.read_bytes(), boot=args.boot,
                                        service_generation=args.service_generation), indent=2))
