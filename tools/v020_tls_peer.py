"""Loopback TLS peer for the QEMU SEC-N lane, using repository test keys."""
import base64
import hashlib
import math
from pathlib import Path
import secrets
import socket
import ssl
import struct
import tempfile
import time


FIXTURES = Path(__file__).resolve().parents[1] / "crates/net-transport/tests/fixtures"
ALPN = "cyxia-echo/1"
HEADER = struct.Struct("<HHIQ")
CHALLENGE_BYTES = 32
FRAME_BYTES = HEADER.size + CHALLENGE_BYTES
# The test pair uses single-day certificates. Match the guest's pinned-key
# profile while retaining OpenSSL signature and trust-anchor validation.
X509_V_FLAG_NO_CHECK_TIME = 0x200000


def _load_identity(context: ssl.SSLContext, name: str) -> bytes:
    cert = (FIXTURES / f"{name}-test-cert.der").read_bytes()
    key = (FIXTURES / f"{name}-test-key.der").read_bytes()
    # CPython load_cert_chain takes filenames. NamedTemporaryFile creates
    # a private file and removes it as soon as OpenSSL imports the pair.
    with tempfile.NamedTemporaryFile() as pem:
        pem.write(ssl.DER_cert_to_PEM_cert(cert).encode("ascii"))
        pem.write(b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(key)
                  + b"-----END PRIVATE KEY-----\n")
        pem.flush()
        context.load_cert_chain(pem.name)
    return cert


def exchange(port: int, timeout: float = 5.0, *, orderly_close: bool = False) -> dict:
    """Exchange one unpredictable read-only Echo frame with a pinned fixture guest.

    Both byte counts refer to the application frame. An invalid or incomplete
    exchange raises an exception and never produces a successful transcript.
    """
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ValueError("TLS peer timeout must be positive and at most 300 seconds")
    end = time.monotonic() + timeout

    def remaining() -> float:
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("TLS Echo peer deadline")
        return left

    server_cert = (FIXTURES / "b-test-cert.der").read_bytes()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_flags |= X509_V_FLAG_NO_CHECK_TIME
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(server_cert))
    context.set_alpn_protocols([ALPN])
    if hasattr(context, "set_groups"):
        context.set_groups("X25519")
    else:
        context.set_ecdh_curve("X25519")
    client_cert = _load_identity(context, "a")

    # OpenSSL can complete a server-only handshake even with a client key
    # configured. Require the client CertificateVerify in this handshake.
    client_signed = False
    close_notify = set()

    def observe(_sock, direction, _version, content_type, msg_type, _data):
        nonlocal client_signed
        if direction == "write" and content_type == 22 and msg_type == 15:
            client_signed = True
        if content_type == 21 and msg_type == 0:
            close_notify.add(direction)

    if not hasattr(context, "_msg_callback"):
        raise RuntimeError("SEC-N peer requires the CPython TLS message callback")
    context._msg_callback = observe

    with socket.create_connection(("127.0.0.1", port), timeout=remaining()) as raw:
        raw.settimeout(remaining())
        with context.wrap_socket(raw, suppress_ragged_eofs=not orderly_close) as conn:
            if conn.getpeercert(binary_form=True) != server_cert:
                raise ValueError("SEC-N server certificate differs from pinned fixture b")
            if conn.selected_alpn_protocol() != ALPN:
                raise ValueError("SEC-N server did not negotiate the Echo ALPN")
            if not client_signed:
                raise ValueError("SEC-N handshake omitted client CertificateVerify")
            challenge = secrets.token_bytes(CHALLENGE_BYTES)
            frame = HEADER.pack(1, 1, len(challenge), secrets.randbits(64)) + challenge
            conn.settimeout(remaining())
            conn.sendall(frame)
            reply = bytearray()
            while len(reply) < len(frame):
                conn.settimeout(remaining())
                chunk = conn.recv(len(frame) - len(reply))
                if not chunk:
                    raise EOFError("SEC-N peer closed before returning the Echo frame")
                reply.extend(chunk)
            if reply != frame:
                raise ValueError("SEC-N Echo header or challenge mismatch")
            result = {
                "tls_version": conn.version(),
                "alpn": conn.selected_alpn_protocol(),
                "client_certificate_verify": client_signed,
                "server_certificate_sha256": hashlib.sha256(server_cert).hexdigest(),
                "client_certificate_sha256": hashlib.sha256(client_cert).hexdigest(),
                "request_sha256": hashlib.sha256(frame).hexdigest(),
                "reply_sha256": hashlib.sha256(reply).hexdigest(),
                "sent": len(frame),
                "received": len(reply),
                "tls_close_notify_verified": False,
                "tcp_orderly_eof": False,
            }
            if orderly_close:
                conn.settimeout(remaining())
                with conn.unwrap() as transport:
                    if close_notify != {"read", "write"}:
                        raise ValueError("SEC-N TLS close_notify missing in one direction")
                    transport.settimeout(remaining())
                    transport.shutdown(socket.SHUT_WR)
                    if transport.recv(1):
                        raise ValueError("unexpected bytes before SEC-N TCP EOF")
                result["tls_close_notify_verified"] = True
                result["tcp_orderly_eof"] = True
            return result
