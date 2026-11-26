"""Real loopback handshakes for the fixture client, independent of QEMU."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v020_tls_peer as peer


@contextmanager
def server(handler, *, identity="b", alpn="cyxia-echo/1", request_client=True):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0  # The guest also disables post-handshake tickets.
    context.set_alpn_protocols([alpn])
    peer._load_identity(context, identity)
    if request_client:
        context.verify_mode = ssl.CERT_REQUIRED
        client = (peer.FIXTURES / "a-test-cert.der").read_bytes()
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(client))
        context.verify_flags |= peer.X509_V_FLAG_NO_CHECK_TIME
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            with listener.accept()[0] as sock:
                sock.settimeout(5)
                with context.wrap_socket(sock, server_side=True) as tls:
                    return handler(tls)

        result = executor.submit(serve)
        yield listener.getsockname()[1], result


def read_exact(tls, n):
    data = bytearray()
    while len(data) < n:
        chunk = tls.recv(n - len(data))
        if not chunk:
            raise EOFError("incomplete client request")
        data.extend(chunk)
    return bytes(data)


class FixturePeerTests(unittest.TestCase):
    def test_mutual_tls_and_fragmented_exact_echo(self):
        def echo(tls):
            header = read_exact(tls, 16)
            version, op, length, _ = struct.unpack("<HHIQ", header)
            self.assertEqual((version, op, length), (1, 1, 32))
            frame = header + read_exact(tls, length)
            for chunk in (frame[:13], frame[13:]):
                tls.sendall(chunk)
            return tls.getpeercert(binary_form=True), frame

        with server(echo) as (port, server_result):
            result = peer.exchange(port)
            client_cert, frame = server_result.result()
        self.assertEqual(client_cert, (peer.FIXTURES / "a-test-cert.der").read_bytes())
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertTrue(result["client_certificate_verify"])
        self.assertEqual(result["alpn"], "cyxia-echo/1")
        self.assertEqual((result["sent"], result["received"]), (48, 48))
        self.assertEqual(result["request_sha256"], hashlib.sha256(frame).hexdigest())
        self.assertEqual(result["reply_sha256"], result["request_sha256"])

    def test_rejects_wrong_server_certificate(self):
        with server(lambda tls: tls.recv(1), identity="a") as (port, server_result):
            with self.assertRaises(ssl.SSLCertVerificationError):
                peer.exchange(port)
            with self.assertRaises(ssl.SSLError):
                server_result.result()

    def test_rejects_one_way_tls_or_wrong_alpn_before_request(self):
        for options, reason in (({"request_client": False}, "CertificateVerify"),
                                ({"alpn": "cyxia-cluster/1"}, "ALPN")):
            with self.subTest(options=options):
                with server(lambda tls: tls.recv(1), **options) as (port, server_result):
                    with self.assertRaisesRegex(ValueError, reason):
                        peer.exchange(port)
                    self.assertEqual(server_result.result(), b"")

    def test_rejects_mismatched_or_truncated_reply(self):
        def send_reply(tls):
            frame = read_exact(tls, 48)
            tls.sendall(frame[:-1] if truncated else frame[:-1] + bytes([frame[-1] ^ 1]))

        for truncated in (True, False):
            with self.subTest(truncated=truncated):
                with server(send_reply) as (port, server_result):
                    with self.assertRaises(EOFError if truncated else ValueError):
                        peer.exchange(port)
                    server_result.result()

    def test_silent_peer_exhausts_deadline(self):
        def withhold_reply(tls):
            read_exact(tls, 48)
            return tls.recv(1)

        with server(withhold_reply) as (port, server_result):
            with self.assertRaises(TimeoutError):
                peer.exchange(port, timeout=1.0)
            self.assertEqual(server_result.result(), b"")

    def test_orderly_tls_and_tcp_shutdown(self):
        def echo_and_close(tls):
            tls.sendall(read_exact(tls, peer.FRAME_BYTES))
            with tls.unwrap() as transport:
                self.assertEqual(transport.recv(1), b"")
                transport.shutdown(socket.SHUT_WR)

        with server(echo_and_close) as (port, server_result):
            result = peer.exchange(port, orderly_close=True)
            server_result.result()
        self.assertTrue(result["tls_close_notify_verified"])
        self.assertTrue(result["tcp_orderly_eof"])

    def test_echo_without_close_notify_cannot_prove_shutdown(self):
        def echo_only(tls):
            tls.sendall(read_exact(tls, peer.FRAME_BYTES))

        with server(echo_only) as (port, server_result):
            with self.assertRaises((OSError, EOFError, ValueError)):
                peer.exchange(port, orderly_close=True)
            server_result.result()
