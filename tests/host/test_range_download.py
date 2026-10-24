"""Offline tests. Fake HTTP responses verify transport logic, not availability."""
from email.message import Message
from email.utils import formatdate
import fcntl
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from range_download import DownloadError, download_ranges, retry_delay

URL = "https://example.invalid/pinned.tar.xz"
BODY = b"fixed upstream bytes"
PIN = hashlib.sha256(BODY).hexdigest()


class Clock:
    def __init__(self): self.value = 0; self.delays = []
    def now(self): return self.value
    def wall(self): return 1700000000 + self.value
    def sleep(self, delay): self.delays.append(delay); self.value += delay


class Response(io.BytesIO):
    def __init__(self, data, start, end, total):
        super().__init__(data)
        self.status = 206
        self.url = URL
        self.headers = {"Content-Range": f"bytes {start}-{end}/{total}", "Content-Length": str(end-start+1)}
    def geturl(self): return self.url


class Opener:
    def __init__(self, body=BODY, failures=(), alter=None):
        self.body = body; self.failures = list(failures); self.alter = alter; self.requests = []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.failures:
            raise self.failures.pop(0)
        bounds = request.get_header("Range").removeprefix("bytes=")
        start, end = map(int, bounds.split("-"))
        response = Response(self.body[start:end+1], start, end, len(self.body))
        if self.alter: self.alter(response)
        return response


def http(code, retry=None):
    headers = Message()
    if retry is not None: headers["Retry-After"] = retry
    return HTTPError(URL, code, "test response", headers, io.BytesIO())


class RangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.output = self.root / "source.tar.xz"; self.clock = Clock()
    def download(self, opener, **extra):
        options = dict(size=len(BODY), sha256=PIN, max_bytes=1024, chunk_size=4, opener=opener,
                       clock=self.clock.now, wall_clock=self.clock.wall, sleep=self.clock.sleep)
        options.update(extra)
        return download_ranges(URL, self.output, **options)
    def test_exact_ranges_are_assembled_and_verified(self):
        opener = Opener(); self.assertEqual(self.download(opener), self.output)
        self.assertEqual(self.output.read_bytes(), BODY)
        self.assertEqual([r.get_header("Range") for r, _ in opener.requests],
                         [f"bytes={i}-{min(i+3,len(BODY)-1)}" for i in range(0,len(BODY),4)])
        self.assertTrue(all(r.get_header("Accept-encoding") == "identity" for r, _ in opener.requests))
    def test_429_respects_server_retry_after(self):
        self.download(Opener(failures=[http(429,"5")]))
        self.assertEqual(self.clock.delays,[5.0])
    def test_http_date_retry_after(self):
        date = formatdate(self.clock.wall()+12, usegmt=True)
        self.download(Opener(failures=[http(503,date)]))
        self.assertEqual(self.clock.delays,[12.0])
    def test_transient_errors_use_bounded_exponential_backoff(self):
        self.download(Opener(failures=[http(503), URLError("offline test"), TimeoutError()]))
        self.assertEqual(self.clock.delays,[1.0,2.0,4.0])
    def test_retry_budget_is_finite(self):
        opener=Opener(failures=[http(429)]*4)
        with self.assertRaisesRegex(DownloadError,"retry budget"):
            self.download(opener)
        self.assertEqual(len(opener.requests),4); self.assertFalse(self.output.exists())
    def test_does_not_ignore_long_retry_after(self):
        with self.assertRaisesRegex(DownloadError,"Retry-After"):
            self.download(Opener(failures=[http(429,"600")]),budget_seconds=30)
        self.assertEqual(self.clock.delays,[])
    def test_permanent_http_errors_not_retried(self):
        opener=Opener(failures=[http(404)])
        with self.assertRaisesRegex(DownloadError,"non-retryable"):
            self.download(opener)
        self.assertEqual(len(opener.requests),1);self.assertEqual(self.clock.delays,[])
    def test_status_200_not_accepted_as_a_range(self):
        with self.assertRaises(DownloadError):
            self.download(Opener(alter=lambda r:setattr(r,"status",200)))
        self.assertFalse(self.output.exists())
    def test_wrong_range_total_rejected(self):
        with self.assertRaises(DownloadError):
            self.download(Opener(alter=lambda r:r.headers.update({"Content-Range":"bytes 0-3/999"})))
    def test_incorrect_content_length_rejected(self):
        with self.assertRaises(DownloadError):
            self.download(Opener(alter=lambda r:r.headers.update({"Content-Length":"999"})))
    def test_compressed_ranges_rejected(self):
        with self.assertRaises(DownloadError):
            self.download(Opener(alter=lambda r:r.headers.update({"Content-Encoding":"gzip"})))
    def test_https_downgrade_response_rejected(self):
        with self.assertRaises(DownloadError):
            self.download(Opener(alter=lambda r:setattr(r,"url","http://example.invalid/archive")))
    def test_truncated_body_rejected(self):
        def truncate(r): r.seek(0);r.truncate(1);r.seek(0)
        with self.assertRaises(DownloadError):self.download(Opener(alter=truncate))
    def test_oversized_body_rejected(self):
        def grow(r): r.seek(0,2);r.write(b"extra");r.seek(0)
        with self.assertRaises(DownloadError):self.download(Opener(alter=grow))
    def test_invalid_hash_never_publishes_archive(self):
        with self.assertRaisesRegex(DownloadError,"SHA256"):
            self.download(Opener(),sha256="0"*64)
        self.assertFalse(self.output.exists());self.assertEqual(list(self.root.glob(".unverified-*")),[])
    def test_verified_archive_reuse_requires_no_network(self):
        self.download(Opener());opener=Opener(failures=[AssertionError("network not expected")])
        self.download(opener);self.assertEqual(opener.requests,[])
    def test_corrupt_existing_archive_preserved(self):
        self.output.write_bytes(b"existing evidence")
        with self.assertRaisesRegex(DownloadError,"Existing archive"):
            self.download(Opener())
        self.assertEqual(self.output.read_bytes(),b"existing evidence")
    def test_symlink_archive_never_overwrites_target(self):
        other=self.root/"other";other.write_bytes(b"untouched");self.output.symlink_to(other)
        with self.assertRaisesRegex(DownloadError,"symlink"):
            self.download(Opener())
        self.assertEqual(other.read_bytes(),b"untouched")
    def test_symlink_part_rejected(self):
        parts=self.root/f".ranges-{PIN}-{len(BODY)}-4";parts.mkdir()
        other=self.root/"other";other.write_bytes(BODY[:4]);(parts/"0-3.part").symlink_to(other)
        with self.assertRaisesRegex(DownloadError,"symlink"):
            self.download(Opener())
    def test_corrupted_length_matching_cache_still_fails_final_hash(self):
        parts=self.root/f".ranges-{PIN}-{len(BODY)}-4";parts.mkdir();(parts/"0-3.part").write_bytes(b"BAD!")
        with self.assertRaisesRegex(DownloadError,"SHA256"):
            self.download(Opener())
        self.assertFalse(self.output.exists())
    def test_other_writer_is_not_waited_on(self):
        lock=self.output.with_suffix(self.output.suffix+".lock")
        with lock.open("wb") as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(DownloadError,"Another download"):
                self.download(Opener())
    def test_invalid_manifest_fields_fail_before_network(self):
        for options in [dict(size=True),dict(size=1025),dict(sha256="bad"),dict(attempts=0),dict(chunk_size=0),dict(budget_seconds=0)]:
            with self.subTest(options=options):
                opener=Opener()
                with self.assertRaises(DownloadError):self.download(opener,**options)
                self.assertEqual(opener.requests,[])
    def test_unsafe_url_is_rejected(self):
        for url in ["http://example.invalid/a","https://name:secret@example.invalid/a","https://example.invalid/a#frag"]:
            with self.assertRaises(DownloadError):download_ranges(url,self.output,size=len(BODY),sha256=PIN,max_bytes=1024,opener=Opener())
    def test_bad_retry_after_uses_bounded_default(self):
        for value in ["bad","-4","1.5",""]:
            self.assertEqual(retry_delay(value,0,self.clock.wall()),1.0)
        self.assertEqual(retry_delay(None,8,self.clock.wall()),16.0)
    def test_deadline_includes_response_processing(self):
        def slow(response): self.clock.value += 31
        with self.assertRaisesRegex(DownloadError,"elapsed budget"):
            self.download(Opener(alter=slow),budget_seconds=30)
        self.assertFalse(self.output.exists())


if __name__ == "__main__": unittest.main()
