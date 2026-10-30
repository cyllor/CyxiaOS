"""Reassemble reviewed transport fragments; require the original delivered bytes."""
from pathlib import Path
import hashlib
import sys

root = Path(__file__).resolve().parent
names = ["v013-pending-delivered.patch"] + [
    f"v013-pending-delivered.part-{part:02}.patch" for part in (2, 3, 4)
]
data = b"".join((root / name).read_bytes() for name in names)
expected = "f741458ac033bd7dda0b02bb020da1702bca126c5afc09a410961f5ac61af536"
transport = "1d3c0f774effb735aec712b507cebd8f0c39e3a1314a633cf77de8d43bb66d36"
if hashlib.sha256(data).hexdigest() == transport:
    # A context line lost its trailing bracket during text transfer. This is
    # neither a product-source edit nor permission to accept a different patch.
    old = b"         lock = source[source.index('fn locked<R>'):source.index('/// CPU0, before')\n"
    new = b"         lock = source[source.index('fn locked<R>'):source.index('/// CPU0, before')]\n"
    if data.count(old) != 1:
        raise SystemExit("transport correction did not match exactly once")
    data = data.replace(old, new)
actual = hashlib.sha256(data).hexdigest()
if actual != expected or len(data) != 98774:
    raise SystemExit(f"original patch identity mismatch: {actual}, bytes={len(data)}")
Path(sys.argv[1]).write_bytes(data)
print(f"ORIGINAL_PATCH_VERIFIED={actual} bytes={len(data)}")
