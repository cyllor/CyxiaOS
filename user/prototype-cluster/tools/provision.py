#!/usr/bin/env python3
"""Provision two dev identities outside source/images; each node dir has own key only."""
import hashlib, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(mode=0o700, parents=True, exist_ok=True)
if any(root.iterdir()):
    raise SystemExit("destination must be empty; refusing identity replacement")
with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    for name in ("a", "b"):
        node = root / name
        node.mkdir(mode=0o700)
        key = temp / (name + ".pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "DER", "-out", str(node / "key.der")], check=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(key), "-subj", "/CN=Cyxia development " + name, "-days", "3650", "-outform", "DER", "-out", str(node / "cert.der")], check=True)
        public = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
        if public[:12] != bytes.fromhex("302a300506032b6570032100") or len(public) != 44:
            raise SystemExit("invalid Ed25519 SPKI")
        (node / "own.pub").write_bytes(public[12:])
        (node / "local.pin").write_bytes(hashlib.sha256(public[12:]).digest())
    for name, peer in (("a", "b"), ("b", "a")):
        node = root / name
        (node / "peer.pub").write_bytes((root / peer / "own.pub").read_bytes())
        (node / "peer.pin").write_bytes((root / peer / "local.pin").read_bytes())
        for path in node.iterdir():
            os.chmod(path, 0o600)
        print(name, "NodeID=" + (node / "local.pin").read_bytes().hex())
