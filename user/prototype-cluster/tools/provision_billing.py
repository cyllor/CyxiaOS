#!/usr/bin/env python3
"""Add independent EL1 billing identities to an existing paired TLS identity."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def provision(root):
    nodes = [Path(root).resolve(strict=True) / name for name in ('a', 'b')]
    names = ('billing.seed', 'billing.pub', 'peer.billing.pub')
    for i, node in enumerate(nodes):
        public = (node / 'own.pub').read_bytes()
        if len(public) != 32 or hashlib.sha256(public).digest() != (node / 'local.pin').read_bytes():
            raise ValueError('TLS identity pin mismatch')
        if (node / 'peer.pin').read_bytes() != (nodes[1-i] / 'local.pin').read_bytes() or (node / 'peer.pub').read_bytes() != (nodes[1-i] / 'own.pub').read_bytes():
            raise ValueError('identities are not a mutual pair')
        if any((node / name).exists() for name in names):
            raise ValueError('refusing to replace or complete partial billing identities')
    with tempfile.TemporaryDirectory() as temp:
        seeds, publics = [], []
        for i in range(2):
            key = Path(temp) / f'{i}.der'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-outform', 'DER', '-out', str(key)], check=True)
            private = key.read_bytes()
            public = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', str(key), '-pubout', '-outform', 'DER'])
            if len(private) != 48 or private[:16] != bytes.fromhex('302e020100300506032b657004220420'):
                raise ValueError('noncanonical Ed25519 private key')
            if len(public) != 44 or public[:12] != bytes.fromhex('302a300506032b6570032100'):
                raise ValueError('noncanonical Ed25519 public key')
            seeds.append(private[16:]); publics.append(public[12:])
        if seeds[0] == seeds[1]:
            raise ValueError('billing identities must be independent')
        for i, node in enumerate(nodes):
            for name, data in zip(names, (seeds[i], publics[i], publics[1-i])):
                fd = os.open(node / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pair_directory')
    provision(parser.parse_args().pair_directory)
