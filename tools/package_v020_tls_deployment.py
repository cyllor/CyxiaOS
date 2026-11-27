#!/usr/bin/env python3
"""Prepare public SEC-N deployment inputs and the detached TLS signing message."""
import argparse
import hashlib
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path
import struct


def digest(data):
    return hashlib.sha256(data).digest()


def read_bounded(path, minimum, maximum):
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if not minimum <= len(data) <= maximum:
        raise ValueError(f"invalid public input size for {path.name}")
    return data


def generation(value):
    integer = int(value)
    if not 1 <= integer < 2**64:
        raise argparse.ArgumentTypeError("expected nonzero u64 generation")
    return integer


def prepare(args):
    predecessor = None
    if args.predecessor is not None:
        predecessor = read_bounded(args.predecessor, 576, 65_856)
    wire = bytearray(184)
    wire[:8] = b"CYXNET01"
    struct.pack_into("<3Q", wire, 8, args.key_generation, args.verifier_generation,
                     args.signer_generation)
    if predecessor is not None:
        wire[32:64] = digest(predecessor)
    files = {}
    if args.state == "revoked":
        if predecessor is None:
            raise ValueError("revocation requires the exact preceding offline envelope")
        wire[73] = 2
    else:
        network = args.local.network
        local = args.local.ip
        peer = args.peer
        if (not 1 <= network.prefixlen <= 30 or not 1 <= args.port <= 65535
                or local == peer or peer not in network or any(
                    not 1 <= address.packed[0] < 224 or address.packed[0] == 127
                    or address in (network.network_address, network.broadcast_address)
                    for address in (local, peer))):
            raise ValueError("expected distinct usable IPv4 hosts in the same subnet")
        mac = bytes.fromhex(args.mac.replace(":", ""))
        if len(mac) != 6 or mac == bytes(6) or mac[0] & 1:
            raise ValueError("expected a unicast NIC MAC")
        local_pin = read_bounded(args.local_pin, 32, 32)
        peer_pin = read_bounded(args.peer_pin, 32, 32)
        if local_pin <= peer_pin or peer_pin == bytes(32):
            raise ValueError("the passive Echo server pin must sort after the client pin")
        files = {
            "tls-verifier.elf": read_bounded(args.verifier, 64, 4 * 1024 * 1024),
            "tls-signer.elf": read_bounded(args.signer, 64, 256 * 1024),
            "tls-ingress.elf": read_bounded(args.ingress, 64, 64 * 1024),
        }
        wire[64:68] = local.packed
        wire[68:72] = peer.packed
        wire[72] = network.prefixlen
        wire[73] = 1
        struct.pack_into("<H", wire, 74, args.port)
        wire[76:82] = mac
        wire[88:120] = local_pin
        wire[120:152] = peer_pin
        wire[152:184] = digest(files["tls-ingress.elf"])
        files["tls-packages-to-sign.bin"] = (
            b"CYX/TLS-PACKAGES/v1"
            + struct.pack("<3Q", args.verifier_generation, args.signer_generation,
                          args.key_generation)
            + digest(wire) + digest(files["tls-verifier.elf"]) + digest(files["tls-signer.elf"])
        )
    files["key-manifest.bin"] = wire
    files["key-generation.txt"] = f"{args.key_generation}\n".encode("ascii")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-generation", type=generation, required=True)
    parser.add_argument("--verifier-generation", type=generation, required=True)
    parser.add_argument("--signer-generation", type=generation, required=True)
    parser.add_argument("--predecessor", type=Path, help="exact prior offline-config.bin")
    modes = parser.add_subparsers(dest="state", required=True)
    active = modes.add_parser("active")
    active.add_argument("--local", type=IPv4Interface, required=True)
    active.add_argument("--peer", type=IPv4Address, required=True)
    active.add_argument("--port", type=int, required=True)
    active.add_argument("--mac", required=True)
    for name in ("local-pin", "peer-pin", "verifier", "signer", "ingress"):
        active.add_argument("--" + name, type=Path, required=True)
    modes.add_parser("revoked")
    args = parser.parse_args()
    try:
        files = prepare(args)
        args.output.mkdir()
        for name, data in files.items():
            (args.output / name).write_bytes(data)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
