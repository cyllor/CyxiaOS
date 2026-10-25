# CyxiaOS native cluster transport

This crate implements guest-resident Ethernet/ARP/IPv4/TCP, the v1.3 96-byte RPC
header and bounded stream decoder, plus an optional real mutual TLS 1.3 engine.
Transport authentication does not authorize membership or resource admission.
The original kernel-core cluster wire format is a different legacy protocol.

## Memory and ownership

The default build is `no_std`, forbids unsafe code and uses no heap. `Tcp` borrows
one fixed socket slot and two 32 KiB TCP buffers. Its `Ethernet` adapter stages one
1514-byte frame per direction and preserves packets under NIC backpressure.
`VirtioPort` borrows the existing pinned, single-owner VirtIO-net driver. Polling
does not wait for the peer. Address configuration, monotonic clock regression,
NIC failure and an unexpected peer endpoint fail closed.

TCP is one static directly connected IPv4 pair (prefix lengths 1–30); there is no
routing, DNS, DHCP or IPv4 reassembly in this profile. UDP discovery and its
eight-candidate/four-handshake budgets remain pending. The TCP seed must come
from the guest entropy service. A numeric seed argument is not entropy proof.

The RPC decoder borrows 65,632 bytes, accepts exactly one message at a time and
preserves the next message's suffix. Malformed headers poison the stream. The
replay gate checks monotonically increasing session sequences and current boot
epochs; it is not an authentication or persistent deduplication API.

## TLS feature

`--features tls` enables rustls's unbuffered client/server API with allocation.
Both peers must prove possession of the pinned Ed25519 key; NodeID is SHA-256 of
the raw public key. Certificate parsing uses rustls-webpki. There is no accepting
verifier, anonymous mode or plaintext fallback. The sole suite is
TLS_AES_128_GCM_SHA256, with X25519 and Ed25519 CertificateVerify. TLS 1.2,
resumption and early data are disabled. The smaller NodeID initiates the primary
connection. Certificate validity dates do not establish authority for this
closed pairing model; an explicit TimeProvider is still mandatory and None
rejects construction/continued use.

Per session, caller storage is 96 KiB (two 32 KiB ciphertext buffers and two
16 KiB plaintext buffers), in addition to rustls allocations. A five-second
handshake deadline and monotonic clock checks apply even under output
backpressure. A full input buffer with no possible progress poisons the session.
Every TCP EOF, reset, timeout and fatal NIC error **must call Session::abort**;
that revokes the live peer identity and clears pending buffers. A reconnect
requires a new TLS connection and subsequent HELLO/STATUS/READY reconciliation.
Only call consume_tls for bytes the real TCP stream has accepted.

**Native TLS is not yet integrated.** The current kernel has no quota-backed
GlobalAlloc for rustls, no registered getrandom callback backed by its entropy
service, and no provisioned private identity service. ring 0.17.14's bare-metal
C build needs its freestanding RING_CORE_NOSTDLIBINC setting; the existing
`aarch64-unknown-none-softfloat` target then fails ring's AArch64 NEON assertion.
Do not suppress that assertion: a separately protected EL0 service target with
FP/SIMD support and a measured allocation budget is required. Host TLS tests use
the host CSPRNG and prove the library integration, not guest TLS execution.
Test private keys under tests/fixtures are public fixtures, never deployment keys.

## Dependencies and verification

Pinned direct dependencies:

- [smoltcp 0.14.0](https://docs.rs/smoltcp/0.14.0/smoltcp/), default features off;
  medium-ethernet, proto-ipv4, socket-tcp, socket-udp.
- [rustls 0.23.45](https://docs.rs/rustls/0.23.45/rustls/), optional, default
  features off; ring only.
- [ring 0.17.14](https://docs.rs/ring/0.17.14/ring/), optional, default features
  off; alloc and less-safe-getrandom-custom-or-rdrand. The latter is explicitly
  contingent on a reviewed guest CSPRNG integration, not a random fallback.
- [getrandom 0.2.17](https://docs.rs/getrandom/0.2.17/getrandom/), optional custom
  backend support; there is currently no guest backend registration.

Run `cargo test --locked --offline -p cyxia-cluster-transport --features tls` and
`cargo clippy --locked --offline -p cyxia-cluster-transport --features tls
--all-targets -- -D warnings`. Default cross-check:
`cargo check --locked --offline -p cyxia-cluster-transport
--target aarch64-unknown-none-softfloat`.

`tcp-v13-selftest` boots two four-core, 1 GiB native guests. Each first commits
BootEpoch on a different 512 MiB volume, acquires VirtIO entropy, then exchanges
65,536 diagnostic payload bytes in each direction with application ACKs. This
is **EL1 plaintext TCP bring-up**, not the final EL0 network service. The runner
`tools/verify_v13_tcp.py` independently checks PCAP IPv4/TCP checksums, the actual
three-way handshake, TCP stream reassembly including retransmissions, cumulative
ACKs, both captures' challenge identity, native evidence, and committed disk
records. `--disconnected` and `--without-entropy` are negative runs that must FAIL.
No full A/T/E or action-family acceptance is granted by these component checks.

Still pending: guest TLS/identity integration, UDP discovery, HELLO binding,
heartbeats and isolation, canonical message bodies/schema hash, persistent member
proofs, QUOTE/PREPARE/COMMIT/ACTIVATE, result handoff and full native fault matrix.
