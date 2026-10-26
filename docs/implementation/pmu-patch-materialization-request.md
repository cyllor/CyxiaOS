# PMU accounting patch materialization request

This marker triggers the bounded workflow that converts the staged gzip patch into reviewable bytes before applying it to the native prototype source. It does not change runtime behaviour.

Attempt: 3 — commit an RFC 4648 base64 representation plus SHA-256 checksums so the exact staged payload can be decoded and inspected independently of gzip tooling.
