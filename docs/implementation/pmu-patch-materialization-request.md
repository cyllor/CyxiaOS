# PMU accounting patch materialization request

This marker triggers the bounded workflow that converts the staged gzip patch into a reviewable UTF-8 diff before applying it to the native prototype source. It does not change runtime behaviour.

Attempt: 2 — use Python gzip decompression and commit the exact text payload.
