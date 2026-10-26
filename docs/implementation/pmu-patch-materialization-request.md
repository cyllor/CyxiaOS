# PMU accounting patch materialization request

This marker triggers the bounded workflow that reconstructs the checksum-pinned source repair, validates the full native and host test surface, and commits only runtime source, tests, and non-workflow staging cleanup. It does not change runtime behaviour by itself.

Attempt: 7 — exclude repository workflows and this trigger marker from the historical patch while retaining byte-for-byte checksum verification of the runtime repair.
