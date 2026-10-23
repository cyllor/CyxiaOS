# Independently launched Wayland clients

`user/ported/smithay_dynamic_client.c` is a native CyxiaOS libwayland client for the dynamic admission fixture. The serial shell launches the same ELF with role arguments `1`, `2`, `3`, or capacity-probe role `0`. The role selects the test's expected events and pixel pattern; it is not the server's ownership credential.

The client rejects an inherited `WAYLAND_SOCKET` or open descriptor 3, sets `XDG_RUNTIME_DIR=/tmp` and `WAYLAND_DISPLAY=cyxia-wayland-0`, and calls the pinned upstream `wl_display_connect(NULL)`. Libwayland opens and connects the Unix socket itself. Each client queries actual `SO_PEERCRED`, records the server PID/UID/GID, and only then requests Wayland globals. The probe sends no Wayland request and succeeds only after reading real EOF; a connection failure, byte, polling error, or timeout fails.

The three normal roles use real registry bindings, an xdg-toplevel, configure acknowledgements, the received XKB keymap, and shared ARGB8888 buffers. A real synchronization callback establishes server buffer import before the client writes pixels. Every committed frame waits for its actual frame callback. Subsequent pixels use the received physical D-key code as their seed. Activation changes do not manufacture repaint input.

| Role | Frame seeds | Configure activation | Keyboard enter / ordinary leave | Ending |
| --- | --- | --- | --- | --- |
| A / 1 | 0, 32, 32, 32 | 1, 0, 1, 0, 1 | 3 / 2 | Q: null commit, release buffers, destroy objects, disconnect |
| B / 2 | 0, 32 | 1 | 1 / 0 | Q: normal teardown |
| C / 3 | 0, 32 | 1 | 1 / 0 | X: disconnect with live objects, then process exit |

All buffers are 64 × 48. Frame callback scene indices are A `[1, 2, 6, 10]`, B `[3, 4]`, and C `[7, 8]`. A and B require every buffer release and their closing keyboard leave before success. C instead records its actual two callbacks, one retired-buffer release, and four keyboard events while its current buffer is still live. It calls `wl_display_disconnect` without a null commit, proxy destruction, or shared-memory unmapping, then `_exit(0)`. Server retirement and kernel reclamation must be independently verified; the client does not claim graceful cleanup for C.

Each `DYN_CLIENT` receipt occupies one write of at most 64 bytes. Interrupted writes retry the same full record; short writes fail. Display waits obey libwayland's prepare/read/cancel contract and use bounded monotonic deadlines.

The new builder uses the checked static target SDK and exact pinned xdg-shell XML, records actual compiler dependencies, includes the audited libwayland connection implementation in its input manifest, and rechecks hashes after linking. It creates fresh output directories and does not modify the SDK or earlier milestones.

## Verification status

The 15 targeted host tests pass in `artifacts/smithay-dynamic-client-host-r0.txt`. They cover protocol/archive/scanner provenance, dependency containment, immutable outputs, real C atomic receipt boundaries, and the production EOF gate's byte/error/timeout/retry cases. The frozen cross-build in `artifacts/smithay-dynamic-client-r0` passed: the 411,968-byte ELF has SHA-256 `613d8817be4e8a082d17cc684bb8ff8e42fbabf5d86378987c43a9005ad2fac2`, and its report binds 68 actual inputs. Guest runtime and independent raw evidence review are pending; host and link results alone do not establish dynamic guest admission.
