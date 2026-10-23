# PTY and terminal implementation

The terminal is an actual AArch64 EL0 Xlib application. It opens a kernel PTY,
starts a separate `/bin/cyxia-sh` ELF process with the slave mapped to descriptors
0, 1 and 2, and draws bytes read from the master into its X11 window. Keyboard
events write bytes to that master. Neither input handling nor shell commands run
on the host. X.Org performs the rendering through the CyxiaOS graphics driver.

## Components and policy

- `crates/posix/src/pty.rs` is an allocation-free state machine with four PTY
  records, independent 4096-byte input/output rings, 512-byte canonical editing
  storage and 64 committed line/EOF records per PTY.
- `kernel/src/user/pty.rs` owns the foreground-only pool and checked ioctl
  user-copy. Pool backing is bootstrap memory. Creating a master requires an
  actual local-model 8193 decision on logical free-pool occupancy; denial returns
  `EAGAIN`. The current policy can deny before all four physical slots fill.
- The existing process and thread models admit and schedule the terminal and its
  shell as separate processes. PTY byte movement and line discipline are bounded
  mechanisms, not additional learned policies.
- The supervisor routes pending `SIGINT`, `SIGHUP` and `SIGWINCH` to the actual
  controlling process. Existing signal masks, handlers, interruption, and exit
  handling apply. Each process releases an endpoint only after its last local
  descriptor alias is closed. Spawn grants the shared endpoint once per child
  description; failed spawn and process exit roll back those grants.

## Implemented interface

`/dev/ptmx` opens a locked master. `TIOCSPTLCK` unlocks the corresponding slave;
`TIOCGPTN`, `/dev/pts/N`, and `TIOCGPTPEER` expose it. Both ends participate in
`read`, `write`, `readv`, `writev`, `poll`, descriptor duplication, `fcntl` status
flags, `FIONREAD`, `fstat` as a character device, and explicit spawn mappings.
Partial I/O and nonblocking `EAGAIN` preserve ring contents. Blocking I/O yields
to the AI scheduler. Each ordinary syscall copy window remains bounded to 1 KiB.

`TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF`, `TCFLSH`, `TIOCOUTQ`,
`TIOCGWINSZ`/`TIOCSWINSZ`, `TIOCSCTTY`, and `TIOCGPGRP`/`TIOCSPGRP` have explicit
bounded implementations. Canonical mode supports erase, kill, newline, partial
line EOF, and empty EOF. Raw mode supports `VMIN=1, VTIME=0`. Echo and CR/LF
mapping are real byte transformations. Unsupported flags, timing modes and
control characters are rejected rather than accepted without implementation.
Changing canonical mode with pending input requires an input flush or returns
`EAGAIN`; drain setters also return `EAGAIN` while output remains buffered.
An input exceeding the PTY's own 511 content-byte canonical bound is discarded
through newline/EOF and produces one `E2BIG` read result. This explicit bounded
extension prevents a truncated command from executing and lets queued delimiters
still make progress. Ordinary canonical short reads preserve the unread line
remainder; valid 512-byte records including newline remain readable in full.

The current controlling-terminal contract has one foreground **process**, not a
full process-group/session/job-control implementation. A slave holder may claim
only its own PID. An unrelated PID cannot be targeted through these ioctls.
There is one endpoint description per process and side; `dup` and spawn share
that endpoint and its status flags. Independently opening the same side twice in
one process returns `EEXIST`. The slave path is a synthetic device namespace,
not a mounted devpts filesystem.

Linux AArch64 ioctl command values and the 36-byte kernel termios wire layout
follow the upstream [generic ioctl ABI](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/uapi/asm-generic/ioctls.h)
and [termios ABI](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/uapi/asm-generic/termbits.h).
Commands are normalized to 32 bits because musl can sign-extend `_IOR` values.

## Programs and limits

`cyxia-terminal` uses the upstream Xlib fixed font, a resizable grid bounded to
120 columns × 48 rows, and CR/LF/backspace/tab plus ANSI cursor/erase sequences.
It preserves pending keyboard bytes under PTY backpressure and bounds output
draining to keep X events responsive. It closes its master on window close,
causing a real hangup of its controlling shell, and reaps the child. It renders
ASCII text; Unicode shaping, selection/clipboard, scrollback, full xterm escape
sequences and terminal applications requiring job control are future work.
Each resize performs `TIOCSWINSZ` followed by `TIOCGWINSZ` and checks the exact
returned rows/columns before reporting a successful resize. An ioctl/readback
failure makes the application exit with an error.

`cyxia-sh` is a basic built-in command shell. It implements `help`, `pwd`, `cd`,
`ls`, `cat`, `write`, `append`, `touch`, `mkdir`, `rm`, `rmdir`, `mv`, `cp`, `stat`,
`sleep`, `clear`, and `exit`. Simple quoted arguments preserve spaces. File
commands call the real kernel filesystem API. Ctrl-C interrupts read/sleep;
Ctrl-D exits. Pipelines, command expansion and external-command job control are
not implemented. The desktop's explicit Save files action is still required for
durability; normal shell writes alone do not imply a completed disk checkpoint.
The shell buffers a complete legal canonical record and treats the over-capacity
error as a rejected line, then resumes its prompt. Guest tests confirm that an
overlong `write` command cannot create its target file.

## Validation

The POSIX host tests cover canonical edits/line boundaries/EOF, ring wrap and
backpressure, output translation, termios rejection, endpoint sharing and
descriptor aliases, stale handles, retired generations, and foreground-process
signal isolation. All 87 POSIX host tests and host Clippy with warnings denied
passed during implementation.

`tools/verify_pty.py` runs the actual target `pty-probe`, including raw byte
transfers, a spawned child with canonical input and real signal handlers, exit
status/reaping, repeated PTY reuse, and a second spawned `cyxia-sh` which writes
and reads a RAMFS file and handles Ctrl-C. It checks the exact embedded probe
image and final memory/process receipts. Runtime results are recorded separately;
the existence of source code or a successful build alone is not a runtime pass.

The final 512 MiB profile passed a real guest run in
`artifacts/desktop-integrated-r4/pty/summary.json`, using the saved
`artifacts/desktop-integrated-r4/cyxia-kernel.elf`, SHA-256
`f432d168507faf0276f97dd4689401314d91d9b90c5b08c67ca054b990a929ee`.
Every run passed raw bounds, canonical child exchange, actual SIGINT/SIGWINCH
and EOF, repeated endpoint lifetime/reuse, and real shell file/Ctrl-C/exit
workflows. All process, heap, image and thread allocations were reclaimed.
Six existing ABI probes also passed on this image in
`artifacts/desktop-integrated-r4/abi/summary.json`.

The baseline 256 MiB profile, including the final over-capacity line rejection,
also passed in `artifacts/pty-runtime-256-r5/summary.json`, using the saved
`artifacts/pty-runtime-256-r5/cyxia-kernel.elf`, SHA-256
`c98a50b43bb960a0d91bc504aa1c1600c92b157c0c712725d4c381bf3517ddc8`.

This gate found and fixed a supervisor retry race: a timer could mark a blocked
read runnable while its PC still pointed to the retried SVC. A signal arriving
in that interval ran its handler and then retried the old read. Each thread now
retains the retry marker until actual syscall re-entry; signal delivery skips
the saved SVC and returns `EINTR` even after a readiness wake.

`tools/verify_terminal.py` separately tests the complete real graphical path:
LXPanel menu launch, physical keyboard mkdir/write/cat, cross-check against the
serial filesystem, Openbox resize, sleep interruption, normal exit, window-close
hangup, and reclamation. Its result is separate from the PTY ABI gate.

The complete graphical gate passed on the same final `f432d168…` kernel in
[`artifacts/desktop-integrated-r4/terminal-final/summary.json`](../../artifacts/desktop-integrated-r4/terminal-final/summary.json).
Real menu launch created a terminal and a separate shell; physical keyboard
input created `/terminal-test/note.txt` containing exactly the expected text,
which the independent serial shell read back. Alt+right-drag changed the client
from **496 × 328** to **616 × 393**, and the final PTY readback was **100 columns ×
29 rows**. A command queued behind `sleep 10` remained unexecuted after one
second; Ctrl-C flushed that queued input and allowed a different file write
before the original sleep deadline. Normal shell exit reaped status zero; closing
the terminal with Alt+F4 delivered real SIGHUP to the shell (signal 1, code 129)
and reaped it. Final process states were inactive, all owned image/heap/thread
counts were zero, the admission ledger had 64 free pages, and every process's
heap/image pools returned to 4096 free pages.

The [file-operation screenshot](../../artifacts/desktop-integrated-r4/terminal-final/terminal-file.png)
and [resized/interrupted screenshot](../../artifacts/desktop-integrated-r4/terminal-final/terminal-resized.png)
were also visually inspected: the actual `cat` output is visible, and the latter
shows Ctrl-C followed by the completed write command and a new shell prompt.
This visual inspection is recorded separately from automated assertions in
`artifacts/desktop-integrated-r4/terminal-final/visual-review.json`. Original QEMU
PPM captures, QMP events and serial transcripts are retained in the same folder.
