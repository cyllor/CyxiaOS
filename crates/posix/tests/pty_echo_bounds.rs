//! Regressions for the real public PTY interface; run in the normal POSIX crate.
use cyxia_posix::{
    Errno, O_NONBLOCK,
    pty::{CAPACITY, ECHO, ICANON, Ptys, Termios},
};

fn pair(p: &mut Ptys) -> (u64, u64) {
    let master = p.open_master(10, O_NONBLOCK).unwrap();
    let number = p.number(10, master).unwrap();
    p.lock(10, master, false).unwrap();
    let slave = p.open_slave(10, number, 0).unwrap();
    (master, slave)
}
#[test]
fn transformed_erase_backpressure_preserves_the_line() {
    let mut p = Ptys::new();
    let (m, s) = pair(&mut p);
    let mut t = Termios::DEFAULT;
    t.input = 0;
    t.local = ICANON | ECHO;
    t.cc[2] = b'\n';
    p.set_termios(10, s, t, false, false).unwrap();
    p.write(10, m, b"x").unwrap();
    p.write(10, s, &[b'a'; CAPACITY - 2]).unwrap();
    assert_eq!(p.output_pending(10, m), Ok(CAPACITY - 1));
    assert_eq!(p.write(10, m, b"\n"), Err(Errno::Again));
    assert_eq!(p.output_pending(10, m), Ok(CAPACITY - 1));
    let mut output = [0; CAPACITY + 1];
    assert_eq!(p.read(10, m, &mut output), Ok(CAPACITY - 1));
    // Undo the rejected erase mapping. The original x must still be present.
    t.cc[2] = 127;
    p.set_termios(10, s, t, false, false).unwrap();
    p.write(10, m, b"\n").unwrap();
    assert_eq!(p.read(10, s, &mut output), Ok(2));
    assert_eq!(&output[..2], b"x\n");
}
#[test]
fn transformed_kill_needs_four_bytes_not_three() {
    let mut p = Ptys::new();
    let (m, s) = pair(&mut p);
    let mut t = Termios::DEFAULT;
    t.input = 0;
    t.cc[3] = b'\n';
    p.set_termios(10, s, t, false, false).unwrap();
    p.write(10, m, b"x").unwrap();
    p.write(10, s, &[b'a'; CAPACITY - 4]).unwrap();
    assert_eq!(p.write(10, m, b"\n"), Err(Errno::Again));
    assert_eq!(p.output_pending(10, m), Ok(CAPACITY - 3));
    let mut output = [0; CAPACITY + 1];
    assert_eq!(p.read(10, m, &mut output), Ok(CAPACITY - 3));
    assert_eq!(p.write(10, m, b"\n"), Ok(1));
    assert_eq!(p.read(10, m, &mut output), Ok(4));
    assert_eq!(&output[..4], b"\r\n\r\n");
    t.cc[3] = 21;
    p.set_termios(10, s, t, false, false).unwrap();
    p.write(10, m, b"ok\n").unwrap();
    assert_eq!(p.read(10, s, &mut output), Ok(3));
    assert_eq!(&output[..3], b"ok\n");
}
#[test]
fn erase_and_kill_echo_reservation_matches_all_supported_output_flags() {
    for operation in [2, 3] {
        for output_flags in [0, 1, 4, 5] {
            for editing in [0, 0x10, 0x20, 0x30] {
                for free in 0..=5 {
                    let mut p = Ptys::new();
                    let (m, s) = pair(&mut p);
                    let mut t = Termios::DEFAULT;
                    t.input = 0;
                    t.output = output_flags;
                    t.local = ICANON | ECHO | editing;
                    t.cc[operation] = b'\n';
                    p.set_termios(10, s, t, false, false).unwrap();
                    p.write(10, m, b"x").unwrap();
                    p.write(10, s, &[b'a'; CAPACITY][..CAPACITY - free - 1])
                        .unwrap();
                    let newline = if output_flags == 5 { 2 } else { 1 };
                    let needed = if operation == 2 {
                        if editing & 0x10 != 0 { 3 } else { newline }
                    } else {
                        newline + if editing & 0x20 != 0 { newline } else { 0 }
                    };
                    let result = p.write(10, m, b"\n");
                    assert_eq!(
                        result,
                        if free >= needed {
                            Ok(1)
                        } else {
                            Err(Errno::Again)
                        },
                        "operation={operation} output={output_flags} local={editing} free={free}"
                    );
                    assert_eq!(
                        p.output_pending(10, m),
                        Ok(CAPACITY - free + if free >= needed { needed } else { 0 })
                    );
                }
            }
        }
    }
}
