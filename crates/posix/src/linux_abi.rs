//! ISA-specific Linux syscall numbers and wire codecs, separated from shared policy.
//! Number sources: pinned musl 1.2.6 arch/{aarch64,x86_64}/bits/syscall.h.in.
//! Unsupported operations return Nosys; an x86 number is never interpreted as Arm.
use crate::{Errno, FileInfo, ImageAbi};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Readlinkat,
    Accept,
    Accept4,
    ArchPrctl,
    Bind,
    Brk,
    Chdir,
    ClockGetres,
    ClockGettime,
    ClockNanosleep,
    Clone,
    Close,
    Connect,
    Dup,
    Dup2,
    Dup3,
    EpollCreate1,
    EpollCtl,
    EpollPwait,
    Eventfd2,
    Exit,
    ExitGroup,
    Faccessat,
    Fchmod,
    Fchmodat,
    Fcntl,
    Fdatasync,
    Flock,
    Fstat,
    Fsync,
    Ftruncate,
    Futex,
    Getcwd,
    Getdents64,
    Getegid,
    Geteuid,
    Getgid,
    Getpeername,
    Getpgid,
    Getpid,
    Getppid,
    Getrandom,
    Getresgid,
    Getresuid,
    Getrlimit,
    Getsid,
    Getsockname,
    Getsockopt,
    Gettid,
    Gettimeofday,
    Getuid,
    InotifyInit1,
    InotifyAddWatch,
    InotifyRmWatch,
    Ioctl,
    Kill,
    Listen,
    Lseek,
    MemfdCreate,
    Mkdirat,
    Mmap,
    Mprotect,
    Munmap,
    Nanosleep,
    Newfstatat,
    Openat,
    Pipe2,
    Poll,
    Ppoll,
    Pread64,
    Prlimit64,
    Pwrite64,
    Read,
    Readv,
    Recvfrom,
    Recvmsg,
    Renameat,
    Renameat2,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    SchedYield,
    Sendmsg,
    Sendto,
    SetTidAddress,
    Setpgid,
    Setsockopt,
    Shutdown,
    Sigaltstack,
    Socket,
    Socketpair,
    Tgkill,
    TimerfdCreate,
    TimerfdGettime,
    TimerfdSettime,
    Tkill,
    Umask,
    Uname,
    Unlinkat,
    Wait4,
    Write,
    Writev,
    DisplayInfo,
    DisplayBlit,
    InputRead,
    InputState,
    Spawn,
    CheckpointStart,
    CheckpointPoll,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub call: Call,
    pub args: [u64; 6],
}
pub fn decode(abi: ImageAbi, number: u64, mut args: [u64; 6]) -> Result<Invocation, Errno> {
    let call = match number {
        0x43595801 => Some(Call::DisplayInfo),
        0x43595802 => Some(Call::DisplayBlit),
        0x43595803 => Some(Call::InputRead),
        0x43595804 => Some(Call::InputState),
        0x43595810 => Some(Call::Spawn),
        0x43595820 => Some(Call::CheckpointStart),
        0x43595821 => Some(Call::CheckpointPoll),
        _ => None,
    };
    if let Some(call) = call {
        return Ok(Invocation { call, args });
    }
    if abi == ImageAbi::X86_64 {
        let at = (-100i64) as u64;
        let special = match number {
            2 => {
                args = [at, args[0], args[1], args[2], 0, 0];
                Some(Call::Openat)
            }
            4 | 6 => {
                args = [
                    at,
                    args[0],
                    args[1],
                    if number == 6 { 0x100 } else { 0 },
                    0,
                    0,
                ];
                Some(Call::Newfstatat)
            }
            21 => {
                args = [at, args[0], args[1], 0, 0, 0];
                Some(Call::Faccessat)
            }
            22 => {
                args[1] = 0;
                Some(Call::Pipe2)
            }
            82 => {
                args = [at, args[0], at, args[1], 0, 0];
                Some(Call::Renameat)
            }
            83 => {
                args = [at, args[0], args[1], 0, 0, 0];
                Some(Call::Mkdirat)
            }
            84 | 87 => {
                args = [at, args[0], if number == 84 { 0x200 } else { 0 }, 0, 0, 0];
                Some(Call::Unlinkat)
            }
            89 => {
                args = [at, args[0], args[1], args[2], 0, 0];
                Some(Call::Readlinkat)
            }
            90 => {
                args = [at, args[0], args[1], 0, 0, 0];
                Some(Call::Fchmodat)
            }
            213 => {
                // Legacy epoll_create takes a signed C int, not a u64 size.
                if (args[0] as i32) <= 0 {
                    return Err(Errno::Inval);
                }
                args[0] = 0;
                Some(Call::EpollCreate1)
            }
            232 => {
                args[4] = 0;
                args[5] = 0;
                Some(Call::EpollPwait)
            }
            253 => {
                args[0] = 0;
                Some(Call::InotifyInit1)
            }
            284 => {
                args[1] = 0;
                Some(Call::Eventfd2)
            }
            _ => None,
        };
        if let Some(call) = special {
            if call == Call::Openat {
                args[2] = decode_open_flags(abi, args[2])?;
            }
            return Ok(Invocation { call, args });
        }
    }
    let call = match abi {
        ImageAbi::Aarch64 => match number {
            17 => Call::Getcwd,
            19 => Call::Eventfd2,
            20 => Call::EpollCreate1,
            21 => Call::EpollCtl,
            22 => Call::EpollPwait,
            23 => Call::Dup,
            24 => Call::Dup3,
            25 => Call::Fcntl,
            26 => Call::InotifyInit1,
            27 => Call::InotifyAddWatch,
            28 => Call::InotifyRmWatch,
            29 => Call::Ioctl,
            32 => Call::Flock,
            34 => Call::Mkdirat,
            35 => Call::Unlinkat,
            38 => Call::Renameat,
            46 => Call::Ftruncate,
            48 => Call::Faccessat,
            49 => Call::Chdir,
            52 => Call::Fchmod,
            53 => Call::Fchmodat,
            56 => Call::Openat,
            57 => Call::Close,
            59 => Call::Pipe2,
            61 => Call::Getdents64,
            62 => Call::Lseek,
            63 => Call::Read,
            64 => Call::Write,
            65 => Call::Readv,
            66 => Call::Writev,
            67 => Call::Pread64,
            68 => Call::Pwrite64,
            73 => Call::Ppoll,
            79 => Call::Newfstatat,
            80 => Call::Fstat,
            82 => Call::Fsync,
            83 => Call::Fdatasync,
            85 => Call::TimerfdCreate,
            86 => Call::TimerfdSettime,
            87 => Call::TimerfdGettime,
            93 => Call::Exit,
            94 => Call::ExitGroup,
            96 => Call::SetTidAddress,
            98 => Call::Futex,
            101 => Call::Nanosleep,
            113 => Call::ClockGettime,
            114 => Call::ClockGetres,
            115 => Call::ClockNanosleep,
            124 => Call::SchedYield,
            129 => Call::Kill,
            130 => Call::Tkill,
            131 => Call::Tgkill,
            132 => Call::Sigaltstack,
            134 => Call::RtSigaction,
            135 => Call::RtSigprocmask,
            139 => Call::RtSigreturn,
            148 => Call::Getresuid,
            150 => Call::Getresgid,
            154 => Call::Setpgid,
            155 => Call::Getpgid,
            156 => Call::Getsid,
            160 => Call::Uname,
            163 => Call::Getrlimit,
            166 => Call::Umask,
            169 => Call::Gettimeofday,
            172 => Call::Getpid,
            173 => Call::Getppid,
            174 => Call::Getuid,
            175 => Call::Geteuid,
            176 => Call::Getgid,
            177 => Call::Getegid,
            178 => Call::Gettid,
            198 => Call::Socket,
            199 => Call::Socketpair,
            200 => Call::Bind,
            201 => Call::Listen,
            202 => Call::Accept,
            203 => Call::Connect,
            204 => Call::Getsockname,
            205 => Call::Getpeername,
            206 => Call::Sendto,
            207 => Call::Recvfrom,
            208 => Call::Setsockopt,
            209 => Call::Getsockopt,
            210 => Call::Shutdown,
            211 => Call::Sendmsg,
            212 => Call::Recvmsg,
            214 => Call::Brk,
            215 => Call::Munmap,
            220 => Call::Clone,
            222 => Call::Mmap,
            226 => Call::Mprotect,
            242 => Call::Accept4,
            260 => Call::Wait4,
            261 => Call::Prlimit64,
            276 => Call::Renameat2,
            278 => Call::Getrandom,
            279 => Call::MemfdCreate,
            _ => return Err(Errno::Nosys),
        },
        ImageAbi::X86_64 => match number {
            0 => Call::Read,
            1 => Call::Write,
            3 => Call::Close,
            5 => Call::Fstat,
            7 => Call::Poll,
            8 => Call::Lseek,
            9 => Call::Mmap,
            10 => Call::Mprotect,
            11 => Call::Munmap,
            12 => Call::Brk,
            13 => Call::RtSigaction,
            14 => Call::RtSigprocmask,
            15 => Call::RtSigreturn,
            16 => Call::Ioctl,
            17 => Call::Pread64,
            18 => Call::Pwrite64,
            19 => Call::Readv,
            20 => Call::Writev,
            24 => Call::SchedYield,
            32 => Call::Dup,
            33 => Call::Dup2,
            35 => Call::Nanosleep,
            39 => Call::Getpid,
            41 => Call::Socket,
            42 => Call::Connect,
            43 => Call::Accept,
            44 => Call::Sendto,
            45 => Call::Recvfrom,
            46 => Call::Sendmsg,
            47 => Call::Recvmsg,
            48 => Call::Shutdown,
            49 => Call::Bind,
            50 => Call::Listen,
            51 => Call::Getsockname,
            52 => Call::Getpeername,
            53 => Call::Socketpair,
            54 => Call::Setsockopt,
            55 => Call::Getsockopt,
            56 => Call::Clone,
            60 => Call::Exit,
            61 => Call::Wait4,
            62 => Call::Kill,
            63 => Call::Uname,
            72 => Call::Fcntl,
            73 => Call::Flock,
            74 => Call::Fsync,
            75 => Call::Fdatasync,
            77 => Call::Ftruncate,
            79 => Call::Getcwd,
            80 => Call::Chdir,
            91 => Call::Fchmod,
            95 => Call::Umask,
            96 => Call::Gettimeofday,
            97 => Call::Getrlimit,
            102 => Call::Getuid,
            104 => Call::Getgid,
            107 => Call::Geteuid,
            108 => Call::Getegid,
            109 => Call::Setpgid,
            110 => Call::Getppid,
            118 => Call::Getresuid,
            120 => Call::Getresgid,
            121 => Call::Getpgid,
            124 => Call::Getsid,
            131 => Call::Sigaltstack,
            158 => Call::ArchPrctl,
            186 => Call::Gettid,
            200 => Call::Tkill,
            202 => Call::Futex,
            217 => Call::Getdents64,
            218 => Call::SetTidAddress,
            228 => Call::ClockGettime,
            229 => Call::ClockGetres,
            230 => Call::ClockNanosleep,
            231 => Call::ExitGroup,
            233 => Call::EpollCtl,
            234 => Call::Tgkill,
            254 => Call::InotifyAddWatch,
            255 => Call::InotifyRmWatch,
            257 => Call::Openat,
            258 => Call::Mkdirat,
            262 => Call::Newfstatat,
            263 => Call::Unlinkat,
            264 => Call::Renameat,
            268 => Call::Fchmodat,
            269 => Call::Faccessat,
            271 => Call::Ppoll,
            281 => Call::EpollPwait,
            283 => Call::TimerfdCreate,
            286 => Call::TimerfdSettime,
            287 => Call::TimerfdGettime,
            288 => Call::Accept4,
            290 => Call::Eventfd2,
            291 => Call::EpollCreate1,
            292 => Call::Dup3,
            293 => Call::Pipe2,
            294 => Call::InotifyInit1,
            302 => Call::Prlimit64,
            316 => Call::Renameat2,
            318 => Call::Getrandom,
            319 => Call::MemfdCreate,
            _ => return Err(Errno::Nosys),
        },
    };
    if abi == ImageAbi::X86_64 && call == Call::Clone {
        args.swap(3, 4);
    }
    if call == Call::Openat {
        args[2] = decode_open_flags(abi, args[2])?;
    }
    Ok(Invocation { call, args })
}
/// The shared descriptor policy retains its original flag values; translate at
/// the Linux wire boundary, including the inverse F_GETFL conversion.
pub fn decode_open_flags(abi: ImageAbi, flags: u64) -> Result<u64, Errno> {
    let flags = u32::try_from(flags).map_err(|_| Errno::Inval)?;
    if abi == ImageAbi::Aarch64 {
        return Ok(u64::from(flags & !0x20000));
    }
    if flags & 0x4000 != 0 {
        return Err(Errno::Inval);
    } // Unsupported O_DIRECT, never O_DIRECTORY.
    let out = (flags & !(0x8000 | 0x10000 | 0x20000))
        | if flags & 0x10000 != 0 {
            crate::O_DIRECTORY
        } else {
            0
        }
        | if flags & 0x20000 != 0 {
            crate::O_NOFOLLOW
        } else {
            0
        };
    Ok(u64::from(out))
}
pub fn encode_open_flags(abi: ImageAbi, flags: u32) -> u64 {
    if abi == ImageAbi::Aarch64 {
        return u64::from(flags);
    }
    u64::from(
        (flags & !(crate::O_DIRECTORY | crate::O_NOFOLLOW))
            | if flags & crate::O_DIRECTORY != 0 {
                0x10000
            } else {
                0
            }
            | if flags & crate::O_NOFOLLOW != 0 {
                0x20000
            } else {
                0
            },
    )
}
pub const fn epoll_bytes(abi: ImageAbi) -> usize {
    match abi {
        ImageAbi::X86_64 => 12,
        ImageAbi::Aarch64 => 16,
    }
}
pub const fn epoll_data_offset(abi: ImageAbi) -> usize {
    match abi {
        ImageAbi::X86_64 => 4,
        ImageAbi::Aarch64 => 8,
    }
}
pub fn stat_x86_64(info: FileInfo) -> [u8; 144] {
    let mut bytes = [0; 144];
    for (at, value) in [
        (0, 1u64),
        (8, info.inode),
        (16, u64::from(info.links)),
        (48, info.size),
        (56, 4096),
        (64, info.size.div_ceil(512)),
    ] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[24..28].copy_from_slice(&info.mode.to_le_bytes());
    bytes
}

/// The admitted musl clone wrappers leave argument data at the exact child SP.
/// This returns only the access length; it never aligns or moves that pointer.
/// Source: musl v1.2.6 src/thread/{x86_64,aarch64}/clone.s.
pub fn validate_clone_stack(abi: ImageAbi, stack: u64) -> Result<usize, Errno> {
    match abi {
        ImageAbi::Aarch64 => {
            if stack == 0 || !stack.is_multiple_of(16) {
                Err(Errno::Inval)
            } else {
                Ok(16)
            }
        }
        ImageAbi::X86_64 => {
            if !(4096..0x0000_8000_0000_0000).contains(&stack) {
                Err(Errno::Inval)
            } else {
                Ok(8)
            }
        }
    }
}
