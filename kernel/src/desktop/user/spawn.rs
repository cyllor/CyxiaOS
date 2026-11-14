//! Explicit Cyxia static-image spawn. It does not implement fork/vfork or reuse
//! a parent's address space. The supervisor alone publishes admitted children.
use super::{Context, Errno, FileSystem, PORTED, Runner, Supervisor, UserState, Wait, now};
use cyxia_posix::{OPEN_MAX, executable, spawn::Mapping};

const STRING_BYTES: usize = 4096;
const RECEIPTS: usize = 10;
#[derive(Clone, Copy)]
pub(super) struct Request {
    tid: u32,
    flags: u32,
    path: [u8; 96],
    path_len: usize,
    cwd: [u8; 96],
    cwd_len: Option<usize>,
    bytes: [u8; STRING_BYTES],
    args: [[u16; 2]; 32],
    argc: usize,
    env: [[u16; 2]; 32],
    envc: usize,
    mappings: [Mapping; OPEN_MAX],
    map_count: usize,
}
impl Request {
    fn decode(runner: &Runner, address: u64) -> Result<Self, Errno> {
        let mut header = [0; 64];
        runner.copy_from(address, &mut header)?;
        let word = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap());
        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if u32::from_le_bytes(header[..4].try_into().unwrap()) != 64
            || flags & !1 != 0
            || header[52..].iter().any(|b| *b != 0)
        {
            return Err(Errno::Inval);
        }
        let mut request = Self {
            tid: runner.thread.tid,
            flags,
            path: [0; 96],
            path_len: 0,
            cwd: [0; 96],
            cwd_len: None,
            bytes: [0; STRING_BYTES],
            args: [[0; 2]; 32],
            argc: 0,
            env: [[0; 2]; 32],
            envc: 0,
            mappings: [Mapping {
                source: -1,
                target: 0,
            }; OPEN_MAX],
            map_count: 0,
        };
        request.path_len = runner.path(word(8), &mut request.path)?;
        if request.path_len == 0 {
            return Err(Errno::Noent);
        }
        core::str::from_utf8(&request.path[..request.path_len]).map_err(|_| Errno::Inval)?;
        if word(32) != 0 {
            let n = runner.path(word(32), &mut request.cwd)?;
            core::str::from_utf8(&request.cwd[..n]).map_err(|_| Errno::Inval)?;
            request.cwd_len = Some(n);
        }
        let mut used = 0;
        request.argc = Self::vector(
            runner,
            word(16),
            &mut request.args,
            &mut request.bytes,
            &mut used,
        )?;
        request.envc = Self::vector(
            runner,
            word(24),
            &mut request.env,
            &mut request.bytes,
            &mut used,
        )?;
        if request.argc == 0 || request.args[0][1] == 0 {
            return Err(Errno::Inval);
        }
        request.map_count = u32::from_le_bytes(header[48..52].try_into().unwrap()) as usize;
        if request.map_count > OPEN_MAX {
            return Err(Errno::Inval);
        }
        let mut maps = [0; OPEN_MAX * 8];
        runner.copy_from(word(40), &mut maps[..request.map_count * 8])?;
        for (index, map) in request.mappings[..request.map_count].iter_mut().enumerate() {
            map.source = i32::from_le_bytes(maps[index * 8..index * 8 + 4].try_into().unwrap());
            map.target = i32::from_le_bytes(maps[index * 8 + 4..index * 8 + 8].try_into().unwrap());
        }
        Ok(request)
    }
    fn vector(
        runner: &Runner,
        address: u64,
        spans: &mut [[u16; 2]; 32],
        bytes: &mut [u8; STRING_BYTES],
        used: &mut usize,
    ) -> Result<usize, Errno> {
        if address == 0 {
            return Err(Errno::Fault);
        }
        for index in 0..=spans.len() {
            let mut pointer = [0; 8];
            runner.copy_from(
                address.checked_add(index as u64 * 8).ok_or(Errno::Fault)?,
                &mut pointer,
            )?;
            let pointer = u64::from_le_bytes(pointer);
            if pointer == 0 {
                return Ok(index);
            }
            if index == spans.len() {
                return Err(Errno::TooBig);
            }
            let start = *used;
            loop {
                if *used == bytes.len() {
                    return Err(Errno::TooBig);
                }
                runner.copy_from(
                    pointer
                        .checked_add((*used - start) as u64)
                        .ok_or(Errno::Fault)?,
                    &mut bytes[*used..*used + 1],
                )?;
                let end = bytes[*used] == 0;
                *used += 1;
                if end {
                    break;
                }
            }
            spans[index] = [start as u16, (*used - start - 1) as u16];
        }
        unreachable!()
    }
}

#[derive(Clone, Copy)]
struct Receipt {
    parent: u32,
    child: u32,
    status: Option<u32>,
    auto_reap: bool,
}
pub(super) struct Children {
    receipts: [Option<Receipt>; RECEIPTS],
}
impl Children {
    pub const fn new() -> Self {
        Self {
            receipts: [None; RECEIPTS],
        }
    }
}

impl Runner {
    pub(super) fn request_spawn(&mut self, address: u64) -> Result<u64, Errno> {
        if self.pending_spawn.is_some() {
            return Err(Errno::Again);
        }
        let request = Request::decode(self, address)?;
        self.pending_spawn = Some(request);
        self.block(Wait::Spawn);
        Ok(0)
    }
    pub(super) fn request_wait(
        &mut self,
        pid: u64,
        status: u64,
        options: u64,
        rusage: u64,
    ) -> Result<u64, Errno> {
        let pid = pid as i64;
        if pid != -1 && (pid <= 0 || pid > i32::MAX as i64) {
            return Err(Errno::Inval);
        }
        if options & !1 != 0 {
            return Err(Errno::Inval);
        }
        if rusage != 0 {
            return Err(Errno::Nosys);
        }
        if status != 0 {
            self.validate(status, 4, true)?;
        }
        self.block(Wait::Child {
            pid: pid as i32,
            status,
            nonblock: options == 1,
        });
        Ok(0)
    }
    fn supervisor_result(&mut self, tid: u32, result: Result<u64, Errno>) {
        let value = result.unwrap_or_else(|e| (-(e as i64)) as u64);
        for thread in core::iter::once(&mut self.thread).chain(self.threads.parked.iter_mut()) {
            if thread.active && thread.tid == tid {
                thread.context.regs[0] = value;
                thread.waiting = None;
                thread.ready_since = now();
                self.status.wakeups = self.status.wakeups.saturating_add(1);
                break;
            }
        }
        self.refresh_thread_state();
    }
}

impl Supervisor {
    // Keep bounded spawn staging off the resident dispatch frame. Inlining it
    // makes every unrelated mmap syscall pay for argv/env and child metadata.
    #[inline(never)]
    fn spawn_image(
        &mut self,
        parent: usize,
        request: &Request,
        fs: &mut FileSystem,
    ) -> Result<u32, Errno> {
        let mut attempt = cyxia_ai_runtime::accounting::Attempt::default();
        let result = self.spawn_image_accounted(parent, request, fs, &mut attempt);
        super::ai::admission(super::ai::Domain::SpawnReceipt, attempt, &result);
        result
    }
    #[inline(never)]
    fn spawn_image_accounted(
        &mut self,
        parent: usize,
        request: &Request,
        fs: &mut FileSystem,
        attempt: &mut cyxia_ai_runtime::accounting::Attempt,
    ) -> Result<u32, Errno> {
        let path =
            core::str::from_utf8(&request.path[..request.path_len]).map_err(|_| Errno::Inval)?;
        let resolved = self.runners[parent].process.resolved_path(fs, path)?;
        let (_, actual_path, bytes) = PORTED
            .iter()
            .find(|(_, p, _)| *p == resolved.as_str())
            .ok_or(Errno::Noent)?;
        let plan = executable::parse(bytes).map_err(|_| Errno::Inval)?;
        let cwd = request
            .cwd_len
            .map(|n| core::str::from_utf8(&request.cwd[..n]).unwrap());
        self.runners[parent].process.validate_spawn_descriptors(
            fs,
            cwd,
            &request.mappings[..request.map_count],
        )?;
        let parent_pid = self.runners[parent].status.pid;
        let parent_mask = self.runners[parent].thread.signals.mask();
        let child_actions = self.runners[parent].threads.shared.actions.for_exec();
        let free = self
            .children
            .receipts
            .iter()
            .filter(|r| r.is_none())
            .count();
        attempt.proposed(8193);
        let (allowed, model) =
            cyxia_ai_runtime::user_memory_policy(free as u32, 1).map_err(|_| Errno::Io)?;
        attempt.decided(allowed, model);
        if !allowed {
            return Err(Errno::Again);
        }
        let receipt = self
            .children
            .receipts
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Again)?;
        let mut random = [0; 16];
        super::super::entropy::fill(&mut random)?;
        let slot = self.launch("idle", true)?;
        let child_pid = self.runners[slot].status.pid;
        let result = (|| {
            // The temporary native launch owns only stdio. Close that set before
            // acquiring inherited references, so any error still has one owner.
            for released in self.runners[slot].process.close_all(fs)? {
                super::objects::release(fs, released)?;
            }
            let child_process = self.runners[parent].process.spawn_descriptors(
                fs,
                cwd,
                &request.mappings[..request.map_count],
                child_pid,
            )?;
            // All subsequent load failures are handled by finish() on this table.
            self.runners[slot].process = child_process;
            let args: [&[u8]; 32] = core::array::from_fn(|i| {
                let [start, len] = request.args[i];
                &request.bytes[start as usize..(start + len) as usize]
            });
            let env: [&[u8]; 32] = core::array::from_fn(|i| {
                let [start, len] = request.env[i];
                &request.bytes[start as usize..(start + len) as usize]
            });
            let runner = &mut self.runners[slot];
            let owner = runner.lease.ok_or(Errno::Io)?.0;
            let sp = runner.executable.load(
                slot,
                owner,
                &plan,
                super::super::exec_memory::StackInput {
                    random,
                    argv: &args[..request.argc],
                    envp: &env[..request.envc],
                    execfn: actual_path.as_bytes(),
                },
            )?;
            runner.l2.0[0] = 0;
            runner.arena.clear();
            for (index, root) in runner.executable.roots() {
                runner.l2.0[index] = root;
            }
            runner.thread.context = Context {
                pc: plan.entry,
                sp,
                ..Context::empty()
            };
            runner.thread.signals.set_mask(parent_mask);
            runner.threads.shared.actions = child_actions;
            runner.linux = true;
            runner.status.parent_pid = parent_pid;
            Ok(())
        })();
        if let Err(error) = result {
            self.runners[slot].finish(fs, &mut self.ledger, &mut self.ipc, UserState::Killed, 137);
            return Err(error);
        }
        self.children.receipts[receipt] = Some(Receipt {
            parent: parent_pid,
            child: child_pid,
            status: None,
            auto_reap: request.flags & 1 != 0,
        });
        super::ai::record(super::ai::Domain::SpawnReceipt, |c| c.grant(1));
        super::super::log(b"SPAWN_CHILD pid,parent AI_DIRECT model=8193 image_model=8195\n");
        super::super::hex(child_pid as u64);
        super::super::hex(parent_pid as u64);
        Ok(child_pid)
    }
    #[inline(never)]
    pub(super) fn service_spawn(&mut self, parent: usize, fs: &mut FileSystem) {
        if let Some(request) = self.runners[parent].pending_spawn.take() {
            let result = self.spawn_image(parent, &request, fs).map(u64::from);
            self.runners[parent].supervisor_result(request.tid, result);
        }
    }
    pub(super) fn collect_children(&mut self) {
        for receipt in &mut self.children.receipts {
            let Some(child) = receipt else {
                continue;
            };
            let parent_alive = self
                .runners
                .iter()
                .any(|r| r.status.pid == child.parent && r.status.state.active());
            if !parent_alive {
                // Kernel-owned orphan: it may finish independently, with no
                // caller left to consume an exit receipt. PIDs never recycle.
                if let Some(orphan) = self
                    .runners
                    .iter_mut()
                    .find(|r| r.status.pid == child.child)
                {
                    orphan.status.parent_pid = 0;
                }
                *receipt = None;
                super::ai::record(super::ai::Domain::SpawnReceipt, |c| c.release(1));
                continue;
            }
            if child.status.is_none() {
                let Some(runner) = self.runners.iter().find(|r| r.status.pid == child.child) else {
                    continue;
                };
                if !runner.status.state.active() {
                    let signal = runner.status.exit_signal;
                    let status = if signal == 0 {
                        (runner.status.code & 255) << 8
                    } else {
                        signal & 127
                    };
                    child.status = Some(status);
                    if let Some(parent) = self
                        .runners
                        .iter_mut()
                        .find(|r| r.status.pid == child.parent)
                    {
                        let _ = parent.threads.shared.pending.raise(
                            &parent.threads.shared.actions,
                            17,
                            cyxia_posix::signal::Info {
                                code: if signal == 0 { 1 } else { 2 },
                                sender_pid: child.child,
                                address: if signal == 0 {
                                    (status >> 8) as u64
                                } else {
                                    signal as u64
                                },
                            },
                            false,
                        );
                    }
                    if child.auto_reap {
                        *receipt = None;
                        super::ai::record(super::ai::Domain::SpawnReceipt, |c| c.release(1));
                    }
                }
            }
        }
        for runner in &mut self.runners {
            if !runner.status.state.active() {
                continue;
            }
            // Move each parked record through the foreground usercopy context;
            // only this one process's address space is consulted.
            for index in 0..8 {
                if index != 0 {
                    core::mem::swap(&mut runner.thread, &mut runner.threads.parked[index - 1]);
                }
                if let Some(Wait::Child {
                    pid,
                    status,
                    nonblock,
                }) = runner.thread.waiting
                {
                    let matches = |r: &Receipt| {
                        r.parent == runner.status.pid
                            && !r.auto_reap
                            && (pid == -1 || r.child == pid as u32)
                    };
                    let ready =
                        self.children.receipts.iter().position(|r| {
                            r.as_ref().is_some_and(|r| matches(r) && r.status.is_some())
                        });
                    let exists = self.children.receipts.iter().flatten().any(matches);
                    let result = if let Some(index) = ready {
                        let receipt = self.children.receipts[index].unwrap();
                        let copy = if status == 0 {
                            Ok(())
                        } else {
                            runner.copy_to(status, &receipt.status.unwrap().to_le_bytes())
                        };
                        Some(copy.map(|()| {
                            self.children.receipts[index] = None;
                            super::ai::record(super::ai::Domain::SpawnReceipt, |c| c.release(1));
                            receipt.child as u64
                        }))
                    } else if !exists {
                        Some(Err(Errno::Child))
                    } else if nonblock {
                        Some(Ok(0))
                    } else {
                        None
                    };
                    if let Some(result) = result {
                        runner.supervisor_result(runner.thread.tid, result);
                    }
                }
                if index != 0 {
                    core::mem::swap(&mut runner.thread, &mut runner.threads.parked[index - 1]);
                }
            }
            runner.refresh_thread_state();
        }
    }
}
