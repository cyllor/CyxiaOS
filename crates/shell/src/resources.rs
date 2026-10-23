use super::{CommandError, Shell, no_args, split};
use core::{fmt::Write, str::FromStr};
use cyxia_ai_runtime::{Device, MemoryId, Workload};
fn number<T: FromStr>(s: Option<&str>) -> Result<T, CommandError> {
    s.ok_or(CommandError::Usage)?
        .parse()
        .map_err(|_| CommandError::Usage)
}
fn device(s: Option<&str>) -> Result<Device, CommandError> {
    match s {
        Some("uart") => Ok(Device::Uart),
        Some("timer") => Ok(Device::Timer),
        _ => Err(CommandError::Usage),
    }
}
fn end(mut args: core::str::SplitWhitespace<'_>) -> Result<(), CommandError> {
    if args.next().is_none() {
        Ok(())
    } else {
        Err(CommandError::Usage)
    }
}
impl Shell {
    pub(super) fn resource_status(&self, out: &mut impl Write) -> Result<(), CommandError> {
        let s = self.runtime.status();
        let m = self.runtime.memory_status();
        writeln!(
            out,
            "AI resources: fixed local models memory=8193 cpu=12289 device=16385\r"
        )?;
        writeln!(
            out,
            "tick={} tasks={} cpu_ai={} safety={} device_ai={} failures={} expired={} device_mechanism={}\r",
            s.tick,
            s.tasks,
            s.dispatches,
            s.guards,
            s.device_decisions,
            s.device_failures,
            s.device_guards,
            s.device_mechanisms
        )?;
        writeln!(
            out,
            "memory free={} used={} decisions={} denied={} audit_dropped={}\r",
            m.free, m.used, m.decisions, m.denied, s.audit_dropped
        )?;
        writeln!(
            out,
            "EL1 cooperative tasks only; use ai system for EL0 and desktop; CPU0\r"
        )?;
        Ok(())
    }
    pub(super) fn resource_audit(&self, out: &mut impl Write) -> Result<(), CommandError> {
        for a in self.runtime.audit() {
            writeln!(
                out,
                "#{} {:?} {:?} model={} owner={} object={} amount={} accepted={} event={:?} state={:?} uncertain={}\r",
                a.serial,
                a.domain,
                a.source,
                a.model,
                a.owner,
                a.object,
                a.amount,
                a.accepted,
                a.event,
                a.request_state,
                a.uncertain
            )?;
        }
        Ok(())
    }
    pub(super) fn resource_command(
        &mut self,
        cmd: &str,
        rest: &str,
        out: &mut impl Write,
    ) -> Result<(), CommandError> {
        let (op, tail) = split(rest);
        let mut args = tail.split_whitespace();
        match cmd {
            "mem" => match op {
                "status" => {
                    no_args(tail)?;
                    let m = self.runtime.memory_status();
                    writeln!(
                        out,
                        "RAM pages total={} free={} used={} allocations={} page_bytes=4096\r",
                        m.total, m.free, m.used, m.allocations
                    )?;
                }
                "list" => {
                    no_args(tail)?;
                    for (id, owner, pages, grant) in self.runtime.allocations() {
                        writeln!(
                            out,
                            "allocation={} owner={} pages={} grant={}\r",
                            id.0, owner, pages, grant
                        )?;
                    }
                }
                "alloc" => {
                    let pages = number(args.next())?;
                    end(args)?;
                    let id = self.runtime.allocate(pages)?;
                    writeln!(
                        out,
                        "allocated id={} pages={} source=AI_DIRECT\r",
                        id.0, pages
                    )?;
                }
                "free" => {
                    let id = MemoryId(number(args.next())?);
                    end(args)?;
                    self.runtime.free(id)?;
                    writeln!(out, "freed id={}\r", id.0)?;
                }
                "peek" => {
                    let id = MemoryId(number(args.next())?);
                    let offset = number(args.next())?;
                    end(args)?;
                    let value = self.runtime.peek(id, offset)?;
                    writeln!(out, "byte={}\r", value)?;
                }
                "poke" => {
                    let id = MemoryId(number(args.next())?);
                    let offset = number(args.next())?;
                    let value = number(args.next())?;
                    end(args)?;
                    self.runtime.poke(id, offset, value)?;
                    writeln!(out, "written\r")?;
                }
                _ => return Err(CommandError::Usage),
            },
            "proc" => match op {
                "spawn" => {
                    let kind = match args.next() {
                        Some("compute") => Workload::Compute,
                        Some("memory") => Workload::Memory,
                        Some("uart") => Workload::Uart,
                        _ => return Err(CommandError::Usage),
                    };
                    let work = number(args.next())?;
                    let priority = number(Some(args.next().unwrap_or("1")))?;
                    let pages = number(Some(args.next().unwrap_or("1")))?;
                    end(args)?;
                    let pid = self.runtime.spawn(kind, work, priority, pages)?;
                    writeln!(out, "spawned pid={}\r", pid)?;
                }
                "list" => {
                    no_args(tail)?;
                    for t in self.runtime.tasks() {
                        writeln!(
                            out,
                            "pid={} {:?} {:?} paused={} work={}/{} priority={} pages={} slices={} budget={} checksum={} error={:?}\r",
                            t.id,
                            t.kind,
                            t.state,
                            t.paused,
                            t.done,
                            t.total,
                            t.priority,
                            t.pages,
                            t.slices,
                            t.last_budget,
                            t.checksum,
                            t.error
                        )?;
                    }
                }
                "pause" | "resume" | "kill" | "reap" => {
                    let pid = number(args.next())?;
                    end(args)?;
                    match op {
                        "pause" => self.runtime.pause(pid, true)?,
                        "resume" => self.runtime.pause(pid, false)?,
                        "kill" => self.runtime.kill(pid)?,
                        _ => self.runtime.reap(pid)?,
                    };
                    writeln!(out, "{} pid={}\r", op, pid)?;
                }
                _ => return Err(CommandError::Usage),
            },
            "dev" => match op {
                "batch" => {
                    let count = number(args.next())?;
                    end(args)?;
                    let first = self.runtime.device_batch(count)?;
                    writeln!(
                        out,
                        "timer batch first={} count={} priorities=0..3\r",
                        first, count
                    )?;
                }
                "list" => {
                    no_args(tail)?;
                    for d in [Device::Uart, Device::Timer] {
                        let i = self.runtime.device_info(d);
                        writeln!(
                            out,
                            "{:?} present={} requests_enabled={} pending={} kernel_reserved=true\r",
                            d, i.present, i.enabled, i.pending
                        )?;
                    }
                }
                "write" => {
                    let id = self.runtime.device_submit(Device::Uart, tail.as_bytes())?;
                    writeln!(out, "queued request={}\r", id)?;
                }
                "read" => {
                    if device(args.next())? != Device::Timer {
                        return Err(CommandError::Usage);
                    }
                    end(args)?;
                    let id = self.runtime.device_submit(Device::Timer, b"")?;
                    writeln!(out, "queued request={}\r", id)?;
                }
                "requests" => {
                    no_args(tail)?;
                    for r in self.runtime.requests() {
                        writeln!(
                            out,
                            "request={} owner={} {:?} {:?} bytes={}/{} result={} retries={} uncertain={}\r",
                            r.id,
                            r.owner,
                            r.device,
                            r.state,
                            r.done,
                            r.len,
                            r.result,
                            r.retries,
                            r.uncertain
                        )?;
                    }
                }
                "cancel" | "reap" => {
                    let id = number(args.next())?;
                    end(args)?;
                    if op == "cancel" {
                        self.runtime.request_cancel(id)?;
                    } else {
                        self.runtime.request_reap(id)?;
                    }
                    writeln!(out, "{} request={}\r", op, id)?;
                }
                "enable" | "disable" => {
                    let d = device(args.next())?;
                    end(args)?;
                    self.runtime.device_enable(d, op == "enable")?;
                    writeln!(
                        out,
                        "{:?} ordinary requests {}; kernel console/timer reserved\r",
                        d, op
                    )?;
                }
                _ => return Err(CommandError::Usage),
            },
            _ => return Err(CommandError::Usage),
        }
        Ok(())
    }
}
