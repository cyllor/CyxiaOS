extern crate std;
use super::*;
#[derive(Default)]
struct Io {
    bytes: std::vec::Vec<u8>,
    blocked: bool,
    partial: usize,
}
impl DeviceIo for Io {
    fn uart_write(&mut self, data: &[u8]) -> Result<usize, IoError> {
        if self.blocked {
            return Err(IoError::Again);
        }
        let n = if self.partial > 0 {
            self.partial.min(data.len())
        } else {
            data.len()
        };
        self.bytes.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn timer_read(&mut self) -> Result<u64, IoError> {
        Ok(12345)
    }
}
fn runtime() -> Runtime {
    let mut r = Runtime::new();
    r.bind_devices(true, true).unwrap();
    r
}
#[test]
fn memory_is_real_owned_zeroed_and_accounted() {
    let mut r = runtime();
    let a = r.allocate(2).unwrap();
    assert_eq!(r.memory_status().used, 2);
    r.poke(a, 4096, 173).unwrap();
    assert_eq!(r.peek(a, 4096), Ok(173));
    assert_eq!(r.peek(a, 8192), Err(Error::Bounds));
    assert_eq!(r.memory.read(2, a, 0), Err(Error::Owner));
    r.free(a).unwrap();
    assert_eq!(r.free(a), Err(Error::Stale));
    assert_eq!(r.memory_status().free, 32);
    let b = r.allocate(2).unwrap();
    assert_ne!(a, b);
    assert_eq!(r.peek(b, 4096), Ok(0));
    assert_eq!(r.peek(a, 0), Err(Error::Stale));
}
#[test]
fn ai_memory_denial_has_no_allocation_side_effect() {
    let mut r = runtime();
    for _ in 0..3 {
        r.allocate(8).unwrap();
    }
    let before = r.memory_status();
    assert_eq!(r.allocate(8), Err(Error::AiDenied));
    assert_eq!(r.memory_status().used, before.used);
    assert_eq!(r.memory_status().denied, 1);
    assert_eq!(r.allocate(0), Err(Error::Invalid));
    assert_eq!(r.allocate(9), Err(Error::Invalid));
}
#[test]
fn tasks_run_actual_work_and_release_all_pages() {
    let mut r = runtime();
    let mut io = Io::default();
    r.spawn(Workload::Compute, 1000, 1, 1).unwrap();
    r.spawn(Workload::Memory, 9000, 2, 3).unwrap();
    for now in 1..1000 {
        r.tick(now, &mut io).unwrap();
    }
    for t in r.tasks() {
        assert_eq!(t.state, TaskState::Exited);
        assert_eq!(t.done, t.total);
        assert_ne!(t.checksum, 0);
        assert!(t.slices > 0);
    }
    assert_eq!(r.memory_status().free, 32);
    assert!(
        r.audit()
            .any(|a| a.domain as u8 == Domain::Cpu as u8 && a.source == DecisionSource::AiDirect)
    );
}
#[test]
fn pause_resume_kill_reap_and_stale_identity() {
    let mut r = runtime();
    let mut io = Io::default();
    let pid = r.spawn(Workload::Compute, 1000, 1, 2).unwrap();
    r.pause(pid, true).unwrap();
    r.tick(1, &mut io).unwrap();
    assert_eq!(r.tasks().next().unwrap().done, 0);
    r.pause(pid, false).unwrap();
    r.tick(2, &mut io).unwrap();
    assert!(r.tasks().next().unwrap().done > 0);
    r.kill(pid).unwrap();
    assert_eq!(r.memory_status().free, 32);
    assert_eq!(r.pause(pid, false), Err(Error::State));
    r.reap(pid).unwrap();
    let new = r.spawn(Workload::Memory, 10, 1, 1).unwrap();
    assert_ne!(pid, new);
    assert_eq!(r.kill(pid), Err(Error::Stale));
}
#[test]
fn invalid_cpu_decisions_cannot_execute_and_replay_is_stale() {
    let mut r = runtime();
    r.spawn(Workload::Compute, 1000, 1, 1).unwrap();
    let mut d = r.decide().unwrap();
    d.budget = 10000;
    assert_eq!(r.dispatch(d), Err(Error::InvalidDecision));
    let d = r.decide().unwrap();
    r.pause(2, true).unwrap();
    assert_eq!(r.dispatch(d), Err(Error::InvalidDecision));
    assert_eq!(r.tasks().next().unwrap().done, 0);
}
#[test]
fn model_priority_and_guard_both_take_effect() {
    let mut r = runtime();
    r.spawn(Workload::Compute, 1000, 0, 1).unwrap();
    let high = r.spawn(Workload::Compute, 1000, 3, 1).unwrap();
    assert_eq!(r.decide().unwrap().task, high);
    r.now = 40;
    r.tasks[1].as_mut().unwrap().ready_since = 39;
    let d = r.decide().unwrap();
    assert!(d.guard);
    assert_eq!(d.task, 2);
}
#[test]
fn uart_task_waits_completes_and_reclaims_request() {
    let mut r = runtime();
    let mut io = Io::default();
    r.spawn(Workload::Uart, 3, 1, 1).unwrap();
    r.tick(1, &mut io).unwrap();
    assert_eq!(r.tasks().next().unwrap().state, TaskState::Waiting);
    for n in 2..20 {
        r.tick(n, &mut io).unwrap();
    }
    let t = r.tasks().next().unwrap();
    assert_eq!(t.state, TaskState::Exited);
    assert_eq!(t.done, 3);
    assert_eq!(r.requests().count(), 0);
    assert_eq!(r.memory_status().free, 32);
    assert_eq!(io.bytes, b"[CyxiaOS AI task UART]\r\n".repeat(3));
}
#[test]
fn io_backpressure_and_failure_cannot_block_other_tasks() {
    let mut r = runtime();
    let mut io = Io {
        blocked: true,
        ..Io::default()
    };
    r.spawn(Workload::Uart, 1, 3, 1).unwrap();
    r.spawn(Workload::Compute, 100, 1, 1).unwrap();
    for n in 1..30 {
        r.tick(n, &mut io).unwrap();
    }
    assert_eq!(
        r.tasks().find(|t| t.kind == Workload::Uart).unwrap().state,
        TaskState::Failed
    );
    assert_eq!(
        r.tasks()
            .find(|t| t.kind == Workload::Compute)
            .unwrap()
            .state,
        TaskState::Exited
    );
    assert_eq!(r.memory_status().free, 32);
}
#[test]
fn partial_io_exactly_once_owner_and_offline_checks() {
    let mut r = runtime();
    let mut io = Io {
        partial: 2,
        ..Io::default()
    };
    let id = r.device_submit(Device::Uart, b"abcdef").unwrap();
    assert_eq!(r.device_enable(Device::Uart, false), Err(Error::Busy));
    assert_eq!(r.devices.reap(2, id), Err(Error::Owner));
    for n in 1..4 {
        r.tick(n, &mut io).unwrap();
    }
    assert_eq!(io.bytes, b"abcdef");
    assert_eq!(r.request_reap(id).unwrap().done, 6);
    assert_eq!(r.request_reap(id), Err(Error::Stale));
    r.device_enable(Device::Uart, false).unwrap();
    assert_eq!(r.device_submit(Device::Uart, b"a"), Err(Error::Offline));
    let timer = r.device_submit(Device::Timer, b"").unwrap();
    r.tick(4, &mut io).unwrap();
    assert_eq!(r.request_reap(timer).unwrap().result, 12345);
}
#[test]
fn kill_waiting_task_cancels_future_io_and_reclaims_memory() {
    let mut r = runtime();
    let mut io = Io::default();
    let pid = r.spawn(Workload::Uart, 1, 1, 1).unwrap();
    r.tick(1, &mut io).unwrap();
    r.kill(pid).unwrap();
    r.tick(2, &mut io).unwrap();
    assert!(io.bytes.is_empty());
    assert_eq!(r.requests().count(), 0);
    assert_eq!(r.memory_status().free, 32);
}
#[test]
fn task_and_request_capacity_errors_do_not_leak() {
    let mut r = runtime();
    for _ in 0..8 {
        r.spawn(Workload::Compute, 1, 1, 1).unwrap();
    }
    let free = r.memory_status().free;
    assert_eq!(r.spawn(Workload::Compute, 1, 1, 1), Err(Error::Capacity));
    assert_eq!(r.memory_status().free, free);
    for _ in 0..16 {
        r.device_submit(Device::Timer, b"").unwrap();
    }
    assert_eq!(r.device_submit(Device::Timer, b""), Err(Error::Capacity));
}
#[test]
fn clock_duplicate_tick_and_epoch_exhaustion_are_safe() {
    let mut r = runtime();
    let mut io = Io::default();
    r.spawn(Workload::Compute, 1000, 1, 1).unwrap();
    r.tick(1, &mut io).unwrap();
    let done = r.tasks().next().unwrap().done;
    r.tick(1, &mut io).unwrap();
    assert_eq!(r.tasks().next().unwrap().done, done);
    assert_eq!(r.tick(0, &mut io), Err(Error::Clock));
    r.epoch = u64::MAX;
    assert_eq!(r.tick(2, &mut io), Err(Error::Exhausted));
    assert_eq!(r.tasks().next().unwrap().done, done);
}
#[test]
fn fixed_runtime_budget() {
    assert!(core::mem::size_of::<Runtime>() < 256 * 1024);
}

#[test]
fn consumed_cpu_proposal_cannot_be_replayed() {
    let mut r = runtime();
    r.spawn(Workload::Compute, 1000, 1, 1).unwrap();
    let d = r.decide().unwrap();
    r.dispatch(d).unwrap();
    let done = r.tasks().next().unwrap().done;
    assert_eq!(r.dispatch(d), Err(Error::InvalidDecision));
    assert_eq!(r.tasks().next().unwrap().done, done);
}
#[test]
fn paused_waiting_task_completes_only_inflight_io() {
    let mut r = runtime();
    let mut io = Io::default();
    let pid = r.spawn(Workload::Uart, 2, 1, 1).unwrap();
    r.tick(1, &mut io).unwrap();
    r.pause(pid, true).unwrap();
    for n in 2..10 {
        r.tick(n, &mut io).unwrap();
    }
    let t = r.tasks().next().unwrap();
    assert!(t.paused);
    assert_eq!(t.done, 1);
    assert_eq!(r.requests().count(), 0);
    r.pause(pid, false).unwrap();
    for n in 10..14 {
        r.tick(n, &mut io).unwrap();
    }
    assert_eq!(r.tasks().next().unwrap().state, TaskState::Exited);
}
#[test]
fn expired_and_cancelled_requests_never_reach_driver() {
    let mut r = runtime();
    let mut io = Io::default();
    let a = r.device_submit(Device::Uart, b"expired").unwrap();
    r.tick(64, &mut io).unwrap();
    assert_eq!(r.request_reap(a).unwrap().state, RequestState::Failed);
    assert!(io.bytes.is_empty());
    assert_eq!(r.status().device_guards, 1);
    let b = r.device_submit(Device::Uart, b"cancelled").unwrap();
    r.request_cancel(b).unwrap();
    r.tick(65, &mut io).unwrap();
    assert_eq!(r.request_reap(b).unwrap().state, RequestState::Cancelled);
    assert!(io.bytes.is_empty());
}
#[test]
fn model_denied_spawn_and_exhausted_pid_leave_no_task_or_pages() {
    let mut r = runtime();
    for _ in 0..3 {
        r.allocate(8).unwrap();
    }
    assert_eq!(r.spawn(Workload::Memory, 10, 1, 8), Err(Error::AiDenied));
    assert_eq!(r.tasks().count(), 0);
    assert_eq!(r.memory_status().used, 24);
    r.next_task = u32::MAX;
    assert_eq!(r.spawn(Workload::Compute, 10, 1, 1), Err(Error::Exhausted));
    assert_eq!(r.memory_status().used, 24);
}

#[test]
fn device_competition_uses_model_but_uncontested_progress_is_mechanism() {
    let mut r = runtime();
    let mut io = Io::default();
    let first = r.device_batch(4).unwrap();
    r.tick(1, &mut io).unwrap();
    assert_eq!(
        r.devices.get(first + 3).unwrap().state,
        RequestState::Complete
    );
    assert_eq!(r.devices.get(first).unwrap().state, RequestState::Queued);
    assert_eq!(r.status().device_decisions, 1);
    for n in 2..5 {
        r.tick(n, &mut io).unwrap();
    }
    assert_eq!(r.status().device_decisions, 3);
    assert_eq!(r.status().device_mechanisms, 1);
    assert!(r.audit().any(|a| a.source == DecisionSource::AiDirect
        && a.object == first + 3
        && a.event == AuditEvent::Completed));
}
#[test]
fn cancellation_and_task_cleanup_preserve_terminal_receipts() {
    let mut r = runtime();
    let mut io = Io::default();
    let id = r.device_submit(Device::Uart, b"cancel me").unwrap();
    r.request_cancel(id).unwrap();
    r.request_reap(id).unwrap();
    let receipts: std::vec::Vec<_> = r.audit().filter(|a| a.object == id).collect();
    assert!(receipts.iter().any(|a| a.event == AuditEvent::Submitted));
    assert!(
        receipts.iter().any(|a| a.event == AuditEvent::Cancelled
            && a.request_state == Some(RequestState::Cancelled))
    );
    assert!(receipts.iter().any(|a| a.event == AuditEvent::Reaped));
    let pid = r.spawn(Workload::Uart, 2, 1, 1).unwrap();
    r.tick(1, &mut io).unwrap();
    r.kill(pid).unwrap();
    assert!(
        r.audit()
            .any(|a| a.owner == pid && a.event == AuditEvent::Cancelled)
    );
    assert!(
        r.audit()
            .any(|a| a.owner == pid && a.event == AuditEvent::Released)
    );
    assert_eq!(r.memory_status().free, 32);
}
#[test]
fn platform_backpressure_adapter_retains_retry_semantics() {
    assert_eq!(
        IoError::from(cyxia_contracts::PlatformError::Again),
        IoError::Again
    );
    struct Once {
        attempts: usize,
    }
    impl DeviceIo for Once {
        fn uart_write(&mut self, d: &[u8]) -> Result<usize, IoError> {
            self.attempts += 1;
            if self.attempts == 1 {
                Err(cyxia_contracts::PlatformError::Again.into())
            } else {
                Ok(d.len())
            }
        }
        fn timer_read(&mut self) -> Result<u64, IoError> {
            Ok(1)
        }
    }
    let mut r = runtime();
    let id = r.device_submit(Device::Uart, b"eventual").unwrap();
    let mut io = Once { attempts: 0 };
    r.tick(1, &mut io).unwrap();
    assert_eq!(r.devices.get(id).unwrap().state, RequestState::Queued);
    r.tick(2, &mut io).unwrap();
    assert_eq!(r.request_reap(id).unwrap().state, RequestState::Complete);
    assert_eq!(r.status().device_decisions, 0);
}
#[test]
fn audit_id_exhaustion_rejects_before_resource_changes() {
    let mut r = runtime();
    r.audit_next = u64::MAX - 2;
    assert_eq!(r.allocate(1), Err(Error::Exhausted));
    assert_eq!(r.memory_status().free, 32);
    assert_eq!(r.device_batch(2), Err(Error::Exhausted));
    assert_eq!(r.requests().count(), 0);
}

#[test]
fn user_policy_bounds_and_actual_dispatch_choices() {
    assert_eq!(user_memory_policy(64, 8), Ok((true, 8193)));
    assert_eq!(user_memory_policy(16, 8), Ok((true, 8193)));
    assert_eq!(user_memory_policy(8, 8), Ok((false, 8193)));
    assert_eq!(user_memory_policy(1000, 8), Err(Error::Invalid));
    assert_eq!(user_memory_policy(65, 8), Err(Error::Invalid));
    assert_eq!(user_memory_policy(64, 0), Err(Error::Invalid));
    assert_eq!(user_memory_policy(64, 9), Err(Error::Invalid));
    assert_eq!(user_cpu_policy(false, 0), Ok((1, 12290)));
    assert_eq!(user_cpu_policy(true, 0), Ok((4, 12290)));
    assert_eq!(user_cpu_policy(true, 1), Ok((1, 12290)));
    assert_eq!(user_cpu_policy(true, 9), Err(Error::Invalid));
}
#[test]
fn eight_slot_admission_keeps_the_trained_boundary_and_one_slot_reserve() {
    for free in 0..=64 {
        for requested in 1..=8 {
            let (allowed, model_id) = user_memory_policy(free, requested).unwrap();
            assert_eq!(model_id, 8193);
            assert_eq!(
                allowed,
                model::memory((free as usize).min(PAGES), requested as usize)
            );
            assert!(!allowed || requested <= free);
        }
    }
    let mut free = 64;
    let mut admitted = 0;
    while user_memory_policy(free, 8).unwrap().0 {
        admitted += 1;
        free -= 8;
    }
    assert_eq!(admitted, 7);
    assert_eq!(free, 8);
    assert!(user_memory_policy(free + 8, 8).unwrap().0);
}
#[test]
fn anonymous_memory_policy_bounds_and_capacity_conservatism() {
    assert_eq!(anonymous_memory_policy(1024, 96), Ok((true, 8194)));
    assert_eq!(anonymous_memory_policy(128, 128), Ok((false, 8194)));
    assert_eq!(anonymous_memory_policy(4096, 1024), Ok((true, 8194)));
    for (free, request) in [(4097, 1), (1024, 0), (2048, 2049)] {
        assert_eq!(anonymous_memory_policy(free, request), Err(Error::Invalid));
    }
    // Exhaustively check the kernel's 4 MiB domain: rounding must not approve
    // more pages than exist. Actual grants independently enforce capacity.
    for free in 0..=2048 {
        for requested in 1..=2048 {
            let (allowed, _) = anonymous_memory_policy(free, requested).unwrap();
            assert!(!allowed || requested <= free);
        }
    }
}
#[test]
fn executable_memory_policy_cannot_overcommit_image_arena() {
    assert_eq!(executable_memory_policy(4096, 20), Ok((true, 8195)));
    assert_eq!(executable_memory_policy(4096, 4096), Ok((false, 8195)));
    for (free, requested) in [(4097, 1), (4096, 0), (4096, 4097)] {
        assert_eq!(
            executable_memory_policy(free, requested),
            Err(Error::Invalid)
        );
    }
    // Test all quantized model inputs at their most permissive boundaries.
    for free in (0..=4096).step_by(16) {
        for requested in (1..=4096).step_by(16) {
            let (allowed, id) = executable_memory_policy(free, requested).unwrap();
            assert_eq!(id, 8195);
            assert!(!allowed || requested <= free);
        }
    }
}
#[test]
fn isolated_process_selection_uses_model_and_bounds_starvation() {
    let io = UserCandidate {
        waiting_ms: 1,
        cpu_bound: false,
    };
    let cpu = UserCandidate {
        waiting_ms: 1,
        cpu_bound: true,
    };
    let decision = user_dispatch_policy(&[Some(cpu), Some(io)])
        .unwrap()
        .unwrap();
    assert_eq!(decision.index, 1);
    assert_eq!(decision.source, DecisionSource::AiDirect);
    assert_eq!(decision.model, 0x3001);
    let older = UserCandidate {
        waiting_ms: 20,
        ..cpu
    };
    assert_eq!(
        user_dispatch_policy(&[Some(io), Some(older)])
            .unwrap()
            .unwrap()
            .index,
        1
    );
    let starved = UserCandidate {
        waiting_ms: 100,
        ..cpu
    };
    let decision = user_dispatch_policy(&[Some(io), Some(starved)])
        .unwrap()
        .unwrap();
    assert_eq!(decision.index, 1);
    assert_eq!(decision.source, DecisionSource::SafetyGuard);
    assert!(user_dispatch_policy(&[None; 8]).unwrap().is_none());
    assert_eq!(user_dispatch_policy(&[None; 9]), Err(Error::Invalid));
}
#[test]
fn eight_dispatch_candidates_keep_model_ranking_ties_and_starvation_guard() {
    let candidate = UserCandidate {
        waiting_ms: 1,
        cpu_bound: true,
    };
    let mut candidates = [Some(candidate); 8];
    candidates[7] = Some(UserCandidate {
        waiting_ms: 20,
        ..candidate
    });
    let selected = user_dispatch_policy(&candidates).unwrap().unwrap();
    assert_eq!(selected.index, 7);
    assert_eq!(selected.source, DecisionSource::AiDirect);
    assert_eq!(selected.model, 12289);
    candidates[6] = candidates[7];
    assert_eq!(user_dispatch_policy(&candidates).unwrap().unwrap().index, 6);
    candidates[7] = Some(UserCandidate {
        waiting_ms: 100,
        ..candidate
    });
    let selected = user_dispatch_policy(&candidates).unwrap().unwrap();
    assert_eq!(selected.index, 7);
    assert_eq!(selected.source, DecisionSource::SafetyGuard);
}
