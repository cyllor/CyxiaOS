//! Independently verified D01 terminal custody on the metered CPU0 turn.

use super::{
    APPLY_DEADLINE_NS, DOMAIN, Error, NativeControl, REPORT_BYTES, RpcError, Stage, Terminal,
    binding, now_ns, sha, signed_d01, with_control,
};
use cyxia_kernel_core::control_plane::{
    apply_report_v1::{
        ActionStatus, ApplyReportV1, BoundReport, MAX_APPLY_REPORT_BYTES, ReportOrigin,
        TrustedApplyScope,
    },
    apply_work_v1::{ApplyWorkV1, WorkFrame},
    plan_wire_v2::PlanV2,
};

const ORIGIN: ReportOrigin = ReportOrigin::Kernel;

pub(crate) fn tick_native(now: u64) -> Result<(), Error> {
    with_control(|state| match state.apply_turn(now) {
        Err(Error::Busy | Error::NotReady) => Ok(()),
        result => result,
    })
}

impl NativeControl {
    fn apply_turn(&mut self, now: u64) -> Result<(), Error> {
        let (Some(setup), Some(owners), Some(plan)) = (self.setup, self.owners, self.plan.as_mut())
        else {
            return Ok(());
        };
        if matches!(plan.stage, Stage::Prepared | Stage::Unknown) {
            return Ok(());
        }
        let action = self
            .desired
            .pending(DOMAIN, setup.target.object)?
            .ok_or(Error::Stale)?;
        if action.key != plan.key || action.binding != binding(setup.target) {
            return Err(Error::Stale);
        }
        let scope = TrustedApplyScope {
            boot_epoch: setup.boot_epoch(),
            plan_version: action.version,
            now_ns: now,
        };
        let apply_deadline = action
            .published_ns
            .checked_add(APPLY_DEADLINE_NS)
            .ok_or(Error::Clock)?;
        let raw = match &plan.stage {
            Stage::Published if !super::publications_fenced() && now < apply_deadline => {
                let frame = self.gate.claim_apply_work(
                    &plan.wire,
                    0,
                    scope,
                    action.binding,
                    ORIGIN,
                    |work| {
                        self.desired.accept(work, ORIGIN, now, |a| {
                            signed_d01::apply(
                                *work,
                                a.prior_target_version,
                                plan.sampled_ns,
                                a.until_ns,
                                a.published_ns,
                                apply_deadline,
                            )
                        })
                    },
                );
                let frame = match frame {
                    Err(Error::Expired | Error::Stale) => return Ok(()),
                    result => result?,
                };
                plan.stage = Stage::Applying(frame);
                return Ok(());
            }
            Stage::Published => {
                // CPU0 still owns both admission slots and no work was handed
                // to the scheduler. Seal that exact no-effect fact before any
                // terminal can free the reservation.
                let wire = PlanV2::decode(&plan.wire)?;
                let frame = WorkFrame::from_plan(
                    &wire,
                    0,
                    scope.boot_epoch,
                    scope.plan_version,
                    action.binding,
                    ORIGIN,
                )?;
                let w = ApplyWorkV1::decode(frame.bytes())?;
                let reason = if super::publications_fenced() {
                    RpcError::Auth
                } else {
                    RpcError::Timeout
                };
                let raw =
                    encode_report(make_report(w, now, ActionStatus::Cancelled, reason as i32))?;
                let report = BoundReport {
                    bytes: &raw,
                    origin: ORIGIN,
                };
                self.gate.seal_unaccepted_terminal(
                    owners.supervisor.holder,
                    &plan.wire,
                    report,
                    scope,
                    action.binding,
                    |work, r| {
                        if *work != w || action.accepted_ns.is_some() {
                            return Err(Error::Denied);
                        }
                        self.desired.seal_unaccepted(r, ORIGIN, now, |a| {
                            if a == action {
                                Ok(())
                            } else {
                                Err(Error::Stale)
                            }
                        })
                    },
                )?;
                plan.stage = Stage::Cancelled(raw);
                raw
            }
            Stage::Applying(frame) => {
                let work = ApplyWorkV1::decode(frame.bytes())?;
                // The native verifier reads the version actually adopted by
                // the business scheduler at its dispatch point.
                let completed_ns = match signed_d01::verify_applied(work, now) {
                    Err(Error::Expired | Error::Stale) => return Ok(()),
                    result => result?,
                };
                encode_report(make_report(work, completed_ns, ActionStatus::Applied, 0))?
            }
            Stage::Cancelled(saved) => *saved,
            Stage::Prepared | Stage::Unknown => unreachable!(),
        };
        let report = ApplyReportV1::decode(&raw)?;
        let now = now_ns();
        let scope = TrustedApplyScope {
            now_ns: now,
            ..scope
        };
        let copied = BoundReport {
            bytes: &raw,
            origin: ORIGIN,
        };
        let plan_digest = sha(&plan.wire);
        let decision_digest = sha(&plan.decision);
        let terminal = Terminal {
            key: plan.key,
            decision_seq: plan.decision_seq,
            plan_digest,
            decision_digest,
            report: raw,
        };
        let effect_verified = matches!(plan.stage, Stage::Applying(_));
        self.gate.settle_verified_apply_reports_with_feedback(
            owners.supervisor.holder,
            &plan.wire,
            &[copied],
            &[action.binding],
            scope,
            None,
            |_, actual| {
                if *actual == report
                    && match actual.state {
                        ActionStatus::Applied => effect_verified && action.accepted_ns.is_some(),
                        ActionStatus::Cancelled => !effect_verified && action.accepted_ns.is_none(),
                        _ => false,
                    }
                {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            },
            |batch| {
                if batch.plan_wire() != plan.wire || batch.count() != 1 {
                    return Err(Error::Denied);
                }
                // Close the exact desired reservation under the same CPU0
                // serializer after native proof and before the gate releases
                // registration custody. History installation is infallible.
                self.desired.finish(&report, ORIGIN, now, |a| {
                    if a == action {
                        Ok(())
                    } else {
                        Err(Error::Stale)
                    }
                })?;
                self.terminal[self.next_terminal] = Some(terminal);
                self.next_terminal = (self.next_terminal + 1) % self.terminal.len();
                Ok(())
            },
        )?;
        if effect_verified && report.action != plan.weight_before.to_le_bytes() {
            self.last_weight_change_ns = Some(report.completed_ns);
        }
        self.plan = None;
        Ok(())
    }
}

fn make_report(
    work: ApplyWorkV1<'_>,
    completed_ns: u64,
    state: ActionStatus,
    result: i32,
) -> ApplyReportV1<'_> {
    ApplyReportV1 {
        key: work.key,
        action_index: work.action_index,
        domain_id: work.domain,
        state,
        target: work.target,
        executor_generation: work.executor_generation,
        plan_version: work.plan_version,
        result,
        completed_ns,
        action: work.payload,
    }
}

fn encode_report(report: ApplyReportV1<'_>) -> Result<[u8; REPORT_BYTES], Error> {
    let mut frame = [0; MAX_APPLY_REPORT_BYTES];
    let len = report.encode(&mut frame)?;
    frame[..len].try_into().map_err(|_| Error::Invalid)
}
