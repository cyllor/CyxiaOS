//! Read-only reports from the real guest-owned services. No synthetic coverage score.
use super::Shell;
use core::fmt::{self, Write};

impl Shell {
    pub fn ai_status(&self, out: &mut impl Write) -> fmt::Result {
        let runtime = self.runtime.status();
        let memory = self.runtime.memory_status();
        let fs = self.fs.status();
        writeln!(
            out,
            "AI_DOMAIN name=el1_memory model=8193 proposals={} denied={} used_pages={} free_pages={} backing=BOOTSTRAP learning=offline\r",
            memory.decisions, memory.denied, memory.used, memory.free
        )?;
        writeln!(
            out,
            "AI_DOMAIN name=el1_cpu model=12289 ai_executed={} guard_executed={} tasks={} learning=offline\r",
            runtime.dispatches, runtime.guards, runtime.tasks
        )?;
        writeln!(
            out,
            "AI_DOMAIN name=uart_timer model=16385 ai_executed={} guard_executed={} mechanism={} failed={} learning=offline\r",
            runtime.device_decisions,
            runtime.device_guards,
            runtime.device_mechanisms,
            runtime.device_failures
        )?;
        let policy = fs.policy;
        writeln!(
            out,
            "AI_DOMAIN name=fs_admission proposals={} approved={} denied={} capacity={} revision={} learning=offline\r",
            policy.admission_proposals,
            policy.admission_allowed,
            policy.admission_denied,
            policy.capacity_rejected,
            fs.revision
        )?;
        writeln!(
            out,
            "AI_DOMAIN name=fs_cache proposals={} ai_selected={} rejected={} mechanism={} hits={} misses={} learning=local_operator_publish\r",
            policy.cache_proposals,
            policy.cache_selected,
            policy.cache_rejected,
            policy.cache_mechanisms,
            fs.hits,
            fs.misses
        )?;
        writeln!(
            out,
            "AI_LEARNING scope=fs_cache version={} samples={} trained={} candidate={} rollback={} publication=OPERATOR persistence=volatile\r",
            fs.model.version,
            fs.model.samples,
            fs.model.trained,
            fs.model.candidate,
            fs.model.rollback
        )?;
        writeln!(
            out,
            "AI_LEARNING_COUNTS requests={} insufficient_samples={} validation_rejections={} publications={} rollbacks={}\r",
            fs.model.train_requests,
            fs.model.insufficient_samples,
            fs.model.validation_rejections,
            fs.model.publications,
            fs.model.rollbacks
        )?;
        writeln!(
            out,
            "AI_VALIDATION scope=fs_cache result={:?}\r",
            fs.model.validation
        )?;
        writeln!(
            out,
            "AI_AUDIT scope=el1 capacity=64 dropped={} persistent=false command=ai_audit\r",
            runtime.audit_dropped
        )?;
        Ok(())
    }
}
