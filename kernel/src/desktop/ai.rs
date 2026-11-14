//! One CPU0 foreground snapshot of actual subsystem policy and execution counters.
//! This is observability, not an additional resource authority or model coordinator.
use core::fmt::Write;

pub fn poll(shell: &mut cyxia_shell::Shell, out: &mut impl Write) {
    if !shell.take_system_request() {
        return;
    }
    let _ = writeln!(
        out,
        "\r\nAI_SYSTEM schema=1 architecture=aarch64 cpus=1 ram_mib={} models=local_integer full_contract=false\r",
        cyxia_platform_virt::RAM_MIB
    );
    let _ = shell.ai_status(out);
    super::user::ai_status(out);
    super::storage::ai_status(out);
    #[cfg(feature = "graphics")]
    super::graphics::ai_status(out);
    #[cfg(not(feature = "graphics"))]
    let _ = writeln!(out, "AI_DOMAIN name=display state=not_built\r");
    let _ = writeln!(
        out,
        "AI_DOMAIN name=input policy=MECHANISM purpose=ordered_user_events\r"
    );
    let _ = writeln!(
        out,
        "AI_DOMAIN name=security policy=SAFETY_GUARD purpose=permissions_ownership_wx\r"
    );
    let _ = writeln!(
        out,
        "AI_GAPS coordinator=absent network=absent smp=absent cross_platform=unverified global_learning=absent durable_model_state=absent\r"
    );
    let _ = writeln!(out, "AI_SYSTEM_END\r");
}
