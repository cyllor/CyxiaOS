// Feature/profile registration for the ARM integration. No runtime behavior lives here.
#[cfg(all(
    feature = "register-v15-selftest",
    any(
        feature = "prototype-runtime",
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest"
    )
))]
compile_error!("register-v15-selftest has an independent evidence scope");
#[cfg(all(
    feature = "smp-selftest",
    any(feature = "ported", feature = "graphics", feature = "large-memory")
))]
compile_error!("smp-selftest cannot certify the CPU0-only desktop/ported profile");
#[cfg(all(feature = "net-selftest", feature = "ai-control-selftest"))]
compile_error!("net-selftest and ai-control-selftest have separate evidence scopes");
#[cfg(all(
    feature = "model-v13-selftest",
    any(feature = "ai-control-selftest", feature = "net-selftest")
))]
compile_error!("model-v13-selftest must run as a separate evidence profile");
#[cfg(all(
    feature = "storage-v13-selftest",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime"
    )
))]
compile_error!("storage-v13-selftest must run as a separate evidence profile");
#[cfg(all(
    feature = "prototype-runtime",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest"
    )
))]
compile_error!("prototype-runtime must run as a separate evidence profile");
#[cfg(any(
    feature = "storage-v13-selftest",
    feature = "prototype-runtime",
    feature = "tcp-v13-selftest"
))]
#[path = "../platform/virt/prototype_storage.rs"]
mod prototype_storage;
#[cfg(all(
    feature = "tcp-v13-selftest",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime",
        feature = "storage-v13-selftest"
    )
))]
compile_error!("tcp-v13-selftest must run as a separate evidence profile");
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/a02_capture.rs"]
mod a02_capture;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/a03_demand.rs"]
mod a03_demand;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/recovery/boot_recovery.rs"]
mod boot_recovery;
#[cfg(feature = "tcp-v13-selftest")]
#[path = "../runtime/network/cluster_transport.rs"]
mod cluster_transport;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/control/control_pool.rs"]
mod control_pool;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/control/domain_control.rs"]
mod domain_control;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/domain_evidence.rs"]
mod domain_evidence;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/files/domain_file_abi.rs"]
mod domain_file_abi;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/network/domain_network.rs"]
mod domain_network;
#[cfg(feature = "unified-runtime")]
#[path = "../platform/virt/domain_platform.rs"]
mod domain_platform;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/services/domain_services.rs"]
mod domain_services;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/files/domain_storage.rs"]
mod domain_storage;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/tasks/domain_tasks.rs"]
mod domain_tasks;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_canary.rs"]
mod learning_canary;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_evidence.rs"]
mod learning_evidence;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_history.rs"]
mod learning_history;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_prewarm.rs"]
mod learning_prewarm;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_replay.rs"]
mod learning_replay;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_session.rs"]
mod learning_session;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/learning_workload.rs"]
mod learning_workload;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/tasks/local_placement.rs"]
mod local_placement;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/memory_fault_capture.rs"]
mod memory_fault_capture;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/learning/model_bank.rs"]
mod model_bank;
#[cfg(feature = "net-selftest")]
#[path = "../selftest/net_selftest.rs"]
mod net_selftest;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/network_diagnostics.rs"]
mod network_diagnostics;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/ownership_evidence.rs"]
mod ownership_evidence;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/cluster/peer_replay.rs"]
mod peer_replay;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/services/service_windows.rs"]
mod service_windows;
#[cfg(feature = "smp-selftest")]
#[cfg_attr(
    any(
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "prototype-runtime",
        feature = "tcp-v13-selftest"
    ),
    allow(dead_code)
)]
#[path = "../arch/aarch64/smp.rs"]
mod smp;
#[cfg(feature = "unified-runtime")]
#[path = "../diagnostics/storage_fault_capture.rs"]
mod storage_fault_capture;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/cluster/unified.rs"]
mod unified;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/cluster/unified_store.rs"]
mod unified_store;
#[cfg(feature = "unified-runtime")]
#[path = "../runtime/cluster/unified_task.rs"]
mod unified_task;
#[cfg(not(feature = "selftest"))]
#[path = "../desktop/ai.rs"]
mod ai;
#[path = "../platform/virt/clock.rs"]
mod clock;
#[cfg(any(
    feature = "tcp-v13-selftest",
    feature = "unified-runtime",
    all(feature = "ported", not(feature = "selftest"))
))]
#[path = "../platform/virt/entropy.rs"]
mod entropy;
#[cfg(all(feature = "ported", not(feature = "selftest")))]
#[path = "../desktop/memory/exec_memory.rs"]
mod exec_memory;
#[cfg(feature = "graphics")]
#[path = "../desktop/graphics.rs"]
mod graphics;
#[cfg_attr(feature = "smp-selftest", allow(dead_code))]
#[path = "../platform/virt/interrupts.rs"]
mod interrupts;
#[cfg(all(feature = "ported", not(feature = "selftest")))]
#[path = "../desktop/memory/shared_memory.rs"]
mod shared_memory;
#[cfg(not(feature = "selftest"))]
#[path = "../desktop/shell.rs"]
mod shell;
#[cfg(not(feature = "selftest"))]
#[path = "../desktop/storage.rs"]
mod storage;
#[cfg(not(feature = "selftest"))]
#[path = "../desktop/user.rs"]
mod user;
#[cfg(not(feature = "selftest"))]
#[path = "../desktop/memory/user_heap.rs"]
mod user_heap;
#[cfg(any(
    feature = "graphics",
    feature = "storage-v13-selftest",
    feature = "tcp-v13-selftest",
    feature = "prototype-runtime",
    feature = "net-selftest",
    not(feature = "selftest")
))]
#[path = "../platform/virt/virtio_platform.rs"]
mod virtio_platform;
