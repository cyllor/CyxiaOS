// Long-running PC operating-system composition. CPU mechanics remain in machine.
#[path = "../runtime/os.rs"]
mod os;
#[path = "../platform/pc/devices.rs"]
mod devices;
#[path = "../platform/pc/virtio_platform.rs"]
mod virtio_platform;
#[path = "../platform/pc/clock.rs"]
mod clock;
#[path = "../desktop/entropy.rs"]
mod entropy;
#[path = "../desktop/process_arch.rs"]
mod process_arch;
#[path = "../desktop/address_space.rs"]
mod address_space;
#[path = "../desktop/user.rs"]
mod user;
#[path = "../desktop/ai.rs"]
mod ai;
#[path = "../desktop/memory/user_heap.rs"]
mod user_heap;
#[cfg(feature = "ported")]
#[path = "../desktop/memory/exec_memory.rs"]
mod exec_memory;
#[cfg(feature = "ported")]
#[path = "../desktop/memory/shared_memory.rs"]
mod shared_memory;
#[path = "../desktop/storage.rs"]
mod storage;
#[cfg(feature = "graphics")]
#[path = "../desktop/graphics.rs"]
mod graphics;
pub(crate) use machine::{HIGH, halt, hex, log, try_log};
