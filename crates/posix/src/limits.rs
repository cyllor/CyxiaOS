//! Explicit metadata envelopes. Per-process quotas do not reserve a share of
//! the global pools; global exhaustion remains an ordinary checked error.
pub struct ObjectProfile {
    pub name: &'static str,
    pub fds_per_process: usize,
    pub open_descriptions: usize,
    pub epolls_per_owner: usize,
    pub epoll_instances: usize,
    pub inotify_per_owner: usize,
    pub inotify_instances: usize,
}

pub const PROFILE: ObjectProfile = if cfg!(feature = "cosmic-applets-v1") {
    ObjectProfile {
        name: if cfg!(feature = "cosmic-notifications-applet-v1") {
            "cosmic-notifications-applet-objects-v1"
        } else {
            "cosmic-applets-objects-v1"
        },
        fds_per_process: 128,
        open_descriptions: 512,
        epolls_per_owner: 16,
        epoll_instances: 64,
        inotify_per_owner: 8,
        inotify_instances: 32,
    }
} else if cfg!(feature = "full-os") {
    ObjectProfile {
        name: "full-os-objects-v1",
        fds_per_process: 64,
        open_descriptions: 256,
        epolls_per_owner: 16,
        epoll_instances: 64,
        inotify_per_owner: 8,
        inotify_instances: 32,
    }
} else {
    ObjectProfile {
        name: "legacy-objects-v1",
        fds_per_process: 16,
        open_descriptions: 128,
        epolls_per_owner: 2,
        epoll_instances: 16,
        inotify_per_owner: 2,
        inotify_instances: 8,
    }
};
