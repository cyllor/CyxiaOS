//! Explicit metadata envelopes. Per-process quotas do not reserve a share of
//! the global pools; global exhaustion remains an ordinary checked error.
#[derive(Clone, Copy)]
pub struct ObjectProfile {
    pub name: &'static str,
    pub fds_per_process: usize,
    pub open_descriptions: usize,
    pub epolls_per_owner: usize,
    pub epoll_instances: usize,
    pub inotify_per_owner: usize,
    pub inotify_instances: usize,
}

impl ObjectProfile {
    pub(crate) fn is_within_build(self) -> bool {
        (3..=PROFILE.fds_per_process).contains(&self.fds_per_process)
            && (3..=PROFILE.open_descriptions).contains(&self.open_descriptions)
            && (1..=PROFILE.epolls_per_owner).contains(&self.epolls_per_owner)
            && (1..=PROFILE.epoll_instances).contains(&self.epoll_instances)
            && (1..=PROFILE.inotify_per_owner).contains(&self.inotify_per_owner)
            && (1..=PROFILE.inotify_instances).contains(&self.inotify_instances)
    }
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
