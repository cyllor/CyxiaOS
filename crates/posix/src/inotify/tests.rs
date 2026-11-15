extern crate std;
use super::*;
use crate::{epoll, spawn::Mapping};
use cyxia_ai_fs::Path;
use std::{string::String, vec::Vec};

fn path(name: &str) -> Path {
    Path::resolve(Path::ROOT, name).unwrap()
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[derive(Debug, PartialEq, Eq)]
struct Got {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}
fn event(wd: i32, mask: u32, cookie: u32, name: &str) -> Got {
    Got {
        wd,
        mask,
        cookie,
        name: String::from(name),
    }
}
fn read(p: &mut Process<'_>, fs: &FileSystem, fd: i32) -> Vec<Got> {
    let mut bytes = [0xa5; 8192];
    let len = p.inotify_read(fs, fd, &mut bytes).unwrap();
    let mut at = 0;
    let mut result = Vec::new();
    while at < len {
        let size = word(&bytes, at + 12) as usize;
        assert_eq!(size % 16, 0, "Linux pads event names to its header size");
        assert!(at + 16 + size <= len, "read split an event");
        let name = &bytes[at + 16..at + 16 + size];
        let end = if size == 0 {
            0
        } else {
            name.iter().position(|b| *b == 0).unwrap()
        };
        assert!(
            name[end..].iter().all(|b| *b == 0),
            "padding exposed stale bytes"
        );
        result.push(event(
            word(&bytes, at) as i32,
            word(&bytes, at + 4),
            word(&bytes, at + 8),
            core::str::from_utf8(&name[..end]).unwrap(),
        ));
        at += 16 + size;
    }
    assert_eq!(at, len);
    result
}

#[test]
fn committed_filesystem_events_are_readable_records_with_real_names() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/config")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK | O_CLOEXEC).unwrap();
    let wd = p
        .inotify_add_watch(&fs, fd, "/config", CREATE | MODIFY | ATTRIB)
        .unwrap();
    fs.write(path("/config/key"), b"value", false).unwrap();
    let mut bytes = [0; 256];
    let size = p.inotify_read(&fs, fd, &mut bytes).unwrap();
    let first = 16 + word(&bytes, 12) as usize;
    assert_eq!(word(&bytes, 0), wd as u32);
    assert_eq!(word(&bytes, 4), CREATE);
    assert_eq!(&bytes[16..20], b"key\0");
    assert_eq!(word(&bytes, first), wd as u32);
    assert_eq!(word(&bytes, first + 4), MODIFY);
    assert_eq!(size, first + 16 + word(&bytes, first + 12) as usize);
    assert_eq!(p.inotify_read(&fs, fd, &mut bytes), Err(Errno::Again));
    p.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
    assert_eq!(fs.stat(path("/config/key")).unwrap().kind, Kind::File);
}

#[test]
fn masks_change_only_future_events_and_admission_errors_do_not_mutate_watches() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/config")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK | O_CLOEXEC).unwrap();
    assert!(p.close_on_exec(fd).unwrap());
    let wd = p
        .inotify_add_watch(&fs, fd, "/config", CREATE | ONLYDIR | DONT_FOLLOW)
        .unwrap();
    fs.write(path("/config/key"), b"old", false).unwrap();
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config", MODIFY | MASK_ADD),
        Ok(wd)
    );
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, CREATE, 0, "key")]
    );
    fs.write(path("/config/key"), b"next", false).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, MODIFY, 0, "key")]
    );
    assert_eq!(p.inotify_add_watch(&fs, fd, "/config", ATTRIB), Ok(wd));
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config", CREATE | MASK_CREATE),
        Err(Errno::Exist)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config", ATTRIB | MASK_ADD | MASK_CREATE),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config", 0),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config", ATTRIB | 0x1000),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, 0, "/config", ATTRIB),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, -1, "/config", ATTRIB),
        Err(Errno::Badf)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config/key", ATTRIB | ONLYDIR),
        Err(Errno::Notdir)
    );
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/missing", ATTRIB),
        Err(Errno::Noent)
    );
    fs.set_mode(path("/config/key"), 0o200).unwrap();
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/config/key", ATTRIB),
        Err(Errno::Access)
    );
    fs.write(path("/config/key"), b"ignored write", false)
        .unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, ATTRIB, 0, "key")]
    );
    assert_eq!(objects.snapshot().inotify_watches, 1);
    let before = objects.snapshot();
    assert_eq!(p.inotify_init(&fs, 1), Err(Errno::Inval));
    assert_eq!(objects.snapshot(), before);
    p.close_all(&mut fs).unwrap();
}

#[test]
fn oneshot_and_explicit_removal_append_ignored_without_reusing_watch_ids() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/config")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let first = p
        .inotify_add_watch(&fs, fd, "/config", CREATE | ONESHOT)
        .unwrap();
    fs.write(path("/config/one"), b"1", false).unwrap();
    fs.write(path("/config/two"), b"2", false).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(first, CREATE, 0, "one"), event(first, IGNORED, 0, "")]
    );
    assert_eq!(p.inotify_rm_watch(&fs, fd, first), Err(Errno::Inval));
    let second = p.inotify_add_watch(&fs, fd, "/config", CREATE).unwrap();
    assert!(second > first);
    fs.mkdir(path("/config/dir")).unwrap();
    p.inotify_rm_watch(&fs, fd, second).unwrap();
    let third = p.inotify_add_watch(&fs, fd, "/config", CREATE).unwrap();
    assert!(third > second);
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(second, CREATE | ISDIR, 0, "dir"),
            event(second, IGNORED, 0, "")
        ]
    );
    assert_eq!(objects.snapshot().inotify_watches, 1);
    p.close_all(&mut fs).unwrap();
}

#[test]
fn rename_pairs_real_names_and_keeps_the_inode_watch_after_a_move() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/old")).unwrap();
    fs.mkdir(path("/new")).unwrap();
    fs.write(path("/old/key"), b"value", false).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let old = p.inotify_add_watch(&fs, fd, "/old", MOVED_FROM).unwrap();
    let new = p.inotify_add_watch(&fs, fd, "/new", MOVED_TO).unwrap();
    let file = p
        .inotify_add_watch(&fs, fd, "/old/key", MOVE_SELF | MODIFY)
        .unwrap();
    fs.rename_file(path("/old/key"), path("/new/renamed"), false)
        .unwrap();
    let got = read(&mut p, &fs, fd);
    let cookie = got[0].cookie;
    assert_ne!(cookie, 0);
    assert_eq!(
        got,
        std::vec![
            event(old, MOVED_FROM, cookie, "key"),
            event(new, MOVED_TO, cookie, "renamed"),
            event(file, MOVE_SELF, 0, "")
        ]
    );
    fs.write(path("/new/renamed"), b"changed", false).unwrap();
    assert_eq!(read(&mut p, &fs, fd), std::vec![event(file, MODIFY, 0, "")]);
    assert_eq!(
        p.inotify_add_watch(&fs, fd, "/new/renamed", ATTRIB | MASK_ADD),
        Ok(file)
    );
    p.close_all(&mut fs).unwrap();
}

#[test]
fn unlink_filters_only_parent_activity_and_final_pin_release_removes_inode_watch() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/dir")).unwrap();
    fs.write(path("/dir/key"), b"value", false).unwrap();
    let pin = fs.pin(path("/dir/key")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let excluded = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let normal = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let parent = p
        .inotify_add_watch(&fs, excluded, "/dir", ALL_EVENTS | EXCL_UNLINK)
        .unwrap();
    let inode = p
        .inotify_add_watch(&fs, excluded, "/dir/key", ALL_EVENTS)
        .unwrap();
    let normal_parent = p
        .inotify_add_watch(&fs, normal, "/dir", ALL_EVENTS)
        .unwrap();
    fs.remove(path("/dir/key"), false).unwrap();
    assert_eq!(
        read(&mut p, &fs, excluded),
        std::vec![event(parent, DELETE, 0, "key"), event(inode, ATTRIB, 0, "")]
    );
    assert_eq!(
        read(&mut p, &fs, normal),
        std::vec![event(normal_parent, DELETE, 0, "key")]
    );
    fs.write_at(pin, 0, b"next").unwrap();
    assert_eq!(
        read(&mut p, &fs, excluded),
        std::vec![event(inode, MODIFY, 0, "")]
    );
    assert_eq!(
        read(&mut p, &fs, normal),
        std::vec![event(normal_parent, MODIFY, 0, "key")]
    );
    fs.unpin(pin).unwrap();
    assert_eq!(
        read(&mut p, &fs, excluded),
        std::vec![
            event(inode, DELETE_SELF, 0, ""),
            event(inode, IGNORED, 0, "")
        ]
    );
    assert_eq!(
        p.inotify_read(&fs, normal, &mut [0; 128]),
        Err(Errno::Again)
    );
    assert_eq!(p.inotify_rm_watch(&fs, excluded, inode), Err(Errno::Inval));
    fs.write(path("/dir/key"), b"replacement", false).unwrap();
    assert_eq!(
        read(&mut p, &fs, excluded),
        std::vec![
            event(parent, CREATE, 0, "key"),
            event(parent, MODIFY, 0, "key")
        ]
    );
    p.close_all(&mut fs).unwrap();
}

#[test]
fn real_open_access_and_final_close_notify_inode_parent_and_root_once() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/dir")).unwrap();
    fs.write(path("/dir/key"), b"value", false).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let mask = OPEN | ACCESS | CLOSE_WRITE | CLOSE_NOWRITE;
    let dir = p.inotify_add_watch(&fs, fd, "/dir", mask).unwrap();
    let inode = p.inotify_add_watch(&fs, fd, "/dir/key", mask).unwrap();
    let root = p.inotify_add_watch(&fs, fd, "/", mask).unwrap();
    let file = p.open(&mut fs, "/dir/key", crate::O_RDONLY, 0).unwrap();
    assert_eq!(p.read(&mut fs, file, &mut [0; 8]), Ok(5));
    let alias = p.dup(file).unwrap();
    p.close(&mut fs, file).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(dir, OPEN, 0, "key"),
            event(inode, OPEN, 0, ""),
            event(dir, ACCESS, 0, "key"),
            event(inode, ACCESS, 0, "")
        ]
    );
    p.close(&mut fs, alias).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(dir, CLOSE_NOWRITE, 0, "key"),
            event(inode, CLOSE_NOWRITE, 0, "")
        ]
    );
    let directory = p
        .open(&mut fs, "/", crate::O_RDONLY | crate::O_DIRECTORY, 0)
        .unwrap();
    p.close(&mut fs, directory).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(root, OPEN | ISDIR, 0, ""),
            event(root, CLOSE_NOWRITE | ISDIR, 0, "")
        ]
    );
    let file = p.open(&mut fs, "/dir/key", crate::O_RDWR, 0).unwrap();
    p.close(&mut fs, file).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(dir, OPEN, 0, "key"),
            event(inode, OPEN, 0, ""),
            event(dir, CLOSE_WRITE, 0, "key"),
            event(inode, CLOSE_WRITE, 0, "")
        ]
    );
    p.close_all(&mut fs).unwrap();
}

#[test]
fn complete_reads_preserve_queue_on_short_buffers_and_account_exact_bytes() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/dir")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    p.inotify_add_watch(&fs, fd, "/dir", CREATE | MODIFY)
        .unwrap();
    assert_eq!(p.inotify_read(&fs, fd, &mut []), Err(Errno::Again));
    fs.write(path("/dir/中文 key"), b"value", false).unwrap();
    objects.observe_filesystem(&fs);
    let pending = p.inotify_pending(fd).unwrap();
    assert_eq!(pending, 64);
    assert_eq!(p.inotify_read(&fs, fd, &mut []), Err(Errno::Inval));
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 31]), Err(Errno::Inval));
    assert_eq!(p.inotify_pending(fd).unwrap(), pending);
    let mut bytes = [0xa5; 48];
    assert_eq!(p.inotify_read(&fs, fd, &mut bytes), Ok(32));
    assert_eq!(word(&bytes, 4), CREATE);
    assert_eq!(word(&bytes, 12), 16);
    assert!(bytes[32..].iter().all(|b| *b == 0xa5));
    assert_eq!(p.inotify_pending(fd), Ok(32));
    assert_eq!(p.local_readiness(fd), Ok((true, false)));
    assert_eq!(read(&mut p, &fs, fd).len(), 1);
    assert_eq!(p.inotify_pending(fd), Ok(0));
    assert_eq!(p.local_readiness(fd), Ok((false, false)));
    p.close_all(&mut fs).unwrap();
}

#[test]
fn coalescing_and_overflow_are_bounded_ordered_and_recover_after_partial_drain() {
    let mut fs = FileSystem::new();
    fs.write(path("/a"), b"a", false).unwrap();
    fs.write(path("/b"), b"b", false).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let a = p.inotify_add_watch(&fs, fd, "/a", ATTRIB).unwrap();
    let b = p.inotify_add_watch(&fs, fd, "/b", ATTRIB).unwrap();
    fs.set_mode(path("/a"), 0o600).unwrap();
    fs.set_mode(path("/a"), 0o600).unwrap();
    assert_eq!(read(&mut p, &fs, fd), std::vec![event(a, ATTRIB, 0, "")]);
    for i in 0..EVENTS + 4 {
        fs.set_mode(path(if i % 2 == 0 { "/a" } else { "/b" }), 0o600)
            .unwrap();
    }
    objects.observe_filesystem(&fs);
    assert_eq!(objects.snapshot().inotify_events, EVENTS + 1);
    assert_eq!(p.inotify_pending(fd), Ok((EVENTS + 1) * 16));
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 16]), Ok(16));
    fs.set_mode(path("/a"), 0o600).unwrap();
    fs.set_mode(path("/b"), 0o600).unwrap();
    let got = read(&mut p, &fs, fd);
    assert_eq!(got.len(), EVENTS + 1);
    for (index, item) in got[..EVENTS - 1].iter().enumerate() {
        assert_eq!(
            *item,
            event(if index % 2 == 0 { b } else { a }, ATTRIB, 0, "")
        );
    }
    assert_eq!(got[EVENTS - 1], event(-1, Q_OVERFLOW, 0, ""));
    assert_eq!(got[EVENTS], event(a, ATTRIB, 0, ""));
    fs.set_mode(path("/b"), 0o600).unwrap();
    assert_eq!(read(&mut p, &fs, fd), std::vec![event(b, ATTRIB, 0, "")]);
    p.close_all(&mut fs).unwrap();
}

#[test]
fn lost_journal_reports_overflow_and_reclaims_dead_watches_without_replaying_old_events() {
    let mut fs = FileSystem::new();
    fs.write(path("/dead"), b"old", false).unwrap();
    fs.write(path("/noise"), b"noise", false).unwrap();
    fs.write(path("/pinned"), b"old", false).unwrap();
    let pin = fs.pin(path("/pinned")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let old = p.inotify_add_watch(&fs, fd, "/dead", DELETE_SELF).unwrap();
    let retained = p
        .inotify_add_watch(&fs, fd, "/pinned", DELETE_SELF)
        .unwrap();
    fs.remove(path("/dead"), false).unwrap();
    fs.remove(path("/pinned"), false).unwrap();
    for _ in 0..cyxia_ai_fs::events::CAPACITY + 1 {
        fs.set_mode(path("/noise"), 0o600).unwrap();
    }
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(-1, Q_OVERFLOW, 0, ""), event(old, IGNORED, 0, "")]
    );
    assert_eq!(objects.snapshot().inotify_watches, 1);
    fs.unpin(pin).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(retained, DELETE_SELF, 0, ""),
            event(retained, IGNORED, 0, "")
        ]
    );
    assert_eq!(objects.snapshot().inotify_watches, 0);
    fs.write(path("/dead"), b"new", false).unwrap();
    let new = p.inotify_add_watch(&fs, fd, "/dead", ATTRIB).unwrap();
    assert!(new > old);
    let late = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    p.inotify_add_watch(&fs, late, "/dead", ALL_EVENTS).unwrap();
    assert_eq!(p.inotify_read(&fs, late, &mut [0; 128]), Err(Errno::Again));
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 128]), Err(Errno::Again));
    p.close_all(&mut fs).unwrap();
}

fn ready(p: &mut Process<'_>, fd: i32) -> Vec<epoll::Event> {
    let ready = p
        .epoll_sample(fd, |source| match source {
            epoll::Source::Local { read, write } => {
                Ok(u32::from(read) * epoll::IN | u32::from(write) * epoll::OUT)
            }
            _ => panic!("unexpected backend"),
        })
        .unwrap();
    let mut out = [epoll::Event::default(); 4];
    let count = p.epoll_collect(fd, &ready, &mut out).unwrap();
    out[..count].to_vec()
}

#[test]
fn queued_records_wake_nested_edges_and_draining_or_reuse_does_not_create_false_edges() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    p.inotify_add_watch(&fs, fd, "/", CREATE | ATTRIB).unwrap();
    let inner = p.epoll_create(0).unwrap();
    let outer = p.epoll_create(0).unwrap();
    p.epoll_ctl(
        inner,
        1,
        fd,
        epoll::Event {
            events: epoll::IN | epoll::EDGE,
            data: 1,
        },
    )
    .unwrap();
    p.epoll_ctl(
        outer,
        1,
        inner,
        epoll::Event {
            events: epoll::IN | epoll::EDGE,
            data: 2,
        },
    )
    .unwrap();
    assert!(ready(&mut p, outer).is_empty());
    fs.write(path("/key"), b"value", false).unwrap();
    objects.observe_filesystem(&fs);
    assert_eq!(
        ready(&mut p, outer),
        std::vec![epoll::Event {
            events: epoll::IN,
            data: 2
        }]
    );
    assert!(ready(&mut p, outer).is_empty());
    fs.set_mode(path("/key"), 0o600).unwrap();
    objects.observe_filesystem(&fs);
    assert_eq!(
        ready(&mut p, outer),
        std::vec![epoll::Event {
            events: epoll::IN,
            data: 2
        }]
    );
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 32]), Ok(32));
    assert_eq!(p.local_readiness(fd), Ok((true, false)));
    assert!(ready(&mut p, outer).is_empty());
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 32]), Ok(32));
    assert_eq!(p.local_readiness(fd), Ok((false, false)));
    assert!(ready(&mut p, outer).is_empty());
    p.close(&mut fs, fd).unwrap();
    let replacement = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    assert_eq!(replacement, fd);
    p.inotify_add_watch(&fs, replacement, "/key", ATTRIB)
        .unwrap();
    fs.set_mode(path("/key"), 0o600).unwrap();
    objects.observe_filesystem(&fs);
    assert!(ready(&mut p, outer).is_empty());
    p.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}

#[test]
fn duplicate_and_spawn_transfer_keep_one_instance_until_final_reference_release() {
    let mut fs = FileSystem::new();
    fs.write(path("/key"), b"value", false).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK | O_CLOEXEC).unwrap();
    let alias = p.dup(fd).unwrap();
    assert!(!p.close_on_exec(alias).unwrap());
    let identity = p.description_identity(fd).unwrap();
    let wd = p.inotify_add_watch(&fs, alias, "/key", ATTRIB).unwrap();
    let mut child = p
        .spawn_descriptors(
            &fs,
            None,
            &[Mapping {
                source: fd,
                target: 3,
            }],
            2,
        )
        .unwrap();
    p.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().inotify_instances, 1);
    fs.set_mode(path("/key"), 0o600).unwrap();
    assert_eq!(
        read(&mut child, &fs, 3),
        std::vec![event(wd, ATTRIB, 0, "")]
    );
    assert_eq!(child.description_identity(3), Ok(identity));
    child.close_all(&mut fs).unwrap();
    let empty = objects.snapshot();
    assert_eq!(empty.live, 0);
    assert_eq!(empty.inotify_instances, 0);
    assert_eq!(empty.inotify_watches, 0);
    assert_eq!(empty.inotify_events, 0);
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    assert_ne!(p.description_identity(fd), Ok(identity));
    assert_eq!(p.inotify_read(&fs, fd, &mut [0; 64]), Err(Errno::Again));
    p.close_all(&mut fs).unwrap();
}

#[test]
fn owner_quotas_and_the_shared_pool_fail_without_leaks_and_are_reusable() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let mut owners: [Process<'_>; GLOBAL_INSTANCES / INSTANCES] =
        core::array::from_fn(|i| Process::new(&objects, i as u32 + 1).unwrap());
    let mut first = 0;
    for (i, owner) in owners.iter_mut().enumerate() {
        for j in 0..INSTANCES {
            let fd = owner.inotify_init(&fs, O_NONBLOCK).unwrap();
            if i == 0 && j == 0 {
                first = fd;
            }
        }
        let before = objects.snapshot();
        assert_eq!(owner.inotify_init(&fs, O_NONBLOCK), Err(Errno::Mfile));
        assert_eq!(objects.snapshot(), before);
    }
    let mut extra = Process::new(&objects, 99).unwrap();
    let before = objects.snapshot();
    assert_eq!(extra.inotify_init(&fs, O_NONBLOCK), Err(Errno::Mfile));
    assert_eq!(objects.snapshot(), before);
    owners[0].close(&mut fs, first).unwrap();
    extra.inotify_init(&fs, O_NONBLOCK).unwrap();
    assert_eq!(objects.snapshot().inotify_instances, GLOBAL_INSTANCES);
    for owner in &mut owners {
        owner.close_all(&mut fs).unwrap();
    }
    extra.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
    assert_eq!(objects.snapshot().inotify_instances, 0);
}

#[test]
fn directory_unlink_keeps_isdir_on_attrib_but_not_delete_self() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/directory")).unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let parent = p.inotify_add_watch(&fs, fd, "/", DELETE).unwrap();
    let wd = p
        .inotify_add_watch(&fs, fd, "/directory", ALL_EVENTS)
        .unwrap();
    p.rmdir(&mut fs, "/directory").unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![
            event(parent, DELETE | ISDIR, 0, "directory"),
            event(wd, ATTRIB | ISDIR, 0, ""),
            event(wd, DELETE_SELF, 0, ""),
            event(wd, IGNORED, 0, "")
        ]
    );
    p.close_all(&mut fs).unwrap();
}

#[test]
fn rights_transfer_and_discard_own_inotify_until_the_final_reference() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let mut sender = Process::new(&objects, 1).unwrap();
    let fd = sender.inotify_init(&fs, O_NONBLOCK | O_CLOEXEC).unwrap();
    let wd = sender.inotify_add_watch(&fs, fd, "/", CREATE).unwrap();
    let ticket = sender.stage_rights(&[fd]).unwrap();
    sender.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().inotify_instances, 1);
    objects.commit_rights(ticket).unwrap();
    fs.write(path("/transfer"), b"", false).unwrap();
    let mut receiver = Process::new(&objects, 2).unwrap();
    let received = receiver.receive_rights(&mut fs, ticket, 1, true).unwrap();
    assert_eq!(received.count, 1);
    assert!(receiver.close_on_exec(received.fds[0]).unwrap());
    assert_eq!(
        read(&mut receiver, &fs, received.fds[0]),
        std::vec![event(wd, CREATE, 0, "transfer")]
    );
    let discarded = receiver.stage_rights(&[received.fds[0]]).unwrap();
    receiver.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().inotify_instances, 1);
    objects.discard_rights(&mut fs, discarded).unwrap();
    assert_eq!(objects.snapshot().live, 0);
    assert_eq!(objects.snapshot().inotify_instances, 0);
    assert_eq!(objects.snapshot().inotify_watches, 0);
    assert_eq!(objects.snapshot().inotify_events, 0);
}

#[test]
fn syscall_creation_sets_mode_without_publishing_a_chmod() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let wd = p.inotify_add_watch(&fs, fd, "/", ALL_EVENTS).unwrap();
    let file = p
        .open(&mut fs, "/file", crate::O_CREAT | crate::O_RDWR, 0o2640)
        .unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, CREATE, 0, "file"), event(wd, OPEN, 0, "file")]
    );
    assert_eq!(p.fstat(&fs, file).unwrap().mode & 0o7777, 0o2640);
    p.mkdir(&mut fs, "/folder", 0o1750).unwrap();
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, CREATE | ISDIR, 0, "folder")]
    );
    assert_eq!(fs.stat(path("/folder")).unwrap().mode, 0o1750);
    p.close_all(&mut fs).unwrap();
}

#[test]
fn syscall_directory_reads_publish_access_including_at_end() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let fd = p.inotify_init(&fs, O_NONBLOCK).unwrap();
    let wd = p.inotify_add_watch(&fs, fd, "/", ACCESS).unwrap();
    let dir = p.open(&mut fs, "/", crate::O_DIRECTORY, 0).unwrap();
    assert!(p.getdents(&mut fs, dir, &[], &mut [0; 256]).unwrap() > 0);
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, ACCESS | ISDIR, 0, "")]
    );
    assert_eq!(p.getdents(&mut fs, dir, &[], &mut [0; 256]), Ok(0));
    assert_eq!(
        read(&mut p, &fs, fd),
        std::vec![event(wd, ACCESS | ISDIR, 0, "")]
    );
    p.close_all(&mut fs).unwrap();
}
