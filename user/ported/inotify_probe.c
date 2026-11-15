/* Real musl Linux calls exercise inotify events, queues and OFD lifetime. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define ROOT "/inotify-probe"
#define PATH(name) ROOT "/" name

static int fail(const char *stage, int line) {
    printf("INOTIFY_PROBE FAIL %s line=%d errno=%d\n", stage, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)
#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, value) __atomic_store_n((p), (value), __ATOMIC_RELEASE)

struct captured {
    int wd;
    uint32_t mask, cookie;
    char name[96];
};
static struct captured events[128];
static unsigned event_count;

/* Decode actual returned records; no alignment cast, partial-record acceptance,
 * or dependence on one particular amount of filename padding. */
static int collect(int fd) {
    unsigned char bytes[1024];
    event_count = 0;
    for (unsigned reads = 0; reads < 64; ++reads) {
        ssize_t size = read(fd, bytes, sizeof bytes);
        if (size == -1 && errno == EAGAIN) return (int)event_count;
        if (size <= 0) return -1;
        size_t offset = 0;
        while (offset < (size_t)size) {
            struct inotify_event header;
            if ((size_t)size - offset < sizeof header) { errno = EPROTO; return -1; }
            memcpy(&header, bytes + offset, sizeof header);
            if (header.len > (size_t)size - offset - sizeof header || header.len % 4 ||
                event_count == sizeof events / sizeof events[0]) {
                errno = EPROTO; return -1;
            }
            struct captured *event = &events[event_count++];
            event->wd = header.wd; event->mask = header.mask; event->cookie = header.cookie;
            event->name[0] = 0;
            if (header.len) {
                const unsigned char *name = bytes + offset + sizeof header;
                const unsigned char *end = memchr(name, 0, header.len);
                if (!end || (size_t)(end - name) >= sizeof event->name) {
                    errno = EPROTO; return -1;
                }
                memcpy(event->name, name, (size_t)(end - name) + 1);
            }
            offset += sizeof header + header.len;
        }
    }
    errno = EOVERFLOW;
    return -1;
}
static const struct captured *find(int wd, uint32_t mask, const char *name) {
    for (unsigned i = 0; i < event_count; ++i)
        if (events[i].wd == wd && events[i].mask == mask && !strcmp(events[i].name, name))
            return &events[i];
    return NULL;
}
static int only(int fd, int wd, uint32_t mask, const char *name) {
    return collect(fd) == 1 && find(wd, mask, name) && events[0].cookie == 0;
}
static int quiet(int fd) { return collect(fd) == 0; }
static int instance(void) { return inotify_init1(IN_NONBLOCK | IN_CLOEXEC); }
static int create(const char *path) { return open(path, O_CREAT | O_EXCL | O_RDWR, 0600); }
static int written(int fd) {
    return lseek(fd, 0, SEEK_SET) == 0 && write(fd, "v", 1) == 1;
}
static int polled(int fd, short expected) {
    struct pollfd item = {.fd = fd, .events = POLLIN | POLLOUT};
    return poll(&item, 1, 0) == (expected != 0) && item.revents == expected;
}
static int epoll_ready(int ep, int expected) {
    struct epoll_event event;
    int count = epoll_wait(ep, &event, 1, 0);
    return expected ? count == 1 && event.events == EPOLLIN && event.data.u64 == 71 : count == 0;
}

static int flags_masks(void) {
    CHECK(inotify_init1(-1) == -1 && errno == EINVAL, "flags-invalid-init");
    int fd = instance(), file = create(PATH("masks"));
    CHECK(fd >= 0 && file >= 0, "flags-create");
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0 &&
          fcntl(fd, F_GETFD) == FD_CLOEXEC, "flags-persist");
    CHECK(inotify_add_watch(fd, PATH("absent"), IN_MODIFY) == -1 && errno == ENOENT,
          "flags-missing-path");
    CHECK(inotify_add_watch(fd, PATH("masks"), 0) == -1 && errno == EINVAL,
          "flags-empty-mask");
    CHECK(inotify_add_watch(fd, PATH("masks"), IN_MODIFY | IN_ONLYDIR) == -1 && errno == ENOTDIR,
          "flags-only-directory");
    int wd = inotify_add_watch(fd, PATH("masks"), IN_MODIFY | IN_DONT_FOLLOW);
    CHECK(wd >= 0 && fchmod(file, 0604) == 0 && quiet(fd), "mask-filter");
    CHECK(written(file) && written(file) && only(fd, wd, IN_MODIFY, ""),
          "mask-adjacent-event-coalescing");
    CHECK(inotify_add_watch(fd, PATH("masks"), IN_ATTRIB) == wd, "mask-replace");
    CHECK(written(file) && quiet(fd) && fchmod(file, 0600) == 0 &&
          only(fd, wd, IN_ATTRIB, ""), "mask-replacement-filter");
    CHECK(inotify_add_watch(fd, PATH("masks"), IN_MODIFY | IN_MASK_ADD) == wd,
          "mask-add");
    CHECK(written(file) && fchmod(file, 0604) == 0 && collect(fd) == 2 &&
          find(wd, IN_MODIFY, "") && find(wd, IN_ATTRIB, ""), "mask-union");
    CHECK(inotify_add_watch(fd, PATH("masks"), IN_ACCESS | IN_MASK_CREATE) == -1 &&
          errno == EEXIST, "mask-create-existing");
    CHECK(inotify_add_watch(fd, PATH("masks"), IN_MODIFY | IN_MASK_ADD | IN_MASK_CREATE) == -1 &&
          errno == EINVAL, "mask-exclusive-flags");
    CHECK(written(file) && only(fd, wd, IN_MODIFY, ""), "mask-failure-preserves-watch");
    CHECK(inotify_rm_watch(fd, wd) == 0 && only(fd, wd, IN_IGNORED, ""), "mask-remove");
    CHECK(inotify_rm_watch(fd, wd) == -1 && errno == EINVAL, "mask-remove-missing");
    CHECK(close(fd) == 0 && close(file) == 0 && unlink(PATH("masks")) == 0, "flags-close");
    puts("INOTIFY_PROBE FLAGS_MASKS PASS");
    return 0;
}

static int file_events(void) {
    int fd = instance();
    CHECK(fd >= 0, "events-create-instance");
    uint32_t mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_OPEN |
                    IN_ACCESS | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
    int directory = inotify_add_watch(fd, ROOT, mask | IN_ONLYDIR);
    CHECK(directory >= 0 && mkdir(PATH("directory"), 0700) == 0 && collect(fd) > 0 &&
          find(directory, IN_CREATE | IN_ISDIR, "directory"), "events-directory-name");
    int file = create(PATH("events"));
    CHECK(file >= 0 && collect(fd) > 0 && find(directory, IN_CREATE, "events") &&
          find(directory, IN_OPEN, "events"), "events-create-open");
    int wd = inotify_add_watch(fd, PATH("events"), IN_ALL_EVENTS);
    CHECK(wd >= 0 && written(file) && collect(fd) == 2 &&
          find(directory, IN_MODIFY, "events") && find(wd, IN_MODIFY, ""), "events-write");
    CHECK(fchmod(file, 0604) == 0 && collect(fd) == 2 &&
          find(directory, IN_ATTRIB, "events") && find(wd, IN_ATTRIB, ""), "events-attributes");
    char byte = 0;
    CHECK(lseek(file, 0, SEEK_SET) == 0 && read(file, &byte, 1) == 1 && byte == 'v' &&
          collect(fd) == 2 && find(directory, IN_ACCESS, "events") &&
          find(wd, IN_ACCESS, ""), "events-access");
    CHECK(close(file) == 0 && collect(fd) == 2 && find(directory, IN_CLOSE_WRITE, "events") &&
          find(wd, IN_CLOSE_WRITE, ""), "events-close-write");
    file = open(PATH("events"), O_RDONLY);
    CHECK(file >= 0 && collect(fd) == 2 && find(directory, IN_OPEN, "events") &&
          find(wd, IN_OPEN, ""), "events-open-read");
    CHECK(close(file) == 0 && collect(fd) == 2 && find(directory, IN_CLOSE_NOWRITE, "events") &&
          find(wd, IN_CLOSE_NOWRITE, ""), "events-close-read");
    CHECK(unlink(PATH("events")) == 0 && collect(fd) > 0 &&
          find(directory, IN_DELETE, "events") && find(wd, IN_DELETE_SELF, "") &&
          find(wd, IN_IGNORED, ""), "events-delete-self");
    CHECK(rmdir(PATH("directory")) == 0 && collect(fd) > 0 &&
          find(directory, IN_DELETE | IN_ISDIR, "directory"), "events-directory-delete");
    CHECK(close(fd) == 0, "events-close");
    puts("INOTIFY_PROBE FILE_EVENTS PASS");
    return 0;
}

static int rename_events(void) {
    CHECK(mkdir(PATH("from"), 0700) == 0 && mkdir(PATH("to"), 0700) == 0, "rename-directories");
    int source = create(PATH("from/source")), old = create(PATH("to/target")), fd = instance();
    struct stat before, after;
    CHECK(source >= 0 && old >= 0 && fd >= 0 && fstat(source, &before) == 0, "rename-files");
    int from = inotify_add_watch(fd, PATH("from"), IN_MOVE | IN_CREATE | IN_DELETE);
    int to = inotify_add_watch(fd, PATH("to"), IN_MOVE | IN_CREATE | IN_DELETE);
    int own = inotify_add_watch(fd, PATH("from/source"), IN_MOVE_SELF | IN_MODIFY | IN_DELETE_SELF);
    int replaced = inotify_add_watch(fd, PATH("to/target"), IN_ATTRIB | IN_DELETE_SELF);
    CHECK(from >= 0 && to >= 0 && own >= 0 && replaced >= 0, "rename-watch");
    CHECK(syscall(SYS_renameat2, AT_FDCWD, PATH("from/source"), AT_FDCWD, PATH("to/target"), 1) == -1 &&
          errno == EEXIST && quiet(fd), "rename-failure-no-events");
    CHECK(rename(PATH("from/source"), PATH("to/target")) == 0 && collect(fd) >= 3,
          "rename-replace");
    const struct captured *a = find(from, IN_MOVED_FROM, "source");
    const struct captured *b = find(to, IN_MOVED_TO, "target");
    CHECK(a && b && a->cookie != 0 && a->cookie == b->cookie &&
          find(own, IN_MOVE_SELF, ""), "rename-paired-cookie");
    CHECK(!find(replaced, IN_DELETE_SELF, "") && !find(replaced, IN_IGNORED, ""),
          "rename-old-open-inode-retained");
    CHECK(stat(PATH("to/target"), &after) == 0 && after.st_ino == before.st_ino &&
          fstat(old, &after) == 0 && after.st_nlink == 0, "rename-identity");
    CHECK(inotify_add_watch(fd, PATH("to/target"), IN_MOVE_SELF | IN_MODIFY | IN_DELETE_SELF) == own &&
          written(source) && only(fd, own, IN_MODIFY, ""), "rename-watch-follows-inode");
    CHECK(close(old) == 0 && collect(fd) > 0 && find(replaced, IN_DELETE_SELF, "") &&
          find(replaced, IN_IGNORED, ""), "rename-old-final-close");
    CHECK(close(source) == 0 && unlink(PATH("to/target")) == 0 && collect(fd) > 0 &&
          find(to, IN_DELETE, "target") && find(own, IN_DELETE_SELF, "") &&
          find(own, IN_IGNORED, ""), "rename-source-final-delete");
    CHECK(close(fd) == 0 && rmdir(PATH("from")) == 0 && rmdir(PATH("to")) == 0, "rename-close");
    puts("INOTIFY_PROBE RENAME PASS");
    return 0;
}

static int watch_lifetime(void) {
    int file = create(PATH("lifetime")), fd = instance();
    CHECK(file >= 0 && fd >= 0, "lifetime-create");
    int wd = inotify_add_watch(fd, PATH("lifetime"), IN_ATTRIB | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF);
    CHECK(wd >= 0 && unlink(PATH("lifetime")) == 0 && collect(fd) >= 1 &&
          find(wd, IN_ATTRIB, "") && !find(wd, IN_DELETE_SELF, "") && !find(wd, IN_IGNORED, ""),
          "lifetime-unlink-retains-open-inode");
    CHECK(written(file) && only(fd, wd, IN_MODIFY, ""), "lifetime-unlinked-write");
    CHECK(close(file) == 0 && collect(fd) >= 2 && find(wd, IN_DELETE_SELF, "") &&
          find(wd, IN_IGNORED, ""), "lifetime-last-close");
    file = create(PATH("lifetime"));
    CHECK(file >= 0 && written(file) && quiet(fd), "lifetime-recreated-not-watched");
    int once = inotify_add_watch(fd, PATH("lifetime"), IN_MODIFY | IN_ONESHOT);
    CHECK(once >= 0 && once != wd && written(file) && written(file) && collect(fd) == 2 &&
          find(once, IN_MODIFY, "") && find(once, IN_IGNORED, ""), "lifetime-oneshot");
    CHECK(written(file) && quiet(fd), "lifetime-oneshot-removed");
    int fresh = inotify_add_watch(fd, PATH("lifetime"), IN_MODIFY);
    CHECK(fresh >= 0 && fresh != once && inotify_rm_watch(fd, fresh) == 0 &&
          only(fd, fresh, IN_IGNORED, "") && written(file) && quiet(fd), "lifetime-explicit-remove");
    CHECK(close(fd) == 0 && close(file) == 0 && unlink(PATH("lifetime")) == 0, "lifetime-close");
    puts("INOTIFY_PROBE WATCH_LIFETIME PASS");
    return 0;
}

static int unlink_policy(void) {
    int file = create(PATH("orphan")), normal = instance(), excluded = instance();
    CHECK(file >= 0 && normal >= 0 && excluded >= 0, "unlink-policy-create");
    int wd = inotify_add_watch(normal, ROOT, IN_MODIFY | IN_CLOSE_WRITE);
    CHECK(wd >= 0 && inotify_add_watch(excluded, ROOT, IN_MODIFY | IN_CLOSE_WRITE | IN_EXCL_UNLINK) >= 0,
          "unlink-policy-watch");
    CHECK(unlink(PATH("orphan")) == 0 && quiet(normal) && quiet(excluded), "unlink-policy-unlink");
    CHECK(written(file) && only(normal, wd, IN_MODIFY, "orphan") && quiet(excluded),
          "unlink-policy-write");
    CHECK(close(file) == 0 && only(normal, wd, IN_CLOSE_WRITE, "orphan") && quiet(excluded),
          "unlink-policy-close-event");
    CHECK(close(normal) == 0 && close(excluded) == 0, "unlink-policy-close");
    puts("INOTIFY_PROBE UNLINK_POLICY PASS");
    return 0;
}

static int records_dup(void) {
    int fd = instance(), alias = dup(fd);
    CHECK(fd >= 0 && alias >= 0 && fcntl(alias, F_GETFD) == 0 &&
          (fcntl(alias, F_GETFL) & O_NONBLOCK) != 0, "records-dup-flags");
    int wd = inotify_add_watch(fd, ROOT, IN_CREATE);
    int file = create(PATH("record"));
    CHECK(wd >= 0 && file >= 0, "records-create");
    unsigned char short_buffer[16];
    CHECK(read(fd, short_buffer, 15) == -1 && errno == EINVAL &&
          read(fd, short_buffer, 16) == -1 && errno == EINVAL, "records-short-buffer");
    CHECK(only(alias, wd, IN_CREATE, "record") && quiet(fd), "records-dup-shared-queue");
    int own = inotify_add_watch(fd, PATH("record"), IN_MODIFY | IN_ATTRIB);
    CHECK(own >= 0 && written(file) && fchmod(file, 0604) == 0, "records-two-header-events");
    struct inotify_event header;
    CHECK(read(fd, &header, sizeof header) == sizeof header && header.wd == own &&
          header.mask == IN_MODIFY && header.len == 0 && header.cookie == 0,
          "records-exact-first-header");
    CHECK(read(alias, &header, sizeof header) == sizeof header && header.wd == own &&
          header.mask == IN_ATTRIB && header.len == 0 && quiet(fd), "records-exact-second-header");
    CHECK(close(fd) == 0 && written(file) && only(alias, own, IN_MODIFY, ""),
          "records-alias-keeps-instance");
    int replacement = instance();
    CHECK(replacement == fd && written(file) && quiet(replacement) &&
          only(alias, own, IN_MODIFY, ""), "records-number-reuse-independent");
    CHECK(close(alias) == 0, "records-last-old-reference");
    int reused = instance();
    CHECK(reused == alias && written(file) && quiet(reused) && quiet(replacement),
          "records-final-release-clears-watches");
    CHECK(close(reused) == 0 && close(replacement) == 0 && close(file) == 0 &&
          unlink(PATH("record")) == 0, "records-close");
    puts("INOTIFY_PROBE RECORDS_DUP PASS");
    return 0;
}

static int pending_bytes(int fd, int expected) {
    int bytes = -1;
    return ioctl(fd, FIONREAD, &bytes) == 0 && bytes == expected;
}
static int named_record(const unsigned char bytes[32], int wd, const char *name) {
    struct inotify_event event;
    memcpy(&event, bytes, sizeof event);
    size_t length = strlen(name) + 1;
    return event.wd == wd && event.mask == IN_CREATE && event.cookie == 0 &&
           event.len == 16 && length <= event.len &&
           !memcmp(bytes + sizeof event, name, length);
}
static int vectored_read(void) {
    int fd = instance();
    CHECK(fd >= 0, "vector-create");
    int wd = inotify_add_watch(fd, ROOT, IN_CREATE);
    int file = create(PATH("vector-a"));
    CHECK(wd >= 0 && file >= 0 && close(file) == 0, "vector-first-event");
    CHECK(pending_bytes(fd, 32) && pending_bytes(fd, 32), "vector-size-does-not-consume");
    unsigned char small[8], remainder[24];
    struct iovec split[] = {{.iov_base = small, .iov_len = sizeof small},
                           {.iov_base = remainder, .iov_len = sizeof remainder}};
    /* inotify uses the legacy .read operation: readv does not aggregate short
     * iovecs to make space for a record. The first 8-byte read must fail intact. */
    CHECK(readv(fd, split, 2) == -1 && errno == EINVAL && pending_bytes(fd, 32),
          "vector-split-record-rejected-intact");
    file = create(PATH("vector-b"));
    CHECK(file >= 0 && close(file) == 0 && pending_bytes(fd, 64), "vector-second-event");
    unsigned char first[32], second[32];
    struct iovec whole[] = {{.iov_base = first, .iov_len = sizeof first},
                           {.iov_base = second, .iov_len = sizeof second}};
    CHECK(readv(fd, whole, 2) == 64 && named_record(first, wd, "vector-a") &&
          named_record(second, wd, "vector-b") && pending_bytes(fd, 0) && quiet(fd),
          "vector-two-whole-records");
    file = create(PATH("vector-c"));
    CHECK(file >= 0 && close(file) == 0 && pending_bytes(fd, 32), "vector-single-event");
    memset(second, 0xa5, sizeof second);
    CHECK(readv(fd, whole, 2) == 32 && named_record(first, wd, "vector-c") &&
          pending_bytes(fd, 0) && quiet(fd), "vector-partial-success-before-eagain");
    for (unsigned i = 0; i < sizeof second; ++i)
        CHECK(second[i] == 0xa5, "vector-second-buffer-untouched");
    CHECK(close(fd) == 0 && unlink(PATH("vector-a")) == 0 &&
          unlink(PATH("vector-b")) == 0 && unlink(PATH("vector-c")) == 0,
          "vector-close");
    puts("INOTIFY_PROBE VECTORED_READ PASS");
    return 0;
}

static int readiness(void) {
    int file = create(PATH("ready")), fd = instance(), ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(file >= 0 && fd >= 0 && ep >= 0, "ready-create");
    int wd = inotify_add_watch(fd, PATH("ready"), IN_MODIFY | IN_ATTRIB);
    struct epoll_event registration = {.events = EPOLLIN | EPOLLET, .data.u64 = 71};
    CHECK(wd >= 0 && epoll_ctl(ep, EPOLL_CTL_ADD, fd, &registration) == 0 &&
          polled(fd, 0) && epoll_ready(ep, 0), "ready-add-empty");
    CHECK(written(file) && polled(fd, POLLIN) && epoll_ready(ep, 1) && epoll_ready(ep, 0),
          "ready-first-edge");
    CHECK(fchmod(file, 0604) == 0 && epoll_ready(ep, 1) && epoll_ready(ep, 0),
          "ready-new-event-while-readable");
    CHECK(collect(fd) == 2 && find(wd, IN_MODIFY, "") && find(wd, IN_ATTRIB, "") &&
          polled(fd, 0) && epoll_ready(ep, 0), "ready-drain");
    CHECK(written(file) && epoll_ready(ep, 1) && only(fd, wd, IN_MODIFY, ""),
          "ready-repeat-after-drain");
    CHECK(close(fd) == 0 && epoll_ready(ep, 0), "ready-last-close-clears-epoll");
    int fresh = instance();
    CHECK(fresh == fd, "ready-reused-number");
    wd = inotify_add_watch(fresh, PATH("ready"), IN_MODIFY);
    CHECK(wd >= 0 && written(file) && polled(fresh, POLLIN) && epoll_ready(ep, 0),
          "ready-reused-object-not-inherited");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fresh, &registration) == 0 && epoll_ready(ep, 1) &&
          only(fresh, wd, IN_MODIFY, ""), "ready-explicit-new-registration");
    CHECK(close(fresh) == 0 && close(ep) == 0 && close(file) == 0 && unlink(PATH("ready")) == 0,
          "ready-close");
    puts("INOTIFY_PROBE READINESS PASS");
    return 0;
}

static int overflow(void) {
    int file = create(PATH("overflow")), fd = instance();
    CHECK(file >= 0 && fd >= 0, "overflow-create");
    int wd = inotify_add_watch(fd, PATH("overflow"), IN_MODIFY | IN_ATTRIB);
    CHECK(wd >= 0, "overflow-watch");
    /* Alternating real event kinds cannot be coalesced into one adjacent event.
     * This exceeds CyxiaOS's declared bounded queue without consuming FS nodes. */
    for (unsigned i = 0; i < 300; ++i)
        CHECK(written(file) && fchmod(file, (i & 1) ? 0600 : 0604) == 0, "overflow-fill");
    CHECK(collect(fd) > 0, "overflow-read");
    unsigned overflows = 0;
    for (unsigned i = 0; i < event_count; ++i) {
        if (events[i].mask == IN_Q_OVERFLOW) {
            CHECK(events[i].wd == -1 && events[i].cookie == 0 && !events[i].name[0],
                  "overflow-record");
            ++overflows;
        } else {
            CHECK(events[i].wd == wd && !events[i].name[0] && events[i].cookie == 0 &&
                  (events[i].mask == IN_MODIFY || events[i].mask == IN_ATTRIB),
                  "overflow-intact-records");
        }
    }
    CHECK(overflows == 1 && quiet(fd), "overflow-explicit-once");
    CHECK(written(file) && only(fd, wd, IN_MODIFY, ""), "overflow-recover-after-drain");
    CHECK(close(fd) == 0 && close(file) == 0 && unlink(PATH("overflow")) == 0, "overflow-close");
    puts("INOTIFY_PROBE OVERFLOW PASS");
    return 0;
}

enum blocking_mode { BLOCKING_READ, INTERRUPT_READ, RETRY_REUSE };
struct read_worker {
    int fd, started, done, error;
    ssize_t result;
    unsigned char bytes[sizeof(struct inotify_event)];
};
static int signal_seen;
static int signal_tid;

static void *blocking_reader(void *raw) {
    struct read_worker *worker = raw;
    STORE(&signal_tid, (int)syscall(SYS_gettid));
    STORE(&worker->started, 1);
    worker->result = read(worker->fd, worker->bytes, sizeof worker->bytes);
    worker->error = errno;
    STORE(&worker->done, 1);
    return NULL;
}
static void interrupt_handler(int number) {
    if (number == SIGUSR1 && (pid_t)syscall(SYS_gettid) == (pid_t)LOAD(&signal_tid))
        STORE(&signal_seen, 1);
}
static int before_deadline(const struct timespec *start) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec - start->tv_sec < 20;
}
static int wait_flag(int *flag) {
    struct timespec start;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "blocking-clock");
    while (!LOAD(flag)) {
        CHECK(before_deadline(&start), "blocking-worker-timeout");
        sched_yield();
    }
    return 0;
}
static int wait_gate(const char *gate, struct read_worker *worker) {
    struct timespec start;
    struct stat info;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "blocking-gate-clock");
    /* The controller only creates this gate after observing increasing kernel
     * waits. These parent operations cannot themselves park a read syscall. */
    while (stat(gate, &info) != 0) {
        CHECK(errno == ENOENT && before_deadline(&start), "blocking-gate-timeout");
        CHECK(!LOAD(&worker->done), "read-returned-before-gate");
        sched_yield();
    }
    CHECK(!LOAD(&worker->done), "read-did-not-block");
    CHECK(unlink(gate) == 0, "blocking-remove-gate");
    return 0;
}
static int blocked_case(enum blocking_mode mode) {
    const char *stage = mode == BLOCKING_READ ? "BLOCKING_READ" :
                        mode == INTERRUPT_READ ? "INTERRUPT" : "RETRY_REUSE";
    char gate[96];
    int length = snprintf(gate, sizeof gate, "/run/user/0/inotify-%s", stage);
    CHECK(length > 0 && (size_t)length < sizeof gate &&
          (unlink(gate) == 0 || errno == ENOENT), "blocking-stale-gate");
    int file = create(PATH("blocking")), waiter = inotify_init1(IN_CLOEXEC);
    CHECK(file >= 0 && waiter >= 0 && !(fcntl(waiter, F_GETFL) & O_NONBLOCK),
          "blocking-create");
    int wd = inotify_add_watch(waiter, PATH("blocking"), IN_MODIFY);
    CHECK(wd >= 0 && polled(waiter, 0), "blocking-watch-empty");
    int alias = -1, replacement = -1, other_file = -1, other_wd = -1;
    if (mode == RETRY_REUSE) {
        alias = dup(waiter);
        other_file = create(PATH("replacement"));
        replacement = instance();
        CHECK(alias >= 0 && other_file >= 0 && replacement >= 0, "blocking-reuse-create");
        other_wd = inotify_add_watch(replacement, PATH("replacement"), IN_ATTRIB);
        CHECK(other_wd >= 0 && fchmod(other_file, 0604) == 0 && polled(replacement, POLLIN),
              "blocking-replacement-event-ready");
    }
    STORE(&signal_seen, 0);
    struct read_worker worker = {.fd = waiter};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, blocking_reader, &worker) == 0, "blocking-thread");
    CHECK(wait_flag(&worker.started) == 0, "blocking-worker-start");
    printf("INOTIFY_PROBE WAIT %s\n", stage);
    CHECK(wait_gate(gate, &worker) == 0, "blocking-host-gate");
    if (mode == BLOCKING_READ) {
        CHECK(written(file), "blocking-real-modification");
    } else if (mode == INTERRUPT_READ) {
        CHECK(pthread_kill(thread, SIGUSR1) == 0, "blocking-send-signal");
    } else {
        CHECK(close(waiter) == 0 && dup2(replacement, waiter) == waiter, "blocking-replace-fd");
    }
    CHECK(wait_flag(&worker.done) == 0 && pthread_join(thread, NULL) == 0, "blocking-join");
    if (mode == BLOCKING_READ) {
        struct inotify_event event;
        memcpy(&event, worker.bytes, sizeof event);
        CHECK(worker.result == sizeof event && event.wd == wd && event.mask == IN_MODIFY &&
              event.len == 0 && event.cookie == 0 && polled(waiter, 0), "blocking-read-real-event");
    } else if (mode == INTERRUPT_READ) {
        CHECK(worker.result == -1 && worker.error == EINTR && LOAD(&signal_seen),
              "blocking-read-interrupted");
        CHECK(fcntl(waiter, F_SETFL, O_NONBLOCK) == 0 && written(file) &&
              only(waiter, wd, IN_MODIFY, ""), "blocking-watch-survives-signal");
    } else {
        CHECK(worker.result == -1 && worker.error == EBADF, "blocking-retry-generation-rejected");
        CHECK(polled(alias, 0) && only(replacement, other_wd, IN_ATTRIB, ""),
              "blocking-replacement-queue-not-consumed");
        CHECK(close(alias) == 0 && close(replacement) == 0 && close(other_file) == 0 &&
              unlink(PATH("replacement")) == 0, "blocking-reuse-close");
    }
    CHECK(close(waiter) == 0 && close(file) == 0 && unlink(PATH("blocking")) == 0,
          "blocking-close");
    printf("INOTIFY_PROBE %s PASS\n", stage);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(mkdir(ROOT, 0700) == 0, "root-create");
    if (flags_masks() || file_events() || rename_events() || watch_lifetime() ||
        unlink_policy() || records_dup() || vectored_read() || readiness() || overflow()) return 1;
    struct sigaction action = {.sa_handler = interrupt_handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0, "blocking-signal-action");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0, "blocking-signal-unblock");
    for (enum blocking_mode mode = BLOCKING_READ; mode <= RETRY_REUSE; ++mode)
        CHECK(blocked_case(mode) == 0, "blocking-phase");
    CHECK(rmdir(ROOT) == 0, "root-remove");
    puts("INOTIFY_PROBE PASS");
    return 0;
}
