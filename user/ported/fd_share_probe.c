/* Real independent EL0 processes exercise shared open-file descriptions. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

struct mapping { int32_t source, target; };
struct spawn_request {
    uint32_t size, flags;
    const char *path;
    char *const *argv, *const *envp;
    const char *cwd;
    const struct mapping *mappings;
    uint32_t mapping_count, reserved;
    uint64_t reserved2;
};
_Static_assert(sizeof(struct spawn_request) == 64, "spawn ABI");
static int fail(const char *stage) {
    printf("FD_SHARE_PROBE FAIL %s pid=%d errno=%d\n", stage, getpid(), errno);
    return 1;
}
#define REQUIRE(c, s) do { if (!(c)) return fail(s); } while (0)
static pid_t spawn(const char *mode, struct mapping *maps, unsigned count) {
    char *args[] = {"/bin/fd-share-probe", (char *)mode, NULL};
    char *env[] = {NULL};
    struct spawn_request req = {64, 0, args[0], args, env, NULL, maps, count, 0, 0};
    return syscall(0x43595810, &req);
}
static socklen_t socket_address(struct sockaddr_un *address) {
    static const char name[] = "\0cyxia-ofd-share";
    memset(address, 0, sizeof *address);
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, name, sizeof name - 1);
    return offsetof(struct sockaddr_un, sun_path) + sizeof name - 1;
}
static int joined(pid_t pid) {
    int status = 0;
    pid_t result;
    do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
    return pid > 0 && result == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int exact(int fd, const char *expected, size_t size) {
    char bytes[32];
    size_t used = 0;
    if (size > sizeof bytes) return 0;
    while (used < size) {
        ssize_t n = read(fd, bytes + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        used += (size_t)n;
    }
    return !memcmp(bytes, expected, size);
}

struct blocked_io {
    int fd, writing, started, error;
    ssize_t result;
    size_t size;
    uint64_t value;
};
static void *blocked_worker(void *raw) {
    struct blocked_io *io = raw;
    __atomic_store_n(&io->started, 1, __ATOMIC_RELEASE);
    io->result = io->writing ? write(io->fd, &io->value, io->size)
                            : read(io->fd, &io->value, io->size);
    io->error = errno;
    return NULL;
}
static int endpoints(int kind, int pair[2]) {
    if (kind == 0) return pipe2(pair, O_NONBLOCK | O_CLOEXEC);
    if (kind == 1) {
        pair[0] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        pair[1] = pair[0];
        return pair[0] < 0 ? -1 : 0;
    }
    pair[0] = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    int unlocked = 0;
    if (pair[0] < 0 || ioctl(pair[0], TIOCSPTLCK, &unlocked)) return -1;
    pair[1] = ioctl(pair[0], TIOCGPTPEER, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    struct termios raw;
    if (pair[1] < 0 || tcgetattr(pair[1], &raw)) return -1;
    cfmakeraw(&raw);
    return tcsetattr(pair[1], TCSANOW, &raw);
}
static int close_endpoints(int pair[2]) {
    return close(pair[0]) || (pair[1] != pair[0] && close(pair[1]));
}
static int retry_reuse(int kind, int writing) {
    const char *names[] = {"PIPE", "EVENT", "PTY"};
    char stage[40], gate[60];
    snprintf(stage, sizeof stage, "RETRY_%s_%s", names[kind], writing ? "WRITE" : "READ");
    snprintf(gate, sizeof gate, "/ofd-%s", stage);
    int old[2], replacement[2];
    REQUIRE(endpoints(kind, old) == 0 && endpoints(kind, replacement) == 0, "retry-create");
    int index = kind == 0 ? writing : kind == 2 ? 1 : 0;
    int target = old[index], new_fd = replacement[index], alias = dup(target);
    REQUIRE(alias >= 0, "retry-alias");
    uint64_t value = writing ? UINT64_MAX - 1 : 7;
    char fill[4096]; memset(fill, 'F', sizeof fill);
    if (writing) {
        if (kind == 1) REQUIRE(write(target, &value, 8) == 8, "retry-fill-event");
        else {
            size_t used = 0;
            while (used < sizeof fill) {
                ssize_t n = write(target, fill + used, sizeof fill - used);
                REQUIRE(n > 0, "retry-fill");
                used += (size_t)n;
            }
        }
    } else {
        int writer = kind == 0 ? replacement[1] : replacement[0];
        REQUIRE(write(writer, kind == 1 ? (void *)&value : (void *)"R", kind == 1 ? 8 : 1)
                == (kind == 1 ? 8 : 1), "retry-ready-new");
    }
    REQUIRE(fcntl(target, F_SETFL, 0) == 0, "retry-blocking");
    struct blocked_io io = {.fd=target, .writing=writing, .size=kind == 1 ? 8 : 1, .value=1};
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, blocked_worker, &io) == 0, "retry-thread");
    while (!__atomic_load_n(&io.started, __ATOMIC_ACQUIRE)) sched_yield();
    printf("FD_SHARE_PROBE %s WAIT\n", stage);
    /* The host observer waits for two increasing kernel wait counters before
     * opening this gate. This thread performs no blocking call until then;
     * the worker is the only possible source of those waits. No timing-based
     * assumption is used to infer that the first I/O entered the kernel. */
    struct timespec start, now;
    struct stat st;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "retry-clock");
    while (stat(gate, &st) != 0) {
        REQUIRE(errno == ENOENT && clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
                now.tv_sec - start.tv_sec < 20, "retry-gate-timeout");
        sched_yield();
    }
    REQUIRE(unlink(gate) == 0 && close(target) == 0 && dup2(new_fd, target) == target, "retry-replace");
    REQUIRE(pthread_join(thread, NULL) == 0 && io.result == -1 && io.error == EBADF, "retry-cancel");
    value = 0;
    int reader = writing && kind != 1 ? replacement[0] : new_fd;
    ssize_t n = read(reader, &value, kind == 1 ? 8 : 1);
    if (writing) REQUIRE(n == -1 && errno == EAGAIN, "retry-no-write-new");
    else REQUIRE(n == (kind == 1 ? 8 : 1) && value == (kind == 1 ? 7 : 'R'), "retry-no-read-new");
    REQUIRE(close(alias) == 0 && close_endpoints(old) == 0 && close_endpoints(replacement) == 0,
            "retry-close");
    printf("FD_SHARE_PROBE %s PASS\n", stage);
    return 0;
}
static int child(const char *mode) {
    if (!strcmp(mode, "file")) {
        REQUIRE(fcntl(3, F_GETFD) == 0 && fcntl(4, F_GETFD) == 0, "mapped-cloexec");
        REQUIRE(exact(3, "AB", 2) && lseek(4, 0, SEEK_CUR) == 2, "shared-offset");
        REQUIRE(fcntl(3, F_SETFL, O_NONBLOCK) == 0, "shared-status-set");
        REQUIRE(fcntl(4, F_SETFD, FD_CLOEXEC) == 0 && fcntl(3, F_GETFD) == 0, "fd-local-flags");
        REQUIRE(exact(4, "CD", 2) && close(3) == 0 && exact(4, "EF", 2), "alias-close");
        return 0;
    }
    if (!strcmp(mode, "unlink")) {
        struct stat st;
        REQUIRE(exact(4, "g", 1), "unlink-ready");
        REQUIRE(fstat(3, &st) == 0 && st.st_nlink == 0 && exact(3, "keep", 4), "unlink-pin");
        return 0;
    }
    if (!strcmp(mode, "event")) {
        uint64_t value = 0;
        REQUIRE(read(3, &value, 8) == 8 && value == 5, "event-read");
        value = 9;
        REQUIRE(write(3, &value, 8) == 8 && fcntl(3, F_SETFL, 0) == 0, "event-write");
        return 0;
    }
    if (!strcmp(mode, "epoll")) {
        struct epoll_event event;
        uint64_t value;
        REQUIRE(epoll_wait(3, &event, 1, 0) == 1 && event.data.u64 == 0x1234, "epoll-shared-watch");
        REQUIRE(read(4, &value, 8) == 8 && value == 1, "epoll-shared-source");
        return 0;
    }
    if (!strcmp(mode, "socket")) {
        REQUIRE(exact(3, "ping", 4) && write(3, "pong", 4) == 4, "socket-inherit");
        return 0;
    }
    if (!strcmp(mode, "connect")) {
        struct sockaddr_un address;
        socklen_t size = socket_address(&address);
        REQUIRE(connect(3, (struct sockaddr *)&address, size) == 0, "inherited-connect");
        struct ucred peer;
        socklen_t length = sizeof peer;
        REQUIRE(getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 &&
                length == sizeof peer && peer.pid == getppid(), "listener-actor");
        REQUIRE(write(3, "ping", 4) == 4 && exact(3, "pong", 4), "connected-exchange");
        return 0;
    }
    if (!strcmp(mode, "orphan-parent")) {
        int fd = open("/ofd-orphan", O_CREAT | O_TRUNC | O_RDWR, 0600);
        REQUIRE(fd >= 0 && write(fd, "alive", 5) == 5 && lseek(fd, 0, SEEK_SET) == 0,
                "orphan-create");
        REQUIRE(unlink("/ofd-orphan") == 0, "orphan-unlink");
        struct mapping maps[] = {{-2,0},{1,1},{2,2},{fd,3},{4,4},{5,5}};
        REQUIRE(spawn("orphan-worker", maps, 6) > 0, "orphan-spawn");
        return 0; /* Creator exit must not destroy the descendant's OFD. */
    }
    if (!strcmp(mode, "orphan-worker")) {
        REQUIRE(exact(5, "g", 1) && getppid() == 0, "creator-exited");
        REQUIRE(exact(3, "alive", 5) && write(4, "alive", 5) == 5, "orphan-survives");
        return 0;
    }
    return fail("unknown-mode");
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) return child(argv[1]);
    int file = open("/ofd-file", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    REQUIRE(file >= 0 && write(file, "ABCDEFGH", 8) == 8 && lseek(file, 0, SEEK_SET) == 0, "file-create");
    struct mapping maps[] = {{-2,0},{1,1},{2,2},{file,3},{file,4}};
    REQUIRE(joined(spawn("file", maps, 5)), "file-child");
    REQUIRE(lseek(file, 0, SEEK_CUR) == 6 && exact(file, "GH", 2), "parent-offset");
    REQUIRE((fcntl(file, F_GETFL) & O_NONBLOCK) && fcntl(file, F_GETFD) == FD_CLOEXEC, "parent-flags");
    REQUIRE(close(file) == 0 && unlink("/ofd-file") == 0, "file-close");
    puts("FD_SHARE_PROBE FILE_DESCRIPTION PASS");

    int gate[2];
    REQUIRE(pipe2(gate, O_CLOEXEC) == 0, "unlink-pipe");
    file = open("/ofd-unlink", O_CREAT | O_TRUNC | O_RDWR, 0600);
    REQUIRE(file >= 0 && write(file, "keep", 4) == 4 && lseek(file, 0, SEEK_SET) == 0, "unlink-create");
    maps[3].source = file; maps[4].source = gate[0];
    pid_t pid = spawn("unlink", maps, 5);
    REQUIRE(pid > 0 && close(gate[0]) == 0 && unlink("/ofd-unlink") == 0 && close(file) == 0, "unlink-parent-close");
    REQUIRE(write(gate[1], "g", 1) == 1 && close(gate[1]) == 0 && joined(pid), "unlink-child");
    puts("FD_SHARE_PROBE UNLINK_LIFETIME PASS");

    int event = eventfd(5, EFD_NONBLOCK | EFD_CLOEXEC);
    maps[3].source = event;
    REQUIRE(event >= 0 && joined(spawn("event", maps, 4)), "event-child");
    uint64_t value = 0;
    REQUIRE(read(event, &value, 8) == 8 && value == 9 && !(fcntl(event, F_GETFL) & O_NONBLOCK), "event-shared-state");
    REQUIRE(close(event) == 0, "event-close");
    puts("FD_SHARE_PROBE EVENT_DESCRIPTION PASS");

    event = eventfd(1, EFD_NONBLOCK);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event watch = {.events=EPOLLIN | EPOLLONESHOT, .data.u64=0x1234};
    REQUIRE(event >= 0 && ep >= 0 && epoll_ctl(ep, EPOLL_CTL_ADD, event, &watch) == 0, "epoll-create");
    maps[3].source = ep; maps[4].source = event;
    REQUIRE(joined(spawn("epoll", maps, 5)), "epoll-child");
    value = 2;
    REQUIRE(write(event, &value, 8) == 8 && epoll_wait(ep, &watch, 1, 0) == 0, "oneshot-shared-state");
    REQUIRE(close(ep) == 0 && close(event) == 0, "epoll-close");
    puts("FD_SHARE_PROBE EPOLL_DESCRIPTION PASS");

    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "socket-pair");
    maps[3].source = pair[1];
    pid = spawn("socket", maps, 4);
    REQUIRE(pid > 0 && close(pair[1]) == 0 && write(pair[0], "ping", 4) == 4, "socket-parent");
    REQUIRE(exact(pair[0], "pong", 4) && joined(pid) && read(pair[0], &value, 1) == 0 && close(pair[0]) == 0, "socket-lifetime");
    puts("FD_SHARE_PROBE SOCKET_DESCRIPTION PASS");

    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int connector = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address;
    socklen_t size = socket_address(&address);
    REQUIRE(listener >= 0 && connector >= 0 && bind(listener, (struct sockaddr *)&address, size) == 0 &&
            listen(listener, 1) == 0, "listener-create");
    maps[3].source = connector;
    pid = spawn("connect", maps, 4);
    REQUIRE(pid > 0 && close(connector) == 0, "connect-child");
    int accepted = accept(listener, NULL, NULL);
    struct ucred peer;
    socklen_t peer_size = sizeof peer;
    REQUIRE(accepted >= 0 && getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
            peer_size == sizeof peer && peer.pid == pid, "connecting-actor");
    REQUIRE(exact(accepted, "ping", 4) && write(accepted, "pong", 4) == 4 && joined(pid), "connect-roundtrip");
    REQUIRE(close(accepted) == 0 && close(listener) == 0, "connection-close");
    puts("FD_SHARE_PROBE PEER_CREDENTIALS PASS");

    int output[2];
    REQUIRE(pipe2(output, O_CLOEXEC) == 0 && pipe2(gate, O_CLOEXEC) == 0, "orphan-pipes");
    struct mapping orphan[] = {{-2,0},{1,1},{2,2},{output[1],4},{gate[0],5}};
    pid = spawn("orphan-parent", orphan, 5);
    REQUIRE(pid > 0 && close(output[1]) == 0 && close(gate[0]) == 0 && joined(pid), "creator-join");
    REQUIRE(write(gate[1], "g", 1) == 1 && close(gate[1]) == 0, "orphan-release");
    REQUIRE(exact(output[0], "alive", 5) && read(output[0], &value, 1) == 0 && close(output[0]) == 0, "orphan-result");
    puts("FD_SHARE_PROBE CREATOR_EXIT PASS");

    for (unsigned i = 0; i < 20; ++i) {
        file = open("/ofd-reuse", O_CREAT | O_TRUNC | O_RDWR, 0600);
        REQUIRE(file >= 0, "reuse-open");
        struct mapping bad[] = {{file,3},{-1,3}};
        errno = 0;
        REQUIRE(spawn("file", bad, 2) == -1 && errno == EINVAL, "failed-map");
        REQUIRE(write(file, "x", 1) == 1 && close(file) == 0 && unlink("/ofd-reuse") == 0, "reuse-close");
    }
    puts("FD_SHARE_PROBE ATOMIC_REUSE PASS");
    for (int kind = 0; kind < 3; ++kind)
        for (int writing = 0; writing < 2; ++writing)
            REQUIRE(retry_reuse(kind, writing) == 0, "retry-reuse");
    puts("FD_SHARE_PROBE PASS");
    return 0;
}
