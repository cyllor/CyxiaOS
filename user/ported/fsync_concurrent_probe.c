/* Real fsync contention against a host-throttled VirtIO data disk.
 * The capture must observe the first STORAGE_CHECKPOINT_BEGIN before opening
 * the first gate, and increasing busy-retry waits before the second gate.
 * A finished holder before either gate is a failure, never a concurrency pass. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
static int signal_seen;
static pid_t signal_tid;
static const char first_data[] = "first-snapshot-before-late-write\n";
static const char late_data[] = "late-write-requires-fresh-snapshot\n";
static const char replacement_data[] = "replacement-descriptor-unchanged\n";

static void fail(const char *stage, int line) {
    printf("FSYNC_CONCURRENT_PROBE FAIL stage=%s line=%d errno=%d\n",
           stage, line, errno);
    exit(1);
}
#define CHECK(c, s) do { if (!(c)) fail(s, __LINE__); } while (0)

static long seconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock");
    return now.tv_sec;
}
static void wait_flag(int *flag) {
    long deadline = seconds() + 60;
    while (!LOAD(flag)) {
        CHECK(seconds() < deadline, "worker-timeout");
        sched_yield();
    }
}
static void paths(const char *mode, const char *suffix, char *out, size_t size) {
    int count = snprintf(out, size, "/tmp/fsync-concurrent-%s-%s", mode, suffix);
    CHECK(count > 0 && (size_t)count < size, "path-size");
}
static void remove_old(const char *path) {
    CHECK(unlink(path) == 0 || errno == ENOENT, "remove-old");
}
static int create_file(const char *path, const char *data) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "create-file");
    if (data)
        CHECK(write(fd, data, strlen(data)) == (ssize_t)strlen(data), "write-file");
    return fd;
}
static void read_file(const char *path, const char *expected) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    char bytes[128];
    size_t count = strlen(expected), used = 0;
    CHECK(fd >= 0 && count < sizeof(bytes), "verify-open");
    while (used < count) {
        ssize_t got = read(fd, bytes + used, count - used);
        CHECK(got > 0, "verify-read");
        used += (size_t)got;
    }
    CHECK(memcmp(bytes, expected, count) == 0 && read(fd, bytes, 1) == 0,
          "verify-content");
    CHECK(close(fd) == 0, "verify-close");
}

struct worker {
    int fd, started, done, result, error;
    pid_t tid;
};
static void *sync_worker(void *raw) {
    struct worker *worker = raw;
    worker->tid = (pid_t)syscall(SYS_gettid);
    STORE(&worker->started, 1);
    errno = 0;
    worker->result = fsync(worker->fd);
    worker->error = errno;
    STORE(&worker->done, 1);
    return NULL;
}
static void caught_signal(int number) {
    if (number == SIGUSR1 && (pid_t)syscall(SYS_gettid) == LOAD(&signal_tid))
        STORE(&signal_seen, 1);
}
static void wait_gate(const char *path, struct worker *holder,
                      struct worker *waiter) {
    long deadline = seconds() + 60;
    struct stat info;
    while (stat(path, &info) != 0) {
        CHECK(errno == ENOENT && seconds() < deadline, "gate-timeout");
        CHECK(!LOAD(&holder->done) && (!waiter || !LOAD(&waiter->done)),
              "sync-finished-before-host-gate");
        sched_yield();
    }
    CHECK(!LOAD(&holder->done) && (!waiter || !LOAD(&waiter->done)),
          "sync-was-not-blocked");
    CHECK(unlink(path) == 0, "remove-gate");
}

static void wait_release_gate(const char *path) {
    long deadline = seconds() + 60;
    struct stat info;
    while (stat(path, &info) != 0) {
        CHECK(errno == ENOENT && seconds() < deadline, "release-gate-timeout");
        sched_yield();
    }
    CHECK(unlink(path) == 0, "remove-release-gate");
}

static void verify(const char *mode) {
    char path[96];
    paths(mode, "first", path, sizeof(path));
    read_file(path, first_data);
    paths(mode, "late", path, sizeof(path));
    read_file(path, late_data);
    if (!strcmp(mode, "reuse")) {
        paths(mode, "replacement", path, sizeof(path));
        read_file(path, replacement_data);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode = argc == 1 ? "concurrent" : argv[1];
    CHECK(argc <= 2, "arguments");
    if (!strcmp(mode, "verify")) {
        for (unsigned i = 0; i < 4; ++i)
            verify((const char *[]){"concurrent", "interrupt", "reuse",
                                    "admitted-interrupt"}[i]);
        puts("FSYNC_CONCURRENT_PROBE RECOVERED PASS");
        return 0;
    }
    CHECK(!strcmp(mode, "concurrent") || !strcmp(mode, "interrupt") ||
          !strcmp(mode, "reuse") || !strcmp(mode, "admitted-interrupt"), "mode");
    struct sigaction action = {.sa_handler = caught_signal};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0, "signal-handler");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0, "signal-unblock");

    char first[96], late[96], replacement[96], first_gate[96], second_gate[96];
    paths(mode, "first", first, sizeof(first));
    paths(mode, "late", late, sizeof(late));
    paths(mode, "replacement", replacement, sizeof(replacement));
    paths(mode, "first-go", first_gate, sizeof(first_gate));
    paths(mode, "second-go", second_gate, sizeof(second_gate));
    remove_old(first_gate);
    remove_old(second_gate);
    int first_fd = create_file(first, first_data);
    int late_fd = create_file(late, NULL);
    int alias = -1, replacement_fd = -1;
    if (!strcmp(mode, "reuse")) {
        alias = dup(late_fd);
        replacement_fd = create_file(replacement, replacement_data);
        CHECK(alias >= 0, "original-description-alias");
    }
    struct worker holder = {.fd = first_fd}, waiter = {.fd = late_fd};
    pthread_t first_thread, second_thread;
    CHECK(pthread_create(&first_thread, NULL, sync_worker, &holder) == 0,
          "first-thread");
    wait_flag(&holder.started);
    printf("FSYNC_CONCURRENT_PROBE WAIT FIRST mode=%s gate=%s\n", mode, first_gate);
    wait_gate(first_gate, &holder, NULL);
    /* Host opened the gate only after observing the older staged snapshot. */
    CHECK(write(late_fd, late_data, sizeof(late_data) - 1) == sizeof(late_data) - 1,
          "write-after-first-snapshot");
    printf("FSYNC_CONCURRENT_PROBE LATE_WRITE mode=%s\n", mode);
    if (!strcmp(mode, "admitted-interrupt")) {
        STORE(&signal_tid, holder.tid);
        CHECK(pthread_kill(first_thread, SIGUSR1) == 0, "signal-admitted-fsync");
        wait_flag(&holder.done);
        CHECK(holder.result == -1 && holder.error == EINTR && LOAD(&signal_seen),
              "admitted-fsync-eintr");
        CHECK(pthread_join(first_thread, NULL) == 0, "join-interrupted-holder");
        puts("FSYNC_CONCURRENT_PROBE ADMITTED_INTERRUPTED PASS");
        printf("FSYNC_CONCURRENT_PROBE READY RELEASE mode=%s gate=%s\n",
               mode, second_gate);
        /* Host observes that the admitted generation is still physically
         * pending, removes the device throttle, and only then opens this gate.
         * The subsequent fsync must capture the later write in a new snapshot. */
        wait_release_gate(second_gate);
        CHECK(fsync(late_fd) == 0, "fresh-sync-after-admitted-interrupt");
        puts("FSYNC_CONCURRENT_PROBE SAVE_AFTER_CANCEL PASS");
        CHECK(close(first_fd) == 0 && close(late_fd) == 0, "close-admitted-files");
        verify(mode);
        printf("FSYNC_CONCURRENT_PROBE PASS mode=%s\n", mode);
        return 0;
    }
    CHECK(pthread_create(&second_thread, NULL, sync_worker, &waiter) == 0,
          "second-thread");
    wait_flag(&waiter.started);
    STORE(&signal_tid, waiter.tid);
    printf("FSYNC_CONCURRENT_PROBE WAIT SECOND mode=%s gate=%s\n", mode, second_gate);
    wait_gate(second_gate, &holder, &waiter);
    if (!strcmp(mode, "interrupt")) {
        CHECK(pthread_kill(second_thread, SIGUSR1) == 0, "signal-busy-fsync");
        wait_flag(&waiter.done);
        CHECK(waiter.result == -1 && waiter.error == EINTR && LOAD(&signal_seen),
              "busy-fsync-eintr");
        puts("FSYNC_CONCURRENT_PROBE INTERRUPTED PASS");
    } else if (!strcmp(mode, "reuse")) {
        CHECK(close(late_fd) == 0 && dup2(replacement_fd, late_fd) == late_fd,
              "replace-busy-descriptor");
        wait_flag(&waiter.done);
        CHECK(waiter.result == -1 && waiter.error == EBADF,
              "stale-description-rejected");
        read_file(replacement, replacement_data);
        puts("FSYNC_CONCURRENT_PROBE STALE_DESCRIPTOR PASS");
    }
    CHECK(!LOAD(&holder.done), "holder-still-pending-before-release");
    printf("FSYNC_CONCURRENT_PROBE READY RELEASE mode=%s\n", mode);
    wait_flag(&holder.done);
    wait_flag(&waiter.done);
    CHECK(pthread_join(first_thread, NULL) == 0 &&
          pthread_join(second_thread, NULL) == 0, "join-workers");
    CHECK(holder.result == 0, "first-durable-completion");
    if (!strcmp(mode, "concurrent")) {
        CHECK(waiter.result == 0, "second-fresh-durable-completion");
        puts("FSYNC_CONCURRENT_PROBE BOTH_DURABLE PASS");
    } else {
        /* Cancelling a caller must not cancel the already admitted snapshot
         * or prevent a later independent save from committing its own write. */
        CHECK(fsync(alias >= 0 ? alias : late_fd) == 0, "sync-after-cancel");
        puts("FSYNC_CONCURRENT_PROBE SAVE_AFTER_CANCEL PASS");
    }
    CHECK(close(first_fd) == 0 && close(late_fd) == 0, "close-files");
    if (alias >= 0)
        CHECK(close(alias) == 0 && close(replacement_fd) == 0, "close-reuse-files");
    verify(mode);
    printf("FSYNC_CONCURRENT_PROBE PASS mode=%s\n", mode);
    return 0;
}
