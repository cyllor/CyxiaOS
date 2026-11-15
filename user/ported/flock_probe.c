/* Real Linux musl syscalls exercise advisory open-file-description locks.
 * The native capture opens each WAIT gate only after observing an increasing
 * kernel wait counter. Before that gate the leader only stats and yields, so
 * the flock worker is the only possible source of newly parked syscalls. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char directory[] = "/run/user/0";
static const char path[] = "/run/user/0/flock-probe.lock";
static const char other_path[] = "/run/user/0/flock-probe.other";
static const char renamed_path[] = "/run/user/0/flock-probe.renamed";
static int signal_seen;
static pid_t signal_tid;

static int fail(const char *stage, int line) {
    printf("FLOCK_PROBE FAIL %s line=%d errno=%d\n", stage, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)
#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

static int lock_file(int fd, int operation) {
    return (int)syscall(SYS_flock, fd, operation);
}
static int lock_error(int fd, int operation, int expected) {
    errno = 0;
    return lock_file(fd, operation) == -1 && errno == expected;
}
static int remove_if_present(const char *name) {
    return unlink(name) == 0 || errno == ENOENT;
}

static int independent_and_dup(void) {
    int first = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int second = open(path, O_RDWR);
    CHECK(first >= 0 && second >= 0, "independent-open");
    CHECK(lock_file(first, LOCK_EX | LOCK_NB) == 0, "exclusive-acquire");
    CHECK(lock_error(second, LOCK_EX | LOCK_NB, EWOULDBLOCK), "independent-conflict");
    int alias = dup(first);
    CHECK(alias >= 0 && lock_file(alias, LOCK_EX | LOCK_NB) == 0, "dup-same-owner");
    CHECK(close(first) == 0, "dup-close-original");
    CHECK(lock_error(second, LOCK_EX | LOCK_NB, EWOULDBLOCK), "dup-retains-lock");
    CHECK(close(alias) == 0 && lock_file(second, LOCK_EX | LOCK_NB) == 0,
          "last-close-releases");
    CHECK(lock_file(second, LOCK_UN) == 0 && lock_file(second, LOCK_UN) == 0,
          "explicit-unlock");
    first = open(path, O_RDWR);
    CHECK(first >= 0 && lock_file(first, LOCK_EX | LOCK_NB) == 0, "unlock-reacquire");
    CHECK(lock_error(second, LOCK_EX | LOCK_NB, EWOULDBLOCK), "reacquire-conflict");
    CHECK(close(first) == 0 && close(second) == 0, "independent-close");
    puts("FLOCK_PROBE INDEPENDENT_DUP_RELEASE PASS");
    return 0;
}

static int shared_and_conversion(void) {
    int first = open(path, O_RDWR), second = open(path, O_RDWR), third = open(path, O_RDWR);
    CHECK(first >= 0 && second >= 0 && third >= 0, "shared-open");
    CHECK(lock_file(first, LOCK_SH | LOCK_NB) == 0 &&
          lock_file(second, LOCK_SH | LOCK_NB) == 0, "shared-coexist");
    CHECK(lock_error(third, LOCK_EX | LOCK_NB, EWOULDBLOCK), "shared-excludes-exclusive");
    CHECK(lock_file(third, LOCK_SH | LOCK_NB) == 0, "third-shared");
    CHECK(lock_error(first, LOCK_EX | LOCK_NB, EWOULDBLOCK), "conversion-conflict");
    /* A failed conversion need not preserve the old shared lock. */
    CHECK(lock_file(first, LOCK_SH | LOCK_NB) == 0 && lock_file(second, LOCK_UN) == 0 &&
          lock_file(third, LOCK_UN) == 0, "conversion-prepare");
    CHECK(lock_file(first, LOCK_EX | LOCK_NB) == 0, "shared-to-exclusive");
    CHECK(lock_error(second, LOCK_SH | LOCK_NB, EWOULDBLOCK), "converted-exclusive-conflict");
    CHECK(lock_file(first, LOCK_SH | LOCK_NB) == 0 &&
          lock_file(second, LOCK_SH | LOCK_NB) == 0, "exclusive-to-shared");
    CHECK(close(first) == 0 && close(second) == 0 && close(third) == 0, "shared-close");
    puts("FLOCK_PROBE SHARED_CONVERSION PASS");
    return 0;
}

static int invalid_inputs(void) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0, "invalid-open");
    const int invalid[] = {0, LOCK_NB, LOCK_SH | LOCK_EX, LOCK_EX | LOCK_UN,
                           LOCK_EX | 0x10, -1};
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; ++i)
        CHECK(lock_error(fd, invalid[i], EINVAL), "invalid-operation");
    CHECK(lock_error(-1, LOCK_EX | LOCK_NB, EBADF), "negative-descriptor");
    CHECK(close(fd) == 0 && lock_error(fd, LOCK_EX | LOCK_NB, EBADF), "closed-descriptor");
    puts("FLOCK_PROBE INVALID_INPUT PASS");
    return 0;
}

static int inode_identity(void) {
    int old = open(path, O_RDWR);
    struct stat old_info, fresh_info;
    CHECK(old >= 0 && lock_file(old, LOCK_EX | LOCK_NB) == 0, "inode-old-lock");
    CHECK(rename(path, renamed_path) == 0, "inode-rename");
    int renamed = open(renamed_path, O_RDWR);
    CHECK(renamed >= 0 && lock_error(renamed, LOCK_EX | LOCK_NB, EWOULDBLOCK),
          "renamed-same-inode");
    CHECK(unlink(renamed_path) == 0 && fstat(old, &old_info) == 0 && old_info.st_nlink == 0,
          "unlinked-pinned-inode");
    int fresh = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fresh >= 0 && fstat(fresh, &fresh_info) == 0 && fresh_info.st_ino != old_info.st_ino,
          "recreated-new-inode");
    CHECK(lock_file(fresh, LOCK_EX | LOCK_NB) == 0, "recreated-independent-lock");
    CHECK(lock_error(renamed, LOCK_EX | LOCK_NB, EWOULDBLOCK), "old-lock-retained");
    CHECK(close(old) == 0 && lock_file(renamed, LOCK_EX | LOCK_NB) == 0,
          "old-final-owner-release");
    int observer = open(path, O_RDWR);
    CHECK(observer >= 0 && lock_error(observer, LOCK_EX | LOCK_NB, EWOULDBLOCK),
          "new-lock-retained");
    CHECK(close(renamed) == 0 && close(fresh) == 0 && close(observer) == 0, "inode-close");
    puts("FLOCK_PROBE INODE_IDENTITY PASS");
    return 0;
}

struct worker {
    int fd, started, done, result, error;
};
static void *lock_worker(void *raw) {
    struct worker *worker = raw;
    signal_tid = (pid_t)syscall(SYS_gettid);
    STORE(&worker->started, 1);
    worker->result = lock_file(worker->fd, LOCK_EX);
    worker->error = errno;
    STORE(&worker->done, 1);
    return NULL;
}
static void interrupt_handler(int number) {
    if (number == SIGUSR1 && (pid_t)syscall(SYS_gettid) == signal_tid)
        STORE(&signal_seen, 1);
}
static int before_deadline(const struct timespec *start) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec - start->tv_sec < 20;
}
static int wait_flag(int *flag) {
    struct timespec start;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "worker-clock");
    while (!LOAD(flag)) {
        CHECK(before_deadline(&start), "worker-timeout");
        sched_yield();
    }
    return 0;
}
static int wait_gate(const char *gate, struct worker *worker) {
    struct timespec start;
    struct stat info;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "gate-clock");
    while (stat(gate, &info) != 0) {
        CHECK(errno == ENOENT && before_deadline(&start), "gate-timeout");
        CHECK(!LOAD(&worker->done), "lock-returned-before-gate");
        sched_yield();
    }
    CHECK(!LOAD(&worker->done), "lock-did-not-block");
    CHECK(unlink(gate) == 0, "gate-remove");
    return 0;
}

static int blocked_case(int mode) {
    const char *stages[] = {"BLOCKING_UNLOCK", "INTERRUPT", "RETRY_REUSE"};
    const char *stage = stages[mode];
    char gate[96];
    snprintf(gate, sizeof gate, "%s/flock-%s", directory, stage);
    CHECK(remove_if_present(gate), "stale-gate");
    int holder = open(path, O_RDWR), waiter = open(path, O_RDWR | O_NONBLOCK);
    CHECK(holder >= 0 && waiter >= 0 && (fcntl(waiter, F_GETFL) & O_NONBLOCK), "blocking-open");
    CHECK(lock_file(holder, LOCK_EX | LOCK_NB) == 0, "blocking-holder");
    int alias = -1, replacement = -1, observer = -1;
    if (mode == 2) {
        alias = dup(waiter);
        replacement = open(other_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        observer = open(other_path, O_RDWR);
        CHECK(alias >= 0 && replacement >= 0 && observer >= 0, "reuse-prepare");
    }
    struct worker worker = {.fd = waiter};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, lock_worker, &worker) == 0, "blocking-thread");
    CHECK(wait_flag(&worker.started) == 0, "blocking-start");
    printf("FLOCK_PROBE WAIT %s\n", stage);
    CHECK(wait_gate(gate, &worker) == 0, "blocking-gate");
    if (mode == 0) {
        CHECK(lock_file(holder, LOCK_UN) == 0, "blocking-unlock");
    } else if (mode == 1) {
        CHECK(pthread_kill(thread, SIGUSR1) == 0, "blocking-signal");
    } else {
        CHECK(close(waiter) == 0 && dup2(replacement, waiter) == waiter, "blocking-replace");
    }
    CHECK(wait_flag(&worker.done) == 0 && pthread_join(thread, NULL) == 0, "blocking-join");
    if (mode == 0) {
        CHECK(worker.result == 0, "blocking-acquired");
        CHECK(lock_error(holder, LOCK_EX | LOCK_NB, EWOULDBLOCK), "worker-owns-lock");
        CHECK(lock_file(waiter, LOCK_UN) == 0, "worker-unlock");
    } else if (mode == 1) {
        CHECK(worker.result == -1 && worker.error == EINTR && LOAD(&signal_seen), "blocking-interrupted");
        CHECK(lock_error(waiter, LOCK_EX | LOCK_NB, EWOULDBLOCK), "signal-preserved-owner");
    } else {
        CHECK(worker.result == -1 && worker.error == EBADF, "retry-generation-rejected");
        CHECK(lock_file(observer, LOCK_EX | LOCK_NB) == 0, "retry-did-not-lock-replacement");
        CHECK(lock_error(alias, LOCK_EX | LOCK_NB, EWOULDBLOCK), "retry-preserved-original");
        CHECK(close(alias) == 0 && close(replacement) == 0 && close(observer) == 0,
              "retry-close");
        CHECK(unlink(other_path) == 0, "retry-remove");
    }
    CHECK(close(waiter) == 0 && close(holder) == 0, "blocking-close");
    printf("FLOCK_PROBE %s PASS\n", stage);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    struct stat info;
    CHECK(runtime && !strcmp(runtime, directory), "runtime-environment");
    CHECK(stat(runtime, &info) == 0 && S_ISDIR(info.st_mode) &&
          (info.st_mode & 0777) == 0700 && info.st_uid == getuid(), "runtime-directory");
    CHECK(remove_if_present(path) && remove_if_present(other_path) &&
          remove_if_present(renamed_path), "stale-files");
    puts("FLOCK_PROBE RUNTIME_DIRECTORY PASS");
    CHECK(independent_and_dup() == 0, "independent-phase");
    CHECK(shared_and_conversion() == 0, "shared-phase");
    CHECK(invalid_inputs() == 0, "invalid-phase");
    CHECK(inode_identity() == 0, "inode-phase");
    struct sigaction action = {.sa_handler = interrupt_handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0, "signal-action");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0, "signal-unblock");
    for (int mode = 0; mode < 3; ++mode)
        CHECK(blocked_case(mode) == 0, "blocking-phase");
    CHECK(unlink(path) == 0, "final-remove");
    puts("FLOCK_PROBE PASS");
    return 0;
}
