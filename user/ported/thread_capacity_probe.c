/* Real full-OS pthread capacity, private TLS/stacks, rejection and slot reuse.
 * All fifteen workers stay alive at the rejection boundary. Their futex gate
 * is opened only after the seventeenth simultaneous thread is refused.
 * A final child-wait phase parks fifteen workers in waitpid. The host must
 * observe the parent Waiting with sixteen live threads before releasing the
 * actual child through /thread-wait-go; creation order is not a slot identity. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cyxia_spawn.h"

enum { WORKERS = 15, STACK_BYTES = 64 * 1024, STACK_WORDS = 256 };
#define INITIAL_TLS UINT64_C(0x3104bafd28ce6507)
#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
static _Thread_local uint64_t tls_value = INITIAL_TLS;
static unsigned ready, release_workers, worker_error;
static pid_t main_tid;
static unsigned cycle;
static pid_t wait_child;
static unsigned wait_started, wait_done, wait_reaped, wait_nochild;
#define CHILD_GATE "/thread-wait-go"
#define CHILD_EXIT 37

struct worker {
    unsigned index;
    pid_t tid;
    uintptr_t stack_address, tls_address;
};
static struct worker workers[WORKERS + 1];
static pthread_t threads[WORKERS + 1];
static unsigned created;

static uint64_t tag(unsigned index, unsigned word) {
    return UINT64_C(0xd47a220000000000) | ((uint64_t)cycle << 24) |
           ((uint64_t)index << 16) | word;
}

static void *worker_main(void *raw) {
    struct worker *worker = raw;
    volatile uint64_t stack[STACK_WORDS];
    if (tls_value != INITIAL_TLS || getpid() != main_tid)
        STORE(&worker_error, 1);
    worker->tid = (pid_t)syscall(SYS_gettid);
    if (worker->tid == main_tid || worker->tid <= 0 ||
        ((unsigned)worker->tid & ~0x3fffffffU))
        STORE(&worker_error, 2);
    tls_value = tag(worker->index, 0xf00d);
    for (unsigned i = 0; i < STACK_WORDS; ++i) stack[i] = tag(worker->index, i);
    worker->stack_address = (uintptr_t)&stack[0];
    worker->tls_address = (uintptr_t)&tls_value;
    __atomic_fetch_add(&ready, 1, __ATOMIC_RELEASE);
    while (!LOAD(&release_workers)) {
        struct timespec timeout = {30, 0};
        long result = syscall(SYS_futex, &release_workers, 128, 0, &timeout, 0, 0);
        if (result < 0 && errno != EAGAIN && errno != EINTR) {
            STORE(&worker_error, 3);
            break;
        }
    }
    if (wait_child > 0) {
        int status = 0x12345678;
        pid_t result;
        __atomic_fetch_add(&wait_started, 1, __ATOMIC_RELEASE);
        do result = waitpid(wait_child, &status, 0); while (result < 0 && errno == EINTR);
        int error = result < 0 ? errno : 0;
        if (result == wait_child && WIFEXITED(status) && WEXITSTATUS(status) == CHILD_EXIT)
            __atomic_fetch_add(&wait_reaped, 1, __ATOMIC_RELEASE);
        else if (result == -1 && error == ECHILD && status == 0x12345678)
            __atomic_fetch_add(&wait_nochild, 1, __ATOMIC_RELEASE);
        else
            STORE(&worker_error, 6);
        printf("THREAD_CAPACITY_PROBE CHILD_WAIT RETURN tid=%d child=%d result=%d status=%d error=%d\n",
               worker->tid, wait_child, result, status, error);
        __atomic_fetch_add(&wait_done, 1, __ATOMIC_RELEASE);
        if (syscall(SYS_futex, &wait_done, 129, INT_MAX, 0, 0, 0) < 0)
            STORE(&worker_error, 7);
    }
    if (tls_value != tag(worker->index, 0xf00d) ||
        (pid_t)syscall(SYS_gettid) != worker->tid)
        STORE(&worker_error, 4);
    for (unsigned i = 0; i < STACK_WORDS; ++i)
        if (stack[i] != tag(worker->index, i)) STORE(&worker_error, 5);
    return worker;
}

static int stop_workers(void) {
    STORE(&release_workers, 1);
    if (syscall(SYS_futex, &release_workers, 129, INT_MAX, 0, 0, 0) < 0) return errno;
    int failure = 0;
    while (created) {
        unsigned index = --created;
        void *result = NULL;
        int error = pthread_join(threads[index], &result);
        if (error || result != &workers[index]) failure = error ? error : EIO;
    }
    return failure;
}

static int fail(const char *stage, int error) {
    printf("THREAD_CAPACITY_PROBE FAIL stage=%s error=%d cycle=%u ready=%u created=%u\n",
           stage, error, cycle, LOAD(&ready), created);
    /* A failed child-wait phase must not join workers held behind the host
     * gate. Returning from main terminates the group; the child notices its
     * actual reparenting below and exits instead of becoming a leaked orphan. */
    if (wait_child <= 0) (void)stop_workers();
    return 1;
}

static int wait_ready(void) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return errno;
    while (LOAD(&ready) != WORKERS) {
        if (LOAD(&worker_error)) return EIO;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return errno;
        if (now.tv_sec - start.tv_sec >= 20) return ETIMEDOUT;
        /* Avoid a busy contender while fifteen workers enter their gates. */
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) && errno != EINTR) return errno;
    }
    return 0;
}

static int gated_child(void) {
    printf("THREAD_CAPACITY_PROBE CHILD_WAIT CHILD pid=%d gate=%s\n", getpid(), CHILD_GATE);
    for (;;) {
        if (getppid() == 0) return 74;
        int gate = open(CHILD_GATE, O_RDONLY | O_CLOEXEC);
        if (gate >= 0) {
            char bytes[2];
            ssize_t count = read(gate, bytes, sizeof(bytes));
            if (close(gate) || count != 2 || memcmp(bytes, "go", 2) || unlink(CHILD_GATE))
                return 71;
            printf("THREAD_CAPACITY_PROBE CHILD_WAIT EXIT pid=%d code=%d\n", getpid(), CHILD_EXIT);
            return CHILD_EXIT;
        }
        if (errno != ENOENT) return 72;
        struct timespec delay = {0, 10000000};
        if (nanosleep(&delay, NULL) && errno != EINTR) return 73;
    }
}

static int child_wait_regression(pthread_attr_t *attr) {
    if (unlink(CHILD_GATE) && errno != ENOENT) return fail("remove-stale-child-gate", errno);
    char *args[] = {"/bin/thread-capacity-probe", "wait-child", NULL};
    char *env[] = {NULL};
    struct cyxia_mapping maps[] = {{-2, 0}, {1, 1}, {2, 2}};
    wait_child = cyxia_spawn(args[0], args, env, maps, 3);
    if (wait_child < 0) return fail("spawn-wait-child", errno);
    cycle = 3;
    STORE(&ready, 0);
    STORE(&release_workers, 0);
    STORE(&worker_error, 0);
    memset(workers, 0, sizeof(workers));
    for (unsigned index = 0; index < WORKERS; ++index) {
        workers[index].index = index + 1;
        int error = pthread_create(&threads[index], attr, worker_main, &workers[index]);
        if (error) return fail("create-child-waiters", error);
        ++created;
    }
    int error = wait_ready();
    if (error) return fail("child-waiters-live", error);
    STORE(&release_workers, 1);
    if (syscall(SYS_futex, &release_workers, 129, INT_MAX, 0, 0, 0) < 0)
        return fail("release-child-waiters", errno);
    while (LOAD(&wait_started) != WORKERS) {
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) && errno != EINTR) return fail("enter-child-waits", errno);
    }
    if (LOAD(&wait_done)) return fail("child-exited-before-host-observation", EIO);
    printf("THREAD_CAPACITY_PROBE CHILD_WAIT ARMED parent=%d child=%d waiters=%u gate=%s\n",
           getpid(), wait_child, LOAD(&wait_started), CHILD_GATE);
    /* ARMED precedes some wait syscalls. The host releases the child only once
     * this parent is Waiting with all sixteen threads still alive. With only
     * this main thread outside waitpid, at least seven child waiters must then
     * occupy slots 8..15, regardless of scheduler swaps. There is deliberately
     * no timer/signal that could move a missed upper-slot waiter into slot 0. */
    for (;;) {
        unsigned done = LOAD(&wait_done);
        if (done == WORKERS) break;
        if (syscall(SYS_futex, &wait_done, 128, done, NULL, 0, 0) < 0 &&
            errno != EAGAIN && errno != EINTR)
            return fail("wait-child-completions", errno);
    }
    error = stop_workers();
    if (error || LOAD(&worker_error) || LOAD(&wait_reaped) != 1 ||
        LOAD(&wait_nochild) != WORKERS - 1 || tls_value != UINT64_C(0xffeeddccbbaa9988))
        return fail("all-child-waiters-returned", error ? error : EIO);
    int status = 0x12345678;
    errno = 0;
    if (waitpid(wait_child, &status, WNOHANG) != -1 || errno != ECHILD || status != 0x12345678)
        return fail("child-reaped-once", EIO);
    printf("THREAD_CAPACITY_PROBE CHILD_WAIT PASS waiters=%u reaped=%u nochild=%u\n",
           LOAD(&wait_done), LOAD(&wait_reaped), LOAD(&wait_nochild));
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "wait-child")) return gated_child();
    main_tid = (pid_t)syscall(SYS_gettid);
    if (main_tid != getpid()) return fail("main-identity", EIO);
    tls_value = UINT64_C(0xffeeddccbbaa9988);
    pthread_attr_t attr;
    int error = pthread_attr_init(&attr);
    if (error) return fail("attributes", error);
    error = pthread_attr_setstacksize(&attr, STACK_BYTES);
    if (error) return fail("real-stack-size", error);
    error = pthread_attr_setguardsize(&attr, 4096);
    if (error) return fail("stack-guard", error);
    pid_t previous[WORKERS] = {0};
    for (cycle = 1; cycle <= 2; ++cycle) {
        STORE(&ready, 0);
        STORE(&release_workers, 0);
        STORE(&worker_error, 0);
        memset(workers, 0, sizeof(workers));
        for (unsigned index = 0; index < WORKERS; ++index) {
            workers[index].index = index + 1;
            error = pthread_create(&threads[index], &attr, worker_main, &workers[index]);
            if (error) return fail("create-fifteen-workers", error);
            ++created;
        }
        error = wait_ready();
        if (error) return fail("all-workers-live", error);
        for (unsigned i = 0; i < WORKERS; ++i) {
            if (!workers[i].stack_address || !workers[i].tls_address ||
                workers[i].stack_address == workers[i].tls_address ||
                workers[i].tls_address == (uintptr_t)&tls_value)
                return fail("private-stack-tls-address", EIO);
            for (unsigned j = 0; j < i; ++j)
                if (workers[i].tid == workers[j].tid ||
                    workers[i].stack_address == workers[j].stack_address ||
                    workers[i].tls_address == workers[j].tls_address)
                    return fail("independent-contexts", EIO);
            if (cycle == 2)
                for (unsigned j = 0; j < WORKERS; ++j)
                    if (workers[i].tid == previous[j])
                        return fail("stale-tid-reused", EIO);
        }
        workers[WORKERS].index = WORKERS + 1;
        error = pthread_create(&threads[WORKERS], &attr, worker_main, &workers[WORKERS]);
        if (error == 0) {
            ++created;
            return fail("seventeenth-thread-was-admitted", 0);
        }
        if (error != EAGAIN) return fail("capacity-rejection-errno", error);
        printf("THREAD_CAPACITY_PROBE LIMIT PASS cycle=%u live=16 rejected=17 errno=%d\n",
               cycle, error);
        error = stop_workers();
        if (error || LOAD(&worker_error) || tls_value != UINT64_C(0xffeeddccbbaa9988))
            return fail("join-private-contexts", error ? error : EIO);
        for (unsigned i = 0; i < WORKERS; ++i) previous[i] = workers[i].tid;
        printf("THREAD_CAPACITY_PROBE JOIN_REUSE PASS cycle=%u workers=15\n", cycle);
    }
    if (child_wait_regression(&attr)) return 1;
    if ((error = pthread_attr_destroy(&attr))) return fail("destroy-attributes", error);
    puts("THREAD_CAPACITY_PROBE PASS");
    return 0;
}
