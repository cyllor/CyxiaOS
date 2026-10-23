/* Real musl pthreads: shared objects, isolated TLS/FPSIMD, futexes and lifetime. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef int atomic_int;
#define atomic_load(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_store(p, v) __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)
#define atomic_fetch_add(p, v) __atomic_fetch_add((p), (v), __ATOMIC_SEQ_CST)

static _Thread_local int tls_value = 7;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t recursive_mutex, owner_mutex;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int counter, ready, release_workers;
static atomic_int worker_error, detached_done, signal_seen, signal_ready;
static int shared_fd;
static pid_t main_tid, signal_tid;
static int fail(const char *stage) {
    printf("THREAD_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}
static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static int wait_atomic(atomic_int *value, int wanted) {
    for (int i = 0; i < 5000; ++i) {
        if (atomic_load(value) == wanted) return 0;
        pause_ms(1);
    }
    return -1;
}
static void *basic_worker(void *argument) {
    intptr_t id = (intptr_t)argument;
    if (tls_value != 7 || syscall(SYS_gettid) == main_tid || getpid() != main_tid)
        atomic_store(&worker_error, 1);
    tls_value = (int)id;
    if ((syscall(SYS_gettid) & ~0x3fffffffL) ||
        pthread_mutex_lock(&recursive_mutex) || pthread_mutex_lock(&recursive_mutex) ||
        pthread_mutex_unlock(&recursive_mutex) || pthread_mutex_unlock(&recursive_mutex))
        atomic_store(&worker_error, 12);
    if (pthread_mutex_unlock(&owner_mutex) != EPERM) atomic_store(&worker_error, 13);
    // A syscall-free interval must survive timer preemption with its own TLS
    // and a caller-saved SIMD register intact across other runnable threads.
    uint64_t irq_actual, irq_expected = 0x9876000000000000ULL + (uint64_t)id;
    uint64_t spins = 4000000;
    __asm__ volatile("dup v30.2d, %[value]\n1: subs %[spins], %[spins], #1\nb.ne 1b\numov %[actual], v30.d[1]"
                     : [actual] "=r"(irq_actual), [spins] "+r"(spins)
                     : [value] "r"(irq_expected) : "v30", "cc", "memory");
    if (irq_actual != irq_expected || tls_value != id) atomic_store(&worker_error, 11);
    for (int i = 0; i < 20; ++i) {
        errno = 100 + (int)id;
        uint64_t actual, expected = 0x1234000000000000ULL + (uint64_t)id;
        register long number __asm__("x8") = SYS_sched_yield;
        __asm__ volatile("dup v31.2d, %[value]\nsvc #0\numov %[actual], v31.d[1]"
                         : [actual] "=r"(actual), "+r"(number)
                         : [value] "r"(expected) : "v31", "x0", "memory");
        if (actual != expected || tls_value != id || errno != 100 + id)
            atomic_store(&worker_error, 2);
        if (pthread_mutex_lock(&mutex)) atomic_store(&worker_error, 3);
        ++counter;
        if (pthread_mutex_unlock(&mutex)) atomic_store(&worker_error, 4);
    }
    char byte = (char)('A' + id);
    if (write(shared_fd, &byte, 1) != 1) atomic_store(&worker_error, 5);
    return (void *)(id + 10);
}
static void *park_worker(void *argument) {
    pthread_mutex_lock(&mutex);
    ++ready;
    pthread_cond_broadcast(&condition);
    while (!release_workers) pthread_cond_wait(&condition, &mutex);
    pthread_mutex_unlock(&mutex);
    return argument;
}
static void *detached_worker(void *argument) {
    (void)argument;
    atomic_fetch_add(&detached_done, 1);
    return 0;
}
static void signal_handler(int number, siginfo_t *info, void *context) {
    if (number == SIGUSR1 && info && info->si_code == SI_TKILL &&
        info->si_pid == getpid() && context && tls_value == 99 &&
        syscall(SYS_gettid) == signal_tid) atomic_store(&signal_seen, 1);
    else atomic_store(&worker_error, 6);
}
static void *signal_worker(void *argument) {
    (void)argument;
    tls_value = 99;
    signal_tid = (pid_t)syscall(SYS_gettid);
    atomic_store(&signal_ready, 1);
    // The parent blocked SIGUSR1 before creation; it must be inherited.
    sigset_t mask;
    pthread_sigmask(SIG_SETMASK, 0, &mask);
    if (!sigismember(&mask, SIGUSR1)) atomic_store(&worker_error, 7);
    pause_ms(20);
    if (atomic_load(&signal_seen)) atomic_store(&worker_error, 8);
    sigemptyset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, 0);
    if (wait_atomic(&signal_seen, 1)) atomic_store(&worker_error, 9);
    return 0;
}
static int futex_word, requeue_word;
static atomic_int futex_ready, futex_done;
static void *futex_worker(void *argument) {
    (void)argument;
    atomic_fetch_add(&futex_ready, 1);
    struct timespec timeout = {5, 0};
    long result = syscall(SYS_futex, &futex_word, 128, 0, &timeout, 0, 0);
    if (result) atomic_store(&worker_error, 10);
    atomic_fetch_add(&futex_done, 1);
    return 0;
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    main_tid = (pid_t)syscall(SYS_gettid);
    if (main_tid != getpid()) return fail("leader-id");
    tls_value = 42;
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&recursive_mutex, &mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&owner_mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);
    if (pthread_mutex_lock(&owner_mutex) || pthread_mutex_lock(&owner_mutex) != EDEADLK)
        return fail("errorcheck-owner");
    pthread_t threads[8];
    shared_fd = open("/tmp/thread-shared", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (shared_fd < 0) return fail("shared-open");
    for (intptr_t i = 1; i <= 3; ++i)
        if (pthread_create(&threads[i-1], 0, basic_worker, (void *)i)) return fail("create-basic");
    for (intptr_t i = 1; i <= 3; ++i) {
        void *result = 0;
        if (pthread_join(threads[i-1], &result) || result != (void *)(i+10)) return fail("join-result");
    }
    if (atomic_load(&worker_error) || tls_value != 42 || counter != 60 ||
        lseek(shared_fd, 0, SEEK_CUR) != 3 || close(shared_fd)) return fail("tls-fp-shared-fd");
    if (pthread_mutex_unlock(&owner_mutex) || pthread_mutex_destroy(&owner_mutex) ||
        pthread_mutex_destroy(&recursive_mutex)) return fail("owner-mutex-cleanup");
    puts("THREAD_PROBE BASIC PASS");

    struct timespec timeout;
    pthread_condattr_t attr;
    pthread_cond_t timed;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&timed, &attr);
    pthread_condattr_destroy(&attr);
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_nsec += 5000000;
    if (timeout.tv_nsec >= 1000000000) { ++timeout.tv_sec; timeout.tv_nsec -= 1000000000; }
    pthread_mutex_lock(&mutex);
    int result = pthread_cond_timedwait(&timed, &mutex, &timeout);
    pthread_mutex_unlock(&mutex);
    pthread_cond_destroy(&timed);
    if (result != ETIMEDOUT) return fail("cond-timeout");
    puts("THREAD_PROBE SYNC PASS");

    struct sigaction action = {.sa_sigaction = signal_handler, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0)) return fail("sigaction");
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &mask, 0) || pthread_create(&threads[0], 0, signal_worker, 0) ||
        wait_atomic(&signal_ready, 1) || pthread_kill(threads[0], SIGUSR1) ||
        pthread_join(threads[0], 0) || atomic_load(&worker_error) || !atomic_load(&signal_seen))
        return fail("thread-signal");
    errno = 0;
    if (syscall(SYS_tgkill, getpid(), signal_tid, 0) != -1 || errno != ESRCH) return fail("dead-tid");
    pthread_sigmask(SIG_UNBLOCK, &mask, 0);
    puts("THREAD_PROBE SIGNAL PASS");

    errno = 0;
    if (syscall(SYS_futex, &futex_word, 128, 1, 0, 0, 0) != -1 || errno != EAGAIN)
        return fail("futex-mismatch");
    struct timespec zero = {0, 0};
    errno = 0;
    if (syscall(SYS_futex, &futex_word, 128, 0, &zero, 0, 0) != -1 || errno != ETIMEDOUT)
        return fail("futex-timeout");
    errno = 0;
    if (syscall(SYS_futex, (char *)&futex_word+1, 129, 1, 0, 0, 0) != -1 || errno != EINVAL)
        return fail("futex-alignment");
    for (int i=0; i<2; ++i) if (pthread_create(&threads[i], 0, futex_worker, 0)) return fail("futex-create");
    if (wait_atomic(&futex_ready, 2)) return fail("futex-ready");
    pause_ms(20);
    errno = 0;
    if (syscall(SYS_futex, &futex_word, 132, 0, 2, &requeue_word, 1) != -1 || errno != EAGAIN)
        return fail("cmp-requeue-mismatch");
    if (syscall(SYS_futex, &futex_word, 132, 1, 1, &requeue_word, 0) != 2)
        return fail("cmp-requeue");
    if (syscall(SYS_futex, &futex_word, 129, INT_MAX, 0, 0, 0) != 0 ||
        syscall(SYS_futex, &requeue_word, 129, INT_MAX, 0, 0, 0) != 1) return fail("requeue-wake-count");
    for (int i=0; i<2; ++i) if (pthread_join(threads[i], 0)) return fail("futex-join");
    if (atomic_load(&futex_done) != 2 || atomic_load(&worker_error)) return fail("futex-result");
    puts("THREAD_PROBE FUTEX PASS");

    // Exactly seven workers plus this leader; the ninth context must fail.
    for (intptr_t i=0; i<7; ++i)
        if (pthread_create(&threads[i], 0, park_worker, (void *)(i+1))) return fail("capacity-create");
    pthread_mutex_lock(&mutex);
    while (ready != 7) pthread_cond_wait(&condition, &mutex);
    if (pthread_create(&threads[7], 0, park_worker, 0) != EAGAIN) return fail("capacity-denial");
    release_workers = 1;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);
    for (intptr_t i=0; i<7; ++i) {
        void *value = 0;
        if (pthread_join(threads[i], &value) || value != (void *)(i+1)) return fail("capacity-join");
    }
    for (int i=0; i<20; ++i) {
        if (pthread_create(&threads[0], 0, detached_worker, 0) || pthread_join(threads[0], 0))
            return fail("reuse");
    }
    pthread_attr_t detached;
    pthread_attr_init(&detached);
    pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED);
    for (int i=0; i<12; ++i) {
        if (pthread_create(&threads[0], &detached, detached_worker, 0) ||
            wait_atomic(&detached_done, 21+i)) return fail("detached-create");
        pause_ms(2); // Let detached musl unmap its own stack and execute SYS_exit.
    }
    pthread_attr_destroy(&detached);
    errno = 0;
    if (syscall(SYS_clone, 0, 0, 0, 0, 0) != -1 || errno != ENOSYS) return fail("fork-rejected");
    _Alignas(16) char child_stack[32];
    int parent_tid = 0x1234, child_tid = 0x5678;
    errno = 0;
    if (syscall(SYS_clone, 0x7d0f00, child_stack, 0, 0, &child_tid) != -1 ||
        errno != EFAULT || child_tid != 0x5678 || parent_tid != 0x1234)
        return fail("clone-atomic-fault");
    if (atomic_load(&worker_error)) return fail("worker-error");
    puts("THREAD_PROBE LIMIT_REUSE PASS");
    // Returning from main executes musl's exit_group while two genuine threads
    // are still asleep in a condition variable. The external guest verifier
    // requires all contexts and heap/image grants to be reclaimed afterwards.
    ready = 0; release_workers = 0;
    for (int i = 0; i < 2; ++i)
        if (pthread_create(&threads[i], 0, park_worker, 0)) return fail("group-exit-create");
    pthread_mutex_lock(&mutex);
    while (ready != 2) pthread_cond_wait(&condition, &mutex);
    pthread_mutex_unlock(&mutex);
    puts("THREAD_PROBE GROUP_EXIT PASS");
    unlink("/tmp/thread-shared");
    puts("THREAD_PROBE PASS");
    return 0;
}
