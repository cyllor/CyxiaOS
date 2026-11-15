/* Real musl detached-thread teardown must resume after unmapping its stack. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct worker_gate {
    atomic_int released;
    atomic_int tid;
};

static int fail(const char *stage, int error)
{
    printf("THREAD_EXIT_PROBE FAIL stage=%s error=%d\n", stage, error);
    return 1;
}

static int pause_before_deadline(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return -1;
    if (now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
        errno = ETIMEDOUT;
        return -1;
    }
    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
    if (nanosleep(&pause, NULL) && errno != EINTR)
        return -1;
    return 0;
}

static void *detached_worker(void *argument)
{
    struct worker_gate *gate = argument;
    long tid = syscall(SYS_gettid);
    atomic_store_explicit(&gate->tid, tid > 0 ? (int)tid : -1, memory_order_release);
    while (!atomic_load_explicit(&gate->released, memory_order_acquire))
        sched_yield();
    /* Returning invokes musl's real __pthread_exit and __unmapself. */
    return NULL;
}

static void *joined_worker(void *argument)
{
    return argument;
}

#if defined(__x86_64__)
__attribute__((noreturn)) static void bad_stack(void)
{
    /* Four-level x86 paging cannot represent this RSP. If getpid resumes
     * unexpectedly, report code 77 using only registers and another syscall. */
    __asm__ volatile(
        "movabs $0x0000800000000000, %%rsp\n\t"
        "movl %[getpid], %%eax\n\t"
        "syscall\n\t"
        "movl $77, %%edi\n\t"
        "movl %[exit_group], %%eax\n\t"
        "syscall\n\t"
        "1: jmp 1b\n\t"
        :
        : [getpid] "i" (SYS_getpid), [exit_group] "i" (SYS_exit_group)
        : "rax", "rdi", "rcx", "r11", "cc", "memory");
    __builtin_unreachable();
}
#endif

int main(int argc, char **argv)
{
    if (setvbuf(stdout, NULL, _IONBF, 0))
        return fail("stdout", errno);
    if (argc == 2 && strcmp(argv[1], "bad-stack") == 0) {
#if defined(__x86_64__)
        puts("THREAD_EXIT_PROBE BAD_STACK BEGIN");
        bad_stack();
#else
        return fail("bad-stack-architecture", ENOTSUP);
#endif
    }
    if (argc != 1)
        return fail("arguments", EINVAL);

    const pid_t pid = getpid();
    for (int cycle = 0; cycle < 4; ++cycle) {
        struct worker_gate gate;
        atomic_init(&gate.released, 0);
        atomic_init(&gate.tid, 0);
        struct timespec deadline;
        if (clock_gettime(CLOCK_MONOTONIC, &deadline))
            return fail("clock", errno);
        deadline.tv_sec += 5;
        pthread_t thread;
        int error = pthread_create(&thread, NULL, detached_worker, &gate);
        if (error)
            return fail("create-detached", error);

        int tid;
        while ((tid = atomic_load_explicit(&gate.tid, memory_order_acquire)) == 0)
            if (pause_before_deadline(&deadline))
                return fail("worker-ready", errno);
        if (tid < 0 || tid == pid)
            return fail("worker-tid", EINVAL);
        /* The gate guarantees pthread_detach runs before the worker exits. */
        error = pthread_detach(thread);
        if (error)
            return fail("detach", error);
        atomic_store_explicit(&gate.released, 1, memory_order_release);

        for (;;) {
            long result = syscall(SYS_tgkill, pid, tid, 0);
            if (result == -1 && errno == ESRCH)
                break;
            if (result != 0)
                return fail("thread-liveness", errno);
            if (pause_before_deadline(&deadline))
                return fail("detached-exit", errno);
        }
        /* ESRCH, rather than a worker-set flag, proves SYS_exit completed.
         * No worker can still access this iteration's gate or retain its slot. */
    }
    puts("THREAD_EXIT_PROBE DETACHED_EXIT PASS");

    int token = 42;
    pthread_t thread;
    int error = pthread_create(&thread, NULL, joined_worker, &token);
    if (error)
        return fail("create-reuse", error);
    void *result = NULL;
    error = pthread_join(thread, &result);
    if (error)
        return fail("join-reuse", error);
    if (result != &token)
        return fail("join-result", EINVAL);
    puts("THREAD_EXIT_PROBE JOIN_REUSE PASS");
    puts("THREAD_EXIT_PROBE PASS");
    return 0;
}
