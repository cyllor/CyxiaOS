/* Actual x86 musl signal registration, delivery, restart and EINTR behavior. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cyxia_spawn.h"

static volatile sig_atomic_t calls, bad_handler;
static pthread_t main_thread;
static int worker_error, word;
struct work { int kind, descriptor; };

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static void caught(int number, siginfo_t *info, void *context) {
    if (number != SIGUSR1 || !info || info->si_signo != number || !context)
        bad_handler = 1;
    ++calls;
}
static int install(int restart) {
    struct sigaction action = {0};
    action.sa_sigaction = caught;
    action.sa_flags = SA_SIGINFO | (restart ? SA_RESTART : 0);
    sigemptyset(&action.sa_mask);
    return sigaction(SIGUSR1, &action, 0);
}
static int fail(const char *stage) {
    printf("SIGNAL_RESTART_PROBE FAIL %s errno=%d calls=%d bad=%d worker=%d\n",
           stage, errno, calls, bad_handler, worker_error);
    return 1;
}
static void *worker(void *opaque) {
    struct work *work = opaque;
    pause_ms(50);
    worker_error = pthread_kill(main_thread, SIGUSR1);
    pause_ms(100);
    if (work->kind == 1 && write(work->descriptor, "x", 1) != 1) worker_error = errno;
    if (work->kind == 2) {
        __atomic_store_n(&word, 1, __ATOMIC_RELEASE);
        syscall(SYS_futex, &word, 1 | 128, 1, 0, 0, 0);
    }
    if (work->kind == 3 && flock(work->descriptor, LOCK_UN)) worker_error = errno;
    return 0;
}
static int begin(pthread_t *thread, struct work *work) {
    calls = bad_handler = worker_error = 0;
    return pthread_create(thread, 0, worker, work);
}
static int joined(pthread_t thread) {
    return pthread_join(thread, 0) || calls != 1 || bad_handler || worker_error;
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) { pause_ms(500); return 7; }
    setbuf(stdout, 0);
    puts("SIGNAL_RESTART_PROBE START");
    main_thread = pthread_self();
    if (install(1)) return fail("register-restart");
    puts("SIGNAL_RESTART_PROBE REGISTRATION PASS");

    int fds[2];
    pthread_t thread;
    char byte = 0;
    struct work work = {1, -1};
    if (pipe(fds)) return fail("pipe");
    work.descriptor = fds[1];
    if (begin(&thread, &work)) return fail("thread-read");
    ssize_t n = read(fds[0], &byte, 1);
    if (n != 1 || byte != 'x' || joined(thread)) return fail("read-restart");
    close(fds[0]); close(fds[1]);
    puts("SIGNAL_RESTART_PROBE READ_RESTART PASS");

    if (install(0) || pipe(fds)) return fail("nonrestart-setup");
    work.descriptor = fds[1];
    if (begin(&thread, &work)) return fail("thread-eintr");
    errno = 0;
    n = read(fds[0], &byte, 1);
    int error = errno;
    if (n != -1 || error != EINTR || joined(thread)) return fail("read-eintr");
    close(fds[0]); close(fds[1]);
    puts("SIGNAL_RESTART_PROBE READ_EINTR PASS");

    if (install(1) || pipe(fds)) return fail("poll-setup");
    work.descriptor = fds[1];
    if (begin(&thread, &work)) return fail("thread-poll");
    struct pollfd pollfd = {fds[0], POLLIN, 0};
    int r = poll(&pollfd, 1, 1000);
    error = errno;
    if (r != -1 || error != EINTR || joined(thread)) return fail("poll-eintr");
    close(fds[0]); close(fds[1]);
    puts("SIGNAL_RESTART_PROBE POLL_EINTR PASS");

    work.kind = 0;
    if (begin(&thread, &work)) return fail("thread-sleep");
    struct timespec delay = {1, 0}, left = {0};
    r = nanosleep(&delay, &left);
    error = errno;
    if (r != -1 || error != EINTR || !(left.tv_sec || left.tv_nsec) || joined(thread))
        return fail("sleep-eintr");
    puts("SIGNAL_RESTART_PROBE SLEEP_EINTR PASS");

    int timer = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec spec = {.it_value = {0, 300000000}};
    if (timer < 0 || timerfd_settime(timer, 0, &spec, 0) || begin(&thread, &work))
        return fail("timer-setup");
    uint64_t expirations = 0;
    n = read(timer, &expirations, sizeof expirations);
    if (n != sizeof expirations || !expirations || joined(thread)) return fail("timer-restart");
    close(timer);
    puts("SIGNAL_RESTART_PROBE TIMER_RESTART PASS");

    work.kind = 2;
    word = 0;
    if (begin(&thread, &work)) return fail("thread-futex");
    long fr = syscall(SYS_futex, &word, 128, 0, 0, 0, 0);
    error = errno;
    if ((fr != 0 && !(fr == -1 && error == EAGAIN)) || joined(thread) || word != 1)
        return fail("futex-restart");
    puts("SIGNAL_RESTART_PROBE FUTEX_RESTART PASS");

    work.kind = 0;
    word = 0;
    if (begin(&thread, &work)) return fail("thread-timed-futex");
    struct timespec timeout = {1, 0};
    fr = syscall(SYS_futex, &word, 128, 0, &timeout, 0, 0);
    error = errno;
    if (fr != -1 || error != EINTR || joined(thread)) return fail("timed-futex-eintr");
    puts("SIGNAL_RESTART_PROBE TIMED_FUTEX_EINTR PASS");

    int first = open("/run/user/0/restart-lock", O_CREAT | O_RDWR, 0600);
    int second = open("/run/user/0/restart-lock", O_RDWR);
    if (first < 0 || second < 0 || flock(first, LOCK_EX)) return fail("flock-setup");
    work.kind = 3; work.descriptor = first;
    if (begin(&thread, &work)) return fail("thread-flock");
    r = flock(second, LOCK_EX);
    if (r || joined(thread)) return fail("flock-restart");
    close(first); close(second); unlink("/run/user/0/restart-lock");
    puts("SIGNAL_RESTART_PROBE FLOCK_RESTART PASS");

    char *child_argv[] = {"/bin/signal-restart-probe", "--child", 0};
    char *child_env[] = {0};
    pid_t child = cyxia_spawn(child_argv[0], child_argv, child_env, 0, 0);
    work.kind = 0;
    if (child <= 0 || begin(&thread, &work)) return fail("child-setup");
    int status = 0;
    pid_t waited = waitpid(child, &status, 0);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7 || joined(thread))
        return fail("wait-restart");
    puts("SIGNAL_RESTART_PROBE WAIT_RESTART PASS");
    puts("SIGNAL_RESTART_PROBE PASS");
    return 0;
}
