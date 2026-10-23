#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cyxia_spawn.h"

static unsigned checks;
#define CHECK(x) do { if (!(x)) { printf("TIMERFD_PROBE FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } ++checks; } while (0)
static struct itimerspec setting(long initial, long interval) {
    return (struct itimerspec){{interval / 1000000000, interval % 1000000000},
                              {initial / 1000000000, initial % 1000000000}};
}
static void gate(const char *path) {
    struct stat st;
    while (stat(path, &st)) sched_yield();
}
struct reader { int fd, error; ssize_t result; uint64_t ticks; };
static void *read_worker(void *raw) {
    struct reader *r = raw;
    r->result = read(r->fd, &r->ticks, sizeof r->ticks);
    r->error = errno;
    return NULL;
}
static int blocked(int cancel) {
    const char *stage = cancel ? "REUSE" : "REARM";
    char start[64], finish[64];
    snprintf(start, sizeof start, "/timer-%s-start", stage);
    snprintf(finish, sizeof finish, "/timer-%s-finish", stage);
    int fd = timerfd_create(CLOCK_MONOTONIC, 0), alias = dup(fd);
    CHECK(fd >= 0 && alias >= 0);
    printf("TIMERFD_PROBE %s WAIT\n", stage);
    fflush(stdout);
    gate(start); /* Host captures wait count before this worker can block. */
    struct reader r = {.fd = fd};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, read_worker, &r) == 0);
    gate(finish); /* Host has witnessed an actual parked read. */
    if (cancel) {
        CHECK(close(fd) == 0);
        int fresh = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        CHECK(fresh == fd);
        struct itimerspec past = setting(1, 0);
        CHECK(timerfd_settime(fresh, TFD_TIMER_ABSTIME, &past, NULL) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(r.result == -1 && r.error == EBADF);
        uint64_t value;
        CHECK(read(fresh, &value, 8) == 8 && value == 1);
        CHECK(close(fresh) == 0);
    } else {
        struct itimerspec arm = setting(2000000, 0);
        CHECK(timerfd_settime(alias, 0, &arm, NULL) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(r.result == 8 && r.ticks == 1);
        CHECK(close(fd) == 0);
    }
    CHECK(close(alias) == 0);
    CHECK(unlink(start) == 0 && unlink(finish) == 0);
    printf("TIMERFD_PROBE %s PASS\n", stage);
    return 0;
}
int main(int argc, char **argv) {
    uint64_t ticks = 0;
    if (argc == 2 && !strcmp(argv[1], "child")) {
        CHECK(read(3, &ticks, 8) == 8 && ticks == 1);
        CHECK(read(3, &ticks, 8) == -1 && errno == EAGAIN);
        CHECK(close(3) == 0);
        puts("TIMERFD_PROBE CHILD PASS");
        return 0;
    }
    CHECK(timerfd_create(CLOCK_REALTIME, 0) == -1 && errno == ENOSYS);
    CHECK(timerfd_create((clockid_t)-1, 0) == -1 && errno == EINVAL);
    CHECK(timerfd_create(CLOCK_MONOTONIC, 1) == -1 && errno == EINVAL);
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC && (fcntl(fd, F_GETFL) & O_NONBLOCK));
    int alias = dup(fd);
    CHECK(alias >= 0 && fcntl(alias, F_GETFD) == 0);
    CHECK(read(fd, &ticks, 8) == -1 && errno == EAGAIN);
    CHECK(read(fd, &ticks, 7) == -1 && errno == EINVAL);
    CHECK(write(fd, &ticks, 8) == -1 && errno == EINVAL);
    CHECK(write(fd, &ticks, 0) == -1 && errno == EINVAL);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event watch = {.events = EPOLLIN, .data.u64 = UINT64_C(0xabcde12345678900)}, out;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &watch) == 0);
    CHECK(epoll_wait(ep, &out, 1, 0) == 0);
    struct itimerspec arm = setting(20000000, 0), old, current;
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(timerfd_settime(fd, 0, &arm, &old) == 0 && old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
    CHECK(timerfd_gettime(fd, &current) == 0 && current.it_value.tv_sec == 0 && current.it_value.tv_nsec <= 20000000);
    CHECK(epoll_wait(ep, &out, 1, 2000) == 1 && out.events == EPOLLIN && out.data.u64 == watch.data.u64);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK((after.tv_sec - before.tv_sec) * 1000000000LL + after.tv_nsec - before.tv_nsec >= 20000000);
    CHECK(epoll_wait(ep, &out, 1, 0) == 1);
    struct pollfd pollfd = {fd, POLLIN | POLLOUT, 0};
    CHECK(poll(&pollfd, 1, 0) == 1 && pollfd.revents == POLLIN);
    CHECK(timerfd_gettime(alias, &current) == 0 && current.it_value.tv_sec == 0 && current.it_value.tv_nsec == 0);
    /* Failed copies and short reads must not consume the pending expiration. */
    CHECK(syscall(SYS_read, fd, (void *)1, 8) == -1 && errno == EFAULT);
    struct iovec bad[2] = {{&ticks, 4}, {(void *)1, 4}};
    CHECK(readv(fd, bad, 2) == -1 && errno == EFAULT);
    struct iovec split[2] = {{&ticks, 3}, {(char *)&ticks + 3, 5}};
    CHECK(readv(alias, split, 2) == 8 && ticks == 1);
    CHECK(epoll_wait(ep, &out, 1, 0) == 0);
    arm = setting(1000000, 1000000);
    CHECK(timerfd_settime(fd, 0, &arm, NULL) == 0);
    struct timespec delay = {.tv_nsec = 15000000};
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(timerfd_gettime(fd, &current) == 0 && current.it_interval.tv_nsec == 1000000);
    CHECK(read(alias, &ticks, 8) == 8 && ticks >= 15);
    /* Rearm clears pending counts; unknown flags/invalid times are atomic. */
    arm = setting(0, 1000000);
    CHECK(timerfd_settime(fd, 0, &arm, &old) == 0 && old.it_interval.tv_nsec == 1000000);
    CHECK(read(fd, &ticks, 8) == -1 && errno == EAGAIN);
    CHECK(timerfd_gettime(fd, &current) == 0 && current.it_value.tv_nsec == 0 && current.it_interval.tv_nsec == 1000000);
    arm = setting(1, 0);
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &arm, NULL) == 0);
    struct itimerspec invalid = setting(0, 0);
    invalid.it_value.tv_nsec = 1000000000;
    CHECK(timerfd_settime(fd, 0, &invalid, NULL) == -1 && errno == EINVAL);
    CHECK(timerfd_settime(fd, TFD_TIMER_CANCEL_ON_SET, &arm, NULL) == -1 && errno == EINVAL);
    invalid.it_value.tv_sec = LLONG_MAX;
    invalid.it_value.tv_nsec = 0;
    CHECK(timerfd_settime(fd, 0, &invalid, NULL) == -1 && errno == EOVERFLOW);
    invalid = setting(0, 0);
    CHECK(syscall(SYS_timerfd_settime, fd, 0, &invalid, (void *)1) == -1 && errno == EFAULT);
    CHECK(read(fd, &ticks, 8) == 8 && ticks == 1);
    watch.events = EPOLLIN | EPOLLONESHOT;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &watch) == 0);
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &arm, NULL) == 0);
    CHECK(epoll_wait(ep, &out, 1, 0) == 1);
    CHECK(epoll_wait(ep, &out, 1, 0) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &watch) == 0);
    CHECK(epoll_wait(ep, &out, 1, 0) == 1);
    CHECK(read(alias, &ticks, 8) == 8 && ticks == 1);
    /* Explicit native spawn shares the timer description with a separate EL0 process. */
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &arm, NULL) == 0);
    char *args[] = {"/bin/timerfd-probe", "child", NULL}, *env[] = {NULL};
    struct cyxia_mapping maps[] = {{0, 0}, {1, 1}, {2, 2}, {fd, 3}};
    pid_t child = cyxia_spawn(args[0], args, env, maps, 4);
    CHECK(child > 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(read(alias, &ticks, 8) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0 && close(alias) == 0);
    CHECK(epoll_wait(ep, &out, 1, 0) == 0 && close(ep) == 0);
    puts("TIMERFD_PROBE ABI PASS");
    CHECK(blocked(0) == 0);
    CHECK(blocked(1) == 0);
    printf("TIMERFD_PROBE PASS checks=%u\n", checks);
    return 0;
}
