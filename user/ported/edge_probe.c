#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "cyxia_spawn.h"

static unsigned checks;
static volatile sig_atomic_t broken_pipe_signals;
static void broken_pipe(int signal) {
    if (signal == SIGPIPE) ++broken_pipe_signals;
}
#define CHECK(x) do { if (!(x)) { printf("EDGE_PROBE FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } ++checks; } while (0)
static int watch(int ep, int op, int fd, uint32_t mask, uint64_t data) {
    struct epoll_event event = {.events = mask, .data.u64 = data};
    return epoll_ctl(ep, op, fd, &event);
}
static int quiet(int ep) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, 0) == 0;
}
static int event(int ep, uint32_t mask, uint64_t data) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, 2000) == 1 &&
           event.events == mask && event.data.u64 == data;
}
static int counters(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(ep >= 0 && fd >= 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, fd, EPOLLIN | EPOLLET, 11) == 0);
    CHECK(quiet(ep));
    /* Mio's actual Waker does not consume its eventfd counter between polls. */
    for (int i = 0; i < 3; ++i) {
        uint64_t value = 1;
        CHECK(write(fd, &value, 8) == 8);
        CHECK(event(ep, EPOLLIN, 11) && quiet(ep));
    }
    uint64_t value = 0;
    CHECK(write(fd, &value, 8) == 8 && event(ep, EPOLLIN, 11));
    CHECK(quiet(ep));
    CHECK(read(fd, &value, 8) == 8 && value == 3);
    CHECK(quiet(ep));
    CHECK(write(fd, &value, 8) == 8);
    CHECK(read(fd, &value, 8) == 8);
    CHECK(quiet(ep)); /* No stale notification after consumption. */
    CHECK(write(fd, &value, 8) == 8);
    CHECK(event(ep, EPOLLIN, 11) && quiet(ep));
    CHECK(watch(ep, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLET | EPOLLONESHOT, 12) == 0);
    CHECK(event(ep, EPOLLIN, 12) && quiet(ep));
    CHECK(write(fd, &value, 8) == 8 && quiet(ep));
    CHECK(watch(ep, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLET | EPOLLONESHOT, 13) == 0);
    CHECK(event(ep, EPOLLIN, 13) && quiet(ep));
    CHECK(watch(ep, EPOLL_CTL_MOD, fd, EPOLLOUT | EPOLLET, 14) == 0);
    CHECK(event(ep, EPOLLOUT, 14) && quiet(ep));
    CHECK(write(fd, &value, 8) == 8 && quiet(ep)); /* IN cannot wake OUT watch. */
    CHECK(read(fd, &value, 8) == 8);
    CHECK(event(ep, EPOLLOUT, 14) && quiet(ep));
    CHECK(close(fd) == 0 && close(ep) == 0);
    puts("EDGE_PROBE COUNTERS PASS");
    return 0;
}
static int streams(void) {
    int ep = epoll_create1(0), pair[2];
    CHECK(ep >= 0 && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, pair[1], EPOLLIN | EPOLLET | EPOLLRDHUP, 21) == 0);
    CHECK(write(pair[0], "ab", 2) == 2 && event(ep, EPOLLIN, 21));
    char bytes[8];
    CHECK(read(pair[1], bytes, 1) == 1 && bytes[0] == 'a' && quiet(ep));
    CHECK(write(pair[0], "c", 1) == 1 && event(ep, EPOLLIN, 21) && quiet(ep));
    CHECK(read(pair[1], bytes, sizeof bytes) == 2 && !memcmp(bytes, "bc", 2));
    /* Drain/replenish between waits is a new event, even when both samples are ready. */
    CHECK(write(pair[0], "d", 1) == 1 && event(ep, EPOLLIN, 21));
    CHECK(read(pair[1], bytes, 1) == 1 && write(pair[0], "e", 1) == 1);
    CHECK(event(ep, EPOLLIN, 21) && read(pair[1], bytes, 1) == 1 && quiet(ep));
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    CHECK(event(ep, EPOLLIN | EPOLLRDHUP, 21) && quiet(ep));
    CHECK(close(pair[0]) == 0);
    CHECK(event(ep, EPOLLIN | EPOLLRDHUP | EPOLLHUP, 21) && quiet(ep));
    CHECK(read(pair[1], bytes, 1) == 0);
    CHECK(close(pair[1]) == 0 && close(ep) == 0);
    puts("EDGE_PROBE STREAMS PASS");
    return 0;
}
static int pipes_and_pty(void) {
    int ep = epoll_create1(0), pair[2];
    CHECK(ep >= 0 && pipe2(pair, O_NONBLOCK) == 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, pair[1], EPOLLOUT | EPOLLET, 31) == 0);
    CHECK(event(ep, EPOLLOUT, 31) && quiet(ep));
    char bytes[4096] = {0};
    CHECK(write(pair[1], bytes, sizeof bytes) == sizeof bytes && quiet(ep));
    CHECK(write(pair[1], bytes, 1) == -1 && errno == EAGAIN && quiet(ep));
    CHECK(read(pair[0], bytes, 1) == 1 && event(ep, EPOLLOUT, 31) && quiet(ep));
    CHECK(close(pair[0]) == 0);
    CHECK(event(ep, EPOLLOUT | EPOLLERR, 31) && quiet(ep));
    CHECK(close(pair[1]) == 0);

    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK), unlocked = 0;
    CHECK(master >= 0 && ioctl(master, TIOCSPTLCK, &unlocked) == 0);
    int slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_NONBLOCK);
    CHECK(slave >= 0 && watch(ep, EPOLL_CTL_ADD, slave, EPOLLIN | EPOLLET, 32) == 0);
    CHECK(write(master, "a\n", 2) == 2 && event(ep, EPOLLIN, 32));
    CHECK(read(slave, bytes, 1) == 1 && bytes[0] == 'a' && quiet(ep));
    CHECK(write(master, "b", 1) == 1 && quiet(ep)); /* Incomplete canonical line. */
    CHECK(write(master, "\n", 1) == 1 && event(ep, EPOLLIN, 32) && quiet(ep));
    CHECK(read(slave, bytes, sizeof bytes) == 1 && bytes[0] == '\n');
    CHECK(read(slave, bytes, sizeof bytes) == 2 && !memcmp(bytes, "b\n", 2));
    CHECK(quiet(ep));
    CHECK(write(master, "\004", 1) == 1 && event(ep, EPOLLIN, 32));
    CHECK(read(slave, bytes, sizeof bytes) == 0 && quiet(ep));
    CHECK(close(master) == 0 && event(ep, EPOLLHUP, 32) && quiet(ep));
    CHECK(close(slave) == 0 && close(ep) == 0);
    puts("EDGE_PROBE PIPE_PTY PASS");
    return 0;
}
static int send_abi(void) {
    int ep = epoll_create1(0), pair[2];
    CHECK(ep >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, pair[1], EPOLLIN | EPOLLET, 61) == 0);
    char bytes[4096];
    memset(bytes, 's', sizeof bytes);
    CHECK(send(pair[0], bytes, 1, MSG_OOB) == -1 && errno == ENOSYS && quiet(ep));
    CHECK(sendto(pair[0], bytes, 1, MSG_NOSIGNAL, (void *)bytes, 2) == -1 &&
          errno == ENOSYS && quiet(ep));
    CHECK(send(pair[0], (void *)(uintptr_t)1, 1, MSG_NOSIGNAL) == -1 &&
          errno == EFAULT && quiet(ep));
    CHECK(send(-1, bytes, 1, MSG_NOSIGNAL) == -1 && errno == EBADF);
    CHECK(send(pair[0], bytes, 0, MSG_NOSIGNAL) == 0 && quiet(ep));
    struct sockaddr_storage name, unchanged;
    memset(&name, 0x5a, sizeof name);
    unchanged = name;
    struct iovec vector = {.iov_base = bytes, .iov_len = sizeof bytes};
    struct msghdr message = {.msg_name = &name, .msg_namelen = sizeof name,
                            .msg_iov = &vector, .msg_iovlen = 1};
    CHECK(send(pair[0], "n", 1, MSG_NOSIGNAL) == 1);
    CHECK(recvmsg(pair[1], &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) == 1 &&
          bytes[0] == 'n' && message.msg_namelen == 0 &&
          !memcmp(&name, &unchanged, sizeof name) && quiet(ep));
    /* No source address is returned: a zero-byte copy must not touch its VA. */
    message.msg_name = (void *)(uintptr_t)1;
    message.msg_namelen = sizeof name;
    CHECK(send(pair[0], "p", 1, MSG_NOSIGNAL) == 1 &&
          recvmsg(pair[1], &message, MSG_DONTWAIT) == 1 &&
          bytes[0] == 'p' && message.msg_namelen == 0 && quiet(ep));
    memset(bytes, 's', sizeof bytes);
    for (int i = 0; i < 4; ++i) {
        CHECK(send(pair[0], bytes, sizeof bytes, MSG_DONTWAIT | MSG_NOSIGNAL) == 1024);
        CHECK(event(ep, EPOLLIN, 61) && quiet(ep));
    }
    /* MSG_DONTWAIT applies even though the descriptor itself is blocking. */
    CHECK(send(pair[0], bytes, 1, MSG_DONTWAIT | MSG_NOSIGNAL) == -1 &&
          errno == EAGAIN && quiet(ep));
    for (int i = 0; i < 4; ++i) {
        CHECK(recv(pair[1], bytes, sizeof bytes, MSG_DONTWAIT) == 1024);
        CHECK(bytes[0] == 's' && bytes[1023] == 's');
    }
    CHECK(quiet(ep));
    struct sigaction action = {.sa_handler = broken_pipe}, previous;
    CHECK(sigemptyset(&action.sa_mask) == 0 &&
          sigaction(SIGPIPE, &action, &previous) == 0);
    CHECK(close(pair[1]) == 0);
    CHECK(send(pair[0], bytes, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    CHECK(broken_pipe_signals == 0);
    CHECK(send(pair[0], bytes, 1, 0) == -1 && errno == EPIPE);
    CHECK(broken_pipe_signals == 1);
    CHECK(sigaction(SIGPIPE, &previous, NULL) == 0);
    CHECK(close(pair[0]) == 0 && close(ep) == 0);
    puts("EDGE_PROBE SEND_ABI PASS");
    return 0;
}
static int shared_and_fair(void) {
    int ep = epoll_create1(0), a = eventfd(1, EFD_NONBLOCK), b = eventfd(1, EFD_NONBLOCK);
    CHECK(ep >= 0 && a >= 0 && b >= 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, a, EPOLLIN | EPOLLET, 41) == 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, b, EPOLLIN | EPOLLET, 42) == 0);
    CHECK(event(ep, EPOLLIN, 41));
    CHECK(event(ep, EPOLLIN, 42) && quiet(ep)); /* maxevents=1 retains the second candidate. */
    char *args[] = {"/bin/edge-probe", "child", NULL}, *env[] = {NULL};
    struct cyxia_mapping maps[] = {{0, 0}, {1, 1}, {2, 2}, {a, 3}};
    pid_t child = cyxia_spawn(args[0], args, env, maps, 4);
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(event(ep, EPOLLIN, 41) && quiet(ep));
    int alias = dup(a);
    CHECK(alias >= 0 && close(a) == 0);
    int reused = eventfd(0, EFD_NONBLOCK);
    CHECK(reused == a);
    uint64_t value = 1;
    CHECK(write(reused, &value, 8) == 8 && quiet(ep));
    CHECK(write(alias, &value, 8) == 8 && event(ep, EPOLLIN, 41) && quiet(ep));
    CHECK(close(alias) == 0 && close(reused) == 0 && close(b) == 0);
    CHECK(quiet(ep) && close(ep) == 0);
    puts("EDGE_PROBE SHARING PASS");
    return 0;
}
static int timers(void) {
    int ep = epoll_create1(0), timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(ep >= 0 && timer >= 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, timer, EPOLLIN | EPOLLET, 51) == 0);
    struct itimerspec value = {.it_value.tv_nsec = 2000000};
    for (int i = 0; i < 3; ++i) {
        CHECK(timerfd_settime(timer, 0, &value, NULL) == 0);
        CHECK(event(ep, EPOLLIN, 51) && quiet(ep));
        uint64_t ticks;
        CHECK(read(timer, &ticks, 8) == 8 && ticks == 1 && quiet(ep));
    }
    /* Rearm to the past without reading the preceding expiration. */
    value.it_value.tv_nsec = 1;
    for (int i = 0; i < 3; ++i) {
        CHECK(timerfd_settime(timer, TFD_TIMER_ABSTIME, &value, NULL) == 0);
        CHECK(event(ep, EPOLLIN, 51) && quiet(ep));
    }
    CHECK(close(timer) == 0 && close(ep) == 0);
    puts("EDGE_PROBE TIMERS PASS");
    return 0;
}
static int poll_event(int ep, int timeout, int expected) {
    struct pollfd item = {.fd = ep, .events = POLLIN | POLLOUT};
    return poll(&item, 1, timeout) == (expected != 0) && item.revents == expected;
}
static int polling_epoll(void) {
    int ep = epoll_create1(0), fd = eventfd(0, EFD_NONBLOCK);
    uint64_t value = 1;
    CHECK(ep >= 0 && fd >= 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, fd, EPOLLIN | EPOLLET | EPOLLONESHOT, 71) == 0);
    CHECK(poll_event(ep, 0, 0));
    CHECK(write(fd, &value, 8) == 8);
    for (int i = 0; i < 3; ++i) CHECK(poll_event(ep, 0, POLLIN));
    CHECK(event(ep, EPOLLIN, 71)); /* poll must not consume or disarm it. */
    CHECK(poll_event(ep, 0, 0));
    CHECK(read(fd, &value, 8) == 8 && write(fd, &value, 8) == 8);
    CHECK(watch(ep, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLET, 72) == 0 &&
          poll_event(ep, 0, POLLIN));
    CHECK(read(fd, &value, 8) == 8);
    CHECK(poll_event(ep, 0, 0) && quiet(ep)); /* No stale readiness. */
    CHECK(watch(ep, EPOLL_CTL_MOD, fd, EPOLLIN, 73) == 0);
    CHECK(write(fd, &value, 8) == 8);
    for (int i = 0; i < 3; ++i) CHECK(poll_event(ep, 0, POLLIN) && event(ep, EPOLLIN, 73));
    CHECK(read(fd, &value, 8) == 8);
    CHECK(poll_event(ep, 0, 0));
    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(timer >= 0);
    CHECK(watch(ep, EPOLL_CTL_ADD, timer, EPOLLIN | EPOLLET, 74) == 0);
    struct itimerspec deadline = {.it_value.tv_nsec = 20000000};
    CHECK(timerfd_settime(timer, 0, &deadline, NULL) == 0);
    CHECK(poll_event(ep, 2000, POLLIN)); /* Real blocked poll is awakened. */
    CHECK(poll_event(ep, 0, POLLIN));
    CHECK(event(ep, EPOLLIN, 74));
    CHECK(poll_event(ep, 0, 0));
    CHECK(close(timer) == 0 && close(fd) == 0 && close(ep) == 0);
    puts("EDGE_PROBE POLL_EPOLL PASS");
    return 0;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "child")) {
        uint64_t value = 1;
        CHECK(write(3, &value, 8) == 8 && close(3) == 0);
        puts("EDGE_PROBE CHILD PASS");
        return 0;
    }
    CHECK(counters() == 0);
    CHECK(streams() == 0);
    CHECK(send_abi() == 0);
    CHECK(pipes_and_pty() == 0);
    CHECK(shared_and_fair() == 0);
    CHECK(timers() == 0);
    CHECK(polling_epoll() == 0);
    printf("EDGE_PROBE PASS checks=%u\n", checks);
    return 0;
}
