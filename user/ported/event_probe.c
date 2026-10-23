#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(test) do { if (!(test)) { printf("EVENT_PROBE FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } ++checks; } while (0)
static void *wake_writer(void *raw) {
    struct timespec delay = { .tv_nsec = 20000000 };
    nanosleep(&delay, 0);
    uint64_t value = 1;
    return (void *)(intptr_t)(write(*(int *)raw, &value, sizeof(value)) == sizeof(value) ? 0 : 1);
}
static int receiver_started;
static void *blocked_receiver(void *raw) {
    char byte;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    __atomic_store_n(&receiver_started, 1, __ATOMIC_RELEASE);
    int result = recvmsg(*(int *)raw, &message, 0);
    return (void *)(intptr_t)(result == -1 && errno == EBADF ? 0 : 1);
}

int main(void) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event watch = { .events = EPOLLIN, .data.u64 = UINT64_C(0x12345678abcd0001) };
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pair[1], &watch) == 0);
    struct epoll_event out[32];
    CHECK(epoll_wait(ep, out, 32, 0) == 0);
    char a[] = "way", b[] = "land", received[8] = {0};
    struct iovec vectors[2] = {{a, 3}, {b, 4}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    CHECK(sendmsg(pair[0], &message, MSG_DONTWAIT | MSG_NOSIGNAL) == 7);
    CHECK(epoll_wait(ep, out, 32, 100) == 1 && out[0].data.u64 == watch.data.u64 && (out[0].events & EPOLLIN));
    // Level-triggered readiness remains until the stream is drained.
    CHECK(epoll_wait(ep, out, 32, 0) == 1);
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec incoming[2] = {{received, 2}, {received + 2, 5}};
    struct msghdr response = {.msg_iov = incoming, .msg_iovlen = 2, .msg_control = control, .msg_controllen = sizeof(control)};
    CHECK(recvmsg(pair[1], &response, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) == 7);
    CHECK(strcmp(received, "wayland") == 0 && response.msg_controllen == 0 && response.msg_flags == 0);
    CHECK(epoll_wait(ep, out, 32, 0) == 0);

    // SCM_RIGHTS is unsupported: neither descriptor nor payload may be sent.
    memset(control, 0, sizeof(control));
    message.msg_control = control; message.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pair[0], sizeof(int));
    errno = 0;
    CHECK(sendmsg(pair[0], &message, MSG_NOSIGNAL) == -1 && errno == ENOSYS);
    CHECK(epoll_wait(ep, out, 32, 0) == 0);
    message.msg_control = 0; message.msg_controllen = 0;
    // An invalid later iovec must not commit an earlier valid prefix.
    vectors[1].iov_base = (void *)(uintptr_t)1;
    errno = 0;
    CHECK(sendmsg(pair[0], &message, MSG_DONTWAIT | MSG_NOSIGNAL) == -1 && errno == EFAULT);
    CHECK(epoll_wait(ep, out, 32, 0) == 0);
    vectors[1].iov_base = b;
    watch.events = EPOLLIN | EPOLLEXCLUSIVE;
    errno = 0;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, pair[1], &watch) == -1 && errno == EINVAL);
    watch.events = EPOLLIN | EPOLLONESHOT;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, pair[1], &watch) == 0);
    CHECK(sendmsg(pair[0], &message, MSG_DONTWAIT | MSG_NOSIGNAL) == 7);
    CHECK(epoll_wait(ep, out, 32, 0) == 1);
    CHECK(epoll_wait(ep, out, 32, 0) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, pair[1], &watch) == 0);
    CHECK(epoll_wait(ep, out, 32, 0) == 1);
    CHECK(read(pair[1], received, 7) == 7);
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pair[1], 0) == 0);
    watch.events = EPOLLRDHUP;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pair[1], &watch) == 0);
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    CHECK(epoll_wait(ep, out, 32, 0) == 1 && (out[0].events & EPOLLRDHUP) && !(out[0].events & EPOLLHUP));
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pair[1], 0) == 0);

    // Wait really blocks and wakes from a second EL0 thread; timeout is monotonic.
    int counter = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(counter >= 0);
    watch.events = EPOLLIN; watch.data.u64 = 99;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, counter, &watch) == 0);
    int unconnected = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(unconnected >= 0);
    errno = 0;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, unconnected, &watch) == -1 && errno == ENOTCONN);
    CHECK(close(unconnected) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, wake_writer, &counter) == 0);
    CHECK(epoll_wait(ep, out, 32, 2000) == 1 && out[0].data.u64 == 99);
    void *result;
    CHECK(pthread_join(thread, &result) == 0 && result == 0);
    uint64_t value;
    CHECK(read(counter, &value, 8) == 8 && value == 1);
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(epoll_wait(ep, out, 32, 12) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK((after.tv_sec - before.tv_sec) * 1000000000LL + after.tv_nsec - before.tv_nsec >= 12000000LL);
    CHECK(close(counter) == 0);
    CHECK(close(pair[1]) == 0);
    // MSG_NOSIGNAL must leave no pending fatal SIGPIPE.
    errno = 0;
    CHECK(sendmsg(pair[0], &message, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    CHECK(close(pair[0]) == 0 && close(ep) == 0);
    // Close/reuse while blocked must not switch the old receive to a new
    // connection. Keep an alias alive to exercise cancellation without HUP.
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int saved = pair[1], alias = dup(saved), replacement[2];
    CHECK(alias >= 0);
    CHECK(pthread_create(&thread, 0, blocked_receiver, &saved) == 0);
    while (!__atomic_load_n(&receiver_started, __ATOMIC_ACQUIRE)) sched_yield();
    struct timespec delay = {.tv_nsec = 20000000};
    CHECK(nanosleep(&delay, 0) == 0);
    CHECK(close(saved) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, replacement) == 0);
    CHECK(replacement[0] == saved);
    CHECK(write(replacement[1], "N", 1) == 1);
    CHECK(pthread_join(thread, &result) == 0 && result == 0);
    CHECK(read(replacement[0], received, 1) == 1 && received[0] == 'N');
    CHECK(close(pair[0]) == 0 && close(alias) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
    printf("EVENT_PROBE PASS checks=%u fd_transport=false level_epoll=true\n", checks);
    return 0;
}
