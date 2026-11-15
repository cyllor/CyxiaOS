/* Actual Linux musl calls exercise nested epoll readiness and OFD lifetime. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

static int fail(const char *stage, int line) {
    printf("NESTED_EPOLL_PROBE FAIL %s line=%d errno=%d\n", stage, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)

static int watch(int ep, int op, int fd, uint32_t mask, uint64_t data) {
    struct epoll_event event = {.events = mask, .data.u64 = data};
    return epoll_ctl(ep, op, fd, &event);
}
static int quiet(int ep) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, 0) == 0;
}
static int ready(int ep, uint64_t data) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, 0) == 1 &&
           event.events == EPOLLIN && event.data.u64 == data;
}
static int waited(int ep, uint64_t data) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, 1000) == 1 &&
           event.events == EPOLLIN && event.data.u64 == data;
}
static int polled(int ep, short expected) {
    struct pollfd item = {.fd = ep, .events = POLLIN | POLLOUT};
    return poll(&item, 1, 0) == (expected != 0) && item.revents == expected;
}
static int written(int fd) {
    uint64_t value = 1;
    return write(fd, &value, sizeof value) == sizeof value;
}
static int drained(int fd, uint64_t expected) {
    uint64_t value = 0;
    return read(fd, &value, sizeof value) == sizeof value && value == expected;
}
static int close_tree(int outer, int inner, int counter) {
    return close(counter) == 0 && close(inner) == 0 && close(outer) == 0;
}

static int level(void) {
    int outer = epoll_create1(EPOLL_CLOEXEC);
    int inner = epoll_create1(EPOLL_CLOEXEC);
    int counter = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(outer >= 0 && inner >= 0 && counter >= 0, "level-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN, 11) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 12) == 0, "level-add");
    CHECK(quiet(outer) && polled(outer, 0), "level-initially-quiet");
    CHECK(written(counter), "level-write");
    for (int i = 0; i < 3; ++i) {
        CHECK(polled(outer, POLLIN) && ready(outer, 12), "level-repeat");
    }
    /* Neither poll nor epoll_wait on the parent consumes the child event. */
    CHECK(ready(inner, 11) && ready(outer, 12), "level-child-not-consumed");
    CHECK(drained(counter, 1), "level-drain");
    CHECK(quiet(inner) && quiet(outer) && polled(outer, 0), "level-cleared");
    CHECK(watch(outer, EPOLL_CTL_DEL, inner, 0, 0) == 0 && written(counter) &&
          quiet(outer), "level-delete");
    CHECK(watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 13) == 0 &&
          ready(outer, 13), "level-add-already-ready");
    CHECK(close_tree(outer, inner, counter), "level-close");
    puts("NESTED_EPOLL_PROBE LEVEL PASS");
    return 0;
}

static int inner_oneshot(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0);
    int counter = eventfd(0, EFD_NONBLOCK);
    CHECK(outer >= 0 && inner >= 0 && counter >= 0, "oneshot-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN | EPOLLONESHOT, 21) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 22) == 0, "oneshot-add");
    CHECK(written(counter) && polled(outer, POLLIN), "oneshot-write");
    CHECK(ready(outer, 22) && ready(outer, 22), "oneshot-parent-preserves-child");
    CHECK(ready(inner, 21) && quiet(inner) && quiet(outer) && polled(outer, 0),
          "oneshot-child-disarms");
    CHECK(written(counter) && quiet(outer), "oneshot-disarmed-write");
    CHECK(watch(inner, EPOLL_CTL_MOD, counter, EPOLLIN | EPOLLONESHOT, 23) == 0,
          "oneshot-rearm");
    CHECK(ready(outer, 22) && ready(inner, 23) && quiet(outer), "oneshot-rearmed-delivery");
    CHECK(drained(counter, 2) && close_tree(outer, inner, counter), "oneshot-close");
    puts("NESTED_EPOLL_PROBE INNER_ONESHOT PASS");
    return 0;
}

static int outer_edge(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0);
    int counter = eventfd(0, EFD_NONBLOCK);
    CHECK(outer >= 0 && inner >= 0 && counter >= 0, "edge-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN | EPOLLET, 31) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN | EPOLLET, 32) == 0, "edge-add");
    CHECK(quiet(outer) && written(counter), "edge-first-write");
    CHECK(ready(outer, 32) && quiet(outer), "edge-no-repeat");
    CHECK(written(counter) && ready(outer, 32) && quiet(outer),
          "edge-notification-while-child-ready");
    CHECK(ready(inner, 31) && quiet(inner) && quiet(outer), "edge-child-consumes-candidate");
    CHECK(drained(counter, 2) && written(counter), "edge-drain-replenish");
    CHECK(ready(outer, 32) && quiet(outer) && ready(inner, 31), "edge-new-transition");
    CHECK(drained(counter, 1) && quiet(outer), "edge-final-drain");
    CHECK(close_tree(outer, inner, counter), "edge-close");

    outer = epoll_create1(0); inner = epoll_create1(0);
    counter = eventfd(0, EFD_NONBLOCK);
    CHECK(outer >= 0 && inner >= 0 && counter >= 0, "edge-level-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN, 33) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN | EPOLLET, 34) == 0 &&
          written(counter), "edge-level-add");
    CHECK(ready(outer, 34) && quiet(outer), "edge-level-first-delivery");
    for (int i = 0; i < 3; ++i) {
        /* Sampling/collecting a still-ready LEVEL child is not a new write. */
        CHECK(ready(inner, 33) && quiet(outer), "edge-level-collect-does-not-notify");
    }
    CHECK(written(counter) && ready(outer, 34) && quiet(outer), "edge-level-real-notification");
    CHECK(drained(counter, 2) && quiet(outer) && close_tree(outer, inner, counter),
          "edge-level-close");
    puts("NESTED_EPOLL_PROBE OUTER_EDGE PASS");
    return 0;
}

static int cycle_rejection(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0);
    int alias = dup(outer), counter = eventfd(0, EFD_NONBLOCK);
    CHECK(outer >= 0 && inner >= 0 && alias >= 0 && counter >= 0, "cycle-create");
    CHECK(watch(outer, EPOLL_CTL_ADD, outer, EPOLLIN, 41) == -1 && errno == EINVAL,
          "cycle-self");
    CHECK(watch(outer, EPOLL_CTL_ADD, alias, EPOLLIN, 41) == -1 && errno == EINVAL,
          "cycle-self-alias");
    CHECK(watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 42) == 0, "cycle-first-edge");
    CHECK(watch(inner, EPOLL_CTL_ADD, alias, EPOLLIN, 43) == -1 && errno == ELOOP,
          "cycle-transitive-alias");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN, 44) == 0 && written(counter),
          "cycle-rejection-preserves-tree");
    CHECK(ready(outer, 42) && ready(inner, 44) && drained(counter, 1),
          "cycle-tree-still-works");
    CHECK(close(alias) == 0 && close_tree(outer, inner, counter), "cycle-close");
    puts("NESTED_EPOLL_PROBE CYCLE_REJECTION PASS");
    return 0;
}

static int ofd_reuse(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0);
    int counter = eventfd(0, EFD_NONBLOCK), alias = dup(inner);
    CHECK(outer >= 0 && inner >= 0 && counter >= 0 && alias >= 0, "reuse-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, counter, EPOLLIN, 51) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 52) == 0, "reuse-add");
    CHECK(close(inner) == 0, "reuse-close-original");
    int replacement = eventfd(0, EFD_NONBLOCK);
    CHECK(replacement == inner && written(replacement) && quiet(outer),
          "reuse-number-is-not-identity");
    CHECK(written(counter) && ready(outer, 52) && ready(alias, 51),
          "reuse-alias-keeps-original");
    CHECK(close(alias) == 0 && quiet(outer), "reuse-final-close-removes-watch");
    CHECK(close(replacement) == 0, "reuse-free-old-number");
    int new_inner = epoll_create1(0);
    CHECK(new_inner == inner && watch(new_inner, EPOLL_CTL_ADD, counter, EPOLLIN, 53) == 0,
          "reuse-new-epoll-at-old-number");
    CHECK(ready(new_inner, 53) && quiet(outer), "reuse-new-epoll-not-inherited");
    CHECK(watch(outer, EPOLL_CTL_ADD, new_inner, EPOLLIN, 54) == 0 && ready(outer, 54),
          "reuse-explicit-new-watch");
    CHECK(close(counter) == 0 && quiet(outer), "reuse-leaf-final-close-clears-parent");
    CHECK(close(new_inner) == 0 && close(outer) == 0, "reuse-close");
    puts("NESTED_EPOLL_PROBE OFD_REUSE PASS");
    return 0;
}

static int socket_timer(void) {
    int outer = epoll_create1(0), inner = epoll_create1(0), pair[2];
    CHECK(outer >= 0 && inner >= 0 &&
          socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0,
          "socket-timer-create");
    CHECK(watch(inner, EPOLL_CTL_ADD, pair[1], EPOLLIN, 61) == 0 &&
          watch(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 62) == 0, "socket-timer-add");
    CHECK(quiet(outer) && write(pair[0], "s", 1) == 1, "socket-write");
    CHECK(waited(outer, 62) && ready(inner, 61), "socket-nested-ready");
    char byte = 0;
    CHECK(read(pair[1], &byte, 1) == 1 && byte == 's' && quiet(inner) && quiet(outer),
          "socket-drain");

    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(timer >= 0 && watch(inner, EPOLL_CTL_ADD, timer, EPOLLIN, 63) == 0,
          "timer-add");
    struct itimerspec deadline = {.it_value.tv_nsec = 20000000};
    CHECK(timerfd_settime(timer, 0, &deadline, NULL) == 0, "timer-arm");
    CHECK(waited(outer, 62) && ready(inner, 63), "timer-nested-expiration");
    uint64_t ticks = 0;
    CHECK(read(timer, &ticks, sizeof ticks) == sizeof ticks && ticks == 1 &&
          quiet(inner) && quiet(outer), "timer-drain");
    CHECK(close(timer) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0 &&
          close(inner) == 0 && close(outer) == 0, "socket-timer-close");
    puts("NESTED_EPOLL_PROBE SOCKET_TIMER PASS");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (level() || inner_oneshot() || outer_edge() || cycle_rejection() || ofd_reuse() ||
        socket_timer()) return 1;
    puts("NESTED_EPOLL_PROBE PASS");
    return 0;
}
