#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>

#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#endif

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int efd;
static int pfd[2];
static int futex_word;
static int fw;

static void *futex_writer(void *a) {
    (void)a;
    msleep(100);
    syscall(SYS_futex, &fw, FUTEX_WAKE, 1, NULL, NULL, 0);
    return NULL;
}

static void *writer(void *arg) {
    (void)arg;
    msleep(100);
    uint64_t one = 1;
    if (write(efd, &one, 8) != 8) perror("eventfd write");
    if (write(pfd[1], "x", 1) != 1) perror("pipe write");
    syscall(SYS_futex, &futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
    return NULL;
}

static int epoll_wait_fd(int ep, int timeout) {
    struct epoll_event ev;
    return epoll_wait(ep, &ev, 1, timeout);
}

int main(void) {
    setbuf(stdout, NULL);
    puts("WAKE_PROBE start");

    efd = eventfd(0, EFD_NONBLOCK);
    pipe2(pfd, O_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = efd } };
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);
    struct epoll_event ev2 = { .events = EPOLLIN, .data = { .fd = pfd[0] } };
    epoll_ctl(ep, EPOLL_CTL_ADD, pfd[0], &ev2);

    pthread_t th;
    pthread_create(&th, NULL, writer, NULL);

    int n = epoll_wait_fd(ep, 2000);
    printf("WAKE_PROBE epoll_eventfd_pipe n=%d (expect>=1)\n", n);

    // futex cross-thread wake on a fresh word.
    pthread_t th2;
    struct timespec before, after;
    pthread_create(&th2, NULL, futex_writer, NULL);
    clock_gettime(CLOCK_MONOTONIC, &before);
    long fr = syscall(SYS_futex, &fw, FUTEX_WAIT, 0, NULL, NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &after);
    long ms = (after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
    printf("WAKE_PROBE futex r=%ld errno=%d waited_ms=%ld (expect ~100, not 2000+)\n", fr, errno, ms);

    pthread_join(th, NULL);
    pthread_join(th2, NULL);
    puts("WAKE_PROBE end");
    return 0;
}