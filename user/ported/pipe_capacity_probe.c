/* Public Linux pipe2 calls verify bounded admission and endpoint reuse. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAX_PAIRS = 30, MAX_FDS = 64, ROUNDS = 3, PAYLOAD = 32 };
static int round_index, pair_index;

static int fail(const char *stage, int line) {
    printf("PIPE_CAPACITY_PROBE FAIL %s round=%d pair=%d line=%d errno=%d\n",
           stage, round_index, pair_index, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)

static int empty(int fd) {
    char byte;
    int pending = -1;
    struct pollfd item = {.fd = fd, .events = POLLIN};
    if (ioctl(fd, FIONREAD, &pending) || pending != 0 ||
        poll(&item, 1, 0) != 0 || item.revents != 0) return 0;
    errno = 0;
    return read(fd, &byte, 1) == -1 && errno == EAGAIN;
}

static void payload(char bytes[PAYLOAD], int pair) {
    for (int i = 0; i < PAYLOAD; ++i)
        bytes[i] = (char)(1 + (round_index * 41 + pair * 7 + i) % 251);
}

static int refused(int expected_errno) {
    int ends[2] = {-123, -456};
    errno = 0;
    return pipe2(ends, O_NONBLOCK | O_CLOEXEC) == -1 &&
           errno == expected_errno && ends[0] == -123 && ends[1] == -456;
}

static int capacity_round(int expected) {
    int pairs[MAX_PAIRS][2];
    struct stat identities[MAX_PAIRS];
    char sent[PAYLOAD], received[PAYLOAD];
    for (pair_index = 0; pair_index < expected; ++pair_index) {
        int *ends = pairs[pair_index];
        CHECK(pipe2(ends, O_NONBLOCK | O_CLOEXEC) == 0, "admit-capacity");
        CHECK(fcntl(ends[0], F_GETFL) == (O_RDONLY | O_NONBLOCK) &&
              fcntl(ends[1], F_GETFL) == (O_WRONLY | O_NONBLOCK) &&
              fcntl(ends[0], F_GETFD) == FD_CLOEXEC &&
              fcntl(ends[1], F_GETFD) == FD_CLOEXEC, "descriptor-flags");
        struct stat writer;
        CHECK(fstat(ends[0], &identities[pair_index]) == 0 &&
              fstat(ends[1], &writer) == 0 && S_ISFIFO(writer.st_mode) &&
              S_ISFIFO(identities[pair_index].st_mode) &&
              identities[pair_index].st_ino == writer.st_ino &&
              fcntl(ends[0], F_GETPIPE_SZ) == 4096, "pair-identity-capacity");
        for (int previous = 0; previous < pair_index; ++previous)
            CHECK(identities[previous].st_ino != writer.st_ino, "distinct-identities");
        CHECK(empty(ends[0]), "fresh-empty");
        errno = 0;
        CHECK(read(ends[1], received, 1) == -1 && errno == EBADF, "write-end-not-readable");
        errno = 0;
        CHECK(write(ends[0], "x", 1) == -1 && errno == EBADF, "read-end-not-writable");
        payload(sent, pair_index);
        CHECK(write(ends[1], sent, sizeof sent) == sizeof sent, "write-each-pair");
    }

    /* AI admission precedes FD installation, preserving the two-pair reserve. */
    for (int attempt = 0; attempt < 4; ++attempt)
        CHECK(refused(EAGAIN), "bounded-refusal");
    for (pair_index = 0; pair_index < expected; ++pair_index) {
        int pending = -1;
        CHECK(ioctl(pairs[pair_index][0], FIONREAD, &pending) == 0 && pending == PAYLOAD,
              "refusal-preserves-pending");
        payload(sent, pair_index);
        CHECK(read(pairs[pair_index][0], received, sizeof received) == sizeof received &&
              memcmp(received, sent, sizeof sent) == 0 && empty(pairs[pair_index][0]),
              "independent-contents");
    }
    printf("PIPE_CAPACITY_PROBE CAPACITY PASS round=%d admitted=%d refused=EAGAIN\n",
           round_index, expected);

    pair_index = 0;
    int old_read = pairs[0][0], old_write = pairs[0][1];
    int alias = dup(old_write);
    CHECK(alias >= 0 && fcntl(alias, F_GETFD) == 0 && close(old_write) == 0,
          "duplicate-writer");
    CHECK(empty(old_read) && write(alias, "d", 1) == 1 &&
          read(old_read, received, 1) == 1 && received[0] == 'd', "duplicate-keeps-writer");
    CHECK(close(alias) == 0, "last-writer-close");
    struct pollfd item = {.fd = old_read, .events = POLLIN};
    CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLHUP &&
          read(old_read, received, 1) == 0 && close(old_read) == 0, "last-writer-eof");
    errno = 0;
    CHECK(read(old_read, received, 1) == -1 && errno == EBADF, "closed-read-descriptor");
    errno = 0;
    CHECK(write(old_write, "x", 1) == -1 && errno == EBADF, "closed-write-descriptor");

    CHECK(pipe2(pairs[0], O_NONBLOCK | O_CLOEXEC) == 0 &&
          pairs[0][0] == old_read && pairs[0][1] == old_write, "reuse-freed-descriptors");
    struct stat fresh;
    CHECK(fstat(pairs[0][0], &fresh) == 0 && fresh.st_ino != identities[0].st_ino &&
          empty(pairs[0][0]), "new-identity-no-stale-data");
    alias = dup(pairs[0][0]);
    CHECK(alias >= 0 && close(pairs[0][0]) == 0 &&
          write(pairs[0][1], "r", 1) == 1 && read(alias, received, 1) == 1 &&
          received[0] == 'r', "duplicate-keeps-reader");
    CHECK(close(alias) == 0, "last-reader-close");
    errno = 0;
    CHECK(write(pairs[0][1], "x", 1) == -1 && errno == EPIPE, "last-reader-broken-pipe");
    item.fd = pairs[0][1]; item.events = 0; item.revents = 0;
    CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLERR &&
          close(pairs[0][1]) == 0, "last-reader-poll-error");
    CHECK(pipe2(pairs[0], O_NONBLOCK | O_CLOEXEC) == 0 && empty(pairs[0][0]),
          "reuse-after-last-reader");
    CHECK(refused(EAGAIN), "reuse-retains-bound");

    for (pair_index = 0; pair_index < expected; ++pair_index) {
        /* Deliberately leave unread bytes to detect stale contents next round. */
        payload(sent, pair_index);
        CHECK(write(pairs[pair_index][1], sent, sizeof sent) == sizeof sent &&
              close(pairs[pair_index][0]) == 0 && close(pairs[pair_index][1]) == 0,
              "close-with-unread-data");
    }
    printf("PIPE_CAPACITY_PROBE REUSE PASS round=%d pairs=%d\n", round_index, expected);
    return 0;
}

static int descriptor_rollback(int fd_limit) {
    int aliases[MAX_FDS];
    for (int i = 0; i < fd_limit - 3; ++i) {
        aliases[i] = dup(STDIN_FILENO);
        CHECK(aliases[i] >= 0, "fill-descriptor-table");
    }
    errno = 0;
    CHECK(dup(STDIN_FILENO) == -1 && errno == EMFILE, "descriptor-limit");
    CHECK(close(aliases[fd_limit - 4]) == 0, "leave-single-descriptor-slot");
    /* Pool admission succeeds, but installing a pair must roll back completely. */
    for (int attempt = 0; attempt < 4; ++attempt)
        CHECK(refused(EMFILE), "descriptor-failure-rollback");
    for (int i = 0; i < fd_limit - 4; ++i)
        CHECK(close(aliases[i]) == 0, "release-descriptor-aliases");
    puts("PIPE_CAPACITY_PROBE DESCRIPTOR_ROLLBACK PASS");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int expected = MAX_PAIRS;
    CHECK(argc == 1 || (argc == 2 &&
          (strcmp(argv[1], "6") == 0 || strcmp(argv[1], "30") == 0)), "expected-argument");
    if (argc == 2 && strcmp(argv[1], "6") == 0) expected = 6;
    struct sigaction action = {.sa_handler = SIG_IGN};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0,
          "ignore-sigpipe");
    printf("PIPE_CAPACITY_PROBE START expected=%d\n", expected);
    /* All I/O is nonblocking; all polls have a zero timeout and loops are bounded. */
    for (round_index = 0; round_index < ROUNDS; ++round_index) {
        if (capacity_round(expected)) return 1;
        if (round_index == 0 && descriptor_rollback(expected == MAX_PAIRS ? 64 : 16))
            return 1;
    }
    printf("PIPE_CAPACITY_PROBE PASS admitted=%d rounds=%d\n", expected, ROUNDS);
    return 0;
}
