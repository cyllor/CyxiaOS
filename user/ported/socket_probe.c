/* Real target-musl AF_UNIX stream/ppoll probe; no host-side socket emulation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned char sent[8192];
static unsigned char received[8192];

static int fail(const char *stage)
{
    printf("SOCKET_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}

static int ready(int fd, short events, short required, short forbidden)
{
    struct pollfd pollfd = {fd, events, 0};
    const struct timespec zero = {0, 0};
    int count = ppoll(&pollfd, 1, &zero, NULL);
    if (count < 0 || count > 1 || (count == 1) != (pollfd.revents != 0) ||
        (pollfd.revents & required) != required ||
        (pollfd.revents & forbidden) != 0)
        return -1;
    return 0;
}

static int read_all(int fd, unsigned char *out, size_t length)
{
    size_t done = 0;
    for (unsigned tries = 0; done < length && tries < 64; ++tries) {
        ssize_t count = read(fd, out + done, length - done);
        if (count <= 0) return -1;
        done += (size_t)count;
    }
    return done == length ? 0 : -1;
}

static int pair_probe(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair))
        return fail("socketpair");
    int flags = fcntl(pair[0], F_GETFL), fdflags = fcntl(pair[0], F_GETFD);
    if (flags < 0 || fdflags < 0 || !(flags & O_NONBLOCK) || !(fdflags & FD_CLOEXEC))
        return fail("socketpair-flags");
    errno = 0;
    if (read(pair[1], received, 1) != -1 || errno != EAGAIN)
        return fail("empty-eagain");
    if (ready(pair[1], POLLIN, 0, POLLIN | POLLHUP))
        return fail("empty-ppoll");
    for (size_t i = 0; i < sizeof sent; ++i)
        sent[i] = (unsigned char)(i * 37u + 11u);
    size_t buffered = 0;
    for (unsigned tries = 0; tries < 64 && buffered < sizeof sent; ++tries) {
        ssize_t count = write(pair[0], sent + buffered, sizeof sent - buffered);
        if (count > 0) {
            buffered += (size_t)count;
            continue;
        }
        if (count != -1 || errno != EAGAIN) return fail("write-backpressure");
        break;
    }
    if (buffered < 257 || buffered == sizeof sent)
        return fail("bounded-buffer");
    if (ready(pair[0], POLLOUT, 0, POLLOUT) ||
        ready(pair[1], POLLIN, POLLIN, POLLHUP))
        return fail("full-ppoll");
    if (read_all(pair[1], received, 257) || memcmp(received, sent, 257))
        return fail("short-read");
    if (ready(pair[0], POLLOUT, POLLOUT, POLLHUP))
        return fail("space-ppoll");
    memmove(sent, sent + 257, buffered - 257);
    memset(sent + buffered - 257, 0xa5, 257);
    if (write(pair[0], sent + buffered - 257, 257) != 257)
        return fail("wrapped-write");
    if (read_all(pair[1], received, buffered) || memcmp(received, sent, buffered))
        return fail("wrapped-content");
    if (close(pair[0])) return fail("close-peer");
    if (ready(pair[1], POLLIN, POLLIN | POLLHUP, 0))
        return fail("hangup-ppoll");
    if (read(pair[1], received, sizeof received) != 0)
        return fail("peer-eof");
    if (close(pair[1])) return fail("close-pair");
    printf("SOCKET_PROBE PAIR PASS buffered=%zu\n", buffered);
    return 0;
}

static int named_probe(void)
{
    const char path[] = "/socket-probe.sock";
    const char request[] = "X11 setup over AF_UNIX";
    const char reply[] = "stream reply after unlink";
    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, sizeof path);
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + sizeof path;
    if (unlink(path) && errno != ENOENT) return fail("initial-unlink");
    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (server < 0 || client < 0) return fail("socket");
    if (bind(server, (struct sockaddr *)&address, length) || listen(server, 2))
        return fail("bind-listen");
    errno = 0;
    if (accept(server, NULL, NULL) != -1 || errno != EAGAIN)
        return fail("empty-accept");
    if (connect(client, (struct sockaddr *)&address, length))
        return fail("connect");
    if (ready(server, POLLIN, POLLIN, POLLHUP)) return fail("listener-ppoll");
    if (write(client, request, sizeof request) != sizeof request)
        return fail("preaccept-write");
    int accepted = accept(server, NULL, NULL);
    if (accepted < 0) return fail("accept");
    if (read_all(accepted, received, sizeof request) ||
        memcmp(received, request, sizeof request))
        return fail("accepted-read");
    if (unlink(path)) return fail("unlink-live-name");
    if (write(accepted, reply, sizeof reply) != sizeof reply ||
        ready(client, POLLIN, POLLIN, POLLHUP) ||
        read_all(client, received, sizeof reply) ||
        memcmp(received, reply, sizeof reply))
        return fail("reply-after-unlink");
    int missing = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (missing < 0) return fail("missing-socket");
    errno = 0;
    if (connect(missing, (struct sockaddr *)&address, length) != -1 || errno != ENOENT)
        return fail("unlinked-connect");
    if (close(missing) || close(server) || close(accepted)) return fail("close-named");
    if (read(client, received, 1) != 0) return fail("named-eof");
    if (close(client)) return fail("close-client");
    puts("SOCKET_PROBE NAMED PASS");
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("SOCKET_PROBE START");
    if (pair_probe() || named_probe()) return 1;
    puts("SOCKET_PROBE PASS");
    return 0;
}
