/* Real musl/AArch64 pipe ABI and bounded backpressure checks. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static volatile sig_atomic_t broken_pipes;
static volatile sig_atomic_t bad_signal_info;
static void broken(int number, siginfo_t *info, void *context) {
    if (number == SIGPIPE) ++broken_pipes;
    if (!context || !info || info->si_signo != SIGPIPE || info->si_code != SI_USER ||
        info->si_pid != getpid() || info->si_uid != 0) bad_signal_info = 1;
}
static int fail(const char *stage) {
    printf("PIPE_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    int ends[2] = {-1, -1};
    errno = 0;
    if (syscall(SYS_pipe2, 0, O_NONBLOCK) != -1 || errno != EFAULT)
        return fail("bad-pointer");
    errno = 0;
    if (pipe2(ends, O_APPEND) != -1 || errno != EINVAL || ends[0] != -1 || ends[1] != -1)
        return fail("flags");
    if (pipe2(ends, O_CLOEXEC | O_NONBLOCK)) return fail("pipe2");
    if (fcntl(ends[0], F_GETFL) != (O_RDONLY | O_NONBLOCK) ||
        fcntl(ends[1], F_GETFL) != (O_WRONLY | O_NONBLOCK) ||
        fcntl(ends[0], F_GETFD) != FD_CLOEXEC || fcntl(ends[1], F_GETFD) != FD_CLOEXEC)
        return fail("descriptor-flags");
    struct stat rd, wr;
    if (fstat(ends[0], &rd) || fstat(ends[1], &wr) || !S_ISFIFO(rd.st_mode) ||
        rd.st_ino != wr.st_ino || fcntl(ends[0], F_GETPIPE_SZ) != 4096)
        return fail("stat-capacity");
    errno = 0;
    if (lseek(ends[0], 0, SEEK_SET) != -1 || errno != ESPIPE) return fail("seek");
    char send[8192], received[8192];
    memset(send, 'x', sizeof send);
    errno = 0;
    if (read(ends[0], received, 1) != -1 || errno != EAGAIN) return fail("empty");
    struct pollfd p[2] = {{ends[0], POLLIN, 0}, {ends[1], POLLOUT, 0}};
    if (poll(p, 2, 0) != 1 || p[0].revents || p[1].revents != POLLOUT)
        return fail("empty-poll");
    p[0].events = POLLRDNORM; p[1].events = POLLWRNORM;
    if (poll(p, 2, 0) != 1 || p[0].revents || p[1].revents != POLLWRNORM)
        return fail("normal-poll");
    p[0].events = POLLIN; p[1].events = POLLOUT;
    if (write(ends[1], send, 4090) != 4090) return fail("page-write");
    errno = 0;
    if (write(ends[1], send, 7) != -1 || errno != EAGAIN) return fail("atomic-write");
    int pending = -1;
    if (ioctl(ends[0], FIONREAD, &pending) || pending != 4090) return fail("pending");
    errno = 0;
    if (syscall(SYS_read, ends[0], 0, 1) != -1 || errno != EFAULT ||
        ioctl(ends[0], FIONREAD, &pending) || pending != 4090)
        return fail("bad-read-preserves-data");
    if (write(ends[1], send, sizeof send) != 6) return fail("large-partial");
    size_t done = 0;
    while (done < 4096) {
        ssize_t n = read(ends[0], received + done, 4096 - done);
        if (n <= 0) return fail("drain");
        done += (size_t)n;
    }
    if (memcmp(send, received, 4096)) return fail("contents");
    puts("PIPE_PROBE ATOMIC PASS");

    struct iovec vectors[2] = {{send, 2000}, {send + 2000, 1000}};
    if (write(ends[1], send, 2000) != 2000) return fail("vector-fill");
    errno = 0;
    if (writev(ends[1], vectors, 2) != -1 || errno != EAGAIN ||
        ioctl(ends[0], FIONREAD, &pending) || pending != 2000)
        return fail("atomic-writev");
    done = 0;
    while (done < 2000) {
        ssize_t n = read(ends[0], received + done, 2000 - done);
        if (n <= 0) return fail("vector-drain");
        done += (size_t)n;
    }
    if (writev(ends[1], vectors, 2) != 3000) return fail("vector-write");
    vectors[0].iov_len = 1; vectors[1].iov_base = 0; vectors[1].iov_len = 1;
    errno = 0;
    if (syscall(SYS_writev, ends[1], vectors, 2) != -1 || errno != EFAULT ||
        ioctl(ends[0], FIONREAD, &pending) || pending != 3000)
        return fail("bad-vector-preserves-data");
    vectors[0].iov_base = received; vectors[0].iov_len = 700;
    vectors[1].iov_base = received + 700; vectors[1].iov_len = 500;
    ssize_t n = readv(ends[0], vectors, 2);
    if (n <= 700 || n > 1200 || memcmp(send, received, (size_t)n)) return fail("vector-read");
    if (ioctl(ends[0], FIONREAD, &pending) || pending != 3000 - n)
        return fail("vector-count");
    puts("PIPE_PROBE VECTOR PASS");

    int alias = dup(ends[1]);
    if (alias < 0 || fcntl(alias, F_GETFD) || close(ends[1])) return fail("dup");
    p[0].revents = 0;
    if (poll(p, 1, 0) != 1 || p[0].revents != POLLIN) return fail("dup-keeps-writer");
    if (close(alias)) return fail("last-writer");
    if (poll(p, 1, 0) != 1 || p[0].revents != (POLLIN | POLLHUP))
        return fail("buffered-hangup");
    do { n = read(ends[0], received, sizeof received); } while (n > 0);
    if (n != 0 || poll(p, 1, 0) != 1 || p[0].revents != POLLHUP) return fail("eof");
    if (close(ends[0])) return fail("reader-close");
    puts("PIPE_PROBE LIFETIME PASS");

    if (pipe2(ends, O_NONBLOCK) || close(ends[0])) return fail("broken-setup");
    struct sigaction action = {0};
    action.sa_sigaction = broken;
    action.sa_flags = SA_SIGINFO;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, 0)) return fail("handler");
    errno = 0;
    if (write(ends[1], send, 1) != -1 || errno != EPIPE || broken_pipes != 1 || bad_signal_info)
        return fail("sigpipe");
    sigset_t mask, previous;
    if (sigemptyset(&mask) || sigaddset(&mask, SIGPIPE) ||
        sigprocmask(SIG_BLOCK, &mask, &previous)) return fail("sigpipe-mask");
    errno = 0;
    if (write(ends[1], send, 1) != -1 || errno != EPIPE || broken_pipes != 1)
        return fail("sigpipe-pending");
    if (sigprocmask(SIG_SETMASK, &previous, 0) || broken_pipes != 2 || bad_signal_info)
        return fail("sigpipe-unmask");
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, 0)) return fail("sigpipe-ignore-install");
    errno = 0;
    if (write(ends[1], send, 1) != -1 || errno != EPIPE || broken_pipes != 2)
        return fail("sigpipe-ignore");
    action.sa_sigaction = broken;
    if (sigaction(SIGPIPE, &action, 0) || broken_pipes != 2)
        return fail("sigpipe-no-stale-pending");
    p[0].fd = ends[1]; p[0].events = 0;
    if (poll(p, 1, 0) != 1 || p[0].revents != POLLERR) return fail("broken-poll");
    if (write(ends[1], send, 0) || broken_pipes != 2 || close(ends[1])) return fail("zero-write");
    puts("PIPE_PROBE SIGNAL PASS");

    int second[2];
    if (pipe2(ends, O_NONBLOCK) || pipe2(second, O_NONBLOCK) ||
        dup2(ends[1], second[1]) != second[1]) return fail("dup2-setup");
    p[0].fd = second[0]; p[0].events = POLLIN;
    if (poll(p, 1, 0) != 1 || p[0].revents != POLLHUP) return fail("dup2-closes-old");
    if (close(second[0]) || close(ends[1]) || write(second[1], "a", 1) != 1 ||
        read(ends[0], received, 1) != 1 || received[0] != 'a' ||
        close(second[1]) || read(ends[0], received, 1) != 0 || close(ends[0]))
        return fail("dup2-keeps-new");
    int filled[12];
    for (int i = 0; i < 12; ++i) if ((filled[i] = dup(0)) < 0) return fail("fd-fill");
    for (int i = 0; i < 20; ++i) {
        ends[0] = ends[1] = -1;
        errno = 0;
        if (pipe2(ends, O_NONBLOCK) != -1 || errno != EMFILE || ends[0] != -1 || ends[1] != -1)
            return fail("fd-rollback");
    }
    for (int i = 0; i < 12; ++i) if (close(filled[i])) return fail("fd-release");
    puts("PIPE_PROBE ROLLBACK PASS");
    for (int i = 0; i < 20; ++i) {
        if (pipe2(ends, O_NONBLOCK) || close(ends[0]) || close(ends[1])) return fail("reuse");
    }
    puts("PIPE_PROBE PASS");
    return 0;
}
