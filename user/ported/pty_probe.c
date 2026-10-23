/* End-to-end PTY ABI probe: two distinct EL0 address spaces, real signals/waits. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "cyxia_spawn.h"
static volatile sig_atomic_t interrupts, resizes;
static void signal_seen(int n) {
    if (n == SIGINT) ++interrupts;
    if (n == SIGWINCH) ++resizes;
}
static int fail(const char *where) { printf("PTY_PROBE FAIL %s errno=%d\n", where, errno); return 1; }
static long long now(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}
static int transfer(int fd, char *bytes, size_t size, int writing) {
    while (size) {
        ssize_t n = writing ? write(fd, bytes, size) : read(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n; size -= (size_t)n;
    }
    return 0;
}
static int expect(int fd, const char *needle) {
    char bytes[4096] = {0}; size_t size = 0; long long deadline = now() + 10000;
    while (now() < deadline) {
        ssize_t n = read(fd, bytes + size, sizeof bytes - size - 1);
        if (n > 0) { size += (size_t)n; bytes[size] = 0; if (strstr(bytes, needle)) return 0; }
        else if (!n || (errno != EAGAIN && errno != EINTR)) break;
        if (size == sizeof bytes - 1) break;
        struct pollfd p = {fd, POLLIN, 0}; if (poll(&p, 1, 20) < 0 && errno != EINTR) break;
    }
    fprintf(stderr, "PTY_PROBE expected=%s received=%s\n", needle, bytes); return -1;
}
int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "child")) {
        struct sigaction a = {0}; a.sa_handler = signal_seen; sigemptyset(&a.sa_mask);
        if (sigaction(SIGINT, &a, 0) || sigaction(SIGWINCH, &a, 0) || ioctl(0, TIOCSCTTY, 0) || !isatty(1)) return 71;
        puts("CHILD_READY"); char bytes[128]; ssize_t n = read(0, bytes, sizeof bytes);
        if (n != 6 || memcmp(bytes, "hello\n", 6)) return 72;
        puts("LINE_OK");
        errno = 0; n = read(0, bytes, sizeof bytes);
        if (n != -1 || errno != EINTR || interrupts != 1) return 73;
        puts("INT_OK");
        errno = 0; n = read(0, bytes, sizeof bytes);
        if (n != -1 || errno != EINTR || resizes != 1) return 74;
        struct winsize w;
        if (ioctl(0, TIOCGWINSZ, &w) || w.ws_row != 30 || w.ws_col != 90) return 75;
        puts("WINCH_OK");
        if (read(0, bytes, sizeof bytes) != 0) return 76;
        puts("EOF_OK"); return 37;
    }
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0) return fail("open master");
    unsigned index = 99; int unlocked = 0;
    if (ioctl(master, TIOCGPTN, &index) || index >= 4) return fail("PTY number");
    errno = 0;
    if (ioctl(master, TIOCGPTPEER, O_RDWR) != -1 || errno != EIO) return fail("locked slave");
    if (ioctl(master, TIOCSPTLCK, &unlocked)) return fail("unlock");
    char path[32]; snprintf(path, sizeof path, "/dev/pts/%u", index);
    int slave = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    struct stat st;
    if (slave < 0 || fstat(slave, &st) || !S_ISCHR(st.st_mode) || !isatty(slave)) return fail("slave char tty");
    struct termios saved, raw;
    if (tcgetattr(slave, &saved)) return fail("tcgetattr");
    raw = saved; cfmakeraw(&raw);
    if (tcsetattr(slave, TCSANOW, &raw)) return fail("raw attrs");
    char data[4096], out[4096]; memset(data, 'R', sizeof data);
    if (transfer(master, data, sizeof data, 1)) return fail("raw write");
    errno = 0; if (write(master, "x", 1) != -1 || errno != EAGAIN) return fail("input backpressure");
    int pending = 0;
    if (ioctl(slave, FIONREAD, &pending) || pending != sizeof data) return fail("pending bytes");
    if (read(slave, out, 99) != 99 || write(master, "wrap", 4) != 4) return fail("raw wrap");
    if (transfer(slave, out, sizeof data - 99 + 4, 0) || memcmp(out + sizeof data - 99, "wrap", 4)) return fail("raw bytes");
    if (transfer(slave, data, sizeof data, 1)) return fail("output write");
    errno = 0; if (write(slave, "x", 1) != -1 || errno != EAGAIN) return fail("output backpressure");
    if (transfer(master, out, sizeof out, 0) || memcmp(data, out, sizeof data)) return fail("output bytes");
    if (tcsetattr(slave, TCSANOW, &saved) || fcntl(slave, F_SETFL, 0)) return fail("canonical restore");
    puts("PTY_PROBE RAW_BOUNDS PASS");
    char *args[] = {"/bin/pty-probe", "child", 0}; char *env[] = {0};
    struct cyxia_mapping maps[] = {{slave, 0}, {slave, 1}, {slave, 2}};
    pid_t child = cyxia_spawn(args[0], args, env, maps, 3);
    if (child < 0 || close(slave)) return fail("spawn slave inheritance");
    if (expect(master, "CHILD_READY\r\n")) return fail("child ready");
    if (write(master, "helx\177lo\r", 8) != 8 || expect(master, "LINE_OK\r\n")) return fail("canonical edit");
    puts("PTY_PROBE CANONICAL_CHILD PASS");
    /* Give the child a dispatch to enter its blocking read. A signal delivered
     * before the read is correctly handled but cannot interrupt a future call. */
    struct timespec settle = {0, 50000000}; nanosleep(&settle, 0);
    if (write(master, "discard\003", 8) != 8 || expect(master, "INT_OK\r\n")) return fail("VINTR real signal");
    nanosleep(&settle, 0);
    struct winsize size = {30, 90, 0, 0};
    if (ioctl(master, TIOCSWINSZ, &size) || expect(master, "WINCH_OK\r\n")) return fail("resize signal");
    if (write(master, "\004", 1) != 1 || expect(master, "EOF_OK\r\n")) return fail("canonical EOF");
    puts("PTY_PROBE SIGNALS_EOF PASS");
    int status; pid_t result;
    do result = waitpid(child, &status, 0); while (result < 0 && errno == EINTR);
    if (result != child || !WIFEXITED(status) || WEXITSTATUS(status) != 37) return fail("child wait");
    errno = 0; if (read(master, out, sizeof out) != -1 || errno != EIO) return fail("master final EIO");
    if (close(master)) return fail("master close");
    for (int i = 0; i < 8; ++i) {
        master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (master < 0 || ioctl(master, TIOCSPTLCK, &unlocked)) return fail("reuse master");
        slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
        if (slave < 0 || close(slave) || close(master)) return fail("reuse cleanup");
    }
    puts("PTY_PROBE LIFETIME PASS");
    master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0 || ioctl(master, TIOCSPTLCK, &unlocked)) return fail("shell master");
    slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    if (slave < 0) return fail("shell slave");
    char *shell_args[] = {"/bin/cyxia-sh", 0};
    for (int i = 0; i < 3; ++i) maps[i].source = slave;
    child = cyxia_spawn(shell_args[0], shell_args, env, maps, 3);
    if (child < 0 || close(slave) || expect(master, "cyxia$ ")) return fail("real shell ready");
    /* A maliciously long command must not execute its valid-looking prefix. */
    char too_long[801]; memset(too_long, 'x', sizeof too_long);
    memcpy(too_long, "write /pty-truncated ", 21); too_long[800] = '\n';
    if (transfer(master, too_long, sizeof too_long, 1) || expect(master, "entire line discarded.")) return fail("shell long line rejection");
    errno = 0;
    if (access("/pty-truncated", F_OK) != -1 || errno != ENOENT) return fail("truncated command was executed");
    char command[] = "write /pty-shell.txt 'real PTY shell file'\n";
    if (transfer(master, command, strlen(command), 1) || expect(master, "cyxia$ ")) return fail("shell write");
    int file = open("/pty-shell.txt", O_RDONLY);
    if (file < 0 || read(file, out, sizeof out) != 20 || memcmp(out, "real PTY shell file\n", 20)) return fail("shell real file bytes");
    close(file);
    char cat[] = "cat /pty-shell.txt\n";
    if (transfer(master, cat, strlen(cat), 1) || expect(master, "real PTY shell file\r\n")) return fail("shell cat");
    char sleep[] = "sleep 5\n";
    if (transfer(master, sleep, strlen(sleep), 1) || expect(master, "sleep 5\r\n")) return fail("shell sleep");
    struct timespec delay = {0, 50000000}; nanosleep(&delay, 0);
    if (write(master, "\003", 1) != 1 || expect(master, "cyxia$ ")) return fail("shell interrupt");
    if (write(master, "exit\n", 5) != 5) return fail("shell exit input");
    do result = waitpid(child, &status, 0); while (result < 0 && errno == EINTR);
    if (result != child || !WIFEXITED(status) || WEXITSTATUS(status)) return fail("shell exit");
    close(master); unlink("/pty-shell.txt");
    puts("PTY_PROBE SHELL PASS"); puts("PTY_PROBE PASS"); return 0;
}
