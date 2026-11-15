/* Real filesystem/ABI and same-disk recovery checks; no emulated service. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

static void check(int ok, int line) {
    if (!ok) { printf("FILESYSTEM_PROBE FAIL line=%d errno=%d\n", line, errno); exit(1); }
}
#define CHECK(x) check((x), __LINE__)
static unsigned char pattern[8192];
static void put(int fd, const void *data, size_t length) {
    const char *p = data;
    while (length) {
        ssize_t n = write(fd, p, length);
        CHECK(n > 0); p += n; length -= (size_t)n;
    }
}
static void verify(int directory) {
    struct stat info;
    CHECK(fstatat(directory, "relative", &info, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(info.st_mode));
    CHECK(info.st_size == 5);
    CHECK(fstatat(directory, "relative", &info, 0) == 0 && S_ISREG(info.st_mode));
    CHECK(info.st_size == sizeof(pattern));
    char link[8]; memset(link, 0x55, sizeof(link));
    CHECK(readlinkat(directory, "relative", link, 3) == 3);
    CHECK(!memcmp(link, "lar", 3) && link[3] == 0x55);
    CHECK(syscall(SYS_readlinkat, directory, "relative", link, sizeof(link)) == 5);
    CHECK(!memcmp(link, "large", 5) && link[5] == 0x55);
    int fd = openat(directory, "relative", O_RDONLY);
    CHECK(fd >= 0);
    unsigned char data[8192]; size_t done = 0;
    while (done < sizeof(data)) {
        ssize_t n = read(fd, data + done, sizeof(data) - done);
        CHECK(n > 0); done += (size_t)n;
    }
    CHECK(!memcmp(data, pattern, sizeof(data)) && close(fd) == 0);
    for (unsigned i = 0; i < 70; ++i) {
        char name[16]; snprintf(name, sizeof(name), "entry%u", i);
        CHECK(fstatat(directory, name, &info, 0) == 0 && S_ISREG(info.st_mode));
    }
}
static void retained_capacity(int dir) {
    int fds[40]; unsigned count = 0; int full = 0;
    for (unsigned i = 0; i < 40 && !full; ++i) {
        char name[16]; snprintf(name, sizeof(name), "quota%u", i);
        int fd = openat(dir, name, O_CREAT | O_EXCL | O_RDWR, 0600);
        CHECK(fd >= 0); fds[count++] = fd;
        size_t written = 0;
        while (written < sizeof(pattern)) {
            ssize_t n = write(fd, pattern + written, sizeof(pattern) - written);
            if (n < 0) { CHECK(errno == ENOSPC); full = 1; break; }
            CHECK(n > 0); written += (size_t)n;
        }
    }
    CHECK(full && count > 1);
    int last = fds[count - 1];
    /* Fill the sub-1KiB remainder without assuming unrelated RAMFS contents. */
    for (size_t chunk = 512; chunk; chunk /= 2) {
        for (;;) {
            ssize_t n = write(last, pattern, chunk);
            if (n < 0) { CHECK(errno == ENOSPC); break; }
            CHECK(n > 0);
        }
    }
    struct stat before, after;
    CHECK(fstat(last, &before) == 0);
    errno = 0; CHECK(write(last, pattern, 1) == -1 && errno == ENOSPC);
    CHECK(fstat(last, &after) == 0 && after.st_size == before.st_size);
    CHECK(unlinkat(dir, "quota0", 0) == 0);
    errno = 0; CHECK(write(last, pattern, 1) == -1 && errno == ENOSPC);
    CHECK(close(fds[0]) == 0);
    int replacement = openat(dir, "reuse", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(replacement >= 0); put(replacement, pattern, sizeof(pattern));
    CHECK(fstat(replacement, &after) == 0 && after.st_size == sizeof(pattern));
    CHECK(close(replacement) == 0 && unlinkat(dir, "reuse", 0) == 0);
    for (unsigned i = 1; i < count; ++i) {
        char name[16]; snprintf(name, sizeof(name), "quota%u", i);
        CHECK(close(fds[i]) == 0 && unlinkat(dir, name, 0) == 0);
    }
    puts("FILESYSTEM_PROBE AGGREGATE_REJECT_PINNED_REUSE PASS");
}
static void node_capacity(int dir) {
    unsigned count = 0;
    for (; count < 128; ++count) {
        char name[20]; snprintf(name, sizeof(name), "capacity%u", count);
        int fd = openat(dir, name, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) { CHECK(errno == ENOSPC); break; }
        CHECK(close(fd) == 0);
    }
    CHECK(count > 0 && count < 128);
    CHECK(unlinkat(dir, "capacity0", 0) == 0);
    int fd = openat(dir, "node-reused", O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd >= 0 && close(fd) == 0 && unlinkat(dir, "node-reused", 0) == 0);
    for (unsigned i = 1; i < count; ++i) {
        char name[20]; snprintf(name, sizeof(name), "capacity%u", i);
        CHECK(unlinkat(dir, name, 0) == 0);
    }
    puts("FILESYSTEM_PROBE NODE_REJECT_REUSE PASS");
}
int main(int argc, char **argv) {
    for (unsigned i = 0; i < sizeof(pattern); ++i) pattern[i] = (unsigned char)(i * 31u + 7u);
    int recovery = argc == 2 && !strcmp(argv[1], "verify");
    CHECK(recovery || argc == 1);
    if (!recovery) CHECK(mkdir("/fs-links", 0700) == 0);
    int dir = open("/fs-links", O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 0);
    if (recovery) {
        verify(dir); CHECK(close(dir) == 0);
        puts("FILESYSTEM_PROBE RECOVERY PASS"); return 0;
    }
    int fd = openat(dir, "large", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0); put(fd, pattern, sizeof(pattern)); CHECK(close(fd) == 0);
    CHECK(symlink("/fs-links/large", "/fs-links/absolute") == 0);
    CHECK(syscall(SYS_symlinkat, "large", dir, "relative") == 0);
    char target[40] = {0};
    CHECK(readlink("/fs-links/absolute", target, sizeof(target)) == 15);
    CHECK(!memcmp(target, "/fs-links/large", 15));
    errno = 0; CHECK(syscall(SYS_readlinkat, dir, "relative", target, 0) == -1 && errno == EINVAL);
    errno = 0; CHECK(syscall(SYS_readlinkat, dir, "relative", 1, 4) == -1 && errno == EFAULT);
    errno = 0; CHECK(openat(dir, "relative", O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
    errno = 0; CHECK(openat(dir, "relative", O_CREAT | O_EXCL | O_WRONLY, 0600) == -1 && errno == EEXIST);
    CHECK(symlinkat("created", dir, "dangling") == 0);
    fd = openat(dir, "dangling", O_CREAT | O_WRONLY, 0600); CHECK(fd >= 0);
    put(fd, "ok", 2); CHECK(close(fd) == 0);
    CHECK(renameat(dir, "dangling", dir, "moved") == 0);
    CHECK(unlinkat(dir, "moved", 0) == 0);
    struct stat info;
    CHECK(fstatat(dir, "created", &info, 0) == 0 && info.st_size == 2);
    CHECK(symlinkat("cycle-b", dir, "cycle-a") == 0);
    CHECK(symlinkat("cycle-a", dir, "cycle-b") == 0);
    errno = 0; CHECK(openat(dir, "cycle-a", O_RDONLY) == -1 && errno == ELOOP);
    CHECK(unlinkat(dir, "cycle-a", 0) == 0 && unlinkat(dir, "cycle-b", 0) == 0);
    CHECK(mkdir("/fs-links/sub", 0700) == 0);
    CHECK(symlinkat("sub", dir, "directory") == 0);
    fd = open("/fs-links/directory/../relative", O_RDONLY); CHECK(fd >= 0 && close(fd) == 0);
    CHECK(symlinkat("/usr/share/X11/xkb/rules/evdev", dir, "boot") == 0);
    fd = openat(dir, "boot", O_RDONLY); CHECK(fd >= 0 && close(fd) == 0);
    errno = 0; CHECK(openat(dir, "boot", O_WRONLY) == -1 && errno == EACCES);
    CHECK(unlinkat(dir, "boot", 0) == 0);
    CHECK(symlinkat("/usr/share/X11/xkb/rules", dir, "assets") == 0);
    errno = 0; CHECK(mkdir("/fs-links/assets/evdev", 0700) == -1 && errno == EEXIST);
    CHECK(unlinkat(dir, "assets", 0) == 0);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0); CHECK(sock >= 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, "/fs-links/socket");
    CHECK(bind(sock, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(symlinkat("socket", dir, "socket-link") == 0);
    CHECK(unlinkat(dir, "socket-link", 0) == 0);
    CHECK(fstatat(dir, "socket", &info, 0) == 0 && S_ISSOCK(info.st_mode));
    CHECK(close(sock) == 0 && unlinkat(dir, "socket", 0) == 0);
    sock = socket(AF_UNIX, SOCK_STREAM, 0); CHECK(sock >= 0);
    CHECK(symlinkat("unused", dir, "bind-link") == 0);
    strcpy(address.sun_path, "/fs-links/bind-link");
    errno = 0; CHECK(bind(sock, (struct sockaddr *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    CHECK(close(sock) == 0 && unlinkat(dir, "bind-link", 0) == 0);
    retained_capacity(dir);
    for (unsigned i = 0; i < 70; ++i) {
        char name[16]; snprintf(name, sizeof(name), "entry%u", i);
        fd = openat(dir, name, O_CREAT | O_EXCL | O_WRONLY, 0600);
        CHECK(fd >= 0 && close(fd) == 0);
    }
    node_capacity(dir);
    verify(dir);
    CHECK(fsync(dir) == 0 && close(dir) == 0);
    puts("FILESYSTEM_PROBE LINKS_CAPACITY_DURABILITY PASS");
    return 0;
}
