/* Real target-musl durability calls; reboot verification reads the committed
 * file from the actual VirtIO snapshot. No host filesystem stand-in. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static const char staged[] = "/tmp/fsync-staged";
static const char durable[] = "/tmp/fsync-durable";
static const char contents[] = "fsync-durable-v1\n";

static int fail(const char *stage, int line) {
    printf("FSYNC_PROBE FAIL stage=%s line=%d errno=%d\n", stage, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)

static int rejected(int fd, int data_only, int expected, const char *stage) {
    errno = 0;
    int result = data_only ? fdatasync(fd) : fsync(fd);
    int error = errno;
    if (result != -1 || error != expected) {
        printf("FSYNC_PROBE FAIL stage=%s result=%d errno=%d expected=%d\n",
               stage, result, error, expected);
        return 1;
    }
    return 0;
}

static int sync_directory(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0 && fsync(fd) == 0 && close(fd) == 0, "directory-sync");
    return 0;
}

static int read_durable(void) {
    char actual[sizeof contents];
    int fd = open(durable, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0, "durable-open");
    size_t used = 0;
    while (used < sizeof contents - 1) {
        ssize_t size = read(fd, actual + used, sizeof contents - 1 - used);
        CHECK(size > 0, "durable-read");
        used += (size_t)size;
    }
    CHECK(memcmp(actual, contents, used) == 0 && read(fd, actual, 1) == 0 &&
          close(fd) == 0, "durable-content");
    errno = 0;
    fd = open(staged, O_RDONLY | O_CLOEXEC);
    CHECK(fd == -1 && errno == ENOENT, "rename-staged-absent");
    return 0;
}

static int descriptor_cases(void) {
    if (rejected(-1, 0, EBADF, "bad-fsync-fd") ||
        rejected(-1, 1, EBADF, "bad-fdatasync-fd")) return 1;
    int pipefd[2], sockets[2];
    CHECK(pipe2(pipefd, O_CLOEXEC) == 0 &&
          socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0,
          "nonfile-descriptors");
    if (rejected(pipefd[0], 0, EINVAL, "pipe-fsync") ||
        rejected(pipefd[1], 1, EINVAL, "pipe-fdatasync") ||
        rejected(sockets[0], 0, EINVAL, "socket-fsync")) return 1;
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0 &&
          close(sockets[0]) == 0 && close(sockets[1]) == 0, "nonfile-close");
    int memfd = memfd_create("fsync-volatile", MFD_CLOEXEC);
    CHECK(memfd >= 0 && write(memfd, "ram", 3) == 3 &&
          fsync(memfd) == 0 && fdatasync(memfd) == 0 && close(memfd) == 0,
          "memfd-no-persistent-backing");
    int asset = open("/bin/fsync-probe", O_RDONLY | O_CLOEXEC);
    CHECK(asset >= 0 && fsync(asset) == 0 && fdatasync(asset) == 0 && close(asset) == 0,
          "immutable-boot-asset");
    if (rejected(asset, 0, EBADF, "closed-fd")) return 1;
    puts("FSYNC_PROBE DESCRIPTOR_CASES PASS");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("FSYNC_PROBE START");
    if (argc == 2 && !strcmp(argv[1], "verify")) {
        if (read_durable()) return 1;
        puts("FSYNC_PROBE RECOVERED PASS");
    } else if (argc == 2 && !strcmp(argv[1], "sync-root")) {
        if (sync_directory("/")) return 1;
        puts("FSYNC_PROBE ROOT_DURABLE PASS");
    } else {
        CHECK(argc == 1, "arguments");
        int fd = open(staged, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
        CHECK(fd >= 0 && write(fd, contents, sizeof contents - 1) == sizeof contents - 1,
              "staged-write");
        CHECK(fsync(fd) == 0, "file-fsync");
        CHECK(fdatasync(fd) == 0 && close(fd) == 0, "file-fdatasync");
        CHECK(rename(staged, durable) == 0, "atomic-rename");
        if (sync_directory("/tmp") || read_durable()) return 1;
        puts("FSYNC_PROBE FILE_RENAME_DIRECTORY PASS");
        if (descriptor_cases()) return 1;
        /* The current durable service snapshots the whole RAMFS. This final
         * explicit sync also includes an earlier dbus-uuidgen /etc rename. */
        if (sync_directory("/")) return 1;
        puts("FSYNC_PROBE ROOT_DURABLE PASS");
    }
    puts("FSYNC_PROBE PASS");
    return 0;
}
