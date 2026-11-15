/* Real target-musl socket-option ABI regression. SO_PEERPIDFD is optional in
 * zbus 5.16.0, which requires ENOPROTOOPT when the kernel does not provide it. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Linux x86_64/aarch64 UAPI; the pinned musl headers predate this option. */
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static int fail(const char *stage, int line) {
    printf("SOCKET_OPTIONS_PROBE FAIL stage=%s line=%d errno=%d\n",
           stage, line, errno);
    return 1;
}
#define CHECK(c, s) do { if (!(c)) return fail(s, __LINE__); } while (0)

static int integer_option(int fd, int option, int expected, int positive) {
    struct { int value; uint32_t guard; } out = {-1, 0xa5a5a5a5u};
    socklen_t length = sizeof out;
    CHECK(getsockopt(fd, SOL_SOCKET, option, &out, &length) == 0,
          "integer-option");
    CHECK(length == sizeof out.value && out.guard == 0xa5a5a5a5u,
          "integer-copyout");
    CHECK(positive ? out.value > 0 : out.value == expected, "integer-value");
    return 0;
}

static int supported_options(int fd) {
    if (integer_option(fd, SO_TYPE, SOCK_STREAM, 0) ||
        integer_option(fd, SO_ERROR, 0, 0) ||
        integer_option(fd, SO_SNDBUF, 0, 1) ||
        integer_option(fd, SO_RCVBUF, 0, 1)) return 1;
    int enabled = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) == 0,
          "reuseaddr-enable");
    enabled = 0;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) == 0,
          "reuseaddr-disable");
    return 0;
}

static int peer_credentials(int fd, pid_t expected_pid) {
    struct { struct ucred value; uint32_t guard; } out;
    memset(&out, 0xa5, sizeof out);
    socklen_t length = sizeof out;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &out, &length) == 0,
          "peer-credentials");
    CHECK(length == sizeof out.value && out.guard == 0xa5a5a5a5u,
          "peer-credentials-copyout");
    CHECK(out.value.pid == expected_pid && out.value.uid == geteuid() &&
          out.value.gid == getegid(), "peer-credentials-identity");
    return 0;
}

static int rejected_option(int fd, int writing, int level, int option,
                           int expected, const char *stage) {
    int value = 0x12345678;
    socklen_t length = sizeof value;
    errno = 0;
    int result = writing ? setsockopt(fd, level, option, &value, length)
                         : getsockopt(fd, level, option, &value, &length);
    int error = errno;
    if (result != -1 || error != expected) {
        printf("SOCKET_OPTIONS_PROBE FAIL stage=%s op=%s level=%d option=%d "
               "result=%d errno=%d expected=%d\n", stage, writing ? "set" : "get",
               level, option, result, error, expected);
        return 1;
    }
    CHECK(value == 0x12345678 && length == sizeof value, "rejection-no-copyout");
    return 0;
}

static int unsupported_options(int fd) {
    /* Keep this first: the unmodified guest reports ENOSYS (38), proving the
     * exact optional-feature fallback which zbus rejects. */
    if (rejected_option(fd, 0, SOL_SOCKET, SO_PEERPIDFD, ENOPROTOOPT,
                        "optional-peerpidfd")) return 1;
    puts("SOCKET_OPTIONS_PROBE OPTIONAL_PEERPIDFD PASS");
    const int unknown = 0x7fffffff;
    if (rejected_option(fd, 0, SOL_SOCKET, unknown, ENOPROTOOPT, "unknown-get") ||
        rejected_option(fd, 0, unknown, SO_TYPE, ENOPROTOOPT, "wrong-level-get") ||
        rejected_option(fd, 1, SOL_SOCKET, unknown, ENOPROTOOPT, "unknown-set") ||
        rejected_option(fd, 1, unknown, SO_REUSEADDR, ENOPROTOOPT, "wrong-level-set"))
        return 1;
    puts("SOCKET_OPTIONS_PROBE UNSUPPORTED_LEVEL_OPTIONS PASS");
    return 0;
}

static int copyout_and_faults(int fd) {
    unsigned char bytes[8];
    memset(bytes, 0xa5, sizeof bytes);
    socklen_t length = 1;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, bytes, &length) == 0 &&
          length == 1 && bytes[0] == SOCK_STREAM, "short-option-copyout");
    for (unsigned i = 1; i < sizeof bytes; ++i)
        CHECK(bytes[i] == 0xa5, "short-option-guard");
    memset(bytes, 0xa5, sizeof bytes);
    length = 0;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, bytes, &length) == 0 && length == 0,
          "zero-option-copyout");
    for (unsigned i = 0; i < sizeof bytes; ++i)
        CHECK(bytes[i] == 0xa5, "zero-option-guard");
    length = sizeof(int);
    errno = 0;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)(uintptr_t)1, &length) == -1 &&
          errno == EFAULT && length == sizeof(int), "invalid-option-pointer");
    errno = 0;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, bytes, (socklen_t *)(uintptr_t)1) == -1 &&
          errno == EFAULT, "invalid-length-pointer");
    if (rejected_option(-1, 0, SOL_SOCKET, SO_PEERPIDFD, EBADF, "bad-fd-get") ||
        rejected_option(-1, 1, SOL_SOCKET, SO_REUSEADDR, EBADF, "bad-fd-set"))
        return 1;
    puts("SOCKET_OPTIONS_PROBE COPYOUT_DESCRIPTOR_ERRORS PASS");
    return 0;
}

static int rejected_path_result(int result, int error, int expected,
                                const char *stage) {
    if (result != -1 || error != expected) {
        printf("SOCKET_OPTIONS_PROBE FAIL stage=%s result=%d errno=%d expected=%d\n",
               stage, result, error, expected);
        return 1;
    }
    return 0;
}

static int pathname_socket_cases(void) {
    static const char path[] = "/tmp/socket-options";
    static const char source[] = "/tmp/socket-options-file";
    static const char moved[] = "/tmp/socket-options-moved";
    static const char contents[] = "socket-namespace-kept\n";
    struct sockaddr_un address;
    struct stat original, current, file_info;
    int listener = -1, regular = -1, reader = -1, client = -1;
    int failed = 1;
    char bytes[sizeof contents];
    mode_t saved_mask = umask(0027);
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, sizeof path);
    socklen_t address_size = offsetof(struct sockaddr_un, sun_path) + sizeof path;

    /* Also remove a hidden directory left by the pre-fix mkdir collision. */
    rmdir(path);
    unlink(path);
    unlink(source);
    unlink(moved);
#define PATH_CHECK(c, s) do { if (!(c)) { fail(s, __LINE__); goto cleanup; } } while (0)
#define PATH_ERROR(call, expected, stage) do { \
    errno = 0; \
    int result = (call); \
    int error = errno; \
    if (rejected_path_result(result, error, expected, stage)) goto cleanup; \
} while (0)
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    PATH_CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address,
                                   address_size) == 0 && listen(listener, 1) == 0,
               "pathname-bind-listen");
    umask(saved_mask);
    PATH_CHECK(stat(path, &original) == 0 && S_ISSOCK(original.st_mode) &&
               (original.st_mode & 0777) == 0750 && original.st_ino != 0,
               "pathname-stat-umask");
    puts("SOCKET_OPTIONS_PROBE PATHNAME_BIND_STAT PASS");

    /* First behavioral RED: mkdir currently creates a hidden RAMFS directory
     * over a live binding. Both spellings must preserve the socket entry. */
    PATH_ERROR(mkdir(path, 0700), EEXIST, "pathname-mkdir-collision");
    PATH_ERROR(mkdir("/tmp/socket-options/", 0700), EEXIST,
               "pathname-mkdir-trailing-collision");
    regular = open(source, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    PATH_CHECK(regular >= 0 && write(regular, contents, sizeof contents - 1) ==
               (ssize_t)(sizeof contents - 1) && fstat(regular, &file_info) == 0,
               "pathname-regular-source");
    PATH_ERROR(rename(source, path), EOPNOTSUPP, "pathname-rename-over-socket");
    PATH_ERROR(rename(path, moved), EOPNOTSUPP, "pathname-rename-socket");
    PATH_CHECK(stat(source, &current) == 0 && S_ISREG(current.st_mode) &&
               current.st_ino == file_info.st_ino, "pathname-source-retained");
    reader = open(source, O_RDONLY | O_CLOEXEC);
    PATH_CHECK(reader >= 0 && read(reader, bytes, sizeof bytes) ==
               (ssize_t)(sizeof contents - 1) &&
               memcmp(bytes, contents, sizeof contents - 1) == 0 &&
               read(reader, bytes, 1) == 0, "pathname-source-content-retained");
    PATH_CHECK(close(reader) == 0, "pathname-reader-close");
    reader = -1;
    PATH_ERROR(stat(moved, &current), ENOENT, "pathname-rejected-rename-no-target");
    PATH_ERROR(open(path, O_RDONLY | O_CLOEXEC), ENXIO, "pathname-open-socket");
    PATH_ERROR(open(path, O_CREAT | O_EXCL | O_RDWR, 0600), EEXIST,
               "pathname-exclusive-open-socket");
    PATH_CHECK(chmod(path, 0600) == 0 && stat(path, &current) == 0 &&
               S_ISSOCK(current.st_mode) && (current.st_mode & 07777) == 0600 &&
               current.st_ino == original.st_ino, "pathname-chmod-real-mode");
    puts("SOCKET_OPTIONS_PROBE PATHNAME_MUTATIONS PASS");

    PATH_CHECK(close(listener) == 0, "pathname-listener-close");
    listener = -1;
    PATH_CHECK(stat(path, &current) == 0 && S_ISSOCK(current.st_mode) &&
               current.st_ino == original.st_ino &&
               (current.st_mode & 07777) == 0600, "pathname-closed-binding-stat");
    client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    PATH_CHECK(client >= 0, "pathname-closed-client");
    PATH_ERROR(connect(client, (struct sockaddr *)&address, address_size),
               ECONNREFUSED, "pathname-closed-connect");
    PATH_ERROR(mkdir(path, 0700), EEXIST, "pathname-closed-mkdir-collision");
    PATH_CHECK(close(client) == 0, "pathname-closed-client-close");
    client = -1;
    PATH_CHECK(unlink(path) == 0, "pathname-unlink-closed-binding");
    PATH_ERROR(stat(path, &current), ENOENT, "pathname-unlinked-stat");
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    PATH_CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address,
                                   address_size) == 0 && listen(listener, 1) == 0,
               "pathname-rebind-listen");
    PATH_CHECK(stat(path, &current) == 0 && S_ISSOCK(current.st_mode) &&
               current.st_ino != original.st_ino, "pathname-rebind-new-inode");
    PATH_CHECK(close(listener) == 0, "pathname-rebound-close");
    listener = -1;
    PATH_CHECK(unlink(path) == 0, "pathname-rebound-unlink");
    PATH_CHECK(rename(source, moved) == 0 && stat(moved, &current) == 0 &&
               S_ISREG(current.st_mode) && current.st_ino == file_info.st_ino,
               "pathname-regular-rename-preserved");
    PATH_CHECK(close(regular) == 0, "pathname-regular-close");
    regular = -1;
    PATH_CHECK(unlink(moved) == 0, "pathname-regular-unlink");
    puts("SOCKET_OPTIONS_PROBE PATHNAME_CLOSE_UNLINK_REBIND PASS");
    failed = 0;
cleanup:
    umask(saved_mask);
    if (listener >= 0) close(listener);
    if (regular >= 0) close(regular);
    if (reader >= 0) close(reader);
    if (client >= 0) close(client);
    rmdir(path);
    unlink(path);
    unlink(source);
    unlink(moved);
#undef PATH_ERROR
#undef PATH_CHECK
    return failed;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("SOCKET_OPTIONS_PROBE START");
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0,
          "socketpair");
    if (supported_options(pair[0]) || peer_credentials(pair[0], getpid()) ||
        peer_credentials(pair[1], getpid())) return 1;
    puts("SOCKET_OPTIONS_PROBE SUPPORTED_OPTIONS PASS");
    int alias = dup(pair[0]);
    CHECK(alias >= 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
          "peer-and-original-close");
    if (peer_credentials(alias, getpid())) return 1;
    puts("SOCKET_OPTIONS_PROBE PEER_SNAPSHOT_DUP_CLOSE PASS");
    if (unsupported_options(alias) || copyout_and_faults(alias) ||
        supported_options(alias) || peer_credentials(alias, getpid())) return 1;
    CHECK(close(alias) == 0, "close-alias");
    if (rejected_option(alias, 0, SOL_SOCKET, SO_PEERPIDFD, EBADF, "closed-fd-get"))
        return 1;
    if (pathname_socket_cases()) return 1;
    puts("SOCKET_OPTIONS_PROBE PASS");
    return 0;
}
