/* Real musl ABI checks for the services consumed by the Openbox port. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int fail(const char *stage) {
    printf("DESKTOP_API_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}
static int identities(void) {
    const long calls[] = {SYS_getresuid, SYS_getresgid};
    const uint64_t untouched = UINT64_C(0xfeedbeefcafebabe);
    const uint64_t written = UINT64_C(0xfeedbeef00000000);
    uid_t real_user, effective_user, saved_user;
    gid_t real_group, effective_group, saved_group;
    if (getresuid(&real_user, &effective_user, &saved_user) ||
        getresgid(&real_group, &effective_group, &saved_group) ||
        real_user || effective_user || saved_user || real_group || effective_group || saved_group)
        return fail("identity-libc");
    for (unsigned call = 0; call < sizeof calls / sizeof calls[0]; ++call) {
        uint64_t ids[3] = {untouched, untouched, untouched};
        if (syscall(calls[call], &ids[0], &ids[1], &ids[2]) ||
            ids[0] != written || ids[1] != written || ids[2] != written)
            return fail("identity-width");
        for (unsigned bad = 0; bad < 3; ++bad) {
            for (unsigned i = 0; i < 3; ++i) ids[i] = untouched;
            errno = 0;
            if (syscall(calls[call], bad == 0 ? NULL : &ids[0],
                        bad == 1 ? NULL : &ids[1], bad == 2 ? NULL : &ids[2]) != -1 || errno != EFAULT)
                return fail("identity-fault");
            for (unsigned i = 0; i < 3; ++i)
                if (ids[i] != (i < bad ? written : untouched))
                    return fail("identity-copy-order");
        }
    }
    puts("DESKTOP_API_PROBE IDENTITY PASS");
    return 0;
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (identities()) return 1;
    int counter = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (counter < 0) return fail("eventfd");
    uint64_t value = 7, received = 0;
    struct pollfd p = {counter, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, 0) != 1 || p.revents != POLLOUT) return fail("empty-poll");
    if (eventfd_write(counter, value)) return fail("event-write");
    errno = 0;
    if (syscall(SYS_read, counter, 0, 8) != -1 || errno != EFAULT) return fail("event-bad-pointer");
    int alias = dup(counter);
    if (alias < 0 || close(counter)) return fail("event-dup");
    struct iovec vectors[2] = {{&received, 3}, {(char *)&received + 3, 5}};
    if (readv(alias, vectors, 2) != 8 || received != 7) return fail("event-readv");
    value = 9;
    vectors[0].iov_base = &value; vectors[1].iov_base = (char *)&value + 3;
    errno = 0;
    if (writev(alias, vectors, 2) != -1 || errno != EINVAL) return fail("event-writev-short");
    vectors[0].iov_len = 8; vectors[1].iov_len = 8; vectors[1].iov_base = &value;
    if (writev(alias, vectors, 2) != 16 || eventfd_read(alias, &received) || received != 18)
        return fail("event-writev");
    vectors[1].iov_len = 4;
    if (writev(alias, vectors, 2) != 8 || eventfd_read(alias, &received) || received != 9)
        return fail("event-writev-partial");
    vectors[0].iov_len = 0; vectors[1].iov_len = 0;
    if (readv(alias, vectors, 2) || writev(alias, vectors, 2)) return fail("event-empty-vectors");
    errno = 0;
    if (write(alias, vectors, 16) != -1 || errno != EINVAL) return fail("event-oversize");
    errno = 0;
    if (eventfd_read(alias, &received) != -1 || errno != EAGAIN) return fail("event-drain");
    if (close(alias)) return fail("event-close");
    puts("DESKTOP_API_PROBE EVENT PASS");

    if (mkdir("/api-dir", 0700) || chdir("/api-dir")) return fail("directory-create");
    char cwd[96];
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/api-dir")) return fail("cwd");
    int dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return fail("directory-open");
    int file = openat(dir, "child", O_CREAT | O_RDWR, 0600);
    if (file < 0 || write(file, "child", 5) != 5 || close(file)) return fail("openat");
    struct stat status;
    if (fstatat(dir, "child", &status, 0) || status.st_size != 5 || !S_ISREG(status.st_mode))
        return fail("fstatat");
    DIR *stream = fdopendir(dir);
    if (!stream) return fail("fdopendir");
    unsigned found = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(stream))) {
        if (!strcmp(entry->d_name, ".")) found |= 1;
        if (!strcmp(entry->d_name, "..")) found |= 2;
        if (!strcmp(entry->d_name, "child")) found |= 4;
    }
    if (errno || found != 7) return fail("readdir");
    rewinddir(stream);
    if (!(entry = readdir(stream)) || strcmp(entry->d_name, ".")) return fail("rewinddir");
    if (closedir(stream) || chdir("/")) return fail("directory-close");
    stream = opendir("/usr/share/fonts");
    if (!stream) return fail("font-dir");
    found = 0;
    while ((entry = readdir(stream))) if (!strcmp(entry->d_name, "Roboto-Regular.ttf")) found++;
    if (found != 1 || closedir(stream)) return fail("boot-font-entry");
    if (unlink("/api-dir/child") || rmdir("/api-dir")) return fail("directory-cleanup");
    puts("DESKTOP_API_PROBE DIRECTORY PASS");
    puts("DESKTOP_API_PROBE PASS");
    return 0;
}
