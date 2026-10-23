/* Real musl calls exercising the bounded desktop RAMFS, not disk persistence. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FILE_PROBE FAIL line=%d errno=%d\n",__LINE__,errno); return 1; } } while (0)

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(mkdir("/files-probe", 0700) == 0);
    int directory = open("/files-probe", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    const char *name = "新建 文本.txt";
    int source = openat(directory, name, O_CREAT | O_EXCL | O_RDWR, 0600);
    int old = openat(directory, "saved file.txt", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(source >= 0 && old >= 0 && write(old, "old", 3) == 3);
    unsigned char bytes[4096], readback[4096];
    for (unsigned i=0; i<sizeof bytes; ++i) bytes[i] = (unsigned char)(i*17U+3U);
    size_t written = 0;
    while (written < sizeof bytes) {
        ssize_t n = write(source, bytes+written, sizeof bytes-written);
        CHECK(n > 0); written += (size_t)n;
    }
    CHECK(write(source,"!",1) == -1 && errno == EFBIG);
    struct stat before, after;
    CHECK(fstat(source,&before) == 0 && before.st_size == 4096);
    CHECK(syscall(SYS_renameat2,directory,name,directory,"saved file.txt",1) == -1 && errno == EEXIST);
    CHECK(renameat(directory,name,directory,"saved file.txt") == 0);
    CHECK(fstatat(directory,name,&after,0) == -1 && errno == ENOENT);
    CHECK(fstatat(directory,"saved file.txt",&after,0) == 0 && after.st_ino == before.st_ino);
    CHECK(fstat(old,&after) == 0 && after.st_nlink == 0 && after.st_size == 3);
    CHECK(lseek(old,0,SEEK_SET) == 0 && read(old,readback,3) == 3 && !memcmp(readback,"old",3));
    CHECK(lseek(source,0,SEEK_SET) == 0);
    size_t received = 0;
    while (received < sizeof readback) {
        ssize_t n = read(source,readback+received,sizeof readback-received);
        CHECK(n > 0); received += (size_t)n;
    }
    CHECK(!memcmp(bytes,readback,sizeof bytes));
    puts("FILE_PROBE RENAME PASS");
    CHECK(renameat(directory,"saved file.txt",directory,"saved file.txt") == 0);
    CHECK(syscall(SYS_renameat2,directory,"saved file.txt",directory,"other",2) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_renameat,directory,0,directory,"other") == -1 && errno == EFAULT);
    CHECK(renameat(directory,"saved file.txt",AT_FDCWD,"/etc/passwd") == -1 && errno == EROFS);
    CHECK(renameat(AT_FDCWD,"/etc/passwd",directory,"other") == -1 && errno == EROFS);
    CHECK(fchmod(directory,0500) == 0);
    CHECK(renameat(directory,"saved file.txt",directory,"other") == -1 && errno == EACCES);
    CHECK(fchmod(directory,0700) == 0);
    CHECK(fstatat(directory,"saved file.txt",&after,0) == 0 && after.st_ino == before.st_ino);
    puts("FILE_PROBE ATOMIC_ERRORS PASS");
    CHECK(close(old) == 0 && close(source) == 0);
    CHECK(unlink("/files-probe/saved file.txt") == 0);
    CHECK(close(directory) == 0 && rmdir("/files-probe") == 0);
    puts("FILE_PROBE PASS");
    return 0;
}
