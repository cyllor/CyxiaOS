/* Native CyxiaOS Linux-AArch64-persona probe; links only target musl. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static _Thread_local volatile unsigned tls_cookie = 0x43595849;

static int fail(const char *stage)
{
    printf("PORTED_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}

int main(int argc, char **argv)
{
    /* Force every progress record to reach the guest console immediately. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 1 || !argv[0] || tls_cookie != 0x43595849)
        return fail("startup-tls");
    printf("PORTED_PROBE START argc=%d argv0=%s\n", argc, argv[0]);

    errno = 0;
    int missing = open("/musl-probe-missing", O_RDONLY);
    if (missing != -1 || errno != ENOENT)
        return fail("errno");
    tls_cookie ^= 0x1234;
    if (tls_cookie != (0x43595849 ^ 0x1234) || errno != ENOENT)
        return fail("tls");
    printf("PORTED_PROBE TLS_ERRNO PASS\n");

    /* Above mallocng's MMAP_THRESHOLD: free unmaps a whole allocation. */
    for (unsigned pass = 0; pass < 3; ++pass) {
        const size_t size = 256 * 1024;
        unsigned char *bytes = malloc(size);
        if (!bytes) return fail("malloc");
        for (size_t i = 0; i < size; ++i)
            bytes[i] = (unsigned char)(i ^ pass);
        for (size_t i = 0; i < size; ++i)
            if (bytes[i] != (unsigned char)(i ^ pass))
                return fail("heap-content");
        free(bytes);
    }
    printf("PORTED_PROBE MALLOC_FREE PASS bytes=262144 cycles=3\n");

    const char payload[] = "CyxiaOS musl file IO\n";
    char actual[sizeof payload] = {0};
    int fd = open("/musl-probe.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return fail("open");
    if (write(fd, payload, sizeof payload - 1) != sizeof payload - 1)
        return fail("write");
    if (lseek(fd, 0, SEEK_SET) != 0) return fail("lseek");
    if (read(fd, actual, sizeof actual) != sizeof payload - 1 ||
        memcmp(actual, payload, sizeof payload - 1))
        return fail("read");
    if (close(fd)) return fail("close");
    printf("PORTED_PROBE FILE_IO PASS\n");

    volatile double x = 1.25, y = 2.5, z = 0.5;
    double result = x * y + z;
    if (result != 3.625) return fail("float");
    /* Floating printf exercises real musl vfprintf and compiler-rt quad ABI. */
    printf("PORTED_PROBE FLOAT PASS value=%.3f\n", result);
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return fail("clock");
    double live = 1.25;
    const double increment = 0.5;
    long long elapsed = 0;
    /* d0-equivalent stays live through an actual FP instruction loop, across
     * timer interrupts; the outer bound prevents hangs if the clock stalls. */
    for (unsigned chunk = 0; chunk < 1024 && elapsed < 50000000; ++chunk) {
        unsigned remaining = 65536;
        __asm__ volatile (
            "1: fadd %d0, %d0, %d2\n"
            "fsub %d0, %d0, %d2\n"
            "subs %w1, %w1, #1\n"
            "b.ne 1b"
            : "+w"(live), "+r"(remaining) : "w"(increment) : "cc");
        if (live != 1.25) return fail("fp-irq-state");
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return fail("clock");
        elapsed = (long long)(now.tv_sec - start.tv_sec) * 1000000000LL
                  + now.tv_nsec - start.tv_nsec;
    }
    if (elapsed < 50000000) return fail("fp-irq-duration");
    printf("PORTED_PROBE FP_IRQ PASS elapsed_ns=%lld\n", elapsed);
    printf("PORTED_PROBE PASS\n");
    return 0;
}
