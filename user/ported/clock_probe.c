/* Real board RTC and architectural timer, without a fabricated wall epoch. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { printf("CLOCK_PROBE FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct timespec wall, mono, wall_end, mono_end, resolution;
    struct timeval tv;
    CHECK(clock_gettime(CLOCK_REALTIME, &wall) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &mono) == 0);
    CHECK(gettimeofday(&tv, NULL) == 0);
    CHECK(tv.tv_sec >= wall.tv_sec && tv.tv_sec <= wall.tv_sec + 1);
    CHECK(wall.tv_sec > 0 && wall.tv_nsec == 0 && tv.tv_usec == 0);
    CHECK(clock_getres(CLOCK_REALTIME, &resolution) == 0);
    CHECK(resolution.tv_sec == 1 && resolution.tv_nsec == 0);
    CHECK(clock_getres(CLOCK_MONOTONIC, &resolution) == 0);
    CHECK(resolution.tv_sec == 0 && resolution.tv_nsec > 0);
    CHECK(clock_getres(CLOCK_REALTIME, NULL) == 0);
    errno = 0;
    CHECK(syscall(SYS_clock_gettime, CLOCK_REALTIME, (void *)1) == -1 && errno == EFAULT);
    errno = 0;
    CHECK(clock_gettime(9999, &wall_end) == -1 && errno == EINVAL);
    struct timespec delay = {.tv_sec=1, .tv_nsec=200000000};
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(clock_gettime(CLOCK_REALTIME, &wall_end) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &mono_end) == 0);
    long long elapsed = (mono_end.tv_sec-mono.tv_sec)*1000000000LL + mono_end.tv_nsec-mono.tv_nsec;
    CHECK(elapsed >= 1200000000LL);
    CHECK(wall_end.tv_sec >= wall.tv_sec + 1);
    printf("CLOCK_PROBE RTC seconds=%lld monotonic_ns=%lld\n", (long long)wall_end.tv_sec, elapsed);
    puts("CLOCK_PROBE PASS");
    return 0;
}
