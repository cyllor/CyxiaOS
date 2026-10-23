/* CyxiaOS explicit static-ELF spawn ABI; this is not POSIX fork/exec. */
#ifndef CYXIA_SPAWN_H
#define CYXIA_SPAWN_H
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
struct cyxia_mapping { int32_t source, target; };
struct cyxia_spawn_request {
    uint32_t size, flags;
    const char *path;
    char *const *argv, *const *envp;
    const char *cwd;
    const struct cyxia_mapping *mappings;
    uint32_t mapping_count, reserved;
    uint64_t reserved2;
};
_Static_assert(sizeof(struct cyxia_spawn_request) == 64, "spawn ABI");
static inline pid_t cyxia_spawn(const char *path, char *const argv[], char *const env[],
                              const struct cyxia_mapping *maps, unsigned count) {
    struct cyxia_spawn_request r = {64, 0, path, argv, env, 0, maps, count, 0, 0};
    return syscall(0x43595810, &r);
}
#endif
