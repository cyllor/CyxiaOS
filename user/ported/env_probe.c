/* Minimal env-delivery probe: print whether the process environ carries the
 * kernel-supplied variables. Distinguishes "envp not delivered / environ not
 * initialised" (getenv NULL) from "dirs/cosmic-config logic" (getenv set). */
#include <stdio.h>
#include <stdlib.h>

extern char **environ;

int main(void)
{
    const char *keys[] = { "HOME", "PATH", "XDG_CONFIG_HOME", "XDG_STATE_HOME",
                           "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
                           "WAYLAND_DISPLAY", "LANG" };
    printf("ENV_PROBE BEGIN\n");
    int n = 0;
    if (environ) {
        for (char **e = environ; *e; ++e) ++n;
    }
    printf("ENV_PROBE environ_count=%d\n", n);
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *v = getenv(keys[i]);
        printf("ENV_PROBE %s=%s\n", keys[i], v ? v : "(null)");
    }
    printf("ENV_PROBE END\n");
    return 0;
}