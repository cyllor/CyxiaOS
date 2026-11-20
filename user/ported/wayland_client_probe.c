#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <wayland-client.h>

// An idle second thread makes this a MULTI-thread client process, to test
// cross-process wayland readiness wake with >1 thread (1-thread version PASSed).
static void *idle_thread(void *arg) {
    (void)arg;
    for (;;) sleep(3600);
    return NULL;
}

static void raw_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("WLCLIENT raw %s r=%d errno=%d\n", path, r, errno);
    close(fd);
}

static int globals;

static void registry_global(void *data, struct wl_registry *registry,
                            uint32_t name, const char *interface, uint32_t version) {
    (void)data; (void)registry; (void)name; (void)interface; (void)version;
    globals++;
}

static const struct wl_registry_listener registry_listener = {
    registry_global, NULL
};

int main(void) {
    setbuf(stdout, NULL);
    puts("WLCLIENT start");
    pthread_t idle;
    pthread_create(&idle, NULL, idle_thread, NULL);
    puts("WLCLIENT idle_thread_spawned");
    printf("WLCLIENT env XDG_RUNTIME_DIR=%s WAYLAND_DISPLAY=%s\n",
           getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "(null)",
           getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(null)");
    raw_connect("/run/user/0/wayland-0");
    raw_connect("/run/user/0/wayland-1");
    raw_connect("/run/user/0/bus");
    struct wl_display *display = NULL;
    const char *names[] = { "wayland-0", "wayland-1", "wayland-2", "wayland-3" };
    for (int i = 0; i < 4 && !display; i++) {
        display = wl_display_connect(names[i]);
        if (display) printf("WLCLIENT connected name=%s\n", names[i]);
    }
    if (!display) {
        printf("WLCLIENT connect_fail errno=%d\n", errno);
        return 1;
    }
    struct wl_registry *registry = wl_display_get_registry(display);
    if (!registry || wl_registry_add_listener(registry, &registry_listener, NULL)) {
        puts("WLCLIENT registry_fail");
        return 1;
    }
    int first = wl_display_roundtrip(display);
    printf("WLCLIENT roundtrip1=%d globals=%d\n", first, globals);
    int second = wl_display_roundtrip(display);
    printf("WLCLIENT roundtrip2=%d\n", second);
    wl_registry_destroy(registry);
    wl_display_disconnect(display);
    puts("WLCLIENT PASS");
    return 0;
}