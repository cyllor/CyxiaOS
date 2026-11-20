/* The real wl_client_create called by panel's system Wayland backend. */
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wayland-server-core.h>

int main(void) {
    setbuf(stdout, 0);
    puts("WAYLAND_SERVER_PROBE START");
    struct wl_display *display = wl_display_create();
    if (!display) {
        printf("WAYLAND_SERVER_PROBE FAIL display errno=%d\n", errno);
        return 1;
    }
    int sockets[18][2];
    struct wl_client *clients[18];
    for (int i = 0; i < 18; ++i) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets[i])) {
            printf("WAYLAND_SERVER_PROBE FAIL socketpair index=%d errno=%d\n", i, errno);
            return 1;
        }
        clients[i] = wl_client_create(display, sockets[i][0]);
        if (!clients[i]) {
            printf("WAYLAND_SERVER_PROBE FAIL insert-client index=%d errno=%d\n", i, errno);
            return 1;
        }
    }
    puts("WAYLAND_SERVER_PROBE SOCKETPAIR PASS");
    puts("WAYLAND_SERVER_PROBE INSERT_CLIENT PASS");
    pid_t pid = 0; uid_t uid = 1; gid_t gid = 1;
    wl_client_get_credentials(clients[17], &pid, &uid, &gid);
    if (pid != getpid() || uid != getuid() || gid != getgid()) return 1;
    puts("WAYLAND_SERVER_PROBE CREDENTIALS PASS");
    for (int i = 0; i < 18; ++i) {
        wl_client_destroy(clients[i]);
        close(sockets[i][1]);
    }
    wl_display_destroy(display);
    puts("WAYLAND_SERVER_PROBE PASS");
    return 0;
}
