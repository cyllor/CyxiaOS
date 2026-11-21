/* A real, bounded xdg window gives dynamic workspaces one occupied workspace.
 * It never sends workspace activation or tiling requests. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "xdg-shell.h"

static struct wl_compositor *compositor;
static struct wl_shm *shm;
static struct xdg_wm_base *wm;
static struct wl_surface *surface;
static struct wl_buffer *buffer;
static int configured, closed, xrgb;
static void format(void *d, struct wl_shm *s, uint32_t f) { (void)d; (void)s; xrgb |= f == WL_SHM_FORMAT_XRGB8888; }
static const struct wl_shm_listener shm_listener = { format };
static void released(void *d, struct wl_buffer *b) { (void)d; (void)b; }
static const struct wl_buffer_listener buffer_listener = { released };
static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) _exit(6);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static void ping(void *d, struct xdg_wm_base *w, uint32_t serial) { (void)d; xdg_wm_base_pong(w, serial); }
static const struct xdg_wm_base_listener wm_listener = { ping };
static void global(void *d, struct wl_registry *r, uint32_t name, const char *interface, uint32_t version) {
    (void)d;
    if (!strcmp(interface, "wl_compositor")) compositor = wl_registry_bind(r, name, &wl_compositor_interface, version < 4 ? version : 4);
    else if (!strcmp(interface, "wl_shm")) {
        shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
        wl_shm_add_listener(shm, &shm_listener, NULL);
    }
    else if (!strcmp(interface, "xdg_wm_base")) {
        wm = wl_registry_bind(r, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(wm, &wm_listener, NULL);
    }
}
static void removed(void *d, struct wl_registry *r, uint32_t name) { (void)d; (void)r; (void)name; }
static const struct wl_registry_listener registry_listener = { global, removed };
static void configure(void *d, struct xdg_surface *xdg, uint32_t serial) {
    (void)d; xdg_surface_ack_configure(xdg, serial);
    if (!configured) {
        wl_surface_attach(surface, buffer, 0, 0);
        wl_surface_damage(surface, 0, 0, 160, 100);
        configured = 1;
    }
    wl_surface_commit(surface);
}
static const struct xdg_surface_listener surface_listener = { configure };
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s) {
    (void)d; (void)t; (void)w; (void)h; (void)s;
}
static void close_window(void *d, struct xdg_toplevel *t) { (void)d; (void)t; closed = 1; }
static void bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)d; (void)t; (void)w; (void)h; }
static void capabilities(void *d, struct xdg_toplevel *t, struct wl_array *a) { (void)d; (void)t; (void)a; }
static const struct xdg_toplevel_listener toplevel_listener = { toplevel_configure, close_window, bounds, capabilities };
static int dispatch(struct wl_display *display) {
    if (wl_display_dispatch_pending(display) < 0) return -1;
    if (wl_display_prepare_read(display)) return 0;
    int flush = wl_display_flush(display), blocked = flush < 0 && errno == EAGAIN;
    if (flush < 0 && !blocked) { wl_display_cancel_read(display); return -1; }
    struct pollfd fd = { wl_display_get_fd(display), POLLIN | (blocked ? POLLOUT : 0), 0 };
    int ready = poll(&fd, 1, 1000);
    if (ready < 0 && errno == EINTR) { wl_display_cancel_read(display); return 0; }
    if (ready < 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL))) { wl_display_cancel_read(display); return -1; }
    if (ready && (fd.revents & POLLIN)) return wl_display_read_events(display);
    wl_display_cancel_read(display); return 0;
}
int main(int argc, char **argv) {
    // The application library can still be redrawing and closing its overlay
    // while the new client is connecting on the software-rendered TCG guest.
    int startup_ms = argc == 2 && !strcmp(argv[1], "--app-library") ? 20000 : 5000;
    setbuf(stdout, NULL);
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) { puts("WORKSPACE_WINDOW FAIL connect"); return 1; }
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, NULL);
    int64_t start = milliseconds();
    while ((!compositor || !shm || !wm || !xrgb) && milliseconds() - start < startup_ms) {
        if (dispatch(display) < 0) return 2;
    }
    if (!compositor || !shm || !wm || !xrgb) { puts("WORKSPACE_WINDOW FAIL globals"); return 2; }
    int fd = memfd_create("workspace-window", MFD_CLOEXEC);
    enum { BYTES = 160 * 100 * 4 };
    if (fd < 0 || ftruncate(fd, BYTES)) return 3;
    uint32_t *pixels = mmap(NULL, BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pixels == MAP_FAILED) return 3;
    for (unsigned y = 0; y < 100; y++) for (unsigned x = 0; x < 160; x++)
        pixels[y * 160 + x] = 0xff000000u | ((x / 20 + y / 20) % 2 ? 0x306080u : 0x80b0d0u);
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, BYTES);
    buffer = wl_shm_pool_create_buffer(pool, 0, 160, 100, 640, WL_SHM_FORMAT_XRGB8888);
    wl_buffer_add_listener(buffer, &buffer_listener, NULL);
    wl_shm_pool_destroy(pool); close(fd);
    surface = wl_compositor_create_surface(compositor);
    struct xdg_surface *xdg = xdg_wm_base_get_xdg_surface(wm, surface);
    xdg_surface_add_listener(xdg, &surface_listener, NULL);
    struct xdg_toplevel *toplevel = xdg_surface_get_toplevel(xdg);
    xdg_toplevel_add_listener(toplevel, &toplevel_listener, NULL);
    xdg_toplevel_set_title(toplevel, "Workspace regression window");
    xdg_toplevel_set_app_id(toplevel, "cyxia-workspace-window-probe");
    xdg_toplevel_set_min_size(toplevel, 160, 100); xdg_toplevel_set_max_size(toplevel, 160, 100);
    wl_surface_commit(surface);
    start = milliseconds(); int announced = 0;
    while (!closed && milliseconds() - start < 180000) {
        if (dispatch(display) < 0) { puts("WORKSPACE_WINDOW FAIL dispatch"); return 4; }
        if (configured && !announced) { wl_display_flush(display); puts("WORKSPACE_WINDOW READY"); announced = 1; }
        if (!configured && milliseconds() - start >= startup_ms) { puts("WORKSPACE_WINDOW FAIL configure"); return 4; }
    }
    xdg_toplevel_destroy(toplevel); xdg_surface_destroy(xdg); wl_surface_destroy(surface);
    wl_buffer_destroy(buffer); munmap(pixels, BYTES); wl_registry_destroy(registry); wl_display_disconnect(display);
    puts("WORKSPACE_WINDOW DONE"); return announced ? 0 : 5;
}
