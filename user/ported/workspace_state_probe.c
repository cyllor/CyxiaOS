/* Read-only compositor state observer. Never activates workspaces or tiling. */
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "ext-workspace.h"
#include "cosmic-workspace.h"

/* Diagnostic storage bound, independent of production workspace capacity. */
enum { MAX_OBSERVED = 64 };
struct workspace {
    struct ext_workspace_handle_v1 *handle;
    struct zcosmic_workspace_handle_v2 *cosmic;
    char name[128];
    uint32_t state, tiling;
    int named, tiled, removed;
};
static struct workspace workspaces[MAX_OBSERVED];
static struct ext_workspace_group_handle_v1 *groups[MAX_OBSERVED];
static struct ext_workspace_manager_v1 *manager;
static struct zcosmic_workspace_manager_v2 *cosmic_manager;
static size_t count, group_count;
static int invalid, completed;

static void cosmic_capabilities(void *d, struct zcosmic_workspace_handle_v2 *h, uint32_t v) {
    (void)d; (void)h; (void)v;
}
static void cosmic_tiling(void *d, struct zcosmic_workspace_handle_v2 *h, uint32_t v) {
    (void)h; struct workspace *w = d; w->tiling = v; w->tiled = 1;
    if (v > 1) invalid = 1;
}
static void cosmic_state(void *d, struct zcosmic_workspace_handle_v2 *h, uint32_t v) {
    (void)d; (void)h; (void)v;
}
static const struct zcosmic_workspace_handle_v2_listener cosmic_listener = {
    cosmic_capabilities, cosmic_tiling, cosmic_state
};
static void attach(struct workspace *w) {
    if (!w->cosmic && cosmic_manager) {
        w->cosmic = zcosmic_workspace_manager_v2_get_cosmic_workspace(cosmic_manager, w->handle);
        zcosmic_workspace_handle_v2_add_listener(w->cosmic, &cosmic_listener, w);
    }
}
static void ws_id(void *d, struct ext_workspace_handle_v1 *h, const char *s) {
    (void)d; (void)h; (void)s;
}
static void ws_name(void *d, struct ext_workspace_handle_v1 *h, const char *s) {
    (void)h; struct workspace *w = d;
    if (!s || strlen(s) >= sizeof(w->name)) { invalid = 1; return; }
    strcpy(w->name, s); w->named = 1;
}
static void ws_coordinates(void *d, struct ext_workspace_handle_v1 *h, struct wl_array *a) {
    (void)d; (void)h; (void)a;
}
static void ws_state(void *d, struct ext_workspace_handle_v1 *h, uint32_t s) {
    (void)h; ((struct workspace *)d)->state = s;
}
static void ws_capabilities(void *d, struct ext_workspace_handle_v1 *h, uint32_t s) {
    (void)d; (void)h; (void)s;
}
static void ws_removed(void *d, struct ext_workspace_handle_v1 *h) {
    (void)h; ((struct workspace *)d)->removed = 1;
}
static const struct ext_workspace_handle_v1_listener ws_listener = {
    ws_id, ws_name, ws_coordinates, ws_state, ws_capabilities, ws_removed
};
static void group_caps(void *d, struct ext_workspace_group_handle_v1 *h, uint32_t s) {
    (void)d; (void)h; (void)s;
}
static void group_output(void *d, struct ext_workspace_group_handle_v1 *h, struct wl_output *o) {
    (void)d; (void)h; (void)o;
}
static void group_workspace(void *d, struct ext_workspace_group_handle_v1 *h, struct ext_workspace_handle_v1 *w) {
    (void)d; (void)h; (void)w;
}
static void group_removed(void *d, struct ext_workspace_group_handle_v1 *h) { (void)d; (void)h; }
static const struct ext_workspace_group_handle_v1_listener group_listener = {
    group_caps, group_output, group_output, group_workspace, group_workspace, group_removed
};
static void new_group(void *d, struct ext_workspace_manager_v1 *m, struct ext_workspace_group_handle_v1 *h) {
    (void)d; (void)m;
    if (group_count == MAX_OBSERVED) { invalid = 1; return; }
    groups[group_count++] = h;
    ext_workspace_group_handle_v1_add_listener(h, &group_listener, NULL);
}
static void new_workspace(void *d, struct ext_workspace_manager_v1 *m, struct ext_workspace_handle_v1 *h) {
    (void)d; (void)m;
    if (count == MAX_OBSERVED) { invalid = 1; return; }
    struct workspace *w = &workspaces[count++]; w->handle = h;
    ext_workspace_handle_v1_add_listener(h, &ws_listener, w); attach(w);
}
static void manager_done(void *d, struct ext_workspace_manager_v1 *m) { (void)d; (void)m; completed = 1; }
static void manager_finished(void *d, struct ext_workspace_manager_v1 *m) { (void)d; (void)m; invalid = 1; }
static const struct ext_workspace_manager_v1_listener manager_listener = {
    new_group, new_workspace, manager_done, manager_finished
};
static void global(void *d, struct wl_registry *r, uint32_t n, const char *interface, uint32_t version) {
    (void)d;
    if (!strcmp(interface, "ext_workspace_manager_v1") && !manager) {
        manager = wl_registry_bind(r, n, &ext_workspace_manager_v1_interface, 1);
        ext_workspace_manager_v1_add_listener(manager, &manager_listener, NULL);
    } else if (!strcmp(interface, "zcosmic_workspace_manager_v2") && !cosmic_manager && version >= 2) {
        cosmic_manager = wl_registry_bind(r, n, &zcosmic_workspace_manager_v2_interface, 2);
    }
}
static void global_removed(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = { global, global_removed };
static void synchronized(void *d, struct wl_callback *c, uint32_t serial) {
    (void)serial; *(int *)d = 1; wl_callback_destroy(c);
}
static const struct wl_callback_listener sync_listener = { synchronized };
static int64_t milliseconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int roundtrip(struct wl_display *display) {
    int done = 0; int64_t start = milliseconds();
    struct wl_callback *callback = wl_display_sync(display);
    if (start < 0 || !callback) return -1;
    wl_callback_add_listener(callback, &sync_listener, &done);
    while (!done) {
        if (wl_display_dispatch_pending(display) < 0 || invalid) return -1;
        if (done) break;
        if (wl_display_prepare_read(display)) continue;
        int flushed = wl_display_flush(display), blocked = flushed < 0 && errno == EAGAIN;
        if (flushed < 0 && !blocked) { wl_display_cancel_read(display); return -1; }
        int64_t now = milliseconds();
        if (now < start || now - start >= 5000) { wl_display_cancel_read(display); return -1; }
        struct pollfd fd = { wl_display_get_fd(display), POLLIN | (blocked ? POLLOUT : 0), 0 };
        int ready = poll(&fd, 1, (int)(5000 - (now - start)));
        if (ready < 0 && errno == EINTR) { wl_display_cancel_read(display); continue; }
        if (ready <= 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            wl_display_cancel_read(display); return -1;
        }
        if (fd.revents & POLLIN) {
            if (wl_display_read_events(display) < 0) return -1;
        } else wl_display_cancel_read(display);
    }
    return 0;
}

static int write_state_record(char *line, size_t size) {
    enum { CONSOLE_CHUNK = 64, MAX_VECTORS = 16 };
    struct iovec vectors[MAX_VECTORS];
    int count = 0;
    if (size == 0 || size > CONSOLE_CHUNK * MAX_VECTORS) return 0;

    // CPU0 handles the whole writev in one service turn, including the chunks
    // of long hex names. Keep every vector within the console write limit.
    for (size_t offset = 0; offset < size; offset += CONSOLE_CHUNK) {
        size_t remain = size - offset;
        vectors[count++] = (struct iovec){
            .iov_base = line + offset,
            .iov_len = remain < CONSOLE_CHUNK ? remain : CONSOLE_CHUNK,
        };
    }
    return writev(STDOUT_FILENO, vectors, count) == (ssize_t)size;
}

static int report_workspace(const struct workspace *w) {
    static const char hex[] = "0123456789abcdef";
    char name_hex[2 * sizeof(w->name) + 1];
    size_t used = 0;
    for (const unsigned char *s = (const unsigned char *)w->name; *s; s++) {
        name_hex[used++] = hex[*s >> 4];
        name_hex[used++] = hex[*s & 15];
    }
    name_hex[used] = '\0';
    char line[sizeof(name_hex) + 64];
    int size = snprintf(line, sizeof(line), "WORKSPACE_STATE workspace name_hex=%s active=%u tiling=%u\n",
                        name_hex, (unsigned)(w->state & 1), w->tiling);
    if (size <= 0 || (size_t)size >= sizeof(line)) return 0;
    return write_state_record(line, (size_t)size);
}

int main(void) {
    setbuf(stdout, NULL);
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) { puts("WORKSPACE_STATE FAIL connect"); return 1; }
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, NULL);
    for (int i = 0; i < 4; i++) {
        if (roundtrip(display)) { puts("WORKSPACE_STATE FAIL synchronization"); wl_display_disconnect(display); return 2; }
        for (size_t j = 0; j < count; j++) attach(&workspaces[j]);
    }
    unsigned live = 0, active = 0;
    for (size_t i = 0; i < count; i++) {
        struct workspace *w = &workspaces[i];
        if (w->removed) continue;
        if (!w->named || !w->tiled) invalid = 1;
        if (!report_workspace(w)) invalid = 1;
        live++; active += !!(w->state & 1);
    }
    int passed = !invalid && completed && manager && cosmic_manager && live && active == 1;
    char summary[64];
    int size = snprintf(summary, sizeof(summary), "WORKSPACE_STATE %s workspaces=%u active=%u\n",
                        passed ? "PASS" : "FAIL", live, active);
    if (size <= 0 || (size_t)size >= sizeof(summary) || !write_state_record(summary, (size_t)size)) {
        passed = 0;
    }
    wl_registry_destroy(registry);
    wl_display_disconnect(display);
    return passed ? 0 : 3;
}
