#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>

/* Independent pathname-connected clients. The server learns process identity
 * from SO_PEERCRED, never from the fixture role or an inherited socket. */
enum { MAX_FRAMES = 4, EVENT_TIMEOUT_MS = 30000, KEYMAP_LIMIT = 65536 };

struct client {
    unsigned id, phase, formats, callbacks, releases;
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_surface *surface;
    struct xdg_wm_base *wm_base;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    unsigned configures, acks, closed, pending_configure, painted, work;
    uint32_t serial;
    int32_t width, height;
    struct xkb_context *xkb_context;
    struct xkb_keymap *keymap;
    struct xkb_state *xkb_state;
    bool keyboard_focus, input_down, activated, pending_activated;
    bool paint_pending, abrupt;
    unsigned input_complete, keymaps, key_events;
    unsigned keyboard_enters, keyboard_leaves, closing_keyboard_leaves;
    uint32_t received_code;
};

struct frame {
    struct client *client;
    unsigned phase, done, released;
    struct wl_buffer *buffer;
    uint32_t *pixels;
    size_t size;
};

/* The native console accepts at most 64 bytes per syscall. Every receipt is
 * bounded to that size and written once so concurrent processes cannot splice
 * their records between a prefix and its continuation. */
static void emit(const char *format, ...) {
    char line[65];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (length <= 0 || (size_t)length >= sizeof(line)) _exit(2);
    ssize_t result;
    do {
        result = write(STDOUT_FILENO, line, (size_t)length);
    } while (result < 0 && errno == EINTR);
    if (result != length) _exit(2);
}

static void fail(const char *why) {
    const int error = errno;
    emit("DYN_CLIENT FAIL pid=%d err=%d\n", getpid(), error);
    emit("DYN_CLIENT REASON %.40s\n", why);
    exit(1);
}

#define CHECK(condition, why) do { if (!(condition)) fail(why); } while (0)

static int64_t monotonic_ms(void) {
    struct timespec now = {0};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Respect libwayland's prepare/read/cancel contract, including pending events
 * and output backpressure. A stalled server cannot make this client wait forever. */
static void wait_counter(struct client *client, const unsigned *counter, const char *why) {
    const int64_t deadline = monotonic_ms() + EVENT_TIMEOUT_MS;
    while (!*counter) {
        while (wl_display_prepare_read(client->display) != 0) {
            CHECK(wl_display_dispatch_pending(client->display) >= 0, "pending events");
            if (*counter) return;
            CHECK(monotonic_ms() < deadline, why);
        }
        int flush = wl_display_flush(client->display);
        if (flush < 0 && errno != EAGAIN) {
            wl_display_cancel_read(client->display);
            fail("flush");
        }
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            wl_display_cancel_read(client->display);
            fail(why);
        }
        struct pollfd descriptor = {
            .fd = wl_display_get_fd(client->display), .events = POLLIN | (flush < 0 ? POLLOUT : 0),
        };
        int result = poll(&descriptor, 1, (int)remaining);
        if (result < 0) {
            wl_display_cancel_read(client->display);
            if (errno == EINTR) continue;
            fail("poll");
        }
        if (result && (descriptor.revents & POLLIN)) {
            CHECK(wl_display_read_events(client->display) >= 0, "read events");
        } else {
            wl_display_cancel_read(client->display);
            CHECK(result > 0, why);
            CHECK(!(descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)), "display disconnected");
        }
        CHECK(wl_display_dispatch_pending(client->display) >= 0, "dispatch events");
    }
}

static void sync_done(void *data, struct wl_callback *callback, uint32_t serial) {
    (void)serial;
    unsigned *done = data;
    CHECK((*done)++ == 0, "duplicate sync");
    wl_callback_destroy(callback);
}

static const struct wl_callback_listener sync_listener = {.done = sync_done};

static void synchronize(struct client *client) {
    unsigned done = 0;
    struct wl_callback *callback = wl_display_sync(client->display);
    CHECK(callback && wl_callback_add_listener(callback, &sync_listener, &done) == 0, "sync listener");
    wait_counter(client, &done, "sync timeout");
    CHECK(done == 1, "sync count");
}

static void keymap(void *data, struct wl_keyboard *keyboard, uint32_t format,
                   int fd, uint32_t size) {
    (void)keyboard;
    struct client *client = data;
    CHECK(format == WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 && fd >= 0 &&
          size > 1 && size <= KEYMAP_LIMIT && client->keymaps == 0, "keymap metadata");
    char *text = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(text != MAP_FAILED && text[size - 1] == '\0', "keymap mapping");
    client->keymap = xkb_keymap_new_from_string(client->xkb_context, text,
        XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
    CHECK(munmap(text, size) == 0 && close(fd) == 0, "keymap mapping close");
    CHECK(client->keymap, "real keymap parse");
    client->xkb_state = xkb_state_new(client->keymap);
    CHECK(client->xkb_state, "real keymap state");
    client->keymaps++;
    emit("DYN_CLIENT KEYMAP id=%u bytes=%u\n", client->id, size);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface, struct wl_array *keys) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->xkb_state && !client->keyboard_focus &&
          keys->size == 0 && !client->closed && !client->abrupt &&
          client->keyboard_enters < (client->id == 1 ? 3u : 1u), "keyboard enter focus/order");
    client->keyboard_focus = true;
    emit("DYN_CLIENT K_ENTER id=%u n=%u\n", client->id, client->keyboard_enters++);
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->keyboard_focus && !client->input_down &&
          !client->abrupt, "keyboard leave focus/order");
    unsigned *count = client->closed ? &client->closing_keyboard_leaves : &client->keyboard_leaves;
    CHECK(*count < (client->closed ? 1u : 2u) && (client->closed || client->id == 1),
          "unexpected keyboard leave");
    client->keyboard_focus = false;
    emit("DYN_CLIENT K_LEAVE id=%u n=%u closing=%u\n",
         client->id, (*count)++, client->closed != 0);
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                         uint32_t time, uint32_t code, uint32_t state) {
    (void)keyboard; (void)time;
    struct client *client = data;
    const unsigned frames = client->id == 1 ? 4u : 2u;
    const bool health = client->painted < frames;
    const uint32_t expected_code = health ? 32u : client->id == 3 ? 45u : 16u;
    const xkb_keysym_t expected = health ? XKB_KEY_d : client->id == 3 ? XKB_KEY_x : XKB_KEY_q;
    CHECK(serial != 0 && client->keyboard_focus && client->activated && client->xkb_state &&
          !client->closed && !client->abrupt && client->painted == client->callbacks &&
          client->painted > 0 && code == expected_code &&
          xkb_state_key_get_one_sym(client->xkb_state, code + 8) == expected,
          "key identity/translation/focus");
    if (state == WL_KEYBOARD_KEY_STATE_PRESSED) {
        CHECK(!client->input_down && !client->input_complete, "duplicate key press");
        client->input_down = true;
    } else {
        CHECK(state == WL_KEYBOARD_KEY_STATE_RELEASED && client->input_down && !client->input_complete,
              "key release ordering");
        client->input_down = false;
        client->input_complete = 1;
        client->received_code = code;
        if (health) {
            CHECK(!client->paint_pending, "duplicate health frame");
            client->paint_pending = true;
            client->work = 1;
        } else if (client->id == 3) {
            client->abrupt = true;
            client->work = 1;
        }
    }
    client->key_events++;
    emit("DYN_CLIENT KEY id=%u f=%u s=%u c=%u v=%u sym=%u\n",
         client->id, client->phase, serial, code, state, expected);
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                               uint32_t depressed, uint32_t latched, uint32_t locked,
                               uint32_t group) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(client->xkb_state, "modifiers without keymap");
    xkb_state_update_mask(client->xkb_state, depressed, latched, locked, 0, 0, group);
}

static void repeat_info(void *data, struct wl_keyboard *keyboard, int32_t rate, int32_t delay) {
    (void)data; (void)keyboard; (void)rate; (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = keymap, .enter = keyboard_enter, .leave = keyboard_leave,
    .key = keyboard_key, .modifiers = keyboard_modifiers, .repeat_info = repeat_info,
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct client *client = data;
    CHECK((capabilities & WL_SEAT_CAPABILITY_KEYBOARD) && !client->keyboard,
          "keyboard capability/order");
    client->keyboard = wl_seat_get_keyboard(seat);
    CHECK(client->keyboard && wl_keyboard_add_listener(client->keyboard, &keyboard_listener, client) == 0,
          "keyboard listener");
}

static void seat_name(void *data, struct wl_seat *seat, const char *name) {
    (void)data; (void)seat; (void)name;
}
static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities, .name = seat_name,
};

static void shm_format(void *data, struct wl_shm *shm, uint32_t format) {
    (void)shm;
    struct client *client = data;
    if (format == WL_SHM_FORMAT_ARGB8888) client->formats++;
}
static const struct wl_shm_listener shm_listener = {.format = shm_format};

static void wm_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}
static const struct xdg_wm_base_listener wm_listener = {.ping = wm_ping};

static void toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                               int32_t width, int32_t height, struct wl_array *states) {
    (void)toplevel;
    struct client *client = data;
    CHECK(client->configures < (client->id == 1 ? 5u : 1u) && !client->pending_configure &&
          !client->closed && !client->abrupt && states->size % sizeof(uint32_t) == 0,
          "unexpected toplevel configure");
    bool active = false;
    uint32_t *state;
    wl_array_for_each(state, states) {
        CHECK(*state == XDG_TOPLEVEL_STATE_ACTIVATED && !active, "unexpected configured state");
        active = true;
    }
    const bool expected_active = client->id != 1 || client->configures % 2 == 0;
    CHECK(active == expected_active && width == 64 && height == 48,
          "configured geometry/state sequence");
    client->pending_activated = active;
    client->pending_configure = 1;
}

static void surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct client *client = data;
    CHECK(client->pending_configure == 1 && client->acks == client->configures &&
          serial != 0 && serial != client->serial, "configure sequence/serial");
    const unsigned index = client->configures++;
    client->serial = serial;
    client->width = 64;
    client->height = 48;
    client->activated = client->pending_activated;
    client->pending_configure = 0;
    emit("DYN_CLIENT CFG id=%u n=%u s=%u w=64 h=48 a=%u\n",
         client->id, index, serial, client->activated);
    xdg_surface_ack_configure(surface, serial);
    client->acks++;
    emit("DYN_CLIENT ACK id=%u n=%u s=%u\n", client->id, index, serial);
}
static const struct xdg_surface_listener surface_listener = {.configure = surface_configure};

static void toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)toplevel;
    struct client *client = data;
    const unsigned frames = client->id == 1 ? 4 : 2;
    CHECK(client->id != 3 && !client->abrupt && client->painted == frames &&
          client->callbacks == frames && client->input_complete == 1 &&
          client->received_code == 16 && client->closed++ == 0, "close ordering/count");
    client->work = 1;
    emit("DYN_CLIENT CLOSE id=%u n=1\n", client->id);
}
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure, .close = toplevel_close,
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version) {
    struct client *client = data;
    if (!strcmp(interface, "wl_compositor")) {
        CHECK(version >= 4 && !client->compositor, "compositor global");
        client->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 4);
    } else if (!strcmp(interface, "wl_shm")) {
        CHECK(version >= 1 && !client->shm, "shm global");
        client->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        CHECK(client->shm && wl_shm_add_listener(client->shm, &shm_listener, client) == 0, "shm listener");
    } else if (!strcmp(interface, "xdg_wm_base")) {
        CHECK(version >= 1 && !client->wm_base, "xdg shell global");
        client->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, 1);
        CHECK(client->wm_base &&
              xdg_wm_base_add_listener(client->wm_base, &wm_listener, client) == 0, "wm listener");
    } else if (!strcmp(interface, "wl_seat")) {
        /* Smithay supplies its real sealed keymap memfd at keyboard v7+. */
        CHECK(version >= 7 && !client->seat, "seat global");
        client->seat = wl_registry_bind(registry, name, &wl_seat_interface, 7);
        CHECK(client->seat && wl_seat_add_listener(client->seat, &seat_listener, client) == 0, "seat listener");
    }
}

static void registry_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
    fail("unexpected global removal");
}
static const struct wl_registry_listener registry_listener = {
    .global = registry_global, .global_remove = registry_remove,
};

static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    struct frame *frame = data;
    CHECK(frame->done++ == 0, "duplicate frame callback");
    CHECK(frame->client->callbacks == frame->phase, "frame callback sequence");
    frame->client->callbacks++;
    emit("DYN_CLIENT CALLBACK id=%u f=%u time=%u\n",
         frame->client->id, frame->phase, time);
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)buffer;
    struct frame *frame = data;
    CHECK(frame->released++ == 0, "duplicate buffer release");
    frame->client->releases++;
    emit("DYN_CLIENT RELEASE id=%u f=%u\n",
         frame->client->id, frame->phase);
}
static const struct wl_buffer_listener buffer_listener = {.release = buffer_release};

static uint32_t pixel(unsigned round, unsigned phase, unsigned seed, unsigned x, unsigned y) {
    unsigned red = (3 * x + y + 29 * round + 47 * phase + seed) & 255;
    unsigned green = (x + 5 * y + 11 * round + 31 * phase + 3 * seed) & 255;
    unsigned blue = (7 * (x ^ y) + 13 * round + 19 * phase + 5 * seed) & 255;
    return 0xff000000u | (red << 16) | (green << 8) | blue;
}

static void submit_frame(struct client *client, struct frame *frame) {
    const unsigned phase = client->phase;
    const int width = client->width, height = client->height;
    const unsigned seed = phase == 0 ? 0 : client->received_code;
    CHECK(seed == (phase == 0 ? 0u : 32u), "physical seed");
    const size_t size = (size_t)width * (size_t)height * sizeof(uint32_t);
    CHECK(client->acks == client->configures && client->acks > 0 &&
          client->width == width && client->height == height, "configure before frame");
    *frame = (struct frame){.client = client, .phase = phase, .size = size};
    int fd = memfd_create("smithay-dynamic-pixels", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    CHECK(fd >= 0 && ftruncate(fd, (off_t)size) == 0, "pixel memfd");
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) == 0, "pixel seals");
    uint32_t *pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(pixels != MAP_FAILED, "shared pixel mapping");
    struct wl_shm_pool *pool = wl_shm_create_pool(client->shm, fd, (int)size);
    CHECK(pool, "shm pool");
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, width, height, width * 4,
                                                        WL_SHM_FORMAT_ARGB8888);
    CHECK(buffer && wl_buffer_add_listener(buffer, &buffer_listener, frame) == 0, "buffer listener");
    frame->buffer = buffer;
    frame->pixels = pixels;
    wl_shm_pool_destroy(pool);
    CHECK(close(fd) == 0, "pixel fd close");
    synchronize(client);
    /* Server FD import precedes every write. Only actual shared mappings can
     * pass the independently computed physical scanout oracle. */
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++)
            pixels[y * width + x] = pixel(client->id, phase, seed, (unsigned)x, (unsigned)y);
    client->input_complete = 0;
    client->input_down = false;
    xdg_surface_set_window_geometry(client->xdg_surface, 0, 0, width, height);
    wl_surface_attach(client->surface, buffer, 0, 0);
    wl_surface_damage_buffer(client->surface, 0, 0, width, height);
    struct wl_callback *callback = wl_surface_frame(client->surface);
    CHECK(callback && wl_callback_add_listener(callback, &frame_listener, frame) == 0, "frame listener");
    wl_surface_commit(client->surface);
    client->painted++;
    wait_counter(client, &frame->done, "frame callback timeout");
    CHECK(frame->done == 1, "frame callback completion");
    emit("DYN_CLIENT FRAME id=%u f=%u w=%d h=%d seed=%u\n",
         client->id, phase, width, height, seed);
}
/* The rejection probe sends no Wayland request: only actual EOF is success.
 * An errno, timeout, protocol byte or failed connect is not capacity rejection. */
static void capacity_probe(struct client *client) {
    const int64_t deadline = monotonic_ms() + EVENT_TIMEOUT_MS;
    const int fd = wl_display_get_fd(client->display);
    for (;;) {
        int64_t remaining = deadline - monotonic_ms();
        CHECK(remaining > 0, "capacity EOF timeout");
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        int result = poll(&descriptor, 1, (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        CHECK(result > 0 && !(descriptor.revents & (POLLERR | POLLNVAL)) &&
              (descriptor.revents & (POLLIN | POLLHUP)), "capacity EOF poll");
        unsigned char byte = 0;
        ssize_t received = read(fd, &byte, sizeof(byte));
        if (received < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        CHECK(received == 0, "capacity rejection must be EOF");
        emit("DYN_CLIENT PROBE id=0 eof=1 bytes=0\n");
        wl_display_disconnect(client->display);
        emit("DYN_CLIENT RESULT PASS id=0 eof=1\n");
        return;
    }
}

int main(int argc, char **argv) {
    CHECK(argc == 2 && strlen(argv[1]) == 1 && argv[1][0] >= '0' && argv[1][0] <= '3',
          "identity argument");
    struct client client = {.id = (unsigned)(argv[1][0] - '0')};
    CHECK(getenv("WAYLAND_SOCKET") == NULL, "inherited Wayland socket environment");
    errno = 0;
    CHECK(fcntl(3, F_GETFD) == -1 && errno == EBADF, "inherited descriptor 3");
    CHECK(setenv("XDG_RUNTIME_DIR", "/tmp", 1) == 0 &&
          setenv("WAYLAND_DISPLAY", "cyxia-wayland-0", 1) == 0, "display environment");
    emit("DYN_CLIENT ENV id=%u ws=0 fd3=closed\n", client.id);
    emit("DYN_CLIENT PATH id=%u /tmp/cyxia-wayland-0\n", client.id);
    client.display = wl_display_connect(NULL);
    CHECK(client.display, "named display connection");
    const int display_fd = wl_display_get_fd(client.display);
    emit("DYN_CLIENT START id=%u pid=%d fd=%d\n", client.id, getpid(), display_fd);
    struct ucred peer = {0};
    socklen_t peer_size = sizeof(peer);
    CHECK(getsockopt(display_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
          peer_size == sizeof(peer) && peer.pid > 0 && peer.pid != getpid() &&
          peer.uid == 0 && peer.gid == 0, "actual server peer credentials");
    emit("DYN_CLIENT PEER id=%u pid=%d uid=%u gid=%u\n",
         client.id, peer.pid, peer.uid, peer.gid);
    if (client.id == 0) {
        capacity_probe(&client);
        return 0;
    }
    const unsigned frame_count = client.id == 1 ? 4 : 2;
    const unsigned configure_count = client.id == 1 ? 5 : 1;
    struct frame frames[MAX_FRAMES] = {0};
    client.xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    CHECK(client.xkb_context, "xkb context");
    client.registry = wl_display_get_registry(client.display);
    CHECK(client.registry && wl_registry_add_listener(client.registry, &registry_listener, &client) == 0,
          "registry listener");
    for (unsigned roundtrip = 0; roundtrip < 3; roundtrip++) synchronize(&client);
    CHECK(client.compositor && client.shm && client.wm_base && client.formats == 1 &&
          client.seat && client.keyboard && client.keymaps == 1, "required shell/input globals");
    client.surface = wl_compositor_create_surface(client.compositor);
    CHECK(client.surface, "surface");
    client.xdg_surface = xdg_wm_base_get_xdg_surface(client.wm_base, client.surface);
    CHECK(client.xdg_surface &&
          xdg_surface_add_listener(client.xdg_surface, &surface_listener, &client) == 0,
          "xdg surface/listener");
    client.toplevel = xdg_surface_get_toplevel(client.xdg_surface);
    CHECK(client.toplevel &&
          xdg_toplevel_add_listener(client.toplevel, &toplevel_listener, &client) == 0,
          "toplevel/listener");
    xdg_toplevel_set_title(client.toplevel, "CyxiaOS dynamic client");
    xdg_toplevel_set_app_id(client.toplevel, "org.cyxiaos.smithay-dynamic-client");
    wl_surface_commit(client.surface);
    wait_counter(&client, &client.configures, "initial configure timeout");
    CHECK(client.configures == 1 && client.acks == 1, "initial configure/ack");
    submit_frame(&client, &frames[0]);
    while (!client.closed && !client.abrupt) {
        wait_counter(&client, &client.work, "dynamic event timeout");
        client.work = 0;
        if (client.paint_pending) {
            CHECK(!client.closed && !client.abrupt && client.painted < frame_count, "unexpected repaint");
            client.paint_pending = false;
            client.phase = client.painted;
            submit_frame(&client, &frames[client.phase]);
        }
    }
    CHECK(client.painted == frame_count && client.configures == configure_count &&
          client.acks == configure_count && client.callbacks == frame_count &&
          client.key_events == frame_count * 2 &&
          client.keyboard_enters == (client.id == 1 ? 3u : 1u) &&
          client.keyboard_leaves == (client.id == 1 ? 2u : 0u), "dynamic/focus completion");
    if (client.abrupt) {
        CHECK(client.id == 3 && client.releases == 1 && frames[0].released == 1 &&
              frames[1].released == 0 && client.closed == 0 && client.closing_keyboard_leaves == 0 &&
              client.keyboard_focus && client.received_code == 45, "abrupt live-object state");
        emit("DYN_CLIENT ABORT id=3 f=2 cb=2 rel=1 keys=4\n");
        /* Deliberately leave live proxies and SHM mappings. Disconnect is the
         * only Wayland teardown; process exit must reclaim remaining resources. */
        wl_display_disconnect(client.display);
        emit("DYN_CLIENT DISCONNECT id=3 mode=abrupt\n");
        _exit(0);
    }
    wl_surface_attach(client.surface, NULL, 0, 0);
    wl_surface_commit(client.surface);
    synchronize(&client);
    for (unsigned phase = 0; phase < frame_count; phase++) {
        wait_counter(&client, &frames[phase].released, "buffer release timeout");
        CHECK(frames[phase].released == 1, "buffer release count");
        wl_buffer_destroy(frames[phase].buffer);
        CHECK(munmap(frames[phase].pixels, frames[phase].size) == 0, "shared pixel unmap");
    }
    CHECK(client.releases == frame_count && client.closing_keyboard_leaves == 1 &&
          !client.keyboard_focus, "normal close release/focus total");
    wl_keyboard_release(client.keyboard);
    wl_seat_release(client.seat);
    xdg_toplevel_destroy(client.toplevel);
    xdg_surface_destroy(client.xdg_surface);
    wl_surface_destroy(client.surface);
    xdg_wm_base_destroy(client.wm_base);
    wl_shm_destroy(client.shm);
    wl_compositor_destroy(client.compositor);
    wl_registry_destroy(client.registry);
    synchronize(&client);
    wl_display_disconnect(client.display);
    xkb_state_unref(client.xkb_state);
    xkb_keymap_unref(client.keymap);
    xkb_context_unref(client.xkb_context);
    emit("DYN_CLIENT COUNTS id=%u f=%u cb=%u rel=%u keys=%u\n",
         client.id, frame_count, client.callbacks, client.releases, client.key_events);
    emit("DYN_CLIENT FOCUS id=%u ke=%u kl=%u\n",
         client.id, client.keyboard_enters, client.keyboard_leaves);
    emit("DYN_CLIENT RESULT PASS id=%u cfg=%u ack=%u close=1\n",
         client.id, client.configures, client.acks);
    return 0;
}
