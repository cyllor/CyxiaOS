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
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>

/* Independent anchored-resize libwayland client. Real input serials authorize
 * top-left and left grabs; closing the owner while held must cancel its grab. */
enum { MAX_FRAMES = 8, EVENT_TIMEOUT_MS = 30000, KEYMAP_LIMIT = 65536 };

struct client {
    unsigned id, phase, formats, callbacks, releases;
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct wl_surface *surface;
    struct xdg_wm_base *wm_base;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    unsigned configures, acks, closed, pending_configure, requests, painted, work;
    uint32_t serial;
    int32_t pending_width, pending_height, width, height;
    struct xkb_context *xkb_context;
    struct xkb_keymap *keymap;
    struct xkb_state *xkb_state;
    bool keyboard_focus, pointer_focus, input_down, activated, pending_activated;
    bool resizing, pending_resizing, paint_pending;
    unsigned interaction;
    uint32_t resize_serial;
    unsigned input_complete, keymaps, key_events, button_events;
    unsigned keyboard_enters, keyboard_leaves, pointer_enters, pointer_leaves;
    unsigned closing_keyboard_leaves;
    uint32_t received_code;
    wl_fixed_t pointer_x, pointer_y;
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
    emit("RS_CLIENT FAIL pid=%d err=%d\n", getpid(), error);
    emit("RS_CLIENT REASON %.40s\n", why);
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

static void request_resize(struct client *client, uint32_t serial, uint32_t edge) {
    CHECK(edge == XDG_TOPLEVEL_RESIZE_EDGE_TOP_LEFT || edge == XDG_TOPLEVEL_RESIZE_EDGE_LEFT,
          "resize edge");
    emit("RS_CLIENT REQ id=%u n=%u kind=resize s=%u edge=%u\n",
         client->id, client->requests++, serial, edge);
    xdg_toplevel_resize(client->toplevel, client->seat, serial, edge);
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
    emit("RS_CLIENT KEYMAP id=%u bytes=%u\n", client->id, size);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface, struct wl_array *keys) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->xkb_state && !client->keyboard_focus &&
          keys->size == 0 && !client->closed && client->keyboard_enters < (client->id == 1 ? 1u : 2u),
          "keyboard enter focus/order");
    client->keyboard_focus = true;
    emit("RS_CLIENT K_ENTER id=%u n=%u\n", client->id, client->keyboard_enters++);
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->keyboard_focus && !client->input_down,
          "keyboard leave focus/order");
    unsigned *count = client->closed ? &client->closing_keyboard_leaves : &client->keyboard_leaves;
    CHECK(*count == 0 && (client->closed || client->id == 2), "unexpected keyboard leave");
    client->keyboard_focus = false;
    emit("RS_CLIENT K_LEAVE id=%u n=%u closing=%u\n",
         client->id, (*count)++, client->closed != 0);
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                         uint32_t time, uint32_t code, uint32_t state) {
    (void)keyboard; (void)serial; (void)time;
    struct client *client = data;
    CHECK(client->keyboard_focus && client->activated && client->xkb_state && !client->closed,
          "key without activated focus");
    const bool health = client->phase == (client->id == 1 ? 4u : 0u);
    const uint32_t expected_code = health ? 32 : 16;
    const xkb_keysym_t expected = health ? XKB_KEY_d : XKB_KEY_q;
    CHECK(code == expected_code &&
          (health || client->phase == (client->id == 1 ? 7u : 1u)) &&
          client->resizing == (client->id == 1 && !health) &&
          xkb_state_key_get_one_sym(client->xkb_state, code + 8) == expected,
          "key identity/translation/resize state");
    if (state == WL_KEYBOARD_KEY_STATE_PRESSED) {
        CHECK(!client->input_down && !client->input_complete, "duplicate key press");
        client->input_down = true;
    } else {
        CHECK(state == WL_KEYBOARD_KEY_STATE_RELEASED && client->input_down && !client->input_complete,
              "key release ordering");
        client->input_down = false;
        client->input_complete = 1;
        client->received_code = code;
        if (code == 32) {
            CHECK(!client->paint_pending && client->painted == (client->id == 1 ? 5u : 1u),
                  "duplicate health frame");
            client->paint_pending = true;
            client->work = 1;
        }
    }
    client->key_events++;
    emit("RS_CLIENT KEY id=%u f=%u code=%u state=%u sym=%u\n",
         client->id, client->phase, code, state, expected);
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

static void pointer_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface, wl_fixed_t x, wl_fixed_t y) {
    (void)pointer; (void)serial;
    struct client *client = data;
    CHECK(client->id == 1 && surface == client->surface && !client->pointer_focus &&
          !client->closed && client->pointer_enters < 2, "pointer enter focus/order");
    CHECK(x == wl_fixed_from_int(8) && y == wl_fixed_from_int(8), "pointer enter local coordinates");
    client->pointer_focus = true;
    client->pointer_x = x;
    client->pointer_y = y;
    emit("RS_CLIENT P_ENTER id=1 n=%u x=%d y=%d\n", client->pointer_enters++, x, y);
    if (client->pointer_enters == 2) {
        CHECK(client->interaction == 1 && client->requests == 1, "first resize completion ordering");
        client->interaction = 2;
    }
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface) {
    (void)pointer; (void)serial;
    struct client *client = data;
    CHECK(client->id == 1 && surface == client->surface && client->pointer_focus &&
          !client->closed && client->pointer_leaves < 2 &&
          (client->interaction == 1 || client->interaction == 3),
          "pointer leave outside resize grab");
    client->pointer_focus = false;
    emit("RS_CLIENT P_LEAVE id=1 n=%u closing=0\n", client->pointer_leaves++);
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                           wl_fixed_t x, wl_fixed_t y) {
    (void)data; (void)pointer; (void)time; (void)x; (void)y;
    fail("grab motion leaked to client");
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                           uint32_t time, uint32_t button, uint32_t state) {
    (void)pointer; (void)time;
    struct client *client = data;
    CHECK(client->id == 1 && client->pointer_focus && client->keyboard_focus && client->activated &&
          serial != 0 && state == WL_POINTER_BUTTON_STATE_PRESSED && client->button_events < 2 &&
          button == (client->button_events == 0 ? 272u : 273u), "unexpected physical button");
    CHECK(client->pointer_x == wl_fixed_from_int(8) && client->pointer_y == wl_fixed_from_int(8),
          "button local coordinates");
    emit("RS_CLIENT BUTTON id=1 n=%u s=%u code=%u state=1\n", client->button_events++, serial, button);
    if (button == 272) {
        CHECK(client->interaction == 0 && client->requests == 0 && client->painted == 1,
              "top-left resize press ordering");
        client->interaction = 1;
    } else {
        CHECK(client->interaction == 2 && client->requests == 1 && client->painted == 6 &&
              !client->resizing && serial != client->resize_serial, "left resize press ordering");
        client->interaction = 3;
    }
    client->resize_serial = serial;
    client->received_code = button;
    request_resize(client, serial, button == 272 ? XDG_TOPLEVEL_RESIZE_EDGE_TOP_LEFT :
                                                  XDG_TOPLEVEL_RESIZE_EDGE_LEFT);

}

static void pointer_axis(void *data, struct wl_pointer *pointer, uint32_t time,
                         uint32_t axis, wl_fixed_t value) {
    (void)data; (void)pointer; (void)time; (void)axis; (void)value;
    fail("unexpected pointer axis");
}

static void pointer_frame(void *data, struct wl_pointer *pointer) {
    (void)data; (void)pointer;
}
static void pointer_axis_source(void *data, struct wl_pointer *pointer, uint32_t source) {
    (void)data; (void)pointer; (void)source;
}
static void pointer_axis_stop(void *data, struct wl_pointer *pointer, uint32_t time, uint32_t axis) {
    (void)data; (void)pointer; (void)time; (void)axis;
}
static void pointer_axis_discrete(void *data, struct wl_pointer *pointer, uint32_t axis, int32_t discrete) {
    (void)data; (void)pointer; (void)axis; (void)discrete;
}

static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter, .leave = pointer_leave, .motion = pointer_motion,
    .button = pointer_button, .axis = pointer_axis, .frame = pointer_frame,
    .axis_source = pointer_axis_source, .axis_stop = pointer_axis_stop,
    .axis_discrete = pointer_axis_discrete,
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct client *client = data;
    CHECK((capabilities & (WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER)) ==
          (WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER), "seat capabilities");
    CHECK(!client->keyboard && !client->pointer, "duplicate seat capabilities");
    client->keyboard = wl_seat_get_keyboard(seat);
    client->pointer = wl_seat_get_pointer(seat);
    CHECK(client->keyboard && wl_keyboard_add_listener(client->keyboard, &keyboard_listener, client) == 0,
          "keyboard listener");
    CHECK(client->pointer && wl_pointer_add_listener(client->pointer, &pointer_listener, client) == 0,
          "pointer listener");
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
    static const int widths[8] = {64, 64, 64, 72, 60, 60, 60, 76};
    static const int heights[8] = {48, 48, 48, 52, 44, 44, 44, 44};
    CHECK(client->configures < (client->id == 1 ? 8u : 3u) && !client->pending_configure &&
          !client->closed && states->size % sizeof(uint32_t) == 0, "unexpected toplevel configure");
    bool active = false, resizing = false;
    uint32_t *state;
    wl_array_for_each(state, states) {
        if (*state == XDG_TOPLEVEL_STATE_ACTIVATED) {
            CHECK(!active, "duplicate activated state");
            active = true;
        } else if (*state == XDG_TOPLEVEL_STATE_RESIZING) {
            CHECK(!resizing, "duplicate resizing state");
            resizing = true;
        } else fail("unexpected configured state");
    }
    const bool expected_active = client->id == 1 ? client->configures != 0 : client->configures != 1;
    const bool expected_resizing = client->id == 1 && client->configures >= 2 && client->configures != 5;
    const unsigned index = client->id == 1 ? client->configures : 0;
    CHECK(active == expected_active && resizing == expected_resizing &&
          width == widths[index] && height == heights[index], "configured geometry/state sequence");
    if (client->id == 1 && client->configures >= 2)
        CHECK(client->resize_serial != 0 &&
              client->requests == (client->configures >= 6 ? 2u : 1u) &&
              client->received_code == (client->configures >= 6 ? 273u : 272u) &&
              !client->paint_pending, "resize configure before real request");
    client->pending_width = width;
    client->pending_height = height;
    client->pending_activated = active;
    client->pending_resizing = resizing;
    client->pending_configure = 1;
}

static void surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct client *client = data;
    CHECK(client->pending_configure == 1 && client->acks == client->configures &&
          serial != 0 && serial != client->serial, "configure sequence/serial");
    const unsigned index = client->configures++;
    client->serial = serial;
    client->width = client->pending_width;
    client->height = client->pending_height;
    client->activated = client->pending_activated;
    client->resizing = client->pending_resizing;
    client->pending_configure = 0;
    emit("RS_CLIENT CFG id=%u n=%u s=%u w=%d h=%d a=%u r=%u\n",
         client->id, index, serial, client->width, client->height, client->activated, client->resizing);
    xdg_surface_ack_configure(surface, serial);
    client->acks++;
    emit("RS_CLIENT ACK id=%u n=%u s=%u\n", client->id, index, serial);
    if (client->id == 1 && index >= 2) {
        client->paint_pending = true;
        client->work = 1;
    }
}
static const struct xdg_surface_listener surface_listener = {.configure = surface_configure};

static void toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)toplevel;
    struct client *client = data;
    const unsigned frames = client->id == 1 ? 8 : 2;
    CHECK(client->painted == frames && client->callbacks == frames && client->input_complete == 1 &&
          client->received_code == 16 && !client->pointer_focus &&
          client->resizing == (client->id == 1) &&
          (client->id == 2 || client->interaction == 3) && client->closed++ == 0, "close ordering/count");
    client->work = 1;
    emit("RS_CLIENT CLOSE id=%u n=1\n", client->id);
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
    emit("RS_CLIENT CALLBACK id=%u f=%u time=%u\n",
         frame->client->id, frame->phase, time);
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)buffer;
    struct frame *frame = data;
    CHECK(frame->released++ == 0, "duplicate buffer release");
    frame->client->releases++;
    emit("RS_CLIENT RELEASE id=%u f=%u\n",
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
    static const unsigned seeds[2][MAX_FRAMES] = {{0, 272, 272, 272, 272, 32, 273, 273}, {0, 32, 0, 0, 0, 0, 0, 0}};
    const unsigned seed = phase == 0 ? 0 : client->received_code;
    CHECK(seed == seeds[client->id - 1][phase], "physical seed");
    const size_t size = (size_t)width * (size_t)height * sizeof(uint32_t);
    CHECK(client->acks == client->configures && client->acks > 0 &&
          client->width == width && client->height == height, "configure before frame");
    *frame = (struct frame){.client = client, .phase = phase, .size = size};
    int fd = memfd_create("smithay-resize-pixels", MFD_CLOEXEC | MFD_ALLOW_SEALING);
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
    emit("RS_CLIENT FRAME id=%u f=%u w=%d h=%d seed=%u\n",
         client->id, phase, width, height, seed);
}
int main(int argc, char **argv) {
    CHECK(argc == 2 && strlen(argv[1]) == 1 && argv[1][0] >= '1' && argv[1][0] <= '2',
          "identity argument");
    struct client client = {.id = (unsigned)(argv[1][0] - '0')};
    const unsigned frame_count = client.id == 1 ? 8 : 2;
    const unsigned configure_count = client.id == 1 ? 8 : 3;
    struct frame frames[MAX_FRAMES] = {0};
    client.xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    CHECK(client.xkb_context, "xkb context");
    client.display = wl_display_connect_to_fd(3);
    CHECK(client.display, "display connection");
    emit("RS_CLIENT START id=%u pid=%d fd=3\n", client.id, getpid());
    client.registry = wl_display_get_registry(client.display);
    CHECK(client.registry && wl_registry_add_listener(client.registry, &registry_listener, &client) == 0,
          "registry listener");
    for (unsigned roundtrip = 0; roundtrip < 3; roundtrip++) synchronize(&client);
    CHECK(client.compositor && client.shm && client.wm_base && client.formats == 1 &&
          client.seat && client.keyboard && client.pointer && client.keymaps == 1,
          "required shell/input globals");
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
    xdg_toplevel_set_title(client.toplevel, client.id == 1 ? "CyxiaOS resize A" : "CyxiaOS health B");
    xdg_toplevel_set_app_id(client.toplevel, "org.cyxiaos.smithay-resize-client");
    wl_surface_commit(client.surface);
    wait_counter(&client, &client.configures, "initial configure timeout");
    CHECK(client.configures == 1 && client.acks == 1, "initial configure/ack");
    submit_frame(&client, &frames[0]);
    while (!client.closed) {
        wait_counter(&client, &client.work, "resize event timeout");
        client.work = 0;
        if (client.paint_pending) {
            CHECK(!client.closed && client.painted < frame_count, "unexpected repaint");
            client.paint_pending = false;
            client.phase = client.painted;
            submit_frame(&client, &frames[client.phase]);
        }
    }
    CHECK(client.painted == frame_count && client.configures == configure_count &&
          client.acks == configure_count && client.callbacks == frame_count &&
          client.key_events == 4 &&
          client.button_events == (client.id == 1 ? 2u : 0u) &&
          client.keyboard_enters == (client.id == 1 ? 1u : 2u) &&
          client.keyboard_leaves == (client.id == 1 ? 0u : 1u) &&
          client.pointer_enters == (client.id == 1 ? 2u : 0u) &&
          client.pointer_leaves == (client.id == 1 ? 2u : 0u) &&
          client.requests == (client.id == 1 ? 2u : 0u), "resize/focus completion");
    wl_surface_attach(client.surface, NULL, 0, 0);
    wl_surface_commit(client.surface);
    synchronize(&client);
    for (unsigned phase = 0; phase < frame_count; phase++) {
        wait_counter(&client, &frames[phase].released, "buffer release timeout");
        CHECK(frames[phase].released == 1, "buffer release count");
        wl_buffer_destroy(frames[phase].buffer);
        CHECK(munmap(frames[phase].pixels, frames[phase].size) == 0, "shared pixel unmap");
    }
    CHECK(client.releases == frame_count, "buffer release total");
    wl_keyboard_release(client.keyboard);
    wl_pointer_release(client.pointer);
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
    emit("RS_CLIENT COUNTS id=%u f=%u cb=%u rel=%u keys=%u btn=%u req=%u\n",
         client.id, frame_count, client.callbacks, client.releases, client.key_events,
         client.button_events, client.requests);
    emit("RS_CLIENT FOCUS id=%u ke=%u kl=%u pe=%u pl=%u\n",
         client.id, client.keyboard_enters, client.keyboard_leaves, client.pointer_enters, client.pointer_leaves);
    emit("RS_CLIENT RESULT PASS id=%u cfg=%u ack=%u close=1\n",
         client.id, client.configures, client.acks);
    return 0;
}
