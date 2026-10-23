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

/* Independent concurrent libwayland xdg-shell client. Configure serials, shared pixels,
 * physical seat input, buffer releases and close are actual protocol events. */
enum { MAX_FRAMES = 5, EVENT_TIMEOUT_MS = 30000, KEYMAP_LIMIT = 65536 };

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
    unsigned configures, acks, closed, pending_configure;
    uint32_t serial;
    int32_t pending_width, pending_height, width, height;
    struct xkb_context *xkb_context;
    struct xkb_keymap *keymap;
    struct xkb_state *xkb_state;
    bool keyboard_focus, pointer_focus, input_down, activated, pending_activated;
    unsigned input_complete, keymaps, key_events, button_events, motions;
    unsigned keyboard_enters, keyboard_leaves, pointer_enters, pointer_leaves;
    unsigned closing_keyboard_leaves, closing_pointer_leaves;
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
    emit("MULTI_CLIENT FAIL pid=%d err=%d\n", getpid(), error);
    emit("MULTI_CLIENT REASON %.40s\n", why);
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
            .fd = wl_display_get_fd(client->display),
            .events = POLLIN | (flush < 0 ? POLLOUT : 0),
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
    emit("MULTI_CLIENT KEYMAP id=%u bytes=%u\n", client->id, size);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface, struct wl_array *keys) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->xkb_state && !client->keyboard_focus &&
          keys->size == 0 && !client->closed && client->keyboard_enters < 2,
          "keyboard enter focus/order");
    client->keyboard_focus = true;
    emit("MULTI_CLIENT K_ENTER id=%u n=%u\n", client->id, client->keyboard_enters++);
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->keyboard_focus && !client->input_down,
          "keyboard leave focus/order");
    unsigned *count = client->closed ? &client->closing_keyboard_leaves : &client->keyboard_leaves;
    CHECK(*count == 0, "duplicate keyboard leave");
    client->keyboard_focus = false;
    emit("MULTI_CLIENT K_LEAVE id=%u n=%u closing=%u\n",
         client->id, (*count)++, client->closed != 0);
}

/* Each process accepts only its own known input script. Events sent to an
 * unfocused client, duplicated events and automatic client advancement fail. */
static unsigned expected_input(const struct client *client) {
    static const unsigned inputs[2][MAX_FRAMES] = {{272, 48, 273, 32, 16}, {30, 272, 46, 16, 0}};
    CHECK(client->id >= 1 && client->id <= 2 && client->phase < (client->id == 1 ? 5u : 4u),
          "input phase");
    return inputs[client->id - 1][client->phase];
}

static void physical_input(struct client *client, uint32_t code, uint32_t state) {
    CHECK(!client->closed && code == expected_input(client) && !client->input_complete,
          "unexpected physical input");
    if (state == 1) {
        CHECK(!client->input_down, "duplicate physical press");
        client->input_down = true;
        client->received_code = code;
    } else {
        CHECK(state == 0 && client->input_down && client->received_code == code,
              "physical release ordering");
        client->input_down = false;
        client->input_complete++;
    }
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                         uint32_t time, uint32_t code, uint32_t state) {
    (void)keyboard; (void)serial; (void)time;
    struct client *client = data;
    CHECK(client->keyboard_focus && client->activated && client->xkb_state &&
          code < 256, "key without activated focus");
    xkb_keysym_t expected = code == 30 ? XKB_KEY_a : code == 48 ? XKB_KEY_b :
        code == 46 ? XKB_KEY_c : code == 32 ? XKB_KEY_d : code == 16 ? XKB_KEY_q : XKB_KEY_NoSymbol;
    CHECK(expected != XKB_KEY_NoSymbol &&
          xkb_state_key_get_one_sym(client->xkb_state, code + 8) == expected, "keymap translation");
    physical_input(client, code, state);
    client->key_events++;
    emit("MULTI_CLIENT KEY id=%u f=%u code=%u state=%u sym=%u\n",
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
    CHECK(surface == client->surface && !client->pointer_focus && !client->closed &&
          client->pointer_enters < (client->id == 1 ? 1u : 2u), "pointer enter focus/order");
    const int expected_x = client->id == 2 && client->pointer_enters == 1 ? 56 : 8;
    const int expected_y = client->id == 2 && client->pointer_enters == 1 ? 40 : 8;
    CHECK(x == wl_fixed_from_int(expected_x) && y == wl_fixed_from_int(expected_y),
          "pointer enter local coordinates");
    client->pointer_focus = true;
    client->pointer_x = x;
    client->pointer_y = y;
    emit("MULTI_CLIENT P_ENTER id=%u n=%u x=%d y=%d\n",
         client->id, client->pointer_enters++, x, y);
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface) {
    (void)pointer; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface && client->pointer_focus && !client->input_down,
          "pointer leave focus/order");
    unsigned *count = client->closed ? &client->closing_pointer_leaves : &client->pointer_leaves;
    CHECK(*count == 0, "duplicate pointer leave");
    client->pointer_focus = false;
    emit("MULTI_CLIENT P_LEAVE id=%u n=%u closing=%u\n",
         client->id, (*count)++, client->closed != 0);
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                           wl_fixed_t x, wl_fixed_t y) {
    (void)pointer; (void)time;
    struct client *client = data;
    CHECK(client->id == 1 && client->pointer_focus && client->phase == 2 &&
          client->motions == 0 && !client->closed, "unexpected physical motion");
    CHECK(x == wl_fixed_from_int(48) && y == wl_fixed_from_int(32) &&
          x == client->pointer_x + wl_fixed_from_int(40) &&
          y == client->pointer_y + wl_fixed_from_int(24), "physical motion local coordinates");
    client->pointer_x = x;
    client->pointer_y = y;
    client->motions++;
    emit("MULTI_CLIENT MOTION id=%u f=%u x=%d y=%d\n",
         client->id, client->phase, x, y);
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                           uint32_t time, uint32_t button, uint32_t state) {
    (void)pointer; (void)serial; (void)time;
    struct client *client = data;
    CHECK(client->pointer_focus && client->keyboard_focus && client->activated &&
          (button == 272 || button == 273), "button without activated pointer focus");
    const int expected_x = client->id == 1 ? (button == 272 ? 8 : 48) : 56;
    const int expected_y = client->id == 1 ? (button == 272 ? 8 : 32) : 40;
    CHECK(client->pointer_x == wl_fixed_from_int(expected_x) &&
          client->pointer_y == wl_fixed_from_int(expected_y), "button local coordinates");
    physical_input(client, button, state);
    client->button_events++;
    emit("MULTI_CLIENT BUTTON id=%u f=%u code=%u state=%u x=%d y=%d\n",
         client->id, client->phase, button, state, client->pointer_x, client->pointer_y);
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
    static const bool activation[2][4] = {{false, true, false, true}, {true, false, true, false}};
    CHECK(client->configures < (client->id == 1 ? 4u : 3u) && !client->pending_configure &&
          !client->closed, "unexpected toplevel configure");
    const bool active = activation[client->id - 1][client->configures];
    CHECK(states->size == (active ? sizeof(uint32_t) : 0) &&
          (!active || *(const uint32_t *)states->data == XDG_TOPLEVEL_STATE_ACTIVATED),
          "toplevel activation sequence");
    CHECK(width == 64 && height == 48, "configured dimensions");
    client->pending_width = width;
    client->pending_height = height;
    client->pending_activated = active;
    client->pending_configure = 1;
}

static void surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct client *client = data;
    CHECK(client->pending_configure == 1 && client->acks == client->configures &&
          serial != client->serial, "configure sequence/serial");
    const unsigned index = client->configures++;
    client->serial = serial;
    client->width = client->pending_width;
    client->height = client->pending_height;
    client->activated = client->pending_activated;
    client->pending_configure = 0;
    emit("MULTI_CLIENT CONFIG id=%u seq=%u s=%u w=%d h=%d active=%u\n",
         client->id, index, serial, client->width, client->height, client->activated);
    xdg_surface_ack_configure(surface, serial);
    client->acks++;
    emit("MULTI_CLIENT ACK id=%u seq=%u serial=%u\n", client->id, index, serial);
}
static const struct xdg_surface_listener surface_listener = {.configure = surface_configure};

static void toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)toplevel;
    struct client *client = data;
    const unsigned frames = client->id == 1 ? 5 : 4;
    CHECK(client->phase == frames - 1 && client->input_complete == 1 &&
          client->received_code == 16 && client->callbacks == frames &&
          client->closed++ == 0, "close ordering/count");
    emit("MULTI_CLIENT CLOSE id=%u n=1\n", client->id);
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
    emit("MULTI_CLIENT CALLBACK id=%u f=%u time=%u\n",
         frame->client->id, frame->phase, time);
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)buffer;
    struct frame *frame = data;
    CHECK(frame->released++ == 0, "duplicate buffer release");
    frame->client->releases++;
    emit("MULTI_CLIENT RELEASE id=%u f=%u\n",
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
    const int width = 64, height = 48;
    static const unsigned seeds[2][MAX_FRAMES] = {{0, 272, 48, 273, 32}, {0, 30, 272, 46, 0}};
    const unsigned seed = phase == 0 ? 0 : client->received_code;
    CHECK(seed == seeds[client->id - 1][phase], "physical seed");
    const size_t size = (size_t)width * (size_t)height * sizeof(uint32_t);
    CHECK(client->acks == client->configures && client->acks > 0 &&
          client->width == width && client->height == height, "configure before frame");
    *frame = (struct frame){.client = client, .phase = phase, .size = size};
    int fd = memfd_create("smithay-multi-pixels", MFD_CLOEXEC | MFD_ALLOW_SEALING);
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
    wait_counter(client, &frame->done, "frame callback timeout");
    CHECK(frame->done == 1, "frame callback completion");
    emit("MULTI_CLIENT FRAME id=%u f=%u w=%d h=%d seed=%u\n",
         client->id, phase, width, height, seed);
}



int main(int argc, char **argv) {
    CHECK(argc == 2 && strlen(argv[1]) == 1 && argv[1][0] >= '1' && argv[1][0] <= '2',
          "identity argument");
    struct client client = {.id = (unsigned)(argv[1][0] - '0')};
    const unsigned frame_count = client.id == 1 ? 5 : 4;
    const unsigned configure_count = client.id == 1 ? 4 : 3;
    struct frame frames[MAX_FRAMES] = {0};
    client.xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    CHECK(client.xkb_context, "xkb context");
    client.display = wl_display_connect_to_fd(3);
    CHECK(client.display, "display connection");
    emit("MULTI_CLIENT START id=%u pid=%d fd=3\n",
         client.id, getpid());
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
    xdg_toplevel_set_title(client.toplevel, client.id == 1 ? "CyxiaOS window A" : "CyxiaOS window B");
    xdg_toplevel_set_app_id(client.toplevel, "org.cyxiaos.smithay-multi-client");
    /* The initial empty commit negotiates the role before the first buffer. */
    wl_surface_commit(client.surface);
    wait_counter(&client, &client.configures, "initial configure timeout");
    CHECK(client.configures == 1 && client.acks == 1, "initial configure/ack");
    for (client.phase = 0; client.phase < frame_count; client.phase++) {
        submit_frame(&client, &frames[client.phase]);
        wait_counter(&client, &client.input_complete, "physical input timeout");
        CHECK(client.input_complete == 1 && !client.input_down &&
              client.received_code == expected_input(&client), "input completion");
        if (client.phase == frame_count - 1) wait_counter(&client, &client.closed, "close timeout");
    }
    CHECK(client.closed == 1 && client.configures == configure_count &&
          client.acks == configure_count && client.callbacks == frame_count &&
          client.key_events == 6 && client.button_events == (client.id == 1 ? 4u : 2u) &&
          client.keyboard_enters == 2 && client.keyboard_leaves == 1 &&
          client.pointer_enters == (client.id == 1 ? 1u : 2u) && client.pointer_leaves == 1 &&
          client.motions == (client.id == 1 ? 1u : 0u), "shell/focus/input completion");
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
    emit("MULTI_CLIENT COUNTS id=%u f=%u cb=%u rel=%u ev=%u\n",
         client.id, frame_count, client.callbacks, client.releases, client.key_events + client.button_events);
    emit("MULTI_CLIENT FOCUS id=%u ke=%u kl=%u pe=%u pl=%u\n",
         client.id, client.keyboard_enters, client.keyboard_leaves, client.pointer_enters, client.pointer_leaves);
    emit("MULTI_CLIENT RESULT PASS id=%u configures=%u acks=%u close=1\n",
         client.id, client.configures, client.acks);
    return 0;
}
