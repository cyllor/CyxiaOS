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
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>

/* Independent libwayland client. Only actual wl_seat events advance frames.
 * The compositor verifies/presents these shared pixels in its own process. */
enum { FRAME_COUNT = 3, EVENT_TIMEOUT_MS = 30000, KEYMAP_LIMIT = 65536 };

struct client {
    unsigned round, phase, formats, callbacks, releases;
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct wl_surface *surface;
    struct xkb_context *xkb_context;
    struct xkb_keymap *keymap;
    struct xkb_state *xkb_state;
    bool keyboard_focus, pointer_focus, input_down, motion;
    unsigned input_complete, keymaps;
    uint32_t received_key, received_button;
    wl_fixed_t pointer_x, pointer_y;
};

struct frame {
    struct client *client;
    unsigned done, released;
};

static void emit(const char *format, ...) {
    char line[320];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (length <= 0 || (size_t)length >= sizeof(line)) _exit(2);
    for (size_t sent = 0; sent < (size_t)length;) {
        ssize_t result = write(STDOUT_FILENO, line + sent, (size_t)length - sent);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) _exit(2);
        sent += (size_t)result;
    }
}

static void fail(const char *why) {
    emit("SMITHAY_CLIENT FAIL pid=%d reason=%s errno=%d\n", getpid(), why, errno);
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
    emit("SMITHAY_CLIENT KEYMAP PASS round=%u bytes=%u\n", client->round, size);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface, struct wl_array *keys) {
    (void)keyboard; (void)serial; (void)keys;
    struct client *client = data;
    CHECK(surface == client->surface && client->xkb_state, "keyboard focus");
    client->keyboard_focus = true;
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                           struct wl_surface *surface) {
    (void)keyboard; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface, "keyboard leave");
    client->keyboard_focus = false;
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                         uint32_t time, uint32_t code, uint32_t state) {
    (void)keyboard; (void)serial; (void)time;
    struct client *client = data;
    CHECK(client->keyboard_focus && client->xkb_state, "key without focus");
    CHECK((client->phase == 0 && code == 30) || (client->phase == 2 && code == 16),
          "unexpected physical key");
    const xkb_keysym_t expected = client->phase == 0 ? XKB_KEY_a : XKB_KEY_q;
    CHECK(xkb_state_key_get_one_sym(client->xkb_state, code + 8) == expected, "keymap translation");
    if (state == WL_KEYBOARD_KEY_STATE_PRESSED) {
        CHECK(!client->input_down && !client->input_complete, "duplicate key press");
        client->input_down = true;
        client->received_key = code;
    } else {
        CHECK(state == WL_KEYBOARD_KEY_STATE_RELEASED && client->input_down &&
              !client->input_complete, "key release ordering");
        client->input_down = false;
        client->input_complete++;
    }
    emit("SMITHAY_CLIENT KEY round=%u frame=%u code=%u state=%u keysym=%u\n",
         client->round, client->phase, code, state, expected);
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
    CHECK(surface == client->surface, "pointer focus");
    client->pointer_focus = true;
    client->pointer_x = x;
    client->pointer_y = y;
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface) {
    (void)pointer; (void)serial;
    struct client *client = data;
    CHECK(surface == client->surface, "pointer leave");
    client->pointer_focus = false;
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                           wl_fixed_t x, wl_fixed_t y) {
    (void)pointer; (void)time;
    struct client *client = data;
    CHECK(client->pointer_focus && client->phase == 1, "unexpected physical motion");
    CHECK(x == client->pointer_x + wl_fixed_from_int(4) &&
          y == client->pointer_y + wl_fixed_from_int(3), "physical motion delta");
    CHECK(x >= 0 && x < wl_fixed_from_int(64) && y >= 0 && y < wl_fixed_from_int(48),
          "physical motion bounds");
    CHECK(!client->motion, "duplicate physical motion");
    client->pointer_x = x;
    client->pointer_y = y;
    client->motion = true;
    emit("SMITHAY_CLIENT MOTION round=%u frame=%u x_fixed=%d y_fixed=%d dx=4 dy=3\n",
         client->round, client->phase, x, y);
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                           uint32_t time, uint32_t button, uint32_t state) {
    (void)pointer; (void)serial; (void)time;
    struct client *client = data;
    CHECK(client->phase == 1 && client->pointer_focus && client->motion && button == 272,
          "unexpected physical button");
    if (state == WL_POINTER_BUTTON_STATE_PRESSED) {
        CHECK(!client->input_down && !client->input_complete, "duplicate button press");
        client->input_down = true;
        client->received_button = button;
    } else {
        CHECK(state == WL_POINTER_BUTTON_STATE_RELEASED && client->input_down &&
              !client->input_complete, "button release ordering");
        client->input_down = false;
        client->input_complete++;
    }
    emit("SMITHAY_CLIENT BUTTON round=%u frame=%u code=%u state=%u\n",
         client->round, client->phase, button, state);
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
    CHECK(frame->client->input_complete == 1, "frame callback before real input");
    frame->client->callbacks++;
    emit("SMITHAY_CLIENT CALLBACK round=%u frame=%u time=%u\n",
         frame->client->round, frame->client->phase, time);
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)buffer;
    struct frame *frame = data;
    CHECK(frame->released++ == 0, "duplicate buffer release");
    frame->client->releases++;
}
static const struct wl_buffer_listener buffer_listener = {.release = buffer_release};

static uint32_t pixel(unsigned round, unsigned phase, unsigned seed, unsigned x, unsigned y) {
    unsigned red = (3 * x + y + 29 * round + 47 * phase + seed) & 255;
    unsigned green = (x + 5 * y + 11 * round + 31 * phase + 3 * seed) & 255;
    unsigned blue = (7 * (x ^ y) + 13 * round + 19 * phase + 5 * seed) & 255;
    return 0xff000000u | (red << 16) | (green << 8) | blue;
}

static void submit_frame(struct client *client) {
    const unsigned phase = client->phase;
    const int width = phase == 2 ? 96 : 64;
    const int height = phase == 2 ? 64 : 48;
    const unsigned seed = phase == 0 ? 0 : phase == 1 ? client->received_key : client->received_button;
    CHECK(seed == (phase == 0 ? 0u : phase == 1 ? 30u : 272u), "physical seed");
    const size_t size = (size_t)width * (size_t)height * sizeof(uint32_t);
    struct frame frame = {.client = client};
    int fd = memfd_create("smithay-client-pixels", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    CHECK(fd >= 0 && ftruncate(fd, (off_t)size) == 0, "pixel memfd");
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) == 0, "pixel seals");
    uint32_t *pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(pixels != MAP_FAILED, "shared pixel mapping");
    struct wl_shm_pool *pool = wl_shm_create_pool(client->shm, fd, (int)size);
    CHECK(pool, "shm pool");
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, width, height, width * 4,
                                                        WL_SHM_FORMAT_ARGB8888);
    CHECK(buffer && wl_buffer_add_listener(buffer, &buffer_listener, &frame) == 0, "buffer listener");
    wl_shm_pool_destroy(pool);
    CHECK(close(fd) == 0, "pixel fd close");
    synchronize(client);
    /* FD transfer and server import precede these writes. A copied FD payload
     * cannot pass the independent compositor's exact rendered-pixel oracle. */
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++)
            pixels[y * width + x] = pixel(client->round, phase, seed, (unsigned)x, (unsigned)y);
    client->input_complete = 0;
    client->input_down = false;
    client->motion = false;
    wl_surface_attach(client->surface, buffer, 0, 0);
    wl_surface_damage_buffer(client->surface, 0, 0, width, height);
    struct wl_callback *callback = wl_surface_frame(client->surface);
    CHECK(callback && wl_callback_add_listener(callback, &frame_listener, &frame) == 0, "frame listener");
    wl_surface_commit(client->surface);
    wait_counter(client, &frame.done, "frame/input timeout");
    CHECK(frame.done == 1 && client->input_complete == 1 && !client->input_down,
          "frame/input completion");
    wl_surface_attach(client->surface, NULL, 0, 0);
    wl_surface_commit(client->surface);
    synchronize(client);
    wait_counter(client, &frame.released, "buffer release timeout");
    CHECK(frame.released == 1, "buffer release count");
    wl_buffer_destroy(buffer);
    CHECK(munmap(pixels, size) == 0, "shared pixel unmap");
    synchronize(client);
    emit("SMITHAY_CLIENT FRAME PASS round=%u frame=%u width=%d height=%d seed=%u callback=1 release=1 after_import_write=1\n",
         client->round, phase, width, height, seed);
}

int main(int argc, char **argv) {
    CHECK(argc == 2 && (!strcmp(argv[1], "1") || !strcmp(argv[1], "2")), "round argument");
    struct client client = {.round = (unsigned)(argv[1][0] - '0')};
    client.xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    CHECK(client.xkb_context, "xkb context");
    /* wl_display_connect_to_fd takes ownership of the inherited stream fd. */
    client.display = wl_display_connect_to_fd(3);
    CHECK(client.display, "display connection");
    emit("SMITHAY_CLIENT START round=%u pid=%d fd=3 libwayland=1.24.0\n", client.round, getpid());
    client.registry = wl_display_get_registry(client.display);
    CHECK(client.registry && wl_registry_add_listener(client.registry, &registry_listener, &client) == 0,
          "registry listener");
    for (unsigned roundtrip = 0; roundtrip < 3; roundtrip++) synchronize(&client);
    CHECK(client.compositor && client.shm && client.seat && client.keyboard && client.pointer &&
          client.formats == 1 && client.keymaps == 1, "required protocol globals");
    client.surface = wl_compositor_create_surface(client.compositor);
    CHECK(client.surface, "surface");
    for (client.phase = 0; client.phase < FRAME_COUNT; client.phase++) submit_frame(&client);
    CHECK(client.callbacks == FRAME_COUNT && client.releases == FRAME_COUNT, "callback/release totals");
    wl_keyboard_release(client.keyboard);
    wl_pointer_release(client.pointer);
    wl_seat_release(client.seat);
    synchronize(&client);
    wl_surface_destroy(client.surface);
    wl_shm_destroy(client.shm);
    wl_compositor_destroy(client.compositor);
    wl_registry_destroy(client.registry);
    synchronize(&client);
    wl_display_disconnect(client.display);
    xkb_state_unref(client.xkb_state);
    xkb_keymap_unref(client.keymap);
    xkb_context_unref(client.xkb_context);
    emit("SMITHAY_CLIENT RESULT PASS round=%u frames=3 callbacks=3 releases=3 input=1\n", client.round);
    return 0;
}
