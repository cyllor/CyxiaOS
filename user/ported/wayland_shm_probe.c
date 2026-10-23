#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-server.h>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#include "cyxia_spawn.h"

/* Protocol/shared-page acceptance only: no output renderer or physical input. */
static void emit(const char *format, ...) {
    char line[256];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n <= 0 || (size_t)n >= sizeof(line)) _exit(2);
    size_t sent = 0;
    while (sent < (size_t)n) {
        ssize_t written = write(1, line + sent, (size_t)n - sent);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) _exit(2);
        sent += (size_t)written;
    }
}
static void fail(const char *why) {
    emit("WAYLAND_SHM FAIL pid=%d reason=%s errno=%d\n", getpid(), why, errno);
    exit(1);
}
#define CHECK(test, why) do { if (!(test)) fail(why); } while (0)
static const char keymap_text[] =
 "xkb_keymap {\n"
 " xkb_keycodes \"cyxia-probe\" { minimum=8; maximum=255;"
 " <AC01>=38; <LFSH>=50; <CAPS>=66; <LCTL>=37; };\n"
 " xkb_types \"cyxia-probe\" {"
 " type \"ONE_LEVEL\" { modifiers=None; map[None]=Level1; };"
 " type \"ALPHABETIC\" { modifiers=Shift+Lock; map[None]=Level1;"
 " map[Shift]=Level2; map[Lock]=Level2; map[Shift+Lock]=Level1; }; };\n"
 " xkb_compatibility \"cyxia-probe\" {"
 " interpret Shift_L+AnyOf(all) { action=SetMods(modifiers=Shift); };"
 " interpret Control_L+AnyOf(all) { action=SetMods(modifiers=Control); };"
 " interpret Caps_Lock+AnyOf(all) { action=LockMods(modifiers=Lock); }; };\n"
 " xkb_symbols \"cyxia-probe\" {"
 " key <AC01> { type=\"ALPHABETIC\", [ a, A ] };"
 " key <LFSH> { type=\"ONE_LEVEL\", [ Shift_L ] };"
 " key <LCTL> { type=\"ONE_LEVEL\", [ Control_L ] };"
 " key <CAPS> { type=\"ONE_LEVEL\", repeat=no, [ Caps_Lock ] };"
 " modifier_map Shift { <LFSH> }; modifier_map Lock { <CAPS> };"
 " modifier_map Control { <LCTL> }; };\n"
 "};\n";
static int width(unsigned frame) { return frame ? 48 : 64; }
static int height(unsigned frame) { return frame ? 37 : 48; }
static uint32_t pixel(unsigned round, unsigned frame, unsigned x, unsigned y) {
    return 0xff000000u | (((x + round * 3 + frame * 17) & 255) << 16) |
        (((y * 3 + frame * 7) & 255) << 8) | ((x ^ y ^ round ^ frame) & 255);
}
static uint32_t frame_token(unsigned round, unsigned frame) { return 0xca00 + round * 16 + frame; }

struct server_state { unsigned round, commits, surfaces, keymaps, disconnected; };
struct surface_state {
    struct server_state *server;
    struct wl_resource *buffer, *callback;
    unsigned commits;
};
static void destroy_resource(struct wl_client *client, struct wl_resource *resource) {
    (void)client; wl_resource_destroy(resource);
}
static void surface_gone(struct wl_resource *resource) {
    struct surface_state *state = wl_resource_get_user_data(resource);
    if (state->callback) wl_resource_destroy(state->callback);
    state->server->surfaces--;
    free(state);
}
static void surface_attach(struct wl_client *client, struct wl_resource *resource,
                           struct wl_resource *buffer, int32_t x, int32_t y) {
    (void)client;
    struct surface_state *state = wl_resource_get_user_data(resource);
    CHECK(buffer && !state->buffer && x == 0 && y == 0, "attach");
    state->buffer = buffer;
}
static void surface_damage(struct wl_client *client, struct wl_resource *resource,
                           int32_t x, int32_t y, int32_t w, int32_t h) {
    (void)client; (void)resource; (void)x; (void)y; (void)w; (void)h;
}
static void surface_frame(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct surface_state *state = wl_resource_get_user_data(resource);
    CHECK(!state->callback, "duplicate frame");
    state->callback = wl_resource_create(client, &wl_callback_interface, 1, id);
    CHECK(state->callback, "frame resource");
}
static void surface_region(struct wl_client *client, struct wl_resource *resource,
                           struct wl_resource *region) {
    (void)client; (void)resource; CHECK(!region, "unexpected region");
}
static void surface_commit(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    struct surface_state *state = wl_resource_get_user_data(resource);
    unsigned phase = state->commits, round = state->server->round;
    CHECK(phase < 2 && state->buffer && state->callback, "commit state");
    struct wl_shm_buffer *buffer = wl_shm_buffer_get(state->buffer);
    CHECK(buffer && wl_shm_buffer_get_width(buffer) == width(phase) &&
          wl_shm_buffer_get_height(buffer) == height(phase) &&
          wl_shm_buffer_get_stride(buffer) == width(phase) * 4 &&
          wl_shm_buffer_get_format(buffer) == WL_SHM_FORMAT_XRGB8888, "shm metadata");
    wl_shm_buffer_begin_access(buffer);
    const uint32_t *pixels = wl_shm_buffer_get_data(buffer);
    CHECK(pixels, "shm data");
    for (int y = 0; y < height(phase); y++)
        for (int x = 0; x < width(phase); x++)
            CHECK(pixels[y * width(phase) + x] == pixel(round, phase, x, y), "shared pixel");
    wl_shm_buffer_end_access(buffer);
    wl_callback_send_done(state->callback, frame_token(round, phase));
    wl_resource_destroy(state->callback);
    state->callback = NULL;
    wl_buffer_send_release(state->buffer);
    state->buffer = NULL;
    state->commits++;
    state->server->commits++;
    emit("WAYLAND_SHM PIXELS PASS round=%u frame=%u pixels=%d\n", round, phase, width(phase) * height(phase));
}
static const struct wl_surface_interface surface_implementation = {
    .destroy = destroy_resource, .attach = surface_attach, .damage = surface_damage,
    .frame = surface_frame, .set_opaque_region = surface_region,
    .set_input_region = surface_region, .commit = surface_commit
};
static void create_surface(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct server_state *server = wl_resource_get_user_data(resource);
    struct surface_state *state = calloc(1, sizeof(*state));
    CHECK(state, "surface allocation");
    state->server = server;
    struct wl_resource *surface = wl_resource_create(client, &wl_surface_interface, 1, id);
    CHECK(surface, "surface resource");
    wl_resource_set_implementation(surface, &surface_implementation, state, surface_gone);
    server->surfaces++;
}
static void create_region(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)client; (void)resource; (void)id; fail("unused region request");
}
static const struct wl_compositor_interface compositor_implementation = {create_surface, create_region};
static void bind_compositor(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)version;
    struct wl_resource *resource = wl_resource_create(client, &wl_compositor_interface, 1, id);
    CHECK(resource, "compositor resource");
    wl_resource_set_implementation(resource, &compositor_implementation, data, NULL);
}
static void get_keyboard(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct server_state *server = wl_resource_get_user_data(resource);
    struct wl_resource *keyboard = wl_resource_create(client, &wl_keyboard_interface, 1, id);
    CHECK(keyboard, "keyboard resource");
    wl_resource_set_implementation(keyboard, NULL, NULL, NULL);
    int fd = memfd_create("wl-keymap", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    CHECK(fd >= 0 && ftruncate(fd, sizeof(keymap_text)) == 0 &&
          write(fd, keymap_text, sizeof(keymap_text)) == sizeof(keymap_text), "keymap memfd");
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) == 0, "keymap seals");
    wl_keyboard_send_keymap(keyboard, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd, sizeof(keymap_text));
    CHECK(close(fd) == 0, "keymap original close");
    server->keymaps++;
}
static void unexpected_input(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)client; (void)resource; (void)id; fail("unused input request");
}
static const struct wl_seat_interface seat_implementation = {
    .get_pointer = unexpected_input, .get_keyboard = get_keyboard, .get_touch = unexpected_input
};
static void bind_seat(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)version;
    struct wl_resource *resource = wl_resource_create(client, &wl_seat_interface, 1, id);
    CHECK(resource, "seat resource");
    wl_resource_set_implementation(resource, &seat_implementation, data, NULL);
    wl_seat_send_capabilities(resource, WL_SEAT_CAPABILITY_KEYBOARD);
}
struct disconnect_listener { struct wl_listener listener; struct server_state *server; };
static void disconnected(struct wl_listener *listener, void *data) {
    (void)data;
    struct disconnect_listener *state = wl_container_of(listener, state, listener);
    state->server->disconnected++;
    wl_list_remove(&listener->link);
}
static uint64_t milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock");
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int run_server(void) {
    struct server_state state = {0};
    struct wl_display *display = wl_display_create();
    CHECK(display && wl_display_init_shm(display) == 0, "server shm init");
    struct wl_global *compositor = wl_global_create(display, &wl_compositor_interface, 1, &state, bind_compositor);
    struct wl_global *seat = wl_global_create(display, &wl_seat_interface, 1, &state, bind_seat);
    CHECK(compositor && seat, "server globals");
    for (unsigned round = 0; round < 2; round++) {
        state.round = round;
        int pair[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "socketpair");
        struct wl_client *client = wl_client_create(display, pair[0]);
        CHECK(client, "server client");
        struct disconnect_listener listener = {.listener.notify = disconnected, .server = &state};
        wl_client_add_destroy_listener(client, &listener.listener);
        char number[2] = {(char)('0' + round), 0};
        char *argv[] = {"wayland-shm-probe", "client", number, NULL};
        char *env[] = {NULL};
        struct cyxia_mapping mappings[] = {{-2, 0}, {1, 1}, {2, 2}, {pair[1], 3}};
        pid_t child = cyxia_spawn("/bin/wayland-shm-probe", argv, env, mappings, 4);
        CHECK(child > 0 && child != getpid(), "native spawn");
        CHECK(close(pair[1]) == 0, "parent client socket close");
        emit("WAYLAND_SHM SPAWN parent=%d child=%d round=%u\n", getpid(), child, round);
        uint64_t deadline = milliseconds() + 15000;
        while (state.disconnected <= round) {
            CHECK(milliseconds() < deadline, "server timeout");
            wl_display_flush_clients(display);
            CHECK(wl_event_loop_dispatch(wl_display_get_event_loop(display), 10) >= 0 || errno == EINTR,
                  "server dispatch");
        }
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "client exit");
        CHECK(state.surfaces == 0 && state.commits == (round + 1) * 2 && state.keymaps == round + 1, "reconnect cleanup");
        emit("WAYLAND_SHM RECONNECT PASS round=%u surfaces=0\n", round);
    }
    wl_global_destroy(seat);
    wl_global_destroy(compositor);
    wl_display_destroy_clients(display);
    wl_display_destroy(display);
    emit("WAYLAND_SHM PASS connections=2 frames=4 keymaps=2 distinct_processes=3 render=0\n");
    return 0;
}

struct client_state {
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    unsigned round, keymaps, formats;
};
static void keymap(void *data, struct wl_keyboard *keyboard, uint32_t format, int fd, uint32_t size) {
    (void)keyboard;
    struct client_state *client = data;
    CHECK(format == WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 && size == sizeof(keymap_text), "keymap format");
    char *text = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(text != MAP_FAILED && close(fd) == 0, "keymap fd map");
    CHECK(memcmp(text, keymap_text, size) == 0, "keymap contents");
    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES | XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    CHECK(context, "xkb context");
    struct xkb_keymap *map = xkb_keymap_new_from_string(context, text, XKB_KEYMAP_FORMAT_TEXT_V1, 0);
    CHECK(map, "xkb keymap");
    CHECK(munmap(text, size) == 0, "keymap unmap");
    struct xkb_state *state = xkb_state_new(map);
    CHECK(state && xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a, "xkb base");
    xkb_state_update_key(state, 50, XKB_KEY_DOWN);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_A, "xkb shift");
    xkb_state_update_key(state, 50, XKB_KEY_UP);
    xkb_state_update_key(state, 66, XKB_KEY_DOWN); xkb_state_update_key(state, 66, XKB_KEY_UP);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_A, "xkb caps");
    xkb_state_update_key(state, 66, XKB_KEY_DOWN); xkb_state_update_key(state, 66, XKB_KEY_UP);
    xkb_state_update_key(state, 37, XKB_KEY_DOWN);
    char control[8] = {0};
    CHECK(xkb_state_key_get_utf8(state, 38, control, sizeof(control)) == 1 && control[0] == 1, "xkb control");
    xkb_state_unref(state); xkb_keymap_unref(map); xkb_context_unref(context);
    client->keymaps++;
    emit("WAYLAND_SHM KEYMAP PASS round=%u pid=%d shift=1 caps=1 ctrl=1\n", client->round, getpid());
}
static const struct wl_keyboard_listener keyboard_listener = {.keymap = keymap};
static void capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct client_state *state = data;
    CHECK(capabilities == WL_SEAT_CAPABILITY_KEYBOARD && !state->keyboard, "seat capabilities");
    state->keyboard = wl_seat_get_keyboard(seat);
    CHECK(state->keyboard && wl_keyboard_add_listener(state->keyboard, &keyboard_listener, state) == 0, "keyboard listener");
}
static const struct wl_seat_listener seat_listener = {.capabilities = capabilities};
static void format(void *data, struct wl_shm *shm, uint32_t format) {
    (void)shm;
    struct client_state *state = data;
    if (format == WL_SHM_FORMAT_XRGB8888) state->formats++;
}
static const struct wl_shm_listener shm_listener = {.format = format};
static void global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    struct client_state *state = data;
    CHECK(version >= 1, "global version");
    if (!strcmp(interface, "wl_compositor")) {
        CHECK(!state->compositor, "duplicate compositor");
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 1);
    } else if (!strcmp(interface, "wl_shm")) {
        CHECK(!state->shm, "duplicate shm");
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        CHECK(state->shm && wl_shm_add_listener(state->shm, &shm_listener, state) == 0, "shm listener");
    } else if (!strcmp(interface, "wl_seat")) {
        CHECK(!state->seat, "duplicate seat");
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
        CHECK(state->seat && wl_seat_add_listener(state->seat, &seat_listener, state) == 0, "seat listener");
    }
}
static void global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name; fail("unexpected global removal");
}
static const struct wl_registry_listener registry_listener = {global, global_remove};
struct frame_state { unsigned round, frame, done, released; };
static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    struct frame_state *state = data;
    CHECK(time == frame_token(state->round, state->frame) && state->done++ == 0, "frame callback");
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener callback_listener = {.done = frame_done};
static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)buffer;
    struct frame_state *state = data;
    CHECK(state->released++ == 0, "buffer release");
}
static const struct wl_buffer_listener buffer_listener = {.release = buffer_release};
static int run_client(unsigned round) {
    struct client_state state = {.round = round};
    struct wl_display *display = wl_display_connect_to_fd(3);
    CHECK(display, "client display");
    struct wl_registry *registry = wl_display_get_registry(display);
    CHECK(registry && wl_registry_add_listener(registry, &registry_listener, &state) == 0, "registry listener");
    for (unsigned i = 0; i < 3; i++) CHECK(wl_display_roundtrip(display) >= 0, "registry roundtrip");
    CHECK(state.compositor && state.shm && state.seat && state.keymaps == 1 && state.formats == 1, "client globals");
    struct wl_surface *surface = wl_compositor_create_surface(state.compositor);
    CHECK(surface, "client surface");
    for (unsigned phase = 0; phase < 2; phase++) {
        size_t size = (size_t)width(phase) * height(phase) * 4;
        int fd = memfd_create("wl-pixels", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        CHECK(fd >= 0 && ftruncate(fd, size) == 0, "pixel memfd");
        CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) == 0, "pixel seals");
        uint32_t *pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(pixels != MAP_FAILED, "pixel map");
        struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, fd, (int)size);
        CHECK(pool, "client pool");
        struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, width(phase), height(phase),
                                                            width(phase) * 4, WL_SHM_FORMAT_XRGB8888);
        CHECK(buffer, "client buffer");
        struct frame_state frame = {.round = round, .frame = phase};
        CHECK(wl_buffer_add_listener(buffer, &buffer_listener, &frame) == 0, "buffer listener");
        wl_shm_pool_destroy(pool);
        CHECK(close(fd) == 0 && wl_display_roundtrip(display) >= 0, "pool import barrier");
        /* The server has imported the FD before these writes: copying at transfer fails. */
        for (int y = 0; y < height(phase); y++)
            for (int x = 0; x < width(phase); x++) pixels[y * width(phase) + x] = pixel(round, phase, x, y);
        wl_surface_attach(surface, buffer, 0, 0);
        struct wl_callback *callback = wl_surface_frame(surface);
        CHECK(callback && wl_callback_add_listener(callback, &callback_listener, &frame) == 0, "frame listener");
        wl_surface_damage(surface, 0, 0, width(phase), height(phase));
        wl_surface_commit(surface);
        CHECK(wl_display_roundtrip(display) >= 0 && frame.done == 1 && frame.released == 1, "frame roundtrip");
        emit("WAYLAND_SHM FRAME PASS round=%u frame=%u done=1 release=1 after_import_write=1\n", round, phase);
        wl_buffer_destroy(buffer);
        CHECK(wl_display_roundtrip(display) >= 0 && munmap(pixels, size) == 0, "frame cleanup");
    }
    wl_surface_destroy(surface);
    wl_keyboard_destroy(state.keyboard); wl_seat_destroy(state.seat);
    wl_shm_destroy(state.shm); wl_compositor_destroy(state.compositor); wl_registry_destroy(registry);
    CHECK(wl_display_roundtrip(display) >= 0, "client final roundtrip");
    wl_display_disconnect(display);
    emit("WAYLAND_SHM CLIENT PASS round=%u pid=%d frames=2\n", round, getpid());
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 1) return run_server();
    CHECK(argc == 3 && !strcmp(argv[1], "client") && strlen(argv[2]) == 1 &&
          (argv[2][0] == '0' || argv[2][0] == '1'), "arguments");
    return run_client((unsigned)(argv[2][0] - '0'));
}
