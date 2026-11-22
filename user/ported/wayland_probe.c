#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-server.h>

/* Genuine upstream protocol transport, not a compositor or a rendering test. */
static struct wl_display *server;
static int stop_server, server_error;
static unsigned bindings;
static struct wl_output *output;
static unsigned globals, geometry_ok, mode_ok, done_ok, scale_ok;

static void fail(const char *message) {
    fprintf(stderr, "WAYLAND_PROBE FAIL %s errno=%d\n", message, errno);
    exit(1);
}

static void bind_output(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *resource = wl_resource_create(client, &wl_output_interface,
                                                     version < 2 ? version : 2, id);
    if (!resource) { wl_client_post_no_memory(client); return; }
    wl_resource_set_implementation(resource, NULL, NULL, NULL);
    bindings++;
    wl_output_send_geometry(resource, 0, 0, 300, 200, WL_OUTPUT_SUBPIXEL_UNKNOWN,
                            "CyxiaOS", "Wayland transport probe", WL_OUTPUT_TRANSFORM_NORMAL);
    wl_output_send_mode(resource, WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED,
                       640, 480, 60000);
    if (version >= 2) {
        wl_output_send_scale(resource, 1);
        wl_output_send_done(resource);
    }
}

static void *serve(void *unused) {
    (void)unused;
    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    while (!__atomic_load_n(&stop_server, __ATOMIC_ACQUIRE)) {
        wl_display_flush_clients(server);
        if (wl_event_loop_dispatch(loop, 10) < 0 && errno != EINTR) {
            __atomic_store_n(&server_error, 1, __ATOMIC_RELEASE);
            break;
        }
    }
    wl_display_destroy_clients(server);
    return NULL;
}

static void geometry(void *data, struct wl_output *object, int32_t x, int32_t y,
                     int32_t width, int32_t height, int32_t subpixel,
                     const char *make, const char *model, int32_t transform) {
    (void)data; (void)object;
    geometry_ok += x == 0 && y == 0 && width == 300 && height == 200 &&
        subpixel == WL_OUTPUT_SUBPIXEL_UNKNOWN && strcmp(make, "CyxiaOS") == 0 &&
        strcmp(model, "Wayland transport probe") == 0 && transform == WL_OUTPUT_TRANSFORM_NORMAL;
}
static void mode(void *data, struct wl_output *object, uint32_t flags,
                 int32_t width, int32_t height, int32_t refresh) {
    (void)data; (void)object;
    mode_ok += flags == (WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED) &&
        width == 640 && height == 480 && refresh == 60000;
}
static void done(void *data, struct wl_output *object) {
    (void)data; (void)object; done_ok++;
}
static void scale(void *data, struct wl_output *object, int32_t factor) {
    (void)data; (void)object; scale_ok += factor == 1;
}
static const struct wl_output_listener output_listener = {
    .geometry = geometry, .mode = mode, .done = done, .scale = scale
};
static void global(void *data, struct wl_registry *registry, uint32_t name,
                   const char *interface, uint32_t version) {
    (void)data;
    if (strcmp(interface, "wl_output") == 0 && version == 2) {
        globals++;
        output = wl_registry_bind(registry, name, &wl_output_interface, 2);
        if (!output || wl_output_add_listener(output, &output_listener, NULL)) fail("bind");
    }
}
static void global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
    fail("unexpected global removal");
}
static const struct wl_registry_listener registry_listener = {global, global_remove};

static void ancillary_transfer(void) {
    int pair[2], pipe_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) fail("ancillary socketpair");
    if (pipe2(pipe_fds, O_NONBLOCK) || fcntl(pipe_fds[1], F_GETFD) != 0)
        fail("ancillary pipe");
    char payload = 'X';
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    int invalid_fd = -1;
    memcpy(CMSG_DATA(header), &invalid_fd, sizeof(invalid_fd));
    if (sendmsg(pair[0], &message, MSG_DONTWAIT | MSG_NOSIGNAL) != -1 || errno != EBADF)
        fail("ancillary invalid descriptor");
    if (recv(pair[1], &payload, 1, MSG_DONTWAIT) != -1 || errno != EAGAIN)
        fail("rejected ancillary leaked payload");
    puts("WAYLAND_PROBE ANCILLARY_REJECT bad_fd=1 no_payload=1");

    payload = 'R';
    memcpy(CMSG_DATA(header), &pipe_fds[1], sizeof(pipe_fds[1]));
    if (sendmsg(pair[0], &message, MSG_DONTWAIT | MSG_NOSIGNAL) != 1 || close(pipe_fds[1]))
        fail("ancillary send and close");
    if (read(pipe_fds[0], &payload, 1) != -1 || errno != EAGAIN)
        fail("queued ancillary lost writer");

    payload = 0;
    memset(&control, 0, sizeof(control));
    if (recvmsg(pair[1], &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) != 1 || payload != 'R' ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        fail("ancillary receive payload");
    header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int)))
        fail("ancillary receive control");
    int received_fd;
    memcpy(&received_fd, CMSG_DATA(header), sizeof(received_fd));
    if (fcntl(received_fd, F_GETFD) != FD_CLOEXEC || write(received_fd, "P", 1) != 1 ||
        read(pipe_fds[0], &payload, 1) != 1 || payload != 'P')
        fail("ancillary received writer");
    /* EOF with the sockets still open proves the queue released its writer reference. */
    if (close(received_fd) || read(pipe_fds[0], &payload, 1) != 0)
        fail("ancillary writer not released");
    if (close(pipe_fds[0]) || close(pair[0]) || close(pair[1])) fail("ancillary cleanup");
    puts("WAYLAND_PROBE ANCILLARY_TRANSFER cloexec=1 pipe_eof=1");
}

int main(void) {
    setbuf(stdout, NULL);
    ancillary_transfer();
    server = wl_display_create();
    if (!server) fail("server display");
    struct wl_global *advertisement = wl_global_create(server, &wl_output_interface, 2, NULL, bind_output);
    if (!advertisement) fail("server global");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) fail("socketpair");
    if (!wl_client_create(server, pair[0])) fail("server client");
    struct wl_display *client = wl_display_connect_to_fd(pair[1]);
    if (!client) fail("client display");
    pthread_t worker;
    if (pthread_create(&worker, NULL, serve, NULL)) fail("server thread");
    struct wl_registry *registry = wl_display_get_registry(client);
    if (!registry || wl_registry_add_listener(registry, &registry_listener, NULL)) fail("registry");
    if (wl_display_roundtrip(client) < 0 || globals != 1) fail("registry roundtrip");
    puts("WAYLAND_PROBE REGISTRY globals=1 interface=wl_output version=2");
    if (wl_display_roundtrip(client) < 0 || geometry_ok != 1 || mode_ok != 1 ||
        done_ok != 1 || scale_ok != 1) fail("output roundtrip");
    puts("WAYLAND_PROBE OUTPUT geometry=1 mode=640x480 refresh=60000 done=1 scale=1");
    wl_output_destroy(output);
    wl_registry_destroy(registry);
    wl_display_disconnect(client);
    __atomic_store_n(&stop_server, 1, __ATOMIC_RELEASE);
    if (pthread_join(worker, NULL) || __atomic_load_n(&server_error, __ATOMIC_ACQUIRE) || bindings != 1)
        fail("server join");
    wl_global_destroy(advertisement);
    wl_display_destroy(server);
    puts("WAYLAND_PROBE PASS upstream=1.24.0 roundtrips=2 server_threads=1 cleanup=1 render=0 fd_passing=1");
    return 0;
}
