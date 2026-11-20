/* Actual panel SDK and compositor: render a real layer surface, then sample scanout. */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-egl.h>
#include "layer-shell.h"

enum { WIDTH = 128, HEIGHT = 64 };
static struct wl_compositor *compositor;
static struct zwlr_layer_shell_v1 *shell;
static int configured, closed, framed;

static void global(void *data, struct wl_registry *registry, uint32_t name,
                   const char *interface, uint32_t version) {
    (void)data;
    if (!strcmp(interface, "wl_compositor"))
        compositor = wl_registry_bind(registry, name, &wl_compositor_interface, version < 4 ? version : 4);
    if (!strcmp(interface, "zwlr_layer_shell_v1"))
        shell = wl_registry_bind(registry, name, &zwlr_layer_shell_v1_interface, version < 4 ? version : 4);
}
static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static const struct wl_registry_listener globals = {global, removed};

static void configure(void *data, struct zwlr_layer_surface_v1 *layer,
                      uint32_t serial, uint32_t width, uint32_t height) {
    (void)data; (void)width; (void)height;
    zwlr_layer_surface_v1_ack_configure(layer, serial);
    configured = 1;
}
static void close_layer(void *data, struct zwlr_layer_surface_v1 *layer) {
    (void)data; (void)layer;
    closed = 1;
}
static const struct zwlr_layer_surface_v1_listener layer_events = {configure, close_layer};
static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)data; (void)time;
    framed = 1;
    wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_events = {frame_done};

static int fail(const char *stage) {
    printf("WAYLAND_EGL_PROBE FAIL %s egl=0x%x gl=0x%x errno=%d\n", stage, eglGetError(), glGetError(), errno);
    return 1;
}

int main(void) {
    setbuf(stdout, NULL);
    if (setenv("XDG_RUNTIME_DIR", "/run/user/0", 1)) return 1;
    puts("WAYLAND_EGL_PROBE START");
    struct wl_display *wayland = NULL;
    for (unsigned i = 0; i < 1000 && !wayland; ++i) {
        wayland = wl_display_connect("wayland-1");
        if (!wayland) {
            struct timespec delay = {.tv_nsec = 10000000};
            nanosleep(&delay, NULL);
        }
    }
    if (!wayland) {
        printf("WAYLAND_EGL_PROBE FAIL connect errno=%d\n", errno);
        return 1;
    }
    if (wl_display_roundtrip(wayland) < 0) {
        printf("WAYLAND_EGL_PROBE FAIL roundtrip errno=%d\n", errno);
        return 1;
    }
    puts("WAYLAND_EGL_PROBE CONNECTION PASS");
    EGLDisplay egl = eglGetPlatformDisplay(EGL_PLATFORM_WAYLAND_KHR, wayland, NULL);
    if (egl == EGL_NO_DISPLAY) {
        printf("WAYLAND_EGL_PROBE FAIL display egl=0x%x\n", eglGetError());
        return 1;
    }
    EGLint major = 0, minor = 0;
    if (!eglInitialize(egl, &major, &minor)) {
        printf("WAYLAND_EGL_PROBE FAIL initialize egl=0x%x errno=%d\n", eglGetError(), errno);
        return 1;
    }
    printf("WAYLAND_EGL_PROBE INITIALIZE PASS version=%d.%d\n", major, minor);
    struct wl_registry *registry = wl_display_get_registry(wayland);
    wl_registry_add_listener(registry, &globals, NULL);
    if (wl_display_roundtrip(wayland) < 0 || !compositor || !shell) return fail("globals");
    struct wl_surface *surface = wl_compositor_create_surface(compositor);
    struct zwlr_layer_surface_v1 *layer = zwlr_layer_shell_v1_get_layer_surface(
        shell, surface, NULL, ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY, "cyxia-egl-probe");
    zwlr_layer_surface_v1_add_listener(layer, &layer_events, NULL);
    zwlr_layer_surface_v1_set_size(layer, WIDTH, HEIGHT);
    zwlr_layer_surface_v1_set_anchor(layer,
        ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM | ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT);
    wl_surface_commit(surface);
    while (!configured && !closed) if (wl_display_dispatch(wayland) < 0) return fail("configure-dispatch");
    if (closed) return fail("layer-closed");
    puts("WAYLAND_EGL_PROBE LAYER_CONFIGURE PASS");

    EGLint attrs[] = {EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT_KHR,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE};
    EGLConfig config;
    EGLint count = 0;
    if (!eglBindAPI(EGL_OPENGL_ES_API) || !eglChooseConfig(egl, attrs, &config, 1, &count) || count != 1)
        return fail("config");
    EGLint context_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
    EGLContext context = eglCreateContext(egl, config, EGL_NO_CONTEXT, context_attrs);
    struct wl_egl_window *window = wl_egl_window_create(surface, WIDTH, HEIGHT);
    if (context == EGL_NO_CONTEXT || !window) return fail("window-allocation");
    EGLSurface target = eglCreateWindowSurface(egl, config, (EGLNativeWindowType)window, NULL);
    if (context == EGL_NO_CONTEXT || !window || target == EGL_NO_SURFACE || !eglMakeCurrent(egl, target, target, context))
        return fail("window-context");
    puts("WAYLAND_EGL_PROBE WINDOW_CONTEXT PASS");
    glViewport(0, 0, WIDTH, HEIGHT);
    glEnable(GL_SCISSOR_TEST);
    glScissor(0, 0, WIDTH / 2, HEIGHT);
    glClearColor(1, 0, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    glScissor(WIDTH / 2, 0, WIDTH / 2, HEIGHT);
    glClearColor(0, 1, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    unsigned char pixels[WIDTH * HEIGHT * 4];
    glReadPixels(0, 0, WIDTH, HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    if (glGetError() != GL_NO_ERROR) return fail("readback");
    for (unsigned y = 0; y < HEIGHT; ++y) for (unsigned x = 0; x < WIDTH; ++x) {
        unsigned char *p = pixels + 4 * (y * WIDTH + x);
        if (p[0] != (x < WIDTH / 2 ? 255 : 0) || p[1] != (x < WIDTH / 2 ? 0 : 255) || p[2] || p[3] != 255)
            return fail("readback-pixels");
    }
    puts("WAYLAND_EGL_PROBE READBACK PASS");
    struct wl_callback *callback = wl_surface_frame(surface);
    wl_callback_add_listener(callback, &frame_events, NULL);
    if (!eglSwapBuffers(egl, target)) return fail("swap");
    puts("WAYLAND_EGL_PROBE SWAP PASS");
    while (!framed && !closed) if (wl_display_dispatch(wayland) < 0) return fail("frame-dispatch");
    if (closed) return fail("frame-closed");
    puts("WAYLAND_EGL_PROBE FRAME_READY");
    for (unsigned i = 0; i < 10000 && access("/egl-frame-captured", F_OK); ++i) {
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    if (access("/egl-frame-captured", F_OK)) return fail("host-capture-timeout");
    eglMakeCurrent(egl, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(egl, target);
    eglDestroyContext(egl, context);
    wl_egl_window_destroy(window);
    zwlr_layer_surface_v1_destroy(layer);
    wl_surface_destroy(surface);
    zwlr_layer_shell_v1_destroy(shell);
    wl_compositor_destroy(compositor);
    wl_registry_destroy(registry);
    eglTerminate(egl);
    wl_display_disconnect(wayland);
    puts("WAYLAND_EGL_PROBE PASS");
    return 0;
}
