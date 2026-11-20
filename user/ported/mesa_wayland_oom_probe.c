/* Real EGL error propagation and recovery at the unchanged memfd boundary. */
#define _GNU_SOURCE
#define main retained_egl_draw_probe_main
#include "wayland_egl_probe.c"
#undef main
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

/* A real duplicate keeps the old shared backing live across native resize.
 * Allocation, truncation, mapping and denial still use the genuine target libc
 * and kernel. Only this diagnostic links --wrap=memfd_create. */
static int backing_references[16], backing_count, retain_backings = 1;
int __real_memfd_create(const char *name, unsigned flags);
int __wrap_memfd_create(const char *name, unsigned flags) {
    int fd = __real_memfd_create(name, flags);
    if (fd >= 0 && retain_backings) {
        if (backing_count == 16) { puts("MESA_WAYLAND_OOM_PROBE FAIL reference-limit"); exit(2); }
        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (copy < 0) { puts("MESA_WAYLAND_OOM_PROBE FAIL reference-dup"); exit(2); }
        backing_references[backing_count++] = copy;
    }
    return fd;
}

struct oom_window {
    struct wl_surface *surface;
    struct zwlr_layer_surface_v1 *layer;
    struct wl_egl_window *window;
    EGLSurface target;
    int configured;
};
static void oom_configure(void *data, struct zwlr_layer_surface_v1 *layer,
                          uint32_t serial, uint32_t width, uint32_t height) {
    (void)width; (void)height;
    zwlr_layer_surface_v1_ack_configure(layer, serial);
    ((struct oom_window *)data)->configured = 1;
}
static void oom_closed(void *data, struct zwlr_layer_surface_v1 *layer) {
    (void)layer; ((struct oom_window *)data)->configured = -1;
}
static const struct zwlr_layer_surface_v1_listener oom_events = {oom_configure, oom_closed};
static int make_window(struct wl_display *display, EGLDisplay egl, EGLConfig config,
                       struct oom_window *window, unsigned anchor) {
    window->surface = wl_compositor_create_surface(compositor);
    window->layer = zwlr_layer_shell_v1_get_layer_surface(shell, window->surface, NULL,
        ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY, "cyxia-mesa-oom-probe");
    zwlr_layer_surface_v1_add_listener(window->layer, &oom_events, window);
    zwlr_layer_surface_v1_set_size(window->layer, WIDTH, HEIGHT);
    zwlr_layer_surface_v1_set_anchor(window->layer, ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM | anchor);
    wl_surface_commit(window->surface);
    while (!window->configured) if (wl_display_dispatch(display) < 0) return 0;
    if (window->configured < 0) return 0;
    window->window = wl_egl_window_create(window->surface, WIDTH, HEIGHT);
    window->target = eglCreateWindowSurface(egl, config, (EGLNativeWindowType)window->window, NULL);
    return window->window && window->target != EGL_NO_SURFACE;
}
int main(void) {
    setbuf(stdout, NULL);
    if (setenv("XDG_RUNTIME_DIR", "/run/user/0", 1)) return 1;
    puts("MESA_WAYLAND_OOM_PROBE START");
    struct wl_display *wayland = wl_display_connect("wayland-1");
    if (!wayland || wl_display_roundtrip(wayland) < 0) return fail("connect");
    puts("WAYLAND_EGL_PROBE CONNECTION PASS");
    EGLDisplay egl = eglGetPlatformDisplay(EGL_PLATFORM_WAYLAND_KHR, wayland, NULL);
    if (egl == EGL_NO_DISPLAY || !eglInitialize(egl, NULL, NULL)) return fail("initialize");
    puts("WAYLAND_EGL_PROBE INITIALIZE PASS");
    struct wl_registry *registry = wl_display_get_registry(wayland);
    wl_registry_add_listener(registry, &globals, NULL);
    if (wl_display_roundtrip(wayland) < 0 || !compositor || !shell) return fail("globals");
    EGLint attrs[] = {EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT_KHR,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE};
    EGLConfig config; EGLint count;
    if (!eglBindAPI(EGL_OPENGL_ES_API) || !eglChooseConfig(egl, attrs, &config, 1, &count) || count != 1)
        return fail("config");
    struct oom_window windows[1] = {0};
    if (!make_window(wayland, egl, config, &windows[0], ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT))
        return fail("layer-configure");
    puts("WAYLAND_EGL_PROBE LAYER_CONFIGURE PASS");
    EGLint context_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
    EGLContext context = eglCreateContext(egl, config, EGL_NO_CONTEXT, context_attrs);
    if (context == EGL_NO_CONTEXT || !eglMakeCurrent(egl, windows[0].target, windows[0].target, context))
        return fail("first-context");
    puts("WAYLAND_EGL_PROBE WINDOW_CONTEXT PASS");
    glClearColor(0, 0, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    if (!eglSwapBuffers(egl, windows[0].target)) return fail("healthy-first-swap");
    if (backing_count < 1) return fail("reference-retention-not-reached");
    printf("MESA_WAYLAND_OOM_PROBE RETAIN_REFERENCE PASS descriptors=%d\n", backing_count);
    if (eglGetCurrentSurface(EGL_DRAW) != windows[0].target) return fail("current-target");
    puts("MESA_WAYLAND_OOM_PROBE CURRENT_TARGET PASS");
    int files[16], used = 0;
    for (; used < 16; ++used) {
        files[used] = syscall(SYS_memfd_create, "egl-oom-boundary", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (files[used] < 0) break;
    }
    if (used == 16 || errno != ENOMEM) return fail("metadata-boundary");
    printf("MESA_WAYLAND_OOM_PROBE SATURATE PASS held=%d errno=%d\n", used, errno);
    wl_egl_window_resize(windows[0].window, WIDTH, HEIGHT + 1, 0, 0);
    (void)eglGetError();
    EGLBoolean swapped = eglSwapBuffers(egl, windows[0].target);
    EGLint error = eglGetError();
    if (swapped != EGL_FALSE || error != EGL_BAD_ALLOC) {
        printf("MESA_WAYLAND_OOM_PROBE FAIL SWAP_ERROR returned=%u egl=0x%x\n", swapped, error);
        return 1;
    }
    puts("MESA_WAYLAND_OOM_PROBE SWAP_ERROR PASS");
    PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC damaged = (PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC)eglGetProcAddress("eglSwapBuffersWithDamageKHR");
    if (!damaged || damaged(egl, windows[0].target, NULL, 0) != EGL_FALSE || eglGetError() != EGL_BAD_ALLOC)
        return fail("damage-error");
    puts("MESA_WAYLAND_OOM_PROBE DAMAGE_ERROR PASS");
    for (int i = 0; i < used; ++i) if (close(files[i])) return fail("release-metadata");
    retain_backings = 0;
    for (int i = 0; i < backing_count; ++i) if (close(backing_references[i])) return fail("release-references");
    wl_egl_window_resize(windows[0].window, WIDTH, HEIGHT, 0, 0);
    if (!eglMakeCurrent(egl, windows[0].target, windows[0].target, context)) return fail("recover-context");
    glViewport(0, 0, WIDTH, HEIGHT); glEnable(GL_SCISSOR_TEST);
    glScissor(0, 0, WIDTH / 2, HEIGHT); glClearColor(1, 0, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    glScissor(WIDTH / 2, 0, WIDTH / 2, HEIGHT); glClearColor(0, 1, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    unsigned char pixels[WIDTH * HEIGHT * 4];
    glReadPixels(0, 0, WIDTH, HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    if (glGetError() != GL_NO_ERROR) return fail("recovered-readback");
    for (unsigned y = 0; y < HEIGHT; ++y) for (unsigned x = 0; x < WIDTH; ++x) {
        unsigned char *p = pixels + 4 * (y * WIDTH + x);
        if (p[0] != (x < WIDTH / 2 ? 255 : 0) || p[1] != (x < WIDTH / 2 ? 0 : 255) || p[2] || p[3] != 255)
            return fail("recovered-pixels");
    }
    puts("WAYLAND_EGL_PROBE READBACK PASS");
    puts("MESA_WAYLAND_OOM_PROBE RECOVERY PASS");
    struct wl_callback *callback = wl_surface_frame(windows[0].surface);
    wl_callback_add_listener(callback, &frame_events, NULL);
    if (!eglSwapBuffers(egl, windows[0].target)) return fail("recovered-swap");
    puts("WAYLAND_EGL_PROBE SWAP PASS");
    while (!framed) if (wl_display_dispatch(wayland) < 0) return fail("recovered-frame");
    puts("WAYLAND_EGL_PROBE FRAME_READY");
    for (unsigned i = 0; i < 10000 && access("/egl-frame-captured", F_OK); ++i) {
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    if (access("/egl-frame-captured", F_OK)) return fail("host-capture-timeout");
    eglMakeCurrent(egl, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    for (int i = 0; i < 1; ++i) {
        eglDestroySurface(egl, windows[i].target); wl_egl_window_destroy(windows[i].window);
        zwlr_layer_surface_v1_destroy(windows[i].layer); wl_surface_destroy(windows[i].surface);
    }
    eglDestroyContext(egl, context); eglTerminate(egl);
    zwlr_layer_shell_v1_destroy(shell); wl_compositor_destroy(compositor); wl_registry_destroy(registry);
    wl_display_disconnect(wayland);
    puts("WAYLAND_EGL_PROBE PASS");return 0;
}
