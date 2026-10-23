/* Real Mesa EGL/GLES3 probe. This is a foundation gate, not COSMIC acceptance. */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl31.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIDE 64

static int failures;

static int check(int value, const char *label)
{
    printf("EGL_PROBE CHECK name=%s result=%s\n", label, value ? "PASS" : "FAIL");
    if (!value)
        ++failures;
    return value;
}

static int has_extension(const char *extensions, const char *name)
{
    size_t size = strlen(name);
    const char *at = extensions;
    while (at && (at = strstr(at, name))) {
        if ((at == extensions || at[-1] == ' ') && (at[size] == 0 || at[size] == ' '))
            return 1;
        at += size;
    }
    return 0;
}

static GLuint shader(GLenum type, const char *source)
{
    GLuint object = glCreateShader(type);
    GLint compiled = 0;
    glShaderSource(object, 1, &source, NULL);
    glCompileShader(object);
    glGetShaderiv(object, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        char message[1024];
        glGetShaderInfoLog(object, sizeof(message), NULL, message);
        printf("EGL_PROBE SHADER_ERROR %s\n", message);
        glDeleteShader(object);
        return 0;
    }
    return object;
}

static int pixels_match(void)
{
    static const unsigned char expected[4][4] = {
        {255, 0, 0, 255}, {0, 255, 0, 255}, {0, 0, 255, 255}, {255, 255, 0, 255}
    };
    unsigned char pixels[SIDE * SIDE * 4];
    glReadPixels(0, 0, SIDE, SIDE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    if (glGetError() != GL_NO_ERROR)
        return 0;
    for (unsigned y = 0; y < SIDE; ++y)
        for (unsigned x = 0; x < SIDE; ++x) {
            unsigned quadrant = (x >= SIDE / 2) + 2 * (y >= SIDE / 2);
            if (memcmp(pixels + (y * SIDE + x) * 4, expected[quadrant], 4)) {
                printf("EGL_PROBE PIXEL_MISMATCH x=%u y=%u\n", x, y);
                return 0;
            }
        }
    return 1;
}

static void texture_pixel(unsigned char out[4], unsigned x, unsigned y, int second, int updated)
{
    out[0] = second ? 252 - x * 4 : x * 4;
    out[1] = second ? 252 - y * 4 : y * 4;
    out[2] = second ? 20 : 8;
    out[3] = 255;
    if (!second && updated && x >= 16 && x < 48 && y >= 16 && y < 48) {
        out[0] = 16; out[1] = 92; out[2] = 200;
    }
}

static int texture_pixels_match(int phase)
{
    unsigned char pixels[SIDE * SIDE * 4];
    glReadPixels(0, 0, SIDE, SIDE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    if (glGetError() != GL_NO_ERROR)
        return 0;
    for (unsigned y = 0; y < SIDE; ++y)
        for (unsigned x = 0; x < SIDE; ++x) {
            unsigned char expected[4];
            int second = phase == 3 ? 0 : (phase == 2 ? x < SIDE / 2 : x >= SIDE / 2);
            if (phase == 4) {
                /* Half a texel in both axes gives four equal nonzero weights.
                 * All varying source channels are multiples of four, so this
                 * is an exact byte oracle even on tile edges and clamp edges. */
                unsigned sum[4] = {0};
                for (unsigned dy = 0; dy < 2; ++dy)
                    for (unsigned dx = 0; dx < 2; ++dx) {
                        unsigned char sample[4];
                        unsigned sx = x + dx < SIDE ? x + dx : SIDE - 1;
                        unsigned sy = y + dy < SIDE ? y + dy : SIDE - 1;
                        texture_pixel(sample, sx, sy, second, 0);
                        for (unsigned channel = 0; channel < 4; ++channel)
                            sum[channel] += sample[channel];
                    }
                for (unsigned channel = 0; channel < 4; ++channel)
                    expected[channel] = sum[channel] / 4;
            } else if (phase == 5 && !second) {
                expected[0] = 16; expected[1] = 92;
                expected[2] = 200; expected[3] = 255;
            } else {
                texture_pixel(expected, x, y, second, phase != 0);
            }
            if (memcmp(pixels + (y * SIDE + x) * 4, expected, 4)) {
                printf("EGL_PROBE TEXTURE_MISMATCH phase=%d x=%u y=%u\n", phase, x, y);
                return 0;
            }
        }
    return 1;
}

/* Exercise real sampler caches across 32-pixel tile boundaries. Keep all
 * sixteen cache entries: linear filtering may retain several tile pointers. */
static GLuint compute_program(const char *source)
{
    GLuint compiled = shader(GL_COMPUTE_SHADER, source);
    GLuint program = compiled ? glCreateProgram() : 0;
    GLint linked = 0;
    if (program) {
        glAttachShader(program, compiled);
        glLinkProgram(program);
        glGetProgramiv(program, GL_LINK_STATUS, &linked);
    }
    if (compiled)
        glDeleteShader(compiled);
    if (!linked && program) {
        glDeleteProgram(program);
        program = 0;
    }
    return program;
}

static int compute_buffer_matches(GLuint seed)
{
    const GLuint *values = glMapBufferRange(GL_SHADER_STORAGE_BUFFER, 0,
                                            SIDE * SIDE * sizeof(GLuint), GL_MAP_READ_BIT);
    int match = values != NULL;
    if (values) {
        for (unsigned i = 0; i < SIDE * SIDE; ++i)
            if (values[i] != seed + i) {
                printf("EGL_PROBE COMPUTE_MISMATCH index=%u expected=%u actual=%u\n",
                       i, seed + i, values[i]);
                match = 0;
                break;
            }
        if (glUnmapBuffer(GL_SHADER_STORAGE_BUFFER) != GL_TRUE)
            match = 0;
    }
    return match && glGetError() == GL_NO_ERROR;
}

static int compute_oom_checks(void)
{
    static GLuint initial[SIDE * SIDE];
    const char *body =
        "layout(std430,binding=0) buffer Target {uint values[];};"
        "uniform highp uint seed;"
        "void main(){uint i=gl_GlobalInvocationID.y*64u+gl_GlobalInvocationID.x;"
        "values[i]=seed+i;}";
    char source[512], label[80];
    GLuint programs[2] = {0}, buffer = 0, expected = 0x13570000u;
    GLint saved_program = 0;
    int ok = 0;
    glGetIntegerv(GL_CURRENT_PROGRAM, &saved_program);
    for (unsigned i = 0; i < 2; ++i) {
        snprintf(source, sizeof(source),
                 "#version 310 es\nlayout(local_size_x=%u,local_size_y=%u) in;%s",
                 i ? 4 : 8, i ? 1 : 8, body);
        programs[i] = compute_program(source);
    }
    if (!check(programs[0] && programs[1], "compute-oom-programs"))
        goto done;
    for (unsigned i = 0; i < SIDE * SIDE; ++i)
        initial[i] = expected + i;
    glGenBuffers(1, &buffer);
    glBindBuffer(GL_SHADER_STORAGE_BUFFER, buffer);
    glBufferData(GL_SHADER_STORAGE_BUFFER, sizeof(initial), initial, GL_DYNAMIC_COPY);
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, buffer);
    if (!check(compute_buffer_matches(expected), "compute-oom-initial-target"))
        goto done;
    for (unsigned cycle = 1; cycle <= 3; ++cycle) {
        glUseProgram(programs[0]);
        glUniform1ui(glGetUniformLocation(programs[0], "seed"), 0xbad00000u + cycle);
        snprintf(label, sizeof(label), "compute-oom-preflight-%u", cycle);
        if (!check(glGetError() == GL_NO_ERROR, label))
            goto done;
        printf("EGL_PROBE COMPUTE_OOM_ATTEMPT cycle=%u local=8x8 grid=8x8\n", cycle);
        glDispatchCompute(8, 8, 1);
        GLenum error = glGetError();
        GLenum cleared = glGetError();
        snprintf(label, sizeof(label), "compute-oom-error-%u", cycle);
        if (!check(error == GL_OUT_OF_MEMORY && cleared == GL_NO_ERROR, label))
            goto done;
        glMemoryBarrier(GL_SHADER_STORAGE_BARRIER_BIT | GL_BUFFER_UPDATE_BARRIER_BIT);
        snprintf(label, sizeof(label), "compute-oom-atomic-%u", cycle);
        if (!check(compute_buffer_matches(expected), label))
            goto done;
        expected += 0x10000u;
        glUseProgram(programs[1]);
        glUniform1ui(glGetUniformLocation(programs[1], "seed"), expected);
        glDispatchCompute(16, 64, 1);
        glMemoryBarrier(GL_SHADER_STORAGE_BARRIER_BIT | GL_BUFFER_UPDATE_BARRIER_BIT);
        snprintf(label, sizeof(label), "compute-oom-recovery-%u", cycle);
        if (!check(compute_buffer_matches(expected), label))
            goto done;
    }
    ok = 1;
done:
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, 0);
    glBindBuffer(GL_SHADER_STORAGE_BUFFER, 0);
    glDeleteBuffers(1, &buffer);
    glUseProgram((GLuint)saved_program);
    if (programs[0]) glDeleteProgram(programs[0]);
    if (programs[1]) glDeleteProgram(programs[1]);
    return ok;
}

static int texture_checks(GLuint vertex)
{
    GLuint textures[2] = {0}, pressure[64] = {0}, fragment = 0, program = 0;
    GLuint recovered = 0, compute = 0, compute_program = 0;
    unsigned char pixels[SIDE * SIDE * 4];
    int ok = 0;
    GLint linked = 0;
    fragment = shader(GL_FRAGMENT_SHADER,
        "#version 300 es\nprecision highp float; in vec2 uv; out vec4 color;"
        "uniform sampler2D a; uniform sampler2D b; uniform float shift;"
        "void main(){vec2 p=uv+vec2(shift);"
        "color=uv.x<0.5?texture(a,p):texture(b,p);}");
    program = glCreateProgram();
    if (fragment && program) {
        glAttachShader(program, vertex);
        glAttachShader(program, fragment);
        glLinkProgram(program);
        glGetProgramiv(program, GL_LINK_STATUS, &linked);
    }
    if (!check(linked, "texture-program"))
        goto done;
    glUseProgram(program);
    glUniform1i(glGetUniformLocation(program, "a"), 0);
    glUniform1i(glGetUniformLocation(program, "b"), 1);
    glGenTextures(2, textures);
    for (unsigned which = 0; which < 2; ++which) {
        for (unsigned y = 0; y < SIDE; ++y)
            for (unsigned x = 0; x < SIDE; ++x)
                texture_pixel(pixels + (y * SIDE + x) * 4, x, y, which, 0);
        glActiveTexture(GL_TEXTURE0 + which);
        glBindTexture(GL_TEXTURE_2D, textures[which]);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGBA8, SIDE, SIDE);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, SIDE, SIDE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    }
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(0), "texture-linear-multiple-views-exact"))
        goto done;
    glUniform1f(glGetUniformLocation(program, "shift"), 0.5f / SIDE);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(4), "texture-bilinear-tile-boundaries-exact"))
        goto done;
    glUniform1f(glGetUniformLocation(program, "shift"), 0);
    /* Make the driver actually unbind view zero before updating its storage:
     * the texture object retains that view and its cache for a later rebind. */
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    glFinish();
    for (unsigned i = 0; i < 32 * 32; ++i) {
        pixels[i * 4] = 16; pixels[i * 4 + 1] = 92;
        pixels[i * 4 + 2] = 200; pixels[i * 4 + 3] = 255;
    }
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 16, 16, 32, 32, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    glBindTexture(GL_TEXTURE_2D, 0);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(1), "texture-unbound-update-invalidates-exact"))
        goto done;
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(2), "texture-rebind-exact"))
        goto done;
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(3), "texture-same-view-two-units-exact"))
        goto done;

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    glFinish();
    glActiveTexture(GL_TEXTURE0);
    /* A is now unbound from every sampled slot, but retains its cache. Image
     * stores modify its resource without the CPU-transfer timestamp update. */
    compute = shader(GL_COMPUTE_SHADER,
        "#version 310 es\nlayout(local_size_x=4,local_size_y=1) in;"
        "layout(rgba8,binding=0) writeonly uniform highp image2D target;"
        "void main(){imageStore(target,ivec2(gl_GlobalInvocationID.xy),"
        "vec4(16.0/255.0,92.0/255.0,200.0/255.0,1));}");
    compute_program = glCreateProgram();
    linked = 0;
    if (compute && compute_program) {
        glAttachShader(compute_program, compute);
        glLinkProgram(compute_program);
        glGetProgramiv(compute_program, GL_LINK_STATUS, &linked);
    }
    if (!check(linked, "texture-image-store-program"))
        goto done;
    glUseProgram(compute_program);
    glBindImageTexture(0, textures[0], 0, GL_FALSE, 0, GL_WRITE_ONLY, GL_RGBA8);
    /* One four-lane TGSI machine fits the guest's fixed heap. Across all
     * 16 × 64 workgroups this still performs 4096 genuine image stores. */
    glDispatchCompute(16, 64, 1);
    glMemoryBarrier(GL_SHADER_IMAGE_ACCESS_BARRIER_BIT | GL_TEXTURE_FETCH_BARRIER_BIT);
    glBindImageTexture(0, 0, 0, GL_FALSE, 0, GL_WRITE_ONLY, GL_RGBA8);
    glUseProgram(program);
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(5), "texture-unbound-image-store-rebind-exact"))
        goto done;
    if (!compute_oom_checks())
        goto done;

    /* Allocate texture storage before forcing view/cache creation, so this
     * negative case observes view admission rather than TexImage allocation. */
    const unsigned char tiny[4] = {61, 127, 193, 255};
    glGenTextures(64, pressure);
    for (unsigned i = 0; i < 64; ++i) {
        glBindTexture(GL_TEXTURE_2D, pressure[i]);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, tiny);
    }
    if (!check(glGetError() == GL_NO_ERROR, "texture-pressure-storage"))
        goto done;
    unsigned admitted = 0;
    GLenum error = GL_NO_ERROR;
    for (; admitted < 64; ++admitted) {
        glBindTexture(GL_TEXTURE_2D, pressure[admitted]);
        glDrawArrays(GL_TRIANGLES, 0, 6);
        error = glGetError();
        if (error != GL_NO_ERROR)
            break;
    }
    printf("EGL_PROBE CACHE_PRESSURE admitted_views=%u error=0x%x\n", admitted, error);
    if (!check(admitted > 0 && admitted < 64 && error == GL_OUT_OF_MEMORY,
               "texture-cache-oom-visible"))
        goto done;
    glBindTexture(GL_TEXTURE_2D, textures[0]);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glDeleteTextures(64, pressure);
    memset(pressure, 0, sizeof(pressure));
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(texture_pixels_match(5), "texture-cache-oom-recovery-exact"))
        goto done;
    /* Existing views surviving OOM cannot prove deleted caches were freed.
     * Force an entirely new view/cache allocation before returning to them. */
    glGenTextures(1, &recovered);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, recovered);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, tiny);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    unsigned char recovered_pixel[4];
    glReadPixels(4, 4, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, recovered_pixel);
    if (!check(glGetError() == GL_NO_ERROR && memcmp(recovered_pixel, tiny, 4) == 0,
               "texture-cache-new-allocation-after-oom"))
        goto done;
    glBindTexture(GL_TEXTURE_2D, textures[1]);
    glDeleteTextures(1, &recovered);
    recovered = 0;
    glDrawArrays(GL_TRIANGLES, 0, 6);
    glFinish();
    ok = 1;
done:
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, 0);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, 0);
    glDeleteTextures(64, pressure);
    glDeleteTextures(2, textures);
    glDeleteTextures(1, &recovered);
    if (compute_program) glDeleteProgram(compute_program);
    if (compute) glDeleteShader(compute);
    if (program) glDeleteProgram(program);
    if (fragment) glDeleteShader(fragment);
    glActiveTexture(GL_TEXTURE0);
    return ok;
}

int main(int argc, char **argv)
{
    const int x11 = argc == 2 && strcmp(argv[1], "x11") == 0;
    EGLDisplay display = EGL_NO_DISPLAY;
    EGLContext context = EGL_NO_CONTEXT;
    EGLSurface surface = EGL_NO_SURFACE;
    Display *xdisplay = NULL;
    Window window = 0;
    Colormap colormap = 0;
    GLuint program = 0, vertex = 0, fragment = 0, vao = 0, vbo = 0, texture = 0, fbo = 0;
    EGLConfig config;
    EGLint count = 0, major = 0, minor = 0;
    const EGLint attributes[] = {EGL_SURFACE_TYPE, x11 ? EGL_WINDOW_BIT : EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE};
    const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
    const EGLint pbuffer_attributes[] = {EGL_WIDTH, SIDE, EGL_HEIGHT, SIDE, EGL_NONE};
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 || (argc == 2 && !x11 && strcmp(argv[1], "offscreen") != 0)) {
        puts("EGL_PROBE FAIL usage=egl-probe_[offscreen|x11]");
        return 2;
    }
    setenv("LIBGL_ALWAYS_SOFTWARE", "1", 1);
    setenv("GALLIUM_DRIVER", "softpipe", 1);
    setenv("MESA_SHADER_CACHE_DISABLE", "true", 1);
    printf("EGL_PROBE START mode=%s\n", x11 ? "x11" : "offscreen");
    if (x11) {
        xdisplay = XOpenDisplay(NULL);
        if (!check(xdisplay != NULL, "x11-open"))
            goto done;
        display = eglGetDisplay((EGLNativeDisplayType)xdisplay);
    } else {
        PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform =
            (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
        if (!check(get_platform != NULL, "platform-proc"))
            goto done;
        display = get_platform(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
    }
    if (!check(display != EGL_NO_DISPLAY && eglInitialize(display, &major, &minor), "egl-initialize"))
        goto done;
    printf("EGL_PROBE EGL version=%d.%d vendor=%s\n", major, minor, eglQueryString(display, EGL_VENDOR));
    if (!check(eglBindAPI(EGL_OPENGL_ES_API), "bind-gles") ||
        !check(eglChooseConfig(display, attributes, &config, 1, &count) && count == 1, "choose-config"))
        goto done;
    context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    if (!check(context != EGL_NO_CONTEXT, "gles3-context"))
        goto done;
    if (x11) {
        EGLint visual_id;
        XVisualInfo query, *visual;
        int visual_count = 0;
        XSetWindowAttributes attrs;
        if (!check(eglGetConfigAttrib(display, config, EGL_NATIVE_VISUAL_ID, &visual_id), "native-visual"))
            goto done;
        query.visualid = (VisualID)visual_id;
        visual = XGetVisualInfo(xdisplay, VisualIDMask, &query, &visual_count);
        if (!check(visual != NULL && visual_count > 0, "x11-visual")) {
            if (visual)
                XFree(visual);
            goto done;
        }
        colormap = XCreateColormap(xdisplay, RootWindow(xdisplay, visual->screen), visual->visual, AllocNone);
        attrs.colormap = colormap;
        attrs.event_mask = StructureNotifyMask | ExposureMask;
        window = XCreateWindow(xdisplay, RootWindow(xdisplay, visual->screen), 120, 100,
                               SIDE, SIDE, 0, visual->depth, InputOutput, visual->visual,
                               CWColormap | CWEventMask, &attrs);
        XFree(visual);
        XStoreName(xdisplay, window, "Cyxia Mesa EGL Probe");
        XMapWindow(xdisplay, window);
        XSync(xdisplay, False);
        surface = eglCreateWindowSurface(display, config, (EGLNativeWindowType)window, NULL);
    } else {
        surface = eglCreatePbufferSurface(display, config, pbuffer_attributes);
    }
    if (!check(surface != EGL_NO_SURFACE, "egl-surface") ||
        !check(eglMakeCurrent(display, surface, surface, context), "make-current"))
        goto done;
    const char *version = (const char *)glGetString(GL_VERSION);
    const char *renderer = (const char *)glGetString(GL_RENDERER);
    const char *extensions = (const char *)glGetString(GL_EXTENSIONS);
    printf("EGL_PROBE GL version=%s renderer=%s\n", version ? version : "null", renderer ? renderer : "null");
    GLint gl_major = 0;
    glGetIntegerv(GL_MAJOR_VERSION, &gl_major);
    if (!check(gl_major >= 3, "gles-version") ||
        !check(renderer && strstr(renderer, "softpipe"), "software-renderer") ||
        !check(has_extension(extensions, "GL_EXT_texture_format_BGRA8888"), "bgra-extension"))
        goto done;
    check(eglGetProcAddress("glCreateShader") != NULL, "gl-proc");
    check(eglGetProcAddress("cyxia_nonexistent_gl_function") == NULL, "unknown-proc-rejected");
    vertex = shader(GL_VERTEX_SHADER,
        "#version 300 es\nlayout(location=0) in vec2 p; out vec2 uv;"
        "void main(){uv=(p+1.0)*0.5;gl_Position=vec4(p,0.0,1.0);}");
    fragment = shader(GL_FRAGMENT_SHADER,
        "#version 300 es\nprecision highp float; in vec2 uv; out vec4 color;"
        "void main(){if(uv.y<0.5)color=uv.x<0.5?vec4(1,0,0,1):vec4(0,1,0,1);"
        "else color=uv.x<0.5?vec4(0,0,1,1):vec4(1,1,0,1);}");
    if (!check(vertex && fragment, "compile-shaders"))
        goto done;
    program = glCreateProgram();
    glAttachShader(program, vertex);
    glAttachShader(program, fragment);
    glLinkProgram(program);
    GLint linked = 0;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (!check(linked, "link-program"))
        goto done;
    const float positions[] = {-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1};
    glGenVertexArrays(1, &vao);
    glBindVertexArray(vao);
    glGenBuffers(1, &vbo);
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(positions), positions, GL_STATIC_DRAW);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, NULL);
    glEnableVertexAttribArray(0);
    glUseProgram(program);
    glDisable(GL_DITHER);
    glViewport(0, 0, SIDE, SIDE);
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, SIDE, SIDE, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
    glGenFramebuffers(1, &fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    if (!check(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE, "rgba8-fbo"))
        goto done;
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(pixels_match(), "fbo-exact-4096-pixels"))
        goto done;
    if (!texture_checks(vertex))
        goto done;
    glUseProgram(program);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawArrays(GL_TRIANGLES, 0, 6);
    if (!check(pixels_match(), "surface-exact-4096-pixels") ||
        !check(eglSwapBuffers(display, surface), "swap"))
        goto done;
    if (x11) {
        XSync(xdisplay, False);
        puts("EGL_PROBE PRESENT window=Cyxia_Mesa_EGL_Probe hold_seconds=5");
        const struct timespec delay = {.tv_sec = 5, .tv_nsec = 0};
        nanosleep(&delay, NULL);
    }
done:
    if (context != EGL_NO_CONTEXT && eglGetCurrentContext() == context) {
        glDeleteFramebuffers(1, &fbo);
        glDeleteTextures(1, &texture);
        glDeleteBuffers(1, &vbo);
        glDeleteVertexArrays(1, &vao);
        if (program) glDeleteProgram(program);
        if (vertex) glDeleteShader(vertex);
        if (fragment) glDeleteShader(fragment);
        check(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT), "release-context");
    }
    if (surface != EGL_NO_SURFACE) check(eglDestroySurface(display, surface), "destroy-surface");
    if (context != EGL_NO_CONTEXT) check(eglDestroyContext(display, context), "destroy-context");
    if (display != EGL_NO_DISPLAY) check(eglTerminate(display), "terminate");
    if (window) XDestroyWindow(xdisplay, window);
    if (colormap) XFreeColormap(xdisplay, colormap);
    if (xdisplay) XCloseDisplay(xdisplay);
    printf("EGL_PROBE RESULT %s mode=%s failures=%d\n", failures ? "FAIL" : "PASS", x11 ? "x11" : "offscreen", failures);
    return failures ? 1 : 0;
}
