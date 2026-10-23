/* Query the real guest window manager; this creates no substitute windows.
 * SPDX-License-Identifier: MIT
 */
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <unistd.h>

static int failed;
static int error_handler(Display *d, XErrorEvent *event)
{
    (void)d;
    /* A client can close between the list and the individual query. */
    if (event->error_code != BadWindow) failed = 1;
    return 0;
}

static void quoted(const char *text)
{
    putchar('"');
    if (text) for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static unsigned long property(Display *d, Window w, const char *name, Atom type,
                              unsigned char **data)
{
    Atom actual;
    int format;
    unsigned long count = 0, remaining;
    *data = NULL;
    if (XGetWindowProperty(d, w, XInternAtom(d, name, False), 0, 2048, False,
                           type, &actual, &format, &count, &remaining, data) != Success
            || actual != type || format != 32 || remaining) {
        if (*data) XFree(*data);
        *data = NULL;
        return 0;
    }
    return count;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("X11_INSPECT START pid=%ld\n", (long)getpid());
    XSetErrorHandler(error_handler);
    Display *d = XOpenDisplay(":0");
    if (!d) { puts("X11_INSPECT FAIL display"); return 1; }
    Window root = DefaultRootWindow(d);
    unsigned char *data = NULL;
    unsigned long count = property(d, root, "_NET_SUPPORTING_WM_CHECK", XA_WINDOW, &data);
    if (count != 1) { if (data) XFree(data); XCloseDisplay(d); puts("X11_INSPECT FAIL wm"); return 1; }
    Window wm = ((Window *)data)[0];
    XFree(data);
    data = NULL;
    count = property(d, wm, "_NET_SUPPORTING_WM_CHECK", XA_WINDOW, &data);
    int valid_wm = count == 1 && ((Window *)data)[0] == wm;
    if (data) XFree(data);
    if (!valid_wm) { XCloseDisplay(d); puts("X11_INSPECT FAIL wm-self-check"); return 1; }
    puts("X11_INSPECT WM_READY");
    unsigned long emitted = 0;
    count = property(d, root, "_NET_CLIENT_LIST", XA_WINDOW, &data);
    for (unsigned long i = 0; i < count; ++i) {
        Window w = ((Window *)data)[i], child;
        XWindowAttributes attr;
        if (!XGetWindowAttributes(d, w, &attr) || attr.map_state != IsViewable) continue;
        int x, y;
        if (!XTranslateCoordinates(d, w, root, 0, 0, &x, &y, &child)) continue;
        char *title = NULL;
        XClassHint cls = {0};
        XFetchName(d, w, &title);
        XGetClassHint(d, w, &cls);
        printf("X11_INSPECT WINDOW {\"id\":%lu,\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,\"title\":",
               w, x, y, attr.width, attr.height);
        quoted(title);
        printf(",\"class\":"); quoted(cls.res_class);
        printf(",\"instance\":"); quoted(cls.res_name);
        puts("}");
        ++emitted;
        if (title) XFree(title);
        if (cls.res_class) XFree(cls.res_class);
        if (cls.res_name) XFree(cls.res_name);
    }
    if (data) XFree(data);
    XSync(d, False);
    XCloseDisplay(d);
    if (failed) puts("X11_INSPECT FAIL protocol");
    else printf("X11_INSPECT PASS windows=%lu\n", emitted);
    return failed ? 1 : 0;
}
