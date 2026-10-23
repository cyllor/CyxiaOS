/* Real target Xlib protocol/rendering probe. This is not a desktop shell.
 * SPDX-License-Identifier: MIT
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int protocol_error;

static int on_error(Display *display, XErrorEvent *event)
{
    char message[128];
    XGetErrorText(display, event->error_code, message, sizeof message);
    fprintf(stderr, "X11_PROBE ERROR request=%u minor=%u code=%u %s\n",
            event->request_code, event->minor_code, event->error_code, message);
    protocol_error = 1;
    return 0;
}

static long long milliseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return value.tv_sec * 1000LL + value.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int persistent = argc == 2 && !strcmp(argv[1], "--demo");
    int interactive = persistent || (argc == 2 && !strcmp(argv[1], "--interactive"));
    char input[41] = {0};
    size_t input_len = 0;
    if (argc > 1 && !interactive) {
        fprintf(stderr, "usage: x11-probe [--interactive|--demo]\n");
        return 2;
    }
    puts("X11_PROBE START");
    XSetErrorHandler(on_error);
    Display *display = XOpenDisplay(":0");
    if (!display) {
        fprintf(stderr, "X11_PROBE FAIL open display :0 errno=%d\n", errno);
        return 1;
    }
    int screen = DefaultScreen(display);
    Window window = XCreateSimpleWindow(display, RootWindow(display, screen),
                                         32, 32, 320, 180, 1,
                                         WhitePixel(display, screen), BlackPixel(display, screen));
    XStoreName(display, window, "CyxiaOS native X11 protocol probe");
    Atom delete_window = XInternAtom(display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(display, window, &delete_window, 1);
    XSelectInput(display, window, ExposureMask | KeyPressMask | ButtonPressMask | StructureNotifyMask);
    XMapWindow(display, window);
    XFlush(display);
    /* A real window manager maps asynchronously. Wait for MapNotify rather
     * than reading an unmapped window or assuming a host-side delay. */
    long long map_start = milliseconds();
    int mapped = 0;
    while (!mapped && milliseconds() - map_start < 5000) {
        while (XPending(display)) {
            XEvent event; XNextEvent(display, &event);
            if (event.type == MapNotify) mapped = 1;
        }
        if (!mapped) {
            struct pollfd fd = {ConnectionNumber(display), POLLIN, 0};
            if (poll(&fd, 1, 50) < 0 && errno != EINTR) break;
        }
    }
    if (!mapped) { fprintf(stderr, "X11_PROBE FAIL map timeout\n"); return 1; }
    GC gc = XCreateGC(display, window, 0, NULL);
    XSetForeground(display, gc, WhitePixel(display, screen));
    XFillRectangle(display, window, gc, 20, 20, 80, 60);
    XSync(display, False);
    XImage *pixels = XGetImage(display, window, 20, 20, 1, 1, AllPlanes, ZPixmap);
    if (protocol_error || !pixels || XGetPixel(pixels, 0, 0) != WhitePixel(display, screen)) {
        fprintf(stderr, "X11_PROBE FAIL server pixel readback\n");
        if (pixels) XDestroyImage(pixels);
        XFreeGC(display, gc);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    XDestroyImage(pixels);
    puts("X11_PROBE DRAW PASS real X11 roundtrip and pixel readback");
    XFontStruct *font = XLoadQueryFont(display, "fixed");
    if (font) XSetFont(display, gc, font->fid);
    else {
        fprintf(stderr, "X11_PROBE FAIL built-in fixed font\n");
        protocol_error = 1;
    }
    if (interactive) {
        Window child; int x, y;
        XTranslateCoordinates(display, window, RootWindow(display, screen), 0, 0, &x, &y, &child);
        Window root, parent, *children = NULL; unsigned count;
        if (!XQueryTree(display, window, &root, &parent, &children, &count)) return 1;
        if (children) XFree(children);
        printf("X11_PROBE REPARENTED %s\n", parent != root ? "PASS" : "NONE");
        XChangePointerControl(display, True, True, 1, 1, 0);
        XDrawString(display, window, gc, 20, 120, "Real upstream Xlib on CyxiaOS", 28);
        XFlush(display);
        printf("X11_PROBE WINDOW x=%d y=%d width=320 height=180\n", x, y);
    }
    long long start = milliseconds();
    if (start < 0) protocol_error = 1;
    while (!protocol_error && interactive) {
        long long now = milliseconds();
        if (now < 0) { protocol_error = 1; break; }
        if (!persistent && now - start >= 15000) break;
        while (XPending(display)) {
            XEvent event;
            XNextEvent(display, &event);
            if (event.type == Expose) {
                static const char label[] = "Real upstream Xlib on CyxiaOS";
                XFillRectangle(display, window, gc, 20, 20, 80, 60);
                XDrawString(display, window, gc, 20, 120, label, sizeof label - 1);
                XDrawString(display, window, gc, 20, 150, input, (int)input_len);
            } else if (event.type == KeyPress) {
                char text[32];
                KeySym symbol;
                int length = XLookupString(&event.xkey, text, sizeof text, &symbol, NULL);
                printf("X11_PROBE KEY code=%u keysym=%lu text=%.*s\n",
                       event.xkey.keycode, symbol, length, text);
                if (symbol == XK_Escape) interactive = 0;
                else if (symbol == XK_BackSpace && input_len) input[--input_len] = 0;
                else for (int i = 0; i < length && input_len < sizeof input - 1; ++i) {
                    if (text[i] >= 32 && text[i] <= 126) input[input_len++] = text[i];
                }
                XClearArea(display, window, 0, 130, 0, 40, False);
                XDrawString(display, window, gc, 20, 150, input, (int)input_len);
            } else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == delete_window) {
                interactive = 0;
            } else if (event.type == ConfigureNotify) {
                Window child; int x, y;
                XTranslateCoordinates(display, window, RootWindow(display, screen), 0, 0, &x, &y, &child);
                printf("X11_PROBE GEOMETRY x=%d y=%d width=%d height=%d\n", x, y, event.xconfigure.width, event.xconfigure.height);
            } else if (event.type == ButtonPress) {
                printf("X11_PROBE BUTTON code=%u x=%d y=%d\n",
                       event.xbutton.button, event.xbutton.x, event.xbutton.y);
            }
        }
        XFlush(display);
        struct pollfd fd = {ConnectionNumber(display), POLLIN, 0};
        if (poll(&fd, 1, 50) < 0 && errno != EINTR) protocol_error = 1;
        if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) protocol_error = 1;
    }
    if (font) XFreeFont(display, font);
    XFreeGC(display, gc);
    XDestroyWindow(display, window);
    XSync(display, False);
    XCloseDisplay(display);
    if (protocol_error) return 1;
    puts("X11_PROBE PASS");
    return 0;
}
