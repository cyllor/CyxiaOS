/* Explicit durable save dialog using the guest VirtIO checkpoint service.
 * SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CYXIA_SAVE_BEGIN 0x43595820
#define CYXIA_SAVE_COMPLETE 0x43595821

static const char *failure(int code)
{
    switch (code) {
    case ENODEV: return "No data disk is connected.";
    case EROFS: return "The data disk is read-only.";
    case EBUSY: return "Another save is in progress. Please try again.";
    default: return "The save failed. Your files are still in memory.";
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    Display *display = XOpenDisplay(":0");
    if (!display) { fputs("CYXIA_SAVE FAIL display\n", stderr); return 1; }
    int screen = DefaultScreen(display);
    Window window = XCreateSimpleWindow(display, RootWindow(display, screen), 260, 240,
                                        500, 180, 0, 0, WhitePixel(display, screen));
    XStoreName(display, window, "Save files - CyxiaOS");
    XClassHint hint = {.res_name="cyxia-save", .res_class="CyxiaSave"};
    XSetClassHint(display, window, &hint);
    Atom close = XInternAtom(display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(display, window, &close, 1);
    XSelectInput(display, window, ExposureMask | KeyPressMask | ButtonPressMask);
    GC gc = XCreateGC(display, window, 0, NULL);
    XSetForeground(display, gc, BlackPixel(display, screen));
    XFontStruct *font = XLoadQueryFont(display, "fixed");
    if (font) XSetFont(display, gc, font->fid);
    XMapWindow(display, window);
    XFlush(display);
    long generation = syscall(CYXIA_SAVE_BEGIN);
    const char *message = generation < 0 ? failure(errno) : "Saving current files to disk...";
    int pending = generation >= 0, redraw = 1, running = 1;
    if (pending) printf("CYXIA_SAVE BEGIN generation=%ld\n", generation);
    else printf("CYXIA_SAVE REJECT errno=%d\n", errno);
    while (running) {
        while (XPending(display)) {
            XEvent event; XNextEvent(display, &event);
            if (event.type == Expose) redraw = 1;
            if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == close) running = 0;
            if (event.type == KeyPress) {
                KeySym key = XLookupKeysym(&event.xkey, 0);
                if (key == XK_Return || key == XK_Escape) running = 0;
            }
            if (event.type == ButtonPress && event.xbutton.x >= 390 && event.xbutton.x <= 470
                    && event.xbutton.y >= 125 && event.xbutton.y <= 155) running = 0;
        }
        if (pending) {
            long completed = syscall(CYXIA_SAVE_COMPLETE, generation);
            if (completed >= generation) {
                pending = 0; redraw = 1;
                message = "Current files are saved. You can restart safely.";
                printf("CYXIA_SAVE DURABLE generation=%ld\n", generation);
            } else if (errno != EAGAIN) {
                pending = 0; redraw = 1; message = failure(errno);
                printf("CYXIA_SAVE FAIL errno=%d\n", errno);
            }
        }
        if (redraw) {
            XClearWindow(display, window);
            XDrawString(display, window, gc, 24, 46, "CyxiaOS files", 13);
            XDrawString(display, window, gc, 24, 82, message, (int)strlen(message));
            const char *note = pending ? "Closing this window will not cancel the save." : "Use Save Files again after making more changes.";
            XDrawString(display, window, gc, 24, 108, note, (int)strlen(note));
            XDrawRectangle(display, window, gc, 390, 125, 80, 30);
            XDrawString(display, window, gc, 414, 145, "Close", 5);
            XFlush(display);
            redraw = 0;
        }
        struct pollfd descriptor = {.fd=ConnectionNumber(display), .events=POLLIN};
        if (poll(&descriptor, 1, pending ? 20 : 100) < 0 && errno != EINTR) break;
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
    }
    if (font) XFreeFont(display, font);
    XFreeGC(display, gc);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return 0;
}
