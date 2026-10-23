/* Small real Xlib terminal; PTY I/O and shell both execute inside CyxiaOS.
 * Text grid, CR/LF/BS/tab and a bounded ANSI cursor/erase subset, not full xterm.
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cyxia_spawn.h"

#define COLS 120
#define ROWS 48
static char cells[ROWS][COLS];
static int cols = 80, rows = 24, x, y, escape, parameter, params[4], count;
static int protocol_error;
static int on_error(Display *d, XErrorEvent *e) {
    (void)d; fprintf(stderr, "CYXIA_TERMINAL XERROR request=%u code=%u\n", e->request_code, e->error_code);
    protocol_error = 1; return 0;
}
static int bounded(int value, int low, int high) { return value < low ? low : value > high ? high : value; }
static void newline(void) {
    if (++y >= rows) {
        memmove(cells[0], cells[1], (size_t)(rows - 1) * COLS);
        memset(cells[rows - 1], ' ', COLS); y = rows - 1;
    }
}
static int param(int i, int fallback) { return i < count && params[i] ? params[i] : fallback; }
static void byte(unsigned char c) {
    if (escape == 1) { escape = c == '[' ? 2 : 0; parameter = count = 0; return; }
    if (escape == 2) {
        if (c >= '0' && c <= '9') { parameter = bounded(parameter * 10 + c - '0', 0, 999); return; }
        if (c == ';') { if (count < 3) params[count++] = parameter; parameter = 0; return; }
        if (count < 4) params[count++] = parameter;
        switch (c) {
        case 'A': y = bounded(y - param(0, 1), 0, rows - 1); break;
        case 'B': y = bounded(y + param(0, 1), 0, rows - 1); break;
        case 'C': x = bounded(x + param(0, 1), 0, cols - 1); break;
        case 'D': x = bounded(x - param(0, 1), 0, cols - 1); break;
        case 'H': case 'f': y = bounded(param(0, 1) - 1, 0, rows - 1); x = bounded(param(1, 1) - 1, 0, cols - 1); break;
        case 'J':
            if (params[0] == 2 || params[0] == 3) memset(cells, ' ', sizeof cells);
            else if (params[0] == 0) {
                memset(cells[y] + x, ' ', (size_t)(cols - x));
                for (int i = y + 1; i < rows; ++i) memset(cells[i], ' ', COLS);
            }
            break;
        case 'K':
            if (params[0] == 2) memset(cells[y], ' ', COLS);
            else if (params[0] == 1) memset(cells[y], ' ', (size_t)x + 1);
            else memset(cells[y] + x, ' ', (size_t)(cols - x));
            break;
        default: break;
        }
        escape = 0; return;
    }
    if (c == 27) { escape = 1; return; }
    if (c == '\r') { x = 0; return; }
    if (c == '\n') { newline(); return; }
    if (c == '\b') { if (x) --x; return; }
    if (c == '\t') { x = bounded((x + 8) & ~7, 0, cols - 1); return; }
    if (c < 32 || c == 127) return;
    cells[y][x++] = c >= 32 && c < 127 ? (char)c : '?';
    if (x >= cols) { x = 0; newline(); }
}
static void draw(Display *d, Window w, GC gc, int cw, int ch, int ascent) {
    for (int row = 0; row < rows; ++row)
        XDrawImageString(d, w, gc, 8, 8 + row * ch + ascent, cells[row], cols);
    XDrawLine(d, w, gc, 8 + x * cw, 8 + (y + 1) * ch - 1, 8 + (x + 1) * cw - 1, 8 + (y + 1) * ch - 1);
    XFlush(d);
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0); memset(cells, ' ', sizeof cells);
    XSetErrorHandler(on_error);
    Display *display = XOpenDisplay(":0");
    if (!display) { perror("CYXIA_TERMINAL XOpenDisplay"); return 1; }
    XFontStruct *font = XLoadQueryFont(display, "fixed");
    if (!font) { fprintf(stderr, "CYXIA_TERMINAL fixed font missing\n"); XCloseDisplay(display); return 1; }
    int cw = font->max_bounds.width, ch = font->ascent + font->descent;
    int screen = DefaultScreen(display);
    Window window = XCreateSimpleWindow(display, RootWindow(display, screen), 60, 60,
        (unsigned)(cols * cw + 16), (unsigned)(rows * ch + 16), 0, 0, 0x101820);
    XStoreName(display, window, "CyxiaOS Terminal");
    XClassHint class_hint = {"cyxia-terminal", "CyxiaTerminal"}; XSetClassHint(display, window, &class_hint);
    Atom delete_window = XInternAtom(display, "WM_DELETE_WINDOW", False); XSetWMProtocols(display, window, &delete_window, 1);
    XSizeHints hints = {0}; hints.flags = PMinSize | PMaxSize | PResizeInc | PBaseSize;
    hints.min_width = cw * 20 + 16; hints.min_height = ch * 5 + 16;
    hints.max_width = cw * COLS + 16; hints.max_height = ch * ROWS + 16;
    hints.width_inc = cw; hints.height_inc = ch; hints.base_width = hints.base_height = 16;
    XSetWMNormalHints(display, window, &hints);
    XSelectInput(display, window, ExposureMask | KeyPressMask | StructureNotifyMask);
    GC gc = XCreateGC(display, window, 0, 0); XSetFont(display, gc, font->fid);
    XSetForeground(display, gc, 0xe0ecf0); XSetBackground(display, gc, 0x101820);
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    int unlock = 0, slave = -1;
    if (master >= 0 && !ioctl(master, TIOCSPTLCK, &unlock)) slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) { perror("CYXIA_TERMINAL PTY"); if (master >= 0) close(master); XCloseDisplay(display); return 1; }
    struct winsize size = {(unsigned short)rows, (unsigned short)cols, 0, 0};
    if (ioctl(master, TIOCSWINSZ, &size)) { perror("CYXIA_TERMINAL winsize"); return 1; }
    char *args[] = {"/bin/cyxia-sh", 0};
    char *env[] = {"HOME=/", "PATH=/bin", "TERM=cyxia-basic", "DISPLAY=:0", 0};
    struct cyxia_mapping maps[] = {{slave, 0}, {slave, 1}, {slave, 2}};
    pid_t child = cyxia_spawn(args[0], args, env, maps, 3);
    close(slave);
    if (child < 0) { perror("CYXIA_TERMINAL spawn"); close(master); XCloseDisplay(display); return 1; }
    XMapWindow(display, window); XFlush(display);
    printf("CYXIA_TERMINAL READY child=%d real-pty=1\n", (int)child);
    unsigned char pending[1024]; size_t pending_size = 0;
    int running = 1, dirty = 1, status = 0, reaped = 0;
    while (running && !protocol_error) {
        while (XPending(display)) {
            XEvent event; XNextEvent(display, &event);
            if (event.type == Expose) dirty = 1;
            else if (event.type == ConfigureNotify) {
                int nc = bounded((event.xconfigure.width - 16) / cw, 20, COLS);
                int nr = bounded((event.xconfigure.height - 16) / ch, 5, ROWS);
                if (nc != cols || nr != rows) {
                    cols = nc; rows = nr; x = bounded(x, 0, cols - 1); y = bounded(y, 0, rows - 1);
                    size.ws_row = (unsigned short)rows; size.ws_col = (unsigned short)cols;
                    struct winsize actual;
                    if (ioctl(master, TIOCSWINSZ, &size) || ioctl(master, TIOCGWINSZ, &actual)) {
                        perror("CYXIA_TERMINAL resize"); protocol_error = 1;
                    } else if (actual.ws_row != size.ws_row || actual.ws_col != size.ws_col) {
                        fprintf(stderr, "CYXIA_TERMINAL resize readback mismatch\n"); protocol_error = 1;
                    } else {
                        printf("CYXIA_TERMINAL RESIZE cols=%u rows=%u\n", actual.ws_col, actual.ws_row);
                    }
                    XClearWindow(display, window); dirty = 1;
                }
            } else if (event.type == KeyPress) {
                char text[32]; KeySym symbol;
                int n = XLookupString(&event.xkey, text, sizeof text, &symbol, 0);
                if (symbol == XK_BackSpace) { text[0] = 127; n = 1; }
                else if (symbol == XK_Return || symbol == XK_KP_Enter) { text[0] = '\r'; n = 1; }
                if (n > 0 && (size_t)n <= sizeof pending - pending_size) {
                    memcpy(pending + pending_size, text, (size_t)n); pending_size += (size_t)n;
                } else if (n > 0) XBell(display, 0);
            } else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == delete_window) running = 0;
        }
        if (pending_size) {
            ssize_t n = write(master, pending, pending_size);
            if (n > 0) { pending_size -= (size_t)n; memmove(pending, pending + n, pending_size); }
            else if (n < 0 && errno != EAGAIN && errno != EINTR) running = 0;
        }
        /* Bound each drain so continuous child output cannot starve X events. */
        for (int batch = 0; batch < 8; ++batch) {
            unsigned char data[512]; ssize_t n = read(master, data, sizeof data);
            if (n > 0) { for (ssize_t i = 0; i < n; ++i) byte(data[i]); dirty = 1; }
            else { if (n < 0 && errno != EAGAIN && errno != EINTR && errno != EIO) protocol_error = 1; break; }
        }
        if (dirty) { draw(display, window, gc, cw, ch, font->ascent); dirty = 0; }
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) { reaped = 1; running = 0; }
        else if (result < 0 && errno != EINTR) { perror("CYXIA_TERMINAL waitpid"); protocol_error = 1; }
        if (running) {
            struct pollfd fds[] = {{ConnectionNumber(display), POLLIN, 0}, {master, POLLIN | (pending_size ? POLLOUT : 0), 0}};
            if (poll(fds, 2, 40) < 0 && errno != EINTR) protocol_error = 1;
            if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) protocol_error = 1;
        }
    }
    close(master); /* Actual HUP reaches a surviving controlling shell. */
    if (!reaped) { while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    XFreeGC(display, gc); XFreeFont(display, font); XDestroyWindow(display, window); XCloseDisplay(display);
    printf("CYXIA_TERMINAL EXIT child-status=%d\n", status);
    return protocol_error ? 1 : 0;
}
