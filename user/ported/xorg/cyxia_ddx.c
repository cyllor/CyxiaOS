/* CyxiaOS native software framebuffer DDX for upstream X.Org Kdrive.
 * No host X server, GL, DRM or Linux framebuffer device is used.
 * SPDX-License-Identifier: MIT
 */
#include <dix-config.h>
#include "kdrive.h"
#include "damage.h"
#include "os.h"
#include "cyxia_abi.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static struct cyxia_display_info native_display;
static KdScreenInfo *native_screen;
static OsTimerPtr poll_timer;
static Bool retry_frame, pointer_enabled, keyboard_enabled, dropped, announced;
static KdPointerInfo *native_pointer;
static KdKeyboardInfo *native_keyboard;
static uint32_t tile[CYXIA_MAX_RECT_BYTES / 4];
static uint8_t held_keys[96];
static struct cyxia_input_event pending[128];
static unsigned pending_count;
static int dx, dy, wheel;

static Bool key_held(unsigned code)
{
    return !!(held_keys[code / 8] & (1U << (code % 8)));
}

static void set_held(unsigned code, Bool held)
{
    if (held) held_keys[code / 8] |= 1U << (code % 8);
    else held_keys[code / 8] &= ~(1U << (code % 8));
}

static unsigned pointer_buttons(void)
{
    return (key_held(272) ? KD_BUTTON_1 : 0) |
           (key_held(273) ? KD_BUTTON_3 : 0) |
           (key_held(274) ? KD_BUTTON_2 : 0);
}

static void pointer_report(int x, int y, int scroll)
{
    if (!pointer_enabled) return;
    unsigned buttons = pointer_buttons();
    KdEnqueuePointerEvent(native_pointer, KD_MOUSE_DELTA | buttons, x, y, 0);
    /* Wheel steps are conventional X button 4/5 press-release pairs. */
    unsigned count = scroll < 0 ? (unsigned)-scroll : (unsigned)scroll;
    if (count > 32) count = 32;
    unsigned wheel_button = scroll > 0 ? KD_BUTTON_4 : KD_BUTTON_5;
    for (unsigned i = 0; i < count; ++i) {
        KdEnqueuePointerEvent(native_pointer, KD_MOUSE_DELTA | buttons | wheel_button, 0, 0, 0);
        KdEnqueuePointerEvent(native_pointer, KD_MOUSE_DELTA | buttons, 0, 0, 0);
    }
}

static void key_event(unsigned code, int value)
{
    if (code >= 768 || value < 0 || value > 2) return;
    Bool down = value != 0;
    Bool changed = down != key_held(code);
    if (code < 248 && keyboard_enabled && value != 2 && changed)
        KdEnqueueKeyboardEvent(native_keyboard, code, !down);
    set_held(code, down);
    /* Preserve each button transition, including a press and release contained
     * in one SYN_REPORT frame, instead of reporting only the final bitset. */
    if (code >= 272 && code <= 274 && changed) pointer_report(0, 0, 0);
}

static void resync_input(void)
{
    uint8_t state[96];
    long result = cyxia_input_key_state(state);
    if (result) {
        if (result != -EAGAIN) ErrorF("CyxiaOS: key-state read failed (%ld)\n", result);
        return;
    }
    for (unsigned code = 0; code < 768; ++code)
        key_event(code, !!(state[code / 8] & (1U << (code % 8))));
    pointer_report(0, 0, 0);
    dropped = FALSE;
}

static int bounded_delta(int old, int value)
{
    long long sum = (long long)old + value;
    return sum < -32767 ? -32767 : sum > 32767 ? 32767 : (int)sum;
}

static void input_event(const struct cyxia_input_event *event)
{
    if (event->type == 0 && event->code == 3) { /* SYN_DROPPED */
        dropped = TRUE;
        pending_count = 0;
        dx = dy = wheel = 0;
        return;
    }
    if (event->type == 0 && event->code == 0) { /* SYN_REPORT */
        if (dropped) resync_input();
        else {
            for (unsigned i = 0; i < pending_count; ++i)
                key_event(pending[i].code, pending[i].value);
            pointer_report(dx, dy, wheel);
        }
        pending_count = 0;
        dx = dy = wheel = 0;
        return;
    }
    if (dropped) return;
    if (event->type == 1) { /* EV_KEY, including pointer buttons */
        if (pending_count == sizeof pending / sizeof pending[0]) {
            dropped = TRUE;
            pending_count = 0;
        } else pending[pending_count++] = *event;
    } else if (event->type == 2) { /* EV_REL */
        if (event->code == 0) dx = bounded_delta(dx, event->value);
        else if (event->code == 1) dy = bounded_delta(dy, event->value);
        else if (event->code == 8) wheel = bounded_delta(wheel, event->value);
    }
    /* ABI v1 passes raw evdev ABS values without axis ranges. Absolute tablets
     * are intentionally unsupported; they cannot safely be treated as pixels. */
}

static Bool present_box(int left, int top, int right, int bottom)
{
    KdScreenInfo *screen = native_screen;
    if (!screen || !screen->fb.frameBuffer) return FALSE;
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right > screen->width) right = screen->width;
    if (bottom > screen->height) bottom = screen->height;
    for (int x = left; x < right; ) {
        unsigned width = right - x;
        if (width > native_display.max_rect_bytes / 4) width = native_display.max_rect_bytes / 4;
        unsigned max_rows = native_display.max_rect_bytes / (width * 4);
        for (int y = top; y < bottom; ) {
            unsigned rows = bottom - y;
            if (rows > max_rows) rows = max_rows;
            for (unsigned line = 0; line < rows; ++line)
                memcpy(tile + line * width,
                       screen->fb.frameBuffer + (size_t)(y + line) * screen->fb.byteStride + (size_t)x * 4,
                       (size_t)width * 4);
            long result = cyxia_display_blit(x, y, width, rows, tile, (size_t)width * rows * 4);
            if (result == -EAGAIN) return FALSE;
            if (result) FatalError("CyxiaOS: display submission failed (%ld)\n", result);
            y += rows;
        }
        x += width;
    }
    return TRUE;
}

static void shadow_update(ScreenPtr screen, shadowBufPtr buffer)
{
    RegionPtr damage = DamageRegion(buffer->pDamage);
    BoxPtr boxes = RegionRects(damage);
    int count = RegionNumRects(damage);
    (void)screen;
    for (int i = 0; i < count; ++i)
        if (!present_box(boxes[i].x1, boxes[i].y1, boxes[i].x2, boxes[i].y2))
            retry_frame = TRUE;
    /* shadow clears its damage after this callback. A busy GPU therefore
     * retains an explicit full-frame retry until a later successful fence. */
}

static CARD32 poll_devices(OsTimerPtr timer, CARD32 now, void *argument)
{
    (void)timer; (void)now; (void)argument;
    if (retry_frame && native_screen && native_screen->pScreen &&
        present_box(0, 0, native_screen->width, native_screen->height))
        retry_frame = FALSE;
    if (!announced && pointer_enabled && keyboard_enabled && native_screen && native_screen->pScreen) {
        ErrorF("CYXIA_XORG_READY 1024x768 input=keyboard,mouse\n");
        announced = TRUE;
    }
    if (pointer_enabled || keyboard_enabled) {
        for (unsigned batch = 0; batch < 8; ++batch) {
            struct cyxia_input_event events[CYXIA_MAX_INPUT_EVENTS];
            long count = cyxia_read_input(events, CYXIA_MAX_INPUT_EVENTS);
            if (count == -EAGAIN || count == 0) break;
            if (count < 0 || count > CYXIA_MAX_INPUT_EVENTS)
                FatalError("CyxiaOS: input read failed (%ld)\n", count);
            for (long i = 0; i < count; ++i) input_event(&events[i]);
        }
    }
    return 10;
}

static Bool card_init(KdCardInfo *card)
{
    (void)card;
    long result = cyxia_get_display_info(&native_display);
    if (result || native_display.abi != 1 || native_display.format != CYXIA_PIXEL_XRGB8888_LE ||
        !native_display.width || !native_display.height || native_display.width > 4096 || native_display.height > 4096 ||
        native_display.stride_bytes < native_display.width * 4 || native_display.max_rect_bytes < 4 ||
        native_display.max_rect_bytes > sizeof tile || native_display.max_rect_bytes % 4)
        FatalError("CyxiaOS: incompatible or unavailable display (%ld)\n", result);
    return TRUE;
}

static Bool screen_init(KdScreenInfo *screen)
{
    if (native_screen && native_screen != screen) return FALSE;
    native_screen = screen;
    screen->width = native_display.width;
    screen->height = native_display.height;
    screen->width_mm = native_display.width * 254 / 960;
    screen->height_mm = native_display.height * 254 / 960;
    screen->rate = 60;
    screen->randr = RR_Rotate_0;
    screen->dumb = TRUE;
    screen->softCursor = TRUE;
    screen->fb.depth = 24;
    screen->fb.bitsPerPixel = 32;
    screen->fb.visuals = 1 << TrueColor;
    screen->fb.redMask = 0x00ff0000;
    screen->fb.greenMask = 0x0000ff00;
    screen->fb.blueMask = 0x000000ff;
    if (!KdShadowFbAlloc(screen, FALSE)) return FALSE;
    memset(screen->fb.frameBuffer, 0, (size_t)screen->fb.byteStride * screen->height);
    retry_frame = TRUE;
    return TRUE;
}

#ifdef RANDR
static Bool randr_get_info(ScreenPtr screen, Rotation *rotations)
{
    *rotations = RR_Rotate_0;
    RRScreenSizePtr size = RRRegisterSize(screen, native_screen->width,
                                         native_screen->height, native_screen->width_mm,
                                         native_screen->height_mm);
    if (!size || !RRRegisterRate(screen, size, 60)) return FALSE;
    RRSetCurrentConfig(screen, RR_Rotate_0, 60, size);
    return TRUE;
}

static Bool randr_set_config(ScreenPtr screen, Rotation rotation, int rate, RRScreenSizePtr size)
{
    (void)screen;
    /* The native display ABI v1 exposes one fixed mode, with no mode-setting
     * operation. Accepting the current configuration is the only valid change. */
    return rotation == RR_Rotate_0 && (rate == 0 || rate == 60) &&
           size->width == native_screen->width && size->height == native_screen->height;
}
#endif

static Bool finish_screen(ScreenPtr screen)
{
    if (!shadowSetup(screen)) return FALSE;
#ifdef RANDR
    if (!RRScreenInit(screen)) return FALSE;
    rrScrPrivPtr randr = rrGetScrPriv(screen);
    randr->rrGetInfo = randr_get_info;
    randr->rrSetConfig = randr_set_config;
#endif
    poll_timer = TimerSet(NULL, 0, 10, poll_devices, NULL);
    return poll_timer != NULL;
}

static Bool create_resources(ScreenPtr screen)
{
    return KdShadowSet(screen, RR_Rotate_0, shadow_update, NULL);
}

static void close_screen(ScreenPtr screen)
{
    KdShadowUnset(screen);
    if (poll_timer) TimerFree(poll_timer);
    poll_timer = NULL;
}

static void screen_fini(KdScreenInfo *screen)
{
    KdShadowFbFree(screen);
    native_screen = NULL;
}

static KdCardFuncs card_functions = {
    .cardinit = card_init, .scrinit = screen_init,
    .finishInitScreen = finish_screen, .createRes = create_resources,
    .scrfini = screen_fini, .closeScreen = close_screen,
};

static Status pointer_init(KdPointerInfo *pointer)
{
    pointer->nAxes = 2;
    pointer->nButtons = 5;
    pointer->transformCoordinates = FALSE;
    pointer->emulateMiddleButton = FALSE;
    for (unsigned i = 1; i <= 5; ++i) pointer->map[i] = i;
    native_pointer = pointer;
    return Success;
}
static Status pointer_enable(KdPointerInfo *pointer) { (void)pointer; pointer_enabled = TRUE; return Success; }
static void pointer_disable(KdPointerInfo *pointer) { (void)pointer; pointer_enabled = FALSE; }
static void pointer_fini(KdPointerInfo *pointer) { pointer_disable(pointer); native_pointer = NULL; }
static Status keyboard_init(KdKeyboardInfo *keyboard)
{
    keyboard->minScanCode = 0;
    keyboard->maxScanCode = 247;
    native_keyboard = keyboard;
    return Success;
}
static Status keyboard_enable(KdKeyboardInfo *keyboard) { (void)keyboard; keyboard_enabled = TRUE; return Success; }
static void keyboard_disable(KdKeyboardInfo *keyboard) { (void)keyboard; keyboard_enabled = FALSE; }
static void keyboard_fini(KdKeyboardInfo *keyboard) { keyboard_disable(keyboard); native_keyboard = NULL; }

static KdPointerDriver pointer_driver = {
    .name = "cyxia-relative", .Init = pointer_init, .Enable = pointer_enable,
    .Disable = pointer_disable, .Fini = pointer_fini,
};
static KdKeyboardDriver keyboard_driver = {
    .name = "cyxia-evdev", .Init = keyboard_init, .Enable = keyboard_enable,
    .Disable = keyboard_disable, .Fini = keyboard_fini,
};

void InitCard(char *name) { (void)name; KdCardInfoAdd(&card_functions, NULL); }
void InitOutput(ScreenInfo *info, int argc, char **argv) { KdInitOutput(info, argc, argv); }
void OsVendorInit(void)
{
    if (!KdCardInfoLast()) {
        InitCard(NULL);
        if (!KdScreenInfoAdd(KdCardInfoLast())) FatalError("CyxiaOS: screen allocation failed\n");
    }
}
void InitInput(int argc, char **argv)
{
    (void)argc; (void)argv;
    KdAddKeyboardDriver(&keyboard_driver);
    KdAddPointerDriver(&pointer_driver);
    KdKeyboardInfo *keyboard = KdNewKeyboard();
    KdPointerInfo *pointer = KdNewPointer();
    if (!keyboard || !pointer) FatalError("CyxiaOS: input allocation failed\n");
    keyboard->driver = &keyboard_driver;
    keyboard->xkbRules = strdup("evdev");
    keyboard->xkbModel = strdup("pc105");
    keyboard->xkbLayout = strdup("us");
    if (!keyboard->xkbRules || !keyboard->xkbModel || !keyboard->xkbLayout)
        FatalError("CyxiaOS: keyboard configuration allocation failed\n");
    pointer->driver = &pointer_driver;
    KdAddKeyboard(keyboard);
    KdAddPointer(pointer);
    KdInitInput();
}
void CloseInput(void) { KdCloseInput(); }
void ddxUseMsg(void) { KdUseMsg(); }
int ddxProcessArgument(int argc, char **argv, int i) { return KdProcessArgument(argc, argv, i); }
int main(int argc, char **argv, char **envp) { return dix_main(argc, argv, envp); }
