/* Host-only validation using the same upstream XKM reader as the target server. */
#include <stdio.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <X11/extensions/XKBfile.h>
#include <X11/extensions/XKM.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    XkbInitAtoms(NULL);
    XkbFileInfo info = {0};
    unsigned required = XkmKeyNamesMask | XkmTypesMask | XkmCompatMapMask |
                        XkmSymbolsMask | XkmGeometryMask | XkmVirtualModsMask;
    unsigned missing = XkmReadFile(file, required, 0, &info);
    fclose(file);
    if (missing || !info.xkb || (info.defined & required) != required) return 4;
    XkbDescPtr xkb = info.xkb;
    if (!xkb->names || !xkb->names->keys || !xkb->map || !xkb->geom ||
        xkb->min_key_code != 8 || xkb->max_key_code != 255) return 5;
    /* Linux evdev code + 8, as delivered by the planned VirtIO input DDX. */
    const struct { unsigned code; const char *name; KeySym normal, shifted; } keys[] = {
        {24, "AD01", XK_q, XK_Q}, {38, "AC01", XK_a, XK_A},
        {11, "AE02", XK_2, XK_at}, {36, "RTRN", XK_Return, XK_Return},
        {50, "LFSH", XK_Shift_L, XK_Shift_L},
    };
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        unsigned code = keys[i].code;
        if (memcmp(xkb->names->keys[code].name, keys[i].name, 4) ||
            XkbKeyNumGroups(xkb, code) < 1 ||
            XkbKeySymEntry(xkb, code, 0, 0) != keys[i].normal) return 6;
        if (keys[i].shifted != keys[i].normal && XkbKeyGroupWidth(xkb, code, 0) < 2)
            return 7;
        if (XkbKeyGroupWidth(xkb, code, 0) > 1 &&
            XkbKeySymEntry(xkb, code, 1, 0) != keys[i].shifted) return 7;
    }
    if (!(xkb->map->modmap[50] & ShiftMask)) return 8;
    XkbFreeKeyboard(xkb, XkbAllComponentsMask, True);
    puts("XKM_READ_PASS evdev_us keycodes=8..255 q/Q a/A 2/@ Return Shift");
    return 0;
}
