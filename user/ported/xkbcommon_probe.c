#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#include <xkbcommon/xkbcommon-names.h>

/* Self-contained fixture: genuine libxkbcommon parses and evaluates every rule.
 * No installed xkeyboard-config or host keyboard events are substituted. */
static const char keymap_text[] =
    "xkb_keymap {\n"
    " xkb_keycodes \"cyxia-probe\" { minimum=8; maximum=255;"
    " <AC01>=38; <LFSH>=50; <CAPS>=66; <LCTL>=37; };\n"
    " xkb_types \"cyxia-probe\" {"
    " type \"ONE_LEVEL\" { modifiers=None; map[None]=Level1; };"
    " type \"ALPHABETIC\" { modifiers=Shift+Lock; map[None]=Level1;"
    " map[Shift]=Level2; map[Lock]=Level2; map[Shift+Lock]=Level1; }; };\n"
    " xkb_compatibility \"cyxia-probe\" {"
    " interpret Shift_L+AnyOf(all) { action=SetMods(modifiers=Shift); };"
    " interpret Control_L+AnyOf(all) { action=SetMods(modifiers=Control); };"
    " interpret Caps_Lock+AnyOf(all) { action=LockMods(modifiers=Lock); }; };\n"
    " xkb_symbols \"cyxia-probe\" {"
    " key <AC01> { type=\"ALPHABETIC\", [ a, A ] };"
    " key <LFSH> { type=\"ONE_LEVEL\", [ Shift_L ] };"
    " key <LCTL> { type=\"ONE_LEVEL\", [ Control_L ] };"
    " key <CAPS> { type=\"ONE_LEVEL\", repeat=no, [ Caps_Lock ] };"
    " modifier_map Shift { <LFSH> }; modifier_map Lock { <CAPS> };"
    " modifier_map Control { <LCTL> }; };\n"
    "};\n";

static unsigned checks;
#define CHECK(condition) do { if (!(condition)) { \
    printf("XKBCOMMON_PROBE FAIL line=%d\n", __LINE__); return 1; \
} ++checks; } while (0)

static int text_is(struct xkb_state *state, unsigned key, const char *expected) {
    char text[8] = {0};
    int size = xkb_state_key_get_utf8(state, key, text, sizeof(text));
    return size == (int)strlen(expected) && !strcmp(text, expected);
}

int main(void) {
    setbuf(stdout, NULL);
    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES |
                                                 XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    CHECK(context != NULL);
    struct xkb_keymap *keymap = xkb_keymap_new_from_string(context, keymap_text,
                                XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
    CHECK(keymap != NULL);
    struct xkb_state *state = xkb_state_new(keymap);
    CHECK(state != NULL);
    CHECK(xkb_keymap_key_by_name(keymap, "AC01") == 38);
    CHECK(xkb_keymap_key_repeats(keymap, 66) == 0);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "a"));
    puts("XKBCOMMON_PROBE KEYMAP parsed=1 base=a");

    xkb_state_update_key(state, 50, XKB_KEY_DOWN);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_SHIFT, XKB_STATE_MODS_DEPRESSED) == 1);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_A && text_is(state, 38, "A"));
    xkb_state_update_key(state, 50, XKB_KEY_UP);
    CHECK(text_is(state, 38, "a"));
    puts("XKBCOMMON_PROBE SHIFT down=A release=a");

    xkb_state_update_key(state, 66, XKB_KEY_DOWN);
    xkb_state_update_key(state, 66, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CAPS, XKB_STATE_MODS_LOCKED) == 1);
    CHECK(text_is(state, 38, "A"));
    xkb_state_update_key(state, 50, XKB_KEY_DOWN);
    CHECK(text_is(state, 38, "a"));
    xkb_state_update_key(state, 50, XKB_KEY_UP);
    xkb_state_update_key(state, 66, XKB_KEY_DOWN);
    xkb_state_update_key(state, 66, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CAPS, XKB_STATE_MODS_LOCKED) == 0);
    CHECK(text_is(state, 38, "a"));
    puts("XKBCOMMON_PROBE CAPS lock=A shift_with_lock=a unlock=a");

    xkb_state_update_key(state, 37, XKB_KEY_DOWN);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CTRL, XKB_STATE_MODS_EFFECTIVE) == 1);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "\001"));
    xkb_state_update_key(state, 37, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CTRL, XKB_STATE_MODS_EFFECTIVE) == 0);
    CHECK(text_is(state, 38, "a"));
    puts("XKBCOMMON_PROBE CTRL utf8=01 release=a");

    char *serialized = xkb_keymap_get_as_string(keymap, XKB_KEYMAP_FORMAT_TEXT_V1);
    CHECK(serialized != NULL);
    struct xkb_keymap *copy = xkb_keymap_new_from_string(context, serialized,
                                XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
    CHECK(copy != NULL);
    struct xkb_state *copy_state = xkb_state_new(copy);
    CHECK(copy_state != NULL);
    CHECK(xkb_keymap_key_by_name(copy, "AC01") == 38 && text_is(copy_state, 38, "a"));
    xkb_state_update_key(copy_state, 50, XKB_KEY_DOWN);
    CHECK(text_is(copy_state, 38, "A"));
    CHECK(xkb_keymap_new_from_string(context, "xkb_keymap {", XKB_KEYMAP_FORMAT_TEXT_V1,
                                   XKB_KEYMAP_COMPILE_NO_FLAGS) == NULL);
    puts("XKBCOMMON_PROBE SERIALIZE reparse=1 invalid_rejected=1");
    xkb_state_unref(copy_state);
    xkb_keymap_unref(copy);
    free(serialized);
    xkb_state_unref(state);
    xkb_keymap_unref(keymap);
    xkb_context_unref(context);
    printf("XKBCOMMON_PROBE PASS upstream=1.13.2 checks=%u layouts=embedded full_desktop=false\n", checks);
    return 0;
}
