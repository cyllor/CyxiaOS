/* Exercise the genuine xkbcommon locale loader and complete guest Compose data. */
#include <stdio.h>
#include <string.h>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-compose.h>

static int check(const char *locale) {
    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
    if (!context) return 1;
    struct xkb_compose_table *table = xkb_compose_table_new_from_locale(context, locale, 0);
    struct xkb_compose_state *state = table ? xkb_compose_state_new(table, 0) : 0;
    int error = !state;
    const xkb_keysym_t sequences[][3] = {
        {XKB_KEY_Multi_key, XKB_KEY_apostrophe, XKB_KEY_a},
        {XKB_KEY_Multi_key, XKB_KEY_o, XKB_KEY_e},
        {XKB_KEY_dead_circumflex, XKB_KEY_space, 0},
    };
    const char *expected[] = {"\xc3\xa1", "\xc5\x93", "^"};
    for (unsigned i = 0; !error && i < 3; ++i) {
        xkb_compose_state_reset(state);
        for (unsigned j = 0; j < 3 && sequences[i][j]; ++j)
            if (xkb_compose_state_feed(state, sequences[i][j]) != XKB_COMPOSE_FEED_ACCEPTED)
                error = 1;
        char utf8[16] = {0};
        if (xkb_compose_state_get_status(state) != XKB_COMPOSE_COMPOSED
            || xkb_compose_state_get_utf8(state, utf8, sizeof utf8) != (int)strlen(expected[i])
            || strcmp(utf8, expected[i])) error = 1;
    }
    if (state) xkb_compose_state_unref(state);
    if (table) xkb_compose_table_unref(table);
    xkb_context_unref(context);
    return error;
}

int main(void) {
    setbuf(stdout, 0);
    puts("COMPOSE_PROBE START");
    const char *locales[] = {"en_US.UTF-8", "C.UTF-8", "C.utf8", "en_US.utf8"};
    for (unsigned i = 0; i < 4; ++i) {
        if (check(locales[i])) {
            printf("COMPOSE_PROBE FAIL locale=%s\n", locales[i]);
            return 1;
        }
        printf("COMPOSE_PROBE %s PASS\n", locales[i]);
    }
    puts("COMPOSE_PROBE PASS");
    return 0;
}
