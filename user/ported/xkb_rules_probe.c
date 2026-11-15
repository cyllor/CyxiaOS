/* Exercise the installed XKB database through the genuine upstream library.
 * No embedded keymap or host-side keyboard evaluation supplies the results. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#include <xkbcommon/xkbcommon-names.h>

static const char xkb_root[] = "/usr/share/X11/xkb";
static const char rules_path[] = "/usr/share/X11/xkb/rules/evdev";
static unsigned checks;

static int fail(const char *stage, int line) {
    printf("XKBRULES_PROBE FAIL stage=%s line=%d errno=%d\n", stage, line, errno);
    return 1;
}

#define CHECK(condition, stage) do { \
    if (!(condition)) return fail(stage, __LINE__); \
    ++checks; \
} while (0)

static int text_is(struct xkb_state *state, xkb_keycode_t key, const char *expected) {
    char text[16] = {0};
    int size = xkb_state_key_get_utf8(state, key, text, sizeof(text));
    return size == (int)strlen(expected) && !strcmp(text, expected);
}

static int zero_bytes(const unsigned char *bytes, size_t size) {
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int asset_mapping_checks(void) {
    const size_t page_size = 4096;
    struct stat st;
    CHECK(stat(xkb_root, &st) == 0 && S_ISDIR(st.st_mode), "include-directory-stat");
    CHECK(access(xkb_root, R_OK | X_OK) == 0, "include-directory-access");
    int fd = open(rules_path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0, "rules-open");
    CHECK(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > (off_t)page_size &&
          (uintmax_t)st.st_size <= SIZE_MAX - (page_size - 1), "rules-fstat");
    size_t size = (size_t)st.st_size;
    CHECK(size % page_size != 0, "rules-have-partial-final-page");
    size_t rounded = (size + page_size - 1) & ~(page_size - 1);
    size_t last_page = rounded - page_size;
    unsigned char *bytes = malloc(size);
    CHECK(bytes != NULL, "rules-read-buffer");
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, bytes + done, size - done);
        if (n <= 0) return fail("rules-read-complete", __LINE__);
        done += (size_t)n;
    }
    unsigned char extra;
    CHECK(read(fd, &extra, 1) == 0, "rules-read-eof");
    CHECK(lseek(fd, 17, SEEK_SET) == 17, "rules-seek");
    const unsigned char *shared = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED, "rules-mmap-shared");
    CHECK(!memcmp(shared, bytes, size), "rules-mmap-shared-bytes");
    unsigned char *private = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(private != MAP_FAILED, "rules-mmap-private");
    CHECK(!memcmp(private, bytes, size), "rules-mmap-private-bytes");
    CHECK(lseek(fd, 0, SEEK_CUR) == 17, "rules-mmap-preserves-offset");

    CHECK(mmap(NULL, size, PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EACCES,
          "rules-shared-write-rejected");
    CHECK(mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED &&
          errno == EACCES, "rules-shared-rw-rejected");
    CHECK(mprotect((void *)shared, rounded, PROT_READ | PROT_WRITE) == -1 && errno == EACCES,
          "rules-shared-upgrade-rejected");
    CHECK(!memcmp(shared, bytes, size), "rules-shared-failed-upgrade-atomic");
    CHECK(mprotect((void *)shared, rounded, PROT_NONE) == 0, "rules-shared-none");
    CHECK(mprotect((void *)shared, rounded, PROT_READ | PROT_WRITE) == -1 && errno == EACCES,
          "rules-shared-none-upgrade-rejected");
    CHECK(mprotect((void *)shared, rounded, PROT_READ) == 0 && !memcmp(shared, bytes, size),
          "rules-shared-read-restored");

    CHECK(mprotect(private, rounded, PROT_READ | PROT_WRITE) == 0, "rules-private-write-upgrade");
    private[0] ^= 0x5a;
    private[size - 1] ^= 0xa5;
    CHECK(private[0] == (unsigned char)(bytes[0] ^ 0x5a) &&
          private[size - 1] == (unsigned char)(bytes[size - 1] ^ 0xa5) &&
          !memcmp(private + 1, bytes + 1, size - 2) && !memcmp(shared, bytes, size),
          "rules-private-writes-isolated");
    int source_fd = open(rules_path, O_RDONLY | O_CLOEXEC);
    CHECK(source_fd >= 0 && read(source_fd, &extra, 1) == 1 && extra == bytes[0] &&
          lseek(source_fd, (off_t)size - 1, SEEK_SET) == (off_t)size - 1 &&
          read(source_fd, &extra, 1) == 1 && extra == bytes[size - 1] && close(source_fd) == 0,
          "rules-private-writes-preserve-source");
    CHECK(mprotect(private, rounded, PROT_NONE) == 0 &&
          mprotect(private, rounded, PROT_READ) == 0 &&
          private[0] == (unsigned char)(bytes[0] ^ 0x5a), "rules-private-read-restored");
    CHECK(zero_bytes(shared + size, rounded - size) && zero_bytes(private + size, rounded - size),
          "rules-mmap-eof-tail-zero");

    const unsigned char *offset = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, (off_t)last_page);
    CHECK(offset != MAP_FAILED && !memcmp(offset, bytes + last_page, size - last_page) &&
          zero_bytes(offset + size - last_page, rounded - size), "rules-aligned-offset-final-page");
    /* Bypass musl's offset-alignment precheck to exercise the guest validator. */
    CHECK(syscall(SYS_mmap, NULL, page_size, PROT_READ, MAP_SHARED, fd, (off_t)1) == -1 &&
          errno == EINVAL, "rules-unaligned-offset-rejected");
    CHECK(mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, (off_t)rounded) == MAP_FAILED &&
          errno == EINVAL, "rules-offset-beyond-eof-rejected");
    CHECK(mmap(NULL, rounded + 1, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED &&
          errno == EINVAL, "rules-length-beyond-eof-rejected");
    CHECK(lseek(fd, 0, SEEK_CUR) == 17 && !memcmp(shared, bytes, size),
          "rules-mapping-failures-preserve-offset-and-bytes");
    CHECK(close(fd) == 0, "rules-close");
    CHECK(!memcmp(shared, bytes, size) && private[0] == (unsigned char)(bytes[0] ^ 0x5a) &&
          private[size - 1] == (unsigned char)(bytes[size - 1] ^ 0xa5) &&
          !memcmp(private + 1, bytes + 1, size - 2) &&
          !memcmp(offset, bytes + last_page, size - last_page),
          "rules-mappings-survive-close");
    CHECK(munmap((void *)shared, size) == 0 && munmap(private, size) == 0 &&
          munmap((void *)offset, page_size) == 0,
          "rules-unmap");
    free(bytes);
    printf("XKBRULES_PROBE FILE bytes=%zu read=1 shared=1 private=1 close_lifetime=1\n", size);
    puts("XKBRULES_PROBE MMAP shared_write_rejected=1 shared_upgrade_rejected=1 private_isolated=1 eof_zero=1 offset=1 invalid_rejected=1");
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    if (asset_mapping_checks()) return 1;

    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES |
                                                 XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    CHECK(context != NULL, "context-create");
    CHECK(xkb_context_include_path_append(context, xkb_root) == 1, "include-path-append");
    CHECK(xkb_context_num_include_paths(context) == 1 &&
          !strcmp(xkb_context_include_path_get(context, 0), xkb_root), "include-path-isolated");
    const struct xkb_rule_names names = {
        .rules = "evdev", .model = "pc105", .layout = "us", .variant = "", .options = ""
    };
    struct xkb_keymap *keymap = xkb_keymap_new_from_names(context, &names,
                                                       XKB_KEYMAP_COMPILE_NO_FLAGS);
    CHECK(keymap != NULL, "keymap-from-names");
    CHECK(xkb_keymap_num_layouts(keymap) == 1, "one-us-layout");
    CHECK(xkb_keymap_key_by_name(keymap, "AC01") == 38 &&
          xkb_keymap_key_by_name(keymap, "LFSH") == 50 &&
          xkb_keymap_key_by_name(keymap, "CAPS") == 66 &&
          xkb_keymap_key_by_name(keymap, "LCTL") == 37 &&
          xkb_keymap_key_by_name(keymap, "RTRN") == 36 &&
          xkb_keymap_key_by_name(keymap, "AE06") == 15, "evdev-keycodes");
    CHECK(xkb_keymap_key_repeats(keymap, 38) == 1 &&
          xkb_keymap_key_repeats(keymap, 66) == 0, "repeat-metadata");
    struct xkb_state *state = xkb_state_new(keymap);
    CHECK(state != NULL, "state-create");
    CHECK(xkb_state_serialize_mods(state, XKB_STATE_MODS_EFFECTIVE) == 0, "initial-modifiers");
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "a"),
          "base-a");
    /* Upstream libxkbcommon's test database deliberately changes this key. */
    CHECK(xkb_state_key_get_one_sym(state, 15) == XKB_KEY_6 && text_is(state, 15, "6"),
          "production-us-six");
    puts("XKBRULES_PROBE KEYMAP rules=evdev model=pc105 layout=us base=a digit=6");

    enum xkb_state_component changed = xkb_state_update_key(state, 50, XKB_KEY_DOWN);
    CHECK((changed & XKB_STATE_MODS_DEPRESSED) && (changed & XKB_STATE_MODS_EFFECTIVE),
          "shift-down-changes");
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_SHIFT, XKB_STATE_MODS_DEPRESSED) == 1 &&
          xkb_state_mod_name_is_active(state, XKB_MOD_NAME_SHIFT, XKB_STATE_MODS_EFFECTIVE) == 1,
          "shift-down-active");
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_A && text_is(state, 38, "A"),
          "shift-a");
    CHECK(xkb_state_key_get_one_sym(state, 15) == XKB_KEY_asciicircum && text_is(state, 15, "^"),
          "shift-six");
    changed = xkb_state_update_key(state, 50, XKB_KEY_UP);
    CHECK((changed & XKB_STATE_MODS_DEPRESSED) && (changed & XKB_STATE_MODS_EFFECTIVE),
          "shift-up-changes");
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_SHIFT, XKB_STATE_MODS_EFFECTIVE) == 0 &&
          xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "a"),
          "shift-release");
    puts("XKBRULES_PROBE SHIFT down=A digit=^ release=a");

    xkb_state_update_key(state, 66, XKB_KEY_DOWN);
    xkb_state_update_key(state, 66, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CAPS, XKB_STATE_MODS_LOCKED) == 1 &&
          xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CAPS, XKB_STATE_MODS_DEPRESSED) == 0,
          "caps-lock-persists");
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_A && text_is(state, 38, "A"),
          "caps-a");
    CHECK(xkb_state_key_get_one_sym(state, 15) == XKB_KEY_6 && text_is(state, 15, "6"),
          "caps-preserves-digit");
    xkb_state_update_key(state, 50, XKB_KEY_DOWN);
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "a"),
          "caps-shift-a");
    xkb_state_update_key(state, 50, XKB_KEY_UP);
    CHECK(text_is(state, 38, "A"), "caps-shift-release");
    xkb_state_update_key(state, 66, XKB_KEY_DOWN);
    xkb_state_update_key(state, 66, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CAPS, XKB_STATE_MODS_LOCKED) == 0 &&
          text_is(state, 38, "a"), "caps-unlock");
    puts("XKBRULES_PROBE CAPS lock=A shift_with_lock=a unlock=a");

    changed = xkb_state_update_key(state, 37, XKB_KEY_DOWN);
    CHECK((changed & XKB_STATE_MODS_DEPRESSED) && (changed & XKB_STATE_MODS_EFFECTIVE),
          "ctrl-down-changes");
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CTRL, XKB_STATE_MODS_DEPRESSED) == 1 &&
          xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CTRL, XKB_STATE_MODS_EFFECTIVE) == 1,
          "ctrl-down-active");
    CHECK(xkb_state_key_get_one_sym(state, 38) == XKB_KEY_a && text_is(state, 38, "\001"),
          "ctrl-a-text");
    xkb_state_update_key(state, 37, XKB_KEY_UP);
    CHECK(xkb_state_mod_name_is_active(state, XKB_MOD_NAME_CTRL, XKB_STATE_MODS_EFFECTIVE) == 0 &&
          text_is(state, 38, "a"), "ctrl-release");
    CHECK(xkb_state_key_get_one_sym(state, 36) == XKB_KEY_Return && text_is(state, 36, "\r"),
          "return-text");
    CHECK(xkb_state_serialize_mods(state, XKB_STATE_MODS_EFFECTIVE) == 0, "modifiers-restored");
    puts("XKBRULES_PROBE CTRL utf8=01 release=a return=0d");

    char *serialized = xkb_keymap_get_as_string(keymap, XKB_KEYMAP_FORMAT_TEXT_V1);
    CHECK(serialized != NULL, "serialize");
    /* Reparse without any include directory: the serialized map must stand alone. */
    struct xkb_context *copy_context = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES |
                                                      XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    CHECK(copy_context != NULL, "copy-context");
    struct xkb_keymap *copy = xkb_keymap_new_from_string(copy_context, serialized,
                                XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
    CHECK(copy != NULL, "reparse");
    struct xkb_state *copy_state = xkb_state_new(copy);
    CHECK(copy_state != NULL, "copy-state");
    CHECK(xkb_keymap_key_by_name(copy, "AC01") == 38 && text_is(copy_state, 38, "a") &&
          text_is(copy_state, 15, "6") && text_is(copy_state, 36, "\r"), "copy-base");
    xkb_state_update_key(copy_state, 50, XKB_KEY_DOWN);
    CHECK(text_is(copy_state, 38, "A") && text_is(copy_state, 15, "^"), "copy-shift");
    CHECK(text_is(state, 38, "a"), "copy-state-independent");
    puts("XKBRULES_PROBE SERIALIZE reparse=1 independent=1");

    struct xkb_rule_names missing = names;
    missing.rules = "cyxia-missing-rules";
    CHECK(xkb_keymap_new_from_names(context, &missing, XKB_KEYMAP_COMPILE_NO_FLAGS) == NULL,
          "missing-rules-rejected");
    CHECK(xkb_keymap_new_from_names(copy_context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS) == NULL,
          "no-include-rules-rejected");
    CHECK(xkb_keymap_new_from_string(copy_context, "xkb_keymap {", XKB_KEYMAP_FORMAT_TEXT_V1,
                                   XKB_KEYMAP_COMPILE_NO_FLAGS) == NULL, "malformed-rejected");
    CHECK(text_is(state, 38, "a") && text_is(copy_state, 38, "A"), "failed-compile-preserves-state");
    puts("XKBRULES_PROBE REJECT missing_rules=1 no_includes=1 malformed=1");

    xkb_state_unref(copy_state);
    xkb_keymap_unref(copy);
    xkb_context_unref(copy_context);
    free(serialized);
    xkb_state_unref(state);
    xkb_keymap_unref(keymap);
    xkb_context_unref(context);
    printf("XKBRULES_PROBE PASS checks=%u rules=evdev model=pc105 layout=us installed=1 full_desktop=false\n",
           checks);
    return 0;
}
