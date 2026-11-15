/* Public wire/filesystem regression against the genuine COSMIC settings daemon.
 * This is a client only; it never owns a service name or emulates a daemon. */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char service[] = "com.system76.CosmicSettingsDaemon";
static const char object[] = "/com/system76/CosmicSettingsDaemon";
static const char identity[] = "org.cyxia.SettingsProbe";
static const char *files[] = {
    "/.config/cosmic/org.cyxia.SettingsProbe/v1/enabled",
    "/.local/state/cosmic/org.cyxia.SettingsProbe/v1/enabled"
};
static const char theme_mode[] = "/.config/cosmic/com.system76.CosmicTheme.Mode/v1/is_dark";
static void fail(const char *stage, int line) {
    printf("SETTINGS_PROBE FAIL %s line=%d errno=%d\n", stage, line, errno);
    fflush(stdout);
    exit(1);
}
#define CHECK(c, s) do { if (!(c)) fail(s, __LINE__); } while (0)

static long long milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock");
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void value(const char *file, const char *text) {
    int fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fd >= 0, "open-value");
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text), "write-value");
    CHECK(fsync(fd) == 0 && close(fd) == 0, "persist-value");
    char actual[16] = {0};
    fd = open(file, O_RDONLY);
    CHECK(fd >= 0, "open-readback");
    CHECK(read(fd, actual, sizeof(actual)) == (ssize_t)strlen(text), "readback-length");
    CHECK(!strcmp(actual, text) && close(fd) == 0, "readback-content");
}

static void prepare_value(const char *file, const char *text) {
    char path[180];
    CHECK(strlen(file) < sizeof(path), "prepare-path");
    strcpy(path, file);
    for (char *p = path + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = 0;
        CHECK(mkdir(path, 0700) == 0 || errno == EEXIST, "config-directories");
        *p = '/';
    }
    value(file, text);
}

static void prepare(void) {
    for (unsigned i = 0; i < 2; ++i) prepare_value(files[i], "false\n");
    prepare_value("/.config/cosmic/com.system76.CosmicTk/v1/apply_theme_global", "true\n");
    prepare_value(theme_mode, "false\n");
    prepare_value("/.config/cosmic/com.system76.CosmicTheme.Mode/v1/auto_switch", "false\n");
    puts("SETTINGS_PROBE PREPARED");
}

static void theme_export(const char *expected) {
    long long deadline = milliseconds() + 30000;
    for (;;) {
        int ready = 1;
        const char *links[] = {"/.config/gtk-3.0/gtk.css", "/.config/gtk-4.0/gtk.css"};
        for (unsigned i = 0; i < 2; ++i) {
            char target[180] = {0};
            ssize_t count = readlink(links[i], target, sizeof(target) - 1);
            if (count < 0 || strcmp(target, expected)) { ready = 0; break; }
            struct stat info;
            if (stat(links[i], &info) || info.st_size < 100) { ready = 0; break; }
        }
        if (ready) return;
        CHECK(milliseconds() < deadline, "theme-export-timeout");
        CHECK(usleep(100000) == 0, "theme-export-wait");
    }
}

static DBusMessage *call(DBusConnection *bus, DBusMessage *request) {
    CHECK(request != NULL, "request");
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, request, 10000, &error);
    dbus_message_unref(request);
    if (dbus_error_is_set(&error)) {
        printf("SETTINGS_PROBE ERROR %s %s\n", error.name, error.message);
        dbus_error_free(&error);
        fail("method-call", __LINE__);
    }
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN, "reply");
    return reply;
}

static void unsupported(DBusConnection *bus, const char *method) {
    DBusMessage *request = dbus_message_new_method_call(service, object, service, method);
    CHECK(request != NULL, "unsupported-request");
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, request, 10000, &error);
    dbus_message_unref(request);
    CHECK(reply == NULL && dbus_error_has_name(&error, DBUS_ERROR_NOT_SUPPORTED),
          "unavailable-capability-error");
    dbus_error_free(&error);
}

static void watch(DBusConnection *bus, unsigned index) {
    const char *id = identity;
    dbus_uint64_t version = 1;
    DBusMessage *request = dbus_message_new_method_call(service, object, service,
                                                      index ? "WatchState" : "WatchConfig");
    CHECK(request && dbus_message_append_args(request, DBUS_TYPE_STRING, &id,
        DBUS_TYPE_UINT64, &version, DBUS_TYPE_INVALID), "watch-request");
    DBusMessage *reply = call(bus, request);
    const char *path, *name;
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
        DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID), "watch-signature");
    char expected_path[180], expected_name[180], rule[512];
    snprintf(expected_path, sizeof(expected_path),
        "%s/%s/org/cyxia/SettingsProbe/V1", object, index ? "State" : "Config");
    snprintf(expected_name, sizeof(expected_name),
        "%s.%s.%s.V1", service, index ? "State" : "Config", identity);
    CHECK(!strcmp(path, expected_path) && !strcmp(name, expected_name), "watch-identity");
    snprintf(rule, sizeof(rule), "type='signal',sender='%s',path='%s',"
        "interface='com.system76.CosmicSettingsDaemon.Config',member='Changed'", name, path);
    dbus_bus_add_match(bus, rule, &error);
    CHECK(!dbus_error_is_set(&error), "subscribe-changed");
    dbus_message_unref(reply);
    value(files[index], "true\n");
    long long end = milliseconds() + 15000;
    int observed = 0;
    while (!observed && milliseconds() < end) {
        CHECK(dbus_connection_read_write(bus, 100), "read-signal");
        DBusMessage *message;
        while ((message = dbus_connection_pop_message(bus))) {
            if (dbus_message_is_signal(message, "com.system76.CosmicSettingsDaemon.Config", "Changed")
                && dbus_message_has_path(message, expected_path)) {
                const char *changed_id, *key;
                CHECK(dbus_message_get_args(message, &error, DBUS_TYPE_STRING, &changed_id,
                    DBUS_TYPE_STRING, &key, DBUS_TYPE_INVALID), "changed-signature");
                CHECK(!strcmp(changed_id, identity) && !strcmp(key, "enabled"), "changed-key");
                observed = 1;
            }
            dbus_message_unref(message);
        }
    }
    CHECK(observed, "changed-timeout");
    dbus_bus_remove_match(bus, rule, &error);
    CHECK(!dbus_error_is_set(&error), "unsubscribe");
    printf("SETTINGS_PROBE %s_CHANGED PASS\n", index ? "STATE" : "CONFIG");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "prepare")) { prepare(); return 0; }
    CHECK(argc == 1, "arguments");
    DBusError error = DBUS_ERROR_INIT;
    DBusConnection *bus = dbus_connection_open_private("unix:path=/run/user/0/bus", &error);
    CHECK(bus && !dbus_error_is_set(&error), "connect");
    dbus_connection_set_exit_on_disconnect(bus, FALSE);
    CHECK(dbus_bus_register(bus, &error) && !dbus_error_is_set(&error), "authenticate");
    watch(bus, 0);
    watch(bus, 1);
    theme_export("/.config/gtk-4.0/cosmic/light.css");
    value(theme_mode, "true\n");
    theme_export("/.config/gtk-4.0/cosmic/dark.css");
    puts("SETTINGS_PROBE THEME_LIGHT_DARK PASS");
    unsupported(bus, "VolumeUp");
    unsupported(bus, "VolumeDown");
    unsupported(bus, "IncreaseDisplayBrightness");
    puts("SETTINGS_PROBE UNSUPPORTED_CAPABILITIES PASS");
    dbus_connection_close(bus);
    dbus_connection_unref(bus);
    puts("SETTINGS_PROBE PASS");
    return 0;
}
