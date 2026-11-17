/* Public wire/filesystem regression against the genuine COSMIC settings daemon.
 * This is a client only; it never owns a service name or emulates a daemon.
 * Version 1 adds actual socket-connect readiness and broker-authenticated
 * owner/PID binding. It does not prove a rendered frame or a normal session. */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char service[] = "com.system76.CosmicSettingsDaemon";
static const char object[] = "/com/system76/CosmicSettingsDaemon";
static const char identity[] = "org.cyxia.SettingsProbe";
static char owner[256];
static dbus_uint32_t owner_pid;
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


/* This is only a successful real AF_UNIX stream connection, not a Wayland
 * roundtrip, semantic frame, service owner, or normal-session assertion. */
static void wayland_ready(void) {
    const char *path = "/run/user/0/wayland-1";
    long long deadline = milliseconds() + 30000;
    for (;;) {
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        CHECK(strlen(path) < sizeof(address.sun_path), "wayland-path");
        strcpy(address.sun_path, path);
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0, "wayland-socket");
        int connected = connect(fd, (const struct sockaddr *)&address, sizeof(address));
        int error = errno;
        CHECK(close(fd) == 0, "wayland-close");
        if (connected == 0) {
            printf("SETTINGS_PROBE WAYLAND_READY path=%s client_pid=%ld protocol_verified=false\n",
                   path, (long)getpid());
            CHECK(fflush(stdout) == 0, "wayland-readiness-flush");
            return;
        }
        CHECK(error == ENOENT || error == ECONNREFUSED || error == EAGAIN
              || error == EINPROGRESS || error == EINTR, "wayland-connect");
        CHECK(milliseconds() < deadline, "wayland-connect-timeout");
        CHECK(usleep(100000) == 0, "wayland-connect-wait");
    }
}

static DBusMessage *broker_call(DBusConnection *bus, const char *member,
                                const char *argument, const char *signature,
                                int timeout_ms, int missing_allowed) {
    DBusMessage *request = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
        DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, member);
    CHECK(request && dbus_message_append_args(request, DBUS_TYPE_STRING, &argument,
          DBUS_TYPE_INVALID), "broker-request");
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, request, timeout_ms, &error);
    dbus_message_unref(request);
    if (missing_allowed && dbus_error_has_name(&error, DBUS_ERROR_NAME_HAS_NO_OWNER)) {
        CHECK(reply == NULL, "absent-owner-reply");
        dbus_error_free(&error);
        return NULL;
    }
    if (dbus_error_is_set(&error)) {
        printf("SETTINGS_PROBE ERROR %s %s\n", error.name, error.message);
        dbus_error_free(&error);
        fail("broker-call", __LINE__);
    }
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN
          && dbus_message_has_sender(reply, DBUS_SERVICE_DBUS)
          && dbus_message_has_signature(reply, signature), "broker-reply");
    return reply;
}

static void unique_owner(DBusMessage *reply, char *output, size_t capacity) {
    DBusError error = DBUS_ERROR_INIT;
    const char *name = NULL;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &name,
          DBUS_TYPE_INVALID) && !dbus_error_is_set(&error), "owner-signature");
    CHECK(name && name[0] == ':' && strlen(name) < capacity
          && dbus_validate_bus_name(name, &error) && !dbus_error_is_set(&error), "owner-name");
    strcpy(output, name);
    dbus_message_unref(reply);
}

static dbus_uint32_t broker_pid(DBusConnection *bus, const char *name) {
    DBusMessage *reply = broker_call(bus, "GetConnectionUnixProcessID", name, "u", 10000, 0);
    DBusError error = DBUS_ERROR_INIT;
    dbus_uint32_t pid = 0;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &pid,
          DBUS_TYPE_INVALID) && !dbus_error_is_set(&error) && pid > 0, "broker-pid");
    dbus_message_unref(reply);
    return pid;
}

static void owner_still_matches(DBusConnection *bus, const char *name) {
    char current[sizeof(owner)];
    unique_owner(broker_call(bus, "GetNameOwner", name, "s", 10000, 0), current, sizeof(current));
    CHECK(!strcmp(current, owner) && broker_pid(bus, current) == owner_pid, "owner-changed");
}

static void service_owner(DBusConnection *bus) {
    long long deadline = milliseconds() + 30000;
    DBusMessage *reply = NULL;
    while (reply == NULL) {
        long long remaining = deadline - milliseconds();
        CHECK(remaining > 0, "service-owner-timeout");
        reply = broker_call(bus, "GetNameOwner", service, "s",
                            (int)(remaining < 1000 ? remaining : 1000), 1);
        if (reply == NULL) CHECK(usleep(100000) == 0, "service-owner-wait");
    }
    unique_owner(reply, owner, sizeof(owner));
    owner_pid = broker_pid(bus, owner);
    const char *client = dbus_bus_get_unique_name(bus);
    CHECK(client && broker_pid(bus, client) == (dbus_uint32_t)getpid()
          && owner_pid != (dbus_uint32_t)getpid(), "broker-client-pid");
    printf("SETTINGS_PROBE OWNER PASS unique=%s service_pid=%u client_pid=%ld\n",
           owner, owner_pid, (long)getpid());
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
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN
          && dbus_message_has_sender(reply, owner), "reply");
    return reply;
}

static void unsupported(DBusConnection *bus, const char *method) {
    DBusMessage *request = dbus_message_new_method_call(owner, object, service, method);
    CHECK(request != NULL, "unsupported-request");
    DBusPendingCall *pending = NULL;
    CHECK(dbus_connection_send_with_reply(bus, request, &pending, 10000) && pending,
          "unsupported-pending");
    dbus_message_unref(request);
    dbus_pending_call_block(pending);
    DBusMessage *reply = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR
          && dbus_message_has_sender(reply, owner)
          && dbus_message_is_error(reply, DBUS_ERROR_NOT_SUPPORTED), "unavailable-capability-error");
    dbus_message_unref(reply);
}

static void watch(DBusConnection *bus, unsigned index) {
    const char *id = identity;
    dbus_uint64_t version = 1;
    DBusMessage *request = dbus_message_new_method_call(owner, object, service,
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
    owner_still_matches(bus, expected_name);
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
                CHECK(dbus_message_has_sender(message, owner), "changed-sender");
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
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0, "stdout-buffer");
    if (argc == 2 && !strcmp(argv[1], "prepare")) { prepare(); return 0; }
    CHECK(argc == 1, "arguments");
    puts("SETTINGS_PROBE START service=com.system76.CosmicSettingsDaemon render_verified=false");
    wayland_ready();
    DBusError error = DBUS_ERROR_INIT;
    DBusConnection *bus = dbus_connection_open_private("unix:path=/run/user/0/bus", &error);
    CHECK(bus && !dbus_error_is_set(&error), "connect");
    dbus_connection_set_exit_on_disconnect(bus, FALSE);
    CHECK(dbus_bus_register(bus, &error) && !dbus_error_is_set(&error), "authenticate");
    service_owner(bus);
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
    owner_still_matches(bus, service);
    printf("SETTINGS_PROBE OWNER_STABLE PASS unique=%s service_pid=%u client_pid=%ld\n",
           owner, owner_pid, (long)getpid());
    dbus_connection_close(bus);
    dbus_connection_unref(bus);
    printf("SETTINGS_PROBE PASS service_pid=%u client_pid=%ld render_verified=false\n",
           owner_pid, (long)getpid());
    return 0;
}
