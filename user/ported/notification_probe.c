/* Client of the genuine upstream notification service; never a substitute
 * broker, notification daemon, panel, compositor, or renderer.
 * Server identity is pinned to cosmic-notifications commit
 * 1e4c1f11fdcae273d6954fd0bfc54749a6145267 (Cargo package 1.10.0).
 * A CREATED marker opens a bounded capture window; it is not pixel evidence. */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { TIMEOUT_MS = 5000, CAPTURE_MS = 5000, MESSAGE_LIMIT = 1024 };
static const char address[] = "unix:path=/run/user/0/bus";
static const char service[] = "org.freedesktop.Notifications";
static const char object[] = "/org/freedesktop/Notifications";
static const char interface[] = "org.freedesktop.Notifications";
static DBusConnection *bus;
static char owner[256];
static dbus_uint32_t created_id;

static void disconnect_bus(void) {
    if (bus) {
        dbus_connection_close(bus);
        dbus_connection_unref(bus);
        bus = NULL;
    }
}

/* A failed assertion after Notify must still attempt to remove its real
 * notification. Failure of this bounded cleanup remains a failed probe. */
static void cleanup_notification(void) {
    if (!bus || !created_id || !owner[0]) return;
    DBusMessage *request = dbus_message_new_method_call(owner, object, interface,
                                                       "CloseNotification");
    if (!request) return;
    if (dbus_message_append_args(request, DBUS_TYPE_UINT32, &created_id, DBUS_TYPE_INVALID)) {
        DBusError error = DBUS_ERROR_INIT;
        DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, request, 1000, &error);
        if (reply) dbus_message_unref(reply);
        dbus_error_free(&error);
    }
    dbus_message_unref(request);
}

static void fail(const char *stage, int line) {
    printf("NOTIFICATION_PROBE FAIL stage=%s line=%d errno=%d\n", stage, line, errno);
    fflush(stdout);
    cleanup_notification();
    disconnect_bus();
    exit(1);
}
#define CHECK(c, s) do { if (!(c)) fail(s, __LINE__); } while (0)

static void check_error(DBusError *error, const char *stage) {
    if (dbus_error_is_set(error)) {
        printf("NOTIFICATION_PROBE ERROR stage=%s name=%s message=%s\n", stage,
               error->name, error->message ? error->message : "");
        dbus_error_free(error);
        fail(stage, __LINE__);
    }
}

static int64_t milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic-clock");
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static DBusMessage *call(DBusMessage *request, const char *sender,
                         const char *signature, const char *stage) {
    CHECK(request != NULL, "method-allocation");
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(
        bus, request, TIMEOUT_MS, &error);
    dbus_message_unref(request);
    check_error(&error, stage);
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN,
          "method-return");
    CHECK(dbus_message_has_sender(reply, sender), "method-reply-sender");
    CHECK(dbus_message_has_signature(reply, signature), "method-reply-signature");
    return reply;
}

static DBusMessage *bus_call(const char *member, const char *argument,
                             const char *signature) {
    DBusMessage *request = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
        DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, member);
    CHECK(request && dbus_message_append_args(request, DBUS_TYPE_STRING, &argument,
                                              DBUS_TYPE_INVALID), "broker-argument");
    return call(request, DBUS_SERVICE_DBUS, signature, member);
}

static void get_owner(char *output, size_t capacity) {
    DBusMessage *reply = bus_call("GetNameOwner", service, "s");
    DBusError error = DBUS_ERROR_INIT;
    const char *value = NULL;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &value,
                                DBUS_TYPE_INVALID), "owner-signature");
    check_error(&error, "owner-signature");
    CHECK(value && value[0] == ':' && strlen(value) < capacity, "unique-owner-bound");
    CHECK(dbus_validate_bus_name(value, &error), "unique-owner-name");
    check_error(&error, "unique-owner-name");
    strcpy(output, value);
    dbus_message_unref(reply);
}

static dbus_uint32_t uint_reply(DBusMessage *reply, const char *stage) {
    dbus_uint32_t value = 0;
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &value,
                                DBUS_TYPE_INVALID), stage);
    check_error(&error, stage);
    dbus_message_unref(reply);
    return value;
}

static dbus_uint32_t service_pid(void) {
    dbus_uint32_t pid = uint_reply(bus_call("GetConnectionUnixProcessID", owner, "u"),
                                  "broker-service-pid");
    CHECK(pid > 0 && pid != (dbus_uint32_t)getpid(), "real-service-pid");
    return pid;
}

static void server_information(void) {
    DBusMessage *request = dbus_message_new_method_call(owner, object, interface,
                                                       "GetServerInformation");
    DBusMessage *reply = call(request, owner, "ssss", "GetServerInformation");
    DBusError error = DBUS_ERROR_INIT;
    const char *name = NULL, *vendor = NULL, *version = NULL, *spec = NULL;
    CHECK(dbus_message_get_args(reply, &error,
          DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &vendor,
          DBUS_TYPE_STRING, &version, DBUS_TYPE_STRING, &spec,
          DBUS_TYPE_INVALID), "server-information-signature");
    check_error(&error, "server-information-signature");
    CHECK(name && !strcmp(name, "cosmic-notifications") &&
          vendor && !strcmp(vendor, "System76") &&
          version && !strcmp(version, "1.10.0") && spec && !strcmp(spec, "1.2"),
          "pinned-upstream-server-identity");
    puts("NOTIFICATION_PROBE INFO PASS name=cosmic-notifications vendor=System76 version=1.10.0 spec=1.2");
    dbus_message_unref(reply);
}

static void subscribe_closed(void) {
    char match[512];
    int size = snprintf(match, sizeof(match),
        "type='signal',sender='%s',path='%s',interface='%s',member='NotificationClosed'",
        owner, object, interface);
    CHECK(size > 0 && (size_t)size < sizeof(match), "signal-match-bound");
    DBusMessage *reply = bus_call("AddMatch", match, "");
    dbus_message_unref(reply);
}

static dbus_uint32_t notify(void) {
    DBusMessage *request = dbus_message_new_method_call(owner, object, interface, "Notify");
    CHECK(request != NULL, "notify-allocation");
    char body[160];
    int size = snprintf(body, sizeof(body), "Real upstream D-Bus notification, client PID %ld", (long)getpid());
    CHECK(size > 0 && (size_t)size < sizeof(body), "notification-text-bound");
    const char *app = "CyxiaOS validation", *icon = "", *title = "CyxiaOS genuine notification";
    const char *text = body;
    dbus_uint32_t replaces = 0;
    dbus_int32_t expires = 0; /* Only explicit CloseNotification should close it. */
    DBusMessageIter args, actions, hints;
    dbus_message_iter_init_append(request, &args);
    CHECK(dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &app) &&
          dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &replaces) &&
          dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &icon) &&
          dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &title) &&
          dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &text), "notify-basic-arguments");
    CHECK(dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "s", &actions) &&
          dbus_message_iter_close_container(&args, &actions), "notify-empty-actions");
    CHECK(dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &hints) &&
          dbus_message_iter_close_container(&args, &hints), "notify-empty-hints");
    CHECK(dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &expires) &&
          dbus_message_has_signature(request, "susssasa{sv}i"), "notify-request-signature");
    return uint_reply(call(request, owner, "u", "Notify"), "notification-id-signature");
}

static void capture_window(void) {
    int64_t until = milliseconds() + CAPTURE_MS;
    for (;;) {
        int64_t left = until - milliseconds();
        if (left <= 0) return;
        struct timespec duration = { .tv_sec = (time_t)(left / 1000),
                                     .tv_nsec = (long)(left % 1000) * 1000000 };
        if (nanosleep(&duration, NULL) < 0) CHECK(errno == EINTR, "capture-window-sleep");
    }
}

static void close_notification(void) {
    DBusMessage *request = dbus_message_new_method_call(owner, object, interface,
                                                       "CloseNotification");
    CHECK(request && dbus_message_append_args(request, DBUS_TYPE_UINT32, &created_id,
                                              DBUS_TYPE_INVALID), "close-request-argument");
    CHECK(dbus_message_has_signature(request, "u"), "close-request-signature");
    DBusMessage *reply = call(request, owner, "", "CloseNotification");
    dbus_message_unref(reply);
}

static void wait_closed(void) {
    int64_t deadline = milliseconds() + TIMEOUT_MS;
    unsigned messages = 0;
    for (;;) {
        DBusMessage *message;
        while ((message = dbus_connection_pop_message(bus)) != NULL) {
            CHECK(++messages <= MESSAGE_LIMIT, "signal-message-budget");
            if (dbus_message_has_sender(message, owner) &&
                dbus_message_has_path(message, object) &&
                dbus_message_is_signal(message, interface, "NotificationClosed")) {
                CHECK(dbus_message_has_signature(message, "uu"), "closed-signal-signature");
                dbus_uint32_t id = 0, reason = 0;
                DBusError error = DBUS_ERROR_INIT;
                CHECK(dbus_message_get_args(message, &error, DBUS_TYPE_UINT32, &id,
                      DBUS_TYPE_UINT32, &reason, DBUS_TYPE_INVALID), "closed-signal-values");
                check_error(&error, "closed-signal-values");
                if (id == created_id) {
                    CHECK(reason == 3, "closed-by-request-reason");
                    dbus_message_unref(message);
                    return;
                }
            }
            dbus_message_unref(message);
        }
        int64_t left = deadline - milliseconds();
        CHECK(left > 0, "closed-signal-timeout");
        CHECK(dbus_connection_read_write(bus, (int)(left < 100 ? left : 100)), "bus-disconnected");
    }
}

int main(void) {
    puts("NOTIFICATION_PROBE START service=org.freedesktop.Notifications render_verified=false");
    fflush(stdout);
    DBusError error = DBUS_ERROR_INIT;
    bus = dbus_connection_open_private(address, &error);
    check_error(&error, "open-real-session-bus");
    CHECK(bus != NULL, "real-session-connection");
    dbus_connection_set_exit_on_disconnect(bus, FALSE);
    dbus_bool_t registered = dbus_bus_register(bus, &error);
    check_error(&error, "hello-register");
    CHECK(registered, "hello-register");
    CHECK(dbus_connection_get_is_authenticated(bus), "authenticated-session");
    get_owner(owner, sizeof(owner));
    dbus_uint32_t pid = service_pid();
    printf("NOTIFICATION_PROBE OWNER PASS unique=%s service_pid=%u client_pid=%ld\n", owner, pid, (long)getpid());
    server_information();
    subscribe_closed();
    created_id = notify();
    CHECK(created_id > 0, "nonzero-notification-id");
    printf("NOTIFICATION_PROBE CREATED id=%u service_pid=%u capture_ms=%u render_verified=false\n",
           created_id, pid, (unsigned)CAPTURE_MS);
    fflush(stdout);
    capture_window();
    close_notification();
    wait_closed();
    char final_owner[sizeof(owner)];
    get_owner(final_owner, sizeof(final_owner));
    CHECK(!strcmp(final_owner, owner) && service_pid() == pid, "service-owner-stable");
    printf("NOTIFICATION_PROBE CLOSED id=%u service_pid=%u reason=3\n", created_id, pid);
    dbus_uint32_t completed_id = created_id;
    created_id = 0;
    disconnect_bus();
    printf("NOTIFICATION_PROBE PASS service_pid=%u id=%u render_verified=false\n", pid, completed_id);
    fflush(stdout);
    return 0;
}
