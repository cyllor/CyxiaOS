/* Exercise the real upstream session broker through its public wire/API seams.
 * Two independent authenticated connections route an actual method call; no
 * mock server, fork, worker thread, or privileged authentication override. */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char address[] = "unix:path=/run/user/0/bus";
static const char name[] = "org.cyxia.SessionBusProbe";
static const char match[] =
    "type='signal',sender='org.freedesktop.DBus',"
    "interface='org.freedesktop.DBus',member='NameOwnerChanged',"
    "arg0='org.cyxia.SessionBusProbe'";
enum { TIMEOUT_MS = 5000 };

static void fail(const char *stage, int line) {
    printf("DBUS_PROBE FAIL %s line=%d errno=%d\n", stage, line, errno);
    fflush(stdout);
    exit(1);
}
#define CHECK(c, s) do { if (!(c)) fail(s, __LINE__); } while (0)

static void check_error(DBusError *error, const char *stage) {
    if (dbus_error_is_set(error)) {
        printf("DBUS_PROBE ERROR %s name=%s message=%s\n", stage,
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

static void wrong_identity(void) {
    struct sockaddr_un endpoint = { .sun_family = AF_UNIX };
    strcpy(endpoint.sun_path, "/run/user/0/bus");
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0, "negative-auth-socket");
    CHECK(connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0,
          "negative-auth-connect");
    /* ASCII UID 1 encoded as hex 31. The actual peer's UID is 0. */
    static const char request[] = "\0AUTH EXTERNAL 31\r\n";
    CHECK(send(fd, request, sizeof(request) - 1, MSG_NOSIGNAL) ==
          (ssize_t)(sizeof(request) - 1), "negative-auth-send");
    char response[256] = {0};
    size_t used = 0;
    int64_t deadline = milliseconds() + TIMEOUT_MS;
    while (!strstr(response, "\r\n")) {
        int64_t left = deadline - milliseconds();
        CHECK(left > 0, "negative-auth-timeout");
        struct pollfd item = { .fd = fd, .events = POLLIN };
        int ready = poll(&item, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        CHECK(ready == 1 && (item.revents & POLLIN), "negative-auth-poll");
        ssize_t got = recv(fd, response + used, sizeof(response) - used - 1, 0);
        CHECK(got > 0, "negative-auth-read");
        used += (size_t)got;
        CHECK(used < sizeof(response) - 1, "negative-auth-line-bound");
        response[used] = 0;
    }
    CHECK(strncmp(response, "REJECTED", 8) == 0 &&
          (response[8] == ' ' || response[8] == '\r'), "wrong-uid-rejected");
    CHECK(close(fd) == 0, "negative-auth-close");
    puts("DBUS_PROBE WRONG_IDENTITY_REJECTED PASS");
}

static DBusConnection *connect_bus(void) {
    DBusError error = DBUS_ERROR_INIT;
    DBusConnection *connection = dbus_connection_open_private(address, &error);
    check_error(&error, "open-private");
    CHECK(connection != NULL, "private-connection");
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
    /* libdbus's registration uses its finite default method-call timeout. */
    CHECK(dbus_bus_register(connection, &error), "hello-register");
    check_error(&error, "hello-register");
    CHECK(dbus_connection_get_is_authenticated(connection), "external-authenticated");
    CHECK(dbus_bus_get_unique_name(connection) != NULL, "hello-unique-name");
    return connection;
}

static DBusMessage *bus_call(DBusConnection *connection, const char *member,
                             const char *argument) {
    DBusMessage *request = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
        DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, member);
    CHECK(request != NULL, "bus-call-allocation");
    if (argument)
        CHECK(dbus_message_append_args(request, DBUS_TYPE_STRING, &argument,
                                       DBUS_TYPE_INVALID), "bus-call-argument");
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(
        connection, request, TIMEOUT_MS, &error);
    dbus_message_unref(request);
    check_error(&error, member);
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN,
          "bus-method-return");
    return reply;
}

static void string_reply(DBusMessage *reply, char *output, size_t capacity) {
    const char *value = NULL;
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &value,
                                 DBUS_TYPE_INVALID), "string-reply-signature");
    check_error(&error, "string-reply");
    CHECK(value && strlen(value) < capacity, "string-reply-size");
    strcpy(output, value);
    dbus_message_unref(reply);
}

static dbus_uint32_t uint_reply(DBusMessage *reply) {
    dbus_uint32_t value = 0;
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &value,
                                 DBUS_TYPE_INVALID), "uint-reply-signature");
    check_error(&error, "uint-reply");
    dbus_message_unref(reply);
    return value;
}

static void names_and_identity(DBusConnection *connection, const char *unique) {
    char id[64];
    string_reply(bus_call(connection, "GetId", NULL), id, sizeof(id));
    CHECK(strlen(id) == 32 && strspn(id, "0123456789abcdef") == 32, "bus-id-format");
    CHECK(uint_reply(bus_call(connection, "GetConnectionUnixProcessID", unique)) ==
          (dbus_uint32_t)getpid(), "actual-peer-pid");
    CHECK(uint_reply(bus_call(connection, "GetConnectionUnixUser", unique)) ==
          (dbus_uint32_t)getuid(), "actual-peer-uid");

    DBusMessage *reply = bus_call(connection, "ListNames", NULL);
    DBusError error = DBUS_ERROR_INIT;
    char **names = NULL;
    int count = 0, own = 0, bus = 0;
    CHECK(dbus_message_get_args(reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
          &names, &count, DBUS_TYPE_INVALID), "list-names-signature");
    check_error(&error, "list-names");
    for (int i = 0; i < count; ++i) {
        own += strcmp(names[i], unique) == 0;
        bus += strcmp(names[i], DBUS_SERVICE_DBUS) == 0;
    }
    CHECK(own == 1 && bus == 1, "list-names-membership");
    dbus_free_string_array(names);
    dbus_message_unref(reply);
    printf("DBUS_PROBE IDENTITY PASS unique=%s pid=%ld uid=%ld id=%s\n",
           unique, (long)getpid(), (long)getuid(), id);
}

static void subscribe(DBusConnection *connection) {
    DBusMessage *reply = bus_call(connection, "AddMatch", match);
    CHECK(dbus_message_has_signature(reply, ""), "add-match-empty-reply");
    dbus_message_unref(reply);
}

static void owner_changed(DBusConnection *connection, const char *old_owner,
                          const char *new_owner) {
    int64_t deadline = milliseconds() + TIMEOUT_MS;
    for (;;) {
        DBusMessage *message;
        while ((message = dbus_connection_pop_message(connection)) != NULL) {
            int found = 0;
            if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS,
                                       "NameOwnerChanged")) {
                const char *changed = NULL, *old = NULL, *fresh = NULL;
                DBusError error = DBUS_ERROR_INIT;
                CHECK(dbus_message_get_args(message, &error,
                    DBUS_TYPE_STRING, &changed, DBUS_TYPE_STRING, &old,
                    DBUS_TYPE_STRING, &fresh, DBUS_TYPE_INVALID),
                    "owner-change-signature");
                check_error(&error, "owner-change");
                found = strcmp(changed, name) == 0 && strcmp(old, old_owner) == 0 &&
                        strcmp(fresh, new_owner) == 0;
            }
            dbus_message_unref(message);
            if (found) return;
        }
        CHECK(milliseconds() < deadline, "owner-change-timeout");
        CHECK(dbus_connection_read_write(connection, 20), "owner-change-connected");
    }
}

static void request_name(DBusConnection *connection, int expected) {
    DBusError error = DBUS_ERROR_INIT;
    int result = dbus_bus_request_name(connection, name, DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                     &error);
    check_error(&error, "request-name");
    CHECK(result == expected, "request-name-result");
}

static void echo_roundtrip(DBusConnection *server, DBusConnection *client,
                            const char *server_unique, const char *client_unique) {
    const char *payload = "real-broker-routed-payload";
    DBusMessage *request = dbus_message_new_method_call(name, "/org/cyxia/Probe",
                                                       "org.cyxia.Probe", "Echo");
    CHECK(request && dbus_message_append_args(request, DBUS_TYPE_STRING, &payload,
                                               DBUS_TYPE_INVALID), "echo-request");
    DBusPendingCall *pending = NULL;
    CHECK(dbus_connection_send_with_reply(client, request, &pending, TIMEOUT_MS) &&
          pending, "echo-pending");
    dbus_message_unref(request);
    dbus_connection_flush(client);
    int64_t deadline = milliseconds() + TIMEOUT_MS;
    DBusMessage *received = NULL;
    while (!received) {
        DBusMessage *message;
        while ((message = dbus_connection_pop_message(server)) != NULL) {
            if (dbus_message_is_method_call(message, "org.cyxia.Probe", "Echo")) {
                received = message;
                break;
            }
            dbus_message_unref(message);
        }
        if (!received) {
            CHECK(milliseconds() < deadline, "echo-routing-timeout");
            CHECK(dbus_connection_read_write(server, 20), "echo-server-connected");
        }
    }
    CHECK(dbus_message_has_path(received, "/org/cyxia/Probe") &&
          dbus_message_has_sender(received, client_unique), "echo-route-and-sender");
    const char *value = NULL;
    DBusError error = DBUS_ERROR_INIT;
    CHECK(dbus_message_get_args(received, &error, DBUS_TYPE_STRING, &value,
                                 DBUS_TYPE_INVALID), "echo-input-signature");
    check_error(&error, "echo-input");
    CHECK(strcmp(value, payload) == 0, "echo-input-payload");
    DBusMessage *reply = dbus_message_new_method_return(received);
    CHECK(reply && dbus_message_append_args(reply, DBUS_TYPE_STRING, &value,
                                             DBUS_TYPE_INVALID), "echo-response");
    CHECK(dbus_connection_send(server, reply, NULL), "echo-response-send");
    dbus_message_unref(reply);
    dbus_message_unref(received);
    dbus_connection_flush(server);
    while (!dbus_pending_call_get_completed(pending)) {
        CHECK(milliseconds() < deadline, "echo-response-timeout");
        CHECK(dbus_connection_read_write_dispatch(client, 20), "echo-client-connected");
    }
    reply = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);
    CHECK(reply && dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN &&
          dbus_message_has_sender(reply, server_unique), "echo-reply-sender");
    char returned[128];
    string_reply(reply, returned, sizeof(returned));
    CHECK(strcmp(returned, payload) == 0, "echo-returned-payload");
    puts("DBUS_PROBE METHOD_ROUTING PASS");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(getuid() == 0, "single-uid-domain");
    wrong_identity();
    DBusConnection *first = connect_bus(), *second = connect_bus();
    char first_unique[256], second_unique[256];
    CHECK(strlen(dbus_bus_get_unique_name(first)) < sizeof(first_unique) &&
          strlen(dbus_bus_get_unique_name(second)) < sizeof(second_unique),
          "unique-name-bound");
    strcpy(first_unique, dbus_bus_get_unique_name(first));
    strcpy(second_unique, dbus_bus_get_unique_name(second));
    CHECK(strcmp(first_unique, second_unique) != 0, "independent-connections");
    names_and_identity(first, first_unique);
    names_and_identity(second, second_unique);
    subscribe(first);
    subscribe(second);
    request_name(first, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
    owner_changed(second, "", first_unique);
    request_name(second, DBUS_REQUEST_NAME_REPLY_EXISTS);
    char owner[256];
    string_reply(bus_call(second, "GetNameOwner", name), owner, sizeof(owner));
    CHECK(strcmp(owner, first_unique) == 0, "name-owner");
    puts("DBUS_PROBE OWNERSHIP_CONFLICT PASS");
    echo_roundtrip(first, second, first_unique, second_unique);

    DBusError error = DBUS_ERROR_INIT;
    int released = dbus_bus_release_name(first, name, &error);
    check_error(&error, "release-name");
    CHECK(released == DBUS_RELEASE_NAME_REPLY_RELEASED, "release-name-result");
    owner_changed(second, first_unique, "");
    CHECK(!dbus_bus_name_has_owner(second, name, &error), "released-name-unowned");
    check_error(&error, "released-name-unowned");
    request_name(second, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
    owner_changed(first, "", second_unique);
    dbus_connection_close(second);
    dbus_connection_unref(second);
    owner_changed(first, second_unique, "");
    CHECK(!dbus_bus_name_has_owner(first, name, &error), "disconnected-name-unowned");
    check_error(&error, "disconnected-name-unowned");
    puts("DBUS_PROBE RELEASE_DISCONNECT PASS");
    dbus_connection_close(first);
    dbus_connection_unref(first);
    dbus_shutdown();
    puts("DBUS_PROBE PASS");
    return 0;
}
