/* Real GLib process API acceptance for the explicit CyxiaOS spawn profile.
 * SPDX-License-Identifier: MIT */
#include <glib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *stage, GError *error)
{
    printf("GLIB_SPAWN_PROBE FAIL %s errno=%d error=%s\n", stage, errno,
           error ? error->message : "none");
    if (error) g_error_free(error);
    return 1;
}

static int child(int argc, char **argv)
{
    char cwd[96];
    const char *value = g_getenv("CYXIA_SPAWN_VALUE");
    if (argc != 3 || !value || strcmp(value, "space value") ||
            !getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/tmp")) return 90;
    if (!strcmp(argv[2], "sync")) {
        puts("child argv/env/cwd verified");
        fputs("child stderr verified\n", stderr);
        return 7;
    }
    if (!strcmp(argv[2], "pipe")) {
        char input[5] = {0};
        size_t have = 0;
        while (have < 4) {
            ssize_t n = read(0, input + have, 4 - have);
            if (n <= 0) return 91;
            have += (size_t)n;
        }
        if (memcmp(input, "ping", 4)) return 92;
        puts("child pipe verified");
        return 9;
    }
    return 93;
}

static GMainLoop *loop;
static gboolean watched, expired;
static gint watched_status;
static void child_ready(GPid pid, gint status, gpointer unused)
{
    (void)unused;
    watched = TRUE;
    watched_status = status;
    g_spawn_close_pid(pid);
    g_main_loop_quit(loop);
}
static gboolean timeout(gpointer unused)
{
    (void)unused;
    expired = TRUE;
    g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
}
static void forbidden_setup(gpointer unused) { (void)unused; }
static int descriptors(void)
{
    int n = 0;
    for (int fd = 0; fd < 16; ++fd) n += fcntl(fd, F_GETFD) >= 0;
    return n;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "child")) return child(argc, argv);
    char *environment[] = {"PATH=/bin", "CYXIA_SPAWN_VALUE=space value", NULL};
    char *arguments[] = {"glib-spawn-probe", "child", "sync", NULL};
    GError *error = NULL;
    gchar *output = NULL, *errors = NULL;
    gint status;
    int before = descriptors();
    if (!g_spawn_sync("/tmp", arguments, environment, G_SPAWN_SEARCH_PATH_FROM_ENVP,
                      NULL, NULL, &output, &errors, &status, &error)) return fail("sync", error);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 7 ||
        strcmp(output, "child argv/env/cwd verified\n") ||
        strcmp(errors, "child stderr verified\n")) return fail("sync-content", NULL);
    g_free(output); g_free(errors);
    if (descriptors() != before) return fail("sync-fd-cleanup", NULL);
    puts("GLIB_SPAWN_PROBE SYNC PASS");

    arguments[2] = "pipe";
    GPid pid;
    gint input_fd, output_fd;
    if (!g_spawn_async_with_pipes("/tmp", arguments, environment,
            G_SPAWN_SEARCH_PATH_FROM_ENVP | G_SPAWN_DO_NOT_REAP_CHILD,
            NULL, NULL, &pid, &input_fd, &output_fd, NULL, &error)) return fail("async", error);
    if (write(input_fd, "ping", 4) != 4 || close(input_fd)) return fail("pipe-write", NULL);
    loop = g_main_loop_new(NULL, FALSE);
    g_child_watch_add(pid, child_ready, NULL);
    guint timer = g_timeout_add(10000, timeout, NULL);
    g_main_loop_run(loop);
    if (!expired) g_source_remove(timer);
    g_main_loop_unref(loop);
    if (!watched || expired || !WIFEXITED(watched_status) || WEXITSTATUS(watched_status) != 9)
        return fail("child-watch", NULL);
    char text[64] = {0};
    ssize_t count = read(output_fd, text, sizeof(text)-1);
    if (count < 0 || strcmp(text, "child pipe verified\n") || close(output_fd)) return fail("pipe-read", NULL);
    puts("GLIB_SPAWN_PROBE CHILD_WATCH PASS");

    before = descriptors();
    char *missing[] = {"/bin/does-not-exist", NULL};
    if (g_spawn_async_with_pipes(NULL, missing, NULL, 0, NULL, NULL, &pid,
                                &input_fd, &output_fd, NULL, &error)) return fail("missing-accepted", NULL);
    if (!error || error->domain != G_SPAWN_ERROR || error->code != G_SPAWN_ERROR_NOENT)
        return fail("missing-error", error);
    g_clear_error(&error);
    if (descriptors() != before) return fail("failure-fd-cleanup", NULL);
    if (g_spawn_async("/tmp", arguments, environment, G_SPAWN_SEARCH_PATH_FROM_ENVP,
                      forbidden_setup, NULL, &pid, &error)) return fail("callback-accepted", NULL);
    if (!error) return fail("callback-error", NULL);
    g_clear_error(&error);
    puts("GLIB_SPAWN_PROBE ERRORS PASS");
    puts("GLIB_SPAWN_PROBE PASS");
    return 0;
}
