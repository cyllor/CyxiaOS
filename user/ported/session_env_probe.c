/* Inspect the actual shell session environment and its real spawned Rust child. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "cyxia_spawn.h"

extern char **environ;

int main(void) {
    setbuf(stdout, 0);
    puts("SESSION_ENV_PROBE START");
    const char *keys[] = {"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"};
    for (unsigned i = 0; i < sizeof keys / sizeof keys[0]; ++i) {
        const char *value = getenv(keys[i]);
        printf("SESSION_ENV_PROBE %s=%s\n", keys[i], value ? value : "(null)");
    }
    char *args[] = {"/bin/rust-env-probe", 0};
    const struct cyxia_mapping maps[] = {{0, 0}, {1, 1}, {2, 2}};
    pid_t pid = cyxia_spawn(args[0], args, environ, maps, 3);
    if (pid < 0) {
        printf("SESSION_ENV_PROBE FAIL spawn errno=%d\n", errno);
        return 1;
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
        printf("SESSION_ENV_PROBE FAIL child status=%d errno=%d\n", status, errno);
        return 1;
    }
    char directory[96];
    const char *state = getenv("XDG_STATE_HOME");
    int length = state ? snprintf(directory, sizeof directory, "%s/cosmic", state)
        : snprintf(directory, sizeof directory, "%s.local/state/cosmic", getenv("HOME"));
    if (length < 0 || (size_t)length >= sizeof directory) return 1;
    int events = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    int watch = events < 0 ? -1 : inotify_add_watch(events, directory, IN_CREATE);
    if (watch < 0) {
        printf("SESSION_ENV_PROBE FAIL state-watch errno=%d path=%s\n", errno, directory);
        return 1;
    }
    char file[128];
    snprintf(file, sizeof file, "%s/probe", directory);
    int created = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
    char buffer[256];
    ssize_t count = read(events, buffer, sizeof buffer);
    if (created < 0 || count < (ssize_t)sizeof(struct inotify_event)) return 1;
    struct inotify_event *event = (struct inotify_event *)buffer;
    if (event->wd != watch || !(event->mask & IN_CREATE) || strcmp(event->name, "probe")) return 1;
    close(created); unlink(file); close(events);
    puts("SESSION_ENV_PROBE STATE_WATCH PASS");
    puts("SESSION_ENV_PROBE PASS");
    return 0;
}
