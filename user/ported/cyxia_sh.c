/* A real, deliberately small EL0 shell for CyxiaOS PTYs. SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static void interrupt(int signo) { (void)signo; interrupted = 1; }
static void error(const char *name) { fprintf(stderr, "%s: %s\n", name, strerror(errno)); }
static int write_all(int fd, const char *data, size_t size) {
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR && !interrupted) continue;
        if (n <= 0) return -1;
        data += n; size -= (size_t)n;
    }
    return 0;
}
static int words(char *line, char *argv[], int max) {
    int argc = 0; char *in = line, *out = line;
    while (*in) {
        while (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') ++in;
        if (!*in) break;
        if (argc == max) return -1;
        argv[argc++] = out; char quote = 0;
        while (*in) {
            char c = *in++;
            if (quote) { if (c == quote) quote = 0; else *out++ = c; }
            else if (c == '\'' || c == '"') quote = c;
            else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
            else if (c == '\\' && *in) *out++ = *in++;
            else *out++ = c;
        }
        if (quote) return -1;
        *out++ = 0;
    }
    return argc;
}
static void help(void) {
    puts("CyxiaOS shell: help pwd cd ls cat write append touch mkdir rm rmdir mv cp stat sleep clear exit");
    puts("write PATH TEXT... writes a file; quote spaces with ' or \". Files are limited to 4 KiB.");
    puts("Ctrl-C interrupts input/sleep; Ctrl-D exits. Use Save files in the desktop to persist changes.");
    puts("This shell provides built-ins; pipelines, expansion and job control are not implemented.");
}
static void list(const char *path) {
    DIR *dir = opendir(path); if (!dir) { error(path); return; }
    struct dirent *entry;
    while ((entry = readdir(dir))) printf("%s%s\n", entry->d_name, entry->d_type == DT_DIR ? "/" : "");
    closedir(dir);
}
static void copy(const char *src, const char *dst) {
    int in = open(src, O_RDONLY); if (in < 0) { error(src); return; }
    struct stat st;
    if (dst && fstat(in, &st) == 0) {
        struct stat other;
        if (stat(dst, &other) == 0 && st.st_ino == other.st_ino && st.st_dev == other.st_dev) {
            fprintf(stderr, "cp: source and destination are the same file\n"); close(in); return;
        }
    }
    int out = dst ? open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644) : 1;
    if (out < 0) { error(dst); close(in); return; }
    char buffer[512]; ssize_t n = 0;
    while (!interrupted && (n = read(in, buffer, sizeof buffer)) > 0) {
        if (write_all(out, buffer, (size_t)n)) { error(dst ? dst : "stdout"); break; }
    }
    if (n < 0 && errno != EINTR) error(src);
    close(in); if (dst) close(out);
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0); setvbuf(stderr, 0, _IONBF, 0);
    if (!isatty(0) || ioctl(0, TIOCSCTTY, 0)) { error("controlling PTY"); return 1; }
    struct sigaction action = {0}; action.sa_handler = interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, 0)) { error("sigaction"); return 1; }
    puts("CyxiaOS terminal: real user-mode shell and kernel PTY");
    puts("Type help for commands. Files require an explicit Save files checkpoint.");
    /* One complete 512-byte canonical record plus its C terminator. The kernel
     * preserves normal short-read remainders and rejects only over-capacity
     * canonical records, so a truncated command is never executed here. */
    char line[513], *args[32];
    for (;;) {
        interrupted = 0; printf("cyxia$ ");
        ssize_t length = read(0, line, sizeof line - 1);
        if (length < 0) {
            if (errno == EINTR) { puts(""); continue; }
            if (errno == E2BIG) { puts("Input line too long; entire line discarded."); continue; }
            error("read"); return 1;
        }
        if (!length) break;
        line[length] = 0;
        int n = words(line, args, 32);
        if (n < 0) { puts("syntax: unmatched quote or more than 32 words"); continue; }
        if (!n) continue;
        const char *cmd = args[0];
        if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "clear")) printf("\033[2J\033[H");
        else if (!strcmp(cmd, "pwd")) { char cwd[96]; if (getcwd(cwd, sizeof cwd)) puts(cwd); else error(cmd); }
        else if (!strcmp(cmd, "cd")) { if (chdir(n > 1 ? args[1] : "/")) error(cmd); }
        else if (!strcmp(cmd, "ls")) list(n > 1 ? args[1] : ".");
        else if (!strcmp(cmd, "cat") && n == 2) { copy(args[1], 0); puts(""); }
        else if ((!strcmp(cmd, "write") || !strcmp(cmd, "append")) && n >= 2) {
            int fd = open(args[1], O_WRONLY | O_CREAT | (!strcmp(cmd, "append") ? O_APPEND : O_TRUNC), 0644);
            if (fd < 0) { error(cmd); continue; }
            int failed = 0;
            for (int i = 2; i < n && !failed; ++i) {
                if (i > 2) failed = write_all(fd, " ", 1);
                if (!failed) failed = write_all(fd, args[i], strlen(args[i]));
            }
            if (!failed) failed = write_all(fd, "\n", 1);
            if (failed) error(cmd); close(fd);
        }
        else if (!strcmp(cmd, "touch") && n == 2) {
            int fd = open(args[1], O_WRONLY | O_CREAT, 0644); if (fd < 0) error(cmd); else close(fd);
        }
        else if (!strcmp(cmd, "mkdir") && n == 2) { if (mkdir(args[1], 0755)) error(cmd); }
        else if (!strcmp(cmd, "rm") && n == 2) { if (unlink(args[1])) error(cmd); }
        else if (!strcmp(cmd, "rmdir") && n == 2) { if (rmdir(args[1])) error(cmd); }
        else if (!strcmp(cmd, "mv") && n == 3) { if (rename(args[1], args[2])) error(cmd); }
        else if (!strcmp(cmd, "cp") && n == 3) copy(args[1], args[2]);
        else if (!strcmp(cmd, "stat") && n == 2) {
            struct stat st; if (stat(args[1], &st)) error(cmd);
            else printf("inode=%llu mode=%o size=%lld bytes\n", (unsigned long long)st.st_ino, st.st_mode, (long long)st.st_size);
        }
        else if (!strcmp(cmd, "sleep") && n == 2) {
            char *end; long seconds = strtol(args[1], &end, 10);
            if (*end || seconds < 0 || seconds > 86400) puts("sleep: expected seconds in 0..86400");
            else { struct timespec t = {seconds, 0}; if (nanosleep(&t, 0) && errno != EINTR) error(cmd); }
        }
        else puts("Unknown command or arguments; type help.");
    }
    puts("Shell exited."); return 0;
}
