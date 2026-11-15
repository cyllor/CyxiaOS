/* The explicit Cyxia spawn ABI creates independent static-ELF processes. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SYS_CYXIA_SPAWN 0x43595810
struct mapping { int32_t source, target; };
struct spawn_request {
    uint32_t size, flags;
    const char *path;
    char *const *argv, *const *envp;
    const char *cwd;
    const struct mapping *mappings;
    uint32_t mapping_count, reserved;
    uint64_t reserved2;
};
_Static_assert(sizeof(struct spawn_request) == 64, "spawn ABI layout");
static volatile sig_atomic_t seen_pid, seen_status, seen_code;
static void child_signal(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal == SIGCHLD && info) {
        seen_pid = info->si_pid; seen_status = info->si_status; seen_code = info->si_code;
    }
}
static void pause_ms(long ms) {
    struct timespec t = { ms/1000, ms%1000*1000000 };
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static int fail(const char *stage) {
    printf("SPAWN_PROBE FAIL %s errno=%d\n", stage, errno);
    return 1;
}
static pid_t spawn(char *const argv[], char *const env[], const char *cwd,
                   struct mapping *maps, unsigned count, unsigned flags) {
    struct spawn_request request = {64, flags, "/bin/spawn-probe", argv, env, cwd, maps, count, 0, 0};
    return syscall(SYS_CYXIA_SPAWN, &request);
}
static pid_t waited(pid_t pid, int *status, int flags) {
    pid_t result;
    do result = waitpid(pid, status, flags); while (result < 0 && errno == EINTR);
    return result;
}
static int read_all(int fd, char *bytes, int cap) {
    int total=0;
    while (total < cap) {
        ssize_t n = read(fd, bytes+total, cap-total);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (!n) return total;
        total += n;
    }
    return total;
}

struct signal_packet { int signal, sender, code; };
static int signal_socket = -1;
static void target_signal(int number, siginfo_t *info, void *context) {
    (void)context;
    struct signal_packet packet = {number, info ? info->si_pid : -1,
                                   info ? info->si_code : -1};
    /* The ready byte is the only earlier traffic. This small, blocking write
     * has room and uses only an async-signal-safe function. */
    if (write(signal_socket, &packet, sizeof packet) != sizeof packet) _exit(90);
    _exit(41);
}
static int signal_target(const char *mode) {
    const char *socket_env = getenv("SIGNAL_SOCKET");
    const char *plain_env = getenv("SIGNAL_PLAIN");
    const char *closed_env = getenv("SIGNAL_CLOSED");
    const char *parent_env = getenv("PARENT_PID");
    if (!socket_env || !plain_env || !closed_env || !parent_env) return 81;
    signal_socket = atoi(socket_env);
    int plain = atoi(plain_env), closed = atoi(closed_env);
    char byte;
    if (getppid() != atoi(parent_env) || getuid() != 0 || geteuid() != 0 ||
        fcntl(signal_socket, F_GETFD) != 0 ||
        (fcntl(signal_socket, F_GETFL) & O_NONBLOCK) ||
        fcntl(plain, F_GETFD) != 0 || read(plain, &byte, 1) != 0) return 82;
    errno = 0;
    if (fcntl(closed, F_GETFD) != -1 || errno != EBADF) return 83;
    if (!strcmp(mode, "handler")) {
        struct sigaction action = {.sa_sigaction=target_signal,.sa_flags=SA_SIGINFO};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, 0)) return 84;
    } else if (!strcmp(mode, "ignore")) {
        struct sigaction action = {.sa_handler=SIG_IGN};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, 0)) return 85;
    } else if (strcmp(mode, "default")) return 86;
    if (write(signal_socket, "R", 1) != 1) return 87;
    /* Real readiness handshake precedes every parent signal. Poll bounds a
     * failed RED run and peer EOF lets this child retire if its parent fails. */
    for (int round = 0; round < 2; round++) {
        struct pollfd p = {.fd=signal_socket,.events=POLLIN};
        int result;
        do result = poll(&p, 1, 5000); while (result < 0 && errno == EINTR);
        if (result != 1 || read(signal_socket, &byte, 1) != 1) return 88;
        if (strcmp(mode, "ignore") || byte != 'A' || write(signal_socket, "A", 1) != 1)
            return 89;
    }
    return 91;
}
static int signal_sender(const char *pid_text) {
    pid_t target = atoi(pid_text);
    int status = 0x12345678;
    errno = 0;
    /* Same UID permits signaling a sibling; it does not transfer wait ownership. */
    if (waitpid(target, &status, WNOHANG) != -1 || errno != ECHILD ||
        status != 0x12345678 || kill(target, 0) || kill(target, SIGTERM)) return 92;
    return 31;
}
static int signal_case(const char *mode, int sibling) {
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel))
        return fail("signal-socketpair");
    int plain = open("/dev/null", O_RDONLY), excluded = open("/dev/null", O_RDONLY);
    if (plain < 0 || excluded < 0) return fail("signal-null-fds");
    /* Exercise both launch-pad with_fds (CLOEXEC) and the compositor's ambient
     * non-CLOEXEC source. Native spawn still requires an explicit same-FD map. */
    int source_flags = !strcmp(mode, "default") ? 0 : FD_CLOEXEC;
    if (fcntl(channel[1], F_SETFD, source_flags)) return fail("signal-fd-flags");
    char socket_env[40], plain_env[40], closed_env[40], parent_env[40];
    snprintf(socket_env, sizeof socket_env, "SIGNAL_SOCKET=%d", channel[1]);
    snprintf(plain_env, sizeof plain_env, "SIGNAL_PLAIN=%d", plain);
    snprintf(closed_env, sizeof closed_env, "SIGNAL_CLOSED=%d", excluded);
    snprintf(parent_env, sizeof parent_env, "PARENT_PID=%d", getpid());
    char *env[] = {socket_env, plain_env, closed_env, parent_env, NULL};
    char *args[] = {"/bin/spawn-probe", "signal-target", (char *)mode, NULL};
    struct mapping maps[] = {{0,0},{1,1},{2,2},{channel[1],channel[1]},{plain,plain}};
    pid_t child = spawn(args, env, NULL, maps, 5, 0);
    if (child < 0) return fail("signal-spawn");
    if (fcntl(channel[1], F_GETFD) != source_flags || fcntl(plain, F_GETFD) != 0 ||
        fcntl(excluded, F_GETFD) != 0 || close(channel[1]) || close(plain) || close(excluded))
        return fail("signal-parent-fds");
    char ready = 0;
    if (read_all(channel[0], &ready, 1) != 1 || ready != 'R')
        return fail("signal-child-ready");
    printf("SPAWN_PROBE USER_SIGNAL READY parent=%d child=%d mode=%s sibling=%d\n",
           getpid(), child, mode, sibling);
    /* The current kernel fails here with ESRCH for a real live child PID. */
    if (kill(child, 0)) return fail("signal-live-zero");
    int status = 0x12345678;
    if (waited(child, &status, WNOHANG) != 0 || status != 0x12345678)
        return fail("signal-zero-no-effect");
    errno = 0;
    if (kill(child, 65) != -1 || errno != EINVAL) return fail("signal-invalid-number");
    errno = 0;
    if (kill(child, -1) != -1 || errno != EINVAL) return fail("signal-negative-number");
    errno = 0;
    if (kill(INT_MAX, 0) != -1 || errno != ESRCH) return fail("signal-unknown-zero");
    errno = 0;
    if (kill(INT_MAX, SIGTERM) != -1 || errno != ESRCH) return fail("signal-unknown-term");

    pid_t sender = getpid();
    if (sibling) {
        char target[24]; snprintf(target, sizeof target, "%d", child);
        char *sender_args[] = {"/bin/spawn-probe", "signal-sender", target, NULL};
        char *empty_env[] = {NULL};
        struct mapping sender_maps[] = {{0,0},{1,1},{2,2}};
        sender = spawn(sender_args, empty_env, NULL, sender_maps, 3, 0);
        if (sender < 0) return fail("signal-sibling-spawn");
    } else if (kill(child, SIGTERM)) return fail("signal-user-term");

    if (!strcmp(mode, "handler")) {
        struct signal_packet packet = {0};
        if (read_all(channel[0], (char *)&packet, sizeof packet) != sizeof packet ||
            packet.signal != SIGTERM || packet.sender != sender || packet.code != SI_USER)
            return fail("signal-handler-info");
    } else if (!strcmp(mode, "ignore")) {
        if (write(channel[0], "A", 1) != 1 || read_all(channel[0], &ready, 1) != 1 ||
            ready != 'A' || kill(child, 0) || kill(child, SIGKILL))
            return fail("signal-ignore-then-kill");
    }
    if (waited(child, &status, 0) != child) return fail("signal-parent-wait");
    if (!strcmp(mode, "handler")) {
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 41) return fail("signal-handler-status");
    } else if (!WIFSIGNALED(status) ||
               WTERMSIG(status) != (!strcmp(mode, "ignore") ? SIGKILL : SIGTERM))
        return fail("signal-default-status");
    if (read_all(channel[0], &ready, 1) != 0 || close(channel[0]))
        return fail("signal-final-socket-eof");
    if (seen_pid != child || seen_status != (!strcmp(mode, "handler") ? 41 :
            !strcmp(mode, "ignore") ? SIGKILL : SIGTERM) ||
        seen_code != (!strcmp(mode, "handler") ? CLD_EXITED : CLD_KILLED)) {
        /* A sibling can also exit and its coalesced SIGCHLD may arrive last. */
        if (!sibling) return fail("signal-parent-sigchld");
    }
    errno = 0;
    if (waitpid(child, &status, WNOHANG) != -1 || errno != ECHILD)
        return fail("signal-double-reap");
    errno = 0;
    if (kill(child, 0) != -1 || errno != ESRCH) return fail("signal-dead-zero");
    errno = 0;
    if (kill(child, SIGTERM) != -1 || errno != ESRCH) return fail("signal-dead-term");
    if (sibling && (waited(sender, &status, 0) != sender || !WIFEXITED(status) ||
                    WEXITSTATUS(status) != 31)) return fail("signal-sibling-status");
    printf("SPAWN_PROBE USER_SIGNAL %s%s PASS\n", mode, sibling ? "-sibling" : "");
    return 0;
}
int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "signal-target")) return signal_target(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "signal-sender")) return signal_sender(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "child")) {
        char cwd[96], input[16];
        const char *parent = getenv("PARENT_PID");
        if (argc != 4 || argv[3][0] != (char)0xff || argv[3][1] ||
            strcmp(argv[0], "display-name") || !parent || getppid() != atoi(parent) ||
            !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/spawn dir") ||
            !getenv("CYXIA_SPAWN_TAG") || strcmp(getenv("CYXIA_SPAWN_TAG"), "real-env") ||
            strcmp((char *)getauxval(AT_EXECFN), "/bin/spawn-probe")) return 71;
        errno = 0;
        if (fcntl(3, F_GETFD) != -1 || errno != EBADF) return 72;
        int n=0;
        while (n < 6) { ssize_t got=read(0, input+n, 6-n); if(got<=0) return 73; n+=(int)got; }
        if (memcmp(input,"hello\n",6)) return 74;
        if (fcntl(1,F_SETFL,O_NONBLOCK)) return 75;
        if (write(1,"child-out\n",10)!=10 || write(2,"child-err\n",10)!=10) return 76;
        return 37;
    }
    if (argc > 1 && !strcmp(argv[1], "sleep")) { pause_ms(150); return 12; }
    if (argc > 1 && !strcmp(argv[1], "empty")) return 5;
    if (argc > 1 && !strcmp(argv[1], "signal")) { raise(SIGTERM); return 77; }
    if (argc > 1 && !strcmp(argv[1], "orphan-worker")) {
        pause_ms(60);
        if (getppid() != 0) return 78;
        return write(1,"orphan-live\n",12)==12 ? 0 : 79;
    }
    if (argc > 1 && !strcmp(argv[1], "orphan-parent")) {
        char *child_args[] = {"/bin/spawn-probe", "orphan-worker", 0};
        char *empty_env[] = {0};
        struct mapping maps[] = {{-2,0},{1,1},{2,2}};
        return spawn(child_args, empty_env, 0, maps, 3, 0) > 0 ? 17 : 80;
    }

    struct sigaction action = {.sa_sigaction=child_signal,.sa_flags=SA_SIGINFO|SA_NOCLDSTOP};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD,&action,0)) return fail("sigaction");
    if (mkdir("/spawn dir",0700) && errno!=EEXIST) return fail("mkdir");
    if (access("/bin/spawn-probe",X_OK)) return fail("catalog-executable");
    struct stat st;
    int catalog=open("/bin/spawn-probe",O_RDONLY);
    if (catalog<0 || fstat(catalog,&st) || (st.st_mode&0777)!=0555 || close(catalog)) return fail("catalog-fstat");
    int input[2],output[2];
    if (pipe2(input,O_CLOEXEC)||pipe2(output,O_CLOEXEC)) return fail("pipes");
    struct mapping maps[]={{input[0],0},{output[1],1},{output[1],2}};
    char parent[40]; snprintf(parent,sizeof parent,"PARENT_PID=%d",getpid());
    char raw_arg[]={ (char)0xff,0 };
    char *args[]={"display-name","child","argument",raw_arg,0};
    char *env[]={parent,"CYXIA_SPAWN_TAG=real-env",0};
    pid_t child=spawn(args,env,"/spawn dir",maps,3,0);
    if(child<0) return fail("create");
    if(close(input[0])||write(input[1],"hello\n",6)!=6||close(input[1])) return fail("parent-input");
    int status;
    if(waited(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=37) return fail("wait-exit");
    if(!(fcntl(output[1],F_GETFL)&O_NONBLOCK)) return fail("shared-description-flags");
    if(close(output[1])) return fail("parent-close");
    char data[128]={0}; int n=read_all(output[0],data,sizeof data);
    if(n!=20||memcmp(data,"child-out\nchild-err\n",20)||close(output[0])) return fail("cross-process-pipe");
    if(seen_pid!=child||seen_status!=37||seen_code!=CLD_EXITED) return fail("sigchld-info");
    errno=0;
    if(waitpid(child,&status,WNOHANG)!=-1||errno!=ECHILD) return fail("reaped-child");
    puts("SPAWN_PROBE PIPE_ENV_CWD PASS");

    char *empty_env[]={0};
    char *sleep_args[]={"/bin/spawn-probe","sleep",0};
    struct mapping ordinary[]={{0,0},{1,1},{2,2}};
    child=spawn(sleep_args,empty_env,0,ordinary,3,0);
    status=0x12345678;
    if(child<0||waited(child,&status,WNOHANG)!=0||status!=0x12345678) return fail("nonblocking-wait");
    errno=0;
    if(waitpid(child+1000,&status,WNOHANG)!=-1||errno!=ECHILD) return fail("wrong-child");
    if(waited(-1,&status,0)!=child||!WIFEXITED(status)||WEXITSTATUS(status)!=12) return fail("wait-any");
    char *signal_args[]={"/bin/spawn-probe","signal",0};
    child=spawn(signal_args,empty_env,0,ordinary,3,0);
    if(child<0||waited(child,&status,0)!=child||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGTERM) return fail("wait-signal");
    puts("SPAWN_PROBE WAIT_SIGNAL PASS");

    if (signal_case("handler", 0) || signal_case("default", 0) ||
        signal_case("ignore", 0) || signal_case("handler", 1)) return 1;
    puts("SPAWN_PROBE USER_SIGNALS PASS");

    /* Process-group/broadcast signaling is unsupported; zero must not report
     * a successful self-only substitute. Validate signals before target form. */
    pid_t unsupported_targets[] = {0, -1, -getpid()};
    for (unsigned i = 0; i < sizeof unsupported_targets / sizeof unsupported_targets[0]; i++) {
        errno = 0;
        if (kill(unsupported_targets[i], 65) != -1 || errno != EINVAL)
            return fail("group-invalid-signal-first");
        errno = 0;
        if (kill(unsupported_targets[i], -1) != -1 || errno != EINVAL)
            return fail("group-negative-signal-first");
        errno = 0;
        int result = kill(unsupported_targets[i], 0), error = errno;
        printf("SPAWN_PROBE GROUP_TARGET target=%d result=%d errno=%d\n",
               unsupported_targets[i], result, error);
        if (result != -1 || error != EOPNOTSUPP) {
            errno = error;
            return fail("unsupported-group-target");
        }
    }
    puts("SPAWN_PROBE GROUP_TARGETS_UNSUPPORTED PASS");

    struct spawn_request request={64,0,"/bin/missing",sleep_args,empty_env,0,ordinary,3,0,0};
    errno=0;
    if(syscall(SYS_CYXIA_SPAWN,&request)!=-1||errno!=ENOENT) return fail("missing-image");
    request.path="/bin/spawn-probe"; request.argv=(void *)1; errno=0;
    if(syscall(SYS_CYXIA_SPAWN,&request)!=-1||errno!=EFAULT) return fail("bad-vector");
    request.argv=sleep_args; request.reserved2=1; errno=0;
    if(syscall(SYS_CYXIA_SPAWN,&request)!=-1||errno!=EINVAL) return fail("reserved-field");
    int file=open("/spawn-inherit",O_CREAT|O_RDWR,0600);
    struct mapping badmap[]={{file,0},{16,3}};
    errno=0;
    if(spawn(sleep_args,empty_env,0,badmap,2,0)!=-1||errno!=EBADF) return fail("invalid-inheritance-source");
    if(close(file)||unlink("/spawn-inherit")) return fail("file-cleanup");
    struct mapping duplicate[]={{1,1},{2,1}};
    errno=0;
    if(spawn(sleep_args,empty_env,0,duplicate,2,0)!=-1||errno!=EINVAL) return fail("duplicate-map");
    errno=0;
    if(waitpid(-1,&status,WNOHANG)!=-1||errno!=ECHILD) return fail("failed-spawn-no-zombie");
    puts("SPAWN_PROBE ATOMIC_ERRORS PASS");

    for(int i=0;i<10;i++) {
        child=spawn(sleep_args,empty_env,0,ordinary,3,0);
        if(child<0||waited(child,&status,0)!=child||WEXITSTATUS(status)!=12) return fail("slot-reuse");
    }
    child=spawn(sleep_args,empty_env,0,ordinary,3,1);
    errno=0;
    if(child<0||waitpid(child,&status,0)!=-1||errno!=ECHILD) return fail("auto-reap");
    pause_ms(180);
    if(pipe2(output,O_CLOEXEC)) return fail("orphan-pipe");
    struct mapping orphan_maps[]={{-2,0},{output[1],1},{2,2}};
    char *orphan_args[]={"/bin/spawn-probe","orphan-parent",0};
    child=spawn(orphan_args,empty_env,0,orphan_maps,3,0);
    if(child<0||close(output[1])||waited(child,&status,0)!=child||WEXITSTATUS(status)!=17) return fail("orphan-parent");
    memset(data,0,sizeof data); n=read_all(output[0],data,sizeof data);
    if(n!=12||memcmp(data,"orphan-live\n",12)||close(output[0])) return fail("orphan-survives");
    puts("SPAWN_PROBE LIFETIME PASS");
    // Exit receipts must survive reuse of the child's former process slot.
    // Ten reserved records preserve the local model's two-record floor.
    char *empty_args[]={"/bin/spawn-probe","empty",0};
    pid_t receipts[8];
    for(int i=0;i<8;i++) {
        receipts[i]=spawn(empty_args,empty_env,0,ordinary,3,0);
        if(receipts[i]<0) return fail("receipt-reserve");
        pause_ms(20);
    }
    errno=0;
    if(spawn(empty_args,empty_env,0,ordinary,3,0)!=-1||errno!=EAGAIN) return fail("receipt-capacity");
    errno=0;
    if(syscall(SYS_wait4,receipts[0],(void *)1,WNOHANG,0)!=-1||errno!=EFAULT) return fail("wait-copy-atomic");
    for(int i=7;i>=0;i--) {
        if(waited(receipts[i],&status,0)!=receipts[i]||!WIFEXITED(status)||WEXITSTATUS(status)!=5)
            return fail("receipt-retention");
    }
    child=spawn(empty_args,empty_env,0,ordinary,3,0);
    if(child<0||waited(child,&status,0)!=child||WEXITSTATUS(status)!=5) return fail("receipt-reuse");
    puts("SPAWN_PROBE RECEIPTS PASS");
    if(rmdir("/spawn dir")) return fail("directory-cleanup");
    puts("SPAWN_PROBE PASS");
    return 0;
}
