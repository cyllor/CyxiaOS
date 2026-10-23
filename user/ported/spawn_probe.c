/* The explicit Cyxia spawn ABI creates independent static-ELF processes. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
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
int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
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
