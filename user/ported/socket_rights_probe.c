/* Actual GetFd pattern: pass a connected socket, then close its original FD. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "cyxia_spawn.h"
#include <unistd.h>

static int fail(const char *where) {
    printf("SOCKET_RIGHTS_PROBE FAIL %s errno=%d\n", where, errno);
    return 1;
}
#define CHECK(c, where) do { if (!(c)) return fail(where); } while (0)

static ssize_t send_fds(int transport, const int *fds, size_t count) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(8 * sizeof(int))]; } control = {0};
    char byte = 'F';
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov=&vector, .msg_iovlen=1,
        .msg_control=control.bytes, .msg_controllen=sizeof control};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    memcpy(CMSG_DATA(header), fds, count * sizeof(int));
    return sendmsg(transport, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static ssize_t send_fd(int transport, int fd) { return send_fds(transport, &fd, 1); }
static ssize_t receive_fds(int transport, int *fds, size_t *count, int *flags) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(8 * sizeof(int))]; } control = {0};
    char byte = 0;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov=&vector, .msg_iovlen=1};
    if (*count) { message.msg_control=control.bytes; message.msg_controllen=CMSG_SPACE(*count*sizeof(int)); }
    ssize_t result=recvmsg(transport, &message, MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    *count=0; *flags=message.msg_flags;
    if (result<0) return result;
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    if (header) {
        if (header->cmsg_level!=SOL_SOCKET || header->cmsg_type!=SCM_RIGHTS ||
            header->cmsg_len<CMSG_LEN(0) || header->cmsg_len>CMSG_LEN(8*sizeof(int))) { errno=EINVAL; return -1; }
        size_t bytes=header->cmsg_len-CMSG_LEN(0);
        if (bytes%sizeof(int)) { errno=EINVAL; return -1; }
        *count=bytes/sizeof(int); memcpy(fds,CMSG_DATA(header),bytes);
    }
    return result;
}
static int sender(void) {
    int service[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,service)==0,"child-pair");
    CHECK(send_fds(3,service,2)==1,"child-transfer-both");
    return 0;
}
static int lifecycle_cases(void) {
    int transport[2], received[8], flags; size_t count;
    char byte;
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,transport)==0,"cross-transport");
    char *args[]={"/bin/socket-rights-probe","sender",NULL}, *env[]={NULL};
    struct cyxia_mapping maps[]={{-2,0},{1,1},{2,2},{transport[1],3}};
    pid_t pid=cyxia_spawn(args[0],args,env,maps,4); int status;
    CHECK(pid>0 && close(transport[1])==0 && waitpid(pid,&status,0)==pid && status==0,"creator-exit");
    count=8;
    CHECK(receive_fds(transport[0],received,&count,&flags)==1 && count==2,"receive-after-exit");
    struct ucred credentials; socklen_t length=sizeof credentials;
    CHECK(getsockopt(received[0],SOL_SOCKET,SO_PEERCRED,&credentials,&length)==0 &&
        credentials.pid==pid && credentials.uid==getuid(),"creator-credentials");
    CHECK(write(received[0],"C",1)==1 && read(received[1],&byte,1)==1 && byte=='C',"creator-roundtrip");
    CHECK(close(received[0])==0 && close(received[1])==0 && close(transport[0])==0,"creator-cleanup");
    puts("SOCKET_RIGHTS_PROBE CREATOR_EXIT PASS");

    int self[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,self)==0,"self-pair");
    int alias=dup(self[1]), ep=epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event={.events=EPOLLIN,.data.u64=99};
    CHECK(alias>=0 && ep>=0 && epoll_ctl(ep,EPOLL_CTL_ADD,self[1],&event)==0,"weak-watch");
    CHECK(send_fd(self[0],self[1])==1 && close(self[1])==0,"self-send");
    CHECK(read(self[0],&byte,1)==-1 && errno==EAGAIN,"alias-keeps-cycle");
    CHECK(close(alias)==0 && read(self[0],&byte,1)==0,"self-collection-eof");
    CHECK(epoll_wait(ep,&event,1,0)==0 && close(ep)==0 && close(self[0])==0,"weak-watch-released");
    puts("SOCKET_RIGHTS_PROBE SELF_CYCLE PASS");

    for (unsigned i=0;i<96;++i) {
        int a[2],b[2];
        CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,a)==0 &&
            socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,b)==0,"cycle-reuse-pairs");
        CHECK(send_fd(a[1],b[0])==1 && send_fd(b[1],a[0])==1,"cross-cycle-send");
        CHECK(close(a[0])==0 && close(b[0])==0,"cross-cycle-last-roots");
        CHECK(read(a[1],&byte,1)==0 && read(b[1],&byte,1)==0,"cross-cycle-eof");
        CHECK(close(a[1])==0 && close(b[1])==0,"cross-cycle-cleanup");
    }
    puts("SOCKET_RIGHTS_PROBE CROSS_CYCLE PASS");

    int a[2],b[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,a)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,b)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,transport)==0,"rooted-pairs");
    CHECK(send_fd(a[1],b[0])==1 && send_fd(b[1],a[0])==1 && send_fd(transport[0],a[0])==1,"external-root");
    CHECK(close(a[0])==0 && close(b[0])==0 && read(a[1],&byte,1)==-1 && errno==EAGAIN,"root-keeps-cycle");
    count=8; CHECK(receive_fds(transport[1],received,&count,&flags)==1 && count==1,"restore-root");
    int root=received[0];
    CHECK(close(transport[0])==0 && close(transport[1])==0,"root-transport-close");
    count=8; CHECK(receive_fds(root,received,&count,&flags)==1 && count==1,"restore-peer");
    int peer=received[0];
    count=8; CHECK(receive_fds(peer,received,&count,&flags)==1 && count==1,"restore-alias");
    int duplicate=received[0];
    CHECK(write(root,"R",1)==1 && read(a[1],&byte,1)==1 && byte=='R',"restored-roundtrip");
    CHECK(close(root)==0 && close(peer)==0 && close(duplicate)==0 && close(a[1])==0 && close(b[1])==0,"rooted-cleanup");
    puts("SOCKET_RIGHTS_PROBE ROOTED_CYCLE PASS");

    int service[2],leaf[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,transport)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,service)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,leaf)==0,"shutdown-pairs");
    CHECK(send_fd(service[0],leaf[1])==1 && send_fd(transport[0],service[1])==1 &&
        close(leaf[1])==0 && close(service[1])==0,"shutdown-chain");
    CHECK(shutdown(transport[1],SHUT_RD)==0 && read(service[0],&byte,1)==0 &&
        read(leaf[0],&byte,1)==0,"shutdown-drains-chain");
    CHECK(close(transport[0])==0 && close(transport[1])==0 && close(service[0])==0 && close(leaf[0])==0,"shutdown-cleanup");
    puts("SOCKET_RIGHTS_PROBE SHUTDOWN_CHAIN PASS");

    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,transport)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,service)==0,"truncate-pairs");
    CHECK(send_fd(transport[0],service[1])==1 && close(service[1])==0,"truncate-send");
    count=0;
    CHECK(receive_fds(transport[1],received,&count,&flags)==1 && count==0 &&
        (flags&MSG_CTRUNC) && read(service[0],&byte,1)==0,"truncate-final-release");
    CHECK(close(transport[0])==0 && close(transport[1])==0 && close(service[0])==0,"truncate-cleanup");
    puts("SOCKET_RIGHTS_PROBE TRUNCATION PASS");

    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,transport)==0 &&
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,service)==0,"cancel-pairs");
    CHECK(close(transport[1])==0 && send_fd(transport[0],service[1])==-1 && errno==EPIPE,"cancel-send");
    CHECK(close(service[1])==0 && read(service[0],&byte,1)==0,"cancel-no-staged-leak");
    CHECK(close(transport[0])==0 && close(service[0])==0,"cancel-cleanup");
    puts("SOCKET_RIGHTS_PROBE CANCELLED_SEND PASS");
    return 0;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc==2 && !strcmp(argv[1],"sender")) return sender();
    puts("SOCKET_RIGHTS_PROBE START");
    int transport[2], service[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, transport)==0, "transport");
    CHECK(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, service)==0, "service");
    CHECK(send_fd(transport[0], service[1])==1, "send-connected-socket");
    CHECK(close(service[1])==0, "original-close");
    puts("SOCKET_RIGHTS_PROBE INFLIGHT PASS");
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    char byte = 0;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov=&vector, .msg_iovlen=1,
        .msg_control=control.bytes, .msg_controllen=sizeof control};
    CHECK(recvmsg(transport[1], &message, MSG_CMSG_CLOEXEC)==1 && byte=='F', "receive");
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level==SOL_SOCKET && header->cmsg_type==SCM_RIGHTS &&
        header->cmsg_len==CMSG_LEN(sizeof(int)), "actual-control");
    int received=-1;
    memcpy(&received, CMSG_DATA(header), sizeof received);
    CHECK(fcntl(received, F_GETFD)==FD_CLOEXEC, "closeexec");
    CHECK(close(transport[0])==0 && close(transport[1])==0, "transport-close");
    CHECK(write(service[0], "Q", 1)==1 && read(received, &byte, 1)==1 && byte=='Q', "roundtrip");
    CHECK(write(received, "R", 1)==1 && read(service[0], &byte, 1)==1 && byte=='R', "reverse");
    puts("SOCKET_RIGHTS_PROBE ROUNDTRIP PASS");
    CHECK(close(received)==0 && read(service[0], &byte, 1)==0 && close(service[0])==0, "last-close-eof");
    puts("SOCKET_RIGHTS_PROBE RELEASE PASS");
    CHECK(lifecycle_cases()==0,"lifecycle-cases");
    puts("SOCKET_RIGHTS_PROBE PASS");
    return 0;
}
