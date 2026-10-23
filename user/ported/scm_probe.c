/* Real AF_UNIX SCM_RIGHTS across independent CyxiaOS EL0 address spaces. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cyxia_spawn.h"

static int fail(const char *stage) {
    printf("SCM_PROBE FAIL %s pid=%d errno=%d\n", stage, getpid(), errno);
    return 1;
}
#define CHECK(c,s) do { if (!(c)) return fail(s); } while (0)
static ssize_t send_rights(int socket, const void *data, size_t length, const int *fds, size_t count) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(8 * sizeof(int))]; } control;
    memset(&control, 0, sizeof control);
    struct iovec vector = {(void *)data, length};
    struct msghdr message = {.msg_iov=&vector, .msg_iovlen=1};
    if (count) {
        if (count > 8) { errno = EINVAL; return -1; }
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), fds, count * sizeof(int));
    }
    return sendmsg(socket, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
}
static ssize_t receive_rights(int socket, void *data, size_t length, int *fds, size_t *count,
                              int *out_flags, int flags) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(8 * sizeof(int))]; } control;
    memset(&control, 0, sizeof control);
    struct iovec vector = {data, length};
    struct msghdr message = {.msg_iov=&vector, .msg_iovlen=1};
    if (*count) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(*count * sizeof(int));
    }
    ssize_t n = recvmsg(socket, &message, flags);
    *count = 0;
    *out_flags = message.msg_flags;
    if (n < 0) return n;
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    if (header) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
                header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > sizeof control) {
            errno = EINVAL; return -1;
        }
        size_t size = header->cmsg_len - CMSG_LEN(0);
        if (size % sizeof(int) || size / sizeof(int) > 8 || message.msg_controllen > CMSG_SPACE(size)) {
            errno=EINVAL; return -1;
        }
        memcpy(fds + *count, CMSG_DATA(header), size);
        *count += size / sizeof(int);
    }
    return n;
}
static int joined(pid_t pid) {
    int status;
    return pid > 0 && waitpid(pid,&status,0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int child_sender(void) {
    int file = open("/scm-unlinked",O_CREAT|O_RDWR|O_TRUNC,0600), pipefd[2];
    int event = eventfd(5,EFD_CLOEXEC|EFD_NONBLOCK);
    int asset = open("/bin/scm-probe",O_RDONLY|O_CLOEXEC);
    CHECK(file>=0 && event>=0 && asset>=0 && pipe2(pipefd,O_CLOEXEC)==0,"sender-create");
    CHECK(write(file,"ABCD",4)==4 && lseek(file,0,SEEK_SET)==0 && unlink("/scm-unlinked")==0,"sender-file");
    CHECK(write(pipefd[1],"pipe",4)==4,"sender-pipe");
    int fds[]={file,event,pipefd[0],asset};
    CHECK(send_rights(3,"R",1,fds,4)==1,"sender-rights");
    return 0; /* Every originating FD is closed by actual process exit. */
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    if (argc==2 && !strcmp(argv[1],"sender")) return child_sender();
    int pair[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0,"pair");
    char *args[]={"/bin/scm-probe","sender",NULL}, *env[]={NULL};
    struct cyxia_mapping maps[]={{-2,0},{1,1},{2,2},{pair[1],3}};
    pid_t pid=cyxia_spawn(args[0],args,env,maps,4);
    CHECK(pid>0 && close(pair[1])==0 && joined(pid),"sender-exit");
    char data[2048]={0}; int received[8], flags; size_t count=8;
    CHECK(receive_rights(pair[0],data,sizeof data,received,&count,&flags,MSG_CMSG_CLOEXEC)==1 &&
            data[0]=='R' && count==4 && flags==0,"receive-after-exit");
    struct stat st; uint64_t value;
    CHECK(fstat(received[0],&st)==0 && st.st_nlink==0 && read(received[0],data,4)==4 &&
            !memcmp(data,"ABCD",4),"unlinked-file-survives");
    CHECK(read(received[1],&value,8)==8 && value==5,"event-survives");
    CHECK(read(received[2],data,4)==4 && !memcmp(data,"pipe",4) && read(received[2],data,1)==0,"pipe-survives");
    CHECK(read(received[3],data,4)==4 && !memcmp(data,"\177ELF",4),"readonly-asset-survives");
    for(size_t i=0;i<count;++i) CHECK(fcntl(received[i],F_GETFD)==FD_CLOEXEC && close(received[i])==0,"received-closeexec");
    CHECK(close(pair[0])==0,"pair-close");
    puts("SCM_PROBE CREATOR_EXIT PASS");

    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,pair)==0,"local-pair");
    int event=eventfd(3,EFD_NONBLOCK), ep=epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event watch={.events=EPOLLIN,.data.u64=0x123456};
    CHECK(event>=0 && ep>=0 && epoll_ctl(ep,EPOLL_CTL_ADD,event,&watch)==0,"weak-watch");
    int dupfds[]={event,event};
    CHECK(send_rights(pair[0],"xx",2,dupfds,2)==2 && close(event)==0,"inflight-only");
    CHECK(epoll_wait(ep,&watch,1,0)==1 && watch.data.u64==0x123456,"watch-kept-inflight");
    count=8;
    CHECK(receive_rights(pair[1],data,1,received,&count,&flags,0)==1 && count==2 && flags==0,"duplicate-rights");
    CHECK(received[0]!=received[1] && fcntl(received[0],F_GETFD)==0,"private-new-fds");
    CHECK(read(received[0],&value,8)==8 && value==3 && read(received[1],&value,8)==-1 && errno==EAGAIN,"shared-counter");
    CHECK(close(received[0])==0 && close(received[1])==0 && epoll_wait(ep,&watch,1,0)==0,"watch-final-release");
    CHECK(read(pair[1],data,1)==1 && data[0]=='x' && close(ep)==0,"short-receive-tail");
    puts("SCM_PROBE INFLIGHT_IDENTITY PASS");

    event=eventfd(0,EFD_NONBLOCK);
    CHECK(event>=0 && write(pair[0],"a",1)==1 && send_rights(pair[0],"bc",2,&event,1)==2 &&
            write(pair[0],"d",1)==1,"boundary-send");
    count=8;
    CHECK(receive_rights(pair[1],data,1,received,&count,&flags,0)==1 && data[0]=='a' && count==0,"before-boundary");
    count=8;
    CHECK(receive_rights(pair[1],data,8,received,&count,&flags,0)==2 && !memcmp(data,"bc",2) &&
            count==1 && flags==0 && close(received[0])==0,"at-boundary");
    count=8;
    CHECK(receive_rights(pair[1],data,8,received,&count,&flags,0)==1 && data[0]=='d' && count==0,"after-boundary");
    puts("SCM_PROBE STREAM_BOUNDARY PASS");

    int bad[]={event,999};
    CHECK(send_rights(pair[0],"no",2,bad,2)==-1 && errno==EBADF,"invalid-later-fd");
    CHECK(read(pair[1],data,1)==-1 && errno==EAGAIN,"no-invalid-prefix");
    CHECK(send_rights(pair[0],"no",2,&pair[0],1)==-1 && errno==ENOSYS,"unsupported-cycle");
    CHECK(read(pair[1],data,1)==-1 && errno==EAGAIN,"no-unsupported-prefix");
    CHECK(send_rights(pair[0],"E",1,&event,1)==1,"fault-send");
    struct iovec vector={data,1};
    struct msghdr fault={.msg_iov=&vector,.msg_iovlen=1,.msg_control=(void *)(uintptr_t)1,.msg_controllen=24};
    CHECK(recvmsg(pair[1],&fault,0)==-1 && errno==EFAULT,"bad-control-pointer");
    count=8;
    CHECK(receive_rights(pair[1],data,8,received,&count,&flags,0)==1 && data[0]=='E' && count==1 &&
            close(received[0])==0,"fault-preserves-message");
    puts("SCM_PROBE FAILURE_ATOMICITY PASS");

    dupfds[0]=event; dupfds[1]=event;
    CHECK(send_rights(pair[0],"T",1,dupfds,2)==1,"truncate-send");
    /* 20 bytes contain one FD; CMSG_SPACE(4) would contain room for two on ARM64. */
    union {struct cmsghdr align; char bytes[24];} short_control;
    struct msghdr short_msg={.msg_iov=&vector,.msg_iovlen=1,.msg_control=short_control.bytes,.msg_controllen=20};
    CHECK(recvmsg(pair[1],&short_msg,MSG_CMSG_CLOEXEC)==1 && data[0]=='T' &&
            (short_msg.msg_flags&MSG_CTRUNC) && short_msg.msg_controllen==20,"control-truncation");
    memcpy(&received[0],CMSG_DATA(CMSG_FIRSTHDR(&short_msg)),sizeof(int));
    CHECK(fcntl(received[0],F_GETFD)==FD_CLOEXEC && close(received[0])==0,"truncated-fd-valid");
    CHECK(send_rights(pair[0],"D",1,&event,1)==1 && read(pair[1],data,1)==1 && data[0]=='D',"read-discards-rights");
    CHECK(send_rights(pair[0],"N",1,&event,1)==1,"no-control-send"); count=0;
    CHECK(receive_rights(pair[1],data,1,received,&count,&flags,0)==1 && data[0]=='N' &&
            (flags&MSG_CTRUNC) && count==0,"no-control-discards");
    puts("SCM_PROBE CONTROL_TRUNCATION PASS");

    CHECK(send_rights(pair[0],"F",1,dupfds,2)==1,"fd-full-send");
    int filled[16], filled_count=0, copy;
    while((copy=dup(event))>=0) filled[filled_count++]=copy;
    CHECK(errno==EMFILE && filled_count>0,"fill-fd-table"); count=8;
    CHECK(receive_rights(pair[1],data,1,received,&count,&flags,0)==1 && data[0]=='F' &&
            count==0 && (flags&MSG_CTRUNC),"fd-full-consumes-truncates");
    for(int i=0;i<filled_count;++i) CHECK(close(filled[i])==0,"fd-full-close");
    puts("SCM_PROBE FD_CAPACITY PASS");

    unsigned sent=0;
    while(sent<32 && send_rights(pair[0],"Q",1,&event,1)==1) ++sent;
    CHECK(sent>0 && sent<32 && (errno==EAGAIN || errno==ENOBUFS),"queue-bounded");
    for(unsigned i=0;i<sent;++i) {
        count=8;
        CHECK(receive_rights(pair[1],data,8,received,&count,&flags,0)==1 && count==1 &&
                close(received[0])==0,"queue-drain");
    }
    CHECK(read(pair[1],data,1)==-1 && errno==EAGAIN,"queue-empty");
    puts("SCM_PROBE QUEUE_BACKPRESSURE PASS");

    memset(data,'S',sizeof data);
    CHECK(send_rights(pair[0],data,sizeof data,&event,1)==1024,"positive-short-send");
    count=8;
    CHECK(receive_rights(pair[1],data,sizeof data,received,&count,&flags,0)==1024 && count==1 &&
            close(received[0])==0,"short-send-one-rights");
    CHECK(read(pair[1],data,1)==-1 && errno==EAGAIN,"short-send-no-implicit-tail");
    puts("SCM_PROBE SHORT_WRITE PASS");

    for(unsigned i=0;i<4;++i) CHECK(write(pair[0],data,1024)==1024,"fill-byte-ring");
    CHECK(fcntl(pair[0],F_SETFL,0)==0,"blocking-sender");
    union {struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))];} blocked_control;
    memset(&blocked_control,0,sizeof blocked_control);
    struct msghdr blocked={.msg_iov=&vector,.msg_iovlen=1,.msg_control=blocked_control.bytes,.msg_controllen=sizeof blocked_control};
    struct cmsghdr *header=CMSG_FIRSTHDR(&blocked);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header),&event,sizeof event);
    /* The bounded ABI rejects waiting ancillary sends; it must not replay
     * source FD numbers after another thread could close/reuse them. */
    CHECK(sendmsg(pair[0],&blocked,MSG_NOSIGNAL)==-1 && errno==EAGAIN,"blocking-rights-do-not-replay");
    for(unsigned i=0;i<4;++i) CHECK(read(pair[1],data,1024)==1024,"drain-byte-ring");
    CHECK(read(pair[1],data,1)==-1 && errno==EAGAIN && fcntl(pair[0],F_SETFL,O_NONBLOCK)==0,"no-failed-send-bytes");
    puts("SCM_PROBE BLOCKING_SEND_BOUNDARY PASS");

    CHECK(send_rights(pair[0],"C",1,&event,1)==1 && close(event)==0 &&
            close(pair[1])==0 && close(pair[0])==0,"unreceived-final-close");
    puts("SCM_PROBE UNRECEIVED_RELEASE PASS");
    puts("SCM_PROBE PASS");
    return 0;
}
