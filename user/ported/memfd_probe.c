/* Page-backed sharing and real PTE permissions in independent EL0 processes. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cyxia_spawn.h"
static int fail(const char *stage) {
    printf("MEMFD_PROBE FAIL %s pid=%d errno=%d\n",stage,getpid(),errno); return 1;
}
#define CHECK(c,s) do {if(!(c)) return fail(s);} while(0)
static int send_fd(int socket,int fd) {
    union {struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))];} control;
    memset(&control,0,sizeof control);
    char byte='m'; struct iovec vector={&byte,1};
    struct msghdr msg={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control};
    struct cmsghdr *h=CMSG_FIRSTHDR(&msg);
    h->cmsg_level=SOL_SOCKET; h->cmsg_type=SCM_RIGHTS; h->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h),&fd,sizeof fd);
    return sendmsg(socket,&msg,MSG_NOSIGNAL)==1 ? 0 : -1;
}
static int recv_fd(int socket) {
    union {struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))];} control;
    char byte; struct iovec vector={&byte,1};
    struct msghdr msg={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control};
    if(recvmsg(socket,&msg,MSG_CMSG_CLOEXEC)!=1 || byte!='m' || msg.msg_flags) return -1;
    struct cmsghdr *h=CMSG_FIRSTHDR(&msg); int fd;
    if(!h || h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS || h->cmsg_len!=CMSG_LEN(sizeof fd)) return -1;
    memcpy(&fd,CMSG_DATA(h),sizeof fd); return fd;
}
static pid_t spawn(const char *mode,struct cyxia_mapping *maps,unsigned count) {
    char *args[]={"/bin/memfd-probe",(char *)mode,NULL},*env[]={NULL};
    return cyxia_spawn(args[0],args,env,maps,count);
}
static int joined(pid_t pid,int signal) {
    int status;
    if(pid<0 || waitpid(pid,&status,0)!=pid) return 0;
    return signal ? WIFSIGNALED(status)&&WTERMSIG(status)==signal : WIFEXITED(status)&&WEXITSTATUS(status)==0;
}
static int child(const char *mode) {
    if(!strcmp(mode,"aliases")) {
        volatile unsigned char *map=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_SHARED,3,0);
        CHECK(map!=MAP_FAILED && map[0]==7 && map[4096]==9,"child-map");
        map[0]=11;
        CHECK(close(3)==0 && write(5,"a",1)==1,"child-close-fd");
        char gate;
        CHECK(read(4,&gate,1)==1 && gate=='g' && map[4096]==13,"child-after-parent-unmap");
        map[1]=22;
        CHECK(munmap((void *)map,8192)==0 && write(5,"b",1)==1,"child-final-unmap");
        return 0;
    }
    if(!strcmp(mode,"sender")) {
        int fd=memfd_create("sender",MFD_ALLOW_SEALING|MFD_CLOEXEC);
        CHECK(fd>=0 && ftruncate(fd,8192)==0,"sender-create");
        unsigned char *map=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        CHECK(map!=MAP_FAILED,"sender-map");
        for(unsigned i=0;i<8192;++i) map[i]=(unsigned char)(i*17+3);
        CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_SHRINK)==0 && send_fd(3,fd)==0,"sender-send");
        return 0; /* Kernel exit drops both mapping and FD; SCM keeps backing. */
    }
    if(!strcmp(mode,"write-protected")) {
        volatile unsigned char *map=mmap(NULL,4096,PROT_READ,MAP_SHARED,3,0);
        CHECK(map!=MAP_FAILED,"protected-child-map");
        map[0]=99;
        return fail("read-only-PTE-allowed-write");
    }
    if(!strcmp(mode,"seal-reader")) {
        volatile unsigned char *map=mmap(NULL,4096,PROT_READ,MAP_SHARED,3,0);
        CHECK(map!=MAP_FAILED && map[0]=='b',"seal-child-read-map");
        CHECK(close(3)==0 && write(5,"r",1)==1,"seal-child-map-only");
        char gate;
        CHECK(read(4,&gate,1)==1 && gate=='w' && map[0]=='B',"seal-child-parent-write");
        /* Initial PROT_READ on the writable OFD preserves future write
         * capability even after that OFD is closed in this process. */
        CHECK(mprotect((void *)map,4096,PROT_READ|PROT_WRITE)==0,"seal-child-upgrade");
        map[1]='C';
        CHECK(mprotect((void *)map,4096,PROT_NONE)==0 && write(5,"n",1)==1,"seal-child-none");
        CHECK(read(4,&gate,1)==1 && gate=='u',"seal-child-unmap-gate");
        CHECK(munmap((void *)map,4096)==0 && write(5,"u",1)==1,"seal-child-unmap");
        return 0;
    }
    return fail("mode");
}

static int positioned_io_checks(void) {
    int fd=memfd_create("positioned",MFD_ALLOW_SEALING);
    CHECK(fd>=0 && write(fd,"abcdefgh",8)==8 && lseek(fd,3,SEEK_SET)==3,"positioned-create");
    int alias=dup(fd);
    unsigned char bytes[16];
    CHECK(alias>=0 && pread(alias,bytes,3,1)==3 && !memcmp(bytes,"bcd",3) &&
          lseek(fd,0,SEEK_CUR)==3 && lseek(alias,0,SEEK_CUR)==3,"pread-independent-offset");
    CHECK(pwrite(alias,"XY",2,5)==2 && pread(fd,bytes,8,0)==8 &&
          !memcmp(bytes,"abcdeXYh",8) && lseek(fd,0,SEEK_CUR)==3 &&
          lseek(alias,0,SEEK_CUR)==3,"pwrite-independent-offset");
    CHECK(pread(fd,bytes,1,8)==0 && lseek(fd,0,SEEK_CUR)==3,"pread-eof");
    CHECK(pwrite(fd,"Z",1,10)==1 && pread(fd,bytes,11,0)==11 &&
          !memcmp(bytes,"abcdeXYh",8) && bytes[8]==0 && bytes[9]==0 && bytes[10]=='Z' &&
          lseek(fd,0,SEEK_CUR)==3,"pwrite-growth-zero-gap");
    CHECK(pread(fd,bytes,1,-1)==-1 && errno==EINVAL &&
          pwrite(fd,"?",1,-1)==-1 && errno==EINVAL,"positioned-negative-offset");
    CHECK(pread(fd,(void *)(uintptr_t)1,1,0)==-1 && errno==EFAULT &&
          pwrite(fd,(const void *)(uintptr_t)1,1,0)==-1 && errno==EFAULT,
          "positioned-invalid-buffer");
    CHECK(lseek(fd,0,SEEK_CUR)==3 && pread(fd,bytes,11,0)==11 &&
          !memcmp(bytes,"abcdeXYh",8) && bytes[8]==0 && bytes[9]==0 && bytes[10]=='Z',
          "positioned-failure-atomicity");
    CHECK(fcntl(fd,F_SETFL,O_APPEND)==0 && syscall(SYS_pwrite64,fd,"!",1,0)==1 &&
          pread(fd,bytes,12,0)==12 && bytes[0]=='a' && bytes[11]=='!' &&
          lseek(fd,0,SEEK_CUR)==3,"raw-pwrite64-linux-append");
    struct stat st;
    CHECK(syscall(SYS_pwrite64,fd,"",0,99)==0 && fstat(fd,&st)==0 && st.st_size==12 &&
          lseek(alias,0,SEEK_CUR)==3,"raw-pwrite64-zero-keeps-offset");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE)==0 &&
          syscall(SYS_pwrite64,fd,"?",1,0)==-1 && errno==EPERM &&
          fstat(fd,&st)==0 && st.st_size==12 && lseek(fd,0,SEEK_CUR)==3 &&
          close(alias)==0 && close(fd)==0,"raw-pwrite64-sealed-append-atomic");
    int pipefd[2];
    CHECK(pipe(pipefd)==0 && write(pipefd[1],"p",1)==1,"positioned-pipe-create");
    CHECK(pread(pipefd[0],bytes,1,0)==-1 && errno==ESPIPE &&
          read(pipefd[0],bytes,1)==1 && bytes[0]=='p',"pread-pipe-no-consumption");
    CHECK(pwrite(pipefd[1],"?",1,0)==-1 && errno==ESPIPE &&
          fcntl(pipefd[0],F_SETFL,O_NONBLOCK)==0 && read(pipefd[0],bytes,1)==-1 &&
          errno==EAGAIN && close(pipefd[0])==0 && close(pipefd[1])==0,"pwrite-pipe-no-write");
    int pair[2];
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0 && write(pair[1],"s",1)==1,
          "positioned-socket-create");
    CHECK(pread(pair[0],bytes,1,0)==-1 && errno==ESPIPE &&
          read(pair[0],bytes,1)==1 && bytes[0]=='s',"pread-socket-no-consumption");
    CHECK(pwrite(pair[1],"?",1,0)==-1 && errno==ESPIPE &&
          fcntl(pair[0],F_SETFL,O_NONBLOCK)==0 && read(pair[0],bytes,1)==-1 &&
          errno==EAGAIN && close(pair[0])==0 && close(pair[1])==0,"pwrite-socket-no-write");
    puts("MEMFD_PROBE POSITIONED_IO PASS");
    return 0;
}

static int write_seal_checks(void) {
    int fd=memfd_create("write-seal",MFD_ALLOW_SEALING);
    CHECK(fd>=0 && ftruncate(fd,4096)==0 && write(fd,"immutable",9)==9,"write-seal-create");
    unsigned char *map=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(map!=MAP_FAILED && !memcmp(map,"immutable",9),"write-seal-map");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW)==-1 && errno==EBUSY &&
          fcntl(fd,F_GET_SEALS)==0 && !memcmp(map,"immutable",9),"write-seal-rw-atomic");
    CHECK(mprotect(map,4096,PROT_READ)==0 &&
          fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_SHRINK)==-1 && errno==EBUSY &&
          fcntl(fd,F_GET_SEALS)==0,"write-seal-ro-still-may-write");
    CHECK(mprotect(map,4096,PROT_NONE)==0 &&
          fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE)==-1 && errno==EBUSY &&
          fcntl(fd,F_GET_SEALS)==0,"write-seal-none-still-may-write");
    CHECK(mprotect(map,4096,PROT_READ|PROT_WRITE)==0 && map[0]=='i' &&
          munmap(map,4096)==0,"write-seal-upgrade-before-unmap");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE)==0 &&
          fcntl(fd,F_GET_SEALS)==F_SEAL_WRITE,"write-seal-after-unmap");
    CHECK(lseek(fd,3,SEEK_SET)==3 && write(fd,"X",1)==-1 && errno==EPERM &&
          lseek(fd,0,SEEK_CUR)==3,"write-seal-write-offset");
    CHECK(pwrite(fd,"X",1,0)==-1 && errno==EPERM &&
          lseek(fd,0,SEEK_CUR)==3,"write-seal-pwrite-offset");
    CHECK(fcntl(fd,F_SETFL,O_APPEND)==0 && write(fd,"X",1)==-1 && errno==EPERM &&
          lseek(fd,0,SEEK_CUR)==3,"write-seal-append-offset");
    CHECK(write(fd,"",0)==0 && lseek(fd,0,SEEK_CUR)==3 &&
          fcntl(fd,F_SETFL,0)==0,"write-seal-zero-write");
    struct stat st;
    unsigned char bytes[9];
    CHECK(fstat(fd,&st)==0 && st.st_size==4096 &&
          pread(fd,bytes,sizeof bytes,0)==sizeof bytes && !memcmp(bytes,"immutable",9) &&
          lseek(fd,0,SEEK_CUR)==3,"write-seal-file-unchanged");
    CHECK(mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0)==MAP_FAILED &&
          errno==EPERM,"write-seal-new-rw-rejected");
    map=mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,0);
    unsigned char *none=mmap(NULL,4096,PROT_NONE,MAP_SHARED,fd,0);
    CHECK(map!=MAP_FAILED && none!=MAP_FAILED && map[0]=='i',"write-seal-new-read-none");
    CHECK(mprotect(map,4096,PROT_READ|PROT_WRITE)==-1 && errno==EACCES &&
          map[0]=='i',"write-seal-read-upgrade-rejected");
    CHECK(mprotect(none,4096,PROT_READ|PROT_WRITE)==-1 && errno==EACCES &&
          mprotect(none,4096,PROT_READ)==0 && none[0]=='i',"write-seal-none-upgrade-rejected");
    CHECK(mprotect(map,4096,PROT_NONE)==0 &&
          mprotect(map,4096,PROT_READ|PROT_WRITE)==-1 && errno==EACCES &&
          mprotect(map,4096,PROT_READ)==0 && map[0]=='i',"write-seal-no-upgrade-via-none");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)==0 &&
          fcntl(fd,F_GET_SEALS)==(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL),
          "write-seal-read-only-maps-allow-seals");
    CHECK(close(fd)==0 && map[8]=='e' && none[8]=='e' &&
          munmap(map,4096)==0 && munmap(none,4096)==0,"write-seal-final-release");
    puts("MEMFD_PROBE WRITE_SEAL_ATOMICITY PASS");
    return 0;
}

static int cross_process_seal_checks(void) {
    int fd=memfd_create("cross-seal",MFD_ALLOW_SEALING);
    CHECK(fd>=0 && ftruncate(fd,4096)==0 && write(fd,"before",6)==6,"cross-seal-create");
    int gate[2],ack[2];
    CHECK(pipe(gate)==0 && pipe(ack)==0,"cross-seal-pipes");
    struct cyxia_mapping maps[]={{-2,0},{1,1},{2,2},{fd,3},{gate[0],4},{ack[1],5}};
    pid_t pid=spawn("seal-reader",maps,6);
    char byte;
    CHECK(pid>0 && close(gate[0])==0 && close(ack[1])==0 &&
          read(ack[0],&byte,1)==1 && byte=='r',"cross-seal-child-ready");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW)==-1 && errno==EBUSY &&
          fcntl(fd,F_GET_SEALS)==0,"cross-seal-ro-map-blocks");
    CHECK(pwrite(fd,"B",1,0)==1 && write(gate[1],"w",1)==1 &&
          read(ack[0],&byte,1)==1 && byte=='n',"cross-seal-child-downgrade");
    CHECK(pread(fd,&byte,1,1)==1 && byte=='C' &&
          fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_SHRINK)==-1 && errno==EBUSY &&
          fcntl(fd,F_GET_SEALS)==0,"cross-seal-none-map-blocks");
    CHECK(write(gate[1],"u",1)==1 && read(ack[0],&byte,1)==1 && byte=='u',
          "cross-seal-child-unmapped");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW)==0 &&
          fcntl(fd,F_GET_SEALS)==(F_SEAL_WRITE|F_SEAL_GROW),"cross-seal-after-global-unmap");
    CHECK(close(fd)==0 && joined(pid,0) && close(gate[1])==0 &&
          close(ack[0])==0,"cross-seal-release");
    puts("MEMFD_PROBE CROSS_PROCESS_WRITE_SEAL PASS");
    return 0;
}

static unsigned char private_byte(unsigned index) {
    return (unsigned char)(index*19+37);
}

static int private_snapshot_checks(void) {
    int fd=memfd_create("private-snapshot",MFD_ALLOW_SEALING);
    CHECK(fd>=0 && ftruncate(fd,4097)==0,"private-create");
    unsigned char *shared=mmap(NULL,4097,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(shared!=MAP_FAILED,"private-source-map");
    for(unsigned i=0;i<4097;++i) shared[i]=private_byte(i);
    /* Dirty the accessible tail in the backing page. A valid snapshot must
     * copy only file bytes and zero its own EOF-to-page-boundary tail. */
    memset(shared+4097,0xa5,8192-4097);
    CHECK(munmap(shared,4097)==0,"private-source-unmap");
    CHECK(mmap(NULL,4097,PROT_READ,MAP_PRIVATE,fd,0)==MAP_FAILED && errno==EINVAL,
          "private-unsealed-rejected");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE)==0 &&
          mmap(NULL,4097,PROT_READ,MAP_PRIVATE,fd,0)==MAP_FAILED && errno==EINVAL,
          "private-write-seal-alone-rejected");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_SHRINK)==0 &&
          mmap(NULL,4097,PROT_READ,MAP_PRIVATE,fd,0)==MAP_FAILED && errno==EINVAL,
          "private-growth-still-possible-rejected");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_GROW)==0,"private-immutable-source");
    CHECK(mmap(NULL,4097,PROT_READ,MAP_PRIVATE,fd,1)==MAP_FAILED && errno==EINVAL,
          "private-offset-alignment");
    CHECK(mmap(NULL,2,PROT_READ,MAP_PRIVATE,fd,4096)==MAP_FAILED && errno==EINVAL,
          "private-beyond-eof");
    CHECK(mmap(NULL,4097,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0)==MAP_FAILED && errno==EINVAL,
          "private-no-exec");
    unsigned char *first=mmap(NULL,4097,PROT_READ,MAP_PRIVATE,fd,0);
    unsigned char *offset=mmap(NULL,1,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,4096);
    unsigned char *none=mmap(NULL,4097,PROT_NONE,MAP_PRIVATE,fd,0);
    CHECK(first!=MAP_FAILED && offset!=MAP_FAILED && none!=MAP_FAILED,"private-three-snapshots");
    for(unsigned i=0;i<4097;++i) CHECK(first[i]==private_byte(i),"private-exact-copy");
    for(unsigned i=4097;i<8192;++i) CHECK(first[i]==0,"private-eof-tail-zero");
    CHECK(offset[0]==private_byte(4096),"private-offset-copy");
    for(unsigned i=1;i<4096;++i) CHECK(offset[i]==0,"private-offset-tail-zero");
    CHECK(mprotect(first,8192,PROT_READ|PROT_WRITE)==0 &&
          mprotect(none,8192,PROT_READ)==0,"private-future-write-and-read");
    first[0]^=0xff;
    first[4096]^=0xff;
    offset[0]^=0x55;
    CHECK(none[0]==private_byte(0) && none[4096]==private_byte(4096),"private-copies-independent");
    unsigned char byte;
    CHECK(pread(fd,&byte,1,0)==1 && byte==private_byte(0) &&
          pread(fd,&byte,1,4096)==1 && byte==private_byte(4096),"private-writes-not-file-writes");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_SEAL)==0,"private-rw-does-not-block-seal");
    CHECK(close(fd)==0 && first[0]==(unsigned char)(private_byte(0)^0xff) &&
          offset[0]==(unsigned char)(private_byte(4096)^0x55) &&
          none[4096]==private_byte(4096),"private-survives-backing-close");
    CHECK(mprotect(first,8192,PROT_NONE)==0 && mprotect(first,8192,PROT_READ)==0 &&
          first[4096]==(unsigned char)(private_byte(4096)^0xff),"private-protection-retains-copy");
    CHECK(munmap(first,4097)==0 && munmap(offset,1)==0 && munmap(none,4097)==0,
          "private-final-unmap");
    puts("MEMFD_PROBE SEALED_PRIVATE_SNAPSHOT PASS");
    return 0;
}

int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    if(argc==2) return child(argv[1]);
    int fd=memfd_create("bounds",MFD_ALLOW_SEALING|MFD_CLOEXEC);
    struct stat st;
    CHECK(fd>=0 && fcntl(fd,F_GETFD)==FD_CLOEXEC && fstat(fd,&st)==0 && st.st_size==0 && S_ISREG(st.st_mode),"empty-file");
    CHECK(ftruncate(fd,8193)==0 && fstat(fd,&st)==0 && st.st_size==8193,"grow");
    int alias=dup(fd);
    CHECK(alias>=0 && fcntl(fd,F_SETFL,O_APPEND)==0 && write(alias,"",0)==0 &&
            lseek(fd,0,SEEK_CUR)==0 && fcntl(fd,F_SETFL,0)==0 && close(alias)==0,"zero-append-keeps-shared-offset");
    unsigned char *map=mmap(NULL,8193,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(map!=MAP_FAILED,"map-tail");
    for(unsigned i=0;i<12288;++i) CHECK(map[i]==0,"zero-pages-tail");
    map[4095]=23; map[4096]=24; map[8192]=25;
    unsigned char *offset=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,4096);
    CHECK(offset!=MAP_FAILED && offset[0]==24,"offset-alias"); offset[0]=26;
    CHECK(map[4096]==26 && lseek(fd,4095,SEEK_SET)==4095,"shared-offset");
    unsigned char bytes[16];
    CHECK(read(fd,bytes,2)==2 && bytes[0]==23 && bytes[1]==26,"mapped-file-read");
    CHECK(write(fd,"abc",3)==3 && !memcmp(map+4097,"abc",3),"file-mapped-write");
    CHECK(ftruncate(fd,4096)==-1 && errno==EBUSY,"mapped-shrink-rejected");
    CHECK(munmap(map,4096)==-1 && errno==EINVAL,"partial-unmap-rejected");
    CHECK(mmap(NULL,4096,PROT_READ|PROT_EXEC,MAP_SHARED,fd,0)==MAP_FAILED && errno==EINVAL,"shared-no-exec");
    CHECK(mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,8192)==MAP_FAILED && errno==EINVAL,"beyond-size-rejected");
    CHECK(mprotect(map,12288,PROT_READ)==0 && lseek(fd,0,SEEK_SET)==0,"protect-read");
    CHECK(read(fd,map,1)==-1 && errno==EFAULT && lseek(fd,0,SEEK_CUR)==0,"usercopy-write-protected");
    CHECK(mprotect(map,12288,PROT_NONE)==0 && write(fd,map,1)==-1 && errno==EFAULT,"usercopy-read-protected");
    CHECK(mprotect(map,12288,PROT_READ|PROT_WRITE)==0 && map[4096]==26,"protect-restore");
    CHECK(munmap(offset,4096)==0 && munmap(map,8193)==0,"unmap-whole");
    CHECK(ftruncate(fd,1)==0 && ftruncate(fd,8193)==0 && lseek(fd,4095,SEEK_SET)==4095,"shrink-grow");
    CHECK(read(fd,bytes,2)==2 && bytes[0]==0 && bytes[1]==0,"grow-clears-old-bytes");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_GROW|0x40000000)==-1 && errno==EINVAL &&
          fcntl(fd,F_GET_SEALS)==0,"unknown-seal-rejected-atomically");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW)==0 &&
          fcntl(fd,F_GET_SEALS)==(F_SEAL_SHRINK|F_SEAL_GROW),"seal-state");
    CHECK(ftruncate(fd,1)==-1 && errno==EPERM && ftruncate(fd,16384)==-1 && errno==EPERM,"seal-enforced");
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_SEAL)==0 && fcntl(fd,F_ADD_SEALS,0)==-1 && errno==EPERM && close(fd)==0,"seal-final");
    puts("MEMFD_PROBE FILE_MAPPING_BOUNDS PASS");

    fd=memfd_create("aliases",MFD_ALLOW_SEALING);
    CHECK(fd>=0 && ftruncate(fd,8192)==0,"aliases-create");
    volatile unsigned char *shared=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(shared!=MAP_FAILED,"aliases-map"); shared[0]=7; shared[4096]=9;
    int gate[2],ack[2];
    CHECK(pipe(gate)==0 && pipe(ack)==0,"alias-pipes");
    struct cyxia_mapping maps[]={{-2,0},{1,1},{2,2},{fd,3},{gate[0],4},{ack[1],5}};
    pid_t pid=spawn("aliases",maps,6); char byte;
    CHECK(pid>0 && close(gate[0])==0 && close(ack[1])==0 && read(ack[0],&byte,1)==1 && byte=='a' && shared[0]==11,"child-shared-write");
    shared[4096]=13;
    CHECK(close(fd)==0 && munmap((void *)shared,8192)==0 && write(gate[1],"g",1)==1,"parent-release");
    CHECK(read(ack[0],&byte,1)==1 && byte=='b' && joined(pid,0) && close(gate[1])==0 && close(ack[0])==0,"child-survives");
    puts("MEMFD_PROBE CROSS_PROCESS_ALIASES PASS");

    int pair[2]; CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0,"scm-pair");
    maps[3].source=pair[1];
    pid=spawn("sender",maps,4);
    CHECK(pid>0 && close(pair[1])==0 && joined(pid,0),"scm-sender-exit");
    fd=recv_fd(pair[0]);
    CHECK(fd>=0 && fcntl(fd,F_GETFD)==FD_CLOEXEC && ftruncate(fd,4096)==-1 && errno==EPERM,"received-memfd-seal");
    CHECK(ftruncate(fd,12288)==0,"grow-after-creator-exit");
    map=mmap(NULL,12288,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(map!=MAP_FAILED && close(fd)==0 && close(pair[0])==0,"received-map-only");
    for(unsigned i=0;i<8192;++i) CHECK(map[i]==(unsigned char)(i*17+3),"creator-exit-pixels");
    for(unsigned i=8192;i<12288;++i) CHECK(map[i]==0,"creator-exit-grown-zero");
    CHECK(munmap(map,12288)==0,"received-final-unmap");
    puts("MEMFD_PROBE SCM_CREATOR_EXIT PASS");

    fd=memfd_create("permissions",MFD_CLOEXEC);
    CHECK(fd>=0 && ftruncate(fd,4096)==0 && fcntl(fd,F_GET_SEALS)==F_SEAL_SEAL,"default-seal");
    maps[3].source=fd;
    CHECK(joined(spawn("write-protected",maps,4),SIGSEGV) && close(fd)==0,"real-read-only-PTE");
    puts("MEMFD_PROBE PTE_PERMISSIONS PASS");

    int large=memfd_create("large",MFD_ALLOW_SEALING);
    fd=memfd_create("denied",MFD_ALLOW_SEALING);
    CHECK(large>=0 && fd>=0 && ftruncate(large,8*1024*1024)==0 && ftruncate(fd,4096)==0,"policy-capacity");
    map=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,large,0);
    CHECK(map!=MAP_FAILED && write(fd,"safe",4)==4,"policy-existing-data"); map[0]=73;
    CHECK(ftruncate(fd,8*1024*1024)==-1 && errno==ENOMEM,"actual-AI-growth-denial");
    CHECK(fstat(fd,&st)==0 && st.st_size==4096 && lseek(fd,0,SEEK_CUR)==4 && map[0]==73,"denial-preserves-metadata");
    CHECK(lseek(fd,0,SEEK_SET)==0 && read(fd,bytes,4)==4 && !memcmp(bytes,"safe",4),"denial-preserves-data");
    CHECK(close(large)==0 && close(fd)==0 && map[0]==73 && munmap(map,4096)==0,"denial-release");
    puts("MEMFD_PROBE AI_DENIAL_ATOMICITY PASS");

    for(unsigned run=0;run<20;++run) {
        fd=memfd_create("reuse",MFD_ALLOW_SEALING);
        CHECK(fd>=0 && ftruncate(fd,4096)==0,"reuse-create");
        map=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        CHECK(map!=MAP_FAILED && map[0]==0 && map[4095]==0 && close(fd)==0,"reuse-zero");
        memset(map,0xa5,4096);
        CHECK(munmap(map,4096)==0,"reuse-close");
    }
    puts("MEMFD_PROBE RECLAIM_ZERO PASS");
    CHECK(positioned_io_checks()==0,"positioned-io-regression");
    CHECK(write_seal_checks()==0,"write-seal-regression");
    CHECK(cross_process_seal_checks()==0,"cross-process-write-seal-regression");
    CHECK(private_snapshot_checks()==0,"private-snapshot-regression");
    puts("MEMFD_PROBE PASS"); return 0;
}
