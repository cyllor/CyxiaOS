#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
static char buf[1100];
static const char message[]="POSIX EL0 C program: PASS\r\n";
#define CHECK(x) do {if(!(x)){write(2,"POSIX CHECK FAILED\r\n",20);return __LINE__;}} while(0)
static int same(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
int main(int argc,char **argv){
    CHECK(argc==2);
    if(same(argv[1],"fault")){*(volatile unsigned long*)0=1;return 99;}
    if(same(argv[1],"kernel")){buf[0]=*(volatile char*)0xffffffc040200000UL;return 99;}
    if(same(argv[1],"readonly")){*(volatile char*)message='X';return 99;}
    if(same(argv[1],"guard")){buf[0]=*(volatile char*)0x106000;return 99;}
    if(same(argv[1],"execdata")){((void(*)(void))buf)();return 99;}
    if(same(argv[1],"spin")){for(;;)__asm__ volatile("":::"memory");}
    if(same(argv[1],"preempt")){
        unsigned long ok;
        __asm__ volatile(
            "mov x19, #0x1973\nmov x20, #0x2047\nmov x10, #0x1234\n"
            "movz x9, #0xc6c0\nmovk x9, #0x2d, lsl #16\n1: subs x9,x9,#1\nb.ne 1b\n"
            "mov %0,#0\nmov x11,#0x1973\ncmp x19,x11\nb.ne 2f\n"
            "mov x11,#0x2047\ncmp x20,x11\nb.ne 2f\n"
            "mov x11,#0x1234\ncmp x10,x11\nb.ne 2f\nmov %0,#1\n2:"
            : "=r"(ok) : : "x9","x10","x11","x19","x20","cc");
        CHECK(ok==1);CHECK(write(1,"EL0 REGISTERS PASS\r\n",20)==20);return 0;
    }
    CHECK(getpid()>0);
    CHECK(read(0,buf,1)==0); /* Initial stdin is an explicit null stream. */
    CHECK(open("/absent",O_RDONLY)==-1&&errno==ENOENT);
    CHECK(close(99)==-1&&errno==EBADF);
    CHECK(lseek(1,0,SEEK_SET)==-1&&errno==ESPIPE);
    CHECK(write(1,(void*)0xffffffc040200000UL,1)==-1&&errno==EFAULT);
    CHECK(read(0,(void*)message,1)==-1&&errno==EFAULT);
    CHECK(write(1,(void*)-16UL,32)==-1&&errno==EFAULT);
    CHECK(mkdir("/posix",0700)==0);
    CHECK(chdir("/posix")==0);
    CHECK(getcwd(buf,sizeof buf)==buf&&same(buf,"/posix"));
    CHECK(umask(0022)==0022);
    int f=open("result",O_CREAT|O_EXCL|O_RDWR,0600);CHECK(f>=3);
    CHECK(open("result",O_CREAT|O_EXCL|O_WRONLY,0600)==-1&&errno==EEXIST);
    CHECK(write(f,"abcdef",6)==6);
    CHECK(lseek(f,2,SEEK_SET)==2);
    CHECK(write(f,"XY",2)==2);
    CHECK(lseek(f,0,SEEK_SET)==0);
    int d=dup(f);CHECK(d>=3&&d!=f);
    CHECK(read(d,buf,2)==2&&buf[0]=='a'&&buf[1]=='b');
    CHECK(read(f,buf,4)==4&&buf[0]=='X'&&buf[1]=='Y'&&buf[3]=='f');
    CHECK(read(f,buf,1)==0);
    CHECK(dup2(-1,d)==-1&&errno==EBADF);
    CHECK(lseek(d,10,SEEK_SET)==10);
    CHECK(write(d,"Z",1)==1);
    CHECK(lseek(f,6,SEEK_SET)==6);
    CHECK(read(f,buf,5)==5&&buf[0]==0&&buf[3]==0&&buf[4]=='Z');
    CHECK(close(d)==0);
    int a=open("result",O_WRONLY|O_APPEND);CHECK(a>=3);
    CHECK(lseek(a,0,SEEK_SET)==0&&write(a,"!",1)==1);
    CHECK(lseek(f,0,SEEK_END)==12);
    CHECK(close(a)==0);
    CHECK(open("result/../x",O_CREAT|O_WRONLY,0600)==-1&&errno==ENOTDIR);
    CHECK(unlink("result")==0);
    CHECK(open("result",O_RDONLY)==-1&&errno==ENOENT);
    a=open("result",O_CREAT|O_RDWR,0600);CHECK(a>=3);
    CHECK(write(a,"new",3)==3);
    CHECK(lseek(f,0,SEEK_END)==12); /* Unlinked inode remains distinct. */
    CHECK(close(f)==0&&close(a)==0);
    CHECK(rmdir("/posix")==-1); /* Current and nonempty directory. */
    CHECK(unlink("result")==0);
    CHECK(chdir("/")==0&&rmdir("/posix")==0);
    f=open("/posix-result",O_CREAT|O_TRUNC|O_RDWR,0644);CHECK(f>=3);
    CHECK(write(f,"hello from EL0",14)==14);
    CHECK(lseek(f,4092,SEEK_SET)==4092&&write(f,"12345678",8)==4);
    CHECK(write(f,"x",1)==-1&&errno==EFBIG);
    CHECK(close(f)==0);
    f=open("/posix-result",O_WRONLY|O_TRUNC);CHECK(f>=3);
    CHECK(write(f,"hello from EL0",14)==14);
    CHECK(close(f)==0);
    CHECK(write(1,message,sizeof(message)-1)==sizeof(message)-1);
    return 0;
}
