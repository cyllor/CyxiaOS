/* Minimal single-thread C source-compatibility shim; CyxiaOS ABI, not Linux ABI. */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
int errno;
static long call(long n,long a,long b,long c){
    register long x0 __asm__("x0")=a;
    register long x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x8) : "memory","cc");
    if(x0<0){errno=(int)-x0;return -1;}return x0;
}
int open(const char *p,int f,...){
    mode_t m=0;if(f&O_CREAT){va_list a;va_start(a,f);m=va_arg(a,mode_t);va_end(a);}return (int)call(1,(long)p,f,m);
}
int close(int f){return (int)call(2,f,0,0);}
ssize_t read(int f,void *p,size_t n){return call(3,f,(long)p,(long)n);}
ssize_t write(int f,const void *p,size_t n){return call(4,f,(long)p,(long)n);}
off_t lseek(int f,off_t o,int w){return call(5,f,o,w);}
int dup(int f){return (int)call(6,f,0,0);}
int dup2(int f,int n){return (int)call(7,f,n,0);}
int unlink(const char *p){return (int)call(8,(long)p,0,0);}
int mkdir(const char *p,mode_t m){return (int)call(9,(long)p,m,0);}
int rmdir(const char *p){return (int)call(10,(long)p,0,0);}
int chdir(const char *p){return (int)call(11,(long)p,0,0);}
char *getcwd(char *p,size_t n){return call(12,(long)p,(long)n,0)<0?(char*)0:p;}
pid_t getpid(void){return (pid_t)call(13,0,0,0);}
mode_t umask(mode_t m){return (mode_t)call(14,m,0,0);}
_Noreturn void _exit(int s){call(15,s,0,0);for(;;){} }
void *memcpy(void *d,const void *s,size_t n){unsigned char *o=d;const unsigned char *i=s;while(n--)*o++=*i++;return d;}
void *memset(void *d,int c,size_t n){unsigned char *o=d;while(n--)*o++=(unsigned char)c;return d;}
