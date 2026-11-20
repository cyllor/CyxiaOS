/* Exercise the actual memfd metadata boundary without changing page/FD quotas. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static int failed(const char *stage,int value){printf("SHARED_OBJECT_PROBE FAIL %s value=%d errno=%d\n",stage,value,errno);return 1;}
int main(void){
 setbuf(stdout,0);puts("SHARED_OBJECT_PROBE START");int files[16],n=0;
 for(;n<16;n++){
  files[n]=syscall(SYS_memfd_create,"metadata",MFD_CLOEXEC|MFD_ALLOW_SEALING);
  if(files[n]<0){int saved=errno;for(int j=0;j<n;j++)close(files[j]);errno=saved;return failed("CREATE_16",n);}
  struct stat s;if(fstat(files[n],&s)||s.st_size!=0)return failed("ZERO_EXTENT",n);
 }
 puts("SHARED_OBJECT_PROBE CREATE_16 PASS");
 int extra=syscall(SYS_memfd_create,"seventeenth",MFD_CLOEXEC|MFD_ALLOW_SEALING);
 if(extra>=0||errno!=ENOMEM)return failed("REJECT_17",extra);
 puts("SHARED_OBJECT_PROBE REJECT_17 PASS");
 if(ftruncate(files[0],8*1024*1024))return failed("BACKING_FIRST",0);
 if(!ftruncate(files[1],8*1024*1024)||errno!=ENOMEM)return failed("BACKING_RESERVE",0);
 struct stat s;if(fstat(files[1],&s)||s.st_size!=0)return failed("BACKING_ATOMIC",0);
 if(!ftruncate(files[0],8*1024*1024+4096)||errno!=EINVAL)return failed("OBJECT_BOUND",0);
 if(ftruncate(files[0],0))return failed("SHRINK",0);
 puts("SHARED_OBJECT_PROBE PAGE_BOUNDS PASS");
 close(files[15]);files[15]=syscall(SYS_memfd_create,"reuse",MFD_CLOEXEC|MFD_ALLOW_SEALING);
 if(files[15]<0)return failed("REUSE",15);
 puts("SHARED_OBJECT_PROBE REUSE PASS");
 for(int i=0;i<16;i++)if(close(files[i]))return failed("CLOSE",i);
 for(int i=0;i<16;i++){
  files[i]=syscall(SYS_memfd_create,"second-cycle",MFD_CLOEXEC|MFD_ALLOW_SEALING);
  if(files[i]<0)return failed("SECOND_CYCLE",i);
 }
 for(int i=0;i<16;i++)close(files[i]);
 puts("SHARED_OBJECT_PROBE CLEANUP PASS");puts("SHARED_OBJECT_PROBE PASS");return 0;
}
