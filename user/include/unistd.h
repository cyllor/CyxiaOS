#ifndef CYX_UNISTD_H
#define CYX_UNISTD_H
#include <sys/types.h>
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
ssize_t read(int,void *,size_t);
ssize_t write(int,const void *,size_t);
int close(int);
off_t lseek(int,off_t,int);
int dup(int);
int dup2(int,int);
int unlink(const char *);
int rmdir(const char *);
int chdir(const char *);
char *getcwd(char *,size_t);
pid_t getpid(void);
_Noreturn void _exit(int);
#endif
