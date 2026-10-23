#ifndef CYX_STAT_H
#define CYX_STAT_H
#include <sys/types.h>
int mkdir(const char *,mode_t);
mode_t umask(mode_t);
#endif
