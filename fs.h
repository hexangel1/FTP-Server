#ifndef FS_H_SENTRY
#define FS_H_SENTRY

int str_file_info(char *buf, int len, int dir_fd, const char *path);
int str_modify_time(char *buf, int len, int dir_fd, const char *name);

#endif /* FS_H_SENTRY */

