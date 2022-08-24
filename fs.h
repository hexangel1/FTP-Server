#ifndef FS_H_SENTRY
#define FS_H_SENTRY

/* writes in buf inforamation about file */
int str_file_info(char *buf, int len, const char *name, int dir_fd);

/* writes in buf modify time */
int str_modify_time(char *buf, int len, const char *name, int dir_fd);

/* changes current directory */
int change_directory(const char *path, int dir_fd);

/* writes in buf path to directory associated with dir_fd */
int get_directory_path(char *buf, int size, int dir_fd);

/* returns file size by path in directory associated with dir_fd */
long get_file_size(const char *path, int dir_fd);

/* creates directory by path in directory associated with dir_fd */
int create_directory(const char *path, int dir_fd);

/* removes directory by path in directory associated with dir_fd */
int remove_directory(const char *path, int dir_fd);

/* removes file by path in directory associated with dir_fd */
int remove_file(const char *path, int dir_fd);

#endif /* FS_H_SENTRY */

