#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include "fs.h"

static int get_file_type(int mode)
{
        if (S_ISLNK(mode))
                return 'l';
        if (S_ISREG(mode))
                return '-';
        if (S_ISDIR(mode))
                return 'd';
        if (S_ISCHR(mode))
                return 'c';
        if (S_ISBLK(mode))
                return 'b';
        if (S_ISFIFO(mode))
                return 'p';
        return '?';
}

static void get_permissions(char *buf, int mode)
{
        int mask, i = 0;
        const char *rwx = "rwx";
        for (mask = 0x100; mask; mask >>= 1, i++)
                buf[i] = mode & mask ? rwx[i % 3] : '-';
        buf[i] = 0;
}

static void get_user_group(char *buf, int len, int uid, int gid)
{
        struct passwd *pw;
        struct group *gr;
        pw = getpwuid(uid);
        gr = getgrgid(gid);
        if (pw && gr)
                snprintf(buf, len, "%-8s %-8s", pw->pw_name, gr->gr_name);
        else
                snprintf(buf, len, "%-5d %-5d", uid, gid);
}

static void get_modify_time(char *buf, int len, time_t rawtime)
{
        struct tm *tmptr = localtime(&rawtime);
        strftime(buf, len, "%b %d %H:%M", tmptr);
}

int str_file_info(char *buf, int len, const char *name, int dir_fd)
{
        char perms[10], mtimebuf[80], usrgrpbuf[80];
        struct stat st_buf;
        int res = fstatat(dir_fd, name, &st_buf, AT_SYMLINK_NOFOLLOW);
        if (res == -1) {
                perror("fstatat");
                return -1;
        }
        get_permissions(perms, st_buf.st_mode);
        get_user_group(usrgrpbuf, sizeof(usrgrpbuf),
                       st_buf.st_uid, st_buf.st_gid);
        get_modify_time(mtimebuf, sizeof(mtimebuf), st_buf.st_mtime);
        snprintf(buf, len, "%c%s %4ld %s %8ld %s %s\r\n",
                 get_file_type(st_buf.st_mode), perms, st_buf.st_nlink,
                 usrgrpbuf, st_buf.st_size, mtimebuf, name);
        return 0;
}

int str_modify_time(char *buf, int len, const char *name, int dir_fd)
{
        struct tm *tmptr;
        struct stat st_buf;
        int res = fstatat(dir_fd, name, &st_buf, 0);
        if (res == -1) {
                perror("fstatat");
                return -1;
        }
        tmptr = gmtime(&st_buf.st_mtime);
        strftime(buf, len, "%Y%m%d%H%M%S", tmptr);
        return 0;
}

int change_directory(const char *path, int dir_fd)
{
        int res, new_dir;
        new_dir = openat(dir_fd, path, O_RDONLY | O_DIRECTORY);
        if (new_dir == -1) {
                perror("openat");
                return -1;
        }
        res = dup2(new_dir, dir_fd);
        if (res == -1) {
                perror("dup2");
                return -1;
        }
        close(new_dir);
        return 0;
}

int get_directory_path(char *buf, int size, int dir_fd)
{
        char *path;
        int res, curr_dir;
        curr_dir = get_current_dir_fd();
        if (curr_dir == -1) {
                perror("open");
                return -1;
        }
        res = fchdir(dir_fd);
        if (res == -1) {
                perror("fchdir");
                return -1;
        }
        path = getcwd(buf, size);
        fchdir(curr_dir);
        close(curr_dir);
        return path ? 0 : -1;
}

long get_file_size(const char *path, int dir_fd)
{
        struct stat st_buf;
        int res;
        res = fstatat(dir_fd, path, &st_buf, 0);
        if (res == -1) {
                perror("statat");
                return -1;
        }
        return st_buf.st_size;
}

int is_directory(const char *path, int dir_fd)
{
        struct stat st_buf;
        int res;
        res = fstatat(dir_fd, path, &st_buf, 0);
        return res != -1 ? S_ISDIR(st_buf.st_mode) : 0;
}

int open_directory(const char *path, int dir_fd)
{
        return openat(dir_fd, path, O_RDONLY | O_DIRECTORY);
}

int create_directory(const char *path, int dir_fd)
{
        return mkdirat(dir_fd, path, 0755);
}

int remove_directory(const char *path, int dir_fd)
{
        return unlinkat(dir_fd, path, AT_REMOVEDIR);
}

int remove_file(const char *path, int dir_fd)
{
        return unlinkat(dir_fd, path, 0);
}

int rename_file(const char *oldpath, const char *newpath, int dir_fd)
{
        return renameat(dir_fd, oldpath, dir_fd, newpath);
}

int get_current_dir_fd(void)
{
        return open_directory(".", AT_FDCWD);
}

