#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

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
        if (!pw || !gr)
                return;
        snprintf(buf, len, "%-8s %-8s", pw->pw_name, gr->gr_name);
}

static void get_modify_time(char *buf, int len, time_t rawtime)
{
        struct tm *tmptr = localtime(&rawtime);
        strftime(buf, len, "%b %d %H:%M", tmptr);
}

void str_file_info(char *buf, int len, struct stat *st_buf, const char *name)
{
        char perms[10], mtimebuf[80], usrgrpbuf[80];
        get_permissions(perms, st_buf->st_mode & ALLPERMS);
        get_user_group(usrgrpbuf, sizeof(usrgrpbuf),
                       st_buf->st_uid, st_buf->st_gid);
        get_modify_time(mtimebuf, sizeof(mtimebuf), st_buf->st_mtime);
        snprintf(buf, len, "%c%s %4ld %s %8ld %s %s\r\n",
                 get_file_type(st_buf->st_mode), perms, st_buf->st_nlink,
                 usrgrpbuf, st_buf->st_size, mtimebuf, name);
}

