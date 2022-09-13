#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include "ftp.h"
#include "tcp.h"
#include "fs.h"
#include "server.h"

const char *const ftp_greet_message = "220 Service ready for new user.\n";
const char *const ftp_error_message = "500 Command line too long.\n";

static const char *const cmd_table[] = {
        "ABOR", "ALLO", "APPE", "CDUP", "CWD",
        "DELE", "EPSV", "HELP", "LIST", "MDTM",
        "MKD",  "NLST", "NOOP", "PASS", "PASV",
        "PORT", "PWD",  "QUIT", "REIN", "RETR",
        "RMD",  "RNFR", "RNTO", "SIZE", "STAT",
        "STOR", "STRU", "SYST", "TYPE", "USER"
};

static const char *const user_table[] = {
        "anonymous", "admin", "user", "test"
};

static int search_command(const char *cmd_name)
{
        int i, cmd_table_size = sizeof(cmd_table) / sizeof(*cmd_table);
        for (i = 0; i < cmd_table_size; i++) {
                if (!strcmp(cmd_table[i], cmd_name))
                        return i;
        }
        return -1;
}

static int check_username(const char *username)
{
        int i, user_table_size = sizeof(user_table) / sizeof(*user_table);
        for (i = 0; i < user_table_size; i++) {
                if (!strcmp(user_table[i], username))
                        return 1;
        }
        return 0;
}

static void parse_command(struct ftp_request *ftp_req, const char *cmdstring)
{
        int i;
        for (i = 0; *cmdstring && !isspace(*cmdstring) && i < MAXCMDLEN; i++) {
                ftp_req->cmd[i] = *cmdstring;
                cmdstring++;
        }
        ftp_req->cmd[i] = 0;
        for (cmdstring++; *cmdstring && isspace(*cmdstring); cmdstring++)
                ;
        for (i = 0; *cmdstring && i < MAXARGLEN; cmdstring++, i++)
                ftp_req->arg[i] = *cmdstring;
        ftp_req->arg[i] = 0;
        ftp_req->cmd_idx = search_command(ftp_req->cmd);
}

static int make_connection(struct session *ptr)
{
        int conn = -1;
        if (ptr->state == st_passive) {
                conn = tcp_accept(ptr->sock_pasv, NULL, 0);
                tcp_shutdown(ptr->sock_pasv);
        } else if (ptr->state == st_active) {
                conn = tcp_connect(ptr->ip_actv, ptr->port_actv);
        }
        return conn;
}

static void transfer_mode_reset(struct session *ptr)
{
        if (ptr->state == st_passive) {
                close(ptr->sock_pasv);
                ptr->sock_pasv = -1;
        } else if (ptr->state == st_active) {
                ptr->port_actv = 0;
                memset(ptr->ip_actv, 0, sizeof(ptr->ip_actv));
        }
        ptr->state = st_normal;
}

static void run_process(ftp_routine child, const char *f, struct session *ptr)
{
        int pid, code, conn;
        if (ptr->txrx_pid > 0) {
                send_string(ptr, "451 Wait transmission to finish.\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "451 Internal Server Error.\n");
                return;
        }
        if (pid == 0) {
                conn = make_connection(ptr);
                if (conn == -1) {
                        send_string(ptr, "451 Connection failed.\n");
                        exit(1);
                }
                fchdir(ptr->curr_dir);
                code = child(f, conn, ptr);
                exit(code);
        }
        ptr->txrx_pid = pid;
        transfer_mode_reset(ptr);
}

static int list_directory(const char *dirname, int conn, struct session *ptr)
{
        DIR *dirp;
        struct dirent *dent;
        char buf[256];
        int res, dir_fd;
        dirp = opendir(dirname);
        if (!dirp) {
                send_string(ptr, "550 Failed to open directory.\n");
                return 1;
        }
        dir_fd = dirfd(dirp);
        send_string(ptr, "150 Here comes the directory listing.\n");
        while ((dent = readdir(dirp))) {
                res = str_file_info(buf, sizeof(buf), dent->d_name, dir_fd);
                if (res != -1)
                        tcp_send(conn, buf, strlen(buf));
        }
        send_string(ptr, "226 Closing data connetion.\n");
        tcp_shutdown(conn);
        closedir(dirp);
        return 0;
}

static int nlst_directory(const char *dirname, int conn, struct session *ptr)
{
        DIR *dirp;
        struct dirent *dent;
        dirp = opendir(dirname);
        if (!dirp) {
                send_string(ptr, "550 Failed to open directory.\n");
                return 1;
        }
        send_string(ptr, "150 Here comes the directory listing.\n");
        while ((dent = readdir(dirp))) {
                tcp_send(conn, dent->d_name, strlen(dent->d_name));
                tcp_send(conn, "\r\n", 2);
        }
        send_string(ptr, "226 Closing data connetion.\n");
        tcp_shutdown(conn);
        closedir(dirp);
        return 0;
}

static int file_download(const char *filename, int conn, struct session *ptr)
{
        int fd, res;
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                perror("open");
                tcp_shutdown(conn);
                send_string(ptr, "550 Failed to get file.\n");
                return 1;
        }
        send_string(ptr, "125 Data connection opened, transfer starting.\n");
        res = tcp_transmit(conn, fd);
        tcp_shutdown(conn);
        close(fd);
        if (res == -1) {
                send_string(ptr, "451 File transmission failed.\n");
                return 1;
        }
        send_string(ptr, "226 Closing data connetion. File received OK.\n");
        return 0;
}

static int file_upload(const char *filename, int conn, struct session *ptr)
{
        int fd, res;
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
                perror("open");
                tcp_shutdown(conn);
                send_string(ptr, "553 No such file or directory.\n");
                return 1;
        }
        send_string(ptr, "125 Data connection opened, transfer starting.\n");
        res = tcp_receive(conn, fd);
        tcp_shutdown(conn);
        close(fd);
        if (res == -1) {
                send_string(ptr, "451 File transmission failed.\n");
                return 1;
        }
        send_string(ptr, "226 Closing data connetion. File send OK.\n");
        return 0;
}

static int file_append(const char *filename, int conn, struct session *ptr)
{
        int fd, res;
        fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd == -1) {
                perror("open");
                tcp_shutdown(conn);
                send_string(ptr, "553 No such file or directory.\n");
                return 1;
        }
        send_string(ptr, "125 Data connection opened, transfer starting.\n");
        res = tcp_receive(conn, fd);
        tcp_shutdown(conn);
        close(fd);
        if (res == -1) {
                send_string(ptr, "451 File transmission failed.\n");
                return 1;
        }
        send_string(ptr, "226 Closing data connetion. File send OK.\n");
        return 0;
}

static FTP_COMMAND_HANDLER(abor)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->txrx_pid > 0) {
                kill(ptr->txrx_pid, SIGKILL);
                send_string(ptr, "226 Closing data connection.\n");
        } else {
                send_string(ptr, "550 No transmission running.\n");
        }
}

static FTP_COMMAND_HANDLER(allo)
{
        send_string(ptr, "200 Success.\n");
}

static FTP_COMMAND_HANDLER(appe)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(file_append, ftp_req->arg, ptr);
}

static FTP_COMMAND_HANDLER(cdup)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = change_directory("..", ptr->curr_dir);
        if (res == -1)
                send_string(ptr, "550 Failed to change directory.\n");
        else
                send_string(ptr, "250 Directory successfully changed.\n");
}

static FTP_COMMAND_HANDLER(cwd)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = change_directory(ftp_req->arg, ptr->curr_dir);
        if (res == -1)
                send_string(ptr, "550 Failed to change directory.\n");
        else
                send_string(ptr, "250 Directory successfully changed.\n");
}

static FTP_COMMAND_HANDLER(dele)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = remove_file(ftp_req->arg, ptr->curr_dir);
        if (res == -1) {
                perror("remove_file");
                send_string(ptr, "550 File remove failed.\n");
        } else {
                send_string(ptr, "250 File remove completed.\n");
        }
}

static FTP_COMMAND_HANDLER(help)
{
        int cmd_table_size = sizeof(cmd_table) / sizeof(*cmd_table);
        int i, used = 4;
        strcpy(ptr->sendbuf, "220 ");
        for (i = 0; i < cmd_table_size; i++) {
                strcpy(ptr->sendbuf + used, cmd_table[i]);
                used += strlen(cmd_table[i]);
                ptr->sendbuf[used] = i == cmd_table_size - 1 ? '\n' : ' ';
                used++;
        }
        send_buffer(ptr);
}

static FTP_COMMAND_HANDLER(list)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(list_directory, *ftp_req->arg ? ftp_req->arg : ".", ptr);
}

static FTP_COMMAND_HANDLER(mdtm)
{
        char buf[128];
        int res = str_modify_time(buf, 128, ftp_req->arg, ptr->curr_dir);
        if (res != -1) {
                snprintf(ptr->sendbuf, OUTBUFSIZE, "200 %s.\n", buf);
                send_buffer(ptr);
        } else {
                send_string(ptr, "550 Get modify time failed.\n");
        }
}

static FTP_COMMAND_HANDLER(mkd)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = create_directory(ftp_req->arg, ptr->curr_dir);
        if (res == -1) {
                perror("create_directory");
                send_string(ptr, "550 Directory create failed.\n");
        } else {
                sprintf(ptr->buf, "257 %s created.\n", ftp_req->arg);
                send_buffer(ptr);
        }
}

static FTP_COMMAND_HANDLER(nlst)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(nlst_directory, *ftp_req->arg ? ftp_req->arg : ".", ptr);
}

static FTP_COMMAND_HANDLER(noop)
{
        send_string(ptr, "200 Success.\n");
}

static FTP_COMMAND_HANDLER(pass)
{
        if (ptr->state == st_passwd) {
                ptr->state = st_normal;
                send_string(ptr, "230 User logged in, proceed.\n");
        } else {
                send_string(ptr, "500 Invalid username or password.\n");
        }
}

static FTP_COMMAND_HANDLER(pasv)
{
        int ip[4];
        const char *host;
        unsigned short port;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->sock_pasv != -1)
                tcp_shutdown(ptr->sock_pasv);
        host = get_host_ip(ptr->socket_d);
        port = MIN_PORT_NUM + rand() % (MAX_PORT_NUM - MIN_PORT_NUM + 1);
        ptr->sock_pasv = tcp_create_socket(host, port);
        sscanf(host ,"%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
        snprintf(ptr->sendbuf, OUTBUFSIZE,
                 "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).\n",
                 ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xFF);
        send_buffer(ptr);
        ptr->state = st_passive;
}

static FTP_COMMAND_HANDLER(port)
{
        int ip[4], port[2];
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->sock_pasv != -1)
                tcp_shutdown(ptr->sock_pasv);
        send_string(ptr, "200 Entering Active Mode.\n");
        memset(ip, 0, sizeof(ip));
        memset(port, 0, sizeof(port));
        sscanf(ftp_req->arg ,"%d,%d,%d,%d,%d,%d",
               &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
        sprintf(ptr->ip_actv, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        ptr->port_actv = (port[0] << 8) + port[1];
        ptr->state = st_active;
}

static FTP_COMMAND_HANDLER(pwd)
{
        int res;
        char path[256];
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = get_directory_path(path, sizeof(path), ptr->curr_dir);
        if (res != -1) {
                snprintf(ptr->sendbuf, OUTBUFSIZE, "200 %s\n", path);
                send_buffer(ptr);
        } else {
                send_string(ptr, "550 Get pwd failed.\n");
        }
}

static FTP_COMMAND_HANDLER(quit)
{
        send_string(ptr, "221 Service closing control connection.\n");
        ptr->state = st_goodbye;
}

static FTP_COMMAND_HANDLER(rein)
{
        int dir_fd;
        if (ptr->txrx_pid > 0)
                kill(ptr->txrx_pid, SIGKILL);
        if (ptr->sock_pasv != -1) {
                tcp_shutdown(ptr->sock_pasv);
                ptr->sock_pasv = -1;
        }
        if (ptr->username) {
                free(ptr->username);
                ptr->username = NULL;
        }
        set_token(ptr, NULL);
        dir_fd = get_current_dir_fd();
        dup2(dir_fd, ptr->curr_dir);
        close(dir_fd);
        ptr->state = st_login;
        send_string(ptr, "220 Session restarted.\n");
}

static FTP_COMMAND_HANDLER(retr)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(file_download, ftp_req->arg, ptr);
}

static FTP_COMMAND_HANDLER(rmd)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = remove_directory(ftp_req->arg, ptr->curr_dir);
        if (res == -1) {
                perror("remove_directory");
                send_string(ptr, "550 Directory remove failed.\n");
        } else {
                send_string(ptr, "250 Directory remove completed.\n");
        }
}

static FTP_COMMAND_HANDLER(rnfr)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        send_string(ptr, "350 Needs new path name\n");
        set_token(ptr, ftp_req->arg);
}

static FTP_COMMAND_HANDLER(rnto)
{
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        res = rename_file(ptr->token, ftp_req->arg, ptr->curr_dir);
        if (res == -1) {
                perror("rename_file");
                send_string(ptr, "550 Path rename failed.\n");
        } else {
                send_string(ptr, "250 Path rename completed.\n");
        }
        set_token(ptr, NULL);
}

static FTP_COMMAND_HANDLER(size)
{
        long size;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        size = get_file_size(ftp_req->arg, ptr->curr_dir);
        if (size == -1) {
                send_string(ptr, "550 Could not get file size.\n");
        } else {
                snprintf(ptr->sendbuf, OUTBUFSIZE, "213 %ld\n", size);
                send_buffer(ptr);
        }
}

static FTP_COMMAND_HANDLER(stat)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (*ftp_req->arg) {
                int res, dir_fd;
                DIR *dirp;
                struct dirent *dent;
                dir_fd = open_directory(ftp_req->arg, ptr->curr_dir);
                if (dir_fd == -1) {
                        send_string(ptr, "550 Failed to open directory.\n");
                        return;
                }
                dirp = fdopendir(dir_fd);
                send_string(ptr, "212 Here comes the directory listing.\n");
                while ((dent = readdir(dirp))) {
                        res = str_file_info(ptr->sendbuf, sizeof(ptr->sendbuf),
                                            dent->d_name, dir_fd);
                        if (res != -1)
                                send_buffer(ptr);
                }
                send_string(ptr, "226 Closing data connetion.\n");
                closedir(dirp);
        } else {
                if (ptr->txrx_pid) {
                        send_string(ptr, "200 Data connection established.\n");
                } else {
                        send_string(ptr, "200 Ok.\n");
                }
        }
}

static FTP_COMMAND_HANDLER(stor)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Not logged in.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT.\n");
                return;
        }
        run_process(file_upload, ftp_req->arg, ptr);
}

static FTP_COMMAND_HANDLER(syst)
{
        send_string(ptr, "200 UNIX\n");
}

static FTP_COMMAND_HANDLER(type)
{
        if (ptr->state != st_login && ptr->state != st_passwd) {
                if (ftp_req->arg[0] == 'I')
                        send_string(ptr, "200 Switching to binary mode.\n");
                else if (ftp_req->arg[0] == 'A')
                        send_string(ptr, "200 Switching to ASCII mode.\n");
                else
                        send_string(ptr,
                        "504 Command not implemented for that parameter.\n");
        } else {
                send_string(ptr, "530 Not logged in.\n");
        }
}

static FTP_COMMAND_HANDLER(user)
{
        if (check_username(ftp_req->arg)) {
                ptr->username = strdup(ftp_req->arg);
                ptr->state = st_passwd;
                send_string(ptr, "331 User name okay, enter password.\n");
        } else {
                send_string(ptr, "530 Not logged in.\n");
        }
}

static FTP_COMMAND_HANDLER(fail)
{
        send_string(ptr, "502 Not implemented.\n");
}

void execute_cmd(struct session *ptr, const char *cmdstring)
{
        static const ftp_handler handlers[] = {
                ftp_abor, ftp_allo, ftp_appe, ftp_cdup, ftp_cwd,
                ftp_dele, ftp_fail, ftp_help, ftp_list, ftp_mdtm,
                ftp_mkd,  ftp_nlst, ftp_noop, ftp_pass, ftp_pasv,
                ftp_port, ftp_pwd,  ftp_quit, ftp_rein, ftp_retr,
                ftp_rmd,  ftp_rnfr, ftp_rnto, ftp_size, ftp_stat,
                ftp_stor, ftp_fail, ftp_syst, ftp_type, ftp_user
        };
        struct ftp_request ftp_req;
        parse_command(&ftp_req, cmdstring);
        if (ftp_req.cmd_idx == -1) {
                send_string(ptr, "202 Unknown command.\n");
                return;
        }
        handlers[ftp_req.cmd_idx](&ftp_req, ptr);
}

