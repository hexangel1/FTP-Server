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

static void parse_command(struct ftp_request *request, const char *cmdstring)
{
        int i;
        for (i = 0; *cmdstring && !isspace(*cmdstring) && i < MAXCMDLEN; i++) {
                request->cmd[i] = *cmdstring;
                cmdstring++;
        }
        request->cmd[i] = 0;
        for (cmdstring++; *cmdstring && isspace(*cmdstring); cmdstring++)
                ;
        for (i = 0; *cmdstring && i < MAXARGLEN; cmdstring++, i++)
                request->arg[i] = *cmdstring;
        request->arg[i] = 0;
        request->cmd_idx = search_command(request->cmd);
}

static int make_connection(struct session *sess)
{
        int conn = -1;
        if (sess->state == st_passive) {
                conn = tcp_accept(sess->sock_pasv, NULL, 0);
                tcp_shutdown(sess->sock_pasv);
        } else if (sess->state == st_active) {
                conn = tcp_connect(sess->ip_actv, sess->port_actv);
        }
        return conn;
}

static void transfer_mode_reset(struct session *sess)
{
        if (sess->state == st_passive) {
                close(sess->sock_pasv);
                sess->sock_pasv = -1;
        } else if (sess->state == st_active) {
                sess->port_actv = 0;
                memset(sess->ip_actv, 0, sizeof(sess->ip_actv));
        }
        sess->state = st_normal;
}

static void run_process(ftp_routine child, struct session *sess, const char *f)
{
        int pid, code, conn;
        if (sess->txrx_pid > 0) {
                send_string(sess, "451 Wait transmission to finish.\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(sess, "451 Internal Server Error.\n");
                return;
        }
        if (pid == 0) {
                conn = make_connection(sess);
                if (conn == -1) {
                        send_string(sess, "451 Connection failed.\n");
                        exit(EXIT_FAILURE);
                }
                fchdir(sess->curr_dir);
                code = child(sess, conn, f);
                tcp_shutdown(conn);
                exit(code);
        }
        sess->txrx_pid = pid;
        transfer_mode_reset(sess);
}

static int list_directory(struct session *sess, int conn, const char *dirname)
{
        DIR *dirp;
        struct dirent *dent;
        char buf[256];
        int res, dir_fd;
        dirp = opendir(dirname);
        if (!dirp) {
                perror(dirname);
                send_string(sess, "550 Failed to open directory.\n");
                return 1;
        }
        dir_fd = dirfd(dirp);
        send_string(sess, "150 Here comes the directory listing.\n");
        while ((dent = readdir(dirp))) {
                res = str_file_info(buf, sizeof(buf), dent->d_name, dir_fd);
                if (res != -1)
                        tcp_send(conn, buf, strlen(buf));
        }
        send_string(sess, "226 Closing data connetion.\n");
        closedir(dirp);
        return 0;
}

static int nlst_directory(struct session *sess, int conn, const char *dirname)
{
        DIR *dirp;
        struct dirent *dent;
        dirp = opendir(dirname);
        if (!dirp) {
                perror(dirname);
                send_string(sess, "550 Failed to open directory.\n");
                return 1;
        }
        send_string(sess, "150 Here comes the directory listing.\n");
        while ((dent = readdir(dirp))) {
                tcp_send(conn, dent->d_name, strlen(dent->d_name));
                tcp_send(conn, "\r\n", 2);
        }
        send_string(sess, "226 Closing data connetion.\n");
        closedir(dirp);
        return 0;
}

static int file_download(struct session *sess, int conn, const char *filename)
{
        int fd, res;
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                perror(filename);
                send_string(sess, "550 Requested file not opened.\n");
                return 1;
        }
        send_string(sess, "125 Data connection opened, transfer starting.\n");
        res = tcp_transmit(conn, fd);
        close(fd);
        if (res == -1) {
                send_string(sess, "451 File transmission failed.\n");
                return 1;
        }
        send_string(sess, "226 Closing data connetion. File received OK.\n");
        return 0;
}

static int file_upload(struct session *sess, int conn, const char *filename)
{
        int fd, res;
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
                perror(filename);
                send_string(sess, "550 Requested file not opened.\n");
                return 1;
        }
        send_string(sess, "125 Data connection opened, transfer starting.\n");
        res = tcp_receive(conn, fd);
        close(fd);
        if (res == -1) {
                send_string(sess, "451 File transmission failed.\n");
                return 1;
        }
        send_string(sess, "226 Closing data connetion. File send OK.\n");
        return 0;
}

static int file_append(struct session *sess, int conn, const char *filename)
{
        int fd, res;
        fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd == -1) {
                perror(filename);
                send_string(sess, "550 Requested file not opened.\n");
                return 1;
        }
        send_string(sess, "125 Data connection opened, transfer starting.\n");
        res = tcp_receive(conn, fd);
        close(fd);
        if (res == -1) {
                send_string(sess, "451 File transmission failed.\n");
                return 1;
        }
        send_string(sess, "226 Closing data connetion. File send OK.\n");
        return 0;
}

static FTP_COMMAND_HANDLER(abor)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->txrx_pid > 0) {
                kill(sess->txrx_pid, SIGKILL);
                send_string(sess, "226 Closing data connection.\n");
        } else {
                send_string(sess, "550 No transmission running.\n");
        }
}

static FTP_COMMAND_HANDLER(allo)
{
        send_string(sess, "200 Success.\n");
}

static FTP_COMMAND_HANDLER(appe)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->state == st_normal) {
                send_string(sess, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(file_append, sess, request->arg);
}

static FTP_COMMAND_HANDLER(cdup)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = change_directory("..", sess->curr_dir);
        if (res == -1)
                send_string(sess, "550 Failed to change directory.\n");
        else
                send_string(sess, "250 Directory successfully changed.\n");
}

static FTP_COMMAND_HANDLER(cwd)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = change_directory(request->arg, sess->curr_dir);
        if (res == -1)
                send_string(sess, "550 Failed to change directory.\n");
        else
                send_string(sess, "250 Directory successfully changed.\n");
}

static FTP_COMMAND_HANDLER(dele)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = remove_file(request->arg, sess->curr_dir);
        if (res == -1) {
                perror("remove_file");
                send_string(sess, "550 File remove failed.\n");
        } else {
                send_string(sess, "250 File remove completed.\n");
        }
}

static FTP_COMMAND_HANDLER(help)
{
        int cmd_table_size = sizeof(cmd_table) / sizeof(*cmd_table);
        int i, used = 4;
        strcpy(sess->sendbuf, "220 ");
        for (i = 0; i < cmd_table_size; i++) {
                strcpy(sess->sendbuf + used, cmd_table[i]);
                used += strlen(cmd_table[i]);
                sess->sendbuf[used] = i == cmd_table_size - 1 ? '\n' : ' ';
                used++;
        }
        send_buffer(sess);
}

static FTP_COMMAND_HANDLER(list)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->state == st_normal) {
                send_string(sess, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(list_directory, sess, *request->arg ? request->arg : ".");
}

static FTP_COMMAND_HANDLER(mdtm)
{
        char buf[128];
        int res = str_modify_time(buf, 128, request->arg, sess->curr_dir);
        if (res != -1) {
                snprintf(sess->sendbuf, OUTBUFSIZE, "200 %s.\n", buf);
                send_buffer(sess);
        } else {
                send_string(sess, "550 Get modify time failed.\n");
        }
}

static FTP_COMMAND_HANDLER(mkd)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = create_directory(request->arg, sess->curr_dir);
        if (res == -1) {
                perror("create_directory");
                send_string(sess, "550 Directory create failed.\n");
        } else {
                sprintf(sess->buf, "257 %s created.\n", request->arg);
                send_buffer(sess);
        }
}

static FTP_COMMAND_HANDLER(nlst)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->state == st_normal) {
                send_string(sess, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(nlst_directory, sess, *request->arg ? request->arg : ".");
}

static FTP_COMMAND_HANDLER(noop)
{
        send_string(sess, "200 Success.\n");
}

static FTP_COMMAND_HANDLER(pass)
{
        if (sess->state == st_passwd) {
                sess->state = st_normal;
                send_string(sess, "230 User logged in, proceed.\n");
        } else {
                send_string(sess, "500 Invalid username or password.\n");
        }
}

static FTP_COMMAND_HANDLER(pasv)
{
        int ip[4];
        const char *host;
        unsigned short port;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->sock_pasv != -1)
                tcp_shutdown(sess->sock_pasv);
        host = get_host_ip(sess->socket_d);
        port = MIN_PORT_NUM + rand() % (MAX_PORT_NUM - MIN_PORT_NUM + 1);
        sess->sock_pasv = tcp_create_socket(host, port);
        sscanf(host ,"%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
        snprintf(sess->sendbuf, OUTBUFSIZE,
                 "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).\n",
                 ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xFF);
        send_buffer(sess);
        sess->state = st_passive;
}

static FTP_COMMAND_HANDLER(port)
{
        int ip[4], port[2];
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->sock_pasv != -1)
                tcp_shutdown(sess->sock_pasv);
        send_string(sess, "200 Entering Active Mode.\n");
        memset(ip, 0, sizeof(ip));
        memset(port, 0, sizeof(port));
        sscanf(request->arg ,"%d,%d,%d,%d,%d,%d",
               &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
        sprintf(sess->ip_actv, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        sess->port_actv = (port[0] << 8) + port[1];
        sess->state = st_active;
}

static FTP_COMMAND_HANDLER(pwd)
{
        int res;
        char path[256];
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = get_directory_path(path, sizeof(path), sess->curr_dir);
        if (res != -1) {
                snprintf(sess->sendbuf, OUTBUFSIZE, "200 %s\n", path);
                send_buffer(sess);
        } else {
                send_string(sess, "550 Get pwd failed.\n");
        }
}

static FTP_COMMAND_HANDLER(quit)
{
        send_string(sess, "221 Service closing control connection.\n");
        sess->state = st_goodbye;
}

static FTP_COMMAND_HANDLER(rein)
{
        int dir_fd;
        if (sess->txrx_pid > 0)
                kill(sess->txrx_pid, SIGKILL);
        if (sess->sock_pasv != -1) {
                tcp_shutdown(sess->sock_pasv);
                sess->sock_pasv = -1;
        }
        if (sess->username) {
                free(sess->username);
                sess->username = NULL;
        }
        set_token(sess, NULL);
        dir_fd = get_current_dir_fd();
        dup2(dir_fd, sess->curr_dir);
        close(dir_fd);
        sess->state = st_login;
        send_string(sess, "220 Session restarted.\n");
}

static FTP_COMMAND_HANDLER(retr)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->state == st_normal) {
                send_string(sess, "504 Please select mode with PASV or PORT\n");
                return;
        }
        run_process(file_download, sess, request->arg);
}

static FTP_COMMAND_HANDLER(rmd)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = remove_directory(request->arg, sess->curr_dir);
        if (res == -1) {
                perror("remove_directory");
                send_string(sess, "550 Directory remove failed.\n");
        } else {
                send_string(sess, "250 Directory remove completed.\n");
        }
}

static FTP_COMMAND_HANDLER(rnfr)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        send_string(sess, "350 Needs new path name\n");
        set_token(sess, request->arg);
}

static FTP_COMMAND_HANDLER(rnto)
{
        int res;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        res = rename_file(sess->token, request->arg, sess->curr_dir);
        if (res == -1) {
                perror("rename_file");
                send_string(sess, "550 Path rename failed.\n");
        } else {
                send_string(sess, "250 Path rename completed.\n");
        }
        set_token(sess, NULL);
}

static FTP_COMMAND_HANDLER(size)
{
        long size;
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        size = get_file_size(request->arg, sess->curr_dir);
        if (size == -1) {
                send_string(sess, "550 Could not get file size.\n");
        } else {
                snprintf(sess->sendbuf, OUTBUFSIZE, "213 %ld\n", size);
                send_buffer(sess);
        }
}

static FTP_COMMAND_HANDLER(stat)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (*request->arg) {
                int res, dir_fd;
                DIR *dirp;
                struct dirent *dent;
                dir_fd = open_directory(request->arg, sess->curr_dir);
                if (dir_fd == -1) {
                        send_string(sess, "550 Failed to open directory.\n");
                        return;
                }
                dirp = fdopendir(dir_fd);
                send_string(sess, "212 Here comes the directory listing.\n");
                while ((dent = readdir(dirp))) {
                        res = str_file_info(sess->sendbuf,
                                            sizeof(sess->sendbuf),
                                            dent->d_name, dir_fd);
                        if (res != -1)
                                send_buffer(sess);
                }
                send_string(sess, "226 Closing data connetion.\n");
                closedir(dirp);
        } else {
                if (sess->txrx_pid) {
                        send_string(sess, "200 Data connection established.\n");
                } else {
                        send_string(sess, "200 Ok.\n");
                }
        }
}

static FTP_COMMAND_HANDLER(stor)
{
        if (sess->state == st_login || sess->state == st_passwd) {
                send_string(sess, "530 Not logged in.\n");
                return;
        }
        if (sess->state == st_normal) {
                send_string(sess, "504 Select mode with PASV or PORT.\n");
                return;
        }
        run_process(file_upload, sess, request->arg);
}

static FTP_COMMAND_HANDLER(syst)
{
        send_string(sess, "200 UNIX\n");
}

static FTP_COMMAND_HANDLER(type)
{
        if (sess->state != st_login && sess->state != st_passwd) {
                if (request->arg[0] == 'I')
                        send_string(sess, "200 Switching to binary mode.\n");
                else if (request->arg[0] == 'A')
                        send_string(sess, "200 Switching to ASCII mode.\n");
                else
                        send_string(sess,
                        "504 Command not implemented for that parameter.\n");
        } else {
                send_string(sess, "530 Not logged in.\n");
        }
}

static FTP_COMMAND_HANDLER(user)
{
        if (check_username(request->arg)) {
                sess->username = strdup(request->arg);
                sess->state = st_passwd;
                send_string(sess, "331 User name okay, enter password.\n");
        } else {
                send_string(sess, "530 Not logged in.\n");
        }
}

static FTP_COMMAND_HANDLER(fail)
{
        send_string(sess, "502 Not implemented.\n");
}

void execute_cmd(struct session *sess, const char *cmdstring)
{
        static const ftp_handler handlers[] = {
                ftp_abor, ftp_allo, ftp_appe, ftp_cdup, ftp_cwd,
                ftp_dele, ftp_fail, ftp_help, ftp_list, ftp_mdtm,
                ftp_mkd,  ftp_nlst, ftp_noop, ftp_pass, ftp_pasv,
                ftp_port, ftp_pwd,  ftp_quit, ftp_rein, ftp_retr,
                ftp_rmd,  ftp_rnfr, ftp_rnto, ftp_size, ftp_stat,
                ftp_stor, ftp_fail, ftp_syst, ftp_type, ftp_user
        };
        struct ftp_request request;
        parse_command(&request, cmdstring);
        if (request.cmd_idx == -1) {
                send_string(sess, "202 Unknown command.\n");
                return;
        }
        handlers[request.cmd_idx](sess, &request);
}

