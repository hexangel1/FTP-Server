#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include "ftp.h"
#include "tcp.h"
#include "fs.h"
#include "server.h"

const char *const ftp_greet_message = "220 Welcome!\n";
const char *const ftp_error_message = "500 Bad command\n";

static const char *const cmd_table[] = {
        "ABOR", "CDUP", "CWD",  "DELE", "EPSV",
        "HELP", "LIST", "MDTM", "MKD",  "NLST",
        "NOOP", "PASS", "PASV", "PORT", "PWD",
        "QUIT", "REIN", "RETR", "RMD",  "RNFR",
        "RNTO", "SIZE", "STOR", "SYST", "TYPE",
        "USER"
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
        ftp_req->cmd[0] = 0;
        ftp_req->arg[0] = 0;
        sscanf(cmdstring, "%7s %s", ftp_req->cmd, ftp_req->arg);
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
        }
        ptr->state = st_normal;
}

static int child_proc_tx(const char *filename, struct session *ptr)
{
        int conn, fd, res;
        conn = make_connection(ptr);
        if (conn == -1) {
                send_string(ptr, "451 Internal Server Error\n");
                return 1;
        }
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                perror("open");
                tcp_shutdown(conn);
                send_string(ptr, "550 Failed to get file\n");
                return 1;
        }
        send_string(ptr, "125 Channel open, data exchange started\n");
        res = tcp_transmit(conn, fd);
        tcp_shutdown(conn);
        close(fd);
        if (res == -1) {
                send_string(ptr, "500 File transmission failed.\n");
                return 1;
        }
        send_string(ptr, "226 File send OK.\n");
        return 0;
}

static int child_proc_rx(const char *filename, struct session *ptr)
{
        int conn, fd, res;
        conn = make_connection(ptr);
        if (conn == -1) {
                send_string(ptr, "451 Internal Server Error\n");
                return 1;
        }
        fd = open(filename, O_WRONLY | O_CREAT, 0644);
        if (fd == -1) {
                perror("open");
                tcp_shutdown(conn);
                send_string(ptr, "553 No such file or directory.\n");
                return 1;
        }
        send_string(ptr, "125 Channel open, data exchange started\n");
        res = tcp_receive(conn, fd);
        tcp_shutdown(conn);
        close(fd);
        if (res == -1) {
                send_string(ptr, "451 File transmission failed.\n");
                return 1;
        }
        send_string(ptr, "226 File send OK.\n");
        return 0;
}

static void ftp_abor(struct ftp_request *ftp_req, struct session *ptr)
{
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->txrx_pid > 0) {
                kill(ptr->txrx_pid, SIGKILL);
                ptr->txrx_pid = 0;
                send_string(ptr, "226 Closing data connection.\n");
        }
}

static void ftp_help(struct ftp_request *ftp_req, struct session *ptr)
{
        char buf[256] = "220 ";
        int used = strlen(buf);
        int i, cmd_table_size = sizeof(cmd_table) / sizeof(*cmd_table);
        for (i = 0; i < cmd_table_size; i++) {
                strcpy(buf + used, cmd_table[i]);
                used += strlen(cmd_table[i]);
                buf[used] = i == cmd_table_size - 1 ? '\n' : ' ';
                used++;
        }
        send_string(ptr, buf);
}

static void ftp_list(struct ftp_request *ftp_req, struct session *ptr)
{
        int conn, pid;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "451 Internal Server Error\n");
                return;
        }
        if (pid == 0) {
                char buf[256];
                int res, dir_fd;
                struct stat st_buf;
                struct dirent *entry;
                DIR *dp;
                conn = make_connection(ptr);
                if (conn == -1) {
                        send_string(ptr, "451 Internal Server Error\n");
                        exit(1);
                }
                dp = opendir(ftp_req->arg[0] ? ftp_req->arg : ".");
                if (!dp) {
                        send_string(ptr, "550 Failed to open directory.\n");
                        exit(1);
                }
                dir_fd = dirfd(dp);
                send_string(ptr, "150 Here comes the directory listing.\n");
                while ((entry = readdir(dp))) {
                        res = fstatat(dir_fd, entry->d_name, &st_buf, 0);
                        if (res == -1) {
                                perror("fstatat");
                                continue;
                        }
                        str_file_info(buf, sizeof(buf), &st_buf, entry->d_name);
                        tcp_send(conn, buf, strlen(buf));
                }
                tcp_shutdown(conn);
                closedir(dp);
                send_string(ptr, "226 Directory send OK.\n");
                exit(0);
        }
        ptr->txrx_pid = pid;
        transfer_mode_reset(ptr);
}

static void ftp_nlst(struct ftp_request *ftp_req, struct session *ptr)
{
        int conn, pid;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "451 Internal Server Error\n");
                return;
        }
        if (pid == 0) {
                struct dirent *entry;
                DIR *dp;
                conn = make_connection(ptr);
                if (conn == -1) {
                        send_string(ptr, "451 Internal Server Error\n");
                        exit(1);
                }
                dp = opendir(ftp_req->arg[0] ? ftp_req->arg : ".");
                if (!dp) {
                        send_string(ptr, "550 Failed to open directory.\n");
                        tcp_shutdown(conn);
                        exit(1);
                }
                send_string(ptr, "150 Here comes the directory listing.\n");
                while ((entry = readdir(dp))) {
                        tcp_send(conn, entry->d_name, strlen(entry->d_name));
                        tcp_send(conn, "\r\n", 2);
                }
                tcp_shutdown(conn);
                closedir(dp);
                send_string(ptr, "226 Directory send OK.\n");
                exit(0);
        }
        ptr->txrx_pid = pid;
        transfer_mode_reset(ptr);
}

static void ftp_noop(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "200 NOOP OK!\n");
}

static void ftp_pass(struct ftp_request *ftp_req, struct session *ptr)
{
        if (ptr->state == st_passwd) {
                ptr->state = st_normal;
                send_string(ptr, "230 Login successful\n");
        } else {
                send_string(ptr, "500 Invalid username or password\n");
        }
}

static void ftp_pasv(struct ftp_request *ftp_req, struct session *ptr)
{
        char buff[256];
        int ip[4];
        const char *host;
        unsigned short port;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        host = get_host_ip(ptr->socket_d);
        port = MIN_PORT_NUM + (rand() % (MAX_PORT_NUM - MIN_PORT_NUM + 1));
        if (ptr->sock_pasv != -1)
                tcp_shutdown(ptr->sock_pasv);
        ptr->sock_pasv = tcp_create_socket(host, port);
        sscanf(host ,"%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
        sprintf(buff, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\n",
                ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0x00FF);
        send_string(ptr, buff);
        ptr->state = st_passive;
}

static void ftp_port(struct ftp_request *ftp_req, struct session *ptr)
{
        int ip[4], port[2];
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        send_string(ptr, "227 Entering Active Mode\n");
        sscanf(ftp_req->arg ,"%d,%d,%d,%d,%d,%d",
                     &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
        sprintf(ptr->ip_actv, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        ptr->port_actv = (port[0] << 8) + port[1];
        fprintf(stderr, "%s:%d\n", ptr->ip_actv, ptr->port_actv);
        ptr->state = st_active;
}

static void ftp_quit(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "221 Goodbye!\n");
        ptr->state = st_goodbye;
}

static void ftp_retr(struct ftp_request *ftp_req, struct session *ptr)
{
        int pid, status;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        if (ptr->txrx_pid > 0) {
                send_string(ptr, "451 Wait transmission to finish\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "451 Internal Server Error\n");
                return;
        }
        if (pid == 0) {
                status = child_proc_tx(ftp_req->arg, ptr);
                exit(status);
        }
        ptr->txrx_pid = pid;
        transfer_mode_reset(ptr);
}

static void ftp_size(struct ftp_request *ftp_req, struct session *ptr)
{
        struct stat st_buf;
        char filesize[128];
        int res;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        res = stat(ftp_req->arg, &st_buf);
        if (res == -1) {
                send_string(ptr, "550 Could not get file size.\n");
                return;
        }
        snprintf(filesize, sizeof(filesize), "213 %ld\n", st_buf.st_size);
        send_string(ptr, filesize);
}

static void ftp_stor(struct ftp_request *ftp_req, struct session *ptr)
{
        int pid, status;
        if (ptr->state == st_login || ptr->state == st_passwd) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->state == st_normal) {
                send_string(ptr, "504 Please select mode with PASV or PORT\n");
                return;
        }
        if (ptr->txrx_pid > 0) {
                send_string(ptr, "451 Wait transmission to finish\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "451 Internal Server Error\n");
                return;
        }
        if (pid == 0) {
                status = child_proc_rx(ftp_req->arg, ptr);
                exit(status);
        }
        ptr->txrx_pid = pid;
        transfer_mode_reset(ptr);
}

static void ftp_syst(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "200 UNIX\n");
}

static void ftp_type(struct ftp_request *ftp_req, struct session *ptr)
{
        if (ptr->state != st_login && ptr->state != st_passwd) {
                if (ftp_req->arg[0] == 'I') {
                        send_string(ptr, "200 Switching to Binary mode.\n");
                } else if (ftp_req->arg[0] == 'A') {
                        send_string(ptr, "200 Switching to ASCII mode.\n");
                } else {
                        send_string(ptr,
                        "504 Command not implemented for that parameter.\n");
                }
        } else {
                send_string(ptr, "530 Please login with USER and PASS.\n");
        }
}

static void ftp_user(struct ftp_request *ftp_req, struct session *ptr)
{
        if (check_username(ftp_req->arg)) {
                ptr->username = strdup(ftp_req->arg);
                ptr->state = st_passwd;
                send_string(ptr, "331 Username ok, enter password\n");
        } else {
                send_string(ptr, "530 Invalid username\n");
        }
}

static void ftp_fail(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "202 Not implemented\n");
}

void execute_cmd(struct session *ptr, const char *cmdstring)
{
        static const ftp_handler handlers[] = {
                ftp_abor, ftp_fail, ftp_fail, ftp_fail, ftp_fail,
                ftp_help, ftp_list, ftp_fail, ftp_fail, ftp_nlst,
                ftp_noop, ftp_pass, ftp_pasv, ftp_port, ftp_fail,
                ftp_quit, ftp_fail, ftp_retr, ftp_fail, ftp_fail,
                ftp_fail, ftp_size, ftp_stor, ftp_syst, ftp_type,
                ftp_user
        };
        struct ftp_request ftp_req;
        parse_command(&ftp_req, cmdstring);
        if (ftp_req.cmd_idx == -1) {
                send_string(ptr, "202 Unknown command\n");
                return;
        }
        handlers[ftp_req.cmd_idx](&ftp_req, ptr);
}

