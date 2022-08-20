#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include "ftp.h"
#include "tcp.h"
#include "server.h"

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
        int i;
        for (i = 0; i < sizeof(cmd_table) / sizeof(*cmd_table); i++) {
                if (!strcmp(cmd_table[i], cmd_name))
                        return i;
        }
        return -1;
}

static int check_username(const char *username)
{
        int i;
        for (i = 0; i < sizeof(user_table) / sizeof(*user_table); i++) {
                if (!strcmp(user_table[i], username))
                        return 1;
        }
        return 0;
}

static void parse_command(struct ftp_request *ftp_req, const char *cmdstring)
{
        sscanf(cmdstring, "%7s %s", ftp_req->cmd, ftp_req->arg);
        ftp_req->cmd_idx = search_command(ftp_req->cmd);
}

static int child_proc_tx(const char *filename, struct session *ptr)
{
        int conn, fd, res;
        if (ptr->mode == st_server)
                conn = tcp_accept(ptr->sock_pasv);
        else
                conn = tcp_connect(ptr->tr_ip, ptr->tr_port);
        if (conn == -1) {
                send_string(ptr, "451 Internal Server Error\n");
                return 1;
        }
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                perror("open");
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
        if (ptr->mode == st_server)
                conn = tcp_accept(ptr->sock_pasv);
        else
                conn = tcp_connect(ptr->tr_ip, ptr->tr_port);
        if (conn == -1) {
                send_string(ptr, "451 Internal Server Error\n");
                return 1;
        }
        fd = open(filename, O_WRONLY | O_CREAT, 0644);
        if (fd == -1) {
                perror("open");
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
        if (!ptr->logged_in) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->txrx_pid > 0) {
                kill(ptr->txrx_pid, SIGKILL);
                ptr->txrx_pid = 0;
                send_string(ptr, "226 Closing data connection.\n");
        }
}

static void ftp_noop(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "200 NOOP OK!\n");
}

static void ftp_pass(struct ftp_request *ftp_req, struct session *ptr)
{
        if (ptr->username) {
                ptr->logged_in = 1;
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
        if (!ptr->logged_in) {
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
        ptr->mode = st_server;
}

static void ftp_port(struct ftp_request *ftp_req, struct session *ptr)
{
        int ip[4], port[2];
        if (!ptr->logged_in) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        send_string(ptr, "227 Entering Active Mode\n");
        sscanf(ftp_req->arg ,"%d,%d,%d,%d,%d,%d",
                     &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
        sprintf(ptr->tr_ip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        ptr->tr_port = (port[0] << 8) + port[1];
        fprintf(stderr, "%s:%d\n", ptr->tr_ip, ptr->tr_port);
        ptr->mode = st_client;
}

static void ftp_quit(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "221 Goodbye!\n");
        ptr->flag = st_goodbye;
}

static void ftp_retr(struct ftp_request *ftp_req, struct session *ptr)
{
        int pid, status;
        if (!ptr->logged_in) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->mode == st_normal) {
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
        if (ptr->mode == st_server) {
                close(ptr->sock_pasv);
                ptr->sock_pasv = -1;
        }
        ptr->mode = st_normal;
        ptr->txrx_pid = pid;
}

static void ftp_stor(struct ftp_request *ftp_req, struct session *ptr)
{
        int pid, status;
        if (!ptr->logged_in) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        if (ptr->mode == st_normal) {
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
        if (ptr->mode == st_server) {
                close(ptr->sock_pasv);
                ptr->sock_pasv = -1;
        }
        ptr->mode = st_normal;
        ptr->txrx_pid = pid;
}

static void ftp_syst(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "200 UNIX\n");
}

static void ftp_type(struct ftp_request *ftp_req, struct session *ptr)
{
        if (ptr->logged_in) {
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
                ftp_fail, ftp_fail, ftp_fail, ftp_fail, ftp_fail,
                ftp_noop, ftp_pass, ftp_pasv, ftp_port, ftp_fail,
                ftp_quit, ftp_fail, ftp_retr, ftp_fail, ftp_fail,
                ftp_fail, ftp_fail, ftp_stor, ftp_syst, ftp_type,
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

