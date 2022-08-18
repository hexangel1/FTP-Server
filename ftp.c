#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include "ftp.h"
#include "tcp.h"

static const char *const cmd_table[] = {
        "ABOR", "CDUP", "CWD",  "DELE", "EPSV",
        "HELP", "LIST", "MDTM", "MKD",  "NLST",
        "NOOP", "PASS", "PASV", "PORT", "PWD",
        "QUIT", "REIN", "RETR", "RMD",  "RNFR",
        "RNTO", "SIZE", "STOR", "SYST", "TYPE",
        "USER"
};

static const char *const user_table[] = {
        "anonymous", "admin"
};

static enum ftp_command search_command(const char *cmd_name)
{
        int i;
        for (i = 0; i < sizeof(cmd_table) / sizeof(*cmd_table); i++) {
                if (!strcmp(cmd_table[i], cmd_name))
                        return i;
        }
        return INVALID_CMD;
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

static struct ftp_request *parse_command(const char *cmdstring)
{
        char cmd_name[8];
        struct ftp_request *ftp_req = malloc(sizeof(*ftp_req));
        sscanf(cmdstring, "%7s %s", cmd_name, ftp_req->arg);
        ftp_req->cmd = search_command(cmd_name);
        return ftp_req;
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
        if (ptr->sock_pasv != -1) {
                shutdown(ptr->sock_pasv, 2);
                close(ptr->sock_pasv);
        }
        ptr->sock_pasv = create_socket(host, port); 
        sscanf(host ,"%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]); 
        sprintf(buff, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\n",
                ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0x00FF);
        send_string(ptr, buff);
        ptr->mode = st_server;
}

static void ftp_quit(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "221 Goodbye!\n");
        ptr->flag = st_goodbye;
}

static void ftp_retr(struct ftp_request *ftp_req, struct session *ptr)
{
        int pid;
        if (!ptr->logged_in) {
                send_string(ptr, "530 Please login with USER and PASS.\n");
                return;
        }
        pid = fork();
        if (pid == -1) {
                perror("fork");
                send_string(ptr, "500 Internal Server Error\n");
                return;
        }
        if (pid == 0) {
                int conn, fd;
                struct stat stat_buf;
                send_string(ptr, "150 Opening BINARY mode data connection.\n");
                conn = accept_conn(ptr->sock_pasv);
                if (conn == -1) {
                        perror("accept");
                        send_string(ptr, "500 Internal Server Error\n");
                        exit(1);
                }
                fd = open(ftp_req->arg, O_RDONLY);
                if (fd == -1) {
                        perror("open");
                        send_string(ptr, "550 Failed to get file\n");
                        exit(1);
                }
                fstat(fd, &stat_buf); 
                sendfile(conn, fd, NULL, stat_buf.st_size);
                shutdown(conn, 2);
                close(conn);
                close(fd);
                send_string(ptr, "226 File send OK.\n");
                exit(0);
        }
        ptr->mode = st_normal;
        ptr->tr_pid = pid;
        close(ptr->sock_pasv);
}

static void ftp_syst(struct ftp_request *ftp_req, struct session *ptr)
{
        send_string(ptr, "200 *nix\n");
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

void execute_cmd(struct session *ptr, const char *cmdstring)
{
        struct ftp_request *ftp_req = parse_command(cmdstring);
        switch (ftp_req->cmd) {
        case NOOP:
                ftp_noop(ftp_req, ptr);
                break;
        case PASS:
                ftp_pass(ftp_req, ptr);
                break;
        case PASV:
                ftp_pasv(ftp_req, ptr);
                break;
        case QUIT:
                ftp_quit(ftp_req, ptr);
                break;
        case RETR:
                ftp_retr(ftp_req, ptr);
                break;
        case SYST:
                ftp_syst(ftp_req, ptr);
                break;
        case TYPE:
                ftp_type(ftp_req, ptr);
                break;
        case USER:
                ftp_user(ftp_req, ptr);
                break;
        case INVALID_CMD:
                send_string(ptr, "500 Unknown command\n");
                break;
        default:
                send_string(ptr, "500 Not implemented\n");
        }
        free(ftp_req);
}

