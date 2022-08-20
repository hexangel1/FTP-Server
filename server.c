#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include "server.h"
#include "tcp.h"
#include "ftp.h"

static volatile sig_atomic_t sig_event_flag = sigev_no_events;

static void signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGUSR1)
                sig_event_flag = sigev_terminate;
        else if (signum == SIGUSR2)
                sig_event_flag = sigev_restart;
        else if (signum == SIGCHLD)
                sig_event_flag = sigev_childexit;
}

static void create_session(struct session **sess, int fd)
{
        struct session *tmp = malloc(sizeof(*tmp));
        tmp->socket_d = fd;
        tmp->buf_used = 0;
        tmp->username = 0;
        tmp->logged_in = 0;
        tmp->mode = 0;
        tmp->sock_pasv = -1;
        tmp->txrx_pid = 0;
        tmp->flag = st_normal;
        tmp->next = *sess;
        *sess = tmp;
        send_string(tmp, FTP_GREET_MESSAGE);
}

static void delete_session(struct session *sess)
{
        tcp_shutdown(sess->socket_d);
        if (sess->sock_pasv != -1)
                tcp_shutdown(sess->sock_pasv);
        if (sess->txrx_pid > 0)
                kill(sess->txrx_pid, SIGKILL);
        if (sess->username)
                free(sess->username);
        free(sess);
}

static void delete_sessions(struct session **sess)
{
        struct session *tmp;
        while (*sess) {
                if ((*sess)->flag == st_goodbye) {
                        tmp = *sess;
                        *sess = (*sess)->next;
                        delete_session(tmp);
                } else {
                        sess = &(*sess)->next;
                }
        }
}

static void delete_session_list(struct session *sess)
{
        struct session *tmp;
        while (sess) {
                tmp = sess;
                sess = sess->next;
                delete_session(tmp);
        }
}

static void remove_zombies(struct session *sess)
{
        int pid, res;
        struct session *tmp;
        while ((pid = wait4(-1, &res, WNOHANG, NULL)) > 0) {
                if (!WIFEXITED(res) && !WIFSIGNALED(res))
                        continue;
                if ((WIFEXITED(res) && WEXITSTATUS(res)) || WIFSIGNALED(res))
                        fprintf(stderr, "[%d] Transmission failed\n", pid);
                else
                        fprintf(stderr, "[%d] Transmission success\n", pid);
                for (tmp = sess; tmp; tmp = tmp->next) {
                        if (tmp->txrx_pid == pid) {
                                tmp->txrx_pid = 0;
                                break;
                        }
                }
        }
}

static void check_lf(struct session *ptr, struct tcp_server *serv)
{
        int pos, i;
        char *str;
        for (;;) {
                pos = -1;
                for (i = 0; i < ptr->buf_used; i++) {
                        if (ptr->buf[i] == '\n') {
                                pos = i;
                                break;
                        }
                }
                if (pos == -1)
                        return;
                str = malloc(pos + 1);
                memcpy(str, ptr->buf, pos);
                str[pos] = '\0';
                ptr->buf_used -= pos + 1;
                memmove(ptr->buf, ptr->buf + pos + 1, ptr->buf_used);
                if (pos && str[pos - 1] == '\r')
                        str[pos - 1] = '\0';
                fprintf(stderr, "%s\n", str);
                execute_cmd(ptr, str);
                free(str);
        }
}

static void read_data(struct session *ptr, struct tcp_server *serv)
{
        int rc, busy = ptr->buf_used;
        rc = read(ptr->socket_d, ptr->buf + busy, INBUFSIZE - busy);
        if (rc <= 0) {
                ptr->flag = st_goodbye;
                return;
        }
        ptr->buf_used += rc;
        check_lf(ptr, serv);
        if (ptr->buf_used >= INBUFSIZE) {
                send_string(ptr, FTP_ERROR_MESSAGE);
                ptr->buf_used = 0;
        }
}

static void set_sigactions(sigset_t *orig_mask)
{
        struct sigaction sa;
        sigset_t mask;
        sa.sa_handler = SIG_IGN;
        sigfillset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);
        sa.sa_handler = &signal_handler;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        sa.sa_flags = SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa, NULL);
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, orig_mask);
}

static int handle_signal_event(struct tcp_server *serv)
{
        enum signal_event event = sig_event_flag;
        sig_event_flag = sigev_no_events;
        switch (event) {
        case sigev_terminate:
                delete_session_list(serv->sess);
                return 1;
        case sigev_restart:
                delete_session_list(serv->sess);
                serv->sess = NULL;
                return 0;
        case sigev_childexit:
                remove_zombies(serv->sess);
                return 0;
        case sigev_no_events:
                ;
        }
        return 0;
}

static void accept_connection(struct tcp_server *serv)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        int sockfd;
        sockfd = accept(serv->listen_sock, (struct sockaddr *)&addr, &addrlen);
        if (sockfd == -1) {
                if (errno != EINTR)
                        perror("accept");
        } else {
                fprintf(stderr, "connection from %s:%u\n",
                        get_ip_address(&addr), get_port_number(&addr));
                create_session(&serv->sess, sockfd);
        }
}

void tcp_server_listen(struct tcp_server *serv)
{
        struct session *tmp;
        int res, max_d;
        fd_set readfds;
        sigset_t mask;
        set_sigactions(&mask);
        for (;;) {
                FD_ZERO(&readfds);
                FD_SET(serv->listen_sock, &readfds);
                max_d = serv->listen_sock;
                for (tmp = serv->sess; tmp; tmp = tmp->next) {
                        FD_SET(tmp->socket_d, &readfds);
                        if (tmp->socket_d > max_d)
                                max_d = tmp->socket_d;
                }
                res = pselect(max_d + 1, &readfds, NULL, NULL, NULL, &mask);
                if (res == -1 && errno != EINTR) {
                        perror("pselect");
                        break;
                }
                if (res == -1) {
                        res = handle_signal_event(serv);
                        if (res)
                                break;
                        continue;
                }
                if (FD_ISSET(serv->listen_sock, &readfds))
                        accept_connection(serv);
                for (tmp = serv->sess; tmp; tmp = tmp->next) {
                        if (FD_ISSET(tmp->socket_d, &readfds))
                                read_data(tmp, serv);
                }
                delete_sessions(&serv->sess);
        }
}

struct tcp_server *new_tcp_server(const char *ip, unsigned short port)
{
        struct tcp_server *serv = malloc(sizeof(*serv));
        serv->listen_sock = -1;
        serv->port = port;
        serv->ipaddr = strdup(ip);
        serv->sess = NULL;
        return serv;
}

int tcp_server_up(struct tcp_server *serv)
{
        srand(time(NULL));
        serv->listen_sock = tcp_create_socket(serv->ipaddr, serv->port);
        if (serv->listen_sock == -1)
                return -1;
        return 0;
}

void tcp_server_down(struct tcp_server *serv)
{
        if (serv->listen_sock != -1)
                tcp_shutdown(serv->listen_sock);
        free(serv->ipaddr);
        free(serv);
}

void send_string(struct session *ptr, const char *str)
{
        write(ptr->socket_d, str, strlen(str));
}

