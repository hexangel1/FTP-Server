#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include "server.h"
#include "ftp.h"
#include "tcp.h"
#include "fs.h"

int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *tmo_p, const sigset_t *sigmask);

static volatile sig_atomic_t sig_event_flag = sigev_no_events;

static void signal_handler(int signum)
{
        if (signum == SIGCHLD)
                sig_event_flag = sigev_childexit;
        else if (signum == SIGUSR1 || signum == SIGHUP)
                sig_event_flag = sigev_restart;
        else if (signum == SIGUSR2 || signum == SIGTERM)
                sig_event_flag = sigev_terminate;
}

static struct session *create_session(int idx, int fd, const char *addr)
{
        struct session *ptr = malloc(sizeof(*ptr));
        ptr->fds_idx = idx;
        ptr->socket_d = fd;
        ptr->buf_used = 0;
        strncpy(ptr->address, addr, sizeof(ptr->address));
        ptr->username = 0;
        ptr->token = 0;
        ptr->curr_dir = get_current_dir_fd();
        ptr->sock_pasv = -1;
        ptr->port_actv = 0;
        memset(ptr->ip_actv, 0, sizeof(ptr->ip_actv));
        ptr->txrx_pid = 0;
        ptr->state = st_login;
        send_string(ptr, ftp_greet_message);
        return ptr;
}

static void delete_session(struct session *ptr)
{
        close(ptr->curr_dir);
        tcp_shutdown(ptr->socket_d);
        if (ptr->sock_pasv != -1)
                tcp_shutdown(ptr->sock_pasv);
        if (ptr->txrx_pid > 0)
                kill(ptr->txrx_pid, SIGKILL);
        if (ptr->username)
                free(ptr->username);
        if (ptr->token)
                free(ptr->token);
        free(ptr);
}

static void stop_poll_fd(struct tcp_server *serv, int idx)
{
        serv->fds[idx].fd = -1;
        serv->fds[idx].events = 0;
        serv->fds[idx].revents = 0;
}

static int start_poll_fd(struct tcp_server *serv, int sockfd)
{
        int old_size, i;
        for (i = 0; i < serv->nfds; i++) {
                if (serv->fds[i].fd == -1) {
                        serv->fds[i].fd = sockfd;
                        serv->fds[i].events = POLLIN;
                        return i;
                }
        }
        old_size = serv->nfds;
        serv->nfds = old_size ? old_size << 1 : 4;
        serv->fds = realloc(serv->fds, serv->nfds * sizeof(*serv->fds));
        for (i = old_size; i < serv->nfds; i++)
                stop_poll_fd(serv, i);
        serv->fds[old_size].fd = sockfd;
        serv->fds[old_size].events = POLLIN;
        return old_size;
}

static void register_sigactions(struct tcp_server *serv)
{
        struct sigaction sa;
        sigset_t mask;
        sa.sa_handler = SIG_IGN;
        sigfillset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);
        sa.sa_handler = signal_handler;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        sa.sa_flags = SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa, NULL);
        sigemptyset(&mask);
        sigaddset(&mask, SIGHUP);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, &serv->sigmask);
}

static void delete_all_sessions(struct tcp_server *serv)
{
        struct session *tmp;
        while (serv->sess) {
                tmp = serv->sess;
                serv->sess = serv->sess->next;
                delete_session(tmp);
        }
}

static void delete_finished_sessions(struct tcp_server *serv)
{
        struct session **sess = &serv->sess;
        while (*sess) {
                if ((*sess)->state == st_goodbye) {
                        struct session *tmp = *sess;
                        *sess = (*sess)->next;
                        stop_poll_fd(serv, tmp->fds_idx);
                        delete_session(tmp);
                } else {
                        sess = &(*sess)->next;
                }
        }
}

static void remove_zombies(struct tcp_server *serv)
{
        int pid, res;
        struct session *tmp;
        while ((pid = waitpid(-1, &res, WNOHANG)) > 0) {
                if (!WIFEXITED(res) && !WIFSIGNALED(res))
                        continue;
                if ((WIFEXITED(res) && WEXITSTATUS(res)) || WIFSIGNALED(res))
                        fprintf(stderr, "[%d] Transmission failed\n", pid);
                else
                        fprintf(stderr, "[%d] Transmission success\n", pid);
                for (tmp = serv->sess; tmp; tmp = tmp->next) {
                        if (tmp->txrx_pid == pid) {
                                tmp->txrx_pid = 0;
                                break;
                        }
                }
        }
}

static void check_lf(struct session *ptr)
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
                str[pos] = 0;
                ptr->buf_used -= pos + 1;
                memmove(ptr->buf, ptr->buf + pos + 1, ptr->buf_used);
                if (pos && str[pos - 1] == '\r')
                        str[pos - 1] = 0;
                fprintf(stderr, "%s\n", str);
                execute_cmd(ptr, str);
                free(str);
        }
}

static void receive_data(struct tcp_server *serv, struct session *ptr)
{
        int rc, busy = ptr->buf_used;
        rc = tcp_recv(ptr->socket_d, ptr->buf + busy, INBUFSIZE - busy);
        if (rc <= 0) {
                ptr->state = st_goodbye;
                return;
        }
        ptr->buf_used += rc;
        check_lf(ptr);
        if (ptr->buf_used >= INBUFSIZE) {
                send_string(ptr, ftp_error_message);
                ptr->buf_used = 0;
        }
}

static void accept_connection(struct tcp_server *serv)
{
        int idx, sockfd;
        char address[ADDRESS_LEN];
        struct session *tmp;
        sockfd = tcp_accept(serv->listen_sock, address, sizeof(address));
        if (sockfd != -1) {
                idx = start_poll_fd(serv, sockfd);
                tmp = create_session(idx, sockfd, address);
                tmp->next = serv->sess;
                serv->sess = tmp;
                fprintf(stderr, "connection from %s\n", address);
        }
}

static int handle_signal_event(struct tcp_server *serv)
{
        enum signal_event event = sig_event_flag;
        sig_event_flag = sigev_no_events;
        switch (event) {
        case sigev_childexit:
                remove_zombies(serv);
                return 0;
        case sigev_restart:
                delete_all_sessions(serv);
                free(serv->fds);
                serv->fds = NULL;
                serv->nfds = 0;
                start_poll_fd(serv, serv->listen_sock);
                return 0;
        case sigev_terminate:
                delete_all_sessions(serv);
                free(serv->fds);
                return 1;
        case sigev_no_events:
                ;
        }
        return 0;
}

void tcp_server_handle(struct tcp_server *serv)
{
        struct session *tmp;
        register_sigactions(serv);
        start_poll_fd(serv, serv->listen_sock);
        for (;;) {
                int res = ppoll(serv->fds, serv->nfds, NULL, &serv->sigmask);
                if (res == -1 && errno != EINTR) {
                        perror("ppoll");
                        break;
                }
                if (res == -1) {
                        res = handle_signal_event(serv);
                        if (res)
                                break;
                        continue;
                }
                if (serv->fds[0].revents & POLLIN) {
                        accept_connection(serv);
                        serv->fds[0].revents = 0;
                }
                for (tmp = serv->sess; tmp; tmp = tmp->next) {
                        if (serv->fds[tmp->fds_idx].revents & POLLIN) {
                                receive_data(serv, tmp);
                                serv->fds[tmp->fds_idx].revents = 0;
                        }
                }
                delete_finished_sessions(serv);
        }
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

struct tcp_server *new_tcp_server(const char *ip, unsigned short port)
{
        struct tcp_server *serv = malloc(sizeof(*serv));
        serv->listen_sock = -1;
        serv->port = port;
        serv->ipaddr = strdup(ip);
        sigfillset(&serv->sigmask);
        serv->nfds = 0;
        serv->fds = NULL;
        serv->sess = NULL;
        return serv;
}

void set_token(struct session *ptr, const char *str)
{
        if (ptr->token)
                free(ptr->token);
        ptr->token = str ? strdup(str) : NULL;
}

void send_string(struct session *ptr, const char *str)
{
        tcp_send(ptr->socket_d, str, strlen(str));
}

void send_buffer(struct session *ptr)
{
        tcp_send(ptr->socket_d, ptr->sendbuf, strlen(ptr->sendbuf));
}

