#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#include <signal.h>

#define INBUFSIZE 1024
#define OUTBUFSIZE 512
#define ADDRESS_LEN 32

enum signal_event {
        sigev_no_events,
        sigev_childexit,
        sigev_restart,
        sigev_terminate
};

enum fsm_state {
        st_login,
        st_passwd,
        st_normal,
        st_active,
        st_passive,
        st_goodbye
};

struct session {
        int fds_idx;
        int socket_d;
        int buf_used;
        char buf[INBUFSIZE];
        char sendbuf[OUTBUFSIZE];
        char address[ADDRESS_LEN];
        char *username;
        char *token;
        int curr_dir;
        int sock_pasv;
        int port_actv;
        char ip_actv[32];
        int txrx_pid;
        enum fsm_state state;
        struct session *next;
};

struct tcp_server {
        int listen_sock;
        unsigned short port;
        char *ipaddr;
        sigset_t sigmask;
        int nfds;
        struct pollfd *fds;
        struct session *sess;
};

/* handles signals, listening socket and client connections */
void tcp_server_handle(struct tcp_server *serv);

/* starts tcp server */
int tcp_server_up(struct tcp_server *serv);

/* stops tcp server */
void tcp_server_down(struct tcp_server *serv);

/* creates new tcp server */
struct tcp_server *new_tcp_server(const char *ip, unsigned short port);

/* sets token to session */
void set_token(struct session *ptr, const char *str);

/* sends string to session */
void send_string(struct session *ptr, const char *str);

/* sends accumulated buffer to session */
void send_buffer(struct session *ptr);

#endif /* SERVER_H_SENTRY */

