#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#define INBUFSIZE 1024
#define ADDRESS_LEN 32

enum signal_event {
        sigev_no_events,
        sigev_terminate,
        sigev_restart,
        sigev_childexit
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
        int socket_d;
        int buf_used;
        char buf[INBUFSIZE];
        char address[ADDRESS_LEN];
        char *username;
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
        struct session *sess;
};

void tcp_server_handle(struct tcp_server *serv);
int tcp_server_up(struct tcp_server *serv);
void tcp_server_down(struct tcp_server *serv);
struct tcp_server *new_tcp_server(const char *ip, unsigned short port);
void send_string(struct session *ptr, const char *str);

#endif /* SERVER_H_SENTRY */

