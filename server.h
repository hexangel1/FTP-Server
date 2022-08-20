#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#define INBUFSIZE 1024
#define ADDRESS_LEN 32

enum signal_event {
        sigev_no_events = 0,
        sigev_terminate = 1,
        sigev_restart   = 2,
        sigev_childexit = 3
};

enum fsm_state {
        st_normal,
        st_client,
        st_server,
        st_goodbye
};

struct session {
        int socket_d;
        int buf_used;
        char buf[INBUFSIZE];
        char address[ADDRESS_LEN];
        char *username;
        int logged_in;
        int mode;
        int sock_pasv;
        int tr_port;
        char tr_ip[32];
        int txrx_pid;
        enum fsm_state flag;
        struct session *next;
};

struct tcp_server {
        int listen_sock;
        unsigned short port;
        char *ipaddr;
        struct session *sess;
};

struct tcp_server *new_tcp_server(const char *ip, unsigned short port);
int tcp_server_up(struct tcp_server *serv);
void tcp_server_down(struct tcp_server *serv);
void tcp_server_listen(struct tcp_server *serv);
void send_string(struct session *ptr, const char *str);

#endif /* SERVER_H_SENTRY */

