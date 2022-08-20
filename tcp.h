#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

#define INBUFSIZE 1024

enum signal_events {
        sigev_no_events = 0,
        sigev_terminate = 1,
        sigev_restart   = 2
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
        char *username;
        int logged_in;
        int mode;
        int sock_pasv;
        int tr_port;
        char tr_ip[32];
        int tr_pid;
        enum fsm_state flag;
        struct session *next;
};

struct tcp_server {
        int listen_sock;
        unsigned short port;
        char *ipaddr;
        struct session *sess;
};

const char *get_host_ip(int conn);
void send_string(struct session *ptr, const char *str);
struct tcp_server *new_tcp_server(const char *ip, unsigned short port);
int tcp_server_up(struct tcp_server *serv);
void tcp_server_down(struct tcp_server *serv);
void tcp_server_listen(struct tcp_server *serv);
int create_socket(const char *ipaddr, unsigned short port);
int accept_conn(int ls);
int create_conn(const char *ip, unsigned short port);
int tcp_transmit(int conn, int fd);
int tcp_receive(int conn, int fd);

#endif /* TCP_H_SENTRY */

