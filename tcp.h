#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

#include <sys/types.h>

const char *get_host_ip(int conn);
int tcp_create_socket(const char *ipaddr, unsigned short port);
int tcp_accept(int ls, char *address, int len);
int tcp_connect(const char *ip, unsigned short port);
void tcp_shutdown(int conn);
ssize_t tcp_recv(int conn, char *buf, size_t len);
ssize_t tcp_send(int conn, const char *buf, size_t len);
int tcp_transmit(int conn, int fd);
int tcp_receive(int conn, int fd);

#endif /* TCP_H_SENTRY */

