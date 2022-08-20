#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

#include <sys/types.h>

const char *get_host_ip(int sockfd);
int tcp_create_socket(const char *ipaddr, unsigned short port);
int tcp_connect(const char *ipaddr, unsigned short port);
int tcp_accept(int ls, char *address, int len);
void tcp_shutdown(int sockfd);
ssize_t tcp_send(int sockfd, const char *buf, size_t len);
ssize_t tcp_recv(int sockfd, char *buf, size_t len);
int tcp_transmit(int sockfd, int fd);
int tcp_receive(int sockfd, int fd);

#endif /* TCP_H_SENTRY */

