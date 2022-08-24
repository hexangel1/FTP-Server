#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

#include <sys/types.h>

/* returns hosts ip address */
const char *get_host_ip(int sockfd);

/* creates listening socket */
int tcp_create_socket(const char *ipaddr, unsigned short port);

/* connects to host ipaddr:port */
int tcp_connect(const char *ipaddr, unsigned short port);

/* accepts connection on listen socket ls */
int tcp_accept(int ls, char *address, int len);

/* shutdowns connection */
void tcp_shutdown(int sockfd);

/* writes from sockfd to buf */
ssize_t tcp_send(int sockfd, const char *buf, size_t len);

/* reads from sockfd to buf */
ssize_t tcp_recv(int sockfd, char *buf, size_t len);

/* transmits data from fd and writes to sockfd */
int tcp_transmit(int sockfd, int fd);

/* receives data from sockfd and writes to fd */
int tcp_receive(int sockfd, int fd);

#endif /* TCP_H_SENTRY */

