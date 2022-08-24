#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

#include <sys/types.h>

/* returns host ip address */
const char *get_host_ip(int sockfd);

/* creates listening socket */
int tcp_create_socket(const char *ipaddr, unsigned short port);

/* makes connection to server */
int tcp_connect(const char *ipaddr, unsigned short port);

/* accepts connection on listening socket ls */
int tcp_accept(int ls, char *address, int len);

/* shutdown connection */
void tcp_shutdown(int sockfd);

/* writes data from buf to sockfd*/
ssize_t tcp_send(int sockfd, const char *buf, size_t len);

/* reads data from sockfd to buf */
ssize_t tcp_recv(int sockfd, char *buf, size_t len);

/* reads data from file associated with fd and writes to sockfd */
int tcp_transmit(int sockfd, int fd);

/* reads data from sockfd and writes to file associated with fd */
int tcp_receive(int sockfd, int fd);

#endif /* TCP_H_SENTRY */

