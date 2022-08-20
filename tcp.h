#ifndef TCP_H_SENTRY
#define TCP_H_SENTRY

struct sockaddr_in;

unsigned short get_port_number(struct sockaddr_in *addr);
const char *get_ip_address(struct sockaddr_in *addr);
const char *get_host_ip(int conn);
int tcp_create_socket(const char *ipaddr, unsigned short port);
int tcp_accept(int ls);
int tcp_connect(const char *ip, unsigned short port);
void tcp_shutdown(int sockfd);
int tcp_transmit(int conn, int fd);
int tcp_receive(int conn, int fd);

#endif /* TCP_H_SENTRY */

