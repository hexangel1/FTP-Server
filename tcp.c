#ifdef BUILD_FOR_LINUX
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/sendfile.h>
#undef  _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "tcp.h"

static const char *get_ip_address(struct sockaddr_in *addr)
{
        return inet_ntoa(addr->sin_addr);
}

static unsigned short get_port(struct sockaddr_in *addr)
{
        return ntohs(addr->sin_port);
}

const char *get_host_ip(int sockfd)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
        return get_ip_address(&addr);
}

const char *get_peer_ip(int sockfd)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        getpeername(sockfd, (struct sockaddr *)&addr, &addrlen);
        return get_ip_address(&addr);
}

unsigned short get_host_port(int sockfd)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
        return get_port(&addr);
}

unsigned short get_peer_port(int sockfd)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        getpeername(sockfd, (struct sockaddr *)&addr, &addrlen);
        return get_port(&addr);
}

int tcp_create_socket(const char *ipaddr, unsigned short port)
{
        int ls, res, opt = 1;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ipaddr);
        ls = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (ls == -1) {
                perror("socket");
                return -1;
        }
        res = setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (res == -1) {
                perror("setsockopt");
                return -1;
        }
        res = bind(ls, (struct sockaddr *)&addr, sizeof(addr));
        if (res == -1) {
                perror("bind");
                return -1;
        }
        res = listen(ls, 5);
        if (res == -1) {
                perror("listen");
                return -1;
        }
        return ls;
}

int tcp_connect(const char *ipaddr, unsigned short port)
{
        int sockfd, res;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (!inet_pton(AF_INET, ipaddr, &addr.sin_addr)) {
                fprintf(stderr, "Invalid ip address\n");
                return -1;
        }
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (sockfd == -1) {
                perror("socket");
                return -1;
        }
        res = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        if (res == -1) {
                perror("connect");
                close(sockfd);
                return -1;
        }
        return sockfd;
}

int tcp_accept(int ls)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        int sockfd = accept(ls, (struct sockaddr *)&addr, &addrlen);
        if (sockfd == -1)
                perror("accept");
        return sockfd;
}

void tcp_shutdown(int sockfd)
{
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
}

ssize_t tcp_send(int sockfd, const char *buf, size_t len)
{
        return send(sockfd, buf, len, 0);
}

ssize_t tcp_recv(int sockfd, char *buf, size_t len)
{
        return recv(sockfd, buf, len, 0);
}

#ifdef BUILD_FOR_LINUX
int tcp_transmit(int sockfd, int fd)
{
        struct stat st_buf;
        ssize_t wc;
        int res;
        res = fstat(fd, &st_buf);
        if (res == -1) {
                perror("fstat");
                return -1;
        }
        wc = sendfile(sockfd, fd, NULL, st_buf.st_size);
        if (wc != st_buf.st_size) {
                perror("sendfile");
                return -1;
        }
        return 0;
}

int tcp_receive(int sockfd, int fd)
{
        ssize_t rc;
        int fds[2], buf_size, res;
        buf_size = getpagesize();
        res = pipe(fds);
        if (res == -1) {
                perror("pipe");
                return -1;
        }
        while ((rc = splice(sockfd, 0, fds[1], 0, buf_size, SPLICE_F_MOVE)) > 0)
                splice(fds[0], 0, fd, 0, buf_size, SPLICE_F_MOVE);
        close(fds[0]);
        close(fds[1]);
        if (rc != 0) {
                perror("splice");
                return -1;
        }
        return 0;
}
#else
#define TCP_BUFFER_SIZE 4096
int tcp_transmit(int sockfd, int fd)
{
        ssize_t rc, wc;
        char buf[TCP_BUFFER_SIZE];
        while ((rc = read(fd, buf, sizeof(buf))) > 0) {
                wc = send(sockfd, buf, rc, 0);
                if (wc != rc) {
                        perror("send");
                        return -1;
                }
        }
        if (rc != 0) {
                perror("read");
                return -1;
        }
        return 0;
}

int tcp_receive(int sockfd, int fd)
{
        ssize_t rc, wc;
        char buf[TCP_BUFFER_SIZE];
        while ((rc = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
                wc = write(fd, buf, rc);
                if (wc != rc) {
                        perror("write");
                        return -1;
                }
        }
        if (rc != 0) {
                perror("recv");
                return -1;
        }
        return 0;
}
#endif

