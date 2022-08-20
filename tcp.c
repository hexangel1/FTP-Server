#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "tcp.h"

unsigned short get_port_number(struct sockaddr_in *addr)
{
        return ntohs(addr->sin_port);
}

const char *get_ip_address(struct sockaddr_in *addr)
{
        return inet_ntoa(addr->sin_addr);
}

const char *get_host_ip(int sock)
{
        struct sockaddr_in addr;
        socklen_t addr_size = sizeof(struct sockaddr_in);
        getsockname(sock, (struct sockaddr *)&addr, &addr_size);
        return get_ip_address(&addr);
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
        if (!inet_aton(ipaddr, &(addr.sin_addr))) {
                fprintf(stderr,"Invalid ip address\n");
                return -1;
        }
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (sockfd == -1) {
                perror("socket");
                return -1;
        }
        res = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (res == -1) {
                perror("connect");
                return -1;
        }
        return sockfd;
}

int tcp_accept(int ls)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        int sockfd = accept(ls, (struct sockaddr *)&addr, &addrlen);
        shutdown(ls, 2);
        close(ls);
        return sockfd;
}

void tcp_shutdown(int sockfd)
{
        shutdown(sockfd, 2);
        close(sockfd);
}

#ifdef LINUX
int tcp_transmit(int conn, int fd)
{
        struct stat st_buf;
        ssize_t wc;
        int res;
        res = fstat(fd, &st_buf);
        if (res == -1) {
                perror("fstat");
                return -1;
        }
        wc = sendfile(conn, fd, NULL, st_buf.st_size);
        if (wc != st_buf.st_size) {
                perror("sendfile");
                return -1;
        }
        return 0;
}
#else
int tcp_transmit(int conn, int fd)
{
        ssize_t rc, wc;
        char buf[1024];
        while ((rc = read(fd, buf, sizeof(buf))) > 0) {
                wc = write(conn, buf, rc);
                if (wc != rc) {
                        perror("write");
                        return -1;
                }
        }
        if (rc != 0) {
                perror("read");
                return -1;
        }
        return 0;
}
#endif

#ifdef LINUX
int tcp_receive(int conn, int fd)
{
        ssize_t rc;
        int chan_fd[2];
        int res, buff_size;
        buff_size = getpagesize();
        res = pipe(chan_fd);
        if (res == -1) {
                perror("pipe");
                return -1;
        }
        while ((rc = splice(conn, NULL, chan_fd[1], NULL, buff_size,
                      SPLICE_F_MORE | SPLICE_F_MOVE)) > 0) {
                splice(chan_fd[0], NULL, fd, NULL, buff_size,
                       SPLICE_F_MORE | SPLICE_F_MOVE);
        }
        close(chan_fd[0]);
        close(chan_fd[1]);
        if (rc != 0) {
                perror("splice");
                return -1;
        }
        return 0;

}
#else
int tcp_receive(int conn, int fd)
{
        ssize_t rc, wc;
        char buf[1024];
        while ((rc = read(conn, buf, sizeof(buf))) > 0) {
                wc = write(fd, buf, rc);
                if (wc != rc) {
                        perror("write");
                        return -1;
                }
        }
        if (rc != 0) {
                perror("read");
                return -1;
        }
        return 0;
}
#endif

