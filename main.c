#include <stdio.h>
#include <stdlib.h>
#include "tcp.h"

int main(int argc, char **argv)
{
        int res;
        struct tcp_server *serv;
        if (argc != 3) {
                fputs("Usage: server [ip] [port]\n", stderr);
                exit(1);
        }
        serv = new_tcp_server(argv[1], atoi(argv[2]));
        res = tcp_server_up(serv);
        if (res == -1) {
                fputs("Failed to bring server up\n", stderr);
                exit(1);
        }
        fputs("server is running\n", stderr);
        tcp_server_listen(serv);
        tcp_server_down(serv);
        fputs("server is stopped\n", stderr);
        return 0;
}

