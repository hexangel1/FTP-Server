#include <stdio.h>
#include <stdlib.h>
#include "server.h"

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
        fputs("running...\n", stderr);
        tcp_server_handle(serv);
        tcp_server_down(serv);
        return 0;
}

