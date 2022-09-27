#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "server.h"

static int daemon_state = 0;
static const char *ip_addr = "127.0.0.1";
static unsigned short port = 2000;

static void daemonize(void)
{
        int res, fd, fd_max = 1024;
        struct rlimit rl;
        res = getrlimit(RLIMIT_NOFILE, &rl);
        if (!res && rl.rlim_max != RLIM_INFINITY)
                fd_max = rl.rlim_max;
        for (fd = 0; fd < fd_max; fd++)
                close(fd);
        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
        umask(0);
        chdir("/");
        if (fork() > 0)
                exit(0);
        setsid();
        if (fork() > 0)
                exit(0);
        openlog("ftpservd", LOG_CONS | LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Daemon started, pid == %d", getpid());
}

static void write_log(const char *message)
{
        if (daemon_state) {
                syslog(LOG_INFO, "%s", message);
                closelog();
        }
        fprintf(stderr, "%s\n", message);
}

static int get_command_line_options(int argc, char **argv)
{
        int opt, retval = 0;
        while ((opt = getopt(argc, argv, ":di:p:")) != -1) {
                switch (opt) {
                case 'd':
                        daemon_state = 1;
                        break;
                case 'i':
                        ip_addr = optarg;
                        break;
                case 'p':
                        port = atoi(optarg);
                        break;
                case ':':
                        fprintf(stderr,
                                "Option -%c requires an operand\n", optopt);
                        retval = -1;
                        break;
                case '?':
                        fprintf(stderr, "Unrecognized option: -%c\n", optopt);
                        retval = -1;
                        break;
                }
        }
        return retval;
}

int main(int argc, char **argv)
{
        int res;
        struct tcp_server *serv;
        res = get_command_line_options(argc, argv);
        if (res == -1) {
                fprintf(stderr, "Usage: ftpserv [-d] [-i ipaddr] [-p port]\n");
                exit(EXIT_FAILURE);
        }
        if (daemon_state)
                daemonize();
        serv = new_tcp_server(ip_addr, port);
        res = tcp_server_up(serv);
        if (res == -1) {
                write_log("Failed to bring server up");
                exit(EXIT_FAILURE);
        }
        write_log("Running...");
        tcp_server_handle(serv);
        tcp_server_down(serv);
        write_log("Gracefully stopped");
        return 0;
}

