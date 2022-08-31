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

#ifdef BUILD_DAEMON
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
#endif

static void goodbye_message(const char *message)
{
#ifdef BUILD_DAEMON
        syslog(LOG_INFO, "%s", message);
        closelog();
#else
        fputs(message, stderr);
        fputc('\n', stderr);
#endif
}

int main(int argc, char **argv)
{
        int res;
        struct tcp_server *serv;
#ifdef BUILD_DAEMON
        daemonize();
#endif
        if (argc != 3) {
                goodbye_message("Usage: server [ip] [port]");
                exit(1);
        }
        serv = new_tcp_server(argv[1], atoi(argv[2]));
        res = tcp_server_up(serv);
        if (res == -1) {
                goodbye_message("Failed to bring server up");
                exit(1);
        }
        fputs("running...\n", stderr);
        tcp_server_handle(serv);
        tcp_server_down(serv);
        goodbye_message("Gracefully stopped");
        return 0;
}

