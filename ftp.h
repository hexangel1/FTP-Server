#ifndef FTP_H_SENTRY
#define FTP_H_SENTRY

#define MIN_PORT_NUM 49152
#define MAX_PORT_NUM 65535
#define FTP_GREET_MESSAGE "220 Welcome!\n"
#define FTP_ERROR_MESSAGE "500 Bad command\n"

struct session;

struct ftp_request {
        int cmd_idx;
        char cmd[8];
        char arg[1024];
};

typedef void (*ftp_handler) (struct ftp_request *, struct session *);

void execute_cmd(struct session *ptr, const char *cmdstring);

#endif /* FTP_H_SENTRY */

