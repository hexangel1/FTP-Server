#ifndef FTP_H_SENTRY
#define FTP_H_SENTRY

#define MIN_PORT_NUM 49152
#define MAX_PORT_NUM 65535

struct session;

struct ftp_request {
        int cmd_idx;
        char cmd[8];
        char arg[1024];
};

typedef void (*ftp_handler) (struct ftp_request *, struct session *);
typedef int (*ftp_process) (const char *, struct session *);

extern const char *const ftp_greet_message;
extern const char *const ftp_error_message;

void execute_cmd(struct session *ptr, const char *cmdstring);

#endif /* FTP_H_SENTRY */

