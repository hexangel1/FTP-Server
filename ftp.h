#ifndef FTP_H_SENTRY
#define FTP_H_SENTRY

#define MIN_PORT_NUM 49152
#define MAX_PORT_NUM 65535
#define MAXCMDLEN 7
#define MAXARGLEN 1023

struct ftp_request {
        int cmd_idx;
        char cmd[MAXCMDLEN + 1];
        char arg[MAXARGLEN + 1];
};

struct session;

typedef int  (*ftp_routine) (const char *, int, struct session *);
typedef void (*ftp_handler) (struct ftp_request *, struct session *);

extern const char *const ftp_greet_message;
extern const char *const ftp_error_message;

/* executes ftp command */
void execute_cmd(struct session *ptr, const char *cmdstring);

#endif /* FTP_H_SENTRY */

