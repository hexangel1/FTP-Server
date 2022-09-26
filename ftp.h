#ifndef FTP_H_SENTRY
#define FTP_H_SENTRY

#define MIN_PORT_NUM 49152
#define MAX_PORT_NUM 65535
#define MAX_CMD_LEN 8
#define MAX_ARG_LEN 1024

#define FTP_COMMAND_HANDLER(cmd) \
        void ftp_ ## cmd(struct session *sess, struct ftp_request *request)

struct ftp_request {
        char cmd[MAX_CMD_LEN];
        char arg[MAX_ARG_LEN];
};

struct session;
struct tree_node;

typedef int  (*ftp_routine) (struct session *sess, const char *, int);
typedef void (*ftp_handler) (struct session *sess, struct ftp_request *);

extern const char *const ftp_greet_message;
extern const char *const ftp_error_message;

/* execute ftp command */
void execute_cmd(struct session *sess, const char *cmd, struct tree_node *root);

/* build commands index */
void build_cmd_index(struct tree_node **root);

#endif /* FTP_H_SENTRY */

