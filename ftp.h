#ifndef FTP_H_SENTRY
#define FTP_H_SENTRY

#include "tcp.h"

#define MIN_PORT_NUM 49152
#define MAX_PORT_NUM 65535

enum ftp_command {
        ABOR, CDUP, CWD,  DELE, EPSV,
        HELP, LIST, MDTM, MKD,  NLST,
        NOOP, PASS, PASV, PORT, PWD,
        QUIT, REIN, RETR, RMD,  RNFR,
        RNTO, SIZE, STOR, SYST, TYPE,
        USER, INVALID_CMD
};

struct ftp_request {
        enum ftp_command cmd;
        char arg[1024];
};

void execute_cmd(struct session *ptr, const char *cmdstring);

#endif

