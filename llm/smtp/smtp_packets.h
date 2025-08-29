/* smtp packet definitions */
/* ---- SMTP fixed-size field lengths (include room for trailing NUL) ---- */
#ifndef SMTP_SIZES_H
#define SMTP_SIZES_H

#define SMTP_SZ_CMD          16     /* "HELO"/"EHLO"/"MAIL"/... */
#define SMTP_SZ_SPACE         2     /* "" or " " */
#define SMTP_SZ_CRLF          3     /* "\r\n" */

#define SMTP_SZ_DOMAIN      256     /* FQDN or address-literal */
#define SMTP_SZ_PATH        512     /* "<local@domain>" + routing quirks */
#define SMTP_SZ_OPTARGS     512     /* extension args on MAIL/RCPT */
#define SMTP_SZ_VRFY_STR    512     /* VRFY string */
#define SMTP_SZ_LISTNAME    256     /* EXPN list name */
#define SMTP_SZ_AUTH_MECH    32     /* "PLAIN"/"LOGIN"/"CRAM-MD5"/... */
#define SMTP_SZ_AUTH_IR    1024     /* base64 initial-response */
#define SMTP_SZ_HELP_ARG     32     /* "MAIL"/"RCPT"/... (optional) */

#endif /* SMTP_SIZES_H */

/* ---------------- Packets with fixed-size arrays ---------------- */

typedef struct {
    char command[SMTP_SZ_CMD];          /* "HELO" */
    char space[SMTP_SZ_SPACE];          /* SP (one space or "") */
    char domain[SMTP_SZ_DOMAIN];        /* client id */
    char crlf[SMTP_SZ_CRLF];            /* "\r\n" */
} smtp_helo_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "EHLO" */
    char space[SMTP_SZ_SPACE];          /* SP */
    char domain[SMTP_SZ_DOMAIN];
    char crlf[SMTP_SZ_CRLF];
} smtp_ehlo_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "MAIL" */
    char space1[SMTP_SZ_SPACE];         /* SP */
    char from_keyword[SMTP_SZ_CMD];     /* "FROM:" */
    char reverse_path[SMTP_SZ_PATH];    /* "<user@example.com>" */
    char optional_args[SMTP_SZ_OPTARGS];/* extension args (maybe empty) */
    char crlf[SMTP_SZ_CRLF];
} smtp_mail_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "RCPT" */
    char space1[SMTP_SZ_SPACE];         /* SP */
    char to_keyword[SMTP_SZ_CMD];       /* "TO:" */
    char forward_path[SMTP_SZ_PATH];    /* "<bob@example.com>" */
    char optional_args[SMTP_SZ_OPTARGS];/* extension args (maybe empty) */
    char crlf[SMTP_SZ_CRLF];
} smtp_rcpt_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "DATA" */
    char crlf[SMTP_SZ_CRLF];
} smtp_data_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "RSET" */
    char crlf[SMTP_SZ_CRLF];
} smtp_rset_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "VRFY" */
    char space[SMTP_SZ_SPACE];          /* SP */
    char string[SMTP_SZ_VRFY_STR];      /* local-part/full name/address */
    char crlf[SMTP_SZ_CRLF];
} smtp_vrfy_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "EXPN" */
    char space[SMTP_SZ_SPACE];          /* SP */
    char mailing_list[SMTP_SZ_LISTNAME];
    char crlf[SMTP_SZ_CRLF];
} smtp_expn_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "HELP" */
    char space[SMTP_SZ_SPACE];          /* optional SP ("" or " ") */
    char argument[SMTP_SZ_HELP_ARG];    /* optional command name */
    char crlf[SMTP_SZ_CRLF];
} smtp_help_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "NOOP" */
    char crlf[SMTP_SZ_CRLF];
} smtp_noop_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "QUIT" */
    char crlf[SMTP_SZ_CRLF];
} smtp_quit_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "STARTTLS" */
    char crlf[SMTP_SZ_CRLF];
} smtp_starttls_packet_t;

typedef struct {
    char command[SMTP_SZ_CMD];          /* "AUTH" */
    char space1[SMTP_SZ_SPACE];         /* SP */
    char mechanism[SMTP_SZ_AUTH_MECH];  /* "PLAIN"/"LOGIN"/... */
    char space2[SMTP_SZ_SPACE];         /* optional SP before initial-response */
    char initial_response[SMTP_SZ_AUTH_IR]; /* optional base64 (may be empty) */
    char crlf[SMTP_SZ_CRLF];
} smtp_auth_packet_t;

typedef enum{
    SMTP_PKT_HELO,
    SMTP_PKT_EHLO,
    SMTP_PKT_MAIL,
    SMTP_PKT_RCPT,
    SMTP_PKT_DATA,
    SMTP_PKT_RSET,
    SMTP_PKT_VRFY,
    SMTP_PKT_EXPN,
    SMTP_PKT_HELP,
    SMTP_PKT_NOOP,
    SMTP_PKT_QUIT,
    SMTP_PKT_STARTTLS,
    SMTP_PKT_AUTH,
    SMTP_PKT_UNRECOGNIZED
} smtp_cmd_type_t;

typedef struct {
    smtp_cmd_type_t cmd_type;
    union {
        smtp_helo_packet_t helo;
        smtp_ehlo_packet_t ehlo;
        smtp_mail_packet_t mail;
        smtp_rcpt_packet_t rcpt;
        smtp_data_packet_t data;
        smtp_rset_packet_t rset;
        smtp_vrfy_packet_t vrfy;
        smtp_expn_packet_t expn;
        smtp_help_packet_t help;
        smtp_noop_packet_t noop;
        smtp_quit_packet_t quit;
        smtp_starttls_packet_t starttls;
        smtp_auth_packet_t auth;
    } pkt;
} smtp_packet_t;