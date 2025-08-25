/* ftp packet definitions */
/* ====== unified size limits ====== */
#define FTP_SZ_CMD         8     /* e.g. "USER", "PASS", ... */
#define FTP_SZ_SPACE       2     /* " " or "" */
#define FTP_SZ_CRLF        3     /* "\r\n" */
#define FTP_SZ_USERNAME    512
#define FTP_SZ_PASSWORD    512
#define FTP_SZ_ACCOUNT     512
#define FTP_SZ_PATH        1024
#define FTP_SZ_HOSTPORT    64    /* "255,255,255,255,255,255" fits */
#define FTP_SZ_TYPE        16
#define FTP_SZ_FORMAT      16
#define FTP_SZ_STRUCTURE   16
#define FTP_SZ_MODE        16
#define FTP_SZ_BYTECOUNT   32
#define FTP_SZ_MARKER      64
#define FTP_SZ_PARAMS      512
#define FTP_SZ_ARGUMENT    512

/* ====== packet defs with fixed-size arrays ====== */
typedef struct {
    char command[FTP_SZ_CMD];     // fixed-value, e.g. "USER"
    char space[FTP_SZ_SPACE];     // " " (present) or "" (absent)
    char username[FTP_SZ_USERNAME];
    char crlf[FTP_SZ_CRLF];       // "\r\n"
} ftp_user_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "PASS"
    char space[FTP_SZ_SPACE];
    char password[FTP_SZ_PASSWORD];
    char crlf[FTP_SZ_CRLF];
} ftp_pass_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "ACCT"
    char space[FTP_SZ_SPACE];
    char account_info[FTP_SZ_ACCOUNT];
    char crlf[FTP_SZ_CRLF];
} ftp_acct_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "CWD"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_cwd_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "CDUP"
    char crlf[FTP_SZ_CRLF];
} ftp_cdup_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "SMNT"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_smnt_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "QUIT"
    char crlf[FTP_SZ_CRLF];
} ftp_quit_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "REIN"
    char crlf[FTP_SZ_CRLF];
} ftp_rein_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "PORT"
    char space[FTP_SZ_SPACE];
    char host_port_str[FTP_SZ_HOSTPORT]; // "h1,h2,h3,h4,p1,p2"
    char crlf[FTP_SZ_CRLF];
} ftp_port_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "PASV"
    char crlf[FTP_SZ_CRLF];
} ftp_pasv_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "TYPE"
    char space1[FTP_SZ_SPACE];
    char type_code[FTP_SZ_TYPE];
    char space2[FTP_SZ_SPACE];    // optional: " " or ""
    char format_control[FTP_SZ_FORMAT]; // optional: "" if absent
    char crlf[FTP_SZ_CRLF];
} ftp_type_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "STRU"
    char space[FTP_SZ_SPACE];
    char structure_code[FTP_SZ_STRUCTURE];
    char crlf[FTP_SZ_CRLF];
} ftp_stru_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "MODE"
    char space[FTP_SZ_SPACE];
    char mode_code[FTP_SZ_MODE];
    char crlf[FTP_SZ_CRLF];
} ftp_mode_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "RETR"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_retr_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "STOR"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_stor_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "STOU"
    char space[FTP_SZ_SPACE];     // optional
    char pathname[FTP_SZ_PATH];   // optional: "" if absent
    char crlf[FTP_SZ_CRLF];
} ftp_stou_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "APPE"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_appe_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "ALLO"
    char space1[FTP_SZ_SPACE];
    char byte_count[FTP_SZ_BYTECOUNT];
    char space2[FTP_SZ_SPACE];    // optional
    char record_format[FTP_SZ_FORMAT]; // optional
    char crlf[FTP_SZ_CRLF];
} ftp_allo_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "REST"
    char space[FTP_SZ_SPACE];
    char marker[FTP_SZ_MARKER];
    char crlf[FTP_SZ_CRLF];
} ftp_rest_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "RNFR"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_rnfr_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "RNTO"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_rnto_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "ABOR"
    char crlf[FTP_SZ_CRLF];
} ftp_abor_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "DELE"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_dele_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "RMD"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_rmd_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "MKD"
    char space[FTP_SZ_SPACE];
    char pathname[FTP_SZ_PATH];
    char crlf[FTP_SZ_CRLF];
} ftp_mkd_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "PWD"
    char crlf[FTP_SZ_CRLF];
} ftp_pwd_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "LIST"
    char space[FTP_SZ_SPACE];     // optional
    char pathname[FTP_SZ_PATH];   // optional
    char crlf[FTP_SZ_CRLF];
} ftp_list_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "NLST"
    char space[FTP_SZ_SPACE];     // optional
    char pathname[FTP_SZ_PATH];   // optional
    char crlf[FTP_SZ_CRLF];
} ftp_nlst_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "SITE"
    char space[FTP_SZ_SPACE];
    char parameters[FTP_SZ_PARAMS];
    char crlf[FTP_SZ_CRLF];
} ftp_site_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "SYST"
    char crlf[FTP_SZ_CRLF];
} ftp_syst_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "STAT"
    char space[FTP_SZ_SPACE];     // optional
    char pathname[FTP_SZ_PATH];   // optional
    char crlf[FTP_SZ_CRLF];
} ftp_stat_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "HELP"
    char space[FTP_SZ_SPACE];     // optional
    char argument[FTP_SZ_ARGUMENT]; // optional
    char crlf[FTP_SZ_CRLF];
} ftp_help_packet_t;

typedef struct {
    char command[FTP_SZ_CMD];     // "NOOP"
    char crlf[FTP_SZ_CRLF];
} ftp_noop_packet_t;

/* ====== enums unchanged ====== */
typedef enum {
    FTP_USER, FTP_PASS, FTP_ACCT, FTP_CWD, FTP_CDUP, FTP_SMNT, FTP_QUIT, FTP_REIN,
    FTP_PORT, FTP_PASV, FTP_TYPE, FTP_STRU, FTP_MODE, FTP_RETR, FTP_STOR, FTP_STOU,
    FTP_APPE, FTP_ALLO, FTP_REST, FTP_RNFR, FTP_RNTO, FTP_ABOR, FTP_DELE, FTP_RMD,
    FTP_MKD, FTP_PWD, FTP_LIST, FTP_NLST, FTP_SITE, FTP_SYST, FTP_STAT, FTP_HELP, FTP_NOOP
} ftp_command_type_t;

/* ====== top-level packet union (types updated) ====== */
typedef struct {
    ftp_command_type_t command_type;
    union {
        ftp_user_packet_t user;
        ftp_pass_packet_t pass;
        ftp_acct_packet_t acct;
        ftp_cwd_packet_t cwd;
        ftp_cdup_packet_t cdup;
        ftp_smnt_packet_t smnt;
        ftp_quit_packet_t quit;
        ftp_rein_packet_t rein;
        ftp_port_packet_t port;
        ftp_pasv_packet_t pasv;
        ftp_type_packet_t type;
        ftp_stru_packet_t stru;
        ftp_mode_packet_t mode;
        ftp_retr_packet_t retr;
        ftp_stor_packet_t stor;
        ftp_stou_packet_t stou;
        ftp_appe_packet_t appe;
        ftp_allo_packet_t allo;
        ftp_rest_packet_t rest;
        ftp_rnfr_packet_t rnfr;
        ftp_rnto_packet_t rnto;
        ftp_abor_packet_t abor;
        ftp_dele_packet_t dele;
        ftp_rmd_packet_t rmd;
        ftp_mkd_packet_t mkd;
        ftp_pwd_packet_t pwd;
        ftp_list_packet_t list;
        ftp_nlst_packet_t nlst;
        ftp_site_packet_t site;
        ftp_syst_packet_t syst;
        ftp_stat_packet_t stat;
        ftp_help_packet_t help;
        ftp_noop_packet_t noop;
    } packet;
} ftp_packet_t;
