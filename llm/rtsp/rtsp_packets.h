#include <stdint.h>
#include "rtsp.h"
#define RTSP_HEADER_NAME_LEN   32
#define RTSP_HEADER_VALUE_LEN  256
#define RTSP_SEPARATOR_LEN     3   // ": "
#define RTSP_CRLF_LEN          3
#define RTSP_METHOD_LEN        16
#define RTSP_URI_LEN           256
#define RTSP_VERSION_LEN       16
#define MAX_RTSP_BODY_LEN     1024// 最大 RTSP 消息长度


/* ===========================
   2. Accept
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Accept"
    char colon_space[RTSP_SEPARATOR_LEN]; // ": "
    char media_type[64];                  // "application"
    char slash;                           // '/'
    char sub_type[64];                    // "sdp"
    char crlf[RTSP_CRLF_LEN];             // "\r\n"
} accept_header_rtsp_t;

/* ===========================
   3. Accept-Encoding
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Accept-Encoding"
    char colon_space[RTSP_SEPARATOR_LEN]; // ": "
    char encoding[64];                    // "gzip", "identity", ...
    char crlf[RTSP_CRLF_LEN];             // "\r\n"
} accept_encoding_header_rtsp_t;

/* ===========================
   4. Accept-Language
   =========================== */
#define MAX_ACCEPT_LANG 8   // 最多 8 个语言条目

typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Accept-Language"
    char colon_space[RTSP_SEPARATOR_LEN]; // ": "
    struct {
        char language_tag[16];            // "en-US"
        char qvalue[8];                   // "0.8"（可为空字符串）
    } entries[MAX_ACCEPT_LANG];
    int entry_count;
    char crlf[RTSP_CRLF_LEN];              // "\r\n"
} accept_language_header_rtsp_t;



/* ===========================
   6. Authorization
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Authorization"
    char colon_space[RTSP_SEPARATOR_LEN]; // ": "
    char auth_type[16];                   // "Basic" / "Digest"
    char space;                           // ' '
    char credentials[128];                // Base64 或 Digest 参数串
    char crlf[RTSP_CRLF_LEN];
} authorization_header_rtsp_t;

/* ===========================
   7. Bandwidth
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Bandwidth"
    char colon_space[RTSP_SEPARATOR_LEN]; // ": "
    int value;                            // 数值 (kbps)
    char crlf[RTSP_CRLF_LEN];
} bandwidth_header_rtsp_t;

/* ===========================
   8. Blocksize
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Blocksize"
    char colon_space[RTSP_SEPARATOR_LEN];
    int value;                            // 字节数
    char crlf[RTSP_CRLF_LEN];
} blocksize_header_rtsp_t;

/* ===========================
   9. Cache-Control
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Cache-Control"
    char colon_space[RTSP_SEPARATOR_LEN];
    char directive[64];                   // "no-cache", "public", ...
    char crlf[RTSP_CRLF_LEN];
} cache_control_header_rtsp_t;

/* ===========================
   10. Conference
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Conference"
    char colon_space[RTSP_SEPARATOR_LEN];
    char conference_id[64];               // 标识符
    char crlf[RTSP_CRLF_LEN];
} conference_header_rtsp_t;

/* ===========================
   11. Connection
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Connection"
    char colon_space[RTSP_SEPARATOR_LEN];
    char option[32];                      // "keep-alive" / "close"
    char crlf[RTSP_CRLF_LEN];
} connection_header_rtsp_t;

/* ===========================
   12. Content-Base
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Base"
    char colon_space[RTSP_SEPARATOR_LEN];
    char uri[128];
    char crlf[RTSP_CRLF_LEN];
} content_base_header_rtsp_t;

/* ===========================
   13. Content-Encoding
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Encoding"
    char colon_space[RTSP_SEPARATOR_LEN];
    char encoding[32];                    // "gzip", "compress" 等
    char crlf[RTSP_CRLF_LEN];
} content_encoding_header_rtsp_t;

/* ===========================
   14. Content-Language
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Language"
    char colon_space[RTSP_SEPARATOR_LEN];
    char language[32];                    // "en", "en-US"
    char crlf[RTSP_CRLF_LEN];
} content_language_header_rtsp_t;

/* ===========================
   15. Content-Length
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Length"
    char colon_space[RTSP_SEPARATOR_LEN];
    int length;                           // 正文长度
    char crlf[RTSP_CRLF_LEN];
} content_length_header_rtsp_t;

/* ===========================
   16. Content-Location
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Location"
    char colon_space[RTSP_SEPARATOR_LEN];
    char uri[128];
    char crlf[RTSP_CRLF_LEN];
} content_location_header_rtsp_t;

/* ===========================
   17. Content-Type
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Content-Type"
    char colon_space[RTSP_SEPARATOR_LEN];
    char media_type[64];
    char slash;
    char sub_type[64];
    char crlf[RTSP_CRLF_LEN];
} content_type_header_rtsp_t;

/* ===========================
   18. CSeq
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "CSeq"
    char colon_space[RTSP_SEPARATOR_LEN];
    int number;                           // 请求序号
    char crlf[RTSP_CRLF_LEN];
} cseq_header_rtsp_t;
/* ===========================
   19. Date
   RFC 1123 格式: "Tue, 15 Nov 1994 08:12:31 GMT"
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Date"
    char colon_space[RTSP_SEPARATOR_LEN];
    char wkday[4];                        // "Tue"
    char comma_space[3];                  // ", "
    char day[3];                          // "15"
    char space1;
    char month[4];                        // "Nov"
    char space2;
    char year[5];                         // "1994"
    char space3;
    char time_of_day[9];                  // "08:12:31"
    char space4;
    char gmt[4];                          // "GMT"
    char crlf[RTSP_CRLF_LEN];
} date_header_rtsp_t;

/* ===========================
   20. Expires
   同 Date 格式
   =========================== */
typedef date_header_rtsp_t expires_header_rtsp_t;

/* ===========================
   21. From
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "From"
    char colon_space[RTSP_SEPARATOR_LEN];
    char uri[128];                        // "<sip:user@example.com>"
    char crlf[RTSP_CRLF_LEN];
} from_header_rtsp_t;

/* ===========================
   22. If-Modified-Since
   同 Date 格式
   =========================== */
typedef date_header_rtsp_t if_modified_since_header_rtsp_t;

/* ===========================
   23. Last-Modified
   同 Date 格式
   =========================== */
typedef date_header_rtsp_t last_modified_header_rtsp_t;


/* ===========================
   25. Proxy-Require
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Proxy-Require"
    char colon_space[RTSP_SEPARATOR_LEN];
    char option_tag[64];
    char crlf[RTSP_CRLF_LEN];
} proxy_require_header_rtsp_t;

/* ===========================
   27. Range
   NPT 格式: "npt=0-7.741"
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Range"
    char colon_space[RTSP_SEPARATOR_LEN];
    char unit[8];                         // "npt"
    char equals;                          // '='
    char start[16];                       // "0"
    char dash;                            // '-'
    char end[16];                         // "7.741"
    char crlf[RTSP_CRLF_LEN];
} range_header_rtsp_t;

/* ===========================
   28. Referer
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Referer"
    char colon_space[RTSP_SEPARATOR_LEN];
    char uri[128];
    char crlf[RTSP_CRLF_LEN];
} referer_header_rtsp_t;

/* ===========================
   29. Require
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Require"
    char colon_space[RTSP_SEPARATOR_LEN];
    char option_tag[64];
    char crlf[RTSP_CRLF_LEN];
} require_header_rtsp_t;


/* ===========================
   32. Scale
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Scale"
    char colon_space[RTSP_SEPARATOR_LEN];
    float value;                          // 倍速播放
    char crlf[RTSP_CRLF_LEN];
} scale_header_rtsp_t;

/* ===========================
   33. Session
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Session"
    char colon_space[RTSP_SEPARATOR_LEN];
    char session_id[64];
    char semicolon_timeout[10];           // ";timeout="
    int timeout;
    char crlf[RTSP_CRLF_LEN];
} session_header_rtsp_t;

/* ===========================
   35. Speed
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Speed"
    char colon_space[RTSP_SEPARATOR_LEN];
    float value;                          // 播放速度倍数
    char crlf[RTSP_CRLF_LEN];
} speed_header_rtsp_t;

/* ===========================
   36. Transport
   典型: "RTP/AVP;unicast;client_port=8000-8001"
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Transport"
    char colon_space[RTSP_SEPARATOR_LEN];
    char protocol[16];                    // "RTP/AVP"
    char semicolon1;
    char cast_mode[16];                   // "unicast" / "multicast"
    char semicolon2;
    char client_port_prefix[16];          // "client_port="
    char port_range[16];                  // "8000-8001"
    char crlf[RTSP_CRLF_LEN];
} transport_header_rtsp_t;


/* ===========================
   38. User-Agent
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "User-Agent"
    char colon_space[RTSP_SEPARATOR_LEN];
    char agent_string[128];               // "VLC/3.0.11", "Live555/0.92"
    char crlf[RTSP_CRLF_LEN];
} user_agent_header_rtsp_t;

/* ===========================
   39. Via
   典型: "RTSP/1.0 host"
   =========================== */
typedef struct {
    char name[RTSP_HEADER_NAME_LEN];      // "Via"
    char colon_space[RTSP_SEPARATOR_LEN];
    char protocol[16];                    // "RTSP/1.0"
    char space;
    char host[64];                        // 主机名
    char crlf[RTSP_CRLF_LEN];
} via_header_rtsp_t;


typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed: "OPTIONS"
    char space1;                            // fixed: ' '
    char request_uri[RTSP_URI_LEN];         // 
    char space2;                            // fixed: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // required
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;    // optional
    referer_header_rtsp_t        referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed: "\r\n"
} rtsp_options_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "SETUP"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    cache_control_header_rtsp_t   cache_control_header;   // optional
    conference_header_rtsp_t      conference_header;      // optional
    from_header_rtsp_t            from_header;            // optional
    if_modified_since_header_rtsp_t if_modified_since_header; // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    transport_header_rtsp_t       transport_header;       // mandatory
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_setup_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "DESCRIBE"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_header_rtsp_t         accept_header;         // optional
    accept_encoding_header_rtsp_t accept_encoding_header; // optional
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t  authorization_header;  // optional
    bandwidth_header_rtsp_t      bandwidth_header;      // optional
    blocksize_header_rtsp_t      blocksize_header;      // optional
    content_base_header_rtsp_t   content_base_header;   // optional
    content_encoding_header_rtsp_t content_encoding_header; // optional
    content_language_header_rtsp_t content_language_header; // optional
    content_length_header_rtsp_t content_length_header; // optional
    content_location_header_rtsp_t content_location_header; // optional
    expires_header_rtsp_t        expires_header;        // optional
    from_header_rtsp_t           from_header;           // optional
    if_modified_since_header_rtsp_t if_modified_since_header; // optional
    last_modified_header_rtsp_t  last_modified_header;  // optional
    proxy_require_header_rtsp_t  proxy_require_header;  // optional
    referer_header_rtsp_t        referer_header;        // optional
    require_header_rtsp_t        require_header;        // optional
    session_header_rtsp_t        session_header;        // optional
    user_agent_header_rtsp_t     user_agent_header;     // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_describe_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "PLAY"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    range_header_rtsp_t           range_header;           // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    scale_header_rtsp_t           scale_header;           // optional
    session_header_rtsp_t         session_header;         // optional
    speed_header_rtsp_t           speed_header;           // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_play_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "PAUSE"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    range_header_rtsp_t           range_header;           // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_pause_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "TEARDOWN"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_teardown_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "GET_PARAMETER"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_header_rtsp_t         accept_header;         // optional
    accept_encoding_header_rtsp_t accept_encoding_header; // optional
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t  authorization_header;  // optional
    bandwidth_header_rtsp_t      bandwidth_header;      // optional
    blocksize_header_rtsp_t      blocksize_header;      // optional
    content_base_header_rtsp_t   content_base_header;   // optional
    content_length_header_rtsp_t content_length_header; // optional
    content_location_header_rtsp_t content_location_header; // optional
    from_header_rtsp_t           from_header;           // optional
    last_modified_header_rtsp_t  last_modified_header;  // optional
    proxy_require_header_rtsp_t  proxy_require_header;  // optional
    referer_header_rtsp_t        referer_header;        // optional
    require_header_rtsp_t        require_header;        // optional
    session_header_rtsp_t        session_header;        // optional
    user_agent_header_rtsp_t     user_agent_header;     // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_get_parameter_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "SET_PARAMETER"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    content_encoding_header_rtsp_t content_encoding_header; // optional
    content_length_header_rtsp_t  content_length_header;  // optional
    content_type_header_rtsp_t    content_type_header;    // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    /* ===== Message Body ===== */
    char body[MAX_RTSP_BODY_LEN];
    
    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_set_parameter_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "REDIRECT"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_redirect_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "ANNOUNCE"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    content_encoding_header_rtsp_t content_encoding_header; // optional
    content_language_header_rtsp_t content_language_header; // optional
    content_length_header_rtsp_t  content_length_header;  // optional
    content_type_header_rtsp_t    content_type_header;    // optional
    expires_header_rtsp_t         expires_header;         // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    /* ===== Message Body ===== */
    char body[MAX_RTSP_BODY_LEN];

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_announce_packet_t;

typedef struct {
    char method[RTSP_HEADER_NAME_LEN];      // fixed-value: "RECORD"
    char space1;                            // fixed-value: ' '
    char request_uri[RTSP_URI_LEN];         //
    char space2;                            // fixed-value: ' '
    char rtsp_version[RTSP_VERSION_LEN];    // fixed-value: "RTSP/1.0"
    char crlf1[RTSP_CRLF_LEN];              // fixed-value: "\r\n"

    /* ===== General Headers ===== */
    cseq_header_rtsp_t           cseq_header;           // mandatory
    connection_header_rtsp_t     connection_header;     // optional
    date_header_rtsp_t           date_header;           // optional
    via_header_rtsp_t            via_header;            // optional, repeatable

    /* ===== Request Headers ===== */
    accept_language_header_rtsp_t accept_language_header; // optional
    authorization_header_rtsp_t   authorization_header;   // optional
    bandwidth_header_rtsp_t       bandwidth_header;       // optional
    blocksize_header_rtsp_t       blocksize_header;       // optional
    from_header_rtsp_t            from_header;            // optional
    proxy_require_header_rtsp_t   proxy_require_header;   // optional
    range_header_rtsp_t           range_header;           // optional
    referer_header_rtsp_t         referer_header;         // optional
    require_header_rtsp_t         require_header;         // optional
    scale_header_rtsp_t           scale_header;           // optional
    session_header_rtsp_t         session_header;         // optional
    user_agent_header_rtsp_t      user_agent_header;      // optional

    char end_crlf[RTSP_CRLF_LEN]; // fixed-value: "\r\n"
} rtsp_record_packet_t;

typedef enum {
    RTSP_TYPE_OPTIONS,
    RTSP_TYPE_DESCRIBE,
    RTSP_TYPE_SETUP,
    RTSP_TYPE_PLAY,
    RTSP_TYPE_PAUSE,
    RTSP_TYPE_TEARDOWN,
    RTSP_TYPE_GET_PARAMETER,
    RTSP_TYPE_SET_PARAMETER,
    RTSP_TYPE_REDIRECT,
    RTSP_TYPE_ANNOUNCE,
    RTSP_TYPE_RECORD,
    RTSP_TYPE_UNKNOWN
} rtsp_type_t;

typedef struct {
    rtsp_type_t type;
    union {
        rtsp_options_packet_t       options;
        rtsp_describe_packet_t      describe;
        rtsp_setup_packet_t         setup;
        rtsp_play_packet_t          play;
        rtsp_pause_packet_t         pause;
        rtsp_teardown_packet_t      teardown;
        rtsp_get_parameter_packet_t get_parameter;
        rtsp_set_parameter_packet_t set_parameter;
        rtsp_redirect_packet_t      redirect;
        rtsp_announce_packet_t      announce;
        rtsp_record_packet_t        record;
    };
} rtsp_packet_t;
