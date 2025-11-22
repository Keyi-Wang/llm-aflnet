#include <stddef.h>   /* for size_t */
/* sip packet definitions */
/* ===== Common sizes for SIP header lines (fixed, NUL-terminated) ===== */
#define SIP_HEADER_NAME_LEN   20   /* e.g., "Content-Length" */
#define SIP_SEPARATOR_LEN      3   /* ": " */
#define SIP_CRLF_LEN           3   /* "\r\n" */

#define SIP_TOKEN_LEN         64   /* short tokens: method, scheme, tag */
#define SIP_SHORT_LEN         64   /* media subtype, language tag, etc. */
#define SIP_HOST_LEN         128   /* host[:port] */
#define SIP_URI_LEN          256   /* sip:, sips:, tel: URIs */
#define SIP_PARAMS_LEN       256   /* ;k=v;… flattened */
#define SIP_TEXT_LEN         256   /* generic text field */
#define SIP_DATE_LEN          64   /* RFC1123 date string */
#define SIP_NUM_LEN           16   /* numbers stored as text */
/* ===== 新增：通用 body 上限（可按需调大/调小） ===== */
#ifndef SIP_BODY_MAX
#define SIP_BODY_MAX 8192
#endif

/* -------------------------------------------------------------------- */
/* Group 1: Accept, Accept-Encoding, Accept-Language, Call-ID, Contact  */
/* -------------------------------------------------------------------- */

/* Accept: "Accept: type/subtype[;params]\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];       /* "Accept" */
  char colon_space[SIP_SEPARATOR_LEN];  /* ": "    */
  char media_type[SIP_TOKEN_LEN];       /* "application" */
  char slash;                           /* '/' */
  char sub_type[SIP_SHORT_LEN];         /* "sdp" */
  char params[SIP_PARAMS_LEN];          /* ";q=0.9;level=1" or "" */
  char crlf[SIP_CRLF_LEN];              /* "\r\n" */
} sip_accept_hdr_t;

/* Accept-Encoding: "Accept-Encoding: gzip[;q=0.5]\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN]; 
  char colon_space[SIP_SEPARATOR_LEN];
  char coding[SIP_TOKEN_LEN];           /* "gzip" */
  char params[SIP_PARAMS_LEN];          /* ";q=0.5" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_accept_encoding_hdr_t;

/* Accept-Language: "Accept-Language: en-US[;q=0.7]\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char lang_tag[SIP_SHORT_LEN];         /* "en-US" */
  char params[SIP_PARAMS_LEN];          /* ";q=0.7" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_accept_language_hdr_t;

/* Call-ID: "Call-ID: abc123@host\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char value[SIP_TEXT_LEN];             /* token or token@host */
  char crlf[SIP_CRLF_LEN];
} sip_call_id_hdr_t;

/* Contact: 'Contact: "Bob" <sip:bob@host>;expires=300\r\n' (single entry form) */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char display[SIP_TEXT_LEN];           /* optional display-name (may be "") */
  char sp_opt;                          /* ' ' or '\0' */
  char lt;                              /* '<' */
  char uri[SIP_URI_LEN];                /* "sip:bob@host" */
  char gt;                              /* '>' */
  char params[SIP_PARAMS_LEN];          /* ";expires=300;q=0.5" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_contact_hdr_t;

/* -------------------------------------------------------------------- */
/* Group 2: CSeq, Date, Encryption, Expires, From                       */
/* -------------------------------------------------------------------- */

/* CSeq: "CSeq: 4711 INVITE\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char number[SIP_NUM_LEN];             /* "4711" */
  char sp;                              /* ' ' */
  char method[SIP_TOKEN_LEN];           /* "INVITE" */
  char crlf[SIP_CRLF_LEN];
} sip_cseq_hdr_t;

/* Date: 'Date: Sat, 13 Nov 2010 23:29:00 GMT\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char rfc1123[SIP_DATE_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_date_hdr_t;

/* Encryption (historic): "Encryption: scheme;params\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char scheme[SIP_TOKEN_LEN];           /* "pgp" / token */
  char params[SIP_PARAMS_LEN];          /* ";k=v;…" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_encryption_hdr_t;

/* Expires: "Expires: 3600\r\n" or HTTP-date; store text as-is */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char value[SIP_TEXT_LEN];             /* "3600" or date */
  char crlf[SIP_CRLF_LEN];
} sip_expires_hdr_t;

/* From: 'From: "Alice" <sip:alice@host>;tag=xyz\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char display[SIP_TEXT_LEN];
  char sp_opt;                          /* ' ' or '\0' */
  char lt;
  char uri[SIP_URI_LEN];
  char gt;
  char params[SIP_PARAMS_LEN];          /* ";tag=xyz" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_from_hdr_t;

/* -------------------------------------------------------------------- */
/* Group 3: Record-Route, Timestamp, To, Via, Content-Encoding          */
/* -------------------------------------------------------------------- */

/* Record-Route: 'Record-Route: <sip:proxy@host>;lr\r\n' (single hop) */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char lt;
  char uri[SIP_URI_LEN];
  char gt;
  char params[SIP_PARAMS_LEN];          /* ";lr;foo=bar" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_record_route_hdr_t;

/* Timestamp: "Timestamp: 51.2 2.3\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char value[SIP_TOKEN_LEN];            /* "51.2" */
  char sp_opt;                          /* ' ' or '\0' */
  char delay[SIP_TOKEN_LEN];            /* "2.3" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_timestamp_hdr_t;

/* To: 'To: <sip:bob@host>;tag=abcd\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char display[SIP_TEXT_LEN];
  char sp_opt;
  char lt;
  char uri[SIP_URI_LEN];
  char gt;
  char params[SIP_PARAMS_LEN];          /* ";tag=abcd" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_to_hdr_t;

/* Via: 'Via: SIP/2.0/UDP host:5060;branch=z9hG4bK;received=1.2.3.4\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char sent_protocol[SIP_TOKEN_LEN];    /* "SIP/2.0/UDP" */
  char sp;                              /* ' ' */
  char sent_by[SIP_HOST_LEN];           /* "host:5060" */
  char params[SIP_PARAMS_LEN];          /* ";branch=…;received=…" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_via_hdr_t;

/* Content-Encoding: "Content-Encoding: gzip\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char coding[SIP_TOKEN_LEN];           /* "gzip" */
  char crlf[SIP_CRLF_LEN];
} sip_content_encoding_hdr_t;

/* -------------------------------------------------------------------- */
/* Group 4: Content-Length, Content-Type, Authorization, Hide, Max-Forwards */
/* -------------------------------------------------------------------- */

/* Content-Length: "Content-Length: 129\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char length[SIP_NUM_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_content_length_hdr_t;

/* Content-Type: 'Content-Type: application/sdp;charset=utf-8\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char type_tok[SIP_TOKEN_LEN];         /* "application" */
  char slash;
  char sub_type[SIP_SHORT_LEN];         /* "sdp" */
  char params[SIP_PARAMS_LEN];          /* ";charset=utf-8" or "" */
  char crlf[SIP_CRLF_LEN];
} sip_content_type_hdr_t;

/* Authorization: 'Authorization: Digest username="…", realm="…", …\r\n' */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char scheme[SIP_TOKEN_LEN];           /* "Digest" */
  char sp;                              /* ' ' */
  char kvpairs[SIP_PARAMS_LEN];         /* flattened param list */
  char crlf[SIP_CRLF_LEN];
} sip_authorization_hdr_t;

/* Hide (deprecated): "Hide: hop\r\n" or "route" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char value[SIP_TOKEN_LEN];            /* "hop"/"route" */
  char crlf[SIP_CRLF_LEN];
} sip_hide_hdr_t;

/* Max-Forwards: "Max-Forwards: 70\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char hops[SIP_NUM_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_max_forwards_hdr_t;

/* -------------------------------------------------------------------- */
/* Group 5: Organization, Priority, Proxy-Authorization, Proxy-Require, Route */
/* -------------------------------------------------------------------- */

/* Organization: "Organization: Example Corp\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char text[SIP_TEXT_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_organization_hdr_t;

/* Priority: "Priority: emergency|urgent|normal|non-urgent\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char value[SIP_TOKEN_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_priority_hdr_t;

/* Proxy-Authorization: similar to Authorization */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char scheme[SIP_TOKEN_LEN];
  char sp;
  char kvpairs[SIP_PARAMS_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_proxy_authorization_hdr_t;

/* Proxy-Require: "Proxy-Require: foo;bar" (modeled as a flat token list) */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char option_tags[SIP_TEXT_LEN];       /* e.g., "foo, bar" */
  char crlf[SIP_CRLF_LEN];
} sip_proxy_require_hdr_t;

/* Route: 'Route: <sip:proxy@host>;lr\r\n' (single hop form) */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char lt;
  char uri[SIP_URI_LEN];
  char gt;
  char params[SIP_PARAMS_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_route_hdr_t;

/* -------------------------------------------------------------------- */
/* Group 6: Require, Response-Key, Subject, User-Agent                  */
/* -------------------------------------------------------------------- */

/* Require: "Require: 100rel, timer\r\n" (flat list) */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char option_tags[SIP_TEXT_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_require_hdr_t;

/* Response-Key (historic/rare): "Response-Key: scheme params\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char scheme[SIP_TOKEN_LEN];
  char sp;
  char kvpairs[SIP_PARAMS_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_response_key_hdr_t;

/* Subject: "Subject: Project update\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char text[SIP_TEXT_LEN];
  char crlf[SIP_CRLF_LEN];
} sip_subject_hdr_t;

/* User-Agent: "User-Agent: Softphone/1.2 (Comment)\r\n" */
typedef struct {
  char name[SIP_HEADER_NAME_LEN];
  char colon_space[SIP_SEPARATOR_LEN];
  char product[SIP_TEXT_LEN];           /* product tokens/comments flattened */
  char crlf[SIP_CRLF_LEN];
} sip_user_agent_hdr_t;

/* Assumes the header structs and base sizes from earlier:
   - sip_accept_hdr_t, sip_accept_encoding_hdr_t, sip_accept_language_hdr_t,
     sip_call_id_hdr_t, sip_contact_hdr_t, sip_cseq_hdr_t, sip_date_hdr_t,
     sip_encryption_hdr_t, sip_expires_hdr_t, sip_from_hdr_t,
     sip_record_route_hdr_t, sip_timestamp_hdr_t, sip_to_hdr_t, sip_via_hdr_t,
     sip_content_encoding_hdr_t, sip_content_length_hdr_t, sip_content_type_hdr_t,
     sip_authorization_hdr_t, sip_hide_hdr_t, sip_max_forwards_hdr_t,
     sip_organization_hdr_t, sip_proxy_authorization_hdr_t, sip_proxy_require_hdr_t,
     sip_priority_hdr_t, sip_route_hdr_t, sip_require_hdr_t,
     sip_response_key_hdr_t, sip_subject_hdr_t, sip_user_agent_hdr_t
   - sizes: SIP_TOKEN_LEN, SIP_URI_LEN, SIP_CRLF_LEN, etc.
*/

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA            8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE   8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE          8
#endif

#ifndef SIP_SP_LEN
#define SIP_SP_LEN             2   /* " " */
#endif

typedef struct {
  /* ===== Request-Line =====
     "INVITE SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];            /* "INVITE" (NUL-terminated) */
  char space1[SIP_SP_LEN];               /* " " */
  char request_uri[SIP_URI_LEN];         /* sip/sips/tel URI */
  char space2[SIP_SP_LEN];               /* " " */
  char sip_version[SIP_TOKEN_LEN];       /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];              /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;           /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;              /* CSeq: NNN METHOD */
  sip_from_hdr_t      from_;             /* From: ...        */
  sip_to_hdr_t        to_;               /* To:   ...        */

  size_t              via_count;         /* number of valid Via lines */
  sip_via_hdr_t       via[SIP_MAX_VIA];  /* Via: (repeatable) */

  /* ===== Optional headers =====
     (header is absent if header.name[0] == '\0') */
  sip_accept_hdr_t               accept;
  sip_accept_encoding_hdr_t      accept_encoding;
  sip_accept_language_hdr_t      accept_language;
  sip_authorization_hdr_t        authorization;
  sip_contact_hdr_t              contact;            /* single-line form */
  sip_content_encoding_hdr_t     content_encoding;
  sip_content_length_hdr_t       content_length;     /* typically present if body */
  sip_content_type_hdr_t         content_type;       /* typically present if body */
  sip_date_hdr_t                 date;
  sip_encryption_hdr_t           encryption;
  sip_expires_hdr_t              expires;
  sip_hide_hdr_t                 hide;
  sip_max_forwards_hdr_t         max_forwards;
  sip_organization_hdr_t         organization;
  sip_proxy_authorization_hdr_t  proxy_authorization;
  sip_proxy_require_hdr_t        proxy_require;
  sip_priority_hdr_t             priority;

  size_t                         record_route_count;
  sip_record_route_hdr_t         record_route[SIP_MAX_RECORD_ROUTE]; /* repeatable */

  sip_response_key_hdr_t         response_key;
  sip_require_hdr_t              require;

  size_t                         route_count;
  sip_route_hdr_t                route[SIP_MAX_ROUTE];               /* repeatable */

  sip_subject_hdr_t              subject;
  sip_timestamp_hdr_t            timestamp;
  sip_user_agent_hdr_t           user_agent;

   /* ===== Message body ===== */
  char body[SIP_BODY_MAX];                 /* 实体体；若 content_length/name 非空且 >0 则使用 */

  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];           /* "\r\n" */
} sip_invite_packet_t;

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA            8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE   8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE          8
#endif
#ifndef SIP_SP_LEN
#define SIP_SP_LEN             2   /* " " */
#endif

typedef struct {
  /* ===== Request-Line =====
     "ACK SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];        /* "ACK" */
  char space1[SIP_SP_LEN];           /* " "  */
  char request_uri[SIP_URI_LEN];     /* sip/sips/tel URI */
  char space2[SIP_SP_LEN];           /* " "  */
  char sip_version[SIP_TOKEN_LEN];   /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];          /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;       /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;          /* CSeq: NNN ACK */
  sip_from_hdr_t      from_;         /* From: ...     */
  sip_to_hdr_t        to_;           /* To:   ...     */

  size_t              via_count;     /* number of valid Via lines */
  sip_via_hdr_t       via[SIP_MAX_VIA]; /* Via: (repeatable) */

  /* ===== Optional headers =====
     (mark absent by setting hdr.name[0] = '\0') */
  sip_authorization_hdr_t        authorization;
  sip_contact_hdr_t              contact;            /* single-line form */
  sip_content_length_hdr_t       content_length;
  sip_content_type_hdr_t         content_type;
  sip_date_hdr_t                 date;
  sip_encryption_hdr_t           encryption;
  sip_hide_hdr_t                 hide;
  sip_max_forwards_hdr_t         max_forwards;
  sip_organization_hdr_t         organization;
  sip_proxy_authorization_hdr_t  proxy_authorization;
  sip_proxy_require_hdr_t        proxy_require;
  sip_require_hdr_t              require;

  size_t                         record_route_count;
  sip_record_route_hdr_t         record_route[SIP_MAX_RECORD_ROUTE]; /* repeatable */

  size_t                         route_count;
  sip_route_hdr_t                route[SIP_MAX_ROUTE];               /* repeatable */

  sip_timestamp_hdr_t            timestamp;
  sip_user_agent_hdr_t           user_agent;

  /* ===== Message body ===== */
  char body[SIP_BODY_MAX];               

  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];       /* "\r\n" */
} sip_ack_packet_t;

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA            8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE   8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE          8
#endif
#ifndef SIP_SP_LEN
#define SIP_SP_LEN             2  /* " " */
#endif

typedef struct {
  /* ===== Request-Line =====
     "BYE SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];        /* "BYE" */
  char space1[SIP_SP_LEN];           /* " " */
  char request_uri[SIP_URI_LEN];     /* sip/sips/tel URI */
  char space2[SIP_SP_LEN];           /* " " */
  char sip_version[SIP_TOKEN_LEN];   /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];          /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;       /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;          /* CSeq: NNN BYE */
  sip_from_hdr_t      from_;         /* From: ... */
  sip_to_hdr_t        to_;           /* To:   ...  */

  size_t              via_count;     /* number of populated Via lines */
  sip_via_hdr_t       via[SIP_MAX_VIA]; /* Via: (repeatable) */

  /* ===== Optional headers =====
     (mark “absent” by setting hdr.name[0] = '\0') */
  sip_accept_language_hdr_t     accept_language;
  sip_authorization_hdr_t       authorization;
  sip_content_length_hdr_t      content_length;
  sip_date_hdr_t                date;
  sip_encryption_hdr_t          encryption;
  sip_hide_hdr_t                hide;
  sip_max_forwards_hdr_t        max_forwards;
  sip_proxy_authorization_hdr_t proxy_authorization;
  sip_proxy_require_hdr_t       proxy_require;

  size_t                        record_route_count;
  sip_record_route_hdr_t        record_route[SIP_MAX_RECORD_ROUTE]; /* repeatable */

  sip_response_key_hdr_t        response_key;
  sip_require_hdr_t             require;

  size_t                        route_count;
  sip_route_hdr_t               route[SIP_MAX_ROUTE];               /* repeatable */

  sip_timestamp_hdr_t           timestamp;
  sip_user_agent_hdr_t          user_agent;

  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];       /* "\r\n" */
} sip_bye_packet_t;

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA            8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE   8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE          8
#endif
#ifndef SIP_SP_LEN
#define SIP_SP_LEN             2   /* " " */
#endif

typedef struct {
  /* ===== Request-Line =====
     "CANCEL SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];        /* "CANCEL" */
  char space1[SIP_SP_LEN];           /* " " */
  char request_uri[SIP_URI_LEN];     /* sip/sips/tel URI */
  char space2[SIP_SP_LEN];           /* " " */
  char sip_version[SIP_TOKEN_LEN];   /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];          /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;       /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;          /* CSeq: NNN CANCEL */
  sip_from_hdr_t      from_;         /* From: ... */
  sip_to_hdr_t        to_;           /* To:   ...  */

  size_t              via_count;     /* number of Via lines used */
  sip_via_hdr_t       via[SIP_MAX_VIA];  /* Via: (repeatable) */

  /* ===== Optional headers =====
     Mark an absent optional header by setting hdr.name[0] = '\0'. */
  sip_accept_language_hdr_t     accept_language;
  sip_authorization_hdr_t       authorization;
  sip_content_length_hdr_t      content_length;
  sip_date_hdr_t                date;
  sip_encryption_hdr_t          encryption;
  sip_hide_hdr_t                hide;
  sip_max_forwards_hdr_t        max_forwards;
  sip_proxy_authorization_hdr_t proxy_authorization;
  sip_proxy_require_hdr_t       proxy_require;

  size_t                        record_route_count;
  sip_record_route_hdr_t        record_route[SIP_MAX_RECORD_ROUTE]; /* repeatable */

  sip_response_key_hdr_t        response_key;
  sip_require_hdr_t             require;

  size_t                        route_count;
  sip_route_hdr_t               route[SIP_MAX_ROUTE];               /* repeatable */

  sip_timestamp_hdr_t           timestamp;
  sip_user_agent_hdr_t          user_agent;

  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];       /* "\r\n" */
} sip_cancel_packet_t;

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA              8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE     8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE            8
#endif
#ifndef SIP_MAX_CONTACT
#define SIP_MAX_CONTACT          8
#endif
#ifndef SIP_SP_LEN
#define SIP_SP_LEN               2   /* " " */
#endif

/* Fallback for Retry-After header if not declared elsewhere */
#ifndef HAVE_SIP_RETRY_AFTER_HDR_T
typedef struct {
  char name[SIP_TOKEN_LEN];        /* "Retry-After" */
  char sep[SIP_SP_LEN];            /* ": " */
  char value[64];                  /* seconds or HTTP-date [keep modest] */
  char crlf[SIP_CRLF_LEN];         /* "\r\n" */
} sip_retry_after_hdr_t;
#endif

typedef struct {
  /* ===== Request-Line =====
     "REGISTER SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];        /* "REGISTER" */
  char space1[SIP_SP_LEN];           /* " " */
  char request_uri[SIP_URI_LEN];     /* sip/sips URI of registrar */
  char space2[SIP_SP_LEN];           /* " " */
  char sip_version[SIP_TOKEN_LEN];   /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];          /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;       /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;          /* CSeq: NNN REGISTER */
  sip_from_hdr_t      from_;         /* From: ... */
  sip_to_hdr_t        to_;           /* To:   ...  */

  size_t              via_count;     /* number of Via lines used */
  sip_via_hdr_t       via[SIP_MAX_VIA];      /* Via: (repeatable) */

  /* ===== Optional headers =====
     Mark an absent optional header by setting hdr.name[0] = '\0'. */

  /* Capability / preferences */
  sip_accept_hdr_t            accept;             /* Accept: */
  sip_accept_encoding_hdr_t   accept_encoding;    /* Accept-Encoding: */
  sip_accept_language_hdr_t   accept_language;    /* Accept-Language: */

  /* Auth */
  sip_authorization_hdr_t         authorization;        /* Authorization: */
  sip_proxy_authorization_hdr_t   proxy_authorization;  /* Proxy-Authorization: */

  /* Routing */
  size_t                      record_route_count;
  sip_record_route_hdr_t      record_route[SIP_MAX_RECORD_ROUTE]; /* Record-Route: */

  size_t                      route_count;
  sip_route_hdr_t             route[SIP_MAX_ROUTE];               /* Route: */

  /* Contacts (repeatable in REGISTER) */
  size_t                      contact_count;
  sip_contact_hdr_t           contact[SIP_MAX_CONTACT];           /* Contact: */

  /* Misc headers commonly used with REGISTER */
  sip_content_encoding_hdr_t  content_encoding;   /* Content-Encoding: */
  sip_content_length_hdr_t    content_length;     /* Content-Length: */
  sip_content_type_hdr_t      content_type;       /* Content-Type: */
  sip_date_hdr_t              date;               /* Date: */
  sip_encryption_hdr_t        encryption;         /* Encryption: */
  sip_expires_hdr_t           expires;            /* Expires: */
  sip_hide_hdr_t              hide;               /* Hide: */
  sip_max_forwards_hdr_t      max_forwards;       /* Max-Forwards: */
  sip_organization_hdr_t      organization;       /* Organization: */
  sip_proxy_require_hdr_t     proxy_require;      /* Proxy-Require: */
  sip_response_key_hdr_t      response_key;       /* Response-Key: */
  sip_require_hdr_t           require;            /* Require: */
  sip_timestamp_hdr_t         timestamp;          /* Timestamp: */
  sip_user_agent_hdr_t        user_agent;         /* User-Agent: */

  /* Rare in requests; included per caller’s list */
  sip_retry_after_hdr_t       retry_after;        /* Retry-After: (optional) */

  /* ===== Message body ===== */
  char body[SIP_BODY_MAX];               
  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];                    /* "\r\n" */
} sip_register_packet_t;

#ifndef SIP_MAX_VIA
#define SIP_MAX_VIA              8
#endif
#ifndef SIP_MAX_RECORD_ROUTE
#define SIP_MAX_RECORD_ROUTE     8
#endif
#ifndef SIP_MAX_ROUTE
#define SIP_MAX_ROUTE            8
#endif
#ifndef SIP_MAX_CONTACT
#define SIP_MAX_CONTACT          8
#endif
#ifndef SIP_SP_LEN
#define SIP_SP_LEN               2   /* " " */
#endif

typedef struct {
  /* ===== Request-Line =====
     "OPTIONS SP Request-URI SP SIP/2.0 CRLF" */
  char method[SIP_TOKEN_LEN];        /* "OPTIONS" */
  char space1[SIP_SP_LEN];           /* " " */
  char request_uri[SIP_URI_LEN];     /* sip/sips URI or "*" */
  char space2[SIP_SP_LEN];           /* " " */
  char sip_version[SIP_TOKEN_LEN];   /* "SIP/2.0" */
  char crlf1[SIP_CRLF_LEN];          /* "\r\n" */

  /* ===== Mandatory headers ===== */
  sip_call_id_hdr_t   call_id;       /* Call-ID: ... */
  sip_cseq_hdr_t      cseq;          /* CSeq: NNN OPTIONS */
  sip_from_hdr_t      from_;         /* From: ... */
  sip_to_hdr_t        to_;           /* To:   ...  */

  size_t              via_count;     /* number of Via lines used */
  sip_via_hdr_t       via[SIP_MAX_VIA];      /* Via: (repeatable) */

  /* ===== Optional headers =====
     To mark an absent optional header, set hdr.name[0] = '\0'. */

  /* Capability / preferences */
  sip_accept_hdr_t            accept;             /* Accept: */
  sip_accept_encoding_hdr_t   accept_encoding;    /* Accept-Encoding: */
  sip_accept_language_hdr_t   accept_language;    /* Accept-Language: */

  /* Auth */
  sip_authorization_hdr_t         authorization;        /* Authorization: */
  sip_proxy_authorization_hdr_t   proxy_authorization;  /* Proxy-Authorization: */

  /* Routing (repeatables) */
  size_t                      record_route_count;
  sip_record_route_hdr_t      record_route[SIP_MAX_RECORD_ROUTE]; /* Record-Route: */

  size_t                      route_count;
  sip_route_hdr_t             route[SIP_MAX_ROUTE];               /* Route: */

  /* Contact (often singular; allow repeats) */
  size_t                      contact_count;
  sip_contact_hdr_t           contact[SIP_MAX_CONTACT];           /* Contact: */

  /* Misc */
  sip_content_encoding_hdr_t  content_encoding;   /* Content-Encoding: */
  sip_content_length_hdr_t    content_length;     /* Content-Length: */
  sip_content_type_hdr_t      content_type;       /* Content-Type: */
  sip_date_hdr_t              date;               /* Date: */
  sip_encryption_hdr_t        encryption;         /* Encryption: */
  sip_hide_hdr_t              hide;               /* Hide: */
  sip_max_forwards_hdr_t      max_forwards;       /* Max-Forwards: */
  sip_organization_hdr_t      organization;       /* Organization: */
  sip_proxy_require_hdr_t     proxy_require;      /* Proxy-Require: */
  sip_response_key_hdr_t      response_key;       /* Response-Key: */
  sip_require_hdr_t           require;            /* Require: */
  sip_timestamp_hdr_t         timestamp;          /* Timestamp: */
  sip_user_agent_hdr_t        user_agent;         /* User-Agent: */
/* ===== Message body ===== */
  char body[SIP_BODY_MAX];                 /* 实体体；若 content_length/name 非空且 >0 则使用 */
  /* ===== End of headers (empty line) ===== */
  char end_crlf[SIP_CRLF_LEN];                    /* "\r\n" */
} sip_options_packet_t;

typedef enum {
  SIP_PKT_INVITE,
  SIP_PKT_ACK,
  SIP_PKT_BYE,
  SIP_PKT_CANCEL,
  SIP_PKT_REGISTER,
  SIP_PKT_OPTIONS,
  SIP_PKT_UNKNOWN
} sip_cmd_type_t;

typedef struct {
  sip_cmd_type_t cmd_type;
  union {
    sip_invite_packet_t   invite;
    sip_ack_packet_t      ack;
    sip_bye_packet_t      bye;
    sip_cancel_packet_t   cancel;
    sip_register_packet_t register_;
    sip_options_packet_t  options;
    /* add other packet types here */
  } pkt;
} sip_packet_t;