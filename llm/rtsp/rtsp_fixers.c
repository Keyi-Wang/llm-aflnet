#include "rtsp.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
// fixer_absolute_uri.h / .c
#include <stddef.h>

#include <ctype.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

/* --- small utils --- */
static inline void set_cstr(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    size_t n = MIN(cap - 1, src ? strlen(src) : 0);
    if (src && n) memcpy(dst, src, n);
    dst[n] = '\0';
}
static inline void set_crlf(char crlf[RTSP_CRLF_LEN]) {
    if (RTSP_CRLF_LEN >= 2) crlf[0] = '\r';
    if (RTSP_CRLF_LEN >= 2) crlf[1] = '\n';
    if (RTSP_CRLF_LEN >= 3) crlf[2] = '\0';
}
static inline void set_colon_space(char cs[RTSP_SEPARATOR_LEN]) {
    if (RTSP_SEPARATOR_LEN >= 2) cs[0] = ':', cs[1] = ' ';
    if (RTSP_SEPARATOR_LEN >= 3) cs[2] = '\0';
}
static inline bool hdr_present_name(const char *name) { return name && name[0] != '\0'; }

/* --- fix helpers for common header syntaxes --- */
static void fix_date_like(date_header_rtsp_t *h, const char *std_name) {
    if (!hdr_present_name(h->name)) return;
    if (std_name) set_cstr(h->name, sizeof(h->name), std_name);
    set_colon_space(h->colon_space);
    /* ", " 固定在 comma_space */
    h->comma_space[0] = ',', h->comma_space[1] = ' ', h->comma_space[2] = '\0';
    /* 中间的空格位 */
    h->space1 = ' '; h->space2 = ' '; h->space3 = ' '; h->space4 = ' ';
    set_cstr(h->gmt, sizeof(h->gmt), "GMT");
    set_crlf(h->crlf);
}

static int str_ieq(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

static void fix_accept(accept_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Accept");
    set_colon_space(h->colon_space);
    if (h->slash != '/') h->slash = '/';
    set_crlf(h->crlf);
}

static void fix_accept_encoding(accept_encoding_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Accept-Encoding");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}

static void fix_accept_language(accept_language_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Accept-Language");
    set_colon_space(h->colon_space);
    if (h->entry_count < 0) h->entry_count = 0;
    if (h->entry_count > MAX_ACCEPT_LANG) h->entry_count = MAX_ACCEPT_LANG;
    /* 压紧：删除空 language_tag */
    int w = 0;
    for (int r = 0; r < h->entry_count; r++) {
        if (h->entries[r].language_tag[0]) {
            if (w != r) h->entries[w] = h->entries[r];
            w++;
        }
    }
    h->entry_count = w;
    set_crlf(h->crlf);
}

static void fix_content_type(content_type_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Type");
    set_colon_space(h->colon_space);
    if (h->slash != '/') h->slash = '/';
    set_crlf(h->crlf);
}

static void fix_content_encoding(content_encoding_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Encoding");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}
static void fix_content_language(content_language_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Language");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}
static void fix_content_length(content_length_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Length");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}
static void fix_content_base(content_base_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Base");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}
static void fix_content_location(content_location_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Content-Location");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}

static void fix_connection(connection_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Connection");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}

static void fix_cseq(cseq_header_rtsp_t *h) {
    /* CSeq 属于必选，如果 name 为空，我们也创建一个最小可用的 */
    if (!hdr_present_name(h->name)) set_cstr(h->name, sizeof(h->name), "CSeq");
    set_cstr(h->name, sizeof(h->name), "CSeq");
    set_colon_space(h->colon_space);
    if (h->number < 1) h->number = 1;
    set_crlf(h->crlf);
}

static void fix_via(via_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Via");
    set_colon_space(h->colon_space);
    if (!h->space) h->space = ' ';
    set_crlf(h->crlf);
}

static void fix_range(range_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Range");
    set_colon_space(h->colon_space);
    set_cstr(h->unit, sizeof(h->unit), "npt");
    if (h->equals != '=') h->equals = '=';
    if (h->dash   != '-') h->dash   = '-';
    set_crlf(h->crlf);
}

static void fix_session(session_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Session");
    set_colon_space(h->colon_space);
    if (h->timeout > 0) {
        if (h->semicolon_timeout[0] == '\0') set_cstr(h->semicolon_timeout, sizeof(h->semicolon_timeout), ";timeout=");
    } else {
        h->semicolon_timeout[0] = '\0';
        h->timeout = 0;
    }
    set_crlf(h->crlf);
}

static void fix_transport(transport_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Transport");
    set_colon_space(h->colon_space);
    if (!h->protocol[0]) set_cstr(h->protocol, sizeof(h->protocol), "RTP/AVP");
    if (!h->cast_mode[0]) set_cstr(h->cast_mode, sizeof(h->cast_mode), "unicast");
    if (!h->client_port_prefix[0]) set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "client_port=");
    if (!h->port_range[0]) set_cstr(h->port_range, sizeof(h->port_range), "8000-8001");
    h->semicolon1 = ';';
    h->semicolon2 = ';';
    set_crlf(h->crlf);
}

static void fix_authorization(authorization_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Authorization");
    set_colon_space(h->colon_space);
    if (!h->space) h->space = ' ';
    set_crlf(h->crlf);
}

static void fix_blocksize(blocksize_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Blocksize");
    set_colon_space(h->colon_space);
    if (h->value < 0) h->value = 0;
    set_crlf(h->crlf);
}

static void fix_bandwidth(bandwidth_header_rtsp_t *h) {
    if (!hdr_present_name(h->name)) return;
    set_cstr(h->name, sizeof(h->name), "Bandwidth");
    set_colon_space(h->colon_space);
    if (h->value < 0) h->value = 0;
    set_crlf(h->crlf);
}

static void fix_simple_name_cs_crlf(char *name, size_t cap_name, const char *std_name,
                                    char colon_space[RTSP_SEPARATOR_LEN], char crlf[RTSP_CRLF_LEN]) {
    if (!hdr_present_name(name)) return;
    set_cstr(name, cap_name, std_name);
    set_colon_space(colon_space);
    set_crlf(crlf);
}

/* --- fix start-line (method/URI/version) --- */
static void fix_start_line(char *method, size_t mcap,
                           char *space1, char *space2,
                           char *version, size_t vcap,
                           char crlf1[RTSP_CRLF_LEN],
                           const char *std_method) {
    set_cstr(method, mcap, std_method);
    if (space1) *space1 = ' ';
    if (space2) *space2 = ' ';
    set_cstr(version, vcap, "RTSP/1.0");
    set_crlf(crlf1);
}

/* --- body-length glue --- */
static void sync_content_length_with_body(content_length_header_rtsp_t *cl, const char *body) {
    size_t len = (body && body[0]) ? strlen(body) : 0;
    if (len == 0) {
        /* 约定：body 为空则可以把 Content-Length 清空（不打印） */
        cl->name[0] = '\0';
        cl->length = 0;
        set_crlf(cl->crlf);
        set_colon_space(cl->colon_space);
        return;
    }
    if (!hdr_present_name(cl->name)) set_cstr(cl->name, sizeof(cl->name), "Content-Length");
    set_colon_space(cl->colon_space);
    cl->length = (int)len;
    set_crlf(cl->crlf);
}



/* =============== per-message fixers =============== */
static void fix_options(rtsp_options_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "OPTIONS");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);

    set_crlf(p->end_crlf);
}

static void fix_setup(rtsp_setup_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "SETUP");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_simple_name_cs_crlf(p->cache_control_header.name, sizeof(p->cache_control_header.name), "Cache-Control", p->cache_control_header.colon_space, p->cache_control_header.crlf);
    fix_simple_name_cs_crlf(p->conference_header.name, sizeof(p->conference_header.name), "Conference", p->conference_header.colon_space, p->conference_header.crlf);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_date_like(&p->if_modified_since_header, "If-Modified-Since");
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);

    /* mandatory */
    if (!hdr_present_name(p->transport_header.name)) set_cstr(p->transport_header.name, sizeof(p->transport_header.name), "Transport");
    fix_transport(&p->transport_header);

    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_describe(rtsp_describe_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "DESCRIBE");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept(&p->accept_header);
    fix_accept_encoding(&p->accept_encoding_header);
    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_content_base(&p->content_base_header);
    fix_content_encoding(&p->content_encoding_header);
    fix_content_language(&p->content_language_header);
    fix_content_length(&p->content_length_header);
    fix_content_location(&p->content_location_header);
    fix_date_like(&p->expires_header, "Expires");
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_date_like(&p->if_modified_since_header, "If-Modified-Since");
    fix_date_like(&p->last_modified_header, "Last-Modified");
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_play(rtsp_play_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "PLAY");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_range(&p->range_header);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_simple_name_cs_crlf(p->scale_header.name, sizeof(p->scale_header.name), "Scale", p->scale_header.colon_space, p->scale_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->speed_header.name, sizeof(p->speed_header.name), "Speed", p->speed_header.colon_space, p->speed_header.crlf);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_pause(rtsp_pause_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "PAUSE");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_range(&p->range_header);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_teardown(rtsp_teardown_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "TEARDOWN");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_get_parameter(rtsp_get_parameter_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "GET_PARAMETER");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept(&p->accept_header);
    fix_accept_encoding(&p->accept_encoding_header);
    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_content_base(&p->content_base_header);
    fix_content_length(&p->content_length_header);
    fix_content_location(&p->content_location_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_date_like(&p->last_modified_header, "Last-Modified");
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_set_parameter(rtsp_set_parameter_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "SET_PARAMETER");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_content_encoding(&p->content_encoding_header);
    /* body 相关：优先同步长度；若有 Content-Type 也修正 */
    fix_content_type(&p->content_type_header);
    sync_content_length_with_body(&p->content_length_header, p->body);

    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_redirect(rtsp_redirect_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "REDIRECT");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_announce(rtsp_announce_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "ANNOUNCE");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_content_encoding(&p->content_encoding_header);
    fix_content_language(&p->content_language_header);
    fix_content_type(&p->content_type_header);
    /* 同步长度 */
    sync_content_length_with_body(&p->content_length_header, p->body);

    fix_date_like(&p->expires_header, "Expires");
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}

static void fix_record(rtsp_record_packet_t *p) {
    fix_start_line(p->method, sizeof(p->method), &p->space1, &p->space2, p->rtsp_version, sizeof(p->rtsp_version), p->crlf1, "RECORD");
    fix_cseq(&p->cseq_header);
    fix_connection(&p->connection_header);
    fix_date_like(&p->date_header, "Date");
    fix_via(&p->via_header);

    fix_accept_language(&p->accept_language_header);
    fix_authorization(&p->authorization_header);
    fix_bandwidth(&p->bandwidth_header);
    fix_blocksize(&p->blocksize_header);
    fix_simple_name_cs_crlf(p->from_header.name, sizeof(p->from_header.name), "From", p->from_header.colon_space, p->from_header.crlf);
    fix_simple_name_cs_crlf(p->proxy_require_header.name, sizeof(p->proxy_require_header.name), "Proxy-Require", p->proxy_require_header.colon_space, p->proxy_require_header.crlf);
    fix_range(&p->range_header);
    fix_simple_name_cs_crlf(p->referer_header.name, sizeof(p->referer_header.name), "Referer", p->referer_header.colon_space, p->referer_header.crlf);
    fix_simple_name_cs_crlf(p->require_header.name, sizeof(p->require_header.name), "Require", p->require_header.colon_space, p->require_header.crlf);
    fix_simple_name_cs_crlf(p->scale_header.name, sizeof(p->scale_header.name), "Scale", p->scale_header.colon_space, p->scale_header.crlf);
    fix_session(&p->session_header);
    fix_simple_name_cs_crlf(p->user_agent_header.name, sizeof(p->user_agent_header.name), "User-Agent", p->user_agent_header.colon_space, p->user_agent_header.crlf);
    set_crlf(p->end_crlf);
}


/* ===================== 工具函数 ===================== */

static inline void safe_copy(char *dst, size_t dstsz, const char *src) {
    if (!dst || dstsz == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int has_scheme_prefix(const char *s) {
    // 简单判定：scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    if (!s || !isalpha((unsigned char)*s)) return 0;
    const char *p = s + 1;
    while (*p && *p != ':' ) {
        if (!(isalnum((unsigned char)*p) || *p=='+' || *p=='-' || *p=='.')) return 0;
        ++p;
    }
    return (*p == ':');
}

static int is_absolute_uri(const char *s) {
    // 允许 rtsp://, rtsps:// 等，宽松判断：存在 "://"
    if (!s) return 0;
    const char *p = strstr(s, "://");
    return (p && p > s && has_scheme_prefix(s));
}

static int is_star_uri(const char *s) {
    return s && s[0] == '*' && s[1] == '\0';
}

static const char *strip_to_authority_end(const char *abs_base) {
    // 从绝对 URI 中返回 authority 之后的第一个 '/'（若存在）
    // 形如: rtsp://host:port/path -> 指向 '/path'
    const char *p = strstr(abs_base, "://");
    if (!p) return NULL;
    p += 3; // 跳过 ://
    while (*p && *p != '/') ++p;
    return p; // 可能指向 '\0'
}

static void join_uri(const char *abs_base, const char *rel, char *out, size_t outsz) {
    // 基于 RFC 风格的非常简化拼接：
    // - 若 rel 是绝对 URI：直接复制
    // - 若 rel 以 '/' 开头： scheme://authority + rel
    // - 否则：取 base 的“目录” + "/" + rel
    if (!rel || !*rel) { safe_copy(out, outsz, abs_base ? abs_base : "rtsp://localhost/"); return; }
    if (is_absolute_uri(rel)) { safe_copy(out, outsz, rel); return; }

    const char *base = (abs_base && is_absolute_uri(abs_base)) ? abs_base : "rtsp://localhost/";
    const char *p = strstr(base, "://");
    if (!p) { safe_copy(out, outsz, "rtsp://localhost/"); return; }
    p += 3; // host[:port]...
    const char *path = p;
    while (*path && *path != '/') ++path;

    if (rel[0] == '/') {
        // scheme://authority + rel
        size_t prefix_len = (size_t)(path - base);
        if (prefix_len + strlen(rel) + 1 > outsz) prefix_len = (outsz>1)? outsz-1 : 0;
        memcpy(out, base, prefix_len);
        out[prefix_len] = '\0';
        strncat(out, rel, outsz - 1 - strlen(out));
    } else {
        // 目录拼接：去掉 base 的文件部分，保留末尾 '/'
        const char *last_slash = strrchr(path, '/');
        size_t dir_len;
        if (last_slash) {
            dir_len = (size_t)(last_slash - base + 1); // 保留 '/'
        } else {
            dir_len = (size_t)(path - base);
            // 若 base 没有 path，则补一个 '/'
            if (dir_len + 1 < outsz) ++dir_len;
        }
        if (dir_len >= outsz) dir_len = outsz - 1;
        memcpy(out, base, dir_len);
        out[dir_len] = '\0';
        strncat(out, rel, outsz - 1 - strlen(out));
    }
}

static int method_allows_star(rtsp_type_t t) {
    // 仅 OPTIONS 允许 "*"（服务器能力查询）
    return (t == RTSP_TYPE_OPTIONS);
}

/* 取同包内的 Content-Base（若存在且为绝对 URI），否则返回 NULL */
static const char* get_content_base_if_abs_from_packet(const rtsp_packet_t* pkt) {
    switch (pkt->type) {
        case RTSP_TYPE_DESCRIBE:
            if (is_absolute_uri(pkt->describe.content_base_header.uri) && pkt->describe.content_base_header.uri[0])
                return pkt->describe.content_base_header.uri;
            return NULL;
        case RTSP_TYPE_GET_PARAMETER:
            if (is_absolute_uri(pkt->get_parameter.content_base_header.uri) && pkt->get_parameter.content_base_header.uri[0])
                return pkt->get_parameter.content_base_header.uri;
            return NULL;
        default:
            return NULL;
    }
}

/* 统一修复单个 request_uri；按需使用 content_base 与 last_abs_base */
static void fix_request_uri_of_packet(rtsp_packet_t* pkt, char last_abs_base[RTSP_URI_LEN]) {
    if (!pkt) return;

    // 1) 取得指向 request_uri 的指针
    char *req_uri = NULL;
    switch (pkt->type) {
        case RTSP_TYPE_OPTIONS:       req_uri = pkt->options.request_uri; break;
        case RTSP_TYPE_DESCRIBE:      req_uri = pkt->describe.request_uri; break;
        case RTSP_TYPE_SETUP:         req_uri = pkt->setup.request_uri; break;
        case RTSP_TYPE_PLAY:          req_uri = pkt->play.request_uri; break;
        case RTSP_TYPE_PAUSE:         req_uri = pkt->pause.request_uri; break;
        case RTSP_TYPE_TEARDOWN:      req_uri = pkt->teardown.request_uri; break;
        case RTSP_TYPE_GET_PARAMETER: req_uri = pkt->get_parameter.request_uri; break;
        case RTSP_TYPE_SET_PARAMETER: req_uri = pkt->set_parameter.request_uri; break;
        case RTSP_TYPE_REDIRECT:      req_uri = pkt->redirect.request_uri; break;
        case RTSP_TYPE_ANNOUNCE:      req_uri = pkt->announce.request_uri; break;
        case RTSP_TYPE_RECORD:        req_uri = pkt->record.request_uri; break;
        default: return;
    }
    if (!req_uri) return;

    // 2) 若为 "*"：仅当方法允许；否则改为可推导的绝对 URI
    if (is_star_uri(req_uri)) {
        if (method_allows_star(pkt->type)) {
            // OPTIONS * : 合法，且不更新 last_abs_base
            return;
        }
        // 其他方法不允许 "*": 用 base 替换
        const char *cb = get_content_base_if_abs_from_packet(pkt);
        const char *base = cb ? cb : (last_abs_base[0] ? last_abs_base : "rtsp://localhost/");
        safe_copy(req_uri, RTSP_URI_LEN, base);
    }

    // 3) 若不是绝对 URI：用 base 进行拼接
    if (!is_absolute_uri(req_uri)) {
        const char *cb = get_content_base_if_abs_from_packet(pkt);
        const char *base = cb ? cb : (last_abs_base[0] ? last_abs_base : "rtsp://localhost/");
        char fixed[RTSP_URI_LEN];
        join_uri(base, req_uri, fixed, sizeof(fixed));
        safe_copy(req_uri, RTSP_URI_LEN, fixed);
    }

    // 4) 现在应为绝对 URI；更新 last_abs_base
    if (is_absolute_uri(req_uri)) {
        // 对于后续相对路径拼接，保存“基址”。这里直接保存当前绝对 URI。
        safe_copy(last_abs_base, RTSP_URI_LEN, req_uri);
    }
}

/* ===================== 对外入口 ===================== */

/**
 * 修复规则（SHOT-2）：
 * 1) Request-URI 必须为绝对 URI；
 * 2) 只有 OPTIONS 允许使用 "*" 形式；其他方法若见到 "*"，将替换为推导出的绝对 URI。
 * 3) 相对 URI 优先用同包 Content-Base，其次用扫描过程中最近一次的绝对 URI，再次兜底 "rtsp://localhost/"。
 */
void rtsp_fix_absolute_uri_on_packets(rtsp_packet_t* arr, size_t count) {
    if (!arr) return;
    char last_abs_base[RTSP_URI_LEN]; last_abs_base[0] = '\0';

    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t* pkt = &arr[i];
        fix_request_uri_of_packet(pkt, last_abs_base);
    }
}




/* 计算“C 风格字符串”体的已用长度（最多 MAX_RTSP_BODY_LEN）。
   若消息体在本表示中允许包含 '\0'，则需改为显式长度字段；当前头文件用 char[] 承载，按 C 字符串处理。 */
static inline int body_used_len(const char *buf, size_t cap) {
    if (!buf) return 0;
    size_t n = 0;
    while (n < cap && buf[n] != '\0') ++n;
    return (int)n;
}

static inline void write_content_length_header(content_length_header_rtsp_t *h, int len) {
    if (!h) return;
    if (len < 0) len = 0;
    set_cstr(h->name,        sizeof(h->name),        "Content-Length");
    /* 该结构已预留了冒号+空格的缓冲区 */
    if (sizeof(h->colon_space) >= 3) {
        h->colon_space[0] = ':'; h->colon_space[1] = ' '; h->colon_space[2] = '\0';
    }
    h->length = len;
    set_crlf(h->crlf);
}

/* -------------- per-type fix -------------- */

static inline void fix_describe_content_length(rtsp_describe_packet_t *p) {
    /* 没有 body 字段：若出现 Content-Length，则应为 0（保持兼容也可视为显式声明无实体） */
    write_content_length_header(&p->content_length_header, 0);
}

static inline void fix_get_parameter_content_length(rtsp_get_parameter_packet_t *p) {
    /* 在该结构中无 body 字段，统一写 0 */
    write_content_length_header(&p->content_length_header, 0);
}

static inline void fix_set_parameter_content_length(rtsp_set_parameter_packet_t *p) {
    /* SET_PARAMETER 可携带消息体（参数），按实际已用长度填写 */
    int used = body_used_len(p->body, MAX_RTSP_BODY_LEN);
    write_content_length_header(&p->content_length_header, used);
    /* 可选：若没有内容也建议把 Content-Type/Encoding 保持一致，但本规则不强制 */
}

static inline void fix_announce_content_length(rtsp_announce_packet_t *p) {
    /* ANNOUNCE 可携带 SDP 或参数体 */
    int used = body_used_len(p->body, MAX_RTSP_BODY_LEN);
    write_content_length_header(&p->content_length_header, used);
}

/* -------------- public entry -------------- */
/* SHOT-3: 任何携带实体的 RTSP 报文必须带 Content-Length；若无实体则为 0；不支持 chunked。 */
void rtsp_fix_content_length_on_packets(rtsp_packet_t *arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t *pkt = &arr[i];
        switch (pkt->type) {
            case RTSP_TYPE_DESCRIBE:      fix_describe_content_length(&pkt->describe); break;
            case RTSP_TYPE_GET_PARAMETER: fix_get_parameter_content_length(&pkt->get_parameter); break;
            case RTSP_TYPE_SET_PARAMETER: fix_set_parameter_content_length(&pkt->set_parameter); break;
            case RTSP_TYPE_ANNOUNCE:      fix_announce_content_length(&pkt->announce); break;
            /* 无 body 的类型不必强制生成 Content-Length；缺省即 0 */
            case RTSP_TYPE_OPTIONS:
            case RTSP_TYPE_SETUP:
            case RTSP_TYPE_PLAY:
            case RTSP_TYPE_PAUSE:
            case RTSP_TYPE_TEARDOWN:
            case RTSP_TYPE_REDIRECT:
            case RTSP_TYPE_RECORD:
            case RTSP_TYPE_UNKNOWN:
            default:
                break;
        }
    }
}
static inline void normalize_cseq_header(cseq_header_rtsp_t *h) {
    if (!h) return;
    set_cstr(h->name, RTSP_HEADER_NAME_LEN, "CSeq");
    if (RTSP_SEPARATOR_LEN >= 2) { h->colon_space[0] = ':'; h->colon_space[1] = ' '; }
    if (RTSP_SEPARATOR_LEN >= 3) h->colon_space[2] = '\0';
    if (h->number < 0) h->number = 0;   // 负数视为未设置
    set_crlf(h->crlf);
}

/* 取“方法、URI、SessionId（若有）”指针，以及 CSeq 头指针 */
typedef struct {
    const char *method;   // 指向包内 method
    char       *uri;      // 指向包内 request_uri（可写）
    const char *session;  // 指向包内 session_id（若存在且非空）
    cseq_header_rtsp_t *cseq; // 指向包内 cseq_header
} pkt_view_t;

static pkt_view_t view_of(rtsp_packet_t *pkt) {
    pkt_view_t v = {0};
    if (!pkt) return v;
    switch (pkt->type) {
        case RTSP_TYPE_OPTIONS:
            v.method  = pkt->options.method;
            v.uri     = pkt->options.request_uri;
            v.cseq    = &pkt->options.cseq_header;
            v.session = NULL; // OPTIONS 无 session
            break;
        case RTSP_TYPE_DESCRIBE:
            v.method  = pkt->describe.method;
            v.uri     = pkt->describe.request_uri;
            v.cseq    = &pkt->describe.cseq_header;
            v.session = NULL; // DESCRIBE 可无 session
            break;
        case RTSP_TYPE_SETUP:
            v.method  = pkt->setup.method;
            v.uri     = pkt->setup.request_uri;
            v.cseq    = &pkt->setup.cseq_header;
            v.session = NULL; // SETUP 前通常没有 session
            break;
        case RTSP_TYPE_PLAY:
            v.method  = pkt->play.method;
            v.uri     = pkt->play.request_uri;
            v.cseq    = &pkt->play.cseq_header;
            v.session = pkt->play.session_header.session_id[0] ? pkt->play.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_PAUSE:
            v.method  = pkt->pause.method;
            v.uri     = pkt->pause.request_uri;
            v.cseq    = &pkt->pause.cseq_header;
            v.session = pkt->pause.session_header.session_id[0] ? pkt->pause.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_TEARDOWN:
            v.method  = pkt->teardown.method;
            v.uri     = pkt->teardown.request_uri;
            v.cseq    = &pkt->teardown.cseq_header;
            v.session = pkt->teardown.session_header.session_id[0] ? pkt->teardown.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_GET_PARAMETER:
            v.method  = pkt->get_parameter.method;
            v.uri     = pkt->get_parameter.request_uri;
            v.cseq    = &pkt->get_parameter.cseq_header;
            v.session = pkt->get_parameter.session_header.session_id[0] ? pkt->get_parameter.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_SET_PARAMETER:
            v.method  = pkt->set_parameter.method;
            v.uri     = pkt->set_parameter.request_uri;
            v.cseq    = &pkt->set_parameter.cseq_header;
            v.session = pkt->set_parameter.session_header.session_id[0] ? pkt->set_parameter.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_REDIRECT:
            v.method  = pkt->redirect.method;
            v.uri     = pkt->redirect.request_uri;
            v.cseq    = &pkt->redirect.cseq_header;
            v.session = pkt->redirect.session_header.session_id[0] ? pkt->redirect.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_ANNOUNCE:
            v.method  = pkt->announce.method;
            v.uri     = pkt->announce.request_uri;
            v.cseq    = &pkt->announce.cseq_header;
            v.session = pkt->announce.session_header.session_id[0] ? pkt->announce.session_header.session_id : NULL;
            break;
        case RTSP_TYPE_RECORD:
            v.method  = pkt->record.method;
            v.uri     = pkt->record.request_uri;
            v.cseq    = &pkt->record.cseq_header;
            v.session = pkt->record.session_header.session_id[0] ? pkt->record.session_header.session_id : NULL;
            break;
        default: break;
    }
    return v;
}

/* 对“同一请求”的轻量指纹（方法 + SP + URI + SP + sessionId） */
typedef struct {
    char key[RTSP_METHOD_LEN + 1 + RTSP_URI_LEN + 1 + 64]; // 充足余量
    int  cseq;
} key_cseq_pair_t;

static void make_req_key(const pkt_view_t *v, char out[], size_t outsz) {
    out[0] = '\0';
    if (!v || !v->method || !v->uri) return;
    strncat(out, v->method, outsz - 1 - strlen(out));
    strncat(out, " ", outsz - 1 - strlen(out));
    strncat(out, v->uri, outsz - 1 - strlen(out));
    if (v->session && v->session[0]) {
        strncat(out, " ", outsz - 1 - strlen(out));
        strncat(out, v->session, outsz - 1 - strlen(out));
    }
}

/* 在线性表里查找/记录（最多 count 个，足够用于本修复场景） */
static int find_key(const key_cseq_pair_t *tab, size_t n, const char *key) {
    for (size_t i = 0; i < n; ++i) {
        if (tab[i].key[0] == '\0') continue;
        if (strcmp(tab[i].key, key) == 0) return (int)i;
    }
    return -1;
}

/* ================= 对外入口 ================= */

/**
 * SHOT-5 修复器：
 * - 所有请求保证存在合法 CSeq 头字段；
 * - 同一请求（方法+URI+Session）重传复用首次 CSeq；
 * - 若 CSeq 缺失或 <=0，则分配递增序号（从 1 起）。
 */
void rtsp_fix_cseq_on_packets(rtsp_packet_t *arr, size_t count) {
    if (!arr) return;

    key_cseq_pair_t map[/*max*/ 1024];
    size_t map_cap = sizeof(map)/sizeof(map[0]);
    size_t map_len = 0;

    int last_assigned = 0;

    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t *pkt = &arr[i];
        pkt_view_t v = view_of(pkt);
        if (!v.cseq || !v.method || !v.uri) continue;

        /* 1) 规范化 CSeq 头形态（name/": "/CRLF） */
        normalize_cseq_header(v.cseq);

        /* 2) 为该请求生成 key；查是否已有（视为重传） */
        char keybuf[sizeof(map[0].key)];
        make_req_key(&v, keybuf, sizeof(keybuf));

        int idx = find_key(map, map_len, keybuf);
        if (idx >= 0) {
            /* 重传：强制复用第一次的 CSeq */
            v.cseq->number = map[idx].cseq;
            continue;
        }

        /* 3) 首次出现：决定 CSeq 值
              - 若已有正数，保留并更新 last_assigned；
              - 否则分配 last_assigned+1。 */
        int chosen = (v.cseq->number > 0) ? v.cseq->number : (last_assigned + 1);
        if (chosen <= 0) chosen = 1;
        v.cseq->number = chosen;
        if (chosen > last_assigned) last_assigned = chosen;

        /* 4) 记录 key -> CSeq，用于后续重传复用 */
        if (map_len < map_cap) {
            set_cstr(map[map_len].key, sizeof(map[map_len].key), keybuf);
            map[map_len].cseq = chosen;
            ++map_len;
        }
    }
}

static int ieq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* 解析 "N" 或 "N-M"；返回 0 成功；失败返回 -1 */
static int parse_port_range(const char *s, int *p1, int *p2) {
    if (!s || !*s) return -1;
    int a = -1, b = -1;
    const char *dash = strchr(s, '-');
    if (!dash) {
        if (sscanf(s, "%d", &a) != 1) return -1;
    } else {
        if (sscanf(s, "%d-%d", &a, &b) < 1) return -1;
    }
    if (a < 0 || a > 65535) return -1;
    if (dash) {
        if (b < 0 || b > 65535) b = -1;  // 稍后修复
    }
    *p1 = a; *p2 = b;
    return 0;
}

static void format_port_range(char *buf, size_t cap, int p1, int p2 /* -1 = 单端口*/ ) {
    if (p2 < 0) snprintf(buf, cap, "%d", p1);
    else        snprintf(buf, cap, "%d-%d", p1, p2);
}

/* 约束修正：若为端口对，则使用偶数-奇数（N, N+1）；若为单端口，则改为 N-(N+1) */
static void normalize_ports(char *port_range /*16*/) {
    int p1 = -1, p2 = -1;
    if (parse_port_range(port_range, &p1, &p2) != 0) {
        // 无效 -> 回退默认
        set_cstr(port_range, 16, "5000-5001");
        return;
    }
    // 单端口视为需要 RTCP 邻接端口
    if (p2 < 0) p2 = p1 + 1;

    // 边界修正
    if (p1 < 0 || p1 > 65534) p1 = 5000;
    if (p2 != p1 + 1) p2 = p1 + 1;

    // 偶数-奇数
    if (p1 % 2 != 0) {           // p1 必须为偶数
        if (p1 > 0) --p1; else ++p1;
        p2 = p1 + 1;
    }
    if (p2 != p1 + 1) p2 = p1 + 1;

    format_port_range(port_range, 16, p1, p2);
}

/* 规范化 protocol：仅允许 RTP/AVP[/UDP|/TCP]；若看不出 TCP，就用 /UDP */
static void normalize_protocol(char *protocol /*16*/) {
    char tmp[16]; set_cstr(tmp, sizeof(tmp), protocol);
    // 粗略判断是否已有 "/TCP"
    int has_tcp = (strstr(tmp, "/TCP") || strstr(tmp, "/Tcp") || strstr(tmp, "/tcp")) ? 1 : 0;
    int has_udp = (strstr(tmp, "/UDP") || strstr(tmp, "/Udp") || strstr(tmp, "/udp")) ? 1 : 0;

    if (has_tcp) set_cstr(protocol, 16, "RTP/AVP/TCP");
    else if (has_udp) set_cstr(protocol, 16, "RTP/AVP/UDP");
    else {
        // 若存在 client_port，我们默认 UDP；否则退化到 RTP/AVP
        set_cstr(protocol, 16, "RTP/AVP/UDP");
    }
}

/* 规范化 cast_mode：仅 unicast/multicast，默认 unicast */
static void normalize_cast_mode(char *cast_mode /*16*/) {
    if (ieq(cast_mode, "multicast")) { set_cstr(cast_mode, 16, "multicast"); return; }
    set_cstr(cast_mode, 16, "unicast");
}

/* 规范化整条 Transport 头（按当前结构字段能力） */
static void fix_transport_header(transport_header_rtsp_t *h) {
    if (!h) return;

    // 名称、分隔符、CRLF
    set_cstr(h->name, RTSP_HEADER_NAME_LEN, "Transport");
    if (RTSP_SEPARATOR_LEN >= 2) { h->colon_space[0] = ':'; h->colon_space[1] = ' '; }
    if (RTSP_SEPARATOR_LEN >= 3)   h->colon_space[2] = '\0';
    set_crlf(h->crlf);

    // 分号固定
    h->semicolon1 = ';';
    h->semicolon2 = ';';

    // 协议与 cast_mode
    normalize_protocol(h->protocol);
    normalize_cast_mode(h->cast_mode);

    // client_port= 前缀
    set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "client_port=");

    // 端口/端口对合法化
    normalize_ports(h->port_range);
}

/* ---------------- 对外入口 ---------------- */

/**
 * SHOT-8: 规范 SETUP Transport 头的语法/取值范围（在数据结构允许的范围内）。
 * - 协议限定为 RTP/AVP[/UDP|/TCP]
 * - cast_mode 仅 unicast/multicast
 * - client_port 为合法的端口或端口对；若为端口对则修正为 偶-奇 (N, N+1)
 * - 名称/分隔符/分号/CRLF 规范化
 */
void rtsp_fix_transport_on_packets(rtsp_packet_t *arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t *pkt = &arr[i];
        if (pkt->type == RTSP_TYPE_SETUP) {
            fix_transport_header(&pkt->setup.transport_header);
        }
    }
}

static int has_token_ci(const char* s, const char* token) {
    if (!s || !token) return 0;
    size_t n = strlen(token);
    for (const char* p = s; *p; ++p) {
        if (strncasecmp(p, token, n) == 0) return 1;
    }
    return 0;
}

/* 端口/通道区段解析与格式化："N" 或 "N-M"；返回 0 成功 */
static int parse_range_pair(const char *s, int *a, int *b) {
    if (!s || !*s) return -1;
    int x = -1, y = -1;
    const char* dash = strchr(s, '-');
    if (!dash) { if (sscanf(s, "%d", &x) != 1) return -1; }
    else       { if (sscanf(s, "%d-%d", &x, &y) < 1) return -1; }
    *a = x; *b = y;
    return 0;
}
static void format_range_pair(char *buf, size_t cap, int a, int b /*若 b<0 表示单值*/) {
    if (b < 0) snprintf(buf, cap, "%d", a);
    else       snprintf(buf, cap, "%d-%d", a, b);
}

/* UDP: 端口修正为偶数-奇数对；单端口自动补邻接端口；非法回默认 */
static void normalize_udp_ports(char *port_range /*16*/) {
    int p1=-1, p2=-1;
    if (parse_range_pair(port_range, &p1, &p2) != 0) { set_cstr(port_range, 16, "5000-5001"); return; }
    if (p1 < 0 || p1 > 65534) { set_cstr(port_range, 16, "5000-5001"); return; }
    if (p2 < 0) p2 = p1 + 1;
    if (p2 != p1 + 1) p2 = p1 + 1;
    if (p1 % 2 != 0) { p1 = (p1>0) ? (p1-1) : 0; p2 = p1 + 1; }
    format_range_pair(port_range, 16, p1, p2);
}

/* TCP: interleaved 通道修正为偶-奇对，范围 0..255；单值自动补邻接通道 */
static void normalize_tcp_interleaved(char *range /*16*/, int *next_ch /*in/out*/) {
    int c1=-1, c2=-1;
    if (parse_range_pair(range, &c1, &c2) != 0 || c1 < 0 || c1 > 255) {
        // 分配新的
        int n = (*next_ch < 0) ? 0 : *next_ch;
        if (n > 254) n = 0;            // 环回
        c1 = (n % 2 == 0) ? n : (n-1); // 确保偶数起
        if (c1 < 0) c1 = 0;
        c2 = c1 + 1;
    } else {
        // 既有值：补成偶-奇对并界限化
        if (c2 < 0) c2 = c1 + 1;
        if (c1 % 2 != 0) { --c1; c2 = c1 + 1; }
        if (c1 < 0) c1 = 0;
        if (c2 != c1 + 1) c2 = c1 + 1;
        if (c2 > 255) { c1 = 254; c2 = 255; }
    }
    format_range_pair(range, 16, c1, c2);

    // 更新下一对（+2）
    if (next_ch) {
        int n = c1 + 2;
        if (n > 254) n = 0;
        *next_ch = n;
    }
}

/* 统一化 Transport 头的公共部分（名字、分隔符、分号、CRLF） */
static void normalize_transport_header_common(transport_header_rtsp_t *h) {
    set_cstr(h->name, RTSP_HEADER_NAME_LEN, "Transport");
    if (RTSP_SEPARATOR_LEN >= 2) { h->colon_space[0] = ':'; h->colon_space[1] = ' '; }
    if (RTSP_SEPARATOR_LEN >= 3)   h->colon_space[2] = '\0';
    h->semicolon1 = ';';
    h->semicolon2 = ';';
    set_crlf(h->crlf);
}


/* ----------------- 核心：对数组就地修复 ----------------- */
/* SHOT-9: 
 * - TCP 复用：Transport 使用 interleaved= 偶-奇通道对（0..255），每个 '$' 块一帧上层 PDU；
 * - UDP：Transport 使用 client_port= 偶-奇端口对；
 * - 不生成 CRLF 的 '$' 数据帧（仅工具函数提供打包能力）。
 */
void rtsp_fix_interleaved_on_packets(rtsp_packet_t *arr, size_t count) {
    if (!arr) return;

    int next_interleaved_ch = 0;  // 跨多个 SETUP 顺序分配 0-1, 2-3, ...

    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t *pkt = &arr[i];
        if (pkt->type != RTSP_TYPE_SETUP) continue;

        transport_header_rtsp_t *h = &pkt->setup.transport_header;

        normalize_transport_header_common(h);
        normalize_protocol(h->protocol);
        normalize_cast_mode(h->cast_mode);

        if (str_ieq(h->protocol, "RTP/AVP/TCP")) {
            // TCP 复用：启用 interleaved=
            set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "interleaved=");
            // 规范/分配通道对
            normalize_tcp_interleaved(h->port_range, &next_interleaved_ch);
        } else {
            // UDP：回退/保持 client_port=
            set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "client_port=");
            normalize_udp_ports(h->port_range);
        }
    }
}

/* --------------- 可选：把一帧上层 PDU 封成 "$" 块 --------------- */
/* 输出格式: '$'(0x24) + channel(1B) + length(2B, network order) + payload(长度=length)
 * 返回总输出字节数；若 out_cap 不足返回 -1。 */
int rtsp_make_dollar_frame(uint8_t channel, const uint8_t* pdu, uint16_t pdu_len,
                           uint8_t *out, size_t out_cap)
{
    if (!out || (!pdu && pdu_len)) return -1;
    if (out_cap < (size_t)(4 + pdu_len)) return -1;

    out[0] = 0x24;          // '$'
    out[1] = channel;       // channel
    out[2] = (uint8_t)(pdu_len >> 8);  // length high
    out[3] = (uint8_t)(pdu_len & 0xFF);// length low
    if (pdu_len) memcpy(out + 4, pdu, pdu_len);
    return (int)(4 + pdu_len);
}

static inline void trim_inplace(char *s) {
    if (!s) return;
    // 左裁空白
    size_t i = 0; while (s[i] && isspace((unsigned char)s[i])) ++i;
    if (i) memmove(s, s + i, strlen(s + i) + 1);
    // 右裁空白
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) --n;
    s[n] = '\0';
}
static int is_all_empty(const char *a) { return !a || !*a; }
static int unit_eq(const char *a, const char *b) {
    if (!a || !b) return 0; while (*a && *b) { if (tolower((unsigned char)*a)!=tolower((unsigned char)*b)) return 0; ++a; ++b; }
    return *a=='\0' && *b=='\0';
}

/* npt: 支持十进制 ("12.345")；"now" 原样保留，不参与数值比较 */
static int parse_npt_seconds(const char *txt, double *out) {
    if (!txt || !*txt) return -1;
    if (strcasecmp(txt, "now") == 0) return 1; // 特判：保留 now
    char *endp = NULL;
    double v = strtod(txt, &endp);
    if (endp == txt) return -1;
    if (out) *out = v;
    return 0;
}

/* smpte: "hh:mm:ss[.frac]" 或 "hh:mm:ss;ff"（基本检查，尽量健壮） */
static int parse_smpte_seconds(const char *txt, double *out) {
    if (!txt || !*txt) return -1;
    int h=0,m=0; double s=0.0;
    int n = sscanf(txt, "%d:%d:%lf", &h, &m, &s);
    if (n == 3) { if (out) *out = (double)h*3600 + (double)m*60 + s; return 0; }
    // 支持 ;ff 的形态：忽略帧号
    int ss=0, ff=0;
    n = sscanf(txt, "%d:%d:%d;%d", &h, &m, &ss, &ff);
    if (n >= 3) { if (out) *out = (double)h*3600 + (double)m*60 + (double)ss; return 0; }
    return -1;
}

/* 统一 Range 头字段形态 + 左闭右开策略 */
static void normalize_range_header(range_header_rtsp_t *h) {
    if (!h) return;

    /* 头部形态 */
    set_cstr(h->name, RTSP_HEADER_NAME_LEN, "Range");
    if (RTSP_SEPARATOR_LEN >= 2) { h->colon_space[0] = ':'; h->colon_space[1] = ' '; }
    if (RTSP_SEPARATOR_LEN >= 3)   h->colon_space[2] = '\0';
    if (h->equals != '=') h->equals = '=';
    if (h->dash   != '-') h->dash   = '-';
    set_crlf(h->crlf);

    /* 单位规范：仅保留 npt/smpte/clock；其他一律回退 npt */
    if (!unit_eq(h->unit, "npt") && !unit_eq(h->unit, "smpte") && !unit_eq(h->unit, "clock")) {
        set_cstr(h->unit, sizeof(h->unit), "npt");
    }

    /* 去除首尾空白 */
    trim_inplace(h->start);
    trim_inplace(h->end);

    /* 左闭右开语义的数值校正（能解析才比较） */
    if (unit_eq(h->unit, "npt")) {
        double a=0.0, b=0.0;
        int pa = parse_npt_seconds(h->start, &a);   // 0=ok, 1=now, -1=bad/empty
        int pb = parse_npt_seconds(h->end,   &b);
        if (pa == 0 && pb == 0) {
            if (b <= a) { h->end[0] = '\0'; }  // 变为 open-ended: npt=a-
        }
        // "now" 出现时不做比较；仅保持形态
    } else if (unit_eq(h->unit, "smpte")) {
        double a=0.0, b=0.0;
        int pa = parse_smpte_seconds(h->start, &a);
        int pb = parse_smpte_seconds(h->end,   &b);
        if (pa == 0 && pb == 0) {
            if (b <= a) { h->end[0] = '\0'; }  // smpte=a-
        }
    } else {
        /* clock：结构中只有 start/end 字段，通常是绝对 UTC 文本。无法可靠比较，保持形态不动。 */
    }

    /* 若两端都空：保持 "start-" 形态最小化。npt 默认起点可留空，但为了确定性可将空起点标准化为 "0"。 */
    if (is_all_empty(h->start) && is_all_empty(h->end)) {
        set_cstr(h->unit, sizeof(h->unit), "npt");
        set_cstr(h->start, sizeof(h->start), "0");
        h->dash = '-';
        h->end[0] = '\0';
    }
}

/* ---------- 针对各请求类型调用 ---------- */
static inline void fix_play_range(rtsp_play_packet_t *p)   { normalize_range_header(&p->range_header); }
static inline void fix_pause_range(rtsp_pause_packet_t *p) { normalize_range_header(&p->range_header); }
static inline void fix_record_range(rtsp_record_packet_t *p){ normalize_range_header(&p->range_header); }

/* ---------- 对外入口 ---------- */
/* SHOT-14: 规范并修复 Range 头：
 * - 头部形态统一（name/": "/'='/'-'/CRLF）
 * - 单位限定为 npt/smpte/clock（未知回退 npt）
 * - 可解析时若 end <= start，改为 open-ended（删除 end）以符合左闭右开
 * - 空区间规范为 npt=0-
 * - 不添加结构中不存在的 time=UTC 参数
 */
void rtsp_fix_range_on_packets(rtsp_packet_t *arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) {
        rtsp_packet_t *pkt = &arr[i];
        switch (pkt->type) {
            case RTSP_TYPE_PLAY:   fix_play_range(&pkt->play);   break;
            case RTSP_TYPE_PAUSE:  fix_pause_range(&pkt->pause); break;
            case RTSP_TYPE_RECORD: fix_record_range(&pkt->record); break;
            default: /* 其他方法无 Range 头 */ break;
        }
    }
}

static int ci_eq(const char* a,const char* b){
    if(!a||!b) return 0; while(*a && *b){ if(tolower((unsigned char)*a)!=tolower((unsigned char)*b)) return 0; ++a; ++b; }
    return *a=='\0' && *b=='\0';
}

static int any_nonempty3(const char* a,const char* b,const char* c){
    return (a&&*a) || (b&&*b) || (c&&*c);
}



/* 核心：把 PAUSE 的 Range 统一成“单一时刻” */
static void normalize_pause_range(range_header_rtsp_t *h){
    if(!h) return;

    /* 若 Range 实际不存在（单位/起止均空），直接返回：表示“立即暂停” */
    if(!any_nonempty3(h->unit, h->start, h->end)) return;

    /* 规范头形态 */
    set_cstr(h->name, RTSP_HEADER_NAME_LEN, "Range");
    if(RTSP_SEPARATOR_LEN>=2){ h->colon_space[0]=':'; h->colon_space[1]=' '; }
    if(RTSP_SEPARATOR_LEN>=3)  h->colon_space[2]='\0';
    h->equals='='; h->dash='-'; set_crlf(h->crlf);

    /* 单位规范：仅 npt/smpte/clock，未知回退为 npt */
    if(!ci_eq(h->unit,"npt") && !ci_eq(h->unit,"smpte") && !ci_eq(h->unit,"clock")){
        set_cstr(h->unit, sizeof(h->unit), "npt");
    }

    /* 去空白 */
    trim_inplace(h->start);
    trim_inplace(h->end);

    /* 允许的“单点”表示：
       - npt:  "now" 或 数值秒；输出成 start==end（now-now 或 x.x-x.x）
       - smpte: hh:mm:ss[.frac] 或 hh:mm:ss;ff；输出成 start==end
       - clock: 文本保持，但输出 end=start
    */
    if(ci_eq(h->unit,"npt")){
        if(!h->start[0] && h->end[0]){ set_cstr(h->start, sizeof(h->start), h->end); }
        if(strcasecmp(h->start,"now")==0){
            set_cstr(h->end, sizeof(h->end), "now");
        }else{
            double a=0;
            if(parse_npt_seconds(h->start,&a)==0){
                char buf[32]; snprintf(buf,sizeof(buf), "%g", a);
                set_cstr(h->start, sizeof(h->start), buf);
                set_cstr(h->end,   sizeof(h->end),   buf);
            }else{
                /* 解析失败但非空：仍强制单点 */
                set_cstr(h->end, sizeof(h->end), h->start);
            }
        }
    }else if(ci_eq(h->unit,"smpte")){
        if(!h->start[0] && h->end[0]){ set_cstr(h->start, sizeof(h->start), h->end); }
        /* 能解析则规范，不行则简单复制为单点 */
        double a=0;
        if(parse_smpte_seconds(h->start,&a)==0){
            /* 这里保留原文本格式，仅保证 end==start */
            set_cstr(h->end, sizeof(h->end), h->start);
        }else{
            set_cstr(h->end, sizeof(h->end), h->start);
        }
    }else{ /* clock */
        if(!h->start[0] && h->end[0]){ set_cstr(h->start, sizeof(h->start), h->end); }
        set_cstr(h->end, sizeof(h->end), h->start);
    }
}

/* 针对数组就地修复：仅处理 PAUSE */
void rtsp_fix_pause_range_on_packets(rtsp_packet_t *arr, size_t count){
    if(!arr) return;
    for(size_t i=0;i<count;++i){
        if(arr[i].type != RTSP_TYPE_PAUSE) continue;
        normalize_pause_range(&arr[i].pause.range_header);
    }
}


/* =============== entry =============== */
void fix_rtsp(rtsp_packet_t *packets, int num) {
    for(int i = 0; i < num; i++) {
        rtsp_packet_t *pkt = &packets[i];
    
        if (!pkt) return;
        switch (pkt->type) {
            case RTSP_TYPE_OPTIONS:       fix_options(&pkt->options); break;
            case RTSP_TYPE_DESCRIBE:      fix_describe(&pkt->describe); break;
            case RTSP_TYPE_SETUP:         fix_setup(&pkt->setup); break;
            case RTSP_TYPE_PLAY:          fix_play(&pkt->play); break;
            case RTSP_TYPE_PAUSE:         fix_pause(&pkt->pause); break;
            case RTSP_TYPE_TEARDOWN:      fix_teardown(&pkt->teardown); break;
            case RTSP_TYPE_GET_PARAMETER: fix_get_parameter(&pkt->get_parameter); break;
            case RTSP_TYPE_SET_PARAMETER: fix_set_parameter(&pkt->set_parameter); break;
            case RTSP_TYPE_REDIRECT:      fix_redirect(&pkt->redirect); break;
            case RTSP_TYPE_ANNOUNCE:      fix_announce(&pkt->announce); break;
            case RTSP_TYPE_RECORD:        fix_record(&pkt->record); break;
            default: break;
        }
    }
    rtsp_fix_absolute_uri_on_packets(packets, num);
    rtsp_fix_content_length_on_packets(packets, num);
    rtsp_fix_cseq_on_packets(packets, num);
    rtsp_fix_transport_on_packets(packets, num);
    rtsp_fix_interleaved_on_packets(packets, num);
    rtsp_fix_range_on_packets(packets, num);
    rtsp_fix_pause_range_on_packets(packets, num);
}
