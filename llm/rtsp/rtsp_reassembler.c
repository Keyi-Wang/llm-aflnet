#include "rtsp.h"
#include <string.h>
#include <stdio.h>
#include "rtsp.h"  

#define APPEND_FMT(buf, offset, fmt, ...)                                         \
    do {                                                                          \
        if ((offset) < MAX_RTSP_MSG_LEN) {                                        \
            int __n = snprintf((char *)(buf) + (offset),                          \
                               MAX_RTSP_MSG_LEN - (offset), fmt, ##__VA_ARGS__);  \
            if (__n > 0 && ((offset) + __n) < MAX_RTSP_MSG_LEN) {                 \
                (offset) += __n;                                                  \
            } else if (__n < 0) {                                                 \
                fprintf(stderr, "[!] snprintf error: format = %s\n", fmt);       \
            }                                                                     \
        } else {                                                                  \
            fprintf(stderr, "[!] APPEND_FMT overflow: offset=%u\n", offset);     \
        }                                                                         \
    } while (0)
 #define MAX_RTSP_MSG_LEN 1024 * 1024  

typedef uint8_t u8;
typedef uint32_t u32;

static inline u32 write_bytes(u8 *dst, const void *src, u32 len) {
    memcpy(dst, src, len);
    return len;
}

int serialize_options(const rtsp_options_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request-Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. CSeq Header (mandatory) ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. General Headers (optional) ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers (optional) ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. Empty CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_describe(const rtsp_describe_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. CSeq Header (mandatory) ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. General Headers (optional) ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers (optional) ===
    if (p->accept_header.name[0] &&
        p->accept_header.media_type[0] &&
        p->accept_header.sub_type[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%s/%s%s",
                   p->accept_header.name,
                   p->accept_header.colon_space,
                   p->accept_header.media_type,
                   p->accept_header.sub_type,
                   p->accept_header.crlf);
    }

    if (p->accept_encoding_header.name[0] && p->accept_encoding_header.encoding[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->accept_encoding_header.name,
                   p->accept_encoding_header.colon_space,
                   p->accept_encoding_header.encoding,
                   p->accept_encoding_header.crlf);

    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->content_base_header.name[0] && p->content_base_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_base_header.name,
                   p->content_base_header.colon_space,
                   p->content_base_header.uri,
                   p->content_base_header.crlf);

    if (p->content_encoding_header.name[0] && p->content_encoding_header.encoding[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_encoding_header.name,
                   p->content_encoding_header.colon_space,
                   p->content_encoding_header.encoding,
                   p->content_encoding_header.crlf);

    if (p->content_language_header.name[0] && p->content_language_header.language[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_language_header.name,
                   p->content_language_header.colon_space,
                   p->content_language_header.language,
                   p->content_language_header.crlf);

    if (p->content_length_header.name[0] && p->content_length_header.length >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->content_length_header.name,
                   p->content_length_header.colon_space,
                   p->content_length_header.length,
                   p->content_length_header.crlf);

    if (p->content_location_header.name[0] && p->content_location_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_location_header.name,
                   p->content_location_header.colon_space,
                   p->content_location_header.uri,
                   p->content_location_header.crlf);

    if (p->expires_header.name[0] && p->expires_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->expires_header.name,
                   p->expires_header.colon_space,
                   p->expires_header.wkday,
                   p->expires_header.comma_space,
                   p->expires_header.day,
                   p->expires_header.space1,
                   p->expires_header.month,
                   p->expires_header.space2,
                   p->expires_header.year,
                   p->expires_header.space3,
                   p->expires_header.time_of_day,
                   p->expires_header.space4,
                   p->expires_header.gmt,
                   p->expires_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->if_modified_since_header.name[0] && p->if_modified_since_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->if_modified_since_header.name,
                   p->if_modified_since_header.colon_space,
                   p->if_modified_since_header.wkday,
                   p->if_modified_since_header.comma_space,
                   p->if_modified_since_header.day,
                   p->if_modified_since_header.space1,
                   p->if_modified_since_header.month,
                   p->if_modified_since_header.space2,
                   p->if_modified_since_header.year,
                   p->if_modified_since_header.space3,
                   p->if_modified_since_header.time_of_day,
                   p->if_modified_since_header.space4,
                   p->if_modified_since_header.gmt,
                   p->if_modified_since_header.crlf);

    if (p->last_modified_header.name[0] && p->last_modified_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->last_modified_header.name,
                   p->last_modified_header.colon_space,
                   p->last_modified_header.wkday,
                   p->last_modified_header.comma_space,
                   p->last_modified_header.day,
                   p->last_modified_header.space1,
                   p->last_modified_header.month,
                   p->last_modified_header.space2,
                   p->last_modified_header.year,
                   p->last_modified_header.space3,
                   p->last_modified_header.time_of_day,
                   p->last_modified_header.space4,
                   p->last_modified_header.gmt,
                   p->last_modified_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_setup(const rtsp_setup_packet_t *p, u8 *output_buf, u32 *out_len) {
    if (!p || !output_buf || !out_len) return -1;
    u32 offset = 0;

    // === 1. Request-Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. CSeq (mandatory) ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            if( p->accept_language_header.entries[i].language_tag[0]) {
                APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            }
            
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->cache_control_header.name[0] && p->cache_control_header.directive[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->cache_control_header.name,
                   p->cache_control_header.colon_space,
                   p->cache_control_header.directive,
                   p->cache_control_header.crlf);

    if (p->conference_header.name[0] && p->conference_header.conference_id[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->conference_header.name,
                   p->conference_header.colon_space,
                   p->conference_header.conference_id,
                   p->conference_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->if_modified_since_header.name[0] && p->if_modified_since_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->if_modified_since_header.name,
                   p->if_modified_since_header.colon_space,
                   p->if_modified_since_header.wkday,
                   p->if_modified_since_header.comma_space,
                   p->if_modified_since_header.day,
                   p->if_modified_since_header.space1,
                   p->if_modified_since_header.month,
                   p->if_modified_since_header.space2,
                   p->if_modified_since_header.year,
                   p->if_modified_since_header.space3,
                   p->if_modified_since_header.time_of_day,
                   p->if_modified_since_header.space4,
                   p->if_modified_since_header.gmt,
                   p->if_modified_since_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. Transport Header (mandatory) ===
    if (p->transport_header.name[0] &&
        p->transport_header.protocol[0] &&
        p->transport_header.cast_mode[0] &&
        p->transport_header.client_port_prefix[0] &&
        p->transport_header.port_range[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%s;%s;%s%s%s",
                   p->transport_header.name,
                   p->transport_header.colon_space,
                   p->transport_header.protocol,
                   p->transport_header.cast_mode,
                   p->transport_header.client_port_prefix,
                   p->transport_header.port_range,
                   p->transport_header.crlf);
    }
    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    // === 6. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_play(const rtsp_play_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request-Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. Mandatory Header: CSeq ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. Optional General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->range_header.name[0] && p->range_header.unit[0])
        APPEND_FMT(output_buf, offset, "%s%s%s=%s-%s%s",
                   p->range_header.name,
                   p->range_header.colon_space,
                   p->range_header.unit,
                   p->range_header.start,
                   p->range_header.end,
                   p->range_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->scale_header.name[0])
        APPEND_FMT(output_buf, offset, "%s%s%.3f%s",
                   p->scale_header.name,
                   p->scale_header.colon_space,
                   p->scale_header.value,
                   p->scale_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }


    if (p->speed_header.name[0])
        APPEND_FMT(output_buf, offset, "%s%s%.3f%s",
                   p->speed_header.name,
                   p->speed_header.colon_space,
                   p->speed_header.value,
                   p->speed_header.crlf);

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_pause(const rtsp_pause_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. Mandatory: CSeq ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. Optional General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Optional Request Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->range_header.name[0] && p->range_header.unit[0])
        APPEND_FMT(output_buf, offset, "%s%s%s=%s-%s%s",
                   p->range_header.name,
                   p->range_header.colon_space,
                   p->range_header.unit,
                   p->range_header.start,
                   p->range_header.end,
                   p->range_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_teardown(const rtsp_teardown_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. Mandatory Header: CSeq ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. Optional General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Optional Request Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_get_parameter(const rtsp_get_parameter_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request-Line ===
    APPEND_FMT(output_buf, offset, "%s %s %s%s",
               p->method, p->request_uri, p->rtsp_version, p->crlf1);

    // === 2. Mandatory Header: CSeq ===
    APPEND_FMT(output_buf, offset, "%s%s%d%s",
               p->cseq_header.name,
               p->cseq_header.colon_space,
               p->cseq_header.number,
               p->cseq_header.crlf);

    // === 3. Optional General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Optional Request Headers ===
    if (p->accept_header.name[0] &&
        p->accept_header.media_type[0] &&
        p->accept_header.sub_type[0])
        APPEND_FMT(output_buf, offset, "%s%s%s/%s%s",
                   p->accept_header.name,
                   p->accept_header.colon_space,
                   p->accept_header.media_type,
                   p->accept_header.sub_type,
                   p->accept_header.crlf);

    if (p->accept_encoding_header.name[0] && p->accept_encoding_header.encoding[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->accept_encoding_header.name,
                   p->accept_encoding_header.colon_space,
                   p->accept_encoding_header.encoding,
                   p->accept_encoding_header.crlf);

    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->content_base_header.name[0] && p->content_base_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_base_header.name,
                   p->content_base_header.colon_space,
                   p->content_base_header.uri,
                   p->content_base_header.crlf);

    if (p->content_length_header.name[0] && p->content_length_header.length >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->content_length_header.name,
                   p->content_length_header.colon_space,
                   p->content_length_header.length,
                   p->content_length_header.crlf);

    if (p->content_location_header.name[0] && p->content_location_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_location_header.name,
                   p->content_location_header.colon_space,
                   p->content_location_header.uri,
                   p->content_location_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->last_modified_header.name[0] && p->last_modified_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->last_modified_header.name,
                   p->last_modified_header.colon_space,
                   p->last_modified_header.wkday,
                   p->last_modified_header.comma_space,
                   p->last_modified_header.day,
                   p->last_modified_header.space1,
                   p->last_modified_header.month,
                   p->last_modified_header.space2,
                   p->last_modified_header.year,
                   p->last_modified_header.space3,
                   p->last_modified_header.time_of_day,
                   p->last_modified_header.space4,
                   p->last_modified_header.gmt,
                   p->last_modified_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. End CRLF ===
    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_set_parameter(const rtsp_set_parameter_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    if (p->method[0] && p->request_uri[0] && p->rtsp_version[0] && p->crlf1[0]) {
        APPEND_FMT(output_buf, offset, "%s %s %s%s",
                   p->method, p->request_uri, p->rtsp_version, p->crlf1);
    }

    // === 2. CSeq (mandatory) ===
    if (p->cseq_header.name[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->cseq_header.name,
                   p->cseq_header.colon_space,
                   p->cseq_header.number,
                   p->cseq_header.crlf);
    }

    // === 3. General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers ===
    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. Entity Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->content_encoding_header.name[0] && p->content_encoding_header.encoding[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_encoding_header.name,
                   p->content_encoding_header.colon_space,
                   p->content_encoding_header.encoding,
                   p->content_encoding_header.crlf);

    if (p->content_type_header.name[0] && p->content_type_header.media_type[0])
        APPEND_FMT(output_buf, offset, "%s%s%s/%s%s",
                   p->content_type_header.name,
                   p->content_type_header.colon_space,
                   p->content_type_header.media_type,
                   p->content_type_header.sub_type,
                   p->content_type_header.crlf);

    if (p->content_length_header.name[0] && p->content_length_header.length >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->content_length_header.name,
                   p->content_length_header.colon_space,
                   p->content_length_header.length,
                   p->content_length_header.crlf);

    // === 6. End CRLF ===

    APPEND_FMT(output_buf, offset, "%s", "\r\n");

     // === 7. Message Body ===
    if (p->content_length_header.name[0] &&
        p->content_length_header.length > 0 &&
        p->body[0]) {

        int body_len = p->content_length_header.length;
        if (body_len > MAX_RTSP_BODY_LEN)
            body_len = MAX_RTSP_BODY_LEN;

        if (body_len > 0) {
            memcpy(output_buf + offset, p->body, (size_t)body_len);
            offset += (u32)body_len;
        }
    }
    *out_len = offset;
    return 0;
}


int serialize_redirect(const rtsp_redirect_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    if (p->method[0] && p->request_uri[0] && p->rtsp_version[0] && p->crlf1[0]) {
        APPEND_FMT(output_buf, offset, "%s %s %s%s",
                   p->method, p->request_uri, p->rtsp_version, p->crlf1);
    }

    // === 2. CSeq ===
    if (p->cseq_header.name[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->cseq_header.name,
                   p->cseq_header.colon_space,
                   p->cseq_header.number,
                   p->cseq_header.crlf);
    }

    // === 3. Connection ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    // === 4. Date ===
    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    // === 5. Via ===
    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 6. Accept-Language ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    // === 7. Authorization ===
    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    // === 8. Bandwidth ===
    if (p->bandwidth_header.name[0] && p->bandwidth_header.value >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    // === 9. Blocksize ===
    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    // === 10. From ===
    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    // === 11. Proxy-Require ===
    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    // === 12. Referer ===
    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    // === 13. Require ===
    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    // === 14. Session ===
    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    // === 15. User-Agent ===
    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 16. Final CRLF ===

    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}

int serialize_announce(const rtsp_announce_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    if (p->method[0] && p->request_uri[0] && p->rtsp_version[0] && p->crlf1[0]) {
        APPEND_FMT(output_buf, offset, "%s %s %s%s",
                   p->method, p->request_uri, p->rtsp_version, p->crlf1);
    }

    // === 2. CSeq (mandatory) ===
    if (p->cseq_header.name[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->cseq_header.name,
                   p->cseq_header.colon_space,
                   p->cseq_header.number,
                   p->cseq_header.crlf);
    }
    // === 3. General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers ===
    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    // === 5. Entity Headers ===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    if (p->content_encoding_header.name[0] && p->content_encoding_header.encoding[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_encoding_header.name,
                   p->content_encoding_header.colon_space,
                   p->content_encoding_header.encoding,
                   p->content_encoding_header.crlf);

    if (p->content_language_header.name[0] && p->content_language_header.language[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->content_language_header.name,
                   p->content_language_header.colon_space,
                   p->content_language_header.language,
                   p->content_language_header.crlf);

    if (p->content_type_header.name[0] && p->content_type_header.media_type[0])
        APPEND_FMT(output_buf, offset, "%s%s%s/%s%s",
                   p->content_type_header.name,
                   p->content_type_header.colon_space,
                   p->content_type_header.media_type,
                   p->content_type_header.sub_type,
                   p->content_type_header.crlf);

    if (p->content_length_header.name[0] && p->content_length_header.length >= 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->content_length_header.name,
                   p->content_length_header.colon_space,
                   p->content_length_header.length,
                   p->content_length_header.crlf);

    if (p->expires_header.name[0] && p->expires_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->expires_header.name,
                   p->expires_header.colon_space,
                   p->expires_header.wkday,
                   p->expires_header.comma_space,
                   p->expires_header.day,
                   p->expires_header.space1,
                   p->expires_header.month,
                   p->expires_header.space2,
                   p->expires_header.year,
                   p->expires_header.space3,
                   p->expires_header.time_of_day,
                   p->expires_header.space4,
                   p->expires_header.gmt,
                   p->expires_header.crlf);

    // === 6. End CRLF ===

    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    // === 7. Message Body ===
    if (p->content_length_header.name[0] &&
        p->content_length_header.length > 0 &&
        p->body[0]) {

        int body_len = p->content_length_header.length;
        if (body_len > MAX_RTSP_BODY_LEN)
            body_len = MAX_RTSP_BODY_LEN;

        if (body_len > 0) {
            memcpy(output_buf + offset, p->body, (size_t)body_len);
            offset += (u32)body_len;
        }
    }

    *out_len = offset;
    return 0;
}

int serialize_record(const rtsp_record_packet_t *p, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;

    // === 1. Request Line ===
    if (p->method[0] && p->request_uri[0] && p->rtsp_version[0] && p->crlf1[0]) {
        APPEND_FMT(output_buf, offset, "%s %s %s%s",
                   p->method, p->request_uri, p->rtsp_version, p->crlf1);
    }
    // === 2. CSeq (mandatory) ===
    if (p->cseq_header.name[0]) {
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->cseq_header.name,
                   p->cseq_header.colon_space,
                   p->cseq_header.number,
                   p->cseq_header.crlf);
    }

    // === 3. General Headers ===
    if (p->connection_header.name[0] && p->connection_header.option[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->connection_header.name,
                   p->connection_header.colon_space,
                   p->connection_header.option,
                   p->connection_header.crlf);

    if (p->date_header.name[0] && p->date_header.time_of_day[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s%s%c%s%c%s%c%s%c%s%s",
                   p->date_header.name,
                   p->date_header.colon_space,
                   p->date_header.wkday,
                   p->date_header.comma_space,
                   p->date_header.day,
                   p->date_header.space1,
                   p->date_header.month,
                   p->date_header.space2,
                   p->date_header.year,
                   p->date_header.space3,
                   p->date_header.time_of_day,
                   p->date_header.space4,
                   p->date_header.gmt,
                   p->date_header.crlf);

    if (p->via_header.name[0] && p->via_header.protocol[0] && p->via_header.host[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->via_header.name,
                   p->via_header.colon_space,
                   p->via_header.protocol,
                   p->via_header.host,
                   p->via_header.crlf);

    // === 4. Request Headers ===
    if (p->authorization_header.name[0] && p->authorization_header.credentials[0])
        APPEND_FMT(output_buf, offset, "%s%s%s %s%s",
                   p->authorization_header.name,
                   p->authorization_header.colon_space,
                   p->authorization_header.auth_type,
                   p->authorization_header.credentials,
                   p->authorization_header.crlf);

    if (p->bandwidth_header.name[0] && p->bandwidth_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->bandwidth_header.name,
                   p->bandwidth_header.colon_space,
                   p->bandwidth_header.value,
                   p->bandwidth_header.crlf);

    if (p->blocksize_header.name[0] && p->blocksize_header.value > 0)
        APPEND_FMT(output_buf, offset, "%s%s%d%s",
                   p->blocksize_header.name,
                   p->blocksize_header.colon_space,
                   p->blocksize_header.value,
                   p->blocksize_header.crlf);

    if (p->from_header.name[0] && p->from_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->from_header.name,
                   p->from_header.colon_space,
                   p->from_header.uri,
                   p->from_header.crlf);

    if (p->proxy_require_header.name[0] && p->proxy_require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->proxy_require_header.name,
                   p->proxy_require_header.colon_space,
                   p->proxy_require_header.option_tag,
                   p->proxy_require_header.crlf);

    if (p->referer_header.name[0] && p->referer_header.uri[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->referer_header.name,
                   p->referer_header.colon_space,
                   p->referer_header.uri,
                   p->referer_header.crlf);

    if (p->require_header.name[0] && p->require_header.option_tag[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->require_header.name,
                   p->require_header.colon_space,
                   p->require_header.option_tag,
                   p->require_header.crlf);

    if (p->session_header.name[0] && p->session_header.session_id[0]) {
        if (p->session_header.semicolon_timeout[0]) {
            APPEND_FMT(output_buf, offset, "%s%s%s%s%d%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.semicolon_timeout,
                    p->session_header.timeout,
                    p->session_header.crlf);
        } else {
            APPEND_FMT(output_buf, offset, "%s%s%s%s",
                    p->session_header.name,
                    p->session_header.colon_space,
                    p->session_header.session_id,
                    p->session_header.crlf);
        }
    }

    if (p->user_agent_header.name[0] && p->user_agent_header.agent_string[0])
        APPEND_FMT(output_buf, offset, "%s%s%s%s",
                   p->user_agent_header.name,
                   p->user_agent_header.colon_space,
                   p->user_agent_header.agent_string,
                   p->user_agent_header.crlf);

    if (p->range_header.name[0] && p->range_header.unit[0])
        APPEND_FMT(output_buf, offset, "%s%s%s=%s-%s%s",
                   p->range_header.name,
                   p->range_header.colon_space,
                   p->range_header.unit,
                   p->range_header.start,
                   p->range_header.end,
                   p->range_header.crlf);

    if (p->scale_header.name[0] && p->scale_header.value != 0.0f) {
        APPEND_FMT(output_buf, offset, "%s%s%.3f%s",
                   p->scale_header.name,
                   p->scale_header.colon_space,
                   p->scale_header.value,
                   p->scale_header.crlf);
    }

    // === 5. Entity Header===
    if (p->accept_language_header.name[0] && p->accept_language_header.entry_count > 0) {
        APPEND_FMT(output_buf, offset, "%s%s", p->accept_language_header.name, p->accept_language_header.colon_space);
        for (int i = 0; i < p->accept_language_header.entry_count; ++i) {
            APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.entries[i].language_tag);
            if (p->accept_language_header.entries[i].qvalue[0])
                APPEND_FMT(output_buf, offset, ";q=%s", p->accept_language_header.entries[i].qvalue);
            if (i < p->accept_language_header.entry_count - 1)
                APPEND_FMT(output_buf, offset, ",");
        }
        APPEND_FMT(output_buf, offset, "%s", p->accept_language_header.crlf);
    }

    // === 6. End CRLF ===

    APPEND_FMT(output_buf, offset, "%s", "\r\n");

    *out_len = offset;
    return 0;
}


int reassemble_a_rtsp_msg(const rtsp_packet_t *pkt, u8 *output_buf, u32 *out_len) {
    if (!pkt || !output_buf || !out_len) {
        return -1;
    }

    switch (pkt->type) {
        case RTSP_TYPE_OPTIONS:
            return serialize_options(&pkt->options, output_buf, out_len);
        case RTSP_TYPE_DESCRIBE:
            return serialize_describe(&pkt->describe, output_buf, out_len);
        case RTSP_TYPE_SETUP:
            return serialize_setup(&pkt->setup, output_buf, out_len);
        case RTSP_TYPE_PLAY:
            return serialize_play(&pkt->play, output_buf, out_len);
        case RTSP_TYPE_PAUSE:
            return serialize_pause(&pkt->pause, output_buf, out_len);
        case RTSP_TYPE_TEARDOWN:
            return serialize_teardown(&pkt->teardown, output_buf, out_len);
        case RTSP_TYPE_GET_PARAMETER:
            return serialize_get_parameter(&pkt->get_parameter, output_buf, out_len);
        case RTSP_TYPE_SET_PARAMETER:
            return serialize_set_parameter(&pkt->set_parameter, output_buf, out_len);
        case RTSP_TYPE_ANNOUNCE:
            return serialize_announce(&pkt->announce, output_buf, out_len);
        case RTSP_TYPE_RECORD:
            return serialize_record(&pkt->record, output_buf, out_len);
        case RTSP_TYPE_REDIRECT:
            return serialize_redirect(&pkt->redirect, output_buf, out_len);
        default:
            return -1; 
    }
}

int reassemble_rtsp_msgs(const rtsp_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;
    *out_len = 0;

    for (u32 j = 0; j < num_packets; ++j) {
        u8 temp_buf[1024 * 1024]; 
        u32 temp_len = 0;

        if (reassemble_a_rtsp_msg(&packets[j], temp_buf, &temp_len) != 0) {
            continue;
        }

        if (offset + temp_len >= MAX_FILE) {
            break;
        }

        memcpy(output_buf + offset, temp_buf, temp_len);
        offset += temp_len;
    }

    *out_len = offset;
    return 0;
}