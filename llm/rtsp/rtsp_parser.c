#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>
#include "rtsp.h"
#include <ctype.h>

/* 1. Accept */
void fill_accept_header(accept_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Accept");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    // value 形如 "application/sdp"
    char buf[128];
    strncpy(buf, value, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        strncpy(hdr->media_type, buf, sizeof(hdr->media_type)-1);
        hdr->slash = '/';
        strncpy(hdr->sub_type, slash+1, sizeof(hdr->sub_type)-1);
    } else {
        strncpy(hdr->media_type, buf, sizeof(hdr->media_type)-1);
        hdr->slash = '\0';
        hdr->sub_type[0] = '\0';
    }
}

/* 2. Accept-Encoding */
void fill_accept_encoding_header(accept_encoding_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Accept-Encoding");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->encoding, value, sizeof(hdr->encoding)-1);
}

/* 3. Accept-Language  */
void fill_accept_language_header(accept_language_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Accept-Language");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    hdr->entry_count = 0;
    if (!value) return;

    char buf[256];
    strncpy(buf, value, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *token = strtok(buf, ",");
    while (token && hdr->entry_count < MAX_ACCEPT_LANG) {
        while (*token == ' ') token++;

        char *qpos = strstr(token, ";q=");
        if (qpos) {
            *qpos = '\0';
            qpos += 3;
            strncpy(hdr->entries[hdr->entry_count].qvalue, qpos,
                    sizeof(hdr->entries[hdr->entry_count].qvalue)-1);
        } else {
            hdr->entries[hdr->entry_count].qvalue[0] = '\0';
        }

        strncpy(hdr->entries[hdr->entry_count].language_tag, token,
                sizeof(hdr->entries[hdr->entry_count].language_tag)-1);

        hdr->entry_count++;
        token = strtok(NULL, ",");
    }
}



/* 5. Authorization */
void fill_authorization_header(authorization_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Authorization");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    const char *space = strchr(value, ' ');
    if (space) {
        size_t type_len = space - value;
        strncpy(hdr->auth_type, value, type_len);
        hdr->space = ' ';
        strncpy(hdr->credentials, space+1, sizeof(hdr->credentials)-1);
    } else {
        strncpy(hdr->auth_type, value, sizeof(hdr->auth_type)-1);
        hdr->space = '\0';
        hdr->credentials[0] = '\0';
    }
}

/* 6. Bandwidth */
void fill_bandwidth_header(bandwidth_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Bandwidth");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->value = atoi(value);
}

/* 7. Blocksize */
void fill_blocksize_header(blocksize_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Blocksize");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->value = atoi(value);
}

/* 8. Cache-Control */
void fill_cache_control_header(cache_control_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Cache-Control");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->directive, value, sizeof(hdr->directive)-1);
}

/* 9. Conference */
void fill_conference_header(conference_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Conference");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->conference_id, value, sizeof(hdr->conference_id)-1);
}

/* 10. Connection */
void fill_connection_header(connection_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Connection");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->option, value, sizeof(hdr->option)-1);
}

/* 11. Content-Base */
void fill_content_base_header(content_base_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Base");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->uri, value, sizeof(hdr->uri)-1);
}

/* 12. Content-Encoding */
void fill_content_encoding_header(content_encoding_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Encoding");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->encoding, value, sizeof(hdr->encoding)-1);
}

/* 13. Content-Language */
void fill_content_language_header(content_language_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Language");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->language, value, sizeof(hdr->language)-1);
}

/* 14. Content-Length */
void fill_content_length_header(content_length_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Length");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->length = atoi(value);
}

/* 15. Content-Location */
void fill_content_location_header(content_location_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Location");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->uri, value, sizeof(hdr->uri)-1);
}

/* 16. Content-Type */
void fill_content_type_header(content_type_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Content-Type");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    char buf[128];
    strncpy(buf, value, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        strncpy(hdr->media_type, buf, sizeof(hdr->media_type)-1);
        hdr->slash = '/';
        strncpy(hdr->sub_type, slash+1, sizeof(hdr->sub_type)-1);
    } else {
        strncpy(hdr->media_type, buf, sizeof(hdr->media_type)-1);
        hdr->slash = '\0';
        hdr->sub_type[0] = '\0';
    }
}

/* 17. CSeq */
void fill_cseq_header(cseq_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "CSeq");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->number = atoi(value);
}

/* 18. Date */
void fill_date_header(date_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Date");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    sscanf(value, "%3s , %2s %3s %4s %8s %3s",
           hdr->wkday, hdr->day, hdr->month, hdr->year,
           hdr->time_of_day, hdr->gmt);
    strcpy(hdr->comma_space, ", ");
    hdr->space1 = ' ';
    hdr->space2 = ' ';
    hdr->space3 = ' ';
    hdr->space4 = ' ';
}

/* 19. Expires */
void fill_expires_header(expires_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Expires");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    sscanf(value, "%3s , %2s %3s %4s %8s %3s",
           hdr->wkday, hdr->day, hdr->month, hdr->year,
           hdr->time_of_day, hdr->gmt);
    strcpy(hdr->comma_space, ", ");
    hdr->space1 = ' ';
    hdr->space2 = ' ';
    hdr->space3 = ' ';
    hdr->space4 = ' ';
}

/* 20. From */
void fill_from_header(from_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "From");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->uri, value, sizeof(hdr->uri)-1);
}

/* 21. If-Modified-Since */
void fill_if_modified_since_header(if_modified_since_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "If-Modified-Since");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    sscanf(value, "%3s , %2s %3s %4s %8s %3s",
           hdr->wkday, hdr->day, hdr->month, hdr->year,
           hdr->time_of_day, hdr->gmt);
    strcpy(hdr->comma_space, ", ");
    hdr->space1 = ' ';
    hdr->space2 = ' ';
    hdr->space3 = ' ';
    hdr->space4 = ' ';
}

/* 22. Last-Modified */
void fill_last_modified_header(last_modified_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Last-Modified");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    sscanf(value, "%3s , %2s %3s %4s %8s %3s",
           hdr->wkday, hdr->day, hdr->month, hdr->year,
           hdr->time_of_day, hdr->gmt);
    strcpy(hdr->comma_space, ", ");
    hdr->space1 = ' ';
    hdr->space2 = ' ';
    hdr->space3 = ' ';
    hdr->space4 = ' ';
}

/* 24. Proxy-Require */
void fill_proxy_require_header(proxy_require_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Proxy-Require");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->option_tag, value, sizeof(hdr->option_tag)-1);
}


/* 26. Range */
void fill_range_header(range_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Range");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    sscanf(value, "%7[^=]=%15[^-]-%15s",
           hdr->unit, hdr->start, hdr->end);
    hdr->equals = '=';
    hdr->dash = '-';
}

/* 27. Referer */
void fill_referer_header(referer_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Referer");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->uri, value, sizeof(hdr->uri)-1);
}

/* 28. Require */
void fill_require_header(require_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Require");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->option_tag, value, sizeof(hdr->option_tag)-1);
}



/* 31. Scale */
void fill_scale_header(scale_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Scale");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->value = atof(value);
}

/* 32. Session */
void fill_session_header(session_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Session");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    char buf[128];
    strncpy(buf, value, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *semi = strstr(buf, ";timeout=");
    if (semi) {
        *semi = '\0';
        strncpy(hdr->session_id, buf, sizeof(hdr->session_id)-1);
        strcpy(hdr->semicolon_timeout, ";timeout=");
        hdr->timeout = atoi(semi + 9);
    } else {
        strncpy(hdr->session_id, buf, sizeof(hdr->session_id)-1);
        hdr->semicolon_timeout[0] = '\0';
        hdr->timeout = 0;
    }
}


/* 34. Speed */
void fill_speed_header(speed_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Speed");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    hdr->value = atof(value);
}

/* 35. Transport */
#include <string.h>
#include <ctype.h>
#include <stdio.h>

static const char* skip_sp(const char *s) {
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}

static void copy_trim(char *dst, size_t dstsz, const char *beg, size_t len) {
    if (dstsz == 0) return;
    while (len && (beg[0] == ' ' || beg[0] == '\t')) { ++beg; --len; }
    while (len && (beg[len-1] == ' ' || beg[len-1] == '\t')) { --len; }
    if (len >= 2 && beg[0] == '"' && beg[len-1] == '"') { ++beg; len -= 2; }
    size_t cpy = len < (dstsz - 1) ? len : (dstsz - 1);
    if (cpy) memcpy(dst, beg, cpy);
    dst[cpy] = '\0';
}

static int span_ieq(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (alen != blen) return 0;
    for (size_t i = 0; i < alen; ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return 1;
}

void fill_transport_header(transport_header_rtsp_t *hdr, const char *value) {
    if (!hdr) return;
    memset(hdr, 0, sizeof(*hdr));
    snprintf(hdr->name,        sizeof hdr->name,        "Transport");
    snprintf(hdr->colon_space, sizeof hdr->colon_space, ": ");
    snprintf(hdr->crlf,        sizeof hdr->crlf,        "\r\n");
    hdr->semicolon1 = ';';
    hdr->semicolon2 = ';';

    if (!value) return;

    const char *p = value;
    if (strncasecmp(p, "Transport:", 10) == 0) {
        p += 10;
    }
    p = skip_sp(p);

    int got_protocol = 0;
    int got_cast_mode = 0;
    int got_kv = 0;

    while (*p) {
        const char *seg = p;
        while (*p && *p != ';' && *p != '\r' && *p != '\n') ++p;
        const char *seg_end = p;
        size_t seg_len = (size_t)(seg_end - seg);

        if (*p == ';') ++p;
        const char *s = seg; size_t n = seg_len;
        while (n && (s[0] == ' ' || s[0] == '\t')) { ++s; --n; }
        while (n && (s[n-1] == ' ' || s[n-1] == '\t')) { --n; }
        if (n == 0) continue;

        if (!got_protocol) {
            copy_trim(hdr->protocol, sizeof hdr->protocol, s, n);
            got_protocol = 1;
            continue;
        }

        const char *eq = memchr(s, '=', n);
        if (!eq && !got_cast_mode) {
            if (span_ieq(s, n, "unicast") || span_ieq(s, n, "multicast")) {
                copy_trim(hdr->cast_mode, sizeof hdr->cast_mode, s, n);
                got_cast_mode = 1;
                continue;
            }
        }

        if (!got_kv && eq) {
            // key
            const char *k_beg = s;
            size_t k_len = (size_t)(eq - s);
            // value
            const char *v_beg = eq + 1;
            size_t v_len = (size_t)(s + n - v_beg);

            char keybuf[16];
            copy_trim(keybuf, sizeof keybuf, k_beg, k_len);
            size_t kl = strlen(keybuf);

            if (kl + 1 >= sizeof hdr->client_port_prefix) {
                kl = sizeof hdr->client_port_prefix - 2;
            }
            memcpy(hdr->client_port_prefix, keybuf, kl);
            hdr->client_port_prefix[kl] = '=';
            hdr->client_port_prefix[kl + 1] = '\0';

            copy_trim(hdr->port_range, sizeof hdr->port_range, v_beg, v_len);

            got_kv = 1;
            continue;
        }

    }
}



/* 37. User-Agent */
void fill_user_agent_header(user_agent_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "User-Agent");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");
    strncpy(hdr->agent_string, value, sizeof(hdr->agent_string)-1);
}

/* 38. Via */
void fill_via_header(via_header_rtsp_t *hdr, const char *value) {
    strcpy(hdr->name, "Via");
    strcpy(hdr->colon_space, ": ");
    strcpy(hdr->crlf, "\r\n");

    sscanf(value, "%15s %63s", hdr->protocol, hdr->host);
    hdr->space = ' ';
}




static const char *allowed_headers[][32] = {
    /* OPTIONS */
    {"Accept-Language","Authorization","Bandwidth","Connection","CSeq","Date",
     "From","Proxy-Require","Referer","Require","User-Agent","Via", NULL},

    /* DESCRIBE */
    {"Accept","Accept-Encoding","Accept-Language","Authorization","Bandwidth","Blocksize",
     "Connection","Content-Base","Content-Encoding","Content-Language","Content-Length",
     "Content-Location","CSeq","Date","Expires","From","If-Modified-Since","Last-Modified",
     "Proxy-Require","Referer","Require","Session","User-Agent","Via", NULL},

    /* SETUP */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Cache-Control","Conference",
     "Connection","CSeq","Date","From","If-Modified-Since","Proxy-Require","Session","Referer",
     "Require","Transport","User-Agent","Via", NULL},

    /* PLAY */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","CSeq","Date",
     "From","Proxy-Require","Range","Referer","Require","Scale","Session","Speed",
     "User-Agent","Via", NULL},

    /* PAUSE */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","CSeq","Date",
     "From","Proxy-Require","Range","Referer","Require","Session","User-Agent","Via", NULL},

    /* TEARDOWN */
    {"Accept-Language","Authorization","Bandwidth","Connection","CSeq","Date","From",
     "Proxy-Require","Referer","Require","Session","User-Agent","Via", NULL},

    /* GET_PARAMETER */
    {"Accept","Accept-Encoding","Accept-Language","Authorization","Bandwidth","Blocksize",
     "Connection","Content-Base","Content-Length","Content-Location","CSeq","Date","From",
     "Last-Modified","Proxy-Require","Referer","Require","Session","User-Agent","Via", NULL},

    /* SET_PARAMETER */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","Content-Encoding",
     "Content-Length","Content-Type","CSeq","Date","From","Proxy-Require","Referer","Require",
     "Session","User-Agent","Via", NULL},

    /* REDIRECT */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","CSeq","Date","From",
     "Proxy-Require","Referer","Require","Session","User-Agent","Via", NULL},

    /* ANNOUNCE */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","Content-Encoding",
     "Content-Language","Content-Length","Content-Type","CSeq","Date","Expires","From",
     "Proxy-Require","Referer","Require","Session","User-Agent","Via", NULL},

    /* RECORD */
    {"Accept-Language","Authorization","Bandwidth","Blocksize","Connection","CSeq","Date","From",
     "Proxy-Require","Range","Referer","Require","Scale","Session","User-Agent","Via", NULL}
};

static inline const char **get_allowed_headers(rtsp_type_t type) {
    switch (type) {
        case RTSP_TYPE_OPTIONS:       return allowed_headers[0];
        case RTSP_TYPE_DESCRIBE:      return allowed_headers[1];
        case RTSP_TYPE_SETUP:         return allowed_headers[2];
        case RTSP_TYPE_PLAY:          return allowed_headers[3];
        case RTSP_TYPE_PAUSE:         return allowed_headers[4];
        case RTSP_TYPE_TEARDOWN:      return allowed_headers[5];
        case RTSP_TYPE_GET_PARAMETER: return allowed_headers[6];
        case RTSP_TYPE_SET_PARAMETER: return allowed_headers[7];
        case RTSP_TYPE_REDIRECT:      return allowed_headers[8];
        case RTSP_TYPE_ANNOUNCE:      return allowed_headers[9];
        case RTSP_TYPE_RECORD:        return allowed_headers[10];
        default: return NULL;
    }
}

static inline int is_header_allowed(rtsp_type_t type, const char *header_name) {
    const char **list = get_allowed_headers(type);
    if (!list) return 0;
    for (int i = 0; list[i] != NULL; i++) {
        if (strcasecmp(list[i], header_name) == 0)
            return 1;
    }
    return 0;
}

static size_t get_content_length_for_type(const rtsp_packet_t *pkt) {
    switch (pkt->type) {
        case RTSP_TYPE_ANNOUNCE:
            return (pkt->announce.content_length_header.length > 0)
                    ? (size_t)pkt->announce.content_length_header.length : 0;
        case RTSP_TYPE_SET_PARAMETER:
            return (pkt->set_parameter.content_length_header.length > 0)
                    ? (size_t)pkt->set_parameter.content_length_header.length : 0;
        default:
            return 0;
    }
}

static rtsp_type_t method_to_type(const char *method) {
    if      (strcasecmp(method, "OPTIONS") == 0)       return RTSP_TYPE_OPTIONS;
    else if (strcasecmp(method, "DESCRIBE") == 0)      return RTSP_TYPE_DESCRIBE;
    else if (strcasecmp(method, "SETUP") == 0)         return RTSP_TYPE_SETUP;
    else if (strcasecmp(method, "PLAY") == 0)          return RTSP_TYPE_PLAY;
    else if (strcasecmp(method, "PAUSE") == 0)         return RTSP_TYPE_PAUSE;
    else if (strcasecmp(method, "TEARDOWN") == 0)      return RTSP_TYPE_TEARDOWN;
    else if (strcasecmp(method, "GET_PARAMETER") == 0) return RTSP_TYPE_GET_PARAMETER;
    else if (strcasecmp(method, "SET_PARAMETER") == 0) return RTSP_TYPE_SET_PARAMETER;
    else if (strcasecmp(method, "REDIRECT") == 0)      return RTSP_TYPE_REDIRECT;
    else if (strcasecmp(method, "ANNOUNCE") == 0)      return RTSP_TYPE_ANNOUNCE;
    else if (strcasecmp(method, "RECORD") == 0)        return RTSP_TYPE_RECORD;
    return RTSP_TYPE_UNKNOWN;
}

size_t parse_rtsp_msg(const uint8_t *buf, size_t buf_len,
                           rtsp_packet_t *out_packets, size_t max_count) {
    size_t offset = 0, count = 0;

    while (offset < buf_len && count < max_count) {
        const char *start = (const char *)(buf + offset);
        const char *line_end = strstr(start, "\r\n");
        if (!line_end) break;

        char request_line[512];
        size_t req_len = line_end - start;
        if (req_len >= sizeof(request_line)) req_len = sizeof(request_line) - 1;
        memcpy(request_line, start, req_len);
        request_line[req_len] = '\0';

        char method[32], uri[256], version[16];
        if (sscanf(request_line, "%31s %255s %15s", method, uri, version) != 3)
            break;

        rtsp_type_t type = method_to_type(method);
        out_packets[count].type = type;

        memset(&out_packets[count], 0, sizeof(rtsp_packet_t));
        out_packets[count].type = type;

#define SET_COMMON(pkt) do { \
    strcpy(pkt.method, method); \
    pkt.space1 = ' '; \
    strcpy(pkt.request_uri, uri); \
    pkt.space2 = ' '; \
    strcpy(pkt.rtsp_version, version); \
    strcpy(pkt.crlf1, "\r\n"); \
} while (0)

        switch (type) {
            case RTSP_TYPE_OPTIONS:       SET_COMMON(out_packets[count].options); break;
            case RTSP_TYPE_DESCRIBE:      SET_COMMON(out_packets[count].describe); break;
            case RTSP_TYPE_SETUP:         SET_COMMON(out_packets[count].setup); break;
            case RTSP_TYPE_PLAY:          SET_COMMON(out_packets[count].play); break;
            case RTSP_TYPE_PAUSE:         SET_COMMON(out_packets[count].pause); break;
            case RTSP_TYPE_TEARDOWN:      SET_COMMON(out_packets[count].teardown); break;
            case RTSP_TYPE_GET_PARAMETER: SET_COMMON(out_packets[count].get_parameter); break;
            case RTSP_TYPE_SET_PARAMETER: SET_COMMON(out_packets[count].set_parameter); break;
            case RTSP_TYPE_REDIRECT:      SET_COMMON(out_packets[count].redirect); break;
            case RTSP_TYPE_ANNOUNCE:      SET_COMMON(out_packets[count].announce); break;
            case RTSP_TYPE_RECORD:        SET_COMMON(out_packets[count].record); break;
            default: break;
        }

        const char *pos = line_end + 2;
        const char *msg_end = strstr(pos, "\r\n\r\n");
        if (!msg_end) break;

        while (pos < msg_end) {
            const char *hdr_end = strstr(pos, "\r\n");
            if (!hdr_end || hdr_end > msg_end) break;

            char header_line[512];
            size_t hdr_len = hdr_end - pos;
            if (hdr_len >= sizeof(header_line)) hdr_len = sizeof(header_line) - 1;
            memcpy(header_line, pos, hdr_len);
            header_line[hdr_len] = '\0';

            char name[64], value[448];
            if (sscanf(header_line, "%63[^:]: %447[^\r\n]", name, value) == 2) {
                if (is_header_allowed(type, name)) {
                    rtsp_packet_t *pkt = &out_packets[count];
                    if (type == RTSP_TYPE_OPTIONS) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->options.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->options.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->options.bandwidth_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->options.connection_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->options.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->options.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->options.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->options.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->options.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->options.require_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->options.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->options.via_header, value);

                    } else if (type == RTSP_TYPE_DESCRIBE) {
                        if (strcasecmp(name, "Accept") == 0)
                            fill_accept_header(&pkt->describe.accept_header, value);
                        else if (strcasecmp(name, "Accept-Encoding") == 0)
                            fill_accept_encoding_header(&pkt->describe.accept_encoding_header, value);
                        else if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->describe.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->describe.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->describe.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->describe.blocksize_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->describe.connection_header, value);
                        else if (strcasecmp(name, "Content-Base") == 0)
                            fill_content_base_header(&pkt->describe.content_base_header, value);
                        else if (strcasecmp(name, "Content-Encoding") == 0)
                            fill_content_encoding_header(&pkt->describe.content_encoding_header, value);
                        else if (strcasecmp(name, "Content-Language") == 0)
                            fill_content_language_header(&pkt->describe.content_language_header, value);
                        else if (strcasecmp(name, "Content-Length") == 0)
                            fill_content_length_header(&pkt->describe.content_length_header, value);
                        else if (strcasecmp(name, "Content-Location") == 0)
                            fill_content_location_header(&pkt->describe.content_location_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->describe.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->describe.date_header, value);
                        else if (strcasecmp(name, "Expires") == 0)
                            fill_expires_header(&pkt->describe.expires_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->describe.from_header, value);
                        else if (strcasecmp(name, "If-Modified-Since") == 0)
                            fill_if_modified_since_header(&pkt->describe.if_modified_since_header, value);
                        else if (strcasecmp(name, "Last-Modified") == 0)
                            fill_last_modified_header(&pkt->describe.last_modified_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->describe.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->describe.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->describe.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->describe.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->describe.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->describe.via_header, value);

                    }
                    /* ========================
                                SETUP
                    ======================== */
                    else if (type == RTSP_TYPE_SETUP) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->setup.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->setup.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->setup.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->setup.blocksize_header, value);
                        else if (strcasecmp(name, "Cache-Control") == 0)
                            fill_cache_control_header(&pkt->setup.cache_control_header, value);
                        else if (strcasecmp(name, "Conference") == 0)
                            fill_conference_header(&pkt->setup.conference_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->setup.connection_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->setup.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->setup.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->setup.from_header, value);
                        else if (strcasecmp(name, "If-Modified-Since") == 0)
                            fill_if_modified_since_header(&pkt->setup.if_modified_since_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->setup.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->setup.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->setup.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->setup.session_header, value);
                        else if (strcasecmp(name, "Transport") == 0)
                            fill_transport_header(&pkt->setup.transport_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->setup.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->setup.via_header, value);
                    }

                    /* ========================
                    PLAY
                    ======================== */
                    else if (type == RTSP_TYPE_PLAY) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->play.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->play.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->play.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->play.blocksize_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->play.connection_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->play.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->play.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->play.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->play.proxy_require_header, value);
                        else if (strcasecmp(name, "Range") == 0)
                            fill_range_header(&pkt->play.range_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->play.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->play.require_header, value);
                        else if (strcasecmp(name, "Scale") == 0)
                            fill_scale_header(&pkt->play.scale_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->play.session_header, value);
                        else if (strcasecmp(name, "Speed") == 0)
                            fill_speed_header(&pkt->play.speed_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->play.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->play.via_header, value);
                    }
                    /* ========================
                    PAUSE
                    ======================== */
                    else if (type == RTSP_TYPE_PAUSE) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->pause.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->pause.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->pause.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->pause.blocksize_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->pause.connection_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->pause.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->pause.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->pause.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->pause.proxy_require_header, value);
                        else if (strcasecmp(name, "Range") == 0)
                            fill_range_header(&pkt->pause.range_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->pause.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->pause.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->pause.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->pause.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->pause.via_header, value);
                    }

                    /* ========================
                    TEARDOWN
                    ======================== */
                    else if (type == RTSP_TYPE_TEARDOWN) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->teardown.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->teardown.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->teardown.bandwidth_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->teardown.connection_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->teardown.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->teardown.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->teardown.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->teardown.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->teardown.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->teardown.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->teardown.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->teardown.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->teardown.via_header, value);
                    }

                    /* ========================
                    GET_PARAMETER
                    ======================== */
                    else if (type == RTSP_TYPE_GET_PARAMETER) {
                        if (strcasecmp(name, "Accept") == 0)
                            fill_accept_header(&pkt->get_parameter.accept_header, value);
                        else if (strcasecmp(name, "Accept-Encoding") == 0)
                            fill_accept_encoding_header(&pkt->get_parameter.accept_encoding_header, value);
                        else if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->get_parameter.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->get_parameter.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->get_parameter.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->get_parameter.blocksize_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->get_parameter.connection_header, value);
                        else if (strcasecmp(name, "Content-Base") == 0)
                            fill_content_base_header(&pkt->get_parameter.content_base_header, value);
                        else if (strcasecmp(name, "Content-Length") == 0)
                            fill_content_length_header(&pkt->get_parameter.content_length_header, value);
                        else if (strcasecmp(name, "Content-Location") == 0)
                            fill_content_location_header(&pkt->get_parameter.content_location_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->get_parameter.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->get_parameter.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->get_parameter.from_header, value);
                        else if (strcasecmp(name, "Last-Modified") == 0)
                            fill_last_modified_header(&pkt->get_parameter.last_modified_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->get_parameter.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->get_parameter.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->get_parameter.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->get_parameter.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->get_parameter.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->get_parameter.via_header, value);
                    }

                    /* ========================
                    SET_PARAMETER
                    ======================== */
                    else if (type == RTSP_TYPE_SET_PARAMETER) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->set_parameter.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->set_parameter.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->set_parameter.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->set_parameter.blocksize_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->set_parameter.connection_header, value);
                        else if (strcasecmp(name, "Content-Encoding") == 0)
                            fill_content_encoding_header(&pkt->set_parameter.content_encoding_header, value);
                        else if (strcasecmp(name, "Content-Length") == 0)
                            fill_content_length_header(&pkt->set_parameter.content_length_header, value);
                        else if (strcasecmp(name, "Content-Type") == 0)
                            fill_content_type_header(&pkt->set_parameter.content_type_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->set_parameter.cseq_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->set_parameter.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->set_parameter.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->set_parameter.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->set_parameter.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->set_parameter.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->set_parameter.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->set_parameter.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->set_parameter.via_header, value);
                    }

                    /* ========================
                    REDIRECT
                    ======================== */
                    else if (type == RTSP_TYPE_REDIRECT) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->redirect.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->redirect.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->redirect.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->redirect.blocksize_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->redirect.cseq_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->redirect.connection_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->redirect.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->redirect.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->redirect.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->redirect.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->redirect.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->redirect.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->redirect.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->redirect.via_header, value);
                    }

                    /* ========================
                    ANNOUNCE
                    ======================== */
                    else if (type == RTSP_TYPE_ANNOUNCE) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->announce.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->announce.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->announce.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->announce.blocksize_header, value);
                        else if (strcasecmp(name, "Content-Encoding") == 0)
                            fill_content_encoding_header(&pkt->announce.content_encoding_header, value);
                        else if (strcasecmp(name, "Content-Language") == 0)
                            fill_content_language_header(&pkt->announce.content_language_header, value);
                        else if (strcasecmp(name, "Content-Length") == 0)
                            fill_content_length_header(&pkt->announce.content_length_header, value);
                        else if (strcasecmp(name, "Content-Type") == 0)
                            fill_content_type_header(&pkt->announce.content_type_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->announce.cseq_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->announce.connection_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->announce.date_header, value);
                        else if (strcasecmp(name, "Expires") == 0)
                            fill_expires_header(&pkt->announce.expires_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->announce.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->announce.proxy_require_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->announce.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->announce.require_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->announce.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->announce.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->announce.via_header, value);
                    }

                    /* ========================
                    RECORD
                    ======================== */
                    else if (type == RTSP_TYPE_RECORD) {
                        if (strcasecmp(name, "Accept-Language") == 0)
                            fill_accept_language_header(&pkt->record.accept_language_header, value);
                        else if (strcasecmp(name, "Authorization") == 0)
                            fill_authorization_header(&pkt->record.authorization_header, value);
                        else if (strcasecmp(name, "Bandwidth") == 0)
                            fill_bandwidth_header(&pkt->record.bandwidth_header, value);
                        else if (strcasecmp(name, "Blocksize") == 0)
                            fill_blocksize_header(&pkt->record.blocksize_header, value);
                        else if (strcasecmp(name, "CSeq") == 0)
                            fill_cseq_header(&pkt->record.cseq_header, value);
                        else if (strcasecmp(name, "Connection") == 0)
                            fill_connection_header(&pkt->record.connection_header, value);
                        else if (strcasecmp(name, "Date") == 0)
                            fill_date_header(&pkt->record.date_header, value);
                        else if (strcasecmp(name, "From") == 0)
                            fill_from_header(&pkt->record.from_header, value);
                        else if (strcasecmp(name, "Proxy-Require") == 0)
                            fill_proxy_require_header(&pkt->record.proxy_require_header, value);
                        else if (strcasecmp(name, "Range") == 0)
                            fill_range_header(&pkt->record.range_header, value);
                        else if (strcasecmp(name, "Referer") == 0)
                            fill_referer_header(&pkt->record.referer_header, value);
                        else if (strcasecmp(name, "Require") == 0)
                            fill_require_header(&pkt->record.require_header, value);
                        else if (strcasecmp(name, "Scale") == 0)
                            fill_scale_header(&pkt->record.scale_header, value);
                        else if (strcasecmp(name, "Session") == 0)
                            fill_session_header(&pkt->record.session_header, value);
                        else if (strcasecmp(name, "User-Agent") == 0)
                            fill_user_agent_header(&pkt->record.user_agent_header, value);
                        else if (strcasecmp(name, "Via") == 0)
                            fill_via_header(&pkt->record.via_header, value);
                    }
                }
            }

            pos = hdr_end + 2;
        }

        const uint8_t *body_start = (const uint8_t *)msg_end + 4;
        size_t header_total = (size_t)(body_start - (const uint8_t *)start);

        size_t content_len = get_content_length_for_type(&out_packets[count]);

        if (content_len > 0) {
            if (header_total + content_len > (buf_len - offset)) {
                break;
            }

            size_t copy_len = content_len;
            if (copy_len >= MAX_RTSP_BODY_LEN) 
                copy_len = MAX_RTSP_BODY_LEN - 1;

            if (out_packets[count].type == RTSP_TYPE_ANNOUNCE) {
                memcpy(out_packets[count].announce.body, body_start, copy_len);
                out_packets[count].announce.body[copy_len] = '\0';
            } else if (out_packets[count].type == RTSP_TYPE_SET_PARAMETER) {
                memcpy(out_packets[count].set_parameter.body, body_start, copy_len);
                out_packets[count].set_parameter.body[copy_len] = '\0';
            }

            offset += header_total + content_len;
        } else {
            offset += header_total;
        }

        count++;

    }

    return count;
}

