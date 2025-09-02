/* sip fixers source file */
#include "sip.h"

/* SHOT-5 fixer: remove forbidden URI params and any headers element from SIP Request-URIs */
#include <string.h>
#include <ctype.h>
#include <stddef.h>

/* ---- helpers --------------------------------------------------------- */

static int ci_eq_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (tolower(ca) != tolower(cb)) return 0;
    }
    return 1;
}

static int ci_starts_with(const char *s, const char *prefix) {
    size_t n = strlen(prefix);
    return strnlen(s, n) >= n && ci_eq_n(s, prefix, n);
}

/* true if token (length tok_len) starts with name and the next char is '=' or ends */
static int token_is_param(const char *tok, size_t tok_len, const char *name) {
    size_t n = strlen(name);
    if (tok_len < n) return 0;
    if (!ci_eq_n(tok, name, n)) return 0;
    if (tok_len == n) return 1;
    return tok[n] == '=';
}

/* Remove '?headers' (the entire headers element) and drop ;transport=, ;maddr=, ;ttl= params */
static void strip_forbidden_from_sip_uri(char *uri, size_t cap) {
    if (!uri || cap == 0) return;

    /* Only process SIP URLs as Request-URI (sip: or sips:) */
    const char *p = uri;
    while (*p == ' ' || *p == '\t') p++;
    if (!(ci_starts_with(p, "sip:") || ci_starts_with(p, "sips:"))) {
        return; /* not a SIP URL -> nothing to do per SHOT-5 */
    }

    /* find where the headers element ("?") begins, if any; we will drop it entirely */
    size_t len = strnlen(uri, cap);
    size_t qm_pos = len;
    for (size_t i = 0; i < len; ++i) {
        if (uri[i] == '?') { qm_pos = i; break; }
    }

    /* Split into base( userinfo@host[:port]/path ) + parameters part before '?' */
    size_t base_end = qm_pos;
    size_t first_sc = qm_pos; /* position of first ';' before '?' */
    for (size_t i = 0; i < qm_pos; ++i) {
        if (uri[i] == ';') { first_sc = i; break; }
    }
    if (first_sc == qm_pos) {
        base_end = qm_pos; /* no params at all */
    } else {
        base_end = first_sc;
    }

    /* Build the cleaned URI into a local buffer */
    char out[SIP_URI_LEN];
    size_t w = 0;

    /* copy base part */
    size_t base_copy = (base_end < SIP_URI_LEN - 1) ? base_end : (SIP_URI_LEN - 1);
    if (base_copy > 0) {
        memcpy(out, uri, base_copy);
        w = base_copy;
    }

    /* iterate params (between first_sc .. qm_pos), copy only allowed ones */
    size_t i = base_end;
    while (i < qm_pos) {
        /* skip all consecutive ';' */
        while (i < qm_pos && uri[i] == ';') i++;
        size_t tok_start = i;
        while (i < qm_pos && uri[i] != ';') i++;
        size_t tok_len = i - tok_start;
        if (tok_len == 0) continue;

        const char *tok = uri + tok_start;

        int drop =
            token_is_param(tok, tok_len, "transport") ||
            token_is_param(tok, tok_len, "maddr")     ||
            token_is_param(tok, tok_len, "ttl");

        if (!drop) {
            /* keep this token: append as ";token" if space permits */
            if (w + 1 < SIP_URI_LEN) out[w++] = ';';
            size_t to_copy = tok_len;
            if (w + to_copy >= SIP_URI_LEN) to_copy = SIP_URI_LEN - 1 - w;
            if (to_copy > 0) {
                memcpy(out + w, tok, to_copy);
                w += to_copy;
            }
        }
    }

    /* terminate; do NOT append the headers element (everything after '?') */
    out[w] = '\0';

    /* copy back to original buffer */
    strncpy(uri, out, cap);
    uri[cap - 1] = '\0';
}

/* fetch a writable pointer to the Request-URI inside a sip_packet_t, or NULL if none */
static char *get_request_uri_ptr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
    case SIP_PKT_INVITE:   return p->pkt.invite.request_uri;
    case SIP_PKT_ACK:      return p->pkt.ack.request_uri;
    case SIP_PKT_BYE:      return p->pkt.bye.request_uri;
    case SIP_PKT_CANCEL:   return p->pkt.cancel.request_uri;
    case SIP_PKT_REGISTER: return p->pkt.register_.request_uri;
    case SIP_PKT_OPTIONS:  return p->pkt.options.request_uri;
    default:               return NULL;
    }
}

/* ---- public API ------------------------------------------------------ */
/* Fix SHOT-5 on an array of SIP packets, editing the original data in place. */
void fix_shot5_request_uri_params(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        char *uri = get_request_uri_ptr(&arr[i]);
        if (uri && uri[0] != '\0') {
            strip_forbidden_from_sip_uri(uri, SIP_URI_LEN);
        }
    }
}


/* SHOT-6: [SIP-4.3.1-SIP-Version]
 * SIP-Version in the Request-Line MUST be “SIP/2.0”, with the case as shown.
 */

static inline void set_sip_version_field(char dst[SIP_TOKEN_LEN]) {
    /* Ensure exact literal with proper NUL termination */
    const char *req = "SIP/2.0";
    /* Use memcpy then NUL to avoid repeated strlen calls */
    size_t n = strlen(req);
    if (n >= SIP_TOKEN_LEN) n = SIP_TOKEN_LEN - 1;
    memcpy(dst, req, n);
    dst[n] = '\0';
}

/* Fix on origin array. Safe no-op for NULL/zero. */
void fix_shot6_sip_version(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        switch (p->cmd_type) {
            case SIP_PKT_INVITE:
                set_sip_version_field(p->pkt.invite.sip_version);
                break;
            case SIP_PKT_ACK:
                set_sip_version_field(p->pkt.ack.sip_version);
                break;
            case SIP_PKT_BYE:
                set_sip_version_field(p->pkt.bye.sip_version);
                break;
            case SIP_PKT_CANCEL:
                set_sip_version_field(p->pkt.cancel.sip_version);
                break;
            case SIP_PKT_REGISTER:
                set_sip_version_field(p->pkt.register_.sip_version);
                break;
            case SIP_PKT_OPTIONS:
                set_sip_version_field(p->pkt.options.sip_version);
                break;
            default: /* SIP_PKT_UNKNOWN or unhandled types */ 
                break;
        }
    }
}

/* SHOT-7: [SIP-6.6-Header-Field-Format]
 * Header fields are “field-name: value<CRLF>”; field-names are case-insensitive;
 * headers MAY be folded via LWS but senders SHOULD produce one header per line.
 * This fixer normalizes:
 *   1) header name text -> canonical case (e.g., "Call-ID")
 *   2) the separator    -> ": "
 *   3) terminator       -> "\r\n"
 *   4) header values    -> unfolded (strip CR/LF and collapse LWS)
 *
 * It operates in-place on an array of sip_packet_t.
 */


/* ===== Helpers ===== */

static inline void set_sep(char dst[SIP_SEPARATOR_LEN]) {
    /* NUL-terminated ": " */
    dst[0] = ':'; dst[1] = ' '; dst[2] = '\0';
}
static inline void set_crlf(char dst[SIP_CRLF_LEN]) {
    dst[0] = '\r'; dst[1] = '\n'; dst[2] = '\0';
}
static inline void set_name(char *dst, size_t cap, const char *canon) {
    size_t n = strlen(canon);
    if (n >= cap) n = cap - 1;
    memcpy(dst, canon, n);
    dst[n] = '\0';
}

/* Unfold & normalize LWS inside a header *value*:
   - Replace CR/LF/TAB with SP
   - Collapse runs of spaces to a single SP
   - Trim leading & trailing spaces */
static void unfold_lws(char *s, size_t cap) {
    if (!s || cap == 0) return;
    size_t r = 0, w = 0;
    int last_space = 1; /* start in "space" to trim leading */
    while (r < cap && s[r] != '\0') {
        unsigned char c = (unsigned char)s[r++];
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
        if (c == ' ') {
            if (!last_space) {
                if (w + 1 < cap) s[w++] = ' ';
                last_space = 1;
            }
        } else {
            if (w + 1 < cap) s[w++] = (char)c;
            last_space = 0;
        }
    }
    /* trim trailing space */
    while (w > 0 && s[w-1] == ' ') w--;
    s[w] = '\0';
}

/* Replace CR/LF in single-char markers that *must* be literal tokens */
static inline void enforce_char(char *dst, char must_be) {
    if (!dst) return;
    *dst = must_be;
}

/* ===== Per-header normalizers (present-if name[0] != '\0') ===== */

static void fix_accept(sip_accept_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Accept");
    set_sep(h->colon_space);
    enforce_char(&h->slash, '/');
    unfold_lws(h->media_type, sizeof(h->media_type));
    unfold_lws(h->sub_type, sizeof(h->sub_type));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_accept_encoding(sip_accept_encoding_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Accept-Encoding");
    set_sep(h->colon_space);
    unfold_lws(h->coding, sizeof(h->coding));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_accept_language(sip_accept_language_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Accept-Language");
    set_sep(h->colon_space);
    unfold_lws(h->lang_tag, sizeof(h->lang_tag));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_call_id(sip_call_id_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Call-ID");
    set_sep(h->colon_space);
    unfold_lws(h->value, sizeof(h->value));
    set_crlf(h->crlf);
}

static void fix_contact(sip_contact_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Contact");
    set_sep(h->colon_space);
    unfold_lws(h->display, sizeof(h->display));
    /* ensure one-line, keep URI punctuation */
    enforce_char(&h->lt, '<'); enforce_char(&h->gt, '>');
    /* keep or clear optional space in a sane way */
    if (h->display[0] != '\0') h->sp_opt = ' '; else h->sp_opt = '\0';
    unfold_lws(h->uri, sizeof(h->uri));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_cseq(sip_cseq_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "CSeq");
    set_sep(h->colon_space);
    unfold_lws(h->number, sizeof(h->number));
    h->sp = ' ';
    unfold_lws(h->method, sizeof(h->method));
    set_crlf(h->crlf);
}

static void fix_date(sip_date_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Date");
    set_sep(h->colon_space);
    unfold_lws(h->rfc1123, sizeof(h->rfc1123));
    set_crlf(h->crlf);
}

static void fix_encryption(sip_encryption_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Encryption");
    set_sep(h->colon_space);
    unfold_lws(h->scheme, sizeof(h->scheme));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_expires(sip_expires_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Expires");
    set_sep(h->colon_space);
    unfold_lws(h->value, sizeof(h->value));
    set_crlf(h->crlf);
}

static void fix_from(sip_from_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "From");
    set_sep(h->colon_space);
    unfold_lws(h->display, sizeof(h->display));
    if (h->display[0] != '\0') h->sp_opt = ' '; else h->sp_opt = '\0';
    enforce_char(&h->lt, '<'); enforce_char(&h->gt, '>');
    unfold_lws(h->uri, sizeof(h->uri));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_record_route(sip_record_route_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Record-Route");
    set_sep(h->colon_space);
    enforce_char(&h->lt, '<'); enforce_char(&h->gt, '>');
    unfold_lws(h->uri, sizeof(h->uri));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_timestamp(sip_timestamp_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Timestamp");
    set_sep(h->colon_space);
    unfold_lws(h->value, sizeof(h->value));
    unfold_lws(h->delay, sizeof(h->delay));
    h->sp_opt = (h->delay[0] ? ' ' : '\0');
    set_crlf(h->crlf);
}

static void fix_to(sip_to_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "To");
    set_sep(h->colon_space);
    unfold_lws(h->display, sizeof(h->display));
    if (h->display[0] != '\0') h->sp_opt = ' '; else h->sp_opt = '\0';
    enforce_char(&h->lt, '<'); enforce_char(&h->gt, '>');
    unfold_lws(h->uri, sizeof(h->uri));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_via(sip_via_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Via");
    set_sep(h->colon_space);
    unfold_lws(h->sent_protocol, sizeof(h->sent_protocol));
    h->sp = ' ';
    unfold_lws(h->sent_by, sizeof(h->sent_by));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_content_encoding(sip_content_encoding_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Content-Encoding");
    set_sep(h->colon_space);
    unfold_lws(h->coding, sizeof(h->coding));
    set_crlf(h->crlf);
}

static void fix_content_length(sip_content_length_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Content-Length");
    set_sep(h->colon_space);
    unfold_lws(h->length, sizeof(h->length));
    set_crlf(h->crlf);
}

static void fix_content_type(sip_content_type_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Content-Type");
    set_sep(h->colon_space);
    unfold_lws(h->type_tok, sizeof(h->type_tok));
    enforce_char(&h->slash, '/');
    unfold_lws(h->sub_type, sizeof(h->sub_type));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_authorization(sip_authorization_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Authorization");
    set_sep(h->colon_space);
    unfold_lws(h->scheme, sizeof(h->scheme));
    h->sp = ' ';
    unfold_lws(h->kvpairs, sizeof(h->kvpairs));
    set_crlf(h->crlf);
}

static void fix_hide(sip_hide_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Hide");
    set_sep(h->colon_space);
    unfold_lws(h->value, sizeof(h->value));
    set_crlf(h->crlf);
}

static void fix_max_forwards(sip_max_forwards_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Max-Forwards");
    set_sep(h->colon_space);
    unfold_lws(h->hops, sizeof(h->hops));
    set_crlf(h->crlf);
}

static void fix_organization(sip_organization_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Organization");
    set_sep(h->colon_space);
    unfold_lws(h->text, sizeof(h->text));
    set_crlf(h->crlf);
}

static void fix_priority(sip_priority_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Priority");
    set_sep(h->colon_space);
    unfold_lws(h->value, sizeof(h->value));
    set_crlf(h->crlf);
}

static void fix_proxy_authorization(sip_proxy_authorization_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Proxy-Authorization");
    set_sep(h->colon_space);
    unfold_lws(h->scheme, sizeof(h->scheme));
    h->sp = ' ';
    unfold_lws(h->kvpairs, sizeof(h->kvpairs));
    set_crlf(h->crlf);
}

static void fix_proxy_require(sip_proxy_require_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Proxy-Require");
    set_sep(h->colon_space);
    unfold_lws(h->option_tags, sizeof(h->option_tags));
    set_crlf(h->crlf);
}

static void fix_route(sip_route_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Route");
    set_sep(h->colon_space);
    enforce_char(&h->lt, '<'); enforce_char(&h->gt, '>');
    unfold_lws(h->uri, sizeof(h->uri));
    unfold_lws(h->params, sizeof(h->params));
    set_crlf(h->crlf);
}

static void fix_require(sip_require_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Require");
    set_sep(h->colon_space);
    unfold_lws(h->option_tags, sizeof(h->option_tags));
    set_crlf(h->crlf);
}

static void fix_response_key(sip_response_key_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Response-Key");
    set_sep(h->colon_space);
    unfold_lws(h->scheme, sizeof(h->scheme));
    h->sp = ' ';
    unfold_lws(h->kvpairs, sizeof(h->kvpairs));
    set_crlf(h->crlf);
}

static void fix_subject(sip_subject_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "Subject");
    set_sep(h->colon_space);
    unfold_lws(h->text, sizeof(h->text));
    set_crlf(h->crlf);
}

static void fix_user_agent(sip_user_agent_hdr_t *h) {
    if (!h || !h->name[0]) return;
    set_name(h->name, sizeof(h->name), "User-Agent");
    set_sep(h->colon_space);
    unfold_lws(h->product, sizeof(h->product));
    set_crlf(h->crlf);
}

/* ===== Packet-level fixers ===== */

static void fix_all_headers_in_invite(sip_invite_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_accept(&m->accept);
    fix_accept_encoding(&m->accept_encoding);
    fix_accept_language(&m->accept_language);
    fix_authorization(&m->authorization);
    fix_contact(&m->contact);
    fix_content_encoding(&m->content_encoding);
    fix_content_length(&m->content_length);
    fix_content_type(&m->content_type);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_expires(&m->expires);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_organization(&m->organization);
    fix_proxy_authorization(&m->proxy_authorization);
    fix_proxy_require(&m->proxy_require);
    fix_priority(&m->priority);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    fix_response_key(&m->response_key);
    fix_require(&m->require);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    fix_subject(&m->subject);
    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);
}

static void fix_all_headers_in_ack(sip_ack_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_authorization(&m->authorization);
    fix_contact(&m->contact);
    fix_content_length(&m->content_length);
    fix_content_type(&m->content_type);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_organization(&m->organization);
    fix_proxy_authorization(&m->proxy_authorization);
    fix_proxy_require(&m->proxy_require);
    fix_require(&m->require);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);
}

static void fix_all_headers_in_bye(sip_bye_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_accept_language(&m->accept_language);
    fix_authorization(&m->authorization);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_proxy_authorization(&m->proxy_authorization);
    fix_proxy_require(&m->proxy_require);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    fix_response_key(&m->response_key);
    fix_require(&m->require);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);
}

static void fix_all_headers_in_cancel(sip_cancel_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_accept_language(&m->accept_language);
    fix_authorization(&m->authorization);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_proxy_authorization(&m->proxy_authorization);
    fix_proxy_require(&m->proxy_require);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    fix_response_key(&m->response_key);
    fix_require(&m->require);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);
}

static void fix_all_headers_in_register(sip_register_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_accept(&m->accept);
    fix_accept_encoding(&m->accept_encoding);
    fix_accept_language(&m->accept_language);

    fix_authorization(&m->authorization);
    fix_proxy_authorization(&m->proxy_authorization);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    for (size_t i = 0; i < m->contact_count && i < SIP_MAX_CONTACT; ++i)
        fix_contact(&m->contact[i]);

    fix_content_encoding(&m->content_encoding);
    fix_content_length(&m->content_length);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_expires(&m->expires);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_organization(&m->organization);
    fix_proxy_require(&m->proxy_require);
    fix_response_key(&m->response_key);
    fix_require(&m->require);
    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);

    /* NOTE: Retry-After fallback struct uses non-standard 'sep' size; skip. */
}

static void fix_all_headers_in_options(sip_options_packet_t *m) {
    if (!m) return;
    fix_call_id(&m->call_id);
    fix_cseq(&m->cseq);
    fix_from(&m->from_);
    fix_to(&m->to_);
    for (size_t i = 0; i < m->via_count && i < SIP_MAX_VIA; ++i) fix_via(&m->via[i]);

    fix_accept(&m->accept);
    fix_accept_encoding(&m->accept_encoding);
    fix_accept_language(&m->accept_language);

    fix_authorization(&m->authorization);
    fix_proxy_authorization(&m->proxy_authorization);

    for (size_t i = 0; i < m->record_route_count && i < SIP_MAX_RECORD_ROUTE; ++i)
        fix_record_route(&m->record_route[i]);

    for (size_t i = 0; i < m->route_count && i < SIP_MAX_ROUTE; ++i)
        fix_route(&m->route[i]);

    for (size_t i = 0; i < m->contact_count && i < SIP_MAX_CONTACT; ++i)
        fix_contact(&m->contact[i]);

    fix_content_encoding(&m->content_encoding);
    fix_content_length(&m->content_length);
    fix_date(&m->date);
    fix_encryption(&m->encryption);
    fix_hide(&m->hide);
    fix_max_forwards(&m->max_forwards);
    fix_organization(&m->organization);
    fix_proxy_require(&m->proxy_require);
    fix_response_key(&m->response_key);
    fix_require(&m->require);
    fix_timestamp(&m->timestamp);
    fix_user_agent(&m->user_agent);
}

/* ===== Public entry point ===== */

void fix_shot7_header_field_format(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        switch (p->cmd_type) {
            case SIP_PKT_INVITE:   fix_all_headers_in_invite(&p->pkt.invite);     break;
            case SIP_PKT_ACK:      fix_all_headers_in_ack(&p->pkt.ack);           break;
            case SIP_PKT_BYE:      fix_all_headers_in_bye(&p->pkt.bye);           break;
            case SIP_PKT_CANCEL:   fix_all_headers_in_cancel(&p->pkt.cancel);     break;
            case SIP_PKT_REGISTER: fix_all_headers_in_register(&p->pkt.register_);break;
            case SIP_PKT_OPTIONS:  fix_all_headers_in_options(&p->pkt.options);   break;
            default: /* SIP_PKT_UNKNOWN */ break;
        }
    }
}


/* SHOT-10: [SIP-6.15-Content-Length-Parsing]
 *
 * Constraint recap:
 * - If Content-Length is present, its value (bytes) DEFINES the message-body length.
 * - Over TCP, if Content-Length is absent, body length is zero.
 * - Over UDP, if Content-Length is absent, the remainder of the datagram is the body.
 * - If Content-Length is too small, TCP connection is closed.
 *
 * Our fixer operates purely on the in-memory sip_packet_t structures (no transport
 * context, no socket control). To make packets safe and unambiguous across transports,
 * we ensure that:
 *   1) Content-Length header is PRESENT for packets that carry a body buffer,
 *   2) It is CANONICAL ("Content-Length: <len>\r\n"),
 *   3) Its numeric value EXACTLY MATCHES the current body bytes (NUL-terminated,
 *      up to SIP_BODY_MAX).
 *
 * This prevents undersized Content-Length (which would otherwise imply a TCP close)
 * and removes ambiguity when the header is missing (UDP remainder case).
 *
 * The function fixes the array IN PLACE.
 */


/* ---------- helpers ---------- */

static inline void cl_set_name_sep_crlf(sip_content_length_hdr_t *h) {
    /* name */
    const char *canon = "Content-Length";
    size_t n = strlen(canon);
    if (n >= sizeof(h->name)) n = sizeof(h->name) - 1;
    memcpy(h->name, canon, n);
    h->name[n] = '\0';

    /* ": " */
    h->colon_space[0] = ':'; h->colon_space[1] = ' '; h->colon_space[2] = '\0';

    /* "\r\n" */
    h->crlf[0] = '\r'; h->crlf[1] = '\n'; h->crlf[2] = '\0';
}

/* bounded strlen for possibly non-filled buffers */
static size_t buf_nstrlen(const char *s, size_t cap) {
    if (!s) return 0;
    size_t i = 0;
    while (i < cap && s[i] != '\0') ++i;
    return i;
}

static void cl_sync_header_to_body(sip_content_length_hdr_t *h,
                                   const char *body,
                                   size_t body_cap)
{
    if (!h) return;
    /* compute current body length (bytes) under our storage model */
    size_t blen = buf_nstrlen(body, body_cap);

    /* canonicalize header boilerplate and set numeric value */
    cl_set_name_sep_crlf(h);
    (void)snprintf(h->length, sizeof(h->length), "%zu", blen);
}

/* ---------- per-message fixers ---------- */

static void fix_cl_invite(sip_invite_packet_t *m){
    if (!m) return;
    cl_sync_header_to_body(&m->content_length, m->body, sizeof(m->body));
}

static void fix_cl_ack(sip_ack_packet_t *m){
    if (!m) return;
    cl_sync_header_to_body(&m->content_length, m->body, sizeof(m->body));
}

static void fix_cl_register(sip_register_packet_t *m){
    if (!m) return;
    cl_sync_header_to_body(&m->content_length, m->body, sizeof(m->body));
}

static void fix_cl_options(sip_options_packet_t *m){
    if (!m) return;
    cl_sync_header_to_body(&m->content_length, m->body, sizeof(m->body));
}

/* BYE/CANCEL structures in this model do not carry a Content-Length header member,
   so we cannot (and need not) adjust it here. If their body is non-empty and your
   pipeline requires a Content-Length header, extend the structs similarly. */

/* ---------- public entry point ---------- */

void fix_shot10_content_length_parsing(sip_packet_t *arr, size_t num_packets){
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        switch (p->cmd_type) {
            case SIP_PKT_INVITE:   fix_cl_invite(&p->pkt.invite);       break;
            case SIP_PKT_ACK:      fix_cl_ack(&p->pkt.ack);             break;
            case SIP_PKT_REGISTER: fix_cl_register(&p->pkt.register_);  break;
            case SIP_PKT_OPTIONS:  fix_cl_options(&p->pkt.options);     break;

            /* These types have no Content-Length field in the provided model. */
            case SIP_PKT_BYE:
            case SIP_PKT_CANCEL:
            case SIP_PKT_UNKNOWN:
            default:
                break;
        }
    }
}


#include <strings.h>


/* ---------- helpers ---------- */

static int ci_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    return strcasecmp(a, b) == 0;
}

static void cl_set(sip_content_length_hdr_t *cl, size_t n) {
    if (!cl) return;
    /* mark header present and fill fields */
    snprintf(cl->name, sizeof(cl->name), "Content-Length");
    snprintf(cl->colon_space, sizeof(cl->colon_space), ": ");
    snprintf(cl->length, sizeof(cl->length), "%zu", n);
    snprintf(cl->crlf, sizeof(cl->crlf), "\r\n");
}

static void ce_clear_if_chunked(sip_content_encoding_hdr_t *ce) {
    if (!ce) return;
    if (ce->name[0] == '\0') return; /* absent */
    if (ci_eq(ce->coding, "chunked")) {
        /* This header is misused for transfer-coding; drop it. */
        ce->name[0] = '\0';
    }
}

/* Very small HTTP/1.1 chunked decoder (tolerates chunk-extensions).
 * Returns 1 if decoded and body changed, 0 if input did not look like valid chunked.
 * Works on NUL-terminated text bodies (typical for SIP/SDP). */
static int http_chunked_decode_inplace(char *buf) {
    if (!buf) return 0;
    size_t len = strlen(buf);
    size_t r = 0, w = 0;

    /* Require: first line begins with 1+ hex digits and ends with CRLF */
    while (r < len) {
        /* Parse chunk-size line: <hex>[;ext...] \r\n */
        size_t line_start = r;
        size_t i = r;
        int saw_hex = 0;
        while (i < len && isxdigit((unsigned char)buf[i])) { saw_hex = 1; i++; }
        if (!saw_hex) return 0;
        /* skip extensions until CRLF */
        while (i + 1 < len && !(buf[i] == '\r' && buf[i+1] == '\n')) { i++; }
        if (i + 1 >= len) return 0;

        /* extract hex number up to ';' or CR */
        char hexnum[32];
        size_t hn = 0;
        for (size_t j = line_start; j < i && hn + 1 < sizeof(hexnum); j++) {
            if (buf[j] == ';') break;
            hexnum[hn++] = buf[j];
        }
        hexnum[hn] = '\0';
        unsigned long chunk_sz = strtoul(hexnum, NULL, 16);

        r = i + 2; /* past CRLF */

        if (chunk_sz == 0) {
            /* final-chunk: optional trailers followed by CRLF CRLF — we just stop here */
            buf[w] = '\0';
            return 1;
        }

        if (r + chunk_sz + 2 > len) return 0; /* not enough data */

        /* copy data */
        memmove(buf + w, buf + r, chunk_sz);
        w += chunk_sz;
        r += chunk_sz;

        /* each chunk data must be followed by CRLF */
        if (r + 1 >= len || buf[r] != '\r' || buf[r+1] != '\n') return 0;
        r += 2;
    }
    /* No zero-sized chunk encountered -> not valid chunked */
    return 0;
}

/* Create a view for packets that can carry a body and the related headers. */
typedef struct {
    char *body; /* may be NULL if packet has no body buffer */
    sip_content_length_hdr_t *cl;
    sip_content_encoding_hdr_t *ce;
} sip_body_view_t;

static int get_body_view(sip_packet_t *p, sip_body_view_t *v) {
    if (!p || !v) return 0;
    v->body = NULL; v->cl = NULL; v->ce = NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            v->body = p->pkt.invite.body;
            v->cl   = &p->pkt.invite.content_length;
            v->ce   = &p->pkt.invite.content_encoding;
            return 1;
        case SIP_PKT_ACK:
            v->body = p->pkt.ack.body;
            v->cl   = &p->pkt.ack.content_length;
            return 1;
        case SIP_PKT_REGISTER:
            v->body = p->pkt.register_.body;
            v->cl   = &p->pkt.register_.content_length;
            v->ce   = &p->pkt.register_.content_encoding;
            return 1;
        case SIP_PKT_OPTIONS:
            v->body = p->pkt.options.body;
            v->cl   = &p->pkt.options.content_length;
            v->ce   = &p->pkt.options.content_encoding;
            return 1;
        /* BYE / CANCEL do not have body buffers or Content-* headers in this model */
        default:
            return 0;
    }
}

/* ---------- main fixer ---------- */
/* SHOT-11: [SIP-6.16-No-Chunked]
 * HTTP/1.1 “chunked” transfer-coding MUST NOT be used in SIP requests.
 * Strategy:
 *  1) If Content-Encoding is (incorrectly) set to "chunked", remove that header.
 *  2) If the message body appears to be HTTP chunked, decode it in place and
 *     update/insert an accurate Content-Length.
 */
void fix_sip_shot11_no_chunked(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        sip_body_view_t v;
        if (!get_body_view(p, &v)) continue;

        /* 1) Drop any misuse of Content-Encoding: chunked */
        ce_clear_if_chunked(v.ce);

        /* 2) If body looks chunked, decode it and fix Content-Length */
        if (v.body && v.body[0]) {
            if (http_chunked_decode_inplace(v.body)) {
                size_t new_len = strlen(v.body);
                cl_set(v.cl, new_len);
            }
        }
    }
}


#include <stdlib.h>
#include <stdint.h>


/*
 * SHOT-12: [SIP-6.17-CSeq]
 * Every request MUST contain exactly one CSeq header field.
 * - CSeq number is a 32-bit unsigned integer.
 * - It increases by one for each new request within a call leg.
 * - CANCEL and ACK use the same CSeq as the request being cancelled/acknowledged (typically INVITE).
 *
 * Assumptions / Strategy for fixing in-place:
 * 1) This model contains exactly one cseq struct per request; we ensure it is present and well-formed.
 * 2) We treat the input array order as chronological.
 * 3) We define a "leg key" primarily by Call-ID + From-tag + To-tag when present (falling back to Call-ID + From-tag, then Call-ID).
 * 4) For each leg, we maintain:
 *      - next_expected: next CSeq to assign for *new* requests (non-ACK/CANCEL).
 *      - last_request:  last CSeq used for a new request in this leg.
 *      - last_invite:   last CSeq used for INVITE in this leg (for ACK/CANCEL alignment).
 * 5) For non-ACK/CANCEL requests:
 *      - If first occurrence in a leg and current CSeq parses as valid uint32 => keep it, set next_expected = number + 1.
 *      - Otherwise set number = next_expected and then next_expected++ (32-bit wrap allowed).
 * 6) For ACK/CANCEL:
 *      - If we have last_invite, set CSeq to that; else fall back to last_request (if any).
 * 7) Ensure CSeq header line is syntactically normalized: name, ": ", <number>, " ", <METHOD>, CRLF.
 */

/* -------------------- small helpers -------------------- */

static inline void set_cseq_line(sip_cseq_hdr_t *cseq, uint32_t num, const char *method) {
    if (!cseq || !method) return;
    snprintf(cseq->name, sizeof(cseq->name), "CSeq");
    snprintf(cseq->colon_space, sizeof(cseq->colon_space), ": ");
    snprintf(cseq->number, sizeof(cseq->number), "%u", (unsigned)num);
    cseq->sp = ' ';
    snprintf(cseq->method, sizeof(cseq->method), "%s", method);
    snprintf(cseq->crlf, sizeof(cseq->crlf), "\r\n");
}

/* parse a positive uint32 from text; return 1 on success */
static int parse_uint32_ci(const char *s, uint32_t *out) {
    if (!s || !*s) return 0;
    const char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!isdigit((unsigned char)*p)) return 0;
    unsigned long long v = 0;
    while (*p && isdigit((unsigned char)*p)) {
        v = v * 10ull + (unsigned)(*p - '0');
        if (v > 0xFFFFFFFFull) return 0;
        p++;
    }
    /* allow trailing spaces */
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '\0') {
        /* non-space trailing chars -> treat as invalid */
        return 0;
    }
    if (out) *out = (uint32_t)v;
    return 1;
}

static uint32_t inc_u32(uint32_t x) { return (uint32_t)(x + 1u); }

/* Extract ;tag=VALUE from parameter string (e.g., ";tag=xyz;foo=1").
 * Writes up to tag_buf_len-1 chars. Returns 1 if found. */
static int extract_tag(const char *params, char *tag_buf, size_t tag_buf_len) {
    if (tag_buf_len == 0) return 0;
    tag_buf[0] = '\0';
    if (!params || !*params) return 0;

    const char *p = params;
    while (*p) {
        /* find start of a param */
        if (*p == ';') {
            p++;
            const char *key = p;
            while (*p && *p != '=' && *p != ';') p++;
            size_t keylen = (size_t)(p - key);
            if (keylen == 3 && strncasecmp(key, "tag", 3) == 0 && *p == '=') {
                p++; /* skip '=' */
                const char *val = p;
                while (*p && *p != ';') p++;
                size_t vlen = (size_t)(p - val);
                if (vlen >= tag_buf_len) vlen = tag_buf_len - 1;
                memcpy(tag_buf, val, vlen);
                tag_buf[vlen] = '\0';
                return 1;
            }
            /* skip to next ';' or end */
            while (*p && *p != ';') p++;
        } else {
            p++;
        }
    }
    return 0;
}

/* Get request-line method string for a packet. */
static const char* pkt_method_str(const sip_packet_t *p) {
    if (!p) return "UNKNOWN";
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:  return p->pkt.invite.method;
        case SIP_PKT_ACK:     return p->pkt.ack.method;
        case SIP_PKT_BYE:     return p->pkt.bye.method;
        case SIP_PKT_CANCEL:  return p->pkt.cancel.method;
        case SIP_PKT_REGISTER:return p->pkt.register_.method;
        case SIP_PKT_OPTIONS: return p->pkt.options.method;
        default: return "UNKNOWN";
    }
}

/* Get pointers to CSeq header and related mandatory headers for a packet. */
typedef struct {
    sip_cseq_hdr_t *cseq;
    sip_call_id_hdr_t *call_id;
    const char *from_params;
    const char *to_params;
    const char *req_method; /* request-line method */
    int is_ack;
    int is_cancel;
    int is_new_request; /* true for "new" requests (not ACK/CANCEL) */
} sip_req_view_t;

static int view_from_pkt(sip_packet_t *p, sip_req_view_t *v) {
    if (!p || !v) return 0;
    memset(v, 0, sizeof(*v));
    v->req_method = pkt_method_str(p);
    v->is_ack    = 0;
    v->is_cancel = 0;
    v->is_new_request = 0;

    switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            v->cseq = &p->pkt.invite.cseq;
            v->call_id = &p->pkt.invite.call_id;
            v->from_params = p->pkt.invite.from_.params;
            v->to_params   = p->pkt.invite.to_.params;
            v->is_new_request = 1;
            break;
        case SIP_PKT_ACK:
            v->cseq = &p->pkt.ack.cseq;
            v->call_id = &p->pkt.ack.call_id;
            v->from_params = p->pkt.ack.from_.params;
            v->to_params   = p->pkt.ack.to_.params;
            v->is_ack = 1;
            break;
        case SIP_PKT_BYE:
            v->cseq = &p->pkt.bye.cseq;
            v->call_id = &p->pkt.bye.call_id;
            v->from_params = p->pkt.bye.from_.params;
            v->to_params   = p->pkt.bye.to_.params;
            v->is_new_request = 1;
            break;
        case SIP_PKT_CANCEL:
            v->cseq = &p->pkt.cancel.cseq;
            v->call_id = &p->pkt.cancel.call_id;
            v->from_params = p->pkt.cancel.from_.params;
            v->to_params   = p->pkt.cancel.to_.params;
            v->is_cancel = 1;
            break;
        case SIP_PKT_REGISTER:
            v->cseq = &p->pkt.register_.cseq;
            v->call_id = &p->pkt.register_.call_id;
            v->from_params = p->pkt.register_.from_.params;
            v->to_params   = p->pkt.register_.to_.params;
            v->is_new_request = 1;
            break;
        case SIP_PKT_OPTIONS:
            v->cseq = &p->pkt.options.cseq;
            v->call_id = &p->pkt.options.call_id;
            v->from_params = p->pkt.options.from_.params;
            v->to_params   = p->pkt.options.to_.params;
            v->is_new_request = 1;
            break;
        default:
            return 0;
    }
    return 1;
}

/* Build a leg key string: Call-ID|FromTag|ToTag (case-insensitive on tags not required here).
 * key_out must have room; we keep it modest. */
static void build_leg_key(const sip_req_view_t *v, char *key_out, size_t key_len) {
    const char *cid = v->call_id ? v->call_id->value : "";
    char ftag[128], ttag[128];
    ftag[0] = ttag[0] = '\0';
    (void)extract_tag(v->from_params, ftag, sizeof(ftag));
    (void)extract_tag(v->to_params,   ttag, sizeof(ttag));
    if (key_len == 0) return;
    /* Prefer both tags if present, else degrade. */
    if (ftag[0] && ttag[0]) {
        snprintf(key_out, key_len, "%s|%s|%s", cid, ftag, ttag);
    } else if (ftag[0]) {
        snprintf(key_out, key_len, "%s|%s|", cid, ftag);
    } else {
        snprintf(key_out, key_len, "%s||", cid);
    }
}

/* -------------------- leg state table -------------------- */

typedef struct {
    char key[512];
    int in_use;
    uint32_t next_expected;  /* next seq for new request */
    uint32_t last_request;   /* last seq used for a new request */
    int have_last_request;
    uint32_t last_invite;    /* last seq used for INVITE */
    int have_last_invite;
} leg_state_t;

#define MAX_LEGS 128

static leg_state_t* find_or_add_leg(leg_state_t table[], const char *key) {
    int free_idx = -1;
    for (int i = 0; i < MAX_LEGS; ++i) {
        if (table[i].in_use) {
            if (strncmp(table[i].key, key, sizeof(table[i].key)) == 0) {
                return &table[i];
            }
        } else if (free_idx < 0) {
            free_idx = i;
        }
    }
    if (free_idx >= 0) {
        leg_state_t *ls = &table[free_idx];
        memset(ls, 0, sizeof(*ls));
        snprintf(ls->key, sizeof(ls->key), "%s", key);
        ls->in_use = 1;
        ls->next_expected = 1; /* default start */
        ls->have_last_request = 0;
        ls->have_last_invite = 0;
        return ls;
    }
    /* Fallback: reuse slot 0 if table exhausted (unlikely) */
    return &table[0];
}

/* Normalize header syntax (name, separators, CRLF) regardless of numeric fix outcome. */
static void normalize_cseq_header(sip_cseq_hdr_t *cseq, const char *req_method) {
    uint32_t num = 0;
    if (!parse_uint32_ci(cseq->number, &num)) {
        num = 1u;
    }
    set_cseq_line(cseq, num, req_method ? req_method : "UNKNOWN");
}

/* -------------------- main fixer -------------------- */

void fix_sip_shot12_cseq(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    leg_state_t legs[MAX_LEGS];
    memset(legs, 0, sizeof(legs));

    for (size_t i = 0; i < num_packets; ++i) {
        sip_req_view_t v;
        if (!view_from_pkt(&arr[i], &v)) continue;

        /* Ensure CSeq header exists and syntactically normalized first */
        normalize_cseq_header(v.cseq, v.req_method);

        /* Build/find leg */
        char key[512];
        build_leg_key(&v, key, sizeof(key));
        leg_state_t *ls = find_or_add_leg(legs, key);

        /* Current CSeq numeric value (post-normalization) */
        uint32_t cur = 0;
        int have_cur = parse_uint32_ci(v.cseq->number, &cur);
        if (!have_cur) cur = 0;

        if (v.is_ack || v.is_cancel) {
            /* ACK/CANCEL must reuse the INVITE CSeq when available, else last request */
            uint32_t target;
            if (ls->have_last_invite) {
                target = ls->last_invite;
            } else if (ls->have_last_request) {
                target = ls->last_request;
            } else if (have_cur) {
                target = cur; /* nothing known, keep */
            } else {
                target = 1u;
            }
            set_cseq_line(v.cseq, target, v.req_method);
            /* Do not change next_expected for ACK/CANCEL */
        } else {
            /* New request (INVITE/BYE/REGISTER/OPTIONS/...) */
            if (!ls->have_last_request) {
                /* first in this leg: if current is valid, keep it; else initialize to 1 */
                uint32_t base = have_cur ? cur : 1u;
                set_cseq_line(v.cseq, base, v.req_method);
                ls->last_request = base;
                ls->have_last_request = 1;
                if (arr[i].cmd_type == SIP_PKT_INVITE) {
                    ls->last_invite = base;
                    ls->have_last_invite = 1;
                }
                ls->next_expected = inc_u32(base);
            } else {
                /* enforce strictly +1 progression */
                uint32_t target = ls->next_expected;
                set_cseq_line(v.cseq, target, v.req_method);
                ls->last_request = target;
                if (arr[i].cmd_type == SIP_PKT_INVITE) {
                    ls->last_invite = target;
                    ls->have_last_invite = 1;
                }
                ls->next_expected = inc_u32(target);
            }
        }
    }
}



/*
 * SHOT-13: [SIP-6.21-From]
 * Every request MUST contain a From header field identifying the initiator;
 * UACs MUST include a "tag" parameter in From. This fixer:
 *   1) Ensures each request has a syntactically valid "From" header line.
 *   2) Ensures a single, canonical ;tag=XYZ is present in From-params.
 *   3) Keeps one stable tag per "leg" across the input array (keyed by Call-ID + From-URI).
 *
 * Fixes are applied in-place to the provided sip_packet_t array.
 */

/* ====================== small helpers ====================== */

static int ci_equal_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (tolower(ca) != tolower(cb)) return 0;
    }
    return 1;
}


/* Extract ;tag=VALUE from parameter string (e.g., ";tag=xyz;foo=1").
 * Writes up to tag_buf_len-1 chars. Returns 1 if found. */
static int extract_from_tag(const char *params, char *tag_buf, size_t tag_buf_len) {
    if (!params || !*params || tag_buf_len == 0) return 0;
    tag_buf[0] = '\0';

    const char *p = params;
    while (*p) {
        if (*p == ';') {
            p++;
            const char *key = p;
            while (*p && *p != '=' && *p != ';') p++;
            size_t keylen = (size_t)(p - key);
            if (keylen == 3 && ci_equal_n(key, "tag", 3) && *p == '=') {
                p++; /* skip '=' */
                const char *val = p;
                while (*p && *p != ';') p++;
                size_t vlen = (size_t)(p - val);
                if (vlen >= tag_buf_len) vlen = tag_buf_len - 1;
                memcpy(tag_buf, val, vlen);
                tag_buf[vlen] = '\0';
                return 1;
            }
            while (*p && *p != ';') p++;
        } else {
            p++;
        }
    }
    return 0;
}

/* Remove all ;tag=... occurrences from params. Preserve other params. */
static void strip_tag_params(const char *params_in, char *params_out, size_t out_len) {
    if (!params_out || out_len == 0) return;
    params_out[0] = '\0';
    if (!params_in || !*params_in) return;

    const char *p = params_in;
    size_t out_used = 0;

    while (*p) {
        if (*p == ';') {
            const char *start = p; /* include leading ';' */
            p++;
            const char *key = p;
            while (*p && *p != '=' && *p != ';') p++;
            size_t keylen = (size_t)(p - key);
            int is_tag = (keylen == 3 && ci_equal_n(key, "tag", 3));

            if (*p == '=') {
                p++;
                while (*p && *p != ';') p++; /* consume value */
            }
            /* p now at ';' or '\0' */

            if (!is_tag) {
                size_t copy_len = (size_t)(p - start);
                if (copy_len > 0) {
                    if (copy_len >= out_len - out_used) copy_len = (out_len - out_used) - 1;
                    if (copy_len > 0) {
                        memcpy(params_out + out_used, start, copy_len);
                        out_used += copy_len;
                        params_out[out_used] = '\0';
                    }
                }
            }
        } else {
            /* Unexpected char before first ';' (shouldn't happen, but keep it) */
            char c[2] = { *p, '\0' };
            if (out_used + 1 < out_len) {
                params_out[out_used++] = c[0];
                params_out[out_used] = '\0';
            }
            p++;
        }
    }
}

/* Ensure presence of a single ;tag=<tag> at end of params (after removing any existing tag).
 * params_buf is updated in-place. */
static void upsert_tag_param(char *params_buf, size_t buf_len, const char *tag_value) {
    if (!params_buf || buf_len == 0 || !tag_value) return;

    /* 1) Build a stripped copy without any tag */
    char stripped[SIP_PARAMS_LEN];
    strip_tag_params(params_buf, stripped, sizeof(stripped));

    /* 2) Append ;tag=VALUE */
    char appended[SIP_PARAMS_LEN];
    appended[0] = '\0';
    if (stripped[0] != '\0') {
        snprintf(appended, sizeof(appended), "%s;tag=%s", stripped, tag_value);
    } else {
        snprintf(appended, sizeof(appended), ";tag=%s", tag_value);
    }

    /* 3) Copy back (truncate if needed, maintain NUL) */
    snprintf(params_buf, buf_len, "%s", appended);
}

/* Minimal "From" header synthesis if input is broken/empty. */
static void synthesize_min_from(sip_from_hdr_t *fromh) {
    if (!fromh) return;
    snprintf(fromh->name, sizeof(fromh->name), "From");
    snprintf(fromh->colon_space, sizeof(fromh->colon_space), ": ");
    fromh->display[0] = '\0';      /* no display-name */
    fromh->sp_opt = ' ';           /* put a space before <...> */
    fromh->lt = '<';
    snprintf(fromh->uri, sizeof(fromh->uri), "sip:anonymous@localhost");
    fromh->gt = '>';
    fromh->params[0] = '\0';       /* params will be appended later */
    snprintf(fromh->crlf, sizeof(fromh->crlf), "\r\n");
}

/* Normalize "From" header's fixed tokens (name, sep, delimiters, CRLF). */
static void normalize_from_tokens(sip_from_hdr_t *fromh) {
    if (!fromh) return;
    if (fromh->name[0] == '\0') snprintf(fromh->name, sizeof(fromh->name), "From");
    if (fromh->colon_space[0] == '\0') snprintf(fromh->colon_space, sizeof(fromh->colon_space), ": ");
    if (fromh->lt == '\0') fromh->lt = '<';
    if (fromh->gt == '\0') fromh->gt = '>';
    if (fromh->crlf[0] == '\0') snprintf(fromh->crlf, sizeof(fromh->crlf), "\r\n");
    if (fromh->sp_opt == '\0')  fromh->sp_opt = ' ';
}

/* Compute a stable-ish small hash for a string (for tag derivation). */
static uint32_t djb2_hash_ci(const char *s) {
    uint32_t h = 5381u;
    if (!s) return h;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        h = ((h << 5) + h) + (uint32_t)tolower(c); /* h*33 + c */
    }
    return h ? h : 0xA5A5A5A5u;
}

/* Build a leg key: Call-ID + '|' + From-URI (without params). */
static void build_leg_key1(const sip_call_id_hdr_t *cid,
                          const char *from_uri,
                          char *out, size_t out_len) {
    const char *cidv = (cid && cid->value[0]) ? cid->value : "";
    const char *uri  = (from_uri && from_uri[0]) ? from_uri : "";
    if (out_len == 0) return;
    snprintf(out, out_len, "%s|%s", cidv, uri);
}

/* Generate a deterministic tag for the leg from Call-ID + URI. */
static void generate_leg_tag(const char *leg_key, char *tag_out, size_t tag_len) {
    if (!tag_out || tag_len == 0) return;
    uint32_t h = djb2_hash_ci(leg_key);
    /* short deterministic tag */
    snprintf(tag_out, tag_len, "t%08x", (unsigned)h);
}

/* =================== packet routing helpers =================== */

typedef struct {
    sip_from_hdr_t *fromh;
    sip_call_id_hdr_t *call_id;
} from_view_t;

static int get_from_view(sip_packet_t *p, from_view_t *v) {
    if (!p || !v) return 0;
    memset(v, 0, sizeof(*v));
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            v->fromh = &p->pkt.invite.from_;
            v->call_id = &p->pkt.invite.call_id;
            return 1;
        case SIP_PKT_ACK:
            v->fromh = &p->pkt.ack.from_;
            v->call_id = &p->pkt.ack.call_id;
            return 1;
        case SIP_PKT_BYE:
            v->fromh = &p->pkt.bye.from_;
            v->call_id = &p->pkt.bye.call_id;
            return 1;
        case SIP_PKT_CANCEL:
            v->fromh = &p->pkt.cancel.from_;
            v->call_id = &p->pkt.cancel.call_id;
            return 1;
        case SIP_PKT_REGISTER:
            v->fromh = &p->pkt.register_.from_;
            v->call_id = &p->pkt.register_.call_id;
            return 1;
        case SIP_PKT_OPTIONS:
            v->fromh = &p->pkt.options.from_;
            v->call_id = &p->pkt.options.call_id;
            return 1;
        default:
            return 0;
    }
}

/* =================== leg state table =================== */

typedef struct {
    int in_use;
    char key[512];
    char tag[64];
} from_leg_t;

#define MAX_FROM_LEGS 256

static from_leg_t* find_or_add_leg1(from_leg_t table[], const char *key) {
    int free_idx = -1;
    for (int i = 0; i < MAX_FROM_LEGS; ++i) {
        if (table[i].in_use) {
            if (strncmp(table[i].key, key, sizeof(table[i].key)) == 0) {
                return &table[i];
            }
        } else if (free_idx < 0) {
            free_idx = i;
        }
    }
    if (free_idx >= 0) {
        from_leg_t *slot = &table[free_idx];
        memset(slot, 0, sizeof(*slot));
        snprintf(slot->key, sizeof(slot->key), "%s", key);
        slot->in_use = 1;
        slot->tag[0] = '\0';
        return slot;
    }
    /* fallback: reuse slot 0 if exhausted */
    return &table[0];
}

/* =================== main fixer =================== */

void fix_sip_shot13_from(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    from_leg_t legs[MAX_FROM_LEGS];
    memset(legs, 0, sizeof(legs));

    for (size_t i = 0; i < num_packets; ++i) {
        from_view_t v;
        if (!get_from_view(&arr[i], &v)) continue;

        /* Synthesize/normalize a minimal From header if broken */
        if (!v.fromh->uri[0]) {
            synthesize_min_from(v.fromh);
        } else {
            normalize_from_tokens(v.fromh);
        }

        /* Build leg key (Call-ID + From-URI) */
        char leg_key[512];
        build_leg_key1(v.call_id, v.fromh->uri, leg_key, sizeof(leg_key));
        from_leg_t *leg = find_or_add_leg1(legs, leg_key);

        /* Learn/assign the canonical tag for this leg */
        char existing_tag[64];
        int have_existing = extract_from_tag(v.fromh->params, existing_tag, sizeof(existing_tag));

        if (leg->tag[0] == '\0') {
            if (have_existing && existing_tag[0] != '\0') {
                snprintf(leg->tag, sizeof(leg->tag), "%s", existing_tag);
            } else {
                char gtag[64];
                generate_leg_tag(leg_key, gtag, sizeof(gtag));
                snprintf(leg->tag, sizeof(leg->tag), "%s", gtag);
            }
        }

        /* Ensure exactly one ;tag=<canonical> present */
        upsert_tag_param(v.fromh->params, sizeof(v.fromh->params), leg->tag);

        /* Make sure header tokens are still sane */
        normalize_from_tokens(v.fromh);

        /* If somehow URI got wiped, synthesize a minimal one */
        if (!v.fromh->uri[0]) {
            snprintf(v.fromh->uri, sizeof(v.fromh->uri), "sip:anonymous@localhost");
        }
    }
}

/*
 * SHOT-14: [SIP-6.37-To]
 *  - Every request MUST contain a To header field identifying the target.
 *  - A To URI with an unrecognized scheme would cause 400; here we FIX by
 *    coercing the scheme to a recognized one ("sip:" by default).
 *  - Name-addr form MUST be used if the addr-spec contains ',' '?' or ';'.
 *
 * This fixer:
 *   • Ensures there is a syntactically valid To header for each request.
 *   • Ensures the To-URI uses a recognized scheme (sip/sips/tel). Unknown or
 *     missing scheme is rewritten to "sip:" (preserving the content after ':'
 *     if present).
 *   • Ensures name-addr form (angle brackets) when the URI contains ',', '?' or ';'.
 *   • Normalizes constant tokens: header name "To", ": ", CRLF, and delimiters.
 *
 * All changes are applied IN-PLACE on the provided array.
 */


static int is_known_scheme(const char *uri) {
    if (!uri || !*uri) return 0;
    return ci_starts_with(uri, "sip:")  ||
           ci_starts_with(uri, "sips:") ||
           ci_starts_with(uri, "tel:");
}

static void coerce_uri_scheme_to_sip(char *uri_buf, size_t buf_len) {
    if (!uri_buf || buf_len == 0) return;
    if (!*uri_buf) {
        /* No URI -> synthesize a minimal one */
        snprintf(uri_buf, buf_len, "sip:unknown@localhost");
        return;
    }

    const char *colon = strchr(uri_buf, ':');
    char tmp[SIP_URI_LEN];

    if (colon) {
        /* Replace existing (possibly unknown) scheme with sip: preserving rhs */
        const char *rhs = colon + 1; /* content after ':' */
        snprintf(tmp, sizeof(tmp), "sip:%s", rhs);
    } else {
        /* No scheme present, prefix with sip: */
        snprintf(tmp, sizeof(tmp), "sip:%s", uri_buf);
    }

    /* Copy back safely */
    tmp[sizeof(tmp)-1] = '\0';
    snprintf(uri_buf, buf_len, "%s", tmp);
}

static int uri_needs_name_addr(const char *uri) {
    if (!uri) return 0;
    return (strchr(uri, ',') != NULL) ||
           (strchr(uri, '?') != NULL) ||
           (strchr(uri, ';') != NULL);
}

static void normalize_to_tokens(sip_to_hdr_t *toh) {
    if (!toh) return;
    if (toh->name[0] == '\0')        snprintf(toh->name, sizeof(toh->name), "To");
    if (toh->colon_space[0] == '\0') snprintf(toh->colon_space, sizeof(toh->colon_space), ": ");
    if (toh->crlf[0] == '\0')        snprintf(toh->crlf, sizeof(toh->crlf), "\r\n");
    /* If name-addr is required (or already used), enforce delimiters and space */
    if (uri_needs_name_addr(toh->uri) || toh->lt == '<' || toh->gt == '>') {
        toh->sp_opt = (toh->sp_opt == '\0') ? ' ' : toh->sp_opt;
        toh->lt = '<';
        toh->gt = '>';
    }
}

static void synthesize_min_to(sip_to_hdr_t *toh) {
    if (!toh) return;
    snprintf(toh->name, sizeof(toh->name), "To");
    snprintf(toh->colon_space, sizeof(toh->colon_space), ": ");
    toh->display[0] = '\0';
    toh->sp_opt = ' ';
    toh->lt = '<';
    snprintf(toh->uri, sizeof(toh->uri), "sip:unknown@localhost");
    toh->gt = '>';
    toh->params[0] = '\0';
    snprintf(toh->crlf, sizeof(toh->crlf), "\r\n");
}

static sip_to_hdr_t* get_to_view(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.to_;
        case SIP_PKT_ACK:      return &p->pkt.ack.to_;
        case SIP_PKT_BYE:      return &p->pkt.bye.to_;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.to_;
        case SIP_PKT_REGISTER: return &p->pkt.register_.to_;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.to_;
        default: return NULL;
    }
}

void fix_sip_shot14_to(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_to_hdr_t *toh = get_to_view(&arr[i]);
        if (!toh) continue;

        /* Ensure header exists and minimally valid */
        if (toh->uri[0] == '\0') {
            synthesize_min_to(toh);
        } else {
            /* Normalize base tokens */
            normalize_to_tokens(toh);
        }

        /* Ensure recognized URI scheme; if not, coerce to sip: */
        if (!is_known_scheme(toh->uri)) {
            coerce_uri_scheme_to_sip(toh->uri, sizeof(toh->uri));
        }

        /* If URI contains ',', '?' or ';', enforce name-addr (angle brackets) */
        if (uri_needs_name_addr(toh->uri)) {
            if (toh->sp_opt == '\0') toh->sp_opt = ' ';
            toh->lt = '<';
            toh->gt = '>';
        } else {
            /* Name-addr form is always legal; keep existing lt/gt if already set.
               If neither set, we can leave as addr-spec (lt/gt == '\0' allowed). */
            /* No change needed */
        }

        /* Make sure header constant tokens are set */
        if (toh->name[0] == '\0')        snprintf(toh->name, sizeof(toh->name), "To");
        if (toh->colon_space[0] == '\0') snprintf(toh->colon_space, sizeof(toh->colon_space), ": ");
        if (toh->crlf[0] == '\0')        snprintf(toh->crlf, sizeof(toh->crlf), "\r\n");

        /* As a final safety: if URI somehow got cleared, synthesize again */
        if (toh->uri[0] == '\0') {
            snprintf(toh->uri, sizeof(toh->uri), "sip:unknown@localhost");
        }
    }
}

#include <time.h>

/*
 * SHOT-15: [SIP-6.12-Call-ID]
 * Every request MUST contain a Call-ID header field that uniquely identifies the call.
 *
 * This fixer:
 *  - Ensures each request has a Call-ID header with proper constant tokens ("Call-ID", ": ", CRLF).
 *  - Normalizes/cleans the Call-ID value (removes LWS and CRLF).
 *  - If missing or empty after cleanup, generates a globally-unique-ish value:
 *      "cid-<packetIndex>-<rand32>@example.invalid"
 *  - Operates IN-PLACE on the provided array.
 */

static void seed_once(void) {
    static int seeded = 0;
    if (!seeded) {
        seeded = 1;
        srand((unsigned)time(NULL));
    }
}

static sip_call_id_hdr_t* get_call_id_view(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.call_id;
        case SIP_PKT_ACK:      return &p->pkt.ack.call_id;
        case SIP_PKT_BYE:      return &p->pkt.bye.call_id;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.call_id;
        case SIP_PKT_REGISTER: return &p->pkt.register_.call_id;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.call_id;
        default: return NULL; /* Unknown or non-request */
    }
}

/* Trim leading/trailing LWS; then strip any CR/LF; then collapse internal spaces/tabs */
static void normalize_call_id_value(char *s) {
    if (!s) return;

    /* 1) trim leading/trailing spaces/tabs */
    size_t len = strlen(s);
    size_t start = 0, end = len;
    while (start < len && (s[start] == ' ' || s[start] == '\t')) start++;
    while (end > start && (s[end-1] == ' ' || s[end-1] == '\t')) end--;

    /* 2) copy into tmp without CR/LF and without any spaces/tabs inside (token req) */
    char tmp[SIP_TEXT_LEN];
    size_t w = 0;
    for (size_t i = start; i < end && w + 1 < sizeof(tmp); ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n') continue;          /* strip CRLF */
        if (c == ' '  || c == '\t') continue;          /* no whitespace in Call-ID token */
        tmp[w++] = (char)c;
    }
    tmp[w] = '\0';

    snprintf(s, SIP_TEXT_LEN, "%s", tmp);
}

/* Generate deterministic-enough unique Call-ID for this array element */
static void synth_call_id(char *dst, size_t dstlen, size_t pkt_index) {
    if (!dst || dstlen == 0) return;
    seed_once();
    unsigned rnd = (unsigned)rand();
    /* Use .invalid TLD (RFC 2606/6761) to avoid real host collisions */
    snprintf(dst, dstlen, "cid-%zu-%08x@example.invalid", pkt_index, rnd);
}

static void ensure_call_id_tokens(sip_call_id_hdr_t *h) {
    if (!h) return;
    if (h->name[0] == '\0')        snprintf(h->name, sizeof(h->name), "Call-ID");
    else                           snprintf(h->name, sizeof(h->name), "Call-ID"); /* normalize case */
    if (h->colon_space[0] == '\0') snprintf(h->colon_space, sizeof(h->colon_space), ": ");
    if (h->crlf[0] == '\0')        snprintf(h->crlf, sizeof(h->crlf), "\r\n");
}

void fix_sip_shot15_call_id(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_call_id_hdr_t *cid = get_call_id_view(&arr[i]);
        if (!cid) continue;

        /* Ensure constant tokens present */
        ensure_call_id_tokens(cid);

        /* If value missing, synthesize; else normalize and re-check */
        if (cid->value[0] == '\0') {
            synth_call_id(cid->value, sizeof(cid->value), i);
        } else {
            normalize_call_id_value(cid->value);
            if (cid->value[0] == '\0') {
                synth_call_id(cid->value, sizeof(cid->value), i);
            }
        }

        /* Final safeguard against overflow or accidental clearing */
        cid->value[sizeof(cid->value) - 1] = '\0';
    }
}



/*
 * SHOT-16: [SIP-6.40.1-Via-Insertion]
 * A client originating a request MUST insert a Via header field with its host
 * name or network address and, if not the default, the port at which it wishes
 * to receive responses. Each proxy that forwards the request MUST add its own
 * Via above existing ones.
 *
 * This fixer operates IN-PLACE on a sip_packet_t array and:
 *  - Ensures every request has at least one Via header line.
 *  - If Via is absent, inserts a new topmost Via with sane defaults:
 *      sent_protocol: "SIP/2.0/UDP"
 *      sent_by:       "uac.example.invalid:5060"
 *      params:        ";branch=z9hG4bK<rand32>"
 *  - Normalizes tokens for existing Via lines (name, ": ", space, CRLF).
 *  - Keeps total Via lines <= SIP_MAX_VIA (drops the last one when inserting if full).
 *
 * Notes:
 *  - We cannot know the true local host/port/transport here; we choose safe, spec-conformant
 *    defaults. Callers that know better can post-process or generate packets with correct values.
 */


static void to_upper_copy(const char *src, char *dst, size_t dstlen) {
    if (!dst || dstlen == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; src[i] && i + 1 < dstlen; ++i) dst[i] = (char)toupper((unsigned char)src[i]);
    dst[i] = '\0';
}

static void via_set_tokens(sip_via_hdr_t *v) {
    if (!v) return;
    snprintf(v->name, sizeof(v->name), "Via");
    snprintf(v->colon_space, sizeof(v->colon_space), ": ");
    v->sp = ' ';
    snprintf(v->crlf, sizeof(v->crlf), "\r\n");
}

static void build_new_via(sip_via_hdr_t *out)
{
    if (!out) return;
    seed_once();

    char transport_up[16];
    to_upper_copy("UDP", transport_up, sizeof(transport_up)); /* default transport */

    via_set_tokens(out);
    snprintf(out->sent_protocol, sizeof(out->sent_protocol), "SIP/2.0/%s", transport_up);
    snprintf(out->sent_by, sizeof(out->sent_by), "uac.example.invalid:5060");

    unsigned r = (unsigned)rand();
    /* Ensure branch param with the well-known magic cookie */
    snprintf(out->params, sizeof(out->params), ";branch=z9hG4bK%08x", r);
}

/* Normalize an existing Via line to have required constant tokens. */
static void normalize_existing_via(sip_via_hdr_t *v) {
    if (!v) return;
    via_set_tokens(v);
    /* If protocol is empty or malformed, make it sane. */
    if (v->sent_protocol[0] == '\0' || strncmp(v->sent_protocol, "SIP/2.0/", 8) != 0) {
        snprintf(v->sent_protocol, sizeof(v->sent_protocol), "SIP/2.0/UDP");
    }
    /* If sent-by is empty, fill a safe default. */
    if (v->sent_by[0] == '\0') {
        snprintf(v->sent_by, sizeof(v->sent_by), "uac.example.invalid:5060");
    }
    /* params may be empty; if empty, add a branch */
    if (v->params[0] == '\0') {
        unsigned r = (unsigned)rand();
        snprintf(v->params, sizeof(v->params), ";branch=z9hG4bK%08x", r);
    }
}

/* Get pointers to Via array, count and capacity for a given packet. */
static int get_via_view(sip_packet_t *p, sip_via_hdr_t **via_arr, size_t **via_count, size_t *cap)
{
    if (!p || !via_arr || !via_count || !cap) return 0;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            *via_arr = p->pkt.invite.via;
            *via_count = &p->pkt.invite.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        case SIP_PKT_ACK:
            *via_arr = p->pkt.ack.via;
            *via_count = &p->pkt.ack.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        case SIP_PKT_BYE:
            *via_arr = p->pkt.bye.via;
            *via_count = &p->pkt.bye.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        case SIP_PKT_CANCEL:
            *via_arr = p->pkt.cancel.via;
            *via_count = &p->pkt.cancel.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        case SIP_PKT_REGISTER:
            *via_arr = p->pkt.register_.via;
            *via_count = &p->pkt.register_.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        case SIP_PKT_OPTIONS:
            *via_arr = p->pkt.options.via;
            *via_count = &p->pkt.options.via_count;
            *cap = SIP_MAX_VIA;
            return 1;
        default:
            return 0;
    }
}

/* Insert a new Via at the top; if full, drop the last one. */
static void insert_top_via(sip_via_hdr_t *via, size_t *count, size_t cap, const sip_via_hdr_t *newv)
{
    if (!via || !count || !newv || cap == 0) return;
    size_t n = *count;
    if (n >= cap) {
        /* Make room by dropping the last (lowest) Via */
        n = cap - 1;
    }
    /* shift down to make room at index 0 */
    memmove(&via[1], &via[0], n * sizeof(sip_via_hdr_t));
    via[0] = *newv;
    if (*count < cap) (*count)++;
}

/* Public fixer */
void fix_sip_shot16_via_insertion(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;
    seed_once();

    for (size_t i = 0; i < num_packets; ++i) {
        sip_via_hdr_t *vias = NULL;
        size_t *vcount = NULL;
        size_t vcap = 0;
        if (!get_via_view(&arr[i], &vias, &vcount, &vcap)) continue;

        if (!vias || !vcount) continue;

        if (*vcount == 0) {
            /* No Via present -> create a proper one and insert at top */
            sip_via_hdr_t nv;
            memset(&nv, 0, sizeof(nv));
            build_new_via(&nv);
            insert_top_via(vias, vcount, vcap, &nv);
        } else {
            /* Normalize existing Via lines; ensure topmost has proper tokens */
            for (size_t k = 0; k < *vcount; ++k) {
                normalize_existing_via(&vias[k]);
            }
            /* If the first Via had an empty/missing name (corrupted), fix it explicitly */
            via_set_tokens(&vias[0]);
            if (vias[0].sent_protocol[0] == '\0')
                snprintf(vias[0].sent_protocol, sizeof(vias[0].sent_protocol), "SIP/2.0/UDP");
            if (vias[0].sent_by[0] == '\0')
                snprintf(vias[0].sent_by, sizeof(vias[0].sent_by), "uac.example.invalid:5060");
            if (vias[0].params[0] == '\0') {
                unsigned r = (unsigned)rand();
                snprintf(vias[0].params, sizeof(vias[0].params), ";branch=z9hG4bK%08x", r);
            }
        }
    }
}



#include <stdbool.h>


/*
 * SHOT-17: [SIP-6.40.1-Via-Addressing]
 * The Via host SHOULD be a fully-qualified domain name; the port in Via can
 * differ from the UDP source port.
 *
 * This fixer operates IN-PLACE on a sip_packet_t array and:
 *  - For each Via line in each packet, ensures sent_by is of the form FQDN[:port].
 *  - If host is missing, not FQDN, or an IP literal (v4/v6), it is replaced with
 *      "uac.example.invalid".
 *  - If port is missing or invalid, ":5060" is added.
 *  - Does NOT attempt to synchronize with any network-layer ports (the spec
 *    explicitly allows the Via port to differ).
 *  - Also normalizes the constant tokens for Via ("Via", ": ", ' ', CRLF).
 */


static bool is_decimal(const char *s) {
    if (!s || !*s) return false;
    for (const unsigned char *p=(const unsigned char*)s; *p; ++p) {
        if (!isdigit(*p)) return false;
    }
    return true;
}

static bool port_valid(const char *s) {
    if (!is_decimal(s)) return false;
    long v = strtol(s, NULL, 10);
    return (v >= 1 && v <= 65535);
}

static bool is_ipv4_literal(const char *h) {
    if (!h || !*h) return false;
    int dots = 0;
    int part = 0;
    int digits = 0;
    for (const unsigned char *p=(const unsigned char*)h; *p; ++p) {
        if (*p == '.') {
            if (digits == 0) return false;
            dots++;
            digits = 0;
            part = 0;
        } else if (isdigit(*p)) {
            digits++;
            part = part * 10 + (*p - '0');
            if (digits > 3 || part > 255) return false;
        } else {
            return false;
        }
    }
    return (dots == 3 && digits > 0);
}

static bool is_ipv6_like(const char *h) {
    if (!h || !*h) return false;
    /* Simplified heuristic: contains ':' or bracketed form */
    return (strchr(h, ':') != NULL) || (h[0] == '[' && strchr(h, ']'));
}

static void trim_spaces(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len-1])) s[--len] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}

static bool label_ok(const char *lab) {
    if (!lab || !*lab) return false;
    size_t n = strlen(lab);
    if (n > 63) return false;
    if (lab[0] == '-' || lab[n-1] == '-') return false;
    for (size_t i=0;i<n;i++) {
        unsigned char c = (unsigned char)lab[i];
        if (!(isalnum(c) || c=='-')) return false;
    }
    return true;
}

static bool looks_like_fqdn(const char *h) {
    if (!h || !*h) return false;
    /* Should have at least one '.' separating labels */
    const char *dot = strchr(h, '.');
    if (!dot) return false;
    /* Very loose check of labels */
    char tmp[SIP_HOST_LEN];
    snprintf(tmp, sizeof(tmp), "%s", h);
    char *save=NULL;
    char *tok = strtok_r(tmp, ".", &save);
    int labels = 0;
    while (tok) {
        if (!label_ok(tok)) return false;
        labels++;
        tok = strtok_r(NULL, ".", &save);
    }
    return labels >= 2;
}

/* Parse sent-by into host and port (both outputs are trimmed).
 * Supports:
 *  - "host"
 *  - "host:port"
 *  - "[v6addr]"
 *  - "[v6addr]:port"
 * For malformed cases, best-effort extraction.
 */
static void parse_sent_by(const char *in, char *host, size_t hostsz, char *port, size_t portsz)
{
    if (!host || !port || hostsz==0 || portsz==0) return;
    host[0] = '\0';
    port[0] = '\0';

    if (!in || !*in) return;

    char buf[SIP_HOST_LEN];
    snprintf(buf, sizeof(buf), "%s", in);
    trim_spaces(buf);

    if (buf[0] == '[') {
        /* [v6] or [v6]:port */
        char *rb = strchr(buf, ']');
        if (rb) {
            size_t hlen = (size_t)(rb - (buf + 1));
            if (hlen >= hostsz) hlen = hostsz - 1;
            memcpy(host, buf + 1, hlen);
            host[hlen] = '\0';
            if (rb[1] == ':' && rb[2] != '\0') {
                snprintf(port, portsz, "%s", rb + 2);
            }
        } else {
            /* No closing ']' – treat as host only, drop '[' */
            snprintf(host, hostsz, "%s", buf + 1);
        }
    } else {
        /* Count colons to distinguish host:port vs. bare ipv6 (non-bracket) */
        int colon_count = 0;
        for (const char *p = buf; *p; ++p) if (*p==':') colon_count++;
        if (colon_count == 0) {
            snprintf(host, hostsz, "%s", buf);
        } else if (colon_count == 1) {
            /* host:port */
            char *c = strrchr(buf, ':');
            if (c) {
                *c = '\0';
                snprintf(host, hostsz, "%s", buf);
                snprintf(port, portsz, "%s", c + 1);
            } else {
                snprintf(host, hostsz, "%s", buf);
            }
        } else {
            /* Likely IPv6 without brackets -> take whole as host */
            snprintf(host, hostsz, "%s", buf);
        }
    }
    trim_spaces(host);
    trim_spaces(port);
}


/* Public fixer */
void fix_sip_shot17_via_addressing(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_via_hdr_t *vias = NULL;
        size_t *vcount = NULL;
        size_t vcap = 0;
        if (!get_via_view(&arr[i], &vias, &vcount, &vcap)) continue;
        if (!vias || !vcount) continue;

        for (size_t k = 0; k < *vcount; ++k) {
            via_set_tokens(&vias[k]);

            char host[SIP_HOST_LEN] = {0};
            char port[16] = {0};
            parse_sent_by(vias[k].sent_by, host, sizeof(host), port, sizeof(port));

            /* Decide on FQDN */
            bool need_replace =
                host[0] == '\0' ||
                is_ipv4_literal(host) ||
                is_ipv6_like(host) ||
                !looks_like_fqdn(host);

            if (need_replace) {
                snprintf(host, sizeof(host), "uac.example.invalid");
            }

            /* Port handling (SHOULD allow any; ensure present & valid) */
            if (!port_valid(port)) {
                snprintf(port, sizeof(port), "5060");
            }

            /* Assemble "host:port" (host is FQDN now, no brackets required) */
            if (snprintf(vias[k].sent_by, sizeof(vias[k].sent_by), "%s:%s", host, port) >= (int)sizeof(vias[k].sent_by)) {
                /* Truncate safely if needed */
                vias[k].sent_by[sizeof(vias[k].sent_by)-1] = '\0';
            }
        }
    }
}



/*
 * SHOT-18: [SIP-6.23-Max-Forwards]
 * - Requests MAY contain Max-Forwards.
 * - A proxy that forwards MUST decrement it by one; if it becomes 0,
 *   the request MUST NOT be forwarded further (483 for most methods;
 *   final-recipient behavior for OPTIONS/REGISTER).
 *
 * This fixer operates IN-PLACE on a sip_packet_t array and:
 *   • If Max-Forwards is present, normalizes its tokens and value.
 *   • Parses the numeric value; on malformed value, set to a safe default (70).
 *   • Decrements by 1 if current value > 0 (simulating the proxy hop).
 *   • Clamps to 0..2^32-1 for robustness.
 *   • If absent, leaves it absent (the header is optional per spec).
 *
 * Note: Whether to forward/respond at MF=0 is a transaction/routing decision
 * outside the scope of these pure-struct fixups; here we only ensure the field
 * is valid and decremented as required when forwarding.
 */

static void mf_set_tokens(sip_max_forwards_hdr_t *mf) {
    if (!mf) return;
    snprintf(mf->name, sizeof(mf->name), "Max-Forwards");
    snprintf(mf->colon_space, sizeof(mf->colon_space), ": ");
    snprintf(mf->crlf, sizeof(mf->crlf), "\r\n");
}


static bool parse_uint32_strict(const char *txt, uint32_t *out) {
    if (!txt || !*txt || !out) return false;
    char buf[SIP_NUM_LEN];
    snprintf(buf, sizeof(buf), "%s", txt);
    trim_spaces(buf);

    // Entire string must be digits
    const unsigned char *p = (const unsigned char*)buf;
    if (!*p) return false;
    uint64_t acc = 0;
    for (; *p; ++p) {
        if (!isdigit(*p)) return false;
        acc = acc * 10u + (uint64_t)(*p - '0');
        if (acc > 0xFFFFFFFFull) { // overflow uint32
            *out = 0xFFFFFFFFu;
            return true;
        }
    }
    *out = (uint32_t)acc;
    return true;
}

static void write_uint32(char *dst, size_t dstsz, uint32_t v) {
    if (!dst || dstsz == 0) return;
    // ensure NUL-terminated
    snprintf(dst, dstsz, "%u", (unsigned)v);
}

/* Return a view of Max-Forwards header for a packet (optional header):
 * If hdr.name[0] == '\0', it is considered absent and we leave as-is.
 */
static sip_max_forwards_hdr_t* get_mf_ptr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.max_forwards;
        case SIP_PKT_ACK:      return &p->pkt.ack.max_forwards;
        case SIP_PKT_BYE:      return &p->pkt.bye.max_forwards;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.max_forwards;
        case SIP_PKT_REGISTER: return &p->pkt.register_.max_forwards;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.max_forwards;
        default:               return NULL;
    }
}

/* Public fixer: decrement Max-Forwards when present and normalize it. */
void fix_sip_shot18_max_forwards(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_max_forwards_hdr_t *mf = get_mf_ptr(&arr[i]);
        if (!mf) continue;

        /* Optional header: skip if marked absent by convention (name[0] == '\0') */
        if (mf->name[0] == '\0') continue;

        /* Normalize tokens (header-name, ": ", CRLF) */
        mf_set_tokens(mf);

        /* Parse numeric value; if bad, set to default 70 */
        uint32_t hops = 70;
        if (!parse_uint32_strict(mf->hops, &hops)) {
            hops = 70;
        }

        /* Decrement by 1 if > 0 (proxy hop behavior) */
        if (hops > 0) {
            hops -= 1u;
        } else {
            hops = 0; /* clamp (can't go negative) */
        }

        /* Write back normalized value */
        write_uint32(mf->hops, sizeof(mf->hops), hops);
    }
}



/*
 * SHOT-20: [SIP-6.28-Proxy-Require and SIP-6.30-Require]
 *
 * A request MAY include Proxy-Require and/or Require to indicate features
 * that proxies or endpoints MUST support to process the request; unsupported
 * option-tags cause appropriate error responses.
 *
 * Fix strategy (in-place):
 *  1) If the headers are present (name[0] != '\0'), normalize header tokens:
 *     - Canonical field-name ("Proxy-Require" / "Require"), ": ", CRLF.
 *  2) Parse option-tags list (accept comma or semicolon separated), trim LWS,
 *     validate tokens against token grammar, lowercase and de-duplicate.
 *  3) Drop obviously invalid tokens and (conservatively) drop tokens that are
 *     not in a small whitelist of well-known SIP option-tags to avoid creating
 *     requests that would elicit errors due to unsupported features.
 *  4) If the resulting list is empty, mark the header absent (name[0] = '\0').
 *
 * Notes:
 *  - This fixer does not *add* these headers (they're optional).
 *  - The whitelist is not exhaustive; extend as needed for your stack.
 */

static void set_proxy_require_tokens(sip_proxy_require_hdr_t *h) {
    if (!h) return;
    snprintf(h->name, sizeof(h->name), "Proxy-Require");
    snprintf(h->colon_space, sizeof(h->colon_space), ": ");
    snprintf(h->crlf, sizeof(h->crlf), "\r\n");
}

static void set_require_tokens(sip_require_hdr_t *h) {
    if (!h) return;
    snprintf(h->name, sizeof(h->name), "Require");
    snprintf(h->colon_space, sizeof(h->colon_space), ": ");
    snprintf(h->crlf, sizeof(h->crlf), "\r\n");
}

/* RFC token-ish allowed chars for option-tag:
   ALPHA / DIGIT / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~"
*/
static bool optchar_ok(unsigned char c) {
    return (isalnum(c) ||
            c=='-'||c=='.'||c=='!'||c=='%'||c=='*'||c=='_'||
            c=='+'||c=='`'||c=='\''||c=='~');
}

static void trim(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}

static void to_lower_inplace(char *s) {
    if (!s) return;
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

static bool token_valid(const char *t) {
    if (!t || !*t) return false;
    for (const unsigned char *p=(const unsigned char*)t; *p; ++p) {
        if (!optchar_ok(*p)) return false;
    }
    return true;
}

/* Small, conservative whitelist of common option-tags.
   Extend as needed for your testing environment. */
static bool is_supported_option_tag(const char *t) {
    if (!t) return false;
    /* all entries MUST be lowercase for comparison */
    static const char *const wl[] = {
        "100rel", "timer", "replaces", "norefersub", "precondition",
        "path", "gruu", "target-dialog", "outbound", "join",
        "resource-priority", "sec-agree", "privacy", "from-change",
        "history-info", "update" /* (RFC3311 method capability) */
    };
    for (size_t i=0;i<sizeof(wl)/sizeof(wl[0]);++i) {
        if (strcmp(t, wl[i]) == 0) return true;
    }
    return false;
}

static void normalize_option_tags(char *dst, size_t dstsz) {
    if (!dst || dstsz == 0) return;

    /* Replace semicolons with commas to unify separators */
    for (char *p = dst; *p; ++p) {
        if (*p == ';') *p = ',';
        if (*p == '\r' || *p == '\n') *p = ' '; /* unfold any stray LWS */
    }

    /* Work on a local copy to split; rebuild into dst */
    char buf[SIP_TEXT_LEN];
    snprintf(buf, sizeof(buf), "%s", dst);

    char out[SIP_TEXT_LEN] = {0};
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);

    /* Keep a small set to dedupe */
    char kept[32][SIP_TOKEN_LEN];
    size_t kept_cnt = 0;

    while (tok) {
        trim(tok);
        /* Collapse internal spaces: option-tag should not have spaces */
        char clean[SIP_TOKEN_LEN] = {0};
        size_t w = 0;
        for (size_t i=0; tok[i] && w+1<sizeof(clean); ++i) {
            if (!isspace((unsigned char)tok[i])) clean[w++] = tok[i];
        }
        clean[w] = '\0';

        if (*clean) {
            to_lower_inplace(clean);
            if (token_valid(clean) && is_supported_option_tag(clean)) {
                /* dedupe */
                bool dup = false;
                for (size_t i=0;i<kept_cnt;i++){
                    if (strcmp(kept[i], clean) == 0) { dup = true; break; }
                }
                if (!dup && kept_cnt < (sizeof(kept)/sizeof(kept[0]))) {
                    snprintf(kept[kept_cnt++], sizeof(kept[0]), "%s", clean);
                }
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    /* Rebuild as "tag1, tag2, ..." */
    out[0] = '\0';
    for (size_t i=0;i<kept_cnt;i++) {
        if (i) strncat(out, ", ", sizeof(out)-strlen(out)-1);
        strncat(out, kept[i], sizeof(out)-strlen(out)-1);
    }

    /* Write back (or clear) */
    if (kept_cnt == 0) {
        dst[0] = '\0';
    } else {
        snprintf(dst, dstsz, "%s", out);
    }
}

static sip_proxy_require_hdr_t* get_proxy_require_hdr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.proxy_require;
        case SIP_PKT_ACK:      return &p->pkt.ack.proxy_require;
        case SIP_PKT_BYE:      return &p->pkt.bye.proxy_require;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.proxy_require;
        case SIP_PKT_REGISTER: return &p->pkt.register_.proxy_require;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.proxy_require;
        default:               return NULL;
    }
}

static sip_require_hdr_t* get_require_hdr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.require;
        case SIP_PKT_ACK:      return &p->pkt.ack.require;
        case SIP_PKT_BYE:      return &p->pkt.bye.require;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.require;
        case SIP_PKT_REGISTER: return &p->pkt.register_.require;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.require;
        default:               return NULL;
    }
}

static void fix_one_proxy_require(sip_proxy_require_hdr_t *h) {
    if (!h) return;
    if (h->name[0] == '\0') return; /* header absent -> nothing to do */
    set_proxy_require_tokens(h);
    normalize_option_tags(h->option_tags, sizeof(h->option_tags));
    if (h->option_tags[0] == '\0') {
        /* Nothing meaningful left -> drop header (it's optional) */
        h->name[0] = '\0';
    }
}

static void fix_one_require(sip_require_hdr_t *h) {
    if (!h) return;
    if (h->name[0] == '\0') return; /* header absent -> nothing to do */
    set_require_tokens(h);
    normalize_option_tags(h->option_tags, sizeof(h->option_tags));
    if (h->option_tags[0] == '\0') {
        /* Nothing meaningful left -> drop header (it's optional) */
        h->name[0] = '\0';
    }
}

/* Public fixer */
void fix_sip_shot20_require_and_proxy_require(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i=0; i<num_packets; ++i) {
        sip_packet_t *p = &arr[i];

        sip_proxy_require_hdr_t *preq = get_proxy_require_hdr(p);
        if (preq) fix_one_proxy_require(preq);

        sip_require_hdr_t *req = get_require_hdr(p);
        if (req) fix_one_require(req);
    }
}


/*
 * SHOT-21: [SIP-6.33-Route]
 *
 * If present, the Route header field in a request constrains the next hop(s)
 * per loose/strict routing rules. For robustness and interoperability,
 * normalize all Route headers and prefer *loose routing* by ensuring ";lr"
 * is present on Route URIs. Also sanitize name/separators, remove obviously
 * invalid entries, and de-duplicate.
 *
 * This fixer operates in-place on the given sip_packet_t array.
 */

static void route_set_tokens(sip_route_hdr_t *r) {
    if (!r) return;
    snprintf(r->name, sizeof(r->name), "Route");
    snprintf(r->colon_space, sizeof(r->colon_space), ": ");
    r->lt = '<';
    r->gt = '>';
    snprintf(r->crlf, sizeof(r->crlf), "\r\n");
}

/* Recognized URI schemes for Route targets */
static bool route_scheme_ok(const char *uri) {
    if (!uri || !*uri) return false;
    return (strncmp(uri, "sip:", 4) == 0) || (strncmp(uri, "sips:", 5) == 0);
}

/* Check if params already include an lr parameter (case-insensitive) */
static bool route_has_lr(const char *params) {
    if (!params || !*params) return false;
    /* look for ;lr or lr[=...] token boundaries; normalize by scanning */
    const char *p = params;
    while (*p) {
        /* skip until potential token start */
        while (*p && (*p == ';' || isspace((unsigned char)*p))) p++;
        if (!*p) break;

        const char *tok = p;
        /* read token up to ; or end */
        while (*p && *p != ';' && !isspace((unsigned char)*p)) p++;
        size_t len = (size_t)(p - tok);
        if (len >= 2) {
            /* compare "lr" case-insensitive and allow lr=foo */
            if ((len == 2 && (tok[0]=='l' || tok[0]=='L') && (tok[1]=='r' || tok[1]=='R')) ||
                (len > 2 && (tok[0]=='l' || tok[0]=='L') && (tok[1]=='r' || tok[1]=='R') && tok[2]=='=')) {
                return true;
            }
        }
        /* continue; if at ';', loop will consume */
    }
    return false;
}

/* Append ";lr" to params if there is room and not already present */
static void route_add_lr(sip_route_hdr_t *r) {
    if (!r) return;
    if (route_has_lr(r->params)) return;

    size_t cur = strlen(r->params);
    const char *to_add = ";lr";
    size_t add_len = strlen(to_add);

    if (cur == 0) {
        /* write fresh */
        if (add_len < sizeof(r->params)) {
            memcpy(r->params, to_add, add_len + 1);
        }
    } else {
        if (cur + add_len < sizeof(r->params)) {
            strncat(r->params, to_add, sizeof(r->params) - cur - 1);
        }
        /* else: no room -> skip (leave as-is) */
    }
}

/* Trim leading/trailing ASCII whitespace from a small buffer (in-place) */
static void trim_ascii(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}

/* Compare two Route entries for equality (URI + params) */
static bool route_equal(const sip_route_hdr_t *a, const sip_route_hdr_t *b) {
    if (!a || !b) return false;
    return strcmp(a->uri, b->uri) == 0 && strcmp(a->params, b->params) == 0;
}

static void get_routes_ref(sip_packet_t *p, sip_route_hdr_t **routes, size_t **countp) {
    *routes = NULL;
    *countp = NULL;
    if (!p) return;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            *routes = p->pkt.invite.route;
            *countp = &p->pkt.invite.route_count;
            break;
        case SIP_PKT_ACK:
            *routes = p->pkt.ack.route;
            *countp = &p->pkt.ack.route_count;
            break;
        case SIP_PKT_BYE:
            *routes = p->pkt.bye.route;
            *countp = &p->pkt.bye.route_count;
            break;
        case SIP_PKT_CANCEL:
            *routes = p->pkt.cancel.route;
            *countp = &p->pkt.cancel.route_count;
            break;
        case SIP_PKT_REGISTER:
            *routes = p->pkt.register_.route;
            *countp = &p->pkt.register_.route_count;
            break;
        case SIP_PKT_OPTIONS:
            *routes = p->pkt.options.route;
            *countp = &p->pkt.options.route_count;
            break;
        default:
            break;
    }
}

static void clear_unused_tail(sip_route_hdr_t *routes, size_t start, size_t maxn) {
    if (!routes) return;
    for (size_t i = start; i < maxn; ++i) {
        routes[i].name[0] = '\0';
        routes[i].colon_space[0] = '\0';
        routes[i].lt = routes[i].gt = '\0';
        routes[i].uri[0] = '\0';
        routes[i].params[0] = '\0';
        routes[i].crlf[0] = '\0';
    }
}

/* Normalize and fix one packet's Route set */
static void fix_one_packet_routes(sip_packet_t *p) {
    if (!p) return;

    sip_route_hdr_t *routes = NULL;
    size_t *pcount = NULL;
    get_routes_ref(p, &routes, &pcount);
    if (!routes || !pcount) return;

    size_t cnt = *pcount;
    if (cnt == 0) {
        /* ensure tail cleared */
        clear_unused_tail(routes, 0, SIP_MAX_ROUTE);
        return;
    }

    if (cnt > SIP_MAX_ROUTE) cnt = *pcount = SIP_MAX_ROUTE;

    /* Pass 1: normalize tokens, trim fields, drop invalid scheme/empty URI */
    size_t w = 0;
    for (size_t i = 0; i < cnt; ++i) {
        sip_route_hdr_t tmp = routes[i];

        /* sanitize */
        route_set_tokens(&tmp);
        trim_ascii(tmp.uri);
        trim_ascii(tmp.params);

        if (tmp.uri[0] == '\0' || !route_scheme_ok(tmp.uri)) {
            /* drop this entry */
            continue;
        }

        /* prefer loose routing: add ;lr if missing */
        if (!route_has_lr(tmp.params)) {
            route_add_lr(&tmp);
        }

        /* keep */
        if (w != i) routes[w] = tmp;
        else routes[i] = tmp;
        w++;
    }
    cnt = *pcount = w;

    /* Pass 2: de-duplicate while keeping first occurrences */
    for (size_t i = 0; i < cnt; ++i) {
        for (size_t j = i + 1; j < cnt; ) {
            if (route_equal(&routes[i], &routes[j])) {
                /* remove j by shifting left */
                for (size_t k = j + 1; k < cnt; ++k) {
                    routes[k - 1] = routes[k];
                }
                cnt--;
                *pcount = cnt;
            } else {
                j++;
            }
        }
    }

    /* Final: clamp and clear unused tail for cleanliness */
    if (cnt > SIP_MAX_ROUTE) {
        cnt = *pcount = SIP_MAX_ROUTE;
    }
    clear_unused_tail(routes, cnt, SIP_MAX_ROUTE);
}

/* Public fixer */
void fix_sip_shot21_route(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;
    for (size_t i = 0; i < num_packets; ++i) {
        fix_one_packet_routes(&arr[i]);
    }
}


/* SHOT-23 fixer
 * If a request carries a message body, it MUST include Content-Type and Content-Length;
 * Content-Encoding is used only if a content coding is applied. We conservatively:
 *   - ensure Content-Type and Content-Length when body is non-empty;
 *   - remove Content-Encoding when body is empty (not applied);
 *   - normalize Content-Length to the actual byte length of the in-struct body.
 */



/* ---- small helpers to (re)build header lines in our fixed-width fields ---- */

static void set_fixed_token(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    /* cap includes room for the trailing NUL */
    snprintf(dst, cap, "%s", src);
}


static void clear_optional_header_name(char *name_field, size_t cap) {
    if (name_field && cap) name_field[0] = '\0';
}

/* Simple body detectors for typical SIP payloads (best-effort) */
static int looks_like_sdp(const char *b) {
    if (!b) return 0;
    /* SDP often starts with v= or contains a line starting with v= */
    if (b[0]=='v' && b[1]=='=') return 1;
    const char *p = strstr(b, "\nv=");
    return p != NULL;
}

static int looks_like_xml(const char *b) {
    if (!b) return 0;
    /* very naive guess */
    while (*b && isspace((unsigned char)*b)) b++;
    return *b == '<';
}

static int is_mostly_printable_text(const char *b) {
    if (!b) return 0;
    /* Treat as text if majority of bytes are printable or whitespace */
    size_t printable = 0, total = 0;
    for (const unsigned char *p=(const unsigned char*)b; *p && total < 256; ++p, ++total) {
        if (isprint(*p) || isspace(*p)) printable++;
    }
    return total > 0 && printable * 100 / total >= 90;
}

/* Choose a reasonable Content-Type based on body sniffing */
static void choose_content_type(const char *body,
                                char type_tok[SIP_TOKEN_LEN],
                                char *slash,
                                char sub_type[SIP_SHORT_LEN],
                                char params[SIP_PARAMS_LEN]) {
    const char *type_main = "application";
    const char *type_sub  = "octet-stream";

    if (looks_like_sdp(body)) { type_main = "application"; type_sub = "sdp"; }
    else if (looks_like_xml(body)) { type_main = "application"; type_sub = "xml"; }
    else if (is_mostly_printable_text(body)) { type_main = "text"; type_sub = "plain"; }

    set_fixed_token(type_tok, SIP_TOKEN_LEN, type_main);
    if (slash) *slash = '/';
    set_fixed_token(sub_type, SIP_SHORT_LEN, type_sub);
    if (params) params[0] = '\0'; /* no parameters by default */
}

/* Ensure Content-Length header equals body_len and is present */
static void ensure_content_length(sip_content_length_hdr_t *cl, size_t body_len) {
    if (!cl) return;
    set_fixed_token(cl->name, SIP_HEADER_NAME_LEN, "Content-Length");
    set_sep(cl->colon_space);
    snprintf(cl->length, SIP_NUM_LEN, "%zu", body_len);
    set_crlf(cl->crlf);
}

/* Ensure Content-Type header is present with a reasonable value */
static void ensure_content_type(sip_content_type_hdr_t *ct, const char *body) {
    if (!ct) return;
    set_fixed_token(ct->name, SIP_HEADER_NAME_LEN, "Content-Type");
    set_sep(ct->colon_space);
    choose_content_type(body, ct->type_tok, &ct->slash, ct->sub_type, ct->params);
    set_crlf(ct->crlf);
}

/* Remove Content-Type (mark optional header absent) */
static void drop_content_type(sip_content_type_hdr_t *ct) {
    if (!ct) return;
    clear_optional_header_name(ct->name, SIP_HEADER_NAME_LEN);
}

/* Remove Content-Encoding unless truly applied (we assume "not applied" if no body) */
static void drop_content_encoding(sip_content_encoding_hdr_t *ce) {
    if (!ce) return;
    clear_optional_header_name(ce->name, SIP_HEADER_NAME_LEN);
}

/* Normalize a packet having a body: ensure CT + CL, keep CE only if already present. */
static void fix_entity_headers_for_body(char *body,
                                        sip_content_type_hdr_t *ct,
                                        sip_content_length_hdr_t *cl,
                                        sip_content_encoding_hdr_t *ce) {
    size_t blen = body ? strnlen(body, SIP_BODY_MAX) : 0;
    if (blen == 0) {
        /* No body: CT not required; CE must not be used; CL not required (leave as-is or zero it) */
        if (ct) drop_content_type(ct);
        if (ce) drop_content_encoding(ce);
        if (cl && cl->name[0]) { /* if present, normalize to "0" */
            ensure_content_length(cl, 0);
        }
        return;
    }
    /* Has body: MUST have CT and CL */
    if (ct) ensure_content_type(ct, body);
    if (cl) ensure_content_length(cl, blen);

    /* CE: keep only if already present and non-empty coding token; otherwise do nothing.
       (We do not auto-add CE since we cannot prove a content coding is applied.) */
    if (ce && ce->name[0]) {
        /* If coding is empty, drop it. */
        if (ce->coding[0] == '\0') {
            drop_content_encoding(ce);
        } else {
            /* make sure separators/CRLF look sane */
            set_fixed_token(ce->name, SIP_HEADER_NAME_LEN, "Content-Encoding");
            set_sep(ce->colon_space);
            set_crlf(ce->crlf);
        }
    }
}

/* Public fixer for SHOT-23 */
void fix_sip_shot23_entity_headers(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        switch (p->cmd_type) {
        case SIP_PKT_INVITE: {
            /* INVITE has body + CT + CL + CE in our model */
            fix_entity_headers_for_body(
                p->pkt.invite.body,
                &p->pkt.invite.content_type,
                &p->pkt.invite.content_length,
                &p->pkt.invite.content_encoding
            );
            break;
        }
        case SIP_PKT_ACK: {
            /* ACK has body + CT + CL (no CE in this struct) */
            fix_entity_headers_for_body(
                p->pkt.ack.body,
                &p->pkt.ack.content_type,
                &p->pkt.ack.content_length,
                NULL /* no Content-Encoding member in ack */
            );
            break;
        }
        case SIP_PKT_REGISTER: {
            /* REGISTER has body + CT + CL + CE in our model */
            fix_entity_headers_for_body(
                p->pkt.register_.body,
                &p->pkt.register_.content_type,
                &p->pkt.register_.content_length,
                &p->pkt.register_.content_encoding
            );
            break;
        }
        case SIP_PKT_OPTIONS: {
            /* OPTIONS has body + CT + CL + CE in our model */
            fix_entity_headers_for_body(
                p->pkt.options.body,
                &p->pkt.options.content_type,
                &p->pkt.options.content_length,
                &p->pkt.options.content_encoding
            );
            break;
        }
        case SIP_PKT_BYE:
        case SIP_PKT_CANCEL:
        default:
            /* BYE/CANCEL usually carry no body in this model; nothing to do here */
            break;
        }
    }
}



/*
 * SHOT-26: [SIP-Message-Body-Use]
 * - Request bodies are used by specific methods (e.g., INVITE, OPTIONS, REGISTER).
 * - BYE requests MUST NOT include a message body.
 *
 * In this codebase, sip_bye_packet_t has no body or entity headers, so
 * the constraint is satisfied by construction. We still provide a fixer
 * that walks the array and (a) does nothing for BYE (already compliant),
 * (b) leaves other methods unchanged (they MAY carry a body).
 *
 * If your serializer ever reused union memory across variants without
 * reinit, keep the BYE case as the place to clear any out-of-band
 * payload/printing paths. With the current structs, there's nothing
 * to clear programmatically.
 */

void fix_sip_shot26_message_body_use(sip_packet_t *arr, size_t num_packets)
{
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];

        switch (p->cmd_type) {
        case SIP_PKT_BYE:
            /*
             * BYE MUST NOT include a message body.
             * sip_bye_packet_t has no 'body' field and no Content-* headers,
             * so there is nothing to clear here. If a future revision
             * adds a body or entity headers to BYE, clear them here, e.g.:
             *   p->pkt.bye.body[0] = '\0';
             *   p->pkt.bye.content_length.name[0] = '\0';
             *   p->pkt.bye.content_type.name[0]   = '\0';
             */
            break;

        case SIP_PKT_INVITE:
        case SIP_PKT_ACK:
        case SIP_PKT_REGISTER:
        case SIP_PKT_OPTIONS:
            /* These methods MAY carry a message body; no change needed. */
            break;

        default:
            /* Unknown/other types: no action. */
            break;
        }
    }
}



static void safe_strcpy(char *dst, size_t dstsz, const char *src) {
    if (!dst || dstsz == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
}

static void upper_ascii_inplace(char *s) {
    if (!s) return;
    for (; *s; ++s) {
        if (*s >= 'a' && *s <= 'z') *s = (char)(*s - 'a' + 'A');
    }
}

static void ltrim_lws_inplace(char *s) {
    if (!s) return;
    size_t i = 0;
    while (s[i] == ' ' || s[i] == '\t') i++;
    if (i) memmove(s, s + i, strlen(s + i) + 1);
}

static void fix_one_via_hdr(sip_via_hdr_t *v) {
    if (!v) return;

    /* Normalize fixed tokens */
    safe_strcpy(v->name, SIP_HEADER_NAME_LEN, "Via");
    safe_strcpy(v->colon_space, SIP_SEPARATOR_LEN, ": ");
    v->sp = ' ';
    safe_strcpy(v->crlf, SIP_CRLF_LEN, "\r\n");

    /* sent_protocol: must be "SIP/2.0/<TRANSPORT>" */
    if (strncmp(v->sent_protocol, "SIP/2.0/", 8) != 0) {
        safe_strcpy(v->sent_protocol, SIP_TOKEN_LEN, "SIP/2.0/UDP");
    } else {
        char *transport = v->sent_protocol + 8;
        if (*transport == '\0') {
            safe_strcpy(v->sent_protocol, SIP_TOKEN_LEN, "SIP/2.0/UDP");
        } else {
            /* Uppercase transport token; stop at first space or control char */
            upper_ascii_inplace(transport);
            /* (Optional sanity) trim trailing spaces inside sent_protocol */
            size_t len = strlen(v->sent_protocol);
            while (len > 0 && (unsigned char)v->sent_protocol[len-1] <= ' ') {
                v->sent_protocol[--len] = '\0';
            }
        }
    }

    /* sent_by: must be present (host[:port]) */
    if (v->sent_by[0] == '\0') {
        safe_strcpy(v->sent_by, SIP_HOST_LEN, "client.invalid");
    } else {
        /* Trim leading spaces if any */
        ltrim_lws_inplace(v->sent_by);
        if (v->sent_by[0] == '\0') {
            safe_strcpy(v->sent_by, SIP_HOST_LEN, "client.invalid");
        }
    }

    /* params: trim leading LWS; ensure leading ';' if non-empty */
    ltrim_lws_inplace(v->params);
    if (v->params[0] != '\0' && v->params[0] != ';') {
        char tmp[SIP_PARAMS_LEN];
        /* Prepend a ';' safely */
        if (SIP_PARAMS_LEN > 0) {
            tmp[0] = ';';
            safe_strcpy(tmp + 1, sizeof(tmp) - 1, v->params);
            safe_strcpy(v->params, SIP_PARAMS_LEN, tmp);
        }
    }
}

static void fix_via_block(size_t via_count, sip_via_hdr_t *via_arr) {
    if (!via_arr) return;
    for (size_t i = 0; i < via_count; ++i) {
        fix_one_via_hdr(&via_arr[i]);
    }
}

/* Public fixer: SHOT-27 */
void fix_sip_shot27_via_syntax(sip_packet_t *arr, size_t num_packets) {
    if (!arr || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; ++i) {
        sip_packet_t *p = &arr[i];
        switch (p->cmd_type) {
        case SIP_PKT_INVITE:
            fix_via_block(p->pkt.invite.via_count, p->pkt.invite.via);
            break;
        case SIP_PKT_ACK:
            fix_via_block(p->pkt.ack.via_count, p->pkt.ack.via);
            break;
        case SIP_PKT_BYE:
            fix_via_block(p->pkt.bye.via_count, p->pkt.bye.via);
            break;
        case SIP_PKT_CANCEL:
            fix_via_block(p->pkt.cancel.via_count, p->pkt.cancel.via);
            break;
        case SIP_PKT_REGISTER:
            fix_via_block(p->pkt.register_.via_count, p->pkt.register_.via);
            break;
        case SIP_PKT_OPTIONS:
            fix_via_block(p->pkt.options.via_count, p->pkt.options.via);
            break;
        default:
            /* Unknown packet type: nothing to do */
            break;
        }
    }
}


void fix_sip(sip_packet_t *pkts, size_t count){
    fix_shot5_request_uri_params(pkts, count);
    fix_shot6_sip_version(pkts, count);
    fix_shot7_header_field_format(pkts, count);
    fix_shot10_content_length_parsing(pkts, count);
    fix_sip_shot11_no_chunked(pkts, count);
    fix_sip_shot12_cseq(pkts, count);
    fix_sip_shot13_from(pkts, count);
    fix_sip_shot14_to(pkts, count);
    fix_sip_shot15_call_id(pkts, count);
    fix_sip_shot16_via_insertion(pkts, count);
    fix_sip_shot17_via_addressing(pkts, count);
    fix_sip_shot18_max_forwards(pkts, count);
    fix_sip_shot20_require_and_proxy_require(pkts, count);
    fix_sip_shot21_route(pkts, count);
    fix_sip_shot23_entity_headers(pkts, count);
    fix_sip_shot26_message_body_use(pkts, count);
    fix_sip_shot27_via_syntax(pkts, count);
}