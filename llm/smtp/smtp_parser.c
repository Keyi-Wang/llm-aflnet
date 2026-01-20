/* smtp parser source file */
#include "smtp.h"

#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>


static void set_cstr(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
    (void)snprintf(dst, cap, "%s", s);
}

static void set_crlf(char dst[SMTP_SZ_CRLF]) {
    set_cstr(dst, SMTP_SZ_CRLF, "\r\n");
}

static void set_space_opt(char dst[SMTP_SZ_SPACE], int present) {
    set_cstr(dst, SMTP_SZ_SPACE, present ? " " : "");
}

static void set_span_trim(char dst[], size_t cap, const char *b, const char *e) {
    if (!dst || cap == 0) return;
    if (!b || !e || e < b) { dst[0] = '\0'; return; }
    while (b < e && (*b == ' ' || *b == '\t')) ++b;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    if (n > 0) memcpy(dst, b, n);
    dst[n] = '\0';
}


static int line_is_blank(const char *b, const char *e) {
    while (b < e) {
        unsigned char c = (unsigned char)*b++;
        if (c != ' ' && c != '\t' && c != '\r') return 0;
    }
    return 1;
}


static int cmd_ieq(const char *s, size_t n, const char *NAME) {
    for (size_t i = 0; i < n; ++i) {
        int a = (unsigned char)s[i];
        int b = (unsigned char)NAME[i];
        if (!b) return 0;
        if (toupper(a) != toupper(b)) return 0;
    }
    return NAME[n] == '\0';
}

static const char* parse_cmd_token(const char *b, const char *e,
                                   const char **tok_b, const char **tok_e) {
    const char *p = b;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    const char *tb = p;
    while (p < e && *p != ' ' && *p != '\t') ++p;
    *tok_b = tb;
    *tok_e = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    return p;
}

static int map_cmd(const char *b, const char *e) {
#define M(NAME) if (cmd_ieq(b,(size_t)(e-b), #NAME)) return SMTP_PKT_##NAME
    M(HELO);
    M(EHLO);
    M(MAIL);
    M(RCPT);
    M(DATA);
    M(RSET);
    M(VRFY);
    M(EXPN);
    M(HELP);
    M(NOOP);
    M(QUIT);
    M(STARTTLS);
    M(AUTH);
    M(BDAT); 
#undef M
    return -1;
}

static int parse_u32_dec(const char *b, const char *e, uint32_t *out) {
    uint64_t v = 0;
    const char *p = b;
    if (p >= e) return 0;
    while (p < e && *p >= '0' && *p <= '9') {
        v = v * 10u + (uint64_t)(*p - '0');
        if (v > 0xFFFFFFFFu) return 0;
        ++p;
    }
    if (p == b) return 0;
    *out = (uint32_t)v;
    return 1;
}

static const char* next_token(const char *b, const char *e,
                              const char **tb, const char **te) {
    const char *p = b;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    const char *t0 = p;
    while (p < e && *p != ' ' && *p != '\t') ++p;
    *tb = t0; *te = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    return p;
}


size_t parse_smtp_msg(const uint8_t *buf, u32 buf_len,
                      smtp_packet_t *out_packets, u32 max_count)
{
    if (!buf || !out_packets || max_count == 0) return 0;

    const char *cur = (const char*)buf;
    const char *end = (const char*)buf + buf_len;

    size_t out_n = 0;
    int in_data_mode = 0;
    while (cur < end && out_n < max_count) {
        if (in_data_mode) {
            const char *scan = cur;
            const char *dot_line_beg = NULL;
            const char *dot_line_end = NULL;

            while (1) {
                const char *nl = memchr(scan, '\n', (size_t)(end - scan));
                if (!nl) {
                    if (out_n < max_count) {
                        smtp_packet_t *bp = &out_packets[out_n++];
                        memset(bp, 0, sizeof(*bp));
                        bp->cmd_type = SMTP_PKT_DATA_BLOCK;
                        bp->pkt.data_block.data = (const uint8_t*)cur;
                        bp->pkt.data_block.len  = (uint32_t)(end - cur);
                    }
                    cur = end;
                    break;
                }

                const char *lb = scan;               
                const char *le = nl;                 
                if (le > lb && le[-1] == '\r') --le; 
                if ((le - lb) == 1 && lb[0] == '.') {
                    dot_line_beg = lb;
                    dot_line_end = nl + 1; 
                    break;
                }

                scan = nl + 1;
            }

            if (!in_data_mode) break;

            if (dot_line_beg) {

                if (out_n < max_count) {
                    smtp_packet_t *bp = &out_packets[out_n++];
                    memset(bp, 0, sizeof(*bp));
                    bp->cmd_type = SMTP_PKT_DATA_BLOCK;
                    bp->pkt.data_block.data = (const uint8_t*)cur;
                    bp->pkt.data_block.len  = (uint32_t)(dot_line_beg - cur);
                }

                if (out_n < max_count) {
                    smtp_packet_t *dp = &out_packets[out_n++];
                    memset(dp, 0, sizeof(*dp));
                    dp->cmd_type = SMTP_PKT_DOT;
                    dp->pkt.dot.dot[0] = '.';
                    dp->pkt.dot.dot[1] = '\0';
                    set_crlf(dp->pkt.dot.crlf);
                }

                cur = dot_line_end;
                in_data_mode = 0;
                continue; 
            } else {
            
                break;
            }
        }

        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        if (!nl) break;
        const char *lb = cur;
        const char *le = nl;
        if (le > lb && le[-1] == '\r') --le;

        if (line_is_blank(lb, le)) { cur = nl + 1; continue; }
        if ((le - lb) == 1 && lb[0] == '.') {
            smtp_packet_t *pkt = &out_packets[out_n];
            memset(pkt, 0, sizeof(*pkt));
            pkt->cmd_type = SMTP_PKT_DOT;
            pkt->pkt.dot.dot[0] = '.';
            pkt->pkt.dot.dot[1] = '\0';
            set_crlf(pkt->pkt.dot.crlf);

            ++out_n;
            cur = nl + 1;
            continue;
        }

        const char *cb, *ce;
        const char *rest = parse_cmd_token(lb, le, &cb, &ce);
        int ct = map_cmd(cb, ce);
        if (ct < 0) {
            cur = nl + 1;
            continue;
        }

        smtp_packet_t *pkt = &out_packets[out_n];
        memset(pkt, 0, sizeof(*pkt));
        pkt->cmd_type = (smtp_cmd_type_t)ct;

        const char *ab = rest, *ae = le;
        while (ab < ae && (*ab == ' ' || *ab == '\t')) ++ab;
        while (ae > ab && (ae[-1] == ' ' || ae[-1] == '\t')) --ae;
        int has_arg = (ab < ae);

        switch (pkt->cmd_type) {
            case SMTP_PKT_HELO: {
                set_cstr(pkt->pkt.helo.command, SMTP_SZ_CMD, "HELO");
                if (has_arg) set_space_opt(pkt->pkt.helo.space, 1);
                else         set_space_opt(pkt->pkt.helo.space, 0);
                if (has_arg) set_span_trim(pkt->pkt.helo.domain, SMTP_SZ_DOMAIN, ab, ae);
                else         set_cstr(pkt->pkt.helo.domain, SMTP_SZ_DOMAIN, "");
                set_crlf(pkt->pkt.helo.crlf);
            } break;

            case SMTP_PKT_EHLO: {
                set_cstr(pkt->pkt.ehlo.command, SMTP_SZ_CMD, "EHLO");
                if (has_arg) set_space_opt(pkt->pkt.ehlo.space, 1);
                else         set_space_opt(pkt->pkt.ehlo.space, 0);
                if (has_arg) set_span_trim(pkt->pkt.ehlo.domain, SMTP_SZ_DOMAIN, ab, ae);
                else         set_cstr(pkt->pkt.ehlo.domain, SMTP_SZ_DOMAIN, "");
                set_crlf(pkt->pkt.ehlo.crlf);
            } break;

            case SMTP_PKT_MAIL: {
                set_cstr(pkt->pkt.mail.command, SMTP_SZ_CMD, "MAIL");


                const char *t1b=NULL, *t1e=NULL;
                const char *p = next_token(ab, ae, &t1b, &t1e);
                if (t1b && t1b < t1e && cmd_ieq(t1b,(size_t)(t1e-t1b),"FROM:")) {
                    set_cstr(pkt->pkt.mail.from_keyword, SMTP_SZ_CMD, "FROM:");
                    set_space_opt(pkt->pkt.mail.space1, has_arg ? 1 : 0);
                    const char *rp_b=NULL, *rp_e=NULL;
                    p = next_token(p, ae, &rp_b, &rp_e);
                    if (rp_b && rp_b < rp_e) {
                        set_span_trim(pkt->pkt.mail.reverse_path, SMTP_SZ_PATH, rp_b, rp_e);
                    } else {
                        set_cstr(pkt->pkt.mail.reverse_path, SMTP_SZ_PATH, "");
                    }

                    if (p < ae) {
                        set_span_trim(pkt->pkt.mail.optional_args, SMTP_SZ_OPTARGS, p, ae);
                    } else {
                        set_cstr(pkt->pkt.mail.optional_args, SMTP_SZ_OPTARGS, "");
                    }
                } else {
                    if (has_arg)
                        set_span_trim(pkt->pkt.mail.reverse_path, SMTP_SZ_PATH, ab, ae);
                    else
                        set_cstr(pkt->pkt.mail.reverse_path, SMTP_SZ_PATH, "");
                    set_cstr(pkt->pkt.mail.optional_args, SMTP_SZ_OPTARGS, "");
                }
                set_crlf(pkt->pkt.mail.crlf);
            } break;

            case SMTP_PKT_RCPT: {
                set_cstr(pkt->pkt.rcpt.command, SMTP_SZ_CMD, "RCPT");

                const char *t1b=NULL, *t1e=NULL;
                const char *p = next_token(ab, ae, &t1b, &t1e);
                if (t1b && t1b < t1e && cmd_ieq(t1b,(size_t)(t1e-t1b),"TO:")) {
                    set_space_opt(pkt->pkt.rcpt.space1, has_arg ? 1 : 0);
                    set_cstr(pkt->pkt.rcpt.to_keyword, SMTP_SZ_CMD, "TO:");
                    const char *fp_b=NULL, *fp_e=NULL;
                    p = next_token(p, ae, &fp_b, &fp_e);
                    if (fp_b && fp_b < fp_e) {
                        set_span_trim(pkt->pkt.rcpt.forward_path, SMTP_SZ_PATH, fp_b, fp_e);
                    } else {
                        set_cstr(pkt->pkt.rcpt.forward_path, SMTP_SZ_PATH, "");
                    }
                    if (p < ae) {
                        set_span_trim(pkt->pkt.rcpt.optional_args, SMTP_SZ_OPTARGS, p, ae);
                    } else {
                        set_cstr(pkt->pkt.rcpt.optional_args, SMTP_SZ_OPTARGS, "");
                    }
                } else {
                    if (has_arg)
                        set_span_trim(pkt->pkt.rcpt.forward_path, SMTP_SZ_PATH, ab, ae);
                    else
                        set_cstr(pkt->pkt.rcpt.forward_path, SMTP_SZ_PATH, "");
                    set_cstr(pkt->pkt.rcpt.optional_args, SMTP_SZ_OPTARGS, "");
                }
                set_crlf(pkt->pkt.rcpt.crlf);
            } break;

            case SMTP_PKT_DATA: {
                set_cstr(pkt->pkt.data.command, SMTP_SZ_CMD, "DATA");
                set_crlf(pkt->pkt.data.crlf);
                in_data_mode = 1;
            } break;

            case SMTP_PKT_RSET: {
                set_cstr(pkt->pkt.rset.command, SMTP_SZ_CMD, "RSET");
                set_crlf(pkt->pkt.rset.crlf);
            } break;

            case SMTP_PKT_VRFY: {
                set_cstr(pkt->pkt.vrfy.command, SMTP_SZ_CMD, "VRFY");
                if (has_arg) set_space_opt(pkt->pkt.vrfy.space, 1);
                else         set_space_opt(pkt->pkt.vrfy.space, 0);
                if (has_arg) set_span_trim(pkt->pkt.vrfy.string, SMTP_SZ_VRFY_STR, ab, ae);
                else         set_cstr(pkt->pkt.vrfy.string, SMTP_SZ_VRFY_STR, "");
                set_crlf(pkt->pkt.vrfy.crlf);
            } break;

            case SMTP_PKT_EXPN: {
                set_cstr(pkt->pkt.expn.command, SMTP_SZ_CMD, "EXPN");
                if (has_arg) set_space_opt(pkt->pkt.expn.space, 1);
                else         set_space_opt(pkt->pkt.expn.space, 0);
                if (has_arg) set_span_trim(pkt->pkt.expn.mailing_list, SMTP_SZ_LISTNAME, ab, ae);
                else         set_cstr(pkt->pkt.expn.mailing_list, SMTP_SZ_LISTNAME, "");
                set_crlf(pkt->pkt.expn.crlf);
            } break;

            case SMTP_PKT_HELP: {
                set_cstr(pkt->pkt.help.command, SMTP_SZ_CMD, "HELP");
                if (has_arg) set_space_opt(pkt->pkt.help.space, 1);
                else         set_space_opt(pkt->pkt.help.space, 0);
                if (has_arg) set_span_trim(pkt->pkt.help.argument, SMTP_SZ_HELP_ARG, ab, ae);
                else         set_cstr(pkt->pkt.help.argument, SMTP_SZ_HELP_ARG, "");
                set_crlf(pkt->pkt.help.crlf);
            } break;

            case SMTP_PKT_NOOP: {
                set_cstr(pkt->pkt.noop.command, SMTP_SZ_CMD, "NOOP");
                set_crlf(pkt->pkt.noop.crlf);
            } break;

            case SMTP_PKT_QUIT: {
                set_cstr(pkt->pkt.quit.command, SMTP_SZ_CMD, "QUIT");
                set_crlf(pkt->pkt.quit.crlf);
            } break;

            case SMTP_PKT_STARTTLS: {
                set_cstr(pkt->pkt.starttls.command, SMTP_SZ_CMD, "STARTTLS");
                set_crlf(pkt->pkt.starttls.crlf);
            } break;

            case SMTP_PKT_AUTH: {
                set_cstr(pkt->pkt.auth.command, SMTP_SZ_CMD, "AUTH");
                if (!has_arg) {
                    set_space_opt(pkt->pkt.auth.space1, 0);
                    set_cstr(pkt->pkt.auth.mechanism, SMTP_SZ_AUTH_MECH, "");
                    set_space_opt(pkt->pkt.auth.space2, 0);
                    set_cstr(pkt->pkt.auth.initial_response, SMTP_SZ_AUTH_IR, "");
                } else {
                    set_space_opt(pkt->pkt.auth.space1, 1);
                    const char *m_b=NULL, *m_e=NULL;
                    const char *p = next_token(ab, ae, &m_b, &m_e);
                    if (m_b && m_b < m_e)
                        set_span_trim(pkt->pkt.auth.mechanism, SMTP_SZ_AUTH_MECH, m_b, m_e);
                    else
                        set_cstr(pkt->pkt.auth.mechanism, SMTP_SZ_AUTH_MECH, "");
                    if (p < ae) {
                        set_space_opt(pkt->pkt.auth.space2, 1);
                        set_span_trim(pkt->pkt.auth.initial_response, SMTP_SZ_AUTH_IR, p, ae);
                    } else {
                        set_space_opt(pkt->pkt.auth.space2, 0);
                        set_cstr(pkt->pkt.auth.initial_response, SMTP_SZ_AUTH_IR, "");
                    }
                }
                set_crlf(pkt->pkt.auth.crlf);
            } break;
            case SMTP_PKT_BDAT: {
                set_cstr(pkt->pkt.bdat.command, SMTP_SZ_CMD, "BDAT");

                const char *sz_b=NULL, *sz_e=NULL;
                const char *p = next_token(ab, ae, &sz_b, &sz_e);
                if (sz_b == sz_e || !sz_b) { 
                    set_space_opt(pkt->pkt.bdat.space1, 0);
                    set_cstr(pkt->pkt.bdat.size_str, SMTP_SZ_NUM, "");
                } else {
                    set_space_opt(pkt->pkt.bdat.space1, 1);
                    set_span_trim(pkt->pkt.bdat.size_str, SMTP_SZ_NUM, sz_b, sz_e);
                }

                const char *last_b=NULL, *last_e=NULL;
                if (p < ae) {
                    const char *p2 = next_token(p, ae, &last_b, &last_e);
                    (void)p2;
                    if (last_b && last_b < last_e && cmd_ieq(last_b,(size_t)(last_e-last_b),"LAST")) {
                        set_space_opt(pkt->pkt.bdat.space2, 1);
                        set_cstr(pkt->pkt.bdat.last_token, SMTP_SZ_LAST, "LAST");
                    } else {
                        set_space_opt(pkt->pkt.bdat.space2, 0);
                        set_cstr(pkt->pkt.bdat.last_token, SMTP_SZ_LAST, "");
                    }
                } else {
                    set_space_opt(pkt->pkt.bdat.space2, 0);
                    set_cstr(pkt->pkt.bdat.last_token, SMTP_SZ_LAST, "");
                }
                set_crlf(pkt->pkt.bdat.crlf);

                uint32_t want = 0;
                if (!parse_u32_dec(pkt->pkt.bdat.size_str, pkt->pkt.bdat.size_str + strlen(pkt->pkt.bdat.size_str), &want)) {
                    want = 0;
                }

                const char *payload_beg = nl + 1;
                const char *payload_end = end;
                size_t remain = (size_t)(payload_end - payload_beg);
                size_t take = (want <= remain) ? (size_t)want : remain;

                pkt->pkt.bdat.data     = (const uint8_t*)payload_beg;
                pkt->pkt.bdat.data_len = (uint32_t)take;

                cur = payload_beg + take;

                ++out_n;

            } break;

            default:

                cur = nl + 1;
                continue;
        }

        ++out_n;
        cur = nl + 1;
    }

    return out_n;
}
