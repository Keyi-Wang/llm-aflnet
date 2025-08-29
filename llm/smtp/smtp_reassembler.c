/* smtp reassembler source file */
#include "smtp.h"
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ---------------- 小工具：安全字符串写入 / 拷贝 ---------------- */

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

/* 拷贝 [b,e) （不含 e），并裁剪首尾空白（空格/Tab） */
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

/* 不裁剪，仅按范围拷贝 */
static void set_span_raw(char dst[], size_t cap, const char *b, const char *e) {
    if (!dst || cap == 0) return;
    if (!b || !e || e < b) { dst[0] = '\0'; return; }
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    if (n > 0) memcpy(dst, b, n);
    dst[n] = '\0';
}

/* line 是否全空白（空格/Tab/CR） */
static int line_is_blank(const char *b, const char *e) {
    while (b < e) {
        unsigned char c = (unsigned char)*b++;
        if (c != ' ' && c != '\t' && c != '\r') return 0;
    }
    return 1;
}

/* 输出缓冲安全追加 */
static int out_put(u8 *out, u32 cap, u32 *pos, const char *s) {
    if (!s) return 1;
    size_t n = strlen(s);
    if (*pos > cap || cap - *pos < n) return 0;
    memcpy(out + *pos, s, n);
    *pos += (u32)n;
    return 1;
}
static int out_put_if_nonempty(u8 *out, u32 cap, u32 *pos,
                               const char *maybe_space, const char *field) {
    if (!field || !*field) return 1;
    if (maybe_space && *maybe_space) {
        if (!out_put(out, cap, pos, maybe_space)) return 0;
    }
    return out_put(out, cap, pos, field);
}

/* ---------------- 重组单行 ---------------- */

static int reassemble_one(const smtp_packet_t *p, u8 *out, u32 cap, u32 *pos) {
    switch (p->cmd_type) {
        case SMTP_PKT_HELO:
            return out_put(out,cap,pos,p->pkt.helo.command)
                && out_put_if_nonempty(out,cap,pos,p->pkt.helo.space,p->pkt.helo.domain)
                && out_put(out,cap,pos,p->pkt.helo.crlf);

        case SMTP_PKT_EHLO:
            return out_put(out,cap,pos,p->pkt.ehlo.command)
                && out_put_if_nonempty(out,cap,pos,p->pkt.ehlo.space,p->pkt.ehlo.domain)
                && out_put(out,cap,pos,p->pkt.ehlo.crlf);

        case SMTP_PKT_MAIL: {
            if (!out_put(out,cap,pos,p->pkt.mail.command)) return 0;
            if (!out_put(out,cap,pos,p->pkt.mail.space1)) return 0;
            if (!out_put(out,cap,pos,p->pkt.mail.from_keyword)) return 0;
            if (p->pkt.mail.reverse_path[0]) {
                if (!out_put(out,cap,pos," ")) return 0;
                if (!out_put(out,cap,pos,p->pkt.mail.reverse_path)) return 0;
            }
            if (p->pkt.mail.optional_args[0]) {
                if (!out_put(out,cap,pos," ")) return 0;
                if (!out_put(out,cap,pos,p->pkt.mail.optional_args)) return 0;
            }
            return out_put(out,cap,pos,p->pkt.mail.crlf);
        }

        case SMTP_PKT_RCPT: {
            if (!out_put(out,cap,pos,p->pkt.rcpt.command)) return 0;
            if (!out_put(out,cap,pos,p->pkt.rcpt.space1)) return 0;
            if (!out_put(out,cap,pos,p->pkt.rcpt.to_keyword)) return 0;
            if (p->pkt.rcpt.forward_path[0]) {
                if (!out_put(out,cap,pos," ")) return 0;
                if (!out_put(out,cap,pos,p->pkt.rcpt.forward_path)) return 0;
            }
            if (p->pkt.rcpt.optional_args[0]) {
                if (!out_put(out,cap,pos," ")) return 0;
                if (!out_put(out,cap,pos,p->pkt.rcpt.optional_args)) return 0;
            }
            return out_put(out,cap,pos,p->pkt.rcpt.crlf);
        }

        case SMTP_PKT_DATA:
            return out_put(out,cap,pos,p->pkt.data.command)
                && out_put(out,cap,pos,p->pkt.data.crlf);

        case SMTP_PKT_RSET:
            return out_put(out,cap,pos,p->pkt.rset.command)
                && out_put(out,cap,pos,p->pkt.rset.crlf);

        case SMTP_PKT_VRFY:
            return out_put(out,cap,pos,p->pkt.vrfy.command)
                && out_put_if_nonempty(out,cap,pos,p->pkt.vrfy.space,p->pkt.vrfy.string)
                && out_put(out,cap,pos,p->pkt.vrfy.crlf);

        case SMTP_PKT_EXPN:
            return out_put(out,cap,pos,p->pkt.expn.command)
                && out_put_if_nonempty(out,cap,pos,p->pkt.expn.space,p->pkt.expn.mailing_list)
                && out_put(out,cap,pos,p->pkt.expn.crlf);

        case SMTP_PKT_HELP:
            return out_put(out,cap,pos,p->pkt.help.command)
                && out_put_if_nonempty(out,cap,pos,p->pkt.help.space,p->pkt.help.argument)
                && out_put(out,cap,pos,p->pkt.help.crlf);

        case SMTP_PKT_NOOP:
            return out_put(out,cap,pos,p->pkt.noop.command)
                && out_put(out,cap,pos,p->pkt.noop.crlf);

        case SMTP_PKT_QUIT:
            return out_put(out,cap,pos,p->pkt.quit.command)
                && out_put(out,cap,pos,p->pkt.quit.crlf);

        case SMTP_PKT_STARTTLS:
            return out_put(out,cap,pos,p->pkt.starttls.command)
                && out_put(out,cap,pos,p->pkt.starttls.crlf);

        case SMTP_PKT_AUTH:
            if (!out_put(out,cap,pos,p->pkt.auth.command)) return 0;
            if (p->pkt.auth.mechanism[0]) {
                if (!out_put(out,cap,pos,p->pkt.auth.space1)) return 0;
                if (!out_put(out,cap,pos,p->pkt.auth.mechanism)) return 0;
                if (p->pkt.auth.initial_response[0]) {
                    if (!out_put(out,cap,pos,p->pkt.auth.space2)) return 0;
                    if (!out_put(out,cap,pos,p->pkt.auth.initial_response)) return 0;
                }
            }
            return out_put(out,cap,pos,p->pkt.auth.crlf);

        default:
            return 0;
    }
}

/* ---------------- 对外重组接口 ---------------- */

int reassemble_smtp_msgs(const smtp_packet_t *packets, u32 num_packets,
                         u8 *output_buf, u32 *out_len)
{
    if (!packets || !output_buf || !out_len) return -1;
    u32 cap = 1024*1024;
    u32 pos = 0;

    for (u32 i = 0; i < num_packets; ++i) {
        if (!reassemble_one(&packets[i], output_buf, cap, &pos)) {
            *out_len = pos; /* 返回目前已写入长度，便于诊断 */
            return -2;      /* 缓冲不足或数据异常 */
        }
    }

    *out_len = pos;
    return 0;
}
