/* ftp parser source file */
#include "ftp.h"
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


static void set_span_trim(char dst[], size_t cap, const char *b, const char *e) {
    if (!dst || cap == 0) return;
    if (!b || !e || e < b) { dst[0] = '\0'; return; }
    /* trim */
    while (b < e && (*b == ' ' || *b == '\t')) ++b;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    if (n > 0) memcpy(dst, b, n);
    dst[n] = '\0';
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
    *tok_b = tb; *tok_e = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p; 
    return p;
}


static void split_two_params(const char *b, const char *e,
                             const char **p1b, const char **p1e,
                             const char **p2b, const char **p2e) {
    *p1b = *p1e = *p2b = *p2e = NULL;

    while (b < e && (*b == ' ' || *b == '\t')) ++b;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
    if (b >= e) return;
    const char *p = b;
    while (p < e && *p != ' ' && *p != '\t') ++p;
    *p1b = b; *p1e = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    if (p < e) { *p2b = p; *p2e = e; }
}


static int map_cmd(const char *b, const char *e) {
    size_t n = (size_t)(e - b);

#define CMD(NAME) if (cmd_ieq(b, n, #NAME)) return FTP_##NAME
    CMD(USER); CMD(PASS); CMD(ACCT); CMD(CWD);  CMD(CDUP); CMD(SMNT); CMD(QUIT); CMD(REIN);
    CMD(PORT); CMD(PASV); CMD(TYPE); CMD(STRU); CMD(MODE);
    CMD(RETR); CMD(STOR); CMD(STOU); CMD(APPE); CMD(ALLO); CMD(REST);
    CMD(RNFR); CMD(RNTO); CMD(ABOR); CMD(DELE); CMD(RMD);  CMD(MKD);  CMD(PWD);
    CMD(LIST); CMD(NLST); CMD(SITE); CMD(SYST); CMD(STAT); CMD(HELP); CMD(NOOP);
#undef CMD
    return -1;
}


static void set_crlf(char dst[FTP_SZ_CRLF]) {
    set_cstr(dst, FTP_SZ_CRLF, "\r\n");
}


static void set_space(char dst[FTP_SZ_SPACE], int present) {
    set_cstr(dst, FTP_SZ_SPACE, present ? " " : "");
}

static int line_is_blank(const char *b, const char *e) {
    while (b < e) {
        if (*b != ' ' && *b != '\t' && *b != '\r') return 0;
        ++b;
    }
    return 1;
}

size_t parse_ftp_msg(const uint8_t *buf, u32 buf_len,
                     ftp_packet_t *out_packets, u32 max_count)
{
    if (!buf || !out_packets || max_count == 0) return 0;

    const char *cur = (const char*)buf;
    const char *end = (const char*)buf + buf_len;

    size_t out_n = 0;

    while (cur < end && out_n < max_count) {
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        if (!nl) break; 
        const char *line_b = cur;
        const char *line_e = nl;
        if (line_e > line_b && line_e[-1] == '\r') --line_e;

        if (line_is_blank(line_b, line_e)) { cur = nl + 1; continue; }

        const char *cmd_b, *cmd_e;
        const char *rest = parse_cmd_token(line_b, line_e, &cmd_b, &cmd_e);
        int ct = map_cmd(cmd_b, cmd_e);
        if (ct < 0) { 
            cur = nl + 1;
            continue;
        }

        ftp_packet_t *pkt = &out_packets[out_n];
        memset(pkt, 0, sizeof(*pkt));
        pkt->command_type = (ftp_command_type_t)ct;

        const char *arg_b = rest, *arg_e = line_e;
        while (arg_b < arg_e && (arg_b[0] == ' ' || arg_b[0] == '\t')) ++arg_b;
        while (arg_e > arg_b && (arg_e[-1] == ' ' || arg_e[-1] == '\t')) --arg_e;
        int has_arg = (arg_b < arg_e);

        switch (pkt->command_type) {
            case FTP_CDUP: {
                set_cstr(pkt->packet.cdup.command, FTP_SZ_CMD, "CDUP");
                set_crlf(pkt->packet.cdup.crlf);
            } break;
            case FTP_QUIT: {
                set_cstr(pkt->packet.quit.command, FTP_SZ_CMD, "QUIT");
                set_crlf(pkt->packet.quit.crlf);
            } break;
            case FTP_REIN: {
                set_cstr(pkt->packet.rein.command, FTP_SZ_CMD, "REIN");
                set_crlf(pkt->packet.rein.crlf);
            } break;
            case FTP_PASV: {
                set_cstr(pkt->packet.pasv.command, FTP_SZ_CMD, "PASV");
                set_crlf(pkt->packet.pasv.crlf);
            } break;
            case FTP_ABOR: {
                set_cstr(pkt->packet.abor.command, FTP_SZ_CMD, "ABOR");
                set_crlf(pkt->packet.abor.crlf);
            } break;
            case FTP_PWD: {
                set_cstr(pkt->packet.pwd.command, FTP_SZ_CMD, "PWD");
                set_crlf(pkt->packet.pwd.crlf);
            } break;
            case FTP_SYST: {
                set_cstr(pkt->packet.syst.command, FTP_SZ_CMD, "SYST");
                set_crlf(pkt->packet.syst.crlf);
            } break;
            case FTP_NOOP: {
                set_cstr(pkt->packet.noop.command, FTP_SZ_CMD, "NOOP");
                set_crlf(pkt->packet.noop.crlf);
            } break;

            case FTP_USER: {
                set_cstr(pkt->packet.user.command, FTP_SZ_CMD, "USER");
                set_space(pkt->packet.user.space, 1);
                set_span_trim(pkt->packet.user.username, FTP_SZ_USERNAME, arg_b, arg_e);
                set_crlf(pkt->packet.user.crlf);
            } break;
            case FTP_PASS: {
                set_cstr(pkt->packet.pass.command, FTP_SZ_CMD, "PASS");
                set_space(pkt->packet.pass.space, 1);
                set_span_trim(pkt->packet.pass.password, FTP_SZ_PASSWORD, arg_b, arg_e);
                set_crlf(pkt->packet.pass.crlf);
            } break;
            case FTP_ACCT: {
                set_cstr(pkt->packet.acct.command, FTP_SZ_CMD, "ACCT");
                set_space(pkt->packet.acct.space, 1);
                set_span_trim(pkt->packet.acct.account_info, FTP_SZ_ACCOUNT, arg_b, arg_e);
                set_crlf(pkt->packet.acct.crlf);
            } break;
            case FTP_CWD: {
                set_cstr(pkt->packet.cwd.command, FTP_SZ_CMD, "CWD");
                set_space(pkt->packet.cwd.space, 1);
                set_span_trim(pkt->packet.cwd.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.cwd.crlf);
            } break;
            case FTP_SMNT: {
                set_cstr(pkt->packet.smnt.command, FTP_SZ_CMD, "SMNT");
                set_space(pkt->packet.smnt.space, 1);
                set_span_trim(pkt->packet.smnt.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.smnt.crlf);
            } break;
            case FTP_PORT: {
                set_cstr(pkt->packet.port.command, FTP_SZ_CMD, "PORT");
                set_space(pkt->packet.port.space, 1);
                set_span_trim(pkt->packet.port.host_port_str, FTP_SZ_HOSTPORT, arg_b, arg_e);
                set_crlf(pkt->packet.port.crlf);
            } break;
            case FTP_STRU: {
                set_cstr(pkt->packet.stru.command, FTP_SZ_CMD, "STRU");
                set_space(pkt->packet.stru.space, 1);
                set_span_trim(pkt->packet.stru.structure_code, FTP_SZ_STRUCTURE, arg_b, arg_e);
                set_crlf(pkt->packet.stru.crlf);
            } break;
            case FTP_MODE: {
                set_cstr(pkt->packet.mode.command, FTP_SZ_CMD, "MODE");
                set_space(pkt->packet.mode.space, 1);
                set_span_trim(pkt->packet.mode.mode_code, FTP_SZ_MODE, arg_b, arg_e);
                set_crlf(pkt->packet.mode.crlf);
            } break;
            case FTP_RETR: {
                set_cstr(pkt->packet.retr.command, FTP_SZ_CMD, "RETR");
                set_space(pkt->packet.retr.space, 1);
                set_span_trim(pkt->packet.retr.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.retr.crlf);
            } break;
            case FTP_STOR: {
                set_cstr(pkt->packet.stor.command, FTP_SZ_CMD, "STOR");
                set_space(pkt->packet.stor.space, 1);
                set_span_trim(pkt->packet.stor.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.stor.crlf);
            } break;
            case FTP_APPE: {
                set_cstr(pkt->packet.appe.command, FTP_SZ_CMD, "APPE");
                set_space(pkt->packet.appe.space, 1);
                set_span_trim(pkt->packet.appe.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.appe.crlf);
            } break;
            case FTP_REST: {
                set_cstr(pkt->packet.rest.command, FTP_SZ_CMD, "REST");
                set_space(pkt->packet.rest.space, 1);
                set_span_trim(pkt->packet.rest.marker, FTP_SZ_MARKER, arg_b, arg_e);
                set_crlf(pkt->packet.rest.crlf);
            } break;
            case FTP_RNFR: {
                set_cstr(pkt->packet.rnfr.command, FTP_SZ_CMD, "RNFR");
                set_space(pkt->packet.rnfr.space, 1);
                set_span_trim(pkt->packet.rnfr.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.rnfr.crlf);
            } break;
            case FTP_RNTO: {
                set_cstr(pkt->packet.rnto.command, FTP_SZ_CMD, "RNTO");
                set_space(pkt->packet.rnto.space, 1);
                set_span_trim(pkt->packet.rnto.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.rnto.crlf);
            } break;
            case FTP_DELE: {
                set_cstr(pkt->packet.dele.command, FTP_SZ_CMD, "DELE");
                set_space(pkt->packet.dele.space, 1);
                set_span_trim(pkt->packet.dele.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.dele.crlf);
            } break;
            case FTP_RMD: {
                set_cstr(pkt->packet.rmd.command, FTP_SZ_CMD, "RMD");
                set_space(pkt->packet.rmd.space, 1);
                set_span_trim(pkt->packet.rmd.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.rmd.crlf);
            } break;
            case FTP_MKD: {
                set_cstr(pkt->packet.mkd.command, FTP_SZ_CMD, "MKD");
                set_space(pkt->packet.mkd.space, 1);
                set_span_trim(pkt->packet.mkd.pathname, FTP_SZ_PATH, arg_b, arg_e);
                set_crlf(pkt->packet.mkd.crlf);
            } break;
            case FTP_SITE: {
                set_cstr(pkt->packet.site.command, FTP_SZ_CMD, "SITE");
                set_space(pkt->packet.site.space, 1);
                set_span_trim(pkt->packet.site.parameters, FTP_SZ_PARAMS, arg_b, arg_e);
                set_crlf(pkt->packet.site.crlf);
            } break;

            case FTP_TYPE: {
                set_cstr(pkt->packet.type.command, FTP_SZ_CMD, "TYPE");
                set_space(pkt->packet.type.space1, 1);
                const char *p1b,*p1e,*p2b,*p2e;
                split_two_params(arg_b, arg_e, &p1b,&p1e,&p2b,&p2e);
                set_span_trim(pkt->packet.type.type_code, FTP_SZ_TYPE,
                              p1b ? p1b : arg_b, p1b ? p1e : arg_b);
                if (p2b && p2b < p2e) {
                    set_space(pkt->packet.type.space2, 1);
                    set_span_trim(pkt->packet.type.format_control, FTP_SZ_FORMAT, p2b, p2e);
                } else {
                    set_space(pkt->packet.type.space2, 0);
                    set_cstr(pkt->packet.type.format_control, FTP_SZ_FORMAT, "");
                }
                set_crlf(pkt->packet.type.crlf);
            } break;

            case FTP_ALLO: {
                set_cstr(pkt->packet.allo.command, FTP_SZ_CMD, "ALLO");
                set_space(pkt->packet.allo.space1, 1);
                const char *p1b,*p1e,*p2b,*p2e;
                split_two_params(arg_b, arg_e, &p1b,&p1e,&p2b,&p2e);
                set_span_trim(pkt->packet.allo.byte_count, FTP_SZ_BYTECOUNT,
                              p1b ? p1b : arg_b, p1b ? p1e : arg_b);
                if (p2b && p2b < p2e) {
                    set_space(pkt->packet.allo.space2, 1);
                    set_span_trim(pkt->packet.allo.record_format, FTP_SZ_FORMAT, p2b, p2e);
                } else {
                    set_space(pkt->packet.allo.space2, 0);
                    set_cstr(pkt->packet.allo.record_format, FTP_SZ_FORMAT, "");
                }
                set_crlf(pkt->packet.allo.crlf);
            } break;

            case FTP_STOU: {
                set_cstr(pkt->packet.stou.command, FTP_SZ_CMD, "STOU");
                set_space(pkt->packet.stou.space, has_arg ? 1 : 0);
                if (has_arg) set_span_trim(pkt->packet.stou.pathname, FTP_SZ_PATH, arg_b, arg_e);
                else         set_cstr(pkt->packet.stou.pathname, FTP_SZ_PATH, "");
                set_crlf(pkt->packet.stou.crlf);
            } break;
            case FTP_LIST: {
                set_cstr(pkt->packet.list.command, FTP_SZ_CMD, "LIST");
                set_space(pkt->packet.list.space, has_arg ? 1 : 0);
                if (has_arg) set_span_trim(pkt->packet.list.pathname, FTP_SZ_PATH, arg_b, arg_e);
                else         set_cstr(pkt->packet.list.pathname, FTP_SZ_PATH, "");
                set_crlf(pkt->packet.list.crlf);
            } break;
            case FTP_NLST: {
                set_cstr(pkt->packet.nlst.command, FTP_SZ_CMD, "NLST");
                set_space(pkt->packet.nlst.space, has_arg ? 1 : 0);
                if (has_arg) set_span_trim(pkt->packet.nlst.pathname, FTP_SZ_PATH, arg_b, arg_e);
                else         set_cstr(pkt->packet.nlst.pathname, FTP_SZ_PATH, "");
                set_crlf(pkt->packet.nlst.crlf);
            } break;
            case FTP_STAT: {
                set_cstr(pkt->packet.stat.command, FTP_SZ_CMD, "STAT");
                set_space(pkt->packet.stat.space, has_arg ? 1 : 0);
                if (has_arg) set_span_trim(pkt->packet.stat.pathname, FTP_SZ_PATH, arg_b, arg_e);
                else         set_cstr(pkt->packet.stat.pathname, FTP_SZ_PATH, "");
                set_crlf(pkt->packet.stat.crlf);
            } break;
            case FTP_HELP: {
                set_cstr(pkt->packet.help.command, FTP_SZ_CMD, "HELP");
                set_space(pkt->packet.help.space, has_arg ? 1 : 0);
                if (has_arg) set_span_trim(pkt->packet.help.argument, FTP_SZ_ARGUMENT, arg_b, arg_e);
                else         set_cstr(pkt->packet.help.argument, FTP_SZ_ARGUMENT, "");
                set_crlf(pkt->packet.help.crlf);
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


