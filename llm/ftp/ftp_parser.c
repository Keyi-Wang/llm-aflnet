/* ftp parser source file */
#include "ftp.h"
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* === 这里假定已包含你给出的所有 typedef/enum 定义与宏尺寸 === */
/* 例如：FTP_SZ_CMD/FTP_SZ_SPACE/FTP_SZ_CRLF/... 以及各个 *_packet_t 与 ftp_packet_t */

/* ---------- 小工具：安全拷贝 & 片段拷贝（裁剪空白） ---------- */
static void set_cstr(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
    /* snprintf 总会写入 '\0'（cap>0），并在超长时安全截断 */
    (void)snprintf(dst, cap, "%s", s);
}

/* 拷贝 [b,e) 片段（不含 e），并裁剪首尾空白 */
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

/* 大小写不敏感命令名匹配：s[0..n) vs "NAME" */
static int cmd_ieq(const char *s, size_t n, const char *NAME) {
    for (size_t i = 0; i < n; ++i) {
        int a = (unsigned char)s[i];
        int b = (unsigned char)NAME[i];
        if (!b) return 0; /* s 比 NAME 更长 */
        if (toupper(a) != toupper(b)) return 0;
    }
    return NAME[n] == '\0';
}

/* 取首个 token（命令），返回 token 后第一个非空白位置 */
static const char* parse_cmd_token(const char *b, const char *e,
                                   const char **tok_b, const char **tok_e) {
    const char *p = b;
    /* 跳前导空白 */
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    const char *tb = p;
    while (p < e && *p != ' ' && *p != '\t') ++p;
    *tok_b = tb; *tok_e = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p; /* 跳过一个或多个空格 */
    return p;
}

/* 拆出最多两个以空白分隔的参数：p1 [p2]（用于 TYPE/ALLO） */
static void split_two_params(const char *b, const char *e,
                             const char **p1b, const char **p1e,
                             const char **p2b, const char **p2e) {
    *p1b = *p1e = *p2b = *p2e = NULL;
    /* trim 整体参数串 */
    while (b < e && (*b == ' ' || *b == '\t')) ++b;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
    if (b >= e) return;
    const char *p = b;
    while (p < e && *p != ' ' && *p != '\t') ++p;
    *p1b = b; *p1e = p;
    while (p < e && (*p == ' ' || *p == '\t')) ++p;
    if (p < e) { *p2b = p; *p2e = e; }
}

/* 映射命令名到枚举；返回 -1 表示未知 */
static int map_cmd(const char *b, const char *e) {
    size_t n = (size_t)(e - b);
    /* 使用宏简化 */
#define CMD(NAME) if (cmd_ieq(b, n, #NAME)) return FTP_##NAME
    CMD(USER); CMD(PASS); CMD(ACCT); CMD(CWD);  CMD(CDUP); CMD(SMNT); CMD(QUIT); CMD(REIN);
    CMD(PORT); CMD(PASV); CMD(TYPE); CMD(STRU); CMD(MODE);
    CMD(RETR); CMD(STOR); CMD(STOU); CMD(APPE); CMD(ALLO); CMD(REST);
    CMD(RNFR); CMD(RNTO); CMD(ABOR); CMD(DELE); CMD(RMD);  CMD(MKD);  CMD(PWD);
    CMD(LIST); CMD(NLST); CMD(SITE); CMD(SYST); CMD(STAT); CMD(HELP); CMD(NOOP);
#undef CMD
    return -1;
}

/* 固定把 CRLF 字段置为 "\r\n" */
static void set_crlf(char dst[FTP_SZ_CRLF]) {
    set_cstr(dst, FTP_SZ_CRLF, "\r\n");
}

/* 固定/可选空格的设定：present? " " : "" */
static void set_space(char dst[FTP_SZ_SPACE], int present) {
    set_cstr(dst, FTP_SZ_SPACE, present ? " " : "");
}

/* 判断这一行（不含换行）是否全空白 */
static int line_is_blank(const char *b, const char *e) {
    while (b < e) {
        if (*b != ' ' && *b != '\t' && *b != '\r') return 0;
        ++b;
    }
    return 1;
}

/* ---------- 主解析函数 ---------- */
size_t parse_ftp_msg(const uint8_t *buf, size_t buf_len,
                     ftp_packet_t *out_packets, size_t max_count)
{
    if (!buf || !out_packets || max_count == 0) return 0;

    const char *cur = (const char*)buf;
    const char *end = (const char*)buf + buf_len;

    size_t out_n = 0;

    while (cur < end && out_n < max_count) {
        /* 找到一行：以 '\n' 结束；line_e 指向 '\n' 前（若有 '\r' 去掉） */
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        if (!nl) break; /* 不完整的一行，停止 */
        const char *line_b = cur;
        const char *line_e = nl;
        if (line_e > line_b && line_e[-1] == '\r') --line_e;

        /* 跳过空行 */
        if (line_is_blank(line_b, line_e)) { cur = nl + 1; continue; }

        /* 解析命令 token */
        const char *cmd_b, *cmd_e;
        const char *rest = parse_cmd_token(line_b, line_e, &cmd_b, &cmd_e);
        int ct = map_cmd(cmd_b, cmd_e);
        if (ct < 0) { /* 未知命令：跳过该行 */
            cur = nl + 1;
            continue;
        }

        /* 输出槽位 */
        ftp_packet_t *pkt = &out_packets[out_n];
        memset(pkt, 0, sizeof(*pkt));
        pkt->command_type = (ftp_command_type_t)ct;

        /* 参数区间（rest..line_e） */
        const char *arg_b = rest, *arg_e = line_e;
        /* 去掉整体参数尾部空白（保形：需要时再单独裁剪） */
        while (arg_b < arg_e && (arg_b[0] == ' ' || arg_b[0] == '\t')) ++arg_b;
        while (arg_e > arg_b && (arg_e[-1] == ' ' || arg_e[-1] == '\t')) --arg_e;
        int has_arg = (arg_b < arg_e);

        switch (pkt->command_type) {
            /* ---- 无参数命令 ---- */
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

            /* ---- 单参数（固定 space） ---- */
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
                /* 保留原样（不额外裁剪中间空白），只裁两端 */
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

            /* ---- 两段参数：TYPE/ALLO ---- */
            case FTP_TYPE: {
                set_cstr(pkt->packet.type.command, FTP_SZ_CMD, "TYPE");
                set_space(pkt->packet.type.space1, 1);
                const char *p1b,*p1e,*p2b,*p2e;
                split_two_params(arg_b, arg_e, &p1b,&p1e,&p2b,&p2e);
                /* 第一段必填（为空则置空串） */
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

            /* ---- 可选参数命令：STOU/LIST/NLST/STAT/HELP ---- */
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
                /* 不会到这里，防御性：跳过 */
                cur = nl + 1;
                continue;
        }

        ++out_n;
        cur = nl + 1;
    }

    return out_n;
}



// static void fprint_escaped(FILE *out, const char *s) {
//     if (!s) return;
//     for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
//         unsigned char c = *p;
//         switch (c) {
//             case '\r': fputs("\\r", out); break;
//             case '\n': fputs("\\n", out); break;
//             case '\t': fputs("\\t", out); break;
//             case '\\': fputs("\\\\", out); break;
//             case '\"': fputs("\\\"", out); break;
//             default:
//                 if (c < 0x20 || c >= 0x7f) {
//                     fprintf(out, "\\x%02X", (unsigned)c);
//                 } else {
//                     fputc(c, out);
//                 }
//         }
//     }
// }

// static const char* cmd_to_str(ftp_command_type_t t) {
//     /* 顺序需与 ftp_packets.h 中的枚举一致 */
//     static const char* names[] = {
//         "USER","PASS","ACCT","CWD","CDUP","SMNT","REIN","QUIT",
//         "PORT","PASV","TYPE","STRU","MODE",
//         "RETR","STOR","STOU","APPE","ALLO","REST","RNFR","RNTO",
//         "ABOR","DELE","RMD","MKD","PWD",
//         "LIST","NLST","SITE","SYST","STAT","HELP","NOOP"
//     };
//     size_t n = sizeof(names)/sizeof(names[0]);
//     return ((unsigned)t < n) ? names[t] : "UNKNOWN";
// }

// void print_ftp_packets(const ftp_packet_t *packets, size_t pkt_num) {
//     if (!packets) return;

//     for (size_t i = 0; i < pkt_num; ++i) {
//         const ftp_packet_t *pk = &packets[i];
//         printf("[%04zu] CMD=%s\n", i, cmd_to_str(pk->command_type));
//         printf("        line: \"");

//         switch (pk->command_type) {
//             case FTP_USER:
//                 fprint_escaped(stdout, pk->packet.user.command);
//                 fprint_escaped(stdout, pk->packet.user.space);
//                 fprint_escaped(stdout, pk->packet.user.username);
//                 fprint_escaped(stdout, pk->packet.user.crlf);
//                 break;

//             case FTP_PASS:
//                 fprint_escaped(stdout, pk->packet.pass.command);
//                 fprint_escaped(stdout, pk->packet.pass.space);
//                 fprint_escaped(stdout, pk->packet.pass.password);
//                 fprint_escaped(stdout, pk->packet.pass.crlf);
//                 break;

//             case FTP_ACCT:
//                 fprint_escaped(stdout, pk->packet.acct.command);
//                 fprint_escaped(stdout, pk->packet.acct.space);
//                 fprint_escaped(stdout, pk->packet.acct.account_info);
//                 fprint_escaped(stdout, pk->packet.acct.crlf);
//                 break;

//             case FTP_CWD:
//                 fprint_escaped(stdout, pk->packet.cwd.command);
//                 fprint_escaped(stdout, pk->packet.cwd.space);
//                 fprint_escaped(stdout, pk->packet.cwd.pathname);
//                 fprint_escaped(stdout, pk->packet.cwd.crlf);
//                 break;

//             case FTP_CDUP:
//                 fprint_escaped(stdout, pk->packet.cdup.command);
//                 fprint_escaped(stdout, pk->packet.cdup.crlf);
//                 break;

//             case FTP_SMNT:
//                 fprint_escaped(stdout, pk->packet.smnt.command);
//                 fprint_escaped(stdout, pk->packet.smnt.space);
//                 fprint_escaped(stdout, pk->packet.smnt.pathname);
//                 fprint_escaped(stdout, pk->packet.smnt.crlf);
//                 break;

//             case FTP_REIN:
//                 fprint_escaped(stdout, pk->packet.rein.command);
//                 fprint_escaped(stdout, pk->packet.rein.crlf);
//                 break;

//             case FTP_QUIT:
//                 fprint_escaped(stdout, pk->packet.quit.command);
//                 fprint_escaped(stdout, pk->packet.quit.crlf);
//                 break;

//             case FTP_PORT:
//                 fprint_escaped(stdout, pk->packet.port.command);
//                 fprint_escaped(stdout, pk->packet.port.space);
//                 fprint_escaped(stdout, pk->packet.port.host_port_str);
//                 fprint_escaped(stdout, pk->packet.port.crlf);
//                 break;

//             case FTP_PASV:
//                 fprint_escaped(stdout, pk->packet.pasv.command);
//                 fprint_escaped(stdout, pk->packet.pasv.crlf);
//                 break;

//             case FTP_TYPE:
//                 fprint_escaped(stdout, pk->packet.type.command);
//                 fprint_escaped(stdout, pk->packet.type.space1);
//                 fprint_escaped(stdout, pk->packet.type.type_code);
//                 fprint_escaped(stdout, pk->packet.type.space2);
//                 fprint_escaped(stdout, pk->packet.type.format_control);
//                 fprint_escaped(stdout, pk->packet.type.crlf);
//                 break;

//             case FTP_STRU:
//                 fprint_escaped(stdout, pk->packet.stru.command);
//                 fprint_escaped(stdout, pk->packet.stru.space);
//                 fprint_escaped(stdout, pk->packet.stru.structure_code);
//                 fprint_escaped(stdout, pk->packet.stru.crlf);
//                 break;

//             case FTP_MODE:
//                 fprint_escaped(stdout, pk->packet.mode.command);
//                 fprint_escaped(stdout, pk->packet.mode.space);
//                 fprint_escaped(stdout, pk->packet.mode.mode_code);
//                 fprint_escaped(stdout, pk->packet.mode.crlf);
//                 break;

//             case FTP_RETR:
//                 fprint_escaped(stdout, pk->packet.retr.command);
//                 fprint_escaped(stdout, pk->packet.retr.space);
//                 fprint_escaped(stdout, pk->packet.retr.pathname);
//                 fprint_escaped(stdout, pk->packet.retr.crlf);
//                 break;

//             case FTP_STOR:
//                 fprint_escaped(stdout, pk->packet.stor.command);
//                 fprint_escaped(stdout, pk->packet.stor.space);
//                 fprint_escaped(stdout, pk->packet.stor.pathname);
//                 fprint_escaped(stdout, pk->packet.stor.crlf);
//                 break;

//             case FTP_STOU:
//                 fprint_escaped(stdout, pk->packet.stou.command);
//                 fprint_escaped(stdout, pk->packet.stou.space);
//                 fprint_escaped(stdout, pk->packet.stou.pathname);
//                 fprint_escaped(stdout, pk->packet.stou.crlf);
//                 break;

//             case FTP_APPE:
//                 fprint_escaped(stdout, pk->packet.appe.command);
//                 fprint_escaped(stdout, pk->packet.appe.space);
//                 fprint_escaped(stdout, pk->packet.appe.pathname);
//                 fprint_escaped(stdout, pk->packet.appe.crlf);
//                 break;

//             case FTP_ALLO:
//                 fprint_escaped(stdout, pk->packet.allo.command);
//                 fprint_escaped(stdout, pk->packet.allo.space1);
//                 fprint_escaped(stdout, pk->packet.allo.byte_count);
//                 fprint_escaped(stdout, pk->packet.allo.space2);
//                 fprint_escaped(stdout, pk->packet.allo.record_format); /* 若为空则不会输出额外内容 */
//                 fprint_escaped(stdout, pk->packet.allo.crlf);
//                 break;

//             case FTP_REST:
//                 fprint_escaped(stdout, pk->packet.rest.command);
//                 fprint_escaped(stdout, pk->packet.rest.space);
//                 fprint_escaped(stdout, pk->packet.rest.marker);
//                 fprint_escaped(stdout, pk->packet.rest.crlf);
//                 break;

//             case FTP_RNFR:
//                 fprint_escaped(stdout, pk->packet.rnfr.command);
//                 fprint_escaped(stdout, pk->packet.rnfr.space);
//                 fprint_escaped(stdout, pk->packet.rnfr.pathname);
//                 fprint_escaped(stdout, pk->packet.rnfr.crlf);
//                 break;

//             case FTP_RNTO:
//                 fprint_escaped(stdout, pk->packet.rnto.command);
//                 fprint_escaped(stdout, pk->packet.rnto.space);
//                 fprint_escaped(stdout, pk->packet.rnto.pathname);
//                 fprint_escaped(stdout, pk->packet.rnto.crlf);
//                 break;

//             case FTP_ABOR:
//                 fprint_escaped(stdout, pk->packet.abor.command);
//                 fprint_escaped(stdout, pk->packet.abor.crlf);
//                 break;

//             case FTP_DELE:
//                 fprint_escaped(stdout, pk->packet.dele.command);
//                 fprint_escaped(stdout, pk->packet.dele.space);
//                 fprint_escaped(stdout, pk->packet.dele.pathname);
//                 fprint_escaped(stdout, pk->packet.dele.crlf);
//                 break;

//             case FTP_RMD:
//                 fprint_escaped(stdout, pk->packet.rmd.command);
//                 fprint_escaped(stdout, pk->packet.rmd.space);
//                 fprint_escaped(stdout, pk->packet.rmd.pathname);
//                 fprint_escaped(stdout, pk->packet.rmd.crlf);
//                 break;

//             case FTP_MKD:
//                 fprint_escaped(stdout, pk->packet.mkd.command);
//                 fprint_escaped(stdout, pk->packet.mkd.space);
//                 fprint_escaped(stdout, pk->packet.mkd.pathname);
//                 fprint_escaped(stdout, pk->packet.mkd.crlf);
//                 break;

//             case FTP_PWD:
//                 fprint_escaped(stdout, pk->packet.pwd.command);
//                 fprint_escaped(stdout, pk->packet.pwd.crlf);
//                 break;

//             case FTP_LIST:
//                 fprint_escaped(stdout, pk->packet.list.command);
//                 fprint_escaped(stdout, pk->packet.list.space);
//                 fprint_escaped(stdout, pk->packet.list.pathname);
//                 fprint_escaped(stdout, pk->packet.list.crlf);
//                 break;

//             case FTP_NLST:
//                 fprint_escaped(stdout, pk->packet.nlst.command);
//                 fprint_escaped(stdout, pk->packet.nlst.space);
//                 fprint_escaped(stdout, pk->packet.nlst.pathname);
//                 fprint_escaped(stdout, pk->packet.nlst.crlf);
//                 break;

//             case FTP_SITE:
//                 fprint_escaped(stdout, pk->packet.site.command);
//                 fprint_escaped(stdout, pk->packet.site.space);
//                 fprint_escaped(stdout, pk->packet.site.parameters);
//                 fprint_escaped(stdout, pk->packet.site.crlf);
//                 break;

//             case FTP_SYST:
//                 fprint_escaped(stdout, pk->packet.syst.command);
//                 fprint_escaped(stdout, pk->packet.syst.crlf);
//                 break;

//             case FTP_STAT:
//                 fprint_escaped(stdout, pk->packet.stat.command);
//                 fprint_escaped(stdout, pk->packet.stat.space);
//                 fprint_escaped(stdout, pk->packet.stat.pathname);
//                 fprint_escaped(stdout, pk->packet.stat.crlf);
//                 break;

//             case FTP_HELP:
//                 fprint_escaped(stdout, pk->packet.help.command);
//                 fprint_escaped(stdout, pk->packet.help.space);
//                 fprint_escaped(stdout, pk->packet.help.argument);
//                 fprint_escaped(stdout, pk->packet.help.crlf);
//                 break;

//             case FTP_NOOP:
//                 fprint_escaped(stdout, pk->packet.noop.command);
//                 fprint_escaped(stdout, pk->packet.noop.crlf);
//                 break;

//             default:
//                 /* 尝试保守打印：若有 user 子结构就按 user 打，否则仅打印命令名 */
//                 if (pk->packet.user.command[0]) {
//                     fprint_escaped(stdout, pk->packet.user.command);
//                     fprint_escaped(stdout, pk->packet.user.space);
//                     fprint_escaped(stdout, pk->packet.user.username);
//                     fprint_escaped(stdout, pk->packet.user.crlf);
//                 }
//                 break;
//         }
//         printf("\"\n");
//     }
// }
