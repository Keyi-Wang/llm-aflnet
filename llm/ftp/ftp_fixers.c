/* ftp fixers source file */
#include "ftp.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

/* clamp to [1,255] */
static inline int clamp_1_255(long v){
    if (v < 1)   return 1;
    if (v > 255) return 255;
    return (int)v;
}

/* extract up to max_n decimal integers from s; non-digits are treated as separators */
static size_t extract_dec_ints(const char *s, long *out, size_t max_n){
    size_t k = 0;
    while (s && *s && k < max_n){
        /* skip non-digit */
        while (*s && !isdigit((unsigned char)*s)) ++s;
        if (!*s) break;
        /* parse decimal run */
        long v = 0; int have = 0;
        while (*s && isdigit((unsigned char)*s)){
            have = 1;
            v = v*10 + (*s - '0');
            ++s;
        }
        if (have && k < max_n) out[k++] = v;
    }
    return k;
}

/* format back to "a,b,c,d,e,f" */
static void fmt_six(char *dst, size_t cap, const int v[6]){
    if (!dst || cap == 0) return;
    (void)snprintf(dst, cap, "%d,%d,%d,%d,%d,%d", v[0],v[1],v[2],v[3],v[4],v[5]);
}

/* 从任意“乱分隔”的 host_port 字符串中提取最多 6 个十进制整数（允许前导+/-），
   其它字符都当作分隔符；得到不足 6 个时用 1 填充；得到超过 6 个时仅取前 6 个。 */
static void normalize_hostport_decimal(char *dst, size_t dst_cap, const char *src) {
    unsigned vals[6];
    int n = 0;

    /* 解析阶段：宽松扫描，只要遇到 [+|-]?[0-9]+ 就按十进制读取一个数 */
    const char *p = src ? src : "";
    while (*p && n < 6) {
        /* 跳过非数字起始字符（允许 + / - 作为起始） */
        while (*p && !(isdigit((unsigned char)*p) || *p=='+' || *p=='-')) ++p;
        if (!*p) break;

        char *end = NULL;
        long v = strtol(p, &end, 10);   /* 十进制 */
        if (end == p) { ++p; continue; } /* 未推进，跳过一个字符重试 */

        vals[n++] = clamp_1_255(v);
        p = end;
    }

    /* 不足 6 个 → 用 1 补齐；超出 → 上面已限制为最多 6 个 */
    while (n < 6) vals[n++] = 1u;

    /* 输出为严格规范形式：d,d,d,d,d,d */
    if (dst && dst_cap) {
        (void)snprintf(dst, dst_cap, "%u,%u,%u,%u,%u,%u",
                       vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]);
    }
}
/* 若需要“严格 ASCII”，打开此宏：把所有 >=0x80 的字节替换成 '?' */
// #define FTP_FIXER_STRICT_ASCII 1

/* 就地移除 CR/LF；（可选）把非 ASCII 映射为 '?' */
static inline void sanitize_no_crlf_ascii(char *s) {
    if (!s) return;
    char *d = s;
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '\r' || c == '\n') continue;      /* 删除 CR/LF */
#ifdef FTP_FIXER_STRICT_ASCII
        if (c >= 0x80) c = '?';                    /* 非 ASCII → '?' */
#endif
        *d++ = (char)c;
    }
    *d = '\0';
}

/* 规则 SHOT-4 修复器：清除所有 <string> 参数中的 CR/LF */
void fixer_shot4_no_crlf(ftp_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;

    for (int i = 0; i < num_packets; ++i) {
        ftp_packet_t *p = &pkts[i];

        switch (p->command_type) {

        /* 账号类 */
        case FTP_USER:  sanitize_no_crlf_ascii(p->packet.user.username);   break;
        case FTP_PASS:  sanitize_no_crlf_ascii(p->packet.pass.password);   break;
        case FTP_ACCT:  sanitize_no_crlf_ascii(p->packet.acct.account_info); break;

        /* 路径类（单参数） */
        case FTP_CWD:   sanitize_no_crlf_ascii(p->packet.cwd.pathname);    break;
        case FTP_RETR:  sanitize_no_crlf_ascii(p->packet.retr.pathname);   break;
        case FTP_STOR:  sanitize_no_crlf_ascii(p->packet.stor.pathname);   break;
        case FTP_STOU:  sanitize_no_crlf_ascii(p->packet.stou.pathname);   break;
        case FTP_APPE:  sanitize_no_crlf_ascii(p->packet.appe.pathname);   break;
        case FTP_RNFR:  sanitize_no_crlf_ascii(p->packet.rnfr.pathname);   break;
        case FTP_RNTO:  sanitize_no_crlf_ascii(p->packet.rnto.pathname);   break;
        case FTP_DELE:  sanitize_no_crlf_ascii(p->packet.dele.pathname);   break;
        case FTP_RMD:   sanitize_no_crlf_ascii(p->packet.rmd.pathname);    break;
        case FTP_MKD:   sanitize_no_crlf_ascii(p->packet.mkd.pathname);    break;

        /* 列表类（可选路径/模式） */
        case FTP_LIST:  sanitize_no_crlf_ascii(p->packet.list.pathname);   break;
        case FTP_NLST:  sanitize_no_crlf_ascii(p->packet.nlst.pathname);   break;

        /* 状态/站点扩展 */
        case FTP_STAT:  sanitize_no_crlf_ascii(p->packet.stat.pathname);   break;
        case FTP_SITE:  sanitize_no_crlf_ascii(p->packet.site.parameters); break;

        /* 传输参数类 */
        case FTP_PORT:  sanitize_no_crlf_ascii(p->packet.port.host_port_str); break;
        case FTP_TYPE:
            sanitize_no_crlf_ascii(p->packet.type.type_code);
            sanitize_no_crlf_ascii(p->packet.type.format_control);
            break;
        case FTP_STRU:  sanitize_no_crlf_ascii(p->packet.stru.structure_code); break;
        case FTP_MODE:  sanitize_no_crlf_ascii(p->packet.mode.mode_code);      break;

        /* 存储/断点/帮助等 */
        case FTP_ALLO:
            sanitize_no_crlf_ascii(p->packet.allo.byte_count);
            sanitize_no_crlf_ascii(p->packet.allo.record_format); /* 可选字段存在时也安全处理 */
            break;
        case FTP_REST:  sanitize_no_crlf_ascii(p->packet.rest.marker);     break;
        case FTP_HELP:  sanitize_no_crlf_ascii(p->packet.help.argument);   break;

        /* 如还有其它含 <string> 的命令，在此继续补充 */
        default:
            break; /* 无字符串参数或不需处理 */
        }
    }
}



/* SHOT-5 修复器：遍历数组，规范化所有 PORT 的 host_port_str 为十进制且各段 1..255 */
void fixer_shot5_hostport(ftp_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;

    for (int i = 0; i < num_packets; ++i) {
        ftp_packet_t *p = &pkts[i];
        if (p->command_type != FTP_PORT) continue;

        /* 直接就地改写为规范串；保留/不改动 space 字段（只修 host-port 语义） */
        char src[FTP_SZ_HOSTPORT];
        /* 备份原串，避免 snprintf 覆盖源时的自别名问题 */
        (void)snprintf(src, sizeof(src), "%s", p->packet.port.host_port_str);

        normalize_hostport_decimal(p->packet.port.host_port_str,
                                   sizeof(p->packet.port.host_port_str),
                                   src);
    }
}



/* Public fixer: fix in-place for an array of ftp_packet_t */
void fix_shot6_port_arguments(ftp_packet_t *arr, size_t count){
    static const int DEF[6] = {127,1,1,1,1,1}; /* safe defaults within [1..255] */

    if (!arr) return;

    for (size_t i = 0; i < count; ++i){
        if (arr[i].command_type != FTP_PORT) continue;

        ftp_port_packet_t *pkt = &arr[i].packet.port;

        /* extract up to many tokens then keep first 6 */
        long tmp[16];
        size_t got = extract_dec_ints(pkt->host_port_str, tmp, 16);

        int six[6];
        if (got == 0){
            /* nothing usable -> full defaults */
            memcpy(six, DEF, sizeof(six));
        } else {
            /* take first 6 (or fewer), clamp, then pad with defaults */
            size_t take = (got > 6) ? 6 : got;
            for (size_t j = 0; j < take; ++j)
                six[j] = clamp_1_255(tmp[j]);
            for (size_t j = take; j < 6; ++j)
                six[j] = DEF[j];
        }

        /* enforce leading space when argument present */
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';

        /* write normalized, no spaces */
        fmt_six(pkt->host_port_str, sizeof(pkt->host_port_str), six);

        /* ensure CRLF field is untouched; if you also want to sanitize CR/LF inside
           host_port_str (should not occur after fmt), we already rewrote from clean ints. */
    }
}


/* —— 小工具 —— */
static inline void str_set(char *dst, size_t cap, const char *s){
    if (!dst || cap == 0) return;
    if (!s) s = "";
    (void)snprintf(dst, cap, "%s", s);
}
static void strip_crlf_inplace(char *s){
    if (!s) return;
    size_t w = 0;
    for (size_t r = 0; s[r]; ++r){
        char c = s[r];
        if (c != '\r' && c != '\n') s[w++] = c;
    }
    s[w] = '\0';
}
static void trim_spaces_inplace(char *s){
    if (!s) return;
    size_t len = strlen(s);
    size_t i = 0, j = len ? len - 1 : 0;
    while (i < len && isspace((unsigned char)s[i])) ++i;
    while (j + 1 > i && isspace((unsigned char)s[j])) --j;
    size_t w = 0;
    for (size_t k = i; k <= j && s[k]; ++k) s[w++] = s[k];
    s[w] = '\0';
}
static void upcase_inplace(char *s){
    if (!s) return;
    for (; *s; ++s) *s = (char)toupper((unsigned char)*s);
}
static int is_decimal_positive(const char *s){
    if (!s || !*s) return 0;
    for (const char *p = s; *p; ++p){
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

/* —— SHOT-8 fixer —— */
void fix_shot8_type(ftp_packet_t *arr, int count){
    if (!arr || count <= 0) return;

    for (int i = 0; i < count; ++i){
        if (arr[i].command_type != FTP_TYPE) continue;

        ftp_type_packet_t *tp = &arr[i].packet.type;

        /* 清理输入（移除 CR/LF、裁剪空白、统一大写） */
        strip_crlf_inplace(tp->type_code);
        strip_crlf_inplace(tp->format_control);
        trim_spaces_inplace(tp->type_code);
        trim_spaces_inplace(tp->format_control);
        upcase_inplace(tp->type_code);
        upcase_inplace(tp->format_control);

        /* 规范化主类型码：A/E/I/L；非法则默认 A */
        char tc = (tp->type_code[0] ? (char)toupper((unsigned char)tp->type_code[0]) : '\0');
        if (tc != 'A' && tc != 'E' && tc != 'I' && tc != 'L'){
            tc = 'A'; /* 默认 ASCII */
        }
        char tc_str[2] = { tc, '\0' };
        str_set(tp->type_code, sizeof(tp->type_code), tc_str);

        /* TYPE 后的第一个空格必有 */
        str_set(tp->space1, sizeof(tp->space1), " ");

        switch (tc){
            case 'A':
            case 'E': {
                /* form-code 可选：N/T/C；若缺失或非法，设为 N，并显式带上 */
                const char *fc = tp->format_control;
                int ok = 0;
                if (fc && fc[0]) {
                    if ((fc[0]=='N' || fc[0]=='T' || fc[0]=='C') && fc[1]=='\0') ok = 1;
                }
                if (!ok){
                    str_set(tp->format_control, sizeof(tp->format_control), "N");
                }
                str_set(tp->space2, sizeof(tp->space2), " ");
                break;
            }
            case 'I': {
                /* 不得带 form-code：清空 space2/format_control */
                tp->space2[0] = '\0';
                tp->format_control[0] = '\0';
                break;
            }
            case 'L': {
                /* 必须带十进制 byte-size：非法或缺失 -> 设为 "8" */
                const char *bs = tp->format_control;
                if (!is_decimal_positive(bs)) {
                    str_set(tp->format_control, sizeof(tp->format_control), "8");
                } else {
                    /* 去掉前导零（至少留一个数字），保持十进制形式 */
                    char buf[FTP_SZ_FORMAT];
                    str_set(buf, sizeof(buf), tp->format_control);
                    size_t k = 0; while (buf[k] == '0' && buf[k+1]) ++k;
                    str_set(tp->format_control, sizeof(tp->format_control), buf + k);
                    if (!tp->format_control[0]) str_set(tp->format_control, sizeof(tp->format_control), "8");
                }
                str_set(tp->space2, sizeof(tp->space2), " ");
                break;
            }
            default: /* 不会到达 */ break;
        }

        /* 再次确保字段里没有 CR/LF */
        strip_crlf_inplace(tp->type_code);
        strip_crlf_inplace(tp->format_control);
        strip_crlf_inplace(tp->space1);
        strip_crlf_inplace(tp->space2);
    }
}

static void set_cstr(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
    /* snprintf 总会写入 '\0'（cap>0），并在超长时安全截断 */
    (void)snprintf(dst, cap, "%s", s);
}

static void set_space(char dst[FTP_SZ_SPACE], int present) {
    set_cstr(dst, FTP_SZ_SPACE, present ? " " : "");
}
static void set_space2(char s[2], int present){
    s[0] = present ? ' ' : '\0';
    s[1] = '\0';
}

static char up1(char c){
    return (char)toupper((unsigned char)c);
}

void fix_shot9_type_default(ftp_packet_t *pkts, size_t count){
    if (!pkts || count == 0) return;

    for (size_t i = 0; i < count; ++i){
        if (pkts[i].command_type != FTP_TYPE) continue;

        ftp_type_packet_t *tp = &pkts[i].packet.type;

        // 规范化第一参数大小写（若为空则不动）
        if (tp->type_code[0]) {
            tp->type_code[0] = up1(tp->type_code[0]);
            tp->type_code[1] = '\0';
        }

        char t = tp->type_code[0];

        if (t == 'A' || t == 'E'){
            // 若只有首参（缺少格式）→ 恢复默认 N
            int has_second = (tp->space2[0] != '\0' && tp->format_control[0] != '\0');

            if (!has_second){
                set_space2(tp->space2, 1);
                tp->format_control[0] = 'N';
                tp->format_control[1] = '\0';
            } else {
                // 已给出格式时，限定为 N/T/C；否则恢复 N
                tp->format_control[0] = up1(tp->format_control[0]);
                tp->format_control[1] = '\0';
                char fc = tp->format_control[0];
                if (fc != 'N' && fc != 'T' && fc != 'C'){
                    tp->format_control[0] = 'N';
                    tp->format_control[1] = '\0';
                }
            }
        } else if (t == 'I'){
            // Image 类型没有格式参数：清理可能残留的第二参
            tp->format_control[0] = '\0';
            set_space2(tp->space2, 0);
        } else if (t == 'L'){
            // Local byte size 由 SHOT-8 的修复器负责；这里不做处理
            // （如果你希望此处也兜底，可在缺失时设定一个安全缺省如 "8"）
        } else {
            // 未知/空：不处理
        }
    }
}


/* helpers */
static inline void set_str(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
    (void)snprintf(dst, cap, "%s", s);
}
static inline void set_space_required(char space[FTP_SZ_SPACE]) {
    space[0] = ' '; space[1] = '\0';
}
static inline void set_crlf(char crlf[FTP_SZ_CRLF]) {
    crlf[0] = '\r'; crlf[1] = '\n'; crlf[2] = '\0';
}

/* 从任意字符串中提取第一个落在 {F,R,P} 的 ASCII 字符（大小写不敏感）；失败时返回 'F' 作为回退 */
static char pick_stru_code(const char *s) {
    if (!s) return 'F';
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned char c = *p;
        /* 跳过非 ASCII、空白、引号、控制符 */
        if (c >= 0x80 || c == '"' || c == '\'' || c == '\r' || c == '\n' || c == '\t' || c == ' ')
            continue;
        char u = (char)toupper(c);
        if (u == 'F' || u == 'R' || u == 'P') return u;
        /* 其它可见字符忽略，继续找 */
    }
    return 'F';
}

/* 主修复器：就地修正数组中的 STRU 报文 */
void fix_shot10_stru_single_code(ftp_packet_t *pkts, size_t count) {
    if (!pkts) return;
    for (size_t i = 0; i < count; ++i) {
        if (pkts[i].command_type != FTP_STRU) continue;

        ftp_stru_packet_t *sp = &pkts[i].packet.stru;

        /* 规范化固定字段 */
        set_str(sp->command, sizeof(sp->command), "STRU");
        set_space_required(sp->space);
        set_crlf(sp->crlf);

        /* 选取并压缩为单字符代码 */
        char code = pick_stru_code(sp->structure_code);
        sp->structure_code[0] = code;
        sp->structure_code[1] = '\0';
    }
}


/* 从任意字符串中提取第一个落在 {S,B,C} 的 ASCII 字符（大小写不敏感）；失败回退为 'S' */
static char pick_mode_code(const char *s){
    if (!s) return 'S';
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p){
        unsigned char c = *p;
        /* 跳过非 ASCII、空白、引号、控制符 */
        if (c >= 0x80 || c == '"' || c == '\'' || c == '\r' || c == '\n' || c == '\t' || c == ' ')
            continue;
        char u = (char)toupper(c);
        if (u == 'S' || u == 'B' || u == 'C') return u;
        /* 其他字符忽略继续找（如 'STREAM' 会匹配到 S） */
    }
    return 'S';
}

/* 主修复器：就地修正数组中的 MODE 报文 */
void fix_shot11_mode_single_code(ftp_packet_t *pkts, size_t count){
    if (!pkts) return;

    for (size_t i = 0; i < count; ++i){
        if (pkts[i].command_type != FTP_MODE) continue;

        ftp_mode_packet_t *mp = &pkts[i].packet.mode;

        /* 规范固定字段（命令、空格、CRLF） */
        set_str(mp->command, sizeof(mp->command), "MODE");
        set_space_required(mp->space);
        set_crlf(mp->crlf);

        /* 选取合法代码并压缩为单字符 */
        char code = pick_mode_code(mp->mode_code);
        mp->mode_code[0] = code;
        mp->mode_code[1] = '\0';
    }
}


static void set_token(char *dst, size_t cap, const char *s){
    if (!dst || cap==0){ return; }
    if (!s){ dst[0]='\0'; return; }
    // 使用 snprintf 以确保结尾 0
    snprintf(dst, cap, "%s", s);
}

static void set_space_opt(char *space_field, int present){
    if (!space_field) return;
    if (present){ space_field[0] = ' '; space_field[1] = '\0'; }
    else { space_field[0] = '\0'; }
}


// 规范化十进制整数字符串：提取连续数字，去掉前导 0（至少保留一个 0）
static void normalize_decimal_str(const char *in, char *out, size_t cap){
    if (!out || cap==0){ return; }
    if (!in){ set_token(out, cap, "0"); return; }

    // 跳过前导空白与可选的正负号/前缀
    const char *p = in;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p=='+' || *p=='-'){ p++; }
    if (p[0]=='0' && (p[1]=='x' || p[1]=='X')){ // 诸如 0x...
        p += 2;
        // 对 0x 前缀的输入直接置为 0（因为要求十进制），不尝试按十六进制解析
        set_token(out, cap, "0");
        return;
    }

    // 抽取数字
    char buf[128];
    size_t n = 0;
    for (; *p && n+1 < sizeof(buf); ++p){
        if (isdigit((unsigned char)*p)){
            buf[n++] = *p;
        }else if (isspace((unsigned char)*p)){
            // 读到空白就停止，避免把后续非数字拼进去
            break;
        }else{
            // 非数字（如逗号/点/字母等）直接停止
            break;
        }
    }
    buf[n] = '\0';

    // 若没有任何数字，置为 "0"
    if (n == 0){
        set_token(out, cap, "0");
        return;
    }

    // 去前导 0（至少保留一个 0）
    size_t i = 0;
    while (buf[i]=='0' && buf[i+1] != '\0'){ i++; }
    set_token(out, cap, buf + i);
}

// 将 record_format 统一为 "R <dec>" 形式。返回是否最终存在第二参数
static int normalize_allo_record_format(char *space2, char *record_format, size_t cap_fmt){
    // 提取任意十进制数字
    const char *src = record_format ? record_format : "";
    char dec[64]; dec[0] = '\0';

    // 在原串中找到第一段数字
    const char *p = src;
    while (*p && !isdigit((unsigned char)*p)) p++;
    if (*p){
        // 抽取连续数字
        size_t n = 0;
        while (isdigit((unsigned char)*p) && n+1<sizeof(dec)){ dec[n++]=*p++; }
        dec[n]='\0';
    }

    if (dec[0] == '\0'){
        // 无有效数字 ⇒ 移除第二参数
        if (record_format) record_format[0] = '\0';
        set_space_opt(space2, 0);
        return 0;
    }

    // 规范为 "R <dec>"
    char fmt_buf[128];
    snprintf(fmt_buf, sizeof(fmt_buf), "R %s", dec);
    set_token(record_format, cap_fmt, fmt_buf);
    set_space_opt(space2, 1);
    return 1;
}

static void normalize_allo_packet(ftp_allo_packet_t *ap){
    if (!ap) return;

    // 命令字与第一个空格
    set_token(ap->command, sizeof(ap->command), "ALLO");
    set_space_opt(ap->space1, 1);

    // 规范 byte_count
    char dec[FTP_SZ_BYTECOUNT];
    normalize_decimal_str(ap->byte_count, dec, sizeof(dec));
    set_token(ap->byte_count, sizeof(ap->byte_count), dec);

    // 规范第二参数（若存在）
    (void)normalize_allo_record_format(ap->space2, ap->record_format, sizeof(ap->record_format));

    // 统一 CRLF
    set_crlf(ap->crlf);
}

// 构造一个最小合法 STOR（用于占位修复）
static void make_default_stor(ftp_packet_t *pkt){
    pkt->command_type = FTP_STOR;
    set_token(pkt->packet.stor.command,  sizeof(pkt->packet.stor.command),  "STOR");
    set_space_opt(pkt->packet.stor.space, 1);
    set_token(pkt->packet.stor.pathname, sizeof(pkt->packet.stor.pathname), "upload.bin");
    set_crlf(pkt->packet.stor.crlf);
}

// 构造一个 NOOP（当 ALLO 位于最后且无法跟随 STOR/APPE 时使用）
static void make_noop(ftp_packet_t *pkt){
    pkt->command_type = FTP_NOOP;
    set_token(pkt->packet.noop.command, sizeof(pkt->packet.noop.command), "NOOP");
    set_crlf(pkt->packet.noop.crlf);
}

static int is_stor_or_appe(const ftp_packet_t *pkt){
    return pkt && (pkt->command_type == FTP_STOR || pkt->command_type == FTP_APPE);
}

static void swap_packets(ftp_packet_t *a, ftp_packet_t *b){
    if (!a || !b) return;
    ftp_packet_t tmp = *a;
    *a = *b;
    *b = tmp;
}

// 主修复函数
void fix_shot_12_allo(ftp_packet_t *arr, size_t count){
    if (!arr || count == 0) return;

    for (size_t i = 0; i < count; ++i){
        if (arr[i].command_type != FTP_ALLO) continue;

        // 1) 规范化 ALLO 自身
        normalize_allo_packet(&arr[i].packet.allo);

        // 2) 必须由 STOR 或 APPE 跟随
        if (i + 1 >= count){
            // 无法跟随任何命令 ⇒ 把 ALLO 降级为 NOOP 以满足规范
            make_noop(&arr[i]);
            continue;
        }

        // 如果紧跟的就是 STOR/APPE，则无需动作
        if (is_stor_or_appe(&arr[i+1])) continue;

        // 在后续查找首个 STOR 或 APPE
        size_t j = i + 2;
        while (j < count && !is_stor_or_appe(&arr[j])) ++j;

        if (j < count){
            // 找到了 ⇒ 与 i+1 交换，使其紧随 ALLO
            swap_packets(&arr[i+1], &arr[j]);
        }else{
            // 找不到 ⇒ 直接把紧随的一个包改写为默认 STOR（覆盖原内容）
            make_default_stor(&arr[i+1]);
        }
    }
}


/* —— 内部小工具 —— */
static inline int is_ascii_printable_no_crlf(unsigned char c){
    /* 允许空格(0x20)~波浪线(0x7E)，显式排除 CR/LF 与其它控制字符 */
    if (c == '\r' || c == '\n') return 0;
    return (c >= 0x20 && c <= 0x7E);
}

static void sanitize_marker_ascii(char *s){
    if (!s) return;
    size_t w = 0;
    for (size_t r = 0; s[r]; ++r){
        unsigned char c = (unsigned char)s[r];
        if (is_ascii_printable_no_crlf(c)){
            s[w++] = (char)c;
        }
    }
    s[w] = '\0';
    if (w == 0){
        /* 空则给个安全默认值 */
        s[0] = '0'; s[1] = '\0';
    }
}

/* 传输命令判定：REST 之后必须紧跟其一 */
static inline int is_transfer_cmd(ftp_command_type_t t){
    return (t == FTP_RETR || t == FTP_STOR || t == FTP_APPE);
}

/* 将一个 REST 包就地“降级”为 NOOP（用于无法满足“紧跟传输命令”的末尾或无可交换场景） */
static void rest_to_noop(ftp_packet_t *p){
    if (!p) return;
    p->command_type = FTP_NOOP;
    /* 覆盖为 NOOP 文本帧 */
    memset(&p->packet, 0, sizeof(p->packet));
    snprintf(p->packet.noop.command, sizeof(p->packet.noop.command), "NOOP");
    snprintf(p->packet.noop.crlf,    sizeof(p->packet.noop.crlf),    "\r\n");
}

/* —— 主修复器 —— */
/**
 * 修复 SHOT-13:
 * 1) REST 参数必须由可打印字符组成（ASCII/EBCDIC；此处按 ASCII 过滤控制字符/CRLF）。
 * 2) REST 必须“立即”跟随合适的传输命令（RETR/STOR/APPE）；若不是：
 *    - 向后寻找最近的传输命令并交换到紧邻位置；
 *    - 若找不到，则将该 REST 降级为 NOOP（避免悬空 REST 违规）。
 */
void fix_shot_13_rest_sequence_and_marker(ftp_packet_t *pkts, size_t n){
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; ++i){
        if (pkts[i].command_type != FTP_REST) continue;

        /* 1) 规范化 REST 的参数（marker）与空格 */
        pkts[i].packet.rest.command[0] = 'R';
        pkts[i].packet.rest.command[1] = 'E';
        pkts[i].packet.rest.command[2] = 'S';
        pkts[i].packet.rest.command[3] = 'T';
        /* REST 需要参数 -> 强制 space = " " */
        pkts[i].packet.rest.space[0] = ' ';
        pkts[i].packet.rest.space[1] = '\0';

        sanitize_marker_ascii(pkts[i].packet.rest.marker);

        /* 2) 必须紧跟传输命令 */
        if (i + 1 < n){
            if (!is_transfer_cmd(pkts[i+1].command_type)){
                /* 向后查找最近的传输命令并交换到 i+1 */
                size_t j;
                int found = 0;
                for (j = i + 2; j < n; ++j){
                    if (is_transfer_cmd(pkts[j].command_type)){
                        found = 1;
                        break;
                    }
                }
                if (found){
                    ftp_packet_t tmp = pkts[i+1];
                    pkts[i+1] = pkts[j];
                    pkts[j]   = tmp;
                }else{
                    /* 找不到任何传输命令：将该 REST 降级为 NOOP，避免违规 */
                    rest_to_noop(&pkts[i]);
                }
            }
        }else{
            /* REST 位于队列尾部：无法满足“紧跟”，降级为 NOOP */
            rest_to_noop(&pkts[i]);
        }
    }
}


/* 将一个包就地降级为 NOOP（最小破坏、保持数组尺寸不变） */
static void to_noop(ftp_packet_t *p){
    if (!p) return;
    p->command_type = FTP_NOOP;
    memset(&p->packet, 0, sizeof(p->packet));
    /* 根据常见 NOOP 文本帧填充 */
    snprintf(p->packet.noop.command, sizeof(p->packet.noop.command), "NOOP");
    snprintf(p->packet.noop.crlf,    sizeof(p->packet.noop.crlf),    "\r\n");
}

static inline int is_rnfr(const ftp_packet_t *p){
    return p && p->command_type == FTP_RNFR;
}
static inline int is_rnto(const ftp_packet_t *p){
    return p && p->command_type == FTP_RNTO;
}

/**
 * SHOT-14 修复器：
 * - 确保每个 RNFR 之后“立即”跟随 RNTO（必要时把后面的 RNTO 交换到 i+1）。
 * - 若 RNFR 后根本不存在 RNTO，则把该 RNFR 降级为 NOOP。
 * - 把任何不紧跟在 RNFR 后的孤立 RNTO 降级为 NOOP。
 */
void fix_shot_14_rename_sequence(ftp_packet_t *pkts, size_t n){
    if (!pkts || n == 0) return;

    /* 第一遍：逐个 RNFR 处理，使其后紧跟 RNTO；否则降级 RNFR */
    for (size_t i = 0; i < n; ++i){
        if (!is_rnfr(&pkts[i])) continue;

        if (i + 1 < n){
            if (!is_rnto(&pkts[i + 1])){
                /* 向后寻找最近的 RNTO 并交换到 i+1 */
                size_t j;
                int found = 0;
                for (j = i + 2; j < n; ++j){
                    if (is_rnto(&pkts[j])){
                        found = 1;
                        break;
                    }
                }
                if (found){
                    ftp_packet_t tmp = pkts[i + 1];
                    pkts[i + 1] = pkts[j];
                    pkts[j]     = tmp;
                }else{
                    /* 找不到 RNTO：该 RNFR 无法满足“紧跟” → 降级为 NOOP */
                    to_noop(&pkts[i]);
                }
            }
            /* 若 i+1 已是 RNTO，则天然满足，什么也不做 */
        }else{
            /* RNFR 位于末尾：不可能紧跟 RNTO → 降级为 NOOP */
            to_noop(&pkts[i]);
        }
    }

    /* 第二遍：把任何不以 RNFR 紧邻前导的 RNTO 降级为 NOOP（清理孤立 RNTO） */
    for (size_t k = 0; k < n; ++k){
        if (!is_rnto(&pkts[k])) continue;
        if (k == 0 || !is_rnfr(&pkts[k - 1])){
            to_noop(&pkts[k]);
        }
    }
}

/* 允许：可打印 ASCII（0x20..0x7E）；显式排除 CRLF */
static inline int is_ascii_print_no_crlf(unsigned char c){
    return (c >= 0x20 && c <= 0x7E);
}


/* 压缩同类分隔符：把多个 '/' 变成一个，把多个 '\\' 变成一个 */
static void collapse_same_separators_inplace(char *s){
    if (!s) return;
    char out[FTP_SZ_PATH];
    size_t w = 0;
    int last_is_slash = 0, last_is_backslash = 0;
    for (size_t r = 0; s[r] && w + 1 < sizeof(out); ++r){
        char c = s[r];
        if (c == '/'){
            if (last_is_slash) continue;
            last_is_slash = 1; last_is_backslash = 0;
        }else if (c == '\\'){
            if (last_is_backslash) continue;
            last_is_backslash = 1; last_is_slash = 0;
        }else{
            last_is_slash = last_is_backslash = 0;
        }
        out[w++] = c;
    }
    out[w] = '\0';
    strncpy(s, out, FTP_SZ_PATH);
    s[FTP_SZ_PATH - 1] = '\0';
}

/* 就地清洗 pathname：去 CR/LF 与非打印/非 ASCII，\t->空格，修剪前后空格，压缩重复分隔符 */
static void sanitize_pathname(char *pathname){
    if (!pathname) return;

    char tmp[FTP_SZ_PATH];
    size_t w = 0;
    for (size_t r = 0; pathname[r] && w + 1 < sizeof(tmp); ++r){
        unsigned char c = (unsigned char)pathname[r];

        /* 丢弃 CR/LF 与其它控制字符；\t 变为空格 */
        if (c == '\r' || c == '\n') continue;
        if (c < 0x20 || c == 0x7F){
            if (c == '\t'){
                /* 写入空格，但避免产生多余尾随空格，交给 trim 处理 */
                tmp[w++] = ' ';
            }
            /* 其它控制字符直接跳过 */
            continue;
        }
        if (c >= 0x80) {
            /* 非 ASCII：直接丢弃（保守策略） */
            continue;
        }
        /* 可打印 ASCII */
        tmp[w++] = (char)c;
    }
    tmp[w] = '\0';

    /* 修剪 + 压缩重复分隔符 */
    strncpy(pathname, tmp, FTP_SZ_PATH);
    pathname[FTP_SZ_PATH - 1] = '\0';
    trim_spaces_inplace(pathname);
    collapse_same_separators_inplace(pathname);
}

/* 根据是否有参数，设置可选空格字段 */
static inline void set_space_optional(char space[FTP_SZ_SPACE], const char *arg){
    if (arg && arg[0]) set_space(space, 1);
    else               set_space(space, 0);
}

/* 主修复器：遍历数组，对含 pathname 的服务命令做就地规范化 */
void fixer_shot_15_pathname_arg(ftp_packet_t *arr, size_t n){
    if (!arr) return;

    for (size_t i = 0; i < n; ++i){
        switch (arr[i].command_type){
            /* —— 需要 pathname 的典型服务命令 —— */
            case FTP_CWD:
                sanitize_pathname(arr[i].packet.cwd.pathname);
                /* CWD 参数通常存在，但规范只要求“若存在则合规”，不强行变更 space */
                if (arr[i].packet.cwd.pathname[0]) set_space(arr[i].packet.cwd.space, 1);
                break;

            case FTP_RETR:
                sanitize_pathname(arr[i].packet.retr.pathname);
                if (arr[i].packet.retr.pathname[0]) set_space(arr[i].packet.retr.space, 1);
                break;

            case FTP_STOR:
                sanitize_pathname(arr[i].packet.stor.pathname);
                if (arr[i].packet.stor.pathname[0]) set_space(arr[i].packet.stor.space, 1);
                break;

            case FTP_APPE:
                sanitize_pathname(arr[i].packet.appe.pathname);
                if (arr[i].packet.appe.pathname[0]) set_space(arr[i].packet.appe.space, 1);
                break;

            case FTP_STOU: /* 可选路径名 */
                sanitize_pathname(arr[i].packet.stou.pathname);
                set_space_optional(arr[i].packet.stou.space, arr[i].packet.stou.pathname);
                break;

            case FTP_DELE:
                sanitize_pathname(arr[i].packet.dele.pathname);
                if (arr[i].packet.dele.pathname[0]) set_space(arr[i].packet.dele.space, 1);
                break;

            case FTP_RMD:
                sanitize_pathname(arr[i].packet.rmd.pathname);
                if (arr[i].packet.rmd.pathname[0]) set_space(arr[i].packet.rmd.space, 1);
                break;

            case FTP_MKD:
                sanitize_pathname(arr[i].packet.mkd.pathname);
                if (arr[i].packet.mkd.pathname[0]) set_space(arr[i].packet.mkd.space, 1);
                break;

            case FTP_RNFR:
                sanitize_pathname(arr[i].packet.rnfr.pathname);
                if (arr[i].packet.rnfr.pathname[0]) set_space(arr[i].packet.rnfr.space, 1);
                break;

            case FTP_RNTO:
                sanitize_pathname(arr[i].packet.rnto.pathname);
                if (arr[i].packet.rnto.pathname[0]) set_space(arr[i].packet.rnto.space, 1);
                break;

            /* —— 可选 pathname 的服务命令 —— */
            case FTP_LIST:
                sanitize_pathname(arr[i].packet.list.pathname);
                set_space_optional(arr[i].packet.list.space, arr[i].packet.list.pathname);
                break;

            case FTP_NLST:
                sanitize_pathname(arr[i].packet.nlst.pathname);
                set_space_optional(arr[i].packet.nlst.space, arr[i].packet.nlst.pathname);
                break;

            case FTP_STAT:
                sanitize_pathname(arr[i].packet.stat.pathname);
                set_space_optional(arr[i].packet.stat.space, arr[i].packet.stat.pathname);
                break;

            /* 某些实现的 SMNT 也接受 pathname（若你在头文件中定义了该字段） */
            case FTP_SMNT:
                sanitize_pathname(arr[i].packet.smnt.pathname);
                if (arr[i].packet.smnt.pathname[0]) set_space(arr[i].packet.smnt.space, 1);
                break;

            /* 其余命令无 pathname 或不在本规则范围 */
            default:
                break;
        }
    }
}


void fix_ftp(ftp_packet_t *pkts, size_t count){
    if (!pkts || count == 0) return;

    fixer_shot_15_pathname_arg(pkts, count);
    fix_shot_14_rename_sequence(pkts, count);
    fix_shot_13_rest_sequence_and_marker(pkts, count);
    fix_shot_12_allo(pkts, count);
    fix_shot11_mode_single_code(pkts, count);
    fix_shot10_stru_single_code(pkts, count);
    fix_shot9_type_default(pkts, count);
    fix_shot8_type(pkts, count);
    fix_shot6_port_arguments(pkts, count);
    fixer_shot5_hostport(pkts, count);
    fixer_shot4_no_crlf(pkts, count);
}