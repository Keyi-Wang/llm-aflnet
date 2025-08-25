/* ftp mutators source file */
#include "ftp.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* 依赖你的固定尺寸宏与结构体定义：FTP_SZ_USERNAME, FTP_SZ_SPACE, ftp_user_packet_t ... */

/*—— 小工具：安全写/附加 ——*/
static inline void buf_set(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
    /* snprintf 会自动 '\0'，超长时安全截断 */
    (void)snprintf(dst, cap, "%s", s);
}
static inline void buf_fill_repeat(char dst[], size_t cap, char ch, size_t n) {
    if (!dst || cap == 0) return;
    if (n >= cap) n = cap - 1;
    if (n > 0) memset(dst, (unsigned char)ch, n);
    dst[n] = '\0';
}
static inline void buf_copy_span(char dst[], size_t cap, const char *b, const char *e) {
    if (!dst || cap == 0) return;
    if (!b || !e || e < b) { dst[0] = '\0'; return; }
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, b, n);
    dst[n] = '\0';
}
static inline void buf_append_char(char dst[], size_t cap, char c) {
    size_t n = strnlen(dst, cap);
    if (n + 1 < cap) { dst[n] = c; dst[n+1] = '\0'; }
}
static inline void buf_append_str(char dst[], size_t cap, const char *s) {
    if (!s) return;
    size_t n = strnlen(dst, cap);
    size_t rem = (n < cap) ? cap - n : 0;
    if (rem == 0) return;
    (void)snprintf(dst + n, rem, "%s", s);
}

/* 简单 PRNG：xorshift32（用于位翻转/随机选择） */
static uint32_t xorshift32(uint32_t *st) {
    uint32_t x = (*st ? *st : 0x9e3779b9u);
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *st = x; return x;
}

/* 变异算子实现（全部在固定缓冲内进行，自动截断） */
static void op_empty(char dst[], size_t cap) { buf_set(dst, cap, ""); }                           /* 0: 空用户名（非法） */
static void op_spaces(char dst[], size_t cap) { buf_set(dst, cap, "     "); }                     /* 1: 全空白（非法/边界） */
static void op_overlongA(char dst[], size_t cap) { buf_fill_repeat(dst, cap, 'A', cap ? cap-1 : 0); } /* 2: 超长填充 */
static void op_anonymous(char dst[], size_t cap) { buf_set(dst, cap, "anonymous"); }              /* 3: 常见合法名 */
static void op_anon_email(char dst[], size_t cap) { buf_set(dst, cap, "anonymous@example.com"); } /* 4: 合法匿名格式 */
static void op_pathy(char dst[], size_t cap) { buf_set(dst, cap, "../../etc/passwd"); }           /* 5: 路径样式 */
static void op_trailing_ws(char dst[], size_t cap) { buf_set(dst, cap, "admin   "); }             /* 6: 尾随空白 */
static void op_quoted(char dst[], size_t cap) { buf_set(dst, cap, "\"John Doe\""); }              /* 7: 引号+空格 */
static void op_shellmeta(char dst[], size_t cap) { buf_set(dst, cap, "*?$()<>|"); }               /* 8: 外壳/通配符 */
static void op_pct(char dst[], size_t cap) { buf_set(dst, cap, "%00%0D%0A%25%20%7F"); }           /* 9: 百分号编码 */
static void op_utf8(char dst[], size_t cap) { buf_set(dst, cap, "用户😀"); }                        /* 10: 多字节 UTF-8 */
static void op_digits(char dst[], size_t cap) { buf_fill_repeat(dst, cap, '7', 256); }            /* 11: 纯数字长串 */
static void op_crlf_inject(char dst[], size_t cap) {                                              /* 12: CRLF 注入 */
    buf_set(dst, cap, "name"); buf_append_str(dst, cap, "\r\nPASS hacked\r\n");
}
static void op_repeat_orig(char dst[], size_t cap, const char *orig) {                             /* 13: 重复膨胀 */
    if (!orig) orig = "";
    dst[0] = '\0';
    for (int i = 0; i < 8; ++i) buf_append_str(dst, cap, orig);
}
static void op_altcase(char dst[], size_t cap, const char *orig) {                                 /* 14: 大小写交替 */
    if (!orig) orig = "";
    size_t n = strnlen(orig, FTP_SZ_USERNAME);
    if (n >= cap) n = cap - 1;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)orig[i];
        if (isalpha(c)) dst[i] = (i & 1) ? (char)tolower(c) : (char)toupper(c);
        else dst[i] = (char)c;
    }
    dst[n] = '\0';
}
static void op_bitflip_once(char dst[], size_t cap, const char *orig, uint32_t *rng) {             /* 15: 位翻转 */
    if (!orig || !*orig) orig = "user";
    buf_set(dst, cap, orig);
    size_t n = strnlen(dst, cap);
    if (n == 0) return;
    size_t idx = xorshift32(rng) % n;
    unsigned flips = (xorshift32(rng) % 7) + 1; /* 1..7 位 */
    for (unsigned k = 0; k < flips; ++k) {
        unsigned bit = (xorshift32(rng) % 8);
        dst[idx] ^= (char)(1u << bit);
    }
}

/**
 * 对 USER 消息中的 username 字段做充分变异（≥16 种算子）
 * @param pkt  目标 USER 包（就地修改 pkt->username）
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 表示随机选择；>=0 表示使用指定算子编号（0..15）
 * @return 1 成功，0 失败/参数不合法
 */
int mutate_user_username(ftp_user_packet_t *pkt, uint32_t seed, int op) {
    if (!pkt) return 0;

    /* USER 的 space 应为必有空格，若为空则补上（与协议/解析器一致） */
    if (pkt->space[0] == '\0') { pkt->space[0] = ' '; pkt->space[1] = '\0'; }

    /* 基于当前用户名作为“原始输入” */
    char orig[FTP_SZ_USERNAME];
    buf_set(orig, sizeof(orig), pkt->username);

    uint32_t rng = (seed ? seed : 0xC0FFEEu);
    const int OPS = 16;
    if (op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch (op) {
        case 0:  op_empty(pkt->username, FTP_SZ_USERNAME); break;
        case 1:  op_spaces(pkt->username, FTP_SZ_USERNAME); break;
        case 2:  op_overlongA(pkt->username, FTP_SZ_USERNAME); break;
        case 3:  op_anonymous(pkt->username, FTP_SZ_USERNAME); break;
        case 4:  op_anon_email(pkt->username, FTP_SZ_USERNAME); break;
        case 5:  op_pathy(pkt->username, FTP_SZ_USERNAME); break;
        case 6:  op_trailing_ws(pkt->username, FTP_SZ_USERNAME); break;
        case 7:  op_quoted(pkt->username, FTP_SZ_USERNAME); break;
        case 8:  op_shellmeta(pkt->username, FTP_SZ_USERNAME); break;
        case 9:  op_pct(pkt->username, FTP_SZ_USERNAME); break;
        case 10: op_utf8(pkt->username, FTP_SZ_USERNAME); break;
        case 11: op_digits(pkt->username, FTP_SZ_USERNAME); break;
        case 12: op_crlf_inject(pkt->username, FTP_SZ_USERNAME); break;
        case 13: op_repeat_orig(pkt->username, FTP_SZ_USERNAME, orig); break;
        case 14: op_altcase(pkt->username, FTP_SZ_USERNAME, orig); break;
        case 15: op_bitflip_once(pkt->username, FTP_SZ_USERNAME, orig, &rng); break;
        default: return 0;
    }
    return 1;
}


/* --------- 各类变异算子（覆盖合法与非法场景） --------- */
static void op_common_pwd(char dst[], size_t cap){ buf_set(dst, cap, "password"); }         /* 3: 弱口令 */
static void op_leet(char dst[], size_t cap){ buf_set(dst, cap, "P@ssw0rd!"); }              /* 5: 常见形变 */
static void op_pair(char dst[], size_t cap){ buf_set(dst, cap, "admin:admin"); }            /* 6: 账号:密码样式 */
static void op_quotes(char dst[], size_t cap){ buf_set(dst, cap, "\"ab c\\\"d\""); }        /* 7: 引号/空格/转义 */
static void op_escapes(char dst[], size_t cap){ buf_set(dst, cap, "pa\\ss\\n\\tword"); }    /* 8: 反斜杠转义 */
static void op_fmt(char dst[], size_t cap){ buf_set(dst, cap, "%x%x%x%s"); }                /* 11: 格式串 */
static void op_sql(char dst[], size_t cap){ buf_set(dst, cap, "' OR '1'='1"); }             /* 12: SQL 注入样式 */
static void op_crlf(char dst[], size_t cap){ buf_set(dst, cap, "pwd\r\nQUIT\r\n"); }        /* 14: CRLF 注入 */
static void op_hexrep(char dst[], size_t cap){                                             /* 15: 十六进制串 */
    dst[0] = '\0'; for (int i = 0; i < 128; ++i) buf_append_str(dst, cap, "AA");
}
static void op_path(char d[], size_t c) { buf_set(d, c, "../../etc/passwd"); } /* 13: 路径穿越风格 */

/**
 * 对 PASS 消息的 password 字段进行“充分变异”（≥19 种算子）
 * - 就地修改 pkt->password；不分配堆内存；自动截断并 '\0' 终止
 * - 若 pkt->space 为空，则补成 " "（与语法一致）
 *
 * @param pkt  PASS 包指针
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机选择；>=0 指定算子编号（0..18）
 * @return 1 成功，0 失败/参数无效
 */
int mutate_pass_password(ftp_pass_packet_t *pkt, uint32_t seed, int op) {
    if (!pkt) return 0;

    /* PASS 命令语法需要一个空格（即使 password 为空也应有 " "） */
    if (pkt->space[0] == '\0') { pkt->space[0] = ' '; pkt->space[1] = '\0'; }

    /* 备份原始输入，供基于原文的算子使用 */
    char orig[FTP_SZ_PASSWORD];
    buf_set(orig, sizeof(orig), pkt->password);

    uint32_t rng = (seed ? seed : 0xBADC0DEu);
    const int OPS = 19;
    if (op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch (op) {
        case 0:  op_empty(pkt->password, FTP_SZ_PASSWORD); break;
        case 1:  op_spaces(pkt->password, FTP_SZ_PASSWORD); break;
        case 2:  op_overlongA(pkt->password, FTP_SZ_PASSWORD); break;
        case 3:  op_common_pwd(pkt->password, FTP_SZ_PASSWORD); break;
        case 4:  op_digits(pkt->password, FTP_SZ_PASSWORD); break;
        case 5:  op_leet(pkt->password, FTP_SZ_PASSWORD); break;
        case 6:  op_pair(pkt->password, FTP_SZ_PASSWORD); break;
        case 7:  op_quotes(pkt->password, FTP_SZ_PASSWORD); break;
        case 8:  op_escapes(pkt->password, FTP_SZ_PASSWORD); break;
        case 9:  op_pct(pkt->password, FTP_SZ_PASSWORD); break;
        case 10: op_utf8(pkt->password, FTP_SZ_PASSWORD); break;
        case 11: op_fmt(pkt->password, FTP_SZ_PASSWORD); break;
        case 12: op_sql(pkt->password, FTP_SZ_PASSWORD); break;
        case 13: op_path(pkt->password, FTP_SZ_PASSWORD); break;
        case 14: op_crlf(pkt->password, FTP_SZ_PASSWORD); break;
        case 15: op_hexrep(pkt->password, FTP_SZ_PASSWORD); break;
        case 16: op_repeat_orig(pkt->password, FTP_SZ_PASSWORD, orig); break;
        case 17: op_altcase(pkt->password, FTP_SZ_PASSWORD, orig); break;
        case 18: op_bitflip_once(pkt->password, FTP_SZ_PASSWORD, orig, &rng); break;
        default: return 0;
    }
    return 1;
}


/* ---- 变异算子（覆盖合法与非法场景） ---- */
static void op_common(char d[], size_t c)       { buf_set(d, c, "acct123"); }                      /* 3: 常见账户样式 */
static void op_kv(char d[], size_t c)           { buf_set(d, c, "dept=R&D;quota=unlimited"); }     /* 5: key=value 列表 */
static void op_csv(char d[], size_t c)          { buf_set(d, c, "team,role,region"); }             /* 6: CSV */
static void op_json(char d[], size_t c)         { buf_set(d, c, "{\"acct\":\"alice\",\"tier\":3}"); } /* 7: JSON */
static void op_xml(char d[], size_t c)          { buf_set(d, c, "<acct id='42' tier='gold'/>"); }  /* 8: XML-like */
static void op_b64(char d[], size_t c)          { buf_set(d, c, "YWNjdF9rZXk6c2VjcmV0"); }         /* 9: Base64-like */
static void op_hex(char d[], size_t c)          { d[0]='\0'; for(int i=0;i<128;++i) buf_append_str(d,c,"DE"); } /* 15: HEX 串 */
static void op_repeat(char d[], size_t c, const char *orig){ d[0]='\0'; if(!orig) orig=""; for(int i=0;i<8;++i) buf_append_str(d,c,orig);} /* 16 */

/**
 * 对 ACCT 的 account_info 字段做充分变异（≥19 种算子）
 * - 仅修改 pkt->account_info；不改 command/space/crlf
 * - 必要时把 pkt->space 补为 " "
 *
 * @param pkt  ftp_acct_packet_t 指针
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机选择；>=0 指定算子编号（0..18）
 * @return 1 成功，0 失败/参数错误
 */
int mutate_acct_account_info(ftp_acct_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;

    /* ACCT 语法需要空格：ACCT <SP> <account-info> */
    if (pkt->space[0] == '\0') { pkt->space[0]=' '; pkt->space[1]='\0'; }

    /* 基于原始输入的算子需要用到它 */
    char orig[FTP_SZ_ACCOUNT];
    buf_set(orig, sizeof(orig), pkt->account_info);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);
    const int OPS = 19;
    if (op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        case 0:  op_empty(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 1:  op_spaces(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 2:  op_overlongA(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 3:  op_common(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 4:  op_digits(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 5:  op_kv(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 6:  op_csv(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 7:  op_json(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 8:  op_xml(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 9:  op_b64(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 10: op_utf8(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 11: op_pct(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 12: op_sql(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 13: op_path(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 14: op_crlf(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 15: op_hex(pkt->account_info, FTP_SZ_ACCOUNT); break;
        case 16: op_repeat(pkt->account_info, FTP_SZ_ACCOUNT, orig); break;
        case 17: op_altcase(pkt->account_info, FTP_SZ_ACCOUNT, orig); break;
        case 18: op_bitflip_once(pkt->account_info, FTP_SZ_ACCOUNT, orig, &rng); break;
        default: return 0;
    }
    return 1;
}


/* ====== 变异算子（覆盖丰富语义与畸形情况） ====== */

static void op_root(char d[], size_t c){ buf_set(d,c,"/"); }                                     /* 1: 根目录 */
static void op_many_slash(char d[], size_t c){ buf_set(d,c,"///////"); }                         /* 2: 多斜杠 */
static void op_dot(char d[], size_t c){ buf_set(d,c,"."); }                                      /* 3: 当前目录 */
static void op_dotdot(char d[], size_t c){ buf_set(d,c,".."); }                                  /* 4: 父目录 */
static void op_traversal(char d[], size_t c){ d[0]='\0'; for(int i=0;i<16;++i) buf_append_str(d,c,"../"); } /* 5 */
static void op_dot_segments(char d[], size_t c){ buf_set(d,c,"/a/./b/./c"); }                    /* 6: /./ 段 */
static void op_windows_sep(char d[], size_t c){ buf_set(d,c,"dir\\sub\\file"); }                 /* 7: 反斜杠 */
static void op_spacey(char d[], size_t c){ buf_set(d,c,"\" spaced name \"/with space"); }        /* 8: 含空格/引号 */
static void op_glob(char d[], size_t c){ buf_set(d,c,"/tmp/*?.[[]"); }                           /* 9: 通配符 */
static void op_urlish(char d[], size_t c){ buf_set(d,c,"ftp://host/path/to/dir"); }              /* 11: URL 风格 */
static void op_trailing_dots(char d[], size_t c){ buf_set(d,c,"dir.../sub..."); }                /* 12: 结尾点 */
static void op_device_name(char d[], size_t c){ buf_set(d,c,"CON/NUL/AUX"); }                    /* 13: 设备名 */
static void op_longA(char d[], size_t c){ buf_fill_repeat(d,c,'A', c?c-1:0); }                   /* 15: 超长填满 */
static void op_hex_dirs(char d[], size_t c){ buf_set(d,c,"/DEAD/BEEF/C0DE"); }                   /* 16: 十六进制段 */
static void op_mixed_slashes(char d[], size_t c){ buf_set(d,c,"/a\\b/c\\d"); }                   /* 17: 混合分隔符 */
static void op_dup_slashes(char d[], size_t c){ buf_set(d,c,"/a////b///c"); }                    /* 19: 重复斜杠 */

/**
 * 对 CWD 的 pathname 字段做“充分变异”（≥23 种算子）
 * - 就地修改 pkt->pathname；若 pkt->space 为空则补成 " "
 * - 无堆分配，写入自动截断并 '\0' 终止
 *
 * @param pkt  ftp_cwd_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1=随机选择；>=0 指定算子编号（0..22）
 * @return 1 成功；0 失败/参数非法
 */
int mutate_cwd_pathname(ftp_cwd_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 23;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        case 0:  op_empty(pkt->pathname, FTP_SZ_PATH); break;
        case 1:  op_root(pkt->pathname, FTP_SZ_PATH); break;
        case 2:  op_many_slash(pkt->pathname, FTP_SZ_PATH); break;
        case 3:  op_dot(pkt->pathname, FTP_SZ_PATH); break;
        case 4:  op_dotdot(pkt->pathname, FTP_SZ_PATH); break;
        case 5:  op_traversal(pkt->pathname, FTP_SZ_PATH); break;
        case 6:  op_dot_segments(pkt->pathname, FTP_SZ_PATH); break;
        case 7:  op_windows_sep(pkt->pathname, FTP_SZ_PATH); break;
        case 8:  op_spacey(pkt->pathname, FTP_SZ_PATH); break;
        case 9:  op_glob(pkt->pathname, FTP_SZ_PATH); break;
        case 10: op_pct(pkt->pathname, FTP_SZ_PATH); break;
        case 11: op_urlish(pkt->pathname, FTP_SZ_PATH); break;
        case 12: op_trailing_dots(pkt->pathname, FTP_SZ_PATH); break;
        case 13: op_device_name(pkt->pathname, FTP_SZ_PATH); break;
        case 14: op_utf8(pkt->pathname, FTP_SZ_PATH); break;
        case 15: op_longA(pkt->pathname, FTP_SZ_PATH); break;
        case 16: op_hex_dirs(pkt->pathname, FTP_SZ_PATH); break;
        case 17: op_mixed_slashes(pkt->pathname, FTP_SZ_PATH); break;
        case 18: op_crlf_inject(pkt->pathname, FTP_SZ_PATH); break;
        case 19: op_dup_slashes(pkt->pathname, FTP_SZ_PATH); break;
        case 20: op_repeat_orig(pkt->pathname, FTP_SZ_PATH, orig); break;
        case 21: op_altcase(pkt->pathname, FTP_SZ_PATH, orig); break;
        case 22: op_bitflip_once(pkt->pathname, FTP_SZ_PATH, orig, &rng); break;
        default: return 0;
    }
    return 1;
}


/* ====== 变异算子（涵盖合法/非法/边界） ====== */
static void op_dev(char d[], size_t c){ buf_set(d,c,"/dev/sda1"); }                            /* 2: 类设备路径 */
static void op_win_drive(char d[], size_t c){ buf_set(d,c,"C:\\\\mount\\\\point"); }           /* 8: Windows 盘符 */
static void op_unc(char d[], size_t c){ buf_set(d,c,"\\\\server\\share\\dir"); }               /* 9: UNC 路径 */
static void op_nfs(char d[], size_t c){ buf_set(d,c,"host:/export/path"); }                    /* 10: NFS 风格 */
static void op_smb_url(char d[], size_t c){ buf_set(d,c,"smb://server/share/dir"); }           /* 11: SMB URL */
static void op_file_url(char d[], size_t c){ buf_set(d,c,"file:///mnt/data"); }                /* 12: file:// URL */
static void op_opts(char d[], size_t c){ buf_set(d,c,"/mnt/point;opts=rw,noatime,nosuid"); }   /* 15: 挂载选项 */
static void op_mixed(char d[], size_t c){ buf_set(d,c,"/a\\b/c\\d"); }                         /* 18: 混合分隔符 */
static void op_device_names(char d[], size_t c){ buf_set(d,c,"CON/NUL/AUX"); }                 /* 19: 设备名片段 */ 

/**
 * 对 SMNT 的 pathname 字段进行充分变异（≥26 种算子）
 * - 就地修改 pkt->pathname；若 pkt->space 为空则补成 " "
 * - 无堆分配；自动截断并 '\0' 终止
 *
 * @param pkt  ftp_smnt_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1=随机选择；>=0 指定算子编号（0..25）
 * @return 1 成功；0 失败/参数非法
 */
int mutate_smnt_pathname(ftp_smnt_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 26;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        case 0:  op_empty(pkt->pathname, FTP_SZ_PATH); break;
        case 1:  op_root(pkt->pathname, FTP_SZ_PATH); break;
        case 2:  op_dev(pkt->pathname, FTP_SZ_PATH); break;
        case 3:  op_many_slash(pkt->pathname, FTP_SZ_PATH); break;
        case 4:  op_dot(pkt->pathname, FTP_SZ_PATH); break;
        case 5:  op_dotdot(pkt->pathname, FTP_SZ_PATH); break;
        case 6:  op_traversal(pkt->pathname, FTP_SZ_PATH); break;
        case 7:  op_dot_segments(pkt->pathname, FTP_SZ_PATH); break;
        case 8:  op_win_drive(pkt->pathname, FTP_SZ_PATH); break;
        case 9:  op_unc(pkt->pathname, FTP_SZ_PATH); break;
        case 10: op_nfs(pkt->pathname, FTP_SZ_PATH); break;
        case 11: op_smb_url(pkt->pathname, FTP_SZ_PATH); break;
        case 12: op_file_url(pkt->pathname, FTP_SZ_PATH); break;
        case 13: op_spacey(pkt->pathname, FTP_SZ_PATH); break;
        case 14: op_pct(pkt->pathname, FTP_SZ_PATH); break;
        case 15: op_opts(pkt->pathname, FTP_SZ_PATH); break;
        case 16: op_utf8(pkt->pathname, FTP_SZ_PATH); break;
        case 17: op_longA(pkt->pathname, FTP_SZ_PATH); break;
        case 18: op_mixed(pkt->pathname, FTP_SZ_PATH); break;
        case 19: op_device_names(pkt->pathname, FTP_SZ_PATH); break;
        case 20: op_crlf_inject(pkt->pathname, FTP_SZ_PATH); break;
        case 21: op_hex_dirs(pkt->pathname, FTP_SZ_PATH); break;
        case 22: op_dup_slashes(pkt->pathname, FTP_SZ_PATH); break;
        case 23: op_repeat_orig(pkt->pathname, FTP_SZ_PATH, orig); break;
        case 24: op_altcase(pkt->pathname, FTP_SZ_PATH, orig); break;
        case 25: op_bitflip_once(pkt->pathname, FTP_SZ_PATH, orig, &rng); break;
        default: return 0;
    }
    return 1;
}



/* 格式化合法 host,port -> "h1,h2,h3,h4,p1,p2" */
static void fmt_hostport(char d[], size_t c, int h1,int h2,int h3,int h4,int p1,int p2){
    if(!d || c==0) return;
    (void)snprintf(d, c, "%d,%d,%d,%d,%d,%d", h1,h2,h3,h4,p1,p2);
}

/* ====== 变异算子（涵盖合法/非法/边界） ====== */

static void op_spaces_commas(char d[], size_t c){ buf_set(d,c," , , , , , "); }                        /* 1  全空白+逗号 */
static void op_valid_localhost_21(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,0,21); }             /* 2  合法：127.0.0.1:21 */
static void op_valid_private_50000(char d[], size_t c){ fmt_hostport(d,c,192,168,1,10,195,80); }       /* 3  合法：:50000 */
static void op_all_zero(char d[], size_t c){ fmt_hostport(d,c,0,0,0,0,0,0); }                          /* 4  0.0.0.0:0 */
static void op_broadcast(char d[], size_t c){ fmt_hostport(d,c,255,255,255,255,255,255); }             /* 5  255.*:65535(非法端口编码但常见边界) */
static void op_over255(char d[], size_t c){ buf_set(d,c,"300,1,1,1,1,1"); }                            /* 6  >255 */
static void op_negative(char d[], size_t c){ buf_set(d,c,"-1,2,3,4,5,6"); }                            /* 7  负数 */
static void op_short_fields(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5"); }                           /* 8  字段数<6 */
static void op_many_fields(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5,6,7"); }                        /* 9  字段数>6 */
static void op_non_numeric(char d[], size_t c){ buf_set(d,c,"a,b,c,d,e,f"); }                          /* 10 非数字 */
static void op_spaces_around(char d[], size_t c){ buf_set(d,c," 127 , 0 , 0 , 1 , 0 , 21 "); }         /* 11 空格包围 */
static void op_tabs_around(char d[], size_t c){ buf_set(d,c,"\t1,\t2,\t3,\t4,\t5,\t6"); }              /* 12 制表符 */
static void op_hex_numbers(char d[], size_t c){ buf_set(d,c,"0x7F,0x0,0x0,0x1,0x0,0x15"); }            /* 13 十六进制 */
static void op_octal_numbers(char d[], size_t c){ buf_set(d,c,"010,000,000,001,000,025"); }            /* 14 八进制 */
static void op_floats(char d[], size_t c){ buf_set(d,c,"127.0,0,0,1,0,21"); }                          /* 15 浮点 */
static void op_dot_ip_mix(char d[], size_t c){ buf_set(d,c,"127.0.0.1,0,21"); }                        /* 16 点分IP混用 */
static void op_percent_encoded(char d[], size_t c){ buf_set(d,c,"%31%32%37,0,0,1,0,21"); }             /* 17 百分号编码 */
static void op_trailing_comma(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5,6,"); }                      /* 19 末尾逗号 */
static void op_empty_components(char d[], size_t c){ buf_set(d,c,"1,,3,4,,6"); }                       /* 20 空组件 */
static void op_semicolons(char d[], size_t c){ buf_set(d,c,"1;2;3;4;5;6"); }                           /* 21 分号分隔 */
static void op_slashes(char d[], size_t c){ buf_set(d,c,"1/2/3/4/5/6"); }                               /* 22 斜杠分隔 */
static void op_random_valid(char d[], size_t c, uint32_t *rng){                                        /* 23 合法随机 */
    int h1=(int)(xorshift32(rng)%256), h2=(int)(xorshift32(rng)%256);
    int h3=(int)(xorshift32(rng)%256), h4=(int)(xorshift32(rng)%256);
    int port=(int)(xorshift32(rng)%65536);
    int p1=(port>>8)&0xFF, p2=port&0xFF;
    fmt_hostport(d,c,h1,h2,h3,h4,p1,p2);
}
static void op_port_zero(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,0,0); }                       /* 24 端口=0 */
static void op_port_65535(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,255,255); }                  /* 25 端口=65535 */
static void op_leading_plus(char d[], size_t c){ buf_set(d,c,"+127,+0,+0,+1,+0,+21"); }                /* 26 前导+号 */
static void op_huge_numbers(char d[], size_t c){ buf_set(d,c,"9999,9999,9999,9999,9999,9999"); }       /* 27 超大数字串 */

/**
 * 对 PORT 的 host_port_str 字段进行充分变异（≥28 种算子）
 * - 就地修改 pkt->host_port_str；若 pkt->space 为空则补成 " "
 * - 无堆分配；写入自动截断并 '\0' 终止
 *
 * @param pkt  ftp_port_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1=随机选择；>=0 指定算子编号（0..27）
 * @return 1 成功；0 失败/参数非法
 */
int mutate_port_host_port_str(ftp_port_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;

    /* PORT 语法需要空格：PORT <SP> h1,h2,h3,h4,p1,p2 */
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }

    uint32_t rng = (seed?seed:0xACCEBEEFu); /* 任意非零默认种子（编译器会解析为十六进制常量的前缀 0xP? 非法，这里换成 0xA1B2C3D4）*/
    rng = (seed?seed:0xA1B2C3D4u);

    const int OPS = 28;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        case 0:  op_empty(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 1:  op_spaces_commas(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 2:  op_valid_localhost_21(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 3:  op_valid_private_50000(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 4:  op_all_zero(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 5:  op_broadcast(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 6:  op_over255(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 7:  op_negative(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 8:  op_short_fields(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 9:  op_many_fields(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 10: op_non_numeric(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 11: op_spaces_around(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 12: op_tabs_around(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 13: op_hex_numbers(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 14: op_octal_numbers(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 15: op_floats(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 16: op_dot_ip_mix(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 17: op_percent_encoded(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 18: op_crlf_inject(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 19: op_trailing_comma(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 20: op_empty_components(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 21: op_semicolons(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 22: op_slashes(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 23: op_random_valid(pkt->host_port_str, FTP_SZ_HOSTPORT, &rng); break;
        case 24: op_port_zero(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 25: op_port_65535(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 26: op_leading_plus(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        case 27: op_huge_numbers(pkt->host_port_str, FTP_SZ_HOSTPORT); break;
        default: return 0;
    }
    return 1;
}



/* 辅助：设置必需/可选部分 */
static inline void set_space1(ftp_type_packet_t *pkt){
    if(pkt->space1[0]=='\0'){ pkt->space1[0]=' '; pkt->space1[1]='\0'; }
}
static inline void set_opt(ftp_type_packet_t *pkt, const char *code, const char *opt){
    buf_set(pkt->type_code, sizeof(pkt->type_code), code);
    if(opt && opt[0]){
        buf_set(pkt->space2, sizeof(pkt->space2), " ");
        buf_set(pkt->format_control, sizeof(pkt->format_control), opt);
    }else{
        pkt->space2[0]='\0';
        pkt->format_control[0]='\0';
    }
}
static size_t cstrnlen_(const char *s, size_t maxn){
    size_t i=0; if(!s) return 0; while(i<maxn && s[i]) ++i; return i;
}

/**
 * 对 TYPE 的 type_code 字段做充分变异（≥20 种）
 * - 就地修改 pkt->type_code；必要时同步 space2/format_control；
 * - 始终确保 space1 = " "（满足语法 "TYPE <SP> ..."）
 *
 * @param pkt  ftp_type_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子编号（0..21）
 * @return 1 成功；0 失败
 */
int mutate_type_type_code(ftp_type_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    set_space1(pkt);

    /* 备份原值（供部分算子参考） */
    char orig_type[FTP_SZ_TYPE];      buf_set(orig_type, sizeof(orig_type), pkt->type_code);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 22;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法取值 —— */
        case 0:  set_opt(pkt, "A", NULL);                 break;           /* TYPE A */
        case 1:  set_opt(pkt, "I", NULL);                 break;           /* TYPE I */
        case 2:  set_opt(pkt, "E", "N");                  break;           /* TYPE E N */
        case 3:  set_opt(pkt, "A", "N");                  break;           /* TYPE A N (Non-print) */
        case 4:  set_opt(pkt, "A", "T");                  break;           /* TYPE A T (Telnet) */
        case 5:  set_opt(pkt, "A", "C");                  break;           /* TYPE A C (ASA Control) */
        case 6:  set_opt(pkt, "L", "8");                  break;           /* TYPE L 8 (常见) */
        case 7:  set_opt(pkt, "L", "16");                 break;           /* TYPE L 16 (实现相关) */

        /* —— 边界/非法/鲁棒性 —— */
        case 8:  set_opt(pkt, "", NULL);                  break;           /* 空 type_code（非法） */
        case 9:  set_opt(pkt, "a", NULL);                 break;           /* 小写（大小写容忍性） */
        case 10: set_opt(pkt, "Z", NULL);                 break;           /* 未知字母 */
        case 11: set_opt(pkt, "123", NULL);               break;           /* 数字串 */
        case 12: set_opt(pkt, "L", "0");                  break;           /* L 0（无效大小） */
        case 13: set_opt(pkt, "L", "-1");                 break;           /* L -1（负数） */
        case 14: set_opt(pkt, "L", "65535");              break;           /* L 超大数 */
        case 15: set_opt(pkt, "A N", NULL);               break;           /* 把空格放进 type_code 本身 */
        case 16: set_opt(pkt, "I\r\nNOOP", NULL);         break;           /* CRLF 注入 */
        case 17: set_opt(pkt, "0x49", NULL);              break;           /* 十六进制风格 */
        case 18: set_opt(pkt, "Ａ", NULL);                break;           /* 全角 A（UTF-8 多字节） */
        case 19: {                                                      /* 超长填满 */
            buf_fill_repeat(pkt->type_code, sizeof(pkt->type_code), 'A', sizeof(pkt->type_code)?sizeof(pkt->type_code)-1:0);
            pkt->space2[0]='\0'; pkt->format_control[0]='\0';
            break;
        }
        case 20: {                                                      /* 随机 bitflip 一处 */
            char tmp[FTP_SZ_TYPE]; buf_set(tmp, sizeof(tmp), orig_type[0]?orig_type:"A");
            size_t n = cstrnlen_(tmp, sizeof(tmp)); if(n==0){ set_opt(pkt, "A", NULL); break; }
            size_t idx = xorshift32(&rng) % n; unsigned flips=(xorshift32(&rng)%7)+1;
            for(unsigned k=0;k<flips;++k){ tmp[idx] ^= (char)(1u << (xorshift32(&rng)%8)); }
            set_opt(pkt, tmp, NULL);
            break;
        }
        case 21: set_opt(pkt, "E", "X");                  break;           /* E X（未知 format-control） */
        default: return 0;
    }
    return 1;
}

/* —— 基本操作 —— */
static inline void ensure_space1(ftp_type_packet_t *pkt){
    if(pkt->space1[0]=='\0'){ pkt->space1[0]=' '; pkt->space1[1]='\0'; }
}
static inline void set_fc(ftp_type_packet_t *pkt, const char *fc){
    if(fc && fc[0]){
        buf_set(pkt->space2, sizeof(pkt->space2), " ");
        buf_set(pkt->format_control, sizeof(pkt->format_control), fc);
    }else{
        pkt->space2[0]='\0';
        pkt->format_control[0]='\0';
    }
}
static inline void set_tc(ftp_type_packet_t *pkt, const char *tc){
    if(tc) buf_set(pkt->type_code, sizeof(pkt->type_code), tc);
}

/* ====== 增删接口（题目第2点） ====== */
void add_type_format_control(ftp_type_packet_t *pkt, const char *value){
    if(!pkt) return;
    ensure_space1(pkt);
    set_fc(pkt, value && value[0] ? value : "N");  /* 默认给个常见值 N */
}
void delete_type_format_control(ftp_type_packet_t *pkt){
    if(!pkt) return;
    set_fc(pkt, "");  /* 清空，同时 space2 也清空 */
}

/**
 * 充分变异 format_control（≥21 种算子）
 * - 非空 => 自动保障 space2=" "
 * - 为空 => 同时清空 space2
 * - 部分算子会顺带设置 type_code，以形成合法/非法组合
 *
 * @param pkt  ftp_type_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..21）
 * @return 1 成功；0 失败
 */
int mutate_type_format_control(ftp_type_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    ensure_space1(pkt);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 22;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法组合：A/E + N/T/C —— */
        case 0:  set_tc(pkt, "A"); set_fc(pkt, "N"); break;   /* TYPE A N */
        case 1:  set_tc(pkt, "A"); set_fc(pkt, "T"); break;   /* TYPE A T */
        case 2:  set_tc(pkt, "A"); set_fc(pkt, "C"); break;   /* TYPE A C */
        case 3:  set_tc(pkt, "E"); set_fc(pkt, "N"); break;   /* TYPE E N（常见） */

        /* —— 合法但边界/大小写/宽字符 —— */
        case 4:  set_tc(pkt, "A"); set_fc(pkt, "n"); break;   /* 小写（大小写宽容性） */
        case 5:  set_tc(pkt, "A"); set_fc(pkt, "Ｎ"); break;  /* 全角 N（UTF-8 多字节） */
        case 6:  set_tc(pkt, "E"); set_fc(pkt, " t "); break; /* 带空白的值（前后空格） */

        /* —— 非法/鲁棒性：不该有 format_control 的类型 —— */
        case 7:  set_tc(pkt, "I"); set_fc(pkt, "N"); break;   /* I N（非法组合） */
        case 8:  set_tc(pkt, "L"); set_fc(pkt, "C"); break;   /* L C（非法组合，L 应为数字） */

        /* —— 值域异常/注入/编码 —— */
        case 9:  set_fc(pkt, ""); break;                      /* 删除该字段（为空） */
        case 10: set_fc(pkt, "X"); break;                     /* 未知字母 */
        case 11: set_fc(pkt, "0"); break;                     /* 数字 */
        case 12: set_fc(pkt, "0x4E"); break;                  /* 十六进制风格 */
        case 13: set_fc(pkt, "%4E"); break;                   /* 百分号编码 */
        case 14: set_fc(pkt, "N\r\nNOOP"); break;             /* CRLF 注入 */
        case 15: {                                            /* 超长填满 */
            buf_fill_repeat(pkt->format_control, sizeof(pkt->format_control), 'A',
                            sizeof(pkt->format_control)?sizeof(pkt->format_control)-1:0);
            buf_set(pkt->space2, sizeof(pkt->space2), " ");
            break;
        }
        case 16: set_fc(pkt, "N T"); break;                   /* 含空格的多标记 */
        case 17: set_fc(pkt, "NONPRINT"); break;              /* 长 token */
        case 18: set_fc(pkt, "\tN"); break;                   /* 制表符前缀 */
        case 19: set_fc(pkt, "😀"); break;                    /* 纯 emoji */
        case 20: {                                            /* 随机从 {N,T,C,X} 选一 */
            const char *cands[] = {"N","T","C","X"};
            set_fc(pkt, cands[xorshift32(&rng)%4]);
            break;
        }
        case 21: {                                            /* 和 type_code 同时做“错配” */
            const char *tc[] = {"I","L","Z","123","a"};
            set_tc(pkt, tc[xorshift32(&rng)%5]);
            set_fc(pkt, (xorshift32(&rng)&1) ? "N" : "C");
            break;
        }
        default: return 0;
    }
    return 1;
}
static inline void ensure_space(ftp_retr_packet_t *pkt){
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }
}

/**
 * 对 STRU 的 structure_code 进行充分变异（≥20 种算子）
 * - 就地修改 pkt->structure_code；必要时补 space=" "
 * - 无堆分配；写入自动截断并 '\0' 终止
 *
 * @param pkt  ftp_stru_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1=随机选择；>=0 指定算子编号（0..21）
 * @return 1 成功；0 失败/参数非法
 */
int mutate_stru_structure_code(ftp_stru_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    ensure_space(pkt);

    char orig[FTP_SZ_STRUCTURE];
    buf_set(orig, sizeof(orig), pkt->structure_code);

    uint32_t rng = (seed?seed:0xA1B2C3D4u);
    const int OPS = 22;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法取值 —— */
        case 0:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "F"); break;  /* File */
        case 1:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "R"); break;  /* Record */
        case 2:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "P"); break;  /* Page */

        /* —— 大小写/空白/可接受的轻微偏差（考察宽容性） —— */
        case 3:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "f"); break;  /* 小写 */
        case 4:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "  F  "); break; /* 前后空格 */
        case 5:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "FILE"); break;  /* 长 token */

        /* —— 非法/边界 —— */
        case 6:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), ""); break;       /* 空值 */
        case 7:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "X"); break;      /* 未知字母 */
        case 8:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "0"); break;      /* 数字 */
        case 9:  buf_set(pkt->structure_code, sizeof(pkt->structure_code), "FR"); break;     /* 多字符组合 */
        case 10: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "Ｆ"); break;     /* 全角 F（UTF-8） */
        case 11: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "%46"); break;    /* 百分号编码 'F' */
        case 12: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "F\r\nNOOP"); break; /* CRLF 注入 */
        case 13: buf_fill_repeat(pkt->structure_code, sizeof(pkt->structure_code), 'A',
                                 sizeof(pkt->structure_code)?sizeof(pkt->structure_code)-1:0); break; /* 超长填满 */

        /* —— 与原值相关的扰动 —— */
        case 14: { /* 随机从 F/R/P 选一个合法值 */
            const char *ok[] = {"F","R","P"};
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), ok[xorshift32(&rng)%3]);
            break;
        }
        case 15: { /* 基于原值的大小写翻转（若原值为空则用 "F"） */
            char tmp[FTP_SZ_STRUCTURE];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"F");
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            for(size_t i=0;i<n;++i) if(isalpha((unsigned char)tmp[i])) tmp[i]^=0x20;
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), tmp);
            break;
        }
        case 16: { /* 位翻转一次（对首字符） */
            char tmp[FTP_SZ_STRUCTURE];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"F");
            if(tmp[0]) tmp[0] ^= (char)(1u << (xorshift32(&rng)%5));
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), tmp);
            break;
        }
        case 17: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "\tF"); break;   /* 制表符前缀 */
        case 18: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "\"F\""); break; /* 引号包裹 */
        case 19: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "PAGE"); break;  /* 另一长 token */
        case 20: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "R\nev"); break; /* 内含换行 */
        case 21: buf_set(pkt->structure_code, sizeof(pkt->structure_code), "𝔉"); break;    /* 花体字母（多字节） */

        default: return 0;
    }
    return 1;
}



/**
 * 对 MODE 的 mode_code 做充分变异（≥20 种算子）
 * - 就地修改 pkt->mode_code；必要时补 space=" "
 * - 无动态分配；写入自动截断并 '\0' 结尾
 *
 * @param pkt  ftp_mode_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..21）
 * @return 1 成功；0 失败
 */
int mutate_mode_mode_code(ftp_mode_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    ensure_space(pkt);

    char orig[FTP_SZ_MODE];
    buf_set(orig, sizeof(orig), pkt->mode_code);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 22;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法取值 —— */
        case 0:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "S"); break; /* Stream */
        case 1:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "B"); break; /* Block  */
        case 2:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "C"); break; /* Compressed */

        /* —— 大小写/空白/长 token（考察宽容性） —— */
        case 3:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "s"); break;         /* 小写 */
        case 4:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "  S  "); break;     /* 前后空格 */
        case 5:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "STREAM"); break;    /* 长 token */

        /* —— 非法/边界 —— */
        case 6:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), ""); break;          /* 空值 */
        case 7:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "X"); break;         /* 未知字母 */
        case 8:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "0"); break;         /* 数字 */
        case 9:  buf_set(pkt->mode_code, sizeof(pkt->mode_code), "SB"); break;        /* 多字符组合 */
        case 10: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "Ｓ"); break;        /* 全角 S（UTF-8） */
        case 11: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "%53"); break;       /* 百分号编码 'S' */
        case 12: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "S\r\nNOOP"); break; /* CRLF 注入 */
        case 13: buf_fill_repeat(pkt->mode_code, sizeof(pkt->mode_code), 'A',
                                 sizeof(pkt->mode_code)?sizeof(pkt->mode_code)-1:0); break; /* 超长填满 */

        /* —— 基于原值的扰动 —— */
        case 14: { /* 在 {S,B,C} 中随机一个合法值 */
            const char *ok[] = {"S","B","C"};
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), ok[xorshift32(&rng)%3]);
            break;
        }
        case 15: { /* 大小写翻转（若原值为空则用 "S"） */
            char tmp[FTP_SZ_MODE];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"S");
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            for(size_t i=0;i<n;++i) if(isalpha((unsigned char)tmp[i])) tmp[i]^=0x20;
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), tmp);
            break;
        }
        case 16: { /* 位翻转一次（对首字符） */
            char tmp[FTP_SZ_MODE];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"S");
            if(tmp[0]) tmp[0] ^= (char)(1u << (xorshift32(&rng)%5));
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), tmp);
            break;
        }

        /* —— 其它鲁棒性场景 —— */
        case 17: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "\tS"); break;       /* 制表符前缀 */
        case 18: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "\"S\""); break;     /* 引号包裹 */
        case 19: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "S B"); break;       /* 中间含空格 */
        case 20: buf_set(pkt->mode_code, sizeof(pkt->mode_code), "𝕊"); break;        /* 花体/多字节 */
        case 21: { /* 从 {S,B,C,X,0,a} 随机选 */
            const char *cand[] = {"S","B","C","X","0","a"};
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), cand[xorshift32(&rng)%6]);
            break;
        }

        default: return 0;
    }
    return 1;
}


/**
 * 对 RETR 的 pathname 做充分变异（≥25 种算子）
 * - 就地修改 pkt->pathname；必要时补 space=" "
 * - 无动态分配；写入自动截断并 '\0' 结尾
 *
 * @param pkt  ftp_retr_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..26）
 * @return 1 成功；0 失败
 */
int mutate_retr_pathname(ftp_retr_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    ensure_space(pkt);

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 27;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法常见 —— */
        case 0:  buf_set(pkt->pathname, sizeof(pkt->pathname), "file.txt"); break;
        case 1:  buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/log/syslog"); break;
        case 2:  buf_set(pkt->pathname, sizeof(pkt->pathname), "./a/b/c.txt"); break;
        case 3:  buf_set(pkt->pathname, sizeof(pkt->pathname), "../secret/report.pdf"); break;
        case 4:  buf_set(pkt->pathname, sizeof(pkt->pathname), ".hidden"); break;
        case 5:  buf_set(pkt->pathname, sizeof(pkt->pathname), "My Documents/report 2020.txt"); break;

        /* —— 目录结构与规格边界 —— */
        case 6:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir///sub////file"); break;   /* 多重斜杠 */
        case 7:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/"); break;                /* 目录结尾斜杠 */
        case 8:  { /* 很深的路径 */
            char tmp[FTP_SZ_PATH]; tmp[0]='\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0;
            while(used + strlen(seg) + 8 < cap){ strcat(tmp, seg); used += strlen(seg); }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 9:  buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                                 sizeof(pkt->pathname)?sizeof(pkt->pathname)-1:0); break; /* 超长填满 */

        /* —— 特殊字符与通配 —— */
        case 10: buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat"); break;
        case 11: buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c"); break;
        case 12: buf_set(pkt->pathname, sizeof(pkt->pathname), "set/[abc]/x.txt"); break;
        case 13: buf_set(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\".txt"); break;

        /* —— 平台差异（Windows 风格） —— */
        case 14: buf_set(pkt->pathname, sizeof(pkt->pathname), "dir\\sub\\file.txt"); break;
        case 15: buf_set(pkt->pathname, sizeof(pkt->pathname), "C:\\Windows\\system32\\drivers\\etc\\hosts"); break;
        case 16: buf_set(pkt->pathname, sizeof(pkt->pathname), "con.txt"); break; /* 保留名 */

        /* —— 编码/Unicode/空白 —— */
        case 17: buf_set(pkt->pathname, sizeof(pkt->pathname), "测试/文件.txt"); break;
        case 18: buf_set(pkt->pathname, sizeof(pkt->pathname), "école/über/naïve.txt"); break;
        case 19: buf_set(pkt->pathname, sizeof(pkt->pathname), "📄.txt"); break;
        case 20: buf_set(pkt->pathname, sizeof(pkt->pathname), "  spaced-leading-and-trailing  "); break;

        /* —— Percent 编码与注入（可按需关闭） —— */
        case 21: buf_set(pkt->pathname, sizeof(pkt->pathname), "/etc/%70asswd"); break; /* %70 == 'p' */
        case 22: buf_set(pkt->pathname, sizeof(pkt->pathname), "file%00.txt"); break;   /* 编码的 NUL */
        case 23: buf_set(pkt->pathname, sizeof(pkt->pathname), "foo\r\nNOOP"); break;   /* CRLF 注入 */

        /* —— 相对路径/穿越与波浪线 —— */
        case 24: buf_set(pkt->pathname, sizeof(pkt->pathname), "../../../../../etc/shadow"); break;
        case 25: buf_set(pkt->pathname, sizeof(pkt->pathname), "~user/.ssh/id_rsa"); break;

        /* —— 基于原值的微扰 —— */
        case 26: {
            /* 若原值为空则先给一个基础值，再随机改一个字符 */
            char tmp[FTP_SZ_PATH];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"base.txt");
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            if(n==0){ buf_set(pkt->pathname, sizeof(pkt->pathname), "base.txt"); break; }
            size_t pos = xorshift32(&rng) % n;
            unsigned char c = (unsigned char)tmp[pos];
            /* 随机替换为可见字符或翻转某个位 */
            if((xorshift32(&rng) & 1) == 0){
                tmp[pos] = (char)('!' + (xorshift32(&rng) % (126-'!'+1)));
            }else{
                tmp[pos] = (char)(c ^ (1u << (xorshift32(&rng)%6)));
            }
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        default: return 0;
    }
    return 1;
}
static inline void ensure_space_stor(ftp_stor_packet_t *pkt){
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }
}

/**
 * 对 STOR 的 pathname 做充分变异（≥25 种算子）
 * - 就地修改 pkt->pathname；必要时补 space=" "
 * - 无动态分配；写入自动截断并 '\0' 结尾
 *
 * @param pkt  ftp_stor_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..28）
 * @return 1 成功；0 失败
 */
int mutate_stor_pathname(ftp_stor_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;
    ensure_space_stor(pkt);

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 29;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法常见路径 —— */
        case 0:  buf_set(pkt->pathname, sizeof(pkt->pathname), "upload.bin"); break;
        case 1:  buf_set(pkt->pathname, sizeof(pkt->pathname), "/tmp/out.dat"); break;
        case 2:  buf_set(pkt->pathname, sizeof(pkt->pathname), "./docs/new.txt"); break;
        case 3:  buf_set(pkt->pathname, sizeof(pkt->pathname), "backup/2025-08-23.tar.gz"); break;
        case 4:  buf_set(pkt->pathname, sizeof(pkt->pathname), ".hidden/file"); break;

        /* —— 结构/长度边界 —— */
        case 5:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir///sub////file"); break;  /* 多斜杠 */
        case 6:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/"); break;               /* 目录结尾 */
        case 7:  { /* 很深的层级 */
            char tmp[FTP_SZ_PATH]; tmp[0]='\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0;
            while(used + strlen(seg) + 8 < cap){ strcat(tmp, seg); used += strlen(seg); }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 8:  buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                                 sizeof(pkt->pathname)?sizeof(pkt->pathname)-1:0); break; /* 填满上限 */
        case 9:  buf_set(pkt->pathname, sizeof(pkt->pathname), "a"); break; /* 极短 */

        /* —— 特殊字符/通配/引用 —— */
        case 10: buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat"); break; /* 一些服务器不支持 */
        case 11: buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c"); break;
        case 12: buf_set(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\".txt"); break;
        case 13: buf_set(pkt->pathname, sizeof(pkt->pathname), "name with spaces .txt"); break;

        /* —— 平台差异/保留名 —— */
        case 14: buf_set(pkt->pathname, sizeof(pkt->pathname), "dir\\sub\\file.txt"); break; /* 反斜杠 */
        case 15: buf_set(pkt->pathname, sizeof(pkt->pathname), "CON"); break;                /* Windows 保留名 */
        case 16: buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt."); break;          /* 结尾点/空格 */

        /* —— 编码/Unicode —— */
        case 17: buf_set(pkt->pathname, sizeof(pkt->pathname), "输出/结果-测试.txt"); break;
        case 18: buf_set(pkt->pathname, sizeof(pkt->pathname), "mañana/über/naïve.txt"); break;
        case 19: buf_set(pkt->pathname, sizeof(pkt->pathname), "📦/📄.bin"); break;

        /* —— 百分号编码/控制字符/注入 —— */
        case 20: buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/%6C%6F%67.txt"); break; /* %编码 */
        case 21: buf_set(pkt->pathname, sizeof(pkt->pathname), "file%00.txt"); break;       /* 编码的 NUL */
        case 22: buf_set(pkt->pathname, sizeof(pkt->pathname), "foo\r\nNOOP"); break;       /* CRLF 注入 */
        case 23: { /* 内嵌制表/退格 */
            char tmp[] = "tab\tname\t.txt";
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        /* —— 相对/穿越/家目录 —— */
        case 24: buf_set(pkt->pathname, sizeof(pkt->pathname), "../../../../../root/.bashrc"); break;
        case 25: buf_set(pkt->pathname, sizeof(pkt->pathname), "~/.ssh/authorized_keys"); break;

        /* —— 版本/时间戳/碰撞名字 —— */
        case 26: buf_set(pkt->pathname, sizeof(pkt->pathname), "report(1).pdf"); break;
        case 27: buf_set(pkt->pathname, sizeof(pkt->pathname), "report:2025-08-23T12:34:56Z.log"); break;

        /* —— 基于原值的微扰（保留原始语义做细微破坏） —— */
        case 28: {
            char tmp[FTP_SZ_PATH];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"upload.bin");
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            if(n==0){ buf_set(pkt->pathname, sizeof(pkt->pathname), "upload.bin"); break; }
            size_t pos = xorshift32(&rng) % n;
            unsigned char c = (unsigned char)tmp[pos];
            if((xorshift32(&rng) & 1) == 0){
                /* 替换为可见 ASCII */
                tmp[pos] = (char)('!' + (xorshift32(&rng) % (126-'!'+1)));
            }else{
                /* 随机翻转若干 bit */
                tmp[pos] = (char)(c ^ (1u << (xorshift32(&rng)%6)));
            }
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        default: return 0;
    }
    return 1;
}


/* —— 可选字段辅助 —— */
int add_stou_pathname(ftp_stou_packet_t *pkt, const char *name){
    if(!pkt) return 0;
    pkt->space[0] = ' '; pkt->space[1] = '\0';
    buf_set(pkt->pathname, sizeof(pkt->pathname), name && name[0]? name : "upload-unique.bin");
    return 1;
}
int delete_stou_pathname(ftp_stou_packet_t *pkt){
    if(!pkt) return 0;
    pkt->space[0] = '\0';
    pkt->pathname[0] = '\0';
    return 1;
}

/**
 * 对 STOU 的 pathname 做充分变异（≥25 种算子）
 * - 就地修改 pkt->pathname；必要时补 space=" "
 * - op=-1 时随机选择算子；op>=0 指定算子（0..28）
 * - 算子中也包含 “删除参数” 与 “仅保留空参数” 等可选字段场景
 *
 * @param pkt  ftp_stou_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..28）
 * @return 1 成功；0 失败
 */
int mutate_stou_pathname(ftp_stou_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xACCEBEEFu);
    const int OPS = 29;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 可选字段相关 —— */
        case 0:  /* 删除参数：让服务器自行生成唯一名（规范允许） */
            return delete_stou_pathname(pkt);

        case 1:  /* 空参数但保留空格（边缘非法/实现依赖） */
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            pkt->pathname[0] = '\0';
            return 1;

        /* —— 合法常见路径 —— */
        case 2:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "upload-unique.bin"); break;
        case 3:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "uploads/out.dat"); break;
        case 4:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "./docs/new.txt"); break;

        /* —— 结构/长度边界 —— */
        case 5:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "dir///sub////file"); break;
        case 6:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/"); break;
        case 7:  { /* 很深的层级 */
            pkt->space[0]=' '; pkt->space[1]='\0';
            char tmp[FTP_SZ_PATH]; tmp[0]='\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0;
            while(used + strlen(seg) + 8 < cap){ strcat(tmp, seg); used += strlen(seg); }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 8:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                                 sizeof(pkt->pathname)?sizeof(pkt->pathname)-1:0); break;
        case 9:  pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "a"); break;

        /* —— 特殊字符/通配/引用 —— */
        case 10: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat"); break;
        case 11: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c"); break;
        case 12: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\".txt"); break;
        case 13: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), " name with spaces .txt"); break;

        /* —— 平台差异/保留名 —— */
        case 14: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "dir\\sub\\file.txt"); break;
        case 15: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "CON"); break;          /* Windows 保留名 */
        case 16: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt."); break;     /* 结尾点/空格 */

        /* —— 编码/Unicode —— */
        case 17: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "输出/唯一-测试.txt"); break;
        case 18: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "mañana/über/naïve.txt"); break;
        case 19: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "📦/📄.bin"); break;

        /* —— 百分号编码/控制字符/注入 —— */
        case 20: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/%6C%6F%67.txt"); break; /* %编码 */
        case 21: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "file%00.txt"); break;       /* 编码的 NUL */
        case 22: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "foo\r\nNOOP"); break;       /* CRLF 注入 */
        case 23: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "tab\tname\t.txt"); break;

        /* —— 相对/穿越/家目录 —— */
        case 24: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "../../../../../etc/passwd"); break;
        case 25: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "~/.ssh/authorized_keys"); break;

        /* —— 时间戳/随机唯一后缀 —— */
        case 26: pkt->space[0]=' '; pkt->space[1]='\0';
                 buf_set(pkt->pathname, sizeof(pkt->pathname), "stou-2025-08-23T12:34:56Z.log"); break;
        case 27: { /* 生成随机十六进制后缀，模拟“唯一名” */
            pkt->space[0]=' '; pkt->space[1]='\0';
            char tmp[FTP_SZ_PATH];
            char suf[17]; for(int i=0;i<16;i++){ static const char H[]="0123456789abcdef";
                suf[i]=H[xorshift32(&rng)&0xF]; } suf[16]='\0';
            (void)snprintf(tmp, sizeof(tmp), "upload_%s.bin", suf);
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        /* —— 基于原值的微扰 —— */
        case 28: {
            pkt->space[0]=' '; pkt->space[1]='\0';
            char tmp[FTP_SZ_PATH];
            buf_set(tmp, sizeof(tmp), (orig[0]?orig:"upload-unique.bin"));
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            size_t pos = (n? (xorshift32(&rng)%n) : 0);
            if(n==0){ buf_set(pkt->pathname, sizeof(pkt->pathname), "upload-unique.bin"); break; }
            /* 随机替换或翻转 bit */
            if((xorshift32(&rng) & 1)==0){
                tmp[pos] = (char)('!' + (xorshift32(&rng) % (126-'!'+1)));
            }else{
                tmp[pos] = (char)(tmp[pos] ^ (1u << (xorshift32(&rng)%6)));
            }
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        default: return 0;
    }
    return 1;
}



static inline void ensure_space_required(char space[/*FTP_SZ_SPACE*/]){
    /* APPE 的参数是必选：强制令 space = " " */
    space[0] = ' '; space[1] = '\0';
}

/**
 * 对 APPE 的 pathname 做充分变异（≥25 种算子）
 * - 就地修改 pkt->pathname；始终保证 pkt->space = " "
 * - op=-1 时随机选择算子；op>=0 指定算子（0..29）
 *
 * @param pkt  ftp_appe_packet_t*
 * @param seed 随机种子（相同 seed 可复现）
 * @param op   -1 随机；>=0 指定算子（0..29）
 * @return 1 成功；0 失败
 */
int mutate_appe_pathname(ftp_appe_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;

    ensure_space_required(pkt->space);

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed?seed:0xA99EEDu);
    const int OPS = 30;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法常见 —— */
        case 0:  buf_set(pkt->pathname, sizeof(pkt->pathname), "logs/app.log"); break;
        case 1:  buf_set(pkt->pathname, sizeof(pkt->pathname), "data/out.bin"); break;
        case 2:  buf_set(pkt->pathname, sizeof(pkt->pathname), "./append.txt"); break;
        case 3:  buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/file"); break;

        /* —— 结构/长度边界 —— */
        case 4:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir///sub////file"); break;
        case 5:  buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/"); break; /* 末尾斜杠 */
        case 6: { /* 很深层级 */
            char tmp[FTP_SZ_PATH]; tmp[0]='\0';
            const char *seg = "aaaa/";
            size_t used = 0, cap = sizeof(tmp);
            while(used + strlen(seg) + 8 < cap){ strcat(tmp, seg); used += strlen(seg); }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 7:  buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                                 sizeof(pkt->pathname)?sizeof(pkt->pathname)-1:0); break;
        case 8:  buf_set(pkt->pathname, sizeof(pkt->pathname), "a"); break;

        /* —— 通配/空白/引号 —— */
        case 9:  buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat"); break;
        case 10: buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c"); break;
        case 11: buf_set(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\".txt"); break;
        case 12: buf_set(pkt->pathname, sizeof(pkt->pathname), " name with spaces .txt"); break;

        /* —— 平台差异/保留名/奇异后缀 —— */
        case 13: buf_set(pkt->pathname, sizeof(pkt->pathname), "dir\\sub\\file.txt"); break; /* 反斜杠 */
        case 14: buf_set(pkt->pathname, sizeof(pkt->pathname), "CON"); break;          /* Windows 保留名 */
        case 15: buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt."); break;     /* 结尾点/空格 */

        /* —— 非 ASCII/Unicode —— */
        case 16: buf_set(pkt->pathname, sizeof(pkt->pathname), "输出/追加-测试.txt"); break;
        case 17: buf_set(pkt->pathname, sizeof(pkt->pathname), "mañana/über/naïve.txt"); break;
        case 18: buf_set(pkt->pathname, sizeof(pkt->pathname), "📂/📄.log"); break;

        /* —— 百分号/控制字符/注入 —— */
        case 19: buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/%6C%6F%67.txt"); break; /* %编码 */
        case 20: buf_set(pkt->pathname, sizeof(pkt->pathname), "file%00.txt"); break;       /* 编码的 NUL */
        case 21: buf_set(pkt->pathname, sizeof(pkt->pathname), "foo\r\nNOOP"); break;       /* CRLF 注入 */
        case 22: buf_set(pkt->pathname, sizeof(pkt->pathname), "tab\tname\t.txt"); break;

        /* —— 穿越/家目录/相对 —— */
        case 23: buf_set(pkt->pathname, sizeof(pkt->pathname), "../../../../../etc/passwd"); break;
        case 24: buf_set(pkt->pathname, sizeof(pkt->pathname), "~/.ssh/authorized_keys"); break;
        case 25: buf_set(pkt->pathname, sizeof(pkt->pathname), "./../..//./a"); break;

        /* —— 时间戳/随机后缀（模拟唯一化） —— */
        case 26: buf_set(pkt->pathname, sizeof(pkt->pathname), "appe-2025-08-23T12:34:56Z.log"); break;
        case 27: {
            char tmp[FTP_SZ_PATH], suf[17];
            for(int i=0;i<16;i++){ static const char H[]="0123456789abcdef";
                suf[i]=H[xorshift32(&rng)&0xF]; } suf[16]='\0';
            (void)snprintf(tmp, sizeof(tmp), "append_%s.bin", suf);
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        /* —— 变形：前后空格/点/大小写 —— */
        case 28: buf_set(pkt->pathname, sizeof(pkt->pathname), "  file . log  "); break;

        /* —— 基于原值的微扰（若原值为空则给默认） —— */
        case 29: {
            char tmp[FTP_SZ_PATH];
            buf_set(tmp, sizeof(tmp), (orig[0]?orig:"append.log"));
            size_t n = cstrnlen_(tmp, sizeof(tmp));
            if(n==0){ buf_set(pkt->pathname, sizeof(pkt->pathname), "append.log"); break; }
            size_t pos = (xorshift32(&rng)%n);
            if((xorshift32(&rng) & 1)==0){
                tmp[pos] = (char)('!' + (xorshift32(&rng) % (126-'!'+1))); /* 随机可打印符号 */
            }else{
                tmp[pos] = (char)(tmp[pos] ^ (1u << (xorshift32(&rng)%6))); /* 翻转 bit */
            }
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        default: return 0;
    }
    return 1;
}




/**
 * 变异 ftp_allo_packet_t.byte_count
 * - op = -1 随机选择一种算子；op >= 0 时指定算子（0..29）
 * - 始终保证 pkt->space1 = " "（byte_count 为必选参数）
 *
 * 变异覆盖：0/正数/极大数/负数/前导零/符号/十六进制/八进制/科学计数/小数/NaN/Inf/
 * 千分位/控制字符/CRLF 注入/超长填充/全角数字/随机数字串/原值微扰/单位后缀等
 *
 * @return 1 成功；0 失败
 */
int mutate_allo_byte_count(ftp_allo_packet_t *pkt, uint32_t seed, int op){
    if(!pkt) return 0;

    ensure_space_required(pkt->space1);

    char orig[FTP_SZ_BYTECOUNT];
    buf_set(orig, sizeof(orig), pkt->byte_count);

    uint32_t rng = (seed ? seed : 0xA5A5F00Du);
    const int OPS = 30;
    if(op < 0 || op >= OPS) op = (int)(xorshift32(&rng) % OPS);

    switch(op){
        /* —— 合法常见 —— */
        case 0:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "0"); break;
        case 1:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1"); break;
        case 2:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "512"); break;
        case 3:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1048576"); break;          /* 1 MiB */
        case 4:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "2147483647"); break;       /* INT_MAX */
        case 5:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "4294967295"); break;       /* UINT32_MAX */

        /* —— 数字表示变体 —— */
        case 6:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "-1"); break;               /* 负数（非法） */
        case 7:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "+1024"); break;            /* 显式正号 */
        case 8:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "000000001024"); break;     /* 前导零 */
        case 9:  buf_set(pkt->byte_count, sizeof(pkt->byte_count), "0x400"); break;            /* 十六进制 */
        case 10: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "0400"); break;             /* 八进制歧义 */
        case 11: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1e6"); break;              /* 科学计数 */
        case 12: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "3.14159"); break;          /* 小数（非法） */
        case 13: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "inf"); break;              /* 无穷大（非法） */
        case 14: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "NaN"); break;              /* 非数（非法） */
        case 15: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1,024"); break;            /* 千分位分隔 */

        /* —— 空白/控制/注入 —— */
        case 16: buf_set(pkt->byte_count, sizeof(pkt->byte_count), " \t 1024 \t "); break;     /* 环绕空白 */
        case 17: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1024\t"); break;           /* 尾随制表符 */
        case 18: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1024\r\nNOOP"); break;     /* CRLF 注入 */

        /* —— 超长/边界 —— */
        case 19: {                                                                             /* 填满缓冲区 */
            size_t cap = sizeof(pkt->byte_count);
            if(cap > 1){
                memset(pkt->byte_count, '9', cap-1);
                pkt->byte_count[cap-1] = '\0';
            } else {
                buf_set(pkt->byte_count, cap, "9");
            }
            break;
        }
        case 20: buf_set(pkt->byte_count, sizeof(pkt->byte_count),
                         "18446744073709551615"); break;                                      /* U64_MAX */

        /* —— 非 ASCII —— */
        case 21: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "１２３４"); break;          /* 全角数字 */

        /* —— 随机类 —— */
        case 22: {                                                                             /* 随机数字串 */
            char tmp[FTP_SZ_BYTECOUNT];
            size_t cap = sizeof(tmp);
            size_t n = (xorshift32(&rng) % (cap ? cap : 1));
            if(n == 0) n = 1;
            for(size_t i=0;i+1<cap && i<n;i++){
                tmp[i] = (char)('0' + (xorshift32(&rng) % 10));
            }
            tmp[(n < cap)?n:(cap-1)] = '\0';
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), tmp);
            break;
        }
        case 23: {                                                                             /* 原值微扰：翻转一位或改一字符 */
            char tmp[FTP_SZ_BYTECOUNT];
            buf_set(tmp, sizeof(tmp), orig[0]?orig:"1024");
            size_t len = strnlen(tmp, sizeof(tmp));
            if(len == 0){ buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1024"); break; }
            size_t pos = xorshift32(&rng) % len;
            if((xorshift32(&rng) & 1) == 0){
                /* 改成随机可打印字符 */
                tmp[pos] = (char)('!' + (xorshift32(&rng) % (126 - '!' + 1)));
            }else{
                /* 简单数字抖动 */
                tmp[pos] = (char)('0' + (xorshift32(&rng) % 10));
            }
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), tmp);
            break;
        }

        /* —— 语义花样 —— */
        case 24: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1024K"); break;            /* 单位后缀 */
        case 25: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "2G"); break;               /* 大单位 */
        case 26: buf_set(pkt->byte_count, sizeof(pkt->byte_count), ""); break;                 /* 空字串（非法） */
        case 27: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "999999999999999999999999999999999"); break; /* 超大数 */
        case 28: buf_set(pkt->byte_count, sizeof(pkt->byte_count), " 000 "); break;            /* 全零+空白 */
        case 29: buf_set(pkt->byte_count, sizeof(pkt->byte_count), "123abc"); break;           /* 数字+垃圾 */

        default: return 0;
    }
    return 1;
}


static inline void set_space(char s2[/*FTP_SZ_SPACE*/], int present){
    if (present){ s2[0] = ' '; s2[1] = '\0'; }
    else        { s2[0] = '\0'; }
}

static inline void set_cstr(char *dst, size_t cap, const char *s){
    if (!dst || cap == 0) return;
    if (!s) s = "";
    (void)snprintf(dst, cap, "%s", s);
}


/* (a) 增加该字段：设置为一个合理合法的形式 */
int add_allo_record_format(ftp_allo_packet_t *pkt){
    if(!pkt) return 0;
    set_space(pkt->space2, 1);
    set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 512");
    return 1;
}

/* (b) 删除该字段：清空并移除分隔空格 */
int delete_allo_record_format(ftp_allo_packet_t *pkt){
    if(!pkt) return 0;
    set_space(pkt->space2, 0);
    pkt->record_format[0] = '\0';
    return 1;
}

/* 覆盖丰富场景的就地变异器（仅变异 record_format/space2） */
int mutate_allo_record_format(ftp_allo_packet_t *pkt){
    if(!pkt) return 0;

    static unsigned op_idx = 0;         /* 每次调用轮转一个算子，满足“只收指针”为入参 */
    const unsigned OPS = 24;
    unsigned op = (op_idx++) % OPS;

    /* 保留原值以便做“微扰”等 */
    char orig[FTP_SZ_FORMAT];
    set_cstr(orig, sizeof(orig), pkt->record_format);

    switch(op){
        /* —— 合法代表值 —— */
        case 0:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format),"R 1"); break;
        case 1:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format),"R 0"); break;
        case 2:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format),"R 512"); break;
        case 3:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format),"R 2147483647"); break;

        /* —— 边界/非法数值与表示变体 —— */
        case 4:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format),"R -1"); break;
        case 5:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R +64"); break;
        case 6:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 00064"); break;
        case 7:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 0x40"); break;
        case 8:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 1e3"); break;
        case 9:  set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 3.14"); break;

        /* —— 语法缺失/多余 —— */
        case 10: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R"); break;                 /* 缺少尺寸 */
        case 11: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R\t1024"); break;          /* 制表空白 */
        case 12: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "r 512"); break;            /* 小写关键字 */
        case 13: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "M 4096"); break;           /* 未知关键字 */
        case 14: {                                                                                                             /* 填满缓冲 */
            set_space(pkt->space2,1);
            size_t cap = sizeof(pkt->record_format);
            if (cap >= 4){
                pkt->record_format[0]='R'; pkt->record_format[1]=' '; pkt->record_format[2]='9';
                for(size_t i=3;i<cap-1;i++) pkt->record_format[i]='9';
                pkt->record_format[cap-1]='\0';
            }else{
                set_cstr(pkt->record_format,cap,"R");
            }
            break;
        }
        case 15: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 512 extra"); break;      /* 多余 token */
        case 16: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R,512"); break;            /* 分隔符异常 */
        case 17: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R:512"); break;            /* 分隔符异常 */

        /* —— 控制字符/注入 —— */
        case 18: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 512\r\nNOOP"); break;

        /* —— 非 ASCII/本地化数字 —— */
        case 19: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R １２３"); break;          /* 全角数字 */

        /* —— 分隔空格缺失（非法但有用的模糊） —— */
        case 20: set_space(pkt->space2,0); set_cstr(pkt->record_format,sizeof(pkt->record_format), "R 256"); break;

        /* —— 前导/仅空白 —— */
        case 21: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), "   R 256"); break;
        case 22: set_space(pkt->space2,0); set_cstr(pkt->record_format,sizeof(pkt->record_format), ""); break;                  /* 等价删除 */
        case 23: set_space(pkt->space2,1); set_cstr(pkt->record_format,sizeof(pkt->record_format), " \t "); break;              /* 只有空白 */

        default: return 0;
    }
    return 1;
}


/* 针对 REST.marker 的充分变异（仅修改 pkt->marker / pkt->space） */
int mutate_rest_marker(ftp_rest_packet_t *pkt){
    if(!pkt) return 0;

    /* 无外部 seed 入参，这里采用轮转算子，保证多次调用覆盖不同场景 */
    static unsigned op_idx = 0;
    const unsigned OPS = 22;
    unsigned op = (op_idx++) % OPS;

    switch(op){
        /* —— 合法代表值/边界 —— */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "0"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "1"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "1234567890"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "2147483647"); break;          /* int32_max */
        case 4:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "4294967295"); break;          /* uint32_max */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "9223372036854775807"); break; /* int64_max */

        /* —— 符号/前导零/非十进制表示 —— */
        case 6:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "-1"); break;                  /* 负数 */
        case 7:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "+0"); break;                  /* 显式正号 */
        case 8:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "00000000"); break;            /* 前导零 */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "0x7fffffff"); break;          /* 十六进制 */
        case 10: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "1e12"); break;                /* 科学计数法 */
        case 11: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "3.1415"); break;              /* 小数 */

        /* —— 缺失/仅空白/空白变体 —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), ""); break;                    /* 缺失参数（非法） */
        case 13: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), " "); break;                   /* 只有空格 */
        case 14: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "\t123"); break;               /* 制表符前缀 */
        case 15: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "123   "); break;              /* 尾随空白 */
        case 16: set_space(pkt->space,0); set_cstr(pkt->marker, sizeof(pkt->marker), "123"); break;                 /* 缺失必需空格 */

        /* —— 长度与缓冲边界/超长 —— */
        case 17: {                                                                                                  /* 用'9'占满缓冲 */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->marker);
            if (cap > 1){
                memset(pkt->marker, '9', cap-1);
                pkt->marker[cap-1] = '\0';
            }else{
                set_cstr(pkt->marker, cap, "");
            }
            break;
        }
        case 18: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "18446744073709551616"); break;/* >uint64_max */

        /* —— 非数字/混合/Unicode —— */
        case 19: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "abc"); break;                 /* 非数字 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "12abc34"); break;             /* 混合 */
        case 21: set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "１２３"); break;               /* 全角数字 */

        /* —— 额外：控制字符/注入（可与上面任一替换某个 case 使用）
           set_space(pkt->space,1); set_cstr(pkt->marker, sizeof(pkt->marker), "123\r\nNOOP");
         */

        default: return 0;
    }
    return 1;
}



/* 针对 RNFR.pathname 的充分变异（只改 pkt->pathname / pkt->space） */
int mutate_rnfr_pathname(ftp_rnfr_packet_t *pkt){
    if(!pkt) return 0;

    /* 轮转式算子选择：多次调用覆盖不同场景 */
    static unsigned op_idx = 0;
    const unsigned OPS = 24;
    unsigned op = (op_idx++) % OPS;

    switch(op){
        /* —— 合法基础/常见形式 —— */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "file.txt"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/log/syslog"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./a/b/c"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/"); break;          /* 目录尾随斜杠 */

        /* —— 路径遍历/可疑目标 —— */
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".././../..////secret"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../.."); break;

        /* —— 平台/分隔符变体（Windows/Mix） —— */
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//file.bin"); break;

        /* —— 模式/通配符/特殊名 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*?.[0-9]{1,3}"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;      /* Windows 保留名 */
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden"); break;  /* 隐藏文件 */

        /* —— 空白与引号 —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "a b/ c.txt"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\""); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "'single quoted'"); break;

        /* —— 编码/Unicode —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "%2e%2e%2fetc%2fpasswd"); break;           /* URL 编码 */
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "%252e%252e%252fetc%252fpasswd"); break;   /* 双重编码 */
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "目录/文件.txt"); break;                   /* 非 ASCII */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir/😀.bin"); break;                      /* emoji */

        /* —— 控制字符/注入（非法） —— */
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "foo\r\nNOOP"); break;                     /* 试探命令拼接 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "\tpath\\with\\tab"); break;               /* 前导制表符 */

        /* —— 长度与边界 —— */
        case 21: {  /* 填满缓冲：重复 'A' */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'A', cap-1);
                pkt->pathname[cap-1] = '\0';
            }else{
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 22: {  /* 以 ../../ 重复填充到接近上限 */
            set_space(pkt->space,1);
            const char *seg = "../";
            size_t cap = sizeof(pkt->pathname);
            size_t pos = 0;
            if (cap == 0) break;
            while (pos + strlen(seg) < cap - 1){
                memcpy(pkt->pathname + pos, seg, strlen(seg));
                pos += strlen(seg);
            }
            pkt->pathname[pos] = '\0';
            break;
        }

        /* —— 缺失/分隔符异常 —— */
        case 23: set_space(pkt->space,0); set_cstr(pkt->pathname, sizeof(pkt->pathname), "missing-space.txt"); break;

        /* 也可按需增加：
           set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "abc\0def"); // 内嵌 NUL（C 字符串在 \0 截断）
        */

        default: return 0;
    }
    return 1;
}


/* 小工具：将分隔符 / 和 \ 互换 */
static void swap_separators(char *s){
    if (!s) return;
    for (; *s; ++s){
        if (*s == '/') *s = '\\';
        else if (*s == '\\') *s = '/';
    }
}

/* 小工具：大小写翻转 */
static void toggle_case(char *s){
    if (!s) return;
    for (; *s; ++s){
        if (islower((unsigned char)*s)) *s = (char)toupper((unsigned char)*s);
        else if (isupper((unsigned char)*s)) *s = (char)tolower((unsigned char)*s);
    }
}

/* 针对 RNTO.pathname 的充分变异（主要改 pkt->pathname；必要时也调整 pkt->space） */
int mutate_rnto_pathname(ftp_rnto_packet_t *pkt){
    if(!pkt) return 0;

    /* 轮转式算子选择：多次调用覆盖不同场景（也可改为 RNG） */
    static unsigned op_idx = 0;
    const unsigned OPS = 26;
    unsigned op = (op_idx++) % OPS;

    /* 记录原值，便于基于原始输入的就地变形 */
    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— A. 基于原值的就地变形 —— */
        case 0: { /* A1: 在原名后追加扩展名/后缀 */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s%s", orig[0] ? orig : "name", ".new");
            break;
        }
        case 1: { /* A2: 分隔符互换（/ <-> \） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/file");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { /* A3: 大小写翻转 */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeDCaSe.txt");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { /* A4: 前置目录遍历前缀 ../ */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "../%s", orig[0] ? orig : "target");
            break;
        }
        case 4: { /* A5: 删除中间的多余斜杠（压缩 //...// -> / ） */
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b///c////file";
            char *d = pkt->pathname;
            size_t cap = sizeof(pkt->pathname);
            if (cap == 0) break;
            size_t i = 0;
            for (size_t j = 0; src[j] && i+1 < cap; ++j){
                if (src[j] == '/' && d > pkt->pathname && d[-1] == '/') continue;
                d[i++] = src[j];
            }
            d[i] = '\0';
            break;
        }

        /* —— B. 合法常见目标名称 —— */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "newname.txt"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/newname"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./renamed/file"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/"); break;          /* 目录尾斜杠 */

        /* —— C. 路径遍历/可疑位置 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".././..////.//secret"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../.."); break;

        /* —— D. 平台/分隔符变体（Windows/Mix） —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "C:\\\\Temp\\\\new\\\\name.txt"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//new.bin"); break;

        /* —— E. 特殊/危险名、通配、ADS —— */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;      /* Win 保留名 */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "file.txt:stream"); break; /* NTFS ADS */
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "bad<>:\"/\\|?*.txt"); break;
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_new"); break;

        /* —— F. 空白/引号/尾随点空格（Windows 怪异点） —— */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "new name final.txt"); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted new\""); break;
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "trailingdot."); break;   /* 尾随点 */
        
        /* —— G. 编码/Unicode —— */
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "new%20name.txt"); break;                    /* URL 编码空格 */
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "%252e%252e%252fescape"); break;             /* 双重编码 */
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "新文件名.txt"); break;                      /* 非 ASCII */
        
        /* —— H. 控制字符/注入（非法） —— */
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "new\r\nNOOP"); break;                       /* 命令拼接探测 */
        
        /* —— I. 边界长度/协议违规 —— */
        case 25: { /* 填满缓冲：重复 'B'；亦测试缺失空格情况 */
            set_space(pkt->space,0); /* 故意去掉必需空格，考察解析器容错 */
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'B', cap-1);
                pkt->pathname[cap-1] = '\0';
            }else{
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        default: return 0;
    }

    return 1;
}


/* 压缩重复斜杠 */
static void collapse_slashes(const char *src, char *dst, size_t cap){
    if (!src || !dst || cap == 0) return;
    size_t i = 0;
    char prev = '\0';
    for (size_t j = 0; src[j] && i+1 < cap; ++j){
        char c = src[j];
        if (c == '/' && prev == '/') continue;
        dst[i++] = c;
        prev = c;
    }
    dst[i] = '\0';
}

/* 针对 DELE.pathname 的充分变异（主要改 pkt->pathname；必要时也调整 pkt->space） */
int mutate_dele_pathname(ftp_dele_packet_t *pkt){
    if(!pkt) return 0;

    /* 轮转式算子选择：多次调用覆盖不同场景（也可改为 RNG） */
    static unsigned op_idx = 0;
    const unsigned OPS = 28;
    unsigned op = (op_idx++) % OPS;

    /* 记录原值，便于基于原始输入的就地变形 */
    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— A. 基于原值的就地变形 —— */
        case 0: { /* A1: 在原名后追加后缀（保留原始基线） */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s%s", orig[0] ? orig : "file", ".bak");
            break;
        }
        case 1: { /* A2: 分隔符互换（/ <-> \） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/file.txt");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { /* A3: 大小写翻转 */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/File.TXT");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { /* A4: 前置遍历 ../ */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "../%s", orig[0] ? orig : "target.txt");
            break;
        }
        case 4: { /* A5: 压缩多斜杠 */
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b///c////file";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }

        /* —— B. 合法常见目标 —— */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old.log"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/old.data"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./cache/item"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden"); break;

        /* —— C. 路径遍历/可疑位置 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".././..////.//shadow"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../.."); break;

        /* —— D. 平台/分隔符变体（Windows/Mix） —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "C:\\\\Temp\\\\old\\\\file.bin"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//to_del.tmp"); break;

        /* —— E. 特殊名/通配/ADS/保留名 —— */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*.log"); break;   /* 通配 */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;     /* Win 保留名 */
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "nul"); break;     /* Win 保留名(大小写) */
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "file.txt:stream"); break; /* NTFS ADS */

        /* —— F. 空白/引号/尾随点空格 —— */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced name .txt "); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\""); break;
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "trailingdot."); break;

        /* —— G. 编码/Unicode —— */
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old%20name.txt"); break; /* URL 空格 */
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%252e%252e%252fescape"); break; /* 双重编码 */
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "删除我.txt"); break; /* 非 ASCII */

        /* —— H. 控制字符/命令注入（非法） —— */
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "victim\r\nNOOP"); break;

        /* —— I. 边界/协议违规 —— */
        case 25: { /* 填满缓冲：重复 'D' */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'D', cap-1);
                pkt->pathname[cap-1] = '\0';
            }else{
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 26: { /* 故意去掉必需空格（协议错误探测） */
            set_space(pkt->space,0);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "no-space.txt");
            break;
        }
        case 27: { /* 空字符串（缺参） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
            break;
        }
        default: return 0;
    }

    return 1;
}



/* 针对 RMD.pathname 的充分变异（主要改 pkt->pathname；必要时也调整 pkt->space） */
int mutate_rmd_pathname(ftp_rmd_packet_t *pkt){
    if(!pkt) return 0;

    /* 轮转式算子选择（可替换为 RNG） */
    static unsigned op_idx = 0;
    const unsigned OPS = 30;
    unsigned op = (op_idx++) % OPS;

    /* 保存原值，便于基于原始输入的就地变形 */
    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— A. 基线与就地变形 —— */
        case 0: { /* A1: 添加尾随斜杠（目录常见写法） */
            set_space(pkt->space,1);
            if (orig[0]) {
                size_t cap = sizeof(pkt->pathname);
                (void)snprintf(pkt->pathname, cap, "%s/", orig);
            } else {
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "logs/");
            }
            break;
        }
        case 1: { /* A2: 分隔符互换（/ <-> \） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/old/");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { /* A3: 大小写翻转（大小写不敏感实现差异） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/Path/To/DEL");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { /* A4: 压缩多重分隔符 */
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b\\\\\\\\c/////";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 4: { /* A5: 在前面加上 ./ */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "./%s", orig[0] ? orig : "tmp");
            break;
        }

        /* —— B. 合法常见目录 —— */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/cache"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./build"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_dir"); break;

        /* —— C. 风险/遍历/边界目录 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".."); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../.."); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/"); break;          /* 根目录 */
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "C:\\\\"); break;     /* Windows 盘根 */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/./."); break;    /* 自指目录 */

        /* —— D. 平台混合/奇怪分隔 —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//to_remove/"); break;

        /* —— E. 特殊名/保留名/通配 —— */
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;   /* Windows 保留名 */
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "PRN "); break;  /* 尾随空格+保留名 */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "aux."); break;  /* 保留名+点 */
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*"); break;     /* 通配符 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir*"); break;

        /* —— F. 空白/引号/尾随点空格 —— */
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced dir "); break;
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted dir\""); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "traildot."); break;

        /* —— G. 编码/Unicode —— */
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old%20dir"); break;           /* URL 编码空格 */
        case 25: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%2e%2e/%2e%2e/escape"); break;/* 编码遍历 */
        case 26: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "删除我"); break;               /* 非 ASCII */

        /* —— H. 控制字符/协议拼接（非法） —— */
        case 27: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "victim\r\nNOOP"); break;

        /* —— I. 长度/协议违规 —— */
        case 28: { /* 极限长度：填满缓冲（全部 'R'） */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'R', cap-1);
                pkt->pathname[cap-1] = '\0';
            } else {
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 29: { /* 去掉必需空格（语法错误）或空参数 */
            if (op_idx & 1){
                set_space(pkt->space,0);                    /* 无空格 */
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "nospaceDir");
            }else{
                set_space(pkt->space,1);
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "");  /* 空 pathname */
            }
            break;
        }

        default: return 0;
    }

    return 1;
}





/* 针对 MKD.pathname 的充分变异（主要改 pkt->pathname；必要时也调整 pkt->space） */
int mutate_mkd_pathname(ftp_mkd_packet_t *pkt){
    if(!pkt) return 0;

    /* 轮转式算子选择（可替换为 RNG） */
    static unsigned op_idx = 0;
    const unsigned OPS = 30;
    unsigned op = (op_idx++) % OPS;

    /* 保存原值，便于基于原始输入的就地变形 */
    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— A. 基线与就地变形 —— */
        case 0: { /* A1: 添加尾随斜杠（目录常见写法） */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s/", orig[0] ? orig : "newdir");
            break;
        }
        case 1: { /* A2: 分隔符互换（/ <-> \） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/new");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { /* A3: 大小写翻转（大小写不敏感实现差异） */
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/Path/To/New");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { /* A4: 压缩多重分隔符 */
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b\\\\\\\\c////new";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 4: { /* A5: 在前面加上 ./ */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "./%s", orig[0] ? orig : "tmp");
            break;
        }

        /* —— B. 合法常见目录 —— */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "newdir"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/newdir"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_new"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "a/b/c/new"); break;

        /* —— C. 风险/遍历/边界目录 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".."); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../new"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../../../../new"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/"); break;          /* 根目录 */
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "C:\\\\new"); break;  /* Windows 盘根 */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "a\\\\b/c//new"); break; /* 平台混合 */

        /* —— D. UNC/网络共享 —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "\\\\server\\share\\newdir"); break;

        /* —— E. 特殊名/保留名/通配 —— */
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;   /* Windows 保留名 */
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "PRN "); break;  /* 尾随空格+保留名 */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "NUL."); break;  /* 保留名+点 */
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*"); break;     /* 通配符 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir*"); break;

        /* —— F. 空白/引号/尾随点空格 —— */
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced dir "); break;
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted dir\""); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "traildot."); break;

        /* —— G. 编码/Unicode —— */
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%2e%2e/new"); break; /* 编码遍历 */
        case 25: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "new%20dir"); break;  /* URL 编码空格 */
        case 26: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "新建目录"); break;     /* 非 ASCII */

        /* —— H. 控制字符/协议拼接（非法） —— */
        case 27: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "new\r\nLIST"); break;

        /* —— I. 长度/协议违规 —— */
        case 28: { /* 极限长度：填满缓冲（全部 'M'） */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'M', cap-1);
                pkt->pathname[cap-1] = '\0';
            } else {
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 29: { /* 去掉必需空格或空实参；或构造很多层级 */
            if ((op_idx & 1) == 0){
                set_space(pkt->space,0);                    /* 无空格：语法错误 */
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "nospaceDir");
            } else if ((op_idx & 2) == 0){
                set_space(pkt->space,1);                    /* 空 pathname：语法错误 */
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
            } else {
                set_space(pkt->space,1);                    /* 过多分段 */
                pkt->pathname[0] = '\0';
                size_t cap = sizeof(pkt->pathname);
                size_t len = 0;
                while (len + 2 < cap){                      /* 反复追加 "/a" */
                    pkt->pathname[len++] = '/';
                    if (len+1 >= cap) break;
                    pkt->pathname[len++] = 'a';
                }
                pkt->pathname[len] = '\0';
            }
            break;
        }

        default: return 0;
    }

    return 1;
}



/* 2) add/delete: 用于显式增加/删除可选 pathname 字段 */
int add_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 1);
    /* 缺省添加列当前目录的常见选项（可按需替换为 "." 或空字符串） */
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "-la");
    return 1;
}

int delete_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 0);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
    return 1;
}

/* 4) 充分变异器：在原始输入基础上做多样化（合法/非法）变异 */
int mutate_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 26;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— 常见合法目标 —— */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;              /* 当前目录 */
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".."); break;             /* 父目录 */
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;              /* 根目录 */
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/www"); break;       /* 绝对路径 */
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "sub/dir"); break;        /* 相对多级 */

        /* —— 服务器常见LIST选项（GNU ls 风格，很多FTP服务端兼容） —— */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-l"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-la"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-alh"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-la /etc"); break;       /* 选项+路径 */

        /* —— 模式/通配 —— */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[a-z]??.c"); break;

        /* —— 空白/引号/带空格目录名 —— */
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"My Folder\""); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "my folder"); break;

        /* —— 平台差异/分隔符混用 —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "C:\\\\Users\\\\Public"); break;
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\\\\server\\share"); break; /* UNC */
        case 17: { set_space(pkt->space,1);
                   set_cstr(pkt->pathname,sizeof(pkt->pathname), orig[0]?orig:"/a/b/c");
                   swap_separators(pkt->pathname);
                   break; }

        /* —— 编码/遍历/特殊字符 —— */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir%20with%20space"); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "%2e%2e/%2e%2e"); break;    /* 编码遍历 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "foo\r\nSTAT"); break;      /* 控制字符注入 */

        /* —— 分隔压缩/混排 —— */
        case 21: { set_space(pkt->space,1);
                   const char *src = orig[0]?orig:"a////b\\\\\\\\c////";
                   collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
                   break; }
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "a\\\\b/c//d"); break;

        /* —— 长度边界/层级爆炸 —— */
        case 23: { /* 极限长度：填满缓冲 */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){ memset(pkt->pathname, 'L', cap-1); pkt->pathname[cap-1]='\0'; }
            else set_cstr(pkt->pathname, cap, "");
            break;
        }
        case 24: { /* 过多层级直到接近上限 */
            set_space(pkt->space,1);
            pkt->pathname[0] = '\0';
            size_t cap = sizeof(pkt->pathname), len = 0;
            while (len + 2 < cap){ pkt->pathname[len++] = '/'; if (len+1>=cap) break; pkt->pathname[len++] = 'a'; }
            pkt->pathname[len] = '\0';
            break;
        }

        /* —— 协议级错误：去掉空格但给出路径 —— */
        case 25: set_space(pkt->space,0); set_cstr(pkt->pathname,sizeof(pkt->pathname), "nospace_arg"); break;

        default: return 0;
    }
    return 1;
}


/*** 2) add/delete: 针对可选 pathname 字段 ***/
int add_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 1);
    /* 缺省给一个常见目标（可改为 "." 或空字符串） */
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "*");
    return 1;
}

int delete_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 0);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
    return 1;
}

/*** 4) 充分变异器（合法/非法混合，覆盖多种场景与边界） ***/
int mutate_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 28;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        /* —— 合法：常见目录与相对/绝对路径 —— */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".."); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/tmp"); break;
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "sub/dir"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "./subdir"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "../other"); break;

        /* —— 合法：名称列表常用通配 —— */
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "file?.c"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[0-9]*"); break;

        /* —— 可能被服务器支持但非标准：选项/组合（非法/兼容性待定） —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-a"); break;     /* 显示隐藏 */
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-R"); break;     /* 递归 */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-a /etc"); break;/* 选项+路径 */

        /* —— 空白/引号/带空格名称 —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"My Folder\""); break;
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "my folder"); break;

        /* —— 平台差异路径 —— */
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "C:\\\\Temp\\\\"); break;
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\\\\server\\share"); break;
        case 19: { set_space(pkt->space,1);
                   set_cstr(pkt->pathname,sizeof(pkt->pathname), orig[0]?orig:"a/b\\c\\d/e");
                   swap_separators(pkt->pathname);
                   break; }

        /* —— 编码/遍历/控制字符注入（非法/畸形） —— */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir%20with%20space"); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "%2e%2e/%2e%2e"); break; /* 编码遍历 */
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "foo\r\nSTAT"); break;   /* 命令注入 */

        /* —— 分隔压缩/混排 —— */
        case 23: { set_space(pkt->space,1);
                   const char *src = orig[0]?orig:"a////b\\\\\\\\c////";
                   collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
                   break; }
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "a\\\\b/c//d"); break;

        /* —— 长度与层级边界 —— */
        case 25: { /* 极限长度填充 */
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){ memset(pkt->pathname, 'N', cap-1); pkt->pathname[cap-1]='\0'; }
            else set_cstr(pkt->pathname, cap, "");
            break;
        }
        case 26: { /* 层级爆炸直至接近上限 */
            set_space(pkt->space,1);
            pkt->pathname[0] = '\0';
            size_t cap = sizeof(pkt->pathname), len = 0;
            while (len + 2 < cap){ pkt->pathname[len++] = '/'; if (len+1>=cap) break; pkt->pathname[len++] = 'n'; }
            pkt->pathname[len] = '\0';
            break;
        }

        /* —— 协议级故障：不给空格却有实参 —— */
        case 27: set_space(pkt->space,0); set_cstr(pkt->pathname,sizeof(pkt->pathname), "nospace_arg"); break;

        default: return 0;
    }
    return 1;
}




/* 压缩多空白为单空格 */
static void squeeze_spaces(const char *src, char *dst, size_t cap){
    if (!src || !dst || cap == 0) return;
    size_t i=0; int in_space=0;
    for (size_t j=0; src[j] && i+1<cap; ++j){
        char c = src[j];
        if (c==' ' || c=='\t'){
            if (!in_space){ dst[i++]=' '; in_space=1; }
        }else{
            dst[i++]=c; in_space=0;
        }
    }
    dst[i]='\0';
}

/*** 充分变异器（轮转执行多种算子；必要时也会对 space 做非法变异） ***/
int mutate_site_parameters(ftp_site_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PARAMS];
    set_cstr(orig, sizeof(orig), pkt->parameters);

    switch (op){
        /* —— 合法：常见子命令 —— */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "HELP"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "HELP CHMOD"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 755 /var/tmp/file"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 000 \"My File.txt\""); break;
        case 4:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "UMASK 022"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "UMASK 077"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE 0"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE 3600"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SETTYPE A"); break;   /* ASCII */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SETTYPE I"); break;   /* Binary/Image */
        case 10: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "ZONE +0800"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "EXEC echo ping"); break; /* 相对安全 */

        /* —— 合法但“非典型/边角” —— */
        case 12: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHGRP staff /srv/data"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SYMLINK /srv/a /srv/b"); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "MSG Hello World"); break;

        /* —— 格式/空白/大小写相关 —— */
        case 15: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "   chmod    644\tfoo.txt  "); squeeze_spaces(pkt->parameters, pkt->parameters, sizeof(pkt->parameters)); break;
        case 16: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), orig[0]?orig:"ChMoD 7a5 bad"); toggle_case(pkt->parameters); break;
        case 17: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "\"Folder With Spaces\""); break;
        case 18: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD\t700\tfolder"); break;

        /* —— 数值边界/类型错误 —— */
        case 19: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "UMASK 999"); break;   /* 超范围 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE -10"); break;   /* 负数 */
        case 21: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE 3.14159"); break; /* 浮点 */
        case 22: { /* 极长数字（溢出） */
            set_space(pkt->space,1);
            memset(pkt->parameters, '9', sizeof(pkt->parameters)-1);
            pkt->parameters[sizeof(pkt->parameters)-1] = '\0';
            break;
        }

        /* —— 编码/奇异字符/国际化 —— */
        case 23: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 640 /path/with%20space"); break;
        case 24: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 755 /数据/文件"); break; /* UTF-8 */
        case 25: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SETTYPE X"); break;  /* 非法类型 */

        /* —— 注入/控制字符/协议畸形 —— */
        case 26: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "HELP\r\nSTAT"); break; /* CRLF 注入 */
        case 27: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 700 ../../tmp/x"); break; /* 遍历意图 */
        case 28: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "JSON {\"cmd\":\"CHMOD\",\"mode\":511,\"path\":\"/var/tmp/x\"}"); break;
        case 29: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "KEY=VALUE;MODE=755;PATH=/var/tmp/x"); break;

        /* —— 长度边界/缓冲类 —— */
        case 30: { /* 充满 A 的极限长度 */
            set_space(pkt->space,1);
            memset(pkt->parameters, 'A', sizeof(pkt->parameters)-1);
            pkt->parameters[sizeof(pkt->parameters)-1] = '\0';
            break;
        }
        case 31: { /* 协议级错误：去掉必须空格（构造异常帧） */
            set_space(pkt->space,0);
            set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 600 /no/space/prefix");
            break;
        }

        default: return 0;
    }
    return 1;
}


/* —— 可选字段 mutators —— */
void add_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return;
    set_space(pkt->space, 1);                        /* 有参数时一般需要空格 */
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/log");
}

void delete_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return;
    set_cstr(pkt->pathname, sizeof(pkt->pathname), ""); /* 清空参数 */
    set_space(pkt->space, 0);                            /* 同时移除可选空格 */
}

/* —— 充分变异器：轮转多种算子 —— */
int mutate_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch (op){
        /* 合法：典型路径/模式 */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/log/syslog"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir/subdir/file.txt"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[a-zA-Z]*.log"); break;

        /* 平台/路径风格差异 */
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\\\\SERVER\\share\\folder\\file"); break;

        /* 空白/引号/转义 */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"My Folder/file name.txt\""); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "path/with%20space"); break;

        /* 遍历/可疑路径 */
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "../../etc/passwd"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "////a///b//c/"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "./././target"); break;

        /* 非 ASCII / UTF-8 */
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/数据/文件.txt"); break;
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/tmp/😀.txt"); break;

        /* 长度/缓冲边界 */
        case 16: { /* 极限长度填充 */
            set_space(pkt->space,1);
            memset(pkt->pathname, 'A', sizeof(pkt->pathname)-1);
            pkt->pathname[sizeof(pkt->pathname)-1] = '\0';
            break;
        }
        case 17: { /* 深层嵌套 */
            set_space(pkt->space,1);
            char *p = pkt->pathname; size_t cap = sizeof(pkt->pathname); size_t used = 0;
            const char *seg = "deep/";
            while (used + strlen(seg) + 1 < cap){ strcpy(p+used, seg); used += strlen(seg); }
            if (used+5 < cap) strcpy(p+used, "end");
            break;
        }

        /* 控制字符/注入 */
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "path\r\nANOTHER"); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/tmp/\x1b[31mred\x1b[0m"); break;

        /* 特殊文件/保留名 */
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/dev/null"); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "NUL"); break;

        /* Shell/扩展风格（服务端应当当作普通字符串或拒绝） */
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "~/file"); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "$HOME/.ssh/id_rsa"); break;
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "file{1..100}"); break;

        /* 空白边界/裁剪相关 */
        case 25: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "  trailing-space  "); break;

        /* 基于原值的微扰（保留/利用已有测试用例） */
        case 26: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), orig[0]?orig:"relative.txt"); toggle_case(pkt->pathname); break;

        /* 协议畸形：带路径但去掉空格（测试解析器健壮性） */
        case 27: set_space(pkt->space,0); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/no/leading/space"); break;

        /* 其他边角 */
        case 28: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"unterminated"); break;
        case 29: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "path/with#hash?query=1"); break;
        case 30: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "CONIN$"); break;
        case 31: /* 无参数形态：即“STAT”纯服务器状态 */
                 set_space(pkt->space,0); set_cstr(pkt->pathname,sizeof(pkt->pathname), ""); break;

        default: return 0;
    }
    return 1;
}


/* —— 可选字段 mutators —— */
void add_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return;
    set_space(pkt->space, 1);                        /* 有参数→需要空格 */
    set_cstr(pkt->argument, sizeof(pkt->argument), "USER");
}

void delete_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return;
    set_cstr(pkt->argument, sizeof(pkt->argument), ""); /* 清空参数 */
    set_space(pkt->space, 0);                            /* 同步移除空格 */
}

/* —— 充分变异器：覆盖多维度（合法/非法） —— */
int mutate_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_ARGUMENT];
    set_cstr(orig, sizeof(orig), pkt->argument);

    switch (op){
        /* 合法：典型命令名/关键词 */
        case 0:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "STAT"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "RETR"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "abor"); break; /* 小写合法 */

        /* 非法/未知命令名 */
        case 4:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "FOO"); break;

        /* 多词参数（某些实现会显示子帮助或当作一串文字） */
        case 5:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "SITE CHMOD"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER PASS"); break;

        /* 通配/占位符/疑问 */
        case 7:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "*"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "?"); break;

        /* 数字/标志风格 */
        case 9:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "12345"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "-h"); break;

        /* 非 ASCII / UTF-8 */
        case 11: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "帮助"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "📄"); break;

        /* 控制字符 / 注入 */
        case 13: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\r\nQUIT"); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "ABOR\tRETR"); break;
        case 15: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "ESC:\x1b[31mRED\x1b[0m"); break;

        /* 长度/缓冲边界 */
        case 16: {
            set_space(pkt->space,1);
            memset(pkt->argument, 'A', sizeof(pkt->argument)-1);
            pkt->argument[sizeof(pkt->argument)-1] = '\0';
            break;
        }

        /* 引号/未闭合字符串 */
        case 17: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "\"unterminated"); break;
        case 18: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\"PASS"); break;

        /* 百分号编码/可疑内容 */
        case 19: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "PASV%0AQUIT"); break;

        /* 边界空白（前后空格、仅空白） */
        case 20: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "  USER  "); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "   "); break;

        /* 协议畸形：有参数但去掉前导空格；或有空格但空参数 */
        case 22: set_space(pkt->space,0); set_cstr(pkt->argument,sizeof(pkt->argument), "USER"); break; /* 缺少必要空格 */
        case 23: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), ""); break;     /* 多余空格 */

        /* 特殊符号/分隔 */
        case 24: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER,RETR"); break;
        case 25: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "!@#$%^&*()"); break;

        /* 路径/奇异文本（有实现会把它当普通文本显示） */
        case 26: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "/etc/passwd"); break;

        /* 类似注入的无害字符串（测试过滤/显示） */
        case 27: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "'; DROP TABLE"); break;

        /* 递用 HELP 自身 / 大小写扰动（基于原值） */
        case 28: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "HELP"); break;
        case 29: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), orig[0]?orig:"stor"); toggle_case(pkt->argument); break;

        /* 制表/换行混合与多词 */
        case 30: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\tPASS LIST"); break;

        /* 组合用例：长 Unicode（含组合音符） */
        case 31: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "caf\u0301e"); break;

        default: return 0;
    }
    return 1;
}


#define ARR_CNT(a) (int)(sizeof(a)/sizeof((a)[0]))
static inline uint32_t rnd32(void){
    /* 粗略拼接两次 rand() 以得到 32-bit 种子 */
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

/* ============== 统一包装：把不同签名适配成 (pkt, int) ============== */
/* USER */
typedef void (*user_mutator_fn)(ftp_user_packet_t*, int);
static void w_user_username(ftp_user_packet_t *p, int n){ (void)n; (void)mutate_user_username(p, rnd32(), -1); }

/* PASS */
typedef void (*pass_mutator_fn)(ftp_pass_packet_t*, int);
static void w_pass_password(ftp_pass_packet_t *p, int n){ (void)n; (void)mutate_pass_password(p, rnd32(), -1); }

/* ACCT */
typedef void (*acct_mutator_fn)(ftp_acct_packet_t*, int);
static void w_acct_account_info(ftp_acct_packet_t *p, int n){ (void)n; (void)mutate_acct_account_info(p, rnd32(), -1); }

/* CWD/SMNT */
typedef void (*cwd_mutator_fn)(ftp_cwd_packet_t*, int);
static void w_cwd_pathname(ftp_cwd_packet_t *p, int n){ (void)n; (void)mutate_cwd_pathname(p, rnd32(), -1); }
typedef void (*smnt_mutator_fn)(ftp_smnt_packet_t*, int);
static void w_smnt_pathname(ftp_smnt_packet_t *p, int n){ (void)n; (void)mutate_smnt_pathname(p, rnd32(), -1); }

/* PORT */
typedef void (*port_mutator_fn)(ftp_port_packet_t*, int);
static void w_port_host_port(ftp_port_packet_t *p, int n){ (void)n; (void)mutate_port_host_port_str(p, rnd32(), -1); }

/* TYPE */
typedef void (*type_mutator_fn)(ftp_type_packet_t*, int);
static void w_type_type_code(ftp_type_packet_t *p, int n){ (void)n; (void)mutate_type_type_code(p, rnd32(), -1); }
static void w_type_format_control(ftp_type_packet_t *p, int n){ (void)n; (void)mutate_type_format_control(p, rnd32(), -1); }
static void w_add_type_fc(ftp_type_packet_t *p, int n){ (void)n; add_type_format_control(p, "N"); }
static void w_del_type_fc(ftp_type_packet_t *p, int n){ (void)n; delete_type_format_control(p); }

/* STRU / MODE */
typedef void (*stru_mutator_fn)(ftp_stru_packet_t*, int);
static void w_stru(ftp_stru_packet_t *p, int n){ (void)n; (void)mutate_stru_structure_code(p, rnd32(), -1); }
typedef void (*mode_mutator_fn)(ftp_mode_packet_t*, int);
static void w_mode(ftp_mode_packet_t *p, int n){ (void)n; (void)mutate_mode_mode_code(p, rnd32(), -1); }

/* RETR / STOR / STOU / APPE */
typedef void (*retr_mutator_fn)(ftp_retr_packet_t*, int);
static void w_retr(ftp_retr_packet_t *p, int n){ (void)n; (void)mutate_retr_pathname(p, rnd32(), -1); }
typedef void (*stor_mutator_fn)(ftp_stor_packet_t*, int);
static void w_stor(ftp_stor_packet_t *p, int n){ (void)n; (void)mutate_stor_pathname(p, rnd32(), -1); }
typedef void (*stou_mutator_fn)(ftp_stou_packet_t*, int);
static void w_stou_mutate(ftp_stou_packet_t *p, int n){ (void)n; (void)mutate_stou_pathname(p, rnd32(), -1); }
static void w_stou_add(ftp_stou_packet_t *p, int n){ (void)n; (void)add_stou_pathname(p, NULL); }
static void w_stou_del(ftp_stou_packet_t *p, int n){ (void)n; (void)delete_stou_pathname(p); }
typedef void (*appe_mutator_fn)(ftp_appe_packet_t*, int);
static void w_appe(ftp_appe_packet_t *p, int n){ (void)n; (void)mutate_appe_pathname(p, rnd32(), -1); }

/* ALLO */
typedef void (*allo_mutator_fn)(ftp_allo_packet_t*, int);
static void w_allo_bc(ftp_allo_packet_t *p, int n){ (void)n; (void)mutate_allo_byte_count(p, rnd32(), -1); }
static void w_allo_rf_mut(ftp_allo_packet_t *p, int n){ (void)n; (void)mutate_allo_record_format(p); }
static void w_allo_rf_add(ftp_allo_packet_t *p, int n){ (void)n; (void)add_allo_record_format(p); }
static void w_allo_rf_del(ftp_allo_packet_t *p, int n){ (void)n; (void)delete_allo_record_format(p); }

/* REST / RNFR / RNTO / DELE / RMD / MKD */
typedef void (*rest_mutator_fn)(ftp_rest_packet_t*, int);
static void w_rest(ftp_rest_packet_t *p, int n){ (void)n; (void)mutate_rest_marker(p); }

typedef void (*rnfr_mutator_fn)(ftp_rnfr_packet_t*, int);
static void w_rnfr(ftp_rnfr_packet_t *p, int n){ (void)n; (void)mutate_rnfr_pathname(p); }

typedef void (*rnto_mutator_fn)(ftp_rnto_packet_t*, int);
static void w_rnto(ftp_rnto_packet_t *p, int n){ (void)n; (void)mutate_rnto_pathname(p); }

typedef void (*dele_mutator_fn)(ftp_dele_packet_t*, int);
static void w_dele(ftp_dele_packet_t *p, int n){ (void)n; (void)mutate_dele_pathname(p); }

typedef void (*rmd_mutator_fn)(ftp_rmd_packet_t*, int);
static void w_rmd(ftp_rmd_packet_t *p, int n){ (void)n; (void)mutate_rmd_pathname(p); }

typedef void (*mkd_mutator_fn)(ftp_mkd_packet_t*, int);
static void w_mkd(ftp_mkd_packet_t *p, int n){ (void)n; (void)mutate_mkd_pathname(p); }

/* 如你有 LIST / NLST / STAT / SITE / HELP，可追加对应 wrapper */
typedef void (*list_mutator_fn)(ftp_list_packet_t*, int);
static void w_list_pathname(ftp_list_packet_t *p, int n){ (void)n; (void)mutate_list_pathname(p); } 
typedef void (*nlst_mutator_fn)(ftp_nlst_packet_t*, int);
static void w_nlst_pathname(ftp_nlst_packet_t *p, int n){ (void)n; (void)mutate_nlst_pathname(p); }
typedef void (*stat_mutator_fn)(ftp_stat_packet_t*, int);
static void w_stat_pathname(ftp_stat_packet_t *p, int n){ (void)n; (void)mutate_stat_pathname(p); }
typedef void (*site_mutator_fn)(ftp_site_packet_t*, int);
static void w_site_parameters(ftp_site_packet_t *p, int n){ (void)n; (void)mutate_site_parameters(p); }
typedef void (*help_mutator_fn)(ftp_help_packet_t*, int);
static void w_help_argument(ftp_help_packet_t *p, int n){ (void)n; (void)mutate_help_argument(p); } 

/* ============== 每类 mutator 列表（可自由增删项） ============== */
static user_mutator_fn user_mutators[] = {
    w_user_username,
};
static pass_mutator_fn pass_mutators[] = {
    w_pass_password,
};
static acct_mutator_fn acct_mutators[] = {
    w_acct_account_info,
};

static cwd_mutator_fn  cwd_mutators[]  = { w_cwd_pathname };
static smnt_mutator_fn smnt_mutators[] = { w_smnt_pathname };

static port_mutator_fn port_mutators[] = { w_port_host_port };

static type_mutator_fn type_mutators[] = {
    w_type_type_code,
    w_type_format_control,
    w_add_type_fc,
    w_del_type_fc,
};

static stru_mutator_fn stru_mutators[] = { w_stru };
static mode_mutator_fn mode_mutators[] = { w_mode };

static retr_mutator_fn retr_mutators[] = { w_retr };
static stor_mutator_fn stor_mutators[] = { w_stor };

static stou_mutator_fn stou_mutators[] = {
    w_stou_mutate,
    w_stou_add,
    w_stou_del,
};

static appe_mutator_fn appe_mutators[] = { w_appe };

static allo_mutator_fn allo_mutators[] = {
    w_allo_bc,
    w_allo_rf_mut,
    w_allo_rf_add,
    w_allo_rf_del,
};

static rest_mutator_fn rest_mutators[] = { w_rest };
static rnfr_mutator_fn rnfr_mutators[] = { w_rnfr };
static rnto_mutator_fn rnto_mutators[] = { w_rnto };
static dele_mutator_fn dele_mutators[] = { w_dele };
static rmd_mutator_fn  rmd_mutators[]  = { w_rmd };
static mkd_mutator_fn  mkd_mutators[]  = { w_mkd };

static list_mutator_fn list_mutators[] = { w_list_pathname };
static nlst_mutator_fn nlst_mutators[] = { w_nlst_pathname };
static stat_mutator_fn stat_mutators[] = { w_stat_pathname };
static site_mutator_fn site_mutators[] = { w_site_parameters };
static help_mutator_fn help_mutators[] = { w_help_argument };   

/* ============== 计数宏 ============== */
#define USER_MUTATOR_COUNT  ARR_CNT(user_mutators)
#define PASS_MUTATOR_COUNT  ARR_CNT(pass_mutators)
#define ACCT_MUTATOR_COUNT  ARR_CNT(acct_mutators)

#define CWD_MUTATOR_COUNT   ARR_CNT(cwd_mutators)
#define SMNT_MUTATOR_COUNT  ARR_CNT(smnt_mutators)
#define PORT_MUTATOR_COUNT  ARR_CNT(port_mutators)

#define TYPE_MUTATOR_COUNT  ARR_CNT(type_mutators)
#define STRU_MUTATOR_COUNT  ARR_CNT(stru_mutators)
#define MODE_MUTATOR_COUNT  ARR_CNT(mode_mutators)

#define RETR_MUTATOR_COUNT  ARR_CNT(retr_mutators)
#define STOR_MUTATOR_COUNT  ARR_CNT(stor_mutators)
#define STOU_MUTATOR_COUNT  ARR_CNT(stou_mutators)
#define APPE_MUTATOR_COUNT  ARR_CNT(appe_mutators)

#define ALLO_MUTATOR_COUNT  ARR_CNT(allo_mutators)

#define REST_MUTATOR_COUNT  ARR_CNT(rest_mutators)
#define RNFR_MUTATOR_COUNT  ARR_CNT(rnfr_mutators)
#define RNTO_MUTATOR_COUNT  ARR_CNT(rnto_mutators)
#define DELE_MUTATOR_COUNT  ARR_CNT(dele_mutators)
#define RMD_MUTATOR_COUNT   ARR_CNT(rmd_mutators)
#define MKD_MUTATOR_COUNT   ARR_CNT(mkd_mutators)
#define LIST_MUTATOR_COUNT  ARR_CNT(list_mutators)
#define NLST_MUTATOR_COUNT  ARR_CNT(nlst_mutators)
#define STAT_MUTATOR_COUNT  ARR_CNT(stat_mutators)
#define SITE_MUTATOR_COUNT  ARR_CNT(site_mutators)
#define HELP_MUTATOR_COUNT  ARR_CNT(help_mutators)  

/* ============== 单类随机调度 ============== */
static inline void dispatch_user_mutation (ftp_user_packet_t *p, int n){ if(!p) return; user_mutators[rand()%USER_MUTATOR_COUNT](p,1); }
static inline void dispatch_pass_mutation (ftp_pass_packet_t *p, int n){ if(!p) return; pass_mutators[rand()%PASS_MUTATOR_COUNT](p,1); }
static inline void dispatch_acct_mutation (ftp_acct_packet_t *p, int n){ if(!p) return; acct_mutators[rand()%ACCT_MUTATOR_COUNT](p,1); }

static inline void dispatch_cwd_mutation  (ftp_cwd_packet_t  *p, int n){ if(!p) return;  cwd_mutators[rand()%CWD_MUTATOR_COUNT](p,1); }
static inline void dispatch_smnt_mutation (ftp_smnt_packet_t *p, int n){ if(!p) return; smnt_mutators[rand()%SMNT_MUTATOR_COUNT](p,1); }
static inline void dispatch_port_mutation (ftp_port_packet_t *p, int n){ if(!p) return; port_mutators[rand()%PORT_MUTATOR_COUNT](p,1); }

static inline void dispatch_type_mutation (ftp_type_packet_t *p, int n){ if(!p) return; type_mutators[rand()%TYPE_MUTATOR_COUNT](p,1); }
static inline void dispatch_stru_mutation (ftp_stru_packet_t *p, int n){ if(!p) return;  stru_mutators[rand()%STRU_MUTATOR_COUNT](p,1); }
static inline void dispatch_mode_mutation (ftp_mode_packet_t *p, int n){ if(!p) return;  mode_mutators[rand()%MODE_MUTATOR_COUNT](p,1); }

static inline void dispatch_retr_mutation (ftp_retr_packet_t *p, int n){ if(!p) return; retr_mutators[rand()%RETR_MUTATOR_COUNT](p,1); }
static inline void dispatch_stor_mutation (ftp_stor_packet_t *p, int n){ if(!p) return; stor_mutators[rand()%STOR_MUTATOR_COUNT](p,1); }
static inline void dispatch_stou_mutation (ftp_stou_packet_t *p, int n){ if(!p) return; stou_mutators[rand()%STOU_MUTATOR_COUNT](p,1); }
static inline void dispatch_appe_mutation (ftp_appe_packet_t *p, int n){ if(!p) return; appe_mutators[rand()%APPE_MUTATOR_COUNT](p,1); }

static inline void dispatch_allo_mutation (ftp_allo_packet_t *p, int n){ if(!p) return; allo_mutators[rand()%ALLO_MUTATOR_COUNT](p,1); }

static inline void dispatch_rest_mutation (ftp_rest_packet_t *p, int n){ if(!p) return; rest_mutators[rand()%REST_MUTATOR_COUNT](p,1); }
static inline void dispatch_rnfr_mutation (ftp_rnfr_packet_t *p, int n){ if(!p) return; rnfr_mutators[rand()%RNFR_MUTATOR_COUNT](p,1); }
static inline void dispatch_rnto_mutation (ftp_rnto_packet_t *p, int n){ if(!p) return; rnto_mutators[rand()%RNTO_MUTATOR_COUNT](p,1); }
static inline void dispatch_dele_mutation (ftp_dele_packet_t *p, int n){ if(!p) return; dele_mutators[rand()%DELE_MUTATOR_COUNT](p,1); }
static inline void dispatch_rmd_mutation  (ftp_rmd_packet_t  *p, int n){ if(!p) return;  rmd_mutators[rand()%RMD_MUTATOR_COUNT](p,1); }
static inline void dispatch_mkd_mutation  (ftp_mkd_packet_t  *p, int n){ if(!p) return;  mkd_mutators[rand()%MKD_MUTATOR_COUNT](p,1); }

static inline void dispatch_list_mutation (ftp_list_packet_t *p, int n){ if(!p) return; list_mutators[rand()%LIST_MUTATOR_COUNT](p,1); }
static inline void dispatch_nlst_mutation (ftp_nlst_packet_t *p, int n){ if(!p) return; nlst_mutators[rand()%NLST_MUTATOR_COUNT](p,1); }
static inline void dispatch_stat_mutation (ftp_stat_packet_t *p, int n){ if(!p) return; stat_mutators[rand()%STAT_MUTATOR_COUNT](p,1); }
static inline void dispatch_site_mutation (ftp_site_packet_t *p, int n){ if(!p) return; site_mutators[rand()%SITE_MUTATOR_COUNT](p,1); }
static inline void dispatch_help_mutation (ftp_help_packet_t *p, int n){ if(!p) return; help_mutators[rand()%HELP_MUTATOR_COUNT](p,1); }

/* ============== 顶层多轮调度（与 MQTT 版本同构） ============== */
void dispatch_ftp_multiple_mutations(ftp_packet_t *pkt, int num_packets, int rounds) {
    if (!pkt || num_packets <= 0 || rounds <= 0) return;

    for (int r = 0; r < rounds; ++r) {
        int idx = rand() % num_packets;
        ftp_packet_t *P = &pkt[idx];

        switch (P->command_type) {
            /* 帐号阶段 */
            case FTP_USER: dispatch_user_mutation(&P->packet.user, 1); break;
            case FTP_PASS: dispatch_pass_mutation(&P->packet.pass, 1); break;
            case FTP_ACCT: dispatch_acct_mutation(&P->packet.acct, 1); break;

            /* 路径/目录相关（必参/可疑路径等） */
            case FTP_CWD:  dispatch_cwd_mutation (&P->packet.cwd, 1);  break;
            case FTP_SMNT: dispatch_smnt_mutation(&P->packet.smnt, 1); break;

            /* 数据连接控制 */
            case FTP_PORT: dispatch_port_mutation(&P->packet.port, 1); break;
            case FTP_TYPE: dispatch_type_mutation(&P->packet.type, 1); break;
            case FTP_STRU: dispatch_stru_mutation(&P->packet.stru, 1); break;
            case FTP_MODE: dispatch_mode_mutation(&P->packet.mode, 1); break;

            /* 文件传输目标 */
            case FTP_RETR: dispatch_retr_mutation(&P->packet.retr, 1); break;
            case FTP_STOR: dispatch_stor_mutation(&P->packet.stor, 1); break;
            case FTP_STOU: dispatch_stou_mutation(&P->packet.stou, 1); break;
            case FTP_APPE: dispatch_appe_mutation(&P->packet.appe, 1); break;

            /* 分配/断点续传 */
            case FTP_ALLO: dispatch_allo_mutation(&P->packet.allo, 1); break;
            case FTP_REST: dispatch_rest_mutation(&P->packet.rest, 1); break;

            /* 重命名/删除/目录操作 */
            case FTP_RNFR: dispatch_rnfr_mutation(&P->packet.rnfr, 1); break;
            case FTP_RNTO: dispatch_rnto_mutation(&P->packet.rnto, 1); break;
            case FTP_DELE: dispatch_dele_mutation(&P->packet.dele, 1); break;
            case FTP_RMD:  dispatch_rmd_mutation (&P->packet.rmd, 1);  break;
            case FTP_MKD:  dispatch_mkd_mutation (&P->packet.mkd, 1);  break;

            /* 其余命令（如 PASV/CDUP/QUIT/NOOP/PWD/SYST 等）当前未挂接变异器，可按需补充 */
            case FTP_LIST: dispatch_list_mutation(&P->packet.list, 1); break;
            case FTP_NLST: dispatch_nlst_mutation(&P->packet.nlst, 1); break;
            case FTP_STAT: dispatch_stat_mutation(&P->packet.stat, 1); break;
            case FTP_SITE: dispatch_site_mutation(&P->packet.site, 1); break;
            case FTP_HELP: dispatch_help_mutation(&P->packet.help, 1); break;

            default:
                break;
        }
    }
}