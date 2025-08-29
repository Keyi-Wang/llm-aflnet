/* smtp mutators source file */
#include "smtp.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>


/* —— 安全写入到定长数组 —— */
static void set_cstr(char dst[], size_t cap, const char *s){
    if (!dst || cap == 0) return;
    if (!s) s = "";
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, s, n);
    dst[n] = '\0';
}

/* 生成长度为 len 的单一字符段，写入 dst（不含终止符）；返回写入的字符数 */
static size_t emit_run(char *dst, size_t cap, char ch, size_t len){
    if (!dst || cap == 0) return 0;
    size_t n = len < (cap-1) ? len : (cap-1);
    memset(dst, (unsigned char)ch, n);
    dst[n] = '\0';
    return n;
}

/* 切换大小写（就地） */
static void toggle_case(char *s){
    if (!s) return;
    for (; *s; ++s){
        unsigned char c = (unsigned char)*s;
        if (c >= 'a' && c <= 'z') *s = (char)toupper(c);
        else if (c >= 'A' && c <= 'Z') *s = (char)tolower(c);
    }
}

/* 构造由若干 label 组成的域名，每个 label 用同一字符填充（尽量贴近 cap 限制） */
static void build_multilabel(char *dst, size_t cap,
                             size_t labels, size_t label_len, char base_ch){
    if (!dst || cap == 0){ return; }
    size_t pos = 0;
    for (size_t i = 0; i < labels; ++i){
        /* label 字符，随 i 稍微变化，避免全同 */
        char ch = (char)(base_ch + (i % 10));
        for (size_t j = 0; j < label_len && pos + 1 < cap; ++j){
            dst[pos++] = ch;
        }
        if (i + 1 < labels && pos + 1 < cap){
            dst[pos++] = '.';
        }
    }
    dst[pos < cap ? pos : cap-1] = '\0';
}

/* —— 充分变异器：对所有 HELO 的 domain 做轮转变异 —— */
int mutate_helo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    /* 变异算子设计（合法 + 畸形） */
    enum { OPS = 21 };
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELO) continue;

        smtp_helo_packet_t *h = &pkts[i].pkt.helo;

        /* 确保 command/space 形态看起来像 HELO（仅防御性，核心仍然变 domain） */
        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "HELO");
        if (h->space[0] == '\0')   set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* —— 合法形态 —— */
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "example.com."); break; /* 带根点（有些实现接受） */
            case 3:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break;  /* 地址字面量（IPv4） */
            case 4:  set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break; /* IPv6 literal（规范） */
            case 5: { /* 多级短标签 */
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); /* aaa.bbb.ccc... */
                break;
            }
            case 6: { /* 更长但仍在边界内（接近 255）*/
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x'); /* 30 字符 label × 4 */
                break;
            }

            /* —— 边界 / 违规形态 —— */
            case 7: { /* label=63 字符（极限合法），再拼 .com */
                char tmp[SMTP_SZ_DOMAIN];
                size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'a', 63);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                const char *com = "com";
                size_t l = strlen(com);
                if (pos + l < sizeof(tmp)){
                    memcpy(tmp+pos, com, l); pos += l;
                }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 8: { /* label>63（不合法） */
                char tmp[SMTP_SZ_DOMAIN];
                size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64); /* 64 超限 */
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)) { tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 9:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;           /* 连续点 */
            case 10: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;       /* 以连字符开头的 label */
            case 11: set_cstr(h->domain, sizeof h->domain, ""); break;               /* 空域名（缺参） */
            case 12: set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;      /* 裸 IPv4（按规范应使用 [ ]） */
            case 13: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;          /* 缺少 IPv6: 前缀（很多实现拒绝） */
            case 14: set_cstr(h->domain, sizeof h->domain, "[IPv6:]"); break;        /* IPv6 空字面量 */
            case 15: set_cstr(h->domain, sizeof h->domain, "[127.0.0.1"); break;     /* 括号不配对 */
            case 16: { /* 注入控制字符（CRLF） */
                set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>");
                break;
            }
            case 17: set_cstr(h->domain, sizeof h->domain, "my host"); break;        /* 含空格（无效） */
            case 18: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break;/* Punycode（IDNA） */
            case 19: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;      /* 直写 UTF-8（部分实现拒绝） */
            case 20: { /* 极限长度填充，触达缓冲区边界 */
                size_t cap = sizeof h->domain;
                if (cap > 1){
                    memset(h->domain, 'D', cap-1);
                    h->domain[cap-1] = '\0';
                }else{
                    h->domain[0] = '\0';
                }
                break;
            }
            default: break;
        }

        /* 再给一个大小写扰动的机会（对合法字符串也有意义） */
        if (op % 5 == 0 && h->domain[0]){
            toggle_case(h->domain);
        }

        mutated++;
    }

    return (int)mutated; /* 返回被变异的 HELO 个数 */
}



/* —— 充分变异器：对所有 EHLO 的 domain 做轮转变异 —— */
int mutate_ehlo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 22 }; /* >= 10，含合法+非法多种形态 */
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EHLO) continue;

        smtp_ehlo_packet_t *h = &pkts[i].pkt.ehlo;

        /* 防御性补全命令与空格 */
        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "EHLO");
        if (h->space[0]   == '\0') set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* —— 合法/常见 —— */
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "example.com."); break; /* 末尾根点 */
            case 3:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break;  /* IPv4 字面量 */
            case 4:  set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break; /* IPv6 字面量 */
            case 5: { set_cstr(h->domain, sizeof h->domain, "");
                      build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); break; }
            case 6: { set_cstr(h->domain, sizeof h->domain, "");
                      build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x'); break; }

            /* —— 边界/违规 —— */
            case 7: { /* label 恰好 63 */
                char tmp[SMTP_SZ_DOMAIN]; size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'a', 63);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                const char *com = "com";
                size_t l = strlen(com);
                if (pos + l < sizeof(tmp)){ memcpy(tmp+pos, com, l); pos += l; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 8: { /* label 64（非法） */
                char tmp[SMTP_SZ_DOMAIN]; size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)){ tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 9:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;           /* 连续点 */
            case 10: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;       /* 以连字符开头 */
            case 11: set_cstr(h->domain, sizeof h->domain, ""); break;               /* 缺参（必填→非法） */
            case 12: set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;      /* 裸 IPv4（非字面量） */
            case 13: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;          /* 无 IPv6: 前缀 */
            case 14: set_cstr(h->domain, sizeof h->domain, "[IPv6:]"); break;        /* 空 IPv6 */
            case 15: set_cstr(h->domain, sizeof h->domain, "[127.0.0.1"); break;     /* 括号不配对 */
            case 16: set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>"); break; /* CRLF 注入 */
            case 17: set_cstr(h->domain, sizeof h->domain, "my host"); break;        /* 含空格 */
            case 18: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break;/* Punycode */
            case 19: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;      /* 直写 UTF-8 */
            case 20: { /* 极限长度填满缓冲 */
                size_t cap = sizeof h->domain;
                if (cap > 1){ memset(h->domain, 'D', cap-1); h->domain[cap-1] = '\0'; }
                else h->domain[0] = '\0';
                break;
            }
            case 21: set_cstr(h->domain, sizeof h->domain, "[IPv6:GGGG::1]"); break; /* 非法十六进制 */
            default: break;
        }

        /* 偶尔扰动大小写（对 FQDN 形态有时仍被接受） */
        if (op % 5 == 0 && h->domain[0]) toggle_case(h->domain);

        mutated++;
    }

    return (int)mutated;  /* 返回被变异的 EHLO 数量 */
}



/* 构造 label 重复的长域名（尽量靠近总长上限），结果写入 out（不带尖括号） */
static void build_long_domain(char *out, size_t cap){
    if (!out || cap == 0) return;
    /* 63 长度的 label 多个 + ".com" */
    const char *tail = "com";
    size_t pos = 0;
    while (pos + 63 + 1 + strlen(tail) + 1 < cap) {
        memset(out + pos, 'a', 63); pos += 63;
        out[pos++] = '.';
    }
    /* 收尾 */
    if (pos + 3 < cap) { memcpy(out+pos, tail, 3); pos += 3; }
    out[pos < cap ? pos : cap-1] = '\0';
}

/* 构造近 64 长 local-part */
static void build_long_local(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = (cap-1 > 64 ? 64 : cap-1);
    memset(out, 'L', n ? n-1 : 0);
    if (n) out[n-1] = 'x';
    out[n] = '\0';
}

/* 确保 MAIL 前缀三元组为规范形态：command="MAIL", space1=" ", from_keyword="FROM:" */
static void ensure_mail_prefix(smtp_mail_packet_t *m){
    if (!m) return;
    if (m->command[0] == '\0') set_cstr(m->command, sizeof m->command, "MAIL");
    if (m->space1[0]  == '\0') set_cstr(m->space1,  sizeof m->space1,  " ");
    if (m->from_keyword[0] == '\0') set_cstr(m->from_keyword, sizeof m->from_keyword, "FROM:");
}

/* —— 充分变异器：对所有 MAIL 的 reverse_path 做轮转变异 —— */
int mutate_mail_reverse_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };  /* 至少 10，这里给 24 种 */
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;

        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* —— 合法形态 —— */
            case 0:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<>"); break; /* 空路径（退信） */
            case 1:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com>"); break;
            case 2:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user.name+tag@example.com>"); break;
            case 3:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<\"weird name\"@example.com>"); break;
            case 4:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[127.0.0.1]>"); break;       /* domain-literal IPv4 */
            case 5:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:2001:db8::1]>"); break;/* domain-literal IPv6 */
            case 6:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<postmaster>"); break;            /* 特例本地名 */

            /* 源路由（历史/可选支持） */
            case 7:  set_cstr(m->reverse_path, sizeof m->reverse_path,
                              "<@a.example,@b.example:user@c.example>"); break;

            /* 长度边界（近 RFC 上限：local 64, domain 255；受我们缓冲区限制） */
            case 8: {
                char local[128]; build_long_local(local, sizeof local);
                char dom[256];   build_long_domain(dom, sizeof dom);
                char tmp[SMTP_SZ_PATH];
                snprintf(tmp, sizeof tmp, "<%s@%s>", local, dom);
                set_cstr(m->reverse_path, sizeof m->reverse_path, tmp);
            } break;

            /* 极长（填满缓冲区内部，但保留尖括号） */
            case 9: {
                size_t cap = sizeof m->reverse_path;
                if (cap <= 2) { set_cstr(m->reverse_path, cap, ""); break; }
                m->reverse_path[0] = '<';
                memset(m->reverse_path+1, 'A', cap-3);
                m->reverse_path[cap-2] = '>';
                m->reverse_path[cap-1] = '\0';
            } break;

            /* —— 语法错误 / 畸形 —— */
            case 10: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com"); break; /* 缺少 '>' */
            case 11: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com>"); break; /* 缺少 '<' */
            case 12: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com"); break;  /* 无尖括号 */
            case 13: set_cstr(m->reverse_path, sizeof m->reverse_path, "<userexample.com>"); break; /* 缺少 @ */
            case 14: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@-bad-.com>"); break;  /* 非法标签 */
            case 15: set_cstr(m->reverse_path, sizeof m->reverse_path, "<u..ser@example.com>"); break; /* 连续点 */
            case 16: set_cstr(m->reverse_path, sizeof m->reverse_path, "<us er@example.com>"); break;  /* 空格 */
            case 17: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@\r\nRCPT TO:evil@example.com>"); break; /* 注入 */
            case 18: set_cstr(m->reverse_path, sizeof m->reverse_path, "<用户@例子.测试>"); break; /* 直写 Unicode */
            case 19: set_cstr(m->reverse_path, sizeof m->reverse_path, "<xn--fsqu00a@xn--0zwm56d.xn--0zwm56d>"); break; /* Punycode */
            case 20: set_cstr(m->reverse_path, sizeof m->reverse_path,
                              "<\"very.(),:;<>[]\\\".VERY.\\\"very@\\ \\\"very\\\".unusual\"@strange.example.com>"); break; /* 复杂引号 */
            case 21: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:]>"); break; /* IPv6 空前缀 */
            case 22: set_cstr(m->reverse_path, sizeof m->reverse_path, "<@>"); break; /* 空源路由（畸形） */
            case 23: set_cstr(m->reverse_path, sizeof m->reverse_path, ""); break;    /* 整个字段清空（畸形） */

            default: break;
        }

        mutated++;
    }

    return (int)mutated; /* 返回被变异的 MAIL 条目数 */
}


/* 构造近上限长度的 ENVID 值（仅大小写字母与数字） */
static void build_long_envid(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = cap - 1;
    for (size_t i = 0; i < n; ++i) out[i] = (i % 2) ? '9' : 'A';
    out[n] = '\0';
}



/* ========== 1) add：为没有可选参数的 MAIL 添加一个典型参数串 ========== */
int add_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        if (m->optional_args[0] == '\0'){
            /* 选择一个兼容面广的组合：SIZE + BODY */
            set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=12345 BODY=7BIT");
            changed++;
        }
    }
    return changed;
}

/* ========== 2) delete：清空可选参数 ========== */
int delete_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        if (m->optional_args[0] != '\0'){
            m->optional_args[0] = '\0';
            changed++;
        }
    }
    return changed;
}

/* ========== 3) 充分变异器：覆盖合法/非法多维度 (≥10 ops) ========== */
int mutate_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 }; /* 提供 24 种轮转算子 */
    int mutated = 0;

    char buf[SMTP_SZ_OPTARGS];
    char envid[64];

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* —— 合法常见 —— */
            case 0:  set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=1"); break;
            case 1:  set_cstr(m->optional_args, sizeof m->optional_args, "BODY=7BIT"); break;
            case 2:  set_cstr(m->optional_args, sizeof m->optional_args, "BODY=8BITMIME"); break;
            case 3:  set_cstr(m->optional_args, sizeof m->optional_args, "RET=FULL"); break;
            case 4:  set_cstr(m->optional_args, sizeof m->optional_args, "RET=HDRS"); break;
            case 5:  set_cstr(m->optional_args, sizeof m->optional_args, "SMTPUTF8"); break;
            case 6:  set_cstr(m->optional_args, sizeof m->optional_args, "AUTH=<>"); break;
            case 7:  set_cstr(m->optional_args, sizeof m->optional_args, "AUTH=ZGVtbw=="); break; /* base64 'demo' */
            case 8:  set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=123 BODY=8BITMIME SMTPUTF8"); break;
            case 9:  set_cstr(m->optional_args, sizeof m->optional_args, "ENVID=abc-123_./"); break;
            case 10: set_cstr(m->optional_args, sizeof m->optional_args, "MT-PRIORITY=3"); break; /* RFC 6710 */

            /* —— 合法但边界值 —— */
            case 11:
                /* SIZE 巨大值（合法数字，但可能超实现阈值） */
                set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=4294967295");
                break;
            case 12:
                /* 超长 ENVID（贴近缓冲上限） */
                build_long_envid(envid, sizeof envid);
                snprintf(buf, sizeof buf, "ENVID=%s", envid);
                set_cstr(m->optional_args, sizeof m->optional_args, buf);
                break;

            /* —— 语法错误/畸形 —— */
            case 13: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=-1"); break;/* 负数 */
            case 14: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=0x100"); break;/* 非十进制 */
            case 15: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE"); break; /* 缺失 '=' */
            case 16: set_cstr(m->optional_args, sizeof m->optional_args, "BODY=9BIT"); break; /* 非法枚举 */
            case 17: set_cstr(m->optional_args, sizeof m->optional_args, "AUTH="); break; /* 空值 */
            case 18: set_cstr(m->optional_args, sizeof m->optional_args, "FROB=1"); break;/* 未知参数 */
            case 19: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1\r\nRCPT TO:<evil@example.com>"); break;  /* CRLF 注入 */
            case 20: set_cstr(m->optional_args, sizeof m->optional_args,
                              " SIZE=1   BODY=8BITMIME  "); break; /* 前后/多重空白 */
            case 21: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1;BODY=8BITMIME"); break; /* 非法分隔符 */
            case 22: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1 SIZE=2"); break; /* 重复参数冲突 */
            case 23: {
                /* 充满缓冲：一长串 'A'（无意义参数） */
                size_t cap = sizeof m->optional_args;
                if (cap) {
                    memset(m->optional_args, 'A', cap-1);
                    m->optional_args[cap-1] = '\0';
                }
            } break;

            default: break;
        }

        mutated++;
    }

    return mutated; /* 被变异的 MAIL 条目数 */
}


static void ensure_rcpt_prefix(smtp_rcpt_packet_t *r){
    if (!r) return;
    if (!r->command[0])   set_cstr(r->command,   sizeof r->command,   "RCPT");
    if (!r->space1[0])    set_cstr(r->space1,    sizeof r->space1,    " ");
    if (!r->to_keyword[0])set_cstr(r->to_keyword,sizeof r->to_keyword,"TO:");
}

/* 追加字符串（安全裁剪） */
static void cat_s(char *dst, size_t cap, const char *s){
    if (!dst || !cap || !s) return;
    size_t cur = strlen(dst);
    if (cur >= cap) { dst[cap-1] = '\0'; return; }
    size_t rem = cap - 1 - cur;
    size_t n = strlen(s);
    if (n > rem) n = rem;
    if (n) memcpy(dst + cur, s, n);
    dst[cur + n] = '\0';
}

/* 填充 n 次字符 ch，写到 dst 末尾 */
static void cat_repeat(char *dst, size_t cap, char ch, size_t n){
    if (!dst || !cap || n == 0) return;
    size_t cur = strlen(dst);
    if (cur >= cap) { dst[cap-1] = '\0'; return; }
    size_t rem = cap - 1 - cur;
    if (n > rem) n = rem;
    memset(dst + cur, (unsigned char)ch, n);
    dst[cur + n] = '\0';
}

/* 构造一个较长的 source-route，直到接近上限 */
static void build_route_addr(char *out, size_t cap){
    if (!out || cap == 0) return;
    out[0] = '\0';
    cat_s(out, cap, "<");
    /* 反复追加路由主机 */
    for (int i = 0; i < 16; ++i){
        char hop[64];
        snprintf(hop, sizeof hop, "@r%d.example,", i);
        size_t before = strlen(out);
        cat_s(out, cap, hop);
        if (strlen(out) == before) break; /* 满了 */
    }
    cat_s(out, cap, "user@example.com>");
    /* 若没空间补全 '>'，上面的 cat_s 也会保证结尾 NUL */
}

/* ========== 充分变异器：对 RCPT.forward_path 做就地多样化变异 ========== */
int mutate_rcpt_forward_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 }; /* 可自由增改 */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);

        unsigned op = (op_idx++) % OPS;

        switch (op){

        /* —— 合法：典型/边角合法 —— */
        case 0:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<alice@example.com>"); break;
        case 1:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"weird name\"@example.com>"); break;
        case 2:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user+tag@example.com>"); break;
        case 3:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[192.0.2.1]>"); break;  /* IPv4 literal */
        case 4:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:2001:db8::1]>"); break;
        case 5:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<@a.example,@b.example:user@example.net>"); break; /* 源路由 */
        case 6:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@xn--exmple-cua.com>"); break; /* IDNA/punycode */
        case 7:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<δοκιμή@παράδειγμα.δοκιμή>"); break; /* SMTPUTF8 路径 */

        /* —— 合法：转义/引号细节 —— */
        case 8:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"a\\\"b\"@example.com>"); break;
        case 9:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"very..dot\"@example.com>"); break;

        /* —— 语法缺陷 / 协议畸形 —— */
        case 10: set_cstr(r->forward_path, SMTP_SZ_PATH, "user@example.com"); break;  /* 缺少尖括号 */
        case 11: set_cstr(r->forward_path, SMTP_SZ_PATH, "<>"); break;                /* 空路径（对 RCPT 非法） */
        case 12: set_cstr(r->forward_path, SMTP_SZ_PATH, "<userexample.com>"); break; /* 无 @ */
        case 13: set_cstr(r->forward_path, SMTP_SZ_PATH, "<.user.@example..com>"); break; /* 点错误 */
        case 14: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user @example.com>"); break;    /* 含空格 */
        case 15: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@-bad-.com>"); break;       /* 非法标签 */
        case 16: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@example.com.>"); break;    /* 结尾点 */
        case 17: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:fe80::1%25eth0]>"); break; /* zone id */

        /* —— 注入 / 控制字符 —— */
        case 18: set_cstr(r->forward_path, SMTP_SZ_PATH, "<victim@example.com\r\nDATA>"); break;
        case 19: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@\x01example.com>"); break; /* 非打印字符 */

        /* —— 长度/边界压力 —— */
        case 20: {
            char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
            cat_s(tmp, sizeof tmp, "<");
            cat_repeat(tmp, sizeof tmp, 'A', 256); /* 长 local-part */
            cat_s(tmp, sizeof tmp, "@example.com>");
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 21: {
            /* 贴近上限：一长串标签拼接 */
            char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
            cat_s(tmp, sizeof tmp, "<u@");
            for (int j = 0; j < 20; ++j){
                char lab[16]; snprintf(lab, sizeof lab, "d%d.", j);
                size_t before = strlen(tmp);
                cat_s(tmp, sizeof tmp, lab);
                if (strlen(tmp) == before) break;
            }
            /* 尝试结尾域 + '>' */
            cat_s(tmp, sizeof tmp, "example>");
            /* 若被截断也无妨，用于鲁棒性测试 */
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 22: {
            /* 超长源路由 */
            char tmp[SMTP_SZ_PATH]; build_route_addr(tmp, sizeof tmp);
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 23:
            /* 古怪风格（非 RFC-5321 path）：bang 路径，故意非法 */
            set_cstr(r->forward_path, SMTP_SZ_PATH, "<host!user>");
            break;

        default: break;
        }

        mutated++;
    }

    return mutated; /* 被变异的 RCPT 条目数 */
}



/* ====== (2) add / delete mutators（字段是否出现）====== */

/* 若某 RCPT 的 optional_args 为空，则添加一个合理参数集合；返回被添加的条目数 */
int add_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int added = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);
        if (!r->optional_args[0]){
            /* 合理默认：DSN 通知 + 原收件人类型 */
            set_cstr(r->optional_args, sizeof r->optional_args,
                     "NOTIFY=SUCCESS,DELAY,FAILURE ORCPT=rfc822;user@example.com");
            added++;
        }
    }
    return added;
}

/* 清空所有 RCPT 的 optional_args；返回被清空的条目数 */
int delete_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int removed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        if (r->optional_args[0]){
            r->optional_args[0] = '\0';
            removed++;
        }
    }
    return removed;
}

/* ====== (3) 充分变异 mutator（≥20 个算子）====== */
/*
 * 仅修改 RCPT.optional_args，覆盖：合法/边界合法/语法错误/大小写/空白/重复键/极长值/控制字符/CRLF 注入等。
 * 字段本身不会“重复出现”；需要多参数时在同一 optional_args 内堆叠。
 */
int mutate_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 26 };
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);

        unsigned op = (op_idx++) % OPS;

        switch (op){
        /* —— 合法 DSN / ORCPT 组合 —— */
        case 0:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS,DELAY,FAILURE"); break;
        case 1:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "notify=never"); break; /* 大小写松弛场景 */
        case 2:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;Bob@example.com"); break;
        case 3:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=utf-8;δοκιμή@παράδειγμα.δοκιμή"); break; /* SMTPUTF8 */
        case 4:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS ORCPT=rfc822;user@example.com"); break;

        /* —— 合法但带空白/引号/奇怪格式 —— */
        case 5:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NoTiFy = success , failure"); break;
        case 6:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=\"rfc822;user@example.com\""); break; /* 值整体加引号 */
        case 7:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=\tsuccess,delay"); break; /* 制表符 */

        /* —— 明确语法缺陷 —— */
        case 8:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY="); break;                      /* 空值 */
        case 9:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY"); break;                        /* 无 '=' */
        case 10: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822 user@example.com"); break; /* 少 ';' */
        case 11: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=success,unknown"); break;        /* 非法选项 */
        case 12: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=badtype;user@example.com"); break;/* 未知 type */

        /* —— 未知/扩展参数（容错/前瞻） —— */
        case 13: set_cstr(r->optional_args, sizeof r->optional_args,
                          "FOO=bar"); break;                       /* 未知关键词 */
        case 14: set_cstr(r->optional_args, sizeof r->optional_args,
                          "X-LONGKEY="); break;                    /* 自定义空值 */

        /* —— 重复键/冲突参数 —— */
        case 15: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS NOTIFY=NEVER"); break;   /* 冲突 */
        case 16: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;u@example.com ORCPT=rfc822;v@example.net"); break;

        /* —— 超长值/边界压力 —— */
        case 17: {
            char tmp[SMTP_SZ_OPTARGS]; tmp[0]='\0';
            cat_s(tmp, sizeof tmp, "ORCPT=rfc822;");
            cat_repeat(tmp, sizeof tmp, 'A', 400);
            cat_s(tmp, sizeof tmp, "@example.com");
            set_cstr(r->optional_args, sizeof r->optional_args, tmp);
        } break;
        case 18: {
            char tmp[SMTP_SZ_OPTARGS]; tmp[0]='\0';
            cat_s(tmp, sizeof tmp, "NOTIFY=");
            for (int j = 0; j < 50; ++j){
                cat_s(tmp, sizeof tmp, "success,");
            }
            set_cstr(r->optional_args, sizeof r->optional_args, tmp);
        } break;

        /* —— 控制字符/注入尝试 —— */
        case 19: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;user@\x01example.com"); break;
        case 20: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=success\r\nDATA"); break;        /* CRLF 注入 */

        /* —— 空白/等号怪异 —— */
        case 21: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY =\tNEVER"); break;
        case 22: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY==NEVER"); break;                 /* 双 '=' */
        case 23: set_cstr(r->optional_args, sizeof r->optional_args,
                          "=NEVER"); break;                        /* 缺键名 */

        /* —— 组合多参数、顺序/重复分隔 —— */
        case 24: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;u@example.com   NOTIFY=SUCCESS,FAILURE"); break;
        case 25: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=,," ); break;                    /* 仅分隔符 */
        default: break;
        }

        mutated++;
    }

    return mutated; /* 被变异的 RCPT 条目数 */
}


/* 确保 VRFY 行具备“VRFY<SP>”前缀（若 string 非空） */
static void ensure_vrfy_prefix(smtp_vrfy_packet_t *v){
    if (!v) return;
    if (!v->command[0]) set_cstr(v->command, sizeof v->command, "VRFY");
    if (!v->crlf[0])    set_cstr(v->crlf,    sizeof v->crlf,    "\r\n");
    /* string 非空则保证有一个空格；string 为空也可以保留空格以便触发服务端错误路径 */
    if (!v->space[0]) set_cstr(v->space, sizeof v->space, " ");
}

/* 仅变异 VRFY.string；返回被修改的 VRFY 条目数量 */
int mutate_vrfy_string(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    /* 至少 20 个变异算子，这里给 24 个 */
    enum { OPS = 24 };

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_VRFY) continue;
        smtp_vrfy_packet_t *v = &pkts[i].pkt.vrfy;

        ensure_vrfy_prefix(v);

        unsigned op = (op_idx++) % OPS;

        switch (op){
        /* —— 合法 / 常见形式 —— */
        case 0:  set_cstr(v->string, sizeof v->string, "user@example.com"); break;
        case 1:  set_cstr(v->string, sizeof v->string, "postmaster"); break; /* 特例 */
        case 2:  set_cstr(v->string, sizeof v->string, "Full Name <user@example.com>"); break;
        case 3:  set_cstr(v->string, sizeof v->string, "\"weird name\"@example.com"); break;
        case 4:  set_cstr(v->string, sizeof v->string, "用户@例子.公司"); break; /* SMTPUTF8/IDN */

        /* 地址字面量 */
        case 5:  set_cstr(v->string, sizeof v->string, "user@[192.0.2.1]"); break;
        case 6:  set_cstr(v->string, sizeof v->string, "user@[IPv6:2001:db8::1]"); break;

        /* 过时/兼容形态（仍可考服务端健壮性） */
        case 7:  set_cstr(v->string, sizeof v->string, "<@a.example,@b.example:user@example.com>"); break; /* source-route */
        case 8:  set_cstr(v->string, sizeof v->string, "user%example.com@relay.local"); break;            /* percent-hack */
        case 9:  set_cstr(v->string, sizeof v->string, "host1!host2!user"); break;                        /* bang path */

        /* 注释/空白花样（RFC 5322 风格） */
        case 10: set_cstr(v->string, sizeof v->string, "User (comment) <user@example.com>"); break;
        case 11: set_cstr(v->string, sizeof v->string, "  user.name+tag  @  example.com  "); break;

        /* —— 明确非法 / 触发错误路径 —— */
        case 12: set_cstr(v->string, sizeof v->string, ""); break;                     /* 空参数（501） */
        case 13: set_cstr(v->string, sizeof v->string, "\t  "); break;                 /* 仅空白 */
        case 14: set_cstr(v->string, sizeof v->string, "user@exa\x01mple.com"); break; /* 控制字符 */
        case 15: set_cstr(v->string, sizeof v->string, "user@example.com\r\nRCPT TO:<evil@example.com>"); break; /* CRLF 注入 */
        case 16: set_cstr(v->string, sizeof v->string, ".user@example.com"); break;    /* 以点开头 */
        case 17: set_cstr(v->string, sizeof v->string, "user@example.com."); break;    /* 域末尾点 */
        case 18: set_cstr(v->string, sizeof v->string, "a..b@example.com"); break;     /* 连续点 */
        case 19: set_cstr(v->string, sizeof v->string, "userexample.com"); break;      /* 缺 @ */
        case 20: set_cstr(v->string, sizeof v->string, "\"user@example.com"); break;   /* 引号不闭合 */

        /* —— 超长/边界压力 —— */
        case 21: {
            char tmp[SMTP_SZ_VRFY_STR]; tmp[0] = '\0';
            /* 构造极长 local-part */
            cat_repeat(tmp, sizeof tmp, 'A', 450);
            cat_s(tmp, sizeof tmp, "@example.com");
            set_cstr(v->string, sizeof v->string, tmp);
        } break;

        /* 反斜杠转义/奇形怪状 */
        case 22: set_cstr(v->string, sizeof v->string, "\"us\\er\"@exa\\mple.com"); break;

        /* Punycode（服务端可能解码或按字面处理） */
        case 23: set_cstr(v->string, sizeof v->string, "xn--fsqu00a@xn--0zwm56d"); break;

        default: break;
        }

        /* 若为了触发“无参”路径设置了空串，你也可以随机清空前导空格：
           这里保持有一个空格，既考察服务器对“VRFY<SP><空/空白>”的处理，也方便别的路径。
         */

        mutated++;
    }

    return mutated;
}


/* 兜底：保证 EXPN 行的前后固定件 */
static void ensure_expn_prefix(smtp_expn_packet_t *e){
    if (!e) return;
    if (!e->command[0]) set_cstr(e->command, sizeof e->command, "EXPN");
    if (!e->space[0])   set_cstr(e->space,   sizeof e->space,   " ");
    if (!e->crlf[0])    set_cstr(e->crlf,    sizeof e->crlf,    "\r\n");
}

/* 仅变异 EXPN.mailing_list；返回被修改的 EXPN 条目数 */
int mutate_expn_mailing_list(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 }; /* ≥ 20 种 */

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EXPN) continue;
        smtp_expn_packet_t *e = &pkts[i].pkt.expn;

        ensure_expn_prefix(e);

        unsigned op = (op_idx++) % OPS;

        switch (op){
        /* —— 合法/常见 —— */
        case 0:  set_cstr(e->mailing_list, sizeof e->mailing_list, "staff"); break;
        case 1:  set_cstr(e->mailing_list, sizeof e->mailing_list, "all"); break;
        case 2:  set_cstr(e->mailing_list, sizeof e->mailing_list, "dev-team"); break;
        case 3:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list@example.com"); break;
        case 4:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list+tag@example.com"); break;

        /* 历史/兼容形态 */
        case 5:  set_cstr(e->mailing_list, sizeof e->mailing_list, "owner-list"); break;
        case 6:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list-request"); break;
        case 7:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list%example.com@relay.local"); break; /* percent hack */
        case 8:  set_cstr(e->mailing_list, sizeof e->mailing_list, "host1!host2!list"); break;            /* bang path */

        /* 注释/空白/引号 */
        case 9:  set_cstr(e->mailing_list, sizeof e->mailing_list, "\"Dev Team\""); break;
        case 10: set_cstr(e->mailing_list, sizeof e->mailing_list, "  team  "); break;
        case 11: set_cstr(e->mailing_list, sizeof e->mailing_list, "list(comment)"); break;

        /* 地址字面量 */
        case 12: set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[192.0.2.5]"); break;
        case 13: set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[IPv6:2001:db8::25]"); break;

        /* 明确非法/触发错误路径 */
        case 14: set_cstr(e->mailing_list, sizeof e->mailing_list, ""); break;               /* 空参数（501） */
        case 15: set_cstr(e->mailing_list, sizeof e->mailing_list, "\t \t"); break;          /* 仅空白 */
        case 16: set_cstr(e->mailing_list, sizeof e->mailing_list, "list\r\nRCPT TO:<evil@example.com>"); break; /* CRLF 注入 */
        case 17: set_cstr(e->mailing_list, sizeof e->mailing_list, "li..st"); break;         /* 连续点 */
        case 18: set_cstr(e->mailing_list, sizeof e->mailing_list, ".list"); break;          /* 以点开头 */
        case 19: set_cstr(e->mailing_list, sizeof e->mailing_list, "li\x01st"); break;       /* 控制字符 */
        case 20: set_cstr(e->mailing_list, sizeof e->mailing_list, "\"unclosed"); break;     /* 引号不闭合 */

        /* 超长/边界压力 */
        case 21: {
            char tmp[SMTP_SZ_LISTNAME]; tmp[0] = '\0';
            cat_repeat(tmp, sizeof tmp, 'A', SMTP_SZ_LISTNAME - 10);
            set_cstr(e->mailing_list, sizeof e->mailing_list, tmp);
        } break;

        /* 非 ASCII/IDN 风格（未 punycode，考察服务器路径） */
        case 22: set_cstr(e->mailing_list, sizeof e->mailing_list, "开发者列表"); break;

        /* source-route（历史遗留） */
        case 23: set_cstr(e->mailing_list, sizeof e->mailing_list, "<@a.example,@b.example:list@example.com>"); break;

        default: break;
        }

        mutated++;
    }

    return mutated;
}



/* 统一保证 HELP 前后固定字段存在；space 由调用者按需设置 */
static void ensure_help_prefix(smtp_help_packet_t *h){
    if (!h) return;
    if (!h->command[0]) set_cstr(h->command, sizeof h->command, "HELP");
    if (!h->crlf[0])    set_cstr(h->crlf,    sizeof h->crlf,    "\r\n");
}

/* 可选参数：argument 为空则通常无空格；但我们允许特定算子制造“HELP ␠\r\n”的异常空格 */
static void sync_space_for_help(smtp_help_packet_t *h, int force_trailing_space_when_empty){
    if (!h) return;
    if (h->argument[0] == '\0') {
        set_cstr(h->space, sizeof h->space, force_trailing_space_when_empty ? " " : "");
    } else {
        set_cstr(h->space, sizeof h->space, " ");
    }
}

/* 2a) 增加 HELP.argument（若已存在则覆写为一个常见合法值） */
int add_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);
        set_cstr(h->argument, sizeof h->argument, "MAIL");
        sync_space_for_help(h, 0);
        changed++;
    }
    return changed;
}

/* 2b) 删除 HELP.argument（置空） */
int delete_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);
        set_cstr(h->argument, sizeof h->argument, "");
        sync_space_for_help(h, 0);
        changed++;
    }
    return changed;
}

/* 3) 充分变异：在所有 HELP 上执行；包含 >= 18 个算子（合法/非法/边界/编码） */
int mutate_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;

    static unsigned seq = 0;
    enum { OPS = 20 }; /* 至少 10，这里给 20 个 */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);

        unsigned op = (seq++) % OPS;
        int force_trailing_space_when_empty = 0;

        switch (op){
        /* —— 合法：典型命令名 —— */
        case 0:  set_cstr(h->argument, sizeof h->argument, "MAIL"); break;
        case 1:  set_cstr(h->argument, sizeof h->argument, "RCPT"); break;
        case 2:  set_cstr(h->argument, sizeof h->argument, "DATA"); break;
        case 3:  set_cstr(h->argument, sizeof h->argument, "STARTTLS"); break;
        case 4:  set_cstr(h->argument, sizeof h->argument, "AUTH"); break;

        /* 大小写/变形 */
        case 5:  set_cstr(h->argument, sizeof h->argument, "mail"); break;
        case 6:  set_cstr(h->argument, sizeof h->argument, "sTaTuS"); break;

        /* 空白变体（合法或边界） */
        case 7:  set_cstr(h->argument, sizeof h->argument, "MAIL   "); break; /* 尾随空格 */
        case 8:  set_cstr(h->argument, sizeof h->argument, "   MAIL"); break; /* 前导空格 */

        /* 空实参 / 仅空格（边界与异常） */
        case 9:  set_cstr(h->argument, sizeof h->argument, ""); break;        /* 经典 HELP\r\n */
        case 10: set_cstr(h->argument, sizeof h->argument, ""); force_trailing_space_when_empty = 1; break; /* “HELP ␠\r\n” */

        /* 控制字符与注入 */
        case 11: set_cstr(h->argument, sizeof h->argument, "MA\001IL"); break; /* 控制字节 */
        case 12: set_cstr(h->argument, sizeof h->argument, "MAIL\r\nRCPT TO:<evil@example.com>"); break; /* CRLF 注入 */

        /* 超长与边界填充 */
        case 13: {
            set_cstr(h->argument, sizeof h->argument, "");
            cat_repeat(h->argument, sizeof h->argument, 'A', SMTP_SZ_HELP_ARG - 1);
        } break;

        /* 标点/符号 */
        case 14: set_cstr(h->argument, sizeof h->argument, "--help"); break;
        case 15: set_cstr(h->argument, sizeof h->argument, "MAIL?param=1&x=y"); break;
        case 16: set_cstr(h->argument, sizeof h->argument, "\"MAIL"); break; /* 未闭合引号 */

        /* 非 ASCII / 本地化 */
        case 17: set_cstr(h->argument, sizeof h->argument, "帮助"); break;

        /* 未知/扩展关键字 */
        case 18: set_cstr(h->argument, sizeof h->argument, "X-UNKNOWN-CMD"); break;
        case 19: set_cstr(h->argument, sizeof h->argument, "8BITMIME"); break;

        default: break;
        }

        /* 自动整理空格（除非特意制造“空实参但保留空格”的异常） */
        sync_space_for_help(h, force_trailing_space_when_empty);

        mutated++;
    }

    return mutated;
}



static void ensure_auth_prefix(smtp_auth_packet_t *a){
    if (!a) return;
    if (!a->command[0])  set_cstr(a->command,  sizeof a->command,  "AUTH");
    if (!a->space1[0])   set_cstr(a->space1,   sizeof a->space1,   " ");
    if (!a->mechanism[0])set_cstr(a->mechanism,sizeof a->mechanism,"PLAIN");
    if (!a->crlf[0])     set_cstr(a->crlf,     sizeof a->crlf,     "\r\n");
}

/* 当 initial_response 为空时通常不应有 space2；反之应有一个空格。
   允许通过 force_keep_space2_when_empty 人为制造“有空格但无参数”的异常布局。 */
static void sync_space_for_auth(smtp_auth_packet_t *a, int force_keep_space2_when_empty){
    if (!a) return;
    if (a->initial_response[0] == '\0') {
        set_cstr(a->space2, sizeof a->space2, force_keep_space2_when_empty ? " " : "");
    } else {
        if (a->space2[0] == '\t') {
            /* 如果算子想保留 TAB，就别强改；否则标准化为单空格 */
            return;
        }
        set_cstr(a->space2, sizeof a->space2, " ");
    }
}

/* ===== 2a) 增加 AUTH.initial_response （若已有则覆写为一个常见合法值） ===== */
int add_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        /* 使用典型 PLAIN 初始响应: base64("\0user\0pass") = "AHVzZXIAcGFzcw==" */
        set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
        set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}

/* ===== 2b) 删除 AUTH.initial_response（置空） ===== */
int delete_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        set_cstr(a->initial_response, sizeof a->initial_response, "");
        /* 删除后按标准形态去掉 space2 */
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}

/* ===== 3) 充分变异：对所有 AUTH 的 initial_response 做多样化操作 =====
   至少 10 种算子（这里提供 20 个），涵盖：合法/非法、缺失/过长、填充错误、
   注入 CRLF、空白/制表、非 ASCII、与机制不匹配等。 */
int mutate_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;

    static unsigned seq = 0;
    enum { OPS = 20 };
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);

        unsigned op = (seq++) % OPS;
        int force_keep_space2_when_empty = 0; /* 特意制造“有空格但无参数”的异常 */

        switch (op){
        /* —— 合法 PLAIN 初始响应：\0authzid(空)\0authcid=user\0pass —— */
        case 0:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw=="); /* \0user\0pass */
            break;

        /* 合法 PLAIN：\0alice\0secret => "AGFsaWNlAHNlY3JldA==" */
        case 1:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AGFsaWNlAHNlY3JldA==");
            break;

        /* 合法但超长（大量 'A'，有效 base64 字符） */
        case 2:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            cat_repeat(a->initial_response, sizeof a->initial_response, 'A',
                       (SMTP_SZ_AUTH_IR/2));
            /* 尝试补齐 padding */
            if ((strlen(a->initial_response) & 3) == 1) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 3);
            else if ((strlen(a->initial_response) & 3) == 2) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 2);
            else if ((strlen(a->initial_response) & 3) == 3) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 1);
            break;

        /* 去掉 padding（常见解析边界） */
        case 3:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw"); /* 无 "==" */
            break;

        /* 非 base64 字符串 */
        case 4:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "####not_base64####");
            break;

        /* CRLF 注入，试探多行解析 */
        case 5:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVz\r\nRCPT TO:<x@x>");
            break;

        /* 前后空白 */
        case 6:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "  AHVzZXIAcGFzcw==  ");
            break;

        /* 与机制不匹配：LOGIN + 初始响应（有的实现不接受） */
        case 7:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "LOGIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "dXNlcm5hbWU="); /* "username" */
            break;

        /* 非 ASCII / 非 UTF-8 片段（无效 base64 串中混入高位字节） */
        case 8:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "inv\xC3\x28" "alid=="); /* 0xC3 0x28 = 错 UTF-8 */
            break;

        /* 极长填充至上限（溢出/截断路径） */
        case 9:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            cat_repeat(a->initial_response, sizeof a->initial_response, 'B',
                       SMTP_SZ_AUTH_IR - 1);
            break;

        /* 删除 IR，但故意保留一个空格（错位：有 space2 无实参） */
        case 10:
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            set_cstr(a->space2,           sizeof a->space2,           " ");
            force_keep_space2_when_empty = 1;
            break;

        /* 将分隔空格改为 TAB（某些解析器不接受） */
        case 11:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
            set_cstr(a->space2,           sizeof a->space2,           "\t");
            break;

        /* XOAUTH2 风格（合法示例） */
        case 12:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "XOAUTH2");
            set_cstr(a->initial_response, sizeof a->initial_response,
                     "dXNlcj1mb28BYXV0aD1CZWFyZXIgdG9rZW4BAQ==");
            break;

        /* CRAM-MD5 风格（伪造响应内容） */
        case 13:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "CRAM-MD5");
            set_cstr(a->initial_response, sizeof a->initial_response,
                     "dXNlciA5ZTc5Y2RmNTQzN2QxY2QzZjQzY2EwMDAwMDAwMDAwMDAwMDA="); /* "user <hex>" */
            break;

        /* 多余的等号 padding */
        case 14:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw====");
            break;

        /* 混入分号和逗号等分隔符 */
        case 15:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXI7Y3Bhc3Ms,LS0=");
            break;

        /* 只给 "+"（非法 base64 长度/字符集边界） */
        case 16:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "+");
            break;

        /* 空串：彻底无 IR（标准合法情况） */
        case 17:
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            break;

        /* 在合法串中间插入空格 */
        case 18:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVz ZXIAcGFz cw==");
            break;

        /* 在合法串尾部加入 CR（单独 \r） */
        case 19:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==\r");
            break;
        }

        /* 同步空格（除非我们特意保持“空串但留空格”的畸形布局） */
        sync_space_for_auth(a, force_keep_space2_when_empty);

        mutated++;
    }

    return mutated;
}

typedef void (*helo_mutator_fn)(smtp_helo_packet_t *pkt, int num_packets);
typedef void (*ehlo_mutator_fn)(smtp_ehlo_packet_t *pkt, int num_packets);
typedef void (*mail_mutator_fn)(smtp_mail_packet_t *pkt, int num_packets);
typedef void (*rcpt_mutator_fn)(smtp_rcpt_packet_t *pkt, int num_packets);
typedef void (*vrfy_mutator_fn)(smtp_vrfy_packet_t *pkt, int num_packets);
typedef void (*expn_mutator_fn)(smtp_expn_packet_t *pkt, int num_packets);
typedef void (*help_mutator_fn)(smtp_help_packet_t *pkt, int num_packets);
typedef void (*auth_mutator_fn)(smtp_auth_packet_t *pkt, int num_packets);

/* DATA / RSET / NOOP / QUIT / STARTTLS —— 无具体字段，给 NOP */
typedef void (*data_mutator_fn)(smtp_data_packet_t *pkt, int num_packets);
typedef void (*rset_mutator_fn)(smtp_rset_packet_t *pkt, int num_packets);
typedef void (*noop_mutator_fn)(smtp_noop_packet_t *pkt, int num_packets);
typedef void (*quit_mutator_fn)(smtp_quit_packet_t *pkt, int num_packets);
typedef void (*starttls_mutator_fn)(smtp_starttls_packet_t *pkt, int num_packets);

static void data_nop(smtp_data_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void rset_nop(smtp_rset_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void noop_nop(smtp_noop_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void quit_nop(smtp_quit_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void starttls_nop(smtp_starttls_packet_t *pkt, int n){ (void)pkt; (void)n; }
/* ========================= mutator 列表 ========================= */

/* HELO */
static helo_mutator_fn helo_mutators[] = {
  mutate_helo_domain,
};
/* EHLO */
static ehlo_mutator_fn ehlo_mutators[] = {
  mutate_ehlo_domain,
};
/* MAIL */
static mail_mutator_fn mail_mutators[] = {
  mutate_mail_reverse_path,
  mutate_mail_optional_args,
  add_mail_optional_args,
  delete_mail_optional_args,
};
/* RCPT */
static rcpt_mutator_fn rcpt_mutators[] = {
  mutate_rcpt_forward_path,
  mutate_rcpt_optional_args,
  add_rcpt_optional_args,
  delete_rcpt_optional_args,
};
/* VRFY */
static vrfy_mutator_fn vrfy_mutators[] = {
  mutate_vrfy_string,

};
/* EXPN */
static expn_mutator_fn expn_mutators[] = {
  mutate_expn_mailing_list,
};
/* HELP —— 使用带 smtp_ 前缀的安全名称 */
static help_mutator_fn help_mutators[] = {
  mutate_smtp_help_argument,
  add_smtp_help_argument,
  delete_smtp_help_argument
  /* 若你实现了：smtp_repeat_help_argument */
};
/* AUTH */
static auth_mutator_fn auth_mutators[] = {
  mutate_auth_initial_response,
  add_auth_initial_response,
  delete_auth_initial_response,
};
/* 纯 NOP */
static data_mutator_fn data_mutators[]         = { data_nop };
static rset_mutator_fn rset_mutators[]         = { rset_nop };
static noop_mutator_fn noop_mutators[]         = { noop_nop };
static quit_mutator_fn quit_mutators[]         = { quit_nop };
static starttls_mutator_fn starttls_mutators[] = { starttls_nop };

/* 计数宏 */
#define HELO_MUTATOR_COUNT      (sizeof(helo_mutators)/sizeof(helo_mutator_fn))
#define EHLO_MUTATOR_COUNT      (sizeof(ehlo_mutators)/sizeof(ehlo_mutator_fn))
#define MAIL_MUTATOR_COUNT      (sizeof(mail_mutators)/sizeof(mail_mutator_fn))
#define RCPT_MUTATOR_COUNT      (sizeof(rcpt_mutators)/sizeof(rcpt_mutator_fn))
#define VRFY_MUTATOR_COUNT      (sizeof(vrfy_mutators)/sizeof(vrfy_mutator_fn))
#define EXPN_MUTATOR_COUNT      (sizeof(expn_mutators)/sizeof(expn_mutator_fn))
#define HELP_MUTATOR_COUNT      (sizeof(help_mutators)/sizeof(help_mutator_fn))
#define AUTH_MUTATOR_COUNT      (sizeof(auth_mutators)/sizeof(auth_mutator_fn))
#define DATA_MUTATOR_COUNT      (sizeof(data_mutators)/sizeof(data_mutator_fn))
#define RSET_MUTATOR_COUNT      (sizeof(rset_mutators)/sizeof(rset_mutator_fn))
#define NOOP_MUTATOR_COUNT      (sizeof(noop_mutators)/sizeof(noop_mutator_fn))
#define QUIT_MUTATOR_COUNT      (sizeof(quit_mutators)/sizeof(quit_mutator_fn))
#define STARTTLS_MUTATOR_COUNT  (sizeof(starttls_mutators)/sizeof(starttls_mutator_fn))

/* ========================= 单类型调度器 ========================= */

static inline int rr(int n) { return (n > 0) ? rand() % n : 0; }

void dispatch_helo_mutation(smtp_helo_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  helo_mutators[rr(HELO_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_ehlo_mutation(smtp_ehlo_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  ehlo_mutators[rr(EHLO_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_mail_mutation(smtp_mail_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  mail_mutators[rr(MAIL_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_rcpt_mutation(smtp_rcpt_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  rcpt_mutators[rr(RCPT_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_vrfy_mutation(smtp_vrfy_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  vrfy_mutators[rr(VRFY_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_expn_mutation(smtp_expn_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  expn_mutators[rr(EXPN_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_help_mutation(smtp_help_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  help_mutators[rr(HELP_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_smtp_auth_mutation(smtp_auth_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  auth_mutators[rr(AUTH_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_data_mutation(smtp_data_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  data_mutators[rr(DATA_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_rset_mutation(smtp_rset_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  rset_mutators[rr(RSET_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_noop_mutation(smtp_noop_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  noop_mutators[rr(NOOP_MUTATOR_COUNT)](pkt, 1); 
}
void dispatch_quit_mutation(smtp_quit_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  quit_mutators[rr(QUIT_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_starttls_mutation(smtp_starttls_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  starttls_mutators[rr(STARTTLS_MUTATOR_COUNT)](pkt, 1);
}



/* ========================= 总调度（多轮） ========================= */

void dispatch_smtp_multiple_mutations(smtp_packet_t *pkts, int num_packets, int rounds) {
  if (!pkts || num_packets <= 0 || rounds <= 0) return;

  for (int i = 0; i < rounds; ++i) {
    int idx = rand() % num_packets;
    switch (pkts[idx].cmd_type) {
      case SMTP_PKT_HELO:
        dispatch_helo_mutation(&pkts[idx].pkt.helo, 1);
        break;
      case SMTP_PKT_EHLO:
        dispatch_ehlo_mutation(&pkts[idx].pkt.ehlo, 1);
        break;
      case SMTP_PKT_MAIL:
        dispatch_mail_mutation(&pkts[idx].pkt.mail, 1);
        break;
      case SMTP_PKT_RCPT:
        dispatch_rcpt_mutation(&pkts[idx].pkt.rcpt, 1);
        break;
      case SMTP_PKT_DATA:
        dispatch_data_mutation(&pkts[idx].pkt.data, 1);
        break;
      case SMTP_PKT_RSET:
        dispatch_rset_mutation(&pkts[idx].pkt.rset, 1);
        break;
      case SMTP_PKT_VRFY:
        dispatch_vrfy_mutation(&pkts[idx].pkt.vrfy, 1);
        break;
      case SMTP_PKT_EXPN:
        dispatch_expn_mutation(&pkts[idx].pkt.expn, 1);
        break;
      case SMTP_PKT_HELP:
        dispatch_help_mutation(&pkts[idx].pkt.help, 1);
        break;
      case SMTP_PKT_NOOP:
        dispatch_noop_mutation(&pkts[idx].pkt.noop, 1);
        break;
      case SMTP_PKT_QUIT:
        dispatch_quit_mutation(&pkts[idx].pkt.quit, 1);
        break;
      case SMTP_PKT_STARTTLS:
        dispatch_starttls_mutation(&pkts[idx].pkt.starttls, 1);
        break;
      case SMTP_PKT_AUTH:
        dispatch_smtp_auth_mutation(&pkts[idx].pkt.auth, 1);
        break;
      case SMTP_PKT_UNRECOGNIZED:
      default:
        /* 未识别类型：跳过 */
        break;
    }
  }
}
