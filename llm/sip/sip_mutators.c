/* sip mutators source file */
#include "sip.h"

/* mutate_accept_media_type.c */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h> 
#include <stdarg.h>  
/* ---------- 小工具 ---------- */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
static void scpy(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    size_t n = src ? strnlen(src, cap - 1) : 0;
    if (src && n) memcpy(dst, src, n);
    dst[n] = '\0';
}

static void set_present(sip_require_hdr_t *h, const char *val){
    scpy(h->name, sizeof h->name, "Require");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->option_tags, sizeof h->option_tags, val ? val : "");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}
static void set_present1(sip_response_key_hdr_t *h, const char *scheme, const char *params){
    scpy(h->name, sizeof h->name, "Response-Key");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->scheme, sizeof h->scheme, scheme ? scheme : "");
    if (params && params[0]) {
        h->sp = ' ';
        scpy(h->kvpairs, sizeof h->kvpairs, params);
    } else {
        h->sp = '\0';
        h->kvpairs[0] = '\0';
    }
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}

static void smemset(char *dst, size_t cap, int ch, size_t nfill) {
    if (!cap) return;
    size_t n = MIN(cap - 1, nfill);
    memset(dst, ch, n);
    dst[n] = '\0';
}

/* 线性同余生成器：可复现随机 */
static unsigned rnd_next(unsigned *state) {
    *state = (*state * 1103515245u + 12345u);
    return *state;
}
static unsigned rnd_pick(unsigned *state, unsigned mod) {
    return (rnd_next(state) >> 16) % (mod ? mod : 1);
}

/* 标记 Accept 头为“存在”并设置默认值 */
static void accept_set_present_default(sip_accept_hdr_t *h) {
    scpy(h->name,        sizeof h->name,        "Accept");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
    scpy(h->media_type,  sizeof h->media_type,  "application");
    h->slash = '/';
    scpy(h->sub_type,    sizeof h->sub_type,    "sdp");
    h->params[0] = '\0';
}

/* 若不存在则补一个默认 Accept */
static sip_accept_hdr_t* ensure_accept_hdr_for_pkt(sip_packet_t *p) {
    switch (p->cmd_type) {
    case SIP_PKT_INVITE: {
        sip_accept_hdr_t *h = &p->pkt.invite.accept;
        if (h->name[0] == '\0') accept_set_present_default(h);
        return h;
    }
    case SIP_PKT_REGISTER: {
        sip_accept_hdr_t *h = &p->pkt.register_.accept;
        if (h->name[0] == '\0') accept_set_present_default(h);
        return h;
    }
    case SIP_PKT_OPTIONS: {
        sip_accept_hdr_t *h = &p->pkt.options.accept;
        if (h->name[0] == '\0') accept_set_present_default(h);
        return h;
    }
    default:
        return NULL;
    }
}

/* 删除 Accept（用于 delete_*） */
static void accept_delete_for_pkt(sip_packet_t *p) {
    sip_accept_hdr_t *h = NULL;
    switch (p->cmd_type) {
    case SIP_PKT_INVITE:   h = &p->pkt.invite.accept; break;
    case SIP_PKT_REGISTER: h = &p->pkt.register_.accept; break;
    case SIP_PKT_OPTIONS:  h = &p->pkt.options.accept; break;
    default: break;
    }
    if (h) h->name[0] = '\0';
}

/* ---------- 变异算子（只动 media_type，必要时搭配 slash/sub_type） ---------- */
static void op_set_common_valid(sip_accept_hdr_t *h, unsigned *rs) {
    static const char *k[] = { "application","audio","video","image","text",
                               "message","multipart","model" };
    scpy(h->media_type, sizeof h->media_type, k[rnd_pick(rs, (unsigned)(sizeof k/sizeof k[0]))]);
    h->slash = '/';
    if (h->sub_type[0] == '\0') scpy(h->sub_type, sizeof h->sub_type, "sdp");
}

static void op_set_star(sip_accept_hdr_t *h) {
    scpy(h->media_type, sizeof h->media_type, "*");
    h->slash = 0;
    h->sub_type[0] = '\0';
}

static void op_set_star_star(sip_accept_hdr_t *h) {
    scpy(h->media_type, sizeof h->media_type, "*");
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "*");
}

static void op_empty(sip_accept_hdr_t *h) {
    h->media_type[0] = '\0'; /* 非法：空主类型 */
    /* 保持其他不动，触发解析/重组的鲁棒性 */
}

static void op_maxlen_fill(sip_accept_hdr_t *h) {
    smemset(h->media_type, sizeof h->media_type, 'A', sizeof h->media_type - 1);
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "sdp");
}

static void op_invalid_chars(sip_accept_hdr_t *h) {
    /* 含空格/分号/等号等非法 token 字符 */
    scpy(h->media_type, sizeof h->media_type, "app lic;=ation");
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "sdp");
}

static void op_toggle_case(sip_accept_hdr_t *h) {
    for (size_t i = 0; i + 1 < sizeof h->media_type && h->media_type[i]; ++i) {
        char c = h->media_type[i];
        if (isalpha((unsigned char)c)) {
            h->media_type[i] = (char)(islower((unsigned char)c) ? toupper((unsigned char)c)
                                                               : tolower((unsigned char)c));
        }
    }
}

static void op_vendor_x(sip_accept_hdr_t *h, unsigned *rs) {
    /* 虚构/厂商自定义主类型（严格讲应是 subtype 的习惯，但这里专门对 media_type 搅动） */
    static const char *k[] = {"x-foo","x_bar","vnd.example"};
    scpy(h->media_type, sizeof h->media_type, k[rnd_pick(rs, (unsigned)(sizeof k/sizeof k[0]))]);
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "sdp");
}

static void op_params_misplaced(sip_accept_hdr_t *h) {
    /* 把参数故意塞进 media_type，语义/语法均错 */
    scpy(h->media_type, sizeof h->media_type, "application;level=1;q=0.9");
    h->slash = 0;
    h->sub_type[0] = '\0';
}

static void op_double_slash(sip_accept_hdr_t *h) {
    scpy(h->media_type, sizeof h->media_type, "application");
    h->slash = '/';
    /* subtype 以 '/' 开头，输出将成为 "application//sdp" */
    scpy(h->sub_type, sizeof h->sub_type, "/sdp");
}

static void op_no_slash_but_subtype(sip_accept_hdr_t *h) {
    scpy(h->media_type, sizeof h->media_type, "application");
    h->slash = 0;                       /* 缺斜杠 */
    scpy(h->sub_type, sizeof h->sub_type, "sdp"); /* 但仍给 subtype -> 状态不一致 */
}

static void op_crlf_inject_repeat(sip_accept_hdr_t *h) {
    /* 在 media_type 注入 CRLF，引出第二个 Accept 行（重复） */
    scpy(h->media_type, sizeof h->media_type, "text\r\nAccept: image");
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "jpeg");
}

static void op_non_ascii(sip_accept_hdr_t *h) {
    /* 放入高位字节/控制字节 */
    h->media_type[0] = (char)0xFF;
    h->media_type[1] = (char)0xFE;
    h->media_type[2] = (char)0x01;
    h->media_type[3] = 'A';
    h->media_type[4] = '\0';
    h->slash = '/';
    scpy(h->sub_type, sizeof h->sub_type, "sdp");
}

static void op_garbage_token(sip_accept_hdr_t *h, unsigned *rs) {
    /* 随机噪声 token（字母/数字/下划线/点/破折号混合） */
    size_t cap = sizeof h->media_type;
    size_t n = 10 + rnd_pick(rs, (unsigned)(cap > 12 ? cap - 12 : 2));
    if (n >= cap) n = cap - 1;
    for (size_t i = 0; i < n; ++i) {
        unsigned r = rnd_pick(rs, 6);
        char c = (r==0)?('_'): (r==1)?('-'): (r==2)?('.'):
                  (r==3)?('0'+(char)rnd_pick(rs,10)):
                  (r==4)?('A'+(char)rnd_pick(rs,26)):
                         ('a'+(char)rnd_pick(rs,26));
        h->media_type[i] = c;
    }
    h->media_type[n] = '\0';
    /* 随机是否给斜杠/子类型 */
    if ((rnd_pick(rs,2)&1)==0) {
        h->slash = '/';
        scpy(h->sub_type, sizeof h->sub_type, "bin");
    } else {
        h->slash = 0;
        h->sub_type[0] = '\0';
    }
}
/* 将一条 Accept 的 media_type 做一次随机“合法变异”（只筛选合法算子） */
static void mutate_one_media_type(sip_accept_hdr_t *h, unsigned *rs) {
    /* 确保头存在基本形态，避免空 name 导致重组器不输出 */
    if (h->name[0] == '\0') accept_set_present_default(h);

    /* 只从合法算子里选：0,2,6,7 */
    static const unsigned legal_ops[] = {0, 2, 6, 7};
    unsigned op = legal_ops[rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))];

    switch (op) {
    case 0:  op_set_common_valid(h, rs); break; // 合法：常见主类型 type/subtype
    case 2:  op_set_star_star(h);        break; // 合法：*/*
    case 6:  op_toggle_case(h);          break; // 合法：大小写摇摆（不改结构）
    case 7:  op_vendor_x(h, rs);         break; // 合法：厂商前缀（仍为合法 token）
    default: op_set_common_valid(h, rs); break;
    }
}

// /* 将一条 Accept 的 media_type 做一次随机变异（从 ≥12 个算子中挑选） */
// static void mutate_one_media_type(sip_accept_hdr_t *h, unsigned *rs) {
//     /* 确保头存在基本形态，避免空 name 导致重组器不输出 */
//     if (h->name[0] == '\0') accept_set_present_default(h);

//     switch (rnd_pick(rs, 12)) {
//     case 0:  op_set_common_valid(h, rs);         break; // 合法：常见主类型
//     case 1:  op_set_star(h);                     break; // 合法：*
//     case 2:  op_set_star_star(h);                break; // 合法：*/*
//     case 3:  op_empty(h);                        break; // 非法：空
//     case 4:  op_maxlen_fill(h);                  break; // 边界：最大长度
//     case 5:  op_invalid_chars(h);                break; // 非法：空格/分号/等号
//     case 6:  op_toggle_case(h);                  break; // 合法：大小写摇摆
//     case 7:  op_vendor_x(h, rs);                 break; // 可疑：厂商前缀
//     case 8:  op_params_misplaced(h);             break; // 非法：参数错位到主类型
//     case 9:  op_double_slash(h);                 break; // 非法：双斜杠
//     case 10: op_no_slash_but_subtype(h);         break; // 不一致：无斜杠但有 subtype
//     case 11: op_crlf_inject_repeat(h);           break; // 重复：CRLF 注入第二个 Accept
//     default: op_non_ascii(h);                    break; // 非法：非 ASCII/控制字节
//     }
// }

/* ---------- 对外：主 mutator ----------
   在给定的报文数组上，针对可含 Accept 的请求变异其 media_type 字段 */
void mutate_accept_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    unsigned rs = seed ? seed : 0xC0FFEEu;
    for (size_t i = 0; i < npkts; ++i) {
        sip_packet_t *p = &pkts[i];
        if (p->cmd_type != SIP_PKT_INVITE &&
            p->cmd_type != SIP_PKT_REGISTER &&
            p->cmd_type != SIP_PKT_OPTIONS) {
            continue; /* 其他类型通常无 Accept，跳过 */
        }
        sip_accept_hdr_t *h = ensure_accept_hdr_for_pkt(p);
        if (!h) continue;
        int times = 1 ;
        for (int t = 0; t < times; ++t) {
            mutate_one_media_type(h, &rs);
        }
    }
}

/* ---------- 题目第 2/3 点要求的增/删/重复样例接口 ---------- */

/* add_<msg_type>_<field_name> */
void add_INVITE_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)
        accept_set_present_default(&pkts[i].pkt.invite.accept);
}
void add_REGISTER_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER)
        accept_set_present_default(&pkts[i].pkt.register_.accept);
}
void add_OPTIONS_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)
        accept_set_present_default(&pkts[i].pkt.options.accept);
}

/* delete_<msg_type>_<field_name> */
void delete_INVITE_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)
        pkts[i].pkt.invite.accept.name[0]='\0';
}
void delete_REGISTER_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER)
        pkts[i].pkt.register_.accept.name[0]='\0';
}
void delete_OPTIONS_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)
        pkts[i].pkt.options.accept.name[0]='\0';
}

/* repeat_<msg_type>_<field_name>
   由于结构体不支持多条 Accept，这里用 CRLF 注入手法复用 reassembler 造成重复头 */
void repeat_INVITE_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE) {
        sip_accept_hdr_t *h = &pkts[i].pkt.invite.accept;
        if (h->name[0]=='\0') accept_set_present_default(h);
        op_crlf_inject_repeat(h);
    }
}
void repeat_REGISTER_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) {
        sip_accept_hdr_t *h = &pkts[i].pkt.register_.accept;
        if (h->name[0]=='\0') accept_set_present_default(h);
        op_crlf_inject_repeat(h);
    }
}
void repeat_OPTIONS_media_type(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    for (size_t i=0;i<npkts;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS) {
        sip_accept_hdr_t *h = &pkts[i].pkt.options.accept;
        if (h->name[0]=='\0') accept_set_present_default(h);
        op_crlf_inject_repeat(h);
    }
}


static void sfill(char *dst, size_t cap, int ch, size_t n) {
    if (!dst || !cap) return;
    size_t m = MIN(cap - 1, n);
    memset(dst, ch, m);
    dst[m] = '\0';
}


/* ---------------- sub_type: 变异算子（≥10） ---------------- */

static void st_set_common_valid(sip_accept_hdr_t *h, unsigned *rs) {
    static const char *subs[] = { "sdp","plain","xml","json","jpeg","mpeg","x-www-form-urlencoded","dns-message" };
    scpy(h->sub_type, sizeof h->sub_type, subs[rnd_pick(rs,(unsigned)(sizeof subs/sizeof subs[0]))]);
    if (!h->slash) h->slash = '/';
    if (!h->media_type[0]) scpy(h->media_type, sizeof h->media_type, "application");
}
static void st_wildcard(sip_accept_hdr_t *h) {
    scpy(h->sub_type, sizeof h->sub_type, "*");
    if (!h->media_type[0]) scpy(h->media_type, sizeof h->media_type, "*");
    h->slash = '/';
}
static void st_empty(sip_accept_hdr_t *h) { /* 非法：空 subtype */
    h->sub_type[0] = '\0';
    if (!h->media_type[0]) scpy(h->media_type, sizeof h->media_type, "application");
    /* slash 随机保留或清空由调用方整体组合去触发不一致 */
}
static void st_maxlen(sip_accept_hdr_t *h) {
    sfill(h->sub_type, sizeof h->sub_type, 'B', sizeof h->sub_type - 1);
    if (!h->slash) h->slash = '/';
}
static void st_invalid_chars(sip_accept_hdr_t *h) { /* 非法字符 */
    scpy(h->sub_type, sizeof h->sub_type, "sd p;=x");
    if (!h->slash) h->slash = '/';
}
static void st_toggle_case(sip_accept_hdr_t *h) {
    for (size_t i=0; h->sub_type[i] && i+1<sizeof h->sub_type; ++i) {
        char c = h->sub_type[i];
        if (isalpha((unsigned char)c))
            h->sub_type[i] = (char)(islower((unsigned char)c)? toupper((unsigned char)c) : tolower((unsigned char)c));
    }
}
static void st_vendor_tree(sip_accept_hdr_t *h, unsigned *rs) {
    static const char *v[] = {"vnd.ms-sip","vnd.example.foo","x-foo.bar-baz_09"};
    scpy(h->sub_type, sizeof h->sub_type, v[rnd_pick(rs,(unsigned)(sizeof v/sizeof v[0]))]);
    if (!h->slash) h->slash = '/';
}
static void st_param_injection(sip_accept_hdr_t *h) { /* 把参数塞进 subtype（语法错） */
    scpy(h->sub_type, sizeof h->sub_type, "sdp;q=0.5;level=1");
    if (!h->slash) h->slash = '/';
}
static void st_crlf_inject(sip_accept_hdr_t *h) { /* 头注入 */
    scpy(h->sub_type, sizeof h->sub_type, "sdp\r\nAccept: image/png");
    if (!h->slash) h->slash = '/';
}
static void st_leading_slash(sip_accept_hdr_t *h) { /* 非法：以 '/' 开头 */
    scpy(h->sub_type, sizeof h->sub_type, "/sdp");
    if (!h->slash) h->slash = '/';
}
static void st_non_ascii(sip_accept_hdr_t *h) {
    h->sub_type[0] = (char)0xFF; h->sub_type[1]=(char)0xFE; h->sub_type[2]='x'; h->sub_type[3]=0;
    if (!h->slash) h->slash = '/';
}
// static void mutate_one_sub_type(sip_accept_hdr_t *h, unsigned *rs) {
//     /* 确保头与主类型可输出 */
//     if (h->name[0] == '\0') accept_set_present_default(h);
//     if (!h->media_type[0]) scpy(h->media_type, sizeof h->media_type, "application");
//     if (!h->slash) h->slash = '/';

//     switch (rnd_pick(rs, 12)) {
//     case 0:  st_set_common_valid(h, rs);   break;
//     case 1:  st_wildcard(h);               break;
//     case 2:  st_empty(h);                  break;
//     case 3:  st_maxlen(h);                 break;
//     case 4:  st_invalid_chars(h);          break;
//     case 5:  st_toggle_case(h);            break;
//     case 6:  st_vendor_tree(h, rs);        break;
//     case 7:  st_param_injection(h);        break;
//     case 8:  st_crlf_inject(h);            break;
//     case 9:  st_leading_slash(h);          break;
//     case 10: st_non_ascii(h);              break;
//     default: st_set_common_valid(h, rs);   break;
//     }
// }
static void mutate_one_sub_type(sip_accept_hdr_t *h, unsigned *rs) {
    /* 确保头与主类型可输出 */
    if (h->name[0] == '\0') accept_set_present_default(h);
    if (!h->media_type[0]) scpy(h->media_type, sizeof h->media_type, "application");
    if (!h->slash) h->slash = '/';

    /* 只从合法算子里选：0,1,5,6 */
    static const unsigned legal_ops[] = {0, 1, 5, 6};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op) {
    case 0:  st_set_common_valid(h, rs); break; // 合法：常见 subtype
    case 1:  st_wildcard(h);             break; // 合法：*
    case 5:  st_toggle_case(h);          break; // 合法：大小写扰动
    case 6:  st_vendor_tree(h, rs);      break; // 合法：vnd/x- 系列
    default: st_set_common_valid(h, rs); break;
    }
}

/* ---------------- params: 变异算子（≥10） ---------------- */
/* 注意：结构中约定 params 若存在需以 ';' 开始。 */

static void ps_set_valid_basic(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q=0.9;level=1"); }
static void ps_empty(sip_accept_hdr_t *h) { h->params[0] = '\0'; }
static void ps_q_out_of_range(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q=1.5"); }
static void ps_q_negative(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q=-1"); }
static void ps_q_missing_eq(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q"); }
static void ps_q_missing_val(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q="); }
static void ps_double_semicolon(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";;level=1"); }
static void ps_very_long(sip_accept_hdr_t *h) {
    /* 构造近上限的长参数串 */
    size_t cap = sizeof h->params;
    if (cap < 4) { ps_empty(h); return; }
    h->params[0] = ';';
    size_t fill = cap - 2;
    memset(h->params+1, 'A', fill);
    h->params[1+fill] = '\0';
}
static void ps_duplicate_keys(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";level=1;level=2;q=0.8"); }
static void ps_with_spaces(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, "; q = 0.9 ; level = 1 "); }
static void ps_quoted_string(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";desc=\"a,b;c\\\"quote\";q=0.2"); }
static void ps_header_inject(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";\r\nAccept: image/png"); }
static void ps_comma_new_range(sip_accept_hdr_t *h) { scpy(h->params, sizeof h->params, ";q=0.7, text/html;q=0.1"); }
static void ps_control_bytes(sip_accept_hdr_t *h) { h->params[0]=';'; h->params[1]=1; h->params[2]=2; h->params[3]='x'; h->params[4]=0; }

// static void mutate_one_params(sip_accept_hdr_t *h, unsigned *rs) {
//     if (h->name[0] == '\0') accept_set_present_default(h);
//     switch (rnd_pick(rs, 14)) {
//     case 0:  ps_set_valid_basic(h);     break;
//     case 1:  ps_empty(h);               break;
//     case 2:  ps_q_out_of_range(h);      break;
//     case 3:  ps_q_negative(h);          break;
//     case 4:  ps_q_missing_eq(h);        break;
//     case 5:  ps_q_missing_val(h);       break;
//     case 6:  ps_double_semicolon(h);    break;
//     case 7:  ps_very_long(h);           break;
//     case 8:  ps_duplicate_keys(h);      break;
//     case 9:  ps_with_spaces(h);         break;
//     case 10: ps_quoted_string(h);       break;
//     case 11: ps_header_inject(h);       break;
//     case 12: ps_comma_new_range(h);     break;
//     default: ps_control_bytes(h);       break;
//     }
// }
static void mutate_one_params(sip_accept_hdr_t *h, unsigned *rs) {
    if (h->name[0] == '\0') accept_set_present_default(h);

    /* 只从“语法仍合法”的算子里选：0,8,10 */
    static const unsigned legal_ops[] = {0, 8, 10};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op) {
    case 0:  ps_set_valid_basic(h);  break;  /* 合法基础参数 */
    case 8:  ps_duplicate_keys(h);   break;  /* 语法合法：重复 accept-param */
    case 10: ps_quoted_string(h);    break;  /* 语法合法：quoted-string 值 */
    default: ps_set_valid_basic(h);  break;
    }
}

/* 将 params 内容重复/扩增（repeat_* 需求） */
static void params_repeat_inplace(sip_accept_hdr_t *h) {
    if (h->name[0] == '\0') accept_set_present_default(h);
    if (h->params[0] == '\0') { scpy(h->params, sizeof h->params, ";q=0.5"); return; }
    size_t len = strnlen(h->params, sizeof h->params);
    /* 追加一份（用分号起头），若放不下就尽力截断 */
    const char *tail = ";level=1;q=0.1;foo=bar";
    size_t cap = sizeof h->params;
    if (len + strlen(tail) < cap) {
        memcpy(h->params + len, tail, strlen(tail) + 1);
    } else {
        size_t room = cap - 1 - len;
        if (room > 0) {
            memcpy(h->params + len, tail, room);
            h->params[len + room] = '\0';
        }
    }
}


void mutate_accept_sub_type_and_params(sip_packet_t *pkts, size_t npkts, unsigned seed) {
    unsigned rs = seed ? seed : 0xA11CEu;
    for (size_t i = 0; i < npkts; ++i) {
        sip_packet_t *p = &pkts[i];
        if (p->cmd_type != SIP_PKT_INVITE &&
            p->cmd_type != SIP_PKT_REGISTER &&
            p->cmd_type != SIP_PKT_OPTIONS) continue;

        sip_accept_hdr_t *h = ensure_accept_hdr_for_pkt(p);
        if (!h) continue;

        if(rand()%2){
            mutate_one_sub_type(h, &rs);
        }
        else{
            mutate_one_params(h, &rs);
        }

    }
}

/* ---- params 的 add / delete / repeat（仅 INVITE/REGISTER/OPTIONS） ---- */
static void params_add_for_pkt(sip_packet_t *p) {
    sip_accept_hdr_t *h = ensure_accept_hdr_for_pkt(p);
    if (h) scpy(h->params, sizeof h->params, ";q=0.9;level=1");
}
static void params_delete_for_pkt(sip_packet_t *p) {
    sip_accept_hdr_t *h = ensure_accept_hdr_for_pkt(p);
    if (h) h->params[0] = '\0';
}
static void params_repeat_for_pkt(sip_packet_t *p) {
    sip_accept_hdr_t *h = ensure_accept_hdr_for_pkt(p);
    if (h) params_repeat_inplace(h);
}

/* add_<msg>_params */
void add_INVITE_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)   params_add_for_pkt(&pkts[i]); }
void add_REGISTER_params(sip_packet_t *pkts, size_t n, unsigned seeds){for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) params_add_for_pkt(&pkts[i]);}
void add_OPTIONS_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)  params_add_for_pkt(&pkts[i]); }

/* delete_<msg>_params */
void delete_INVITE_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)   params_delete_for_pkt(&pkts[i]); }
void delete_REGISTER_params(sip_packet_t *pkts, size_t n, unsigned seeds){for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) params_delete_for_pkt(&pkts[i]);}
void delete_OPTIONS_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)  params_delete_for_pkt(&pkts[i]); }

/* repeat_<msg>_params */
void repeat_INVITE_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)   params_repeat_for_pkt(&pkts[i]); }
void repeat_REGISTER_params(sip_packet_t *pkts, size_t n, unsigned seeds){for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) params_repeat_for_pkt(&pkts[i]);}
void repeat_OPTIONS_params(sip_packet_t *pkts, size_t n, unsigned seeds){ for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)  params_repeat_for_pkt(&pkts[i]); }



/* 设置 Date 头为“存在”，并给一个默认合法值 */
static void date_set_present_default(sip_date_hdr_t *h) {
    scpy(h->name,        sizeof h->name,        "Date");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->rfc1123,     sizeof h->rfc1123,     "Sat, 13 Nov 2010 23:29:00 GMT");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
}

/* 若包中 Date 头不存在，则补齐基本字段并填一个合规值 */
static sip_date_hdr_t* ensure_date_hdr_for_pkt(sip_packet_t *p) {
    if (!p) return NULL;
    sip_date_hdr_t *h = NULL;
    switch (p->cmd_type) {
      case SIP_PKT_INVITE:   h = &p->pkt.invite.date; break;
      case SIP_PKT_ACK:      h = &p->pkt.ack.date; break;
      case SIP_PKT_BYE:      h = &p->pkt.bye.date; break;
      case SIP_PKT_CANCEL:   h = &p->pkt.cancel.date; break;
      case SIP_PKT_REGISTER: h = &p->pkt.register_.date; break;
      case SIP_PKT_OPTIONS:  h = &p->pkt.options.date; break;
      default: return NULL;
    }
    if (h->name[0] == '\0') date_set_present_default(h);
    return h;
}

/* 尝试用当前时间生成合法 RFC1123（GMT） */
static void set_rfc1123_now(sip_date_hdr_t *h) {
    time_t t = time(NULL);
    struct tm g; 
#if defined(_WIN32)
    gmtime_s(&g, &t);
#else
    g = *gmtime(&t);
#endif
    /* 例：Sun, 06 Nov 1994 08:49:37 GMT */
    char buf[128];
    size_t n = strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &g);
    if (n == 0) scpy(h->rfc1123, sizeof h->rfc1123, "Sun, 06 Nov 1994 08:49:37 GMT");
    else        scpy(h->rfc1123, sizeof h->rfc1123, buf);
}

/* -------------------- 变异算子（rfc1123） >= 10 --------------------
   既有“合法但边界”的，也有“格式/语法非法”的。
*/

static void dt_valid_now(sip_date_hdr_t *h) { set_rfc1123_now(h); }
static void dt_fixed_past(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Mon, 01 Jan 1901 00:00:00 GMT"); }
static void dt_fixed_future(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Fri, 01 Jan 2100 12:34:56 GMT"); }

/* 非法/边界 */
static void dt_bad_wkday(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Fry, 13 Nov 2010 23:29:00 GMT"); }     /* 错误的 weekday */
static void dt_bad_month(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Xxx 2010 23:29:00 GMT"); }     /* 错误的 month */
static void dt_day_32(sip_date_hdr_t *h)    { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 32 Nov 2010 23:29:00 GMT"); }
static void dt_hour_24(sip_date_hdr_t *h)   { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2010 24:00:00 GMT"); }
static void dt_sec_60(sip_date_hdr_t *h)    { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2016 23:59:60 GMT"); }     /* 闰秒 */
static void dt_no_gmt(sip_date_hdr_t *h)    { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2010 23:29:00"); }         /* 缺少 GMT */
static void dt_tz_offset(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2010 23:29:00 +0000"); }   /* 非 RFC1123 */
static void dt_missing_comma(sip_date_hdr_t *h){ scpy(h->rfc1123, sizeof h->rfc1123, "Sat 13 Nov 2010 23:29:00 GMT"); }
static void dt_lowercase(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "sat, 13 nov 2010 23:29:00 gmt"); }
static void dt_spaces_tabs(sip_date_hdr_t *h){ scpy(h->rfc1123, sizeof h->rfc1123, "Sat,\t13  Nov  2010  23:29:00\tGMT"); }
static void dt_two_digit_year(sip_date_hdr_t *h){ scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 10 23:29:00 GMT"); }
static void dt_no_seconds(sip_date_hdr_t *h){ scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2010 23:29 GMT"); }
static void dt_empty(sip_date_hdr_t *h)     { h->rfc1123[0] = '\0'; }
static void dt_maxlen(sip_date_hdr_t *h)    { sfill(h->rfc1123, sizeof h->rfc1123, 'D', sizeof h->rfc1123 - 1); }
static void dt_ctrl_bytes(sip_date_hdr_t *h){ h->rfc1123[0]=1; h->rfc1123[1]='G'; h->rfc1123[2]=0; }
static void dt_header_inject(sip_date_hdr_t *h){ scpy(h->rfc1123, sizeof h->rfc1123, "Sat, 13 Nov 2010 23:29:00 GMT\r\nVia: SIP/2.0/UDP evil"); }

/* 兼容/历史格式（HTTP 的 obs-date） */
static void dt_rfc850(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Saturday, 13-Nov-10 23:29:00 GMT"); }
static void dt_ansi_ctime(sip_date_hdr_t *h) { scpy(h->rfc1123, sizeof h->rfc1123, "Sat Nov 13 23:29:00 2010"); }


// static void mutate_one_date_value(sip_date_hdr_t *h, unsigned *rs) {
//     if (h->name[0] == '\0') date_set_present_default(h);
//     switch (rnd_pick(rs, 21)) {
//       case 0:  dt_valid_now(h); break;
//       case 1:  dt_fixed_past(h); break;
//       case 2:  dt_fixed_future(h); break;
//       case 3:  dt_bad_wkday(h); break;
//       case 4:  dt_bad_month(h); break;
//       case 5:  dt_day_32(h); break;
//       case 6:  dt_hour_24(h); break;
//       case 7:  dt_sec_60(h); break;
//       case 8:  dt_no_gmt(h); break;
//       case 9:  dt_tz_offset(h); break;
//       case 10: dt_missing_comma(h); break;
//       case 11: dt_lowercase(h); break;
//       case 12: dt_spaces_tabs(h); break;
//       case 13: dt_two_digit_year(h); break;
//       case 14: dt_no_seconds(h); break;
//       case 15: dt_empty(h); break;
//       case 16: dt_maxlen(h); break;
//       case 17: dt_ctrl_bytes(h); break;
//       case 18: dt_header_inject(h); break;
//       case 19: dt_rfc850(h); break;
//       default: dt_ansi_ctime(h); break;
//     }
// }
static void mutate_one_date_value(sip_date_hdr_t *h, unsigned *rs) {
    if (h->name[0] == '\0') date_set_present_default(h);

    /* 只从语法合法的算子中选：0,1,2,19,20 */
    static const unsigned legal_ops[] = {0, 1, 2, 19, 20};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op) {
      case 0:  dt_valid_now(h);      break;  /* IMF-fixdate */
      case 1:  dt_fixed_past(h);     break;  /* IMF-fixdate */
      case 2:  dt_fixed_future(h);   break;  /* IMF-fixdate */
      case 19: dt_rfc850(h);         break;  /* RFC850-date */
      case 20: dt_ansi_ctime(h);     break;  /* asctime-date */
      default: dt_valid_now(h);      break;
    }
}

/* -------------------- 对外：强力变异入口 -------------------- */
/* 对数组中的 INVITE/ACK/BYE/CANCEL/REGISTER/OPTIONS 的 Date 头做 1~3 次随机变异。 */
void mutate_date_rfc1123(sip_packet_t *pkts, size_t n_pkts, unsigned seed) {
    unsigned rs = seed ? seed : 0xDACEu;
    for (size_t i=0; i<n_pkts; ++i) {
        sip_packet_t *p = &pkts[i];
        if (p->cmd_type != SIP_PKT_INVITE &&
            p->cmd_type != SIP_PKT_ACK &&
            p->cmd_type != SIP_PKT_BYE &&
            p->cmd_type != SIP_PKT_CANCEL &&
            p->cmd_type != SIP_PKT_REGISTER &&
            p->cmd_type != SIP_PKT_OPTIONS) continue;

        sip_date_hdr_t *h = ensure_date_hdr_for_pkt(p);
        if (!h) continue;

        int times = 1;
        for (int t=0; t<times; ++t) mutate_one_date_value(h, &rs);
    }
}

/* -------------------- 可选字段 add / delete -------------------- */
/* add_*_rfc1123：若无 Date 则补齐并填一个合法值；若已存在则刷新为“当前时间” */
static void add_rfc1123_for_pkt(sip_packet_t *p){
    sip_date_hdr_t *h = ensure_date_hdr_for_pkt(p);
    if (!h) return;
    set_rfc1123_now(h);
}

/* delete_*_rfc1123：删除（标记缺省） */
static void delete_rfc1123_for_pkt(sip_packet_t *p){
    sip_date_hdr_t *h = ensure_date_hdr_for_pkt(p);
    if (!h) return;
    h->name[0] = '\0';                 /* 标记为不存在 */
    h->rfc1123[0] = '\0';              /* 清空值（可选） */
}

/* 六种方法各自的 add/delete 包装 */
void add_INVITE_rfc1123(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_INVITE)   add_rfc1123_for_pkt(&pkts[i]); }
void add_ACK_rfc1123   (sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_ACK)      add_rfc1123_for_pkt(&pkts[i]); }
void add_BYE_rfc1123   (sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_BYE)      add_rfc1123_for_pkt(&pkts[i]); }
void add_CANCEL_rfc1123(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_CANCEL)   add_rfc1123_for_pkt(&pkts[i]); }
void add_REGISTER_rfc1123(sip_packet_t *pkts,size_t n, unsigned seed){for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_REGISTER) add_rfc1123_for_pkt(&pkts[i]); }
void add_OPTIONS_rfc1123 (sip_packet_t *pkts,size_t n, unsigned seed){for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_OPTIONS)  add_rfc1123_for_pkt(&pkts[i]); }

void delete_INVITE_rfc1123(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_INVITE)   delete_rfc1123_for_pkt(&pkts[i]); }
void delete_ACK_rfc1123   (sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_ACK)      delete_rfc1123_for_pkt(&pkts[i]); }
void delete_BYE_rfc1123   (sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_BYE)      delete_rfc1123_for_pkt(&pkts[i]); }
void delete_CANCEL_rfc1123(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_CANCEL)   delete_rfc1123_for_pkt(&pkts[i]); }
void delete_REGISTER_rfc1123(sip_packet_t *pkts,size_t n, unsigned seed){for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_REGISTER) delete_rfc1123_for_pkt(&pkts[i]); }
void delete_OPTIONS_rfc1123 (sip_packet_t *pkts,size_t n, unsigned seed){for(size_t i=0;i<n;i++) if(pkts[i].cmd_type==SIP_PKT_OPTIONS)  delete_rfc1123_for_pkt(&pkts[i]); }




/* 取出（或确保构造）当前包的 Encryption 头指针；若不存在则按默认填充（scheme=pgp, params=""） */
static sip_encryption_hdr_t* ensure_enc_hdr_for_pkt(sip_packet_t *p) {
    if (!p) return NULL;
    sip_encryption_hdr_t *h = NULL;
    switch (p->cmd_type) {
      case SIP_PKT_INVITE:   h = &p->pkt.invite.encryption; break;
      case SIP_PKT_ACK:      h = &p->pkt.ack.encryption; break;
      case SIP_PKT_BYE:      h = &p->pkt.bye.encryption; break;
      case SIP_PKT_CANCEL:   h = &p->pkt.cancel.encryption; break;
      case SIP_PKT_REGISTER: h = &p->pkt.register_.encryption; break;
      case SIP_PKT_OPTIONS:  h = &p->pkt.options.encryption; break;
      default: return NULL;
    }
    if (h->name[0] == '\0') {
        scpy(h->name,        sizeof h->name,        "Encryption");
        scpy(h->colon_space, sizeof h->colon_space, ": ");
        scpy(h->scheme,      sizeof h->scheme,      "pgp");
        h->params[0] = '\0';
        scpy(h->crlf,        sizeof h->crlf,        "\r\n");
    }
    return h;
}

/* 仅取指针（不自动创建），用于 delete_* 安全判空 */
static sip_encryption_hdr_t* peek_enc_hdr_for_pkt(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
      case SIP_PKT_INVITE:   return &p->pkt.invite.encryption;
      case SIP_PKT_ACK:      return &p->pkt.ack.encryption;
      case SIP_PKT_BYE:      return &p->pkt.bye.encryption;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.encryption;
      case SIP_PKT_REGISTER: return &p->pkt.register_.encryption;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.encryption;
      default: return NULL;
    }
}

/* -------------------- 字段级 add / delete -------------------- */
/* scheme：增加/删除（删除后留下空 scheme，属于非法但用于 fuzz） */
static void add_scheme_for_pkt(sip_packet_t *p) {
    sip_encryption_hdr_t *h = ensure_enc_hdr_for_pkt(p);
    if (!h) return;
    if (h->scheme[0] == '\0') scpy(h->scheme, sizeof h->scheme, "pgp");
}
static void delete_scheme_for_pkt(sip_packet_t *p) {
    sip_encryption_hdr_t *h = peek_enc_hdr_for_pkt(p);
    if (!h || h->name[0] == '\0') return;
    h->scheme[0] = '\0'; /* header 仍在，但 scheme 空 -> 非法情形 */
}

/* params：增加/删除（删除后 params 置空，属于合法情况） */
static void add_params_for_pkt(sip_packet_t *p) {
    sip_encryption_hdr_t *h = ensure_enc_hdr_for_pkt(p);
    if (!h) return;
    if (h->params[0] == '\0') scpy(h->params, sizeof h->params, ";alg=pgp;key=abc123");
}
static void delete_params_for_pkt(sip_packet_t *p) {
    sip_encryption_hdr_t *h = peek_enc_hdr_for_pkt(p);
    if (!h || h->name[0] == '\0') return;
    h->params[0] = '\0';
}

/* 6 种方法的包装（add/delete scheme、add/delete params） */
#define GEN_ADD_DEL_SCHEME(MSGNAME, PRED) \
void add_##MSGNAME##_scheme(sip_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if PRED add_scheme_for_pkt(&pkts[i]); } \
void delete_##MSGNAME##_scheme(sip_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if PRED delete_scheme_for_pkt(&pkts[i]); }

#define GEN_ADD_DEL_PARAMS(MSGNAME, PRED) \
void add_##MSGNAME##_params(sip_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if PRED add_params_for_pkt(&pkts[i]); } \
void delete_##MSGNAME##_params(sip_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if PRED delete_params_for_pkt(&pkts[i]); }

static void op_scheme_set(sip_encryption_hdr_t *h, const char *v){ scpy(h->scheme, sizeof h->scheme, v); }
static void op_params_set(sip_encryption_hdr_t *h, const char *v){ scpy(h->params, sizeof h->params, v); }

// static void mutate_one_enc(sip_encryption_hdr_t *h, unsigned *rs) {
//     /* 0..19 → 20 种变异 */
//     switch (rnd_pick(rs, 20)) {
//       /* ---- scheme 合法/语义变体 ---- */
//       case 0:  op_scheme_set(h, "pgp"); break;
//       case 1:  op_scheme_set(h, "clear"); break;                 /* 明文声明 */
//       case 2:  op_scheme_set(h, "s-mime"); break;                /* 历史/扩展 token */
//       case 3:  op_scheme_set(h, "tls"); break;                   /* 非典型，但看栈容忍度 */
//       /* ---- scheme 边界/非法 ---- */
//       case 4:  h->scheme[0] = '\0'; break;                       /* 空 scheme（非法） */
//       case 5:  op_scheme_set(h, " PGP"); break;                  /* 前置空格（非法） */
//       case 6:  op_scheme_set(h, "pgp/1*bad"); break;             /* 非 token 字符 */
//       case 7:  sfill(h->scheme, sizeof h->scheme, 'X', sizeof h->scheme-1); break; /* 过长 */
//       /* ---- params：合法/常见 ---- */
//       case 8:  op_params_set(h, ""); break;                      /* 空参数（合法） */
//       case 9:  op_params_set(h, ";alg=pgp;key=abc123"); break;   /* 正常多参数 */
//       case 10: op_params_set(h, ";alg=\"pgp\";key=\"a b c\""); break; /* 引号与空格 */
//       case 11: op_params_set(h, ";iv=01020304;nonce=deadbeef"); break;
//       /* ---- params：格式错误/注入/边界 ---- */
//       case 12: op_params_set(h, "key=abc"); break;               /* 缺少前导 ';'（非法） */
//       case 13: op_params_set(h, ";;;;"); break;                  /* 只有分号（非法/边界） */
//       case 14: op_params_set(h, ";alg==pgp"); break;             /* 双 '='（非法） */
//       case 15: op_params_set(h, ";alg=pgp;alg=clear"); break;    /* 重复键 */
//       case 16: op_params_set(h, ";a="); break;                   /* 空值（非法边界） */
//       case 17: { char tmp[SIP_PARAMS_LEN]; sfill(tmp, sizeof tmp, 'A', sizeof tmp-1); op_params_set(h, tmp); } break; /* 超长 */
//       case 18: { char inj[64]; scpy(inj, sizeof inj, ";x=1\r\nVia: SIP/2.0/UDP evil"); op_params_set(h, inj); } break; /* 头注入 */
//       default: { char odd[32]; odd[0]=(char)0x01; odd[1]='Z'; odd[2]=(char)0xFF; odd[3]=0; op_params_set(h, odd); } break; /* 控制字节/非ASCII */
//     }
// }
static void mutate_one_enc(sip_encryption_hdr_t *h, unsigned *rs) {
    /* 若 scheme 为空，先补一个合法 token，避免选 params 时形成非法头 */
    if (h->scheme[0] == '\0') op_scheme_set(h, "pgp");

    /* 只从语法合法的算子中选：0,1,2,3,7,8,9,10,11,15 */
    static const unsigned legal_ops[] = {0, 1, 2, 3, 7, 8, 9, 10, 11, 15};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op) {
      /* ---- scheme 合法/语义变体 ---- */
      case 0:  op_scheme_set(h, "pgp"); break;
      case 1:  op_scheme_set(h, "clear"); break;
      case 2:  op_scheme_set(h, "s-mime"); break;
      case 3:  op_scheme_set(h, "tls"); break;
      case 7:  sfill(h->scheme, sizeof h->scheme, 'X', sizeof h->scheme-1); break;

      /* ---- params：合法/常见 ---- */
      case 8:  op_params_set(h, ""); break;
      case 9:  op_params_set(h, ";alg=pgp;key=abc123"); break;
      case 10: op_params_set(h, ";alg=\"pgp\";key=\"a b c\""); break;
      case 11: op_params_set(h, ";iv=01020304;nonce=deadbeef"); break;
      case 15: op_params_set(h, ";alg=pgp;alg=clear"); break;

      default: op_scheme_set(h, "pgp"); op_params_set(h, ""); break;
    }
}

void mutate_encryption_fields(sip_packet_t *pkts, size_t n_pkts, unsigned seed) {
    unsigned rs = seed ? seed : 0xE1C3u;
    for (size_t i=0; i<n_pkts; ++i) {
        sip_encryption_hdr_t *h = ensure_enc_hdr_for_pkt(&pkts[i]);
        if (!h) continue;

        mutate_one_enc(h, &rs);
    }
}


static unsigned lcg_next(unsigned *st){ *st = (*st*1103515245u + 12345u); return *st; }

/* 仅 INVITE / REGISTER 有 Expires；其余返回 NULL */
static sip_expires_hdr_t* peek_expires_for_pkt(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
      case SIP_PKT_INVITE:   return &p->pkt.invite.expires;
      case SIP_PKT_REGISTER: return &p->pkt.register_.expires;
      default: return NULL;
    }
}
/* 确保 Expires 存在；若缺失则以一个安全默认值建一个 */
static sip_expires_hdr_t* ensure_expires_for_pkt(sip_packet_t *p) {
    sip_expires_hdr_t *h = peek_expires_for_pkt(p);
    if (!h) return NULL;
    if (h->name[0] == '\0') {
        scpy(h->name,        sizeof h->name,        "Expires");
        scpy(h->colon_space, sizeof h->colon_space, ": ");
        scpy(h->value,       sizeof h->value,       "3600");
        scpy(h->crlf,        sizeof h->crlf,        "\r\n");
    }
    return h;
}

/* -------------------- add / delete -------------------- */
void add_INVITE_expires(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE) {
        sip_expires_hdr_t *h = ensure_expires_for_pkt(&pkts[i]);
        if (h && h->value[0]=='\0') scpy(h->value, sizeof h->value, "3600");
    }
}
void delete_INVITE_expires(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE) {
        sip_expires_hdr_t *h = peek_expires_for_pkt(&pkts[i]);
        if (h) h->name[0] = '\0'; /* 你的解析/重组约定：name[0]==0 表示头缺省 */
    }
}
void add_REGISTER_expires(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) {
        sip_expires_hdr_t *h = ensure_expires_for_pkt(&pkts[i]);
        if (h && h->value[0]=='\0') scpy(h->value, sizeof h->value, "300");
    }
}
void delete_REGISTER_expires(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) {
        sip_expires_hdr_t *h = peek_expires_for_pkt(&pkts[i]);
        if (h) h->name[0] = '\0';
    }
}
static void set_val(sip_expires_hdr_t *h, const char *v){ scpy(h->value, sizeof h->value, v); }

// static void mutate_one_expires(sip_expires_hdr_t *h, unsigned *rs) {
//     switch (rnd_pick(rs, 16)) {
//       /* ---- 合法 delta-seconds ---- */
//       case 0:  set_val(h, "0"); break;
//       case 1:  set_val(h, "1"); break;
//       case 2:  set_val(h, "60"); break;
//       case 3:  set_val(h, "3600"); break;
//       /* ---- 边界/非法数字 ---- */
//       case 4:  set_val(h, "-1"); break;                 /* 负数 */
//       case 5:  set_val(h, "4294967295"); break;         /* 2^32-1 边界 */
//       case 6:  set_val(h, "9999999999"); break;         /* 极大值 */
//       case 7:  set_val(h, "  300 \t"); break;           /* 前后空白 */
//       /* ---- 格式错数字 ---- */
//       case 8:  set_val(h, "12.34"); break;              /* 小数 */
//       case 9:  set_val(h, "0x10"); break;               /* 十六进制风格 */
//       /* ---- 合法/非法 HTTP-date（RFC1123风格） ---- */
//       case 10: set_val(h, "Sat, 13 Nov 2010 23:29:00 GMT"); break;      /* 合法 */
//       case 11: set_val(h, "Mon, 01 Jan 2035 00:00:00 GMT"); break;      /* 合法未来 */
//       case 12: set_val(h, "Fak, 32 Foo 2010 99:99:99 GMT"); break;      /* 伪日期 */
//       case 13: set_val(h, "Sat, 13 Nov 2010 23:29:00 UTC"); break;      /* 非 GMT 时区 */
//       /* ---- 其他极端 ---- */
//       case 14: { char tmp[SIP_TEXT_LEN]; sfill(tmp, sizeof tmp, 'A', sizeof tmp-1); set_val(h, tmp); } break; /* 超长 */
//       default: set_val(h, "3600\r\nVia: SIP/2.0/UDP evil"); break;      /* 头注入 */
//     }
// }
static void mutate_one_expires(sip_expires_hdr_t *h, unsigned *rs) {
    /* 只从语法合法的算子中选：0,1,2,3,5,6,10,11 */
    static const unsigned legal_ops[] = {0, 1, 2, 3, 5, 6, 10, 11};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op) {
      /* ---- 合法 delta-seconds ---- */
      case 0:  set_val(h, "0"); break;
      case 1:  set_val(h, "1"); break;
      case 2:  set_val(h, "60"); break;
      case 3:  set_val(h, "3600"); break;

      /* ---- 纯数字大值（语法合法） ---- */
      case 5:  set_val(h, "4294967295"); break;
      case 6:  set_val(h, "9999999999"); break;

      /* ---- 合法 HTTP-date（RFC1123 + GMT） ---- */
      case 10: set_val(h, "Sat, 13 Nov 2010 23:29:00 GMT"); break;
      case 11: set_val(h, "Mon, 01 Jan 2035 00:00:00 GMT"); break;

      default: set_val(h, "3600"); break; /* 理论不会到这 */
    }
}

void mutate_expires_values(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed ? seed : 0xC0FFEEu;
    for (size_t i=0;i<n;i++){
        sip_expires_hdr_t *h = ensure_expires_for_pkt(&pkts[i]);
        if (!h) continue;                /* 只处理 INVITE/REGISTER */

        mutate_one_expires(h, &rs);
    }
}


static char rnd_alnum(unsigned *st){
    static const char T[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return T[rnd_pick(st, (unsigned)(sizeof(T)-1))];
}
static void gen_token(char *dst, size_t cap, unsigned *st, size_t min_len, size_t max_len){
    if (!dst || cap==0) return;
    size_t L = min_len + rnd_pick(st, (unsigned)(max_len - min_len + 1));
    size_t m = MIN(cap-1, L);
    for (size_t i=0;i<m;i++) dst[i]=rnd_alnum(st);
    dst[m]='\0';
}

static void ensure_from_present(sip_from_hdr_t *h){
    if (h->name[0]) return;
    scpy(h->name,        sizeof h->name,        "From");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    h->display[0] = '\0';
    h->sp_opt = '\0';
    h->lt = '<';
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
    h->gt = '>';
    scpy(h->params, sizeof h->params, ";tag=init");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}

/* 所有请求类型都含 From，统一获取指针 */
static sip_from_hdr_t* get_from_ptr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.from_;
        case SIP_PKT_ACK:      return &p->pkt.ack.from_;
        case SIP_PKT_BYE:      return &p->pkt.bye.from_;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.from_;
        case SIP_PKT_REGISTER: return &p->pkt.register_.from_;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.from_;
        default: return NULL;
    }
}

/* ---------- 具体变异算子（≥16） ---------- */
static void op_canonical_min(sip_from_hdr_t *h){
    scpy(h->display, sizeof h->display, "");
    h->sp_opt = '\0';
    h->lt = '\0';
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
    h->gt = '\0';
    scpy(h->params, sizeof h->params, ";tag=abc");
}
static void op_name_addr_with_quote(sip_from_hdr_t *h){
    scpy(h->display, sizeof h->display, "\"Alice Example\"");
    h->sp_opt = ' ';
    h->lt = '<';
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com;transport=udp");
    h->gt = '>';
    scpy(h->params, sizeof h->params, ";tag=abcd1234");
}
static void op_remove_tag_param(sip_from_hdr_t *h){          /* 非法：去掉 tag */
    scpy(h->params, sizeof h->params, "");
}
static void op_empty_tag(sip_from_hdr_t *h){                 /* 非法：空 tag 值 */
    scpy(h->params, sizeof h->params, ";tag=");
}
static void op_dup_tag(sip_from_hdr_t *h){                   /* 非法：重复 tag */
    scpy(h->params, sizeof h->params, ";tag=xyz;tag=dup");
}
static void op_long_tag(sip_from_hdr_t *h){
    char big[SIP_PARAMS_LEN];
    char tagval[200];
    sfill(tagval, sizeof tagval, 'A', 180);
    snprintf(big, sizeof big, ";tag=%s", tagval);
    scpy(h->params, sizeof h->params, big);
}
static void op_ipv6_host(sip_from_hdr_t *h){
    h->lt = '<'; h->gt = '>'; h->sp_opt=' ';
    scpy(h->display, sizeof h->display, "\"V6\"");
    scpy(h->uri, sizeof h->uri, "sip:alice@[2001:db8::1];transport=TCP");
    scpy(h->params, sizeof h->params, ";tag=v6tag");
}
static void op_scheme_sips(sip_from_hdr_t *h){
    scpy(h->uri, sizeof h->uri, "sips:alice@example.com");
    scpy(h->params, sizeof h->params, ";tag=sips1");
}
static void op_scheme_tel(sip_from_hdr_t *h){
    h->lt='\0'; h->gt='\0'; h->sp_opt='\0'; h->display[0]='\0';
    scpy(h->uri, sizeof h->uri, "tel:+15551234567");
    scpy(h->params, sizeof h->params, ";tag=telT");
}
static void op_bad_scheme(sip_from_hdr_t *h){                /* 非法 scheme */
    scpy(h->uri, sizeof h->uri, "sipx:alice@example.com");
    scpy(h->params, sizeof h->params, ";tag=badS");
}
static void op_uri_with_headers(sip_from_hdr_t *h){          /* URI ?headers */
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com?subject=Hi&priority=urgent");
    scpy(h->params, sizeof h->params, ";tag=hdrs");
}
static void op_weird_params_on_from(sip_from_hdr_t *h){      /* 非法/无意义参数 */
    scpy(h->params, sizeof h->params, ";tag=X1;lr;maddr=1.2.3.4;foo=bar");
}
static void op_inject_in_params(sip_from_hdr_t *h){          /* 头注入尝试（恶意） */
    scpy(h->params, sizeof h->params, ";tag=xyz\r\nVia: SIP/2.0/UDP attacker");
}
static void op_inject_in_display(sip_from_hdr_t *h){         /* 显示名注入 */
    scpy(h->display, sizeof h->display, "\"Evil\\\"\"\r\nRecord-Route: <sip:evil>"); /* 带 CRLF */
    h->sp_opt = ' ';
    h->lt = '<'; h->gt = '>';
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
    scpy(h->params, sizeof h->params, ";tag=inj");
}
static void op_whitespace_variants(sip_from_hdr_t *h){       /* 空白变体 */
    scpy(h->display, sizeof h->display, "Alice");
    h->sp_opt = '\0'; /* 故意不加空格 */
    h->lt = '<'; h->gt='>';
    scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
    scpy(h->params, sizeof h->params, ";tag=ws");
}
static void op_empty_uri(sip_from_hdr_t *h){                 /* 非法：空 URI */
    h->uri[0]='\0';
    scpy(h->params, sizeof h->params, ";tag=empty");
}

// /* 根据随机选择应用一个算子；并随机生成 tag 值以增加多样性 */
// static void mutate_one_from(sip_from_hdr_t *h, unsigned *rs){
//     if (!h) return;
//     /* 随机给 tag 值换一个 token（对带 tag 的场景都能生效） */
//     if (h->params[0]){
//         char newtag[32]; gen_token(newtag, sizeof newtag, rs, 3, 12);
//         /* 简单替换常见形式 ;tag=xxxx （找第一个出现）*/
//         char *pos = strstr(h->params, ";tag=");
//         if (pos){
//             pos += 5;
//             size_t remain = (size_t)((h->params + sizeof h->params - 1) - pos);
//             scpy(pos, remain, newtag);
//         }
//     }

//     switch (rnd_pick(rs, 17)){
//         case 0:  op_canonical_min(h); break;
//         case 1:  op_name_addr_with_quote(h); break;
//         case 2:  op_remove_tag_param(h); break;
//         case 3:  op_empty_tag(h); break;
//         case 4:  op_dup_tag(h); break;
//         case 5:  op_long_tag(h); break;
//         case 6:  op_ipv6_host(h); break;
//         case 7:  op_scheme_sips(h); break;
//         case 8:  op_scheme_tel(h); break;
//         case 9:  op_bad_scheme(h); break;
//         case 10: op_uri_with_headers(h); break;
//         case 11: op_weird_params_on_from(h); break;
//         case 12: op_inject_in_params(h); break;
//         case 13: op_inject_in_display(h); break;
//         case 14: op_whitespace_variants(h); break;
//         case 15: op_empty_uri(h); break;
//         default: { /* 超长 display */
//             sfill(h->display, sizeof h->display, 'D', sizeof h->display-1);
//             h->sp_opt = ' '; h->lt='<'; h->gt='>';
//             scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
//             scpy(h->params, sizeof h->params, ";tag=DD");
//         } break;
//     }
// }
/* 根据随机选择应用一个算子；并随机生成 tag 值以增加多样性 */
static void mutate_one_from(sip_from_hdr_t *h, unsigned *rs){
    if (!h) return;

    /* 随机给 tag 值换一个 token（对带 tag 的场景都能生效） */
    if (h->params[0]){
        char newtag[32]; gen_token(newtag, sizeof newtag, rs, 3, 12);
        /* 简单替换常见形式 ;tag=xxxx （找第一个出现）*/
        char *pos = strstr(h->params, ";tag=");
        if (pos){
            pos += 5;
            size_t remain = (size_t)((h->params + sizeof h->params - 1) - pos);
            scpy(pos, remain, newtag);
        }
    }

    /* 只从语法合法的算子中选 */
    static const unsigned legal_ops[] = {0, 1, 2, 4, 5, 6, 7, 8, 10, 16};
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op){
        case 0:  op_canonical_min(h); break;
        case 1:  op_name_addr_with_quote(h); break;
        case 2:  op_remove_tag_param(h); break;
        case 3:  op_empty_tag(h); break;              /* 不会被选到 */
        case 4:  op_dup_tag(h); break;
        case 5:  op_long_tag(h); break;
        case 6:  op_ipv6_host(h); break;
        case 7:  op_scheme_sips(h); break;
        case 8:  op_scheme_tel(h); break;
        case 9:  op_bad_scheme(h); break;            /* 不会被选到 */
        case 10: op_uri_with_headers(h); break;
        case 11: op_weird_params_on_from(h); break;  /* 不会被选到 */
        case 12: op_inject_in_params(h); break;      /* 不会被选到 */
        case 13: op_inject_in_display(h); break;     /* 不会被选到 */
        case 14: op_whitespace_variants(h); break;   /* 不会被选到 */
        case 15: op_empty_uri(h); break;             /* 不会被选到 */
        default: { /* 超长 display（语法合法） */
            sfill(h->display, sizeof h->display, 'D', sizeof h->display-1);
            h->sp_opt = ' '; h->lt='<'; h->gt='>';
            scpy(h->uri, sizeof h->uri, "sip:alice@example.com");
            scpy(h->params, sizeof h->params, ";tag=DD");
        } break;
    }
}

/* --------- 对外：遍历数组做 1~3 次随机变异/包 --------- */
void mutate_from_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed ? seed : 0xF00DFACEu;
    for (size_t i=0;i<n;i++){
        sip_from_hdr_t *h = get_from_ptr(&pkts[i]);
        if (!h) continue;
        ensure_from_present(h);

        mutate_one_from(h, &rs);

        /* 最后兜底：如果没有 tag，就给一个（虽然某些算子故意去掉了它） */
        if (!strstr(h->params, ";tag=")){
            char rndtag[16]; gen_token(rndtag, sizeof rndtag, &rs, 4, 10);
            size_t cur = strnlen(h->params, sizeof h->params);
            if (cur + 6 + strlen(rndtag) < sizeof h->params){
                strcat(h->params, ";tag=");
                strcat(h->params, rndtag);
            }else{
                scpy(h->params, sizeof h->params, ";tag=fix");
            }
        }
    }
}


static void rr_set_present(sip_record_route_hdr_t *h,
                           const char *uri, const char *params,
                           int use_angle)
{
    scpy(h->name,        sizeof h->name,        "Record-Route");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    if (use_angle){ h->lt = '<'; h->gt = '>'; }
    else           { h->lt = '\0'; h->gt = '\0'; }
    scpy(h->uri,    sizeof h->uri,    uri?uri:"sip:proxy.example.com");
    scpy(h->params, sizeof h->params, params?params:";lr");
    scpy(h->crlf,   sizeof h->crlf,   "\r\n");
}

static void rr_mark_absent(sip_record_route_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

typedef struct {
    sip_record_route_hdr_t *arr;
    size_t *count;
    size_t cap;
} rr_array_t;

/* 取到当前包的 RR 数组、count、容量 */
static rr_array_t get_rr_array(sip_packet_t *p){
    rr_array_t r = {0};
    if (!p) return r;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:
            r.arr   = p->pkt.invite.record_route;
            r.count = &p->pkt.invite.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        case SIP_PKT_ACK:
            r.arr   = p->pkt.ack.record_route;
            r.count = &p->pkt.ack.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        case SIP_PKT_BYE:
            r.arr   = p->pkt.bye.record_route;
            r.count = &p->pkt.bye.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        case SIP_PKT_CANCEL:
            r.arr   = p->pkt.cancel.record_route;
            r.count = &p->pkt.cancel.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        case SIP_PKT_REGISTER:
            r.arr   = p->pkt.register_.record_route;
            r.count = &p->pkt.register_.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        case SIP_PKT_OPTIONS:
            r.arr   = p->pkt.options.record_route;
            r.count = &p->pkt.options.record_route_count;
            r.cap   = SIP_MAX_RECORD_ROUTE; break;
        default: break;
    }
    return r;
}

/* ============== add / delete / repeat API ============== */
/* add_<msg>_record_route：为匹配类型的包追加 1 条 RR */
static void add_record_route_for_pkt(sip_packet_t *p, const char *uri, const char *params, int use_angle){
    rr_array_t r = get_rr_array(p);
    if (!r.arr || !r.count || *r.count >= r.cap) return;
    rr_set_present(&r.arr[*r.count], uri, params, use_angle);
    (*r.count)++;
}

void add_invite_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}
void add_ack_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_ACK)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}
void add_bye_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_BYE)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}
void add_cancel_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_CANCEL)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}
void add_register_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}
void add_options_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)
        add_record_route_for_pkt(&pkts[i], "sip:proxy.example.com", ";lr", 1);
}

/* delete_<msg>_record_route：清空该字段（所有条目） */
static void delete_record_route_for_pkt(sip_packet_t *p){
    rr_array_t r = get_rr_array(p);
    if (!r.arr || !r.count) return;
    for (size_t i=0;i<*r.count;i++) rr_mark_absent(&r.arr[i]);
    *r.count = 0;
}

void delete_invite_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE) delete_record_route_for_pkt(&pkts[i]);
}
void delete_ack_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_ACK) delete_record_route_for_pkt(&pkts[i]);
}
void delete_bye_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_BYE) delete_record_route_for_pkt(&pkts[i]);
}
void delete_cancel_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_CANCEL) delete_record_route_for_pkt(&pkts[i]);
}
void delete_register_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) delete_record_route_for_pkt(&pkts[i]);
}
void delete_options_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS) delete_record_route_for_pkt(&pkts[i]);
}

/* repeat_<msg>_record_route：把已有条目复制/扩展至上限 */
static void repeat_record_route_for_pkt(sip_packet_t *p){
    rr_array_t r = get_rr_array(p);
    if (!r.arr || !r.count || r.cap==0) return;
    if (*r.count==0){
        add_record_route_for_pkt(p, "sip:first.proxy.example.com", ";lr", 1);
    }
    /* 简单复制现有条目直到容量，最后一条稍作变化 */
    while (*r.count < r.cap){
        r.arr[*r.count] = r.arr[(*r.count-1)];
        /* 末尾两条放点变化 */
        if (*r.count == r.cap-1){
            scpy(r.arr[*r.count].uri, sizeof r.arr[*r.count].uri, "sips:last.proxy.example.com;transport=tcp");
            scpy(r.arr[*r.count].params, sizeof r.arr[*r.count].params, ";lr;foo=bar");
        }
        (*r.count)++;
    }
}

void repeat_invite_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE) repeat_record_route_for_pkt(&pkts[i]);
}
void repeat_ack_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_ACK) repeat_record_route_for_pkt(&pkts[i]);
}
void repeat_bye_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_BYE) repeat_record_route_for_pkt(&pkts[i]);
}
void repeat_cancel_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_CANCEL) repeat_record_route_for_pkt(&pkts[i]);
}
void repeat_register_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) repeat_record_route_for_pkt(&pkts[i]);
}
void repeat_options_record_route(sip_packet_t *pkts, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS) repeat_record_route_for_pkt(&pkts[i]);
}

/* ================== 综合变异器（≥16 种算子） ================== */

static void rr_op_toggle_angle(sip_record_route_hdr_t *h){ h->lt = (h->lt?'\0':'<'); h->gt = (h->lt?'>':'\0'); }
static void rr_op_remove_gt_only(sip_record_route_hdr_t *h){ h->gt='\0'; }              /* 非法：缺右尖括号 */
static void rr_op_remove_lt_only(sip_record_route_hdr_t *h){ h->lt='\0'; }              /* 非法：缺左尖括号 */
static void rr_op_empty_uri(sip_record_route_hdr_t *h){ h->uri[0]='\0'; }               /* 非法：空 URI */
static void rr_op_set_tel_uri(sip_record_route_hdr_t *h){ scpy(h->uri,sizeof h->uri,"tel:+15551234567"); } /* 非法或非典型 */
static void rr_op_set_sips(sip_record_route_hdr_t *h){ scpy(h->uri,sizeof h->uri,"sips:proxy.example.com"); }
static void rr_op_set_bad_scheme(sip_record_route_hdr_t *h){ scpy(h->uri,sizeof h->uri,"sipx:proxy.example.com"); } /* 非法 */
static void rr_op_ipv6(sip_record_route_hdr_t *h){ scpy(h->uri,sizeof h->uri,"sip:[2001:db8::1]"); }
static void rr_op_uri_params_transport(sip_record_route_hdr_t *h){ scpy(h->uri,sizeof h->uri,"sip:proxy.example.com;transport=tcp"); }
static void rr_op_add_lr(sip_record_route_hdr_t *h){ /* 加上 ;lr（若没有） */
    if (!strstr(h->params, ";lr")){
        size_t cur=strnlen(h->params,sizeof h->params);
        if (cur+3 < sizeof h->params) strcat(h->params, ";lr");
        else scpy(h->params,sizeof h->params,";lr");
    }
}
static void rr_op_del_lr(sip_record_route_hdr_t *h){ /* 删除 ;lr（非法/不推荐） */
    char *p=strstr(h->params,";lr");
    if (p){ memmove(p, p+3, strlen(p+3)+1); }
}
static void rr_op_lr_with_value(sip_record_route_hdr_t *h){ scpy(h->params,sizeof h->params,";lr=true"); } /* 非法：lr 是 flag-param */
static void rr_op_dup_lr(sip_record_route_hdr_t *h){ scpy(h->params,sizeof h->params,";lr;lr;foo=bar"); } /* 非法/奇异 */
static void rr_op_long_params(sip_record_route_hdr_t *h){ char big[SIP_PARAMS_LEN]; sfill(big,sizeof big,'A',sizeof big-2); big[0]=';'; scpy(h->params,sizeof h->params,big); }
static void rr_op_inject_header(sip_record_route_hdr_t *h){ scpy(h->params,sizeof h->params,";x=\r\nVia: SIP/2.0/UDP evil"); } /* CRLF 注入 */
static void rr_op_multi_in_one_line(sip_record_route_hdr_t *h){ scpy(h->params,sizeof h->params,", <sip:extra.proxy>;lr"); }   /* 逗号拼多个值（语法合法，但此结构非最佳承载） */
static void rr_op_randomize_case_lr(sip_record_route_hdr_t *h){ scpy(h->params,sizeof h->params,";LR;Lr;lR"); }               /* 大小写混淆 */
static void rr_op_overlong_uri(sip_record_route_hdr_t *h){ sfill(h->uri,sizeof h->uri,'U',sizeof h->uri-1); }                 /* 超长 */

// static void mutate_one_rr_line(sip_record_route_hdr_t *h, unsigned *rs){
//     if (!h || !h->name[0]) return;
//     switch (rnd_pick(rs, 18)){
//         case 0:  rr_op_toggle_angle(h); break;
//         case 1:  rr_op_remove_gt_only(h); break;
//         case 2:  rr_op_remove_lt_only(h); break;
//         case 3:  rr_op_empty_uri(h); break;
//         case 4:  rr_op_set_tel_uri(h); break;
//         case 5:  rr_op_set_sips(h); break;
//         case 6:  rr_op_set_bad_scheme(h); break;
//         case 7:  rr_op_ipv6(h); break;
//         case 8:  rr_op_uri_params_transport(h); break;
//         case 9:  rr_op_add_lr(h); break;
//         case 10: rr_op_del_lr(h); break;
//         case 11: rr_op_lr_with_value(h); break;
//         case 12: rr_op_dup_lr(h); break;
//         case 13: rr_op_long_params(h); break;
//         case 14: rr_op_inject_header(h); break;
//         case 15: rr_op_multi_in_one_line(h); break;
//         case 16: rr_op_randomize_case_lr(h); break;
//         default: rr_op_overlong_uri(h); break;
//     }
// }
static void mutate_one_rr_line(sip_record_route_hdr_t *h, unsigned *rs){
    if (!h || !h->name[0]) return;

    /* 只从语法合法的算子中选 */
    static const unsigned legal_ops[] = {
        0, 4, 5, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17
    };
    unsigned op = legal_ops[
        rnd_pick(rs, (unsigned)(sizeof(legal_ops)/sizeof(legal_ops[0])))
    ];

    switch (op){
        case 0:  rr_op_toggle_angle(h); break;
        case 1:  rr_op_remove_gt_only(h); break;     /* 不会被选到 */
        case 2:  rr_op_remove_lt_only(h); break;     /* 不会被选到 */
        case 3:  rr_op_empty_uri(h); break;          /* 不会被选到 */
        case 4:  rr_op_set_tel_uri(h); break;
        case 5:  rr_op_set_sips(h); break;
        case 6:  rr_op_set_bad_scheme(h); break;     /* 不会被选到 */
        case 7:  rr_op_ipv6(h); break;
        case 8:  rr_op_uri_params_transport(h); break;
        case 9:  rr_op_add_lr(h); break;
        case 10: rr_op_del_lr(h); break;
        case 11: rr_op_lr_with_value(h); break;
        case 12: rr_op_dup_lr(h); break;
        case 13: rr_op_long_params(h); break;
        case 14: rr_op_inject_header(h); break;      /* 不会被选到 */
        case 15: rr_op_multi_in_one_line(h); break;
        case 16: rr_op_randomize_case_lr(h); break;
        default: rr_op_overlong_uri(h); break;
    }
}


static void mutate_rr_for_pkt(sip_packet_t *p, unsigned *rs){
    rr_array_t r = get_rr_array(p);
    if (!r.arr || !r.count) return;


    unsigned dice = rnd_pick(rs, 10);
    if (dice < 2){
        delete_record_route_for_pkt(p);
    } else if (dice < 5){
        add_record_route_for_pkt(p, "sip:proxy.example.com", ";lr", 1);
    } else if (dice < 7){
        repeat_record_route_for_pkt(p);
    } else {
        for (size_t k=0;k<*r.count;k++){
            mutate_one_rr_line(&r.arr[k], rs);
        }
    }


}

/* --------- 对外：遍历数组，按包类型执行 RR 变异 --------- */
void mutate_record_route_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed?seed:0xA11CE777u;
    for (size_t i=0;i<n;i++){
        switch (pkts[i].cmd_type){
            case SIP_PKT_INVITE:
            case SIP_PKT_ACK:
            case SIP_PKT_BYE:
            case SIP_PKT_CANCEL:
            case SIP_PKT_REGISTER:
            case SIP_PKT_OPTIONS:
                mutate_rr_for_pkt(&pkts[i], &rs);
                break;
            default: break;
        }
    }
}


/* ========= 取到各包的 Timestamp 指针 ========= */
static sip_timestamp_hdr_t* get_ts_ptr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.timestamp;
        case SIP_PKT_ACK:      return &p->pkt.ack.timestamp;
        case SIP_PKT_BYE:      return &p->pkt.bye.timestamp;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.timestamp;
        case SIP_PKT_REGISTER: return &p->pkt.register_.timestamp;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.timestamp;
        default: return NULL;
    }
}

/* ========= 设为“存在”与“缺省(不存在)” ========= */
static void ts_set_present(sip_timestamp_hdr_t *h, const char *val, const char *delay, int put_space){
    if (!h) return;
    scpy(h->name,        sizeof h->name,        "Timestamp");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->value,       sizeof h->value,       val ? val : "0");
    if (delay && delay[0]){
        h->sp_opt = put_space ? ' ' : ' ';          /* 合法形态建议放一个空格 */
        scpy(h->delay, sizeof h->delay, delay);
    }else{
        h->sp_opt = '\0';
        h->delay[0] = '\0';
    }
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}
static void ts_mark_absent(sip_timestamp_hdr_t *h){
    if (h) h->name[0] = '\0';
}
static int ts_is_absent(const sip_timestamp_hdr_t *h){
    return !h || h->name[0] == '\0';
}

/* ========= add_<msg>_timestamp / delete_<msg>_timestamp ========= */
static void add_timestamp_for_pkt(sip_packet_t *p){
    sip_timestamp_hdr_t *h = get_ts_ptr(p);
    if (!h) return;
    ts_set_present(h, "0", "", 0);
}
static void delete_timestamp_for_pkt(sip_packet_t *p){
    sip_timestamp_hdr_t *h = get_ts_ptr(p);
    if (!h) return;
    ts_mark_absent(h);
}

/* 按类型暴露便捷 API（可按需裁剪） */
void add_invite_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){   for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)   add_timestamp_for_pkt(&pkts[i]); }
void add_ack_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){      for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_ACK)      add_timestamp_for_pkt(&pkts[i]); }
void add_bye_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){      for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_BYE)      add_timestamp_for_pkt(&pkts[i]); }
void add_cancel_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){   for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_CANCEL)   add_timestamp_for_pkt(&pkts[i]); }
void add_register_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) add_timestamp_for_pkt(&pkts[i]); }
void add_options_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){  for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)  add_timestamp_for_pkt(&pkts[i]); }

void delete_invite_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){   for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_INVITE)   delete_timestamp_for_pkt(&pkts[i]); }
void delete_ack_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){      for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_ACK)      delete_timestamp_for_pkt(&pkts[i]); }
void delete_bye_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){      for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_BYE)      delete_timestamp_for_pkt(&pkts[i]); }
void delete_cancel_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){   for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_CANCEL)   delete_timestamp_for_pkt(&pkts[i]); }
void delete_register_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){ for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_REGISTER) delete_timestamp_for_pkt(&pkts[i]); }
void delete_options_timestamp(sip_packet_t *pkts, size_t n, unsigned seed){  for(size_t i=0;i<n;i++) if (pkts[i].cmd_type==SIP_PKT_OPTIONS)  delete_timestamp_for_pkt(&pkts[i]); }

/* ========= ≥10 种算子的综合变异 =========
   覆盖：数值/格式/空格/非法字符/超长/注入等 */
static void ts_op_empty_value(sip_timestamp_hdr_t *h){ h->value[0]='\0'; h->sp_opt='\0'; h->delay[0]='\0'; } /* 非法：空主值 */
static void ts_op_zero(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"0"); h->sp_opt='\0'; h->delay[0]='\0'; }
static void ts_op_bigint(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"42949672960"); }              /* 超大值 */
static void ts_op_many_decimals(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"123.4567890123"); }
static void ts_op_trailing_dot(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"77."); }                /* 非法/边缘 */
static void ts_op_leading_dot(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,".77"); }                /* 非法/边缘 */
static void ts_op_negative(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"-1.0"); }                  /* 非法/边缘 */
static void ts_op_scientific(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"1e10"); }                /* 非法/边缘 */
static void ts_op_alpha_value(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"NaN"); }                /* 非法 */
static void ts_op_comma_decimal(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"1,23"); }             /* 地域格式 */
static void ts_op_value_ws(sip_timestamp_hdr_t *h){ scpy(h->value,sizeof h->value,"  77.3  "); }              /* 前后空格 */

static void ts_op_add_delay(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"2.3"); }
static void ts_op_delay_big(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"9999999999.999"); }
static void ts_op_delay_negative(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"-0.5"); }
static void ts_op_delay_sci(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"3e-2"); }
static void ts_op_delay_alpha(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"xx"); }
static void ts_op_no_space_but_delay(sip_timestamp_hdr_t *h){ h->sp_opt='\0'; scpy(h->delay,sizeof h->delay,"2.3"); } /* 结构不一致 */
static void ts_op_space_no_delay(sip_timestamp_hdr_t *h){ h->sp_opt=' '; h->delay[0]='\0'; }                 /* 单独空格 */

static void ts_op_inject_header(sip_timestamp_hdr_t *h){ h->sp_opt=' '; scpy(h->delay,sizeof h->delay,"\r\nVia: SIP/2.0/UDP evil"); } /* CRLF 注入 */
static void ts_op_overlong_value(sip_timestamp_hdr_t *h){ sfill(h->value,sizeof h->value,'V',sizeof h->value-1); }
static void ts_op_overlong_delay(sip_timestamp_hdr_t *h){ h->sp_opt=' '; sfill(h->delay,sizeof h->delay,'D',sizeof h->delay-1); }
static void ts_op_random_alnum_value(sip_timestamp_hdr_t *h, unsigned *rs){ gen_token(h->value,sizeof h->value,rs,8,20); }
static void ts_op_random_alnum_delay(sip_timestamp_hdr_t *h, unsigned *rs){ h->sp_opt=' '; gen_token(h->delay,sizeof h->delay,rs,8,20); }

static void mutate_one_timestamp(sip_timestamp_hdr_t *h, unsigned *rs){
    if (!h || ts_is_absent(h)) return;
    switch (rnd_pick(rs, 24)){
        case 0:  ts_op_empty_value(h); break;
        case 1:  ts_op_zero(h); break;
        case 2:  ts_op_bigint(h); break;
        case 3:  ts_op_many_decimals(h); break;
        case 4:  ts_op_trailing_dot(h); break;
        case 5:  ts_op_leading_dot(h); break;
        case 6:  ts_op_negative(h); break;
        case 7:  ts_op_scientific(h); break;
        case 8:  ts_op_alpha_value(h); break;
        case 9:  ts_op_comma_decimal(h); break;
        case 10: ts_op_value_ws(h); break;
        case 11: ts_op_add_delay(h); break;
        case 12: ts_op_delay_big(h); break;
        case 13: ts_op_delay_negative(h); break;
        case 14: ts_op_delay_sci(h); break;
        case 15: ts_op_delay_alpha(h); break;
        case 16: ts_op_no_space_but_delay(h); break;
        case 17: ts_op_space_no_delay(h); break;
        case 18: ts_op_inject_header(h); break;
        case 19: ts_op_overlong_value(h); break;
        case 20: ts_op_overlong_delay(h); break;
        case 21: ts_op_random_alnum_value(h, rs); break;
        default: ts_op_random_alnum_delay(h, rs); break;
    }
}

/* 对单个包：20% 删除、30% 若缺则添加、其余在现有上做 1~2 次随机算子 */
static void mutate_ts_for_pkt(sip_packet_t *p, unsigned *rs){
    sip_timestamp_hdr_t *h = get_ts_ptr(p);
    if (!h) return;

    unsigned dice = rnd_pick(rs, 10);
    if (dice < 2){
        ts_mark_absent(h);
        return;
    } else if (dice < 5){
        if (ts_is_absent(h)) ts_set_present(h, "0", "", 0);
    } else {
        if (ts_is_absent(h) && rnd_pick(rs,2)==0){
            ts_set_present(h, "0.0", "1.0", 1);
        }
    }

    /* 现有则做 1~2 次细粒度变异 */
    if (!ts_is_absent(h)){
        size_t times = 1 + rnd_pick(rs, 2);
        for (size_t t=0;t<times;t++) mutate_one_timestamp(h, rs);
    }
}

/* 对外：遍历数组，处理所有支持 Timestamp 的方法 */
void mutate_timestamp_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed?seed:0xC0FFEE77u;
    for (size_t i=0;i<n;i++){
        switch (pkts[i].cmd_type){
            case SIP_PKT_INVITE:
            case SIP_PKT_ACK:
            case SIP_PKT_BYE:
            case SIP_PKT_CANCEL:
            case SIP_PKT_REGISTER:
            case SIP_PKT_OPTIONS:
                mutate_ts_for_pkt(&pkts[i], &rs);
                break;
            default: break;
        }
    }
}


static sip_to_hdr_t* get_to_ptr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.to_;
        case SIP_PKT_ACK:      return &p->pkt.ack.to_;
        case SIP_PKT_BYE:      return &p->pkt.bye.to_;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.to_;
        case SIP_PKT_REGISTER: return &p->pkt.register_.to_;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.to_;
        default: return NULL;
    }
}
/* 显示名加/去引号 */
static void toggle_quotes(char *s, size_t cap){
    if (!s || !cap) return;
    size_t len = strnlen(s, cap);
    if (len >= 2 && s[0]=='"' && s[len-1]=='"'){ /* 去引号 */
        memmove(s, s+1, len-2);
        s[len-2] = '\0';
    }else{ /* 加引号 */
        if (len+2 >= cap) len = cap>3 ? cap-3 : 0;
        memmove(s+1, s, len);
        s[0] = '"';
        s[len+1] = '"';
        s[len+2] = '\0';
    }
}

/* ---------- 变异算子（≥20） ---------- */
/* 显示名 */
static void to_op_display_empty(sip_to_hdr_t *h){ h->display[0]='\0'; h->sp_opt='\0'; }
static void to_op_display_random(sip_to_hdr_t *h, unsigned *rs){ gen_token(h->display, sizeof h->display, rs, 5, 20); h->sp_opt=' '; }
static void to_op_display_toggle_quotes(sip_to_hdr_t *h){ if (!h->display[0]) scpy(h->display,sizeof h->display,"Anon"); toggle_quotes(h->display, sizeof h->display); h->sp_opt=' '; }
static void to_op_display_long(sip_to_hdr_t *h){ sfill(h->display, sizeof h->display, 'D', sizeof h->display-1); h->sp_opt=' '; }
static void to_op_display_crlf_inject(sip_to_hdr_t *h){ scpy(h->display,sizeof h->display,"evil\r\nMax-Forwards: 0"); h->sp_opt=' '; }
static void to_op_sp_mismatch(sip_to_hdr_t *h){ /* 故意不放空格，即使有 display */
    if (h->display[0]) h->sp_opt = (h->sp_opt==' ')? '\0':' ';
}

/* 角括号形态 */
static void to_op_remove_angles(sip_to_hdr_t *h){ h->lt = '\0'; h->gt = '\0'; }
static void to_op_only_lt(sip_to_hdr_t *h){ h->lt = '<'; h->gt = '\0'; }
static void to_op_only_gt(sip_to_hdr_t *h){ h->lt = '\0'; h->gt = '>'; }

/* URI 相关（协议/主机/参数/长度/非法） */
static void to_op_uri_sips(sip_to_hdr_t *h){ scpy(h->uri, sizeof h->uri, "sips:alice@example.com"); }
static void to_op_uri_tel(sip_to_hdr_t *h){ scpy(h->uri, sizeof h->uri, "tel:+12025550123"); }
static void to_op_uri_ipv6(sip_to_hdr_t *h){ scpy(h->uri, sizeof h->uri, "sip:alice@[2001:db8::1]:5061"); }
static void to_op_uri_with_params(sip_to_hdr_t *h){ scpy(h->uri, sizeof h->uri, "sip:bob@example.com;transport=tcp;user=phone;ttl=1;maddr=224.2.0.1"); }
static void to_op_uri_no_scheme(sip_to_hdr_t *h){ scpy(h->uri, sizeof h->uri, "bob@example.net"); } /* 非法/边缘 */
static void to_op_uri_overlong(sip_to_hdr_t *h){ sfill(h->uri, sizeof h->uri, 'U', sizeof h->uri-1); }

/* 参数（header params，位于 URI/‘>’ 之后） */
static void to_op_params_add_tag(sip_to_hdr_t *h, unsigned *rs){ char tmp[64]; gen_token(tmp, sizeof tmp, rs, 4, 10); char buf[128]; snprintf(buf,sizeof buf,";tag=%s", tmp); scpy(h->params, sizeof h->params, buf); }
static void to_op_params_remove(sip_to_hdr_t *h){ h->params[0]='\0'; }
static void to_op_params_dup_tag(sip_to_hdr_t *h){ scpy(h->params, sizeof h->params, ";tag=a;tag=b"); }
static void to_op_params_many(sip_to_hdr_t *h){
    scpy(h->params, sizeof h->params, ";tag=z;foo=bar;lr;opaque=1;verylongparam=xxxxxxxxxxxxxxxxxxxxxxxx");
}
static void to_op_params_crlf_inject(sip_to_hdr_t *h){
    scpy(h->params, sizeof h->params, ";\r\nVia: SIP/2.0/UDP injected");
}

/* 组合修饰 */
static void to_op_make_minimal_addr_spec(sip_to_hdr_t *h){
    /* 无显示名、无角括号、仅裸 URI+params */
    h->display[0]='\0'; h->sp_opt='\0'; h->lt='\0'; h->gt='\0';
    if (!h->uri[0]) scpy(h->uri, sizeof h->uri, "sip:user@host");
}
static void to_op_make_classic_angle_form(sip_to_hdr_t *h){
    /* 有显示名 + <URI>;params */
    if (!h->display[0]) scpy(h->display, sizeof h->display, "User");
    h->sp_opt=' '; h->lt='<'; if (!h->uri[0]) scpy(h->uri, sizeof h->uri, "sip:user@example.com"); h->gt='>';
}

/* ---------- 单条 To 的随机变异 ---------- */
static void mutate_one_to(sip_to_hdr_t *h, unsigned *rs){
    if (!h || h->name[0]=='\0') return; /* To 是必选，但做个防护 */

    switch (rnd_pick(rs, 24)){
        /* 显示名/空格 */
        case 0:  to_op_display_empty(h); break;
        case 1:  to_op_display_random(h, rs); break;
        case 2:  to_op_display_toggle_quotes(h); break;
        case 3:  to_op_display_long(h); break;
        case 4:  to_op_display_crlf_inject(h); break;
        case 5:  to_op_sp_mismatch(h); break;

        /* 角括号形态 */
        case 6:  to_op_remove_angles(h); break;
        case 7:  to_op_only_lt(h); break;
        case 8:  to_op_only_gt(h); break;

        /* URI */
        case 9:  to_op_uri_sips(h); break;
        case 10: to_op_uri_tel(h); break;
        case 11: to_op_uri_ipv6(h); break;
        case 12: to_op_uri_with_params(h); break;
        case 13: to_op_uri_no_scheme(h); break;
        case 14: to_op_uri_overlong(h); break;

        /* 参数 */
        case 15: to_op_params_add_tag(h, rs); break;
        case 16: to_op_params_remove(h); break;
        case 17: to_op_params_dup_tag(h); break;
        case 18: to_op_params_many(h); break;
        case 19: to_op_params_crlf_inject(h); break;

        /* 组合 */
        case 20: to_op_make_minimal_addr_spec(h); break;
        default: to_op_make_classic_angle_form(h); break;
    }

    /* 小概率：强制不一致的形态（角括号 + 空 params 或者 无角括号 + 非空 params 都可） */
    if (rnd_pick(rs, 5)==0){
        if (h->lt && !h->gt && rnd_pick(rs,2)==0) h->gt = '>';        /* 补齐/不补齐随缘 */
        if (!h->lt && h->gt && rnd_pick(rs,2)==0) h->lt = '<';
    }
}

/* ---------- 对外：遍历整个数组 ---------- */
void mutate_to_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed ? seed : 0xA11CE777u;
    for (size_t i=0;i<n;i++){
        sip_to_hdr_t *h = get_to_ptr(&pkts[i]);
        if (!h) continue;
        /* 对必选头，不做删除/新增，只在现有上做 1~3 次随机算子 */
        size_t times = 1 + rnd_pick(&rs, 3);
        for (size_t t=0; t<times; t++) mutate_one_to(h, &rs);
    }
}


/* 取某包的 Via 集合指针 */
typedef struct {
    sip_via_hdr_t *arr;
    size_t *count;
    size_t cap;
} via_set_t;

static via_set_t get_via_set(sip_packet_t *p){
    via_set_t vs = {0};
    if (!p) return vs;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   vs.arr = p->pkt.invite.via;   vs.count = &p->pkt.invite.via_count;   vs.cap = SIP_MAX_VIA; break;
        case SIP_PKT_ACK:      vs.arr = p->pkt.ack.via;      vs.count = &p->pkt.ack.via_count;      vs.cap = SIP_MAX_VIA; break;
        case SIP_PKT_BYE:      vs.arr = p->pkt.bye.via;      vs.count = &p->pkt.bye.via_count;      vs.cap = SIP_MAX_VIA; break;
        case SIP_PKT_CANCEL:   vs.arr = p->pkt.cancel.via;   vs.count = &p->pkt.cancel.via_count;   vs.cap = SIP_MAX_VIA; break;
        case SIP_PKT_REGISTER: vs.arr = p->pkt.register_.via;vs.count = &p->pkt.register_.via_count;vs.cap = SIP_MAX_VIA; break;
        case SIP_PKT_OPTIONS:  vs.arr = p->pkt.options.via;  vs.count = &p->pkt.options.via_count;  vs.cap = SIP_MAX_VIA; break;
        default: break;
    }
    return vs;
}

/* 基准化一个 Via（填 name/sep/crlf，以防起草数据缺省） */
static void ensure_via_prefix(sip_via_hdr_t *h){
    if (!h) return;
    if (!h->name[0])   scpy(h->name, sizeof h->name, "Via");
    if (!h->colon_space[0]) scpy(h->colon_space, sizeof h->colon_space, ": ");
    if (!h->crlf[0])   scpy(h->crlf, sizeof h->crlf, "\r\n");
    if (!h->sent_protocol[0]) scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/UDP");
    if (!h->sent_by[0]) scpy(h->sent_by, sizeof h->sent_by, "client.invalid:5060");
    h->sp = (h->sp==0)?' ':h->sp;
}

/* ========== 单条 Via 的变异算子（≥20） ========== */
/* 协议族 */
static void via_op_proto_udp(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/UDP"); }
static void via_op_proto_tcp(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/TCP"); }
static void via_op_proto_tls(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/TLS"); }
static void via_op_proto_sctp(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/SCTP"); }
static void via_op_proto_ws(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/WS"); }
static void via_op_proto_wss(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/WSS"); }
static void via_op_proto_invalid_ver(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/3.0/UDP"); } /* 非法版本 */
static void via_op_proto_malformed(sip_via_hdr_t *h){ scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP//UDP"); }      /* 缺版本 */

/* 空格变异 */
static void via_op_sp_missing(sip_via_hdr_t *h){ h->sp = '\0'; }
static void via_op_sp_tab(sip_via_hdr_t *h){ h->sp = '\t'; }

/* sent-by 主机端口 */
static void via_op_by_host_only(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "proxy.example.com"); }
static void via_op_by_host_port(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "proxy.example.com:5080"); }
static void via_op_by_ipv4(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "198.51.100.10:5062"); }
static void via_op_by_ipv6(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "[2001:db8::10]:5070"); }
static void via_op_by_port0(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "host:0"); }          /* 边界端口 */
static void via_op_by_port65536(sip_via_hdr_t *h){ scpy(h->sent_by, sizeof h->sent_by, "host:65536"); }  /* 非法端口 */
static void via_op_by_empty(sip_via_hdr_t *h){ h->sent_by[0] = '\0'; }                                   /* 非法：空 */
static void via_op_by_overlong(sip_via_hdr_t *h){ sfill(h->sent_by, sizeof h->sent_by, 'H', sizeof h->sent_by-1); }

/* params：branch/rport/received/maddr/ttl/alias/comp/lr/未知参数/CRLF 注入/删除/超长/乱分号 */
static void via_op_params_good_branch(sip_via_hdr_t *h, unsigned *rs){
    char rnd[16]; gen_token(rnd, sizeof rnd, rs, 6, 12);
    char buf[128]; snprintf(buf, sizeof buf, ";branch=z9hG4bK%s", rnd);
    scpy(h->params, sizeof h->params, buf);
}
static void via_op_params_bad_branch_prefix(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";branch=zzzzG4bKxxx"); }
static void via_op_params_branch_only_prefix(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";branch=z9hG4bK"); }
static void via_op_params_branch_dup(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";branch=z9hG4bKa;branch=z9hG4bKb"); }
static void via_op_params_rport_flag(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";rport"); }
static void via_op_params_rport_val(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";rport=65535"); }
static void via_op_params_received(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";received=203.0.113.1"); }
static void via_op_params_maddr_ttl(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";maddr=224.2.0.1;ttl=1"); }
static void via_op_params_alias_lr(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";alias;lr"); }
static void via_op_params_comp(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";comp=sigcomp"); }
static void via_op_params_unknown(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";x_foo=bar;_weird=1"); }
static void via_op_params_remove(sip_via_hdr_t *h){ h->params[0]='\0'; }
static void via_op_params_overlong(sip_via_hdr_t *h){ sfill(h->params, sizeof h->params, 'P', sizeof h->params-1); }
static void via_op_params_semicolons(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";;;;;"); }
static void via_op_params_crlf_inject(sip_via_hdr_t *h){ scpy(h->params, sizeof h->params, ";\r\nVia: SIP/2.0/UDP injected"); }

/* 单条 Via 的随机变异 */
static void mutate_one_via(sip_via_hdr_t *h, unsigned *rs){
    if (!h) return;
    ensure_via_prefix(h);

    switch (rnd_pick(rs, 34)){
        /* sent_protocol 8 */
        case 0: via_op_proto_udp(h); break;
        case 1: via_op_proto_tcp(h); break;
        case 2: via_op_proto_tls(h); break;
        case 3: via_op_proto_sctp(h); break;
        case 4: via_op_proto_ws(h); break;
        case 5: via_op_proto_wss(h); break;
        case 6: via_op_proto_invalid_ver(h); break;
        case 7: via_op_proto_malformed(h); break;

        /* sp 2 */
        case 8: via_op_sp_missing(h); break;
        case 9: via_op_sp_tab(h); break;

        /* sent_by 8 */
        case 10: via_op_by_host_only(h); break;
        case 11: via_op_by_host_port(h); break;
        case 12: via_op_by_ipv4(h); break;
        case 13: via_op_by_ipv6(h); break;
        case 14: via_op_by_port0(h); break;
        case 15: via_op_by_port65536(h); break;
        case 16: via_op_by_empty(h); break;
        case 17: via_op_by_overlong(h); break;

        /* params 14 */
        case 18: via_op_params_good_branch(h, rs); break;
        case 19: via_op_params_bad_branch_prefix(h); break;
        case 20: via_op_params_branch_only_prefix(h); break;
        case 21: via_op_params_branch_dup(h); break;
        case 22: via_op_params_rport_flag(h); break;
        case 23: via_op_params_rport_val(h); break;
        case 24: via_op_params_received(h); break;
        case 25: via_op_params_maddr_ttl(h); break;
        case 26: via_op_params_alias_lr(h); break;
        case 27: via_op_params_comp(h); break;
        case 28: via_op_params_unknown(h); break;
        case 29: via_op_params_remove(h); break;
        case 30: via_op_params_overlong(h); break;
        case 31: via_op_params_semicolons(h); break;
        default: via_op_params_crlf_inject(h); break; /* 32/33 */
    }
}

/* ========== 多条 Via（链路级）算子 ========== */
static void via_set_dup_top(via_set_t *vs){
    if (!vs->arr || !vs->count) return;
    if (*vs->count==0 || *vs->count>=vs->cap) return;
    vs->arr[*vs->count] = vs->arr[0];
    (*vs->count)++;
}
static void via_set_shuffle(via_set_t *vs, unsigned *rs){
    if (!vs->arr || !vs->count) return;
    for (size_t i=0;i<*vs->count;i++){
        size_t j = rnd_pick(rs, (unsigned)*vs->count);
        sip_via_hdr_t tmp = vs->arr[i];
        vs->arr[i] = vs->arr[j];
        vs->arr[j] = tmp;
    }
}
static void via_set_add_chain(via_set_t *vs, unsigned *rs){
    if (!vs->arr || !vs->count) return;
    /* 尝试追加 1~3 条随机代理链 */
    unsigned extra = 1 + rnd_pick(rs, 3);
    while (extra-- && *vs->count < vs->cap){
        sip_via_hdr_t *h = &vs->arr[*vs->count];
        memset(h, 0, sizeof *h);
        scpy(h->name, sizeof h->name, "Via");
        scpy(h->colon_space, sizeof h->colon_space, ": ");
        scpy(h->crlf, sizeof h->crlf, "\r\n");
        scpy(h->sent_protocol, sizeof h->sent_protocol, (rnd_pick(rs,2)? "SIP/2.0/UDP":"SIP/2.0/TCP"));
        h->sp = ' ';
        char host[64]; snprintf(host, sizeof host, "proxy-%u.example.net:%u",
                                rnd_pick(rs,1000), 5060 + rnd_pick(rs, 50));
        scpy(h->sent_by, sizeof h->sent_by, host);
        /* branch 故意重复/变化 */
        if (rnd_pick(rs,2)){
            char br[64]; snprintf(br, sizeof br, ";branch=z9hG4bK%04x", rnd_pick(rs, 0xFFFF));
            scpy(h->params, sizeof h->params, br);
        }else{
            scpy(h->params, sizeof h->params, ";rport;received=203.0.113.55");
        }
        (*vs->count)++;
    }
}
static void via_set_truncate(via_set_t *vs, unsigned *rs){
    if (!vs->arr || !vs->count) return;
    if (*vs->count==0) return;
    size_t keep = rnd_pick(rs, (unsigned)(*vs->count)); /* 0..count-1（可能清空，非法） */
    *vs->count = keep;
}
static void via_set_limit_to_one(via_set_t *vs){
    if (!vs->arr || !vs->count) return;
    if (*vs->count>1) *vs->count = 1; /* 保留顶层，合法但改变路径 */
}

/* ========== 对外入口：遍历整个数组 ========== */
void mutate_via_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned rs = seed ? seed : 0xC0FFEEu;

    for (size_t i=0;i<n;i++){
        via_set_t vs = get_via_set(&pkts[i]);
        if (!vs.arr || !vs.count) continue;

        /* 若没有 Via（理论上不该发生），构造 1 条基准 */
        if (*vs.count==0 && vs.cap>0){
            sip_via_hdr_t *h = &vs.arr[0];
            memset(h, 0, sizeof *h);
            scpy(h->name, sizeof h->name, "Via");
            scpy(h->colon_space, sizeof h->colon_space, ": ");
            scpy(h->sent_protocol, sizeof h->sent_protocol, "SIP/2.0/UDP");
            h->sp = ' ';
            scpy(h->sent_by, sizeof h->sent_by, "client.invalid:5060");
            scpy(h->params, sizeof h->params, ";branch=z9hG4bKseed");
            scpy(h->crlf, sizeof h->crlf, "\r\n");
            *vs.count = 1;
        }

        /* 对每条 Via 做 1~3 次单条变异 */
        for (size_t k=0;k<*vs.count;k++){
            size_t times = 1 + rnd_pick(&rs, 3);
            while (times--) mutate_one_via(&vs.arr[k], &rs);
        }

        /* 链路级随机 0~2 个操作 */
        switch (rnd_pick(&rs, 6)){
            case 0: via_set_dup_top(&vs); break;
            case 1: via_set_shuffle(&vs, &rs); break;
            case 2: via_set_add_chain(&vs, &rs); break;
            case 3: via_set_truncate(&vs, &rs); break;      /* 可能清空（非法） */
            case 4: via_set_limit_to_one(&vs); break;
            default: /* no-op */ break;
        }
    }
}



/* 取得各消息里 Content-Encoding 的指针；无则返回 NULL */
static sip_content_encoding_hdr_t* get_ce_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.content_encoding;
        case SIP_PKT_REGISTER: return &p->pkt.register_.content_encoding;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.content_encoding;
        default: return NULL;
    }
}

/* 将头标记为“存在”的标准形态，并设置 coding */
static void set_ce_present(sip_content_encoding_hdr_t *h, const char *coding){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Content-Encoding");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
    scpy(h->coding, sizeof h->coding, coding ? coding : "gzip");
}

/* 将头标记为“缺省/删除”（按照你的解析器约定：name[0] == '\0' 表示无此头） */
static void set_ce_absent(sip_content_encoding_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}


void add_invite_content_encoding(sip_packet_t *p, const char *coding){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_ce_present(&p->pkt.invite.content_encoding, coding);
}
void delete_invite_content_encoding(sip_packet_t *p){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_ce_absent(&p->pkt.invite.content_encoding);
}

void add_register_content_encoding(sip_packet_t *p, const char *coding){
    if (!p || p->cmd_type != SIP_PKT_REGISTER) return;
    set_ce_present(&p->pkt.register_.content_encoding, coding);
}
void delete_register_content_encoding(sip_packet_t *p){
    if (!p || p->cmd_type != SIP_PKT_REGISTER) return;
    set_ce_absent(&p->pkt.register_.content_encoding);
}

void add_options_content_encoding(sip_packet_t *p, const char *coding){
    if (!p || p->cmd_type != SIP_PKT_OPTIONS) return;
    set_ce_present(&p->pkt.options.content_encoding, coding);
}
void delete_options_content_encoding(sip_packet_t *p){
    if (!p || p->cmd_type != SIP_PKT_OPTIONS) return;
    set_ce_absent(&p->pkt.options.content_encoding);
}

/* ---------- 单头的变异（≥10 种算子） ---------- */
typedef void (*ce_op_fn)(sip_content_encoding_hdr_t*);

static void op_set_gzip(sip_content_encoding_hdr_t* h){ set_ce_present(h, "gzip"); }
static void op_set_deflate(sip_content_encoding_hdr_t* h){ set_ce_present(h, "deflate"); }
static void op_set_compress(sip_content_encoding_hdr_t* h){ set_ce_present(h, "compress"); }
static void op_set_identity(sip_content_encoding_hdr_t* h){ set_ce_present(h, "identity"); }
static void op_set_br(sip_content_encoding_hdr_t* h){ set_ce_present(h, "br"); } /* brotli，有实现会忽略 */
static void op_set_mixedcase(sip_content_encoding_hdr_t* h){ set_ce_present(h, "GzIp"); }
static void op_set_list_gzip_deflate(sip_content_encoding_hdr_t* h){ set_ce_present(h, "gzip, deflate"); } /* 逗号列表 */
static void op_set_empty(sip_content_encoding_hdr_t* h){ set_ce_present(h, ""); } /* 非法：空令牌 */
static void op_set_overlong(sip_content_encoding_hdr_t* h){ sfill(h->coding, sizeof h->coding, 'X', sizeof h->coding-1); }
static void op_set_with_params_like(sip_content_encoding_hdr_t* h){ set_ce_present(h, "gzip;q=1.0"); } /* 结构不支持参数，构造歧义 */
static void op_set_quoted(sip_content_encoding_hdr_t* h){ set_ce_present(h, "\"gzip\""); }
static void op_set_inject_crlf(sip_content_encoding_hdr_t* h){ set_ce_present(h, "gz\r\nContent-Length: 9999"); } /* 注入尝试 */
static void op_set_unknown_token(sip_content_encoding_hdr_t* h){ set_ce_present(h, "x-super-enc"); }
static void op_set_leading_space(sip_content_encoding_hdr_t* h){ set_ce_present(h, "  gzip"); }
static void op_set_trailing_space(sip_content_encoding_hdr_t* h){ set_ce_present(h, "gzip  "); }

/* 随机挑一个算子 */
static void mutate_one_ce(sip_content_encoding_hdr_t *h, unsigned *st){
    if (!h) return;
    if (h->name[0] == '\0'){
        /* 原本没有 → 先“添加”再变异，模拟从无到有 */
        set_ce_present(h, "gzip");
    }
    switch (rnd_pick(st, 16)){
        case 0:  op_set_gzip(h); break;
        case 1:  op_set_deflate(h); break;
        case 2:  op_set_compress(h); break;
        case 3:  op_set_identity(h); break;
        case 4:  op_set_br(h); break;
        case 5:  op_set_mixedcase(h); break;
        case 6:  op_set_list_gzip_deflate(h); break;
        case 7:  op_set_empty(h); break;
        case 8:  op_set_overlong(h); break;
        case 9:  op_set_with_params_like(h); break;
        case 10: op_set_quoted(h); break;
        case 11: op_set_inject_crlf(h); break;
        case 12: op_set_star(h); break;
        case 13: op_set_unknown_token(h); break;
        case 14: op_set_leading_space(h); break;
        default: op_set_trailing_space(h); break;
    }
}

/* ---------- 对外总入口：遍历数组并变异 ---------- */
void mutate_content_encoding_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xC0FFEEu;
    for (size_t i=0;i<n;i++){
        sip_content_encoding_hdr_t *h = get_ce_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 删除；30% 确保存在；其余随机算子 */
        unsigned r = rnd_pick(&st, 10);
        if (r < 2){
            set_ce_absent(h);                 /* delete_* 效果 */
        } else if (r < 5){
            if (h->name[0] == '\0') set_ce_present(h, "gzip"); /* add_* 效果 */
        } else {
            /* 做 1~2 次随机变异 */
            size_t times = 1 + rnd_pick(&st, 2);
            while (times--) mutate_one_ce(h, &st);
        }
    }
}



static void set_dec(char *dst, size_t cap, unsigned long v){
    if (!dst || cap == 0) return;
    (void)snprintf(dst, cap, "%lu", v);
}
static size_t body_len_textual(const char *body, size_t max_cap){
    if (!body || max_cap == 0) return 0;
    /* 这里假定 body 为文本/不含 NUL；若要支持二进制，可另传真实长度 */
    return strnlen(body, max_cap);
}
static void pad_body(char *body, size_t cap, size_t newlen, char ch){
    if (!body || cap == 0) return;
    size_t cur = strnlen(body, cap);
    if (newlen >= cap) newlen = cap-1;
    if (newlen > cur){
        memset(body + cur, ch, newlen - cur);
        body[newlen] = '\0';
    } else {
        body[newlen] = '\0'; /* 截断 */
    }
}


/* ---------- 访问各消息的 CL 与 body ---------- */

static sip_content_length_hdr_t* get_cl_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.content_length;
        case SIP_PKT_ACK:      return &p->pkt.ack.content_length;
        case SIP_PKT_REGISTER: return &p->pkt.register_.content_length;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.content_length;
        default: return NULL;
    }
}
static char* get_body_buf(sip_packet_t *p, size_t *cap){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   if (cap) *cap = sizeof p->pkt.invite.body;   return p->pkt.invite.body;
        case SIP_PKT_ACK:      if (cap) *cap = sizeof p->pkt.ack.body;      return p->pkt.ack.body;
        case SIP_PKT_REGISTER: if (cap) *cap = sizeof p->pkt.register_.body;return p->pkt.register_.body;
        case SIP_PKT_OPTIONS:  if (cap) *cap = sizeof p->pkt.options.body;  return p->pkt.options.body;
        default: if (cap) *cap = 0; return NULL;
    }
}

/* 将头标记为“存在”的标准形态，并设置 length 文本 */
static void set_cl_present(sip_content_length_hdr_t *h, const char *len_text){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Content-Length");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
    scpy(h->length, sizeof h->length, len_text ? len_text : "0");
}
static void set_cl_absent(sip_content_length_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

void add_invite_content_length(sip_packet_t *p, unsigned long v){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_cl_present(&p->pkt.invite.content_length, NULL);
    set_dec(p->pkt.invite.content_length.length, sizeof p->pkt.invite.content_length.length, v);
}
void delete_invite_content_length(sip_packet_t *p, size_t n, unsigned int seed){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_cl_absent(&p->pkt.invite.content_length);
}

void add_ack_content_length(sip_packet_t *p, unsigned long v){
    if (!p || p->cmd_type != SIP_PKT_ACK) return;
    set_cl_present(&p->pkt.ack.content_length, NULL);
    set_dec(p->pkt.ack.content_length.length, sizeof p->pkt.ack.content_length.length, v);
}
void delete_ack_content_length(sip_packet_t *p, size_t n, unsigned int seed){
    if (!p || p->cmd_type != SIP_PKT_ACK) return;
    set_cl_absent(&p->pkt.ack.content_length);
}

void add_register_content_length(sip_packet_t *p, unsigned long v){
    if (!p || p->cmd_type != SIP_PKT_REGISTER) return;
    set_cl_present(&p->pkt.register_.content_length, NULL);
    set_dec(p->pkt.register_.content_length.length, sizeof p->pkt.register_.content_length.length, v);
}
void delete_register_content_length(sip_packet_t *p, size_t n, unsigned int seed){
    if (!p || p->cmd_type != SIP_PKT_REGISTER) return;
    set_cl_absent(&p->pkt.register_.content_length);
}

void add_options_content_length(sip_packet_t *p, unsigned long v){
    if (!p || p->cmd_type != SIP_PKT_OPTIONS) return;
    set_cl_present(&p->pkt.options.content_length, NULL);
    set_dec(p->pkt.options.content_length.length, sizeof p->pkt.options.content_length.length, v);
}
void delete_options_content_length(sip_packet_t *p, size_t n, unsigned int seed){
    if (!p || p->cmd_type != SIP_PKT_OPTIONS) return;
    set_cl_absent(&p->pkt.options.content_length);
}

/* ---------- 单头多算子变异（≥10） ---------- */

static void op_sync_to_body(sip_content_length_hdr_t *h, sip_packet_t *p){
    size_t cap=0; char *b = get_body_buf(p,&cap);
    size_t bl = body_len_textual(b, cap);
    set_cl_present(h, NULL);
    set_dec(h->length, sizeof h->length, (unsigned long)bl);
}

static void op_zero(sip_content_length_hdr_t *h){ set_cl_present(h, "0"); }
static void op_negative(sip_content_length_hdr_t *h){ set_cl_present(h, "-1"); }
static void op_plus_sign(sip_content_length_hdr_t *h, unsigned long v){ char tmp[32]; snprintf(tmp,sizeof tmp, "+%lu", v); set_cl_present(h, tmp); }
static void op_off_by_one_over(sip_content_length_hdr_t *h, sip_packet_t *p){
    size_t cap=0; char *b = get_body_buf(p,&cap);
    size_t bl = body_len_textual(b, cap);
    char tmp[32]; snprintf(tmp,sizeof tmp, "%lu", (unsigned long)(bl+1));
    set_cl_present(h, tmp);
}
static void op_off_by_one_under(sip_content_length_hdr_t *h, sip_packet_t *p){
    size_t cap=0; char *b = get_body_buf(p,&cap);
    size_t bl = body_len_textual(b, cap);
    char tmp[32]; snprintf(tmp,sizeof tmp, "%lu", (unsigned long)(bl?bl-1:0));
    set_cl_present(h, tmp);
}
static void op_large_value(sip_content_length_hdr_t *h){ set_cl_present(h, "999999999"); }
static void op_very_long_digits(sip_content_length_hdr_t *h){
    memset(h->length, '9', sizeof h->length - 1);
    h->length[sizeof h->length - 1] = '\0';
}
static void op_leading_zeros(sip_content_length_hdr_t *h, unsigned long v){
    char tmp[64]; snprintf(tmp,sizeof tmp, "000000%lu", v); set_cl_present(h, tmp);
}
static void op_spaces_around(sip_content_length_hdr_t *h, unsigned long v){
    char tmp[64]; snprintf(tmp,sizeof tmp, "   %lu   ", v); set_cl_present(h, tmp);
}
static void op_scientific(sip_content_length_hdr_t *h){ set_cl_present(h, "1e6"); }
static void op_hexlike(sip_content_length_hdr_t *h){ set_cl_present(h, "0x100"); }
static void op_alpha(sip_content_length_hdr_t *h){ set_cl_present(h, "NaN"); }
static void op_with_semicolon(sip_content_length_hdr_t *h, unsigned long v){
    char tmp[64]; snprintf(tmp,sizeof tmp, "%lu;foo=bar", v); set_cl_present(h, tmp);
}
static void op_with_comma_list(sip_content_length_hdr_t *h, unsigned long v){
    char tmp[64]; snprintf(tmp,sizeof tmp, "%lu, %lu", v, v+10); set_cl_present(h, tmp);
}
static void op_inject_crlf(sip_content_length_hdr_t *h){
    set_cl_present(h, "10\r\nContent-Type: text/plain");
}

static void op_random_decimal(sip_content_length_hdr_t *h, unsigned *st){
    unsigned long v = (unsigned long)(rnd_pick(st, 1000000u));
    set_dec(h->length, sizeof h->length, v);
    set_cl_present(h, h->length);
}
/* 同步 body 到 header（造“自洽”），或造“自洽但极大” */
static void op_resize_body_and_sync(sip_content_length_hdr_t *h, sip_packet_t *p, unsigned *st){
    size_t cap=0; char *b = get_body_buf(p,&cap);
    if (!b || cap==0){ op_random_decimal(h, st); return; }
    size_t target = rnd_pick(st, (unsigned)(cap-1)); /* 0..cap-2 */
    pad_body(b, cap, target, 'X');
    set_dec(h->length, sizeof h->length, (unsigned long)target);
    set_cl_present(h, h->length);
}

/* ---------- 主变异入口：遍历数组并变异 ---------- */
void mutate_content_length_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0x5A17u;

    for (size_t i=0;i<n;i++){
        sip_packet_t *p = &pkts[i];
        sip_content_length_hdr_t *h = get_cl_hdr(p);
        if (!h) continue;

        /* 20% 删除；30% 确保存在并同步；其余进行随机算子（1~2 次） */
        unsigned r = rnd_pick(&st, 10);
        if (r < 2){
            set_cl_absent(h);                      /* delete_* */
            continue;
        }

        /* 若缺失则添加一个基础值 */
        if (h->name[0] == '\0'){
            size_t cap=0; char *b = get_body_buf(p,&cap);
            size_t bl = body_len_textual(b, cap);
            set_cl_present(h, NULL);
            set_dec(h->length, sizeof h->length, (unsigned long)bl);
        }

        if (r < 5){
            op_sync_to_body(h, p);                 /* 使 header 与 body 一致 */
            continue;
        }

        /* 随机 1~2 次变异 */
        size_t times = 1 + rnd_pick(&st, 2);
        while (times--){
            switch (rnd_pick(&st, 18)){
                case 0:  op_zero(h); break;
                case 1:  op_negative(h); break;
                case 2:  op_plus_sign(h, 123ul); break;
                case 3:  op_off_by_one_over(h, p); break;
                case 4:  op_off_by_one_under(h, p); break;
                case 5:  op_large_value(h); break;
                case 6:  op_very_long_digits(h); break;
                case 7:  op_leading_zeros(h, 42ul); break;
                case 8:  op_spaces_around(h, 99ul); break;
                case 9:  op_scientific(h); break;
                case 10: op_hexlike(h); break;
                case 11: op_alpha(h); break;
                case 12: op_with_semicolon(h, 77ul); break;
                case 13: op_with_comma_list(h, 33ul); break;
                case 14: op_inject_crlf(h); break;
                case 15: op_empty(h); break;
                case 16: op_random_decimal(h, &st); break;
                default: op_resize_body_and_sync(h, p, &st); break; /* 自洽场景 */
            }
        }
    }
}

static void set_ct_present(sip_content_type_hdr_t *h,
                           const char *type_tok, int with_slash,
                           const char *sub_type, const char *params){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Content-Type");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    h->slash = with_slash ? '/' : '\0';
    scpy(h->type_tok, sizeof h->type_tok, type_tok ? type_tok : "");
    scpy(h->sub_type, sizeof h->sub_type, sub_type ? sub_type : "");
    scpy(h->params, sizeof h->params, params ? params : "");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}
static void set_ct_absent(sip_content_type_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}
static sip_content_type_hdr_t* get_ct_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.content_type;
      case SIP_PKT_ACK:      return &p->pkt.ack.content_type;
      default: return NULL;
    }
}

static size_t body_len_text(const char *b, size_t cap){
    if (!b || cap==0) return 0;
    return strnlen(b, cap);
}

static void sync_cl_to_body_if_present(sip_packet_t *p){
    sip_content_length_hdr_t *cl = get_cl_hdr(p);
    if (!cl || cl->name[0]=='\0') return;
    size_t cap=0; char *b = get_body_buf(p,&cap);
    char tmp[32];
    (void)snprintf(tmp, sizeof tmp, "%lu", (unsigned long)body_len_text(b, cap));
    scpy(cl->length, sizeof cl->length, tmp);
}

/* ---------------- add_/delete_ ---------------- */
void add_invite_content_type(sip_packet_t *p, const char *type_tok, const char *subtype, const char *params){
    if (!p || p->cmd_type!=SIP_PKT_INVITE) return;
    set_ct_present(&p->pkt.invite.content_type, type_tok, 1, subtype, params);
}
void delete_invite_content_type(sip_packet_t *p, size_t n, unsigned seed){
    if (!p || p->cmd_type!=SIP_PKT_INVITE) return;
    set_ct_absent(&p->pkt.invite.content_type);
}
void add_ack_content_type(sip_packet_t *p, const char *type_tok, const char *subtype, const char *params){
    if (!p || p->cmd_type!=SIP_PKT_ACK) return;
    set_ct_present(&p->pkt.ack.content_type, type_tok, 1, subtype, params);
}
void delete_ack_content_type(sip_packet_t *p, size_t n, unsigned seed){
    if (!p || p->cmd_type!=SIP_PKT_ACK) return;
    set_ct_absent(&p->pkt.ack.content_type);
}

/* ---------------- 变异算子（≥10） ---------------- */

/* 1) application/sdp（并可注入最小 SDP 体 & 同步 CL） */
static void op_set_sdp(sip_packet_t *p, sip_content_type_hdr_t *h, int touch_body){
    set_ct_present(h, "application", 1, "sdp", "");
    if (touch_body){
        size_t cap=0; char *b = get_body_buf(p,&cap);
        if (b && cap>=32){
            scpy(b, cap,
                 "v=0\r\n"
                 "o=- 0 0 IN IP4 127.0.0.1\r\n"
                 "s=-\r\n"
                 "t=0 0\r\n");
            sync_cl_to_body_if_present(p);
        }
    }
}

/* 2) text/plain; charset=utf-8（可把 body 变成纯文本） */
static void op_set_text_plain(sip_packet_t *p, sip_content_type_hdr_t *h, int touch_body){
    set_ct_present(h, "text", 1, "plain", ";charset=utf-8");
    if (touch_body){
        size_t cap=0; char *b = get_body_buf(p,&cap);
        if (b) { scpy(b, cap, "hello"); sync_cl_to_body_if_present(p); }
    }
}

/* 3) application/pidf+xml */
static void op_set_pidf_xml(sip_packet_t *p, sip_content_type_hdr_t *h, int touch_body){
    set_ct_present(h, "application", 1, "pidf+xml", "");
    if (touch_body){
        size_t cap=0; char *b = get_body_buf(p,&cap);
        if (b) { scpy(b, cap, "<presence/>"); sync_cl_to_body_if_present(p); }
    }
}

/* 4) message/sipfrag */
static void op_set_sipfrag(sip_packet_t *p, sip_content_type_hdr_t *h, int touch_body){
    set_ct_present(h, "message", 1, "sipfrag", "");
    if (touch_body){
        size_t cap=0; char *b = get_body_buf(p,&cap);
        if (b) { scpy(b, cap, "SIP/2.0 200 OK\r\nVia: X\r\n\r\n"); sync_cl_to_body_if_present(p); }
    }
}

/* 5) multipart/mixed; boundary=... 并构造简单多段体 */
static void op_set_multipart(sip_packet_t *p, sip_content_type_hdr_t *h, int touch_body){
    set_ct_present(h, "multipart", 1, "mixed", ";boundary=\"----BOUNDary\"");
    if (touch_body){
        size_t cap=0; char *b = get_body_buf(p,&cap);
        if (b){
            scpy(b, cap,
                 "------BOUNDary\r\n"
                 "Content-Type: text/plain\r\n\r\n"
                 "part1\r\n"
                 "------BOUNDary\r\n"
                 "Content-Type: application/sdp\r\n\r\n"
                 "v=0\r\ns=-\r\n\r\n"
                 "------BOUNDary--\r\n");
            sync_cl_to_body_if_present(p);
        }
    }
}

/* 6) * / * （非法/滥用 Accept 语义） */
static void op_star_star(sip_content_type_hdr_t *h){
    set_ct_present(h, "*", 1, "*", "");
}

/* 7) 缺少 subtype（只有 type，无斜杠） */
static void op_missing_subtype(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 0, "", ""); /* slash=0 */
}

/* 8) 仅 "/" 或 type/subtype 为空等极端 */
static void op_empty_type_and_slash(sip_content_type_hdr_t *h){
    set_ct_present(h, "", 1, "", "");
}

/* 9) 非法 token：在 type 里塞空格/非法字符 */
static void op_illegal_token(sip_content_type_hdr_t *h){
    set_ct_present(h, "app lic", 1, "sdp", "");
}

/* 10) 超长 subtype（填满缓冲） */
static void op_long_subtype(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "", "");
    memset(h->sub_type, 'x', sizeof h->sub_type - 1);
    h->sub_type[sizeof h->sub_type - 1] = '\0';
}

/* 11) vendor + suffix（合法但少见） */
static void op_vendor_json(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "vnd.foo+json", "");
}

/* 12) 参数变体：重复/空/无值/奇怪 key */
static void op_params_odd(sip_content_type_hdr_t *h){
    set_ct_present(h, "text", 1, "plain",
        ";charset=utf-8;charset=gbk;empty=;noval;weird*param=42");
}

/* 13) 参数注入换行（CRLF 注入） */
static void op_param_inject_crlf(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "sdp",
        ";level=1\r\nVia: SIP/2.0/UDP evil");
}

/* 14) 只留分号/空白参数集 */
static void op_params_semicolon_only(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "sdp", ";");
}

/* 15) 在 params 前加空格、混合大小写（解析宽容性） */
static void op_spaces_mixedcase(sip_content_type_hdr_t *h){
    set_ct_present(h, "ApPlIcAtIoN", 1, "SdP", "  ;Charset=\"utf-8\"  ");
}

/* 16) 与 body 故意不一致（宣称 sdp，但 body 是 JSON） */
static void op_mismatch_with_body(sip_packet_t *p, sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "sdp", "");
    size_t cap=0; char *b = get_body_buf(p,&cap);
    if (b) scpy(b, cap, "{\"not\":\"sdp\"}");
    /* 不同步 CL，制造双重不一致 */
}

/* 17) 清空 Content-Type（删除） */
static void op_delete_ct(sip_packet_t *p, sip_content_type_hdr_t *h){
    (void)p;
    set_ct_absent(h);
}

/* 18) 乱堆很多 params 逼近缓冲上限 */
static void op_params_fill(sip_content_type_hdr_t *h){
    set_ct_present(h, "application", 1, "sdp", "");
    size_t L = sizeof h->params;
    memset(h->params, 0, L);
    size_t pos = 0;
    /* 重复插入；防止超界 */
    while (pos + 10 < L-1){
        size_t n = (size_t)snprintf(h->params + pos, L - pos, ";k%u=v%u", (unsigned)pos, (unsigned)pos);
        if (n==0 || n >= L - pos) break;
        pos += n;
    }
}

void mutate_content_type_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xC0FFEEu;

    for (size_t i=0;i<n;i++){
        sip_packet_t *p = &pkts[i];
        sip_content_type_hdr_t *h = get_ct_hdr(p);
        if (!h) continue;

        /* 20% 删除，30% 设为常见且与 body 自洽，50% 随机挑算子（1~2 个） */
        unsigned r = rnd_pick(&st, 10);
        if (r < 2){                 /* 删除 */
            op_delete_ct(p, h);
            continue;
        }
        if (r < 5){                 /* 常见且自洽 */
            switch (rnd_pick(&st, 3)){
                case 0: op_set_sdp(p, h, 1); break;
                case 1: op_set_text_plain(p, h, 1); break;
                default: op_set_pidf_xml(p, h, 1); break;
            }
            continue;
        }

        /* 确保有头作为基底（若之前缺失） */
        if (h->name[0]=='\0') set_ct_present(h, "application", 1, "sdp", "");

        /* 随机 1~2 次变异（可能会覆盖前一步） */
        size_t times = 1 + rnd_pick(&st, 2);
        while (times--){
            switch (rnd_pick(&st, 18)){
                case 0:  op_set_sipfrag(p, h, 0); break;
                case 1:  op_set_multipart(p, h, 1); break;
                case 2:  op_star_star(h); break;
                case 3:  op_missing_subtype(h); break;
                case 4:  op_empty_type_and_slash(h); break;
                case 5:  op_illegal_token(h); break;
                case 6:  op_long_subtype(h); break;
                case 7:  op_vendor_json(h); break;
                case 8:  op_params_odd(h); break;
                case 9:  op_param_inject_crlf(h); break;
                case 10: op_params_semicolon_only(h); break;
                case 11: op_spaces_mixedcase(h); break;
                case 12: op_mismatch_with_body(p, h); break;
                case 13: op_params_fill(h); break;
                case 14: op_set_text_plain(p, h, 0); break; /* 不改 body 制造轻微不一致 */
                case 15: op_set_pidf_xml(p, h, 0); break;
                case 16: op_set_sdp(p, h, 0); break;
                default: op_set_multipart(p, h, 0); break;
            }
        }

        /* 10/10 情况下，如果我们刚刚“触碰了 body”，同步 CL。
           这里简单策略：multipart/text/plain/sdp/pidf+xml 中若 params 或体被改过，上面对应算子已调用过同步。
           保险起见，这里再随机 50% 进行一次同步，以制造自洽样本。 */
        if (rnd_pick(&st, 2)==0) sync_cl_to_body_if_present(p);
    }
}

static void set_auth_present(sip_authorization_hdr_t *h,
                             const char *scheme, char sp, const char *kvpairs){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Authorization");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->scheme, sizeof h->scheme, scheme ? scheme : "");
    h->sp = sp;
    scpy(h->kvpairs, sizeof h->kvpairs, kvpairs ? kvpairs : "");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}

static void set_auth_absent(sip_authorization_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

/* 获取当前包的 Authorization 指针 */
static sip_authorization_hdr_t* get_auth_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.authorization;
      case SIP_PKT_ACK:      return &p->pkt.ack.authorization;
      case SIP_PKT_BYE:      return &p->pkt.bye.authorization;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.authorization;
      case SIP_PKT_REGISTER: return &p->pkt.register_.authorization;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.authorization;
      default: return NULL;
    }
}

/* 提取请求行中 method/uri（用于构造 Digest 的 uri=… 或制造不一致） */
static const char* get_req_method(const sip_packet_t *p){
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return p->pkt.invite.method;
      case SIP_PKT_ACK:      return p->pkt.ack.method;
      case SIP_PKT_BYE:      return p->pkt.bye.method;
      case SIP_PKT_CANCEL:   return p->pkt.cancel.method;
      case SIP_PKT_REGISTER: return p->pkt.register_.method;
      case SIP_PKT_OPTIONS:  return p->pkt.options.method;
      default: return "INVITE";
    }
}
static const char* get_req_uri(const sip_packet_t *p){
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return p->pkt.invite.request_uri;
      case SIP_PKT_ACK:      return p->pkt.ack.request_uri;
      case SIP_PKT_BYE:      return p->pkt.bye.request_uri;
      case SIP_PKT_CANCEL:   return p->pkt.cancel.request_uri;
      case SIP_PKT_REGISTER: return p->pkt.register_.request_uri;
      case SIP_PKT_OPTIONS:  return p->pkt.options.request_uri;
      default: return "sip:example@host";
    }
}

/* 最小可用的 Digest 参数集（未真正计算 response，仅占位），自洽：uri=请求行 URI */
static void make_digest_minimal(const sip_packet_t *p, char *out, size_t cap,
                                const char *alg, const char *qop){
    const char *uri = get_req_uri(p);
    /* 注意引号与顺序 */
    snprintf(out, cap,
        "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"%s\", "
        "response=\"0123456789abcdef\", algorithm=%s%s%s",
        uri,
        alg ? alg : "MD5",
        qop ? ", qop=" : "",
        qop ? qop : ""
    );
}


/* ---------------- add_/delete_ helper ---------------- */
void add_invite_authorization  (sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;  set_auth_present(&p->pkt.invite.authorization,   scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_invite_authorization(sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;  set_auth_absent(&p->pkt.invite.authorization); }

void add_ack_authorization     (sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;     set_auth_present(&p->pkt.ack.authorization,      scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_ack_authorization  (sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;     set_auth_absent(&p->pkt.ack.authorization); }

void add_bye_authorization     (sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;     set_auth_present(&p->pkt.bye.authorization,      scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_bye_authorization  (sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;     set_auth_absent(&p->pkt.bye.authorization); }

void add_cancel_authorization  (sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;  set_auth_present(&p->pkt.cancel.authorization,    scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_cancel_authorization(sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return; set_auth_absent(&p->pkt.cancel.authorization); }

void add_register_authorization(sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_auth_present(&p->pkt.register_.authorization, scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_register_authorization(sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_auth_absent(&p->pkt.register_.authorization); }

void add_options_authorization (sip_packet_t *p, const char *scheme, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_auth_present(&p->pkt.options.authorization,   scheme?scheme:"Digest", ' ', kv?kv:""); }
void delete_options_authorization(sip_packet_t *p, size_t n, unsigned int seeds){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return; set_auth_absent(&p->pkt.options.authorization); }

/* ---------------- 具体算子（≥18） ---------------- */

/* 1) 合法：Digest + qop=auth + algorithm=MD5，自洽 uri */
static void op_digest_ok_md5(sip_packet_t *p, sip_authorization_hdr_t *h){
    char buf[SIP_PARAMS_LEN]; make_digest_minimal(p, buf, sizeof buf, "MD5", "auth");
    set_auth_present(h, "Digest", ' ', buf);
}

/* 2) 合法：Digest + qop=auth-int + MD5-sess（仍占位 response） */
static void op_digest_authint_md5sess(sip_packet_t *p, sip_authorization_hdr_t *h){
    char buf[SIP_PARAMS_LEN]; make_digest_minimal(p, buf, sizeof buf, "MD5-sess", "auth-int");
    set_auth_present(h, "Digest", ' ', buf);
}

/* 3) 合法：Digest + SHA-256 */
static void op_digest_sha256(sip_packet_t *p, sip_authorization_hdr_t *h){
    char buf[SIP_PARAMS_LEN]; make_digest_minimal(p, buf, sizeof buf, "SHA-256", "auth");
    set_auth_present(h, "Digest", ' ', buf);
}

/* 4) 合法：Digest + AKA（移动域常见） */
static void op_digest_aka(sip_packet_t *p, sip_authorization_hdr_t *h){
    char buf[SIP_PARAMS_LEN]; make_digest_minimal(p, buf, sizeof buf, "AKAv1-MD5", "auth");
    set_auth_present(h, "Digest", ' ', buf);
}

/* 5) 合法但 SIP 不常见：Basic */
static void op_basic(sip_authorization_hdr_t *h){
    set_auth_present(h, "Basic", ' ', "dXNlcjpzZWNyZXQ="); /* user:secret */
}

/* 6) 合法但非常规：Bearer */
static void op_bearer(sip_authorization_hdr_t *h){
    set_auth_present(h, "Bearer", ' ', "eyJhbGciOiAiUlMyNTYifQ.e30.xxx");
}

/* 7) 仅 scheme，无 kvpairs（语法缺失） */
static void op_scheme_only(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ', "");
}

/* 8) 缺少空格（sp=0） */
static void op_no_space0(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", '\0', "username=\"u\", realm=\"r\"");
}

/* 9) 用 TAB 代替空格 */
static void op_tab_space(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", '\t', "username=\"u\", realm=\"r\"");
}

/* 10) kvpairs 缺少必填项（无 response） */
static void op_missing_response(sip_packet_t *p, sip_authorization_hdr_t *h){
    char b[SIP_PARAMS_LEN];
    const char *uri = get_req_uri(p);
    snprintf(b, sizeof b, "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"%s\"", uri);
    set_auth_present(h, "Digest", ' ', b);
}

/* 11) uri 与请求行不一致（语义错误） */
static void op_mismatch_uri(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:evil@else\", response=\"00\"");
}

/* 12) 重复键/空参数 */
static void op_dup_keys(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "username=\"u\", username=\"v\", realm=\"\", nonce=, uri=\"sip:a@b\", response=\"00\"");
}

/* 13) 未加引号/引号不配对 */
static void op_bad_quotes(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "username=u, realm=\"r, nonce=\"n\", uri=sip:a@b, response=00");
}

/* 14) 非法字符/非 ASCII */
static void op_non_ascii1(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "usernäme=\"u\", reálm=\"r\", nonce=\"ñ\", uri=\"sip:a@b\", response=\"00\"");
}

/* 15) CRLF 注入 */
static void op_crlf_inject(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "username=\"u\"\r\nVia: SIP/2.0/UDP attacker\r\n, realm=\"r\", response=\"00\"");
}

/* 16) 值超长填充 */
static void op_long_nonce(sip_authorization_hdr_t *h){
    char big[SIP_PARAMS_LEN]; memset(big, 0, sizeof big);
    size_t pos = (size_t)snprintf(big, sizeof big, "username=\"u\", realm=\"r\", nonce=\"");
    /* 填充很多 'x' 直到接近边界 */
    while (pos + 2 < sizeof big - 1) big[pos++]='x';
    if (pos < sizeof big - 1) big[pos++]='"';
    if (pos < sizeof big - 1) big[pos++]=',';
    scpy(big+pos, sizeof big - pos, " uri=\"sip:a@b\", response=\"00\"");
    set_auth_present(h, "Digest", ' ', big);
}

/* 17) 多凭据合并在一个头（逗号分隔） */
static void op_multi_credentials_one_header(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", ' ',
        "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:a@b\", response=\"00\", "
        "Digest username=\"u2\", realm=\"r2\", nonce=\"n2\", uri=\"sip:c@d\", response=\"11\"");
}

/* 18) 怪异大小写/怪方案名 */
static void op_weird_scheme_case(sip_authorization_hdr_t *h){
    set_auth_present(h, "DiGESt", ' ', "username=\"U\", REALM=\"R\", NONCE=\"N\"");
}

/* ---------------- 入口：遍历数组并随机应用算子 ---------------- */

void mutate_authorization_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xA11C0DEu;

    for (size_t i=0;i<n;i++){
        sip_packet_t *p = &pkts[i];
        sip_authorization_hdr_t *h = get_auth_hdr(p);
        if (!h) continue;

        /* 20% 删除，30% 设为“看起来自洽”的 Digest，50% 随机畸形/边界 */
        unsigned r = rnd_pick(&st, 10);
        if (r < 2){
            set_auth_absent(h);
            continue;
        }
        if (r < 5){
            switch (rnd_pick(&st, 4)){
                case 0: op_digest_ok_md5(p, h); break;
                case 1: op_digest_authint_md5sess(p, h); break;
                case 2: op_digest_sha256(p, h); break;
                default: op_digest_aka(p, h); break;
            }
            continue;
        }

        /* 若原先缺失，给个基底再变异 */
        if (h->name[0]=='\0') op_digest_ok_md5(p, h);

        /* 1~2 次变异覆盖 */
        size_t times = 1 + rnd_pick(&st, 2);
        while (times--){
            switch (rnd_pick(&st, 18)){
                case 0:  op_basic(h); break;
                case 1:  op_bearer(h); break;
                case 2:  op_scheme_only(h); break;
                case 3:  op_no_space0(h); break;
                case 4:  op_tab_space(h); break;
                case 5:  op_missing_response(p, h); break;
                case 6:  op_mismatch_uri(h); break;
                case 7:  op_dup_keys(h); break;
                case 8:  op_bad_quotes(h); break;
                case 9:  op_non_ascii1(h); break;
                case 10: op_crlf_inject(h); break;
                case 11: op_long_nonce(h); break;
                case 12: op_multi_credentials_one_header(h); break;
                case 13: op_weird_scheme_case(h); break;
                case 14: op_digest_ok_md5(p, h); break;
                case 15: op_digest_authint_md5sess(p, h); break;
                case 16: op_digest_sha256(p, h); break;
                default: op_digest_aka(p, h); break;
            }
        }
    }
}


static void set_hide_present(sip_hide_hdr_t *h, const char *val){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Hide");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->value, sizeof h->value, val ? val : "");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}

static void set_hide_absent(sip_hide_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

static sip_hide_hdr_t* get_hide_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.hide;
      case SIP_PKT_ACK:      return &p->pkt.ack.hide;
      case SIP_PKT_BYE:      return &p->pkt.bye.hide;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.hide;
      case SIP_PKT_REGISTER: return &p->pkt.register_.hide;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.hide;
      default: return NULL;
    }
}


/* ------------ add_/delete_ 便捷接口（可选用） ------------ */
void add_invite_hide   (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_hide_present(&p->pkt.invite.hide,   val?val:"hop"); }
void delete_invite_hide(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_hide_absent(&p->pkt.invite.hide); }

void add_ack_hide      (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_hide_present(&p->pkt.ack.hide,      val?val:"hop"); }
void delete_ack_hide   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_hide_absent(&p->pkt.ack.hide); }

void add_bye_hide      (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_hide_present(&p->pkt.bye.hide,      val?val:"hop"); }
void delete_bye_hide   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_hide_absent(&p->pkt.bye.hide); }

void add_cancel_hide   (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_hide_present(&p->pkt.cancel.hide,   val?val:"hop"); }
void delete_cancel_hide(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_hide_absent(&p->pkt.cancel.hide); }

void add_register_hide (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_hide_present(&p->pkt.register_.hide, val?val:"hop"); }
void delete_register_hide(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_hide_absent(&p->pkt.register_.hide); }

void add_options_hide  (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_hide_present(&p->pkt.options.hide,  val?val:"hop"); }
void delete_options_hide(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_hide_absent(&p->pkt.options.hide); }

/* ------------ 具体算子（≥12） ------------ */

/* 1) 合法：hop */
static void op_hide_hop(sip_hide_hdr_t *h){ set_hide_present(h, "hop"); }

/* 2) 合法：route */
static void op_hide_route(sip_hide_hdr_t *h){ set_hide_present(h, "route"); }

/* 3) 兼容：大小写混合 */
static void op_hide_mixedcase(sip_hide_hdr_t *h){ set_hide_present(h, "HoP"); }

/* 4) 兼容：前后空白（接收端可能 trim） */
static void op_hide_spaces(sip_hide_hdr_t *h){ set_hide_present(h, "   hop  "); }

/* 5) 兼容/异常：未知取值 */
static void op_hide_unknown(sip_hide_hdr_t *h){ set_hide_present(h, "session"); }

/* 6) 异常：空值 */
static void op_hide_empty(sip_hide_hdr_t *h){ set_hide_present(h, ""); }

/* 7) 异常：逗号分隔多个值 */
static void op_hide_multi(sip_hide_hdr_t *h){ set_hide_present(h, "hop, route"); }

/* 8) 异常：带“参数”样式（虽然语义不存在） */
static void op_hide_params(sip_hide_hdr_t *h){ set_hide_present(h, "hop;foo=bar;lr"); }

/* 9) 异常：CRLF 注入 */
static void op_hide_crlf_inject(sip_hide_hdr_t *h){
    set_hide_present(h, "hop\r\nMax-Forwards: 0\r\n");
}

/* 10) 异常：非 ASCII */
static void op_hide_non_ascii(sip_hide_hdr_t *h){ set_hide_present(h, "routé"); }

/* 11) 异常：加引号 */
static void op_hide_quoted(sip_hide_hdr_t *h){ set_hide_present(h, "\"hop\""); }

/* 12) 异常：等号/奇怪符号 */
static void op_hide_equals(sip_hide_hdr_t *h){ set_hide_present(h, "hop=1"); }

/* 13) 边界：超长填充 */
static void op_hide_very_long(sip_hide_hdr_t *h){
    char big[SIP_TOKEN_LEN]; size_t i=0;
    /* 用 'X' 填满（保留 '\0'），也可以掺杂分隔符 */
    for (; i+1 < sizeof(big); ++i) big[i] = (i%17==0)?';':'X';
    big[i]='\0';
    set_hide_present(h, big);
}

/* ------------ 入口：遍历数组并随机应用 ------------ */

void mutate_hide_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xC0FFEEu;

    for (size_t i=0;i<n;i++){
        sip_hide_hdr_t *h = get_hide_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 直接删除；否则保证存在并随机选择一种变异 */
        if (rnd_pick(&st, 10) < 2u){
            set_hide_absent(h);
            continue;
        }
        if (h->name[0]=='\0') op_hide_hop(h); /* 不存在则给个基底 */

        switch (rnd_pick(&st, 13)){
            case 0:  op_hide_hop(h); break;
            case 1:  op_hide_route(h); break;
            case 2:  op_hide_mixedcase(h); break;
            case 3:  op_hide_spaces(h); break;
            case 4:  op_hide_unknown(h); break;
            case 5:  op_hide_empty(h); break;
            case 6:  op_hide_multi(h); break;
            case 7:  op_hide_params(h); break;
            case 8:  op_hide_crlf_inject(h); break;
            case 9:  op_hide_non_ascii(h); break;
            case 10: op_hide_quoted(h); break;
            case 11: op_hide_equals(h); break;
            default: op_hide_very_long(h); break;
        }
    }
}

static void set_mf_present(sip_max_forwards_hdr_t *h, const char *val){
    if (!h) return;
    scpy(h->name, sizeof h->name, "Max-Forwards");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->hops, sizeof h->hops, val ? val : "");
    scpy(h->crlf, sizeof h->crlf, "\r\n");
}
static void set_mf_absent(sip_max_forwards_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

/* 在不同消息中定位该头指针 */
static sip_max_forwards_hdr_t* get_mf_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.max_forwards;
      case SIP_PKT_ACK:      return &p->pkt.ack.max_forwards;
      case SIP_PKT_BYE:      return &p->pkt.bye.max_forwards;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.max_forwards;
      case SIP_PKT_REGISTER: return &p->pkt.register_.max_forwards;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.max_forwards;
      default: return NULL;
    }
}


/* ---------- add_/delete_ 便捷接口（可选） ---------- */
void add_invite_max_forwards   (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_mf_present(&p->pkt.invite.max_forwards,   val?val:"70"); }
void delete_invite_max_forwards(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_mf_absent(&p->pkt.invite.max_forwards); }

void add_ack_max_forwards      (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_mf_present(&p->pkt.ack.max_forwards,      val?val:"70"); }
void delete_ack_max_forwards   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_mf_absent(&p->pkt.ack.max_forwards); }

void add_bye_max_forwards      (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_mf_present(&p->pkt.bye.max_forwards,      val?val:"70"); }
void delete_bye_max_forwards   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_mf_absent(&p->pkt.bye.max_forwards); }

void add_cancel_max_forwards   (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_mf_present(&p->pkt.cancel.max_forwards,   val?val:"70"); }
void delete_cancel_max_forwards(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_mf_absent(&p->pkt.cancel.max_forwards); }

void add_register_max_forwards (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_mf_present(&p->pkt.register_.max_forwards, val?val:"70"); }
void delete_register_max_forwards(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_mf_absent(&p->pkt.register_.max_forwards); }

void add_options_max_forwards  (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_mf_present(&p->pkt.options.max_forwards,  val?val:"70"); }
void delete_options_max_forwards(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_mf_absent(&p->pkt.options.max_forwards); }

/* ---------- 变异算子（≥14） ---------- */

/* 合法值 */
static void op_mf_std   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "70"); }
static void op_mf_one   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "1"); }
static void op_mf_zero  (sip_max_forwards_hdr_t *h){ set_mf_present(h, "0"); }  /* 立即终止转发（合法边界） */
static void op_mf_255   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "255"); }

/* 语法异常 / 边界扩展 */
static void op_mf_big   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "9999999999"); }
static void op_mf_neg   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "-1"); }
static void op_mf_plus  (sip_max_forwards_hdr_t *h){ set_mf_present(h, "+10"); }
static void op_mf_lz    (sip_max_forwards_hdr_t *h){ set_mf_present(h, "00000010"); }
static void op_mf_hex   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "0x10"); }
static void op_mf_space (sip_max_forwards_hdr_t *h){ set_mf_present(h, "   10  "); }
static void op_mf_empty (sip_max_forwards_hdr_t *h){ set_mf_present(h, ""); }
static void op_mf_alpha (sip_max_forwards_hdr_t *h){ set_mf_present(h, "abc"); }
static void op_mf_sci   (sip_max_forwards_hdr_t *h){ set_mf_present(h, "1e9"); }
static void op_mf_param (sip_max_forwards_hdr_t *h){ set_mf_present(h, "10;foo=bar"); }

/* CRLF/注入测试（分行/头部走样） */
static void op_mf_inject(sip_max_forwards_hdr_t *h){
    set_mf_present(h, "10\r\nVia: SIP/2.0/UDP evil:5060\r\n");
}

/* 最大长度填充 */
static void op_mf_very_long(sip_max_forwards_hdr_t *h){
    char buf[SIP_NUM_LEN];
    size_t i=0;
    for (; i+1<sizeof(buf); ++i) buf[i] = '9';
    buf[i]='\0';
    set_mf_present(h, buf);
}

/* ---------- 主入口：遍历并随机应用 ---------- */
void mutate_max_forwards_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0x5EEDu;

    for (size_t i=0;i<n;i++){
        sip_max_forwards_hdr_t *h = get_mf_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 概率删除；否则确保存在并随机选择一种变异 */
        if ((rnd_pick(&st, 10)) < 2u){
            set_mf_absent(h);
            continue;
        }
        if (h->name[0]=='\0') op_mf_std(h);

        switch (rnd_pick(&st, 16)){
            case 0:  op_mf_std(h); break;
            case 1:  op_mf_one(h); break;
            case 2:  op_mf_zero(h); break;
            case 3:  op_mf_255(h); break;
            case 4:  op_mf_big(h); break;
            case 5:  op_mf_neg(h); break;
            case 6:  op_mf_plus(h); break;
            case 7:  op_mf_lz(h); break;
            case 8:  op_mf_hex(h); break;
            case 9:  op_mf_space(h); break;
            case 10: op_mf_empty(h); break;
            case 11: op_mf_alpha(h); break;
            case 12: op_mf_sci(h); break;
            case 13: op_mf_param(h); break;
            case 14: op_mf_inject(h); break;
            default: op_mf_very_long(h); break;
        }
    }
}


static void set_org_present(sip_organization_hdr_t *h, const char *val){
    if (!h) return;
    scpy(h->name,        sizeof h->name,        "Organization");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->text,        sizeof h->text,        val ? val : "");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
}
static void set_org_absent(sip_organization_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

/* 在不同消息中定位 Organization 头指针 */
static sip_organization_hdr_t* get_org_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.organization;
      case SIP_PKT_ACK:      return &p->pkt.ack.organization;
      case SIP_PKT_REGISTER: return &p->pkt.register_.organization;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.organization;
      default: return NULL; /* BYE / CANCEL 无该字段 */
    }
}

/* ---------- add_/delete_ 便捷接口 ---------- */
void add_invite_organization   (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_INVITE)   return; set_org_present(&p->pkt.invite.organization,   val?val:"Example Corp"); }
void delete_invite_organization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE)   return; set_org_absent(&p->pkt.invite.organization); }

void add_ack_organization      (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_ACK)      return; set_org_present(&p->pkt.ack.organization,      val?val:"Example Corp"); }
void delete_ack_organization   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK)      return; set_org_absent(&p->pkt.ack.organization); }

void add_register_organization (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_org_present(&p->pkt.register_.organization, val?val:"Example Corp"); }
void delete_register_organization(sip_packet_t *p, size_t n, unsigned int seed){if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_org_absent(&p->pkt.register_.organization); }

void add_options_organization  (sip_packet_t *p, const char *val){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS)  return; set_org_present(&p->pkt.options.organization,  val?val:"Example Corp"); }
void delete_options_organization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS)  return; set_org_absent(&p->pkt.options.organization); }

/* ---------- 变异算子（≥16） ---------- */
/* 合法/常见 */
static void op_org_std   (sip_organization_hdr_t *h){ set_org_present(h, "Example Corp"); }
static void op_org_acme  (sip_organization_hdr_t *h){ set_org_present(h, "ACME Inc."); }
static void op_org_lc_ws (sip_organization_hdr_t *h){ set_org_present(h, "   ACME   Corporation  "); }

/* 边界长度 */
static void op_org_long  (sip_organization_hdr_t *h){
    char buf[SIP_TEXT_LEN];
    size_t i=0;
    for (; i+1<sizeof(buf); ++i) buf[i] = 'A';
    buf[i]='\0';
    set_org_present(h, buf);
}

/* 空/仅空白 */
static void op_org_empty (sip_organization_hdr_t *h){ set_org_present(h, ""); }
static void op_org_ws    (sip_organization_hdr_t *h){ set_org_present(h, " \t "); }

/* 非 ASCII / 本地化 */
static void op_org_cn    (sip_organization_hdr_t *h){ set_org_present(h, "北京某某科技有限公司"); }
static void op_org_de    (sip_organization_hdr_t *h){ set_org_present(h, "München GmbH"); }
static void op_org_emoji (sip_organization_hdr_t *h){ set_org_present(h, "ACME 🚀 Lab"); }

/* 无效 UTF-8 片段（触发解码/日志健壮性） */
static void op_org_bad_utf8(sip_organization_hdr_t *h){
    set_org_present(h, "");                 /* 先填好固定字段 */
    h->text[0] = (char)0xC3;                /* 独立前导字节 */
    h->text[1] = (char)0x28;                /* 无效续字节 */
    h->text[2] = 'X';
    h->text[3] = '\0';
}

/* 控制符/注入 */
static void op_org_ctrl  (sip_organization_hdr_t *h){ set_org_present(h, "ACME\tCorp"); }
static void op_org_inject(sip_organization_hdr_t *h){ set_org_present(h, "ACME\r\nVia: SIP/2.0/UDP evil:5060\r\n"); }

/* 标点、分隔与奇异字符 */
static void op_org_punct (sip_organization_hdr_t *h){ set_org_present(h, "ACME; \"Corp\", (R&D) <HQ> [Unit]"); }
static void op_org_quote (sip_organization_hdr_t *h){ set_org_present(h, "\"Unbalanced Quote Corp"); }

/* 百分号编码/路径/HTML */
static void op_org_pct   (sip_organization_hdr_t *h){ set_org_present(h, "ACME%20Corp%0d%0aX"); }
static void op_org_path  (sip_organization_hdr_t *h){ set_org_present(h, "../../etc/passwd"); }
static void op_org_html  (sip_organization_hdr_t *h){ set_org_present(h, "<script>alert(1)</script>"); }

/* RLO/PDF（双向文本） */
static void op_org_bidi  (sip_organization_hdr_t *h){
    /* U+202E (RLO) + "CBA" + U+202C (PDF) */
    set_org_present(h, "\xE2\x80\xAE""CBA""\xE2\x80\xAC");
}

/* ---------- 主入口：遍历并随机变异 ---------- */
void mutate_organization_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xA11CEu;

    for (size_t i=0;i<n;i++){
        sip_organization_hdr_t *h = get_org_hdr(&pkts[i]);
        if (!h) continue;

        /* 25% 概率删除；否则确保存在并随机一种变异 */
        if ((rnd_pick(&st, 100)) < 25u){
            set_org_absent(h);
            continue;
        }
        if (h->name[0]=='\0') op_org_std(h);

        switch (rnd_pick(&st, 18)){
            case 0:  op_org_std(h);   break;
            case 1:  op_org_acme(h);  break;
            case 2:  op_org_lc_ws(h); break;
            case 3:  op_org_long(h);  break;
            case 4:  op_org_empty(h); break;
            case 5:  op_org_ws(h);    break;
            case 6:  op_org_cn(h);    break;
            case 7:  op_org_de(h);    break;
            case 8:  op_org_emoji(h); break;
            case 9:  op_org_bad_utf8(h); break;
            case 10: op_org_ctrl(h);  break;
            case 11: op_org_inject(h);break;
            case 12: op_org_punct(h); break;
            case 13: op_org_quote(h); break;
            case 14: op_org_pct(h);   break;
            case 15: op_org_path(h);  break;
            case 16: op_org_html(h);  break;
            default: op_org_bidi(h);  break;
        }
    }
}


static void set_prio_present(sip_priority_hdr_t *h, const char *val){
    if (!h) return;
    scpy(h->name,        sizeof h->name,        "Priority");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->value,       sizeof h->value,       val ? val : "");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
}
static void set_prio_absent(sip_priority_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

/* 在不同消息中定位 Priority 头（当前仅 INVITE 有该字段） */
static sip_priority_hdr_t* get_priority_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE: return &p->pkt.invite.priority;
      default: return NULL; /* 其它类型未定义该字段 */
    }
}

/* -------- add_/delete_ 便捷接口（仅 INVITE 生效） -------- */
void add_invite_priority(sip_packet_t *p, const char *val){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_prio_present(&p->pkt.invite.priority, val ? val : "normal");
}
void delete_invite_priority(sip_packet_t *p, size_t n, unsigned int seed){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    set_prio_absent(&p->pkt.invite.priority);
}

/* ---------------- 变异算子（≥16 个） ---------------- */
/* 合法取值 */
static void op_prio_emergency(sip_priority_hdr_t *h){ set_prio_present(h, "emergency"); }
static void op_prio_urgent   (sip_priority_hdr_t *h){ set_prio_present(h, "urgent"); }
static void op_prio_normal   (sip_priority_hdr_t *h){ set_prio_present(h, "normal"); }
static void op_prio_nonurg   (sip_priority_hdr_t *h){ set_prio_present(h, "non-urgent"); }

/* 大小写/格式变体（对大小写敏感实现可能触发差异） */
static void op_prio_upper    (sip_priority_hdr_t *h){ set_prio_present(h, "EMERGENCY"); }
static void op_prio_mixed    (sip_priority_hdr_t *h){ set_prio_present(h, "Non-Urgent"); }

/* 空与空白 */
static void op_prio_empty    (sip_priority_hdr_t *h){ set_prio_present(h, ""); }
static void op_prio_ws       (sip_priority_hdr_t *h){ set_prio_present(h, " \t "); }

/* 非法 token / 数字 */
static void op_prio_illegal1 (sip_priority_hdr_t *h){ set_prio_present(h, "super-urgent"); }
static void op_prio_illegal2 (sip_priority_hdr_t *h){ set_prio_present(h, "low"); }
static void op_prio_numeric  (sip_priority_hdr_t *h){ set_prio_present(h, "12345"); }

/* 带“参数”形态（通常不被接受） */
static void op_prio_param    (sip_priority_hdr_t *h){ set_prio_present(h, "urgent;q=1.0"); }

/* 过长值（边界） */
static void op_prio_long     (sip_priority_hdr_t *h){
    char buf[SIP_TOKEN_LEN];
    size_t i=0; for (; i+1<sizeof(buf); ++i) buf[i] = 'A';
    buf[i] = '\0';
    set_prio_present(h, buf);
}

/* 控制符/注入 */
static void op_prio_ctrl     (sip_priority_hdr_t *h){ set_prio_present(h, "urgent\tHIGH"); }
static void op_prio_inject   (sip_priority_hdr_t *h){ set_prio_present(h, "normal\r\nVia: SIP/2.0/UDP evil:5060\r\n"); }

/* 非 ASCII / 本地化 */
static void op_prio_cn       (sip_priority_hdr_t *h){ set_prio_present(h, "紧急"); }

/* 无效 UTF-8 */
static void op_prio_badutf8  (sip_priority_hdr_t *h){
    set_prio_present(h, "");
    h->value[0] = (char)0xC3; /* 孤立前导字节 */
    h->value[1] = (char)0x28; /* 非续字节 */
    h->value[2] = '\0';
}

/* 引号包裹（有的实现不接受） */
static void op_prio_quoted   (sip_priority_hdr_t *h){ set_prio_present(h, "\"urgent\""); }

/* -------- 主入口：遍历并随机变异 -------- */
void mutate_priority_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xBADDCAFEu;

    for (size_t i=0; i<n; ++i){
        sip_priority_hdr_t *h = get_priority_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 概率删除该头；否则确保存在并做一次随机变异 */
        if (rnd_pick(&st, 100) < 20u){
            set_prio_absent(h);
            continue;
        }
        if (h->name[0] == '\0') op_prio_normal(h);

        switch (rnd_pick(&st, 18)){
            case 0:  op_prio_emergency(h); break;
            case 1:  op_prio_urgent(h);    break;
            case 2:  op_prio_normal(h);    break;
            case 3:  op_prio_nonurg(h);    break;
            case 4:  op_prio_upper(h);     break;
            case 5:  op_prio_mixed(h);     break;
            case 6:  op_prio_empty(h);     break;
            case 7:  op_prio_ws(h);        break;
            case 8:  op_prio_illegal1(h);  break;
            case 9:  op_prio_illegal2(h);  break;
            case 10: op_prio_numeric(h);   break;
            case 11: op_prio_param(h);     break;
            case 12: op_prio_long(h);      break;
            case 13: op_prio_ctrl(h);      break;
            case 14: op_prio_inject(h);    break;
            case 15: op_prio_cn(h);        break;
            case 16: op_prio_badutf8(h);   break;
            default: op_prio_quoted(h);    break;
        }
    }
}

static void sset_present(char *name, size_t nlen, char *sep, size_t slen, char *crlf, size_t clen, const char *n){
    scpy(name, nlen, n);
    scpy(sep,  slen, ": ");
    scpy(crlf, clen, "\r\n");
}
static int sformat(char *dst, size_t cap, const char *fmt, ...){
    if (!dst || !cap) return 0;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    if (n < 0) { dst[0] = '\0'; return 0; }
    if ((size_t)n >= cap) dst[cap-1] = '\0';
    return n;
}

/* 定位不同消息中的 Proxy-Authorization 头 */
static sip_proxy_authorization_hdr_t* get_pauth_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.proxy_authorization;
      case SIP_PKT_ACK:      return &p->pkt.ack.proxy_authorization;
      case SIP_PKT_BYE:      return &p->pkt.bye.proxy_authorization;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.proxy_authorization;
      case SIP_PKT_REGISTER: return &p->pkt.register_.proxy_authorization;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.proxy_authorization;
      default: return NULL;
    }
}

static void set_pauth_present(sip_proxy_authorization_hdr_t *h,
                              const char *scheme, const char *kv, int with_space){
    if (!h) return;
    sset_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
                 h->crlf, sizeof h->crlf, "Proxy-Authorization");
    scpy(h->scheme, sizeof h->scheme, scheme ? scheme : "Digest");
    h->sp = with_space ? ' ' : '\0';
    scpy(h->kvpairs, sizeof h->kvpairs, kv ? kv : "");
}
static void set_pauth_absent(sip_proxy_authorization_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';
}

/* add_/delete_ for each msg type (薄封装) */
void add_invite_proxy_authorization  (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_pauth_present(&p->pkt.invite.proxy_authorization,   "Digest", kv, 1); }
void delete_invite_proxy_authorization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_pauth_absent(&p->pkt.invite.proxy_authorization); }

void add_ack_proxy_authorization     (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_pauth_present(&p->pkt.ack.proxy_authorization,      "Digest", kv, 1); }
void delete_ack_proxy_authorization   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_pauth_absent(&p->pkt.ack.proxy_authorization); }

void add_bye_proxy_authorization     (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_pauth_present(&p->pkt.bye.proxy_authorization,      "Digest", kv, 1); }
void delete_bye_proxy_authorization   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_pauth_absent(&p->pkt.bye.proxy_authorization); }

void add_cancel_proxy_authorization  (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_pauth_present(&p->pkt.cancel.proxy_authorization,   "Digest", kv, 1); }
void delete_cancel_proxy_authorization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_pauth_absent(&p->pkt.cancel.proxy_authorization); }

void add_register_proxy_authorization  (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_pauth_present(&p->pkt.register_.proxy_authorization,"Digest", kv, 1); }
void delete_register_proxy_authorization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_pauth_absent(&p->pkt.register_.proxy_authorization); }

void add_options_proxy_authorization  (sip_packet_t *p, const char *kv){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_pauth_present(&p->pkt.options.proxy_authorization,  "Digest", kv, 1); }
void delete_options_proxy_authorization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_pauth_absent(&p->pkt.options.proxy_authorization); }

/* repeat_*：在同一行拼接第二个凭据 */
static void repeat_hdr(sip_proxy_authorization_hdr_t *h, const char *extra){
    if (!h || !h->name[0]) return;
    size_t cur = strnlen(h->kvpairs, sizeof h->kvpairs);
    if (cur + 2 < sizeof h->kvpairs){
        if (cur) strncat(h->kvpairs, ", ", sizeof(h->kvpairs)-strlen(h->kvpairs)-1);
        strncat(h->kvpairs, extra ? extra : "Digest username=\"u2\", realm=\"r2\", nonce=\"n2\", uri=\"sip:a@b\", response=\"deadbeef\"", sizeof(h->kvpairs)-strlen(h->kvpairs)-1);
    }
}
void repeat_invite_proxy_authorization  (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   repeat_hdr(&p->pkt.invite.proxy_authorization, NULL); }
void repeat_ack_proxy_authorization     (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      repeat_hdr(&p->pkt.ack.proxy_authorization, NULL); }
void repeat_bye_proxy_authorization     (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      repeat_hdr(&p->pkt.bye.proxy_authorization, NULL); }
void repeat_cancel_proxy_authorization  (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   repeat_hdr(&p->pkt.cancel.proxy_authorization, NULL); }
void repeat_register_proxy_authorization(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; repeat_hdr(&p->pkt.register_.proxy_authorization, NULL); }
void repeat_options_proxy_authorization (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  repeat_hdr(&p->pkt.options.proxy_authorization, NULL); }

static unsigned rnd(unsigned *st, unsigned mod){ return (lcg_next(st)>>16) % (mod?mod:1); }

/* ---------------- 变异算子（≥20） ---------------- */
/* 1. 标准 Digest（合法） */
static void op_digest_min(sip_proxy_authorization_hdr_t *h){
    set_pauth_present(h, "Digest", NULL, 1);
    sformat(h->kvpairs, sizeof h->kvpairs,
        "username=\"alice\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:bob@example.com\", response=\"0123456789abcdef\"");
}
/* 2. 大写方案 */
static void op_digest_upper(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "DIGEST", "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", response=\"ff\"", 1); }
/* 3. 未知方案 */
static void op_scheme_unknown(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Foo", "k=v", 1); }
/* 4. Basic 形态（HTTP 风格，SIP 通常不用） */
static void op_basic1(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Basic", "YWxpY2U6cGFzcw==", 1); }
/* 5. 缺少空格（sp=0） */
static void op_no_space1(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\"", 0); }
/* 6. 空 kvpairs */
static void op_empty_params(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "", 1); }
/* 7. 缺引号（非法） */
static void op_no_quotes(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=alice, realm=example, nonce=n, uri=sip:x@y, response=beef", 1); }
/* 8. 重复参数键（冲突） */
static void op_dup_param(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\", username=\"u2\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", response=\"aa\"", 1); }
/* 9. 非法分隔符（`;` 而非 `,`） */
static void op_semicolon_sep(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\"; realm=\"r\"; nonce=\"n\"; uri=\"sip:x@y\"; response=\"aa\"", 1); }
/* 10. 超长 nonce */
static void op_long_nonce1(sip_proxy_authorization_hdr_t *h){
    char buf[512]; memset(buf, 'N', sizeof(buf)-1); buf[sizeof(buf)-1] = 0;
    set_pauth_present(h, "Digest", NULL, 1);
    sformat(h->kvpairs, sizeof h->kvpairs, "username=\"u\", realm=\"r\", nonce=\"%s\", uri=\"sip:x@y\", response=\"aa\"", buf);
}
/* 11. CRLF 注入 */
static void op_crlf_inject1(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\"\r\nVia: SIP/2.0/UDP evil:5060\r\n", 1); }
/* 12. 非 ASCII 值 */
static void op_non_ascii2(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"阿里斯\", realm=\"例子\", nonce=\"ñ\", uri=\"sip:x@y\", response=\"aa\"", 1); }
/* 13. 坏 UTF-8 */
static void op_bad_utf8(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "\xC3\x28", 1); }
/* 14. qop 非法 */
static void op_bad_qop(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", qop=\"weird\", nc=00000001, cnonce=\"c\", response=\"aa\"", 1); }
/* 15. nc 位数错误 */
static void op_bad_nc(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", qop=auth, nc=1, cnonce=\"c\", response=\"aa\"", 1); }
/* 16. 不支持的算法 */
static void op_bad_alg(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", algorithm=md5-sessX, response=\"aa\"", 1); }
/* 17. 多凭据列表（模拟重复） */
static void op_multi_creds(sip_proxy_authorization_hdr_t *h){
    set_pauth_present(h, "Digest", NULL, 1);
    sformat(h->kvpairs, sizeof h->kvpairs,
      "username=\"u1\", realm=\"r1\", nonce=\"n1\", uri=\"sip:a@b\", response=\"11\", qop=auth, nc=00000001, cnonce=\"c1\", "
      "Digest username=\"u2\", realm=\"r2\", nonce=\"n2\", uri=\"sip:c@d\", response=\"22\"");
}
/* 18. 额外空白/Tab */
static void op_weird_ws(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username = \t \"u\" ,   realm =\"r\"", 1); }
/* 19. 顺序异常（nonce 先） */
static void op_reorder(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "nonce=\"n\", response=\"aa\", uri=\"sip:x@y\", realm=\"r\", username=\"u\"", 1); }
/* 20. 反斜杠转义 */
static void op_backslash(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "username=\"u\\\"quote\\\"\", realm=\"r\", nonce=\"n\", uri=\"sip:x@y\", response=\"aa\"", 1); }
/* 21. 只有方案，无参数 */
static void op_scheme_only1(sip_proxy_authorization_hdr_t *h){ set_pauth_present(h, "Digest", "", 1); }
/* 22. 极长整串（填满缓冲） */
static void op_fill_buffer(sip_proxy_authorization_hdr_t *h){
    set_pauth_present(h, "Digest", NULL, 1);
    /* 用 'a=' + 重复填充，保证以 NUL 结尾 */
    size_t left = sizeof h->kvpairs; size_t pos = 0;
    while (left > 4){ int n = sformat(h->kvpairs + pos, left, "a%zu=%zu,", pos, pos); if (n<=0) break; pos += (size_t)n; left = sizeof h->kvpairs - pos; }
    if (pos>0 && h->kvpairs[pos-1]==',') h->kvpairs[pos-1]='\0';
}
static void op_no_space(sip_authorization_hdr_t *h){
    set_auth_present(h, "Digest", '\0', "username=\"u\", realm=\"r\"");
}

/* 主入口：遍历并随机变异 */
void mutate_proxy_authorization_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xCAFEBABEu;
    for (size_t i=0; i<n; ++i){
        sip_proxy_authorization_hdr_t *h = get_pauth_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 删除；10% 重复；其余进行一次随机算子 */
        unsigned r = rnd(&st, 100);
        if (r < 20u){ set_pauth_absent(h); continue; }
        if (h->name[0] == '\0') op_digest_min(h);

        if (r >= 20u && r < 30u){
            /* repeat（在同一行模拟多条凭据） */
            op_multi_creds(h);
            continue;
        }

        switch (rnd(&st, 22)){
          case 0:  op_digest_min(h);      break;
          case 1:  op_digest_upper(h);    break;
          case 2:  op_scheme_unknown(h);  break;
          case 3:  op_basic1(h);           break;
          case 4:  op_no_space(h);        break;
          case 5:  op_empty_params(h);    break;
          case 6:  op_no_quotes(h);       break;
          case 7:  op_dup_param(h);       break;
          case 8:  op_semicolon_sep(h);   break;
          case 9:  op_long_nonce1(h);      break;
          case 10: op_crlf_inject1(h);     break;
          case 11: op_non_ascii2(h);       break;
          case 12: op_bad_utf8(h);        break;
          case 13: op_bad_qop(h);         break;
          case 14: op_bad_nc(h);          break;
          case 15: op_bad_alg(h);         break;
          case 16: op_multi_creds(h);     break;
          case 17: op_weird_ws(h);        break;
          case 18: op_reorder(h);         break;
          case 19: op_backslash(h);       break;
          case 20: op_scheme_only1(h);     break;
          default: op_fill_buffer(h);     break;
        }
    }
}



/* 定位各消息的 Proxy-Require 头 */
static sip_proxy_require_hdr_t* get_preq_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.proxy_require;
      case SIP_PKT_ACK:      return &p->pkt.ack.proxy_require;
      case SIP_PKT_BYE:      return &p->pkt.bye.proxy_require;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.proxy_require;
      case SIP_PKT_REGISTER: return &p->pkt.register_.proxy_require;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.proxy_require;
      default: return NULL;
    }
}
static void set_preq_present(sip_proxy_require_hdr_t *h, const char *tags){
    if (!h) return;
    sset_present(h->name, sizeof h->name,
                 h->colon_space, sizeof h->colon_space,
                 h->crlf, sizeof h->crlf, "Proxy-Require");
    scpy(h->option_tags, sizeof h->option_tags, tags ? tags : "");
}
static void set_preq_absent(sip_proxy_require_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0';            /* 约定：name[0]==0 表示该头缺失 */
}
static void append_tag(sip_proxy_require_hdr_t *h, const char *tag){
    if (!h || !h->name[0] || !tag || !tag[0]) return;
    size_t cur = strnlen(h->option_tags, sizeof h->option_tags);
    if (cur == 0){
        scpy(h->option_tags, sizeof h->option_tags, tag);
        return;
    }
    /* 追加为 ", tag" */
    if (cur + 2 < sizeof h->option_tags){
        strncat(h->option_tags, ", ", sizeof(h->option_tags)-strlen(h->option_tags)-1);
        strncat(h->option_tags, tag,  sizeof(h->option_tags)-strlen(h->option_tags)-1);
    }
}

/* add_/delete_ per message（薄封装） */
void add_invite_proxy_require   (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_preq_present(&p->pkt.invite.proxy_require,   tags); }
void delete_invite_proxy_require(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   set_preq_absent(&p->pkt.invite.proxy_require); }

void add_ack_proxy_require      (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_preq_present(&p->pkt.ack.proxy_require,      tags); }
void delete_ack_proxy_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      set_preq_absent(&p->pkt.ack.proxy_require); }

void add_bye_proxy_require      (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_preq_present(&p->pkt.bye.proxy_require,      tags); }
void delete_bye_proxy_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      set_preq_absent(&p->pkt.bye.proxy_require); }

void add_cancel_proxy_require   (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_preq_present(&p->pkt.cancel.proxy_require,   tags); }
void delete_cancel_proxy_require(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   set_preq_absent(&p->pkt.cancel.proxy_require); }

void add_register_proxy_require   (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_preq_present(&p->pkt.register_.proxy_require, tags); }
void delete_register_proxy_require(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_preq_absent(&p->pkt.register_.proxy_require); }

void add_options_proxy_require   (sip_packet_t *p, const char *tags){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_preq_present(&p->pkt.options.proxy_require,  tags); }
void delete_options_proxy_require(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  set_preq_absent(&p->pkt.options.proxy_require); }

/* repeat_<msg>_proxy_require: 在同一行追加更多标签 */
void repeat_invite_proxy_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   if(!p->pkt.invite.proxy_require.name[0]) set_preq_present(&p->pkt.invite.proxy_require,"timer"); append_tag(&p->pkt.invite.proxy_require, "100rel"); }
void repeat_ack_proxy_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      if(!p->pkt.ack.proxy_require.name[0]) set_preq_present(&p->pkt.ack.proxy_require,"timer"); append_tag(&p->pkt.ack.proxy_require, "100rel"); }
void repeat_bye_proxy_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      if(!p->pkt.bye.proxy_require.name[0]) set_preq_present(&p->pkt.bye.proxy_require,"timer"); append_tag(&p->pkt.bye.proxy_require, "100rel"); }
void repeat_cancel_proxy_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   if(!p->pkt.cancel.proxy_require.name[0]) set_preq_present(&p->pkt.cancel.proxy_require,"timer"); append_tag(&p->pkt.cancel.proxy_require, "100rel"); }
void repeat_register_proxy_require (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; if(!p->pkt.register_.proxy_require.name[0]) set_preq_present(&p->pkt.register_.proxy_require,"timer"); append_tag(&p->pkt.register_.proxy_require, "100rel"); }
void repeat_options_proxy_require  (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  if(!p->pkt.options.proxy_require.name[0]) set_preq_present(&p->pkt.options.proxy_require,"timer"); append_tag(&p->pkt.options.proxy_require, "100rel"); }


/* ---------- 变异算子（针对 option_tags，覆盖合法/非法 ≥ 12 种） ---------- */
static void op_valid_basic(sip_proxy_require_hdr_t *h){ set_preq_present(h, "100rel,timer"); }
static void op_valid_many(sip_proxy_require_hdr_t *h){ set_preq_present(h, "100rel,timer,path,precondition,resource-priority,sec-agree"); }
static void op_upper_mix (sip_proxy_require_hdr_t *h){ set_preq_present(h, "TIMER,100REL"); }
static void op_unknown    (sip_proxy_require_hdr_t *h){ set_preq_present(h, "x-super-proxy,x-foo"); }
static void op_duplicate  (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer,timer,100rel,100rel"); }
static void op_spaces     (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer ,  100rel ,   path"); }
static void op_illegal_ch (sip_proxy_require_hdr_t *h){ set_preq_present(h, "ti@mer,10#0rel"); }
static void op_param_like (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer=on,100rel=1"); }
static void op_trailing_c (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer,100rel,"); }     /* 结尾逗号 */
static void op_leading_c  (sip_proxy_require_hdr_t *h){ set_preq_present(h, ",timer,100rel"); }     /* 开头逗号 */
static void op_star       (sip_proxy_require_hdr_t *h){ set_preq_present(h, "*,timer"); }            /* 通配符（非法） */
static void op_crlf_inj   (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer\r\nVia: SIP/2.0/UDP evil:5060"); }
static void op_fold_ws    (sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer,\r\n 100rel"); }  /* 行折叠（历史做法） */

/* 填满缓冲的长 token 列表 */
static void op_fill(sip_proxy_require_hdr_t *h){
    char buf[sizeof h->option_tags]; buf[0]='\0';
    size_t left = sizeof buf, pos = 0;
    for (int i=0; i<1000; ++i){
        int n = sformat(buf+pos, left, (pos? ",t%d":"t%d"), i);
        if (n<=0) break;
        pos += (size_t)n; left = sizeof buf - pos;
        if (left < 4) break;
    }
    set_preq_present(h, buf);
}

/* 混入奇怪括号/引号 */
static void op_weird_chars(sip_proxy_require_hdr_t *h){ set_preq_present(h, "timer(abc),\"100rel\""); }

/* 将标签打乱顺序 + 去/留重复 */
static void op_shuffle_unique(sip_proxy_require_hdr_t *h, unsigned *st){
    const char *pool[] = {"100rel","timer","path","precondition","sec-agree","histinfo","gruu","norefersub","from-change","target-dialog","replaces"};
    int used[ (int)(sizeof(pool)/sizeof(pool[0])) ]; memset(used,0,sizeof used);
    char out[sizeof h->option_tags]; out[0]='\0';
    size_t pos = 0, left = sizeof out;
    int num = 2 + (int)rnd(st, 8); /* 2..9 个 */
    for (int i=0;i<num;i++){
        int idx = (int)rnd(st, (unsigned)(sizeof(pool)/sizeof(pool[0])));
        if (rnd(st,2)==0) used[idx]=0; /* 有时允许重复 */
        if (used[idx]) { i--; continue; }
        used[idx]=1;
        int n = sformat(out+pos, left, (pos? ",%s":"%s"), pool[idx]);
        if (n<=0) break;
        pos += (size_t)n; left = sizeof out - pos;
        if (left < 4) break;
    }
    set_preq_present(h, out);
}

/* ---------------- 批量变异入口 ---------------- */
void mutate_proxy_require_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xA55A1234u;
    for (size_t i=0; i<n; ++i){
        sip_proxy_require_hdr_t *h = get_preq_hdr(&pkts[i]);
        if (!h) continue;

        unsigned r = rnd(&st, 100);
        /* 20% 删除；10% 做 repeat；其余从算子里随机选 */
        if (r < 20u){ set_preq_absent(h); continue; }

        if (!h->name[0]) set_preq_present(h, "timer"); /* 若原本不存在，先放一个基准值 */

        if (r >= 20u && r < 30u){
            append_tag(h, "100rel");
            append_tag(h, "path");
            continue;
        }

        switch (rnd(&st, 16)){
          case 0:  op_valid_basic(h); break;
          case 1:  op_valid_many(h);  break;
          case 2:  op_upper_mix(h);   break;
          case 3:  op_unknown(h);     break;
          case 4:  op_duplicate(h);   break;
          case 5:  op_spaces(h);      break;
          case 6:  op_illegal_ch(h);  break;
          case 7:  op_param_like(h);  break;
          case 8:  op_trailing_c(h);  break;
          case 9:  op_leading_c(h);   break;
          case 10: op_empty(h);       break;
          case 11: op_star(h);        break;
          case 12: op_crlf_inj(h);    break;
          case 13: op_fold_ws(h);     break;
          case 14: op_fill(h);        break;
          default: op_weird_chars(h); break;
        }

        /* 25% 再做一次“乱序唯一/可重复”的重混，增加覆盖 */
        if (rnd(&st,4)==0) op_shuffle_unique(h, &st);
    }
}



/* 访问不同请求的 route[]/count/cap */
static void get_routes(sip_packet_t *p, sip_route_hdr_t **arr, size_t *count, size_t *cap){
    *arr = NULL; *count = 0; *cap = 0;
    if (!p) return;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   *arr = p->pkt.invite.route;   *count = p->pkt.invite.route_count;   *cap = SIP_MAX_ROUTE; break;
      case SIP_PKT_ACK:      *arr = p->pkt.ack.route;      *count = p->pkt.ack.route_count;      *cap = SIP_MAX_ROUTE; break;
      case SIP_PKT_BYE:      *arr = p->pkt.bye.route;      *count = p->pkt.bye.route_count;      *cap = SIP_MAX_ROUTE; break;
      case SIP_PKT_CANCEL:   *arr = p->pkt.cancel.route;   *count = p->pkt.cancel.route_count;   *cap = SIP_MAX_ROUTE; break;
      case SIP_PKT_REGISTER: *arr = p->pkt.register_.route;*count = p->pkt.register_.route_count;*cap = SIP_MAX_ROUTE; break;
      case SIP_PKT_OPTIONS:  *arr = p->pkt.options.route;  *count = p->pkt.options.route_count;  *cap = SIP_MAX_ROUTE; break;
      default: break;
    }
}
static void set_route_count(sip_packet_t *p, size_t n){
    if (!p) return;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   p->pkt.invite.route_count   = n; break;
      case SIP_PKT_ACK:      p->pkt.ack.route_count      = n; break;
      case SIP_PKT_BYE:      p->pkt.bye.route_count      = n; break;
      case SIP_PKT_CANCEL:   p->pkt.cancel.route_count   = n; break;
      case SIP_PKT_REGISTER: p->pkt.register_.route_count= n; break;
      case SIP_PKT_OPTIONS:  p->pkt.options.route_count  = n; break;
      default: break;
    }
}
static void set_route_present(sip_route_hdr_t *h, const char *uri, const char *params, int with_angle){
    if (!h) return;
    sset_present(h->name, sizeof h->name,
                 h->colon_space, sizeof h->colon_space,
                 h->crlf, sizeof h->crlf, "Route");
    h->lt  = with_angle ? '<' : '\0';
    scpy(h->uri, sizeof h->uri, uri ? uri : "");
    h->gt  = with_angle ? '>' : '\0';
    scpy(h->params, sizeof h->params, params ? params : "");
}
static void set_route_absent(sip_route_hdr_t *h){
    if (!h) return;
    h->name[0] = '\0'; /* 缺失的判定依据 */
}
static int push_route(sip_packet_t *p, const char *uri, const char *params, int with_angle){
    sip_route_hdr_t *arr; size_t n, cap;
    get_routes(p, &arr, &n, &cap);
    if (!arr) return -1;
    if (n >= cap) { /* 挤掉最后一个，保留 n-1 个 */
        n = cap - 1;
        set_route_count(p, n);
    }
    set_route_present(&arr[n], uri, params, with_angle);
    set_route_count(p, n+1);
    return 0;
}

/* ---------------- add/delete/repeat ---------------- */
void add_invite_route   (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return;   push_route(p, uri, params, 1); }
void delete_invite_route(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_INVITE) return; set_route_count(p,0); }

void add_ack_route      (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      push_route(p, uri, params, 1); }
void delete_ack_route   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return; set_route_count(p,0); }

void add_bye_route      (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      push_route(p, uri, params, 1); }
void delete_bye_route   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return; set_route_count(p,0); }

void add_cancel_route   (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   push_route(p, uri, params, 1); }
void delete_cancel_route(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return; set_route_count(p,0); }

void add_register_route   (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; push_route(p, uri, params, 1); }
void delete_register_route(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; set_route_count(p,0); }

void add_options_route   (sip_packet_t *p, const char *uri, const char *params){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  push_route(p, uri, params, 1); }
void delete_options_route(sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return; set_route_count(p,0); }

/* repeat：复制第 0 条到尾部；若不存在则先加一个默认 */
void repeat_invite_route   (sip_packet_t *p){
    if(!p||p->cmd_type!=SIP_PKT_INVITE) return;
    sip_route_hdr_t *arr; size_t n, cap; get_routes(p,&arr,&n,&cap);
    if (n==0) { push_route(p, "sip:proxy.example.com;lr", ";lr", 1); return; }
    push_route(p, arr[0].uri, arr[0].params, arr[0].lt?1:0);
}
void repeat_ack_route      (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_ACK) return;      repeat_invite_route(p); }
void repeat_bye_route      (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_BYE) return;      repeat_invite_route(p); }
void repeat_cancel_route   (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_CANCEL) return;   repeat_invite_route(p); }
void repeat_register_route (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_REGISTER) return; repeat_invite_route(p); }
void repeat_options_route  (sip_packet_t *p, size_t n, unsigned int seed){ if(!p||p->cmd_type!=SIP_PKT_OPTIONS) return;  repeat_invite_route(p); }


/* ---------------- 针对单条 Route 的变异算子（≥ 14 种） ---------------- */
static void op_valid_basic1(sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com", ";lr", 1); }
static void op_no_lr      (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com", "", 1); }
static void op_ipv6       (sip_route_hdr_t *h){ set_route_present(h, "sip:[2001:db8::1]:5080", ";lr", 1); }
static void op_maddr_ttl  (sip_route_hdr_t *h){ set_route_present(h, "sip:gw@example.com", ";lr;maddr=224.2.0.1;ttl=15", 1); }
static void op_transport   (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com;transport=udp", ";lr", 1); }
static void op_params_dup  (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com", ";lr;lr;foo=bar", 1); }
static void op_illegal_uri (sip_route_hdr_t *h){ set_route_present(h, "http://evil/", ";lr", 1); }   /* 非法 scheme */
static void op_tel_uri     (sip_route_hdr_t *h){ set_route_present(h, "tel:+1555123456", ";lr", 1); } /* 不期望的 scheme */
static void op_no_angles   (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com", ";lr", 0); }
static void op_unbalanced  (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy.example.com", ";lr", 1); h->gt = '\0'; }
static void op_space_in_uri(sip_route_hdr_t *h){ set_route_present(h, "sip:pro xy@example.com", ";lr", 1); }
static void op_weird_chars1 (sip_route_hdr_t *h){ set_route_present(h, "sip:pro\"xy\"@example.com", ";lr", 1); }
static void op_crlf_inj1    (sip_route_hdr_t *h){ set_route_present(h, "sip:proxy@example.com", ";\r\nVia: SIP/2.0/UDP bad", 1); }
static void op_empty_params1(sip_route_hdr_t *h){ set_route_present(h, "sip:proxy@example.com", ";;;", 1); }
static void op_fill_uri    (sip_route_hdr_t *h){
    char big[SIP_URI_LEN]; size_t L = sizeof(big)-1;
    for (size_t i=0;i<L;i++) big[i] = (i%26)+'a';
    big[L]='\0';
    set_route_present(h, big, ";lr", 1);
}
static inline void scpy_safe(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void set_route_present_safe(sip_route_hdr_t *h, const char *uri, const char *params, int with_angle){
    if (!h) return;
    // 你的 sset_present 若也写字符串，请同样带容量
    // sset_present(..., "Route");

    h->lt  = with_angle ? '<' : '\0';
    scpy_safe(h->uri,    sizeof h->uri,    uri    ? uri    : "");
    h->gt  = with_angle ? '>' : '\0';
    scpy_safe(h->params, sizeof h->params, params ? params : "");
}

static void op_long_params (sip_route_hdr_t *h){
    char big[SIP_PARAMS_LEN];
    size_t pos = 0, left = sizeof(big);

    if (!h) return;
    big[0] = '\0';

    for (int i = 0; i < 1000; ++i) {
        // 需要追加的片段；注意第一项是否要以分号开头，这里始终以分号开头
        // 若你希望第一项不带分号，可用 i ? "; p%d=v%d" : "p%d=v%d"
        int need = snprintf(NULL, 0, "%s p%d=v%d", ";", i, i);  // “应写长度”
        if (need < 0) break;

        // 检查剩余空间是否足够（包括终止符）
        if ((size_t)need + 1 > left) {
            // 空间不够，不写入，直接停
            break;
        }

        int wrote = snprintf(big + pos, left, "%s p%d=v%d", ";", i, i);
        if (wrote < 0) break;

        // 这里 wrote == need，一定小于 left
        pos  += (size_t)wrote;
        left -= (size_t)wrote;
    }

    set_route_present_safe(h, "sip:proxy@example.com", big, 1);
}


/* 为某个包构造多条 route（合法/混合） */
static void op_route_set(sip_packet_t *p, unsigned *st){
    /* 清空，再填 2..N 条 */
    set_route_count(p, 0);
    int cnt = 2 + (int)rnd(st, (unsigned)(SIP_MAX_ROUTE>6?5: (SIP_MAX_ROUTE>2? (SIP_MAX_ROUTE-2):1)));
    for (int i=0;i<cnt;i++){
        char uri[128];
        sformat(uri, sizeof uri, "sip:hop%d.proxy.example.com", i);
        push_route(p, uri, (i%2? ";lr": ""), 1);
    }
    /* 25% 在末尾追加一个非法的 */
    if ((rnd(st,4)==0)){
        sip_route_hdr_t *arr; size_t n, cap; get_routes(p,&arr,&n,&cap);
        if (arr && n>0){
            op_illegal_uri(&arr[n-1]);
        }
    }
}

/* ---------------- 批量变异入口 ---------------- */
void mutate_route_headers(sip_packet_t *pkts, size_t n, unsigned int seed){
    unsigned int st = seed ? seed : 0xC001D00Du;

    for (size_t i=0; i<n; ++i){
        sip_packet_t *p = &pkts[i];
        sip_route_hdr_t *arr = NULL; 
        size_t cnt = 0, cap = 0;

        get_routes(p, &arr, &cnt, &cap);

        /* 统一做健壮性校验：空指针或容量为 0，则直接清零并跳过 */
        if (!arr || cap == 0){
            set_route_count(p, 0);
            continue;
        }
        /* 钳制坏掉的计数，避免后续越界 */
        if (cnt > cap){
            cnt = cap;
            set_route_count(p, cap);
        }

        /* 20% 删除全部 Route（可选头） */
        if (rnd(&st,100) < 20u){ 
            set_route_count(p,0); 
            continue; 
        }

        /* 若不存在则先建一个基线（仅在有容量时） */
        if (cnt == 0 && cap > 0){
            push_route(p, "sip:proxy.example.com", ";lr", 1);
            get_routes(p, &arr, &cnt, &cap);
            if (!arr || cap == 0){
                set_route_count(p, 0);
                continue;
            }
            if (cnt > cap){
                cnt = cap;
                set_route_count(p, cap);
            }
        }

        /* 20% 改成多跳 Route set */
        if (rnd(&st,100) < 20u){ 
            op_route_set(p, &st); 
            /* 这里不继续使用旧的 arr/cnt，直接进入下一包 */
            continue; 
        }

        /* 否则对现有每条做一次随机算子（挑选 ≥14 种之一） */
        for (size_t k=0; k<cnt; ++k){
            
            sip_route_hdr_t *h = &arr[k];
            if (!h) continue; /* 额外防护 */
            switch (rnd(&st, 16)){
              case 0:  op_valid_basic1(h);   break;
              case 1:  op_no_lr(h);          break;
              case 2:  op_ipv6(h);           break;
              case 3:  op_maddr_ttl(h);      break;
              case 4:  op_transport(h);      break;
              case 5:  op_params_dup(h);     break;
              case 6:  op_illegal_uri(h);    break;
              case 7:  op_tel_uri(h);        break;
              case 8:  op_no_angles(h);      break;
              case 9:  op_unbalanced(h);     break;
              case 10: op_space_in_uri(h);   break;
              case 11: op_weird_chars1(h);   break;
              case 12: op_crlf_inj1(h);      break;
              case 13: op_empty_params1(h);  break;
              case 14: op_fill_uri(h);       break;
              default: op_long_params(h);    break;
            }
        }

        /* 25% 再追加一次 repeat（复制第一条，模拟重复出现） */
        if (rnd(&st,4)==0){
            sip_route_hdr_t *a = NULL; 
            size_t c = 0, C = 0; 
            get_routes(p, &a, &c, &C);

            if (!a || C == 0){
                /* 没有可用容量或数组无效，跳过 */
                continue;
            }
            if (c > C){
                /* 再次钳制，防护其他分支可能写坏的 count */
                c = C;
                set_route_count(p, C);
            }
            if (c > 0 && c < C){
                push_route(p, a[0].uri, a[0].params, a[0].lt ? 1 : 0);
            }
        }

    }
}



static void set_absent(sip_require_hdr_t *h){
    if (h) h->name[0] = '\0'; /* 缺省标志 */
}
static size_t sappend_csv(char *dst, size_t cap, const char *token){
    size_t used = strnlen(dst, cap);
    if (!token || !token[0]) return used;
    if (used && used < cap-1) { dst[used++] = ','; dst[used] = '\0'; }
    size_t left = (cap>used)?(cap-used):0;
    if (left == 0) return used;
    size_t n = strnlen(token, left-1);
    memcpy(dst+used, token, n);
    dst[used+n] = '\0';
    return used + n;
}

/* ---------- 访问不同请求的 Require 指针 ---------- */
static sip_require_hdr_t* get_require(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.require;
      case SIP_PKT_ACK:      return &p->pkt.ack.require;
      case SIP_PKT_BYE:      return &p->pkt.bye.require;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.require;
      case SIP_PKT_REGISTER: return &p->pkt.register_.require;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.require;
      default: return NULL;
    }
}

/* ---------- add / delete / repeat ---------- */
/* add_<msg>_require：若不存在则新增，默认选择一组常用标签 */
static void add_require_with(sip_packet_t *p, const char *tags){
    sip_require_hdr_t *h = get_require(p);
    if (!h) return;
    set_present(h, tags && tags[0] ? tags : "100rel,timer");
}
void add_invite_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_INVITE)   add_require_with(p, "100rel,timer"); }
void add_ack_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_ACK)      add_require_with(p, "100rel"); }
void add_bye_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_BYE)      add_require_with(p, "timer"); }
void add_cancel_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_CANCEL)   add_require_with(p, "from-change"); }
void add_register_require (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_REGISTER) add_require_with(p, "sec-agree"); }
void add_options_require  (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_OPTIONS)  add_require_with(p, "100rel,timer,replaces"); }

/* delete_<msg>_require：删除该头 */
void delete_invite_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_INVITE)   set_absent(get_require(p)); }
void delete_ack_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_ACK)      set_absent(get_require(p)); }
void delete_bye_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_BYE)      set_absent(get_require(p)); }
void delete_cancel_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_CANCEL)   set_absent(get_require(p)); }
void delete_register_require (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_REGISTER) set_absent(get_require(p)); }
void delete_options_require  (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_OPTIONS)  set_absent(get_require(p)); }

/* repeat_<msg>_require：在同一行重复标签，模拟“多次出现”效果 */
static void repeat_require_inplace(sip_packet_t *p){
    sip_require_hdr_t *h = get_require(p);
    if (!h || !h->name[0]) return;
    /* 简单策略：把第一段 token 再附加一次（或把整串重复一次） */
    char tmp[SIP_TEXT_LEN]; scpy(tmp, sizeof tmp, h->option_tags);
    const char *comma = strchr(tmp, ',');
    char first[64]; first[0]='\0';
    if (comma){
        size_t n = MIN((size_t)(comma - tmp), sizeof(first)-1);
        memcpy(first, tmp, n); first[n]='\0';
    }else{
        scpy(first, sizeof first, tmp);
    }
    /* 以逗号再追加一次 first （或整个串） */
    if (first[0]) sappend_csv(h->option_tags, sizeof h->option_tags, first);
}
void repeat_invite_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_INVITE)   repeat_require_inplace(p); }
void repeat_ack_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_ACK)      repeat_require_inplace(p); }
void repeat_bye_require      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_BYE)      repeat_require_inplace(p); }
void repeat_cancel_require   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_CANCEL)   repeat_require_inplace(p); }
void repeat_register_require (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_REGISTER) repeat_require_inplace(p); }
void repeat_options_require  (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_OPTIONS)  repeat_require_inplace(p); }


/* ---------- 变异算子（≥ 14 种，合法+非法） ---------- */
static const char *k_known[] = {
    "100rel","timer","replaces","from-change","precondition","sec-agree","answer-mode","nosdp","tdialog"
};
static void op_valid_single(sip_require_hdr_t *h){
    set_present(h, "100rel");
}
static void op_valid_multi(sip_require_hdr_t *h){
    set_present(h, "100rel,timer,replaces");
}
static void op_unknown_token(sip_require_hdr_t *h){
    set_present(h, "fooext");
}
static void op_mixed_known_unknown(sip_require_hdr_t *h){
    set_present(h, "timer,fooext,100rel,bar");
}
static void op_uppercase(sip_require_hdr_t *h){
    set_present(h, "100REL,TIMER,REPLACES");
}
static void op_whitespace_variants1(sip_require_hdr_t *h){
    set_present(h, " 100rel ,  timer ,\tprecondition ");
}
static void op_empty_tokens(sip_require_hdr_t *h){
    set_present(h, "100rel,,timer,,,replaces,");
}
static void op_semicolon_instead_of_comma(sip_require_hdr_t *h){ /* 非法分隔符 */
    set_present(h, "100rel;timer;replaces");
}
static void op_param_like_garbage(sip_require_hdr_t *h){ /* 非法形态 */
    set_present(h, "100rel;q=0.9,timer;level=1");
}
static void op_illegal_chars(sip_require_hdr_t *h){ /* 非法字符 */
    set_present(h, "ti mer,\"100rel\",repl|aces");
}
static void op_crlf_injection(sip_require_hdr_t *h){ /* 头注入 */
    set_present(h, "100rel\r\nVia: SIP/2.0/UDP evil");
}
static void op_duplicate_many(sip_require_hdr_t *h){
    set_present(h, "100rel,100rel,100rel,timer,timer");
}
static void op_long_bomb(sip_require_hdr_t *h){
    char big[SIP_TEXT_LEN]; big[0]='\0';
    size_t left = sizeof(big), used = 0;
    for (int i=0;i<1000;i++){
        char tok[16]; sformat(tok, sizeof tok, "t%d", i);
        used = sappend_csv(big, sizeof(big), tok);
        if (sizeof(big)-used < 4) break;
    }
    set_present(h, big);
}
static void op_shuffle_and_trim(sip_require_hdr_t *h, unsigned *st){
    /* 从已知集中随机抽样 1..5 个，打乱并带空格 */
    char buf[SIP_TEXT_LEN]; buf[0]='\0';
    int cnt = 1 + (int)rnd(st, 5);
    for (int i=0;i<cnt;i++){
        const char *tok = k_known[rnd(st, (unsigned)(sizeof(k_known)/sizeof(k_known[0])))];
        char tmp[64]; sformat(tmp, sizeof tmp, " %s ", tok);
        sappend_csv(buf, sizeof buf, tmp);
    }
    set_present(h, buf);
}
static void op_remove_some(sip_require_hdr_t *h){ /* 合法：减少为子集 */
    set_present(h, "timer");
}


/* ---------- 批量变异入口 ---------- */
void mutate_require_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0x5A17B007u;

    for (size_t i=0;i<n;i++){
        sip_packet_t *p = &pkts[i];
        sip_require_hdr_t *h = get_require(p);
        /* 30% 直接删除（可选头） */
        if (rnd(&st,100) < 30u){ if(h) set_absent(h); continue; }

        /* 若不存在则 50% 新增一个“合理”的 */
        if (!h || !h->name[0]){
            if (rnd(&st,100) < 50u){
                add_require_with(p, "100rel,timer");
                h = get_require(p);
            } else {
                continue;
            }
        }

        /* 应用 1~2 个算子 */
        int ops = 1 + (int)rnd(&st, 2);
        for (int k=0; k<ops; ++k){
            switch (rnd(&st, 16)){
              case 0:  op_valid_single(h); break;
              case 1:  op_valid_multi(h); break;
              case 2:  op_unknown_token(h); break;
              case 3:  op_mixed_known_unknown(h); break;
              case 4:  op_uppercase(h); break;
              case 5:  op_whitespace_variants1(h); break;
              case 6:  op_empty_tokens(h); break;
              case 7:  op_semicolon_instead_of_comma(h); break;
              case 8:  op_param_like_garbage(h); break;
              case 9:  op_illegal_chars(h); break;
              case 10: op_crlf_injection(h); break;
              case 11: op_duplicate_many(h); break;
              case 12: op_long_bomb(h); break;
              case 13: op_remove_some(h); break;
              case 14: op_empty(h); break;
              default: op_shuffle_and_trim(h, &st); break;
            }
        }

        /* 25% 触发 repeat_*（在同一行重复 token，模拟多次出现） */
        if (rnd(&st,4)==0) repeat_require_inplace(p);
    }
}



static size_t sappend(char *dst, size_t cap, const char *suffix){
    size_t used = strnlen(dst, cap);
    if (!suffix) return used;
    size_t left = (cap>used)?(cap-used):0;
    if (!left) return used;
    size_t n = strnlen(suffix, left-1);
    memcpy(dst+used, suffix, n);
    dst[used+n] = '\0';
    return used + n;
}

/* ---------- 访问不同请求的 Response-Key 指针 ---------- */
static sip_response_key_hdr_t* get_rkey(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
      case SIP_PKT_INVITE:   return &p->pkt.invite.response_key;
      case SIP_PKT_BYE:      return &p->pkt.bye.response_key;
      case SIP_PKT_CANCEL:   return &p->pkt.cancel.response_key;
      case SIP_PKT_REGISTER: return &p->pkt.register_.response_key;
      case SIP_PKT_OPTIONS:  return &p->pkt.options.response_key;
      default: return NULL; /* ACK 无此头 */
    }
}

/* ---------- add / delete / repeat ---------- */
/* 选取几种“看起来像”的 scheme：pgp/inline、http、integrity（历史用法） */
static void add_rkey_with(sip_packet_t *p, const char *scheme, const char *params){
    sip_response_key_hdr_t *h = get_rkey(p);
    if (!h) return;
    set_present1(h, scheme?scheme:"pgp", params?params:"keyid=abc123;alg=md5");
}
void add_invite_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_INVITE)   add_rkey_with(p,"pgp","keyid=abc123"); }
void add_bye_response_key      (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_BYE)      add_rkey_with(p,"pgp/inline","fingerprint=deadbeef"); }
void add_cancel_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_CANCEL)   add_rkey_with(p,"integrity","alg=sha-256"); }
void add_register_response_key (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_REGISTER) add_rkey_with(p,"http","uri=\"http://k.example/respkey\""); }
void add_options_response_key  (sip_packet_t *p, size_t n, unsigned int seed){ if(p && p->cmd_type==SIP_PKT_OPTIONS)  add_rkey_with(p,"pgp","q=0.5;level=1"); }

/* 删除该头 */
void delete_invite_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p) set_absent(get_rkey(p)); }
void delete_bye_response_key      (sip_packet_t *p, size_t n, unsigned int seed){ if(p) set_absent(get_rkey(p)); }
void delete_cancel_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p) set_absent(get_rkey(p)); }
void delete_register_response_key (sip_packet_t *p, size_t n, unsigned int seed){ if(p) set_absent(get_rkey(p)); }
void delete_options_response_key  (sip_packet_t *p, size_t n, unsigned int seed){ if(p) set_absent(get_rkey(p)); }

/* repeat：在同一行 kvpairs 后追加一段，模拟“多个头”合并 */
static void repeat_rkey_inplace(sip_packet_t *p){
    sip_response_key_hdr_t *h = get_rkey(p);
    if (!h || !h->name[0]) return;
    if (!h->kvpairs[0]) { /* 无参数则造一点再追加 */
        h->sp = ' ';
        scpy(h->kvpairs, sizeof h->kvpairs, "dup=1");
        return;
    }
    sappend(h->kvpairs, sizeof h->kvpairs, ",dup=1");
}
void repeat_invite_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p) repeat_rkey_inplace(p); }
void repeat_bye_response_key      (sip_packet_t *p, size_t n, unsigned int seed){ if(p) repeat_rkey_inplace(p); }
void repeat_cancel_response_key   (sip_packet_t *p, size_t n, unsigned int seed){ if(p) repeat_rkey_inplace(p); }
void repeat_register_response_key (sip_packet_t *p, size_t n, unsigned int seed){ if(p) repeat_rkey_inplace(p); }
void repeat_options_response_key  (sip_packet_t *p, size_t n, unsigned int seed){ if(p) repeat_rkey_inplace(p); }


/* ---------- 变异算子（≥18种） ---------- */
static void op_valid_min(sip_response_key_hdr_t *h){ set_present1(h,"pgp",NULL); }
static void op_valid_with_params(sip_response_key_hdr_t *h){ set_present1(h,"pgp","keyid=deadbeef;alg=md5"); }
static void op_valid_http_uri(sip_response_key_hdr_t *h){ set_present1(h,"http","uri=\"https://k.example/rk\";q=0.8"); }
static void op_unknown_scheme(sip_response_key_hdr_t *h){ set_present1(h,"fooext","x=1;y=2"); }
static void op_uppercase_scheme(sip_response_key_hdr_t *h){ set_present1(h,"PGP","KEYID=DEADBEEF"); }
static void op_illegal_space_in_scheme(sip_response_key_hdr_t *h){ set_present1(h,"pg p","key=val"); }             /* 非法 */
static void op_quoted_scheme(sip_response_key_hdr_t *h){ set_present1(h,"\"pgp\"","key=val"); }                    /* 非法 */
static void op_missing_space_before_params(sip_response_key_hdr_t *h){ /* sp 缺失但有参数 */
    set_present1(h,"pgp","keyid=1");
    h->sp = '\0';
}
static void op_params_semicolons(sip_response_key_hdr_t *h){ set_present1(h,"pgp","a=1;b=2;c=3"); }
static void op_params_commas(sip_response_key_hdr_t *h){ set_present1(h,"pgp","a=1,b=2,c=3"); }
static void op_params_empty_tokens(sip_response_key_hdr_t *h){ set_present1(h,"pgp","a=1,,b=2,,,c="); }           /* 非法 */
static void op_params_missing_eq(sip_response_key_hdr_t *h){ set_present1(h,"pgp","a,b=2,=3"); }                  /* 非法 */
static void op_params_quotes_escapes(sip_response_key_hdr_t *h){ set_present1(h,"pgp","k=\"va\\\"l\";p=\"\""); }
static void op_params_illegal_chars(sip_response_key_hdr_t *h){ set_present1(h,"pgp","k=va l, x=\"repl|ace\""); }  /* 非法 */
static void op_params_crlf_inject(sip_response_key_hdr_t *h){ set_present1(h,"pgp","k=1\r\nVia: SIP/2.0/UDP X"); } /* 注入 */
static void op_params_long_bomb(sip_response_key_hdr_t *h){
    char big[SIP_PARAMS_LEN]; big[0]='\0';
    for (int i=0;i<400;i++){
        char t[16]; sformat(t,sizeof t,"p%03d=%03d",i,i);
        if (strnlen(big,sizeof big)+strnlen(t,sizeof t)+2 >= sizeof(big)) break;
        if (i) sappend(big,sizeof big,";");
        sappend(big,sizeof big,t);
    }
    set_present1(h,"pgp",big);
}
static void op_nonascii(sip_response_key_hdr_t *h){ /* 非 ASCII 字节 */
    char buf[32] = "x=\xFF\xC3\xA9"; /* 0xFF, UTF-8 é 起头等 */
    set_present1(h,"pgp",buf);
}
static void op_header_fold(sip_response_key_hdr_t *h){ /* 旧式折行 */
    set_present1(h,"pgp","k=1\r\n\tcont=2");
}
static void op_empty_params_but_sp(sip_response_key_hdr_t *h){ set_present1(h,"pgp",""); h->sp = ' '; }            /* 非法 */
static void op_empty_all(sip_response_key_hdr_t *h){ set_present1(h,"",""); }                                      /* 非法 */

/* 随机化：在已知集合里挑 scheme / 造参数 */
static const char *k_schemes[] = { "pgp","pgp/inline","http","integrity","fooext" };
static void op_shuffle_random(sip_response_key_hdr_t *h, unsigned *st){
    const char *sch = k_schemes[rnd(st,(unsigned)(sizeof k_schemes/sizeof k_schemes[0]))];
    char pbuf[128]; pbuf[0]='\0';
    int n = 1 + (int)rnd(st,4);
    for (int i=0;i<n;i++){
        char kv[32];
        switch (rnd(st,4)){
          case 0: sformat(kv,sizeof kv,"k%d=v%d",i,i); break;
          case 1: sformat(kv,sizeof kv,"f%d=%d",i,i*i); break;
          case 2: sformat(kv,sizeof kv,"x%d",i); break;           /* 无 '=' */
          default: sformat(kv,sizeof kv,"q%d=\"v%d\"",i,i); break;
        }
        if (i) sappend(pbuf,sizeof pbuf, (rnd(st,2) ? ";" : ","));
        sappend(pbuf,sizeof pbuf, kv);
    }
    set_present1(h, sch, pbuf);
}

/* ---------- 主入口：批量变异 ---------- */
void mutate_response_key_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xA55A1234u;

    for (size_t i=0;i<n;i++){
        sip_packet_t *p = &pkts[i];
        sip_response_key_hdr_t *h = get_rkey(p);
        if (!h) continue;

        /* 25% 直接删除（可选） */
        if (rnd(&st,100) < 25u){ set_absent(h); continue; }

        /* 若不存在则 60% 新增一个“看起来合理”的 */
        if (!h->name[0]){
            if (rnd(&st,100) < 60u){
                add_rkey_with(p,"pgp","keyid=abc123;alg=md5");
                h = get_rkey(p);
            } else {
                continue;
            }
        }

        /* 应用 1~3 个算子 */
        int ops = 1 + (int)rnd(&st, 3);
        for (int k=0;k<ops;k++){
            switch (rnd(&st,22)){
              case 0:  op_valid_min(h); break;
              case 1:  op_valid_with_params(h); break;
              case 2:  op_valid_http_uri(h); break;
              case 3:  op_unknown_scheme(h); break;
              case 4:  op_uppercase_scheme(h); break;
              case 5:  op_illegal_space_in_scheme(h); break;
              case 6:  op_quoted_scheme(h); break;
              case 7:  op_missing_space_before_params(h); break;
              case 8:  op_params_semicolons(h); break;
              case 9:  op_params_commas(h); break;
              case 10: op_params_empty_tokens(h); break;
              case 11: op_params_missing_eq(h); break;
              case 12: op_params_quotes_escapes(h); break;
              case 13: op_params_illegal_chars(h); break;
              case 14: op_params_crlf_inject(h); break;
              case 15: op_params_long_bomb(h); break;
              case 16: op_nonascii(h); break;
              case 17: op_header_fold(h); break;
              case 18: op_empty_params_but_sp(h); break;
              case 19: op_empty_all(h); break;
              default: op_shuffle_random(h, &st); break;
            }
        }

        /* 20% 触发 repeat_*（同一行尾部追加），模拟“多次出现” */
        if (rnd(&st,5)==0) repeat_rkey_inplace(p);
    }
}

static void subject_set_present(sip_subject_hdr_t *h, const char *text){
    scpy(h->name,        sizeof h->name,        "Subject");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->text,        sizeof h->text,        text ? text : "");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
}
static void subject_set_absent(sip_subject_hdr_t *h){
    if (h) h->name[0] = '\0';
}

/* ---- add / delete（仅 INVITE 有 Subject） ---- */
void add_invite_subject(sip_packet_t *p){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    subject_set_present(&p->pkt.invite.subject, "Project update");
}
void delete_invite_subject(sip_packet_t *p){
    if (!p || p->cmd_type != SIP_PKT_INVITE) return;
    subject_set_absent(&p->pkt.invite.subject);
}

static void op_simple(sip_subject_hdr_t *h){ subject_set_present(h, "Hello from SIP"); }            /* 正常值 */
static void op_long(sip_subject_hdr_t *h){                                                          /* 超长轰炸 */
    char buf[SIP_TEXT_LEN]; size_t n=0;
    while (n+1 < sizeof(buf)) buf[n++] = 'A';
    buf[n] = '\0';
    subject_set_present(h, buf);
}
static void op_unicode(sip_subject_hdr_t *h){ subject_set_present(h, "会议议程 – αβγ Привет 😀"); }  /* UTF-8 */
static void op_ws_edges(sip_subject_hdr_t *h){ subject_set_present(h, "   padded\ttext  "); }       /* 前后空白 */
static void op_punct(sip_subject_hdr_t *h){ subject_set_present(h, "foo,bar;baz|qux"); }            /* 标点组合 */
static void op_quotes(sip_subject_hdr_t *h){ subject_set_present(h, "\"Quoted \\ Subject\""); }     /* 引号与转义 */
static void op_ctrl(sip_subject_hdr_t *h){ subject_set_present(h, "X\x01\x02Y"); }                  /* 控制字节 */
static void op_crlf_inject2(sip_subject_hdr_t *h){ subject_set_present(h, "X\r\nVia: SIP/2.0/UDP x"); } /* 头注入 */
static void op_fold(sip_subject_hdr_t *h){ subject_set_present(h, "Line1\r\n\tLine2"); }            /* 折行延续 */
static void op_encoded_word(sip_subject_hdr_t *h){ subject_set_present(h, "=?utf-8?b?5pel5pys6Kqe?="); } /* “貌似”MIME 编码字 */
static void op_random(sip_subject_hdr_t *h, unsigned *st){                                          /* 随机串 */
    char buf[SIP_TEXT_LEN]; size_t len = 10 + rnd(st, (unsigned)(SIP_TEXT_LEN-11));
    for (size_t i=0;i<len && i+1<sizeof(buf);++i){
        static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_- /,.;:!@#";
        buf[i] = cs[rnd(st,(unsigned)(sizeof(cs)-1))];
    }
    buf[(len<sizeof(buf))?len:(sizeof(buf)-1)] = '\0';
    subject_set_present(h, buf);
}
static void op_very_long_word(sip_subject_hdr_t *h){                                                /* 单长词无空格 */
    char buf[SIP_TEXT_LEN]; size_t n=0;
    while(n+1<sizeof(buf)) buf[n++]='Z';
    buf[n]='\0'; subject_set_present(h, buf);
}
static void op_space_only(sip_subject_hdr_t *h){ subject_set_present(h, " \t \t   "); }             /* 纯空白 */
static void op_many_prefixes(sip_subject_hdr_t *h){ subject_set_present(h, "Re: Re: Fwd: RE: FW: topic"); }
static void op_compact_name_10pct(sip_subject_hdr_t *h, unsigned *st){                              /* 紧凑头名（非标准实现可能不识别） */
    if (rnd(st,10)==0){ scpy(h->name, sizeof h->name, "s"); }
}

/* ---- 主入口：批量变异（仅 INVITE） ---- */
void mutate_subject_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xC0FFEEu;

    for (size_t i=0;i<n;i++){
        if (pkts[i].cmd_type != SIP_PKT_INVITE) continue;
        sip_subject_hdr_t *h = &pkts[i].pkt.invite.subject;

        /* 25% 直接删除（可选头） */
        if (rnd(&st,100) < 25u){ subject_set_absent(h); continue; }

        /* 若不存在则 70% 新增一个正常值 */
        if (!h->name[0]){
            if (rnd(&st,100) < 70u){ subject_set_present(h, "Project update"); }
            else { continue; }
        }

        /* 应用 1~3 个算子 */
        int ops = 1 + (int)rnd(&st,3);
        for (int k=0;k<ops;k++){
            switch (rnd(&st,15)){
              case 0:  op_empty(h); break;
              case 1:  op_simple(h); break;
              case 2:  op_long(h); break;
              case 3:  op_unicode(h); break;
              case 4:  op_ws_edges(h); break;
              case 5:  op_punct(h); break;
              case 6:  op_quotes(h); break;
              case 7:  op_ctrl(h); break;
              case 8:  op_crlf_inject2(h); break;
              case 9:  op_fold(h); break;
              case 10: op_encoded_word(h); break;
              case 11: op_random(h, &st); break;
              case 12: op_very_long_word(h); break;
              case 13: op_space_only(h); break;
              default: op_many_prefixes(h); break;
            }
        }

        /* 10% 将头名改为紧凑形式 "s"（测试接收端兼容性） */
        op_compact_name_10pct(h, &st);

        /* 确保固定部件仍在 */
        if (!h->colon_space[0]) scpy(h->colon_space, sizeof h->colon_space, ": ");
        if (!h->crlf[0])        scpy(h->crlf,        sizeof h->crlf,        "\r\n");
    }
}



/* ---------- User-Agent 头的存在/缺省 ---------- */
static void ua_set_present(sip_user_agent_hdr_t *h, const char *product){
    scpy(h->name,        sizeof h->name,        "User-Agent");
    scpy(h->colon_space, sizeof h->colon_space, ": ");
    scpy(h->product,     sizeof h->product,     product ? product : "");
    scpy(h->crlf,        sizeof h->crlf,        "\r\n");
}
static void ua_set_absent(sip_user_agent_hdr_t *h){
    if (h) h->name[0] = '\0';
}

/* ---------- 访问不同报文内的 User-Agent 指针 ---------- */
static sip_user_agent_hdr_t* get_user_agent_hdr(sip_packet_t *p){
    if (!p) return NULL;
    switch (p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.user_agent;
        case SIP_PKT_ACK:      return &p->pkt.ack.user_agent;
        case SIP_PKT_BYE:      return &p->pkt.bye.user_agent;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.user_agent;
        case SIP_PKT_REGISTER: return &p->pkt.register_.user_agent;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.user_agent;
        default: return NULL;
    }
}

/* ---------- add / delete（分别提供 6 个，便于脚本化调用） ---------- */
void add_invite_user_agent  (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_INVITE)   return; ua_set_present(&p->pkt.invite.user_agent,   "Softphone/1.0 (Default)"); }
void delete_invite_user_agent(sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_INVITE)   return; ua_set_absent(&p->pkt.invite.user_agent); }

void add_ack_user_agent     (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_ACK)       return; ua_set_present(&p->pkt.ack.user_agent,      "Softphone/1.0 (ACK)"); }
void delete_ack_user_agent  (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_ACK)       return; ua_set_absent(&p->pkt.ack.user_agent); }

void add_bye_user_agent     (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_BYE)       return; ua_set_present(&p->pkt.bye.user_agent,      "Softphone/1.0 (BYE)"); }
void delete_bye_user_agent  (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_BYE)       return; ua_set_absent(&p->pkt.bye.user_agent); }

void add_cancel_user_agent  (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_CANCEL)    return; ua_set_present(&p->pkt.cancel.user_agent,   "Softphone/1.0 (CANCEL)"); }
void delete_cancel_user_agent(sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_CANCEL)   return; ua_set_absent(&p->pkt.cancel.user_agent); }

void add_register_user_agent(sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_REGISTER)  return; ua_set_present(&p->pkt.register_.user_agent,"Softphone/1.0 (REGISTER)"); }
void delete_register_user_agent(sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_REGISTER)return; ua_set_absent(&p->pkt.register_.user_agent); }

void add_options_user_agent (sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_OPTIONS)   return; ua_set_present(&p->pkt.options.user_agent,  "Softphone/1.0 (OPTIONS)"); }
void delete_options_user_agent(sip_packet_t *p, size_t n, unsigned int seed){ if (!p || p->cmd_type!=SIP_PKT_OPTIONS) return; ua_set_absent(&p->pkt.options.user_agent); }

static void op_minimal_token(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA"); }                                /* 最小 token */
static void op_common(sip_user_agent_hdr_t *h){ ua_set_present(h, "Softphone/1.2"); }                             /* 常见形态 */
static void op_two_products(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0 Lib/2.3"); }                      /* 多 product */
static void op_long1(sip_user_agent_hdr_t *h){                                                                      /* 纯超长 */
    char buf[SIP_TEXT_LEN]; size_t n=0; while(n+1<sizeof(buf)) buf[n++]='A'; buf[n]='\0'; ua_set_present(h, buf);
}
static void op_unicode1(sip_user_agent_hdr_t *h){ ua_set_present(h, "客户端/1.0 (测试) – αβγ 😀"); }                /* Unicode */
static void op_comment(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0 (Test Build 2025)"); }                 /* 注释 */
static void op_nested_comment(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0 (a(b(c)))"); }                  /* 嵌套注释 */
static void op_unbalanced_comment(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0 (oops"); }                  /* 不闭合 */
static void op_params_like(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0;os=win;arch=x86_64"); }            /* 类参数 */
static void op_random1(sip_user_agent_hdr_t *h, unsigned *st){                                                     /* 随机串 */
    char buf[SIP_TEXT_LEN]; size_t len = 8 + rnd(st, (unsigned)(SIP_TEXT_LEN-9));
    for (size_t i=0;i<len && i+1<sizeof(buf);++i){
        static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-. ()/;:\t";
        buf[i] = cs[rnd(st,(unsigned)(sizeof(cs)-1))];
    }
    buf[(len<sizeof(buf))?len:(sizeof(buf)-1)] = '\0';
    ua_set_present(h, buf);
}
static void op_ctrl1(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA\x01/1\x7f.0"); }                               /* 控制字节 */
static void op_crlf_inject3(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0\r\nVia: SIP/2.0/UDP evil"); }      /* 头注入 */
static void op_tabs_spaces(sip_user_agent_hdr_t *h){ ua_set_present(h, "  UA\t/\t1.0   ( spaced ) "); }           /* 空白花样 */
static void op_quotes1(sip_user_agent_hdr_t *h){ ua_set_present(h, "\"UA\"/\"1.0\" (quoted)"); }                   /* 引号混用 */
static void op_many_slashes(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA////////1.0"); }                        /* 多 '/' */
static void op_huge_version(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/999999999999999999999"); }            /* 巨版号 */
static void op_scheme_like(sip_user_agent_hdr_t *h){ ua_set_present(h, "sip:UA/1.0 (nonsense)"); }                /* 协议样式 */
static void op_fold1(sip_user_agent_hdr_t *h){ ua_set_present(h, "UA/1.0\r\n\t(continued)"); }                      /* obs-fold */

/* 10% 概率在头名后拼奇怪的大小写/空格（部分实现不健壮） */
static void op_weird_name_10pct(sip_user_agent_hdr_t *h, unsigned *st){
    if (rnd(st,10)==0){
        scpy(h->name, sizeof h->name, "User-agent"); /* 非标准大小写 */
        if (rnd(st,2)==0) scpy(h->colon_space, sizeof h->colon_space, ":"); /* 去掉空格 */
    }
}

/* ---------- 批量随机变异（原位） ---------- */
void mutate_user_agent_headers(sip_packet_t *pkts, size_t n, unsigned seed){
    unsigned st = seed ? seed : 0xBADC0DEu;

    for (size_t i=0;i<n;i++){
        sip_user_agent_hdr_t *h = get_user_agent_hdr(&pkts[i]);
        if (!h) continue;

        /* 20% 直接删除（可选头） */
        if (rnd(&st,100) < 20u){ ua_set_absent(h); continue; }

        /* 若不存在，则 70% 添加一个普通值 */
        if (!h->name[0]){
            if (rnd(&st,100) < 70u) ua_set_present(h, "Softphone/1.0");
            else continue;
        }

        /* 应用 1~3 个随机算子叠加 */
        int ops = 1 + (int)rnd(&st,3);
        for (int k=0;k<ops;k++){
            switch (rnd(&st,18)){ /* 0..17 共 18 种 */
              case 0:  op_empty(h); break;
              case 1:  op_minimal_token(h); break;
              case 2:  op_common(h); break;
              case 3:  op_two_products(h); break;
              case 4:  op_long1(h); break;
              case 5:  op_unicode1(h); break;
              case 6:  op_comment(h); break;
              case 7:  op_nested_comment(h); break;
              case 8:  op_unbalanced_comment(h); break;
              case 9:  op_params_like(h); break;
              case 10: op_random1(h, &st); break;
              case 11: op_ctrl1(h); break;
              case 12: op_crlf_inject3(h); break;
              case 13: op_tabs_spaces(h); break;
              case 14: op_quotes1(h); break;
              case 15: op_many_slashes(h); break;
              case 16: op_huge_version(h); break;
              default: op_fold1(h); break;
            }
        }

        /* 10% 概率“异常”头名/分隔符 */
        op_weird_name_10pct(h, &st);

        /* 保底：分隔和 CRLF 存在 */
        if (!h->colon_space[0]) scpy(h->colon_space, sizeof h->colon_space, ": ");
        if (!h->crlf[0])        scpy(h->crlf,        sizeof h->crlf,        "\r\n");
    }
}


/* 轻量随机：xorshift32，可传入种子以得到确定/非确定行为 */
static uint32_t xs32(uint32_t *s) {
    uint32_t x = (*s ? *s : 0x9E3779B9u);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}
static uint32_t rnd_u32(uint32_t *s, uint32_t n) { /* [0,n) */
    return (n == 0) ? 0 : (xs32(s) % n);
}

/* 安全写入 request_uri */
static void set_uri(char dst[], size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    /* 使用 snprintf 防溢出，自动 NUL 终止 */
    (void)snprintf(dst, cap, "%s", src);
}

/* 生成一个很长的主机名（合法/非法皆可用于压力） */
static void gen_long_host(char *buf, size_t cap, uint32_t *seed) {
    /* 由多个 label 组成，尽量逼近 cap */
    size_t pos = 0;
    while (pos + 10 < cap - 1) {
        int label_len = 3 + (int)rnd_u32(seed, 10); /* 3..12 */
        for (int i = 0; i < label_len && pos < cap - 1; ++i) {
            char c = "abcdefghijklmnopqrstuvwxyz0123456789"[rnd_u32(seed, 36)];
            buf[pos++] = c;
        }
        if (pos < cap - 1) buf[pos++] = '.';
        if (pos > cap / 2 && rnd_u32(seed, 3) == 0) break;
    }
    if (pos == 0) { set_uri(buf, cap, "example.com"); return; }
    if (buf[pos-1] == '.') pos--; /* 去掉末尾 '.' */
    buf[pos] = '\0';
}

/* ——— 12 个变异算子（根据 op_id 选择） ——— */

static void op1_set_basic_sip(char *dst, size_t cap) {
    set_uri(dst, cap, "sip:alice@example.com");
}
static void op2_set_sips_tls(char *dst, size_t cap) {
    set_uri(dst, cap, "sips:bob@example.com;transport=tls");
}
static void op3_set_tel(char *dst, size_t cap) {
    set_uri(dst, cap, "tel:+14155550101");
}
static void op4_ipv6_with_port(char *dst, size_t cap) {
    set_uri(dst, cap, "sip:carol@[2001:db8::1]:5061;transport=tcp");
}
static void op5_add_params(char *dst, size_t cap) {
    set_uri(dst, cap, "sip:dave@example.com;user=phone;lr;ttl=1;maddr=239.255.255.1");
}
static void op6_add_headers(char *dst, size_t cap) {
    set_uri(dst, cap, "sip:eve@example.com?subject=Hello&Priority=urgent");
}
static void op7_percent_user(char *dst, size_t cap) {
    /* %61lice -> alice */
    set_uri(dst, cap, "sip:%61lice@example.com");
}
static void op8_no_scheme(char *dst, size_t cap) { /* 非法 */
    set_uri(dst, cap, "frank@example.com");
}
static void op9_star(char *dst, size_t cap) { /* 非法于 INVITE */
    set_uri(dst, cap, "*");
}
static void op10_overlong(char *dst, size_t cap, uint32_t *seed) { /* 非法：超长（上限保底） */
    /* 尽量填满，保持 NUL 终止 */
    if (!dst || cap == 0) return;
    /* 前缀 sip: 以兼顾“看似合理但超长 host” */
    size_t prefix = snprintf(dst, cap, "sip:");
    if (prefix >= cap) { dst[cap-1] = '\0'; return; }
    size_t remain = cap - 1 - prefix;
    for (size_t i = 0; i < remain; ++i) {
        dst[prefix + i] = (char)('A' + (int)rnd_u32(seed, 26));
    }
    dst[cap-1] = '\0';
}
static void op11_ws_injection(char *dst, size_t cap, uint32_t *seed) { /* 非法：空白/分隔注入 */
    const char *variants[] = {
        " sip:alice@example.com",       /* 前导空格 */
        "sip: alice@example.com",       /* scheme 后空格 */
        "sip:alice @example.com",       /* user 后空格 */
        "sip:alice@example.com ",       /* 末尾空格 */
        "sip:\talice@example.com",      /* 制表符 */
    };
    set_uri(dst, cap, variants[rnd_u32(seed, (uint32_t)(sizeof(variants)/sizeof(variants[0])) )]);
}
static void op12_bad_edge_cases(char *dst, size_t cap, uint32_t *seed) { /* 多个非法边界任选其一 */
    const char *variants[] = {
        "sip:",                                   /* 缺 host */
        "sip:alice@[2001:db8::1",                 /* IPv6 缺 ']' */
        "sip:%GZ@example.com",                    /* 坏的百分号编码 */
        "sips:alice@exa mple.com",                /* host 中空格 */
        "sip:alice@exa%2",                        /* 尾部坏 % */
        "sip:@example.com",                       /* 空用户 */
    };
    set_uri(dst, cap, variants[rnd_u32(seed, (uint32_t)(sizeof(variants)/sizeof(variants[0])) )]);
}

/* 额外：基于现有 host 构造长 host 的合法变体 */
static void opX_build_long_host(char *dst, size_t cap, uint32_t *seed) {
    char host[256];
    gen_long_host(host, sizeof(host), seed);
    char tmp[512];
    (void)snprintf(tmp, sizeof(tmp), "sip:mutant@%s;transport=%s",
                   host,
                   (rnd_u32(seed, 2) ? "udp" : "tcp"));
    set_uri(dst, cap, tmp);
}

/* 选择并应用一个算子 */
static void mutate_one_invite_uri(char *dst, size_t cap, uint32_t *seed) {
    uint32_t op = rnd_u32(seed, 13); /* 0..12 （我们给了 13 类操作） */
    switch (op) {
        case 0:  op1_set_basic_sip(dst, cap); break;
        case 1:  op2_set_sips_tls(dst, cap); break;
        case 2:  op3_set_tel(dst, cap); break;
        case 3:  op4_ipv6_with_port(dst, cap); break;
        case 4:  op5_add_params(dst, cap); break;
        case 5:  op6_add_headers(dst, cap); break;
        case 6:  op7_percent_user(dst, cap); break;
        case 7:  op8_no_scheme(dst, cap); break;
        case 8:  op9_star(dst, cap); break;
        case 9:  op10_overlong(dst, cap, seed); break;
        case 10: op11_ws_injection(dst, cap, seed); break;
        case 11: op12_bad_edge_cases(dst, cap, seed); break;
        default: opX_build_long_host(dst, cap, seed); break;
    }
}


void mutate_sip_request_uri(sip_packet_t *pkts, size_t n, uint32_t seed)
{
    if (!pkts) return;
    uint32_t s = (seed ? seed : 0xC0FFEEu);
    for (size_t i = 0; i < n; ++i) {
        if (pkts[i].cmd_type == SIP_PKT_INVITE){
            mutate_one_invite_uri(pkts[i].pkt.invite.request_uri, sizeof(pkts[i].pkt.invite.request_uri), &s);
        }
        else if( pkts[i].cmd_type == SIP_PKT_REGISTER ){
            mutate_one_invite_uri(pkts[i].pkt.register_.request_uri, sizeof(pkts[i].pkt.register_.request_uri), &s);
        }
        else if( pkts[i].cmd_type == SIP_PKT_OPTIONS ){
            mutate_one_invite_uri(pkts[i].pkt.options.request_uri, sizeof(pkts[i].pkt.options.request_uri), &s);
        }
        else if( pkts[i].cmd_type == SIP_PKT_ACK ){
            mutate_one_invite_uri(pkts[i].pkt.ack.request_uri, sizeof(pkts[i].pkt.ack.request_uri), &s);
        }
        else if( pkts[i].cmd_type == SIP_PKT_BYE ){
            mutate_one_invite_uri(pkts[i].pkt.bye.request_uri, sizeof(pkts[i].pkt.bye.request_uri), &s);
        }
        else if( pkts[i].cmd_type == SIP_PKT_CANCEL ){
            mutate_one_invite_uri(pkts[i].pkt.cancel.request_uri, sizeof(pkts[i].pkt.cancel.request_uri), &s);
        }
    }
}


#ifndef SIP_BODY_MAX
#define SIP_BODY_MAX 8192
#endif
#ifndef SIP_TOKEN_LEN
#define SIP_TOKEN_LEN 64
#endif
#ifndef SIP_TEXT_LEN
#define SIP_TEXT_LEN 256
#endif





static void set_str(char *dst, size_t cap, const char *src){
  if(!dst||!cap){return;}
  if(!src){ dst[0]='\0'; return; }
  snprintf(dst, cap, "%s", src);
}

/* 取指向各包的 body / CT / CL 指针 */
typedef struct {
  char *body;
  sip_content_type_hdr_t   *ct;
  sip_content_length_hdr_t *cl;
} body_bundle_t;

static body_bundle_t get_body_bundle(sip_packet_t *p){
  body_bundle_t b = {0};
  if(!p) return b;
  switch (p->cmd_type){
    case SIP_PKT_INVITE:
      b.body = p->pkt.invite.body;
      b.ct   = &p->pkt.invite.content_type;
      b.cl   = &p->pkt.invite.content_length; break;
    case SIP_PKT_ACK:
      b.body = p->pkt.ack.body;
      b.ct   = &p->pkt.ack.content_type;
      b.cl   = &p->pkt.ack.content_length; break;
    case SIP_PKT_REGISTER:
      b.body = p->pkt.register_.body;
      b.ct   = &p->pkt.register_.content_type;
      b.cl   = &p->pkt.register_.content_length; break;
    case SIP_PKT_OPTIONS:
      b.body = p->pkt.options.body;
      b.ct   = &p->pkt.options.content_type;
      b.cl   = &p->pkt.options.content_length; break;
    default: break;
  }
  return b;
}

/* 规范化/构造 Content-Type 与 Content-Length */
static void ensure_ct(sip_content_type_hdr_t *ct,
                      const char *type_tok, const char *sub_type, const char *params){
  if(!ct) return;
  set_str(ct->name, sizeof(ct->name), "Content-Type");
  set_str(ct->colon_space, sizeof(ct->colon_space), ": ");
  set_str(ct->type_tok, sizeof(ct->type_tok), type_tok?type_tok:"application");
  ct->slash = '/';
  set_str(ct->sub_type, sizeof(ct->sub_type), sub_type?sub_type:"octet-stream");
  set_str(ct->params, sizeof(ct->params), params?params:"");
  set_str(ct->crlf, sizeof(ct->crlf), "\r\n");
}
static void clear_ct(sip_content_type_hdr_t *ct){
  if(!ct) return;
  ct->name[0] = '\0'; /* 题设：name[0]==0 表示该可选头不存在 */
}

static void set_cl_len(sip_content_length_hdr_t *cl, size_t n){
  if(!cl) return;
  set_str(cl->name, sizeof(cl->name), "Content-Length");
  set_str(cl->colon_space, sizeof(cl->colon_space), ": ");
  char buf[32]; snprintf(buf, sizeof(buf), "%zu", n);
  set_str(cl->length, sizeof(cl->length), buf);
  set_str(cl->crlf, sizeof(cl->crlf), "\r\n");
}
static void clear_cl(sip_content_length_hdr_t *cl){
  if(!cl) return;
  cl->name[0] = '\0';
}

/* 填充 body 并（通常）同步 Content-Length；若 want_mismatch>=0 刻意制造不一致 */
static void write_body_and_maybe_len(sip_packet_t *p,
                                     const char *payload,
                                     const char *ct_type, const char *ct_sub,
                                     const char *ct_params,
                                     int want_mismatch /* -1: 同步；>=0: 指定CL文本 */){
  body_bundle_t b = get_body_bundle(p);
  if(!b.body) return;
  size_t L = payload? strlen(payload):0;
  if (payload) set_str(b.body, SIP_BODY_MAX, payload);
  else         b.body[0]='\0';
  if (ct_type || ct_sub || ct_params) ensure_ct(b.ct, ct_type, ct_sub, ct_params);
  /* Content-Length：默认与 strlen 同步（注意我们不在此处支持嵌入 NUL 的纯二进制，避免 strlen 问题） */
  if (want_mismatch < 0) {
    set_cl_len(b.cl, L);
  } else {
    ensure_ct(b.ct, ct_type?ct_type:"application", ct_sub?ct_sub:"octet-stream", ct_params?ct_params:"");
    set_str(b.cl->name, sizeof(b.cl->name), "Content-Length");
    set_str(b.cl->colon_space, sizeof(b.cl->colon_space), ": ");
    char buf[32]; snprintf(buf, sizeof(buf), "%d", want_mismatch);
    set_str(b.cl->length, sizeof(b.cl->length), buf);
    set_str(b.cl->crlf, sizeof(b.cl->crlf), "\r\n");
  }
}

/* 生成一些常见 payload 模板 */
static void gen_min_sdp(char *out, size_t cap, const char *ip){
  snprintf(out, cap,
    "v=0\r\n"
    "o=- 0 0 IN IP4 %s\r\n"
    "s=-\r\n"
    "c=IN IP4 %s\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8 96\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n", ip, ip);
}
static void gen_big_sdp(char *out, size_t cap){
  size_t n=0; n += snprintf(out+n, cap-n, "v=0\r\no=- 0 0 IN IP4 203.0.113.1\r\ns=x\r\nc=IN IP4 203.0.113.1\r\nt=0 0\r\n");
  for(int i=0;i<150 && n+64<cap;i++){
    n += snprintf(out+n, cap-n, "m=audio %d RTP/AVP 0 8 96\r\n", 20000+i);
    n += snprintf(out+n, cap-n, "a=rtpmap:%d opus/48000/2\r\n", 96);
    n += snprintf(out+n, cap-n, "a=fmtp:%d maxplaybackrate=%d\r\n", 96, 48000);
  }
}
static void gen_pidf(char *out, size_t cap){
  snprintf(out, cap,
    "<?xml version=\"1.0\"?>\n"
    "<presence entity=\"sip:alice@example.com\">\n"
    " <tuple id=\"t1\"><status><basic>open</basic></status></tuple>\n"
    "</presence>\n");
}
static void gen_sipfrag(char *out, size_t cap){
  snprintf(out, cap,
    "SIP/2.0 180 Ringing\r\n"
    "Via: SIP/2.0/UDP x;branch=z9hG4bK\r\n"
    "To: <sip:bob@example.com>;tag=abc\r\n\r\n");
}
static void gen_json(char *out, size_t cap){
  snprintf(out, cap, "{\"type\":\"offer\",\"sdp\":\"v=0\\r\\n...\"}\n");
}

/* ---------------- 可选字段的 add_/delete_ ---------------- */
/* add_*_body: 若 body 为空，则填入最小 SDP；若已有，则保持不变（或覆盖也行，按需改） */
void add_invite_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_INVITE) return;
  body_bundle_t b = get_body_bundle(p);
  if(!b.body) return;
  if (b.body[0] == '\0'){
    char buf[1024]; gen_min_sdp(buf, sizeof(buf), "0.0.0.0");
    write_body_and_maybe_len(p, buf, "application","sdp",";charset=utf-8", -1);
  }
}
void delete_invite_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_INVITE) return;
  body_bundle_t b = get_body_bundle(p);
  if(!b.body) return;
  b.body[0] = '\0';
  /* 清空或置 0；两种都有价值，这里设为 0 并清掉 Content-Type */
  set_cl_len(b.cl, 0);
  clear_ct(b.ct);
}

void add_ack_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_ACK) return;
  body_bundle_t b = get_body_bundle(p);
  if (b.body[0]=='\0'){
    set_str(b.body, SIP_BODY_MAX, ""); /* ACK 通常无 body；这里演示可加一段纯文本 */
    ensure_ct(b.ct, "text","plain", ";charset=utf-8");
    set_cl_len(b.cl, strlen(b.body));
  }
}
void delete_ack_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_ACK) return;
  body_bundle_t b = get_body_bundle(p);
  b.body[0]='\0'; set_cl_len(b.cl,0); clear_ct(b.ct);
}

void add_register_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_REGISTER) return;
  body_bundle_t b = get_body_bundle(p);
  if (b.body[0]=='\0'){
    set_str(b.body, SIP_BODY_MAX, "action=register&contact=sip:alice@example.com");
    ensure_ct(b.ct, "application","x-www-form-urlencoded", "");
    set_cl_len(b.cl, strlen(b.body));
  }
}
void delete_register_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_REGISTER) return;
  body_bundle_t b = get_body_bundle(p);
  b.body[0]='\0'; set_cl_len(b.cl,0); clear_ct(b.ct);
}

void add_options_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_OPTIONS) return;
  body_bundle_t b = get_body_bundle(p);
  if (b.body[0]=='\0'){
    set_str(b.body, SIP_BODY_MAX, "ping");
    ensure_ct(b.ct, "text","plain",";charset=utf-8");
    set_cl_len(b.cl, strlen(b.body));
  }
}
void delete_options_body(sip_packet_t *p, size_t n, unsigned int seed){
  if(!p || p->cmd_type!=SIP_PKT_OPTIONS) return;
  body_bundle_t b = get_body_bundle(p);
  b.body[0]='\0'; set_cl_len(b.cl,0); clear_ct(b.ct);
}



static void mutate_one_body(sip_packet_t *p, uint32_t *seed){
  if(!p) return;
  body_bundle_t b = get_body_bundle(p);
  if(!b.body) return;

  int op = (int)rnd(seed, 13); /* 0..12 */
  char buf[SIP_BODY_MAX];

  switch (op){
    case 0: { /* 最小 SDP */
      gen_min_sdp(buf, sizeof(buf), "203.0.113.10");
      write_body_and_maybe_len(p, buf, "application","sdp",";charset=utf-8", -1);
    } break;

    case 1: { /* 超长 SDP */
      gen_big_sdp(buf, sizeof(buf));
      write_body_and_maybe_len(p, buf, "application","sdp","", -1);
    } break;

    case 2: { /* SDP 破坏：缺 v=，仅 LF，重复属性 */
      size_t n=0;
      n+=snprintf(buf+n,sizeof(buf)-n,"o=- 0 0 IN IP4 198.51.100.1\n");
      n+=snprintf(buf+n,sizeof(buf)-n,"s=broken\n");
      n+=snprintf(buf+n,sizeof(buf)-n,"c=IN IP4 198.51.100.1\n");
      n+=snprintf(buf+n,sizeof(buf)-n,"t=0 0\n");
      n+=snprintf(buf+n,sizeof(buf)-n,"a=rtpmap:0 PCMU/8000\n");
      n+=snprintf(buf+n,sizeof(buf)-n,"a=rtpmap:0 PCMU/8000\n"); /* 重复 */
      n+=snprintf(buf+n,sizeof(buf)-n,"m=audio 40000 RTP/AVP 0\n");
      write_body_and_maybe_len(p, buf, "application","sdp","", -1);
    } break;

    case 3: { /* 非 ASCII/UTF-8 注入 */
      snprintf(buf,sizeof(buf),
        "v=0\r\n"
        "o=- 0 0 IN IP4 203.0.113.5\r\n"
        "s=\xE4\xBE\x8B\xE5\xAD\x90SDP\r\n" /* “例子SDP” */
        "c=IN IP4 203.0.113.5\r\n"
        "t=0 0\r\n"
        "a=remark:\x07control\r\n" /* 控制字符混入 */
        "m=audio 9 RTP/AVP 0\r\n");
      write_body_and_maybe_len(p, buf, "application","sdp",";charset=utf-8", -1);
    } break;

    case 4: { /* text/plain */
      snprintf(buf,sizeof(buf), "hello from %u\n", xs32(seed));
      write_body_and_maybe_len(p, buf, "text","plain",";charset=utf-8", -1);
    } break;

    case 5: { /* pidf+xml */
      gen_pidf(buf, sizeof(buf));
      write_body_and_maybe_len(p, buf, "application","pidf+xml",";charset=utf-8", -1);
    } break;

    case 6: { /* sipfrag */
      gen_sipfrag(buf, sizeof(buf));
      write_body_and_maybe_len(p, buf, "message","sipfrag","", -1);
    } break;

    case 7: { /* CL 小于实际 */
      gen_min_sdp(buf, sizeof(buf), "192.0.2.1");
      int fake_len = (int)(strlen(buf)/2);
      write_body_and_maybe_len(p, buf, "application","sdp","", fake_len);
    } break;

    case 8: { /* CL 大于实际 */
      gen_min_sdp(buf, sizeof(buf), "192.0.2.2");
      int fake_len = (int)(strlen(buf)*2 + 100);
      write_body_and_maybe_len(p, buf, "application","sdp","", fake_len);
    } break;

    case 9: { /* 空体，无 CT，CL=0 */
      b.body[0]='\0';
      clear_ct(b.ct);
      set_cl_len(b.cl, 0);
    } break;

    case 10: { /* application/json */
      gen_json(buf, sizeof(buf));
      write_body_and_maybe_len(p, buf, "application","json",";charset=utf-8", -1);
    } break;

    case 11: { /* multipart/mixed 边界问题 */
      const char *boundary = "xyzBOUND";
      size_t n=0;
      n+=snprintf(buf+n,sizeof(buf)-n,"--%s\r\n", boundary);
      n+=snprintf(buf+n,sizeof(buf)-n,"Content-Type: text/plain\r\n\r\npart1\r\n");
      /* 故意不写终止边界或重复错误边界 */
      write_body_and_maybe_len(p, buf, "multipart","mixed",";boundary=xyzBOUND", -1);
    } break;

    default: { /* 前后多余 CRLF/前置空行 */
      snprintf(buf,sizeof(buf), "\r\n\r\nv=0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nm=audio 0 RTP/AVP 0\r\n");
      write_body_and_maybe_len(p, buf, "application","sdp","", -1);
    } break;
  }

  /* 特殊：ACK 场景常见“无体”，我们再随机清空一次，制造差异 */
  if (p->cmd_type == SIP_PKT_ACK && rnd(seed,4)==0){
    b.body[0]='\0'; set_cl_len(b.cl,0); clear_ct(b.ct);
  }
}

/* 批量就地变异：对 INVITE/ACK/REGISTER/OPTIONS 进行 1~3 次随机 body 变异 */
size_t mutate_body_inv_ack_reg_opt(sip_packet_t *arr, size_t n, uint32_t seed){
  if(!arr || n==0) return 0;
  uint32_t s = seed ? seed : ((uint32_t)time(NULL) ^ 0xC0FFEEu);
  size_t cnt=0;
  for(size_t i=0;i<n;i++){
    sip_packet_t *p = &arr[i];
    if (!(p->cmd_type==SIP_PKT_INVITE || p->cmd_type==SIP_PKT_ACK ||
          p->cmd_type==SIP_PKT_REGISTER || p->cmd_type==SIP_PKT_OPTIONS)) {
      continue;
    }
    int times = 1 + (int)rnd(&s,3); /* 1..3 次 */
    for(int t=0;t<times;t++) mutate_one_body(p, &s);
    cnt++;
  }
  return cnt;
}

static void seed_once(unsigned seed){
    static int done = 0;
    if(!done){
        done = 1;
        srand(seed ? seed : (unsigned)time(NULL));
    }
}
static unsigned r32(void){
    return ((unsigned)rand() << 16) ^ (unsigned)rand();
}


static void set_hdr_name(sip_call_id_hdr_t *h, const char *name){
    if(!h) return;
    snprintf(h->name, SIP_HEADER_NAME_LEN, "%s", name);
}
static void set_colon_space(sip_call_id_hdr_t *h, const char *cs){
    if(!h) return;
    /* 目标数组长度为 3，形如 ": " + '\0' */
    h->colon_space[0] = cs && cs[0] ? cs[0] : ':';
    h->colon_space[1] = (cs && cs[1]) ? cs[1] : ' ';
    h->colon_space[2] = '\0';
}
static void set_crlf(sip_call_id_hdr_t *h, const char *crlf){
    if(!h) return;
    /* 目标数组长度为 3，形如 "\r\n" + '\0' */
    if(crlf && crlf[0]){
        h->crlf[0] = crlf[0];
        h->crlf[1] = (crlf[1] ? crlf[1] : '\0');
        h->crlf[2] = '\0';
    }else{
        h->crlf[0] = '\r';
        h->crlf[1] = '\n';
        h->crlf[2] = '\0';
    }
}
static void set_value(sip_call_id_hdr_t *h, const char *v){
    if(!h) return;
    if(!v) v = "";
    snprintf(h->value, SIP_TEXT_LEN, "%s", v);
}

static int rint(int lo, int hi){ /* [lo,hi] */
    if(hi <= lo) return lo;
    return lo + (rand() % (hi - lo + 1));
}

/* 生成 host（合法，含 FQDN / IPv4 / [IPv6]） */
static void gen_host(char *out, size_t cap){
    int t = rand()%3;
    if(t==0){
        /* FQDN */
        snprintf(out, cap, "host-%d.example.com", r32()%100000);
    }else if(t==1){
        /* IPv4 */
        snprintf(out, cap, "%d.%d.%d.%d",
                 rint(1,223), rint(0,255), rint(0,255), rint(1,254));
    }else{
        /* IPv6 */
        snprintf(out, cap, "[2001:db8:%x:%x::%x]", r32()&0xffff, r32()&0xffff, r32()&0xffff);
    }
}
/* 统一获取当前包的 call-id 指针 */
static sip_call_id_hdr_t* pick_call_id_hdr(sip_packet_t *p){
    if(!p) return NULL;
    switch(p->cmd_type){
        case SIP_PKT_INVITE:   return &p->pkt.invite.call_id;
        case SIP_PKT_ACK:      return &p->pkt.ack.call_id;
        case SIP_PKT_BYE:      return &p->pkt.bye.call_id;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.call_id;
        case SIP_PKT_REGISTER: return &p->pkt.register_.call_id;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.call_id;
        default: return NULL;
    }
}
/* 就地大小写翻转（非法/边界混合） */
static void flip_case(char *s){
    if(!s) return;
    for(size_t i=0;s[i];++i){
        if(isalpha((unsigned char)s[i])){
            if(islower((unsigned char)s[i])) s[i] = (char)toupper((unsigned char)s[i]);
            else s[i] = (char)tolower((unsigned char)s[i]);
        }
    }
}
static void gen_token2(char *out, size_t cap){
    static const char ALPH[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-!~*+'%";
    size_t n = (size_t)rint(4, 20);
    if(cap == 0) return;
    for(size_t i=0;i+1<cap && i<n;i++){
        out[i] = ALPH[rand()% (int)(sizeof(ALPH)-1)];
    }
    out[MIN(n,cap-1)] = '\0';
}

static void mutate_one_call_id(sip_call_id_hdr_t *h){
    if(!h) return;

    int op = rand()%13;
    char buf[SIP_TEXT_LEN];
    char tkn[64], host[128];

    /* 默认把头名与分隔、CRLF先“复原”为规范，再在具体算子中按需修改 */
    set_hdr_name(h, "Call-ID");
    set_colon_space(h, ": ");
    set_crlf(h, "\r\n");

    switch(op){
    case 0: { /* 合法：随机 token */
        gen_token2(tkn, sizeof(tkn));
        set_value(h, tkn);
        break;
    }
    case 1: { /* 合法：token@host */
        gen_token2(tkn, sizeof(tkn));
        gen_host(host, sizeof(host));
        snprintf(buf, sizeof(buf), "%s@%s", tkn, host);
        set_value(h, buf);
        break;
    }
    case 2: { /* 合法：token@host:port */
        gen_token2(tkn, sizeof(tkn));
        gen_host(host, sizeof(host));
        int port = rint(1, 65535);
        snprintf(buf, sizeof(buf), "%s@%s:%d", tkn, host, port);
        set_value(h, buf);
        break;
    }
    case 3: { /* 合法：使用紧凑头名 'i' */
        set_hdr_name(h, "i");
        gen_token2(tkn, sizeof(tkn));
        gen_host(host, sizeof(host));
        snprintf(buf, sizeof(buf), "%s@%s", tkn, host);
        set_value(h, buf);
        break;
    }
    case 4: { /* 非法：空值 */
        set_value(h, "");
        break;
    }
    case 5: { /* 非法：空白扰动 */
        gen_token2(tkn, sizeof(tkn));
        gen_host(host, sizeof(host));
        /* 在 @ 两侧与首尾加空白/制表符 */
        snprintf(buf, sizeof(buf), "  %s \t @ \t %s  ", tkn, host);
        set_value(h, buf);
        break;
    }
    case 6: { /* 非法：超长填充 */
        size_t want = SIP_TEXT_LEN - 1;
        for(size_t i=0;i<want;i++) buf[i] = 'A' + (char)(i%26);
        buf[want] = '\0';
        set_value(h, buf);
        break;
    }
    case 7: { /* 非法：非 ASCII / UTF-8 */
        /* 注意：这里只是字节序列，真实编码校验留给被测方 */
        const char *u8 = "idéntité@例子.测试";
        set_value(h, u8);
        break;
    }
    case 8: { /* 非法：插入不被 token 允许的字符 */
        snprintf(buf, sizeof(buf), "abc<bad>\"id\" @ example.com");
        set_value(h, buf);
        break;
    }
    case 9: { /* 非法：CRLF 异常 */
        gen_token2(tkn, sizeof(tkn));
        set_value(h, tkn);
        /* 只放 '\n' 或者只放 '\r' */
        if(rand()&1) set_crlf(h, "\n");
        else         set_crlf(h, "\r");
        break;
    }
    case 10: { /* 非法：": " 分隔异常 */
        gen_token2(tkn, sizeof(tkn));
        set_value(h, tkn);
        if(rand()&1) set_colon_space(h, ":");   /* 少空格 */
        else         set_colon_space(h, "  ");  /* 没有冒号 */
        break;
    }
    case 11: { /* 非法：多值（逗号分隔） */
        char t2[64];
        gen_token2(tkn, sizeof(tkn));
        gen_token2(t2,  sizeof(t2));
        snprintf(buf, sizeof(buf), "%s,%s", tkn, t2);
        set_value(h, buf);
        break;
    }
    case 12: { /* 合法/边界：大小写变换 + host 变化 */
        gen_token2(tkn, sizeof(tkn));
        gen_host(host, sizeof(host));
        snprintf(buf, sizeof(buf), "%s@%s", tkn, host);
        set_value(h, buf);
        int style = rand()%3;
        if(style==0){ /* 全大写头名 */
            set_hdr_name(h, "CALL-ID");
        }else if(style==1){ /* 全小写头名（不规范但常见容错） */
            set_hdr_name(h, "call-id");
        }else{
            /* 反转 value 的大小写（对 token 字母起作用） */
            flip_case(h->value);
        }
        break;
    }
    default: break;
    }
}

void mutate_call_id(sip_packet_t *pkts, size_t n, unsigned seed){
    if(!pkts || n == 0) return;
    seed_once(seed);

    size_t idx = (size_t)(rand() % (int)n);
    sip_packet_t *p = &pkts[idx];
    sip_call_id_hdr_t *h = pick_call_id_hdr(p);
    if(!h) return;

    mutate_one_call_id(h);
}

static void safe_strcpy(char *dst, size_t cap, const char *src) {
    if (cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    snprintf(dst, cap, "%s", src);  /* 保证 NUL 结尾 */
}

static void safe_memcpy_str(char *dst, size_t cap, const char *s, size_t n) {
    if (cap == 0) return;
    size_t m = (n < cap - 1) ? n : (cap - 1);
    memcpy(dst, s, m);
    dst[m] = '\0';
}

/* —— 获取 CSeq 与请求行方法指针 —— */
static sip_cseq_hdr_t* get_cseq_hdr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.cseq;
        case SIP_PKT_ACK:      return &p->pkt.ack.cseq;
        case SIP_PKT_BYE:      return &p->pkt.bye.cseq;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.cseq;
        case SIP_PKT_REGISTER: return &p->pkt.register_.cseq;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.cseq;
        default:               return NULL;
    }
}

static char* get_reqline_method_buf(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return p->pkt.invite.method;
        case SIP_PKT_ACK:      return p->pkt.ack.method;
        case SIP_PKT_BYE:      return p->pkt.bye.method;
        case SIP_PKT_CANCEL:   return p->pkt.cancel.method;
        case SIP_PKT_REGISTER: return p->pkt.register_.method;
        case SIP_PKT_OPTIONS:  return p->pkt.options.method;
        default:               return NULL;
    }
}

/* —— 常见方法集合（供制造不匹配或替换） —— */
static const char* k_methods[] = {
    "INVITE","ACK","BYE","CANCEL","REGISTER","OPTIONS",
    "INFO","UPDATE","PRACK","REFER","MESSAGE","SUBSCRIBE","NOTIFY","PUBLISH"
};
static size_t k_methods_count = sizeof(k_methods)/sizeof(k_methods[0]);

static uint32_t xorshift32(uint32_t *s) {
  uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x; return x;
}
static uint32_t frand_u32(uint32_t *st){ return xorshift32(st); }
static int      frand_int(uint32_t *st, int lo, int hi){
    if (hi <= lo) return lo;
    uint32_t r = frand_u32(st);
    return lo + (int)(r % (uint32_t)(hi - lo + 1));
}

/* —— 数字解析（容错：非数字则当 0） —— */
static unsigned parse_uint_fuzzy(const char *s) {
    if (!s) return 0;
    unsigned v = 0;
    for (; *s; ++s) {
        if (*s >= '0' && *s <= '9') {
            unsigned d = (unsigned)(*s - '0');
            v = v * 10u + d;
        } else {
            /* 非数字直接停止 */
            break;
        }
    }
    return v;
}

/* —— 方法大小写变换 —— */
static void to_lower_token(char *s) {
    if (!s) return;
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}
static void to_mixed_token(char *s) {
    if (!s) return;
    int flip = 0;
    for (; *s; ++s) {
        char c = *s;
        if (isalpha((unsigned char)c)) {
            *s = (char)((flip ^= 1) ? toupper((unsigned char)c) : tolower((unsigned char)c));
        }
    }
}

/* —— 构造一些典型异常串 —— */
static void make_all9(char *buf, size_t cap) {
    if (cap == 0) return;
    size_t n = cap - 1;
    for (size_t i = 0; i < n; ++i) buf[i] = '9';
    buf[n] = '\0';
}
static void make_spaces(char *buf, size_t cap) {
    if (cap == 0) return;
    size_t n = cap - 1;
    for (size_t i = 0; i < n; ++i) buf[i] = (i & 1) ? '\t' : ' ';
    buf[n] = '\0';
}

/* —— 生成不匹配方法 —— */
static void pick_mismatched_method(char *dst, size_t cap, const char *current) {
    /* 随机挑一个不同于 current 的方法 */
    int idx = 0;
    if (k_methods_count > 1) {
        do { idx = rand() % (int)k_methods_count; } while (current && strcasecmp(k_methods[idx], current) == 0);
    }
    safe_strcpy(dst, cap, k_methods[idx]);
}

/* —— 单报文的 CSeq 变异：从下列算子中任选若干 —— */
typedef enum {
    OP_INC = 0,
    OP_DEC,
    OP_RAND32,
    OP_ALL9,
    OP_LEADING_ZERO,
    OP_EMPTY_NUM,
    OP_NON_DIGIT,
    OP_WS_NUM,
    OP_TRUNC_NUM,
    OP_MISMATCH_METHOD,
    OP_LOWER_METHOD,
    OP_MIXED_METHOD,
    OP_PARAM_METHOD,
    OP_NO_SPACE,
    OP_BAD_COLON,
    OP_BAD_CRLF,
    OP_BAD_NAME,
    OP_UTF8_INJECT,
    OP__COUNT
} cseq_op_t;

static void mutate_cseq_one(sip_packet_t *p, uint32_t *rng_state, int how_many_ops) {
    sip_cseq_hdr_t *h = get_cseq_hdr(p);
    if (!h) return;

    /* 记录请求行方法（用来制造匹配/不匹配） */
    char *reqline_method = get_reqline_method_buf(p);
    char  req_method_copy[SIP_TOKEN_LEN];
    safe_strcpy(req_method_copy, sizeof(req_method_copy), reqline_method ? reqline_method : "");

    for (int k = 0; k < how_many_ops; ++k) {
        int op = frand_int(rng_state, 0, OP__COUNT - 1);
        switch (op) {
        case OP_INC: {
            unsigned v = parse_uint_fuzzy(h->number);
            if (v < 0xFFFFFFFFu) v++;
            char buf[32]; snprintf(buf, sizeof(buf), "%u", v);
            safe_strcpy(h->number, sizeof(h->number), buf);
        } break;
        case OP_DEC: {
            /* 允许产生负号（非法） */
            unsigned v = parse_uint_fuzzy(h->number);
            if (v == 0) safe_strcpy(h->number, sizeof(h->number), "-1");
            else {
                char buf[32]; snprintf(buf, sizeof(buf), "%u", v - 1u);
                safe_strcpy(h->number, sizeof(h->number), buf);
            }
        } break;
        case OP_RAND32: {
            uint32_t r = frand_u32(rng_state);
            char buf[32]; snprintf(buf, sizeof(buf), "%u", r);
            safe_strcpy(h->number, sizeof(h->number), buf);
        } break;
        case OP_ALL9: {
            make_all9(h->number, sizeof(h->number));
        } break;
        case OP_LEADING_ZERO: {
            char tmp[32];
            unsigned v = parse_uint_fuzzy(h->number);
            snprintf(tmp, sizeof(tmp), "%08u", v);            /* 固定 8 位带前导零 */
            safe_strcpy(h->number, sizeof(h->number), tmp);
        } break;
        case OP_EMPTY_NUM: {
            h->number[0] = '\0';                              /* 数字为空 */
        } break;
        case OP_NON_DIGIT: {
            char buf[32];
            unsigned v = parse_uint_fuzzy(h->number);
            snprintf(buf, sizeof(buf), "%uabc", v);           /* 掺入非数字 */
            safe_strcpy(h->number, sizeof(h->number), buf);
        } break;
        case OP_WS_NUM: {
            make_spaces(h->number, sizeof(h->number));        /* 全空白 */
        } break;
        case OP_TRUNC_NUM: {
            if (h->number[0]) {
                char c = h->number[0];
                h->number[0] = c;
                h->number[1] = '\0';
            }
        } break;
        case OP_MISMATCH_METHOD: {
            pick_mismatched_method(h->method, sizeof(h->method), req_method_copy);
        } break;
        case OP_LOWER_METHOD: {
            to_lower_token(h->method);
        } break;
        case OP_MIXED_METHOD: {
            to_mixed_token(h->method);
        } break;
        case OP_PARAM_METHOD: {
            /* 在方法后追加伪参数；若空间不足则截断 */
            size_t len = strnlen(h->method, sizeof(h->method));
            const char *tail = ";q=1;foo=bar";
            size_t cap = sizeof(h->method);
            if (len < cap - 1) {
                size_t room = cap - 1 - len;
                safe_memcpy_str(h->method + len, room + 1, tail, room);
            }
        } break;
        case OP_NO_SPACE: {
            /* 破坏 number 与 method 之间的空格 */
            h->sp = '\t';  /* 或者置为 '\0' 以彻底去掉 */
        } break;
        case OP_BAD_COLON: {
            /* 破坏 ": " 分隔（注意容量 3: 允许 ":","::","; " 等） */
            /* 举例改为 "::" */
            h->colon_space[0] = ':';
            h->colon_space[1] = ':';
            h->colon_space[2] = '\0';
        } break;
        case OP_BAD_CRLF: {
            /* 只用 LF 或者错误顺序 */
            safe_strcpy(h->crlf, sizeof(h->crlf), "\n");
        } break;
        case OP_BAD_NAME: {
            /* 破坏首部名（大小写无关，这里做拼写偏差） */
            safe_strcpy(h->name, sizeof(h->name), "CSeqq");
        } break;
        case OP_UTF8_INJECT: {
            /* 在方法或数字注入非 ASCII（UTF-8） */
            if (frand_int(rng_state, 0, 1) == 0) {
                /* 数字中注入 */
                safe_strcpy(h->number, sizeof(h->number), "12\xC3\xA9" "34");  /* "12é34" */
            } else {
                safe_strcpy(h->method, sizeof(h->method), "INVIT\xC3\x89");     /* "INVITÉ" */
            }
        } break;
        default: break;
        }
    }
}

/* —— 批量接口：对数组中每个报文施加 1~N 个算子 —— */
void mutate_sip_cseq(sip_packet_t *pkts, size_t count, unsigned seed) {
    if (!pkts || count == 0) return;
    int max_ops_per_pkt = 3;

    /* RNG 初始化 */
    uint32_t st = (uint32_t)(seed ? seed : 0xC0FFEEu);
    /* 可选：轻度标准化格式，确保字段非空，以避免“空上再空”的弱刺激 */
    for (size_t i = 0; i < count; ++i) {
        sip_cseq_hdr_t *h = get_cseq_hdr(&pkts[i]);
        if (!h) continue;
        if (h->name[0] == '\0') safe_strcpy(h->name, sizeof(h->name), "CSeq");
        if (h->colon_space[0] == '\0') safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
        if (h->crlf[0] == '\0') safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
        if (h->number[0] == '\0') safe_strcpy(h->number, sizeof(h->number), "1");
        if (h->method[0] == '\0') safe_strcpy(h->method, sizeof(h->method), "INVITE");
        if (h->sp == '\0') h->sp = ' ';
    }

    for (size_t i = 0; i < count; ++i) {
        int ops = frand_int(&st, 1, (max_ops_per_pkt > 8 ? 8 : max_ops_per_pkt));
        mutate_cseq_one(&pkts[i], &st, ops);
    }
}

/* ——（可选）提供一个只做“合法递增/匹配”的轻量版本 —— */
void tweak_cseq_legal_progression(sip_packet_t *pkts, size_t count) {
    if (!pkts) return;
    for (size_t i = 0; i < count; ++i) {
        sip_cseq_hdr_t *h = get_cseq_hdr(&pkts[i]);
        char *req = get_reqline_method_buf(&pkts[i]);
        if (!h || !req) continue;
        unsigned v = parse_uint_fuzzy(h->number);
        char buf[32]; snprintf(buf, sizeof(buf), "%u", v + 1);
        safe_strcpy(h->number, sizeof(h->number), buf);
        safe_strcpy(h->method, sizeof(h->method), req);  /* 与请求行方法保持一致 */
        h->sp = ' ';
        safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
        safe_strcpy(h->name, sizeof(h->name), "CSeq");
    }
}

static void safe_append(char *dst, size_t cap, const char *suffix) {
    if (!dst || cap == 0 || !suffix) return;
    size_t len = strnlen(dst, cap);
    size_t room = (len < cap) ? (cap - 1 - len) : 0;
    if (room == 0) return;
    size_t sl = strnlen(suffix, room + 1);
    memcpy(dst + len, suffix, sl > room ? room : sl);
    dst[len + (sl > room ? room : sl)] = '\0';
}



static int rnd_int(uint32_t *st, int lo, int hi) {
    if (hi <= lo) return lo;
    return lo + (int)(xorshift32(st) % (uint32_t)(hi - lo + 1));
}
static char rnd_hex(uint32_t *st) {
    const char *d = "0123456789abcdef";
    return d[xorshift32(st) % 16u];
}

/* 获取各报文的 From 指针 */
static sip_from_hdr_t* get_from_hdr(sip_packet_t *p) {
    if (!p) return NULL;
    switch (p->cmd_type) {
        case SIP_PKT_INVITE:   return &p->pkt.invite.from_;
        case SIP_PKT_ACK:      return &p->pkt.ack.from_;
        case SIP_PKT_BYE:      return &p->pkt.bye.from_;
        case SIP_PKT_CANCEL:   return &p->pkt.cancel.from_;
        case SIP_PKT_REGISTER: return &p->pkt.register_.from_;
        case SIP_PKT_OPTIONS:  return &p->pkt.options.from_;
        default: return NULL;
    }
}

/* （可选）获取 To，用于某些互换类变异 */
static sip_to_hdr_t* get_to_hdr(sip_packet_t *p) {
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

/* 规范化：若为空则填入一个保守、合法的基线值 */
static void normalize_from(sip_from_hdr_t *h) {
    if (!h) return;
    if (h->name[0] == '\0')        safe_strcpy(h->name, sizeof(h->name), "From");
    if (h->colon_space[0] == '\0') safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
    if (h->display[0] == '\0')     safe_strcpy(h->display, sizeof(h->display), "\"Alice\"");
    if (h->sp_opt == '\0')         h->sp_opt = ' ';
    if (h->lt == '\0')             h->lt = '<';
    if (h->uri[0] == '\0')         safe_strcpy(h->uri, sizeof(h->uri), "sip:alice@example.com");
    if (h->gt == '\0')             h->gt = '>';
    if (h->params[0] == '\0')      safe_strcpy(h->params, sizeof(h->params), ";tag=a1b2c3");
    if (h->crlf[0] == '\0')        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
}

/* 生成随机 tag 值（十六进制，长度 1..32） */
static void make_rand_tag(uint32_t *st, char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    int n = rnd_int(st, 1, 32);
    size_t m = (size_t)n < cap - 1 ? (size_t)n : cap - 1;
    for (size_t i = 0; i < m; ++i) buf[i] = rnd_hex(st);
    buf[m] = '\0';
}

/* 设置/替换 params 为仅包含一个 tag=xxxx */
static void set_params_tag_only(sip_from_hdr_t *h, const char *tagval) {
    if (!h) return;
    h->params[0] = '\0';
    safe_append(h->params, sizeof(h->params), ";tag=");
    safe_append(h->params, sizeof(h->params), tagval ? tagval : "");
}

/* 在现有 params 末尾追加一个参数（带前缀 ';'） */
static void append_param(sip_from_hdr_t *h, const char *kv) {
    if (!h || !kv) return;
    safe_append(h->params, sizeof(h->params), ";");
    safe_append(h->params, sizeof(h->params), kv);
}

/* 查找 tag= 起始位置（非常简化的子串查找） */
static char* find_tag(char *params) {
    if (!params) return NULL;
    /* 既匹配 ";tag=" 也匹配 "tag="（容错） */
    char *p = strstr(params, "tag=");
    if (!p) p = strstr(params, ";tag=");
    return p;
}

/* 删除 params 中的第一个 tag=xxx （粗暴做法：直接清空或仅留其它示例）*/
static void remove_tag_simple(sip_from_hdr_t *h) {
    if (!h) return;
    /* 为简洁，直接去掉全部参数 */
    h->params[0] = '\0';
}

/* 大小写处理 */
static void to_lower_str(char *s) { if (!s) return; for (; *s; ++s) *s = (char)tolower((unsigned char)*s); }
static void to_mixed_caps(char *s) {
    if (!s) return;
    int flip = 0;
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (isalpha(c)) *s = (char)((flip ^= 1) ? toupper(c) : tolower(c));
    }
}

/* 构造超长主机名 "aaaa....example.com" */
static void make_long_host(char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    buf[0] = '\0';
    while (strnlen(buf, cap) + 5 < cap - 1) safe_append(buf, cap, "a");
    safe_append(buf, cap, ".com");
}

/* ================= 变异算子定义 ================= */

typedef enum {
    /* 语义：tag 参数家族 */
    OP_TAG_NEW_OR_CHANGE = 0, /* 新建或改写 tag= 值（合法） */
    OP_TAG_REMOVE,            /* 移除 tag（非法：请求必须含 tag） */
    OP_TAG_DUPLICATE,         /* 重复出现 tag（非法/边界） */
    OP_TAG_EMPTY,             /* tag= 空值 */
    OP_TAG_LONG,              /* tag 超长接近上限 */
    /* params 其它形态 */
    OP_PARAMS_ADD_COMMON,     /* 追加常见/伪造参数 */
    OP_PARAMS_BAD_SYNTAX,     /* 缺分号/多等号/裸 key */
    /* 显示名 display */
    OP_DISPLAY_EMPTY,         /* 置空显示名 */
    OP_DISPLAY_NO_QUOTE,      /* 去掉引号或制造不配对引号 */
    OP_DISPLAY_UTF8,          /* 注入非 ASCII（UTF-8） */
    OP_DISPLAY_LONG,          /* 显示名超长 */
    /* LT/GT 与空格 */
    OP_TOGGLE_SP_OPT,         /* 切换/破坏空格 */
    OP_DROP_LT_OR_GT,         /* 去掉 '<' 或 '>' */
    /* URI 家族 */
    OP_URI_SCHEME_VARIANTS,   /* 切换 sip/sips/tel/http/mailto 等 */
    OP_URI_USER_WEIRD,        /* 用户名含转义/不常见字符 */
    OP_URI_HOST_LONG,         /* 超长主机名/端口极值 */
    OP_URI_IPV6_FORMS,        /* IPv6 各种括号/缩写/无括号 */
    OP_URI_ADD_HDRS,          /* URI 末尾追加 ?subject=... */
    OP_URI_TRUNC,             /* 截断 URI */
    OP_URI_SWAP_WITH_TO,      /* 与 To 的 URI 互换（语义对调） */
    /* 行/名/分隔符 */
    OP_NAME_CASE_OR_MISSPELL, /* "From"/"from"/"FROM"/"Fr0m" */
    OPP_BAD_COLON,             /* 破坏 ": " 分隔 */
    OPP_BAD_CRLF,              /* 破坏 CRLF */
    OPP__COUNT
} from_op_t;

/* 单个报文的 From 变异 */
static void mutate_from_one(sip_packet_t *p, uint32_t *st, int ops) {
    sip_from_hdr_t *h = get_from_hdr(p);
    if (!h) return;

    /* 先规范化，保证字段非空且有一个基线 tag */
    normalize_from(h);

    for (int k = 0; k < ops; ++k) {
        int op = rnd_int(st, 0, OPP__COUNT - 1);
        switch (op) {
        case OP_TAG_NEW_OR_CHANGE: {
            char tag[128]; make_rand_tag(st, tag, sizeof(tag));
            set_params_tag_only(h, tag); /* 合法：确保有 tag */
        } break;
        case OP_TAG_REMOVE: {
            remove_tag_simple(h);        /* 非法：去掉全部 params（含 tag） */
        } break;
        case OP_TAG_DUPLICATE: {
            char tag[64]; make_rand_tag(st, tag, sizeof(tag));
            /* 若已有 tag，简单在末尾再追加一个 */
            append_param(h, "tag=");
            safe_append(h->params, sizeof(h->params), tag);
        } break;
        case OP_TAG_EMPTY: {
            set_params_tag_only(h, "");  /* tag= 空值 */
        } break;
        case OP_TAG_LONG: {
            /* 构造接近上限的 tag 值 */
            size_t room = sizeof(h->params) - 1 - 5; /* 预留 ";tag=" */
            char big[512]; size_t n = room > sizeof(big)-1 ? sizeof(big)-1 : room;
            for (size_t i = 0; i < n; ++i) big[i] = 'A' + (char)(i % 26);
            big[n] = '\0';
            set_params_tag_only(h, big);
        } break;
        case OP_PARAMS_ADD_COMMON: {
            /* 追加一些看起来像 URI/From 参数的键值 */
            const char* pool[] = {"user=phone","transport=tcp","foo=bar","lr","ob","maddr=239.1.1.1","ttl=255"};
            append_param(h, pool[rnd_int(st,0,(int)(sizeof(pool)/sizeof(pool[0])-1))]);
        } break;
        case OP_PARAMS_BAD_SYNTAX: {
            /* 制造语法错误：少分号、多等号、裸 key */
            const char* bads[] = {"tag==abc","tag", "key value", ";;;=", "tag=abc=def", "tagabc"};
            safe_strcpy(h->params, sizeof(h->params), "");
            append_param(h, bads[rnd_int(st,0,(int)(sizeof(bads)/sizeof(bads[0])-1))]);
        } break;
        case OP_DISPLAY_EMPTY: {
            h->display[0] = '\0';
            h->sp_opt = (rnd_int(st,0,1)? ' ' : '\0');
        } break;
        case OP_DISPLAY_NO_QUOTE: {
            /* 去引号或制造不配对引号 */
            const char* v[] = {"Alice", "\"Alice", "Alice\"", "\"A\\\"li\\\"ce"};
            safe_strcpy(h->display, sizeof(h->display), v[rnd_int(st,0,3)]);
        } break;
        case OP_DISPLAY_UTF8: {
            /* 插入非 ASCII（UTF-8），例如中文“测试者” */
            safe_strcpy(h->display, sizeof(h->display), "测试者");
            h->sp_opt = ' ';
        } break;
        case OP_DISPLAY_LONG: {
            /* 构造接近上限的显示名 */
            size_t cap = sizeof(h->display);
            memset(h->display, 'D', cap ? cap-1 : 0);
            if (cap) h->display[cap-1] = '\0';
        } break;
        case OP_TOGGLE_SP_OPT: {
            /* 随机在 ' '、'\t'、'\0' 之间切换 */
            int r = rnd_int(st,0,2);
            h->sp_opt = (r==0? ' ' : (r==1? '\t' : '\0'));
        } break;
        case OP_DROP_LT_OR_GT: {
            /* 去掉 < 或 >，或替换为其它符号 */
            int r = rnd_int(st,0,2);
            if (r==0) h->lt = '\0';
            else if (r==1) h->gt = '\0';
            else { h->lt = '('; h->gt = ')'; }
        } break;
        case OP_URI_SCHEME_VARIANTS: {
            const char* pool[] = {
                "sip:alice@example.com",
                "sips:alice@example.com",
                "tel:+12025550123",
                "mailto:alice@example.com",   /* 异常/不期望 */
                "http://example.com/alice"    /* 异常/不期望 */
            };
            safe_strcpy(h->uri, sizeof(h->uri), pool[rnd_int(st,0,4)]);
        } break;
        case OP_URI_USER_WEIRD: {
            const char* users[] = {"al%69ce","a!$&'()*+,;=._~-","\"ali ce\"", "a:b", "a%ZZ"};
            char tmp[SIP_URI_LEN]; tmp[0]='\0';
            safe_append(tmp, sizeof(tmp), "sip:");
            safe_append(tmp, sizeof(tmp), users[rnd_int(st,0,4)]);
            safe_append(tmp, sizeof(tmp), "@example.com");
            safe_strcpy(h->uri, sizeof(h->uri), tmp);
        } break;
        case OP_URI_HOST_LONG: {
            char host[256]; host[0]='\0'; make_long_host(host, sizeof(host));
            char tmp[SIP_URI_LEN]; snprintf(tmp, sizeof(tmp), "sip:alice@%s:%u", host, (unsigned)rnd_int(st,1,70000));
            safe_strcpy(h->uri, sizeof(h->uri), tmp);
        } break;
        case OP_URI_IPV6_FORMS: {
            const char* forms[] = {
                "sip:alice@[2001:db8::1]",
                "sip:alice@2001:db8::1",   /* 缺括号 */
                "sip:alice@[::ffff:192.0.2.1]",
                "sip:alice@[2001:db8:0:0:0:0:2:1]" /* 全写 */
            };
            safe_strcpy(h->uri, sizeof(h->uri), forms[rnd_int(st,0,3)]);
        } break;
        case OP_URI_ADD_HDRS: {
            /* 在 URI 后追加 header/查询部 */
            safe_append(h->uri, sizeof(h->uri), "?subject=hello&priority=urgent");
        } break;
        case OP_URI_TRUNC: {
            /* 截断为前 8~16 字符 */
            size_t n = (size_t)rnd_int(st, 8, 16);
            safe_memcpy_str(h->uri, sizeof(h->uri), h->uri, n);
        } break;
        case OP_URI_SWAP_WITH_TO: {
            sip_to_hdr_t *to = get_to_hdr(p);
            if (to) safe_strcpy(h->uri, sizeof(h->uri), to->uri);
        } break;
        case OP_NAME_CASE_OR_MISSPELL: {
            const char* pool[] = {"From","from","FROM","Fr0m","Fromm"};
            safe_strcpy(h->name, sizeof(h->name), pool[rnd_int(st,0,4)]);
        } break;
        case OPP_BAD_COLON: {
            /* 破坏 “: ” 分隔，改成 ":" 或 "::" 或 "; " */
            const char* v[] = {":", "::", "; "};
            safe_strcpy(h->colon_space, sizeof(h->colon_space), v[rnd_int(st,0,2)]);
        } break;
        case OPP_BAD_CRLF: {
            /* 仅 LF、错序、缺失 */
            const char* v[] = {"\n", "\r\n\r", ""};
            safe_strcpy(h->crlf, sizeof(h->crlf), v[rnd_int(st,0,2)]);
        } break;
        default: break;
        }
    }
}

/* 批量接口：对数组内每个报文施加 1..max_ops_per_pkt 个随机算子 */
void mutate_from_packets(sip_packet_t *pkts, size_t count, unsigned seed, int max_ops_per_pkt) {
    if (!pkts || count == 0) return;
    if (max_ops_per_pkt <= 0) max_ops_per_pkt = 4;
    uint32_t st = seed ? (uint32_t)seed : 0xF00DCAFEu;

    for (size_t i = 0; i < count; ++i) {
        sip_from_hdr_t *h = get_from_hdr(&pkts[i]);
        if (h) normalize_from(h);
    }
    for (size_t i = 0; i < count; ++i) {
        int ops = rnd_int(&st, 1, (max_ops_per_pkt > 10 ? 10 : max_ops_per_pkt));
        mutate_from_one(&pkts[i], &st, ops);
    }
}

/* （可选）只做“合法化/基线”修正：确保存在 tag、LT/GT、分隔与 CRLF 正确 */
void legalize_from_packets(sip_packet_t *pkts, size_t count) {
    if (!pkts) return;
    for (size_t i = 0; i < count; ++i) {
        sip_from_hdr_t *h = get_from_hdr(&pkts[i]);
        if (!h) continue;
        normalize_from(h);
        /* 确保 params 至少包含一个 tag */
        if (!find_tag(h->params)) set_params_tag_only(h, "a1b2c3");
        /* 标准外观 */
        safe_strcpy(h->name, sizeof(h->name), "From");
        safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
        h->sp_opt = ' ';
        h->lt = '<'; h->gt = '>';
        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
    }
}



/* 规范化 To：若为空则填入一个保守、合法的基线值（初始请求风格：无 tag） */
static void normalize_to(sip_to_hdr_t *h){
    if (!h) return;
    if (h->name[0] == '\0')        safe_strcpy(h->name, sizeof(h->name), "To");
    if (h->colon_space[0] == '\0') safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
    if (h->display[0] == '\0')     safe_strcpy(h->display, sizeof(h->display), "\"Bob\"");
    if (h->sp_opt == '\0')         h->sp_opt = ' ';
    if (h->lt == '\0')             h->lt = '<';
    if (h->uri[0] == '\0')         safe_strcpy(h->uri, sizeof(h->uri), "sip:bob@example.com");
    if (h->gt == '\0')             h->gt = '>';
    /* 初始请求通常无 To-tag：留空 params */
    /* 若你想基线设为“对话内请求”，可在外层另行设置 params 包含 ;tag=remote */
    if (h->crlf[0] == '\0')        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
}



static void set_params_tag_only_to(sip_to_hdr_t *h, const char *tagval){
    if (!h) return;
    h->params[0] = '\0';
    safe_append(h->params, sizeof(h->params), ";tag=");
    safe_append(h->params, sizeof(h->params), tagval ? tagval : "");
}
static void append_param_to(sip_to_hdr_t *h, const char *kv){
    if (!h || !kv) return;
    safe_append(h->params, sizeof(h->params), ";");
    safe_append(h->params, sizeof(h->params), kv);
}
static void remove_tag_simple_to(sip_to_hdr_t *h){
    if (!h) return;
    /* 简化处理：直接清空所有参数 */
    h->params[0] = '\0';
}



/* =================== 变异算子 =================== */
typedef enum {
    /* tag 系列（覆盖对话外/对话内） */
    OP_TO_TAG_ADD_OR_CHANGE = 0, /* 新建或改写 tag（对话内合法；初始请求非常见） */
    OP_TO_TAG_REMOVE,            /* 去掉 tag（对话内非法；初始请求常见） */
    OP_TO_TAG_DUPLICATE,         /* 重复 tag */
    OP_TO_TAG_EMPTY,             /* tag= 空 */
    OP_TO_TAG_LONG,              /* 超长 tag 值 */
    OP_TO_TAG_SET_FROM_TAG,      /* 将 To-tag 设置为 From 的 tag（常导致“本端/远端混淆”） */

    /* params 其它形态与错误 */
    OP_TO_PARAMS_ADD_COMMON,     /* 追加常见/伪造参数 */
    OP_TO_PARAMS_BAD_SYNTAX,     /* 缺分号 / 多等号 / 裸 key 等 */

    /* 显示名 display */
    OP_TO_DISPLAY_EMPTY,
    OP_TO_DISPLAY_NO_QUOTE,
    OP_TO_DISPLAY_UTF8,
    OP_TO_DISPLAY_LONG,

    /* LT/GT 与空白 */
    OP_TO_TOGGLE_SP_OPT,
    OP_TO_DROP_LT_OR_GT,

    /* URI 多样化 */
    OP_TO_URI_SCHEME_VARIANTS,
    OP_TO_URI_USER_WEIRD,
    OP_TO_URI_HOST_LONG,
    OP_TO_URI_IPV6_FORMS,
    OP_TO_URI_ADD_HDRS,
    OP_TO_URI_TRUNC,

    /* 名称/分隔符/行尾 */
    OP_TO_NAME_CASE_OR_MISSPELL,
    OP_TO_BAD_COLON,
    OP_TO_BAD_CRLF,

    OP_TO__COUNT
} to_op_t;

/* 单报文 To 变异 */
static void mutate_to_one(sip_packet_t *p, uint32_t *st, int how_many_ops){
    sip_to_hdr_t  *h_to  = get_to_hdr(p);
    sip_from_hdr_t*h_from= get_from_hdr(p);
    if (!h_to) return;

    normalize_to(h_to);

    for (int k=0;k<how_many_ops;++k){
        int op = rnd_int(st, 0, OP_TO__COUNT-1);
        switch (op){
        case OP_TO_TAG_ADD_OR_CHANGE: {
            char tag[128]; make_rand_tag(st, tag, sizeof(tag));
            set_params_tag_only_to(h_to, tag);
        } break;
        case OP_TO_TAG_REMOVE: {
            remove_tag_simple_to(h_to);
        } break;
        case OP_TO_TAG_DUPLICATE: {
            char tag[64]; make_rand_tag(st, tag, sizeof(tag));
            append_param_to(h_to, "tag=");
            safe_append(h_to->params, sizeof(h_to->params), tag);
        } break;
        case OP_TO_TAG_EMPTY: {
            set_params_tag_only_to(h_to, "");
        } break;
        case OP_TO_TAG_LONG: {
            size_t room = sizeof(h_to->params) - 1 - 5; /* 预留 ;tag= */
            char big[512]; size_t n = room > sizeof(big)-1 ? sizeof(big)-1 : room;
            for (size_t i=0;i<n;++i) big[i] = 'A' + (char)(i%26);
            big[n]='\0';
            set_params_tag_only_to(h_to, big);
        } break;
        case OP_TO_TAG_SET_FROM_TAG: {
            /* 粗略把 To-tag 设为 From 的 tag（对话内应为远端 tag，通常不等于 From-tag） */
            if (h_from){
                /* 在 from_.params 中找 tag=（极简） */
                char *pf = find_tag(h_from->params);
                if (pf){
                    pf = strstr(pf, "tag=");
                    if (pf){
                        pf += 4; /* 指向值开始 */
                        set_params_tag_only_to(h_to, pf);
                        break;
                    }
                }
            }
            /* 若没有 From-tag，则随机一个 */
            char tag[64]; make_rand_tag(st, tag, sizeof(tag));
            set_params_tag_only_to(h_to, tag);
        } break;

        case OP_TO_PARAMS_ADD_COMMON: {
            const char* pool[] = {"user=phone","transport=udp","maddr=239.1.1.1","ttl=255","lr","ob","foo=bar"};
            append_param_to(h_to, pool[rnd_int(st,0,(int)(sizeof(pool)/sizeof(pool[0])-1))]);
        } break;
        case OP_TO_PARAMS_BAD_SYNTAX: {
            const char* bads[] = {"tag==abc","tag", "key value", ";;;=", "tag=abc=def", "tagabc"};
            safe_strcpy(h_to->params, sizeof(h_to->params), "");
            append_param_to(h_to, bads[rnd_int(st,0,(int)(sizeof(bads)/sizeof(bads[0])-1))]);
        } break;

        case OP_TO_DISPLAY_EMPTY: {
            h_to->display[0] = '\0';
            h_to->sp_opt = (rnd_int(st,0,1) ? ' ' : '\0');
        } break;
        case OP_TO_DISPLAY_NO_QUOTE: {
            const char* v[] = {"Bob", "\"Bob", "Bob\"", "\"B\\\"o\\\"b"};
            safe_strcpy(h_to->display, sizeof(h_to->display), v[rnd_int(st,0,3)]);
        } break;
        case OP_TO_DISPLAY_UTF8: {
            safe_strcpy(h_to->display, sizeof(h_to->display), "接收者");
            h_to->sp_opt = ' ';
        } break;
        case OP_TO_DISPLAY_LONG: {
            size_t cap = sizeof(h_to->display);
            memset(h_to->display, 'D', cap?cap-1:0);
            if (cap) h_to->display[cap-1]='\0';
        } break;

        case OP_TO_TOGGLE_SP_OPT: {
            int r = rnd_int(st,0,2);
            h_to->sp_opt = (r==0? ' ' : (r==1? '\t' : '\0'));
        } break;
        case OP_TO_DROP_LT_OR_GT: {
            int r = rnd_int(st,0,2);
            if (r==0) h_to->lt = '\0';
            else if (r==1) h_to->gt = '\0';
            else { h_to->lt='(' ; h_to->gt=')'; }
        } break;

        case OP_TO_URI_SCHEME_VARIANTS: {
            const char* pool[] = {
                "sip:bob@example.com",
                "sips:bob@example.com",
                "tel:+12025550124",
                "mailto:bob@example.com",
                "http://example.com/bob"
            };
            safe_strcpy(h_to->uri, sizeof(h_to->uri), pool[rnd_int(st,0,4)]);
        } break;
        case OP_TO_URI_USER_WEIRD: {
            const char* users[] = {"bo%62","b!$&'()*+,;=._~-","\"bo b\"","b:b","b%ZZ"};
            char tmp[SIP_URI_LEN]; tmp[0]='\0';
            safe_append(tmp, sizeof(tmp), "sip:");
            safe_append(tmp, sizeof(tmp), users[rnd_int(st,0,4)]);
            safe_append(tmp, sizeof(tmp), "@example.com");
            safe_strcpy(h_to->uri, sizeof(h_to->uri), tmp);
        } break;
        case OP_TO_URI_HOST_LONG: {
            char host[256]; host[0]='\0'; make_long_host(host, sizeof(host));
            char tmp[SIP_URI_LEN];
            snprintf(tmp, sizeof(tmp), "sip:bob@%s:%u", host, (unsigned)rnd_int(st,1,70000));
            safe_strcpy(h_to->uri, sizeof(h_to->uri), tmp);
        } break;
        case OP_TO_URI_IPV6_FORMS: {
            const char* forms[] = {
                "sip:bob@[2001:db8::2]",
                "sip:bob@2001:db8::2",       /* 缺括号 */
                "sip:bob@[::ffff:192.0.2.2]",
                "sip:bob@[2001:db8:0:0:0:0:2:2]"
            };
            safe_strcpy(h_to->uri, sizeof(h_to->uri), forms[rnd_int(st,0,3)]);
        } break;
        case OP_TO_URI_ADD_HDRS: {
            safe_append(h_to->uri, sizeof(h_to->uri), "?priority=urgent&subject=hi");
        } break;
        case OP_TO_URI_TRUNC: {
            size_t n = (size_t)rnd_int(st, 8, 16);
            safe_memcpy_str(h_to->uri, sizeof(h_to->uri), h_to->uri, n);
        } break;

        case OP_TO_NAME_CASE_OR_MISSPELL: {
            const char* pool[] = {"To","to","TO","T0","Too"};
            safe_strcpy(h_to->name, sizeof(h_to->name), pool[rnd_int(st,0,4)]);
        } break;
        case OP_TO_BAD_COLON: {
            const char* v[] = {":", "::", "; "};
            safe_strcpy(h_to->colon_space, sizeof(h_to->colon_space), v[rnd_int(st,0,2)]);
        } break;
        case OP_TO_BAD_CRLF: {
            const char* v[] = {"\n", "\r\n\r", ""};
            safe_strcpy(h_to->crlf, sizeof(h_to->crlf), v[rnd_int(st,0,2)]);
        } break;
        default: break;
        }
    }
}

/* 批量接口：对数组中每个报文施加 1..max_ops_per_pkt 个随机算子 */
void mutate_to_packets(sip_packet_t *pkts, size_t count, unsigned seed, int max_ops_per_pkt){
    if (!pkts || count==0) return;
    if (max_ops_per_pkt <= 0) max_ops_per_pkt = 5;
    uint32_t st = seed ? (uint32_t)seed : 0xA1B2C3D4u;

    for (size_t i=0;i<count;++i){
        sip_to_hdr_t *h = get_to_hdr(&pkts[i]);
        if (h) normalize_to(h);
    }
    for (size_t i=0;i<count;++i){
        int ops = rnd_int(&st, 1, (max_ops_per_pkt > 10 ? 10 : max_ops_per_pkt));
        mutate_to_one(&pkts[i], &st, ops);
    }
}

/* （可选）合法化基线
   - 对话外（常见）：不带 To-tag
   - 若你已知“远端 tag”（对话内），可调用带 remote_tag 的版本设置 tag 一致
*/
void legalize_to_packets_out_of_dialog(sip_packet_t *pkts, size_t count){
    if (!pkts) return;
    for (size_t i=0;i<count;++i){
        sip_to_hdr_t *h = get_to_hdr(&pkts[i]);
        if (!h) continue;
        normalize_to(h);
        /* 去掉 params，保持无 tag */
        h->params[0] = '\0';
        safe_strcpy(h->name, sizeof(h->name), "To");
        safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
        h->sp_opt = ' '; h->lt = '<'; h->gt = '>';
        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
    }
}
void legalize_to_packets_in_dialog(sip_packet_t *pkts, size_t count, const char *remote_tag){
    if (!pkts) return;
    for (size_t i=0;i<count;++i){
        sip_to_hdr_t *h = get_to_hdr(&pkts[i]);
        if (!h) continue;
        normalize_to(h);
        set_params_tag_only_to(h, remote_tag ? remote_tag : "rmt1");
        safe_strcpy(h->name, sizeof(h->name), "To");
        safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
        h->sp_opt = ' '; h->lt = '<'; h->gt = '>';
        safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
    }
}



/* ================ 生成/规范化单条 Via ================ */
static void make_branch(char *buf, size_t cap, uint32_t *st, int good_prefix){
    if (!buf || cap==0) return;
    buf[0]='\0';
    if (good_prefix) safe_append(buf, cap, "z9hG4bK");
    int n = rnd_int(st, 4, 24);
    char tmp[64]; int m = n < (int)sizeof(tmp)-1 ? n : (int)sizeof(tmp)-1;
    for (int i=0;i<m;++i) tmp[i]=rnd_hex(st);
    tmp[m]='\0'; safe_append(buf, cap, tmp);
}
static void normalize_via_line(sip_via_hdr_t *h, uint32_t *st){
    if (!h) return;
    if (h->name[0]=='\0')         safe_strcpy(h->name, sizeof(h->name), "Via");
    if (h->colon_space[0]=='\0')  safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
    if (h->sent_protocol[0]=='\0')safe_strcpy(h->sent_protocol, sizeof(h->sent_protocol), "SIP/2.0/UDP");
    if (h->sp=='\0')              h->sp = ' ';
    if (h->sent_by[0]=='\0')      safe_strcpy(h->sent_by, sizeof(h->sent_by), "host.example.com:5060");
    if (h->params[0]=='\0'){      char b[64]; make_branch(b,sizeof(b),st,1);
                                   safe_append(h->params, sizeof(h->params), ";branch=");
                                   safe_append(h->params, sizeof(h->params), b);
                                   safe_append(h->params, sizeof(h->params), ";rport"); }
    if (h->crlf[0]=='\0')         safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
}
static void ensure_min_one_via(sip_packet_t *p, uint32_t *st){
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count) return;
    if (*s.count == 0){
        *s.count = 1;
        memset(&s.arr[0], 0, sizeof(sip_via_hdr_t));
        normalize_via_line(&s.arr[0], st);
    } else {
        for (size_t i=0;i<*s.count;++i) normalize_via_line(&s.arr[i], st);
    }
}

/* ================ 修改 Via 个数（用于 repeat/增删） ================ */
static int add_via_bottom(sip_packet_t *p, uint32_t *st){ /* 追加一跳在末尾 */
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count) return -1;
    if (*s.count >= s.cap) return -1;
    size_t i = (*s.count)++;
    memset(&s.arr[i], 0, sizeof(sip_via_hdr_t));
    normalize_via_line(&s.arr[i], st);
    return (int)i;
}
static int add_via_top(sip_packet_t *p, uint32_t *st){ /* 栈顶插入（代理前插） */
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count) return -1;
    if (*s.count >= s.cap) return -1;
    memmove(&s.arr[1], &s.arr[0], (*s.count) * sizeof(sip_via_hdr_t));
    memset(&s.arr[0], 0, sizeof(sip_via_hdr_t));
    normalize_via_line(&s.arr[0], st);
    (*s.count)++;
    return 0;
}
static void delete_via_idx(sip_packet_t *p, size_t idx){ /* 非法路径：可能导致 0 条 Via */
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count || *s.count==0 || idx >= *s.count) return;
    memmove(&s.arr[idx], &s.arr[idx+1], (*s.count - idx - 1)*sizeof(sip_via_hdr_t));
    (*s.count)--;
}

/* ================ repeat_<msg_type>_via（可重复） ================ */
static void repeat_packet_via(sip_packet_t *p, size_t times, uint32_t *st){
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count) return;
    if (times == 0) return;
    size_t original = *s.count;
    for (size_t t=0; t<times && *s.count < s.cap; ++t){
        int pos = add_via_bottom(p, st);
        if (pos >= 0){
            /* 简单变一点：不同分支、不同比特 */
            make_branch(s.arr[pos].params + strnlen(s.arr[pos].params, sizeof(s.arr[pos].params)),
                        sizeof(s.arr[pos].params) - strnlen(s.arr[pos].params, sizeof(s.arr[pos].params)),
                        st, 1);
        }
    }
    (void)original;
}
/* 为每种类型提供同名封装（按题意） */
void repeat_invite_via (sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E1u; if (p && p->cmd_type==SIP_PKT_INVITE ) repeat_packet_via(p,times,&st); }
void repeat_ack_via    (sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E2u; if (p && p->cmd_type==SIP_PKT_ACK    ) repeat_packet_via(p,times,&st); }
void repeat_bye_via    (sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E3u; if (p && p->cmd_type==SIP_PKT_BYE    ) repeat_packet_via(p,times,&st); }
void repeat_cancel_via (sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E4u; if (p && p->cmd_type==SIP_PKT_CANCEL ) repeat_packet_via(p,times,&st); }
void repeat_register_via(sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E5u; if (p && p->cmd_type==SIP_PKT_REGISTER) repeat_packet_via(p,times,&st); }
void repeat_options_via(sip_packet_t *p, size_t n, unsigned int seed){ size_t times = rint(1,5); uint32_t st=0x517E6u; if (p && p->cmd_type==SIP_PKT_OPTIONS ) repeat_packet_via(p,times,&st); }

/* ================ 变异算子定义 ================ */
typedef enum {
    OP_VIA_PROTO_VARIANTS = 0, /* SIP/2.0/(UDP|TCP|TLS|SCTP|WS|WSS|空|错版本) */
    OP_VIA_PROTO_CASE,         /* 大小写/混排、缺斜杠 */
    OP_VIA_SP_TOGGLE,          /* ' ' / '\t' / '\0' */
    OP_VIA_SENTBY_FORMS,       /* FQDN/IPv4/IPv6(带/不带方括号)/无端口/极值端口 */
    OP_VIA_SENTBY_LONG,        /* 超长/空/仅冒号 */
    OP_VIA_PARAM_BRANCH_GOOD,  /* 合法 branch（z9hG4bK 前缀） */
    OP_VIA_PARAM_BRANCH_BAD,   /* 非法 branch 前缀或随机串 */
    OP_VIA_PARAM_BRANCH_EMPTY, /* branch= 空值 */
    OP_VIA_PARAM_BRANCH_DUP,   /* 重复 branch */
    OP_VIA_PARAM_RPORT_FORMS,  /* rport / rport=0/65535/alpha */
    OP_VIA_PARAM_RECEIVED,     /* received=IP（含非法） */
    OP_VIA_PARAM_MADDR_TTL,    /* maddr=239.x / ttl=0/255/大值 */
    OP_VIA_PARAM_UNKNOWN,      /* 追加未知参数/裸 flag */
    OP_VIA_PARAM_BAD_SYNTAX,   /* 缺分号/多等号/裸 key */
    OP_VIA_NAME_MISSPELL,      /* "Via"/"VIA"/"v"/"ViA"/"Route"(错) */
    OP_VIA_COLON_BAD,          /* ":" / "::" / "; " */
    OP_VIA_CRLF_BAD,           /* "\n" / "\r\n\r" / "" */
    OP_VIA_REORDER,            /* 调换/逆序 Via 列表 */
    OP_VIA_ADD_HOP,            /* 追加一跳（合法） */
    OP_VIA_DELETE_HOP,         /* 删除一跳（可能非法，若为 0） */
    OP_VIA_REPEAT_HOP,         /* 复制某一跳多次（制造环/冗余） */
    OP_VIA_BRANCH_COLLIDE,     /* 让所有 Via 使用相同 branch（冲突） */
    OP_VIA__COUNT
} via_op_t;

/* 辅助：设置/替换 params 为仅包含某个 branch=xxx */
static void via_set_params_branch_only(sip_via_hdr_t *h, const char *val){
    if (!h) return;
    h->params[0]='\0';
    safe_append(h->params, sizeof(h->params), ";branch=");
    safe_append(h->params, sizeof(h->params), val?val:"");
}

/* 对某条 Via 执行一个随机算子 */
static void mutate_via_line(sip_packet_t *p, uint32_t *st){
    via_set_t s = get_via_set(p);
    if (!s.arr || !s.count || *s.count==0) return;
    size_t i = (size_t)rnd_int(st, 0, (int)*s.count - 1);
    sip_via_hdr_t *h = &s.arr[i];
    normalize_via_line(h, st);

    int op = rnd_int(st, 0, OP_VIA__COUNT-1);
    switch (op){
    case OP_VIA_PROTO_VARIANTS: {
        const char *v[] = {"SIP/2.0/UDP","SIP/2.0/TCP","SIP/2.0/TLS","SIP/2.0/SCTP","SIP/2.0/WS","SIP/2.0/WSS","SIP/3.0/TCP","SIP//UDP","SIP/2.0/"}; 
        safe_strcpy(h->sent_protocol, sizeof(h->sent_protocol), v[rnd_int(st,0,(int)(sizeof(v)/sizeof(v[0])-1))]);
    } break;
    case OP_VIA_PROTO_CASE: {
        char tmp[SIP_TOKEN_LEN]; safe_strcpy(tmp, sizeof(tmp), h->sent_protocol);
        for (char *c=tmp; *c; ++c) *c = (rnd_int(st,0,1)? (char)toupper((unsigned char)*c) : (char)tolower((unsigned char)*c));
        safe_strcpy(h->sent_protocol, sizeof(h->sent_protocol), tmp);
    } break;
    case OP_VIA_SP_TOGGLE: {
        int r = rnd_int(st,0,2);
        h->sp = (r==0? ' ' : (r==1? '\t' : '\0'));
    } break;
    case OP_VIA_SENTBY_FORMS: {
        const char *forms[] = {
            "proxy.example.com",
            "10.0.0.1:5060",
            "[2001:db8::1]:5061",
            "2001:db8::1",              /* 缺括号 */
            "gw.example.com:0",         /* 端口 0 */
            "gw.example.com:65535",
            "gw.example.com:65536"      /* 溢出 */
        };
        safe_strcpy(h->sent_by, sizeof(h->sent_by), forms[rnd_int(st,0,(int)(sizeof(forms)/sizeof(forms[0])-1))]);
    } break;
    case OP_VIA_SENTBY_LONG: {
        size_t cap = sizeof(h->sent_by);
        memset(h->sent_by, 'a', cap?cap-1:0);
        if (cap) h->sent_by[cap-1]='\0';
        if (rnd_int(st,0,3)==0) h->sent_by[0]='\0'; /* 空 sent-by */
    } break;
    case OP_VIA_PARAM_BRANCH_GOOD: {
        char b[96]; make_branch(b,sizeof(b),st,1);
        via_set_params_branch_only(h, b);
    } break;
    case OP_VIA_PARAM_BRANCH_BAD: {
        char b[96]; make_branch(b,sizeof(b),st,0); /* 无 z9hG4bK 前缀 */
        via_set_params_branch_only(h, b);
    } break;
    case OP_VIA_PARAM_BRANCH_EMPTY: {
        via_set_params_branch_only(h, "");
    } break;
    case OP_VIA_PARAM_BRANCH_DUP: {
        char b[64]; make_branch(b,sizeof(b),st,1);
        safe_append(h->params, sizeof(h->params), ";branch=");
        safe_append(h->params, sizeof(h->params), b);
    } break;
    case OP_VIA_PARAM_RPORT_FORMS: {
        const char *v[] = {";rport",";rport=0",";rport=65535",";rport=abc"};
        safe_append(h->params, sizeof(h->params), v[rnd_int(st,0,3)]);
    } break;
    case OP_VIA_PARAM_RECEIVED: {
        const char *v[] = {";received=203.0.113.7",";received=2001:db8::2",";received=bad.ip.addr"};
        safe_append(h->params, sizeof(h->params), v[rnd_int(st,0,2)]);
    } break;
    case OP_VIA_PARAM_MADDR_TTL: {
        const char *v[] = {";maddr=239.1.2.3",";ttl=0",";ttl=255",";ttl=9999"};
        safe_append(h->params, sizeof(h->params), v[rnd_int(st,0,3)]);
    } break;
    case OP_VIA_PARAM_UNKNOWN: {
        const char *v[] = {";foo=bar",";ob",";lr",";x-zz",";k=v=w"};
        safe_append(h->params, sizeof(h->params), v[rnd_int(st,0,4)]);
    } break;
    case OP_VIA_PARAM_BAD_SYNTAX: {
        const char *v[] = {"branch==abc","branch","key value",";;;=","branch=abc=def","branchabc"};
        safe_strcpy(h->params, sizeof(h->params), "");
        safe_append(h->params, sizeof(h->params), ";");
        safe_append(h->params, sizeof(h->params), v[rnd_int(st,0,5)]);
    } break;
    case OP_VIA_NAME_MISSPELL: {
        const char *v[] = {"Via","VIA","v","ViA","Route"}; /* 最后一个明显错误 */
        safe_strcpy(h->name, sizeof(h->name), v[rnd_int(st,0,4)]);
    } break;
    case OP_VIA_COLON_BAD: {
        const char *v[] = {":", "::", "; "};
        safe_strcpy(h->colon_space, sizeof(h->colon_space), v[rnd_int(st,0,2)]);
    } break;
    case OP_VIA_CRLF_BAD: {
        const char *v[] = {"\n", "\r\n\r", ""};
        safe_strcpy(h->crlf, sizeof(h->crlf), v[rnd_int(st,0,2)]);
    } break;
    case OP_VIA_REORDER: {
        via_set_t ss = s;
        if (*ss.count >= 2){
            /* 简单逆序 */
            for (size_t l=0,r=*ss.count-1; l<r; ++l, --r){
                sip_via_hdr_t tmp = ss.arr[l]; ss.arr[l]=ss.arr[r]; ss.arr[r]=tmp;
            }
        }
    } break;
    case OP_VIA_ADD_HOP: {
        add_via_top(p, st); /* 代理前插：合法 */
    } break;
    case OP_VIA_DELETE_HOP: {
        if (*s.count > 0) delete_via_idx(p, (size_t)rnd_int(st,0,(int)*s.count-1)); /* 若删成 0，则形成非法场景 */
    } break;
    case OP_VIA_REPEAT_HOP: {
        if (*s.count > 0 && *s.count < s.cap){
            size_t src = (size_t)rnd_int(st,0,(int)*s.count-1);
            int dst = add_via_bottom(p, st);
            if (dst >= 0) s = get_via_set(p), memcpy(&s.arr[dst], &s.arr[src], sizeof(sip_via_hdr_t));
        }
    } break;
    case OP_VIA_BRANCH_COLLIDE: {
        if (*s.count > 1){
            char b[96]; make_branch(b,sizeof(b),st,1);
            for (size_t j=0;j<*s.count;++j) via_set_params_branch_only(&s.arr[j], b);
        }
    } break;
    default: break;
    }
}

/* ================ 主入口：批量变异 Via ================ */
void mutate_sip_via(sip_packet_t *pkts, size_t count, unsigned seed){
    if (!pkts || count==0) return;
    int max_ops_per_pkt = 6;
    uint32_t st = seed ? (uint32_t)seed : 0xCAFEBABE;

    for (size_t i=0;i<count;++i){
        ensure_min_one_via(&pkts[i], &st);
    }
    for (size_t i=0;i<count;++i){
        int ops = rnd_int(&st, 1, (max_ops_per_pkt > 12 ? 12 : max_ops_per_pkt));
        for (int k=0;k<ops;++k) mutate_via_line(&pkts[i], &st);
        /* 可选：保证至少 1 条 Via（若你不想留下“非法无 Via”末态） */
        ensure_min_one_via(&pkts[i], &st);
    }
}

/* （可选）合法化基线：统一规范、生成有效 branch 等 */
void legalize_via_packets(sip_packet_t *pkts, size_t count){
    uint32_t st = 0x1234ABCDu;
    if (!pkts) return;
    for (size_t i=0;i<count;++i){
        ensure_min_one_via(&pkts[i], &st);
        via_set_t s = get_via_set(&pkts[i]);
        for (size_t j=0;j<(s.count?*s.count:0);++j){
            sip_via_hdr_t *h = &s.arr[j];
            /* 规范字段 */
            safe_strcpy(h->name, sizeof(h->name), "Via");
            safe_strcpy(h->colon_space, sizeof(h->colon_space), ": ");
            safe_strcpy(h->sent_protocol, sizeof(h->sent_protocol), "SIP/2.0/UDP");
            h->sp = ' ';
            if (!strchr(h->sent_by, ':')) safe_append(h->sent_by, sizeof(h->sent_by), ":5060");
            /* 确保 branch 合法 */
            char b[96]; make_branch(b,sizeof(b),&st,1);
            via_set_params_branch_only(h, b);
            safe_strcpy(h->crlf, sizeof(h->crlf), "\r\n");
        }
    }
}



/* —— 本地工具：一次性播种 —— */
static void rng_seed_once(void){
    static int seeded = 0;
    if(!seeded){
        seeded = 1;
        srand((unsigned)time(NULL));
    }
}
static unsigned rnd32(void){
    /* rand() 可能只有 15 位，这里做个简单拼接 */
    return ((unsigned)rand() << 16) ^ (unsigned)rand();
}

typedef void (*sip_mutator_fn)(sip_packet_t *pkt, size_t num_packets, unsigned seed);
/* 按 sip_mutators.c 中已实现/声明的 mutator 组织 */
static sip_mutator_fn sip_invite_mutators[] = {
    /* ====== Request-Line / 路由基线 ====== */
    mutate_sip_request_uri,                       /* Request-URI 变异 */ 

    /* ====== 对话相关头 ====== */
    mutate_from_headers,                      /* From: 变异 */
    mutate_to_headers,                        /* To:   变异 */
    mutate_sip_via,                       /* Via:  变异（含多跳处理） */
    mutate_call_id,
    mutate_sip_cseq,

    /* ====== 常见可选头（INVITE 结构体中均有） ====== */
    /* Accept 系列 */
    mutate_accept_media_type,                 /* Accept: type */
    mutate_accept_sub_type_and_params,        /* Accept: subtype/params */

    /* 内容与实体 */
    mutate_content_type_headers,              /* Content-Type */
    mutate_content_length_headers,            /* Content-Length */


    /* 认证类 */
    mutate_authorization_headers,             /* Authorization */
    mutate_proxy_authorization_headers,       /* Proxy-Authorization */

    /* 时间/寿命/加密 */
    mutate_date_rfc1123,                      /* Date */
    mutate_encryption_fields,                 /* Encryption (historic) */
    mutate_expires_values,                    /* Expires */

    /* 其他通用头 */
    // add_invite_hide,
    delete_invite_hide,
    mutate_hide_headers,                       /* Hide (deprecated) */
    mutate_max_forwards_headers,              /* Max-Forwards */
    // add_invite_priority,
    delete_invite_priority,
    mutate_priority_headers,                   /* Priority */
    mutate_require_headers,                   /* Require */
    add_invite_response_key,
    delete_invite_response_key,
    repeat_invite_response_key,
    mutate_response_key_headers,               /* Response-Key */
    mutate_subject_headers,                      /* Subject */
    mutate_timestamp_headers,                 /* Timestamp */
    mutate_user_agent_headers,                /* User-Agent */
    mutate_record_route_headers,              /* Record-Route（可重复头） */

    /* ====== INVITE 专属/便捷 add/delete/repeat 助手（文件中已提供者） ====== */
    /* Accept 便捷操作 */
    add_INVITE_media_type,
    delete_INVITE_media_type,

    /* Date 便捷操作 */
    add_INVITE_rfc1123,
    delete_INVITE_rfc1123,

    /* Expires / Hide / Priority / Max-Forwards 便捷操作 */
    // add_invite_max_forwards, 
    delete_invite_max_forwards,

    /* Proxy-Require（按行追加标签） */
    repeat_invite_proxy_require,

    /* 可重复头：Via（追加多跳等） */
    repeat_invite_via,
};



static sip_mutator_fn sip_ack_mutators[] = {
    /* ===== Request-Line ===== */
    mutate_sip_request_uri,

    /* ===== Dialog headers ===== */
    mutate_from_headers,
    mutate_to_headers,
    mutate_sip_via,
    mutate_call_id,
    mutate_sip_cseq,

    /* ===== Auth / Options ===== */
    mutate_authorization_headers,
    mutate_proxy_authorization_headers,
    mutate_proxy_require_headers,
    mutate_require_headers,

    /* ===== Routing (repeatables) ===== */
    mutate_record_route_headers,
    mutate_route_headers,

    /* ===== Payload & Content ===== */
    mutate_content_type_headers,
    mutate_content_length_headers,
    mutate_body_inv_ack_reg_opt,

    /* ===== Misc ===== */
    mutate_date_rfc1123,
    mutate_encryption_fields,
    mutate_hide_headers,
    mutate_max_forwards_headers,
    mutate_organization_headers,
    mutate_timestamp_headers,
    mutate_user_agent_headers,

    /* ===== add/delete/repeat helpers for ACK ===== */
    /* Date */
    add_ACK_rfc1123, delete_ACK_rfc1123,

    /* Authorization */
    // add_ack_authorization, 
    delete_ack_authorization,

    /* Proxy-Authorization (repeatable) */
    // add_ack_proxy_authorization, 
    delete_ack_proxy_authorization,
    repeat_ack_proxy_authorization,

    /* Proxy-Require (repeatable) */
    // add_ack_proxy_require, 
    delete_ack_proxy_require,
    repeat_ack_proxy_require,

    /* Require (repeatable) */
    add_ack_require, 
    delete_ack_require,
    repeat_ack_require,

    /* Record-Route (repeatable) */
    add_ack_record_route, delete_ack_record_route,
    repeat_ack_record_route,

    /* Route (repeatable) */
    // add_ack_route, 
    delete_ack_route,
    repeat_ack_route,

    /* Content-* & Body */
    // add_ack_content_type, 
    delete_ack_content_type,
    // add_ack_content_length, 
    delete_ack_content_length,
    add_ack_body, 
    delete_ack_body,

    /* Misc optionals */
    // add_ack_hide, 
    delete_ack_hide,
    // add_ack_max_forwards, 
    delete_ack_max_forwards,
    // add_ack_organization, 
    delete_ack_organization,
    add_ack_timestamp, delete_ack_timestamp,
    add_ack_user_agent, delete_ack_user_agent,
};


/* BYE */
static sip_mutator_fn sip_bye_mutators[] = {
    /* ===== Request-Line ===== */
    mutate_sip_request_uri,

    /* ===== Dialog headers ===== */
    mutate_from_headers,
    mutate_to_headers,
    mutate_sip_via,
    mutate_call_id,
    mutate_sip_cseq,

        /* ===== Auth / Options ===== */
    mutate_authorization_headers,
    // add_bye_authorization, 
    delete_bye_authorization,
    mutate_proxy_authorization_headers,
    // add_bye_proxy_authorization, 
    delete_bye_proxy_authorization,
    repeat_bye_proxy_authorization,
    mutate_proxy_require_headers,
    // add_bye_proxy_require, 
    delete_bye_proxy_require,
    repeat_bye_proxy_require,
    mutate_require_headers,
    add_bye_require, delete_bye_require,
    repeat_bye_require,

    /* ===== Routing (repeatables) ===== */
    mutate_record_route_headers,
    add_bye_record_route, delete_bye_record_route,
    repeat_bye_record_route,
    mutate_route_headers,
    // add_bye_route, 
    delete_bye_route,
    repeat_bye_route,

    /* ===== Misc ===== */
     /* Date */
    add_BYE_rfc1123, delete_BYE_rfc1123,
    mutate_date_rfc1123,


    mutate_encryption_fields,
    // add_bye_hide, 
    delete_bye_hide,
    mutate_hide_headers,

    // add_bye_max_forwards,
     delete_bye_max_forwards,
    mutate_max_forwards_headers,

    mutate_timestamp_headers,
    add_bye_timestamp, delete_bye_timestamp,

    mutate_user_agent_headers,
    add_bye_user_agent, delete_bye_user_agent,

    legalize_via_packets,
    legalize_from_packets,
    legalize_to_packets_out_of_dialog,

};


/* CANCEL */
static sip_mutator_fn sip_cancel_mutators[] = {
    /* ===== Request-Line ===== */
    mutate_sip_request_uri,

    /* ===== Dialog headers ===== */
    mutate_from_headers,
    mutate_to_headers,
    mutate_sip_via,
    mutate_call_id,
    mutate_sip_cseq,

    /* ===== Auth / Options ===== */
    mutate_authorization_headers,
    // add_cancel_authorization, 
    delete_cancel_authorization,
    mutate_proxy_authorization_headers,
    // add_cancel_proxy_authorization, 
    delete_cancel_proxy_authorization,
    repeat_cancel_proxy_authorization,
    mutate_proxy_require_headers,
    // add_cancel_proxy_require, 
    delete_cancel_proxy_require,
    repeat_cancel_proxy_require,
    mutate_require_headers,
    add_cancel_require, delete_cancel_require,
    repeat_cancel_require,

    /* ===== Routing (repeatables) ===== */
    mutate_record_route_headers,
    add_cancel_record_route, delete_cancel_record_route,
    repeat_cancel_record_route,
    mutate_route_headers,
    add_cancel_route, delete_cancel_route,
    repeat_cancel_route,

    /* ===== Misc ===== */
    /* Date */
    mutate_date_rfc1123,
    add_CANCEL_rfc1123, delete_CANCEL_rfc1123,

    /* Encryption / Hide / Max-Forwards */
    mutate_encryption_fields,
    mutate_hide_headers,     
    //  add_cancel_hide,
    delete_cancel_hide,
    mutate_max_forwards_headers,
    // add_cancel_max_forwards,
     delete_cancel_max_forwards,

    /* Response-Key (optional) */
    mutate_response_key_headers,
    add_cancel_response_key, delete_cancel_response_key,
    repeat_cancel_response_key,

    /* Timestamp & UA */
    mutate_timestamp_headers, add_cancel_timestamp, delete_cancel_timestamp,
    mutate_user_agent_headers, add_cancel_user_agent, delete_cancel_user_agent,

    /* ===== Legalizers ===== */
    legalize_via_packets,
    legalize_from_packets,
    legalize_to_packets_out_of_dialog,
};


/* REGISTER */
static sip_mutator_fn sip_register_mutators[] = {
    /* ===== Request-Line ===== */
    mutate_sip_request_uri,

    /* ===== Dialog headers ===== */
    mutate_from_headers,
    mutate_to_headers,
    mutate_sip_via,
    mutate_call_id,
    mutate_sip_cseq,

    /* ===== Accept 系列 ===== */
    mutate_accept_media_type,
    mutate_accept_sub_type_and_params,
    add_REGISTER_media_type, delete_REGISTER_media_type,

    /* ===== Auth ===== */
    mutate_authorization_headers,
    // add_register_authorization,
    delete_register_authorization,
    mutate_proxy_authorization_headers,
    // add_register_proxy_authorization, 
    delete_register_proxy_authorization,
    repeat_register_proxy_authorization,

    /* ===== Routing (repeatables) ===== */
    mutate_record_route_headers,
    add_register_record_route, delete_register_record_route,
    repeat_register_record_route,
    mutate_route_headers,
    // add_register_route, 
    delete_register_route,
    repeat_register_route,


    /* ===== Content-* & Body ===== */
    mutate_content_type_headers,
    mutate_content_length_headers,
    mutate_body_inv_ack_reg_opt,
    // add_register_content_length, 
    delete_register_content_length,
    add_register_body,           delete_register_body,

    /* ===== Misc ===== */
    /* Date */
    mutate_date_rfc1123,
    add_REGISTER_rfc1123, delete_REGISTER_rfc1123,

    /* Hide / Max-Forwards */
    mutate_hide_headers, 
    // add_register_hide, 
    delete_register_hide,
    mutate_max_forwards_headers,
    // add_register_max_forwards, 
    delete_register_max_forwards,

    /* Proxy-Require / Require (repeatables) */
    mutate_proxy_require_headers,
    // add_register_proxy_require, 
    delete_register_proxy_require,
    repeat_register_proxy_require,
    mutate_require_headers,
    add_register_require, delete_register_require,
    repeat_register_require,

    /* Response-Key (optional) */
    mutate_response_key_headers,
    add_register_response_key, delete_register_response_key,
    repeat_register_response_key,

    /* Timestamp & UA */
    mutate_timestamp_headers, add_register_timestamp, delete_register_timestamp,
    mutate_user_agent_headers, add_register_user_agent, delete_register_user_agent,

    /* ===== Legalizers ===== */
    legalize_via_packets,
    legalize_from_packets,
    legalize_to_packets_out_of_dialog,
};


/* OPTIONS */
static sip_mutator_fn sip_options_mutators[] = {
    /* ===== Request-Line ===== */
    mutate_sip_request_uri,

    /* ===== Dialog headers ===== */
    mutate_from_headers,
    mutate_to_headers,
    mutate_sip_via,
    mutate_call_id,
    mutate_sip_cseq,

    /* ===== Accept 系列 ===== */
    mutate_accept_media_type,
    mutate_accept_sub_type_and_params,
    add_OPTIONS_media_type, delete_OPTIONS_media_type,

    /* ===== Auth ===== */
    mutate_authorization_headers,
    // add_options_authorization, 
    delete_options_authorization,
    mutate_proxy_authorization_headers,
    // add_options_proxy_authorization, 
    delete_options_proxy_authorization,
    repeat_options_proxy_authorization,

    /* ===== Routing (repeatables) ===== */
    mutate_record_route_headers,
    add_options_record_route, delete_options_record_route,
    repeat_options_record_route,
    mutate_route_headers,
    // add_options_route, 
    delete_options_route,
    repeat_options_route,

    /* ===== Content-* & Body ===== */
    mutate_content_type_headers,
    mutate_content_length_headers,
    mutate_body_inv_ack_reg_opt,
    // add_options_content_length, 
    delete_options_content_length,
    add_options_body,           delete_options_body,

    /* ===== Misc ===== */
    /* Date */
    mutate_date_rfc1123,
    add_OPTIONS_rfc1123, delete_OPTIONS_rfc1123,

    /* Hide / Max-Forwards */
    mutate_hide_headers, 
    // add_options_hide, 
    delete_options_hide,
    mutate_max_forwards_headers,
    // add_options_max_forwards, 
    delete_options_max_forwards,

    /* Proxy-Require / Require (repeatables) */
    mutate_proxy_require_headers,
    // add_options_proxy_require, 
    delete_options_proxy_require,
    repeat_options_proxy_require,
    mutate_require_headers,
    add_options_require, delete_options_require,
    repeat_options_require,

    /* Response-Key (optional) */
    mutate_response_key_headers,
    add_options_response_key, delete_options_response_key,
    repeat_options_response_key,

    /* Timestamp & UA */
    mutate_timestamp_headers, add_options_timestamp, delete_options_timestamp,
    mutate_user_agent_headers, add_options_user_agent, delete_options_user_agent,

    /* ===== Legalizers ===== */
    legalize_via_packets,
    legalize_from_packets,
    legalize_to_packets_out_of_dialog,
};


/* —— 针对不同 SIP 方法的小分发器 —— */
static void dispatch_sip_invite_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_invite_mutators)/sizeof(sip_invite_mutators[0]));
    sip_invite_mutators[idx](p, 1, seed);
}
static void dispatch_sip_ack_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_ack_mutators)/sizeof(sip_ack_mutators[0]));
    sip_ack_mutators[idx](p, 1, seed);
}
static void dispatch_sip_bye_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_bye_mutators)/sizeof(sip_bye_mutators[0]));
    sip_bye_mutators[idx](p, 1, seed);
}
static void dispatch_sip_cancel_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_cancel_mutators)/sizeof(sip_cancel_mutators[0]));
    sip_cancel_mutators[idx](p, 1, seed);
}
static void dispatch_sip_register_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_register_mutators)/sizeof(sip_register_mutators[0]));
    sip_register_mutators[idx](p, 1, seed);
}
static void dispatch_sip_options_mutation(sip_packet_t *p, unsigned seed){
    if(!p) return;
    size_t idx = rand() % (sizeof(sip_options_mutators)/sizeof(sip_options_mutators[0]));
    sip_options_mutators[idx](p, 1, seed);
}

/* —— 顶层分发器（与 RTSP 示例等价的风格） —— */
void dispatch_sip_multiple_mutations(sip_packet_t *arr, int num_packets, int rounds){
    if(!arr || num_packets <= 0) return;
    rng_seed_once();
    if(rounds <= 0) rounds = 1;

    for(int i = 0; i < rounds; ++i){
        int mutate_index = rand() % num_packets;
        sip_packet_t *p = &arr[mutate_index];
        unsigned seed = rnd32();

        switch (p->cmd_type){
            case SIP_PKT_INVITE:   dispatch_sip_invite_mutation(p, seed);   break;
            case SIP_PKT_ACK:      dispatch_sip_ack_mutation(p, seed);      break;
            case SIP_PKT_BYE:      dispatch_sip_bye_mutation(p, seed);      break;
            case SIP_PKT_CANCEL:   dispatch_sip_cancel_mutation(p, seed);   break;
            case SIP_PKT_REGISTER: dispatch_sip_register_mutation(p, seed); break;
            case SIP_PKT_OPTIONS:  dispatch_sip_options_mutation(p, seed);  break;
            default: /* SIP_PKT_UNKNOWN */ break;
        }
    }
}