/* smtp mutators source file */
#include "smtp.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>


static void set_cstr(char dst[], size_t cap, const char *s){
    if (!dst || cap == 0) return;
    if (!s) s = "";
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, s, n);
    dst[n] = '\0';
}

static size_t emit_run(char *dst, size_t cap, char ch, size_t len){
    if (!dst || cap == 0) return 0;
    size_t n = len < (cap-1) ? len : (cap-1);
    memset(dst, (unsigned char)ch, n);
    dst[n] = '\0';
    return n;
}

static void toggle_case(char *s){
    if (!s) return;
    for (; *s; ++s){
        unsigned char c = (unsigned char)*s;
        if (c >= 'a' && c <= 'z') *s = (char)toupper(c);
        else if (c >= 'A' && c <= 'Z') *s = (char)tolower(c);
    }
}

static void build_multilabel(char *dst, size_t cap,
                             size_t labels, size_t label_len, char base_ch){
    if (!dst || cap == 0){ return; }
    size_t pos = 0;
    for (size_t i = 0; i < labels; ++i){
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

int mutate_helo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 21 };
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELO) continue;

        smtp_helo_packet_t *h = &pkts[i].pkt.helo;

        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "HELO");
        if (h->space[0] == '\0')   set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "example.com."); break;
            case 3:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break;  
            case 4:  set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break; 
            case 5: { 
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); /* aaa.bbb.ccc... */
                break;
            }
            case 6: {
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x'); 
                break;
            }

            case 7: {
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
            case 8: { 
                char tmp[SMTP_SZ_DOMAIN];
                size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)) { tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 9:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;          
            case 10: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;      
            case 11: set_cstr(h->domain, sizeof h->domain, ""); break;              
            case 12: set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;     
            case 13: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;         
            case 14: set_cstr(h->domain, sizeof h->domain, "[IPv6:]"); break;       
            case 15: set_cstr(h->domain, sizeof h->domain, "[127.0.0.1"); break;    
            case 16: {
                set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>");
                break;
            }
            case 17: set_cstr(h->domain, sizeof h->domain, "my host"); break;       
            case 18: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break;
            case 19: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;     
            case 20: {
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

        if (op % 5 == 0 && h->domain[0]){
            toggle_case(h->domain);
        }

        mutated++;
    }

    return (int)mutated;
}


int mutate_ehlo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 22 };
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EHLO) continue;

        smtp_ehlo_packet_t *h = &pkts[i].pkt.ehlo;

        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "EHLO");
        if (h->space[0]   == '\0') set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "example.com."); break;
            case 3:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break; 
            case 4:  set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break; 
            case 5: { set_cstr(h->domain, sizeof h->domain, "");
                      build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); break; }
            case 6: { set_cstr(h->domain, sizeof h->domain, "");
                      build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x'); break; }

            case 7: {
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
            case 8: { 
                char tmp[SMTP_SZ_DOMAIN]; size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)){ tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 9:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;           
            case 10: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;       
            case 11: set_cstr(h->domain, sizeof h->domain, ""); break;               
            case 12: set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;      
            case 13: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;          
            case 14: set_cstr(h->domain, sizeof h->domain, "[IPv6:]"); break;        
            case 15: set_cstr(h->domain, sizeof h->domain, "[127.0.0.1"); break;     
            case 16: set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>"); break; 
            case 17: set_cstr(h->domain, sizeof h->domain, "my host"); break;      
            case 18: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break;
            case 19: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;     
            case 20: { 
                size_t cap = sizeof h->domain;
                if (cap > 1){ memset(h->domain, 'D', cap-1); h->domain[cap-1] = '\0'; }
                else h->domain[0] = '\0';
                break;
            }
            case 21: set_cstr(h->domain, sizeof h->domain, "[IPv6:GGGG::1]"); break; 
            default: break;
        }

        if (op % 5 == 0 && h->domain[0]) toggle_case(h->domain);

        mutated++;
    }

    return (int)mutated; 
}


static void build_long_domain(char *out, size_t cap){
    if (!out || cap == 0) return;
    const char *tail = "com";
    size_t pos = 0;
    while (pos + 63 + 1 + strlen(tail) + 1 < cap) {
        memset(out + pos, 'a', 63); pos += 63;
        out[pos++] = '.';
    }
    if (pos + 3 < cap) { memcpy(out+pos, tail, 3); pos += 3; }
    out[pos < cap ? pos : cap-1] = '\0';
}

static void build_long_local(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = (cap-1 > 64 ? 64 : cap-1);
    memset(out, 'L', n ? n-1 : 0);
    if (n) out[n-1] = 'x';
    out[n] = '\0';
}


static void ensure_mail_prefix(smtp_mail_packet_t *m){
    if (!m) return;
    if (m->command[0] == '\0') set_cstr(m->command, sizeof m->command, "MAIL");
    if (m->space1[0]  == '\0') set_cstr(m->space1,  sizeof m->space1,  " ");
    if (m->from_keyword[0] == '\0') set_cstr(m->from_keyword, sizeof m->from_keyword, "FROM:");
}

int mutate_mail_reverse_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 }; 
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;

        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            case 0:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<>"); break;
            case 1:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com>"); break;
            case 2:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user.name+tag@example.com>"); break;
            case 3:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<\"weird name\"@example.com>"); break;
            case 4:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[127.0.0.1]>"); break;       
            case 5:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:2001:db8::1]>"); break;
            case 6:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<postmaster>"); break;          

            case 7:  set_cstr(m->reverse_path, sizeof m->reverse_path,
                              "<@a.example,@b.example:user@c.example>"); break;

            case 8: {
                char local[128]; build_long_local(local, sizeof local);
                char dom[256];   build_long_domain(dom, sizeof dom);
                char tmp[SMTP_SZ_PATH];
                snprintf(tmp, sizeof tmp, "<%s@%s>", local, dom);
                set_cstr(m->reverse_path, sizeof m->reverse_path, tmp);
            } break;

            case 9: {
                size_t cap = sizeof m->reverse_path;
                if (cap <= 2) { set_cstr(m->reverse_path, cap, ""); break; }
                m->reverse_path[0] = '<';
                memset(m->reverse_path+1, 'A', cap-3);
                m->reverse_path[cap-2] = '>';
                m->reverse_path[cap-1] = '\0';
            } break;

            case 10: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com"); break; 
            case 11: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com>"); break; 
            case 12: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com"); break;  
            case 13: set_cstr(m->reverse_path, sizeof m->reverse_path, "<userexample.com>"); break; 
            case 14: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@-bad-.com>"); break;  
            case 15: set_cstr(m->reverse_path, sizeof m->reverse_path, "<u..ser@example.com>"); break; 
            case 16: set_cstr(m->reverse_path, sizeof m->reverse_path, "<us er@example.com>"); break; 
            case 17: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@\r\nRCPT TO:evil@example.com>"); break; 
            case 18: set_cstr(m->reverse_path, sizeof m->reverse_path, "<用户@例子.测试>"); break; 
            case 19: set_cstr(m->reverse_path, sizeof m->reverse_path, "<xn--fsqu00a@xn--0zwm56d.xn--0zwm56d>"); break; 
            case 20: set_cstr(m->reverse_path, sizeof m->reverse_path,
                              "<\"very.(),:;<>[]\\\".VERY.\\\"very@\\ \\\"very\\\".unusual\"@strange.example.com>"); break; 
            case 21: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:]>"); break; 
            case 22: set_cstr(m->reverse_path, sizeof m->reverse_path, "<@>"); break; 
            case 23: set_cstr(m->reverse_path, sizeof m->reverse_path, ""); break;    

            default: break;
        }

        mutated++;
    }

    return (int)mutated;
}


static void build_long_envid(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = cap - 1;
    for (size_t i = 0; i < n; ++i) out[i] = (i % 2) ? '9' : 'A';
    out[n] = '\0';
}


int add_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        if (m->optional_args[0] == '\0'){
            set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=12345 BODY=7BIT");
            changed++;
        }
    }
    return changed;
}

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

int mutate_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };
    int mutated = 0;

    char buf[SMTP_SZ_OPTARGS];
    char envid[64];

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        unsigned op = (op_idx++) % OPS;

        switch (op){
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

            case 11:
                set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=4294967295");
                break;
            case 12:
                build_long_envid(envid, sizeof envid);
                snprintf(buf, sizeof buf, "ENVID=%s", envid);
                set_cstr(m->optional_args, sizeof m->optional_args, buf);
                break;

            case 13: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=-1"); break;
            case 14: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=0x100"); break;
            case 15: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE"); break; 
            case 16: set_cstr(m->optional_args, sizeof m->optional_args, "BODY=9BIT"); break; 
            case 17: set_cstr(m->optional_args, sizeof m->optional_args, "AUTH="); break; 
            case 18: set_cstr(m->optional_args, sizeof m->optional_args, "FROB=1"); break;
            case 19: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1\r\nRCPT TO:<evil@example.com>"); break;  
            case 20: set_cstr(m->optional_args, sizeof m->optional_args,
                              " SIZE=1   BODY=8BITMIME  "); break; 
            case 21: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1;BODY=8BITMIME"); break; 
            case 22: set_cstr(m->optional_args, sizeof m->optional_args,
                              "SIZE=1 SIZE=2"); break; 
            case 23: {
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

    return mutated; 
}


static void ensure_rcpt_prefix(smtp_rcpt_packet_t *r){
    if (!r) return;
    if (!r->command[0])   set_cstr(r->command,   sizeof r->command,   "RCPT");
    if (!r->space1[0])    set_cstr(r->space1,    sizeof r->space1,    " ");
    if (!r->to_keyword[0])set_cstr(r->to_keyword,sizeof r->to_keyword,"TO:");
}

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

static void cat_repeat(char *dst, size_t cap, char ch, size_t n){
    if (!dst || !cap || n == 0) return;
    size_t cur = strlen(dst);
    if (cur >= cap) { dst[cap-1] = '\0'; return; }
    size_t rem = cap - 1 - cur;
    if (n > rem) n = rem;
    memset(dst + cur, (unsigned char)ch, n);
    dst[cur + n] = '\0';
}

static void build_route_addr(char *out, size_t cap){
    if (!out || cap == 0) return;
    out[0] = '\0';
    cat_s(out, cap, "<");
    for (int i = 0; i < 16; ++i){
        char hop[64];
        snprintf(hop, sizeof hop, "@r%d.example,", i);
        size_t before = strlen(out);
        cat_s(out, cap, hop);
        if (strlen(out) == before) break; 
    }
    cat_s(out, cap, "user@example.com>");
}

int mutate_rcpt_forward_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 }; 
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);

        unsigned op = (op_idx++) % OPS;

        switch (op){

        case 0:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<alice@example.com>"); break;
        case 1:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"weird name\"@example.com>"); break;
        case 2:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user+tag@example.com>"); break;
        case 3:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[192.0.2.1]>"); break;  /* IPv4 literal */
        case 4:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:2001:db8::1]>"); break;
        case 5:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<@a.example,@b.example:user@example.net>"); break; 
        case 6:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@xn--exmple-cua.com>"); break; /* IDNA/punycode */
        case 7:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<δοκιμή@παράδειγμα.δοκιμή>"); break; 

        case 8:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"a\\\"b\"@example.com>"); break;
        case 9:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"very..dot\"@example.com>"); break;

        case 10: set_cstr(r->forward_path, SMTP_SZ_PATH, "user@example.com"); break;  
        case 11: set_cstr(r->forward_path, SMTP_SZ_PATH, "<>"); break;              
        case 12: set_cstr(r->forward_path, SMTP_SZ_PATH, "<userexample.com>"); break; 
        case 13: set_cstr(r->forward_path, SMTP_SZ_PATH, "<.user.@example..com>"); break; 
        case 14: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user @example.com>"); break;    
        case 15: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@-bad-.com>"); break;      
        case 16: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@example.com.>"); break;   
        case 17: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:fe80::1%25eth0]>"); break; 

        case 18: set_cstr(r->forward_path, SMTP_SZ_PATH, "<victim@example.com\r\nDATA>"); break;
        case 19: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@\x01example.com>"); break;

        case 20: {
            char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
            cat_s(tmp, sizeof tmp, "<");
            cat_repeat(tmp, sizeof tmp, 'A', 256); 
            cat_s(tmp, sizeof tmp, "@example.com>");
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 21: {
            char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
            cat_s(tmp, sizeof tmp, "<u@");
            for (int j = 0; j < 20; ++j){
                char lab[16]; snprintf(lab, sizeof lab, "d%d.", j);
                size_t before = strlen(tmp);
                cat_s(tmp, sizeof tmp, lab);
                if (strlen(tmp) == before) break;
            }
            cat_s(tmp, sizeof tmp, "example>");
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 22: {
            char tmp[SMTP_SZ_PATH]; build_route_addr(tmp, sizeof tmp);
            set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
        } break;

        case 23:
            set_cstr(r->forward_path, SMTP_SZ_PATH, "<host!user>");
            break;

        default: break;
        }

        mutated++;
    }

    return mutated;
}


int add_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int added = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);
        if (!r->optional_args[0]){
            set_cstr(r->optional_args, sizeof r->optional_args,
                     "NOTIFY=SUCCESS,DELAY,FAILURE ORCPT=rfc822;user@example.com");
            added++;
        }
    }
    return added;
}


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
        case 0:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS,DELAY,FAILURE"); break;
        case 1:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "notify=never"); break;
        case 2:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;Bob@example.com"); break;
        case 3:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=utf-8;δοκιμή@παράδειγμα.δοκιμή"); break; 
        case 4:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS ORCPT=rfc822;user@example.com"); break;

        case 5:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NoTiFy = success , failure"); break;
        case 6:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=\"rfc822;user@example.com\""); break; 
        case 7:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=\tsuccess,delay"); break; 

        case 8:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY="); break;                      
        case 9:  set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY"); break;                       
        case 10: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822 user@example.com"); break; 
        case 11: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=success,unknown"); break;        
        case 12: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=badtype;user@example.com"); break;

        case 13: set_cstr(r->optional_args, sizeof r->optional_args,
                          "FOO=bar"); break;                       
        case 14: set_cstr(r->optional_args, sizeof r->optional_args,
                          "X-LONGKEY="); break;                   

        case 15: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=SUCCESS NOTIFY=NEVER"); break;  
        case 16: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;u@example.com ORCPT=rfc822;v@example.net"); break;

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

        case 19: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;user@\x01example.com"); break;
        case 20: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=success\r\nDATA"); break;       

        case 21: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY =\tNEVER"); break;
        case 22: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY==NEVER"); break;                 
        case 23: set_cstr(r->optional_args, sizeof r->optional_args,
                          "=NEVER"); break;                       

        case 24: set_cstr(r->optional_args, sizeof r->optional_args,
                          "ORCPT=rfc822;u@example.com   NOTIFY=SUCCESS,FAILURE"); break;
        case 25: set_cstr(r->optional_args, sizeof r->optional_args,
                          "NOTIFY=,," ); break;                    
        default: break;
        }

        mutated++;
    }

    return mutated; 
}


static void ensure_vrfy_prefix(smtp_vrfy_packet_t *v){
    if (!v) return;
    if (!v->command[0]) set_cstr(v->command, sizeof v->command, "VRFY");
    if (!v->crlf[0])    set_cstr(v->crlf,    sizeof v->crlf,    "\r\n");
    if (!v->space[0]) set_cstr(v->space, sizeof v->space, " ");
}

int mutate_vrfy_string(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_VRFY) continue;
        smtp_vrfy_packet_t *v = &pkts[i].pkt.vrfy;

        ensure_vrfy_prefix(v);

        unsigned op = (op_idx++) % OPS;

        switch (op){
        case 0:  set_cstr(v->string, sizeof v->string, "user@example.com"); break;
        case 1:  set_cstr(v->string, sizeof v->string, "postmaster"); break; 
        case 2:  set_cstr(v->string, sizeof v->string, "Full Name <user@example.com>"); break;
        case 3:  set_cstr(v->string, sizeof v->string, "\"weird name\"@example.com"); break;
        case 4:  set_cstr(v->string, sizeof v->string, "用户@例子.公司"); break; /* SMTPUTF8/IDN */

        case 5:  set_cstr(v->string, sizeof v->string, "user@[192.0.2.1]"); break;
        case 6:  set_cstr(v->string, sizeof v->string, "user@[IPv6:2001:db8::1]"); break;

        case 7:  set_cstr(v->string, sizeof v->string, "<@a.example,@b.example:user@example.com>"); break; /* source-route */
        case 8:  set_cstr(v->string, sizeof v->string, "user%example.com@relay.local"); break;            /* percent-hack */
        case 9:  set_cstr(v->string, sizeof v->string, "host1!host2!user"); break;                        /* bang path */

        case 10: set_cstr(v->string, sizeof v->string, "User (comment) <user@example.com>"); break;
        case 11: set_cstr(v->string, sizeof v->string, "  user.name+tag  @  example.com  "); break;

        case 12: set_cstr(v->string, sizeof v->string, ""); break;                    
        case 13: set_cstr(v->string, sizeof v->string, "\t  "); break;                
        case 14: set_cstr(v->string, sizeof v->string, "user@exa\x01mple.com"); break;
        case 15: set_cstr(v->string, sizeof v->string, "user@example.com\r\nRCPT TO:<evil@example.com>"); break; 
        case 16: set_cstr(v->string, sizeof v->string, ".user@example.com"); break;    
        case 17: set_cstr(v->string, sizeof v->string, "user@example.com."); break;    
        case 18: set_cstr(v->string, sizeof v->string, "a..b@example.com"); break;     
        case 19: set_cstr(v->string, sizeof v->string, "userexample.com"); break;      
        case 20: set_cstr(v->string, sizeof v->string, "\"user@example.com"); break;   

        case 21: {
            char tmp[SMTP_SZ_VRFY_STR]; tmp[0] = '\0';
            cat_repeat(tmp, sizeof tmp, 'A', 450);
            cat_s(tmp, sizeof tmp, "@example.com");
            set_cstr(v->string, sizeof v->string, tmp);
        } break;

        case 22: set_cstr(v->string, sizeof v->string, "\"us\\er\"@exa\\mple.com"); break;

        case 23: set_cstr(v->string, sizeof v->string, "xn--fsqu00a@xn--0zwm56d"); break;

        default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_expn_prefix(smtp_expn_packet_t *e){
    if (!e) return;
    if (!e->command[0]) set_cstr(e->command, sizeof e->command, "EXPN");
    if (!e->space[0])   set_cstr(e->space,   sizeof e->space,   " ");
    if (!e->crlf[0])    set_cstr(e->crlf,    sizeof e->crlf,    "\r\n");
}

int mutate_expn_mailing_list(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EXPN) continue;
        smtp_expn_packet_t *e = &pkts[i].pkt.expn;

        ensure_expn_prefix(e);

        unsigned op = (op_idx++) % OPS;

        switch (op){

        case 0:  set_cstr(e->mailing_list, sizeof e->mailing_list, "staff"); break;
        case 1:  set_cstr(e->mailing_list, sizeof e->mailing_list, "all"); break;
        case 2:  set_cstr(e->mailing_list, sizeof e->mailing_list, "dev-team"); break;
        case 3:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list@example.com"); break;
        case 4:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list+tag@example.com"); break;

        case 5:  set_cstr(e->mailing_list, sizeof e->mailing_list, "owner-list"); break;
        case 6:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list-request"); break;
        case 7:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list%example.com@relay.local"); break; /* percent hack */
        case 8:  set_cstr(e->mailing_list, sizeof e->mailing_list, "host1!host2!list"); break;            /* bang path */

        case 9:  set_cstr(e->mailing_list, sizeof e->mailing_list, "\"Dev Team\""); break;
        case 10: set_cstr(e->mailing_list, sizeof e->mailing_list, "  team  "); break;
        case 11: set_cstr(e->mailing_list, sizeof e->mailing_list, "list(comment)"); break;

        case 12: set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[192.0.2.5]"); break;
        case 13: set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[IPv6:2001:db8::25]"); break;

        case 14: set_cstr(e->mailing_list, sizeof e->mailing_list, ""); break;               
        case 15: set_cstr(e->mailing_list, sizeof e->mailing_list, "\t \t"); break;          
        case 16: set_cstr(e->mailing_list, sizeof e->mailing_list, "list\r\nRCPT TO:<evil@example.com>"); break; 
        case 17: set_cstr(e->mailing_list, sizeof e->mailing_list, "li..st"); break;        
        case 18: set_cstr(e->mailing_list, sizeof e->mailing_list, ".list"); break;         
        case 19: set_cstr(e->mailing_list, sizeof e->mailing_list, "li\x01st"); break;      
        case 20: set_cstr(e->mailing_list, sizeof e->mailing_list, "\"unclosed"); break;    

        case 21: {
            char tmp[SMTP_SZ_LISTNAME]; tmp[0] = '\0';
            cat_repeat(tmp, sizeof tmp, 'A', SMTP_SZ_LISTNAME - 10);
            set_cstr(e->mailing_list, sizeof e->mailing_list, tmp);
        } break;

        case 22: set_cstr(e->mailing_list, sizeof e->mailing_list, "开发者列表"); break;

        case 23: set_cstr(e->mailing_list, sizeof e->mailing_list, "<@a.example,@b.example:list@example.com>"); break;

        default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_help_prefix(smtp_help_packet_t *h){
    if (!h) return;
    if (!h->command[0]) set_cstr(h->command, sizeof h->command, "HELP");
    if (!h->crlf[0])    set_cstr(h->crlf,    sizeof h->crlf,    "\r\n");
}

static void sync_space_for_help(smtp_help_packet_t *h, int force_trailing_space_when_empty){
    if (!h) return;
    if (h->argument[0] == '\0') {
        set_cstr(h->space, sizeof h->space, force_trailing_space_when_empty ? " " : "");
    } else {
        set_cstr(h->space, sizeof h->space, " ");
    }
}

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

int mutate_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;

    static unsigned seq = 0;
    enum { OPS = 20 }; 
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);

        unsigned op = (seq++) % OPS;
        int force_trailing_space_when_empty = 0;

        switch (op){
        case 0:  set_cstr(h->argument, sizeof h->argument, "MAIL"); break;
        case 1:  set_cstr(h->argument, sizeof h->argument, "RCPT"); break;
        case 2:  set_cstr(h->argument, sizeof h->argument, "DATA"); break;
        case 3:  set_cstr(h->argument, sizeof h->argument, "STARTTLS"); break;
        case 4:  set_cstr(h->argument, sizeof h->argument, "AUTH"); break;

        case 5:  set_cstr(h->argument, sizeof h->argument, "mail"); break;
        case 6:  set_cstr(h->argument, sizeof h->argument, "sTaTuS"); break;

        case 7:  set_cstr(h->argument, sizeof h->argument, "MAIL   "); break;
        case 8:  set_cstr(h->argument, sizeof h->argument, "   MAIL"); break;

        case 9:  set_cstr(h->argument, sizeof h->argument, ""); break;       
        case 10: set_cstr(h->argument, sizeof h->argument, ""); force_trailing_space_when_empty = 1; break; 

        case 11: set_cstr(h->argument, sizeof h->argument, "MA\001IL"); break; 
        case 12: set_cstr(h->argument, sizeof h->argument, "MAIL\r\nRCPT TO:<evil@example.com>"); break; 

        case 13: {
            set_cstr(h->argument, sizeof h->argument, "");
            cat_repeat(h->argument, sizeof h->argument, 'A', SMTP_SZ_HELP_ARG - 1);
        } break;

        case 14: set_cstr(h->argument, sizeof h->argument, "--help"); break;
        case 15: set_cstr(h->argument, sizeof h->argument, "MAIL?param=1&x=y"); break;
        case 16: set_cstr(h->argument, sizeof h->argument, "\"MAIL"); break; 

        case 17: set_cstr(h->argument, sizeof h->argument, "帮助"); break;

        case 18: set_cstr(h->argument, sizeof h->argument, "X-UNKNOWN-CMD"); break;
        case 19: set_cstr(h->argument, sizeof h->argument, "8BITMIME"); break;

        default: break;
        }

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

static void sync_space_for_auth(smtp_auth_packet_t *a, int force_keep_space2_when_empty){
    if (!a) return;
    if (a->initial_response[0] == '\0') {
        set_cstr(a->space2, sizeof a->space2, force_keep_space2_when_empty ? " " : "");
    } else {
        if (a->space2[0] == '\t') {
            return;
        }
        set_cstr(a->space2, sizeof a->space2, " ");
    }
}

int add_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
        set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}


int delete_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        set_cstr(a->initial_response, sizeof a->initial_response, "");
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}


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
        int force_keep_space2_when_empty = 0; 

        switch (op){
        case 0:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw=="); /* \0user\0pass */
            break;

        case 1:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AGFsaWNlAHNlY3JldA==");
            break;

        case 2:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            cat_repeat(a->initial_response, sizeof a->initial_response, 'A',
                       (SMTP_SZ_AUTH_IR/2));

            if ((strlen(a->initial_response) & 3) == 1) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 3);
            else if ((strlen(a->initial_response) & 3) == 2) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 2);
            else if ((strlen(a->initial_response) & 3) == 3) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 1);
            break;

        case 3:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw"); 
            break;

        case 4:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "####not_base64####");
            break;

        case 5:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVz\r\nRCPT TO:<x@x>");
            break;

        case 6:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "  AHVzZXIAcGFzcw==  ");
            break;

        case 7:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "LOGIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "dXNlcm5hbWU="); /* "username" */
            break;

        case 8:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "inv\xC3\x28" "alid=="); 
            break;

        case 9:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            cat_repeat(a->initial_response, sizeof a->initial_response, 'B',
                       SMTP_SZ_AUTH_IR - 1);
            break;

        case 10:
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            set_cstr(a->space2,           sizeof a->space2,           " ");
            force_keep_space2_when_empty = 1;
            break;

        case 11:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
            set_cstr(a->space2,           sizeof a->space2,           "\t");
            break;

        case 12:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "XOAUTH2");
            set_cstr(a->initial_response, sizeof a->initial_response,
                     "dXNlcj1mb28BYXV0aD1CZWFyZXIgdG9rZW4BAQ==");
            break;

        case 13:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "CRAM-MD5");
            set_cstr(a->initial_response, sizeof a->initial_response,
                     "dXNlciA5ZTc5Y2RmNTQzN2QxY2QzZjQzY2EwMDAwMDAwMDAwMDAwMDA="); /* "user <hex>" */
            break;

        case 14:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw====");
            break;

        case 15:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXI7Y3Bhc3Ms,LS0=");
            break;

        case 16:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "+");
            break;

        case 17:
            set_cstr(a->initial_response, sizeof a->initial_response, "");
            break;

        case 18:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVz ZXIAcGFz cw==");
            break;

        case 19:
            set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
            set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==\r");
            break;
        }

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

static help_mutator_fn help_mutators[] = {
  mutate_smtp_help_argument,
  add_smtp_help_argument,
  delete_smtp_help_argument

};
/* AUTH */
static auth_mutator_fn auth_mutators[] = {
  mutate_auth_initial_response,
  add_auth_initial_response,
  delete_auth_initial_response,
};

static data_mutator_fn data_mutators[]         = { data_nop };
static rset_mutator_fn rset_mutators[]         = { rset_nop };
static noop_mutator_fn noop_mutators[]         = { noop_nop };
static quit_mutator_fn quit_mutators[]         = { quit_nop };
static starttls_mutator_fn starttls_mutators[] = { starttls_nop };


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

        break;
    }
  }
}
