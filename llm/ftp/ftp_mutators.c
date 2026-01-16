/* ftp mutators source file */
#include "ftp.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>


static inline void buf_set(char dst[], size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) s = "";
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


static uint32_t xorshift32(uint32_t *st) {
    uint32_t x = (*st ? *st : 0x9e3779b9u);
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *st = x; return x;
}


static void op_empty(char dst[], size_t cap) { buf_set(dst, cap, ""); }                         
static void op_spaces(char dst[], size_t cap) { buf_set(dst, cap, "     "); }                 
static void op_overlongA(char dst[], size_t cap) { buf_fill_repeat(dst, cap, 'A', cap ? cap-1 : 0); } 
static void op_anonymous(char dst[], size_t cap) { buf_set(dst, cap, "anonymous"); }          
static void op_anon_email(char dst[], size_t cap) { buf_set(dst, cap, "anonymous@example.com"); } 
static void op_pathy(char dst[], size_t cap) { buf_set(dst, cap, "../../etc/passwd"); }           
static void op_trailing_ws(char dst[], size_t cap) { buf_set(dst, cap, "admin   "); }         
static void op_quoted(char dst[], size_t cap) { buf_set(dst, cap, "\"John Doe\""); }            
static void op_shellmeta(char dst[], size_t cap) { buf_set(dst, cap, "*?$()<>|"); }               
static void op_pct(char dst[], size_t cap) { buf_set(dst, cap, "%00%0D%0A%25%20%7F"); }           
static void op_utf8(char dst[], size_t cap) { buf_set(dst, cap, "用户😀"); }                     
static void op_digits(char dst[], size_t cap) { buf_fill_repeat(dst, cap, '7', 256); }            
static void op_crlf_inject(char dst[], size_t cap) {                                              
    buf_set(dst, cap, "name"); buf_append_str(dst, cap, "\r\nPASS hacked\r\n");
}
static void op_repeat_orig(char dst[], size_t cap, const char *orig) {                        
    if (!orig) orig = "";
    dst[0] = '\0';
    for (int i = 0; i < 8; ++i) buf_append_str(dst, cap, orig);
}
static void op_altcase(char dst[], size_t cap, const char *orig) {                               
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
static void op_bitflip_once(char dst[], size_t cap, const char *orig, uint32_t *rng) {            
    if (!orig || !*orig) orig = "user";
    buf_set(dst, cap, orig);
    size_t n = strnlen(dst, cap);
    if (n == 0) return;
    size_t idx = xorshift32(rng) % n;
    unsigned flips = (xorshift32(rng) % 7) + 1; /* 1..7  */
    for (unsigned k = 0; k < flips; ++k) {
        unsigned bit = (xorshift32(rng) % 8);
        dst[idx] ^= (char)(1u << bit);
    }
}


static const int k_user_legal_ops[] = {
    3,  /* op_anonymous */
    4,  /* op_anon_email */
    6,  /* op_trailing_ws */
    7,  /* op_quoted */
    11, /* op_digits */
    13, /* op_repeat_orig */
    14  /* op_altcase */
};

static const int USER_LEGAL_OP_COUNT =
    (int)(sizeof(k_user_legal_ops) / sizeof(k_user_legal_ops[0]));


int mutate_user_username(ftp_user_packet_t *pkt, uint32_t seed, int op) {
    if (!pkt) return 0;

    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }

    char orig[FTP_SZ_USERNAME];
    buf_set(orig, sizeof(orig), pkt->username);

    uint32_t rng = (seed ? seed : 0xC0FFEEu);

    if (USER_LEGAL_OP_COUNT <= 0) {
        return 0;  
    }

    int chosen_case;
    if (op < 0 || op >= USER_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % USER_LEGAL_OP_COUNT);
        chosen_case = k_user_legal_ops[idx];
    } else {
        chosen_case = k_user_legal_ops[op];
    }

    switch (chosen_case) {
        case 3:  op_anonymous(pkt->username, FTP_SZ_USERNAME); break;
        case 4:  op_anon_email(pkt->username, FTP_SZ_USERNAME); break;
        case 6:  op_trailing_ws(pkt->username, FTP_SZ_USERNAME); break;
        case 7:  op_quoted(pkt->username, FTP_SZ_USERNAME); break;
        case 11: op_digits(pkt->username, FTP_SZ_USERNAME); break;
        case 13: op_repeat_orig(pkt->username, FTP_SZ_USERNAME, orig); break;
        case 14: op_altcase(pkt->username, FTP_SZ_USERNAME, orig); break;
        default:
            return 0; 
    }

    return 1;
}



static void op_common_pwd(char dst[], size_t cap){ buf_set(dst, cap, "password"); }        
static void op_leet(char dst[], size_t cap){ buf_set(dst, cap, "P@ssw0rd!"); }             
static void op_pair(char dst[], size_t cap){ buf_set(dst, cap, "admin:admin"); }           
static void op_quotes(char dst[], size_t cap){ buf_set(dst, cap, "\"ab c\\\"d\""); }      
static void op_escapes(char dst[], size_t cap){ buf_set(dst, cap, "pa\\ss\\n\\tword"); }   
static void op_fmt(char dst[], size_t cap){ buf_set(dst, cap, "%x%x%x%s"); }               
static void op_sql(char dst[], size_t cap){ buf_set(dst, cap, "' OR '1'='1"); }           
static void op_crlf(char dst[], size_t cap){ buf_set(dst, cap, "pwd\r\nQUIT\r\n"); }      
static void op_hexrep(char dst[], size_t cap){                                           
    dst[0] = '\0'; for (int i = 0; i < 128; ++i) buf_append_str(dst, cap, "AA");
}
static void op_path(char d[], size_t c) { buf_set(d, c, "../../etc/passwd"); } 


static const int k_pass_legal_ops[] = {
    3,  /* op_common_pwd  */
    4,  /* op_digits      */
    5,  /* op_leet        */
    6,  /* op_pair        */
    7,  /* op_quotes      */
    15, /* op_hexrep      */
    16, /* op_repeat_orig */
    17  /* op_altcase     */
};

static const int PASS_LEGAL_OP_COUNT =
    (int)(sizeof(k_pass_legal_ops) / sizeof(k_pass_legal_ops[0]));


int mutate_pass_password(ftp_pass_packet_t *pkt, uint32_t seed, int op) {
    if (!pkt) return 0;

    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }

    char orig[FTP_SZ_PASSWORD];
    buf_set(orig, sizeof(orig), pkt->password);

    uint32_t rng = (seed ? seed : 0xBADC0DEu);

    if (PASS_LEGAL_OP_COUNT <= 0) {
        return 0;  
    }


    int chosen_case;
    if (op < 0 || op >= PASS_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % PASS_LEGAL_OP_COUNT);
        chosen_case = k_pass_legal_ops[idx];
    } else {
        chosen_case = k_pass_legal_ops[op];
    }

    switch (chosen_case) {
        case 3:  op_common_pwd(pkt->password, FTP_SZ_PASSWORD);              break;
        case 4:  op_digits(pkt->password, FTP_SZ_PASSWORD);                  break;
        case 5:  op_leet(pkt->password, FTP_SZ_PASSWORD);                    break;
        case 6:  op_pair(pkt->password, FTP_SZ_PASSWORD);                    break;
        case 7:  op_quotes(pkt->password, FTP_SZ_PASSWORD);                  break;
        case 15: op_hexrep(pkt->password, FTP_SZ_PASSWORD);                  break;
        case 16: op_repeat_orig(pkt->password, FTP_SZ_PASSWORD, orig);       break;
        case 17: op_altcase(pkt->password, FTP_SZ_PASSWORD, orig);           break;
        default:
            return 0; 
    }

    return 1;
}



static void op_common(char d[], size_t c)       { buf_set(d, c, "acct123"); }                     
static void op_kv(char d[], size_t c)           { buf_set(d, c, "dept=R&D;quota=unlimited"); }    
static void op_csv(char d[], size_t c)          { buf_set(d, c, "team,role,region"); }           
static void op_json(char d[], size_t c)         { buf_set(d, c, "{\"acct\":\"alice\",\"tier\":3}"); } 
static void op_xml(char d[], size_t c)          { buf_set(d, c, "<acct id='42' tier='gold'/>"); }  
static void op_b64(char d[], size_t c)          { buf_set(d, c, "YWNjdF9rZXk6c2VjcmV0"); }        
static void op_hex(char d[], size_t c)          { d[0]='\0'; for(int i=0;i<128;++i) buf_append_str(d,c,"DE"); } 
static void op_repeat(char d[], size_t c, const char *orig){ d[0]='\0'; if(!orig) orig=""; for(int i=0;i<8;++i) buf_append_str(d,c,orig);} 


static const int k_acct_legal_ops[] = {
    3,  /* op_common  */
    4,  /* op_digits  */
    5,  /* op_kv      */
    6,  /* op_csv     */
    7,  /* op_json    */
    8,  /* op_xml     */
    9,  /* op_b64     */
    15, /* op_hex     */
    16, /* op_repeat  */
    17  /* op_altcase */
};

static const int ACCT_LEGAL_OP_COUNT =
    (int)(sizeof(k_acct_legal_ops) / sizeof(k_acct_legal_ops[0]));


int mutate_acct_account_info(ftp_acct_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;

    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }


    char orig[FTP_SZ_ACCOUNT];
    buf_set(orig, sizeof(orig), pkt->account_info);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (ACCT_LEGAL_OP_COUNT <= 0) {
        return 0; 
    }


    int chosen_case;
    if (op < 0 || op >= ACCT_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % ACCT_LEGAL_OP_COUNT);
        chosen_case = k_acct_legal_ops[idx];
    } else {
        chosen_case = k_acct_legal_ops[op];
    }

    switch (chosen_case) {
        case 3:  op_common(pkt->account_info, FTP_SZ_ACCOUNT);                break;
        case 4:  op_digits(pkt->account_info, FTP_SZ_ACCOUNT);                break;
        case 5:  op_kv(pkt->account_info, FTP_SZ_ACCOUNT);                    break;
        case 6:  op_csv(pkt->account_info, FTP_SZ_ACCOUNT);                   break;
        case 7:  op_json(pkt->account_info, FTP_SZ_ACCOUNT);                  break;
        case 8:  op_xml(pkt->account_info, FTP_SZ_ACCOUNT);                   break;
        case 9:  op_b64(pkt->account_info, FTP_SZ_ACCOUNT);                   break;
        case 15: op_hex(pkt->account_info, FTP_SZ_ACCOUNT);                   break;
        case 16: op_repeat(pkt->account_info, FTP_SZ_ACCOUNT, orig);          break;
        case 17: op_altcase(pkt->account_info, FTP_SZ_ACCOUNT, orig);         break;
        default:
            return 0; 
    }
    return 1;
}



static void op_root(char d[], size_t c){ buf_set(d,c,"/"); }                                 
static void op_many_slash(char d[], size_t c){ buf_set(d,c,"///////"); }                
static void op_dot(char d[], size_t c){ buf_set(d,c,"."); }                                 
static void op_dotdot(char d[], size_t c){ buf_set(d,c,".."); }                                  
static void op_traversal(char d[], size_t c){ d[0]='\0'; for(int i=0;i<16;++i) buf_append_str(d,c,"../"); } 
static void op_dot_segments(char d[], size_t c){ buf_set(d,c,"/a/./b/./c"); }                    
static void op_windows_sep(char d[], size_t c){ buf_set(d,c,"dir\\sub\\file"); }               
static void op_spacey(char d[], size_t c){ buf_set(d,c,"\" spaced name \"/with space"); }      
static void op_glob(char d[], size_t c){ buf_set(d,c,"/tmp/*?.[[]"); }                          
static void op_urlish(char d[], size_t c){ buf_set(d,c,"ftp://host/path/to/dir"); }             
static void op_trailing_dots(char d[], size_t c){ buf_set(d,c,"dir.../sub..."); }              
static void op_device_name(char d[], size_t c){ buf_set(d,c,"CON/NUL/AUX"); }                   
static void op_longA(char d[], size_t c){ buf_fill_repeat(d,c,'A', c?c-1:0); }                 
static void op_hex_dirs(char d[], size_t c){ buf_set(d,c,"/DEAD/BEEF/C0DE"); }                 
static void op_mixed_slashes(char d[], size_t c){ buf_set(d,c,"/a\\b/c\\d"); }                   
static void op_dup_slashes(char d[], size_t c){ buf_set(d,c,"/a////b///c"); }                    


static const int k_cwd_legal_ops[] = {
    1,  /* op_root           */
    2,  /* op_many_slash     */
    3,  /* op_dot            */
    4,  /* op_dotdot         */
    6,  /* op_dot_segments   */
    7,  /* op_windows_sep    */
    8,  /* op_spacey         */
    9,  /* op_glob           */
    11, /* op_urlish         */
    12, /* op_trailing_dots  */
    15, /* op_longA          */
    16, /* op_hex_dirs       */
    17, /* op_mixed_slashes  */
    19, /* op_dup_slashes    */
    20, /* op_repeat_orig    */
    21  /* op_altcase        */
};

static const int CWD_LEGAL_OP_COUNT =
    (int)(sizeof(k_cwd_legal_ops) / sizeof(k_cwd_legal_ops[0]));


int mutate_cwd_pathname(ftp_cwd_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (CWD_LEGAL_OP_COUNT <= 0) {
        return 0; 
    }

    int chosen_case;
    if (op < 0 || op >= CWD_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % CWD_LEGAL_OP_COUNT);
        chosen_case = k_cwd_legal_ops[idx];
    } else {
        chosen_case = k_cwd_legal_ops[op];
    }

    switch (chosen_case) {
        case 1:  op_root(pkt->pathname, FTP_SZ_PATH);                break;
        case 2:  op_many_slash(pkt->pathname, FTP_SZ_PATH);          break;
        case 3:  op_dot(pkt->pathname, FTP_SZ_PATH);                 break;
        case 4:  op_dotdot(pkt->pathname, FTP_SZ_PATH);              break;
        case 6:  op_dot_segments(pkt->pathname, FTP_SZ_PATH);        break;
        case 7:  op_windows_sep(pkt->pathname, FTP_SZ_PATH);         break;
        case 8:  op_spacey(pkt->pathname, FTP_SZ_PATH);              break;
        case 9:  op_glob(pkt->pathname, FTP_SZ_PATH);                break;
        case 11: op_urlish(pkt->pathname, FTP_SZ_PATH);              break;
        case 12: op_trailing_dots(pkt->pathname, FTP_SZ_PATH);       break;
        case 15: op_longA(pkt->pathname, FTP_SZ_PATH);               break;
        case 16: op_hex_dirs(pkt->pathname, FTP_SZ_PATH);            break;
        case 17: op_mixed_slashes(pkt->pathname, FTP_SZ_PATH);       break;
        case 19: op_dup_slashes(pkt->pathname, FTP_SZ_PATH);         break;
        case 20: op_repeat_orig(pkt->pathname, FTP_SZ_PATH, orig);   break;
        case 21: op_altcase(pkt->pathname, FTP_SZ_PATH, orig);       break;
        default:
            return 0;  
    }
    return 1;
}




static void op_dev(char d[], size_t c){ buf_set(d,c,"/dev/sda1"); }                          
static void op_win_drive(char d[], size_t c){ buf_set(d,c,"C:\\\\mount\\\\point"); }          
static void op_unc(char d[], size_t c){ buf_set(d,c,"\\\\server\\share\\dir"); }              
static void op_nfs(char d[], size_t c){ buf_set(d,c,"host:/export/path"); }                   
static void op_smb_url(char d[], size_t c){ buf_set(d,c,"smb://server/share/dir"); }           
static void op_file_url(char d[], size_t c){ buf_set(d,c,"file:///mnt/data"); }               
static void op_opts(char d[], size_t c){ buf_set(d,c,"/mnt/point;opts=rw,noatime,nosuid"); }  
static void op_mixed(char d[], size_t c){ buf_set(d,c,"/a\\b/c\\d"); }                         
static void op_device_names(char d[], size_t c){ buf_set(d,c,"CON/NUL/AUX"); }                 


static const int k_smnt_legal_ops[] = {
    1,  /* op_root */
    2,  /* op_dev */
    3,  /* op_many_slash */
    4,  /* op_dot */
    5,  /* op_dotdot */
    7,  /* op_dot_segments */
    8,  /* op_win_drive */
    9,  /* op_unc */
    10, /* op_nfs */
    11, /* op_smb_url */
    12, /* op_file_url */
    13, /* op_spacey */
    15, /* op_opts */
    17, /* op_longA */
    18, /* op_mixed */
    21, /* op_hex_dirs */
    22, /* op_dup_slashes */
    23, /* op_repeat_orig */
    24  /* op_altcase */
};

static const int SMNT_LEGAL_OP_COUNT =
    (int)(sizeof(k_smnt_legal_ops) / sizeof(k_smnt_legal_ops[0]));


int mutate_smnt_pathname(ftp_smnt_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }

    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (SMNT_LEGAL_OP_COUNT <= 0) {
        return 0;  
    }

    int chosen_case;
    if (op < 0 || op >= SMNT_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % SMNT_LEGAL_OP_COUNT);
        chosen_case = k_smnt_legal_ops[idx];
    } else {
        chosen_case = k_smnt_legal_ops[op];
    }

    switch (chosen_case) {
        case 1:  op_root(pkt->pathname, FTP_SZ_PATH);              break;
        case 2:  op_dev(pkt->pathname, FTP_SZ_PATH);               break;
        case 3:  op_many_slash(pkt->pathname, FTP_SZ_PATH);        break;
        case 4:  op_dot(pkt->pathname, FTP_SZ_PATH);               break;
        case 5:  op_dotdot(pkt->pathname, FTP_SZ_PATH);            break;
        case 7:  op_dot_segments(pkt->pathname, FTP_SZ_PATH);      break;
        case 8:  op_win_drive(pkt->pathname, FTP_SZ_PATH);         break;
        case 9:  op_unc(pkt->pathname, FTP_SZ_PATH);               break;
        case 10: op_nfs(pkt->pathname, FTP_SZ_PATH);               break;
        case 11: op_smb_url(pkt->pathname, FTP_SZ_PATH);           break;
        case 12: op_file_url(pkt->pathname, FTP_SZ_PATH);          break;
        case 13: op_spacey(pkt->pathname, FTP_SZ_PATH);            break;
        case 15: op_opts(pkt->pathname, FTP_SZ_PATH);              break;
        case 17: op_longA(pkt->pathname, FTP_SZ_PATH);             break;
        case 18: op_mixed(pkt->pathname, FTP_SZ_PATH);             break;
        case 21: op_hex_dirs(pkt->pathname, FTP_SZ_PATH);          break;
        case 22: op_dup_slashes(pkt->pathname, FTP_SZ_PATH);       break;
        case 23: op_repeat_orig(pkt->pathname, FTP_SZ_PATH, orig); break;
        case 24: op_altcase(pkt->pathname, FTP_SZ_PATH, orig);     break;
        default:
            return 0; 
    }
    return 1;
}



static void fmt_hostport(char d[], size_t c, int h1,int h2,int h3,int h4,int p1,int p2){
    if(!d || c==0) return;
    (void)snprintf(d, c, "%d,%d,%d,%d,%d,%d", h1,h2,h3,h4,p1,p2);
}



static void op_spaces_commas(char d[], size_t c){ buf_set(d,c," , , , , , "); }                        
static void op_valid_localhost_21(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,0,21); }             
static void op_valid_private_50000(char d[], size_t c){ fmt_hostport(d,c,192,168,1,10,195,80); }     
static void op_all_zero(char d[], size_t c){ fmt_hostport(d,c,0,0,0,0,0,0); }                          
static void op_broadcast(char d[], size_t c){ fmt_hostport(d,c,255,255,255,255,255,255); }             
static void op_over255(char d[], size_t c){ buf_set(d,c,"300,1,1,1,1,1"); }                           
static void op_negative(char d[], size_t c){ buf_set(d,c,"-1,2,3,4,5,6"); }                           
static void op_short_fields(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5"); }                         
static void op_many_fields(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5,6,7"); }                       
static void op_non_numeric(char d[], size_t c){ buf_set(d,c,"a,b,c,d,e,f"); }                         
static void op_spaces_around(char d[], size_t c){ buf_set(d,c," 127 , 0 , 0 , 1 , 0 , 21 "); }         
static void op_tabs_around(char d[], size_t c){ buf_set(d,c,"\t1,\t2,\t3,\t4,\t5,\t6"); }             
static void op_hex_numbers(char d[], size_t c){ buf_set(d,c,"0x7F,0x0,0x0,0x1,0x0,0x15"); }           
static void op_octal_numbers(char d[], size_t c){ buf_set(d,c,"010,000,000,001,000,025"); }           
static void op_floats(char d[], size_t c){ buf_set(d,c,"127.0,0,0,1,0,21"); }                        
static void op_dot_ip_mix(char d[], size_t c){ buf_set(d,c,"127.0.0.1,0,21"); }                      
static void op_percent_encoded(char d[], size_t c){ buf_set(d,c,"%31%32%37,0,0,1,0,21"); }            
static void op_trailing_comma(char d[], size_t c){ buf_set(d,c,"1,2,3,4,5,6,"); }                     
static void op_empty_components(char d[], size_t c){ buf_set(d,c,"1,,3,4,,6"); }                       
static void op_semicolons(char d[], size_t c){ buf_set(d,c,"1;2;3;4;5;6"); }                           
static void op_slashes(char d[], size_t c){ buf_set(d,c,"1/2/3/4/5/6"); }                               
static void op_random_valid(char d[], size_t c, uint32_t *rng){                                       
    int h1=(int)(xorshift32(rng)%256), h2=(int)(xorshift32(rng)%256);
    int h3=(int)(xorshift32(rng)%256), h4=(int)(xorshift32(rng)%256);
    int port=(int)(xorshift32(rng)%65536);
    int p1=(port>>8)&0xFF, p2=port&0xFF;
    fmt_hostport(d,c,h1,h2,h3,h4,p1,p2);
}
static void op_port_zero(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,0,0); }                      
static void op_port_65535(char d[], size_t c){ fmt_hostport(d,c,127,0,0,1,255,255); }                  
static void op_leading_plus(char d[], size_t c){ buf_set(d,c,"+127,+0,+0,+1,+0,+21"); }             
static void op_huge_numbers(char d[], size_t c){ buf_set(d,c,"9999,9999,9999,9999,9999,9999"); }    


static const int k_port_legal_ops[] = {
    2,  /* op_valid_localhost_21  */
    3,  /* op_valid_private_50000 */
    4,  /* op_all_zero */
    5,  /* op_broadcast */
    11, /* op_spaces_around */
    12, /* op_tabs_around */
    23, /* op_random_valid */
    24, /* op_port_zero */
    25  /* op_port_65535 */
};

static const int PORT_LEGAL_OP_COUNT =
    (int)(sizeof(k_port_legal_ops) / sizeof(k_port_legal_ops[0]));


int mutate_port_host_port_str(ftp_port_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;

    if (pkt->space[0] == '\0') {
        pkt->space[0] = ' ';
        pkt->space[1] = '\0';
    }

    uint32_t rng = (seed ? seed : 0xA1B2C3D4u); 

    if (PORT_LEGAL_OP_COUNT <= 0) {
        return 0;
    }

    int chosen_case;
    if (op < 0 || op >= PORT_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % PORT_LEGAL_OP_COUNT);
        chosen_case = k_port_legal_ops[idx];
    } else {
        chosen_case = k_port_legal_ops[op];
    }

    switch (chosen_case) {
        case 2:  op_valid_localhost_21(pkt->host_port_str, FTP_SZ_HOSTPORT);          break;
        case 3:  op_valid_private_50000(pkt->host_port_str, FTP_SZ_HOSTPORT);         break;
        case 4:  op_all_zero(pkt->host_port_str, FTP_SZ_HOSTPORT);                    break;
        case 5:  op_broadcast(pkt->host_port_str, FTP_SZ_HOSTPORT);                   break;
        case 11: op_spaces_around(pkt->host_port_str, FTP_SZ_HOSTPORT);               break;
        case 12: op_tabs_around(pkt->host_port_str, FTP_SZ_HOSTPORT);                 break;
        case 23: op_random_valid(pkt->host_port_str, FTP_SZ_HOSTPORT, &rng);          break;
        case 24: op_port_zero(pkt->host_port_str, FTP_SZ_HOSTPORT);                   break;
        case 25: op_port_65535(pkt->host_port_str, FTP_SZ_HOSTPORT);                  break;
        default:
            return 0; 
    }

    return 1;
}




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


static const int k_type_legal_ops[] = {
    0,  /* TYPE A     */
    1,  /* TYPE I     */
    2,  /* TYPE E N   */
    3,  /* TYPE A N   */
    4,  /* TYPE A T   */
    5,  /* TYPE A C   */
    6,  /* TYPE L 8   */
    7   /* TYPE L 16  */
};

static const int TYPE_LEGAL_OP_COUNT =
    (int)(sizeof(k_type_legal_ops) / sizeof(k_type_legal_ops[0]));


int mutate_type_type_code(ftp_type_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    set_space1(pkt);

    char orig_type[FTP_SZ_TYPE];
    buf_set(orig_type, sizeof(orig_type), pkt->type_code);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (TYPE_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= TYPE_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % TYPE_LEGAL_OP_COUNT);
        chosen_case = k_type_legal_ops[idx];
    } else {
        chosen_case = k_type_legal_ops[op];
    }

    switch (chosen_case) {
        case 0:  set_opt(pkt, "A",  NULL);  break;   /* TYPE A     */
        case 1:  set_opt(pkt, "I",  NULL);  break;   /* TYPE I     */
        case 2:  set_opt(pkt, "E",  "N");   break;   /* TYPE E N   */
        case 3:  set_opt(pkt, "A",  "N");   break;   /* TYPE A N   */
        case 4:  set_opt(pkt, "A",  "T");   break;   /* TYPE A T   */
        case 5:  set_opt(pkt, "A",  "C");   break;   /* TYPE A C   */
        case 6:  set_opt(pkt, "L",  "8");   break;   /* TYPE L 8   */
        case 7:  set_opt(pkt, "L",  "16");  break;   /* TYPE L 16  */
        default:
            return 0;  
    }

    return 1;
}


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

void add_type_format_control(ftp_type_packet_t *pkt, const char *value){
    if(!pkt) return;
    ensure_space1(pkt);
    set_fc(pkt, value && value[0] ? value : "N"); 
}
void delete_type_format_control(ftp_type_packet_t *pkt){
    if(!pkt) return;
    set_fc(pkt, ""); 
}

static const int k_type_fc_legal_ops[] = {
    0,  /* TYPE A N */
    1,  /* TYPE A T */
    2,  /* TYPE A C */
    3   /* TYPE E N */
};

static const int TYPE_FC_LEGAL_OP_COUNT =
    (int)(sizeof(k_type_fc_legal_ops) / sizeof(k_type_fc_legal_ops[0]));


int mutate_type_format_control(ftp_type_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    ensure_space1(pkt);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (TYPE_FC_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= TYPE_FC_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % TYPE_FC_LEGAL_OP_COUNT);
        chosen_case = k_type_fc_legal_ops[idx];
    } else {
        chosen_case = k_type_fc_legal_ops[op];
    }

    switch (chosen_case) {

        case 0:  set_tc(pkt, "A"); set_fc(pkt, "N"); break;   /* TYPE A N */
        case 1:  set_tc(pkt, "A"); set_fc(pkt, "T"); break;   /* TYPE A T */
        case 2:  set_tc(pkt, "A"); set_fc(pkt, "C"); break;   /* TYPE A C */
        case 3:  set_tc(pkt, "E"); set_fc(pkt, "N"); break;   /* TYPE E N */
        default:
            return 0; 
    }
    return 1;
}


static inline void ensure_space(ftp_retr_packet_t *pkt){
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }
}


static const int k_stru_legal_ops[] = {
    0,  /* "F" */
    1,  /* "R" */
    2,  /* "P" */
    14  
};

static const int STRU_LEGAL_OP_COUNT =
    (int)(sizeof(k_stru_legal_ops) / sizeof(k_stru_legal_ops[0]));


int mutate_stru_structure_code(ftp_stru_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    ensure_space(pkt);

    uint32_t rng = (seed ? seed : 0xA1B2C3D4u);

    if (STRU_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= STRU_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % STRU_LEGAL_OP_COUNT);
        chosen_case = k_stru_legal_ops[idx];
    } else {
        chosen_case = k_stru_legal_ops[op];
    }

    switch (chosen_case) {

        case 0:  /* "F" */
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), "F");
            break;
        case 1:  /* "R" */
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), "R");
            break;
        case 2:  /* "P" */
            buf_set(pkt->structure_code, sizeof(pkt->structure_code), "P");
            break;
        case 14: {
            const char *ok[] = {"F", "R", "P"};
            buf_set(pkt->structure_code, sizeof(pkt->structure_code),
                    ok[xorshift32(&rng) % 3]);
            break;
        }
        default:
            return 0;  
    }
    return 1;
}




static const int k_mode_legal_ops[] = {
    0,  /* "S" */
    1,  /* "B" */
    2,  /* "C" */
    14  
};

static const int MODE_LEGAL_OP_COUNT =
    (int)(sizeof(k_mode_legal_ops) / sizeof(k_mode_legal_ops[0]));


int mutate_mode_mode_code(ftp_mode_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    ensure_space(pkt);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (MODE_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= MODE_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % MODE_LEGAL_OP_COUNT);
        chosen_case = k_mode_legal_ops[idx];
    } else {
        chosen_case = k_mode_legal_ops[op];
    }

    switch (chosen_case) {

        case 0:  /* "S" */
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), "S");
            break;
        case 1:  /* "B" */
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), "B");
            break;
        case 2:  /* "C" */
            buf_set(pkt->mode_code, sizeof(pkt->mode_code), "C");
            break;
        case 14: { 
            const char *ok[] = {"S","B","C"};
            buf_set(pkt->mode_code, sizeof(pkt->mode_code),
                    ok[xorshift32(&rng) % 3]);
            break;
        }
        default:
            return 0;  
    }

    return 1;
}


static const int k_retr_legal_ops[] = {
    0,   /* "file.txt" */
    1,   /* "/var/log/syslog" */
    2,   /* "./a/b/c.txt" */
    3,   /* "../secret/report.pdf" */
    4,   /* ".hidden" */
    5,   /* "My Documents/report 2020.txt" */
    6,   /* "dir///sub////file" */
    7,   /* "dir/" */
    8,   
    9,   
    10,  /* "data/*.dat" */
    11,  /* "src/????.c" */
    12,  /* "set/[abc]/x.txt" */
    13,  /* "\"quoted name\".txt" */
    14,  /* "dir\\sub\\file.txt" */
    15,  /* "C:\\Windows\\system32\\drivers\\etc\\hosts" */
    16,  /* "con.txt" */
    20,  /* "  spaced-leading-and-trailing  " */
    25   /* "~user/.ssh/id_rsa" */
};

static const int RETR_LEGAL_OP_COUNT =
    (int)(sizeof(k_retr_legal_ops) / sizeof(k_retr_legal_ops[0]));


int mutate_retr_pathname(ftp_retr_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    ensure_space(pkt);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (RETR_LEGAL_OP_COUNT <= 0)
        return 0;


    int chosen_case;
    if (op < 0 || op >= RETR_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % RETR_LEGAL_OP_COUNT);
        chosen_case = k_retr_legal_ops[idx];
    } else {
        chosen_case = k_retr_legal_ops[op];
    }

    switch (chosen_case) {

        case 0:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "file.txt");
            break;
        case 1:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/log/syslog");
            break;
        case 2:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "./a/b/c.txt");
            break;
        case 3:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "../secret/report.pdf");
            break;
        case 4:
            buf_set(pkt->pathname, sizeof(pkt->pathname), ".hidden");
            break;
        case 5:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "My Documents/report 2020.txt");
            break;


        case 6:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir///sub////file");
            break;
        case 7:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/");
            break;
        case 8: { 
            char tmp[FTP_SZ_PATH]; tmp[0] = '\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0, seglen = strlen(seg);
            while (used + seglen + 8 < cap) {
                strcat(tmp, seg);
                used += seglen;
            }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 9:
            buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                            sizeof(pkt->pathname)
                                ? sizeof(pkt->pathname) - 1
                                : 0);
            break;


        case 10:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat");
            break;
        case 11:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c");
            break;
        case 12:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "set/[abc]/x.txt");
            break;
        case 13:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "\"quoted name\".txt");
            break;


        case 14:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir\\sub\\file.txt");
            break;
        case 15:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "C:\\Windows\\system32\\drivers\\etc\\hosts");
            break;
        case 16:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "con.txt");
            break;


        case 20:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "  spaced-leading-and-trailing  ");
            break;


        case 25:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "~user/.ssh/id_rsa");
            break;

        default:
            return 0;  
    }
    return 1;
}

static inline void ensure_space_stor(ftp_stor_packet_t *pkt){
    if(pkt->space[0]=='\0'){ pkt->space[0]=' '; pkt->space[1]='\0'; }
}


static const int k_stor_legal_ops[] = {
    0,   /* "upload.bin" */
    1,   /* "/tmp/out.dat" */
    2,   /* "./docs/new.txt" */
    3,   /* "backup/2025-08-23.tar.gz" */
    4,   /* ".hidden/file" */
    5,   /* "dir///sub////file" */
    6,   /* "dir/" */
    7,   
    8,   
    9,   /* "a" */
    10,  /* "data/*.dat" */
    11,  /* "src/????.c" */
    12,  /* "\"quoted name\".txt" */
    13,  /* "name with spaces .txt" */
    14,  /* "dir\\sub\\file.txt" */
    16,  /* "aux.txt." */
    25,  /* "~/.ssh/authorized_keys" */
    26,  /* "report(1).pdf" */
    27   /* "report:2025-08-23T12:34:56Z.log" */
};

static const int STOR_LEGAL_OP_COUNT =
    (int)(sizeof(k_stor_legal_ops) / sizeof(k_stor_legal_ops[0]));


int mutate_stor_pathname(ftp_stor_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;
    ensure_space_stor(pkt);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (STOR_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= STOR_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % STOR_LEGAL_OP_COUNT);
        chosen_case = k_stor_legal_ops[idx];
    } else {
        chosen_case = k_stor_legal_ops[op];
    }

    switch (chosen_case) {
        case 0:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "upload.bin");
            break;
        case 1:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "/tmp/out.dat");
            break;
        case 2:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "./docs/new.txt");
            break;
        case 3:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "backup/2025-08-23.tar.gz");
            break;
        case 4:
            buf_set(pkt->pathname, sizeof(pkt->pathname), ".hidden/file");
            break;
        case 5:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir///sub////file");
            break;
        case 6:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/");
            break;
        case 7: { 
            char tmp[FTP_SZ_PATH]; tmp[0] = '\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0, seglen = strlen(seg);
            while (used + seglen + 8 < cap) {
                strcat(tmp, seg);
                used += seglen;
            }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 8:
            buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                            sizeof(pkt->pathname)
                                ? sizeof(pkt->pathname) - 1
                                : 0);
            break;
        case 9:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "a");
            break;

        case 10:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat");
            break;
        case 11:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c");
            break;
        case 12:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "\"quoted name\".txt");
            break;
        case 13:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "name with spaces .txt");
            break;

        case 14:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir\\sub\\file.txt");
            break;
        case 16:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt.");
            break;

        case 25:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "~/.ssh/authorized_keys");
            break;
        case 26:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "report(1).pdf");
            break;
        case 27:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "report:2025-08-23T12:34:56Z.log");
            break;

        default:
            return 0; 
    }

    return 1;
}



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


static const int k_stou_legal_ops[] = {
    0,   
    2,   
    3,   
    4,  
    5,   
    6,   
    7,   
    8,   
    9,   
    10,  
    11,  
    12,  
    13,  
    14,  
    16,  
    25,  
    26,  
    27   
};

static const int STOU_LEGAL_OP_COUNT =
    (int)(sizeof(k_stou_legal_ops) / sizeof(k_stou_legal_ops[0]));


int mutate_stou_pathname(ftp_stou_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;


    char orig[FTP_SZ_PATH];
    buf_set(orig, sizeof(orig), pkt->pathname);

    uint32_t rng = (seed ? seed : 0xACCEBEEFu);

    if (STOU_LEGAL_OP_COUNT <= 0)
        return 0;


    int chosen_case;
    if (op < 0 || op >= STOU_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % STOU_LEGAL_OP_COUNT);
        chosen_case = k_stou_legal_ops[idx];
    } else {
        chosen_case = k_stou_legal_ops[op];
    }

    switch (chosen_case) {

        case 0: 
            return delete_stou_pathname(pkt);

        case 2:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "upload-unique.bin");
            break;
        case 3:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "uploads/out.dat");
            break;
        case 4:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "./docs/new.txt");
            break;

        case 5:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir///sub////file");
            break;
        case 6:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/");
            break;
        case 7: { 
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            char tmp[FTP_SZ_PATH]; tmp[0] = '\0';
            const char *seg = "aaaa/";
            size_t cap = sizeof(tmp), used = 0, seglen = strlen(seg);
            while (used + seglen + 8 < cap) {
                strcat(tmp, seg);
                used += seglen;
            }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 8:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                            sizeof(pkt->pathname)
                                ? sizeof(pkt->pathname) - 1
                                : 0);
            break;
        case 9:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname), "a");
            break;

        case 10:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat");
            break;
        case 11:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c");
            break;
        case 12:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "\"quoted name\".txt");
            break;
        case 13:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    " name with spaces .txt");
            break;

        case 14:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir\\sub\\file.txt");
            break;
        case 16:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt.");
            break;

        case 25:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "~/.ssh/authorized_keys");
            break;
        case 26:
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "stou-2025-08-23T12:34:56Z.log");
            break;
        case 27: {
            pkt->space[0] = ' '; pkt->space[1] = '\0';
            char tmp[FTP_SZ_PATH];
            char suf[17];
            static const char H[] = "0123456789abcdef";
            for (int i = 0; i < 16; ++i) {
                suf[i] = H[xorshift32(&rng) & 0xF];
            }
            suf[16] = '\0';
            (void)snprintf(tmp, sizeof(tmp), "upload_%s.bin", suf);
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        default:
            return 0;
    }

    return 1;
}




static inline void ensure_space_required(char space[/*FTP_SZ_SPACE*/]){
    space[0] = ' '; space[1] = '\0';
}

static const int k_appe_legal_ops[] = {
    0,   
    1,   
    2,   
    3,   
    4,   
    5,   
    6,   
    7,   
    8,   
    9,   
    10,  
    11,  
    12,  
    13,  
    15,  
    24,  
    25,  
    26,  
    27,  
    28   
};

static const int APPE_LEGAL_OP_COUNT =
    (int)(sizeof(k_appe_legal_ops) / sizeof(k_appe_legal_ops[0]));


int mutate_appe_pathname(ftp_appe_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;

    ensure_space_required(pkt->space);

    uint32_t rng = (seed ? seed : 0xA99EEDu);

    if (APPE_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= APPE_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % APPE_LEGAL_OP_COUNT);
        chosen_case = k_appe_legal_ops[idx];
    } else {
        chosen_case = k_appe_legal_ops[op];
    }

    switch (chosen_case) {
        case 0:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "logs/app.log");
            break;
        case 1:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "data/out.bin");
            break;
        case 2:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "./append.txt");
            break;
        case 3:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/file");
            break;

        case 4:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir///sub////file");
            break;
        case 5:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "dir/");
            break;
        case 6: { 
            char tmp[FTP_SZ_PATH]; tmp[0] = '\0';
            const char *seg = "aaaa/";
            size_t used = 0, cap = sizeof(tmp), seglen = strlen(seg);
            while (used + seglen + 8 < cap) {
                strcat(tmp, seg);
                used += seglen;
            }
            strcat(tmp, "file.bin");
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }
        case 7:
            buf_fill_repeat(pkt->pathname, sizeof(pkt->pathname), 'A',
                            sizeof(pkt->pathname)
                                ? sizeof(pkt->pathname) - 1
                                : 0);
            break;
        case 8:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "a");
            break;

        case 9:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "data/*.dat");
            break;
        case 10:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "src/????.c");
            break;
        case 11:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "\"quoted name\".txt");
            break;
        case 12:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    " name with spaces .txt");
            break;

        case 13:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "dir\\sub\\file.txt");
            break;
        case 15:
            buf_set(pkt->pathname, sizeof(pkt->pathname), "aux.txt.");
            break;

        case 24:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "~/.ssh/authorized_keys");
            break;
        case 25:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "./../..//./a");
            break;

        case 26:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "appe-2025-08-23T12:34:56Z.log");
            break;
        case 27: {
            char tmp[FTP_SZ_PATH], suf[17];
            static const char H[] = "0123456789abcdef";
            for (int i = 0; i < 16; ++i) {
                suf[i] = H[xorshift32(&rng) & 0xF];
            }
            suf[16] = '\0';
            (void)snprintf(tmp, sizeof(tmp), "append_%s.bin", suf);
            buf_set(pkt->pathname, sizeof(pkt->pathname), tmp);
            break;
        }

        case 28:
            buf_set(pkt->pathname, sizeof(pkt->pathname),
                    "  file . log  ");
            break;

        default:
            return 0;
    }

    return 1;
}


static const int k_allo_legal_ops[] = {
    0,   /* "0" */
    1,   /* "1" */
    2,   /* "512" */
    3,   /* "1048576" */
    4,   /* "2147483647" */
    5,   /* "4294967295" */
    8,   /* "000000001024" (leading zeros) */
    10,  /* "0400" */
    19,  /* all '9' filling the buffer */
    20,  /* "18446744073709551615" */
    22,  /* random decimal digit string */
    27   /* very big decimal "9999..." */
};

static const int ALLO_LEGAL_OP_COUNT =
    (int)(sizeof(k_allo_legal_ops) / sizeof(k_allo_legal_ops[0]));


int mutate_allo_byte_count(ftp_allo_packet_t *pkt, uint32_t seed, int op){
    if (!pkt) return 0;

    ensure_space_required(pkt->space1);

    uint32_t rng = (seed ? seed : 0xA5A5F00Du);

    if (ALLO_LEGAL_OP_COUNT <= 0)
        return 0;

    int chosen_case;
    if (op < 0 || op >= ALLO_LEGAL_OP_COUNT) {
        int idx = (int)(xorshift32(&rng) % ALLO_LEGAL_OP_COUNT);
        chosen_case = k_allo_legal_ops[idx];
    } else {
        chosen_case = k_allo_legal_ops[op];
    }

    switch (chosen_case) {
        case 0:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "0");
            break;
        case 1:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1");
            break;
        case 2:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "512");
            break;
        case 3:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "1048576");
            break; /* 1 MiB */
        case 4:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "2147483647");
            break; /* INT_MAX */
        case 5:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), "4294967295");
            break; /* UINT32_MAX */


        case 8:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count),
                    "000000001024"); /* leading zeros */
            break;
        case 10:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count),
                    "0400");         /* digits only, octal-like */
            break;

        case 19: { 
            size_t cap = sizeof(pkt->byte_count);
            if (cap > 1) {
                memset(pkt->byte_count, '9', cap - 1);
                pkt->byte_count[cap - 1] = '\0';
            } else {
                buf_set(pkt->byte_count, cap, "9");
            }
            break;
        }
        case 20:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count),
                    "18446744073709551615"); /* U64_MAX */
            break;

        case 22: {
            char tmp[FTP_SZ_BYTECOUNT];
            size_t cap = sizeof(tmp);
            size_t n = (xorshift32(&rng) % (cap ? cap : 1));
            if (n == 0) n = 1;
            size_t i = 0;
            for (; i + 1 < cap && i < n; ++i) {
                tmp[i] = (char)('0' + (xorshift32(&rng) % 10));
            }
            if (cap > 0)
                tmp[(i < cap) ? i : (cap - 1)] = '\0';
            buf_set(pkt->byte_count, sizeof(pkt->byte_count), tmp);
            break;
        }

        case 27:
            buf_set(pkt->byte_count, sizeof(pkt->byte_count),
                    "999999999999999999999999999999999");
            break;

        default:
            return 0;
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



int add_allo_record_format(ftp_allo_packet_t *pkt){
    if(!pkt) return 0;
    set_space(pkt->space2, 1);
    set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 512");
    return 1;
}

int delete_allo_record_format(ftp_allo_packet_t *pkt){
    if(!pkt) return 0;
    set_space(pkt->space2, 0);
    pkt->record_format[0] = '\0';
    return 1;
}

static const unsigned k_allo_rf_legal_cases[] = {
    0,   
    1,   
    2,   
    3,   
    6,   
    14,  
    21,  
    22   
};

#define ALLO_RF_LEGAL_OPS (sizeof(k_allo_rf_legal_cases) / sizeof(k_allo_rf_legal_cases[0]))

int mutate_allo_record_format(ftp_allo_packet_t *pkt){
    if (!pkt) return 0;

    if (ALLO_RF_LEGAL_OPS == 0) return 0;

    static unsigned op_idx = 0;
    unsigned sel = (op_idx++) % ALLO_RF_LEGAL_OPS;
    unsigned op = k_allo_rf_legal_cases[sel];

    switch (op){
        case 0:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 1");
            break;

        case 1:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 0");
            break;

        case 2:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 512");
            break;

        case 3:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 2147483647");
            break;

        case 6:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "R 00064");
            break;

        case 14: {
            set_space(pkt->space2, 1);
            size_t cap = sizeof(pkt->record_format);
            if (cap >= 4) {
                pkt->record_format[0] = 'R';
                pkt->record_format[1] = ' ';
                pkt->record_format[2] = '9';
                for (size_t i = 3; i < cap - 1; i++) {
                    pkt->record_format[i] = '9';
                }
                pkt->record_format[cap - 1] = '\0';
            } else {
                set_cstr(pkt->record_format, cap, "R");
            }
            break;
        }

        case 21:
            set_space(pkt->space2, 1);
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "   R 256");
            break;

        case 22:
            set_space(pkt->space2, 0);  
            set_cstr(pkt->record_format, sizeof(pkt->record_format), "");
            break;

        default:
            return 0;
    }

    return 1;
}


static const unsigned k_rest_legal_cases[] = {
    0, 
    1, 
    2, 
    3, 
    4, 
    5, 
    8, 
    17,
    18 
};

#define REST_LEGAL_OPS (sizeof(k_rest_legal_cases) / sizeof(k_rest_legal_cases[0]))


int mutate_rest_marker(ftp_rest_packet_t *pkt){
    if(!pkt) return 0;
    if(REST_LEGAL_OPS == 0) return 0;

    static unsigned op_idx = 0;
    unsigned sel = (op_idx++) % REST_LEGAL_OPS;
    unsigned op  = k_rest_legal_cases[sel];

    switch(op){
        case 0:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "0");
            break;

        case 1:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "1");
            break;

        case 2:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "1234567890");
            break;

        case 3:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "2147483647"); /* int32_max */
            break;

        case 4:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "4294967295"); /* uint32_max */
            break;

        case 5:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker),
                     "9223372036854775807"); /* int64_max */
            break;

        case 8:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker), "00000000");
            break;

        case 17: {
            set_space(pkt->space, 1);
            size_t cap = sizeof(pkt->marker);
            if (cap > 1) {
                memset(pkt->marker, '9', cap - 1);
                pkt->marker[cap - 1] = '\0';
            } else {
                set_cstr(pkt->marker, cap, "9");
            }
            break;
        }

        case 18:
            set_space(pkt->space, 1);
            set_cstr(pkt->marker, sizeof(pkt->marker),
                     "18446744073709551616"); 
            break;

        default:
            return 0;
    }

    return 1;
}


static const unsigned k_rnfr_legal_cases[] = {
    0,  1,  2,  3,  4,  5,  6,
    7,  8,  9,  10, 11, 12, 13,
    14, 15, 16, 17, 18,
    20, 21, 22      
};

#define RNFR_LEGAL_OPS (sizeof(k_rnfr_legal_cases)/sizeof(k_rnfr_legal_cases[0]))


int mutate_rnfr_pathname(ftp_rnfr_packet_t *pkt){
    if(!pkt) return 0;
    if(RNFR_LEGAL_OPS == 0) return 0;

    static unsigned op_idx = 0;
    unsigned op = k_rnfr_legal_cases[(op_idx++) % RNFR_LEGAL_OPS];

    switch(op){
        case 0:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "file.txt");
            break;
        case 1:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/log/syslog");
            break;
        case 2:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "./a/b/c");
            break;
        case 3:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/");     
            break;

        case 4:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd");
            break;
        case 5:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     ".././../..////secret");
            break;
        case 6:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../..");
            break;

        case 7:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts");
            break;
        case 8:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "dir\\\\sub/..\\\\..//file.bin");
            break;

        case 9:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "*?.[0-9]{1,3}");
            break;
        case 10:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON");
            break;   
        case 11:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden");
            break;

        case 12:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "a b/ c.txt");
            break;
        case 13:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "\"quoted name\"");
            break;
        case 14:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "'single quoted'");
            break;

        case 15:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "%2e%2e%2fetc%2fpasswd");
            break;   
        case 16:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "%252e%252e%252fetc%252fpasswd");
            break;   
        case 17:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "目录/文件.txt");
            break;
        case 18:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "dir/😀.bin");
            break;

        case 20:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "\tpath\\with\\tab");
            break;

        case 21: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'A', cap-1);
                pkt->pathname[cap-1] = '\0';
            } else {
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 22: {  
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

        default:
            return 0;
    }

    return 1;
}


static void swap_separators(char *s){
    if (!s) return;
    for (; *s; ++s){
        if (*s == '/') *s = '\\';
        else if (*s == '\\') *s = '/';
    }
}


static void toggle_case(char *s){
    if (!s) return;
    for (; *s; ++s){
        if (islower((unsigned char)*s)) *s = (char)toupper((unsigned char)*s);
        else if (isupper((unsigned char)*s)) *s = (char)tolower((unsigned char)*s);
    }
}

int mutate_rnto_pathname(ftp_rnto_packet_t *pkt){
    if(!pkt) return 0;

    static unsigned op_idx = 0;


    static const unsigned k_rnto_legal_cases[] = {
        0,  1,  2,  3,  4,
        5,  6,  7,  8,  9,
        10, 11, 12, 13, 14,
        15, 16, 17, 18, 19,
        20, 21, 22, 23, 25
    };
    const unsigned OPS = (unsigned)(sizeof(k_rnto_legal_cases)/sizeof(k_rnto_legal_cases[0]));
    if (OPS == 0) return 0;

    unsigned op = k_rnto_legal_cases[(op_idx++) % OPS];


    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){

        case 0: {
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s%s", orig[0] ? orig : "name", ".new");
            break;
        }
        case 1: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/file");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeDCaSe.txt");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "../%s", orig[0] ? orig : "target");
            break;
        }
        case 4: { 
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

        case 5:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "newname.txt");
            break;
        case 6:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/newname");
            break;
        case 7:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "./renamed/file");
            break;
        case 8:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/"); 
            break;

        case 9:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd");
            break;
        case 10:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), ".././..////.//secret");
            break;
        case 11:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../..");
            break;

        case 12:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "C:\\\\Temp\\\\new\\\\name.txt");
            break;
        case 13:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "dir\\\\sub/..\\\\..//new.bin");
            break;

        case 14:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); 
            break;
        case 15:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "file.txt:stream"); /* NTFS ADS */
            break;
        case 16:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "bad<>:\"/\\|?*.txt");
            break;
        case 17:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_new");
            break;

        case 18:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "new name final.txt");
            break;
        case 19:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "\"quoted new\"");
            break;
        case 20:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "trailingdot.");
            break;

        case 21:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "new%20name.txt"); 
            break;
        case 22:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "%252e%252e%252fescape"); 
            break;
        case 23:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname),
                     "新文件名.txt");
            break;

        case 25: {
            set_space(pkt->space,1);  
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'B', cap-1);
                pkt->pathname[cap-1] = '\0';
            }else{
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }

        default:
            return 0;
    }

    return 1;
}


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


int mutate_dele_pathname(ftp_dele_packet_t *pkt){
    if(!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 28;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){

        case 0: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s%s", orig[0] ? orig : "file", ".bak");
            break;
        }
        case 1: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/file.txt");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/File.TXT");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "../%s", orig[0] ? orig : "target.txt");
            break;
        }
        case 4: { 
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b///c////file";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }

        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old.log"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/old.data"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./cache/item"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden"); break;

        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/passwd"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".././..////.//shadow"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/../.."); break;

        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "C:\\\\Temp\\\\old\\\\file.bin"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//to_del.tmp"); break;

        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*.log"); break;   
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;     
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "nul"); break;     
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "file.txt:stream"); break; 

        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced name .txt "); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted name\""); break;
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "trailingdot."); break;

        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old%20name.txt"); break; 
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%252e%252e%252fescape"); break; 
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "删除我.txt"); break; 

        case 24:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "victim_NOOP.txt");
            break;

        case 25: { 
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

        case 26: { 
            set_space(pkt->space,1);  
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "no-space.txt");
            break;
        }

        case 27: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "dele-target"); 
            break;
        }

        default: return 0;
    }

    return 1;
}



int mutate_rmd_pathname(ftp_rmd_packet_t *pkt){
    if(!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 30;
    unsigned op = (op_idx++) % OPS;


    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){

        case 0: { 
            set_space(pkt->space,1);
            if (orig[0]) {
                size_t cap = sizeof(pkt->pathname);
                (void)snprintf(pkt->pathname, cap, "%s/", orig);
            } else {
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "logs/");
            }
            break;
        }
        case 1: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/old/");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/Path/To/DEL");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: {
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b\\\\\\\\c/////";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 4: {
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "./%s", orig[0] ? orig : "tmp");
            break;
        }


        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/tmp/cache"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "./build"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_dir"); break;

        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".."); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../.."); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../etc/"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/"); break;         
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "C:\\\\"); break;    
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir/./."); break;  


        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "dir\\\\sub/..\\\\..//to_remove/"); break;


        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;   
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "PRN "); break; 
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "aux."); break; 
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*"); break;
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir*"); break;

        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced dir "); break;
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted dir\""); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "traildot."); break;

        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "old%20dir"); break;           
        case 25: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%2e%2e/%2e%2e/escape"); break;
        case 26: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "删除我"); break;         

        case 27:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "victim_NOOP_dir");
            break;

        case 28: {
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

        case 29: {
            set_space(pkt->space,1); 
            if (orig[0]) {

                size_t cap = sizeof(pkt->pathname);
                (void)snprintf(pkt->pathname, cap, "%s_to_delete", orig);
            } else {
                set_cstr(pkt->pathname, sizeof(pkt->pathname), "rmd-target");
            }
            break;
        }

        default: return 0;
    }

    return 1;
}


int mutate_mkd_pathname(ftp_mkd_packet_t *pkt){
    if(!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 30;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){

        case 0: {
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "%s/", orig[0] ? orig : "newdir");
            break;
        }
        case 1: {
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "dir/sub/new");
            swap_separators(pkt->pathname);
            break;
        }
        case 2: { 
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), orig[0] ? orig : "MiXeD/Path/To/New");
            toggle_case(pkt->pathname);
            break;
        }
        case 3: { 
            set_space(pkt->space,1);
            const char *src = orig[0] ? orig : "a////b\\\\\\\\c////new";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 4: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            (void)snprintf(pkt->pathname, cap, "./%s", orig[0] ? orig : "tmp");
            break;
        }

        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "newdir"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/newdir"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".hidden_new"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "a/b/c/new"); break;

        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), ".."); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../new"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "../../../../../new"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "/"); break;         
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "C:\\\\new"); break;  
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "a\\\\b/c//new"); break; 

        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname),
                                                   "\\\\server\\share\\newdir"); break;

        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "CON"); break;   
        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "PRN "); break;  
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "NUL."); break;  
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "*"); break;     
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "dir*"); break;

        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), " spaced dir "); break;
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "\"quoted dir\""); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "traildot."); break;

        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "%2e%2e/new"); break; 
        case 25: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "new%20dir"); break;  
        case 26: set_space(pkt->space,1); set_cstr(pkt->pathname, sizeof(pkt->pathname), "新建目录"); break;   

        case 27:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname, sizeof(pkt->pathname), "new_LIST_dir");
            break;

        case 28: { 
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
        case 29: {
            set_space(pkt->space,1);
            pkt->pathname[0] = '\0';
            size_t cap = sizeof(pkt->pathname);
            size_t len = 0;

            while (len + 2 < cap){
                pkt->pathname[len++] = '/';
                if (len + 1 >= cap) break;
                pkt->pathname[len++] = 'a';
            }
            pkt->pathname[len] = '\0';
            break;
        }

        default: return 0;
    }

    return 1;
}



int add_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 1);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "-la");
    return 1;
}

int delete_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 0);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
    return 1;
}

int mutate_list_pathname(ftp_list_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 26;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){

        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;              
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".."); break;             
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;              
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/www"); break;       
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "sub/dir"); break;        

        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-l"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-la"); break;
        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-alh"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-la /etc"); break;     

        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[a-z]??.c"); break;

        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"My Folder\""); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "my folder"); break;

        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "C:\\\\Users\\\\Public"); break;
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\\\\server\\share"); break; /* UNC */
        case 17: {
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname), orig[0]?orig:"/a/b/c");
            swap_separators(pkt->pathname);
            break;
        }

        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir%20with%20space"); break;
        case 19: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "%2e%2e/%2e%2e"); break;    
        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "foo_STAT"); break;         


        case 21: {
            set_space(pkt->space,1);
            const char *src = orig[0]?orig:"a////b\\\\\\\\c////";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "a\\\\b/c//d"); break;

        case 23: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'L', cap-1);
                pkt->pathname[cap-1]='\0';
            } else {
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 24: { 
            set_space(pkt->space,1);
            pkt->pathname[0] = '\0';
            size_t cap = sizeof(pkt->pathname), len = 0;
            while (len + 2 < cap){
                pkt->pathname[len++] = '/';
                if (len+1>=cap) break;
                pkt->pathname[len++] = 'a';
            }
            pkt->pathname[len] = '\0';
            break;
        }


        case 25:
            set_space(pkt->space,0);         
            pkt->pathname[0] = '\0';          
            break;

        default: return 0;
    }
    return 1;
}


int add_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 1);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "*");
    return 1;
}

int delete_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;
    set_space(pkt->space, 0);
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "");
    return 1;
}

int mutate_nlst_pathname(ftp_nlst_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 28;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch(op){
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".."); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/tmp"); break;
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "sub/dir"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "./subdir"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "../other"); break;

        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "file?.c"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[0-9]*"); break;

        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-a"); break;     
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-R"); break;     
        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "-a /etc"); break;

        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"My Folder\""); break;
        case 16: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "my folder"); break;

        case 17: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "C:\\\\Temp\\\\"); break;
        case 18: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\\\\server\\share"); break;
        case 19: {
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname), orig[0]?orig:"a/b\\c\\d/e");
            swap_separators(pkt->pathname);
            break;
        }

        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir%20with%20space"); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "%2e%2e/%2e%2e"); break;

        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "foo_STAT"); break;

        case 23: {
            set_space(pkt->space,1);
            const char *src = orig[0]?orig:"a////b\\\\\\\\c////";
            collapse_slashes(src, pkt->pathname, sizeof(pkt->pathname));
            break;
        }
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "a\\\\b/c//d"); break;

        case 25: { 
            set_space(pkt->space,1);
            size_t cap = sizeof(pkt->pathname);
            if (cap > 1){
                memset(pkt->pathname, 'N', cap-1);
                pkt->pathname[cap-1]='\0';
            } else {
                set_cstr(pkt->pathname, cap, "");
            }
            break;
        }
        case 26: { 
            set_space(pkt->space,1);
            pkt->pathname[0] = '\0';
            size_t cap = sizeof(pkt->pathname), len = 0;
            while (len + 2 < cap){
                pkt->pathname[len++] = '/';
                if (len+1>=cap) break;
                pkt->pathname[len++] = 'n';
            }
            pkt->pathname[len] = '\0';
            break;
        }


        case 27:
            set_space(pkt->space,0);       
            pkt->pathname[0] = '\0';        
            break;

        default: return 0;
    }
    return 1;
}



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


int mutate_site_parameters(ftp_site_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PARAMS];
    set_cstr(orig, sizeof(orig), pkt->parameters);

    switch (op){
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
        case 11: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "EXEC echo ping"); break; 


        case 12: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHGRP staff /srv/data"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SYMLINK /srv/a /srv/b"); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "MSG Hello World"); break;


        case 15:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "   chmod    644\tfoo.txt  ");
            squeeze_spaces(pkt->parameters, pkt->parameters, sizeof(pkt->parameters));
            break;
        case 16:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     orig[0]?orig:"ChMoD 7a5 bad");
            toggle_case(pkt->parameters);
            break;
        case 17:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "\"Folder With Spaces\"");
            break;
        case 18:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "CHMOD\t700\tfolder");
            break;


        case 19: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "UMASK 999"); break;
        case 20: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE -10"); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "IDLE 3.14159"); break;
        case 22: {
            set_space(pkt->space,1);
            memset(pkt->parameters, '9', sizeof(pkt->parameters)-1);
            pkt->parameters[sizeof(pkt->parameters)-1] = '\0';
            break;
        }


        case 23: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 640 /path/with%20space"); break;
        case 24: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "CHMOD 755 /数据/文件"); break; /* UTF-8 */
        case 25: set_space(pkt->space,1); set_cstr(pkt->parameters,sizeof(pkt->parameters), "SETTYPE X"); break;  /* 非法类型但语法OK */


        case 26:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters), "HELP STAT");
            break;

        case 27:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "CHMOD 700 ../../tmp/x");
            break;
        case 28:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "JSON {\"cmd\":\"CHMOD\",\"mode\":511,\"path\":\"/var/tmp/x\"}");
            break;
        case 29:
            set_space(pkt->space,1);
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "KEY=VALUE;MODE=755;PATH=/var/tmp/x");
            break;


        case 30: { 
            set_space(pkt->space,1);
            memset(pkt->parameters, 'A', sizeof(pkt->parameters)-1);
            pkt->parameters[sizeof(pkt->parameters)-1] = '\0';
            break;
        }

        case 31: {
            set_space(pkt->space,1);  
            set_cstr(pkt->parameters,sizeof(pkt->parameters),
                     "CHMOD 600 /no/space/prefix");
            break;
        }

        default: return 0;
    }
    return 1;
}



void add_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return;
    set_space(pkt->space, 1);                 
    set_cstr(pkt->pathname, sizeof(pkt->pathname), "/var/log");
}

void delete_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return;
    set_cstr(pkt->pathname, sizeof(pkt->pathname), ""); 
    set_space(pkt->space, 0);                           
}


int mutate_stat_pathname(ftp_stat_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_PATH];
    set_cstr(orig, sizeof(orig), pkt->pathname);

    switch (op){
        case 0:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/var/log/syslog"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "dir/subdir/file.txt"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "."); break;
        case 4:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "*.txt"); break;
        case 5:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), ".*"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "[a-zA-Z]*.log"); break;

        case 7:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "\\\\SERVER\\share\\folder\\file"); break;

        case 9:  set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "\"My Folder/file name.txt\""); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "path/with%20space"); break;

        case 11: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "../../etc/passwd"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "////a///b//c/"); break;
        case 13: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "./././target"); break;

        case 14: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "/数据/文件.txt"); break;
        case 15: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname),
                                                  "/tmp/😀.txt"); break;

        case 16: { 
            set_space(pkt->space,1);
            memset(pkt->pathname, 'A', sizeof(pkt->pathname)-1);
            pkt->pathname[sizeof(pkt->pathname)-1] = '\0';
            break;
        }
        case 17: { 
            set_space(pkt->space,1);
            char *p = pkt->pathname;
            size_t cap = sizeof(pkt->pathname);
            size_t used = 0;
            const char *seg = "deep/";
            if (cap == 0) break;
            p[0] = '\0';
            while (used + strlen(seg) + 1 < cap){
                strcpy(p + used, seg);
                used += strlen(seg);
            }
            if (used + 4 < cap) strcpy(p + used, "end");
            break;
        }

        case 18:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname),
                     "path_^M^J_ANOTHER");
            break;

        case 19:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname),
                     "/tmp/\x1b[31mred\x1b[0m");
            break;

        case 20: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "/dev/null"); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "NUL"); break;

        case 22: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "~/file"); break;
        case 23: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "$HOME/.ssh/id_rsa"); break;
        case 24: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "file{1..100}"); break;

        case 25:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname),
                     "  trailing-space  ");
            break;

        case 26:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname),
                     orig[0]?orig:"relative.txt");
            toggle_case(pkt->pathname);
            break;

        case 27:
            set_space(pkt->space,1);
            set_cstr(pkt->pathname,sizeof(pkt->pathname), "nospace_arg");
            break;

        case 28: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "\"unterminated"); break;
        case 29: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "path/with#hash?query=1"); break;
        case 30: set_space(pkt->space,1); set_cstr(pkt->pathname,sizeof(pkt->pathname), "CONIN$"); break;

        case 31:
            set_space(pkt->space,0); 
            set_cstr(pkt->pathname,sizeof(pkt->pathname), "");
            break;

        default: return 0;
    }
    return 1;
}



void add_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return;
    set_space(pkt->space, 1);                    
    set_cstr(pkt->argument, sizeof(pkt->argument), "USER");
}

void delete_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return;
    set_cstr(pkt->argument, sizeof(pkt->argument), ""); 
    set_space(pkt->space, 0);                            
}

int mutate_help_argument(ftp_help_packet_t *pkt){
    if (!pkt) return 0;

    static unsigned op_idx = 0;
    const unsigned OPS = 32;
    unsigned op = (op_idx++) % OPS;

    char orig[FTP_SZ_ARGUMENT];
    set_cstr(orig, sizeof(orig), pkt->argument);

    switch (op){
        case 0:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER"); break;
        case 1:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "STAT"); break;
        case 2:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "RETR"); break;
        case 3:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "abor"); break; 


        case 4:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "FOO"); break;


        case 5:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "SITE CHMOD"); break;
        case 6:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER PASS"); break;


        case 7:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "*"); break;
        case 8:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "?"); break;


        case 9:  set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "12345"); break;
        case 10: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "-h"); break;


        case 11: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "帮助"); break;
        case 12: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "📄"); break;


        case 13: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\r\nQUIT"); break;
        case 14: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "ABOR\tRETR"); break;
        case 15: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "ESC:\x1b[31mRED\x1b[0m"); break;


        case 16: {
            set_space(pkt->space,1);
            memset(pkt->argument, 'A', sizeof(pkt->argument)-1);
            pkt->argument[sizeof(pkt->argument)-1] = '\0';
            break;
        }


        case 17: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "\"unterminated"); break;
        case 18: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\"PASS"); break;


        case 19: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "PASV%0AQUIT"); break;


        case 20: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "  USER  "); break;
        case 21: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "   "); break;

        case 22: set_space(pkt->space,0); set_cstr(pkt->argument,sizeof(pkt->argument), "USER"); break; 
        case 23: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), ""); break;     

        case 24: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER,RETR"); break;
        case 25: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "!@#$%^&*()"); break;

        case 26: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "/etc/passwd"); break;

        case 27: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "'; DROP TABLE"); break;

        case 28: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "HELP"); break;
        case 29: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), orig[0]?orig:"stor"); toggle_case(pkt->argument); break;

        case 30: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "USER\tPASS LIST"); break;

        case 31: set_space(pkt->space,1); set_cstr(pkt->argument,sizeof(pkt->argument), "caf\u0301e"); break;

        default: return 0;
    }
    return 1;
}


#define ARR_CNT(a) (int)(sizeof(a)/sizeof((a)[0]))
static inline uint32_t rnd32(void){
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

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


void dispatch_ftp_multiple_mutations(ftp_packet_t *pkt, int num_packets, int rounds) {
    if (!pkt || num_packets <= 0 || rounds <= 0) return;

    for (int r = 0; r < rounds; ++r) {
        int idx = rand() % num_packets;
        ftp_packet_t *P = &pkt[idx];

        switch (P->command_type) {
            case FTP_USER: dispatch_user_mutation(&P->packet.user, 1); break;
            case FTP_PASS: dispatch_pass_mutation(&P->packet.pass, 1); break;
            case FTP_ACCT: dispatch_acct_mutation(&P->packet.acct, 1); break;

            case FTP_CWD:  dispatch_cwd_mutation (&P->packet.cwd, 1);  break;
            case FTP_SMNT: dispatch_smnt_mutation(&P->packet.smnt, 1); break;

            case FTP_PORT: dispatch_port_mutation(&P->packet.port, 1); break;
            case FTP_TYPE: dispatch_type_mutation(&P->packet.type, 1); break;
            case FTP_STRU: dispatch_stru_mutation(&P->packet.stru, 1); break;
            case FTP_MODE: dispatch_mode_mutation(&P->packet.mode, 1); break;

            case FTP_RETR: dispatch_retr_mutation(&P->packet.retr, 1); break;
            case FTP_STOR: dispatch_stor_mutation(&P->packet.stor, 1); break;
            case FTP_STOU: dispatch_stou_mutation(&P->packet.stou, 1); break;
            case FTP_APPE: dispatch_appe_mutation(&P->packet.appe, 1); break;

            case FTP_ALLO: dispatch_allo_mutation(&P->packet.allo, 1); break;
            case FTP_REST: dispatch_rest_mutation(&P->packet.rest, 1); break;

            case FTP_RNFR: dispatch_rnfr_mutation(&P->packet.rnfr, 1); break;
            case FTP_RNTO: dispatch_rnto_mutation(&P->packet.rnto, 1); break;
            case FTP_DELE: dispatch_dele_mutation(&P->packet.dele, 1); break;
            case FTP_RMD:  dispatch_rmd_mutation (&P->packet.rmd, 1);  break;
            case FTP_MKD:  dispatch_mkd_mutation (&P->packet.mkd, 1);  break;

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