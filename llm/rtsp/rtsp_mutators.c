#include "rtsp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>


static inline void set_cstr(char *dst, size_t cap, const char *s) {
    if (!dst || cap == 0) return;
    if (!s) { dst[0] = '\0'; return; }

    size_t i = 0;
    for (; i + 1 < cap && s[i] != '\0'; ++i) dst[i] = s[i];
    dst[i] = '\0';
}


static inline void set_colon_space(char cs[RTSP_SEPARATOR_LEN]) {
    cs[0] = ':';
    cs[1] = ' ';
#if RTSP_SEPARATOR_LEN > 2
    cs[2] = '\0';
#endif
}
static inline void set_crlf(char crlf[RTSP_CRLF_LEN]) {
    crlf[0] = '\r';
    crlf[1] = '\n';
#if RTSP_CRLF_LEN > 2
    crlf[2] = '\0';
#endif
}
static inline void rng_seed(){ static int s=0; if(!s){ srand((unsigned)time(NULL)); s=1; } }

#ifndef RTSP_URI_LEN
#define RTSP_URI_LEN 256
#endif

static char* get_request_uri_ptr(rtsp_packet_t* p) {
    switch (p->type) {
        case RTSP_TYPE_OPTIONS:       return p->options.request_uri;
        case RTSP_TYPE_DESCRIBE:      return p->describe.request_uri;
        case RTSP_TYPE_SETUP:         return p->setup.request_uri;
        case RTSP_TYPE_PLAY:          return p->play.request_uri;
        case RTSP_TYPE_PAUSE:         return p->pause.request_uri;
        case RTSP_TYPE_TEARDOWN:      return p->teardown.request_uri;
        case RTSP_TYPE_GET_PARAMETER: return p->get_parameter.request_uri;
        case RTSP_TYPE_SET_PARAMETER: return p->set_parameter.request_uri;
        case RTSP_TYPE_REDIRECT:      return p->redirect.request_uri;
        case RTSP_TYPE_ANNOUNCE:      return p->announce.request_uri;
        case RTSP_TYPE_RECORD:        return p->record.request_uri;
        default: return NULL;
    }
}

static void set_uri(char* dst, const char* src) {
    if (!dst) return;
    size_t cap = RTSP_URI_LEN;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}


static void make_repeated_char(char* out, size_t cap, char ch, size_t count) {
    if (!out || cap == 0) return;
    if (count >= cap) count = cap - 1;
    for (size_t i = 0; i < count; ++i) out[i] = ch;
    out[count] = '\0';
}


static void rand_digits(char* out, size_t cap, int digits) {
    if (!out || cap == 0) return;
    if (digits >= (int)cap) digits = (int)cap - 1;
    for (int i = 0; i < digits; ++i) out[i] = '0' + (rand() % 10);
    out[digits] = '\0';
}


static void mut_op_absolute_valid(char* uri) {
    set_uri(uri, "rtsp://127.0.0.1:8554/test.sdp");
}
static void mut_op_asterisk(char* uri) {
    set_uri(uri, "*");
}
static void mut_op_empty(char* uri) {
    set_uri(uri, "");
}
static void mut_op_very_long_path(char* uri) {
    char buf[RTSP_URI_LEN];
    char path[RTSP_URI_LEN];
    make_repeated_char(path, sizeof(path), 'A', RTSP_URI_LEN-10);
    snprintf(buf, sizeof(buf), "rtsp://host/%s", path);
    set_uri(uri, buf);
}
static void mut_op_traversal(char* uri) {
    set_uri(uri, "rtsp://host/../../../../../../etc/passwd");
}
static void mut_op_percent_encoding(char* uri) {
    set_uri(uri, "rtsp://host/stream%2Esdp?x=%00%2F..%2F&y=%FF");
}
static void mut_op_utf8(char* uri) {

    set_uri(uri, "rtsp://host/摄像头/通道一.sdp");
}
static void mut_op_ipv6_edge_port(char* uri) {
    set_uri(uri, "rtsp://[2001:db8::1]:65535/stream");
}
static void mut_op_userinfo(char* uri) {
    set_uri(uri, "rtsp://user:pa%3Ass@host:0/hidden");
}
static void mut_op_scheme_variants(char* uri) {
    set_uri(uri, "RTSPu://HOST/UPCASE");
}
static void mut_op_query_fragment(char* uri) {
    set_uri(uri, "rtsp://host/stream.sdp?track=video&rate=1.0#frag");
}
static void mut_op_illegal_chars_inject(char* uri) {
    set_uri(uri, "rtsp://host/evil\r\nInjected: yes");
}

typedef void (*uri_mut_fn)(char*);
static uri_mut_fn k_ops[] = {
    mut_op_absolute_valid,
    mut_op_asterisk,
    mut_op_empty,
    mut_op_very_long_path,
    mut_op_traversal,
    mut_op_percent_encoding,
    mut_op_utf8,
    mut_op_ipv6_edge_port,
    mut_op_userinfo,
    mut_op_scheme_variants,
    mut_op_query_fragment,
    mut_op_illegal_chars_inject,
};

static size_t num_ops(void){ return sizeof(k_ops)/sizeof(k_ops[0]); }
static const int k_base_weights[12] = {
    100, 
    100, 
      0, 
      0, 
      0, 
      0, 
    100, 
    100, 
      0, 
      0, 
      0, 
      0  
};

static size_t weighted_pick_idx(const int *w, size_t n){
    long total = 0;
    for(size_t i=0;i<n;++i) total += (w[i] > 0 ? w[i] : 0);
    if(total <= 0) return 0;
    long r = rand() % total;
    long acc = 0;
    for(size_t i=0;i<n;++i){
        int wi = (w[i] > 0 ? w[i] : 0);
        if(wi == 0) continue;
        acc += wi;
        if(r < acc) return i;
    }
    return 0;
}


void mutate_request_uri(rtsp_packet_t *pkts, size_t n) {
    if (!pkts) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; ++i) {
        char* uri = get_request_uri_ptr(&pkts[i]);
        if (!uri) continue;

        int w[12];
        for(size_t j=0;j<12;++j) w[j] = k_base_weights[j];
        if (pkts[i].type != RTSP_TYPE_OPTIONS) {
            w[1] = 0; /* mut_op_asterisk */
        }


        size_t op_idx = weighted_pick_idx(w, num_ops());
        k_ops[op_idx](uri);

    }
}


#ifndef RTSP_HEADER_NAME_LEN
#define RTSP_HEADER_NAME_LEN 16
#endif
#ifndef RTSP_SEPARATOR_LEN
#define RTSP_SEPARATOR_LEN 3
#endif
#ifndef RTSP_CRLF_LEN
#define RTSP_CRLF_LEN 3
#endif

static inline cseq_header_rtsp_t* get_cseq_header_ptr(rtsp_packet_t *pkt) {
    if (!pkt) return NULL;
    switch (pkt->type) {
    case RTSP_TYPE_OPTIONS:        return &pkt->options.cseq_header;
    case RTSP_TYPE_DESCRIBE:       return &pkt->describe.cseq_header;
    case RTSP_TYPE_SETUP:          return &pkt->setup.cseq_header;
    case RTSP_TYPE_PLAY:           return &pkt->play.cseq_header;
    case RTSP_TYPE_PAUSE:          return &pkt->pause.cseq_header;
    case RTSP_TYPE_TEARDOWN:       return &pkt->teardown.cseq_header;
    case RTSP_TYPE_GET_PARAMETER:  return &pkt->get_parameter.cseq_header;
    case RTSP_TYPE_SET_PARAMETER:  return &pkt->set_parameter.cseq_header;
    case RTSP_TYPE_REDIRECT:       return &pkt->redirect.cseq_header;
    case RTSP_TYPE_ANNOUNCE:       return &pkt->announce.cseq_header;
    case RTSP_TYPE_RECORD:         return &pkt->record.cseq_header;
    default:                       return NULL;
    }
}
static inline void ensure_header_shape(cseq_header_rtsp_t *h) {
    if (!h) return;
    if (h->name[0] == '\0') set_cstr(h->name, sizeof(h->name), "CSeq");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
    if (h->number < 1) h->number = 1; 
}


static void op_valid_increment(cseq_header_rtsp_t *h) {
    ensure_header_shape(h);
    if (h->number < INT_MAX) h->number += 1;
}
static void op_zero(cseq_header_rtsp_t *h) { 
    ensure_header_shape(h);
    h->number = 0;
}
static void op_negative(cseq_header_rtsp_t *h) { 
    ensure_header_shape(h);
    h->number = -1 * (1 + rand() % 1000);
}
static void op_int_max(cseq_header_rtsp_t *h) { 
    ensure_header_shape(h);
    h->number = INT_MAX;
}
static void op_int_min(cseq_header_rtsp_t *h) {
    ensure_header_shape(h);
    h->number = INT_MIN;
}
static void op_large_jump_overflow(cseq_header_rtsp_t *h) { 
    ensure_header_shape(h);
    h->number += (1u << 30);
}
static void op_random_32(cseq_header_rtsp_t *h) { 
    ensure_header_shape(h);
    h->number = (int)((unsigned)rand() ^ ((unsigned)rand() << 1));
}
static void op_flip_lowbit(cseq_header_rtsp_t *h) {
    ensure_header_shape(h);
    h->number ^= 1;
}
static void op_off_by_one_zero(cseq_header_rtsp_t *h) {
    ensure_header_shape(h);
    if (h->number == 1) h->number = 0; else h->number = 1;
}
static void op_missing_header(cseq_header_rtsp_t *h) {
    h->name[0] = '\0';
}
static void op_bad_name_spelling(cseq_header_rtsp_t *h) { 
    set_cstr(h->name, sizeof(h->name), (rand()%2)? "CSeQ" : "cseq");
    set_colon_space(h->colon_space);
    set_crlf(h->crlf);
}
static void op_bad_colon_space(cseq_header_rtsp_t *h) {
    set_cstr(h->name, sizeof(h->name), "CSeq");
    int r = rand()%3;
    if (r==0) { h->colon_space[0]=':'; h->colon_space[1]='\0'; }
    else if (r==1){ h->colon_space[0]=' '; h->colon_space[1]=' '; h->colon_space[2]='\0'; }
    else { h->colon_space[0]=':'; h->colon_space[1]=':'; h->colon_space[2]='\0'; }
    set_crlf(h->crlf);
}
static void op_bad_crlf(cseq_header_rtsp_t *h) { 
    set_cstr(h->name, sizeof(h->name), "CSeq");
    set_colon_space(h->colon_space);
    if (RTSP_CRLF_LEN >= 2) h->crlf[0] = '\n', h->crlf[1] = '\0';
}

static void op_non_monotonic_series(rtsp_packet_t *arr, size_t n) {
    if (!arr || n == 0) return;
    int base = 100 + (rand()%100);
    for (size_t i = 0; i < n; ++i) {
        cseq_header_rtsp_t *h = get_cseq_header_ptr(&arr[i]);
        set_cstr(h->name, sizeof(h->name), "CSeq");
        set_colon_space(h->colon_space);
        set_crlf(h->crlf);
        int delta = (int)(rand()%3); 
        base -= delta;
        h->number = base;
        if (rand()%4==0) h->number = base+1; 
    }
}

void mutate_cseq(rtsp_packet_t *pkts, size_t n) {
    if (!pkts) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    typedef void (*one_fn)(cseq_header_rtsp_t*);
    one_fn single_ops[] = {
        op_valid_increment,    
        op_zero,               
        op_negative,           
        op_int_max,            
        op_int_min,            
        op_large_jump_overflow,
        op_random_32,          
        op_flip_lowbit,        
        op_off_by_one_zero,    
        op_missing_header,     
        op_bad_name_spelling,  
        op_bad_colon_space,    
        op_bad_crlf            
    };
    const size_t single_cnt = sizeof(single_ops)/sizeof(single_ops[0]);

    static const int weights_single[13] = {
        100, 
          0, 
          0, 
        100, 
          0, 
          0, 
          0, 
          0, 
          0, 
          0, 
          0, 
          0, 
          0  
    };

    const int weight_series = 0;

    if (n > 1 && weight_series > 0) {
        op_non_monotonic_series(pkts, n);
        return;
    }

    for (size_t i = 0; i < n; ++i) {
        cseq_header_rtsp_t *h = get_cseq_header_ptr(&pkts[i]);
        size_t idx = weighted_pick_idx(weights_single, single_cnt);
        single_ops[idx](h);

        if (h->number <= 0) {
            ensure_header_shape(h);
            h->number = 1;
        }
    }
}





#ifndef RTSP_HEADER_NAME_LEN
#define RTSP_HEADER_NAME_LEN 16
#endif
#ifndef RTSP_SEPARATOR_LEN
#define RTSP_SEPARATOR_LEN 3
#endif
#ifndef RTSP_CRLF_LEN
#define RTSP_CRLF_LEN 3
#endif


static accept_header_rtsp_t* get_accept_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.accept_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.accept_header;
        default: return NULL;
    }
}

void add_accept(rtsp_packet_t *arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; ++i) {
        accept_header_rtsp_t *h = get_accept_ptr(&arr[i]);
        if (!h) continue;
        set_cstr(h->name, sizeof(h->name), "Accept");
        set_colon_space(h->colon_space);
        set_cstr(h->media_type, sizeof(h->media_type), "application");
        h->slash = '/';
        set_cstr(h->sub_type, sizeof(h->sub_type), "sdp");
        set_crlf(h->crlf);
    }
}

void delete_accept(rtsp_packet_t *arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; ++i) {
        accept_header_rtsp_t *h = get_accept_ptr(&arr[i]);
        if (!h) continue;
        h->name[0] = '\0';
    }
}

void repeat_accept(rtsp_packet_t *arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; ++i) {
        accept_header_rtsp_t *h = get_accept_ptr(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Accept");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
        }

        set_cstr(h->name, sizeof(h->name), "Accept");
        set_colon_space(h->colon_space);

        set_cstr(h->media_type, sizeof(h->media_type),
                 "application/sdp, */*;q=0.1, text/plain");
        h->slash = '\0';
        h->sub_type[0] = '\0';
        set_crlf(h->crlf);
    }
}
static void ensure_accept_shape(accept_header_rtsp_t* h){
    if(!h) return;
    if(h->name[0]=='\0') set_cstr(h->name, sizeof(h->name), "Accept");
    set_colon_space(h->colon_space);
    if(h->slash=='\0') h->slash='/';
    set_crlf(h->crlf);
}

static void acc_set_valid_sdp(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp"); set_crlf(h->crlf);
}
static void acc_set_wildcard_any(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"*"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"*"); set_crlf(h->crlf);
}
static void acc_set_with_params(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp;level=1;q=1.0;charset=utf-8"); set_crlf(h->crlf);
}
static void acc_missing_subtype(accept_header_rtsp_t* h){
    ensure_accept_shape(h);
    set_cstr(h->media_type,sizeof(h->media_type),"application");
    h->slash = '/';
    h->sub_type[0]='\0'; 
}
static void acc_missing_slash(accept_header_rtsp_t* h){
    ensure_accept_shape(h);
    set_cstr(h->media_type,sizeof(h->media_type),"applicationsdp"); 
    h->slash = '\0';
    h->sub_type[0]='\0';
}
static void acc_bad_name(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),(rand()%2)?"ACCEPT":"accept"); 
    set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp"); set_crlf(h->crlf);
}
static void acc_bad_sep(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept");
    int r = rand()%3;
    if(r==0){ h->colon_space[0]=':'; h->colon_space[1]='\0'; }
    else if(r==1){ h->colon_space[0]=':'; h->colon_space[1]=':'; h->colon_space[2]='\0'; }
    else { h->colon_space[0]=' '; h->colon_space[1]=' '; h->colon_space[2]='\0'; }
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp"); set_crlf(h->crlf);
}
static void acc_empty(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    h->media_type[0]='\0'; h->slash='\0'; h->sub_type[0]='\0'; set_crlf(h->crlf);
}
static void acc_delete(accept_header_rtsp_t* h){
    h->name[0]='\0'; 
}
static void acc_multi_values_in_one(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application/sdp, */*;q=0.1, text/plain");
    h->slash='\0'; h->sub_type[0]='\0'; set_crlf(h->crlf);
}
static void acc_super_long(accept_header_rtsp_t* h){
    memset(h->media_type,'A',sizeof(h->media_type)-1); h->media_type[sizeof(h->media_type)-1]='\0';
    h->slash='/';
    memset(h->sub_type,'B',sizeof(h->sub_type)-1); h->sub_type[sizeof(h->sub_type)-1]='\0';
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space); set_crlf(h->crlf);
}
static void acc_non_ascii(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"应用"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"描述"); set_crlf(h->crlf);
}
static void acc_inject_crlf(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept");
    set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application\r\nInjected: yes");
    h->slash = '/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp");
    set_crlf(h->crlf);
}
static void acc_illegal_token(accept_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Accept"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"app,lication"); 
    h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sd p");       
    set_crlf(h->crlf);
}

typedef void (*acc_fn)(accept_header_rtsp_t*);
static acc_fn k_acc_ops[] = {
    acc_set_valid_sdp,
    acc_set_wildcard_any,
    acc_set_with_params,
    acc_missing_subtype,
    acc_missing_slash,
    acc_bad_name,
    acc_bad_sep,
    acc_empty,
    acc_delete,
    acc_multi_values_in_one,
    acc_super_long,
    acc_non_ascii,
    acc_inject_crlf,
    acc_illegal_token,
};
static size_t acc_ops_count(void){ return sizeof(k_acc_ops)/sizeof(k_acc_ops[0]); }
static size_t weighted_pick_idx_accept(const int *weights, size_t n_ops) {
    if (!weights || n_ops == 0) {
        return 0; 
    }

    long long total = 0;

    for (size_t i = 0; i < n_ops; i++) {
        if (weights[i] > 0) {
            total += weights[i];
        }
    }

    if (total <= 0) {
        return (size_t)(rand() % n_ops);
    }

    long long r = rand() % total;
    long long acc = 0;

    for (size_t i = 0; i < n_ops; i++) {
        if (weights[i] <= 0) {
            continue;   
        }
        acc += weights[i];
        if (r < acc) {
            return i;
        }
    }

    return n_ops - 1;
}

static const int weights_accept_ops[14] = {
    100, /* 0: acc_set_valid_sdp       */
    100, /* 1: acc_set_wildcard_any    */
    100, /* 2: acc_set_with_params     */
      0, /* 3: acc_missing_subtype     */
      0, /* 4: acc_missing_slash       */
      0, /* 5: acc_bad_name            */
      0, /* 6: acc_bad_sep             */
      0, /* 7: acc_empty               */
      0, /* 8: acc_delete              */
    100, /* 9: acc_multi_values_in_one */
      0, /*10: acc_super_long          */
      0, /*11: acc_non_ascii           */
      0, /*12: acc_inject_crlf         */
      0  /*13: acc_illegal_token       */
};


void mutate_accept(rtsp_packet_t *pkts, size_t n){
    if(!pkts) return;
    static int seeded=0; if(!seeded){ srand((unsigned)time(NULL)); seeded=1; }

    for(size_t i=0;i<n;i++){
        accept_header_rtsp_t *h = get_accept_ptr(&pkts[i]);
        if(!h) continue; 

        size_t idx = weighted_pick_idx_accept(weights_accept_ops, acc_ops_count());
        k_acc_ops[idx](h);
    }
}


static inline accept_encoding_header_rtsp_t* get_ae_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.accept_encoding_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.accept_encoding_header;
        default: return NULL;
    }
}

void add_accept_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_encoding_header_rtsp_t *h = get_ae_ptr(&arr[i]);
        if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Accept-Encoding");
        set_colon_space(h->colon_space);
        set_cstr(h->encoding, sizeof(h->encoding), "gzip, deflate, identity");
        set_crlf(h->crlf);
    }
}

void delete_accept_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_encoding_header_rtsp_t *h = get_ae_ptr(&arr[i]);
        if(!h) continue;
        h->name[0] = '\0';
    }
}

void repeat_accept_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_encoding_header_rtsp_t *h = get_ae_ptr(&arr[i]);
        if(!h) continue;
        if(h->name[0] == '\0'){
            set_cstr(h->name, sizeof(h->name), "Accept-Encoding");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
        }
        set_cstr(h->encoding, sizeof(h->encoding),
                 "gzip, deflate, br, identity;q=0, *;q=0.1, unknown");
    }
}


static void ae_set_gzip(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip");
    set_crlf(h->crlf);
}
static void ae_set_identity_only(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"identity");
    set_crlf(h->crlf);
}
static void ae_set_all_wildcard(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"*");
    set_crlf(h->crlf);
}
static void ae_set_with_qparams(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip;q=1.0, deflate;q=0.5, br;q=0.0");
    set_crlf(h->crlf);
}
static void ae_empty_value(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    h->encoding[0] = '\0'; 
    set_crlf(h->crlf);
}
static void ae_bad_name_case(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),(rand()%2)?"ACCEPT-ENCODING":"accept-encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip, deflate");
    set_crlf(h->crlf);
}
static void ae_bad_separator(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    int r = rand()%3;
    if(r==0){ h->colon_space[0]=':'; h->colon_space[1]='\0'; }
    else if(r==1){ h->colon_space[0]=':'; h->colon_space[1]=':'; h->colon_space[2]='\0'; }
    else { h->colon_space[0]=' '; h->colon_space[1]=' '; h->colon_space[2]='\0'; }
    set_cstr(h->encoding,sizeof(h->encoding),"gzip");
    set_crlf(h->crlf);
}
static void ae_super_long(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    for(size_t i=0;i+1<sizeof(h->encoding);++i) h->encoding[i] = (i%2)?'a':'A';
    h->encoding[sizeof(h->encoding)-1] = '\0';
    set_crlf(h->crlf);
}
static void ae_non_ascii(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"压缩, 无损"); 
    set_crlf(h->crlf);
}
static void ae_inject_crlf(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip\r\nInjected: yes");
    set_crlf(h->crlf);
}
static void ae_illegal_token(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzi p, defl,ate, br; q = 1"); 
    set_crlf(h->crlf);
}
static void ae_duplicates_and_order(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"deflate, gzip, deflate;q=0.2, gzip;q=0.9");
    set_crlf(h->crlf);
}
static void ae_zero_or_over_q(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip;q=0, br;q=1.1, identity;q=-0.1"); 
    set_crlf(h->crlf);
}
static void ae_unknown_and_wildcard(accept_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Encoding");
    set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"x-custom, *;q=0.05");
    set_crlf(h->crlf);
}

typedef void (*ae_fn)(accept_encoding_header_rtsp_t*);
static ae_fn k_ae_ops[] = {
    ae_set_gzip,
    ae_set_identity_only,
    ae_set_all_wildcard,
    ae_set_with_qparams,
    ae_empty_value,
    ae_bad_name_case,
    ae_bad_separator,
    ae_super_long,
    ae_non_ascii,
    ae_inject_crlf,
    ae_illegal_token,
    ae_duplicates_and_order,
    ae_zero_or_over_q,
    ae_unknown_and_wildcard,
};
static size_t ae_ops_count(void){ return sizeof(k_ae_ops)/sizeof(k_ae_ops[0]); }

static const int weights_ae_ops[14] = {
    100, /*  0: ae_set_gzip              */
    100, /*  1: ae_set_identity_only     */
    100, /*  2: ae_set_all_wildcard      */
    100, /*  3: ae_set_with_qparams      */
      0, /*  4: ae_empty_value           */
      0, /*  5: ae_bad_name_case         */
      0, /*  6: ae_bad_separator         */
      0, /*  7: ae_super_long            */
      0, /*  8: ae_non_ascii             */
      0, /*  9: ae_inject_crlf           */
      0, /* 10: ae_illegal_token         */
    100, /* 11: ae_duplicates_and_order  */
      0, /* 12: ae_zero_or_over_q        */
    100, /* 13: ae_unknown_and_wildcard  */
};

void mutate_accept_encoding(rtsp_packet_t *pkts, size_t n){
    if (!pkts) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; i++) {
        accept_encoding_header_rtsp_t *h = get_ae_ptr(&pkts[i]);
        if (!h) continue; 

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Accept-Encoding");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
            set_cstr(h->encoding, sizeof(h->encoding), "identity");
        }

        size_t idx = weighted_pick_idx(weights_ae_ops, ae_ops_count());
        k_ae_ops[idx](h);
    }
}


static inline void clear_entry(accept_language_header_rtsp_t *h){
    if(!h) return;
    for(int i=0;i<MAX_ACCEPT_LANG;i++){
        h->entries[i].language_tag[0] = '\0';
        h->entries[i].qvalue[0] = '\0';
    }
    h->entry_count = 0;
}

static inline accept_language_header_rtsp_t* get_al_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.accept_language_header;
        case RTSP_TYPE_SETUP:         return &p->setup.accept_language_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.accept_language_header;
        case RTSP_TYPE_PLAY:          return &p->play.accept_language_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.accept_language_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.accept_language_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.accept_language_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.accept_language_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.accept_language_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.accept_language_header;
        case RTSP_TYPE_RECORD:        return &p->record.accept_language_header;
        default: return NULL;
    }
}

static inline void al_set_entry(accept_language_header_rtsp_t *h, int idx,
                                const char *tag, const char *q ){
    if(!h || idx<0 || idx>=MAX_ACCEPT_LANG) return;
    set_cstr(h->entries[idx].language_tag, sizeof(h->entries[idx].language_tag), tag?tag:"");
    set_cstr(h->entries[idx].qvalue, sizeof(h->entries[idx].qvalue), q?q:"");
}

/* ========== 2) add_/delete_ ========== */
void add_accept_language(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_language_header_rtsp_t *h = get_al_ptr(&arr[i]);
        if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Accept-Language");
        set_colon_space(h->colon_space);
        clear_entry(h);
        al_set_entry(h, 0, "en-US", "1.0");
        al_set_entry(h, 1, "en",    "0.8");
        h->entry_count = 2;
        set_crlf(h->crlf);
    }
}

void delete_accept_language(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_language_header_rtsp_t *h = get_al_ptr(&arr[i]);
        if(!h) continue;
        h->name[0] = '\0';         
        h->entry_count = 0;
    }
}

void repeat_accept_language(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        accept_language_header_rtsp_t *h = get_al_ptr(&arr[i]);
        if(!h) continue;

        if(h->name[0] == '\0'){
            set_cstr(h->name, sizeof(h->name), "Accept-Language");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
        }
        clear_entry(h);

        const char* tags[] = {"en-US","en-GB","fr-FR","de-DE","zh-CN","zh","es-ES","*"};
        const char* qs[]   = {"1.0","0.9","0.8","0.7","0.5","0.3","0.1",""}; 

        int m = MAX_ACCEPT_LANG;
        for(int k=0;k<m;k++){
            al_set_entry(h, k, tags[k%8], qs[k%8]);
        }
        h->entry_count = m;
    }
}

static void al_valid_simple(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en-US","1.0");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_valid_multi_ordered(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en","1.0");
    al_set_entry(h,1,"fr","0.7");
    al_set_entry(h,2,"de","0.3");
    h->entry_count = 3;
    set_crlf(h->crlf);
}
static void al_with_wildcard(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"*","0.1");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_duplicate_tags(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en-US","1.0");
    al_set_entry(h,1,"en-US","0.5");
    h->entry_count = 2;
    set_crlf(h->crlf);
}
static void al_zero_q_and_over_one(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"fr-CA","0");    
    al_set_entry(h,1,"fr","1.1");    
    h->entry_count = 2;
    set_crlf(h->crlf);
}
static void al_negative_or_alpha_q(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"de-DE","-0.5");
    al_set_entry(h,1,"de","abc");
    h->entry_count = 2;
    set_crlf(h->crlf);
}
static void al_bad_tag_format(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en_US","1.0");  
    al_set_entry(h,1,"","0.5");       
    h->entry_count = 2;
    set_crlf(h->crlf);
}
static void al_super_long_tag(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    char longtag[64]; memset(longtag,'X',sizeof(longtag)); longtag[sizeof(longtag)-1]='\0';
    al_set_entry(h,0,longtag,"0.8");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_non_ascii_tag(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"中文","0.9");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_inject_crlf(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en-US\r\nInjected: yes","1.0");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_bad_separator(accept_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    int r = rand()%3;
    if(r==0){ h->colon_space[0]=':'; h->colon_space[1]='\0'; }
    else if(r==1){ h->colon_space[0]=':'; h->colon_space[1]=':'; h->colon_space[2]='\0'; }
    else { h->colon_space[0]=' '; h->colon_space[1]=' '; h->colon_space[2]='\0'; }
    clear_entry(h);
    al_set_entry(h,0,"en","1.0");
    h->entry_count = 1;
    set_crlf(h->crlf);
}
static void al_delete_header(accept_language_header_rtsp_t *h){ 
    h->name[0] = '\0';
    h->entry_count = 0;
}
static void al_entry_count_overflow(accept_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Accept-Language");
    set_colon_space(h->colon_space);
    clear_entry(h);
    al_set_entry(h,0,"en","1.0");
    h->entry_count = MAX_ACCEPT_LANG + 10; 
    set_crlf(h->crlf);
}

/* 算子表（≥12种） */
typedef void (*al_fn)(accept_language_header_rtsp_t*);
static al_fn k_al_ops[] = {
    al_valid_simple,
    al_valid_multi_ordered,
    al_with_wildcard,
    al_duplicate_tags,
    al_zero_q_and_over_one,
    al_negative_or_alpha_q,
    al_bad_tag_format,
    al_super_long_tag,
    al_non_ascii_tag,
    al_inject_crlf,
    al_bad_separator,
    al_delete_header,
    al_entry_count_overflow,
};
static size_t al_ops_count(void){ return sizeof(k_al_ops)/sizeof(k_al_ops[0]); }
/* —— Accept-Language 变异算子权重：只保留语法合法变体 —— */
static const int weights_al_ops[13] = {
    100, /*  0: al_valid_simple          */
    100, /*  1: al_valid_multi_ordered   */
    100, /*  2: al_with_wildcard         */
    100, /*  3: al_duplicate_tags        */
      0, /*  4: al_zero_q_and_over_one   */
      0, /*  5: al_negative_or_alpha_q   */
      0, /*  6: al_bad_tag_format        */
      0, /*  7: al_super_long_tag        */
      0, /*  8: al_non_ascii_tag         */
      0, /*  9: al_inject_crlf           */
      0, /* 10: al_bad_separator         */
      0, /* 11: al_delete_header         */
      0, /* 12: al_entry_count_overflow  */
};

void mutate_accept_language(rtsp_packet_t *pkts, size_t n){
    if (!pkts) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; i++) {
        accept_language_header_rtsp_t *h = get_al_ptr(&pkts[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Accept-Language");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
            clear_entry(h);
            al_set_entry(h, 0, "en", "1.0");
            h->entry_count = 1;
        }

        size_t idx = weighted_pick_idx(weights_al_ops, al_ops_count());
        k_al_ops[idx](h);
    }
}

static inline authorization_header_rtsp_t* get_auth_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.authorization_header;
        case RTSP_TYPE_SETUP:         return &p->setup.authorization_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.authorization_header;
        case RTSP_TYPE_PLAY:          return &p->play.authorization_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.authorization_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.authorization_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.authorization_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.authorization_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.authorization_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.authorization_header;
        case RTSP_TYPE_RECORD:        return &p->record.authorization_header;
        default: return NULL;
    }
}

/* =============== 2) add_/delete_ ================== */
void add_authorization(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        authorization_header_rtsp_t *h = get_auth_ptr(&arr[i]);
        if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Authorization");
        set_colon_space(h->colon_space);
        set_cstr(h->auth_type, sizeof(h->auth_type), "Basic");
        h->space = ' ';
        set_cstr(h->credentials, sizeof(h->credentials), "dXNlcjpwYXNz");
        set_crlf(h->crlf);
    }
}

void delete_authorization(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        authorization_header_rtsp_t *h = get_auth_ptr(&arr[i]);
        if(!h) continue;
        h->name[0] = '\0';  
        h->auth_type[0] = '\0';
        h->credentials[0] = '\0';
    }
}


void repeat_authorization(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        authorization_header_rtsp_t *h = get_auth_ptr(&arr[i]);
        if(!h) continue;

        if(h->name[0] == '\0'){ 
            set_cstr(h->name, sizeof(h->name), "Authorization");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
        }

        set_cstr(h->auth_type, sizeof(h->auth_type), "Basic");
        h->space = ' ';
        set_cstr(h->credentials, sizeof(h->credentials),
                 "dXNlcjpwYXNz, Zm9vOmJhcg==, Og=="); /* user:pass, foo:bar, ":" */
    }
}


static void auth_basic_valid(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"Z3Vlc3Q6Z3Vlc3Q="); /* guest:guest */
    set_crlf(h->crlf);
}
static void auth_basic_empty(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    h->credentials[0] = '\0';
    set_crlf(h->crlf);
}
static void auth_basic_invalid_b64(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"!!not_base64!!");
    set_crlf(h->crlf);
}
static void auth_basic_super_long(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    for(size_t i=0;i+1<sizeof(h->credentials);++i) h->credentials[i] = (i%3)?'A':'=';
    h->credentials[sizeof(h->credentials)-1] = '\0';
    set_crlf(h->crlf);
}
static void auth_name_badcase(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),(rand()%2)?"AUTHORIZATION":"authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"Zjp4"); /* f:x */
    set_crlf(h->crlf);
}
static void auth_bad_separator(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    int r = rand()%3;
    if(r==0){ h->colon_space[0]=':'; h->colon_space[1]='\0'; }
    else if(r==1){ h->colon_space[0]=':'; h->colon_space[1]=':'; h->colon_space[2]='\0'; }
    else { h->colon_space[0]=' '; h->colon_space[1]=' '; h->colon_space[2]='\0'; }
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"Z3Y6Z3Y="); /* gv:gv */
    set_crlf(h->crlf);
}


static void auth_digest_valid(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "username=\"user\", realm=\"live\", nonce=\"abc\", uri=\"rtsp://x\", "
        "response=\"0123456789abcdef\", qop=auth, nc=00000001, cnonce=\"xyz\"");
    set_crlf(h->crlf);
}


static void auth_digest_missing_params(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"username=\"u\", uri=\"*\"");
    set_crlf(h->crlf);
}
static void auth_digest_bad_qop_nc(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"r\", "
        "qop=auth-int, nc=ZZZZZZZZ, cnonce=\"c\"");
    set_crlf(h->crlf);
}
static void auth_digest_unquoted(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "username=user, realm=r, nonce=n, uri=/, response=deadbeef");
    set_crlf(h->crlf);
}
static void auth_digest_dup_params(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "username=\"u\", username=\"u2\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"r\"");
    set_crlf(h->crlf);
}
static void auth_digest_weird_chars(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Digest");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "username=\"用戶\"\r\nInjected: yes");
    set_crlf(h->crlf);
}

static void auth_unknown_scheme(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Bearer"); 
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),"tok_tok_tok");
    set_crlf(h->crlf);
}
static void auth_multiple_schemes_in_one(authorization_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);
    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ' ';
    set_cstr(h->credentials,sizeof(h->credentials),
        "ZGVtbzpwYXNz, Digest username=\"u\", realm=\"r\"");
    set_crlf(h->crlf);
}
static void auth_no_space_between_scheme_and_cred(authorization_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Authorization");
    set_colon_space(h->colon_space);

    set_cstr(h->auth_type,sizeof(h->auth_type),"Basic");
    h->space = ':'; 
    set_cstr(h->credentials,sizeof(h->credentials),"Zjp6");
    set_crlf(h->crlf);
}
static void auth_delete_whole_header(authorization_header_rtsp_t *h){ 
    h->name[0] = '\0';
    h->auth_type[0] = '\0';
    h->credentials[0] = '\0';
}

typedef void (*auth_op_fn)(authorization_header_rtsp_t*);
static auth_op_fn k_auth_ops[] = {
    auth_basic_valid,
    auth_basic_empty,
    auth_basic_invalid_b64,
    auth_basic_super_long,
    auth_name_badcase,
    auth_bad_separator,
    auth_digest_valid,
    auth_digest_missing_params,
    auth_digest_bad_qop_nc,
    auth_digest_unquoted,
    auth_digest_dup_params,
    auth_digest_weird_chars,
    auth_unknown_scheme,
    auth_multiple_schemes_in_one,
    auth_no_space_between_scheme_and_cred,
    auth_delete_whole_header,
};
static size_t auth_ops_count(void){ return sizeof(k_auth_ops)/sizeof(k_auth_ops[0]); }

static const int weights_auth_ops[16] = {
    100, /*  0: auth_basic_valid             */
      0, /*  1: auth_basic_empty             */
      0, /*  2: auth_basic_invalid_b64       */
      0, /*  3: auth_basic_super_long        */
      0, /*  4: auth_name_badcase            */
      0, /*  5: auth_bad_separator           */
    100, /*  6: auth_digest_valid            */
      0, /*  7: auth_digest_missing_params   */
      0, /*  8: auth_digest_bad_qop_nc       */
      0, /*  9: auth_digest_unquoted         */
    100, /* 10: auth_digest_dup_params       */
      0, /* 11: auth_digest_weird_chars      */
    100, /* 12: auth_unknown_scheme          */
      0, /* 13: auth_multiple_schemes_in_one */
      0, /* 14: auth_no_space_between_scheme_and_cred  */
      0, /* 15: auth_delete_whole_header     */
};

void mutate_authorization(rtsp_packet_t *pkts, size_t n){
    if (!pkts) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; i++) {
        authorization_header_rtsp_t *h = get_auth_ptr(&pkts[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Authorization");
            set_colon_space(h->colon_space);
            set_cstr(h->auth_type, sizeof(h->auth_type), "Basic");
            h->space = ' ';
            set_cstr(h->credentials, sizeof(h->credentials), "Zjp6"); /* "f:z" */
            set_crlf(h->crlf);
        }

        size_t idx = weighted_pick_idx(weights_auth_ops, auth_ops_count());
        k_auth_ops[idx](h);
    }
}


static inline bandwidth_header_rtsp_t* get_bw_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.bandwidth_header;
        case RTSP_TYPE_SETUP:         return &p->setup.bandwidth_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.bandwidth_header;
        case RTSP_TYPE_PLAY:          return &p->play.bandwidth_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.bandwidth_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.bandwidth_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.bandwidth_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.bandwidth_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.bandwidth_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.bandwidth_header;
        case RTSP_TYPE_RECORD:        return &p->record.bandwidth_header;
        default: return NULL;
    }
}

/* ========== 2) add_/delete_ ========== */
void add_bandwidth(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        bandwidth_header_rtsp_t *h = get_bw_ptr(&arr[i]);
        if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Bandwidth");
        set_colon_space(h->colon_space);
        h->value = 64000; 
        set_crlf(h->crlf);
    }
}

void delete_bandwidth(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        bandwidth_header_rtsp_t *h = get_bw_ptr(&arr[i]);
        if(!h) continue;
        h->name[0] = '\0';        
        h->colon_space[0] = '\0';
        h->value = 0;
        h->crlf[0] = '\0';
    }
}

void repeat_bandwidth(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        bandwidth_header_rtsp_t *h = get_bw_ptr(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0'){ 
            set_cstr(h->name, sizeof(h->name), "Bandwidth");
            set_colon_space(h->colon_space);
            set_crlf(h->crlf);
        }
        set_cstr(h->name, sizeof(h->name), "Bandwidth, Bandwidth");
        h->value = 1000; /* 1 Mbps */
    }
}


static void bw_valid_typical(bandwidth_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = 5000; 
    set_crlf(h->crlf);
}
static void bw_zero(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = 0;
    set_crlf(h->crlf);
}
static void bw_negative(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = -1;
    set_crlf(h->crlf);
}
static void bw_int_max(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = INT_MAX;
    set_crlf(h->crlf);
}
static void bw_int_min(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = INT_MIN;
    set_crlf(h->crlf);
}
static void bw_random_large(bandwidth_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = 100000 + rand()%100000000; 
    set_crlf(h->crlf);
}
static void bw_small_random(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = rand()%1024; /* 0..1023 kbps */
    set_crlf(h->crlf);
}
static void bw_scale_up(bandwidth_header_rtsp_t *h){ 
    if(h->name[0]=='\0') bw_valid_typical(h);
    long long v = (long long)h->value * (1 + (rand()%8)); /* ×2..×9 */
    if(v > INT_MAX) v = INT_MAX;
    h->value = (int)v;
}
static void bw_scale_down(bandwidth_header_rtsp_t *h){
    if(h->name[0]=='\0') bw_valid_typical(h);
    int d = 1 + (rand()%8); /* ÷1..÷8 */
    h->value = h->value / d;
}
static void bw_bad_name_case(bandwidth_header_rtsp_t *h){ 
    const char* bads[] = {"bandwidth","BANDWIDTH","Bandwidth "," Bandwidth","Band-Width"};
    set_cstr(h->name,sizeof(h->name), bads[rand()%5]);
    set_colon_space(h->colon_space);
    h->value = 7777;
    set_crlf(h->crlf);
}
static void bw_bad_separator(bandwidth_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    int r = rand()%4;
    if(r==0){ set_cstr(h->colon_space,sizeof(h->colon_space),":"); }
    else if(r==1){ set_cstr(h->colon_space,sizeof(h->colon_space),"::"); }
    else if(r==2){ set_cstr(h->colon_space,sizeof(h->colon_space)," :"); }
    else { set_cstr(h->colon_space,sizeof(h->colon_space),"  "); }
    h->value = 2048;
    set_crlf(h->crlf);
}
static void bw_missing_crlf(bandwidth_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Bandwidth");
    set_colon_space(h->colon_space);
    h->value = 4096;
    h->crlf[0] = '\n'; h->crlf[1] = '\0'; 
}
static void bw_delete_header(bandwidth_header_rtsp_t *h){ 
    h->name[0] = '\0';
    h->colon_space[0] = '\0';
    h->value = 0;
    h->crlf[0] = '\0';
}


typedef void (*bw_op_fn)(bandwidth_header_rtsp_t*);
static bw_op_fn k_bw_ops[] = {
    bw_valid_typical,
    bw_zero,
    bw_negative,
    bw_int_max,
    bw_int_min,
    bw_random_large,
    bw_small_random,
    bw_scale_up,
    bw_scale_down,
    bw_bad_name_case,
    bw_bad_separator,
    bw_missing_crlf,
    bw_delete_header,
};
static size_t bw_ops_count(void){ return sizeof(k_bw_ops)/sizeof(k_bw_ops[0]); }
static const int weights_bw_ops[13] = {
    100, /*  0: bw_valid_typical    */
    100, /*  1: bw_zero             */
      0, /*  2: bw_negative         */
      0, /*  3: bw_int_max          */
      0, /*  4: bw_int_min          */
      0, /*  5: bw_random_large     */
    100, /*  6: bw_small_random     */
    100, /*  7: bw_scale_up         */
    100, /*  8: bw_scale_down       */
      0, /*  9: bw_bad_name_case    */
      0, /* 10: bw_bad_separator    */
      0, /* 11: bw_missing_crlf     */
      0, /* 12: bw_delete_header    */
};


void mutate_bandwidth(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; i++) {
        bandwidth_header_rtsp_t *h = get_bw_ptr(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Bandwidth");
            set_colon_space(h->colon_space);
            h->value = 1000;
            set_crlf(h->crlf);
        }

        size_t idx = weighted_pick_idx(weights_bw_ops, bw_ops_count());
        k_bw_ops[idx](h);
    }
}


static inline blocksize_header_rtsp_t* get_bs_ptr(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_SETUP:         return &p->setup.blocksize_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.blocksize_header;
        case RTSP_TYPE_PLAY:          return &p->play.blocksize_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.blocksize_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.blocksize_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.blocksize_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.blocksize_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.blocksize_header;
        case RTSP_TYPE_RECORD:        return &p->record.blocksize_header;
        default: return NULL;
    }
}

/* ========== 2) add_/delete_ ========== */
void add_blocksize(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        blocksize_header_rtsp_t *h = get_bs_ptr(&arr[i]);
        if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Blocksize");
        set_colon_space(h->colon_space);
        h->value = 4096; 
        set_crlf(h->crlf);
    }
}

void delete_blocksize(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        blocksize_header_rtsp_t *h = get_bs_ptr(&arr[i]);
        if(!h) continue;
        h->name[0] = '\0';          
        h->colon_space[0] = '\0';
        h->value = 0;
        h->crlf[0] = '\0';
    }
}


void repeat_blocksize(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        blocksize_header_rtsp_t *h = get_bs_ptr(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0'){ 
            set_cstr(h->name, sizeof(h->name), "Blocksize");
            set_colon_space(h->colon_space);
            h->value = 1024;
            set_crlf(h->crlf);
        }
        set_cstr(h->name, sizeof(h->name), "Blocksize, Blocksize");
        h->value = 1024;
    }
}


static void bs_valid_typical(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 4096; 
    set_crlf(h->crlf);
}
static void bs_zero(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 0;
    set_crlf(h->crlf);
}
static void bs_one(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 1;
    set_crlf(h->crlf);
}
static void bs_negative(blocksize_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = -128;
    set_crlf(h->crlf);
}
static void bs_int_max(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = INT_MAX;
    set_crlf(h->crlf);
}
static void bs_int_min(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = INT_MIN;
    set_crlf(h->crlf);
}
static void bs_power_of_two(blocksize_header_rtsp_t *h){
    static const int vals[] = {512,1024,2048,4096,8192,16384,32768,65536};
    int v = vals[rand()% (int)(sizeof(vals)/sizeof(vals[0]))];
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = v;
    set_crlf(h->crlf);
}
static void bs_odd_unaligned(blocksize_header_rtsp_t *h){ 
    int v = (rand()%8191)*2 + 1; 
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = v;
    set_crlf(h->crlf);
}
static void bs_mtu_edge(blocksize_header_rtsp_t *h){
    static const int vals[] = {1460,1472,1500,9000};
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = vals[rand()%4];
    set_crlf(h->crlf);
}
static void bs_ts_like(blocksize_header_rtsp_t *h){ 
    static const int vals[] = {188, 376, 564, 752}; 
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = vals[rand()%4];
    set_crlf(h->crlf);
}
static void bs_random_large(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 100000 + rand()%100000000; /* 1e5~1e8 */
    set_crlf(h->crlf);
}
static void bs_small_random(blocksize_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 2 + rand()%8192; /* 2..8193 */
    set_crlf(h->crlf);
}
static void bs_scale_up(blocksize_header_rtsp_t *h){ 
    if(h->name[0]=='\0') bs_valid_typical(h);
    long long v = (long long)h->value * (2 + (rand()%8)); /* ×2..×9 */
    if(v > INT_MAX) v = INT_MAX;
    h->value = (int)v;
}
static void bs_scale_down(blocksize_header_rtsp_t *h){ 
    if(h->name[0]=='\0') bs_valid_typical(h);
    int d = 1 + (rand()%8); /* ÷1..÷8 */
    h->value = h->value / d;
}
static void bs_bad_name_case(blocksize_header_rtsp_t *h){
    const char* bads[] = {"blocksize","BLOCKSIZE","BlockSize"," Blocksize","Block-size"};
    set_cstr(h->name,sizeof(h->name), bads[rand()%5]);
    set_colon_space(h->colon_space);
    h->value = 7777;
    set_crlf(h->crlf);
}
static void bs_bad_separator(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    const char* seps[] = {":", "::", " : ", "  ", "\t: "};
    set_cstr(h->colon_space,sizeof(h->colon_space), seps[rand()%5]);
    h->value = 2048;
    set_crlf(h->crlf);
}
static void bs_missing_crlf(blocksize_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Blocksize");
    set_colon_space(h->colon_space);
    h->value = 4096;
    h->crlf[0] = '\n'; h->crlf[1] = '\0';
}
static void bs_delete_header(blocksize_header_rtsp_t *h){ 
    h->name[0] = '\0';
    h->colon_space[0] = '\0';
    h->value = 0;
    h->crlf[0] = '\0';
}

typedef void (*bs_op_fn)(blocksize_header_rtsp_t*);
static bs_op_fn k_bs_ops[] = {
    bs_valid_typical,
    bs_zero,
    bs_one,
    bs_negative,
    bs_int_max,
    bs_int_min,
    bs_power_of_two,
    bs_odd_unaligned,
    bs_mtu_edge,
    bs_ts_like,
    bs_random_large,
    bs_small_random,
    bs_scale_up,
    bs_scale_down,
    bs_bad_name_case,
    bs_bad_separator,
    bs_missing_crlf,
    bs_delete_header,
};
static size_t bs_ops_count(void){ return sizeof(k_bs_ops)/sizeof(k_bs_ops[0]); }

static const int weights_bs_ops[18] = {
    100, /*  0: bs_valid_typical     */
    100, /*  1: bs_zero              */ 
    100, /*  2: bs_one               */
      0, /*  3: bs_negative          */
      0, /*  4: bs_int_max           */
      0, /*  5: bs_int_min           */
    100, /*  6: bs_power_of_two      */
    100, /*  7: bs_odd_unaligned     */
    100, /*  8: bs_mtu_edge          */
    100, /*  9: bs_ts_like           */
      0, /* 10: bs_random_large      */
    100, /* 11: bs_small_random      */
    100, /* 12: bs_scale_up          */
    100, /* 13: bs_scale_down        */
      0, /* 14: bs_bad_name_case     */
      0, /* 15: bs_bad_separator     */
      0, /* 16: bs_missing_crlf      */
      0, /* 17: bs_delete_header     */
};


void mutate_blocksize(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (size_t i = 0; i < n; i++) {
        blocksize_header_rtsp_t *h = get_bs_ptr(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            set_cstr(h->name, sizeof(h->name), "Blocksize");
            set_colon_space(h->colon_space);
            h->value = 1024;
            set_crlf(h->crlf);
        }

        size_t idx = weighted_pick_idx(weights_bs_ops, bs_ops_count());
        k_bs_ops[idx](h);
    }
}


static inline cache_control_header_rtsp_t* get_cache_control(rtsp_packet_t *p){
    if(!p) return NULL;
    if(p->type == RTSP_TYPE_SETUP) return &p->setup.cache_control_header;
    return NULL;
}

/* add/delete/repeat */
void add_cache_control(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        cache_control_header_rtsp_t *h = get_cache_control(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Cache-Control");
        set_colon_space(h->colon_space);
        set_cstr(h->directive,sizeof(h->directive),"no-cache");
        set_crlf(h->crlf);
    }
}
void delete_cache_control(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        cache_control_header_rtsp_t *h = get_cache_control(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->directive[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_cache_control(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        cache_control_header_rtsp_t *h = get_cache_control(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_cache_control(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Cache-Control, Cache-Control");
        set_cstr(h->directive,sizeof(h->directive),"no-cache, max-age=0, private");
    }
}

/* >=10 ops */
typedef void (*cc_op_fn)(cache_control_header_rtsp_t*);

static void cc_valid_no_cache(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"no-cache");
    set_crlf(h->crlf);
}
static void cc_public(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"public");
    set_crlf(h->crlf);
}
static void cc_private(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"private");
    set_crlf(h->crlf);
}
static void cc_max_age_zero(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"max-age=0");
    set_crlf(h->crlf);
}
static void cc_max_age_large(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"max-age=2147483647");
    set_crlf(h->crlf);
}
static void cc_negative_age(cache_control_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"max-age=-1");
    set_crlf(h->crlf);
}
static void cc_multi_list(cache_control_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"no-store, must-revalidate, proxy-revalidate");
    set_crlf(h->crlf);
}
static void cc_unknown_token(cache_control_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"x-rtsp-foo=bar");
    set_crlf(h->crlf);
}
static void cc_bad_name_case(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"cache-control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"No-Cache");
    set_crlf(h->crlf);
}
static void cc_bad_separator(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->directive,sizeof(h->directive),"no-cache");
    set_crlf(h->crlf);
}
static void cc_missing_crlf(cache_control_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Cache-Control");
    set_colon_space(h->colon_space);
    set_cstr(h->directive,sizeof(h->directive),"no-cache");
    h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void cc_delete(cache_control_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->directive[0]='\0'; h->crlf[0]='\0';
}

static cc_op_fn k_cc_ops[] = {
    cc_valid_no_cache, cc_public, cc_private, cc_max_age_zero, cc_max_age_large,
    cc_negative_age, cc_multi_list, cc_unknown_token, cc_bad_name_case,
    cc_bad_separator, cc_missing_crlf, cc_delete
};

static const int weights_cc_ops[12] = {
    100, /*  0: cc_valid_no_cache   */
    100, /*  1: cc_public           */
    100, /*  2: cc_private          */
    100, /*  3: cc_max_age_zero     */
    100, /*  4: cc_max_age_large    */
      0, /*  5: cc_negative_age     */
    100, /*  6: cc_multi_list       */
    100, /*  7: cc_unknown_token    */
      0, /*  8: cc_bad_name_case    */
      0, /*  9: cc_bad_separator    */
      0, /* 10: cc_missing_crlf     */
      0, /* 11: cc_delete           */
};

static size_t cc_ops_count(void) {
    return sizeof(k_cc_ops) / sizeof(k_cc_ops[0]);
}

void mutate_cache_control(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    size_t M = cc_ops_count(); 

    for (size_t i = 0; i < n; i++) {
        cache_control_header_rtsp_t *h = get_cache_control(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_cache_control(arr + i, 1);
        }


        size_t idx = weighted_pick_idx(weights_cc_ops, M);
        k_cc_ops[idx](h);
    }
}


static inline conference_header_rtsp_t* get_conference(rtsp_packet_t *p){
    if(!p) return NULL;
    if(p->type == RTSP_TYPE_SETUP) return &p->setup.conference_header;
    return NULL;
}

void add_conference(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        conference_header_rtsp_t *h = get_conference(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Conference");
        set_colon_space(h->colon_space);
        set_cstr(h->conference_id,sizeof(h->conference_id),"conf-12345");
        set_crlf(h->crlf);
    }
}
void delete_conference(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        conference_header_rtsp_t *h = get_conference(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->conference_id[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_conference(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        conference_header_rtsp_t *h = get_conference(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_conference(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Conference, Conference");
        set_cstr(h->conference_id,sizeof(h->conference_id),"conf-1, conf-2, conf-3");
    }
}

/* >=10 ops */
typedef void (*cf_op_fn)(conference_header_rtsp_t*);

static void cf_valid_simple(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf-123");
    set_crlf(h->crlf);
}
static void cf_uuid(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"550e8400-e29b-41d4-a716-446655440000");
    set_crlf(h->crlf);
}
static void cf_long(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    memset(h->conference_id,'A', sizeof(h->conference_id)-1); h->conference_id[sizeof(h->conference_id)-1]='\0';
    set_crlf(h->crlf);
}
static void cf_empty(conference_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    h->conference_id[0]='\0';
    set_crlf(h->crlf);
}
static void cf_unicode(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"会議-测试-Конф");
    set_crlf(h->crlf);
}
static void cf_bad_chars(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf id\"; DROP TABLE x;");
    set_crlf(h->crlf);
}
static void cf_pathy(conference_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"../../etc/passwd");
    set_crlf(h->crlf);
}
static void cf_list(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf-1,conf-2,conf-3");
    set_crlf(h->crlf);
}
static void cf_bad_case_name(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf");
    set_crlf(h->crlf);
}
static void cf_bad_sep(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf");
    set_crlf(h->crlf);
}
static void cf_missing_crlf(conference_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Conference");
    set_colon_space(h->colon_space);
    set_cstr(h->conference_id,sizeof(h->conference_id),"conf");
    h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void cf_delete(conference_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->conference_id[0]='\0'; h->crlf[0]='\0';
}

static cf_op_fn k_cf_ops[] = {
    cf_valid_simple, cf_uuid, cf_long, cf_empty, cf_unicode,
    cf_bad_chars, cf_pathy, cf_list, cf_bad_case_name, cf_bad_sep,
    cf_missing_crlf, cf_delete
};

static const int weights_cf_ops[12] = {
    100, /*  0: cf_valid_simple    */
    100, /*  1: cf_uuid            */
    100, /*  2: cf_long            */
      0, /*  3: cf_empty           */
      0, /*  4: cf_unicode         */
      0, /*  5: cf_bad_chars       */
    100, /*  6: cf_pathy           */
    100, /*  7: cf_list            */
      0, /*  8: cf_bad_case_name   */
      0, /*  9: cf_bad_sep         */
      0, /* 10: cf_missing_crlf    */
      0, /* 11: cf_delete          */
};

static size_t cf_ops_count(void) {
    return sizeof(k_cf_ops) / sizeof(k_cf_ops[0]);
}

void mutate_conference(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    size_t M = cf_ops_count();

    for (size_t i = 0; i < n; i++) {
        conference_header_rtsp_t *h = get_conference(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_conference(arr + i, 1);
        }

        size_t idx = weighted_pick_idx(weights_cf_ops, M);
        k_cf_ops[idx](h);
    }
}


static inline connection_header_rtsp_t* get_connection(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.connection_header;
        case RTSP_TYPE_SETUP:         return &p->setup.connection_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.connection_header;
        case RTSP_TYPE_PLAY:          return &p->play.connection_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.connection_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.connection_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.connection_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.connection_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.connection_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.connection_header;
        case RTSP_TYPE_RECORD:        return &p->record.connection_header;
        default: return NULL;
    }
}

void add_connection(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        connection_header_rtsp_t *h = get_connection(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Connection");
        set_colon_space(h->colon_space);
        set_cstr(h->option,sizeof(h->option),"keep-alive");
        set_crlf(h->crlf);
    }
}
void delete_connection(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        connection_header_rtsp_t *h = get_connection(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->option[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_connection(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        connection_header_rtsp_t *h = get_connection(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_connection(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Connection, Connection");
        set_cstr(h->option,sizeof(h->option),"keep-alive, close");
    }
}

/* >=10 ops */
typedef void (*cn_op_fn)(connection_header_rtsp_t*);

static void cn_keep_alive(connection_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"keep-alive");
    set_crlf(h->crlf);
}
static void cn_close(connection_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"close");
    set_crlf(h->crlf);
}
static void cn_token_list(connection_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"keep-alive, foo, bar");
    set_crlf(h->crlf);
}
static void cn_unknown(connection_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"upgrade");
    set_crlf(h->crlf);
}
static void cn_bad_case_name(connection_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"KEEP-ALIVE");
    set_crlf(h->crlf);
}
static void cn_bad_sep(connection_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->option,sizeof(h->option),"keep-alive");
    set_crlf(h->crlf);
}
static void cn_ws_fold(connection_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_cstr(h->colon_space,sizeof(h->colon_space),": \t");
    set_cstr(h->option,sizeof(h->option),"\tkeep-alive");
    set_crlf(h->crlf);
}
static void cn_empty(connection_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    h->option[0]='\0';
    set_crlf(h->crlf);
}
static void cn_inject_chars(connection_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    set_cstr(h->option,sizeof(h->option),"keep\r\n-inject");
    set_crlf(h->crlf);
}
static void cn_long(connection_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Connection");
    set_colon_space(h->colon_space);
    memset(h->option,'K', sizeof(h->option)-1); h->option[sizeof(h->option)-1]='\0';
    set_crlf(h->crlf);
}
static void cn_delete(connection_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->option[0]='\0'; h->crlf[0]='\0';
}

static cn_op_fn k_cn_ops[] = {
    cn_keep_alive, cn_close, cn_token_list, cn_unknown, cn_bad_case_name,
    cn_bad_sep, cn_ws_fold, cn_empty, cn_inject_chars, cn_long, cn_delete
};

static const int weights_cn_ops[11] = {
    100, /* 0: cn_keep_alive     */
    100, /* 1: cn_close          */
    100, /* 2: cn_token_list     */
    100, /* 3: cn_unknown        */
      0, /* 4: cn_bad_case_name  */
      0, /* 5: cn_bad_sep        */
    100, /* 6: cn_ws_fold        */
      0, /* 7: cn_empty          */
      0, /* 8: cn_inject_chars   */
    100, /* 9: cn_long           */
      0, /*10: cn_delete         */
};

static size_t cn_ops_count(void) {
    return sizeof(k_cn_ops) / sizeof(k_cn_ops[0]);
}

void mutate_connection(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    size_t M = cn_ops_count();

    for (size_t i = 0; i < n; i++) {
        connection_header_rtsp_t *h = get_connection(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_connection(arr + i, 1);  
        }

        size_t idx = weighted_pick_idx(weights_cn_ops, M);
        k_cn_ops[idx](h);
    }
}


static inline content_base_header_rtsp_t* get_content_base(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.content_base_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.content_base_header;
        default: return NULL;
    }
}

void add_content_base(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_base_header_rtsp_t *h = get_content_base(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Base");
        set_colon_space(h->colon_space);
        set_cstr(h->uri,sizeof(h->uri),"rtsp://example.com/stream/");
        set_crlf(h->crlf);
    }
}
void delete_content_base(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_base_header_rtsp_t *h = get_content_base(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->uri[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_content_base(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_base_header_rtsp_t *h = get_content_base(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_base(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Content-Base, Content-Base");
        set_cstr(h->uri,sizeof(h->uri),"rtsp://a/ , rtsp://b/");
    }
}

typedef void (*cb_op_fn)(content_base_header_rtsp_t*);
static void cb_valid_abs(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app/");
    set_crlf(h->crlf);
}
static void cb_http_scheme(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"http://host/app/");
    set_crlf(h->crlf);
}
static void cb_no_trailing_slash(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app");
    set_crlf(h->crlf);
}
static void cb_ipv6(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://[2001:db8::1]/app/");
    set_crlf(h->crlf);
}
static void cb_userinfo(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://u:p@host/app/");
    set_crlf(h->crlf);
}
static void cb_unicode(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/路径/流/");
    set_crlf(h->crlf);
}
static void cb_path_traversal(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app/../../secret/");
    set_crlf(h->crlf);
}
static void cb_empty(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    h->uri[0]='\0';
    set_crlf(h->crlf);
}
static void cb_bad_sep(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app/");
    set_crlf(h->crlf);
}
static void cb_inject_crlf(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app/\r\nX-Injected: 1");
    set_crlf(h->crlf);
}
static void cb_missing_crlf(content_base_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Base");
    set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/app/");
    h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void cb_delete(content_base_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->uri[0]='\0'; h->crlf[0]='\0';
}
static cb_op_fn k_cb_ops[] = {
    cb_valid_abs, cb_http_scheme, cb_no_trailing_slash, cb_ipv6, cb_userinfo,
    cb_unicode, cb_path_traversal, cb_empty, cb_bad_sep, cb_inject_crlf,
    cb_missing_crlf, cb_delete
};

static const int weights_cb_ops[12] = {
    100, /*  0: cb_valid_abs         */
    100, /*  1: cb_http_scheme       */
    100, /*  2: cb_no_trailing_slash */
    100, /*  3: cb_ipv6              */
    100, /*  4: cb_userinfo          */
      0, /*  5: cb_unicode           */
      0, /*  6: cb_path_traversal    */
      0, /*  7: cb_empty             */
      0, /*  8: cb_bad_sep           */
      0, /*  9: cb_inject_crlf       */
      0, /* 10: cb_missing_crlf      */
      0, /* 11: cb_delete            */
};

static size_t cb_ops_count(void) {
    return sizeof(k_cb_ops) / sizeof(k_cb_ops[0]);
}

void mutate_content_base(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();  

    size_t M = cb_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_base_header_rtsp_t *h = get_content_base(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_base(arr + i, 1); 
        }

        size_t idx = weighted_pick_idx(weights_cb_ops, M);
        k_cb_ops[idx](h);
    }
}


static inline content_encoding_header_rtsp_t* get_content_enc(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.content_encoding_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.content_encoding_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.content_encoding_header;
        default: return NULL;
    }
}

void add_content_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_encoding_header_rtsp_t *h = get_content_enc(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Encoding");
        set_colon_space(h->colon_space);
        set_cstr(h->encoding,sizeof(h->encoding),"gzip");
        set_crlf(h->crlf);
    }
}
void delete_content_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_encoding_header_rtsp_t *h = get_content_enc(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->encoding[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_content_encoding(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_encoding_header_rtsp_t *h = get_content_enc(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_encoding(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Content-Encoding, Content-Encoding");
        set_cstr(h->encoding,sizeof(h->encoding),"gzip, deflate, br");
    }
}

typedef void (*ce_op_fn)(content_encoding_header_rtsp_t*);
static void ce_gzip(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip"); set_crlf(h->crlf);
}
static void ce_deflate(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"deflate"); set_crlf(h->crlf);
}
static void ce_identity(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"identity"); set_crlf(h->crlf);
}
static void ce_unknown_token(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"x-zstd"); set_crlf(h->crlf);
}
static void ce_multi(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip,br"); set_crlf(h->crlf);
}
static void ce_bad_case_name(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"content-encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"GZIP"); set_crlf(h->crlf);
}
static void ce_bad_sep(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->encoding,sizeof(h->encoding),"gzip"); set_crlf(h->crlf);
}
static void ce_ws_fold(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_cstr(h->colon_space,sizeof(h->colon_space),": \t");
    set_cstr(h->encoding,sizeof(h->encoding),"\tdeflate"); set_crlf(h->crlf);
}
static void ce_empty(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    h->encoding[0]='\0'; set_crlf(h->crlf);
}
static void ce_inject_crlf(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip\r\nX-Injected: 1"); set_crlf(h->crlf);
}
static void ce_missing_crlf(content_encoding_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Encoding"); set_colon_space(h->colon_space);
    set_cstr(h->encoding,sizeof(h->encoding),"gzip"); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void ce_delete(content_encoding_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->encoding[0]='\0'; h->crlf[0]='\0';
}
static ce_op_fn k_ce_ops[] = {
    ce_gzip, ce_deflate, ce_identity, ce_unknown_token, ce_multi,
    ce_bad_case_name, ce_bad_sep, ce_ws_fold, ce_empty, ce_inject_crlf,
    ce_missing_crlf, ce_delete
};

static const int weights_ce_ops[12] = {
    100, /*  0: ce_gzip          */
    100, /*  1: ce_deflate       */
    100, /*  2: ce_identity      */
    100, /*  3: ce_unknown_token */
    100, /*  4: ce_multi         */
      0, /*  5: ce_bad_case_name */
      0, /*  6: ce_bad_sep       */
    100, /*  7: ce_ws_fold       */
      0, /*  8: ce_empty         */
      0, /*  9: ce_inject_crlf   */
      0, /* 10: ce_missing_crlf  */
      0, /* 11: ce_delete        */
};

static size_t ce_ops_count(void) {
    return sizeof(k_ce_ops) / sizeof(k_ce_ops[0]);
}
void mutate_content_encoding(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed(); 

    size_t M = ce_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_encoding_header_rtsp_t *h = get_content_enc(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_encoding(arr + i, 1);
        }

        size_t idx = weighted_pick_idx(weights_ce_ops, M);
        k_ce_ops[idx](h);
    }
}

static inline content_language_header_rtsp_t* get_content_lang(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE: return &p->describe.content_language_header;
        case RTSP_TYPE_ANNOUNCE: return &p->announce.content_language_header;
        default: return NULL;
    }
}

void add_content_language(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_language_header_rtsp_t *h = get_content_lang(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Language");
        set_colon_space(h->colon_space);
        set_cstr(h->language,sizeof(h->language),"en-US");
        set_crlf(h->crlf);
    }
}
void delete_content_language(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_language_header_rtsp_t *h = get_content_lang(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->language[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_content_language(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_language_header_rtsp_t *h = get_content_lang(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_language(arr+i,1);
        set_cstr(h->name,sizeof(h->name),"Content-Language, Content-Language");
        set_cstr(h->language,sizeof(h->language),"en-US, fr, zh-CN;q=0.8");
    }
}

typedef void (*cl_op_fn)(content_language_header_rtsp_t*);
static void cl_en_us(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"en-US"); set_crlf(h->crlf);
}
static void cl_simple_tag(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"fr"); set_crlf(h->crlf);
}
static void cl_multi_list_q(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"en, fr-CA;q=0.9, zh-CN;q=0.1"); set_crlf(h->crlf);
}
static void cl_bad_q(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"en;q=1.5"); set_crlf(h->crlf);
}
static void cl_wildcard_like(content_language_header_rtsp_t *h){ 
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"*"); set_crlf(h->crlf);
}
static void cl_unicode_tag(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"zh-汉字"); set_crlf(h->crlf);
}
static void cl_empty(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    h->language[0]='\0'; set_crlf(h->crlf);
}
static void cl_bad_sep(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->language,sizeof(h->language),"en"); set_crlf(h->crlf);
}
static void cl_case_name(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"content-language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"EN-us"); set_crlf(h->crlf);
}
static void cl_spaces_ws(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_cstr(h->colon_space,sizeof(h->colon_space),":  \t");
    set_cstr(h->language,sizeof(h->language),"\t en ,  fr "); set_crlf(h->crlf);
}
static void cl_inject_crlf(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"en\r\nX-Injected: 1"); set_crlf(h->crlf);
}
static void cl_missing_crlf(content_language_header_rtsp_t *h){
    set_cstr(h->name,sizeof(h->name),"Content-Language"); set_colon_space(h->colon_space);
    set_cstr(h->language,sizeof(h->language),"en"); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void cl_delete(content_language_header_rtsp_t *h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->language[0]='\0'; h->crlf[0]='\0';
}
static cl_op_fn k_cl_ops[] = {
    cl_en_us, cl_simple_tag, cl_multi_list_q, cl_bad_q, cl_wildcard_like,
    cl_unicode_tag, cl_empty, cl_bad_sep, cl_case_name, cl_spaces_ws,
    cl_inject_crlf, cl_missing_crlf, cl_delete
};

static const int weights_cl_ops[13] = {
    100, /*  0: cl_en_us          */
    100, /*  1: cl_simple_tag     */
    100, /*  2: cl_multi_list_q   */
      0, /*  3: cl_bad_q          */
      0, /*  4: cl_wildcard_like  */
      0, /*  5: cl_unicode_tag    */
      0, /*  6: cl_empty          */
      0, /*  7: cl_bad_sep        */
      0, /*  8: cl_case_name      */
    100, /*  9: cl_spaces_ws      */
      0, /* 10: cl_inject_crlf    */
      0, /* 11: cl_missing_crlf   */
      0, /* 12: cl_delete         */
};

static size_t cl_ops_count(void) {
    return sizeof(k_cl_ops) / sizeof(k_cl_ops[0]);
}

void mutate_content_language(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = cl_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_language_header_rtsp_t *h = get_content_lang(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_language(arr + i, 1);
        }

        size_t idx = weighted_pick_idx(weights_cl_ops, M);
        k_cl_ops[idx](h);
    }
}


static inline content_length_header_rtsp_t* get_content_length(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.content_length_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.content_length_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.content_length_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.content_length_header;
        default: return NULL;
    }
}

void add_content_length(rtsp_packet_t *arr, size_t n, int v){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_length_header_rtsp_t *h = get_content_length(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Length");
        set_colon_space(h->colon_space);
        h->length = v; 
        set_crlf(h->crlf);
    }
}
void delete_content_length(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_length_header_rtsp_t *h = get_content_length(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->length=0; h->crlf[0]='\0';
    }
}

void repeat_content_length(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_length_header_rtsp_t *h = get_content_length(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_length(arr+i,1,0);
        set_cstr(h->name,sizeof(h->name),"Content-Length, Content-Length");

        h->length = 1234;
    }
}


typedef void (*clen_op_fn)(content_length_header_rtsp_t*);
static void clen_ok_small(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 0; set_crlf(h->crlf);
}
static void clen_ok_typical(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 128; set_crlf(h->crlf);
}
static void clen_maxint(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = INT_MAX; set_crlf(h->crlf);
}
static void clen_minint(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = INT_MIN; set_crlf(h->crlf);
}
static void clen_minus_one(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = -1; set_crlf(h->crlf);
}
static void clen_huge(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 1<<30; set_crlf(h->crlf);
}
static void clen_off_by_one_low(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 1; set_crlf(h->crlf);
}
static void clen_off_by_one_high(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 1025; set_crlf(h->crlf);
}
static void clen_bad_sep(content_length_header_rtsp_t* h){ 
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    h->length = 100; set_crlf(h->crlf);
}
static void clen_missing_crlf(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Length"); set_colon_space(h->colon_space);
    h->length = 100; h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void clen_bad_case(content_length_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"content-length"); set_colon_space(h->colon_space);
    h->length = 256; set_crlf(h->crlf);
}
static void clen_delete(content_length_header_rtsp_t* h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->length=0; h->crlf[0]='\0';
}

static clen_op_fn k_clen_ops[] = {
    clen_ok_small, clen_ok_typical, clen_maxint, clen_minint, clen_minus_one,
    clen_huge, clen_off_by_one_low, clen_off_by_one_high, clen_bad_sep,
    clen_missing_crlf, clen_bad_case, clen_delete
};

static const int weights_clen_ops[12] = {
    100, /*  0: clen_ok_small        */
    100, /*  1: clen_ok_typical      */
      0, /*  2: clen_maxint          */
      0, /*  3: clen_minint          */
      0, /*  4: clen_minus_one       */
      0, /*  5: clen_huge            */
    100, /*  6: clen_off_by_one_low  */
    100, /*  7: clen_off_by_one_high */
      0, /*  8: clen_bad_sep         */
      0, /*  9: clen_missing_crlf    */
      0, /* 10: clen_bad_case        */
      0, /* 11: clen_delete          */
};

static size_t clen_ops_count(void) {
    return sizeof(k_clen_ops) / sizeof(k_clen_ops[0]);
}

void mutate_content_length(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = clen_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_length_header_rtsp_t *h = get_content_length(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_length(arr + i, 1, 0);
        }

        size_t idx = weighted_pick_idx(weights_clen_ops, M);
        k_clen_ops[idx](h);
    }
}


/* ===========================================================
   Content-Location  (DESCRIBE/GET_PARAMETER)
   =========================================================== */
static inline content_location_header_rtsp_t* get_content_location(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.content_location_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.content_location_header;
        default: return NULL;
    }
}

void add_content_location(rtsp_packet_t *arr, size_t n, const char *uri){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_location_header_rtsp_t *h = get_content_location(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Location");
        set_colon_space(h->colon_space);
        set_cstr(h->uri,sizeof(h->uri), uri?uri:"rtsp://example.com/desc.sdp");
        set_crlf(h->crlf);
    }
}
void delete_content_location(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_location_header_rtsp_t *h = get_content_location(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->uri[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_content_location(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_location_header_rtsp_t *h = get_content_location(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_location(arr+i,1,NULL);
        set_cstr(h->name,sizeof(h->name),"Content-Location, Content-Location");
        set_cstr(h->uri,sizeof(h->uri),"rtsp://a/s.sdp, rtsp://b/s.sdp");
    }
}

typedef void (*cloc_op_fn)(content_location_header_rtsp_t*);
static void cloc_abs_rtsp(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/path/file.sdp"); set_crlf(h->crlf);
}
static void cloc_relative(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"../file.sdp"); set_crlf(h->crlf);
}
static void cloc_http_scheme(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"http://host/file.sdp"); set_crlf(h->crlf);
}
static void cloc_ipv6(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://[2001:db8::2]/a/b.sdp"); set_crlf(h->crlf);
}
static void cloc_userinfo(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://u:p@h/app.sdp"); set_crlf(h->crlf);
}
static void cloc_space_in_uri(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/with space.sdp"); set_crlf(h->crlf);
}
static void cloc_unicode(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/描述/文件.sdp"); set_crlf(h->crlf);
}
static void cloc_traversal(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://host/a/../../x.sdp"); set_crlf(h->crlf);
}
static void cloc_empty(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    h->uri[0]='\0'; set_crlf(h->crlf);
}
static void cloc_bad_sep(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->uri,sizeof(h->uri),"rtsp://h/f.sdp"); set_crlf(h->crlf);
}
static void cloc_inject_crlf(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://h/x\r\nX-Inj:1"); set_crlf(h->crlf);
}
static void cloc_missing_crlf(content_location_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Location"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://h/x"); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void cloc_delete(content_location_header_rtsp_t* h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->uri[0]='\0'; h->crlf[0]='\0';
}
static cloc_op_fn k_cloc_ops[] = {
    cloc_abs_rtsp, cloc_relative, cloc_http_scheme, cloc_ipv6, cloc_userinfo,
    cloc_space_in_uri, cloc_unicode, cloc_traversal, cloc_empty, cloc_bad_sep,
    cloc_inject_crlf, cloc_missing_crlf, cloc_delete
};

static const int weights_cloc_ops[13] = {
    100, /*  0: cloc_abs_rtsp      */
    100, /*  1: cloc_relative      */
    100, /*  2: cloc_http_scheme   */
    100, /*  3: cloc_ipv6          */
    100, /*  4: cloc_userinfo      */
      0, /*  5: cloc_space_in_uri  */
      0, /*  6: cloc_unicode       */
      0, /*  7: cloc_traversal     */
      0, /*  8: cloc_empty         */
      0, /*  9: cloc_bad_sep       */
      0, /* 10: cloc_inject_crlf   */
      0, /* 11: cloc_missing_crlf  */
      0, /* 12: cloc_delete        */
};

static size_t cloc_ops_count(void) {
    return sizeof(k_cloc_ops) / sizeof(k_cloc_ops[0]);
}

void mutate_content_location(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = cloc_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_location_header_rtsp_t *h = get_content_location(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_location(arr + i, 1, NULL);
        }

        size_t idx = weighted_pick_idx(weights_cloc_ops, M);
        k_cloc_ops[idx](h);
    }
}


/* ===========================================================
   Content-Type  (SET_PARAMETER/ANNOUNCE)
   =========================================================== */
static inline content_type_header_rtsp_t* get_content_type(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.content_type_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.content_type_header;
        default: return NULL;
    }
}

void add_content_type(rtsp_packet_t *arr, size_t n, const char *type, const char *sub){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_type_header_rtsp_t *h = get_content_type(&arr[i]);
        if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Content-Type");
        set_colon_space(h->colon_space);
        set_cstr(h->media_type,sizeof(h->media_type), type?type:"application");
        h->slash = '/';
        set_cstr(h->sub_type,sizeof(h->sub_type), sub?sub:"sdp");
        set_crlf(h->crlf);
    }
}
void delete_content_type(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_type_header_rtsp_t *h = get_content_type(&arr[i]);
        if(!h) continue;
        h->name[0]='\0'; h->colon_space[0]='\0'; h->media_type[0]='\0';
        h->slash='\0'; h->sub_type[0]='\0'; h->crlf[0]='\0';
    }
}
void repeat_content_type(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        content_type_header_rtsp_t *h = get_content_type(&arr[i]);
        if(!h) continue;
        if(h->name[0]=='\0') add_content_type(arr+i,1,"application","sdp");
        set_cstr(h->name,sizeof(h->name),"Content-Type, Content-Type");
        set_cstr(h->media_type,sizeof(h->media_type),"application/sdp, text/plain");
        h->slash = '\0'; h->sub_type[0]='\0';
    }
}


typedef void (*ctype_op_fn)(content_type_header_rtsp_t*);
static void ct_sdp(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp"); set_crlf(h->crlf);
}
static void ct_text_plain(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"text"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"plain"); set_crlf(h->crlf);
}
static void ct_json(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"json"); set_crlf(h->crlf);
}
static void ct_wildcard_all(content_type_header_rtsp_t* h){ 
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"*"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"*"); set_crlf(h->crlf);
}
static void ct_param_charset(content_type_header_rtsp_t* h){ 
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp; charset=UTF-8"); set_crlf(h->crlf);
}
static void ct_upper_lower(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"content-type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"APPLICATION"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"SDP"); set_crlf(h->crlf);
}
static void ct_missing_slash(content_type_header_rtsp_t* h){ 
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='\0';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp"); set_crlf(h->crlf);
}
static void ct_empty_subtype(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    h->sub_type[0]='\0'; set_crlf(h->crlf);
}
static void ct_bad_sep(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->media_type,sizeof(h->media_type),"text"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"plain"); set_crlf(h->crlf);
}
static void ct_long_tokens(content_type_header_rtsp_t* h){ 
    char mt[64]; memset(mt,'A',sizeof(mt)-1); mt[sizeof(mt)-1]='\0';
    char st[64]; memset(st,'B',sizeof(st)-1); st[sizeof(st)-1]='\0';
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),mt); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),st); set_crlf(h->crlf);
}
static void ct_param_semicolon_chain(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"application"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"sdp;level=3;profile=cb;boundary=xyz"); set_crlf(h->crlf);
}
static void ct_inject_crlf(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"text"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"plain\r\nX-Inj:1"); set_crlf(h->crlf);
}
static void ct_missing_crlf(content_type_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Content-Type"); set_colon_space(h->colon_space);
    set_cstr(h->media_type,sizeof(h->media_type),"text"); h->slash='/';
    set_cstr(h->sub_type,sizeof(h->sub_type),"plain"); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void ct_delete(content_type_header_rtsp_t* h){
    h->name[0]='\0'; h->colon_space[0]='\0'; h->media_type[0]='\0'; h->slash='\0'; h->sub_type[0]='\0'; h->crlf[0]='\0';
}

static ctype_op_fn k_ctype_ops[] = {
    ct_sdp, ct_text_plain, ct_json, ct_wildcard_all, ct_param_charset,
    ct_upper_lower, ct_missing_slash, ct_empty_subtype, ct_bad_sep,
    ct_long_tokens, ct_param_semicolon_chain, ct_inject_crlf,
    ct_missing_crlf, ct_delete
};

static const int weights_ctype_ops[14] = {
    100, /*  0: ct_sdp                  */
    100, /*  1: ct_text_plain           */
    100, /*  2: ct_json                 */
      0, /*  3: ct_wildcard_all         */
    100, /*  4: ct_param_charset        */
    100, /*  5: ct_upper_lower          */
      0, /*  6: ct_missing_slash        */
      0, /*  7: ct_empty_subtype        */
      0, /*  8: ct_bad_sep              */
    100, /*  9: ct_long_tokens          */
    100, /* 10: ct_param_semicolon_chain*/
      0, /* 11: ct_inject_crlf          */
      0, /* 12: ct_missing_crlf         */
      0, /* 13: ct_delete               */
};

static size_t ctype_ops_count(void) {
    return sizeof(k_ctype_ops) / sizeof(k_ctype_ops[0]);
}

void mutate_content_type(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = ctype_ops_count();

    for (size_t i = 0; i < n; i++) {
        content_type_header_rtsp_t *h = get_content_type(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_content_type(arr + i, 1, "application", "sdp");
        }

        size_t idx = weighted_pick_idx(weights_ctype_ops, M);
        k_ctype_ops[idx](h);
    }
}

static inline date_header_rtsp_t* get_date(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.date_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.date_header;
        case RTSP_TYPE_SETUP:         return &p->setup.date_header;
        case RTSP_TYPE_PLAY:          return &p->play.date_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.date_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.date_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.date_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.date_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.date_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.date_header;
        case RTSP_TYPE_RECORD:        return &p->record.date_header;
        default: return NULL;
    }
}

void add_date(rtsp_packet_t *arr, size_t n, const char *wk, const char *day, const char *mon, const char *year, const char *tod){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        date_header_rtsp_t *h = get_date(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Date");
        set_colon_space(h->colon_space);
        set_cstr(h->wkday,sizeof(h->wkday), wk?wk:"Tue");
        set_cstr(h->comma_space,sizeof(h->comma_space),", ");
        set_cstr(h->day,sizeof(h->day), day?day:"15"); h->space1=' ';
        set_cstr(h->month,sizeof(h->month), mon?mon:"Nov"); h->space2=' ';
        set_cstr(h->year,sizeof(h->year), year?year:"1994"); h->space3=' ';
        set_cstr(h->time_of_day,sizeof(h->time_of_day), tod?tod:"08:12:31"); h->space4=' ';
        set_cstr(h->gmt,sizeof(h->gmt),"GMT");
        set_crlf(h->crlf);
    }
}
void delete_date(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        date_header_rtsp_t *h = get_date(&arr[i]); if(!h) continue;
        h->name[0]='\0';
    }
}
void repeat_date(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        date_header_rtsp_t *h = get_date(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_date(arr+i,1,NULL,NULL,NULL,NULL,NULL);
        set_cstr(h->name,sizeof(h->name),"Date, Date");
    }
}

typedef void (*date_op_fn)(date_header_rtsp_t*);
static void dt_ok_sample(date_header_rtsp_t* h){
    add_date((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL,NULL,NULL,NULL,NULL); 
    set_cstr(h->name,sizeof(h->name),"Date"); set_colon_space(h->colon_space);
    set_cstr(h->wkday,sizeof(h->wkday),"Tue"); set_cstr(h->comma_space,sizeof(h->comma_space),", ");
    set_cstr(h->day,sizeof(h->day),"15"); h->space1=' '; set_cstr(h->month,sizeof(h->month),"Nov");
    h->space2=' '; set_cstr(h->year,sizeof(h->year),"1994"); h->space3=' ';
    set_cstr(h->time_of_day,sizeof(h->time_of_day),"08:12:31"); h->space4=' '; set_cstr(h->gmt,sizeof(h->gmt),"GMT");
    set_crlf(h->crlf);
}
static void dt_wrong_wkday(date_header_rtsp_t* h){ 
    dt_ok_sample(h); set_cstr(h->wkday,sizeof(h->wkday),"Mon");
}
static void dt_bad_month(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->month,sizeof(h->month),"Foo");
}
static void dt_year_2digit(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->year,sizeof(h->year),"94");
}
static void dt_bad_time(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->time_of_day,sizeof(h->time_of_day),"8:2:3");
}
static void dt_timezone_lc(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->gmt,sizeof(h->gmt),"gmt");
}
static void dt_bad_sep(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->colon_space,sizeof(h->colon_space),":");
}
static void dt_lowercase_name(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->name,sizeof(h->name),"date");
}
static void dt_missing_crlf(date_header_rtsp_t* h){
    dt_ok_sample(h); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void dt_future_year(date_header_rtsp_t* h){
    dt_ok_sample(h); set_cstr(h->year,sizeof(h->year),"2999");
}
static void dt_delete(date_header_rtsp_t* h){
    h->name[0]='\0';
}
static date_op_fn k_date_ops[] = {
    dt_ok_sample, dt_wrong_wkday, dt_bad_month, dt_year_2digit, dt_bad_time,
    dt_timezone_lc, dt_bad_sep, dt_lowercase_name, dt_missing_crlf,
    dt_future_year, dt_delete
};

static const int weights_date_ops[11] = {
    100, /* 0: dt_ok_sample       */
    100, /* 1: dt_wrong_wkday     */
      0, /* 2: dt_bad_month       */
      0, /* 3: dt_year_2digit     */
      0, /* 4: dt_bad_time        */
    100, /* 5: dt_timezone_lc     */
      0, /* 6: dt_bad_sep         */
      0, /* 7: dt_lowercase_name  */
      0, /* 8: dt_missing_crlf    */
    100, /* 9: dt_future_year     */
      0, /*10: dt_delete          */
};

static size_t date_ops_count(void) {
    return sizeof(k_date_ops) / sizeof(k_date_ops[0]);
}

void mutate_date(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = date_ops_count();

    for (size_t i = 0; i < n; i++) {
        date_header_rtsp_t *h = get_date(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_date(arr + i, 1, NULL, NULL, NULL, NULL, NULL);
        }

        size_t idx = weighted_pick_idx(weights_date_ops, M);
        k_date_ops[idx](h);
    }
}

static inline expires_header_rtsp_t* get_expires(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE: return &p->describe.expires_header;
        case RTSP_TYPE_ANNOUNCE: return &p->announce.expires_header;
        default: return NULL;
    }
}

void add_expires(rtsp_packet_t *arr, size_t n, const char *wk, const char *day, const char *mon, const char *year, const char *tod){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        expires_header_rtsp_t *h = get_expires(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Expires");
        set_colon_space(h->colon_space);
        set_cstr(h->wkday,sizeof(h->wkday), wk?wk:"Tue");
        set_cstr(h->comma_space,sizeof(h->comma_space),", ");
        set_cstr(h->day,sizeof(h->day), day?day:"15"); h->space1=' ';
        set_cstr(h->month,sizeof(h->month), mon?mon:"Nov"); h->space2=' ';
        set_cstr(h->year,sizeof(h->year), year?year:"1994"); h->space3=' ';
        set_cstr(h->time_of_day,sizeof(h->time_of_day), tod?tod:"08:12:31"); h->space4=' ';
        set_cstr(h->gmt,sizeof(h->gmt),"GMT");
        set_crlf(h->crlf);
    }
}
void delete_expires(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        expires_header_rtsp_t *h = get_expires(&arr[i]); if(!h) continue;
        h->name[0]='\0';
    }
}
void repeat_expires(rtsp_packet_t *arr, size_t n){ 
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        expires_header_rtsp_t *h = get_expires(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_expires(arr+i,1,NULL,NULL,NULL,NULL,NULL);
        set_cstr(h->name,sizeof(h->name),"Expires, Expires");
    }
}


typedef void (*exp_op_fn)(expires_header_rtsp_t*);
static void ex_ok_future(expires_header_rtsp_t* h){
    add_expires((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL,NULL,NULL,NULL,NULL); /* no-op */
    set_cstr(h->name,sizeof(h->name),"Expires"); set_colon_space(h->colon_space);
    set_cstr(h->wkday,sizeof(h->wkday),"Wed"); set_cstr(h->comma_space,sizeof(h->comma_space),", ");
    set_cstr(h->day,sizeof(h->day),"01"); h->space1=' '; set_cstr(h->month,sizeof(h->month),"Jan");
    h->space2=' '; set_cstr(h->year,sizeof(h->year),"2099"); h->space3=' ';
    set_cstr(h->time_of_day,sizeof(h->time_of_day),"00:00:00"); h->space4=' '; set_cstr(h->gmt,sizeof(h->gmt),"GMT");
    set_crlf(h->crlf);
}
static void ex_past(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->year,sizeof(h->year),"1990"); }
static void ex_now(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->time_of_day,sizeof(h->time_of_day),"23:59:59"); }
static void ex_bad_month(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->month,sizeof(h->month),"Foo"); }
static void ex_bad_time(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->time_of_day,sizeof(h->time_of_day),"24:61:61"); }
static void ex_lowercase_name(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->name,sizeof(h->name),"expires"); }
static void ex_bad_sep(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->colon_space,sizeof(h->colon_space),":"); }
static void ex_missing_crlf(expires_header_rtsp_t* h){ ex_ok_future(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void ex_weekday_mismatch(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->wkday,sizeof(h->wkday),"Sun"); }
static void ex_year_2digit(expires_header_rtsp_t* h){ ex_ok_future(h); set_cstr(h->year,sizeof(h->year),"99"); }
static void ex_delete(expires_header_rtsp_t* h){ h->name[0]='\0'; }

static exp_op_fn k_exp_ops[] = {
    ex_ok_future, ex_past, ex_now, ex_bad_month, ex_bad_time,
    ex_lowercase_name, ex_bad_sep, ex_missing_crlf, ex_weekday_mismatch,
    ex_year_2digit, ex_delete
};

static const int weights_exp_ops[11] = {
    100, /* 0: ex_ok_future       */
    100, /* 1: ex_past            */
    100, /* 2: ex_now             */
      0, /* 3: ex_bad_month       */
      0, /* 4: ex_bad_time        */
      0, /* 5: ex_lowercase_name  */
      0, /* 6: ex_bad_sep         */
      0, /* 7: ex_missing_crlf    */
    100, /* 8: ex_weekday_mismatch*/
      0, /* 9: ex_year_2digit     */
      0, /*10: ex_delete          */
};

static size_t exp_ops_count(void) {
    return sizeof(k_exp_ops) / sizeof(k_exp_ops[0]);
}

void mutate_expires(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = exp_ops_count();

    for (size_t i = 0; i < n; i++) {
        expires_header_rtsp_t *h = get_expires(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_expires(arr + i, 1, NULL, NULL, NULL, NULL, NULL);
        }

        size_t idx = weighted_pick_idx(weights_exp_ops, M);
        k_exp_ops[idx](h);
    }
}


static inline from_header_rtsp_t* get_from(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.from_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.from_header;
        case RTSP_TYPE_SETUP:         return &p->setup.from_header;
        case RTSP_TYPE_PLAY:          return &p->play.from_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.from_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.from_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.from_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.from_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.from_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.from_header;
        case RTSP_TYPE_RECORD:        return &p->record.from_header;
        default: return NULL;
    }
}

void add_from(rtsp_packet_t *arr, size_t n, const char *uri){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        from_header_rtsp_t *h = get_from(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"From");
        set_colon_space(h->colon_space);
        set_cstr(h->uri,sizeof(h->uri), uri?uri:"<sip:user@example.com>");
        set_crlf(h->crlf);
    }
}
void delete_from(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){ from_header_rtsp_t *h = get_from(&arr[i]); if(h) h->name[0]='\0'; }
}

void repeat_from(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        from_header_rtsp_t *h = get_from(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_from(arr+i,1,NULL);
        set_cstr(h->name,sizeof(h->name),"From, From");
        set_cstr(h->uri,sizeof(h->uri), "<sip:a@b>, <sip:c@d>");
    }
}


typedef void (*from_op_fn)(from_header_rtsp_t*);
static void fr_ok_sip(from_header_rtsp_t* h){ add_from((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL); }
static void fr_ok_mailto(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"<mailto:user@example.com>"); set_crlf(h->crlf);
}
static void fr_no_angle(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"sip:user@example.com"); set_crlf(h->crlf);
}
static void fr_empty_uri(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_colon_space(h->colon_space);
    h->uri[0]='\0'; set_crlf(h->crlf);
}
static void fr_bad_sep(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->uri,sizeof(h->uri),"<sip:x@y>"); set_crlf(h->crlf);
}
static void fr_lowercase_name(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"from"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"<sip:l@h>"); set_crlf(h->crlf);
}
static void fr_missing_crlf(from_header_rtsp_t* h){
    fr_ok_sip(h); h->crlf[0]='\n'; h->crlf[1]='\0';
}
static void fr_long_uri(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_colon_space(h->colon_space);
    char buf[256]; memset(buf,'A',sizeof(buf)); buf[0]='<'; buf[254]='>'; buf[255]='\0';
    set_cstr(h->uri,sizeof(h->uri),buf); set_crlf(h->crlf);
}
static void fr_inject_comma_list(from_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"From"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"<sip:a@x>, <sip:b@y>"); set_crlf(h->crlf);
}
static void fr_delete(from_header_rtsp_t* h){ h->name[0]='\0'; }

static from_op_fn k_from_ops[] = {
    fr_ok_sip, fr_ok_mailto, fr_no_angle, fr_empty_uri, fr_bad_sep,
    fr_lowercase_name, fr_missing_crlf, fr_long_uri, fr_inject_comma_list,
    fr_delete
};

static const int weights_from_ops[10] = {
    100, /* 0: fr_ok_sip            */
    100, /* 1: fr_ok_mailto         */
    100, /* 2: fr_no_angle          */
      0, /* 3: fr_empty_uri         */
      0, /* 4: fr_bad_sep           */
      0, /* 5: fr_lowercase_name    */
      0, /* 6: fr_missing_crlf      */
    100, /* 7: fr_long_uri          */
    100, /* 8: fr_inject_comma_list */
      0, /* 9: fr_delete            */
};

static size_t from_ops_count(void) {
    return sizeof(k_from_ops) / sizeof(k_from_ops[0]);
}

void mutate_from(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = from_ops_count();

    for (size_t i = 0; i < n; i++) {
        from_header_rtsp_t *h = get_from(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_from(arr + i, 1, NULL); 
        }

        size_t idx = weighted_pick_idx(weights_from_ops, M);
        k_from_ops[idx](h);
    }
}


static inline if_modified_since_header_rtsp_t* get_ims(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_SETUP:    return &p->setup.if_modified_since_header;
        case RTSP_TYPE_DESCRIBE: return &p->describe.if_modified_since_header;
        default: return NULL;
    }
}

void add_if_modified_since(rtsp_packet_t *arr, size_t n,
                           const char *wk, const char *day, const char *mon,
                           const char *year, const char *tod){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        if_modified_since_header_rtsp_t *h = get_ims(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"If-Modified-Since");
        set_colon_space(h->colon_space);
        set_cstr(h->wkday,sizeof(h->wkday), wk?wk:"Tue");
        set_cstr(h->comma_space,sizeof(h->comma_space),", ");
        set_cstr(h->day,sizeof(h->day), day?day:"15"); h->space1=' ';
        set_cstr(h->month,sizeof(h->month), mon?mon:"Nov"); h->space2=' ';
        set_cstr(h->year,sizeof(h->year), year?year:"1994"); h->space3=' ';
        set_cstr(h->time_of_day,sizeof(h->time_of_day), tod?tod:"08:12:31"); h->space4=' ';
        set_cstr(h->gmt,sizeof(h->gmt),"GMT");
        set_crlf(h->crlf);
    }
}
void delete_if_modified_since(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ if_modified_since_header_rtsp_t *h=get_ims(&arr[i]); if(h) h->name[0]='\0'; }
}

void repeat_if_modified_since(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        if_modified_since_header_rtsp_t *h=get_ims(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_if_modified_since(arr+i,1,NULL,NULL,NULL,NULL,NULL);
        set_cstr(h->name,sizeof(h->name),"If-Modified-Since, If-Modified-Since");
    }
}

typedef void (*ims_op_fn)(if_modified_since_header_rtsp_t*);
static void ims_ok_past(if_modified_since_header_rtsp_t* h){
    add_if_modified_since((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL,NULL,NULL,NULL,NULL);
    set_cstr(h->name,sizeof(h->name),"If-Modified-Since");
    set_colon_space(h->colon_space);
    set_cstr(h->wkday,sizeof(h->wkday),"Mon"); set_cstr(h->comma_space,sizeof(h->comma_space),", ");
    set_cstr(h->day,sizeof(h->day),"01"); h->space1=' '; set_cstr(h->month,sizeof(h->month),"Jan");
    h->space2=' '; set_cstr(h->year,sizeof(h->year),"2000"); h->space3=' ';
    set_cstr(h->time_of_day,sizeof(h->time_of_day),"00:00:00"); h->space4=' '; set_cstr(h->gmt,sizeof(h->gmt),"GMT");
    set_crlf(h->crlf);
}
static void ims_future(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->year,sizeof(h->year),"2999"); }
static void ims_bad_month(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->month,sizeof(h->month),"Foo"); }
static void ims_bad_time(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->time_of_day,sizeof(h->time_of_day),"24:61:61"); }
static void ims_lowercase_name(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->name,sizeof(h->name),"if-modified-since"); }
static void ims_no_space_after_colon(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->colon_space,sizeof(h->colon_space),":"); }
static void ims_missing_crlf(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void ims_weekday_mismatch(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->wkday,sizeof(h->wkday),"Sun"); }
static void ims_year_2digit(if_modified_since_header_rtsp_t* h){ ims_ok_past(h); set_cstr(h->year,sizeof(h->year),"99"); }
static void ims_delete(if_modified_since_header_rtsp_t* h){ h->name[0]='\0'; }

static ims_op_fn k_ims_ops[] = {
    ims_ok_past, ims_future, ims_bad_month, ims_bad_time, ims_lowercase_name,
    ims_no_space_after_colon, ims_missing_crlf, ims_weekday_mismatch,
    ims_year_2digit, ims_delete
};

static const int weights_ims_ops[10] = {
    100, /* 0: ims_ok_past            */
    100, /* 1: ims_future             */
      0, /* 2: ims_bad_month          */
      0, /* 3: ims_bad_time           */
      0, /* 4: ims_lowercase_name     */
      0, /* 5: ims_no_space_after_colon/
      0, /* 6: ims_missing_crlf       */
    100, /* 7: ims_weekday_mismatch   */
      0, /* 8: ims_year_2digit        */
      0, /* 9: ims_delete             */
};

static size_t ims_ops_count(void) {
    return sizeof(k_ims_ops) / sizeof(k_ims_ops[0]);
}

void mutate_if_modified_since(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = ims_ops_count();

    for (size_t i = 0; i < n; i++) {
        if_modified_since_header_rtsp_t *h = get_ims(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {

            add_if_modified_since(arr + i, 1, NULL, NULL, NULL, NULL, NULL);
        }


        size_t idx = weighted_pick_idx(weights_ims_ops, M);
        k_ims_ops[idx](h);
    }
}


static inline last_modified_header_rtsp_t* get_last_mod(rtsp_packet_t *p){
    if(!p) return NULL;
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.last_modified_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.last_modified_header;
        default: return NULL;
    }
}

void add_last_modified(rtsp_packet_t *arr, size_t n,
                       const char *wk, const char *day, const char *mon,
                       const char *year, const char *tod){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        last_modified_header_rtsp_t *h = get_last_mod(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Last-Modified");
        set_colon_space(h->colon_space);
        set_cstr(h->wkday,sizeof(h->wkday), wk?wk:"Tue");
        set_cstr(h->comma_space,sizeof(h->comma_space),", ");
        set_cstr(h->day,sizeof(h->day), day?day:"15"); h->space1=' ';
        set_cstr(h->month,sizeof(h->month), mon?mon:"Nov"); h->space2=' ';
        set_cstr(h->year,sizeof(h->year), year?year:"1994"); h->space3=' ';
        set_cstr(h->time_of_day,sizeof(h->time_of_day), tod?tod:"08:12:31"); h->space4=' ';
        set_cstr(h->gmt,sizeof(h->gmt),"GMT");
        set_crlf(h->crlf);
    }
}
void delete_last_modified(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ last_modified_header_rtsp_t *h=get_last_mod(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_last_modified(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        last_modified_header_rtsp_t *h=get_last_mod(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_last_modified(arr+i,1,NULL,NULL,NULL,NULL,NULL);
        set_cstr(h->name,sizeof(h->name),"Last-Modified, Last-Modified");
    }
}


typedef void (*lm_op_fn)(last_modified_header_rtsp_t*);
static void lm_ok_sample(last_modified_header_rtsp_t* h){
    add_last_modified((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL,NULL,NULL,NULL,NULL);
}
static void lm_very_old(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->year,sizeof(h->year),"1970"); }
static void lm_future(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->year,sizeof(h->year),"2999"); }
static void lm_bad_month(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->month,sizeof(h->month),"Foo"); }
static void lm_bad_time(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->time_of_day,sizeof(h->time_of_day),"3:5:7"); }
static void lm_lowercase_name(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->name,sizeof(h->name),"last-modified"); }
static void lm_bad_sep(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->colon_space,sizeof(h->colon_space),":"); }
static void lm_missing_crlf(last_modified_header_rtsp_t* h){ lm_ok_sample(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void lm_weekday_mismatch(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->wkday,sizeof(h->wkday),"Sun"); }
static void lm_year_2digit(last_modified_header_rtsp_t* h){ lm_ok_sample(h); set_cstr(h->year,sizeof(h->year),"99"); }
static void lm_delete(last_modified_header_rtsp_t* h){ h->name[0]='\0'; }

static lm_op_fn k_lm_ops[] = {
    lm_ok_sample, lm_very_old, lm_future, lm_bad_month, lm_bad_time,
    lm_lowercase_name, lm_bad_sep, lm_missing_crlf, lm_weekday_mismatch,
    lm_year_2digit, lm_delete
};

static const int weights_lm_ops[11] = {
    100, /* 0: lm_ok_sample        */
    100, /* 1: lm_very_old         */
    100, /* 2: lm_future           */
      0, /* 3: lm_bad_month        */
      0, /* 4: lm_bad_time         */
      0, /* 5: lm_lowercase_name   */
      0, /* 6: lm_bad_sep          */
      0, /* 7: lm_missing_crlf     */
    100, /* 8: lm_weekday_mismatch */
      0, /* 9: lm_year_2digit      */
      0, /*10: lm_delete           */
};

static size_t lm_ops_count(void) {
    return sizeof(k_lm_ops) / sizeof(k_lm_ops[0]);
}

void mutate_last_modified(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = lm_ops_count();

    for (size_t i = 0; i < n; i++) {
        last_modified_header_rtsp_t *h = get_last_mod(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_last_modified(arr + i, 1, NULL, NULL, NULL, NULL, NULL);
        }

        size_t idx = weighted_pick_idx(weights_lm_ops, M);
        k_lm_ops[idx](h);
    }
}




/* =======================================================
   1) Proxy-Require
   ======================================================= */
static inline proxy_require_header_rtsp_t* get_proxy_require(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.proxy_require_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.proxy_require_header;
        case RTSP_TYPE_SETUP:         return &p->setup.proxy_require_header;
        case RTSP_TYPE_PLAY:          return &p->play.proxy_require_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.proxy_require_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.proxy_require_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.proxy_require_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.proxy_require_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.proxy_require_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.proxy_require_header;
        case RTSP_TYPE_RECORD:        return &p->record.proxy_require_header;
        default: return NULL;
    }
}
void add_proxy_require(rtsp_packet_t *arr, size_t n, const char *tag){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        proxy_require_header_rtsp_t *h = get_proxy_require(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Proxy-Require");
        set_colon_space(h->colon_space);
        set_cstr(h->option_tag,sizeof(h->option_tag), tag?tag:"play.basic");
        set_crlf(h->crlf);
    }
}
void delete_proxy_require(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ proxy_require_header_rtsp_t *h=get_proxy_require(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_proxy_require(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        proxy_require_header_rtsp_t *h=get_proxy_require(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_proxy_require(arr+i,1,NULL);
        set_cstr(h->option_tag,sizeof(h->option_tag),"play.basic, funky.ext, foo");
        set_cstr(h->name,sizeof(h->name),"Proxy-Require, Proxy-Require");
    }
}

typedef void (*pr_op_fn)(proxy_require_header_rtsp_t*);

static void pr_ok_multi(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_colon_space(h->colon_space);
    set_cstr(h->option_tag,sizeof(h->option_tag),"play.basic, com.vendor.feature"); set_crlf(h->crlf);
}
static void pr_empty_tag(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_colon_space(h->colon_space);
    h->option_tag[0]='\0'; set_crlf(h->crlf);
}
static void pr_bad_sep(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_cstr(h->colon_space,sizeof(h->colon_space),":");
    set_cstr(h->option_tag,sizeof(h->option_tag),"play.basic"); set_crlf(h->crlf);
}
static void pr_lowercase_name(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"proxy-require"); set_colon_space(h->colon_space);
    set_cstr(h->option_tag,sizeof(h->option_tag),"x"); set_crlf(h->crlf);
}
// static void pr_missing_crlf(proxy_require_header_rtsp_t* h){ pr_ok_basic(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void pr_long_tag(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_colon_space(h->colon_space);
    char buf[256]; memset(buf,'A',sizeof(buf)); buf[255]='\0'; set_cstr(h->option_tag,sizeof(h->option_tag),buf); set_crlf(h->crlf);
}
static void pr_weird_chars(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_colon_space(h->colon_space);
    set_cstr(h->option_tag,sizeof(h->option_tag),"foo\tbar,\"baz\";param="); set_crlf(h->crlf);
}
static void pr_space_list(proxy_require_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Proxy-Require"); set_colon_space(h->colon_space);
    set_cstr(h->option_tag,sizeof(h->option_tag),"  a  ,   b  ,c "); set_crlf(h->crlf);
}
static void pr_delete(proxy_require_header_rtsp_t* h){ h->name[0]='\0'; }

static pr_op_fn k_pr_ops[] = {
    pr_ok_multi, pr_empty_tag, pr_bad_sep, pr_lowercase_name,
    pr_long_tag, pr_weird_chars, pr_space_list, pr_delete
};

static const int weights_pr_ops[8] = {
    100, /* 0: pr_ok_multi       */
      0, /* 1: pr_empty_tag      */
      0, /* 2: pr_bad_sep        */
      0, /* 3: pr_lowercase_name */
    100, /* 4: pr_long_tag       */
      0, /* 5: pr_weird_chars    */
    100, /* 6: pr_space_list     */
      0, /* 7: pr_delete         */
};

static size_t pr_ops_count(void) {
    return sizeof(k_pr_ops) / sizeof(k_pr_ops[0]);
}

void mutate_proxy_require(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = pr_ops_count();

    for (size_t i = 0; i < n; i++) {
        proxy_require_header_rtsp_t *h = get_proxy_require(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_proxy_require(arr + i, 1, NULL);  
        }

        size_t idx = weighted_pick_idx(weights_pr_ops, M);
        k_pr_ops[idx](h);
    }
}


static inline range_header_rtsp_t* get_range(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_PLAY:   return &p->play.range_header;
        case RTSP_TYPE_PAUSE:  return &p->pause.range_header;
        case RTSP_TYPE_RECORD: return &p->record.range_header;
        default: return NULL;
    }
}
void add_range(rtsp_packet_t *arr, size_t n, const char *start, const char *end){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        range_header_rtsp_t *h = get_range(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Range");
        set_colon_space(h->colon_space);
        set_cstr(h->unit,sizeof(h->unit),"npt"); h->equals='=';
        set_cstr(h->start,sizeof(h->start), start?start:"0"); h->dash='-';
        set_cstr(h->end,sizeof(h->end), end?end:"7.741");
        set_crlf(h->crlf);
    }
}
void delete_range(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ range_header_rtsp_t *h=get_range(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_range(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        range_header_rtsp_t *h=get_range(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_range(arr+i,1,NULL,NULL);
        set_cstr(h->unit,sizeof(h->unit),"npt"); h->equals='=';
        set_cstr(h->start,sizeof(h->start),"0-10, npt=5-15"); h->dash='\0'; h->end[0]='\0';
    }
}

typedef void (*rg_op_fn)(range_header_rtsp_t*);
static void rg_ok_closed(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"0","7.741"); }
static void rg_ok_open_end(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"5.0",""); }
static void rg_ok_open_start(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"","10.0"); }
static void rg_reverse(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"10.0","5.0"); }
static void rg_bad_unit(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"0","1"); set_cstr(h->unit,sizeof(h->unit),"smpte"); }
static void rg_non_numeric(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"zero","ten"); }
static void rg_missing_eq(range_header_rtsp_t* h){ rg_ok_closed(h); h->equals=':'; }
static void rg_missing_dash(range_header_rtsp_t* h){ rg_ok_closed(h); h->dash=':'; }
static void rg_negative(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"-10","-1"); }
static void rg_big_numbers(range_header_rtsp_t* h){ add_range((rtsp_packet_t*)&(rtsp_packet_t){0},0,"999999999","1000000000"); }
static void rg_delete(range_header_rtsp_t* h){ h->name[0]='\0'; }

static rg_op_fn k_rg_ops[] = {
    rg_ok_closed, rg_ok_open_end, rg_ok_open_start, rg_reverse, rg_bad_unit,
    rg_non_numeric, rg_missing_eq, rg_missing_dash, rg_negative, rg_big_numbers,
    rg_delete
};

static const int weights_rg_ops[11] = {
    100, /* 0: rg_ok_closed       */
    100, /* 1: rg_ok_open_end     */
    100, /* 2: rg_ok_open_start   */
    100, /* 3: rg_reverse         */
      0, /* 4: rg_bad_unit        */
      0, /* 5: rg_non_numeric     */
      0, /* 6: rg_missing_eq      */
      0, /* 7: rg_missing_dash    */
      0, /* 8: rg_negative        */
      0, /* 9: rg_big_numbers     */
      0, /*10: rg_delete          */
};

static size_t rg_ops_count(void) {
    return sizeof(k_rg_ops) / sizeof(k_rg_ops[0]);
}

void mutate_range(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();
    size_t M = rg_ops_count();

    for (size_t i = 0; i < n; i++) {
        range_header_rtsp_t *h = get_range(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_range(arr + i, 1, NULL, NULL);  
        }


        size_t idx = weighted_pick_idx(weights_rg_ops, M);
        k_rg_ops[idx](h);
    }
}


/* =======================================================
   3) Referer
   ======================================================= */
static inline referer_header_rtsp_t* get_referer(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.referer_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.referer_header;
        case RTSP_TYPE_SETUP:         return &p->setup.referer_header;
        case RTSP_TYPE_PLAY:          return &p->play.referer_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.referer_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.referer_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.referer_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.referer_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.referer_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.referer_header;
        case RTSP_TYPE_RECORD:        return &p->record.referer_header;
        default: return NULL;
    }
}
void add_referer(rtsp_packet_t *arr, size_t n, const char *uri){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        referer_header_rtsp_t *h = get_referer(&arr[i]); if(!h) continue;
        set_cstr(h->name,sizeof(h->name),"Referer");
        set_colon_space(h->colon_space);
        set_cstr(h->uri,sizeof(h->uri), uri?uri:"rtsp://example.com/prev");
        set_crlf(h->crlf);
    }
}
void delete_referer(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ referer_header_rtsp_t *h=get_referer(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_referer(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        referer_header_rtsp_t *h=get_referer(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_referer(arr+i,1,NULL);
        set_cstr(h->uri,sizeof(h->uri),"rtsp://a/1, rtsp://b/2");
        set_cstr(h->name,sizeof(h->name),"Referer, Referer");
    }
}

typedef void (*rf_op_fn)(referer_header_rtsp_t*);
static void rf_ok_rtsp(referer_header_rtsp_t* h){ add_referer((rtsp_packet_t*)&(rtsp_packet_t){0},0,"rtsp://host/prev"); }
static void rf_ok_http(referer_header_rtsp_t* h){ add_referer((rtsp_packet_t*)&(rtsp_packet_t){0},0,"http://host/page"); }
static void rf_no_schema(referer_header_rtsp_t* h){ add_referer((rtsp_packet_t*)&(rtsp_packet_t){0},0,"//host/path"); }
static void rf_empty(referer_header_rtsp_t* h){ add_referer((rtsp_packet_t*)&(rtsp_packet_t){0},0,""); }
static void rf_bad_sep(referer_header_rtsp_t* h){ rf_ok_rtsp(h); set_cstr(h->colon_space,sizeof(h->colon_space),":"); }
static void rf_lowercase_name(referer_header_rtsp_t* h){ rf_ok_rtsp(h); set_cstr(h->name,sizeof(h->name),"referer"); }
static void rf_missing_crlf(referer_header_rtsp_t* h){ rf_ok_rtsp(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void rf_long_uri(referer_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Referer"); set_colon_space(h->colon_space);
    char buf[300]; memset(buf,'A',sizeof(buf)); buf[0]='r'; buf[1]='t'; buf[2]='s'; buf[3]='p'; buf[4]=':'; buf[5]='/'; buf[6]='/';
    buf[299]='\0'; set_cstr(h->uri,sizeof(h->uri),buf); set_crlf(h->crlf);
}
static void rf_quoted(referer_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Referer"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"\"rtsp://host/with space\""); set_crlf(h->crlf);
}
static void rf_two_values(referer_header_rtsp_t* h){
    set_cstr(h->name,sizeof(h->name),"Referer"); set_colon_space(h->colon_space);
    set_cstr(h->uri,sizeof(h->uri),"rtsp://a, http://b"); set_crlf(h->crlf);
}
static void rf_delete(referer_header_rtsp_t* h){ h->name[0]='\0'; }

static rf_op_fn k_rf_ops[] = {
    rf_ok_rtsp, rf_ok_http, rf_no_schema, rf_empty, rf_bad_sep,
    rf_lowercase_name, rf_missing_crlf, rf_long_uri, rf_quoted,
    rf_two_values, rf_delete
};

static const int weights_rf_ops[11] = {
    100, /* 0: rf_ok_rtsp       */
    100, /* 1: rf_ok_http       */
    100, /* 2: rf_no_schema     */
      0, /* 3: rf_empty         */
      0, /* 4: rf_bad_sep       */
      0, /* 5: rf_lowercase_name*/
      0, /* 6: rf_missing_crlf  */
    100, /* 7: rf_long_uri      */
    100, /* 8: rf_quoted        */
    100, /* 9: rf_two_values    */
      0, /*10: rf_delete        */
};

static size_t rf_ops_count(void) {
    return sizeof(k_rf_ops) / sizeof(k_rf_ops[0]);
}

void mutate_referer(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = rf_ops_count();

    for (size_t i = 0; i < n; i++) {
        referer_header_rtsp_t *h = get_referer(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_referer(arr + i, 1, NULL);
        }

        size_t idx = weighted_pick_idx(weights_rf_ops, M);
        k_rf_ops[idx](h);
    }
}




/* =======================================================
   1) Require
   ======================================================= */
static inline require_header_rtsp_t* get_require(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.require_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.require_header;
        case RTSP_TYPE_SETUP:         return &p->setup.require_header;
        case RTSP_TYPE_PLAY:          return &p->play.require_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.require_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.require_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.require_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.require_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.require_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.require_header;
        case RTSP_TYPE_RECORD:        return &p->record.require_header;
        default: return NULL;
    }
}
void add_require(rtsp_packet_t *arr, size_t n, const char *tag){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        require_header_rtsp_t *h = get_require(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Require");
        set_colon_space(h->colon_space);
        set_cstr(h->option_tag, sizeof(h->option_tag), tag?tag:"implicit-play");
        set_crlf(h->crlf);
    }
}
void delete_require(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ require_header_rtsp_t *h=get_require(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_require(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        require_header_rtsp_t *h=get_require(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_require(arr+i,1,NULL);
        set_cstr(h->option_tag, sizeof(h->option_tag), "implicit-play, com.foo.bar, x");
        set_cstr(h->name, sizeof(h->name), "Require, Require");
    }
}


typedef void (*rq_op_fn)(require_header_rtsp_t*);
static void rq_ok_one(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); set_cstr(h->option_tag, sizeof(h->option_tag), "implicit-play"); set_crlf(h->crlf); }
static void rq_ok_multi(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); set_cstr(h->option_tag, sizeof(h->option_tag), "com.vendor.feature,play.basic"); set_crlf(h->crlf); }
static void rq_empty_tag(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); h->option_tag[0]='\0'; set_crlf(h->crlf); }
static void rq_bad_sep(require_header_rtsp_t* h){ rq_ok_one(h); set_cstr(h->colon_space,3,":"); }
static void rq_lowercase_name(require_header_rtsp_t* h){ rq_ok_one(h); set_cstr(h->name, sizeof(h->name), "Require"); }
static void rq_missing_crlf(require_header_rtsp_t* h){ rq_ok_one(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void rq_long_tag(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); char buf[256]; memset(buf,'R',sizeof(buf)); buf[255]='\0'; set_cstr(h->option_tag,sizeof(h->option_tag),buf); set_crlf(h->crlf); }
static void rq_weird_chars(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); set_cstr(h->option_tag, sizeof(h->option_tag), "foo\tbar;\"baz\"="); set_crlf(h->crlf); }
static void rq_spaces_list(require_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Require"); set_colon_space(h->colon_space); set_cstr(h->option_tag, sizeof(h->option_tag), "  a ,   b, c  "); set_crlf(h->crlf); }
static void rq_delete(require_header_rtsp_t* h){ h->name[0]='\0'; }

static rq_op_fn k_rq_ops[] = {
    rq_ok_one, rq_ok_multi, rq_empty_tag, rq_bad_sep, rq_lowercase_name,
    rq_missing_crlf, rq_long_tag, rq_weird_chars, rq_spaces_list, rq_delete
};

static const int weights_rq_ops[10] = {
    100, /* 0: rq_ok_one        */
    100, /* 1: rq_ok_multi      */
      0, /* 2: rq_empty_tag     */
      0, /* 3: rq_bad_sep       */
      0, /* 4: rq_lowercase_name*/
      0, /* 5: rq_missing_crlf  */
    100, /* 6: rq_long_tag      */
      0, /* 7: rq_weird_chars   */
    100, /* 8: rq_spaces_list   */
      0, /* 9: rq_delete        */
};

static size_t rq_ops_count(void) {
    return sizeof(k_rq_ops) / sizeof(k_rq_ops[0]);
}

void mutate_require(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = rq_ops_count();

    for (size_t i = 0; i < n; i++) {
        require_header_rtsp_t *h = get_require(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_require(arr + i, 1, NULL);  
        }

        size_t idx = weighted_pick_idx(weights_rq_ops, M);
        k_rq_ops[idx](h);
    }
}



static inline scale_header_rtsp_t* get_scale(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_PLAY:   return &p->play.scale_header;
        case RTSP_TYPE_RECORD: return &p->record.scale_header;
        default: return NULL;
    }
}
void add_scale(rtsp_packet_t *arr, size_t n, float v){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        scale_header_rtsp_t *h = get_scale(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Scale");
        set_colon_space(h->colon_space);
        h->value = (v==0.0f?1.0f:v);
        set_crlf(h->crlf);
    }
}
void delete_scale(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ scale_header_rtsp_t *h=get_scale(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_scale(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        scale_header_rtsp_t *h=get_scale(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_scale(arr+i,1,1.0f);
        set_cstr(h->name, sizeof(h->name), "Scale, Scale");
    }
}

typedef void (*sc_op_fn)(scale_header_rtsp_t*);
static void sc_ok_1(scale_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Scale"); set_colon_space(h->colon_space); h->value=1.0f; set_crlf(h->crlf); }
static void sc_ok_half(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = 0.5f; }
static void sc_ok_2(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = 2.0f; }
static void sc_zero(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = 0.0f; }
static void sc_negative(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = -4.0f; }
static void sc_big(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = 1e6f; }
static void sc_small(scale_header_rtsp_t* h){ sc_ok_1(h); h->value = 1e-6f; }
static void sc_bad_sep(scale_header_rtsp_t* h){ sc_ok_1(h); set_cstr(h->colon_space,3,":"); }
static void sc_lowercase_name(scale_header_rtsp_t* h){ sc_ok_1(h); set_cstr(h->name, sizeof(h->name), "scale"); }
static void sc_missing_crlf(scale_header_rtsp_t* h){ sc_ok_1(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }

static sc_op_fn k_sc_ops[] = {
    sc_ok_1, sc_ok_half, sc_ok_2, sc_zero, sc_negative,
    sc_big, sc_small, sc_bad_sep, sc_lowercase_name, sc_missing_crlf
};

static const int weights_sc_ops[10] = {
    100, /* 0: sc_ok_1           */
    100, /* 1: sc_ok_half        */
    100, /* 2: sc_ok_2           */
    100, /* 3: sc_zero           */
      0, /* 4: sc_negative       */
      0, /* 5: sc_big            */
    100, /* 6: sc_small          */
      0, /* 7: sc_bad_sep        */
      0, /* 8: sc_lowercase_name */
      0, /* 9: sc_missing_crlf   */
};

static size_t sc_ops_count(void) {
    return sizeof(k_sc_ops) / sizeof(k_sc_ops[0]);
}

void mutate_scale(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = sc_ops_count();

    for (size_t i = 0; i < n; i++) {
        scale_header_rtsp_t *h = get_scale(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_scale(arr + i, 1, 1.0f);
        }

        size_t idx = weighted_pick_idx(weights_sc_ops, M);
        k_sc_ops[idx](h);
    }
}


static inline session_header_rtsp_t* get_session(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_DESCRIBE:      return &p->describe.session_header;
        case RTSP_TYPE_PLAY:          return &p->play.session_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.session_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.session_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.session_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.session_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.session_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.session_header;
        case RTSP_TYPE_RECORD:        return &p->record.session_header;
        default: return NULL;
    }
}
void add_session(rtsp_packet_t *arr, size_t n, const char *sid, int timeout){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        session_header_rtsp_t *h = get_session(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Session");
        set_colon_space(h->colon_space);
        set_cstr(h->session_id, sizeof(h->session_id), sid?sid:"12345678");
        set_cstr(h->semicolon_timeout, sizeof(h->semicolon_timeout), ";timeout=");
        h->timeout = (timeout<=0?60:timeout);
        set_crlf(h->crlf);
    }
}
void delete_session(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ session_header_rtsp_t *h=get_session(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_session(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        session_header_rtsp_t *h=get_session(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_session(arr+i,1,NULL,60);
        set_cstr(h->name, sizeof(h->name), "Session, Session");
        set_cstr(h->session_id, sizeof(h->session_id), "ABCDEF, 1234");
    }
}

typedef void (*ss_op_fn)(session_header_rtsp_t*);
static void ss_ok_id_timeout(session_header_rtsp_t* h){
    set_cstr(h->name, sizeof(h->name), "Session"); set_colon_space(h->colon_space);
    set_cstr(h->session_id, sizeof(h->session_id),"12345678"); set_cstr(h->semicolon_timeout,10,";timeout="); h->timeout=60; set_crlf(h->crlf);
}
static void ss_ok_id_no_timeout(session_header_rtsp_t* h){
    ss_ok_id_timeout(h); h->semicolon_timeout[0]='\0'; h->timeout=0;
}
static void ss_empty_id(session_header_rtsp_t* h){ ss_ok_id_timeout(h); h->session_id[0]='\0'; }
static void ss_nonhex_id(session_header_rtsp_t* h){ ss_ok_id_timeout(h); set_cstr(h->session_id, sizeof(h->session_id), "GHIJKL"); }
static void ss_long_id(session_header_rtsp_t* h){ ss_ok_id_timeout(h); char buf[200]; memset(buf,'A',sizeof(buf)); buf[199]='\0'; set_cstr(h->session_id,sizeof(h->session_id),buf); }
static void ss_zero_timeout(session_header_rtsp_t* h){ ss_ok_id_timeout(h); h->timeout=0; }
static void ss_negative_timeout(session_header_rtsp_t* h){ ss_ok_id_timeout(h); h->timeout=-10; }
static void ss_big_timeout(session_header_rtsp_t* h){ ss_ok_id_timeout(h); h->timeout=2147483647; }
static void ss_bad_sep(session_header_rtsp_t* h){ ss_ok_id_timeout(h); set_cstr(h->colon_space,3,":"); }
static void ss_lowercase_name(session_header_rtsp_t* h){ ss_ok_id_timeout(h); set_cstr(h->name, sizeof(h->name), "session"); }
static void ss_missing_crlf(session_header_rtsp_t* h){ ss_ok_id_timeout(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void ss_two_values(session_header_rtsp_t* h){ ss_ok_id_timeout(h); set_cstr(h->session_id,sizeof(h->session_id),"1234, 5678"); }

static ss_op_fn k_ss_ops[] = {
    ss_ok_id_timeout, ss_ok_id_no_timeout, ss_empty_id, ss_nonhex_id, ss_long_id,
    ss_zero_timeout, ss_negative_timeout, ss_big_timeout, ss_bad_sep,
    ss_lowercase_name, ss_missing_crlf, ss_two_values
};

static const int weights_ss_ops[12] = {
    100, /*  0: ss_ok_id_timeout     */
    100, /*  1: ss_ok_id_no_timeout  */
      0, /*  2: ss_empty_id          */
      0, /*  3: ss_nonhex_id         */
    100, /*  4: ss_long_id           */
    100, /*  5: ss_zero_timeout      */
      0, /*  6: ss_negative_timeout  */
      0, /*  7: ss_big_timeout       */
      0, /*  8: ss_bad_sep           */
      0, /*  9: ss_lowercase_name    */
      0, /* 10: ss_missing_crlf      */
      0, /* 11: ss_two_values        */
};

static size_t ss_ops_count(void) {
    return sizeof(k_ss_ops) / sizeof(k_ss_ops[0]);
}

void mutate_session(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = ss_ops_count();

    for (size_t i = 0; i < n; i++) {
        session_header_rtsp_t *h = get_session(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_session(arr + i, 1, NULL, 60);
        }

        size_t idx = weighted_pick_idx(weights_ss_ops, M);
        k_ss_ops[idx](h);
    }
}


static inline speed_header_rtsp_t* get_speed(rtsp_packet_t *p){
    return (p->type==RTSP_TYPE_PLAY) ? &p->play.speed_header : NULL;
}
void add_speed(rtsp_packet_t *arr, size_t n, float v){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        speed_header_rtsp_t *h = get_speed(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Speed");
        set_colon_space(h->colon_space);
        h->value = v==0.0f ? 1.0f : v;
        set_crlf(h->crlf);
    }
}
void delete_speed(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ speed_header_rtsp_t *h=get_speed(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_speed(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        speed_header_rtsp_t *h=get_speed(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_speed(arr+i,1,1.0f);
        set_cstr(h->name, sizeof(h->name), "Speed, Speed"); 
    }
}

typedef void (*sp_op_fn)(speed_header_rtsp_t*);
static void sp_ok1(speed_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "Speed"); set_colon_space(h->colon_space); h->value=1.0f; set_crlf(h->crlf); }
static void sp_half(speed_header_rtsp_t* h){ sp_ok1(h); h->value=0.5f; }
static void sp_double(speed_header_rtsp_t* h){ sp_ok1(h); h->value=2.0f; }
static void sp_zero(speed_header_rtsp_t* h){ sp_ok1(h); h->value=0.0f; }
static void sp_negative(speed_header_rtsp_t* h){ sp_ok1(h); h->value=-3.0f; }
static void sp_big(speed_header_rtsp_t* h){ sp_ok1(h); h->value=1e6f; }
static void sp_small(speed_header_rtsp_t* h){ sp_ok1(h); h->value=1e-6f; }
static void sp_badsep(speed_header_rtsp_t* h){ sp_ok1(h); set_cstr(h->colon_space,3,":"); }
static void sp_lower(speed_header_rtsp_t* h){ sp_ok1(h); set_cstr(h->name, sizeof(h->name), "speed"); }
static void sp_no_crlf(speed_header_rtsp_t* h){ sp_ok1(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static sp_op_fn k_sp_ops[] = { sp_ok1, sp_half, sp_double, sp_zero, sp_negative, sp_big, sp_small, sp_badsep, sp_lower, sp_no_crlf };

static const int weights_sp_ops[10] = {
    100, /* 0: sp_ok1      */
    100, /* 1: sp_half     */
    100, /* 2: sp_double   */
    100, /* 3: sp_zero     */
      0, /* 4: sp_negative */
      0, /* 5: sp_big      */
    100, /* 6: sp_small    */
      0, /* 7: sp_badsep   */
      0, /* 8: sp_lower    */
      0, /* 9: sp_no_crlf  */
};

static size_t sp_ops_count(void) {
    return sizeof(k_sp_ops) / sizeof(k_sp_ops[0]);
}

void mutate_speed(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = sp_ops_count();

    for (size_t i = 0; i < n; i++) {
        speed_header_rtsp_t *h = get_speed(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_speed(arr + i, 1, 1.0f); 
        }

        size_t idx = weighted_pick_idx(weights_sp_ops, M);
        k_sp_ops[idx](h);
    }
}


static inline transport_header_rtsp_t* get_transport(rtsp_packet_t *p){
    return (p->type==RTSP_TYPE_SETUP) ? &p->setup.transport_header : NULL;
}
void add_transport(rtsp_packet_t *arr, size_t n,
                   const char *proto, const char *cast, const char *ports){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        transport_header_rtsp_t *h = get_transport(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Transport");
        set_colon_space(h->colon_space);
        set_cstr(h->protocol, sizeof(h->protocol), proto?proto:"RTP/AVP");
        h->semicolon1 = ';';
        set_cstr(h->cast_mode, sizeof(h->cast_mode), cast?cast:"unicast");
        h->semicolon2 = ';';
        set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "client_port=");
        set_cstr(h->port_range, sizeof(h->port_range), ports?ports:"8000-8001");
        set_crlf(h->crlf);
    }
}
void delete_transport(rtsp_packet_t *arr, size_t n){
    if(!arr) return; 
    for(size_t i=0;i<n;i++){ transport_header_rtsp_t *h=get_transport(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_transport(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        transport_header_rtsp_t *h=get_transport(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_transport(arr+i,1,NULL,NULL,NULL);
        set_cstr(h->name, sizeof(h->name), "Transport, Transport");
        set_cstr(h->port_range, sizeof(h->port_range), "8000-8001, 9000-9001");
    }
}

typedef void (*tp_op_fn)(transport_header_rtsp_t*);
static void tp_ok_uni(transport_header_rtsp_t* h){
    set_cstr(h->name, sizeof(h->name), "Transport"); set_colon_space(h->colon_space);
    set_cstr(h->protocol, sizeof(h->protocol), "RTP/AVP"); h->semicolon1=';';
    set_cstr(h->cast_mode, sizeof(h->cast_mode), "unicast"); h->semicolon2=';';
    set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "client_port="); set_cstr(h->port_range, sizeof(h->port_range), "8000-8001"); set_crlf(h->crlf);
}
static void tp_ok_multi(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->cast_mode, sizeof(h->cast_mode), "multicast"); }
static void tp_tcp(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->protocol, sizeof(h->protocol), "RTP/AVP/TCP"); }
static void tp_only_one_port(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->port_range, sizeof(h->port_range), "8000"); }
static void tp_rev_ports(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->port_range, sizeof(h->port_range), "8001-8000"); }
static void tp_bad_prefix(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->client_port_prefix, sizeof(h->client_port_prefix), "clientport="); }
static void tp_miss_semicolon1(transport_header_rtsp_t* h){ tp_ok_uni(h); h->semicolon1='\0'; }
static void tp_miss_semicolon2(transport_header_rtsp_t* h){ tp_ok_uni(h); h->semicolon2='\0'; }
static void tp_lower_name(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->name, sizeof(h->name), "transport"); }
static void tp_no_crlf(transport_header_rtsp_t* h){ tp_ok_uni(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void tp_illegal_chars(transport_header_rtsp_t* h){ tp_ok_uni(h); set_cstr(h->port_range, sizeof(h->port_range), "8000-80\x01\xFF"); }
static void tp_very_long_proto(transport_header_rtsp_t* h){ tp_ok_uni(h); char buf[200]; memset(buf,'P',sizeof(buf)); buf[199]='\0'; set_cstr(h->protocol,sizeof(h->protocol),buf); }

static tp_op_fn k_tp_ops[] = {
    tp_ok_uni, tp_ok_multi, tp_tcp, tp_only_one_port, tp_rev_ports,
    tp_bad_prefix, tp_miss_semicolon1, tp_miss_semicolon2,
    tp_lower_name, tp_no_crlf, tp_illegal_chars, tp_very_long_proto
};

static const int weights_tp_ops[12] = {
    100, /* 0: tp_ok_uni          */
    100, /* 1: tp_ok_multi        */
    100, /* 2: tp_tcp             */
    100, /* 3: tp_only_one_port   */
    100, /* 4: tp_rev_ports       */
      0, /* 5: tp_bad_prefix      */
      0, /* 6: tp_miss_semicolon1 */
      0, /* 7: tp_miss_semicolon2 */
      0, /* 8: tp_lower_name      */
      0, /* 9: tp_no_crlf         */
      0, /*10: tp_illegal_chars   */
      0, /*11: tp_very_long_proto */
};

static size_t tp_ops_count(void) {
    return sizeof(k_tp_ops) / sizeof(k_tp_ops[0]);
}

void mutate_transport(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = tp_ops_count();

    for (size_t i = 0; i < n; i++) {
        transport_header_rtsp_t *h = get_transport(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_transport(arr + i, 1, NULL, NULL, NULL);  
        }

        size_t idx = weighted_pick_idx(weights_tp_ops, M);
        k_tp_ops[idx](h);
    }
}


static inline user_agent_header_rtsp_t* get_user_agent(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.user_agent_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.user_agent_header;
        case RTSP_TYPE_SETUP:         return &p->setup.user_agent_header;
        case RTSP_TYPE_PLAY:          return &p->play.user_agent_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.user_agent_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.user_agent_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.user_agent_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.user_agent_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.user_agent_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.user_agent_header;
        case RTSP_TYPE_RECORD:        return &p->record.user_agent_header;
        default: return NULL;
    }
}
void add_user_agent(rtsp_packet_t *arr, size_t n, const char *ua){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        user_agent_header_rtsp_t *h = get_user_agent(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "User-Agent");
        set_colon_space(h->colon_space);
        set_cstr(h->agent_string, sizeof(h->agent_string), ua?ua:"Live555/0.92");
        set_crlf(h->crlf);
    }
}
void delete_user_agent(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){ user_agent_header_rtsp_t *h=get_user_agent(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_user_agent(rtsp_packet_t *arr, size_t n){
    if(!arr) return; for(size_t i=0;i<n;i++){
        user_agent_header_rtsp_t *h=get_user_agent(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_user_agent(arr+i,1,NULL);
        set_cstr(h->name, sizeof(h->name), "User-Agent, User-Agent");
        set_cstr(h->agent_string, sizeof(h->agent_string), "Foo/1.0, Bar/2.0");
    }
}

typedef void (*ua_op_fn)(user_agent_header_rtsp_t*);
static void ua_ok(user_agent_header_rtsp_t* h){ set_cstr(h->name, sizeof(h->name), "User-Agent"); set_colon_space(h->colon_space); set_cstr(h->agent_string, sizeof(h->agent_string), "VLC/3.0.11"); set_crlf(h->crlf); }
static void ua_blank(user_agent_header_rtsp_t* h){ ua_ok(h); h->agent_string[0]='\0'; }
static void ua_long(user_agent_header_rtsp_t* h){ ua_ok(h); char buf[400]; memset(buf,'A',sizeof(buf)); buf[399]='\0'; set_cstr(h->agent_string,sizeof(h->agent_string),buf); }
static void ua_inject(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->agent_string, sizeof(h->agent_string), "Foo/1.0\r\nCSeq: 9999"); }
static void ua_tabs(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->agent_string, sizeof(h->agent_string), "App\t/1.2\t(arm64)"); }
static void ua_utf8(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->agent_string, sizeof(h->agent_string), "相机/2.1 (测试)"); }
static void ua_many_products(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->agent_string, sizeof(h->agent_string), "A/1 B/2 C/3 D/4"); }
static void ua_lower_name(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->name, sizeof(h->name), "user-agent"); }
static void ua_bad_sep(user_agent_header_rtsp_t* h){ ua_ok(h); set_cstr(h->colon_space,3,":"); }
static void ua_no_crlf(user_agent_header_rtsp_t* h){ ua_ok(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static ua_op_fn k_ua_ops[] = { ua_ok, ua_blank, ua_long, ua_inject, ua_tabs, ua_utf8, ua_many_products, ua_lower_name, ua_bad_sep, ua_no_crlf };

static const int weights_ua_ops[10] = {
    100, /* 0: ua_ok            */
      0, /* 1: ua_blank         */
    100, /* 2: ua_long          */
      0, /* 3: ua_inject        */
    100, /* 4: ua_tabs          */
      0, /* 5: ua_utf8          */
    100, /* 6: ua_many_products */
      0, /* 7: ua_lower_name    */
      0, /* 8: ua_bad_sep       */
      0, /* 9: ua_no_crlf       */
};

static size_t ua_ops_count(void) {
    return sizeof(k_ua_ops) / sizeof(k_ua_ops[0]);
}


void mutate_user_agent(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = ua_ops_count();

    for (size_t i = 0; i < n; i++) {
        user_agent_header_rtsp_t *h = get_user_agent(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_user_agent(arr + i, 1, NULL);
        }

        size_t idx = weighted_pick_idx(weights_ua_ops, M);
        k_ua_ops[idx](h);
    }
}


static inline via_header_rtsp_t* get_via(rtsp_packet_t *p){
    switch(p->type){
        case RTSP_TYPE_OPTIONS:       return &p->options.via_header;
        case RTSP_TYPE_DESCRIBE:      return &p->describe.via_header;
        case RTSP_TYPE_SETUP:         return &p->setup.via_header;
        case RTSP_TYPE_PLAY:          return &p->play.via_header;
        case RTSP_TYPE_PAUSE:         return &p->pause.via_header;
        case RTSP_TYPE_TEARDOWN:      return &p->teardown.via_header;
        case RTSP_TYPE_GET_PARAMETER: return &p->get_parameter.via_header;
        case RTSP_TYPE_SET_PARAMETER: return &p->set_parameter.via_header;
        case RTSP_TYPE_REDIRECT:      return &p->redirect.via_header;
        case RTSP_TYPE_ANNOUNCE:      return &p->announce.via_header;
        case RTSP_TYPE_RECORD:        return &p->record.via_header;
        default: return NULL;
    }
}

void add_via(rtsp_packet_t *arr, size_t n, const char *proto, const char *host){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        via_header_rtsp_t *h = get_via(&arr[i]); if(!h) continue;
        set_cstr(h->name, sizeof(h->name), "Via");
        set_colon_space(h->colon_space);
        set_cstr(h->protocol, sizeof(h->protocol), proto?proto:"RTSP/1.0");
        h->space = ' ';
        set_cstr(h->host, sizeof(h->host), host?host:"example.com");
        set_crlf(h->crlf);
    }
}
void delete_via(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){ via_header_rtsp_t *h=get_via(&arr[i]); if(h) h->name[0]='\0'; }
}
void repeat_via(rtsp_packet_t *arr, size_t n){
    if(!arr) return;
    for(size_t i=0;i<n;i++){
        via_header_rtsp_t *h=get_via(&arr[i]); if(!h) continue;
        if(h->name[0]=='\0') add_via(arr+i,1,NULL,NULL);
        set_cstr(h->name, sizeof(h->name), "Via, Via");
        set_cstr(h->host, sizeof(h->host), "hop1.net, hop2.net");
    }
}


typedef void (*via_op_fn)(via_header_rtsp_t*);
static void via_ok(via_header_rtsp_t* h){ add_via((rtsp_packet_t*)&(rtsp_packet_t){0},0,NULL,NULL); /* no-op for clang */ set_cstr(h->name, sizeof(h->name), "Via"); set_colon_space(h->colon_space); set_cstr(h->protocol, sizeof(h->protocol), "RTSP/1.0"); h->space=' '; set_cstr(h->host, sizeof(h->host), "example.com"); set_crlf(h->crlf);}
static void via_rtsp2(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->protocol, sizeof(h->protocol), "RTSP/2.0"); }
static void via_lower_name(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->name, sizeof(h->name), "via"); }
static void via_no_space(via_header_rtsp_t* h){ via_ok(h); h->space='\0'; }
static void via_ipv6(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->host, sizeof(h->host), "[2001:db8::1]"); }
static void via_empty_host(via_header_rtsp_t* h){ via_ok(h); h->host[0]='\0'; }
static void via_long_host(via_header_rtsp_t* h){ via_ok(h); char buf[300]; memset(buf,'a',sizeof(buf)-1); buf[sizeof(buf)-1]='\0'; set_cstr(h->host,sizeof(h->host),buf); }
static void via_bad_sep(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->colon_space,3,":"); }
static void via_no_crlf(via_header_rtsp_t* h){ via_ok(h); h->crlf[0]='\n'; h->crlf[1]='\0'; }
static void via_inject(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->host, sizeof(h->host), "evil\r\nCSeq: 999"); }
static void via_multi_hops(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->host, sizeof(h->host), "gw1, gw2, gw3"); }
static void via_illegal_proto(via_header_rtsp_t* h){ via_ok(h); set_cstr(h->protocol, sizeof(h->protocol), "R\x01TSP/1.0"); }

static via_op_fn k_via_ops[] = {
    via_ok, via_rtsp2, via_lower_name, via_no_space, via_ipv6,
    via_empty_host, via_long_host, via_bad_sep, via_no_crlf,
    via_inject, via_multi_hops, via_illegal_proto
};

static const int weights_via_ops[12] = {
    100, /*  0: via_ok           */
    100, /*  1: via_rtsp2        */
      0, /*  2: via_lower_name   */
      0, /*  3: via_no_space     */
    100, /*  4: via_ipv6         */
      0, /*  5: via_empty_host   */
    100, /*  6: via_long_host    */
      0, /*  7: via_bad_sep      */
      0, /*  8: via_no_crlf      */
      0, /*  9: via_inject       */
    100, /* 10: via_multi_hops   */
      0, /* 11: via_illegal_proto*/
};

static size_t via_ops_count(void) {
    return sizeof(k_via_ops) / sizeof(k_via_ops[0]);
}

void mutate_via(rtsp_packet_t *arr, size_t n){
    if (!arr) return;
    rng_seed();

    size_t M = via_ops_count();

    for (size_t i = 0; i < n; i++) {
        via_header_rtsp_t *h = get_via(&arr[i]);
        if (!h) continue;

        if (h->name[0] == '\0') {
            add_via(arr + i, 1, NULL, NULL);
        }

        size_t idx = weighted_pick_idx(weights_via_ops, M);
        k_via_ops[idx](h);
    }
}


typedef void (*rtsp_mutator_fn)(rtsp_packet_t *pkt, size_t num_packets);


/* ================= OPTIONS =================
 * General: Connection(opt), Date(opt), Via(opt)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          From(opt), Proxy-Require(opt), Referer(opt), Require(opt),
 *          User-Agent(opt)
 */
static rtsp_mutator_fn options_mutators[] = {
    /* Connection */
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    /* Date */
    // add_date, 
    delete_date, repeat_date, mutate_date,
    /* Via (repeatable in your comment? here it's optional; we still allow repeat_*) */
    // add_via, 
    delete_via, repeat_via, mutate_via,

    /* Accept-Language */
    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,
    /* Authorization */
    // add_authorization, 
    delete_authorization, repeat_authorization, mutate_authorization,
    /* Bandwidth */
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    /* From */
    // add_from, 
    delete_from, repeat_from, mutate_from,
    /* Proxy-Require */
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    /* Referer */
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    /* Require */
    // add_require, 
    delete_require, repeat_require, mutate_require,
    /* User-Agent */
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= SETUP =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), Cache-Control(opt), Conference(opt), From(opt),
 *          If-Modified-Since(opt), Proxy-Require(opt), Referer(opt),
 *          Require(opt), Transport(mand), User-Agent(opt)
 */
static rtsp_mutator_fn setup_mutators[] = {
    /* Connection / Date / Via */
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    /* Accept-Language / Authorization / Bandwidth / Blocksize */
    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization, 
    delete_authorization, repeat_authorization, mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,
     delete_blocksize, repeat_blocksize, mutate_blocksize,

    /* Cache-Control / Conference / From / If-Modified-Since */
    // add_cache_control,
     delete_cache_control, repeat_cache_control, mutate_cache_control,
    // add_conference, 
    delete_conference, repeat_conference, mutate_conference,
    // add_from, 
    delete_from, repeat_from, mutate_from,
    // add_if_modified_since, 
    delete_if_modified_since, repeat_if_modified_since, mutate_if_modified_since,

    /* Proxy-Require / Referer / Require */
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer,  
         delete_referer,       repeat_referer,       mutate_referer,
    // add_require,
           delete_require,       repeat_require,       mutate_require,

    /* Transport (mandatory, 仍允许 mutate) */
    // add_transport,
     delete_transport, repeat_transport, mutate_transport,

    /* User-Agent */
    // add_user_agent,
     delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= DESCRIBE =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept(opt), Accept-Encoding(opt), Accept-Language(opt),
 *          Authorization(opt), Bandwidth(opt), Blocksize(opt),
 *          Content-Base/Encoding/Language/Length/Location(opt),
 *          Expires(opt), From(opt), If-Modified-Since(opt),
 *          Last-Modified(opt), Proxy-Require(opt), Referer(opt),
 *          Require(opt), Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn describe_mutators[] = {
    /* Connection / Date / Via */
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    /* Accept / Accept-Encoding / Accept-Language */
    // add_accept, 
    delete_accept, repeat_accept, mutate_accept,
    // add_accept_encoding, 
    delete_accept_encoding, repeat_accept_encoding, mutate_accept_encoding,
    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,

    /* Authorization / Bandwidth / Blocksize */
    // add_authorization, 
    delete_authorization, repeat_authorization, mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize, 
    delete_blocksize, repeat_blocksize, mutate_blocksize,

    /* Content-* */
    // add_content_base,     
    delete_content_base,     repeat_content_base,     mutate_content_base,
    // add_content_encoding, 
    delete_content_encoding, repeat_content_encoding, mutate_content_encoding,
    // add_content_language, 
    delete_content_language, repeat_content_language, mutate_content_language,
    // add_content_length,   
    delete_content_length,   repeat_content_length,   mutate_content_length,
    // add_content_location, 
    delete_content_location, repeat_content_location, mutate_content_location,

    /* Expires / From / If-Modified-Since / Last-Modified */
    // add_expires,            
    delete_expires,            repeat_expires,            mutate_expires,
    // add_from,       
    delete_from,               repeat_from,               mutate_from,
    // add_if_modified_since,  
    delete_if_modified_since,  repeat_if_modified_since,  mutate_if_modified_since,
    // add_last_modified,      
    delete_last_modified,      repeat_last_modified,      mutate_last_modified,

    /* Proxy-Require / Referer / Require / Session / User-Agent */
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer,       
    delete_referer,       repeat_referer,       mutate_referer,
    // add_require,       
    delete_require,       repeat_require,       mutate_require,
    // add_session,               
    delete_session,       repeat_session,       mutate_session,
    // add_user_agent,    
    delete_user_agent,    repeat_user_agent,    mutate_user_agent
};

/* ================= PLAY =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), From(opt), Proxy-Require(opt), Range(opt),
 *          Referer(opt), Require(opt), Scale(opt), Session(opt),
 *          Speed(opt), User-Agent(opt)
 */
static rtsp_mutator_fn play_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date,
     delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,   
    delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,  
    delete_blocksize, repeat_blocksize, mutate_blocksize,
    // add_from,       
    delete_from,      repeat_from,      mutate_from,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_range, 
    delete_range, repeat_range, mutate_range,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_scale, 
    delete_scale, repeat_scale, mutate_scale,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_speed, 
    delete_speed, repeat_speed, mutate_speed,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= PAUSE =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), From(opt), Proxy-Require(opt), Range(opt),
 *          Referer(opt), Require(opt), Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn pause_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,   
    delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,  
    delete_blocksize, repeat_blocksize, mutate_blocksize,
    // add_from,       
    delete_from,      repeat_from,      mutate_from,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_range, 
    delete_range, repeat_range, mutate_range,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= TEARDOWN =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          From(opt), Proxy-Require(opt), Referer(opt), Require(opt),
 *          Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn teardown_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept_language, 
    delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,   
    delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_from, 
    delete_from, repeat_from, mutate_from,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= GET_PARAMETER =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept(opt), Accept-Encoding(opt), Accept-Language(opt),
 *          Authorization(opt), Bandwidth(opt), Blocksize(opt),
 *          Content-Base(opt), Content-Length(opt), Content-Location(opt),
 *          From(opt), Last-Modified(opt), Proxy-Require(opt), Referer(opt),
 *          Require(opt), Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn get_parameter_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept, 
    delete_accept, repeat_accept, mutate_accept,
    // add_accept_encoding, 
    delete_accept_encoding, repeat_accept_encoding, mutate_accept_encoding,
    // add_accept_language,
     delete_accept_language, repeat_accept_language, mutate_accept_language,

    // add_authorization,
     delete_authorization, repeat_authorization, mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,  
    delete_blocksize, repeat_blocksize, mutate_blocksize,

    // add_content_base,    
    delete_content_base,     repeat_content_base,     mutate_content_base,
    // add_content_length,   
    delete_content_length,   repeat_content_length,   mutate_content_length,
    // add_content_location, 
    delete_content_location, repeat_content_location, mutate_content_location,

    // add_from, 
    delete_from,  repeat_from, mutate_from,
    // add_last_modified, 
    delete_last_modified, repeat_last_modified, mutate_last_modified,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= SET_PARAMETER =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), Content-Encoding(opt), Content-Length(opt),
 *          Content-Type(opt), From(opt), Proxy-Require(opt), Referer(opt),
 *          Require(opt), Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn set_parameter_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via,
     delete_via, repeat_via, mutate_via,

    // add_accept_language,
     delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,   
    delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,  
    delete_blocksize, repeat_blocksize, mutate_blocksize,

    // add_content_encoding,
     delete_content_encoding, repeat_content_encoding, mutate_content_encoding,
    // add_content_length,  
     delete_content_length,   repeat_content_length,   mutate_content_length,
    // add_content_type,     
    delete_content_type,     repeat_content_type,     mutate_content_type,

    // add_from, 
    delete_from, repeat_from, mutate_from,
    // add_proxy_require,
     delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent,
     delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= REDIRECT =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), From(opt), Proxy-Require(opt), Referer(opt),
 *          Require(opt), Session(opt), User-Agent(opt)
 */
static rtsp_mutator_fn redirect_mutators[] = {
    // add_connection,
    delete_connection, repeat_connection, mutate_connection,
    // add_date,
     delete_date, repeat_date, mutate_date,
    // add_via,
     delete_via, repeat_via, mutate_via,

    // add_accept_language,
     delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization, 
      delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth,
     delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,
      delete_blocksize, repeat_blocksize, mutate_blocksize,
    // add_from, 
    delete_from, repeat_from, mutate_from,
    // add_proxy_require,
     delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer,
     delete_referer, repeat_referer, mutate_referer,
    // add_require,
     delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent,
     delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= ANNOUNCE =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), Content-Encoding(opt), Content-Language(opt),
 *          Content-Length(opt), Content-Type(opt), Expires(opt), From(opt),
 *          Proxy-Require(opt), Referer(opt), Require(opt), Session(opt),
 *          User-Agent(opt)
 */
static rtsp_mutator_fn announce_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept_language,
     delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,  
     delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth,
     delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize, 
     delete_blocksize, repeat_blocksize, mutate_blocksize,

    // add_content_encoding,
      delete_content_encoding,  repeat_content_encoding,  mutate_content_encoding,
    // add_content_language,
      delete_content_language,  repeat_content_language,  mutate_content_language,
    // add_content_length,   
     delete_content_length,    repeat_content_length,    mutate_content_length,
    // add_content_type,      
    delete_content_type,      repeat_content_type,      mutate_content_type,

    // add_expires, 
    delete_expires, repeat_expires, mutate_expires,
    // add_from,
     delete_from, repeat_from, mutate_from,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};

/* ================= RECORD =================
 * General: CSeq(mand), Connection(opt), Date(opt), Via(opt, repeatable)
 * Request: Accept-Language(opt), Authorization(opt), Bandwidth(opt),
 *          Blocksize(opt), From(opt), Proxy-Require(opt), Range(opt),
 *          Referer(opt), Require(opt), Scale(opt), Session(opt),
 *          User-Agent(opt)
 */
static rtsp_mutator_fn record_mutators[] = {
    // add_connection, 
    delete_connection, repeat_connection, mutate_connection,
    // add_date, 
    delete_date, repeat_date, mutate_date,
    // add_via, 
    delete_via, repeat_via, mutate_via,

    // add_accept_language,
     delete_accept_language, repeat_accept_language, mutate_accept_language,
    // add_authorization,  
     delete_authorization,   repeat_authorization,   mutate_authorization,
    // add_bandwidth, 
    delete_bandwidth, repeat_bandwidth, mutate_bandwidth,
    // add_blocksize,  
    delete_blocksize, repeat_blocksize, mutate_blocksize,
    // add_from, 
    delete_from, repeat_from, mutate_from,
    // add_proxy_require, 
    delete_proxy_require, repeat_proxy_require, mutate_proxy_require,
    // add_range, 
    delete_range, repeat_range, mutate_range,
    // add_referer, 
    delete_referer, repeat_referer, mutate_referer,
    // add_require, 
    delete_require, repeat_require, mutate_require,
    // add_scale, 
    delete_scale, repeat_scale, mutate_scale,
    // add_session, 
    delete_session, repeat_session, mutate_session,
    // add_user_agent, 
    delete_user_agent, repeat_user_agent, mutate_user_agent
};



#define CNT(a) (sizeof(a)/sizeof((a)[0]))


static void dispatch_rtsp_options_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(options_mutators);
    options_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_describe_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(describe_mutators);
    describe_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_setup_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(setup_mutators);
    setup_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_play_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(play_mutators);
    play_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_pause_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(pause_mutators);
    pause_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_teardown_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(teardown_mutators);
    teardown_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_get_parameter_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(get_parameter_mutators);
    get_parameter_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_set_parameter_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(set_parameter_mutators);
    set_parameter_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_redirect_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(redirect_mutators);
    redirect_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_announce_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(announce_mutators);
    announce_mutators[idx](pkt, 1);
}
static void dispatch_rtsp_record_mutation(rtsp_packet_t *pkt, size_t num_packets){
    if(!pkt || num_packets==0) return;
    size_t idx = rand() % CNT(record_mutators);
    record_mutators[idx](pkt, 1);
}

static inline void rng_seed_once(void){
    static int inited=0; if(!inited){ srand((unsigned)time(NULL)); inited=1; }
}

void dispatch_rtsp_multiple_mutations(rtsp_packet_t *arr, size_t num_packets, int rounds){
    if(!arr || num_packets==0) return;
    rng_seed_once();
    if(rounds <= 0) rounds = 1;

    for(int i=0;i<rounds;i++){
        size_t mutate_index = rand() % num_packets;
        rtsp_packet_t *p = &arr[mutate_index];

        switch(p->type){
        case RTSP_TYPE_OPTIONS:       dispatch_rtsp_options_mutation(p, 1); break;
        case RTSP_TYPE_DESCRIBE:      dispatch_rtsp_describe_mutation(p, 1); break;
        case RTSP_TYPE_SETUP:         dispatch_rtsp_setup_mutation(p, 1); break;
        case RTSP_TYPE_PLAY:          dispatch_rtsp_play_mutation(p, 1); break;
        case RTSP_TYPE_PAUSE:         dispatch_rtsp_pause_mutation(p, 1); break;
        case RTSP_TYPE_TEARDOWN:      dispatch_rtsp_teardown_mutation(p, 1); break;
        case RTSP_TYPE_GET_PARAMETER: dispatch_rtsp_get_parameter_mutation(p, 1); break;
        case RTSP_TYPE_SET_PARAMETER: dispatch_rtsp_set_parameter_mutation(p, 1); break;
        case RTSP_TYPE_REDIRECT:      dispatch_rtsp_redirect_mutation(p, 1); break;
        case RTSP_TYPE_ANNOUNCE:      dispatch_rtsp_announce_mutation(p, 1); break;
        case RTSP_TYPE_RECORD:        dispatch_rtsp_record_mutation(p, 1); break;
        default: /* RTSP_TYPE_UNKNOWN */ break;
        }
    }
}
