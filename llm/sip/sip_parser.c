/* sip parser source file */
#include "sip.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef SIP_BODY_MAX
#define SIP_BODY_MAX 8192
#endif

/* ------------------------------ 工具函数 ------------------------------ */

static inline void memzero(void *p, size_t n) { memset(p, 0, n); }

static size_t cpy_trim(char *dst, size_t dst_sz, const char *src, size_t len) {
  // 去首尾空白并 NUL 终止
  while (len && (src[0] == ' ' || src[0] == '\t')) { src++; len--; }
  while (len && (src[len-1] == ' ' || src[len-1] == '\t' || src[len-1] == '\r' || src[len-1] == '\n')) len--;
  size_t n = MIN(len, dst_sz ? dst_sz - 1 : 0);
  if (dst_sz) {
    memcpy(dst, src, n);
    dst[n] = '\0';
  }
  return n;
}

static size_t cpy_token_until(char *dst, size_t dst_sz, const char *src, size_t len, const char *stops) {
  size_t i = 0;
  for (; i < len; ++i) {
    if (strchr(stops, src[i]) != NULL) break;
  }
  return cpy_trim(dst, dst_sz, src, i);
}

static int iequal_n(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    char ca = a[i], cb = b[i];
    if (!ca || !cb) return tolower((unsigned char)ca) == tolower((unsigned char)cb);
    if (tolower((unsigned char)ca) != tolower((unsigned char)cb)) return 0;
  }
  return 1;
}

static int istarts_with_ci(const char *s, size_t n, const char *prefix) {
  size_t m = strlen(prefix);
  if (n < m) return 0;
  return iequal_n(s, prefix, m);
}

// 把 name 与 ": " 与 "\r\n" 写好
static void hdr_set_present(char name_buf[], size_t name_len,
                            char sep_buf[],  size_t sep_len,
                            char crlf_buf[], size_t crlf_len,
                            const char *name) {
  memzero(name_buf, name_len);
  memzero(sep_buf,  sep_len);
  memzero(crlf_buf, crlf_len);
  snprintf(name_buf, name_len, "%s", name);
  snprintf(sep_buf,  sep_len,  ": ");
  snprintf(crlf_buf, crlf_len, "\r\n");
}

/* 从 Content-Length 头部的文本里解析数值（不存在/非法则返回 -1） */
static long parse_cl_value_from_hdr(const sip_content_length_hdr_t *h) {
  if (!h) return -1;
  if (h->name[0] == '\0') return -1;                 /* header 标记为缺省 */
  const char *s = h->length;
  while (*s && (*s==' ' || *s=='\t')) s++;
  long v = 0;
  int any = 0;
  while (*s >= '0' && *s <= '9') {
    any = 1;
    v = v * 10 + (*s - '0');
    if (v > 0x3fffffff) break;
    s++;
  }
  return any ? v : -1;
}

/* 读取当前报文对象的 Content-Length 值；不支持的类型返回 -1 */
static long get_pkt_content_length(const sip_packet_t *pkt) {
  if (!pkt) return -1;
  switch (pkt->cmd_type) {
    case SIP_PKT_INVITE:   return parse_cl_value_from_hdr(&pkt->pkt.invite.content_length);
    case SIP_PKT_ACK:      return parse_cl_value_from_hdr(&pkt->pkt.ack.content_length);
    case SIP_PKT_REGISTER: return parse_cl_value_from_hdr(&pkt->pkt.register_.content_length);
    case SIP_PKT_OPTIONS:  return parse_cl_value_from_hdr(&pkt->pkt.options.content_length);
    default:               return -1; /* BYE/CANCEL 未定义 Content-Length 解析 */
  }
}

/* 返回可写入 body 的指针和容量（仅在四种允许带 body 的方法上有效） */
static char *get_pkt_body_buf_and_cap(sip_packet_t *pkt, size_t *out_cap) {
  if (!pkt) { if (out_cap) *out_cap = 0; return NULL; }
  switch (pkt->cmd_type) {
    case SIP_PKT_INVITE:
      if (out_cap) *out_cap = SIP_BODY_MAX;
      return pkt->pkt.invite.body;
    case SIP_PKT_ACK:
      if (out_cap) *out_cap = SIP_BODY_MAX;
      return pkt->pkt.ack.body;
    case SIP_PKT_REGISTER:
      if (out_cap) *out_cap = SIP_BODY_MAX;
      return pkt->pkt.register_.body;
    case SIP_PKT_OPTIONS:
      if (out_cap) *out_cap = SIP_BODY_MAX;
      return pkt->pkt.options.body;
    default:
      if (out_cap) *out_cap = 0;
      return NULL;
  }
}


// 把 header 设为“缺省”（name[0] = '\0'）
#define HDR_MARK_ABSENT(hdr) do { (hdr).name[0] = '\0'; } while(0)

/* ------------------------------ 单个头解析 ------------------------------ */

static void parse_accept(const char *v, size_t n, sip_accept_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Accept");
  // type/subtype;params
  const char *slash = memchr(v, '/', n);
  if (!slash) { cpy_trim(h->media_type, sizeof h->media_type, v, n); h->slash=0; h->sub_type[0]=0; h->params[0]=0; return; }
  cpy_trim(h->media_type, sizeof h->media_type, v, slash - v);
  h->slash = '/';
  const char *after = slash + 1;
  size_t rem = (v + n > after) ? (size_t)((v + n) - after) : 0;
  const char *sc = memchr(after, ';', rem);
  if (sc) {
    cpy_trim(h->sub_type, sizeof h->sub_type, after, sc - after);
    cpy_trim(h->params, sizeof h->params, sc, (v+n) - sc);
  } else {
    cpy_trim(h->sub_type, sizeof h->sub_type, after, rem);
    h->params[0] = '\0';
  }
}

static void parse_accept_encoding(const char *v, size_t n, sip_accept_encoding_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Accept-Encoding");
  const char *sc = memchr(v, ';', n);
  if (sc) {
    cpy_trim(h->coding, sizeof h->coding, v, sc - v);
    cpy_trim(h->params, sizeof h->params, sc, (v+n)-sc);
  } else {
    cpy_trim(h->coding, sizeof h->coding, v, n);
    h->params[0] = '\0';
  }
}

static void parse_accept_language(const char *v, size_t n, sip_accept_language_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Accept-Language");
  const char *sc = memchr(v, ';', n);
  if (sc) {
    cpy_trim(h->lang_tag, sizeof h->lang_tag, v, sc - v);
    cpy_trim(h->params, sizeof h->params, sc, (v+n)-sc);
  } else {
    cpy_trim(h->lang_tag, sizeof h->lang_tag, v, n);
    h->params[0] = '\0';
  }
}

static void parse_call_id(const char *v, size_t n, sip_call_id_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Call-ID");
  cpy_trim(h->value, sizeof h->value, v, n);
}

static void parse_simple_text_header(const char *name, const char *v, size_t n, char *name_buf, size_t name_sz,
                                     char *sep_buf, size_t sep_sz, char *text_buf, size_t text_sz, char *crlf_buf, size_t crlf_sz) {
  hdr_set_present(name_buf, name_sz, sep_buf, sep_sz, crlf_buf, crlf_sz, name);
  cpy_trim(text_buf, text_sz, v, n);
}

static void parse_addr_hdr_common(const char *name, const char *v, size_t n,
                                  char *name_buf, size_t name_sz, char *sep_buf, size_t sep_sz,
                                  char *display, size_t display_sz, char *sp_opt,
                                  char *lt, char *uri, size_t uri_sz, char *gt,
                                  char *params, size_t params_sz, char *crlf_buf, size_t crlf_sz) {
  hdr_set_present(name_buf, name_sz, sep_buf, sep_sz, crlf_buf, crlf_sz, name);
  *sp_opt = '\0'; *lt = '\0'; *gt = '\0'; params[0] = '\0'; display[0] = '\0'; uri[0] = '\0';

  // 形如： ["Display" ] <URI> [;params]
  const char *p = v, *end = v + n;
  const char *ltp = memchr(p, '<', end - p);
  const char *gtp = ltp ? memchr(ltp, '>', end - ltp) : NULL;

  if (ltp && gtp && ltp < gtp) {
    // display 部分
    size_t dlen = (size_t)(ltp - p);
    dlen = cpy_trim(display, display_sz, p, dlen);
    if (dlen) *sp_opt = ' ';
    *lt = '<';
    cpy_trim(uri, uri_sz, ltp + 1, (size_t)(gtp - (ltp + 1)));
    *gt = '>';
    if (gtp + 1 < end) {
      cpy_trim(params, params_sz, gtp + 1, (size_t)(end - (gtp + 1)));
    }
  } else {
    // 无尖括号，尽量当作纯 URI
    cpy_trim(uri, uri_sz, v, n);
  }
}

static void parse_contact(const char *v, size_t n, sip_contact_hdr_t *h) {
  parse_addr_hdr_common("Contact", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    h->display, sizeof h->display, &h->sp_opt,
    &h->lt, h->uri, sizeof h->uri, &h->gt,
    h->params, sizeof h->params, h->crlf, sizeof h->crlf);
}

static void parse_from(const char *v, size_t n, sip_from_hdr_t *h) {
  parse_addr_hdr_common("From", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    h->display, sizeof h->display, &h->sp_opt,
    &h->lt, h->uri, sizeof h->uri, &h->gt,
    h->params, sizeof h->params, h->crlf, sizeof h->crlf);
}

static void parse_to(const char *v, size_t n, sip_to_hdr_t *h) {
  parse_addr_hdr_common("To", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    h->display, sizeof h->display, &h->sp_opt,
    &h->lt, h->uri, sizeof h->uri, &h->gt,
    h->params, sizeof h->params, h->crlf, sizeof h->crlf);
}

static void parse_cseq(const char *v, size_t n, sip_cseq_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "CSeq");
  // number SP method
  const char *sp = memchr(v, ' ', n);
  if (sp) {
    cpy_trim(h->number, sizeof h->number, v, sp - v);
    h->sp = ' ';
    cpy_trim(h->method, sizeof h->method, sp + 1, (v+n) - (sp + 1));
  } else {
    cpy_trim(h->number, sizeof h->number, v, n);
    h->sp = '\0';
    h->method[0] = '\0';
  }
}

static void parse_record_route_or_route(const char *name, const char *v, size_t n,
                                        char *name_buf, size_t name_sz, char *sep_buf, size_t sep_sz,
                                        char *lt, char *uri, size_t uri_sz, char *gt, char *params, size_t params_sz, char *crlf_buf, size_t crlf_sz) {
  hdr_set_present(name_buf, name_sz, sep_buf, sep_sz, crlf_buf, crlf_sz, name);
  *lt = *gt = '\0'; params[0]=0; uri[0]=0;
  const char *ltp = memchr(v, '<', n);
  const char *gtp = ltp ? memchr(ltp, '>', (v+n)-ltp) : NULL;
  if (ltp && gtp && ltp < gtp) {
    *lt = '<';
    cpy_trim(uri, uri_sz, ltp+1, gtp-(ltp+1));
    *gt = '>';
    if (gtp + 1 < v + n) cpy_trim(params, params_sz, gtp+1, (v+n)-(gtp+1));
  } else {
    // 尽量把整行当作 URI
    cpy_trim(uri, uri_sz, v, n);
  }
}

static void parse_record_route(const char *v, size_t n, sip_record_route_hdr_t *h) {
  parse_record_route_or_route("Record-Route", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    &h->lt, h->uri, sizeof h->uri, &h->gt, h->params, sizeof h->params, h->crlf, sizeof h->crlf);
}

static void parse_route(const char *v, size_t n, sip_route_hdr_t *h) {
  parse_record_route_or_route("Route", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    &h->lt, h->uri, sizeof h->uri, &h->gt, h->params, sizeof h->params, h->crlf, sizeof h->crlf);
}

static void parse_via(const char *v, size_t n, sip_via_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Via");
  // sent_protocol SP sent_by [params]
  const char *sp = memchr(v, ' ', n);
  if (!sp) {
    cpy_trim(h->sent_protocol, sizeof h->sent_protocol, v, n);
    h->sp = '\0'; h->sent_by[0]=0; h->params[0]=0;
    return;
  }
  cpy_trim(h->sent_protocol, sizeof h->sent_protocol, v, sp - v);
  h->sp = ' ';
  const char *rest = sp + 1;
  size_t rlen = (v+n > rest) ? (size_t)((v+n) - rest) : 0;
  const char *sc = memchr(rest, ';', rlen);
  if (sc) {
    cpy_trim(h->sent_by, sizeof h->sent_by, rest, sc - rest);
    cpy_trim(h->params, sizeof h->params, sc, (v+n) - sc);
  } else {
    cpy_trim(h->sent_by, sizeof h->sent_by, rest, rlen);
    h->params[0] = '\0';
  }
}

static void parse_content_encoding(const char *v, size_t n, sip_content_encoding_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Content-Encoding");
  cpy_trim(h->coding, sizeof h->coding, v, n);
}

static void parse_content_length(const char *v, size_t n, sip_content_length_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Content-Length");
  cpy_trim(h->length, sizeof h->length, v, n);
}

static void parse_content_type(const char *v, size_t n, sip_content_type_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Content-Type");
  const char *slash = memchr(v, '/', n);
  if (!slash) { cpy_trim(h->type_tok, sizeof h->type_tok, v, n); h->slash=0; h->sub_type[0]=0; h->params[0]=0; return; }
  cpy_trim(h->type_tok, sizeof h->type_tok, v, slash - v);
  h->slash = '/';
  const char *after = slash + 1;
  size_t rem = (v+n > after) ? (size_t)((v+n) - after) : 0;
  const char *sc = memchr(after, ';', rem);
  if (sc) {
    cpy_trim(h->sub_type, sizeof h->sub_type, after, sc - after);
    cpy_trim(h->params, sizeof h->params, sc, (v+n)-sc);
  } else {
    cpy_trim(h->sub_type, sizeof h->sub_type, after, rem);
    h->params[0] = '\0';
  }
}

static void parse_authorization_like(const char *name, const char *v, size_t n,
                                     char *name_buf, size_t name_sz, char *sep_buf, size_t sep_sz,
                                     char *scheme, size_t scheme_sz, char *sp, char *kv, size_t kv_sz,
                                     char *crlf_buf, size_t crlf_sz) {
  hdr_set_present(name_buf, name_sz, sep_buf, sep_sz, crlf_buf, crlf_sz, name);
  const char *spc = memchr(v, ' ', n);
  if (spc) {
    cpy_trim(scheme, scheme_sz, v, spc - v);
    *sp = ' ';
    cpy_trim(kv, kv_sz, spc + 1, (v+n) - (spc + 1));
  } else {
    cpy_trim(scheme, scheme_sz, v, n);
    *sp = '\0';
    kv[0] = '\0';
  }
}

static void parse_authorization(const char *v, size_t n, sip_authorization_hdr_t *h) {
  parse_authorization_like("Authorization", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    h->scheme, sizeof h->scheme, &h->sp, h->kvpairs, sizeof h->kvpairs, h->crlf, sizeof h->crlf);
}

static void parse_proxy_authorization(const char *v, size_t n, sip_proxy_authorization_hdr_t *h) {
  parse_authorization_like("Proxy-Authorization", v, n,
    h->name, sizeof h->name, h->colon_space, sizeof h->colon_space,
    h->scheme, sizeof h->scheme, &h->sp, h->kvpairs, sizeof h->kvpairs, h->crlf, sizeof h->crlf);
}

static void parse_encryption(const char *v, size_t n, sip_encryption_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Encryption");
  const char *sc = memchr(v, ';', n);
  if (sc) {
    cpy_trim(h->scheme, sizeof h->scheme, v, sc - v);
    cpy_trim(h->params, sizeof h->params, sc, (v+n)-sc);
  } else {
    cpy_trim(h->scheme, sizeof h->scheme, v, n);
    h->params[0] = '\0';
  }
}

static void parse_timestamp(const char *v, size_t n, sip_timestamp_hdr_t *h) {
  hdr_set_present(h->name, sizeof h->name, h->colon_space, sizeof h->colon_space, h->crlf, sizeof h->crlf, "Timestamp");
  const char *sp = memchr(v, ' ', n);
  if (sp) {
    cpy_trim(h->value, sizeof h->value, v, sp - v);
    h->sp_opt = ' ';
    cpy_trim(h->delay, sizeof h->delay, sp + 1, (v+n) - (sp + 1));
  } else {
    cpy_trim(h->value, sizeof h->value, v, n);
    h->sp_opt = '\0';
    h->delay[0] = '\0';
  }
}

/* ------------------------------ 解析单条报文 ------------------------------ */

static void init_all_headers_absent(sip_packet_t *pkt) {
  switch (pkt->cmd_type) {
    case SIP_PKT_INVITE: {
      sip_invite_packet_t *p = &pkt->pkt.invite;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->accept);
      HDR_MARK_ABSENT(p->accept_encoding);
      HDR_MARK_ABSENT(p->accept_language);
      HDR_MARK_ABSENT(p->authorization);
      HDR_MARK_ABSENT(p->contact);
      HDR_MARK_ABSENT(p->content_encoding);
      HDR_MARK_ABSENT(p->content_length);
      HDR_MARK_ABSENT(p->content_type);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->expires);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->organization);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      HDR_MARK_ABSENT(p->priority);
      p->record_route_count = 0;
      HDR_MARK_ABSENT(p->response_key);
      HDR_MARK_ABSENT(p->require);
      p->route_count = 0;
      HDR_MARK_ABSENT(p->subject);
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
      p->body[0] = '\0';              /* <== 新增 */
    } break;
    case SIP_PKT_ACK: {
      sip_ack_packet_t *p = &pkt->pkt.ack;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->authorization);
      HDR_MARK_ABSENT(p->contact);
      HDR_MARK_ABSENT(p->content_length);
      HDR_MARK_ABSENT(p->content_type);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->organization);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      HDR_MARK_ABSENT(p->require);
      p->record_route_count = 0;
      p->route_count = 0;
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
      p->body[0] = '\0';              /* <== 新增 */
    } break;
    case SIP_PKT_BYE: {
      sip_bye_packet_t *p = &pkt->pkt.bye;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->accept_language);
      HDR_MARK_ABSENT(p->authorization);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      p->record_route_count = 0;
      HDR_MARK_ABSENT(p->response_key);
      HDR_MARK_ABSENT(p->require);
      p->route_count = 0;
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
    } break;
    case SIP_PKT_CANCEL: {
      sip_cancel_packet_t *p = &pkt->pkt.cancel;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->accept_language);
      HDR_MARK_ABSENT(p->authorization);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      p->record_route_count = 0;
      HDR_MARK_ABSENT(p->response_key);
      HDR_MARK_ABSENT(p->require);
      p->route_count = 0;
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
    } break;
    case SIP_PKT_REGISTER: {
      sip_register_packet_t *p = &pkt->pkt.register_;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->accept);
      HDR_MARK_ABSENT(p->accept_encoding);
      HDR_MARK_ABSENT(p->accept_language);
      HDR_MARK_ABSENT(p->authorization);
      p->record_route_count = 0; p->route_count = 0;
      p->contact_count = 0;
      HDR_MARK_ABSENT(p->content_encoding);
      HDR_MARK_ABSENT(p->content_length);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->expires);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->organization);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      HDR_MARK_ABSENT(p->response_key);
      HDR_MARK_ABSENT(p->require);
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      // retry_after 是 optional，占位缺省即可（未显式 name 字段；忽略）
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
      p->body[0] = '\0';              /* <== 新增 */
    } break;
    case SIP_PKT_OPTIONS: {
      sip_options_packet_t *p = &pkt->pkt.options;
      HDR_MARK_ABSENT(p->call_id); HDR_MARK_ABSENT(p->cseq);
      HDR_MARK_ABSENT(p->from_);   HDR_MARK_ABSENT(p->to_);
      p->via_count = 0;
      HDR_MARK_ABSENT(p->accept);
      HDR_MARK_ABSENT(p->accept_encoding);
      HDR_MARK_ABSENT(p->accept_language);
      HDR_MARK_ABSENT(p->authorization);
      p->record_route_count = 0; p->route_count = 0; p->contact_count = 0;
      HDR_MARK_ABSENT(p->content_encoding);
      HDR_MARK_ABSENT(p->content_length);
      HDR_MARK_ABSENT(p->date);
      HDR_MARK_ABSENT(p->encryption);
      HDR_MARK_ABSENT(p->hide);
      HDR_MARK_ABSENT(p->max_forwards);
      HDR_MARK_ABSENT(p->organization);
      HDR_MARK_ABSENT(p->proxy_authorization);
      HDR_MARK_ABSENT(p->proxy_require);
      HDR_MARK_ABSENT(p->response_key);
      HDR_MARK_ABSENT(p->require);
      HDR_MARK_ABSENT(p->timestamp);
      HDR_MARK_ABSENT(p->user_agent);
      snprintf(p->end_crlf, sizeof p->end_crlf, "\r\n");
      p->body[0] = '\0';              /* <== 新增 */
    } break;
    default: break;
  }
}

static const char *skip_line_end(const char *p, const char *end) {
  // 跳过一行的结尾：\r\n, \n, 或 \r
  if (p < end && *p == '\r') p++;
  if (p < end && *p == '\n') p++;
  return p;
}

static const char *find_headers_end(const char *p, const char *end) {
  // 找到空行（\r\n\r\n 或 \n\n）
  const char *s = p;
  while (s < end) {
    const char *line_end = memchr(s, '\n', (size_t)(end - s));
    if (!line_end) break;
    size_t linelen = (size_t)(line_end - s + 1);
    // 只含 CRLF 或 LF？
    if (linelen == 2 && s[0] == '\r' && s[1] == '\n') {
      // 看下一行是否也是立刻开始 body
      return line_end + 1; // 指向空行后第一个字节（即 body 开始）
    }
    if (linelen == 1 && s[0] == '\n') {
      return line_end + 1;
    }
    s = line_end + 1;
  }
  return end;
}

static sip_cmd_type_t method_to_type(const char *m) {
  if (!m) return SIP_PKT_UNKNOWN;
  if (!strcasecmp(m, "INVITE"))   return SIP_PKT_INVITE;
  if (!strcasecmp(m, "ACK"))      return SIP_PKT_ACK;
  if (!strcasecmp(m, "BYE"))      return SIP_PKT_BYE;
  if (!strcasecmp(m, "CANCEL"))   return SIP_PKT_CANCEL;
  if (!strcasecmp(m, "REGISTER")) return SIP_PKT_REGISTER;
  if (!strcasecmp(m, "OPTIONS"))  return SIP_PKT_OPTIONS;
  return SIP_PKT_UNKNOWN;
}

static void parse_request_line(const char *line, size_t n,
                               char *method, size_t method_sz,
                               char *sp1, char *uri, size_t uri_sz,
                               char *sp2, char *ver, size_t ver_sz,
                               char *crlf, size_t crlf_sz) {
  // METHOD SP URI SP VERSION
  const char *p = line, *end = line + n;
  const char *sp = memchr(p, ' ', (size_t)(end - p));
  if (!sp) { cpy_trim(method, method_sz, p, n); sp1[0]=0; uri[0]=0; sp2[0]=0; ver[0]=0; snprintf(crlf, crlf_sz, "\r\n"); return; }
  cpy_trim(method, method_sz, p, sp - p);
  snprintf(sp1, 2, " ");

  p = sp + 1;
  sp = memchr(p, ' ', (size_t)(end - p));
  if (!sp) { cpy_trim(uri, uri_sz, p, (size_t)(end - p)); sp2[0]=0; ver[0]=0; snprintf(crlf, crlf_sz, "\r\n"); return; }
  cpy_trim(uri, uri_sz, p, sp - p);
  snprintf(sp2, 2, " ");

  p = sp + 1;
  cpy_trim(ver, ver_sz, p, (size_t)(end - p));
  snprintf(crlf, crlf_sz, "\r\n");
}

static void parse_one_header_line(const char *line, size_t n, sip_packet_t *pkt) {
  // 找冒号
  const char *colon = memchr(line, ':', n);
  if (!colon) return;
  // 头名
  char hname[64]; cpy_trim(hname, sizeof hname, line, colon - line);
  // 值（跳过 ":" 后的空格）
  const char *val = colon + 1;
  size_t vlen = (size_t)((line + n) - val);
  while (vlen && (*val == ' ' || *val == '\t')) { val++; vlen--; }

  // 按包类型填
  switch (pkt->cmd_type) {
    case SIP_PKT_INVITE: {
      sip_invite_packet_t *p = &pkt->pkt.invite;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Accept"))       parse_accept(val, vlen, &p->accept);
      else if (!strcasecmp(hname, "Accept-Encoding")) parse_accept_encoding(val, vlen, &p->accept_encoding);
      else if (!strcasecmp(hname, "Accept-Language")) parse_accept_language(val, vlen, &p->accept_language);
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Contact"))      parse_contact(val, vlen, &p->contact);
      else if (!strcasecmp(hname, "Content-Encoding")) parse_content_encoding(val, vlen, &p->content_encoding);
      else if (!strcasecmp(hname, "Content-Length"))   parse_content_length(val, vlen, &p->content_length);
      else if (!strcasecmp(hname, "Content-Type"))     parse_content_type(val, vlen, &p->content_type);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Expires"))      parse_simple_text_header("Expires", val, vlen, p->expires.name,sizeof p->expires.name, p->expires.colon_space,sizeof p->expires.colon_space, p->expires.value,sizeof p->expires.value, p->expires.crlf,sizeof p->expires.crlf);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Organization")) parse_simple_text_header("Organization", val, vlen, p->organization.name,sizeof p->organization.name, p->organization.colon_space,sizeof p->organization.colon_space, p->organization.text,sizeof p->organization.text, p->organization.crlf,sizeof p->organization.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Priority"))     parse_simple_text_header("Priority", val, vlen, p->priority.name,sizeof p->priority.name, p->priority.colon_space,sizeof p->priority.colon_space, p->priority.value,sizeof p->priority.value, p->priority.crlf,sizeof p->priority.crlf);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Response-Key")) parse_authorization_like("Response-Key", val, vlen, p->response_key.name,sizeof p->response_key.name, p->response_key.colon_space,sizeof p->response_key.colon_space, p->response_key.scheme,sizeof p->response_key.scheme, &p->response_key.sp, p->response_key.kvpairs,sizeof p->response_key.kvpairs, p->response_key.crlf,sizeof p->response_key.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Subject"))      parse_simple_text_header("Subject", val, vlen, p->subject.name,sizeof p->subject.name, p->subject.colon_space,sizeof p->subject.colon_space, p->subject.text,sizeof p->subject.text, p->subject.crlf,sizeof p->subject.crlf);
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    case SIP_PKT_ACK: {
      sip_ack_packet_t *p = &pkt->pkt.ack;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Contact"))      parse_contact(val, vlen, &p->contact);
      else if (!strcasecmp(hname, "Content-Length")) parse_content_length(val, vlen, &p->content_length);
      else if (!strcasecmp(hname, "Content-Type"))   parse_content_type(val, vlen, &p->content_type);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Organization")) parse_simple_text_header("Organization", val, vlen, p->organization.name,sizeof p->organization.name, p->organization.colon_space,sizeof p->organization.colon_space, p->organization.text,sizeof p->organization.text, p->organization.crlf,sizeof p->organization.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    case SIP_PKT_BYE: {
      sip_bye_packet_t *p = &pkt->pkt.bye;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Accept-Language")) parse_accept_language(val, vlen, &p->accept_language);
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Response-Key")) parse_authorization_like("Response-Key", val, vlen, p->response_key.name,sizeof p->response_key.name, p->response_key.colon_space,sizeof p->response_key.colon_space, p->response_key.scheme,sizeof p->response_key.scheme, &p->response_key.sp, p->response_key.kvpairs,sizeof p->response_key.kvpairs, p->response_key.crlf,sizeof p->response_key.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    case SIP_PKT_CANCEL: {
      sip_cancel_packet_t *p = &pkt->pkt.cancel;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Accept-Language")) parse_accept_language(val, vlen, &p->accept_language);
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Response-Key")) parse_authorization_like("Response-Key", val, vlen, p->response_key.name,sizeof p->response_key.name, p->response_key.colon_space,sizeof p->response_key.colon_space, p->response_key.scheme,sizeof p->response_key.scheme, &p->response_key.sp, p->response_key.kvpairs,sizeof p->response_key.kvpairs, p->response_key.crlf,sizeof p->response_key.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    case SIP_PKT_REGISTER: {
      sip_register_packet_t *p = &pkt->pkt.register_;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Accept"))       parse_accept(val, vlen, &p->accept);
      else if (!strcasecmp(hname, "Accept-Encoding")) parse_accept_encoding(val, vlen, &p->accept_encoding);
      else if (!strcasecmp(hname, "Accept-Language")) parse_accept_language(val, vlen, &p->accept_language);
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Contact"))      { if (p->contact_count < SIP_MAX_CONTACT) parse_contact(val, vlen, &p->contact[p->contact_count++]); }
      else if (!strcasecmp(hname, "Content-Encoding")) parse_content_encoding(val, vlen, &p->content_encoding);
      else if (!strcasecmp(hname, "Content-Length"))   parse_content_length(val, vlen, &p->content_length);
      else if (!strcasecmp(hname, "Content-Type"))     parse_content_type(val, vlen, &p->content_type);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Expires"))      parse_simple_text_header("Expires", val, vlen, p->expires.name,sizeof p->expires.name, p->expires.colon_space,sizeof p->expires.colon_space, p->expires.value,sizeof p->expires.value, p->expires.crlf,sizeof p->expires.crlf);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Organization")) parse_simple_text_header("Organization", val, vlen, p->organization.name,sizeof p->organization.name, p->organization.colon_space,sizeof p->organization.colon_space, p->organization.text,sizeof p->organization.text, p->organization.crlf,sizeof p->organization.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Response-Key")) parse_authorization_like("Response-Key", val, vlen, p->response_key.name,sizeof p->response_key.name, p->response_key.colon_space,sizeof p->response_key.colon_space, p->response_key.scheme,sizeof p->response_key.scheme, &p->response_key.sp, p->response_key.kvpairs,sizeof p->response_key.kvpairs, p->response_key.crlf,sizeof p->response_key.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    case SIP_PKT_OPTIONS: {
      sip_options_packet_t *p = &pkt->pkt.options;
      if (!strcasecmp(hname, "Call-ID"))           parse_call_id(val, vlen, &p->call_id);
      else if (!strcasecmp(hname, "CSeq"))         parse_cseq(val, vlen, &p->cseq);
      else if (!strcasecmp(hname, "From"))         parse_from(val, vlen, &p->from_);
      else if (!strcasecmp(hname, "To"))           parse_to(val, vlen, &p->to_);
      else if (!strcasecmp(hname, "Via"))          { if (p->via_count < SIP_MAX_VIA) parse_via(val, vlen, &p->via[p->via_count++]); }
      else if (!strcasecmp(hname, "Accept"))       parse_accept(val, vlen, &p->accept);
      else if (!strcasecmp(hname, "Accept-Encoding")) parse_accept_encoding(val, vlen, &p->accept_encoding);
      else if (!strcasecmp(hname, "Accept-Language")) parse_accept_language(val, vlen, &p->accept_language);
      else if (!strcasecmp(hname, "Authorization")) parse_authorization(val, vlen, &p->authorization);
      else if (!strcasecmp(hname, "Record-Route")) { if (p->record_route_count < SIP_MAX_RECORD_ROUTE) parse_record_route(val, vlen, &p->record_route[p->record_route_count++]); }
      else if (!strcasecmp(hname, "Route"))        { if (p->route_count < SIP_MAX_ROUTE) parse_route(val, vlen, &p->route[p->route_count++]); }
      else if (!strcasecmp(hname, "Contact"))      { if (p->contact_count < SIP_MAX_CONTACT) parse_contact(val, vlen, &p->contact[p->contact_count++]); }
      else if (!strcasecmp(hname, "Content-Encoding")) parse_content_encoding(val, vlen, &p->content_encoding);
      else if (!strcasecmp(hname, "Content-Length"))   parse_content_length(val, vlen, &p->content_length);
      else if (!strcasecmp(hname, "Content-Type"))     parse_content_type(val, vlen, &p->content_type);
      else if (!strcasecmp(hname, "Date"))         parse_simple_text_header("Date", val, vlen, p->date.name,sizeof p->date.name, p->date.colon_space,sizeof p->date.colon_space, p->date.rfc1123,sizeof p->date.rfc1123, p->date.crlf,sizeof p->date.crlf);
      else if (!strcasecmp(hname, "Encryption"))   parse_encryption(val, vlen, &p->encryption);
      else if (!strcasecmp(hname, "Hide"))         parse_simple_text_header("Hide", val, vlen, p->hide.name,sizeof p->hide.name, p->hide.colon_space,sizeof p->hide.colon_space, p->hide.value,sizeof p->hide.value, p->hide.crlf,sizeof p->hide.crlf);
      else if (!strcasecmp(hname, "Max-Forwards")) parse_simple_text_header("Max-Forwards", val, vlen, p->max_forwards.name,sizeof p->max_forwards.name, p->max_forwards.colon_space,sizeof p->max_forwards.colon_space, p->max_forwards.hops,sizeof p->max_forwards.hops, p->max_forwards.crlf,sizeof p->max_forwards.crlf);
      else if (!strcasecmp(hname, "Organization")) parse_simple_text_header("Organization", val, vlen, p->organization.name,sizeof p->organization.name, p->organization.colon_space,sizeof p->organization.colon_space, p->organization.text,sizeof p->organization.text, p->organization.crlf,sizeof p->organization.crlf);
      else if (!strcasecmp(hname, "Proxy-Authorization")) parse_proxy_authorization(val, vlen, &p->proxy_authorization);
      else if (!strcasecmp(hname, "Proxy-Require")) parse_simple_text_header("Proxy-Require", val, vlen, p->proxy_require.name,sizeof p->proxy_require.name, p->proxy_require.colon_space,sizeof p->proxy_require.colon_space, p->proxy_require.option_tags,sizeof p->proxy_require.option_tags, p->proxy_require.crlf,sizeof p->proxy_require.crlf);
      else if (!strcasecmp(hname, "Response-Key")) parse_authorization_like("Response-Key", val, vlen, p->response_key.name,sizeof p->response_key.name, p->response_key.colon_space,sizeof p->response_key.colon_space, p->response_key.scheme,sizeof p->response_key.scheme, &p->response_key.sp, p->response_key.kvpairs,sizeof p->response_key.kvpairs, p->response_key.crlf,sizeof p->response_key.crlf);
      else if (!strcasecmp(hname, "Require"))      parse_simple_text_header("Require", val, vlen, p->require.name,sizeof p->require.name, p->require.colon_space,sizeof p->require.colon_space, p->require.option_tags,sizeof p->require.option_tags, p->require.crlf,sizeof p->require.crlf);
      else if (!strcasecmp(hname, "Timestamp"))    parse_timestamp(val, vlen, &p->timestamp);
      else if (!strcasecmp(hname, "User-Agent"))   parse_simple_text_header("User-Agent", val, vlen, p->user_agent.name,sizeof p->user_agent.name, p->user_agent.colon_space,sizeof p->user_agent.colon_space, p->user_agent.product,sizeof p->user_agent.product, p->user_agent.crlf,sizeof p->user_agent.crlf);
    } break;
    default: break;
  }
}

static size_t parse_single_message(const u8 *msg, size_t msg_len, sip_packet_t *out_pkt) {
  const char *p = (const char*)msg, *end = (const char*)msg + msg_len;

  // 第一行：Request-Line
  const char *lf = memchr(p, '\n', (size_t)(end - p));
  if (!lf) return 0;
  size_t rl_len = (size_t)(lf - p);
  if (rl_len && p[rl_len-1] == '\r') rl_len--;

  // 取 METHOD
  char method[SIP_TOKEN_LEN]; memzero(method, sizeof method);
  char dummy_sp1[2], dummy_sp2[2];
  char uri[SIP_URI_LEN], ver[SIP_TOKEN_LEN], crlf[SIP_CRLF_LEN];
  memzero(uri, sizeof uri); memzero(ver, sizeof ver);
  parse_request_line(p, rl_len, method, sizeof method, dummy_sp1, uri, sizeof uri, dummy_sp2, ver, sizeof ver, crlf, sizeof crlf);

  sip_cmd_type_t t = method_to_type(method);
  out_pkt->cmd_type = t;

  // 填 request-line 字段
  switch (t) {
    case SIP_PKT_INVITE: {
      sip_invite_packet_t *q = &out_pkt->pkt.invite;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    case SIP_PKT_ACK: {
      sip_ack_packet_t *q = &out_pkt->pkt.ack;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    case SIP_PKT_BYE: {
      sip_bye_packet_t *q = &out_pkt->pkt.bye;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    case SIP_PKT_CANCEL: {
      sip_cancel_packet_t *q = &out_pkt->pkt.cancel;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    case SIP_PKT_REGISTER: {
      sip_register_packet_t *q = &out_pkt->pkt.register_;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    case SIP_PKT_OPTIONS: {
      sip_options_packet_t *q = &out_pkt->pkt.options;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
    default: {
      // Unknown：也按 INVITE 构造，至少不崩
      out_pkt->cmd_type = SIP_PKT_INVITE;
      sip_invite_packet_t *q = &out_pkt->pkt.invite;
      memzero(q, sizeof *q);
      snprintf(q->method, sizeof q->method, "%s", method);
      snprintf(q->space1, sizeof q->space1, " ");
      snprintf(q->request_uri, sizeof q->request_uri, "%s", uri);
      snprintf(q->space2, sizeof q->space2, " ");
      if (ver[0]) snprintf(q->sip_version, sizeof q->sip_version, "%s", ver);
      else snprintf(q->sip_version, sizeof q->sip_version, "SIP/2.0");
      snprintf(q->crlf1, sizeof q->crlf1, "\r\n");
      init_all_headers_absent(out_pkt);
    } break;
  }

  // 进入头部
  const char *s = lf + 1;
  const char *hdr_end = find_headers_end(s, end);
  const char *line = s;

  while (line < hdr_end) {
    const char *nl = memchr(line, '\n', (size_t)(hdr_end - line));
    if (!nl) nl = hdr_end;
    size_t linelen = (size_t)(nl - line);
    if (linelen && line[linelen-1] == '\r') linelen--;
    if (linelen == 0) break; // 空行
    parse_one_header_line(line, linelen, out_pkt);
    line = nl + 1;
  }

  size_t consumed_headers = (size_t)(hdr_end - (const char*)msg);

  long cl = get_pkt_content_length(out_pkt);
  if (cl <= 0) {
    return consumed_headers;
  }

  if (msg_len < consumed_headers + (size_t)cl) {
    return 0;
  }

  size_t cap = 0;
  char *body = get_pkt_body_buf_and_cap(out_pkt, &cap);
  if (body && cap > 0) {
    size_t to_copy = (size_t)cl;
    if (to_copy >= cap) to_copy = cap - 1;  
    memcpy(body, (const char*)msg + consumed_headers, to_copy);
    body[to_copy] = '\0';
  }

  return consumed_headers + (size_t)cl;
}

/* ------------------------------ 对外入口 ------------------------------ */

size_t parse_sip_msg(const uint8_t *buf, size_t buf_len, sip_packet_t *out_packets, size_t max_count) {
  if (!buf || !out_packets || !max_count) return 0;
  size_t count = 0;
  size_t off = 0;

  while (off < buf_len && count < max_count) {
    // 跳过前导空白/空行
    while (off < buf_len && (buf[off] == '\r' || buf[off] == '\n' || buf[off] == ' ' || buf[off] == '\t'))
      off++;
    if (off >= buf_len) break;

    size_t consumed = parse_single_message(buf + off, buf_len - off, &out_packets[count]);
    if (consumed == 0) break; // 非法或剩余不足
    count++;
    off += consumed;

  }

  return count;
}
