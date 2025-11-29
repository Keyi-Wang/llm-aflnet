/* sip reassembler source file */
#include "sip.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef APPEND_CHECK
#define APPEND_CHECK do { if (pos >= cap) return -1; } while(0)
#endif

/* --------- 小工具：统一的 append --------- */
static int out_append(char *dst, size_t cap, size_t *ppos, const char *s) {
  size_t pos = *ppos;
  size_t n = strlen(s);
  if (pos + n > cap) return -1;
  memcpy(dst + pos, s, n);
  *ppos = pos + n;
  return 0;
}

static int out_append_n(char *dst, size_t cap, size_t *ppos, const char *s, size_t n) {
  size_t pos = *ppos;
  if (pos + n > cap) return -1;
  memcpy(dst + pos, s, n);
  *ppos = pos + n;
  return 0;
}

static int out_append_hdr_text(const char *name, const char *val, char *dst, size_t cap, size_t *ppos) {
  if (!name || !name[0]) return 0;
  if (!val) val = "";
  if (out_append(dst, cap, ppos, name)) return -1;
  if (out_append(dst, cap, ppos, ": ")) return -1;
  if (out_append(dst, cap, ppos, val))  return -1;
  if (out_append(dst, cap, ppos, "\r\n")) return -1;
  return 0;
}

/* --------- 前置声明：有的 emit_* 相互调用顺序 ---------- */
static int emit_authorization(const sip_authorization_hdr_t *h, char *dst, size_t cap, size_t *pos);
static int emit_proxy_auth(const sip_proxy_authorization_hdr_t *h, char *dst, size_t cap, size_t *pos);
static int emit_content_encoding(const sip_content_encoding_hdr_t *h, char *dst, size_t cap, size_t *pos);
static int emit_content_length(const sip_content_length_hdr_t *h, char *dst, size_t cap, size_t *pos);
static int emit_encryption(const sip_encryption_hdr_t *h, char *dst, size_t cap, size_t *pos);
static int emit_resp_key(const sip_response_key_hdr_t *h, char *dst, size_t cap, size_t *pos);

/* --------- 头部输出（仅当 name[0] != '\0'） --------- */

static int emit_accept(const sip_accept_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->media_type)) return -1;
  if (h->slash) if (out_append_n(dst, cap, pos, &h->slash, 1)) return -1;
  if (h->sub_type[0]) if (out_append(dst, cap, pos, h->sub_type)) return -1;
  if (h->params[0])  if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_content_type(const sip_content_type_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->type_tok)) return -1;
  if (h->slash) if (out_append_n(dst, cap, pos, &h->slash, 1)) return -1;
  if (h->sub_type[0]) if (out_append(dst, cap, pos, h->sub_type)) return -1;
  if (h->params[0])  if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_accept_enc(const sip_accept_encoding_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->coding)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_accept_lang(const sip_accept_language_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->lang_tag)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_call_id(const sip_call_id_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  return out_append_hdr_text(h->name, h->value, dst, cap, pos);
}


static int emit_addr_like(const char *name, const char *sep,
                          const char *display, char sp_opt,
                          char lt, const char *uri, char gt,
                          const char *params,
                          char *dst, size_t cap, size_t *pos) {
  if (!name || !name[0]) return 0;
  if (out_append(dst, cap, pos, name)) return -1;
  if (sep && out_append(dst, cap, pos, sep)) return -1;
  if (display && display[0]) {
    if (out_append(dst, cap, pos, display)) return -1;
    if (sp_opt) if (out_append_n(dst, cap, pos, &sp_opt, 1)) return -1;
  }
  if (lt)  if (out_append_n(dst, cap, pos, &lt, 1)) return -1;
  if (uri && out_append(dst, cap, pos, uri)) return -1;
  if (gt)  if (out_append_n(dst, cap, pos, &gt, 1)) return -1;
  if (params && params[0]) if (out_append(dst, cap, pos, params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_from(const sip_from_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  return emit_addr_like(h->name, h->colon_space, h->display, h->sp_opt, h->lt, h->uri, h->gt, h->params, dst, cap, pos);
}

static int emit_to(const sip_to_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  return emit_addr_like(h->name, h->colon_space, h->display, h->sp_opt, h->lt, h->uri, h->gt, h->params, dst, cap, pos);
}

static int emit_contact(const sip_contact_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  return emit_addr_like(h->name, h->colon_space, h->display, h->sp_opt, h->lt, h->uri, h->gt, h->params, dst, cap, pos);
}

static int emit_cseq(const sip_cseq_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->number)) return -1;
  if (h->sp) if (out_append_n(dst, cap, pos, &h->sp, 1)) return -1;
  if (h->method[0]) if (out_append(dst, cap, pos, h->method)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_via(const sip_via_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->sent_protocol)) return -1;
  if (h->sp) if (out_append_n(dst, cap, pos, &h->sp, 1)) return -1;
  if (out_append(dst, cap, pos, h->sent_by)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_record_route(const sip_record_route_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (h->lt) if (out_append_n(dst, cap, pos, &h->lt, 1)) return -1;
  if (out_append(dst, cap, pos, h->uri)) return -1;
  if (h->gt) if (out_append_n(dst, cap, pos, &h->gt, 1)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_route(const sip_route_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (h->lt) if (out_append_n(dst, cap, pos, &h->lt, 1)) return -1;
  if (out_append(dst, cap, pos, h->uri)) return -1;
  if (h->gt) if (out_append_n(dst, cap, pos, &h->gt, 1)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_timestamp(const sip_timestamp_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->value)) return -1;
  if (h->sp_opt) if (out_append_n(dst, cap, pos, &h->sp_opt, 1)) return -1;
  if (h->delay[0]) if (out_append(dst, cap, pos, h->delay)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

/* 为避免重复，给 Authorization / Proxy-Authorization / Content-* / Encryption 也写薄封装 */
static int emit_authorization(const sip_authorization_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h || !h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->scheme)) return -1;
  if (h->sp) if (out_append_n(dst, cap, pos, &h->sp, 1)) return -1;
  if (h->kvpairs[0]) if (out_append(dst, cap, pos, h->kvpairs)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_proxy_auth(const sip_proxy_authorization_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h || !h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->scheme)) return -1;
  if (h->sp) if (out_append_n(dst, cap, pos, &h->sp, 1)) return -1;
  if (h->kvpairs[0]) if (out_append(dst, cap, pos, h->kvpairs)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_content_encoding(const sip_content_encoding_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  return out_append_hdr_text(h->name, h->coding, dst, cap, pos);
}

static int emit_content_length(const sip_content_length_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  return out_append_hdr_text(h->name, h->length, dst, cap, pos);
}

static int emit_encryption(const sip_encryption_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->scheme)) return -1;
  if (h->params[0]) if (out_append(dst, cap, pos, h->params)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

static int emit_resp_key(const sip_response_key_hdr_t *h, char *dst, size_t cap, size_t *pos) {
  if (!h->name[0]) return 0;
  if (out_append(dst, cap, pos, h->name)) return -1;
  if (out_append(dst, cap, pos, h->colon_space)) return -1;
  if (out_append(dst, cap, pos, h->scheme)) return -1;
  if (h->sp) if (out_append_n(dst, cap, pos, &h->sp, 1)) return -1;
  if (h->kvpairs[0]) if (out_append(dst, cap, pos, h->kvpairs)) return -1;
  if (out_append(dst, cap, pos, "\r\n")) return -1;
  return 0;
}

/* --------- Content-Length 同步辅助 --------- */
static void ensure_cl_synced(sip_content_length_hdr_t *cl, size_t body_len) {

  /* 长度统一与 body 一致（即便 body 为 0 也同步） */
  snprintf(cl->length, sizeof cl->length, "%zu", body_len);
}

/* ------------------- 各消息发射（含 body 处理） ------------------- */

static int emit_invite(const sip_invite_packet_t *p, char *out, size_t cap, size_t *pos) {
  /* 先同步 CL（若 body 存在或 header 本身存在） */
  size_t body_len = p->body[0] ? strlen(p->body) : 0;
  if (p->content_length.name[0] != '\0' || body_len > 0) {
    /* cast 掉 const 仅用于输出期间修正缓存值；若不希望改原对象，可在栈上拷贝一份 header。 */
    sip_content_length_hdr_t cl = p->content_length;
    ensure_cl_synced(&cl, body_len);

    /* Request-Line */
    if (out_append(out, cap, pos, p->method)) return -1;
    if (out_append(out, cap, pos, p->space1)) return -1;
    if (out_append(out, cap, pos, p->request_uri)) return -1;
    if (out_append(out, cap, pos, p->space2)) return -1;
    if (out_append(out, cap, pos, p->sip_version)) return -1;
    if (out_append(out, cap, pos, p->crlf1)) return -1;

    if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
    if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
    if (emit_from(&p->from_, out, cap, pos)) return -1;
    if (emit_to(&p->to_, out, cap, pos)) return -1;
    for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

    if (emit_accept(&p->accept, out, cap, pos)) return -1;
    if (emit_accept_enc(&p->accept_encoding, out, cap, pos)) return -1;
    if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
    if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
    if (emit_contact(&p->contact, out, cap, pos)) return -1;

    if (emit_content_encoding(&p->content_encoding, out, cap, pos)) return -1;
    if (emit_content_length(&cl, out, cap, pos)) return -1; /* 用同步后的 CL */
    if (emit_content_type(&p->content_type, out, cap, pos)) return -1;

    if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
    if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->expires.name, p->expires.value, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->organization.name, p->organization.text, out, cap, pos)) return -1;
    if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->priority.name, p->priority.value, out, cap, pos)) return -1;
    for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
    if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
    for (size_t i=0;i<p->route_count;i++) if (emit_route(&p->route[i], out, cap, pos)) return -1;
    if (out_append_hdr_text(p->subject.name, p->subject.text, out, cap, pos)) return -1;
    if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
    if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

    if (out_append(out, cap, pos, p->end_crlf)) return -1;
    if (body_len > 0) {
      if (out_append_n(out, cap, pos, p->body, body_len)) return -1;
    }
    return 0;
  }

  /* 无需同步的常规路径（无 CL 且无 body） */
  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_accept(&p->accept, out, cap, pos)) return -1;
  if (emit_accept_enc(&p->accept_encoding, out, cap, pos)) return -1;
  if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
  if (emit_contact(&p->contact, out, cap, pos)) return -1;

  if (emit_content_encoding(&p->content_encoding, out, cap, pos)) return -1;
  if (emit_content_length(&p->content_length, out, cap, pos)) return -1;
  if (emit_content_type(&p->content_type, out, cap, pos)) return -1;

  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->expires.name, p->expires.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->organization.name, p->organization.text, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->priority.name, p->priority.value, out, cap, pos)) return -1;
  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++) if (emit_route(&p->route[i], out, cap, pos)) return -1;
  if (out_append_hdr_text(p->subject.name, p->subject.text, out, cap, pos)) return -1;
  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  return 0;
}

static int emit_ack(const sip_ack_packet_t *p, char *out, size_t cap, size_t *pos) {
  size_t body_len = p->body[0] ? strlen(p->body) : 0;
  sip_content_length_hdr_t cl = p->content_length;
  if (cl.name[0] != '\0' || body_len > 0) {
    ensure_cl_synced(&cl, body_len);
  }

  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
  if (emit_contact(&p->contact, out, cap, pos)) return -1;
  /* 用同步后的 CL（如需） */
  if (cl.name[0]) { if (emit_content_length(&cl, out, cap, pos)) return -1; }
  else            { if (emit_content_length(&p->content_length, out, cap, pos)) return -1; }
  if (emit_content_type(&p->content_type, out, cap, pos)) return -1;

  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->organization.name, p->organization.text, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;

  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++)        if (emit_route(&p->route[i], out, cap, pos)) return -1;

  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  if (body_len > 0) {
    if (out_append_n(out, cap, pos, p->body, body_len)) return -1;
  }
  return 0;
}

static int emit_bye(const sip_bye_packet_t *p, char *out, size_t cap, size_t *pos) {
  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_content_length(&p->content_length, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++) if (emit_route(&p->route[i], out, cap, pos)) return -1;
  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  return 0;
}

static int emit_cancel(const sip_cancel_packet_t *p, char *out, size_t cap, size_t *pos) {
  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
  if (emit_content_length(&p->content_length, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++) if (emit_route(&p->route[i], out, cap, pos)) return -1;
  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  return 0;
}

static int emit_register(const sip_register_packet_t *p, char *out, size_t cap, size_t *pos) {
  size_t body_len = p->body[0] ? strlen(p->body) : 0;
  sip_content_length_hdr_t cl = p->content_length;
  if (cl.name[0] != '\0' || body_len > 0) {
    ensure_cl_synced(&cl, body_len);
  }

  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_accept(&p->accept, out, cap, pos)) return -1;
  if (emit_accept_enc(&p->accept_encoding, out, cap, pos)) return -1;
  if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;

  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++)        if (emit_route(&p->route[i], out, cap, pos)) return -1;

  for (size_t i=0;i<p->contact_count;i++) if (emit_contact(&p->contact[i], out, cap, pos)) return -1;

  if (emit_content_encoding(&p->content_encoding, out, cap, pos)) return -1;
  if (emit_content_type(&p->content_type, out, cap, pos)) return -1;
  if (cl.name[0]) { if (emit_content_length(&cl, out, cap, pos)) return -1; }
  else            { if (emit_content_length(&p->content_length, out, cap, pos)) return -1; }
  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->expires.name, p->expires.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->organization.name, p->organization.text, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->retry_after.name, p->retry_after.value, out, cap, pos)) return -1;
  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  if (body_len > 0) {
    if (out_append_n(out, cap, pos, p->body, body_len)) return -1;
  }
  return 0;
}

static int emit_options(const sip_options_packet_t *p, char *out, size_t cap, size_t *pos) {
  size_t body_len = p->body[0] ? strlen(p->body) : 0;
  sip_content_length_hdr_t cl = p->content_length;
  if (cl.name[0] != '\0' || body_len > 0) {
    ensure_cl_synced(&cl, body_len);
  }

  if (out_append(out, cap, pos, p->method)) return -1;
  if (out_append(out, cap, pos, p->space1)) return -1;
  if (out_append(out, cap, pos, p->request_uri)) return -1;
  if (out_append(out, cap, pos, p->space2)) return -1;
  if (out_append(out, cap, pos, p->sip_version)) return -1;
  if (out_append(out, cap, pos, p->crlf1)) return -1;

  if (emit_call_id(&p->call_id, out, cap, pos)) return -1;
  if (emit_cseq(&p->cseq, out, cap, pos)) return -1;
  if (emit_from(&p->from_, out, cap, pos)) return -1;
  if (emit_to(&p->to_, out, cap, pos)) return -1;
  for (size_t i=0;i<p->via_count;i++) if (emit_via(&p->via[i], out, cap, pos)) return -1;

  if (emit_accept(&p->accept, out, cap, pos)) return -1;
  if (emit_accept_enc(&p->accept_encoding, out, cap, pos)) return -1;
  if (emit_accept_lang(&p->accept_language, out, cap, pos)) return -1;
  if (emit_authorization(&p->authorization, out, cap, pos)) return -1;
  if (emit_proxy_auth(&p->proxy_authorization, out, cap, pos)) return -1;
  for (size_t i=0;i<p->record_route_count;i++) if (emit_record_route(&p->record_route[i], out, cap, pos)) return -1;
  for (size_t i=0;i<p->route_count;i++)        if (emit_route(&p->route[i], out, cap, pos)) return -1;

  for (size_t i=0;i<p->contact_count;i++) if (emit_contact(&p->contact[i], out, cap, pos)) return -1;

  if (emit_content_encoding(&p->content_encoding, out, cap, pos)) return -1;
  if (emit_content_type(&p->content_type, out, cap, pos)) return -1;
  if (cl.name[0]) { if (emit_content_length(&cl, out, cap, pos)) return -1; }
  else            { if (emit_content_length(&p->content_length, out, cap, pos)) return -1; }
  if (out_append_hdr_text(p->date.name, p->date.rfc1123, out, cap, pos)) return -1;
  if (emit_encryption(&p->encryption, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->hide.name, p->hide.value, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->max_forwards.name, p->max_forwards.hops, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->organization.name, p->organization.text, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->proxy_require.name, p->proxy_require.option_tags, out, cap, pos)) return -1;
  if (emit_resp_key(&p->response_key, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->require.name, p->require.option_tags, out, cap, pos)) return -1;
  if (emit_timestamp(&p->timestamp, out, cap, pos)) return -1;
  if (out_append_hdr_text(p->user_agent.name, p->user_agent.product, out, cap, pos)) return -1;

  if (out_append(out, cap, pos, p->end_crlf)) return -1;
  if (body_len > 0) {
    if (out_append_n(out, cap, pos, p->body, body_len)) return -1;
  }
  return 0;
}

/* ------------------------------ 对外入口 ------------------------------ */

int reassemble_sip_msgs(const sip_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
  if (!packets || !output_buf || !out_len) return -1;
  size_t cap = 1024*1024;
  char *out = (char*)output_buf;
  size_t pos = 0;

  for (u32 i = 0; i < num_packets; ++i) {
    int rc = 0;
    switch (packets[i].cmd_type) {
      case SIP_PKT_INVITE:   rc = emit_invite(&packets[i].pkt.invite, out, cap, &pos); break;
      case SIP_PKT_ACK:      rc = emit_ack(&packets[i].pkt.ack, out, cap, &pos); break;
      case SIP_PKT_BYE:      rc = emit_bye(&packets[i].pkt.bye, out, cap, &pos); break;
      case SIP_PKT_CANCEL:   rc = emit_cancel(&packets[i].pkt.cancel, out, cap, &pos); break;
      case SIP_PKT_REGISTER: rc = emit_register(&packets[i].pkt.register_, out, cap, &pos); break;
      case SIP_PKT_OPTIONS:  rc = emit_options(&packets[i].pkt.options, out, cap, &pos); break;
      default:               rc = emit_invite(&packets[i].pkt.invite, out, cap, &pos); break;
    }
    if (rc) return -1;
  }

  *out_len = (u32)pos;
  return 0;
}
