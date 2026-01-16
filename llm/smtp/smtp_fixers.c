/* smtp fixers source file */
#include "smtp.h"

/* smtp_crlf_fixer.c */
#include <stddef.h>
#include <string.h>

static inline void set_crlf(char crlf[SMTP_SZ_CRLF]) {
  crlf[0] = '\r';
  crlf[1] = '\n';
  crlf[2] = '\0';
}

static size_t strip_cr_lf_inplace(char *s) {
  if (!s) return 0;
  char *w = s, *r = s;
  size_t removed = 0;
  while (*r) {
    if (*r == '\r' || *r == '\n') { removed++; r++; continue; }
    *w++ = *r++;
  }
  *w = '\0';
  return removed;
}

#define SCRUB(field) do { fixes += strip_cr_lf_inplace((field)); } while (0)

#define FIX_CRLF(field) do { set_crlf((field)); fixes++; } while (0)


size_t fix_smtp_crlf_rule(smtp_packet_t *pkts, size_t count) {
  if (!pkts) return 0;
  size_t fixes = 0;

  for (size_t i = 0; i < count; ++i) {
    switch (pkts[i].cmd_type) {

      case SMTP_PKT_HELO: {
        smtp_helo_packet_t *p = &pkts[i].pkt.helo;
        SCRUB(p->command);
        SCRUB(p->space);
        SCRUB(p->domain);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_EHLO: {
        smtp_ehlo_packet_t *p = &pkts[i].pkt.ehlo;
        SCRUB(p->command);
        SCRUB(p->space);
        SCRUB(p->domain);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_MAIL: {
        smtp_mail_packet_t *p = &pkts[i].pkt.mail;
        SCRUB(p->command);
        SCRUB(p->space1);
        SCRUB(p->from_keyword);
        SCRUB(p->reverse_path);
        SCRUB(p->optional_args);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_RCPT: {
        smtp_rcpt_packet_t *p = &pkts[i].pkt.rcpt;
        SCRUB(p->command);
        SCRUB(p->space1);
        SCRUB(p->to_keyword);
        SCRUB(p->forward_path);
        SCRUB(p->optional_args);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_DATA: {
        smtp_data_packet_t *p = &pkts[i].pkt.data;
        SCRUB(p->command);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_RSET: {
        smtp_rset_packet_t *p = &pkts[i].pkt.rset;
        SCRUB(p->command);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_VRFY: {
        smtp_vrfy_packet_t *p = &pkts[i].pkt.vrfy;
        SCRUB(p->command);
        SCRUB(p->space);
        SCRUB(p->string);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_EXPN: {
        smtp_expn_packet_t *p = &pkts[i].pkt.expn;
        SCRUB(p->command);
        SCRUB(p->space);
        SCRUB(p->mailing_list);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_HELP: {
        smtp_help_packet_t *p = &pkts[i].pkt.help;
        SCRUB(p->command);
        SCRUB(p->space);
        SCRUB(p->argument);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_NOOP: {
        smtp_noop_packet_t *p = &pkts[i].pkt.noop;
        SCRUB(p->command);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_QUIT: {
        smtp_quit_packet_t *p = &pkts[i].pkt.quit;
        SCRUB(p->command);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_STARTTLS: {
        smtp_starttls_packet_t *p = &pkts[i].pkt.starttls;
        SCRUB(p->command);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_AUTH: {
        smtp_auth_packet_t *p = &pkts[i].pkt.auth;
        SCRUB(p->command);
        SCRUB(p->space1);
        SCRUB(p->mechanism);
        SCRUB(p->space2);
        SCRUB(p->initial_response);
        FIX_CRLF(p->crlf);
      } break;

      case SMTP_PKT_UNRECOGNIZED:
      default:

        break;
    }
  }

  return fixes;
}

#undef SCRUB
#undef FIX_CRLF




#define SMTP_LINE_LIMIT 512

static inline size_t L(const char *s) { return s ? strlen(s) : 0; }
static inline void trunc_len(char *s, size_t keep_len) {
  if (!s) return;
  size_t n = strlen(s);
  if (n > keep_len) s[keep_len] = '\0';
}

static inline void maybe_clear_space(char *space_field, const char *payload_after_space) {
  if (payload_after_space && payload_after_space[0] == '\0') {
    if (space_field) space_field[0] = '\0';
  }
}

static size_t calc_len_helo(const smtp_helo_packet_t *p) {
  return L(p->command) + L(p->space) + L(p->domain) + L(p->crlf);
}
static size_t calc_len_ehlo(const smtp_ehlo_packet_t *p) {
  return L(p->command) + L(p->space) + L(p->domain) + L(p->crlf);
}

static size_t calc_len_mail(const smtp_mail_packet_t *p) {
  size_t oa = L(p->optional_args);
  return L(p->command) + L(p->space1) + L(p->from_keyword) + L(p->reverse_path)
       + (oa ? 1 + oa : 0) + L(p->crlf);
}
/* RCPT: "RCPT SP TO:" <forward-path> [ SP optional_args ] CRLF */
static size_t calc_len_rcpt(const smtp_rcpt_packet_t *p) {
  size_t oa = L(p->optional_args);
  return L(p->command) + L(p->space1) + L(p->to_keyword) + L(p->forward_path)
       + (oa ? 1 + oa : 0) + L(p->crlf);
}
static size_t calc_len_vrfy(const smtp_vrfy_packet_t *p) {
  return L(p->command) + L(p->space) + L(p->string) + L(p->crlf);
}
static size_t calc_len_expn(const smtp_expn_packet_t *p) {
  return L(p->command) + L(p->space) + L(p->mailing_list) + L(p->crlf);
}
static size_t calc_len_help(const smtp_help_packet_t *p) {
  return L(p->command) + L(p->space) + L(p->argument) + L(p->crlf);
}
static size_t calc_len_auth(const smtp_auth_packet_t *p) {
  return L(p->command) + L(p->space1) + L(p->mechanism)
       + L(p->space2) + L(p->initial_response) + L(p->crlf);
}
static size_t calc_len_simple_cmd2(const char *cmd, const char *crlf) {
  return L(cmd) + L(crlf);
}

void fix_smtp_cmd_len(smtp_packet_t *pkts, size_t num_packets) {
  if (!pkts) return;

  for (size_t i = 0; i < num_packets; ++i) {
    smtp_packet_t *p = &pkts[i];

    switch (p->cmd_type) {
      case SMTP_PKT_HELO: {
        size_t total = calc_len_helo(&p->pkt.helo);
        if (total > SMTP_LINE_LIMIT) {
          size_t dom_len = L(p->pkt.helo.domain);
          size_t need_cut = total - SMTP_LINE_LIMIT;
          if (dom_len > need_cut) trunc_len(p->pkt.helo.domain, dom_len - need_cut);
          else {
            p->pkt.helo.domain[0] = 'x';
            p->pkt.helo.domain[1] = '\0';
          }
        }
      } break;

      case SMTP_PKT_EHLO: {
        size_t total = calc_len_ehlo(&p->pkt.ehlo);
        if (total > SMTP_LINE_LIMIT) {
          size_t dom_len = L(p->pkt.ehlo.domain);
          size_t need_cut = total - SMTP_LINE_LIMIT;
          if (dom_len > need_cut) trunc_len(p->pkt.ehlo.domain, dom_len - need_cut);
          else {
            p->pkt.ehlo.domain[0] = 'x';
            p->pkt.ehlo.domain[1] = '\0';
          }
        }
      } break;

      case SMTP_PKT_MAIL: {
        size_t total = calc_len_mail(&p->pkt.mail);
        if (total > SMTP_LINE_LIMIT) {
          if (p->pkt.mail.optional_args[0]) {
            size_t oa = L(p->pkt.mail.optional_args);
            p->pkt.mail.optional_args[0] = '\0';
            total -= (1 + oa);
          }
          if (total > SMTP_LINE_LIMIT) {
            size_t rp_len = L(p->pkt.mail.reverse_path);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (rp_len > need_cut) trunc_len(p->pkt.mail.reverse_path, rp_len - need_cut);
            else p->pkt.mail.reverse_path[0] = '\0';
          }
        }
      } break;

      case SMTP_PKT_RCPT: {
        size_t total = calc_len_rcpt(&p->pkt.rcpt);
        if (total > SMTP_LINE_LIMIT) {
          if (p->pkt.rcpt.optional_args[0]) {
            size_t oa = L(p->pkt.rcpt.optional_args);
            p->pkt.rcpt.optional_args[0] = '\0';
            total -= (1 + oa);
          }
          if (total > SMTP_LINE_LIMIT) {
            size_t fp_len = L(p->pkt.rcpt.forward_path);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (fp_len > need_cut) trunc_len(p->pkt.rcpt.forward_path, fp_len - need_cut);
            else p->pkt.rcpt.forward_path[0] = '\0';
          }
        }
      } break;

      case SMTP_PKT_VRFY: {
        size_t total = calc_len_vrfy(&p->pkt.vrfy);
        if (total > SMTP_LINE_LIMIT) {
          size_t s_len = L(p->pkt.vrfy.string);
          size_t need_cut = total - SMTP_LINE_LIMIT;
          if (s_len > need_cut) trunc_len(p->pkt.vrfy.string, s_len - need_cut);
          else p->pkt.vrfy.string[0] = '\0';
          maybe_clear_space(p->pkt.vrfy.space, p->pkt.vrfy.string);
        }
      } break;

      case SMTP_PKT_EXPN: {
        size_t total = calc_len_expn(&p->pkt.expn);
        if (total > SMTP_LINE_LIMIT) {
          size_t ml_len = L(p->pkt.expn.mailing_list);
          size_t need_cut = total - SMTP_LINE_LIMIT;
          if (ml_len > need_cut) trunc_len(p->pkt.expn.mailing_list, ml_len - need_cut);
          else p->pkt.expn.mailing_list[0] = '\0';
          maybe_clear_space(p->pkt.expn.space, p->pkt.expn.mailing_list);
        }
      } break;

      case SMTP_PKT_HELP: {
        size_t total = calc_len_help(&p->pkt.help);
        if (total > SMTP_LINE_LIMIT) {
          p->pkt.help.argument[0] = '\0';
          p->pkt.help.space[0]    = '\0';
          total = calc_len_help(&p->pkt.help);
          if (total > SMTP_LINE_LIMIT) {
            size_t cmd_len = L(p->pkt.help.command);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (cmd_len > need_cut) trunc_len(p->pkt.help.command, cmd_len - need_cut);
            else trunc_len(p->pkt.help.command, 4); 
          }
        }
      } break;

      case SMTP_PKT_AUTH: {
        size_t total = calc_len_auth(&p->pkt.auth);
        if (total > SMTP_LINE_LIMIT) {
          size_t ir_len = L(p->pkt.auth.initial_response);
          if (ir_len) {
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (ir_len > need_cut) {
              trunc_len(p->pkt.auth.initial_response, ir_len - need_cut);
            } else {
              p->pkt.auth.initial_response[0] = '\0';
              p->pkt.auth.space2[0] = '\0';
            }
            total = calc_len_auth(&p->pkt.auth);
          }
          if (total > SMTP_LINE_LIMIT) {
            size_t mlen = L(p->pkt.auth.mechanism);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (mlen > need_cut) trunc_len(p->pkt.auth.mechanism, (mlen - need_cut > 0) ? (mlen - need_cut) : 1);
            else trunc_len(p->pkt.auth.mechanism, 1);
          }
        }
      } break;

      case SMTP_PKT_DATA: {
        (void)calc_len_simple_cmd2(p->pkt.data.command, p->pkt.data.crlf);
      } break;

      case SMTP_PKT_RSET: {
        (void)calc_len_simple_cmd2(p->pkt.rset.command, p->pkt.rset.crlf);
      } break;

      case SMTP_PKT_NOOP: {
        (void)calc_len_simple_cmd2(p->pkt.noop.command, p->pkt.noop.crlf);
      } break;

      case SMTP_PKT_QUIT: {
        (void)calc_len_simple_cmd2(p->pkt.quit.command, p->pkt.quit.crlf);
      } break;

      case SMTP_PKT_STARTTLS: {
        (void)calc_len_simple_cmd2(p->pkt.starttls.command, p->pkt.starttls.crlf);
      } break;

      case SMTP_PKT_UNRECOGNIZED:
      default:
        break;
    }
  }
}


#ifndef SMTP_FIX_FALLBACK_ADDR_LIT
#define SMTP_FIX_FALLBACK_ADDR_LIT "[127.0.0.1]"
#endif

/* ---------- small safe helpers ---------- */

static void set_cstr(char dst[], size_t cap, const char *s) {
  if (!dst || cap == 0) return;
  if (!s) s = "";
  (void)snprintf(dst, cap, "%s", s);
}

static int is_label_valid(const char *b, const char *e) {
  /* RFC-ish label: [A-Za-z0-9-], len 1..63, not start/end with '-' */
  size_t n = (size_t)(e - b);
  if (n == 0 || n > 63) return 0;
  if (b[0] == '-' || b[n-1] == '-') return 0;
  for (const char *p = b; p < e; ++p) {
    unsigned char c = (unsigned char)*p;
    if (!(isalnum(c) || c == '-')) return 0;
  }
  return 1;
}

static int is_fqdn(const char *s) {
  /* Very loose FQDN check: total <= 253, at least one dot, labels valid */
  if (!s || !*s) return 0;
  size_t L = strlen(s);
  if (L > 253) return 0;

  const char *p = s;
  const char *dot = strchr(s, '.');
  if (!dot) return 0; /* must have at least one dot */

  while (*p) {
    const char *lab_start = p;
    const char *lab_end = strchr(p, '.');
    if (!lab_end) lab_end = s + L;
    if (!is_label_valid(lab_start, lab_end)) return 0;
    if (*lab_end == '\0') break;
    p = lab_end + 1; /* skip dot */
  }
  return 1;
}

static int is_address_literal(const char *s) {
  /* Accept bracketed literals: [ ... ] with simple char whitelist */
  if (!s) return 0;
  size_t L = strlen(s);
  if (L < 2) return 0;
  if (s[0] != '[' || s[L-1] != ']') return 0;
  if (L == 2) return 0; /* empty inside */
  for (size_t i = 1; i < L-1; ++i) {
    unsigned char c = (unsigned char)s[i];
    if (!(isxdigit(c) || c == '.' || c == ':' || c == '%'
          || c == 'v' || c == 'V' || c == '-')) {
      return 0;
    }
  }
  return 1;
}

static int is_valid_domain_arg(const char *s) {
  return is_fqdn(s) || is_address_literal(s);
}

static void make_ehlo(smtp_packet_t *p, const char *domain) {
  p->cmd_type = SMTP_PKT_EHLO;
  set_cstr(p->pkt.ehlo.command, sizeof p->pkt.ehlo.command, "EHLO");
  set_cstr(p->pkt.ehlo.space,   sizeof p->pkt.ehlo.space,   " ");
  set_cstr(p->pkt.ehlo.domain,  sizeof p->pkt.ehlo.domain,
           (domain && *domain) ? domain : SMTP_FIX_FALLBACK_ADDR_LIT);
  if (!is_valid_domain_arg(p->pkt.ehlo.domain)) {
    set_cstr(p->pkt.ehlo.domain, sizeof p->pkt.ehlo.domain,
             SMTP_FIX_FALLBACK_ADDR_LIT);
  }
  set_cstr(p->pkt.ehlo.crlf,    sizeof p->pkt.ehlo.crlf,    "\r\n");
}

static void normalize_greeting_packet(smtp_packet_t *p) {
  if (p->cmd_type == SMTP_PKT_EHLO) {
    set_cstr(p->pkt.ehlo.command, sizeof p->pkt.ehlo.command, "EHLO");
    set_cstr(p->pkt.ehlo.space,   sizeof p->pkt.ehlo.space,   " ");
    if (!is_valid_domain_arg(p->pkt.ehlo.domain) || p->pkt.ehlo.domain[0] == '\0') {
      set_cstr(p->pkt.ehlo.domain, sizeof p->pkt.ehlo.domain,
               SMTP_FIX_FALLBACK_ADDR_LIT);
    }
    set_cstr(p->pkt.ehlo.crlf,    sizeof p->pkt.ehlo.crlf,    "\r\n");
  } else if (p->cmd_type == SMTP_PKT_HELO) {
    set_cstr(p->pkt.helo.command, sizeof p->pkt.helo.command, "HELO");
    set_cstr(p->pkt.helo.space,   sizeof p->pkt.helo.space,   " ");
    if (!is_valid_domain_arg(p->pkt.helo.domain) || p->pkt.helo.domain[0] == '\0') {
      set_cstr(p->pkt.helo.domain, sizeof p->pkt.helo.domain,
               SMTP_FIX_FALLBACK_ADDR_LIT);
    }
    set_cstr(p->pkt.helo.crlf,    sizeof p->pkt.helo.crlf,    "\r\n");
  }
}


int fix_SMTP_4_1_1_1_EHLO(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  ssize_t first_mail = -1;
  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type == SMTP_PKT_MAIL) { first_mail = (ssize_t)i; break; }
  }
  if (first_mail < 0) {
    for (size_t i = 0; i < pkt_cnt; ++i) {
      if (pkts[i].cmd_type == SMTP_PKT_EHLO || pkts[i].cmd_type == SMTP_PKT_HELO) {
        normalize_greeting_packet(&pkts[i]);
      }
    }
    return 0;
  }

  for (ssize_t i = 0; i < first_mail; ++i) {
    if (pkts[i].cmd_type == SMTP_PKT_EHLO || pkts[i].cmd_type == SMTP_PKT_HELO) {
      normalize_greeting_packet(&pkts[i]);
      return 0; 
    }
  }

  if (pkt_cnt == 0) return 0; 
  make_ehlo(&pkts[0], SMTP_FIX_FALLBACK_ADDR_LIT);

  return 0;
}



#ifndef SMTP_FIX_RCPT_FALLBACK_MAILBOX
#define SMTP_FIX_RCPT_FALLBACK_MAILBOX "user@example.com"
#endif


static void trim_bounds(const char *s, const char **pb, const char **pe) {
  const char *b = s, *e = s ? s + strlen(s) : s;
  if (!s) { *pb = *pe = NULL; return; }
  while (b < e && (unsigned char)*b <= ' ') ++b;          /* trim left: space/HT/CR/LF */
  while (e > b && (unsigned char)e[-1] <= ' ') --e;       /* trim right */
  *pb = b; *pe = e;
}

static int is_enclosed_angle(const char *s) {
  if (!s) return 0;
  size_t n = strlen(s);
  return (n >= 2 && s[0] == '<' && s[n-1] == '>');
}

static void fix_one_path(char dst[], size_t cap, int allow_null) {
  if (!dst || cap == 0) return;

  const char *b, *e;
  trim_bounds(dst, &b, &e);
  if (!b || b >= e) {
    if (allow_null) set_cstr(dst, cap, "<>");
    else {
      char out[SMTP_SZ_PATH];
      (void)snprintf(out, sizeof(out), "<%s>", SMTP_FIX_RCPT_FALLBACK_MAILBOX);
      set_cstr(dst, cap, out);
    }
    return;
  }

  if (is_enclosed_angle(b)) {
    size_t n = (size_t)(e - b);
    char tmp[SMTP_SZ_PATH];
    size_t cpy = n < sizeof(tmp)-1 ? n : sizeof(tmp)-1;
    memcpy(tmp, b, cpy); tmp[cpy] = '\0';
    set_cstr(dst, cap, tmp);
    return;
  }

  char inner[SMTP_SZ_PATH];
  size_t wn = 0;
  for (const char *p = b; p < e && wn + 1 < sizeof(inner); ++p) {
    if (*p == '<' || *p == '>') continue;
    inner[wn++] = *p;
  }
  inner[wn] = '\0';

  if (wn == 0) {
    if (allow_null) { set_cstr(dst, cap, "<>"); return; }
    (void)snprintf(inner, sizeof(inner), "%s", SMTP_FIX_RCPT_FALLBACK_MAILBOX);
  }

  char out[SMTP_SZ_PATH];
  (void)snprintf(out, sizeof(out), "<%s>", inner);
  set_cstr(dst, cap, out);
}


int fix_SMTP_4_1_2_PATH_SYNTAX(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {
      case SMTP_PKT_MAIL:
        fix_one_path(pkts[i].pkt.mail.reverse_path,
                     sizeof pkts[i].pkt.mail.reverse_path,
                     /*allow_null=*/1);
        break;

      case SMTP_PKT_RCPT:

        fix_one_path(pkts[i].pkt.rcpt.forward_path,
                     sizeof pkts[i].pkt.rcpt.forward_path,
                     /*allow_null=*/0);
        break;

      default:
        break;
    }
  }
  return 0;
}


static void normalize_path_angle(char dst[], size_t cap, int allow_null) {
  if (!dst || cap == 0) return;

  const char *b, *e;
  trim_bounds(dst, &b, &e);

  if (!b || b >= e) {
    if (allow_null) set_cstr(dst, cap, "<>");
    else set_cstr(dst, cap, "<user@example.com>");
    return;
  }

  if (is_enclosed_angle(b)) {
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    memmove(dst, b, n);
    dst[n] = '\0';
    return;
  }

  char inner[SMTP_SZ_PATH];
  size_t wn = 0;
  for (const char *p = b; p < e && wn + 1 < sizeof(inner); ++p) {
    if (*p == '<' || *p == '>') continue;
    inner[wn++] = *p;
  }
  inner[wn] = '\0';

  if (wn == 0) {
    if (allow_null) { set_cstr(dst, cap, "<>"); return; }
    set_cstr(inner, sizeof(inner), "user@example.com");
  }

  char out[SMTP_SZ_PATH];
  (void)snprintf(out, sizeof(out), "<%s>", inner);
  set_cstr(dst, cap, out);
}

static void normalize_optional_args(char dst[], size_t cap) {
  if (!dst || cap == 0) return;

  char tmp[SMTP_SZ_OPTARGS];
  size_t wn = 0;
  for (const unsigned char *p = (const unsigned char*)dst; *p && wn + 1 < sizeof(tmp); ++p) {
    if (*p == '\r' || *p == '\n') continue;
    tmp[wn++] = (char)*p;
  }
  tmp[wn] = '\0';

  /* trim */
  const char *b, *e;
  trim_bounds(tmp, &b, &e);

  if (!b || b >= e) { set_cstr(dst, cap, ""); return; }

  char out[SMTP_SZ_OPTARGS];
  size_t len = (size_t)(e - b);
  if (len + 2 > sizeof(out)) len = sizeof(out) - 2; 
  out[0] = ' ';
  memcpy(out + 1, b, len);
  out[1 + len] = '\0';

  set_cstr(dst, cap, out);
}


int fix_SMTP_4_1_1_2_MAIL(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;

    smtp_mail_packet_t *m = &pkts[i].pkt.mail;


    set_cstr(m->command, sizeof m->command, "MAIL");
    set_cstr(m->space1, sizeof m->space1, " ");
    set_cstr(m->from_keyword, sizeof m->from_keyword, "FROM:");


    normalize_path_angle(m->reverse_path, sizeof m->reverse_path, /*allow_null=*/1);

    normalize_optional_args(m->optional_args, sizeof m->optional_args);

    set_crlf(m->crlf);
  }

  return 0;
}

#ifndef RCPT_KEEP_DSN
#define RCPT_KEEP_DSN 0 
#endif


static void trim_bounds2(const char *s, const char **pb, const char **pe) {
  if (!s) { *pb = *pe = NULL; return; }
  const char *b = s, *e = s + strlen(s);
  while (b < e && (unsigned char)*b <= ' ') ++b;
  while (e > b && (unsigned char)e[-1] <= ' ') --e;
  *pb = b; *pe = e;
}

static int equals_ci(const char *s, const char *lit) {
  if (!s || !lit) return 0;
  while (*s && *lit) {
    if (tolower((unsigned char)*s) != tolower((unsigned char)*lit)) return 0;
    ++s; ++lit;
  }
  return *s == '\0' && *lit == '\0';
}

static int startswith_ci(const char *s, const char *prefix) {
  if (!s || !prefix) return 0;
  while (*s && *prefix) {
    if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
    ++s; ++prefix;
  }
  return *prefix == '\0';
}

static int is_angle_enclosed(const char *b, const char *e) {
  return (e > b + 1 && b[0] == '<' && e[-1] == '>');
}

static void strip_crlf_inplace(char *s) {
  if (!s) return;
  char *w = s;
  for (char *p = s; *p; ++p) {
    if (*p == '\r' || *p == '\n') continue;
    *w++ = *p;
  }
  *w = '\0';
}


static void normalize_rcpt_forward_path(char dst[], size_t cap) {
  if (!dst || cap == 0) return;

  strip_crlf_inplace(dst);

  const char *b, *e;
  trim_bounds2(dst, &b, &e);

  if (!b || b >= e || (e - b == 2 && b[0] == '<' && b[1] == '>')) {
    set_cstr(dst, cap, "<Postmaster>");
    return;
  }

  if (is_angle_enclosed(b, e)) {
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    memmove(dst, b, n);
    dst[n] = '\0';
    return;
  }

  char inner[SMTP_SZ_PATH];
  size_t wn = 0;
  for (const char *p = b; p < e && wn + 1 < sizeof(inner); ++p) {
    if (*p == '<' || *p == '>') continue;
    inner[wn++] = *p;
  }
  inner[wn] = '\0';

  if (wn == 0) {
    set_cstr(dst, cap, "<Postmaster>");
    return;
  }

  char out[SMTP_SZ_PATH];
  (void)snprintf(out, sizeof(out), "<%s>", inner);
  set_cstr(dst, cap, out);
}


static void normalize_rcpt_optional_args(char dst[], size_t cap) {
#if RCPT_KEEP_DSN
  if (!dst || cap == 0) return;

  char tmp[SMTP_SZ_OPTARGS];
  size_t wn = 0;
  for (const unsigned char *p = (const unsigned char*)dst; *p && wn + 1 < sizeof(tmp); ++p) {
    if (*p == '\r' || *p == '\n') continue;
    tmp[wn++] = (char)*p;
  }
  tmp[wn] = '\0';

  char out[SMTP_SZ_OPTARGS];
  size_t outn = 0;
  const char *s = tmp;
  while (*s) {
    while (*s && isspace((unsigned char)*s)) ++s;
    if (!*s) break;
    const char *tok_b = s;
    while (*s && !isspace((unsigned char)*s)) ++s;
    const char *tok_e = s;

    char tok[256];
    size_t tn = (size_t)(tok_e - tok_b);
    if (tn >= sizeof(tok)) tn = sizeof(tok) - 1;
    memcpy(tok, tok_b, tn); tok[tn] = '\0';

    if (startswith_ci(tok, "NOTIFY=") || startswith_ci(tok, "ORCPT=")) {
      size_t need = (outn ? 1 : 1) + strlen(tok); 
      if (outn + need + 1 < sizeof(out)) {
        if (outn == 0) out[outn++] = ' ';
        else           out[outn++] = ' ';
        memcpy(out + outn, tok, strlen(tok));
        outn += strlen(tok);
        out[outn] = '\0';
      }
    }
  }

  if (outn == 0) set_cstr(dst, cap, "");
  else set_cstr(dst, cap, out);
#else
  (void)cap;
  if (!dst) return;
  dst[0] = '\0';
#endif
}

int fix_SMTP_4_1_1_3_RCPT(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;

    smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;

    set_cstr(r->command, sizeof r->command, "RCPT");
    set_cstr(r->space1,  sizeof r->space1,  " ");
    set_cstr(r->to_keyword, sizeof r->to_keyword, "TO:");
    set_crlf(r->crlf);

    normalize_rcpt_forward_path(r->forward_path, sizeof r->forward_path);

    normalize_rcpt_optional_args(r->optional_args, sizeof r->optional_args);
  }

  return 0;
}



static size_t minz(size_t a, size_t b) { return a < b ? a : b; }

static const char* rfind_char(const char *b, const char *e, int ch) {
  if (!b || !e || e < b) return NULL;
  for (const char *p = e; p > b; ) {
    --p;
    if ((unsigned char)*p == (unsigned char)ch) return p;
  }
  return NULL;
}

static size_t cat_bounded(char *dst, size_t cap, const char *src, size_t n) {
  if (!dst || cap == 0) return 0;
  size_t cur = strlen(dst);
  if (cur >= cap) return 0;
  size_t room = cap - 1 - cur;
  size_t w = n > room ? room : n;
  if (w) memcpy(dst + cur, src, w);
  dst[cur + w] = '\0';
  return w;
}

static void enforce_domain_cap(char *domain) {
  if (!domain) return;
  strip_crlf_inplace(domain);
  size_t len = strlen(domain);
  if (len > 255) domain[255] = '\0';
}

static void parse_path_basic(const char *path,
                             char *route, size_t route_cap,
                             char *local, size_t local_cap,
                             char *domain, size_t domain_cap,
                             int *has_brackets, int *has_domain)
{
  set_cstr(route, route_cap, "");
  set_cstr(local, local_cap, "");
  set_cstr(domain, domain_cap, "");
  if (has_brackets) *has_brackets = 0;
  if (has_domain) *has_domain = 0;

  if (!path) return;

  const char *b, *e;
  trim_bounds(path, &b, &e);
  if (b >= e) return;

  if (b[0] == '<' && e > b+1 && e[-1] == '>') {
    if (has_brackets) *has_brackets = 1;
    ++b; --e;
    trim_bounds(b, &b, &e);
  }

  if (b >= e) return;

  const char *colon = rfind_char(b, e, ':');
  const char *mb_b = b;
  if (colon && colon+1 < e) {
    size_t rlen = (size_t)(colon + 1 - b); 
    if (route_cap) {
      size_t w = minz(rlen, route_cap - 1);
      memcpy(route, b, w); route[w] = '\0';
    }
    mb_b = colon + 1;
  }

  /* mailbox: local [@ domain] */
  const char *at = NULL;
  for (const char *p = mb_b; p < e; ++p) {
    if (*p == '@') { at = p; break; }
  }

  if (at) {
    /* local */
    size_t llen = (size_t)(at - mb_b);
    if (local_cap) {
      size_t w = minz(llen, local_cap - 1);
      memcpy(local, mb_b, w); local[w] = '\0';
    }
    /* domain */
    size_t dlen = (size_t)(e - (at + 1));
    if (domain_cap) {
      size_t w = minz(dlen, domain_cap - 1);
      memcpy(domain, at + 1, w); domain[w] = '\0';
    }
    if (has_domain) *has_domain = 1;
  } else {
    size_t llen = (size_t)(e - mb_b);
    if (local_cap) {
      size_t w = minz(llen, local_cap - 1);
      memcpy(local, mb_b, w); local[w] = '\0';
    }
    if (has_domain) *has_domain = 0;
  }
}


static void rebuild_path_limited(char *dst, size_t dst_cap,
                                 const char *route_in,
                                 const char *local_in,
                                 const char *domain_in,
                                 int has_domain_in)
{
  char route[SMTP_SZ_PATH];  set_cstr(route, sizeof route, route_in ? route_in : "");
  char local[SMTP_SZ_PATH];  set_cstr(local, sizeof local, local_in ? local_in : "");
  char domain[SMTP_SZ_PATH]; set_cstr(domain, sizeof domain, domain_in ? domain_in : "");
  int  has_domain = has_domain_in && domain[0] != '\0';

  if (strlen(local)  > 64)  local[64]  = '\0';
  if (has_domain) {
    if (strlen(domain) > 255) domain[255] = '\0';
  }

  const size_t MAX_TOTAL = 256;
  const size_t BRKT = 2; /* '<' + '>' */
  size_t allowed_inner = (MAX_TOTAL > BRKT) ? (MAX_TOTAL - BRKT) : 0;

  size_t l_len = strlen(local);
  size_t d_len = has_domain ? strlen(domain) : 0;
  size_t r_len = strlen(route);


  size_t mailbox_len = l_len + (has_domain ? (1 + d_len) : 0);
  if (mailbox_len > allowed_inner) {
    if (has_domain) {
      size_t max_d = (allowed_inner > l_len + 1) ? (allowed_inner - l_len - 1) : 0;
      if (d_len > max_d) { domain[max_d] = '\0'; d_len = max_d; }
      if (d_len == 0) has_domain = 0; 
      mailbox_len = l_len + (has_domain ? (1 + d_len) : 0);
    }
    if (mailbox_len > allowed_inner) {
      size_t max_l = allowed_inner; 
      if (l_len > max_l) { local[max_l] = '\0'; l_len = max_l; }
      has_domain = 0; d_len = 0;     
      mailbox_len = l_len;
    }
  }

  size_t rem = (allowed_inner > mailbox_len) ? (allowed_inner - mailbox_len) : 0;
  const char *r_use = route;
  size_t r_use_len = r_len;
  if (r_use_len > rem) {
    r_use = route + (r_len - rem);
    r_use_len = rem;
  }

  set_cstr(dst, dst_cap, "");
  cat_bounded(dst, dst_cap, "<", 1);
  cat_bounded(dst, dst_cap, r_use, r_use_len);
  cat_bounded(dst, dst_cap, local, l_len);
  if (has_domain) {
    cat_bounded(dst, dst_cap, "@", 1);
    cat_bounded(dst, dst_cap, domain, d_len);
  }
  cat_bounded(dst, dst_cap, ">", 1);
}

static void fix_one_path_field(char *path_buf, size_t path_cap) {
  if (!path_buf || path_cap == 0) return;

  strip_crlf_inplace(path_buf);

  char route[SMTP_SZ_PATH], local[SMTP_SZ_PATH], domain[SMTP_SZ_PATH];
  int has_brackets = 0, has_domain = 0;

  parse_path_basic(path_buf,
                   route, sizeof route,
                   local, sizeof local,
                   domain, sizeof domain,
                   &has_brackets, &has_domain);

  rebuild_path_limited(path_buf, path_cap, route, local, domain, has_domain);
}

int fix_SMTP_4_5_3_1_LIMITS(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {

      case SMTP_PKT_HELO:
        /* HELO domain ≤ 255 */
        enforce_domain_cap(pkts[i].pkt.helo.domain);
        strip_crlf_inplace(pkts[i].pkt.helo.domain);
        break;

      case SMTP_PKT_EHLO:
        /* EHLO domain ≤ 255 */
        enforce_domain_cap(pkts[i].pkt.ehlo.domain);
        strip_crlf_inplace(pkts[i].pkt.ehlo.domain);
        break;

      case SMTP_PKT_MAIL:
        fix_one_path_field(pkts[i].pkt.mail.reverse_path, sizeof pkts[i].pkt.mail.reverse_path);
        break;

      case SMTP_PKT_RCPT:
        fix_one_path_field(pkts[i].pkt.rcpt.forward_path, sizeof pkts[i].pkt.rcpt.forward_path);
        break;

      default:
        break;
    }
  }

  return 0;
}



static void strip_spaces(char *s) {
  if (!s) return;
  size_t len = strlen(s);
  size_t b = 0, e = len;
  while (b < e && (unsigned char)s[b] <= ' ') ++b;
  while (e > b && (unsigned char)s[e-1] <= ' ') --e;
  if (b == 0 && e == len) return;
  memmove(s, s + b, e - b);
  s[e - b] = '\0';
}

static int starts_with_ci(const char *s, const char *pfx) {
  if (!s || !pfx) return 0;
  for (; *pfx; ++pfx, ++s) {
    if (!*s) return 0;
    if (tolower((unsigned char)*s) != tolower((unsigned char)*pfx)) return 0;
  }
  return 1;
}

static int inside_brackets(const char *s, char *inner, size_t cap_inner) {
  if (!s) return 0;
  size_t n = strlen(s);
  if (n >= 2 && s[0] == '[' && s[n-1] == ']') {
    if (inner && cap_inner) {
      size_t m = n - 2;
      if (m >= cap_inner) m = cap_inner - 1;
      memcpy(inner, s + 1, m);
      inner[m] = '\0';
    }
    return 1;
  }
  return 0;
}

static int is_uint_dec_0_255(const char *b, const char *e) {
  if (b >= e) return 0;
  int v = 0;
  for (const char *p = b; p < e; ++p) {
    if (*p < '0' || *p > '9') return 0;
    v = v*10 + (*p - '0');
    if (v > 255) return 0;
  }
  return 1;
}

static int looks_like_ipv4(const char *s) {
  if (!s || !*s) return 0;
  const char *p = s;
  const char *seg_b = p;
  int dots = 0;
  for (; *p; ++p) {
    if (*p == '.') {
      if (!is_uint_dec_0_255(seg_b, p)) return 0;
      ++dots;
      seg_b = p + 1;
    } else if (*p < '0' || *p > '9') {
      return 0;
    }
  }
  if (dots != 3) return 0;
  return is_uint_dec_0_255(seg_b, s + strlen(s));
}

static int looks_like_ipv6_core(const char *s) {
  if (!s || !*s) return 0;
  if (starts_with_ci(s, "IPv6:")) return 1;
  int has_colon = 0;
  for (const char *p = s; *p; ++p) {
    char c = *p;
    if (c == ':') { has_colon = 1; continue; }
    if (c == '.') continue;
    if (!isxdigit((unsigned char)c)) return 0;
  }
  return has_colon;
}

static int looks_like_general_literal(const char *s) {
  if (!s || !*s) return 0;
  const char *p = s;
  if (!isalnum((unsigned char)*p) && *p != '-') return 0;
  for (; *p && *p != ':'; ++p) {
    if (!isalnum((unsigned char)*p) && *p != '-') return 0;
  }
  return (*p == ':'); 
}


static void normalize_addr_literal(const char *domain, char out[], size_t out_cap) {
  char inner[SMTP_SZ_DOMAIN];
  int had_brackets = inside_brackets(domain, inner, sizeof inner);
  if (!had_brackets) {
    set_cstr(inner, sizeof inner, domain);
  }
  strip_spaces(inner);

  if (looks_like_ipv6_core(inner) && !starts_with_ci(inner, "IPv6:")) {
    char tmp[SMTP_SZ_DOMAIN];
    set_cstr(tmp, sizeof tmp, "IPv6:");
    strncat(tmp, inner, sizeof(tmp) - 1 - strlen(tmp));
    set_cstr(inner, sizeof inner, tmp);
  }


  if (out_cap) {
    if (strlen(inner) + 2 >= out_cap) {

      out[0] = '[';
      size_t room = out_cap > 3 ? (out_cap - 3) : 0;
      memcpy(out + 1, inner, room);
      out[1 + room] = ']';
      out[2 + room] = '\0';
    } else {
      snprintf(out, out_cap, "[%s]", inner);
    }
  }
}


static void fix_path_mailbox_domain_literal(char *path_buf, size_t cap) {
  if (!path_buf || cap == 0) return;

  size_t n = strlen(path_buf);
  const char *L = memchr(path_buf, '<', n);
  const char *R = L ? memchr(L, '>', (path_buf + n) - L) : NULL;
  if (!L || !R || L + 1 >= R) return;

  /* inner = L+1 .. R-1 */
  char inner[SMTP_SZ_PATH];
  size_t inner_len = (size_t)(R - (L + 1));
  if (inner_len >= sizeof inner) inner_len = sizeof inner - 1;
  memcpy(inner, L + 1, inner_len);
  inner[inner_len] = '\0';

  const char *route_end = strrchr(inner, ':');
  const char *mb = route_end ? route_end + 1 : inner;

  /* mailbox = local [@ domain] */
  const char *at = strchr(mb, '@');
  if (!at) {
    return;
  }

  char route[SMTP_SZ_PATH], local[SMTP_SZ_PATH], domain[SMTP_SZ_PATH];
  if (route_end) {
    size_t rlen = (size_t)(route_end - inner + 1);
    if (rlen >= sizeof route) rlen = sizeof route - 1;
    memcpy(route, inner, rlen); route[rlen] = '\0';
  } else {
    route[0] = '\0';
  }

  { /* local */
    size_t llen = (size_t)(at - mb);
    if (llen >= sizeof local) llen = sizeof local - 1;
    memcpy(local, mb, llen); local[llen] = '\0';
    strip_spaces(local);
  }

  { 
    const char *db = at + 1;
    size_t dlen = strlen(db);
    if (dlen >= sizeof domain) dlen = sizeof domain - 1;
    memcpy(domain, db, dlen); domain[dlen] = '\0';
    strip_spaces(domain);
  }

  if (is_address_literal(domain)) {
    char dom_norm[SMTP_SZ_DOMAIN];
    normalize_addr_literal(domain, dom_norm, sizeof dom_norm);

    char rebuilt[SMTP_SZ_PATH];
    set_cstr(rebuilt, sizeof rebuilt, route);
    strncat(rebuilt, local, sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, "@", sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, dom_norm, sizeof(rebuilt) - 1 - strlen(rebuilt));

    size_t new_len = strlen(rebuilt);
    size_t prefix_len = (size_t)(L + 1 - path_buf);
    size_t suffix_len = strlen(R); 
    if (prefix_len + new_len + suffix_len >= cap) {
      new_len = cap - 1 - prefix_len - suffix_len;
    }
    memmove(path_buf + prefix_len, rebuilt, new_len);
    memmove(path_buf + prefix_len + new_len, R, suffix_len);
    path_buf[prefix_len + new_len + suffix_len] = '\0';
  }
}

static void fix_greeting_domain_literal(char *domain, size_t cap) {
  if (!domain || cap == 0) return;
  char tmp[SMTP_SZ_DOMAIN];
  set_cstr(tmp, sizeof tmp, domain);
  strip_spaces(tmp);

  if (is_address_literal(tmp)) {
    char norm[SMTP_SZ_DOMAIN];
    normalize_addr_literal(tmp, norm, sizeof norm);
    set_cstr(domain, cap, norm);
  }
}

int fix_SMTP_4_1_3_ADDR_LITERAL(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {
      case SMTP_PKT_HELO:
        fix_greeting_domain_literal(pkts[i].pkt.helo.domain, sizeof pkts[i].pkt.helo.domain);
        break;
      case SMTP_PKT_EHLO:
        fix_greeting_domain_literal(pkts[i].pkt.ehlo.domain, sizeof pkts[i].pkt.ehlo.domain);
        break;
      case SMTP_PKT_MAIL:
        fix_path_mailbox_domain_literal(pkts[i].pkt.mail.reverse_path,
                                        sizeof pkts[i].pkt.mail.reverse_path);
        break;
      case SMTP_PKT_RCPT:
        fix_path_mailbox_domain_literal(pkts[i].pkt.rcpt.forward_path,
                                        sizeof pkts[i].pkt.rcpt.forward_path);
        break;
      default:
        break;
    }
  }
  return 0;
}


static void sanitize_label_ldh(const char *in, char *out, size_t cap) {
  if (!out || cap == 0) return;
  char tmp[SMTP_SZ_DOMAIN];
  size_t w = 0;
  int last_dash = 0;

  for (const unsigned char *p = (const unsigned char*)in; *p; ++p) {
    unsigned char c = *p;
    int ok = (isalnum(c) || c == '-');
    char v;
    if (ok) {
      v = (char)tolower(c);
      if (w + 1 < sizeof tmp) tmp[w++] = v;
      last_dash = 0;
    } else {
      if (!last_dash) {
        if (w + 1 < sizeof tmp) tmp[w++] = '-';
        last_dash = 1;
      }
    }
  }

  size_t b = 0, e = w;
  while (b < e && tmp[b] == '-') ++b;
  while (e > b && tmp[e-1] == '-') --e;

  if (e <= b) { 
    set_cstr(out, cap, "a");
    return;
  }

  size_t n = e - b;
  if (n >= cap) n = cap - 1;
  memcpy(out, tmp + b, n);
  out[n] = '\0';
}

static void sanitize_domain_ldh(const char *domain_in, char *out, size_t cap) {
  if (!out || cap == 0) return;

  char inner[SMTP_SZ_DOMAIN];
  if (inside_brackets(domain_in, inner, sizeof inner)) {
    set_cstr(out, cap, domain_in);
    return;
  }

  char buf[SMTP_SZ_DOMAIN];
  set_cstr(buf, sizeof buf, domain_in);
  strip_spaces(buf);

  size_t len = strlen(buf);
  int trailing_dot = (len > 0 && buf[len-1] == '.');

  char label[SMTP_SZ_DOMAIN];
  char acc[SMTP_SZ_DOMAIN];
  acc[0] = '\0';

  const char *p = buf;
  const char *seg = p;

  while (1) {
    if (*p == '.' || *p == '\0') {
      if (p == seg) {
        set_cstr(label, sizeof label, "a");   
      } else {
        char raw[SMTP_SZ_DOMAIN];
        size_t l = (size_t)(p - seg);
        if (l >= sizeof raw) l = sizeof raw - 1;
        memcpy(raw, seg, l); raw[l] = '\0';
        sanitize_label_ldh(raw, label, sizeof label);
      }

      if (acc[0] != '\0') strncat(acc, ".", sizeof(acc) - 1 - strlen(acc));
      strncat(acc, label, sizeof(acc) - 1 - strlen(acc));

      if (*p == '\0') break;
      seg = p + 1;
    }
    ++p;
  }

  if (trailing_dot && strlen(acc) + 1 < sizeof acc) {
    strncat(acc, ".", sizeof(acc) - 1 - strlen(acc));
  }

  set_cstr(out, cap, acc);
}

static void fix_path_mailbox_domain_ldh(char *path_buf, size_t cap) {
  if (!path_buf || cap == 0) return;

  size_t n = strlen(path_buf);
  const char *L = memchr(path_buf, '<', n);
  const char *R = L ? memchr(L, '>', (path_buf + n) - L) : NULL;
  if (!L || !R || L + 1 >= R) return;

  /* inner = L+1..R-1 */
  char inner[SMTP_SZ_PATH];
  size_t inner_len = (size_t)(R - (L + 1));
  if (inner_len >= sizeof inner) inner_len = sizeof inner - 1;
  memcpy(inner, L + 1, inner_len);
  inner[inner_len] = '\0';

  const char *route_end = strrchr(inner, ':');
  const char *mb = route_end ? route_end + 1 : inner;

  const char *at = strrchr(mb, '@');
  if (!at) return; 

  char route[SMTP_SZ_PATH], local[SMTP_SZ_PATH], domain[SMTP_SZ_PATH];
  if (route_end) {
    size_t rlen = (size_t)(route_end - inner + 1); 
    if (rlen >= sizeof route) rlen = sizeof route - 1;
    memcpy(route, inner, rlen); route[rlen] = '\0';
  } else route[0] = '\0';

  { /* local */
    size_t llen = (size_t)(at - mb);
    if (llen >= sizeof local) llen = sizeof local - 1;
    memcpy(local, mb, llen); local[llen] = '\0';
    strip_spaces(local);
  }

  { 
    const char *db = at + 1;
    size_t dlen = strlen(db);
    if (dlen >= sizeof domain) dlen = sizeof domain - 1;
    memcpy(domain, db, dlen); domain[dlen] = '\0';
    strip_spaces(domain);
  }


  if (!inside_brackets(domain, NULL, 0)) {
    char dom_ldh[SMTP_SZ_DOMAIN];
    sanitize_domain_ldh(domain, dom_ldh, sizeof dom_ldh);

    char rebuilt[SMTP_SZ_PATH];
    set_cstr(rebuilt, sizeof rebuilt, route);
    strncat(rebuilt, local, sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, "@", sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, dom_ldh, sizeof(rebuilt) - 1 - strlen(rebuilt));

    size_t new_len = strlen(rebuilt);
    size_t prefix_len = (size_t)(L + 1 - path_buf);
    size_t suffix_len = strlen(R);
    if (prefix_len + new_len + suffix_len >= cap) {
      if (new_len > cap - 1 - prefix_len - suffix_len)
        new_len = cap - 1 - prefix_len - suffix_len;
    }
    memmove(path_buf + prefix_len, rebuilt, new_len);
    memmove(path_buf + prefix_len + new_len, R, suffix_len);
    path_buf[prefix_len + new_len + suffix_len] = '\0';
  }
}

static void fix_greeting_domain_ldh(char *domain, size_t cap) {
  if (!domain || cap == 0) return;
  char tmp[SMTP_SZ_DOMAIN];
  set_cstr(tmp, sizeof tmp, domain);
  strip_spaces(tmp);

  if (!inside_brackets(tmp, NULL, 0)) {
    char out[SMTP_SZ_DOMAIN];
    sanitize_domain_ldh(tmp, out, sizeof out);
    set_cstr(domain, cap, out);
  }
}

int fix_SMTP_2_3_5_DOMAIN_SYNTAX(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {
      case SMTP_PKT_HELO:
        fix_greeting_domain_ldh(pkts[i].pkt.helo.domain, sizeof pkts[i].pkt.helo.domain);
        break;
      case SMTP_PKT_EHLO:
        fix_greeting_domain_ldh(pkts[i].pkt.ehlo.domain, sizeof pkts[i].pkt.ehlo.domain);
        break;
      case SMTP_PKT_MAIL:
        fix_path_mailbox_domain_ldh(pkts[i].pkt.mail.reverse_path,
                                    sizeof pkts[i].pkt.mail.reverse_path);
        break;
      case SMTP_PKT_RCPT:
        fix_path_mailbox_domain_ldh(pkts[i].pkt.rcpt.forward_path,
                                    sizeof pkts[i].pkt.rcpt.forward_path);
        break;
      default:
        break;
    }
  }
  return 0;
}

void fix_smtp(smtp_packet_t *pkts, size_t count){
    if (!pkts || count == 0) return;
    fix_smtp_crlf_rule(pkts, count);
    fix_smtp_cmd_len(pkts, count);
    fix_SMTP_2_3_5_DOMAIN_SYNTAX(pkts, count);
    fix_SMTP_4_1_1_1_EHLO(pkts, count);
    fix_SMTP_4_1_1_2_MAIL(pkts, count);
    fix_SMTP_4_1_1_3_RCPT(pkts, count);
    fix_SMTP_4_1_2_PATH_SYNTAX(pkts, count);
    fix_SMTP_4_1_3_ADDR_LITERAL(pkts, count);
    fix_SMTP_4_5_3_1_LIMITS(pkts, count);
}
