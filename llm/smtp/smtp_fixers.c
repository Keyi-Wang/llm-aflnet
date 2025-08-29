/* smtp fixers source file */
#include "smtp.h"

/* smtp_crlf_fixer.c */
#include <stddef.h>
#include <string.h>

/* 把 buf 填成 "\r\n" 并以 NUL 结尾（缓冲区大小为 SMTP_SZ_CRLF=3） */
static inline void set_crlf(char crlf[SMTP_SZ_CRLF]) {
  crlf[0] = '\r';
  crlf[1] = '\n';
  crlf[2] = '\0';
}

/* 原地删除字符串中的所有 '\r' 和 '\n'，返回删除的字符数 */
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

/* 为了少写样板，定义一个宏对某个字段执行“去 CR/LF” */
#define SCRUB(field) do { fixes += strip_cr_lf_inplace((field)); } while (0)
/* 为 crlf 字段强制设置为 CRLF */
#define FIX_CRLF(field) do { set_crlf((field)); fixes++; } while (0)

/* 核心修复函数：
 * - 遍历每个数据包
 * - 去掉所有字段中出现的裸 CR/LF
 * - 将行终止符统一为 "\r\n"
 * 返回执行的修复动作数量（可用于统计/调试）
 */
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
        /* 未识别类型：无法安全访问 union；最少也不要忘了把末尾 CRLF 规范化。
           这里选“最保守”的处理——不动其它字段，只修 CRLF 的公共尾部不可行，
           因为未定义公共 crlf。因而什么都不做。 */
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

/* 当删除了可选实参时，把与之关联的可选空格一并清掉 */
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
/* MAIL: "MAIL SP FROM:" <reverse-path> [ SP optional_args ] CRLF
 * 我们约定：optional_args 非空时，在线路上前面会加一个单空格 */
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
            /* 仍超限：保底保留 1 个字符，避免把必填字段裁成空 */
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
          /* 先去掉可选参数（含其前置空格） */
          if (p->pkt.mail.optional_args[0]) {
            size_t oa = L(p->pkt.mail.optional_args);
            p->pkt.mail.optional_args[0] = '\0';
            total -= (1 + oa);
          }
          if (total > SMTP_LINE_LIMIT) {
            /* 再裁剪 reverse_path */
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
          /* 若参数被清空，去掉多余空格 */
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
          /* HELP 的 argument 可选，先整体删除（含空格） */
          p->pkt.help.argument[0] = '\0';
          p->pkt.help.space[0]    = '\0';
          total = calc_len_help(&p->pkt.help);
          /* 理论上不会再超，但为稳妥，如果还超就截断 command */
          if (total > SMTP_LINE_LIMIT) {
            size_t cmd_len = L(p->pkt.help.command);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (cmd_len > need_cut) trunc_len(p->pkt.help.command, cmd_len - need_cut);
            else trunc_len(p->pkt.help.command, 4); /* 至少留 "HELP" */
          }
        }
      } break;

      case SMTP_PKT_AUTH: {
        size_t total = calc_len_auth(&p->pkt.auth);
        if (total > SMTP_LINE_LIMIT) {
          /* 先裁剪（或删除）initial_response，并同步 space2 */
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
            /* 再裁剪 mechanism，至少留 1 个字符 */
            size_t mlen = L(p->pkt.auth.mechanism);
            size_t need_cut = total - SMTP_LINE_LIMIT;
            if (mlen > need_cut) trunc_len(p->pkt.auth.mechanism, (mlen - need_cut > 0) ? (mlen - need_cut) : 1);
            else trunc_len(p->pkt.auth.mechanism, 1);
          }
        }
      } break;

      case SMTP_PKT_DATA: {
        (void)calc_len_simple_cmd2(p->pkt.data.command, p->pkt.data.crlf);
        /* DATA 本身短，不处理 */
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
        /* 未识别类型：不做处理 */
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
      /* 允许很宽松的字符集合，适配 IPv4/IPv6/IPvFuture 的常见格式 */
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
  /* 支持既有 HELO/EHLO：统一空格/CRLF并修正 domain */
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

/* ---------- main fixer ---------- */
/* 返回值：
 *   0  成功
 *  -1  参数无效
 *
 * 说明：
 *  - 若序列中存在 MAIL（进入邮件事务），确保在第一条 MAIL 之前已出现 EHLO/HELO；
 *    若没有，则把第 0 个包改写为 EHLO <fallback>（不改变数组长度）。
 *  - 若已存在 EHLO/HELO，则规范化空格/CRLF，并修正无效 Domain 为地址字面量。
 */
int fix_SMTP_4_1_1_1_EHLO(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  /* 1) 找到第一条 MAIL；如果没有 MAIL，则无需强制补齐问候（会话可能不是邮件事务） */
  ssize_t first_mail = -1;
  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type == SMTP_PKT_MAIL) { first_mail = (ssize_t)i; break; }
  }
  if (first_mail < 0) {
    /* 无邮件事务：仍可规范已存在的 EHLO/HELO（非必需） */
    for (size_t i = 0; i < pkt_cnt; ++i) {
      if (pkts[i].cmd_type == SMTP_PKT_EHLO || pkts[i].cmd_type == SMTP_PKT_HELO) {
        normalize_greeting_packet(&pkts[i]);
      }
    }
    return 0;
  }

  /* 2) 在 first_mail 之前寻找 EHLO/HELO；若找到则校验并规范 */
  for (ssize_t i = 0; i < first_mail; ++i) {
    if (pkts[i].cmd_type == SMTP_PKT_EHLO || pkts[i].cmd_type == SMTP_PKT_HELO) {
      normalize_greeting_packet(&pkts[i]);
      return 0; /* 前置问候已存在且已规范 */
    }
  }

  /* 3) 不存在问候：为了不改变数组长度，把第 0 个包直接改写成 EHLO <addr-lit> */
  if (pkt_cnt == 0) return 0; /* 空数组，放弃修复 */
  make_ehlo(&pkts[0], SMTP_FIX_FALLBACK_ADDR_LIT);

  return 0;
}



/* 可定制占位 */
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

/* 把 path 文本规范为 < ... > ；若 allow_null 允许空路径（MAIL），空则返回 "<>" */
static void fix_one_path(char dst[], size_t cap, int allow_null) {
  if (!dst || cap == 0) return;

  /* 取出并裁剪原文本 */
  const char *b, *e;
  trim_bounds(dst, &b, &e);
  if (!b || b >= e) {
    /* 空路径：MAIL 允许 "<>", RCPT 用占位邮箱 */
    if (allow_null) set_cstr(dst, cap, "<>");
    else {
      char out[SMTP_SZ_PATH];
      (void)snprintf(out, sizeof(out), "<%s>", SMTP_FIX_RCPT_FALLBACK_MAILBOX);
      set_cstr(dst, cap, out);
    }
    return;
  }

  /* 已包裹：仅规范 CRLF/空白，保证首尾 <> 存在；内部不做破坏性改写 */
  if (is_enclosed_angle(b)) {
    /* 去掉外层空白后，确保以 '<' 开始、以 '>' 结束 */
    size_t n = (size_t)(e - b);
    /* 复制到临时，顺便去掉外侧多余空白（已在 trim_bounds 完成） */
    char tmp[SMTP_SZ_PATH];
    size_t cpy = n < sizeof(tmp)-1 ? n : sizeof(tmp)-1;
    memcpy(tmp, b, cpy); tmp[cpy] = '\0';

    /* 若内部还有首尾空白（如 "<  a@b  >"），可选地再微调：这里只保留原样 */
    set_cstr(dst, cap, tmp);
    return;
  }

  /* 未包裹：删除内部所有 '<' '>'，再包裹 */
  char inner[SMTP_SZ_PATH];
  size_t wn = 0;
  for (const char *p = b; p < e && wn + 1 < sizeof(inner); ++p) {
    if (*p == '<' || *p == '>') continue;
    inner[wn++] = *p;
  }
  inner[wn] = '\0';

  /* 处理“空内部” */
  if (wn == 0) {
    if (allow_null) { set_cstr(dst, cap, "<>"); return; }
    (void)snprintf(inner, sizeof(inner), "%s", SMTP_FIX_RCPT_FALLBACK_MAILBOX);
  }

  char out[SMTP_SZ_PATH];
  (void)snprintf(out, sizeof(out), "<%s>", inner);
  set_cstr(dst, cap, out);
}

/* ---- 主修复器：遍历并修正 MAIL/RCPT 的 path 语法 ---- */
/* 返回 0 成功；-1 参数无效 */
int fix_SMTP_4_1_2_PATH_SYNTAX(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {
      case SMTP_PKT_MAIL:
        /* MAIL FROM: 允许 null reverse-path "<>" */
        fix_one_path(pkts[i].pkt.mail.reverse_path,
                     sizeof pkts[i].pkt.mail.reverse_path,
                     /*allow_null=*/1);
        break;

      case SMTP_PKT_RCPT:
        /* RCPT TO: 不接受空路径（这里给出占位邮箱确保语法正确） */
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



/* 把 path 规范为 "<...>"；allow_null 为 1 时，空路径写成 "<>" */
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
    /* 已包裹：仅复制（已外部 trim），不动内部 */
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    memmove(dst, b, n);
    dst[n] = '\0';
    return;
  }

  /* 未包裹：去掉内部多余的 '<' '>' 再包裹 */
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

/* 规范可选参数：去 CR/LF，trim，若非空则前置一个空格；为空则置 "" */
static void normalize_optional_args(char dst[], size_t cap) {
  if (!dst || cap == 0) return;

  /* 去除 CR/LF 并复制到临时 */
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

  /* 前置一个空格，避免重复空格 */
  char out[SMTP_SZ_OPTARGS];
  size_t len = (size_t)(e - b);
  if (len + 2 > sizeof(out)) len = sizeof(out) - 2; /* 1 空格 + 内容 + NUL */
  out[0] = ' ';
  memcpy(out + 1, b, len);
  out[1 + len] = '\0';

  set_cstr(dst, cap, out);
}

/* --------- 主修复器 --------- */
/* 返回 0 成功；-1 参数无效 */
int fix_SMTP_4_1_1_2_MAIL(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;

    smtp_mail_packet_t *m = &pkts[i].pkt.mail;

    /* 1) 固定关键字与空格 */
    set_cstr(m->command, sizeof m->command, "MAIL");
    set_cstr(m->space1, sizeof m->space1, " ");
    set_cstr(m->from_keyword, sizeof m->from_keyword, "FROM:");

    /* 2) 规范路径：允许空路径 "<>" */
    normalize_path_angle(m->reverse_path, sizeof m->reverse_path, /*allow_null=*/1);

    /* 3) 规范可选参数：为空则 ""，非空则以单个空格开头 */
    normalize_optional_args(m->optional_args, sizeof m->optional_args);

    /* 4) 结尾 CRLF 固定 */
    set_crlf(m->crlf);
  }

  return 0;
}

/* ========== 可选开关：是否在 RCPT 中保留 DSN 扩展参数 ========== */
#ifndef RCPT_KEEP_DSN
#define RCPT_KEEP_DSN 0  /* 0: 默认全丢弃; 1: 仅保留 NOTIFY= 和 ORCPT= */
#endif



/* 去首尾空白（含 CR/LF、TAB）。返回 [b, e) */
static void trim_bounds2(const char *s, const char **pb, const char **pe) {
  if (!s) { *pb = *pe = NULL; return; }
  const char *b = s, *e = s + strlen(s);
  while (b < e && (unsigned char)*b <= ' ') ++b;
  while (e > b && (unsigned char)e[-1] <= ' ') --e;
  *pb = b; *pe = e;
}

/* 大小写不敏感比较，s 是否等于字面字串 lit */
static int equals_ci(const char *s, const char *lit) {
  if (!s || !lit) return 0;
  while (*s && *lit) {
    if (tolower((unsigned char)*s) != tolower((unsigned char)*lit)) return 0;
    ++s; ++lit;
  }
  return *s == '\0' && *lit == '\0';
}

/* s 是否以某前缀（大小写不敏感） */
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

/* 删除字符串中的 CR/LF（就地），并收敛内部空白到原样（这里只去 CR/LF 不进一步收敛空格） */
static void strip_crlf_inplace(char *s) {
  if (!s) return;
  char *w = s;
  for (char *p = s; *p; ++p) {
    if (*p == '\r' || *p == '\n') continue;
    *w++ = *p;
  }
  *w = '\0';
}

/* 规范 RCPT 的 forward_path：
   - 空（或仅空白/CRLF/“<>”）=> "<Postmaster>"
   - 否则去外部空白；若未被 < > 包裹则包裹；内部不变，但会去掉内部出现的额外 < >
*/
static void normalize_rcpt_forward_path(char dst[], size_t cap) {
  if (!dst || cap == 0) return;

  /* 移除 CRLF，避免被当作内容 */
  strip_crlf_inplace(dst);

  const char *b, *e;
  trim_bounds2(dst, &b, &e);

  if (!b || b >= e || (e - b == 2 && b[0] == '<' && b[1] == '>')) {
    set_cstr(dst, cap, "<Postmaster>");
    return;
  }

  /* 如果已经是 <...>，按“包一层”的语义仅复制出去即可 */
  if (is_angle_enclosed(b, e)) {
    size_t n = (size_t)(e - b);
    if (n >= cap) n = cap - 1;
    memmove(dst, b, n);
    dst[n] = '\0';
    return;
  }

  /* 未包裹：去掉内部任何 '<' '>' 再加上包裹 */
  char inner[SMTP_SZ_PATH];
  size_t wn = 0;
  for (const char *p = b; p < e && wn + 1 < sizeof(inner); ++p) {
    if (*p == '<' || *p == '>') continue;
    inner[wn++] = *p;
  }
  inner[wn] = '\0';

  /* inner 为空 => 用 <Postmaster> */
  if (wn == 0) {
    set_cstr(dst, cap, "<Postmaster>");
    return;
  }

  /* 构造 <inner> */
  char out[SMTP_SZ_PATH];
  (void)snprintf(out, sizeof(out), "<%s>", inner);
  set_cstr(dst, cap, out);
}

/* 处理 RCPT 可选参数：
   缺省：全部清空；若定义 RCPT_KEEP_DSN==1，仅保留 NOTIFY=... 和 ORCPT=...（以 SP 分隔）。
   最终：若有保留，前面加一个单空格；否则置 ""。
*/
static void normalize_rcpt_optional_args(char dst[], size_t cap) {
#if RCPT_KEEP_DSN
  if (!dst || cap == 0) return;

  /* 复制到临时并去 CR/LF */
  char tmp[SMTP_SZ_OPTARGS];
  size_t wn = 0;
  for (const unsigned char *p = (const unsigned char*)dst; *p && wn + 1 < sizeof(tmp); ++p) {
    if (*p == '\r' || *p == '\n') continue;
    tmp[wn++] = (char)*p;
  }
  tmp[wn] = '\0';

  /* 按空白切分，挑选 NOTIFY=/ORCPT= */
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
      size_t need = (outn ? 1 : 1) + strlen(tok); /* 前导空格 + token；第一个也要一个前导空格以契合 [ SP params ] */
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
  /* 无法获知服务器 EHLO 提供的扩展，保守起见移除所有参数以满足规范 */
  dst[0] = '\0';
#endif
}

/* ========== 主修复器 ========== */
/* 返回 0 成功；-1 参数无效 */
int fix_SMTP_4_1_1_3_RCPT(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;

    smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;

    /* 固定关键字与空格、CRLF */
    set_cstr(r->command, sizeof r->command, "RCPT");
    set_cstr(r->space1,  sizeof r->space1,  " ");
    set_cstr(r->to_keyword, sizeof r->to_keyword, "TO:");
    set_crlf(r->crlf);

    /* 规范 forward_path */
    normalize_rcpt_forward_path(r->forward_path, sizeof r->forward_path);

    /* 规范（或移除）可选参数 */
    normalize_rcpt_optional_args(r->optional_args, sizeof r->optional_args);
  }

  return 0;
}



static size_t minz(size_t a, size_t b) { return a < b ? a : b; }

/* 从右向左找字符（无 libc 扩展 memrchr 依赖） */
static const char* rfind_char(const char *b, const char *e, int ch) {
  if (!b || !e || e < b) return NULL;
  for (const char *p = e; p > b; ) {
    --p;
    if ((unsigned char)*p == (unsigned char)ch) return p;
  }
  return NULL;
}

/* 安全拼接到 dst，返回已写入字符数（不含 NUL） */
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

/* 仅对 domain 字段强制 ≤ 255 */
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

  /* 取 inner */
  if (b[0] == '<' && e > b+1 && e[-1] == '>') {
    if (has_brackets) *has_brackets = 1;
    ++b; --e;
    /* 去掉 inner 的首尾空白 */
    trim_bounds(b, &b, &e);
  }

  if (b >= e) return;

  /* 源路由：取最后一个冒号左侧为 route（含冒号） */
  const char *colon = rfind_char(b, e, ':');
  const char *mb_b = b;
  if (colon && colon+1 < e) {
    size_t rlen = (size_t)(colon + 1 - b); /* 含冒号 */
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
    /* 无 @：全作 local（例如 <Postmaster> 或空 <>） */
    size_t llen = (size_t)(e - mb_b);
    if (local_cap) {
      size_t w = minz(llen, local_cap - 1);
      memcpy(local, mb_b, w); local[w] = '\0';
    }
    if (has_domain) *has_domain = 0;
  }
}

/* 组装 path，满足：
   - local ≤ 64，domain ≤ 255；
   - 总长（含尖括号）≤ 256；
   - 优先保留 mailbox，再用剩余空间保留 route（截其右侧后缀）。
*/
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

  /* 1) 单字段上限 */
  if (strlen(local)  > 64)  local[64]  = '\0';
  if (has_domain) {
    if (strlen(domain) > 255) domain[255] = '\0';
  }

  /* 2) 计算在总长限制（含 <>）下的分配 */
  const size_t MAX_TOTAL = 256;
  const size_t BRKT = 2; /* '<' + '>' */
  size_t allowed_inner = (MAX_TOTAL > BRKT) ? (MAX_TOTAL - BRKT) : 0;

  size_t l_len = strlen(local);
  size_t d_len = has_domain ? strlen(domain) : 0;
  size_t r_len = strlen(route);

  /* 2.1 先确保 mailbox（local [@ domain]）装得下 */
  size_t mailbox_len = l_len + (has_domain ? (1 + d_len) : 0);
  if (mailbox_len > allowed_inner) {
    /* 尝试先压缩 domain，再压缩 local */
    if (has_domain) {
      size_t max_d = (allowed_inner > l_len + 1) ? (allowed_inner - l_len - 1) : 0;
      if (d_len > max_d) { domain[max_d] = '\0'; d_len = max_d; }
      if (d_len == 0) has_domain = 0; /* 没空间则移除 @domain */
      mailbox_len = l_len + (has_domain ? (1 + d_len) : 0);
    }
    if (mailbox_len > allowed_inner) {
      size_t max_l = allowed_inner; /* 甚至连 '@domain' 都装不下时，尽量留 local */
      if (l_len > max_l) { local[max_l] = '\0'; l_len = max_l; }
      has_domain = 0; d_len = 0;       /* 放弃 domain */
      mailbox_len = l_len;
    }
  }

  /* 2.2 用剩余空间放 route（靠近 mailbox 的后缀更有信息量） */
  size_t rem = (allowed_inner > mailbox_len) ? (allowed_inner - mailbox_len) : 0;
  const char *r_use = route;
  size_t r_use_len = r_len;
  if (r_use_len > rem) {
    /* 截取右侧 rem 字节 */
    r_use = route + (r_len - rem);
    r_use_len = rem;
  }

  /* 3) 重建 "<route + local [+ '@' + domain]>" */
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

/* 针对单个路径字段执行修正 */
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

  /* 统一按规则输出为尖括号形式，并满足长度限制 */
  rebuild_path_limited(path_buf, path_cap, route, local, domain, has_domain);
}

/* ------------ 主修复器 ------------ */
/* 返回 0 成功；-1 参数无效 */
int fix_SMTP_4_5_3_1_LIMITS(smtp_packet_t *pkts, size_t pkt_cnt) {
  if (!pkts) return -1;

  for (size_t i = 0; i < pkt_cnt; ++i) {
    switch (pkts[i].cmd_type) {

      case SMTP_PKT_HELO:
        /* HELO domain ≤ 255 */
        enforce_domain_cap(pkts[i].pkt.helo.domain);
        /* 也清理潜在 CRLF */
        strip_crlf_inplace(pkts[i].pkt.helo.domain);
        break;

      case SMTP_PKT_EHLO:
        /* EHLO domain ≤ 255 */
        enforce_domain_cap(pkts[i].pkt.ehlo.domain);
        strip_crlf_inplace(pkts[i].pkt.ehlo.domain);
        break;

      case SMTP_PKT_MAIL:
        /* reverse-path 总长 ≤ 256，且 local ≤64 / domain ≤255 */
        fix_one_path_field(pkts[i].pkt.mail.reverse_path, sizeof pkts[i].pkt.mail.reverse_path);
        break;

      case SMTP_PKT_RCPT:
        /* forward-path 总长 ≤ 256，且 local ≤64 / domain ≤255 */
        fix_one_path_field(pkts[i].pkt.rcpt.forward_path, sizeof pkts[i].pkt.rcpt.forward_path);
        break;

      default:
        /* 其它指令不含本规则受限字段 */
        break;
    }
  }

  return 0;
}



static void strip_spaces(char *s) {
  if (!s) return;
  /* 去两端空白；中间空白不动 */
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

/* 简单 IPv4 字面量识别：d.d.d.d（每段 0–255） */
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

/* 宽松 IPv6 识别：包含':'，并且只由 [0-9A-Fa-f:.] 与可能的压缩符号组成；
   若已以 "IPv6:" 开头，也算 IPv6。
*/
static int looks_like_ipv6_core(const char *s) {
  if (!s || !*s) return 0;
  if (starts_with_ci(s, "IPv6:")) return 1;
  int has_colon = 0;
  for (const char *p = s; *p; ++p) {
    char c = *p;
    if (c == ':') { has_colon = 1; continue; }
    if (c == '.') continue; /* 可能带尾部 v4 映射 */
    if (!isxdigit((unsigned char)c)) return 0;
  }
  return has_colon;
}

/* 一般地址字面量：TAG:payload，TAG = 1*(ALPHA / DIGIT / '-') */
static int looks_like_general_literal(const char *s) {
  if (!s || !*s) return 0;
  const char *p = s;
  if (!isalnum((unsigned char)*p) && *p != '-') return 0;
  for (; *p && *p != ':'; ++p) {
    if (!isalnum((unsigned char)*p) && *p != '-') return 0;
  }
  return (*p == ':'); /* 有冒号 */
}


/* 规范化一个 address-literal：
   - 若未带 []，加上；
   - 若 IPv6 未以 "IPv6:" 开头，则在 [] 内补 "IPv6:"；
   - 其它情况保持原样。
   输入 domain（可为 [..] 或裸字面量），输出到 out（带 []）。
*/
static void normalize_addr_literal(const char *domain, char out[], size_t out_cap) {
  char inner[SMTP_SZ_DOMAIN];
  int had_brackets = inside_brackets(domain, inner, sizeof inner);
  if (!had_brackets) {
    set_cstr(inner, sizeof inner, domain);
  }
  strip_spaces(inner);

  /* IPv6: 若是 IPv6 但未带 IPv6: 前缀，补上 */
  if (looks_like_ipv6_core(inner) && !starts_with_ci(inner, "IPv6:")) {
    char tmp[SMTP_SZ_DOMAIN];
    set_cstr(tmp, sizeof tmp, "IPv6:");
    strncat(tmp, inner, sizeof(tmp) - 1 - strlen(tmp));
    set_cstr(inner, sizeof inner, tmp);
  }

  /* 包上 [] */
  if (out_cap) {
    if (strlen(inner) + 2 >= out_cap) {
      /* 溢出保护：尽力而为 */
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

/* 解析并重建 path（用于 MAIL/RCPT）：
   < [route:] local [ @ domain ] >
   这里只做最小必要解析以替换 domain 为 address-literal 的规范形式。 */
static void fix_path_mailbox_domain_literal(char *path_buf, size_t cap) {
  if (!path_buf || cap == 0) return;

  /* 找到尖括号内的内容 */
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

  /* route:mailbox，取最后一个 ':' 右边做 mailbox（若无则全为 mailbox） */
  const char *route_end = strrchr(inner, ':');
  const char *mb = route_end ? route_end + 1 : inner;

  /* mailbox = local [@ domain] */
  const char *at = strchr(mb, '@');
  if (!at) {
    /* 无 domain，无需处理 address-literal 规则（Postmaster、<> 等） */
    return;
  }

  /* 拆 local 与 domain（原样裁剪两端空白） */
  char route[SMTP_SZ_PATH], local[SMTP_SZ_PATH], domain[SMTP_SZ_PATH];
  if (route_end) {
    size_t rlen = (size_t)(route_end - inner + 1); /* 包含 ':' */
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

  { /* domain —— 可能已有 [] 或裸字面量 */
    const char *db = at + 1;
    size_t dlen = strlen(db);
    if (dlen >= sizeof domain) dlen = sizeof domain - 1;
    memcpy(domain, db, dlen); domain[dlen] = '\0';
    strip_spaces(domain);
  }

  if (is_address_literal(domain)) {
    char dom_norm[SMTP_SZ_DOMAIN];
    normalize_addr_literal(domain, dom_norm, sizeof dom_norm);

    /* 重建 inner 到一个缓冲，然后写回 path_buf 中的 <...> */
    char rebuilt[SMTP_SZ_PATH];
    set_cstr(rebuilt, sizeof rebuilt, route);
    strncat(rebuilt, local, sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, "@", sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, dom_norm, sizeof(rebuilt) - 1 - strlen(rebuilt));

    /* 把 rebuilt 写回原来的 <...> 范围 */
    /* 如果长度变化，会改动 path_buf 中 <> 内的内容，<> 外侧不动 */
    size_t new_len = strlen(rebuilt);
    size_t prefix_len = (size_t)(L + 1 - path_buf);
    size_t suffix_len = strlen(R); /* 包括右尖括号及后续 */
    if (prefix_len + new_len + suffix_len >= cap) {
      /* 长度不够，尽力而为：截断 rebuilt */
      new_len = cap - 1 - prefix_len - suffix_len;
    }
    memmove(path_buf + prefix_len, rebuilt, new_len);
    memmove(path_buf + prefix_len + new_len, R, suffix_len);
    path_buf[prefix_len + new_len + suffix_len] = '\0';
  }
}

/* 对 HELO/EHLO 的 domain 规范化 address-literal 形态 */
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

/* --------------- 主修复器 --------------- */
/* 返回 0 成功；-1 参数无效 */
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
        /* 其它指令不涉及本规则 */
        break;
    }
  }
  return 0;
}


/* 将单个 label 规范化为 LDH：只保留 [A-Za-z0-9-]，非法字符折叠为单个 '-'，
   去除首尾 '-'，若结果为空则用 "a" 占位；转为小写。 */
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

  /* 去首尾 '-' */
  size_t b = 0, e = w;
  while (b < e && tmp[b] == '-') ++b;
  while (e > b && tmp[e-1] == '-') --e;

  if (e <= b) { /* 空标签：放置占位符 */
    set_cstr(out, cap, "a");
    return;
  }

  size_t n = e - b;
  if (n >= cap) n = cap - 1;
  memcpy(out, tmp + b, n);
  out[n] = '\0';
}

/* 将域名（非 address-literal）按 '.' 拆分并逐标签 LDH 规范化；
   连续 '.' 造成的空标签会被替换为占位标签（"a"）；保留原有的末尾 '.'（若存在）。 */
static void sanitize_domain_ldh(const char *domain_in, char *out, size_t cap) {
  if (!out || cap == 0) return;

  /* address-literal 则不处理 */
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
      /* seg..p-1 是一个 label（可能为空） */
      if (p == seg) {
        set_cstr(label, sizeof label, "a");      /* 空标签 -> 占位 */
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

/* 修复 MAIL/RCPT 路径中的邮箱域名（若为 address-literal 则跳过） */
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

  /* route:mailbox，取最后一个 ':' 右边做 mailbox（若无则全为 mailbox） */
  const char *route_end = strrchr(inner, ':');
  const char *mb = route_end ? route_end + 1 : inner;

  /* mailbox = local [@ domain] —— 用最后一个 '@' */
  const char *at = strrchr(mb, '@');
  if (!at) return; /* 无域名，不处理 */

  char route[SMTP_SZ_PATH], local[SMTP_SZ_PATH], domain[SMTP_SZ_PATH];
  if (route_end) {
    size_t rlen = (size_t)(route_end - inner + 1); /* 含 ':' */
    if (rlen >= sizeof route) rlen = sizeof route - 1;
    memcpy(route, inner, rlen); route[rlen] = '\0';
  } else route[0] = '\0';

  { /* local */
    size_t llen = (size_t)(at - mb);
    if (llen >= sizeof local) llen = sizeof local - 1;
    memcpy(local, mb, llen); local[llen] = '\0';
    strip_spaces(local);
  }

  { /* domain（可能是 address-literal，如 [1.2.3.4]） */
    const char *db = at + 1;
    size_t dlen = strlen(db);
    if (dlen >= sizeof domain) dlen = sizeof domain - 1;
    memcpy(domain, db, dlen); domain[dlen] = '\0';
    strip_spaces(domain);
  }

  /* address-literal 则跳过（由 4.1.3 规则处理） */
  if (!inside_brackets(domain, NULL, 0)) {
    char dom_ldh[SMTP_SZ_DOMAIN];
    sanitize_domain_ldh(domain, dom_ldh, sizeof dom_ldh);

    char rebuilt[SMTP_SZ_PATH];
    set_cstr(rebuilt, sizeof rebuilt, route);
    strncat(rebuilt, local, sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, "@", sizeof(rebuilt) - 1 - strlen(rebuilt));
    strncat(rebuilt, dom_ldh, sizeof(rebuilt) - 1 - strlen(rebuilt));

    /* 写回到原始 <...> 中 */
    size_t new_len = strlen(rebuilt);
    size_t prefix_len = (size_t)(L + 1 - path_buf);
    size_t suffix_len = strlen(R); /* 含右尖括号及其后续 */
    if (prefix_len + new_len + suffix_len >= cap) {
      if (new_len > cap - 1 - prefix_len - suffix_len)
        new_len = cap - 1 - prefix_len - suffix_len;
    }
    memmove(path_buf + prefix_len, rebuilt, new_len);
    memmove(path_buf + prefix_len + new_len, R, suffix_len);
    path_buf[prefix_len + new_len + suffix_len] = '\0';
  }
}

/* 修复问候命令中的 domain（非 address-literal） */
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

/* ---------- 主修复器：SMTP-2.3.5-DOMAIN-SYNTAX ---------- */
/* 返回 0 成功；-1 参数无效 */
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
        /* 其他报文不含需处理的域名 */
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
