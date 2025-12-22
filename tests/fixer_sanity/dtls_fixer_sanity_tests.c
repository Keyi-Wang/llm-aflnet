// dtls_fixer_sanity_tests.c
// Auto-generated-ish test suite for dtls_fixers.c based on dtls_constraints.txt (SHOT-* rules).
//
// How it works:
// - Build a small dtls_packet_t array directly (no parser).
// - Intentionally violate a constraint targeted by a specific fix_*().
// - Call that fixer.
// - Assert the post-state (oracle) satisfies the SHOT constraint.
//
// Notes:
// - We include dtls_fixers.c directly to access its internal static fix_*() helpers.
// - Place this file at: tests/fixer_sanity/dtls_fixer_sanity_tests.c
//   (or adjust the include path below accordingly)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Include the implementation under test (gives us access to internal static fix_*). */
#include "../../llm/dtls/dtls_fixers.c"

/* ---------------- tiny test framework ---------------- */

#define ARR_LEN(x) ((int)(sizeof(x) / sizeof((x)[0])))

static int g_verbose = 0;

#define T_FAIL(fmt, ...) do { \
  fprintf(stderr, "    [FAIL] " fmt "\n", ##__VA_ARGS__); \
  return 1; \
} while (0)

#define T_ASSERT(cond, fmt, ...) do { \
  if (!(cond)) T_FAIL(fmt, ##__VA_ARGS__); \
} while (0)

static void dump_seq(const dtls_packet_t *pkts, size_t n) {
  if (!g_verbose) return;
  fprintf(stderr, "    seq dump (n=%zu):\n", n);
  for (size_t i = 0; i < n; i++) {
    const dtls_packet_t *p = &pkts[i];
    fprintf(stderr, "      [%zu] kind=%d type=%u epoch=%u ", i, (int)p->kind, (unsigned)p->record_header.type, (unsigned)p->record_header.epoch);
    if (p->kind == DTLS_PKT_HANDSHAKE) {
      fprintf(stderr, "hs.msg_type=%u msg_seq=%u\n",
              (unsigned)p->payload.handshake.handshake_header.msg_type,
              (unsigned)p->payload.handshake.handshake_header.message_seq);
    } else if (p->kind == DTLS_PKT_APPLICATION_DATA) {
      fprintf(stderr, "app.len=%u\n", (unsigned)p->payload.application_data.data_len);
    } else if (p->kind == DTLS_PKT_CHANGE_CIPHER_SPEC) {
      fprintf(stderr, "ccs.value=%u\n", (unsigned)p->payload.change_cipher_spec.value);
    } else if (p->kind == DTLS_PKT_ALERT) {
      fprintf(stderr, "alert.level=%u desc=%u\n",
              (unsigned)p->payload.alert.level, (unsigned)p->payload.alert.description);
    } else {
      fprintf(stderr, "\n");
    }
  }
}

/* ---------------- packet constructors ---------------- */

static void clear_pkts(dtls_packet_t *pkts, size_t n) { memset(pkts, 0, n * sizeof(*pkts)); }

static void make_epoch0_hs(dtls_packet_t *p, uint8_t msg_type) {
  memset(p, 0, sizeof(*p));
  p->kind = DTLS_PKT_HANDSHAKE;
  p->record_header.type = 22; /* handshake */
  p->record_header.epoch = 0;

  p->payload.handshake.handshake_header.msg_type = msg_type;
  /* default: length=0, frag_offset=0, frag_len=0; message_seq maybe overwritten */
  wr_u24(p->payload.handshake.handshake_header.length.b, 0);
  wr_u24(p->payload.handshake.handshake_header.fragment_offset.b, 0);
  wr_u24(p->payload.handshake.handshake_header.fragment_length.b, 0);
  p->payload.handshake.handshake_header.message_seq = 0;
}

static void make_client_hello(dtls_packet_t *p) {
  make_epoch0_hs(p, 1);
  dtls_client_hello_t *ch = &p->payload.handshake.body.client_hello;

  /* DTLS 1.2 is 0xFE 0xFD; TLS 1.2 handshake version equivalent */
  ch->client_version.major = 0xFE;
  ch->client_version.minor = 0xFD;

  /* default offers: 0x002F, 0x0035 */
  ch->cipher_suites_len = 4;
  ch->cipher_suites[0] = 0x00; ch->cipher_suites[1] = 0x2F;
  ch->cipher_suites[2] = 0x00; ch->cipher_suites[3] = 0x35;

  ch->compression_methods_len = 1;
  ch->compression_methods[0] = 0x00;

  ch->session_id.len = 0;
  ch->cookie_len = 0;

  ch->extensions.present = 0;
  ch->extensions.total_len = 0;

  /* handshake header length (not used by fixers except fragment canonicalization) */
  wr_u24(p->payload.handshake.handshake_header.length.b, 0);
  wr_u24(p->payload.handshake.handshake_header.fragment_length.b, 0);
}

static void make_server_hello(dtls_packet_t *p) {
  make_epoch0_hs(p, 2);
  dtls_server_hello_t *sh = &p->payload.handshake.body.server_hello;
  /* set to DTLS 1.2 initially */
  sh->server_version.major = 0xFE;
  sh->server_version.minor = 0xFD;
  sh->session_id.len = 0;
  sh->cipher_suite = 0x002F;
  sh->compression_method = 0x00;
  sh->extensions.present = 0;
  sh->extensions.total_len = 0;
}

static void make_hvr(dtls_packet_t *p) {
  make_epoch0_hs(p, 3);
  dtls_hello_verify_request_t *hv = &p->payload.handshake.body.hello_verify_request;
  hv->server_version.major = 0xFE;
  hv->server_version.minor = 0xFD;
  hv->cookie_len = 0;
}

static void make_finished(dtls_packet_t *p) {
  make_epoch0_hs(p, 20);
  /* verify_data is fixed-size in struct; nothing to set */
  wr_u24(p->payload.handshake.handshake_header.length.b, 12);
  wr_u24(p->payload.handshake.handshake_header.fragment_length.b, 12);
}

static void make_ccs(dtls_packet_t *p, uint8_t value) {
  memset(p, 0, sizeof(*p));
  p->kind = DTLS_PKT_CHANGE_CIPHER_SPEC;
  p->record_header.type = 20;
  p->record_header.epoch = 0;
  p->payload.change_cipher_spec.value = value;
}

static void make_appdata_epoch0(dtls_packet_t *p, uint16_t len) {
  memset(p, 0, sizeof(*p));
  p->kind = DTLS_PKT_APPLICATION_DATA;
  p->record_header.type = 23;
  p->record_header.epoch = 0;
  p->payload.application_data.data_len = len;
  for (uint16_t i = 0; i < len && i < DTLS_MAX_APPDATA_LEN; i++) p->payload.application_data.data[i] = (uint8_t)(i & 0xff);
}

static void make_alert(dtls_packet_t *p, uint8_t level, uint8_t desc, uint8_t set_type21) {
  memset(p, 0, sizeof(*p));
  p->kind = DTLS_PKT_ALERT;
  p->record_header.type = set_type21 ? 21 : 0; /* can intentionally violate */
  p->record_header.epoch = 0;
  p->payload.alert.level = level;
  p->payload.alert.description = desc;
}

/* ---------------- oracles (assertions) ---------------- */

static int oracle_clienthello_cipher_suites_len(const dtls_packet_t *p) {
  const dtls_client_hello_t *ch = &p->payload.handshake.body.client_hello;
  T_ASSERT(ch->cipher_suites_len >= 2, "cipher_suites_len < 2: %u", (unsigned)ch->cipher_suites_len);
  T_ASSERT((ch->cipher_suites_len & 1u) == 0, "cipher_suites_len not even: %u", (unsigned)ch->cipher_suites_len);
  T_ASSERT(ch->cipher_suites_len <= (u16)(DTLS_MAX_CIPHER_SUITES_BYTES & (u16)~1u),
           "cipher_suites_len too large after fix: %u", (unsigned)ch->cipher_suites_len);
  return 0;
}

static int oracle_clienthello_compression_methods(const dtls_packet_t *p) {
  const dtls_client_hello_t *ch = &p->payload.handshake.body.client_hello;
  T_ASSERT(ch->compression_methods_len >= 1, "compression_methods_len == 0");
  T_ASSERT(ch->compression_methods_len <= DTLS_MAX_COMPRESSION_METHODS_LEN,
           "compression_methods_len too large: %u", (unsigned)ch->compression_methods_len);
  return 0;
}

static int oracle_extensions_len(const dtls_extensions_block_t *ext) {
  if (!ext->present) {
    T_ASSERT(ext->total_len == 0, "extensions.present=0 but total_len=%u", (unsigned)ext->total_len);
  } else {
    T_ASSERT(ext->total_len <= DTLS_MAX_EXTENSIONS_LEN, "extensions.total_len too big: %u", (unsigned)ext->total_len);
  }
  return 0;
}

static int oracle_clienthello_session_id_len(const dtls_packet_t *p) {
  const dtls_client_hello_t *ch = &p->payload.handshake.body.client_hello;
  T_ASSERT(ch->session_id.len <= DTLS_MAX_SESSION_ID_LEN, "session_id.len too big: %u", (unsigned)ch->session_id.len);
  return 0;
}

static int oracle_cookie_len(const dtls_client_hello_t *ch) {
  T_ASSERT(ch->cookie_len <= DTLS_MAX_COOKIE_LEN, "cookie_len too big: %u", (unsigned)ch->cookie_len);
  return 0;
}

static int oracle_ccs_value(const dtls_packet_t *p) {
  T_ASSERT(p->kind == DTLS_PKT_CHANGE_CIPHER_SPEC, "not CCS kind after fix");
  T_ASSERT(p->record_header.type == 20, "CCS record type not 20: %u", (unsigned)p->record_header.type);
  T_ASSERT(p->payload.change_cipher_spec.value == 0x01, "CCS value != 0x01: %u", (unsigned)p->payload.change_cipher_spec.value);
  return 0;
}

static int oracle_finished_after_ccs(const dtls_packet_t *pkts, size_t n) {
  int fin = find_first_finished(pkts, n);
  T_ASSERT(fin >= 0, "no Finished found");
  T_ASSERT(fin - 1 >= 0, "Finished at idx0, cannot have CCS before");
  oracle_ccs_value(&pkts[fin - 1]);
  return 0;
}

static int oracle_no_appdata_before_finished(const dtls_packet_t *pkts, size_t n) {
  int fin = find_first_finished(pkts, n);
  if (fin < 0) return 0;
  for (int i = 0; i < fin; i++) {
    T_ASSERT(!is_appdata_epoch0(&pkts[i]), "appdata found before Finished at idx=%d", i);
  }
  return 0;
}

static int oracle_monotonic_message_seq(const dtls_packet_t *pkts, size_t n) {
  u16 expect = 0;
  for (size_t i = 0; i < n; i++) {
    if (is_plaintext_handshake_epoch0(&pkts[i])) {
      u16 got = pkts[i].payload.handshake.handshake_header.message_seq;
      T_ASSERT(got == expect, "message_seq not monotonic: idx=%zu got=%u expect=%u", i, (unsigned)got, (unsigned)expect);
      expect++;
    }
  }
  return 0;
}

static int oracle_fragment_canonical(const dtls_packet_t *p) {
  T_ASSERT(is_plaintext_handshake_epoch0(p), "expected epoch0 handshake");
  const dtls_handshake_header_t *hh = &p->payload.handshake.handshake_header;
  u32 len = rd_u24(hh->length.b);
  u32 off = rd_u24(hh->fragment_offset.b);
  u32 fl  = rd_u24(hh->fragment_length.b);
  T_ASSERT(off == 0, "fragment_offset != 0: %u", (unsigned)off);
  T_ASSERT(fl == len, "fragment_length(%u) != length(%u)", (unsigned)fl, (unsigned)len);
  return 0;
}

static int oracle_server_version_le_client(const dtls_packet_t *pkts, size_t n) {
  /* derive from first ClientHello */
  int idx = find_first_client_hello(pkts, n);
  T_ASSERT(idx >= 0, "no ClientHello found");
  const dtls_client_hello_t *ch = &pkts[idx].payload.handshake.body.client_hello;

  int sh_idx = find_first_server_hello(pkts, n);
  T_ASSERT(sh_idx >= 0, "no ServerHello found");
  const dtls_server_hello_t *sh = &pkts[sh_idx].payload.handshake.body.server_hello;

  /* lexicographic compare */
  T_ASSERT(sh->server_version.major < ch->client_version.major ||
           (sh->server_version.major == ch->client_version.major && sh->server_version.minor <= ch->client_version.minor),
           "server_version (%u.%u) > client_version (%u.%u)",
           (unsigned)sh->server_version.major, (unsigned)sh->server_version.minor,
           (unsigned)ch->client_version.major, (unsigned)ch->client_version.minor);
  return 0;
}

static int oracle_serverhello_session_id_len(const dtls_server_hello_t *sh) {
  T_ASSERT(sh->session_id.len <= DTLS_MAX_SESSION_ID_LEN, "server session_id.len too big: %u", (unsigned)sh->session_id.len);
  return 0;
}

static int oracle_server_cipher_suite_from_client(const dtls_packet_t *pkts, size_t n) {
  int ch_idx = find_first_client_hello(pkts, n);
  int sh_idx = find_first_server_hello(pkts, n);
  T_ASSERT(ch_idx >= 0 && sh_idx >= 0, "need ClientHello and ServerHello");
  const dtls_client_hello_t *ch = &pkts[ch_idx].payload.handshake.body.client_hello;
  const dtls_server_hello_t *sh = &pkts[sh_idx].payload.handshake.body.server_hello;

  T_ASSERT(ch->cipher_suites_len >= 2 && (ch->cipher_suites_len & 1u) == 0, "client cipher_suites_len invalid");
  T_ASSERT(u16_in_u16be_list(sh->cipher_suite, ch->cipher_suites, ch->cipher_suites_len), "server cipher_suite not in client list");
  return 0;
}

static int oracle_server_compression_from_client(const dtls_packet_t *pkts, size_t n) {
  int ch_idx = find_first_client_hello(pkts, n);
  int sh_idx = find_first_server_hello(pkts, n);
  T_ASSERT(ch_idx >= 0 && sh_idx >= 0, "need ClientHello and ServerHello");
  const dtls_client_hello_t *ch = &pkts[ch_idx].payload.handshake.body.client_hello;
  const dtls_server_hello_t *sh = &pkts[sh_idx].payload.handshake.body.server_hello;

  T_ASSERT(ch->compression_methods_len >= 1, "client compression_methods_len invalid");
  T_ASSERT(u8_in_list(sh->compression_method, ch->compression_methods, ch->compression_methods_len), "server compression_method not in client list");
  return 0;
}

static int oracle_hvr_cookie_len(const dtls_hello_verify_request_t *hv) {
  T_ASSERT(hv->cookie_len <= DTLS_MAX_COOKIE_LEN, "HVR cookie_len too big: %u", (unsigned)hv->cookie_len);
  return 0;
}

static int oracle_hvr_version_le_client(const dtls_packet_t *pkts, size_t n) {
  int ch_idx = find_first_client_hello(pkts, n);
  T_ASSERT(ch_idx >= 0, "no ClientHello");
  const dtls_client_hello_t *ch = &pkts[ch_idx].payload.handshake.body.client_hello;

  /* find first HVR */
  int hv_idx = -1;
  for (size_t i = 0; i < n; i++) {
    if (is_plaintext_handshake_epoch0(&pkts[i]) &&
        pkts[i].payload.handshake.handshake_header.msg_type == 3) { hv_idx = (int)i; break; }
  }
  T_ASSERT(hv_idx >= 0, "no HelloVerifyRequest");
  const dtls_hello_verify_request_t *hv = &pkts[hv_idx].payload.handshake.body.hello_verify_request;

  T_ASSERT(hv->server_version.major < ch->client_version.major ||
           (hv->server_version.major == ch->client_version.major && hv->server_version.minor <= ch->client_version.minor),
           "HVR version (%u.%u) > client version (%u.%u)",
           (unsigned)hv->server_version.major, (unsigned)hv->server_version.minor,
           (unsigned)ch->client_version.major, (unsigned)ch->client_version.minor);
  return 0;
}

static int oracle_certreq_before_shd(const dtls_packet_t *pkts, size_t n) {
  int cr = -1, shd = -1;
  for (size_t i = 0; i < n; i++) {
    if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
    u8 t = pkts[i].payload.handshake.handshake_header.msg_type;
    if (t == 13 && cr < 0) cr = (int)i;
    if (t == 14 && shd < 0) shd = (int)i;
  }
  if (cr >= 0 && shd >= 0) {
    T_ASSERT(cr < shd, "CertificateRequest idx=%d not before ServerHelloDone idx=%d", cr, shd);
  }
  return 0;
}

static int oracle_certreq_cert_types_nonempty(const dtls_certificate_request_t *cr) {
  T_ASSERT(cr->cert_types_len >= 1, "cert_types_len is 0");
  T_ASSERT(cr->cert_types_len <= DTLS_MAX_CERT_TYPES_LEN, "cert_types_len too big: %u", (unsigned)cr->cert_types_len);
  return 0;
}

static int oracle_certreq_sig_algs_even(const dtls_certificate_request_t *cr) {
  T_ASSERT(cr->sig_algs_len <= DTLS_MAX_SIG_ALGS_LEN, "sig_algs_len too big: %u", (unsigned)cr->sig_algs_len);
  T_ASSERT((cr->sig_algs_len & 1u) == 0, "sig_algs_len not even: %u", (unsigned)cr->sig_algs_len);
  return 0;
}

static int oracle_certreq_ca_dn_len(const dtls_certificate_request_t *cr) {
  T_ASSERT(cr->ca_dn_len <= DTLS_MAX_CA_DN_LEN, "ca_dn_len too big: %u", (unsigned)cr->ca_dn_len);
  return 0;
}

/* ---------------- per-fixer tests ---------------- */

/* Each test returns 0 (pass) or 1 (fail). */
typedef int (*test_fn_t)(void);
typedef struct {
  const char *fixer;
  const char *name;
  test_fn_t fn;
} test_case_t;

static int test_fix_c2s_shot_0_clienthello_first_swap(void) {
  dtls_packet_t pkts[3]; clear_pkts(pkts, ARR_LEN(pkts));
  make_epoch0_hs(&pkts[0], 2); /* pretend some other hs first */
  make_client_hello(&pkts[1]);
  make_epoch0_hs(&pkts[2], 20);
  dump_seq(pkts, ARR_LEN(pkts));
  fix_c2s_shot_0_clienthello_first(pkts, ARR_LEN(pkts));
  dump_seq(pkts, ARR_LEN(pkts));
  T_ASSERT(pkts[0].payload.handshake.handshake_header.msg_type == 1, "ClientHello not moved to first hs position");
  return 0;
}

static int test_fix_c2s_shot_2_cipher_suites_len_min_and_even(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->cipher_suites_len = 1; /* invalid */
  fix_c2s_shot_2_clienthello_cipher_suites_len(pkts, 1);
  oracle_clienthello_cipher_suites_len(&pkts[0]);
  T_ASSERT(ch->cipher_suites_len == 2, "expected cipher_suites_len==2 when too small, got %u", (unsigned)ch->cipher_suites_len);
  T_ASSERT(ch->cipher_suites[0] == 0x00 && ch->cipher_suites[1] == 0x2F, "expected default 0x002F inserted");
  return 0;
}

static int test_fix_c2s_shot_2_cipher_suites_len_odd_trim(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->cipher_suites_len = 3; /* odd */
  fix_c2s_shot_2_clienthello_cipher_suites_len(pkts, 1);
  oracle_clienthello_cipher_suites_len(&pkts[0]);
  T_ASSERT(ch->cipher_suites_len == 2, "expected trim odd len to 2, got %u", (unsigned)ch->cipher_suites_len);
  return 0;
}

static int test_fix_c2s_shot_2_cipher_suites_len_clamp(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->cipher_suites_len = (u16)(DTLS_MAX_CIPHER_SUITES_BYTES + 20);
  fix_c2s_shot_2_clienthello_cipher_suites_len(pkts, 1);
  oracle_clienthello_cipher_suites_len(&pkts[0]);
  return 0;
}

static int test_fix_c2s_shot_3_compression_methods_nonempty(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->compression_methods_len = 0;
  fix_c2s_shot_3_clienthello_compression_methods(pkts, 1);
  oracle_clienthello_compression_methods(&pkts[0]);
  T_ASSERT(ch->compression_methods[0] == 0x00, "expected default null compression");
  return 0;
}

static int test_fix_c2s_shot_4_extensions_len_present0_zeroed(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->extensions.present = 0;
  ch->extensions.total_len = 123; /* inconsistent */
  fix_c2s_shot_4_clienthello_extensions_len(pkts, 1);
  oracle_extensions_len(&ch->extensions);
  return 0;
}

static int test_fix_c2s_shot_4_extensions_len_clamp(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->extensions.present = 1;
  ch->extensions.total_len = (u16)(DTLS_MAX_EXTENSIONS_LEN + 50);
  fix_c2s_shot_4_clienthello_extensions_len(pkts, 1);
  oracle_extensions_len(&ch->extensions);
  return 0;
}

static int test_fix_c2s_shot_6_session_id_len_clamp(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->session_id.len = (u8)(DTLS_MAX_SESSION_ID_LEN + 7);
  fix_c2s_shot_6_clienthello_session_id_len(pkts, 1);
  oracle_clienthello_session_id_len(&pkts[0]);
  return 0;
}

static int test_fix_c2s_shot_11_cookie_len_clamp(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_client_hello_t *ch = &pkts[0].payload.handshake.body.client_hello;
  ch->cookie_len = (u8)(DTLS_MAX_COOKIE_LEN + 7);
  fix_c2s_shot_11_clienthello_cookie_len(pkts, 1);
  oracle_cookie_len(ch);
  return 0;
}

static int test_fix_c2s_shot_23_ccs_before_finished_create(void) {
  dtls_packet_t pkts[3]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_epoch0_hs(&pkts[1], 2); /* some handshake, will be converted */
  make_finished(&pkts[2]);
  fix_c2s_shot_23_ccs_before_finished(pkts, ARR_LEN(pkts));
  oracle_finished_after_ccs(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_c2s_shot_23_ccs_before_finished_move_existing(void) {
  dtls_packet_t pkts[3]; clear_pkts(pkts, ARR_LEN(pkts));
  make_ccs(&pkts[0], 0x00);
  make_client_hello(&pkts[1]);
  make_finished(&pkts[2]);
  fix_c2s_shot_23_ccs_before_finished(pkts, ARR_LEN(pkts));
  /* CCS should now be right before Finished */
  oracle_finished_after_ccs(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_c2s_shot_24_ccs_value_fix_all(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_ccs(&pkts[0], 0x99);
  make_ccs(&pkts[1], 0x00);
  pkts[1].record_header.type = 0; /* also wrong */
  fix_c2s_shot_24_ccs_value(pkts, ARR_LEN(pkts));
  oracle_ccs_value(&pkts[0]);
  oracle_ccs_value(&pkts[1]);
  return 0;
}

static int test_fix_c2s_shot_30_34_no_appdata_before_done(void) {
  dtls_packet_t pkts[3]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_appdata_epoch0(&pkts[1], 10);
  make_finished(&pkts[2]);
  fix_c2s_shot_30_34_no_appdata_before_done(pkts, ARR_LEN(pkts));
  oracle_no_appdata_before_finished(pkts, ARR_LEN(pkts));
  /* After move, appdata should be last element */
  T_ASSERT(is_appdata_epoch0(&pkts[2]), "expected appdata moved to end");
  return 0;
}

static int test_fix_c2s_shot_31_monotonic_message_seq(void) {
  dtls_packet_t pkts[4]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]); pkts[0].payload.handshake.handshake_header.message_seq = 10;
  make_epoch0_hs(&pkts[1], 2); pkts[1].payload.handshake.handshake_header.message_seq = 99;
  make_ccs(&pkts[2], 1); /* not handshake */
  make_finished(&pkts[3]); pkts[3].payload.handshake.handshake_header.message_seq = 7;
  fix_c2s_shot_31_monotonic_message_seq(pkts, ARR_LEN(pkts));
  oracle_monotonic_message_seq(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_c2s_shot_32_fragment_length_ok(void) {
  dtls_packet_t pkts[1]; make_client_hello(&pkts[0]);
  dtls_handshake_header_t *hh = &pkts[0].payload.handshake.handshake_header;
  wr_u24(hh->length.b, 10);
  wr_u24(hh->fragment_offset.b, 3);
  wr_u24(hh->fragment_length.b, 20); /* invalid */
  fix_c2s_shot_32_fragment_length_ok(pkts, 1);
  oracle_fragment_canonical(&pkts[0]);
  return 0;
}

/* -------- server side -------- */

static int test_fix_s2c_shot_0_serverhello_first_swap(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_epoch0_hs(&pkts[0], 14); /* ServerHelloDone */
  make_server_hello(&pkts[1]);
  fix_s2c_shot_0_serverhello_first(pkts, ARR_LEN(pkts));
  T_ASSERT(pkts[0].payload.handshake.handshake_header.msg_type == 2, "ServerHello not moved to first hs position");
  return 0;
}

static int test_fix_s2c_shot_1_server_version_le_client(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_server_hello(&pkts[1]);
  dtls_server_hello_t *sh = &pkts[1].payload.handshake.body.server_hello;
  sh->server_version.major = 0xFF; sh->server_version.minor = 0xFF; /* higher than client */
  fix_s2c_shot_1_server_version_le_client(pkts, ARR_LEN(pkts));
  oracle_server_version_le_client(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_s2c_shot_3_serverhello_session_id_len_clamp(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_server_hello(&pkts[1]);
  dtls_server_hello_t *sh = &pkts[1].payload.handshake.body.server_hello;
  sh->session_id.len = (u8)(DTLS_MAX_SESSION_ID_LEN + 9);
  fix_s2c_shot_3_serverhello_session_id_len(pkts, ARR_LEN(pkts));
  oracle_serverhello_session_id_len(sh);
  return 0;
}

static int test_fix_s2c_shot_4_server_cipher_suite_from_client(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_server_hello(&pkts[1]);
  dtls_server_hello_t *sh = &pkts[1].payload.handshake.body.server_hello;
  sh->cipher_suite = 0x9999; /* not offered */
  fix_s2c_shot_4_serverhello_cipher_suite_from_client(pkts, ARR_LEN(pkts));
  oracle_server_cipher_suite_from_client(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_s2c_shot_5_server_compression_from_client(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_server_hello(&pkts[1]);
  dtls_server_hello_t *sh = &pkts[1].payload.handshake.body.server_hello;
  sh->compression_method = 1; /* not offered (client only offers 0) */
  fix_s2c_shot_5_serverhello_compression_from_client(pkts, ARR_LEN(pkts));
  oracle_server_compression_from_client(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_s2c_shot_6_serverhello_extensions_len(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_server_hello(&pkts[1]);
  dtls_server_hello_t *sh = &pkts[1].payload.handshake.body.server_hello;
  sh->extensions.present = 0;
  sh->extensions.total_len = 17;
  fix_s2c_shot_6_serverhello_extensions_len(pkts, ARR_LEN(pkts));
  oracle_extensions_len(&sh->extensions);
  sh->extensions.present = 1;
  sh->extensions.total_len = (u16)(DTLS_MAX_EXTENSIONS_LEN + 5);
  fix_s2c_shot_6_serverhello_extensions_len(pkts, ARR_LEN(pkts));
  oracle_extensions_len(&sh->extensions);
  return 0;
}

static int test_fix_s2c_shot_10_hvr_cookie_len(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_hvr(&pkts[1]);
  dtls_hello_verify_request_t *hv = &pkts[1].payload.handshake.body.hello_verify_request;
  hv->cookie_len = (u8)(DTLS_MAX_COOKIE_LEN + 1);
  fix_s2c_shot_10_hvr_cookie_len(pkts, ARR_LEN(pkts));
  oracle_hvr_cookie_len(hv);
  return 0;
}

static int test_fix_s2c_shot_11_hvr_version_le_client(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_client_hello(&pkts[0]);
  make_hvr(&pkts[1]);
  dtls_hello_verify_request_t *hv = &pkts[1].payload.handshake.body.hello_verify_request;
  hv->server_version.major = 0xFF;
  hv->server_version.minor = 0xFF;
  fix_s2c_shot_11_hvr_version_le_client(pkts, ARR_LEN(pkts));
  oracle_hvr_version_le_client(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_s2c_shot_22_certreq_before_shd(void) {
  dtls_packet_t pkts[2]; clear_pkts(pkts, ARR_LEN(pkts));
  make_epoch0_hs(&pkts[0], 14); /* ServerHelloDone */
  make_epoch0_hs(&pkts[1], 13); /* CertificateRequest */
  fix_s2c_shot_22_certreq_before_shd(pkts, ARR_LEN(pkts));
  oracle_certreq_before_shd(pkts, ARR_LEN(pkts));
  return 0;
}

static int test_fix_s2c_shot_23_certreq_cert_types_nonempty(void) {
  dtls_packet_t pkts[1]; make_epoch0_hs(&pkts[0], 13);
  dtls_certificate_request_t *cr = &pkts[0].payload.handshake.body.certificate_request;
  cr->cert_types_len = 0;
  fix_s2c_shot_23_certreq_cert_types_nonempty(pkts, 1);
  oracle_certreq_cert_types_nonempty(cr);

  cr->cert_types_len = (u8)(DTLS_MAX_CERT_TYPES_LEN + 10);
  fix_s2c_shot_23_certreq_cert_types_nonempty(pkts, 1);
  oracle_certreq_cert_types_nonempty(cr);
  return 0;
}

static int test_fix_s2c_shot_24_certreq_sig_algs_even(void) {
  dtls_packet_t pkts[1]; make_epoch0_hs(&pkts[0], 13);
  dtls_certificate_request_t *cr = &pkts[0].payload.handshake.body.certificate_request;
  cr->sig_algs_len = 255; /* odd */
  fix_s2c_shot_24_certreq_sig_algs_even(pkts, 1);
  oracle_certreq_sig_algs_even(cr);

  cr->sig_algs_len = (u16)(DTLS_MAX_SIG_ALGS_LEN + 9);
  fix_s2c_shot_24_certreq_sig_algs_even(pkts, 1);
  oracle_certreq_sig_algs_even(cr);
  return 0;
}

static int test_fix_s2c_shot_25_certreq_ca_dn_len(void) {
  dtls_packet_t pkts[1]; make_epoch0_hs(&pkts[0], 13);
  dtls_certificate_request_t *cr = &pkts[0].payload.handshake.body.certificate_request;
  cr->ca_dn_len = (u16)(DTLS_MAX_CA_DN_LEN + 77);
  fix_s2c_shot_25_certreq_ca_dn_len(pkts, 1);
  oracle_certreq_ca_dn_len(cr);
  return 0;
}

static int test_fix_s2c_shot_35_36_seq_and_frag(void) {
  dtls_packet_t pkts[3]; clear_pkts(pkts, ARR_LEN(pkts));
  make_server_hello(&pkts[0]);
  make_epoch0_hs(&pkts[1], 12); /* Certificate */
  make_epoch0_hs(&pkts[2], 14); /* ServerHelloDone */
  /* violate message_seq and fragment fields */
  pkts[0].payload.handshake.handshake_header.message_seq = 9;
  pkts[1].payload.handshake.handshake_header.message_seq = 2;
  pkts[2].payload.handshake.handshake_header.message_seq = 1;
  wr_u24(pkts[1].payload.handshake.handshake_header.length.b, 20);
  wr_u24(pkts[1].payload.handshake.handshake_header.fragment_offset.b, 7);
  wr_u24(pkts[1].payload.handshake.handshake_header.fragment_length.b, 3);

  fix_s2c_shot_35_36_dtls_seq_and_frag(pkts, ARR_LEN(pkts));
  oracle_monotonic_message_seq(pkts, ARR_LEN(pkts));
  oracle_fragment_canonical(&pkts[1]);
  return 0;
}

static int test_fix_s2c_shot_38_alert_two_bytes_smoke(void) {
  dtls_packet_t pkts[1]; make_alert(&pkts[0], 2, 40, 1);
  fix_s2c_shot_38_alert_two_bytes(pkts, 1);
  /* oracle: alert shape is already 2 bytes; just ensure it didn't corrupt */
  T_ASSERT(pkts[0].payload.alert.level == 2 && pkts[0].payload.alert.description == 40, "alert bytes corrupted");
  return 0;
}

static int test_fix_s2c_shot_40_no_appdata_before_done(void) {
  dtls_packet_t pkts[4]; clear_pkts(pkts, ARR_LEN(pkts));
  make_server_hello(&pkts[0]);
  make_appdata_epoch0(&pkts[1], 5);
  make_epoch0_hs(&pkts[2], 14); /* ServerHelloDone */
  make_finished(&pkts[3]);
  fix_s2c_shot_40_no_appdata_before_done(pkts, ARR_LEN(pkts));
  oracle_no_appdata_before_finished(pkts, ARR_LEN(pkts));
  return 0;
}

/* -------- aggregated dispatcher test (fix_dtls) -------- */

static int test_fix_dtls_c2s_aggregate_many_violations(void) {
  dtls_packet_t pkts[5]; clear_pkts(pkts, ARR_LEN(pkts));
  /* C2S-only sequence: ClientHello not first, missing CCS, appdata early, bad lengths/seq/frags */
  make_epoch0_hs(&pkts[0], 16);       /* ClientKeyExchange (C2S) */
  make_appdata_epoch0(&pkts[1], 9999);/* too big + before Finished */
  make_client_hello(&pkts[2]);
  make_finished(&pkts[3]);           /* Finished without CCS before it */
  make_epoch0_hs(&pkts[4], 15);       /* CertificateVerify (C2S) */

  /* violate ClientHello constraints */
  dtls_client_hello_t *ch = &pkts[2].payload.handshake.body.client_hello;
  ch->cipher_suites_len = 1;
  ch->compression_methods_len = 0;
  ch->session_id.len = (u8)(DTLS_MAX_SESSION_ID_LEN + 1);
  ch->cookie_len = (u8)(DTLS_MAX_COOKIE_LEN + 1);
  ch->extensions.present = 0;
  ch->extensions.total_len = 77;

  /* violate message_seq and fragments */
  pkts[0].payload.handshake.handshake_header.message_seq = 7;
  pkts[2].payload.handshake.handshake_header.message_seq = 9;
  pkts[3].payload.handshake.handshake_header.message_seq = 1;
  pkts[4].payload.handshake.handshake_header.message_seq = 2;

  wr_u24(pkts[4].payload.handshake.handshake_header.length.b, 10);
  wr_u24(pkts[4].payload.handshake.handshake_header.fragment_offset.b, 5);
  wr_u24(pkts[4].payload.handshake.handshake_header.fragment_length.b, 1);

  dump_seq(pkts, ARR_LEN(pkts));
  fix_dtls(pkts, ARR_LEN(pkts));
  dump_seq(pkts, ARR_LEN(pkts));

  /* C2S invariants */
  T_ASSERT(find_first_client_hello(pkts, ARR_LEN(pkts)) == 0, "ClientHello not first after fix_dtls (c2s)");
  if (oracle_clienthello_cipher_suites_len(&pkts[0])) return 1;
  if (oracle_clienthello_compression_methods(&pkts[0])) return 1;
  if (oracle_clienthello_session_id_len(&pkts[0])) return 1;
  if (oracle_cookie_len(&pkts[0].payload.handshake.body.client_hello)) return 1;
  if (oracle_extensions_len(&pkts[0].payload.handshake.body.client_hello.extensions)) return 1;

  if (oracle_finished_after_ccs(pkts, ARR_LEN(pkts))) return 1;
  if (oracle_no_appdata_before_finished(pkts, ARR_LEN(pkts))) return 1;
  if (oracle_monotonic_message_seq(pkts, ARR_LEN(pkts))) return 1;
  /* find the handshake we intentionally broke (msg_type=15) and validate fragment canonicalization */
  int frag_idx = -1;
  for (int i = 0; i < ARR_LEN(pkts); i++) {
    if (is_plaintext_handshake_epoch0(&pkts[i]) &&
        pkts[i].payload.handshake.handshake_header.msg_type == 15) { frag_idx = i; break; }
  }
  T_ASSERT(frag_idx >= 0, "cannot find msg_type=15 handshake to check fragments");
  if (oracle_fragment_canonical(&pkts[frag_idx])) return 1;

  /* appdata length should be clamped */
  for (int i = 0; i < ARR_LEN(pkts); i++) {
    if (pkts[i].kind == DTLS_PKT_APPLICATION_DATA) {
      T_ASSERT(pkts[i].payload.application_data.data_len <= DTLS_MAX_APPDATA_LEN, "appdata len not clamped");
    }
  }

  return 0;
}

static int test_fix_dtls_s2c_aggregate_many_violations(void) {
  dtls_packet_t pkts[6]; clear_pkts(pkts, ARR_LEN(pkts));
  /* S2C-only sequence: ServerHello not first, certreq after shd, missing CCS, appdata early, bad cert fields */
  make_epoch0_hs(&pkts[0], 14); /* ServerHelloDone */
  make_appdata_epoch0(&pkts[1], 7777);
  make_server_hello(&pkts[2]);
  make_epoch0_hs(&pkts[3], 13); /* CertificateRequest */
  make_finished(&pkts[4]);      /* Finished without CCS */
  make_epoch0_hs(&pkts[5], 12); /* Certificate */

  /* violate certreq constraints */
  dtls_certificate_request_t *cr = &pkts[3].payload.handshake.body.certificate_request;
  cr->cert_types_len = 0;
  cr->sig_algs_len = 255;
  cr->ca_dn_len = (u16)(DTLS_MAX_CA_DN_LEN + 1);

  /* violate message_seq and fragments */
  pkts[0].payload.handshake.handshake_header.message_seq = 10;
  pkts[2].payload.handshake.handshake_header.message_seq = 8;
  pkts[3].payload.handshake.handshake_header.message_seq = 99;
  pkts[4].payload.handshake.handshake_header.message_seq = 1;
  pkts[5].payload.handshake.handshake_header.message_seq = 2;

  wr_u24(pkts[5].payload.handshake.handshake_header.length.b, 20);
  wr_u24(pkts[5].payload.handshake.handshake_header.fragment_offset.b, 7);
  wr_u24(pkts[5].payload.handshake.handshake_header.fragment_length.b, 3);

  dump_seq(pkts, ARR_LEN(pkts));
  fix_dtls(pkts, ARR_LEN(pkts));
  dump_seq(pkts, ARR_LEN(pkts));

  /* S2C invariants */
  T_ASSERT(find_first_server_hello(pkts, ARR_LEN(pkts)) == 0, "ServerHello not first after fix_dtls (s2c)");

  if (oracle_certreq_before_shd(pkts, ARR_LEN(pkts))) return 1;

    /* If CertificateRequest still exists after CCS/Finished repair, verify its fields. */
  int certreq_idx = -1;
  for (int i = 0; i < ARR_LEN(pkts); i++) {
    if (is_plaintext_handshake_epoch0(&pkts[i]) &&
        pkts[i].payload.handshake.handshake_header.msg_type == 13) { certreq_idx = i; break; }
  }
  if (certreq_idx >= 0) {
    cr = &pkts[certreq_idx].payload.handshake.body.certificate_request;
    if (oracle_certreq_cert_types_nonempty(cr)) return 1;
    if (oracle_certreq_sig_algs_even(cr)) return 1;
    if (oracle_certreq_ca_dn_len(cr)) return 1;
  }

  if (oracle_finished_after_ccs(pkts, ARR_LEN(pkts))) return 1;
  if (oracle_no_appdata_before_finished(pkts, ARR_LEN(pkts))) return 1;
  if (oracle_monotonic_message_seq(pkts, ARR_LEN(pkts))) return 1;
  /* find the handshake we intentionally broke (msg_type=12) and validate fragment canonicalization */
  int frag_idx = -1;
  for (int i = 0; i < ARR_LEN(pkts); i++) {
    if (is_plaintext_handshake_epoch0(&pkts[i]) &&
        pkts[i].payload.handshake.handshake_header.msg_type == 12) { frag_idx = i; break; }
  }
  if (frag_idx >= 0) {
    if (oracle_fragment_canonical(&pkts[frag_idx])) return 1;
  }

  /* appdata length should be clamped */
  for (int i = 0; i < ARR_LEN(pkts); i++) {
    if (pkts[i].kind == DTLS_PKT_APPLICATION_DATA) {
      T_ASSERT(pkts[i].payload.application_data.data_len <= DTLS_MAX_APPDATA_LEN, "appdata len not clamped");
    }
  }

  return 0;
}

/* ---------------- registry ---------------- */


static test_case_t g_tests[] = {
  {"fix_c2s_shot_0_clienthello_first", "swap ClientHello to first", test_fix_c2s_shot_0_clienthello_first_swap},

  {"fix_c2s_shot_2_clienthello_cipher_suites_len", "min>=2 and even", test_fix_c2s_shot_2_cipher_suites_len_min_and_even},
  {"fix_c2s_shot_2_clienthello_cipher_suites_len", "trim odd length", test_fix_c2s_shot_2_cipher_suites_len_odd_trim},
  {"fix_c2s_shot_2_clienthello_cipher_suites_len", "clamp to max", test_fix_c2s_shot_2_cipher_suites_len_clamp},

  {"fix_c2s_shot_3_clienthello_compression_methods", "ensure nonempty", test_fix_c2s_shot_3_compression_methods_nonempty},

  {"fix_c2s_shot_4_clienthello_extensions_len", "present=0 total_len=0", test_fix_c2s_shot_4_extensions_len_present0_zeroed},
  {"fix_c2s_shot_4_clienthello_extensions_len", "clamp total_len when present", test_fix_c2s_shot_4_extensions_len_clamp},

  {"fix_c2s_shot_6_clienthello_session_id_len", "clamp session_id.len", test_fix_c2s_shot_6_session_id_len_clamp},
  {"fix_c2s_shot_11_clienthello_cookie_len", "clamp cookie_len", test_fix_c2s_shot_11_cookie_len_clamp},

  {"fix_c2s_shot_23_ccs_before_finished", "create CCS before Finished", test_fix_c2s_shot_23_ccs_before_finished_create},
  {"fix_c2s_shot_23_ccs_before_finished", "move existing CCS to before Finished", test_fix_c2s_shot_23_ccs_before_finished_move_existing},
  {"fix_c2s_shot_24_ccs_value", "force CCS byte to 0x01", test_fix_c2s_shot_24_ccs_value_fix_all},

  {"fix_c2s_shot_30_34_no_appdata_before_done", "move appdata after Finished", test_fix_c2s_shot_30_34_no_appdata_before_done},
  {"fix_c2s_shot_31_monotonic_message_seq", "monotonic message_seq", test_fix_c2s_shot_31_monotonic_message_seq},
  {"fix_c2s_shot_32_fragment_length_ok", "canonicalize fragments", test_fix_c2s_shot_32_fragment_length_ok},

  {"fix_s2c_shot_0_serverhello_first", "swap ServerHello to first", test_fix_s2c_shot_0_serverhello_first_swap},
  {"fix_s2c_shot_1_server_version_le_client", "clamp server_version", test_fix_s2c_shot_1_server_version_le_client},
  {"fix_s2c_shot_3_serverhello_session_id_len", "clamp session_id.len", test_fix_s2c_shot_3_serverhello_session_id_len_clamp},
  {"fix_s2c_shot_4_serverhello_cipher_suite_from_client", "cipher_suite from client list", test_fix_s2c_shot_4_server_cipher_suite_from_client},
  {"fix_s2c_shot_5_serverhello_compression_from_client", "compression from client list", test_fix_s2c_shot_5_server_compression_from_client},
  {"fix_s2c_shot_6_serverhello_extensions_len", "extensions len", test_fix_s2c_shot_6_serverhello_extensions_len},

  {"fix_s2c_shot_10_hvr_cookie_len", "clamp HVR cookie_len", test_fix_s2c_shot_10_hvr_cookie_len},
  {"fix_s2c_shot_11_hvr_version_le_client", "clamp HVR version", test_fix_s2c_shot_11_hvr_version_le_client},

  {"fix_s2c_shot_22_certreq_before_shd", "reorder certreq before shd", test_fix_s2c_shot_22_certreq_before_shd},
  {"fix_s2c_shot_23_certreq_cert_types_nonempty", "cert_types nonempty", test_fix_s2c_shot_23_certreq_cert_types_nonempty},
  {"fix_s2c_shot_24_certreq_sig_algs_even", "sig_algs even", test_fix_s2c_shot_24_certreq_sig_algs_even},
  {"fix_s2c_shot_25_certreq_ca_dn_len", "ca_dn_len clamp", test_fix_s2c_shot_25_certreq_ca_dn_len},

  {"fix_s2c_shot_35_36_dtls_seq_and_frag", "monotonic seq and canonical fragments", test_fix_s2c_shot_35_36_seq_and_frag},
  {"fix_s2c_shot_38_alert_two_bytes", "alert smoke", test_fix_s2c_shot_38_alert_two_bytes_smoke},
  {"fix_s2c_shot_40_no_appdata_before_done", "no appdata before Finished", test_fix_s2c_shot_40_no_appdata_before_done},

  {"fix_dtls", "aggregate (c2s): multiple violations", test_fix_dtls_c2s_aggregate_many_violations},
  {"fix_dtls", "aggregate (s2c): multiple violations", test_fix_dtls_s2c_aggregate_many_violations},
};

static int is_same_fixer(const char *a, const char *b) {
  if (!a || !b) return 0;
  return strcmp(a, b) == 0;
}

static void usage(const char *argv0) {
  fprintf(stderr,
    "Usage: %s [--verbose] [--out <dir>]\n"
    "\n"
    "Outputs:\n"
    "  <out>/illegal_fixers.txt  list of fixers that have at least one failing test\n",
    argv0);
}

int main(int argc, char **argv) {
  const char *out_dir = "out_fixer_sanity_dtls";
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--verbose")) {
      g_verbose = 1;
    } else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
      out_dir = argv[++i];
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "[!] unknown arg: %s\n", argv[i]);
      usage(argv[0]);
      return 2;
    }
  }

  /* Run tests, grouped by fixer name */
  int total = ARR_LEN(g_tests);
  int failed_cases = 0;

  /* Track illegal fixers (by name) */
  const char *illegal[256];
  int illegal_cnt = 0;

  fprintf(stderr, "[*] running %d test cases...\n", total);

  for (int ti = 0; ti < total; ti++) {
    test_case_t *tc = &g_tests[ti];
    if (g_verbose) fprintf(stderr, "[*] %s :: %s\n", tc->fixer, tc->name);

    int rc = tc->fn();
    if (rc != 0) {
      failed_cases++;
      fprintf(stderr, "[!] %s FAILED: %s\n", tc->fixer, tc->name);

      /* add fixer to illegal list if not exists */
      int seen = 0;
      for (int j = 0; j < illegal_cnt; j++) {
        if (is_same_fixer(illegal[j], tc->fixer)) { seen = 1; break; }
      }
      if (!seen && illegal_cnt < (int)ARR_LEN(illegal)) illegal[illegal_cnt++] = tc->fixer;
    } else {
      if (g_verbose) fprintf(stderr, "    [OK]\n");
    }
  }

  /* write outputs */
  (void)mkdir(out_dir, 0777);
  char out_path[512];
  snprintf(out_path, sizeof(out_path), "%s/illegal_fixers.txt", out_dir);
  FILE *fp = fopen(out_path, "w");
  if (fp) {
    for (int i = 0; i < illegal_cnt; i++) fprintf(fp, "%s\n", illegal[i]);
    fclose(fp);
  } else {
    fprintf(stderr, "[!] failed to write %s\n", out_path);
  }

  fprintf(stderr, "[*] done. failed_cases=%d, illegal_fixers=%d\n", failed_cases, illegal_cnt);
  if (illegal_cnt) {
    fprintf(stderr, "[*] illegal fixers:\n");
    for (int i = 0; i < illegal_cnt; i++) fprintf(stderr, "    - %s\n", illegal[i]);
  }
  fprintf(stderr, "[*] output: %s\n", out_path);

  return illegal_cnt ? 1 : 0;
}
