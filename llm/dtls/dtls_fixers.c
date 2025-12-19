/* dtls fixers source file */
#include "dtls.h"

/* ===================== dtls_fixers.c =====================
 * Fixers for constraints listed in dtls_constraints.txt
 * Input: dtls_packet_t array (pkts, count). Fix in place.
 *
 * NOTE:
 * - Some constraints require cryptographic validation or negotiated state not represented
 *   in dtls_packet_t; those fixers are implemented as no-ops.
 * - We still try best-effort structural / ordering / length / enum fixes.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* --------- minimal aliases (used by your codebase elsewhere) --------- */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* --------- paste-in struct definitions are assumed available via dtls.h --------- */
/* If you compile this standalone, include your dtls.h instead of redefining. */

/* ---------------- local helpers ---------------- */

static u16 rd_u16(const u8 *p) { return (u16)(((u16)p[0] << 8) | (u16)p[1]); }
static void wr_u16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)(v & 0xff); }

static u32 rd_u24(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2]; }
static void wr_u24(u8 *p, u32 v) {
    p[0] = (u8)((v >> 16) & 0xff);
    p[1] = (u8)((v >> 8) & 0xff);
    p[2] = (u8)(v & 0xff);
}

static int is_plaintext_handshake_epoch0(const dtls_packet_t *p) {
    return p && p->kind == DTLS_PKT_HANDSHAKE && p->record_header.type == 22 && p->record_header.epoch == 0;
}
static int is_ccs(const dtls_packet_t *p) {
    return p && p->kind == DTLS_PKT_CHANGE_CIPHER_SPEC && p->record_header.type == 20;
}
static int is_appdata_epoch0(const dtls_packet_t *p) {
    return p && p->kind == DTLS_PKT_APPLICATION_DATA && p->record_header.type == 23 && p->record_header.epoch == 0;
}
static int is_alert(const dtls_packet_t *p) { return p && p->kind == DTLS_PKT_ALERT && p->record_header.type == 21; }

static u16 clamp_u16(u16 v, u16 lo, u16 hi) { return (v < lo) ? lo : (v > hi) ? hi : v; }
static u8  clamp_u8(u8 v, u8 lo, u8 hi) { return (v < lo) ? lo : (v > hi) ? hi : v; }

static void swap_pkts(dtls_packet_t *a, dtls_packet_t *b) {
    if (!a || !b || a == b) return;
    dtls_packet_t tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Find first ClientHello (handshake msg_type==1) in epoch0 plaintext. */
static int find_first_client_hello(const dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i]) &&
            pkts[i].payload.handshake.handshake_header.msg_type == 1) return (int)i;
    }
    return -1;
}

/* Find first ServerHello (msg_type==2). */
static int find_first_server_hello(const dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i]) &&
            pkts[i].payload.handshake.handshake_header.msg_type == 2) return (int)i;
    }
    return -1;
}

/* Find first Finished (msg_type==20). */
static int find_first_finished(const dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i]) &&
            pkts[i].payload.handshake.handshake_header.msg_type == 20) return (int)i;
    }
    return -1;
}

/* Find nearest CCS before index (exclusive). */
static int find_ccs_before(const dtls_packet_t *pkts, size_t n, int idx_exclusive) {
    if (idx_exclusive <= 0) return -1;
    int end = idx_exclusive;
    if (end > (int)n) end = (int)n;
    for (int i = end - 1; i >= 0; i--) {
        if (is_ccs(&pkts[i])) return i;
    }
    return -1;
}

/* Best-effort: derive offered cipher suites / compression methods from first ClientHello. */
static int get_client_offers(const dtls_packet_t *pkts, size_t n,
                             const u8 **cs, u16 *cs_len,
                             const u8 **cm, u8 *cm_len,
                             u8 *ch_maj, u8 *ch_min) {
    int idx = find_first_client_hello(pkts, n);
    if (idx < 0) return -1;
    const dtls_client_hello_t *ch = &pkts[idx].payload.handshake.body.client_hello;

    if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES) return -1;
    if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN) return -1;

    if (cs) *cs = ch->cipher_suites;
    if (cs_len) *cs_len = ch->cipher_suites_len;

    if (cm) *cm = ch->compression_methods;
    if (cm_len) *cm_len = ch->compression_methods_len;

    if (ch_maj) *ch_maj = ch->client_version.major;
    if (ch_min) *ch_min = ch->client_version.minor;

    return 0;
}

static int u16_in_u16be_list(u16 v, const u8 *list, u16 list_len) {
    if (!list) return 0;
    if ((list_len & 1u) != 0) return 0;
    for (u16 i = 0; i + 1 < list_len; i += 2) {
        u16 x = rd_u16(list + i);
        if (x == v) return 1;
    }
    return 0;
}

static int u8_in_list(u8 v, const u8 *list, u16 list_len) {
    if (!list) return 0;
    for (u16 i = 0; i < list_len; i++) if (list[i] == v) return 1;
    return 0;
}

/* Stable partition: move all application_data (epoch0) that occur before first Finished to after it. */
static void move_appdata_after_finished(dtls_packet_t *pkts, size_t n) {
    int fin = find_first_finished(pkts, n);
    if (fin < 0) return;

    /* Simple O(n^2) stable shift for small sequences typical in fuzzing. */
    for (int i = 0; i < fin; i++) {
        if (is_appdata_epoch0(&pkts[i])) {
            dtls_packet_t tmp = pkts[i];
            for (int j = i; j < (int)n - 1; j++) pkts[j] = pkts[j + 1];
            pkts[n - 1] = tmp;
            fin--; /* finished index shifts left by 1 */
            i--;   /* re-check current index */
        }
    }
}

/* Canonicalize DTLS handshake fragmentation header: offset=0, frag_length=length. */
static void canonicalize_handshake_fragment(dtls_packet_t *p) {
    if (!is_plaintext_handshake_epoch0(p)) return;
    dtls_handshake_header_t *hh = &p->payload.handshake.handshake_header;
    u32 len = rd_u24(hh->length.b);
    wr_u24(hh->fragment_offset.b, 0);
    wr_u24(hh->fragment_length.b, len);
}

/* Ensure message_seq is monotonically increasing across epoch0 handshake packets. */
static void fix_monotonic_message_seq(dtls_packet_t *pkts, size_t n) {
    u16 seq = 0;
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i])) {
            pkts[i].payload.handshake.handshake_header.message_seq = seq++;
        }
    }
}

/* Ensure ChangeCipherSpec payload is 0x01 and record header fields are consistent enough. */
static void fix_ccs_value(dtls_packet_t *p) {
    if (!p) return;
    if (p->kind != DTLS_PKT_CHANGE_CIPHER_SPEC) return;
    p->record_header.type = 20;
    p->payload.change_cipher_spec.value = 0x01;
}

/* Ensure Alert is exactly 2 bytes structurally (we only have 2 bytes in struct). */
static void fix_alert_shape(dtls_packet_t *p) {
    if (!p || !is_alert(p)) return;
    p->record_header.type = 21;
    /* level/description already 1 byte each; nothing else to fix here. */
}

/* Ensure ApplicationData length fits buffer (epoch0 only). */
static void fix_appdata_len(dtls_packet_t *p) {
    if (!p || p->kind != DTLS_PKT_APPLICATION_DATA) return;
    if (p->payload.application_data.data_len > DTLS_MAX_APPDATA_LEN)
        p->payload.application_data.data_len = DTLS_MAX_APPDATA_LEN;
    p->record_header.type = 23;
}

/* ===================== Client-to-Server constraint fixers ===================== */

/* SHOT-0: ClientHello MUST be first client handshake message. */
static void fix_c2s_shot_0_clienthello_first(dtls_packet_t *pkts, size_t n) {
    int ch = find_first_client_hello(pkts, n);
    if (ch < 0) return;
    /* Find first epoch0 handshake index */
    int first_hs = -1;
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i])) { first_hs = (int)i; break; }
    }
    if (first_hs >= 0 && ch != first_hs) swap_pkts(&pkts[ch], &pkts[first_hs]);
}

/* SHOT-2: CipherSuite list length >=2 and multiple of 2. */
static void fix_c2s_shot_2_clienthello_cipher_suites_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 1) continue;
        dtls_client_hello_t *ch = &pkts[i].payload.handshake.body.client_hello;

        if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES)
            ch->cipher_suites_len = DTLS_MAX_CIPHER_SUITES_BYTES & (u16)~1u;

        if ((ch->cipher_suites_len & 1u) != 0) ch->cipher_suites_len--;

        if (ch->cipher_suites_len < 2) {
            ch->cipher_suites_len = 2;
            /* best-effort common TLS 1.2 suite: 0x002F (TLS_RSA_WITH_AES_128_CBC_SHA) */
            ch->cipher_suites[0] = 0x00;
            ch->cipher_suites[1] = 0x2F;
        }
    }
}

/* SHOT-3: CompressionMethods list must contain at least one method. */
static void fix_c2s_shot_3_clienthello_compression_methods(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 1) continue;
        dtls_client_hello_t *ch = &pkts[i].payload.handshake.body.client_hello;

        if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN)
            ch->compression_methods_len = DTLS_MAX_COMPRESSION_METHODS_LEN;

        if (ch->compression_methods_len == 0) {
            ch->compression_methods_len = 1;
            ch->compression_methods[0] = 0x00; /* null compression */
        }
    }
}

/* SHOT-4: If extensions present, length-prefixed correctly. */
static void fix_c2s_shot_4_clienthello_extensions_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 1) continue;
        dtls_client_hello_t *ch = &pkts[i].payload.handshake.body.client_hello;

        if (!ch->extensions.present) {
            ch->extensions.total_len = 0;
            continue;
        }
        if (ch->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN)
            ch->extensions.total_len = DTLS_MAX_EXTENSIONS_LEN;
    }
}


/* SHOT-6: SessionID length 0..32. */
static void fix_c2s_shot_6_clienthello_session_id_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 1) continue;
        dtls_client_hello_t *ch = &pkts[i].payload.handshake.body.client_hello;
        if (ch->session_id.len > DTLS_MAX_SESSION_ID_LEN) ch->session_id.len = DTLS_MAX_SESSION_ID_LEN;
    }
}



/* SHOT-11: cookie length 0..255. */
static void fix_c2s_shot_11_clienthello_cookie_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 1) continue;
        dtls_client_hello_t *ch = &pkts[i].payload.handshake.body.client_hello;
        if (ch->cookie_len > DTLS_MAX_COOKIE_LEN) ch->cookie_len = DTLS_MAX_COOKIE_LEN;
    }
}


/* SHOT-23: Client MUST send CCS immediately before Finished. */
static void fix_c2s_shot_23_ccs_before_finished(dtls_packet_t *pkts, size_t n) {
    int fin = find_first_finished(pkts, n);
    if (fin < 0) return;

    /* ensure there is a CCS just before fin */
    if (fin - 1 >= 0 && is_ccs(&pkts[fin - 1])) {
        fix_ccs_value(&pkts[fin - 1]);
        return;
    }

    int ccs = find_ccs_before(pkts, n, fin);
    if (ccs >= 0) {
        /* move CCS to fin-1 by swapping adjacent */
        for (int i = ccs; i < fin - 1; i++) swap_pkts(&pkts[i], &pkts[i + 1]);
        fix_ccs_value(&pkts[fin - 1]);
        return;
    }

    /* no CCS exists: convert the packet immediately before Finished into CCS */
    if (fin - 1 >= 0) {
        dtls_packet_t *p = &pkts[fin - 1];
        p->kind = DTLS_PKT_CHANGE_CIPHER_SPEC;
        p->record_header.type = 20;
        p->payload.change_cipher_spec.value = 0x01;
    }
}

/* SHOT-24: CCS must be single byte 0x01. */
static void fix_c2s_shot_24_ccs_value(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) fix_ccs_value(&pkts[i]);
}

/* SHOT-25: Finished immediately after CCS. (Handled by SHOT-23 best-effort). */
static void fix_c2s_shot_25_finished_after_ccs(dtls_packet_t *pkts, size_t n) { fix_c2s_shot_23_ccs_before_finished(pkts, n); }



/* SHOT-28/29: handshake ordering; enforce partial: ensure ClientHello first among epoch0 handshake. */
static void fix_c2s_shot_28_29_handshake_order(dtls_packet_t *pkts, size_t n) {
    fix_c2s_shot_0_clienthello_first(pkts, n);
}

/* SHOT-30/34: Application Data MUST NOT be sent before handshake complete. */
static void fix_c2s_shot_30_34_no_appdata_before_done(dtls_packet_t *pkts, size_t n) {
    move_appdata_after_finished(pkts, n);
}

/* SHOT-31: monotonically increasing message_seq. */
static void fix_c2s_shot_31_monotonic_message_seq(dtls_packet_t *pkts, size_t n) {
    fix_monotonic_message_seq(pkts, n);
}

/* SHOT-32: fragment_length must not exceed total length. We'll canonicalize frag fields. */
static void fix_c2s_shot_32_fragment_length_ok(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) canonicalize_handshake_fragment(&pkts[i]);
}


/* ===================== Server-to-Client constraint fixers ===================== */

/* SHOT-0: ServerHello MUST be first server handshake message. */
static void fix_s2c_shot_0_serverhello_first(dtls_packet_t *pkts, size_t n) {
    int sh = find_first_server_hello(pkts, n);
    if (sh < 0) return;

    int first_hs = -1;
    for (size_t i = 0; i < n; i++) {
        if (is_plaintext_handshake_epoch0(&pkts[i])) { first_hs = (int)i; break; }
    }
    if (first_hs >= 0 && sh != first_hs) swap_pkts(&pkts[sh], &pkts[first_hs]);
}

/* SHOT-1: server_version <= client_version. */
static void fix_s2c_shot_1_server_version_le_client(dtls_packet_t *pkts, size_t n) {
    u8 ch_maj = 0, ch_min = 0;
    if (get_client_offers(pkts, n, NULL, NULL, NULL, NULL, &ch_maj, &ch_min) != 0) return;

    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 2) continue;
        dtls_server_hello_t *sh = &pkts[i].payload.handshake.body.server_hello;

        /* compare (major,minor) lexicographically */
        if (sh->server_version.major > ch_maj ||
            (sh->server_version.major == ch_maj && sh->server_version.minor > ch_min)) {
            sh->server_version.major = ch_maj;
            sh->server_version.minor = ch_min;
        }
    }
}

/* SHOT-2/3: random fixed size; session_id len 0..32. */
static void fix_s2c_shot_3_serverhello_session_id_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 2) continue;
        dtls_server_hello_t *sh = &pkts[i].payload.handshake.body.server_hello;
        if (sh->session_id.len > DTLS_MAX_SESSION_ID_LEN) sh->session_id.len = DTLS_MAX_SESSION_ID_LEN;
    }
}

/* SHOT-4: server cipher_suite selected from client-offered list. */
static void fix_s2c_shot_4_serverhello_cipher_suite_from_client(dtls_packet_t *pkts, size_t n) {
    const u8 *cs = NULL; u16 cs_len = 0;
    if (get_client_offers(pkts, n, &cs, &cs_len, NULL, NULL, NULL, NULL) != 0) return;
    if (cs_len < 2 || (cs_len & 1u)) return;

    u16 first = rd_u16(cs);
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 2) continue;
        dtls_server_hello_t *sh = &pkts[i].payload.handshake.body.server_hello;

        if (!u16_in_u16be_list(sh->cipher_suite, cs, cs_len))
            sh->cipher_suite = first;
    }
}

/* SHOT-5: server compression_method from client list. */
static void fix_s2c_shot_5_serverhello_compression_from_client(dtls_packet_t *pkts, size_t n) {
    const u8 *cm = NULL; u8 cm_len = 0;
    if (get_client_offers(pkts, n, NULL, NULL, &cm, &cm_len, NULL, NULL) != 0) return;
    if (cm_len == 0) return;

    u8 first = cm[0];
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 2) continue;
        dtls_server_hello_t *sh = &pkts[i].payload.handshake.body.server_hello;

        if (!u8_in_list(sh->compression_method, cm, cm_len))
            sh->compression_method = first;
    }
}

/* SHOT-6: ServerHello extensions length-prefixed. */
static void fix_s2c_shot_6_serverhello_extensions_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 2) continue;
        dtls_server_hello_t *sh = &pkts[i].payload.handshake.body.server_hello;

        if (!sh->extensions.present) {
            sh->extensions.total_len = 0;
            continue;
        }
        if (sh->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN)
            sh->extensions.total_len = DTLS_MAX_EXTENSIONS_LEN;
    }
}


/* SHOT-10: HVR cookie len 0..255. */
static void fix_s2c_shot_10_hvr_cookie_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 3) continue;
        dtls_hello_verify_request_t *hv = &pkts[i].payload.handshake.body.hello_verify_request;
        if (hv->cookie_len > DTLS_MAX_COOKIE_LEN) hv->cookie_len = DTLS_MAX_COOKIE_LEN;
    }
}

/* SHOT-11: HVR server_version <= client_version. */
static void fix_s2c_shot_11_hvr_version_le_client(dtls_packet_t *pkts, size_t n) {
    u8 ch_maj = 0, ch_min = 0;
    if (get_client_offers(pkts, n, NULL, NULL, NULL, NULL, &ch_maj, &ch_min) != 0) return;

    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 3) continue;
        dtls_hello_verify_request_t *hv = &pkts[i].payload.handshake.body.hello_verify_request;

        if (hv->server_version.major > ch_maj ||
            (hv->server_version.major == ch_maj && hv->server_version.minor > ch_min)) {
            hv->server_version.major = ch_maj;
            hv->server_version.minor = ch_min;
        }
    }
}

/* SHOT-22: If CertificateRequest is sent, it MUST appear before ServerHelloDone. (best-effort reorder) */
static void fix_s2c_shot_22_certreq_before_shd(dtls_packet_t *pkts, size_t n) {
    int cr = -1, shd = -1;
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        u8 t = pkts[i].payload.handshake.handshake_header.msg_type;
        if (t == 13 && cr < 0) cr = (int)i;
        if (t == 14 && shd < 0) shd = (int)i;
    }
    if (cr >= 0 && shd >= 0 && cr > shd) swap_pkts(&pkts[cr], &pkts[shd]);
}

/* SHOT-23: CertificateRequest.cert_types list MUST NOT be empty. */
static void fix_s2c_shot_23_certreq_cert_types_nonempty(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 13) continue;
        dtls_certificate_request_t *cr = &pkts[i].payload.handshake.body.certificate_request;

        if (cr->cert_types_len == 0) {
            cr->cert_types_len = 1;
            cr->cert_types[0] = 1; /* best-effort: rsa_sign (TLS client_certificate_type) */
        } else if (cr->cert_types_len > DTLS_MAX_CERT_TYPES_LEN) {
            cr->cert_types_len = DTLS_MAX_CERT_TYPES_LEN;
        }
    }
}

/* SHOT-24: sig_algs length must be even, valid pairs (we can enforce even + clamp). */
static void fix_s2c_shot_24_certreq_sig_algs_even(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 13) continue;
        dtls_certificate_request_t *cr = &pkts[i].payload.handshake.body.certificate_request;

        if (cr->sig_algs_len > DTLS_MAX_SIG_ALGS_LEN) cr->sig_algs_len = DTLS_MAX_SIG_ALGS_LEN;
        if ((cr->sig_algs_len & 1u) != 0) cr->sig_algs_len--;
    }
}

/* SHOT-25: ca_dn_list may be empty but length-prefixed. We only store ca_dn_len+blob; clamp. */
static void fix_s2c_shot_25_certreq_ca_dn_len(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!is_plaintext_handshake_epoch0(&pkts[i])) continue;
        if (pkts[i].payload.handshake.handshake_header.msg_type != 13) continue;
        dtls_certificate_request_t *cr = &pkts[i].payload.handshake.body.certificate_request;

        if (cr->ca_dn_len > DTLS_MAX_CA_DN_LEN) cr->ca_dn_len = DTLS_MAX_CA_DN_LEN;
    }
}

/* SHOT-28/29: Server CCS before its Finished; CCS value 0x01. */
static void fix_s2c_shot_28_29_server_ccs_before_finished(dtls_packet_t *pkts, size_t n) {
    /* same best-effort as client */
    fix_c2s_shot_23_ccs_before_finished(pkts, n);
    fix_c2s_shot_24_ccs_value(pkts, n);
}

/* SHOT-30/31: Server Finished after CCS; verify_data len 12 (struct). */
static void fix_s2c_shot_30_31_server_finished_after_ccs(dtls_packet_t *pkts, size_t n) {
    fix_s2c_shot_28_29_server_ccs_before_finished(pkts, n);
}

/* SHOT-33: server handshake ordering (partial: ServerHello first). */
static void fix_s2c_shot_33_34_server_order_and_no_appdata(dtls_packet_t *pkts, size_t n) {
    fix_s2c_shot_0_serverhello_first(pkts, n);
    move_appdata_after_finished(pkts, n);
}

/* SHOT-35/36/37: DTLS server sequencing/retransmit; we can fix monotonic message_seq + canonical fragments. */
static void fix_s2c_shot_35_36_dtls_seq_and_frag(dtls_packet_t *pkts, size_t n) {
    fix_monotonic_message_seq(pkts, n);
    for (size_t i = 0; i < n; i++) canonicalize_handshake_fragment(&pkts[i]);
}

/* SHOT-38: alert exactly two bytes (struct). keep type. */
static void fix_s2c_shot_38_alert_two_bytes(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) fix_alert_shape(&pkts[i]);
}

/* SHOT-40: no appdata before handshake complete. */
static void fix_s2c_shot_40_no_appdata_before_done(dtls_packet_t *pkts, size_t n) {
    move_appdata_after_finished(pkts, n);
}

/* ===================== Common structural fixers ===================== */

static void fix_common_lengths_and_kinds(dtls_packet_t *pkts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];

        /* clamp common fields depending on kind */
        if (p->kind == DTLS_PKT_APPLICATION_DATA) {
            fix_appdata_len(p);
        } else if (p->kind == DTLS_PKT_CHANGE_CIPHER_SPEC) {
            fix_ccs_value(p);
        } else if (p->kind == DTLS_PKT_ALERT) {
            fix_alert_shape(p);
        } else if (p->kind == DTLS_PKT_ENCRYPTED) {
            if (p->payload.encrypted.ciphertext_len > DTLS_MAX_CIPHERTEXT_LEN)
                p->payload.encrypted.ciphertext_len = DTLS_MAX_CIPHERTEXT_LEN;
        }

        /* handshake fragment fields canonicalization (safe) */
        if (is_plaintext_handshake_epoch0(p)) {
            canonicalize_handshake_fragment(p);
        }
    }
}

/* ===================== Public dispatcher ===================== */

void fix_dtls(dtls_packet_t *pkts, size_t count)
{
    if (!pkts || count == 0) return;

    /* 0) generic per-packet clamps first */
    fix_common_lengths_and_kinds(pkts, count);

    /* ---- Client-to-Server shots (0..36) ---- */
    fix_c2s_shot_0_clienthello_first(pkts, count);
    fix_c2s_shot_2_clienthello_cipher_suites_len(pkts, count);
    fix_c2s_shot_3_clienthello_compression_methods(pkts, count);
    fix_c2s_shot_4_clienthello_extensions_len(pkts, count);
    fix_c2s_shot_6_clienthello_session_id_len(pkts, count);
    fix_c2s_shot_11_clienthello_cookie_len(pkts, count);
    fix_c2s_shot_23_ccs_before_finished(pkts, count);
    fix_c2s_shot_24_ccs_value(pkts, count);
    fix_c2s_shot_25_finished_after_ccs(pkts, count);
    fix_c2s_shot_28_29_handshake_order(pkts, count);
    fix_c2s_shot_30_34_no_appdata_before_done(pkts, count);
    fix_c2s_shot_31_monotonic_message_seq(pkts, count);
    fix_c2s_shot_32_fragment_length_ok(pkts, count);

    /* ---- Server-to-Client shots (0..40) ---- */
    fix_s2c_shot_0_serverhello_first(pkts, count);
    fix_s2c_shot_1_server_version_le_client(pkts, count);
    fix_s2c_shot_3_serverhello_session_id_len(pkts, count);
    fix_s2c_shot_4_serverhello_cipher_suite_from_client(pkts, count);
    fix_s2c_shot_5_serverhello_compression_from_client(pkts, count);
    fix_s2c_shot_6_serverhello_extensions_len(pkts, count);
    fix_s2c_shot_10_hvr_cookie_len(pkts, count);
    fix_s2c_shot_11_hvr_version_le_client(pkts, count);
    fix_s2c_shot_22_certreq_before_shd(pkts, count);
    fix_s2c_shot_23_certreq_cert_types_nonempty(pkts, count);
    fix_s2c_shot_24_certreq_sig_algs_even(pkts, count);
    fix_s2c_shot_25_certreq_ca_dn_len(pkts, count);
    fix_s2c_shot_28_29_server_ccs_before_finished(pkts, count);
    fix_s2c_shot_30_31_server_finished_after_ccs(pkts, count);
    fix_s2c_shot_33_34_server_order_and_no_appdata(pkts, count);
    fix_s2c_shot_35_36_dtls_seq_and_frag(pkts, count);
    fix_s2c_shot_38_alert_two_bytes(pkts, count);
    fix_s2c_shot_40_no_appdata_before_done(pkts, count);

    /*  final pass for clamps after possible swaps */
    fix_common_lengths_and_kinds(pkts, count);
}
