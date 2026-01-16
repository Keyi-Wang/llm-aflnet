/* ===================== dtls_parser.c (updated for your corrected dtls.h) ===================== */
/* dtls parser
 *
 * Implements:
 *   size_t parse_dtls_msg(const u8 *buf, u32 buf_len, dtls_packet_t *out_packets, u32 max_count);
 *
 * Notes:
 *  - Does NOT decrypt. epoch>0 handshake/application_data are treated as DTLS_PKT_ENCRYPTED (opaque bytes).
 *  - For plaintext handshake epoch==0:
 *      * Known msg_type: parse into typed union fields when possible.
 *      * Unknown msg_type OR parse-fail: store raw_body[] so reassembly can still be byte-identical.
 */

#include "dtls.h"
#include <string.h>
#include <stddef.h>

/* ---------------- helpers ---------------- */

static u16 rd_u16(const u8 *p) { return (u16)(((u16)p[0] << 8) | (u16)p[1]); }
static u32 rd_u24(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2]; }

static void set_zero(void *p, size_t n) { if (p && n) memset(p, 0, n); }

/* Parse TLS/DTLS opaque vector: uint16 length + bytes[] (max bound enforced by caller) */
static int parse_vec_u16(const u8 *body, u32 body_len, u32 *o_io, u8 *out, u16 out_cap, u16 *out_len) {
    u32 o = *o_io;
    if (o + 2 > body_len) return -1;
    u16 l = rd_u16(body + o); o += 2;
    if (l > out_cap) return -1;
    if (o + l > body_len) return -1;
    if (l && out) memcpy(out, body + o, l);
    o += l;
    if (out_len) *out_len = l;
    *o_io = o;
    return 0;
}


/* Parse DH params: ServerDHParams = p<2..> g<2..> Ys<2..> (all uint16 vectors) */
static int parse_server_dh_params(const u8 *body, u32 body_len, u32 *o_io, dtls_server_dh_params_t *p) {
    u32 o = *o_io;
    if (!p) return -1;

    if (parse_vec_u16(body, body_len, &o, p->dh_p, DTLS_MAX_DH_P_LEN, &p->dh_p_len) != 0) return -1;
    if (parse_vec_u16(body, body_len, &o, p->dh_g, DTLS_MAX_DH_G_LEN, &p->dh_g_len) != 0) return -1;
    if (parse_vec_u16(body, body_len, &o, p->dh_Ys, DTLS_MAX_DH_Y_LEN, &p->dh_Ys_len) != 0) return -1;

    *o_io = o;
    return 0;
}

/* Parse DigitallySigned (TLS 1.2): (hash,sig) + uint16 sig_len + sig */
static int parse_digitally_signed(const u8 *body, u32 body_len, u32 *o_io, dtls_digitally_signed_t *ds) {
    u32 o = *o_io;
    if (!ds) return -1;
    if (o + 2 + 2 > body_len) return -1;

    ds->alg.hash_algorithm = body[o++];
    ds->alg.signature_algorithm = body[o++];

    if (o + 2 > body_len) return -1;
    ds->signature_len = rd_u16(body + o); o += 2;
    if (ds->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
    if (o + ds->signature_len > body_len) return -1;

    if (ds->signature_len) memcpy(ds->signature, body + o, ds->signature_len);
    o += ds->signature_len;

    *o_io = o;
    return 0;
}

/* ---------------- parsing: body-specific ---------------- */

static int parse_hello_request(const u8 *body, u32 body_len, dtls_hello_request_t *hr) {
    (void)body;
    if (!hr) return -1;
    hr->_dummy = 0;
    return (body_len == 0) ? 0 : -1;
}

static int parse_client_hello(const u8 *body, u32 body_len, dtls_client_hello_t *ch) {
    u32 o = 0;
    if (!body || !ch) return -1;

    if (body_len < 2 + 32 + 1 + 1 + 2 + 1 + 2) return -1; /* rough minimum */

    ch->client_version.major = body[o++];
    ch->client_version.minor = body[o++];

    memcpy(ch->random.bytes, body + o, 32); o += 32;

    ch->session_id.len = body[o++];
    if (ch->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
    if (o + ch->session_id.len > body_len) return -1;
    memcpy(ch->session_id.id, body + o, ch->session_id.len);
    o += ch->session_id.len;

    ch->cookie_len = body[o++];
    if (ch->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
    if (o + ch->cookie_len > body_len) return -1;
    memcpy(ch->cookie, body + o, ch->cookie_len);
    o += ch->cookie_len;

    if (o + 2 > body_len) return -1;
    ch->cipher_suites_len = rd_u16(body + o); o += 2;
    if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES) return -1;
    if (o + ch->cipher_suites_len > body_len) return -1;
    memcpy(ch->cipher_suites, body + o, ch->cipher_suites_len);
    o += ch->cipher_suites_len;

    if (o + 1 > body_len) return -1;
    ch->compression_methods_len = body[o++];
    if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN) return -1;
    if (o + ch->compression_methods_len > body_len) return -1;
    memcpy(ch->compression_methods, body + o, ch->compression_methods_len);
    o += ch->compression_methods_len;

    if (o == body_len) {
        ch->extensions.present = 0;
        ch->extensions.total_len = 0;
        return 0;
    }

    if (o + 2 > body_len) return -1;
    ch->extensions.present = 1;
    ch->extensions.total_len = rd_u16(body + o); o += 2;
    if (ch->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
    if (o + ch->extensions.total_len > body_len) return -1;
    memcpy(ch->extensions.raw, body + o, ch->extensions.total_len);
    o += ch->extensions.total_len;

    return (o == body_len) ? 0 : -1;
}

static int parse_server_hello(const u8 *body, u32 body_len, dtls_server_hello_t *sh) {
    u32 o = 0;
    if (!body || !sh) return -1;
    if (body_len < 2 + 32 + 1 + 2 + 1) return -1;

    sh->server_version.major = body[o++];
    sh->server_version.minor = body[o++];

    memcpy(sh->random.bytes, body + o, 32); o += 32;

    sh->session_id.len = body[o++];
    if (sh->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
    if (o + sh->session_id.len > body_len) return -1;
    memcpy(sh->session_id.id, body + o, sh->session_id.len);
    o += sh->session_id.len;

    if (o + 2 + 1 > body_len) return -1;
    sh->cipher_suite = rd_u16(body + o); o += 2;
    sh->compression_method = body[o++];

    if (o == body_len) {
        sh->extensions.present = 0;
        sh->extensions.total_len = 0;
        return 0;
    }

    sh->extensions.present = 1;
    if (o + 2 > body_len) return -1;
    sh->extensions.total_len = rd_u16(body + o); o += 2;
    if (sh->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
    if (o + sh->extensions.total_len > body_len) return -1;
    memcpy(sh->extensions.raw, body + o, sh->extensions.total_len);
    o += sh->extensions.total_len;

    return (o == body_len) ? 0 : -1;
}

static int parse_hello_verify_request(const u8 *body, u32 body_len, dtls_hello_verify_request_t *hv) {
    u32 o = 0;
    if (!body || !hv) return -1;
    if (body_len < 2 + 1) return -1;

    hv->server_version.major = body[o++];
    hv->server_version.minor = body[o++];

    hv->cookie_len = body[o++];
    if (hv->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
    if (o + hv->cookie_len > body_len) return -1;
    memcpy(hv->cookie, body + o, hv->cookie_len);
    o += hv->cookie_len;

    return (o == body_len) ? 0 : -1;
}

static int parse_certificate_blob(const u8 *body, u32 body_len, dtls_certificate_body_t *c) {
    if (!body || !c) return -1;
    if (body_len < 3) return -1;

    memcpy(c->cert_blob_len.b, body, 3);
    u32 l = rd_u24(body);
    if (l > DTLS_MAX_CERT_BLOB_LEN) return -1;
    if (3 + l != body_len) return -1;
    memcpy(c->cert_blob, body + 3, l);
    return 0;
}

static int parse_certificate_request(const u8 *body, u32 body_len, dtls_certificate_request_t *cr) {
    u32 o = 0;
    if (!body || !cr) return -1;
    if (body_len < 1 + 2 + 2) return -1;

    cr->cert_types_len = body[o++];
    if (cr->cert_types_len == 0) return -1;
    if (cr->cert_types_len > DTLS_MAX_CERT_TYPES_LEN) return -1;
    if (o + cr->cert_types_len > body_len) return -1;
    memcpy(cr->cert_types, body + o, cr->cert_types_len);
    o += cr->cert_types_len;

    if (o + 2 > body_len) return -1;
    cr->sig_algs_len = rd_u16(body + o); o += 2;
    if (cr->sig_algs_len > DTLS_MAX_SIG_ALGS_LEN) return -1;
    if ((cr->sig_algs_len & 1u) != 0) return -1;
    if (o + cr->sig_algs_len > body_len) return -1;
    memcpy(cr->sig_algs, body + o, cr->sig_algs_len);
    o += cr->sig_algs_len;

    if (o + 2 > body_len) return -1;
    cr->ca_dn_len = rd_u16(body + o); o += 2;
    if (cr->ca_dn_len > DTLS_MAX_CA_DN_LEN) return -1;
    if (o + cr->ca_dn_len > body_len) return -1;
    memcpy(cr->ca_dn_blob, body + o, cr->ca_dn_len);
    o += cr->ca_dn_len;

    return (o == body_len) ? 0 : -1;
}

static int parse_server_hello_done(const u8 *body, u32 body_len, dtls_server_hello_done_t *shd) {
    (void)body;
    if (!shd) return -1;
    shd->_dummy = 0;
    return (body_len == 0) ? 0 : -1;
}

static int parse_certificate_verify(const u8 *body, u32 body_len, dtls_certificate_verify_body_t *cv) {
    u32 o = 0;
    if (!body || !cv) return -1;
    if (body_len < 2 + 2) return -1;

    cv->alg.hash_algorithm = body[o++];
    cv->alg.signature_algorithm = body[o++];

    cv->signature_len = rd_u16(body + o); o += 2;
    if (cv->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
    if (o + cv->signature_len != body_len) return -1;

    memcpy(cv->signature, body + o, cv->signature_len);
    return 0;
}

static int parse_finished_plain(const u8 *body, u32 body_len, dtls_finished_body_t *fin) {
    if (!body || !fin) return -1;
    if (body_len != DTLS_VERIFY_DATA_LEN) return -1;
    memcpy(fin->verify_data, body, DTLS_VERIFY_DATA_LEN);
    return 0;
}

/* ===================== UPDATED: ServerKeyExchange body ===================== */
/*
 * We only parse a few common shapes (enough for your MR + typed mutations).
 * If we cannot confidently parse, return -1 so caller stores raw_body for byte-identical reassembly.
 *
 * Supported attempts:
 *  1) ECDHE_* signed: ECParameters(named_curve only) + ECPoint + DigitallySigned
 *  2) DH anon params only: ServerDHParams
 *  3) DHE_* signed: ServerDHParams + DigitallySigned
 *  4) PSK hint only: identity_hint<0..2^16-1>
 *  5) DHE_PSK: hint + ServerDHParams
 *  6) ECDHE_PSK: hint + ECParameters + ECPoint
 */
static int parse_server_key_exchange_body(const u8 *body, u32 body_len, dtls_server_key_exchange_body_t *ske)
{
    if (!body || !ske) return -1;
    set_zero(ske, sizeof(*ske));

    /* ---- (1) Try ECDHE signed ---- */
    {
        u32 o = 0;
        if (body_len >= 1 + 2 + 1) {
            u8 curve_type = body[o++];
            u16 named_curve = rd_u16(body + o); o += 2;
            u8 ptlen = body[o++];

            if (curve_type == 3 &&
                ptlen <= DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN &&
                o + (u32)ptlen + 2 + 2 <= body_len) {

                /* parse as: params + DigitallySigned */
                dtls_ske_ecdhe_signed_t *E = &ske->u.ecdhe_signed;
                E->params.curve_type = curve_type;
                E->params.named_curve = named_curve;
                E->params.ec_point_len = ptlen;

                if (o + ptlen > body_len) return -1;
                if (ptlen) memcpy(E->params.ec_point, body + o, ptlen);
                o += ptlen;

                if (parse_digitally_signed(body, body_len, &o, &E->sig) != 0) return -1;
                if (o != body_len) return -1;

                ske->kx_alg = KX_ECDHE_ECDSA; /* generic: signed ECDHE */
                return 0;
            }
        }
    }

    /* ---- (6) Try ECDHE_PSK: hint + EC params (no signature) ---- */
    {
        u32 o = 0;
        dtls_ske_ecdhe_psk_t *P = &ske->u.ecdhe_psk;

        /* hint */
        if (parse_vec_u16(body, body_len, &o, P->hint.identity_hint, DTLS_MAX_PSK_IDENTITY_LEN,
                          &P->hint.identity_hint_len) == 0) {
            if (o + 1 + 2 + 1 <= body_len) {
                u8 curve_type = body[o++];
                u16 named_curve = rd_u16(body + o); o += 2;
                u8 ptlen = body[o++];

                if (curve_type == 3 &&
                    ptlen <= DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN &&
                    o + (u32)ptlen == body_len) {

                    P->params.curve_type = curve_type;
                    P->params.named_curve = named_curve;
                    P->params.ec_point_len = ptlen;
                    if (ptlen) memcpy(P->params.ec_point, body + o, ptlen);

                    ske->kx_alg = KX_ECDHE_PSK;
                    return 0;
                }
            }
        }
    }

    /* ---- (5) Try DHE_PSK: hint + DH params (no signature) ---- */
    {
        u32 o = 0;
        dtls_ske_dhe_psk_t *D = &ske->u.dhe_psk;

        if (parse_vec_u16(body, body_len, &o, D->hint.identity_hint, DTLS_MAX_PSK_IDENTITY_LEN,
                          &D->hint.identity_hint_len) == 0) {
            if (parse_server_dh_params(body, body_len, &o, &D->params) == 0) {
                if (o == body_len) {
                    ske->kx_alg = KX_DHE_PSK;
                    return 0;
                }
            }
        }
    }

    /* ---- (4) Try PSK hint only ---- */
    {
        u32 o = 0;
        dtls_ske_psk_t *P = &ske->u.psk;

        if (parse_vec_u16(body, body_len, &o, P->hint.identity_hint, DTLS_MAX_PSK_IDENTITY_LEN,
                          &P->hint.identity_hint_len) == 0) {
            if (o == body_len) {
                ske->kx_alg = KX_PSK;
                return 0;
            }
        }
    }

    /* ---- (2) Try DH anon params only ---- */
    {
        u32 o = 0;
        dtls_ske_dh_anon_t *A = &ske->u.dh_anon;
        if (parse_server_dh_params(body, body_len, &o, &A->params) == 0) {
            if (o == body_len) {
                ske->kx_alg = KX_DH_ANON;
                return 0;
            }
        }
    }

    /* ---- (3) Try DHE signed: DH params + DigitallySigned ---- */
    {
        u32 o = 0;
        dtls_ske_dhe_signed_t *S = &ske->u.dhe_signed;
        if (parse_server_dh_params(body, body_len, &o, &S->params) == 0) {
            if (parse_digitally_signed(body, body_len, &o, &S->sig) == 0) {
                if (o == body_len) {
                    ske->kx_alg = KX_DHE_RSA; /* generic "signed DHE" */
                    return 0;
                }
            }
        }
    }

    return -1;
}

/* ===================== UPDATED: ClientKeyExchange body ===================== */
/*
 * Supported attempts (heuristic, no cipher-suite context):
 *  1) ECDH/ECDHE: ECPoint<1..2^8-1> : uint8 len + bytes (exact fit)
 *  2) PSK: identity<0..2^16-1> : uint16 len + bytes (exact fit)
 *  3) DH public: uint16 len + bytes (exact fit) (ClientDiffieHellmanPublic)
 *  4) RSA: EncryptedPreMasterSecret: uint16 len + bytes (exact fit)
 *
 * If ambiguous, we prefer (1) then (2). If still ambiguous, fail => raw_body.
 */
static int parse_client_key_exchange(const u8 *body, u32 body_len, dtls_client_key_exchange_body_t *cke)
{
    if (!body || !cke) return -1;
    set_zero(cke, sizeof(*cke));
    if (body_len == 0) return -1;

    /* (1) ECPoint (uint8) exact fit */
    if (body_len >= 1) {
        u8 ptlen = body[0];
        if ((u32)ptlen + 1u == body_len && ptlen <= DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) {
            cke->kx_alg = KX_ECDHE_ECDSA; /* generic ECDHE/ECDH */
            cke->u.ecdh.ecdh_pub.ec_point_len = ptlen;
            if (ptlen) memcpy(cke->u.ecdh.ecdh_pub.ec_point, body + 1, ptlen);
            return 0;
        }
    }

    /* Below are all uint16-len vectors. Try exact-fit. */
    if (body_len >= 2) {
        u16 l = rd_u16(body);
        if ((u32)l + 2u == body_len) {
            /* if l is "small-ish", treat as PSK identity; else could be DH/RSA too */
            if (l <= DTLS_MAX_PSK_IDENTITY_LEN) {
                cke->kx_alg = KX_PSK;
                cke->u.psk.psk.identity_len = l;
                if (l) memcpy(cke->u.psk.psk.identity, body + 2, l);
                return 0;
            }
            /* If it doesn't fit PSK cap, still might be DH/RSA (but we cap arrays) */
            if (l <= DTLS_MAX_DH_Y_LEN) {
                cke->kx_alg = KX_DHE_RSA; /* generic DH family */
                cke->u.dh.dh_pub.dh_Yc_len = l;
                if (l) memcpy(cke->u.dh.dh_pub.dh_Yc, body + 2, l);
                return 0;
            }
            if (l <= DTLS_MAX_RSA_ENC_PMS_LEN) {
                cke->kx_alg = KX_RSA;
                cke->u.rsa.enc_pms.enc_pms_len = l;
                if (l) memcpy(cke->u.rsa.enc_pms.enc_pms, body + 2, l);
                return 0;
            }
        }
    }

    return -1;
}

/* ---------------- main parser ---------------- */

size_t parse_dtls_msg(const u8 *buf, u32 buf_len, dtls_packet_t *out_packets, u32 max_count)
{
    if (!buf || !out_packets || max_count == 0) return 0;

    u32 off = 0;
    u32 count = 0;

    while (off + 13 <= buf_len && count < max_count) {
        int keep_pkt = 1;
        dtls_packet_t *pkt = &out_packets[count];
        set_zero(pkt, sizeof(*pkt));

        const u8 *rh = buf + off;

        pkt->record_header.type          = rh[0];
        pkt->record_header.version_major = rh[1];
        pkt->record_header.version_minor = rh[2];
        pkt->record_header.epoch         = rd_u16(rh + 3);
        memcpy(pkt->record_header.sequence_number.b, rh + 5, 6);
        pkt->record_header.length        = rd_u16(rh + 11);

        off += 13;

        if (off + pkt->record_header.length > buf_len) break;

        const u8 *payload = buf + off;
        u16 plen = pkt->record_header.length;

        if (pkt->record_header.type == 22 && pkt->record_header.epoch == 0) {
            /* plaintext handshake */
            if (plen < 12) break;

            pkt->kind = DTLS_PKT_HANDSHAKE;

            const u8 *hh = payload;
            dtls_handshake_header_t *H = &pkt->payload.handshake.handshake_header;

            H->msg_type = hh[0];
            H->length.b[0] = hh[1];
            H->length.b[1] = hh[2];
            H->length.b[2] = hh[3];
            H->message_seq = rd_u16(hh + 4);
            memcpy(H->fragment_offset.b, hh + 6, 3);
            memcpy(H->fragment_length.b, hh + 9, 3);

            u32 h_body_len = rd_u24(hh + 1);
            if (12 + h_body_len > plen) break;

            const u8 *body = hh + 12;

            pkt->payload.handshake.raw_body_len = 0;

            int ok = -1;
            switch (H->msg_type) {
            case 0:  ok = parse_hello_request(body, h_body_len, &pkt->payload.handshake.body.hello_request); break;
            case 1:  ok = parse_client_hello(body, h_body_len, &pkt->payload.handshake.body.client_hello); break;
            case 2:  ok = parse_server_hello(body, h_body_len, &pkt->payload.handshake.body.server_hello); break;
            case 3:  ok = parse_hello_verify_request(body, h_body_len, &pkt->payload.handshake.body.hello_verify_request); break;
            case 11: ok = parse_certificate_blob(body, h_body_len, &pkt->payload.handshake.body.certificate); break;
            case 12: ok = parse_server_key_exchange_body(body, h_body_len, &pkt->payload.handshake.body.server_key_exchange); break;
            case 13: ok = parse_certificate_request(body, h_body_len, &pkt->payload.handshake.body.certificate_request); break;
            case 14: ok = parse_server_hello_done(body, h_body_len, &pkt->payload.handshake.body.server_hello_done); break;
            case 15: ok = parse_certificate_verify(body, h_body_len, &pkt->payload.handshake.body.certificate_verify); break;
            case 16: ok = parse_client_key_exchange(body, h_body_len, &pkt->payload.handshake.body.client_key_exchange); break;
            case 20: ok = parse_finished_plain(body, h_body_len, &pkt->payload.handshake.body.finished); break;
            default: ok = -1; break;
            }

            if (ok != 0) {
                keep_pkt = 0;
            } else {
                pkt->payload.handshake.raw_body_len = 0;
            }

        } else if (pkt->record_header.type == 20) {
            pkt->kind = DTLS_PKT_CHANGE_CIPHER_SPEC;
            if (plen != 1) break;
            pkt->payload.change_cipher_spec.value = payload[0];

        } else if (pkt->record_header.type == 21) {
            pkt->kind = DTLS_PKT_ALERT;
            if (plen < 2) break;
            pkt->payload.alert.level = payload[0];
            pkt->payload.alert.description = payload[1];

        } else if (pkt->record_header.type == 23 && pkt->record_header.epoch == 0) {
            pkt->kind = DTLS_PKT_APPLICATION_DATA;
            if (plen > DTLS_MAX_APPDATA_LEN) break;
            pkt->payload.application_data.data_len = plen;
            memcpy(pkt->payload.application_data.data, payload, plen);

        } else {
            pkt->kind = DTLS_PKT_ENCRYPTED;
            if (plen > DTLS_MAX_CIPHERTEXT_LEN) break;
            pkt->payload.encrypted.ciphertext_len = plen;
            memcpy(pkt->payload.encrypted.ciphertext, payload, plen);
        }

        off += plen;
        if (keep_pkt) {
            count++;
        }

    }

    return (size_t)count;
}
