/* ===================== dtls_reassembler.c (updated for your corrected dtls.h) ===================== */
/* dtls reassembler
 *
 * Implements:
 *   int reassemble_dtls_msgs(const dtls_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);
 *
 * Notes:
 *  - Does NOT decrypt. epoch>0 handshake/application_data are treated as DTLS_PKT_ENCRYPTED (opaque bytes).
 *  - For reassembly:
 *      * For known msg_type: serialize from typed fields.
 *      * For unknown msg_type OR stored raw_body: serialize from raw_body[].
 *      * Record header length is recomputed from payload.
 */

#include "dtls.h"
#include <string.h>
#include <stddef.h>

/* ---------------- reassembler helpers ---------------- */
static u32 rd_u24b(const uint24_t v) { return ((u32)v.b[0] << 16) | ((u32)v.b[1] << 8) | (u32)v.b[2]; }

static int append_bytes(u8 *out, u32 cap, u32 *off, const void *src, u32 n) {
    if (!out || !off || (!src && n)) return -1;
    if (*off > cap) return -1;
    if (n > cap - *off) return -1;
    if (n) memcpy(out + *off, src, n);
    *off += n;
    return 0;
}

static int append_u8(u8 *out, u32 cap, u32 *off, u8 v) {
    if (!out || !off) return -1;
    if (*off >= cap) return -1;
    out[*off] = v;
    (*off)++;
    return 0;
}

static int append_u16(u8 *out, u32 cap, u32 *off, u16 v) {
    if (!out || !off) return -1;
    if (cap - *off < 2) return -1;
    out[*off + 0] = (u8)(v >> 8);
    out[*off + 1] = (u8)(v & 0xff);
    *off += 2;
    return 0;
}

static int append_u24(u8 *out, u32 cap, u32 *off, u32 v) {
    if (!out || !off) return -1;
    if (cap - *off < 3) return -1;
    out[*off + 0] = (u8)((v >> 16) & 0xff);
    out[*off + 1] = (u8)((v >> 8) & 0xff);
    out[*off + 2] = (u8)(v & 0xff);
    *off += 3;
    return 0;
}

static int append_record_header(u8 *out, u32 cap, u32 *off,
                                const dtls_record_header_t *rh, u16 rec_len) {
    if (!rh) return -1;
    if (append_u8(out, cap, off, rh->type)) return -1;
    if (append_u8(out, cap, off, rh->version_major)) return -1;
    if (append_u8(out, cap, off, rh->version_minor)) return -1;
    if (append_u16(out, cap, off, rh->epoch)) return -1;
    if (append_bytes(out, cap, off, rh->sequence_number.b, 6)) return -1;
    if (append_u16(out, cap, off, rec_len)) return -1;
    return 0;
}

/* Serialize helpers for u16 vector / u8 vector */
static int put_vec_u16(u8 *tmp, u32 cap, u32 *o, const u8 *data, u16 len) {
    if (append_u16(tmp, cap, o, len) != 0) return -1;
    if (append_bytes(tmp, cap, o, data, len) != 0) return -1;
    return 0;
}
static int put_vec_u8(u8 *tmp, u32 cap, u32 *o, const u8 *data, u8 len) {
    if (append_u8(tmp, cap, o, len) != 0) return -1;
    if (append_bytes(tmp, cap, o, data, len) != 0) return -1;
    return 0;
}

/* Serialize DigitallySigned */
static int put_digitally_signed(u8 *tmp, u32 cap, u32 *o, const dtls_digitally_signed_t *ds) {
    if (!ds) return -1;
    if (append_u8(tmp, cap, o, ds->alg.hash_algorithm) != 0) return -1;
    if (append_u8(tmp, cap, o, ds->alg.signature_algorithm) != 0) return -1;
    if (ds->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
    if (append_u16(tmp, cap, o, ds->signature_len) != 0) return -1;
    if (append_bytes(tmp, cap, o, ds->signature, ds->signature_len) != 0) return -1;
    return 0;
}

/* Serialize DH params */
static int put_server_dh_params(u8 *tmp, u32 cap, u32 *o, const dtls_server_dh_params_t *p) {
    if (!p) return -1;
    if (p->dh_p_len > DTLS_MAX_DH_P_LEN) return -1;
    if (p->dh_g_len > DTLS_MAX_DH_G_LEN) return -1;
    if (p->dh_Ys_len > DTLS_MAX_DH_Y_LEN) return -1;
    if (put_vec_u16(tmp, cap, o, p->dh_p, p->dh_p_len) != 0) return -1;
    if (put_vec_u16(tmp, cap, o, p->dh_g, p->dh_g_len) != 0) return -1;
    if (put_vec_u16(tmp, cap, o, p->dh_Ys, p->dh_Ys_len) != 0) return -1;
    return 0;
}

/* Serialize plaintext handshake body from typed fields; return 0 on success, -1 on failure */
static int serialize_handshake_body(const dtls_packet_t *pkt, u8 *tmp, u32 tmp_cap, u32 *body_len_out) {
    if (!pkt || !tmp || !body_len_out) return -1;
    *body_len_out = 0;

    const dtls_handshake_header_t *hh = &pkt->payload.handshake.handshake_header;
    u8 t = hh->msg_type;
    u32 o = 0;

    /* If parser stored raw body (unknown/unparsable), use it for byte-identical output. */
    if (pkt->payload.handshake.raw_body_len != 0) {
        // u32 l = pkt->payload.handshake.raw_body_len;
        // if (l > tmp_cap) return -1;
        // memcpy(tmp, pkt->payload.handshake.raw_body, l);
        // *body_len_out = l;
        return -1;
    }

    switch (t) {
    case 0: { /* HelloRequest (empty) */
        *body_len_out = 0;
        return 0;
    }
    case 1: { /* ClientHello */
        const dtls_client_hello_t *ch = &pkt->payload.handshake.body.client_hello;

        if (o + 2 + 32 + 1 > tmp_cap) return -1;
        tmp[o++] = ch->client_version.major;
        tmp[o++] = ch->client_version.minor;
        memcpy(tmp + o, ch->random.bytes, 32); o += 32;

        if (ch->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
        if (put_vec_u8(tmp, tmp_cap, &o, ch->session_id.id, ch->session_id.len) != 0) return -1;

        if (ch->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
        if (put_vec_u8(tmp, tmp_cap, &o, ch->cookie, ch->cookie_len) != 0) return -1;

        if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES) return -1;
        if (append_u16(tmp, tmp_cap, &o, ch->cipher_suites_len) != 0) return -1;
        if (append_bytes(tmp, tmp_cap, &o, ch->cipher_suites, ch->cipher_suites_len) != 0) return -1;

        if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN) return -1;
        if (put_vec_u8(tmp, tmp_cap, &o, ch->compression_methods, ch->compression_methods_len) != 0) return -1;

        if (ch->extensions.present) {
            if (ch->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
            if (append_u16(tmp, tmp_cap, &o, ch->extensions.total_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, ch->extensions.raw, ch->extensions.total_len) != 0) return -1;
        }
        break;
    }
    case 2: { /* ServerHello */
        const dtls_server_hello_t *sh = &pkt->payload.handshake.body.server_hello;

        if (o + 2 + 32 + 1 > tmp_cap) return -1;
        tmp[o++] = sh->server_version.major;
        tmp[o++] = sh->server_version.minor;
        memcpy(tmp + o, sh->random.bytes, 32); o += 32;

        if (sh->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
        if (put_vec_u8(tmp, tmp_cap, &o, sh->session_id.id, sh->session_id.len) != 0) return -1;

        if (append_u16(tmp, tmp_cap, &o, sh->cipher_suite) != 0) return -1;
        if (append_u8(tmp, tmp_cap, &o, sh->compression_method) != 0) return -1;

        if (sh->extensions.present) {
            if (sh->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
            if (append_u16(tmp, tmp_cap, &o, sh->extensions.total_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, sh->extensions.raw, sh->extensions.total_len) != 0) return -1;
        }
        break;
    }
    case 3: { /* HelloVerifyRequest */
        const dtls_hello_verify_request_t *hv = &pkt->payload.handshake.body.hello_verify_request;

        if (append_u8(tmp, tmp_cap, &o, hv->server_version.major) != 0) return -1;
        if (append_u8(tmp, tmp_cap, &o, hv->server_version.minor) != 0) return -1;

        if (hv->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
        if (put_vec_u8(tmp, tmp_cap, &o, hv->cookie, hv->cookie_len) != 0) return -1;
        break;
    }
    case 11: { /* Certificate */
        const dtls_certificate_body_t *c = &pkt->payload.handshake.body.certificate;
        u32 l = rd_u24b(c->cert_blob_len);
        if (l > DTLS_MAX_CERT_BLOB_LEN) return -1;
        if (o + 3 + l > tmp_cap) return -1;

        tmp[o++] = c->cert_blob_len.b[0];
        tmp[o++] = c->cert_blob_len.b[1];
        tmp[o++] = c->cert_blob_len.b[2];
        memcpy(tmp + o, c->cert_blob, l);
        o += l;
        break;
    }
    case 12: { /* ServerKeyExchange (UPDATED: dtls_server_key_exchange_body_t) */
        const dtls_server_key_exchange_body_t *ske = &pkt->payload.handshake.body.server_key_exchange;

        switch (ske->kx_alg) {
        case KX_ECDHE_ECDSA:
        case KX_ECDHE_RSA: {
            const dtls_ske_ecdhe_signed_t *E = &ske->u.ecdhe_signed;
            if (E->params.ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
            if (append_u8(tmp, tmp_cap, &o, E->params.curve_type) != 0) return -1;
            if (append_u16(tmp, tmp_cap, &o, E->params.named_curve) != 0) return -1;
            if (append_u8(tmp, tmp_cap, &o, E->params.ec_point_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, E->params.ec_point, E->params.ec_point_len) != 0) return -1;
            if (put_digitally_signed(tmp, tmp_cap, &o, &E->sig) != 0) return -1;
            break;
        }
        case KX_ECDHE_PSK: {
            const dtls_ske_ecdhe_psk_t *P = &ske->u.ecdhe_psk;
            if (P->hint.identity_hint_len > DTLS_MAX_PSK_IDENTITY_LEN) return -1;
            if (P->params.ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
            if (put_vec_u16(tmp, tmp_cap, &o, P->hint.identity_hint, P->hint.identity_hint_len) != 0) return -1;
            if (append_u8(tmp, tmp_cap, &o, P->params.curve_type) != 0) return -1;
            if (append_u16(tmp, tmp_cap, &o, P->params.named_curve) != 0) return -1;
            if (append_u8(tmp, tmp_cap, &o, P->params.ec_point_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, P->params.ec_point, P->params.ec_point_len) != 0) return -1;
            break;
        }
        case KX_DH_ANON: {
            const dtls_ske_dh_anon_t *A = &ske->u.dh_anon;
            if (put_server_dh_params(tmp, tmp_cap, &o, &A->params) != 0) return -1;
            break;
        }
        case KX_DHE_RSA:
        case KX_DHE_DSS: {
            const dtls_ske_dhe_signed_t *S = &ske->u.dhe_signed;
            if (put_server_dh_params(tmp, tmp_cap, &o, &S->params) != 0) return -1;
            if (put_digitally_signed(tmp, tmp_cap, &o, &S->sig) != 0) return -1;
            break;
        }
        case KX_DHE_PSK: {
            const dtls_ske_dhe_psk_t *D = &ske->u.dhe_psk;
            if (D->hint.identity_hint_len > DTLS_MAX_PSK_IDENTITY_LEN) return -1;
            if (put_vec_u16(tmp, tmp_cap, &o, D->hint.identity_hint, D->hint.identity_hint_len) != 0) return -1;
            if (put_server_dh_params(tmp, tmp_cap, &o, &D->params) != 0) return -1;
            break;
        }
        case KX_PSK: {
            const dtls_ske_psk_t *P = &ske->u.psk;
            if (P->hint.identity_hint_len > DTLS_MAX_PSK_IDENTITY_LEN) return -1;
            if (put_vec_u16(tmp, tmp_cap, &o, P->hint.identity_hint, P->hint.identity_hint_len) != 0) return -1;
            break;
        }
        default:
            /* If not recognized, caller should have set raw_body_len; treat as empty fail */
            return -1;
        }
        break;
    }
    case 13: { /* CertificateRequest */
        const dtls_certificate_request_t *cr = &pkt->payload.handshake.body.certificate_request;

        if (cr->cert_types_len == 0 || cr->cert_types_len > DTLS_MAX_CERT_TYPES_LEN) return -1;
        if (cr->sig_algs_len > DTLS_MAX_SIG_ALGS_LEN) return -1;
        if ((cr->sig_algs_len & 1u) != 0) return -1;
        if (cr->ca_dn_len > DTLS_MAX_CA_DN_LEN) return -1;

        if (append_u8(tmp, tmp_cap, &o, cr->cert_types_len) != 0) return -1;
        if (append_bytes(tmp, tmp_cap, &o, cr->cert_types, cr->cert_types_len) != 0) return -1;

        if (append_u16(tmp, tmp_cap, &o, cr->sig_algs_len) != 0) return -1;
        if (append_bytes(tmp, tmp_cap, &o, cr->sig_algs, cr->sig_algs_len) != 0) return -1;

        if (append_u16(tmp, tmp_cap, &o, cr->ca_dn_len) != 0) return -1;
        if (append_bytes(tmp, tmp_cap, &o, cr->ca_dn_blob, cr->ca_dn_len) != 0) return -1;
        break;
    }
    case 14: { /* ServerHelloDone (empty) */
        *body_len_out = 0;
        return 0;
    }
    case 15: { /* CertificateVerify */
        const dtls_certificate_verify_body_t *cv = &pkt->payload.handshake.body.certificate_verify;
        if (append_u8(tmp, tmp_cap, &o, cv->alg.hash_algorithm) != 0) return -1;
        if (append_u8(tmp, tmp_cap, &o, cv->alg.signature_algorithm) != 0) return -1;
        if (cv->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
        if (append_u16(tmp, tmp_cap, &o, cv->signature_len) != 0) return -1;
        if (append_bytes(tmp, tmp_cap, &o, cv->signature, cv->signature_len) != 0) return -1;
        break;
    }
    case 16: { /* ClientKeyExchange (UPDATED: dtls_client_key_exchange_body_t) */
        const dtls_client_key_exchange_body_t *cke = &pkt->payload.handshake.body.client_key_exchange;

        switch (cke->kx_alg) {
        case KX_PSK:
        case KX_DHE_PSK:
        case KX_RSA_PSK:
        case KX_ECDHE_PSK: {
            const dtls_psk_identity_t *psk = &cke->u.psk.psk;
            if (psk->identity_len > DTLS_MAX_PSK_IDENTITY_LEN) return -1;
            if (append_u16(tmp, tmp_cap, &o, psk->identity_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, psk->identity, psk->identity_len) != 0) return -1;
            break;
        }
        case KX_RSA: {
            const dtls_encrypted_premaster_secret_t *e = &cke->u.rsa.enc_pms;
            if (e->enc_pms_len > DTLS_MAX_RSA_ENC_PMS_LEN) return -1;
            if (append_u16(tmp, tmp_cap, &o, e->enc_pms_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, e->enc_pms, e->enc_pms_len) != 0) return -1;
            break;
        }
        case KX_DH_ANON:
        case KX_DHE_RSA:
        case KX_DHE_DSS:
        case KX_DH_DSS:
        case KX_DH_RSA: {
            const dtls_client_dh_public_t *dh = &cke->u.dh.dh_pub;
            if (dh->dh_Yc_len > DTLS_MAX_DH_Y_LEN) return -1;
            if (append_u16(tmp, tmp_cap, &o, dh->dh_Yc_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, dh->dh_Yc, dh->dh_Yc_len) != 0) return -1;
            break;
        }
        default: {
            /* default to ECDH shape if present */
            const dtls_ecdh_client_public_t *ec = &cke->u.ecdh.ecdh_pub;
            if (ec->ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
            if (append_u8(tmp, tmp_cap, &o, ec->ec_point_len) != 0) return -1;
            if (append_bytes(tmp, tmp_cap, &o, ec->ec_point, ec->ec_point_len) != 0) return -1;
            break;
        }
        }
        break;
    }
    case 20: { /* Finished (plaintext) */
        if (o + DTLS_VERIFY_DATA_LEN > tmp_cap) return -1;
        memcpy(tmp + o, pkt->payload.handshake.body.finished.verify_data, DTLS_VERIFY_DATA_LEN);
        o += DTLS_VERIFY_DATA_LEN;
        break;
    }
    default: {
        // u32 l = pkt->payload.handshake.raw_body_len;
        // if (l > tmp_cap) return -1;
        // if (l) memcpy(tmp, pkt->payload.handshake.raw_body, l);
        // *body_len_out = l;
        // return 0;
        return -1;
    }
    }

    *body_len_out = o;
    return 0;
}

/* ---------------- reassembler ---------------- */

int reassemble_dtls_msgs(const dtls_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len)
{
    if (!output_buf) return -1;

    u32 cap = 1024 * 1024; /* conservative default */
    u32 off = 0;

    for (u32 i = 0; i < num_packets; i++) {
        const dtls_packet_t *pkt = &packets[i];

        if (pkt->kind == DTLS_PKT_HANDSHAKE) {
            u8  body_tmp[DTLS_MAX_HANDSHAKE_RAW];
            u32 body_len = 0;

            if (serialize_handshake_body(pkt, body_tmp, sizeof(body_tmp), &body_len) != 0)
                continue;

            const dtls_handshake_header_t *hh = &pkt->payload.handshake.handshake_header;

            u16 rec_len = (u16)(12u + body_len);

            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;

            /* Handshake header: canonicalize fragment fields (0, body_len) */
            if (append_u8(output_buf, cap, &off, hh->msg_type) != 0) continue;
            if (append_u24(output_buf, cap, &off, body_len) != 0) continue;
            if (append_u16(output_buf, cap, &off, hh->message_seq) != 0) continue;
            if (append_u24(output_buf, cap, &off, 0) != 0) continue;
            if (append_u24(output_buf, cap, &off, body_len) != 0) continue;

            if (append_bytes(output_buf, cap, &off, body_tmp, body_len) != 0)
                continue;

        } else if (pkt->kind == DTLS_PKT_CHANGE_CIPHER_SPEC) {
            u16 rec_len = 1;
            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;
            if (append_u8(output_buf, cap, &off, pkt->payload.change_cipher_spec.value) != 0)
                continue;

        } else if (pkt->kind == DTLS_PKT_ALERT) {
            u16 rec_len = 2;
            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;
            if (append_u8(output_buf, cap, &off, pkt->payload.alert.level) != 0)
                continue;
            if (append_u8(output_buf, cap, &off, pkt->payload.alert.description) != 0)
                continue;

        } else if (pkt->kind == DTLS_PKT_APPLICATION_DATA) {
            u16 rec_len = pkt->payload.application_data.data_len;
            if (rec_len > DTLS_MAX_APPDATA_LEN) continue;
            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;
            if (append_bytes(output_buf, cap, &off, pkt->payload.application_data.data, rec_len) != 0)
                continue;

        } else if (pkt->kind == DTLS_PKT_ENCRYPTED) {
            u16 rec_len = pkt->payload.encrypted.ciphertext_len;
            if (rec_len > DTLS_MAX_CIPHERTEXT_LEN) continue;
            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;
            if (append_bytes(output_buf, cap, &off, pkt->payload.encrypted.ciphertext, rec_len) != 0)
                continue;

        } else {
            continue;
        }
    }

    *out_len = off;
    return 0;
}
