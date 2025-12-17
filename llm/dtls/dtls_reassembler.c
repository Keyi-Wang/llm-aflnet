/* dtls reassembler 
 *
 * Implements:
 *   int reassemble_dtls_msgs(const dtls_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);
 *
 * Notes:
 *  - Does NOT decrypt. epoch>0 handshake/application_data are treated as DTLS_PKT_ENCRYPTED (opaque bytes).

 *  - For reassembly:
 *      * For known msg_type: serialize from typed fields.
 *      * For unknown msg_type: serialize from raw_body[].
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

/* Serialize plaintext handshake body from typed fields; return 0 on success, -1 on failure */
static int serialize_handshake_body(const dtls_packet_t *pkt, u8 *tmp, u32 tmp_cap, u32 *body_len_out) {
    if (!pkt || !tmp || !body_len_out) return -1;
    *body_len_out = 0;

    const dtls_handshake_header_t *hh = &pkt->payload.handshake.handshake_header;
    u8 t = hh->msg_type;
    u32 o = 0;

    /* If parser stored raw body (unknown/unparsable), use it for byte-identical output. */
    if (pkt->payload.handshake.raw_body_len != 0) {
        u32 l = pkt->payload.handshake.raw_body_len;
        if (l > tmp_cap) return -1;
        memcpy(tmp, pkt->payload.handshake.raw_body, l);
        *body_len_out = l;
        return 0;
    }

    switch (t) {
    case 1: { /* ClientHello */
        const dtls_client_hello_t *ch = &pkt->payload.handshake.body.client_hello;

        if (o + 2 + 32 + 1 > tmp_cap) return -1;
        tmp[o++] = ch->client_version.major;
        tmp[o++] = ch->client_version.minor;
        memcpy(tmp + o, ch->random.bytes, 32); o += 32;

        if (ch->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
        if (o + 1 + ch->session_id.len > tmp_cap) return -1;
        tmp[o++] = ch->session_id.len;
        memcpy(tmp + o, ch->session_id.id, ch->session_id.len);
        o += ch->session_id.len;

        if (ch->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
        if (o + 1 + ch->cookie_len > tmp_cap) return -1;
        tmp[o++] = ch->cookie_len;
        memcpy(tmp + o, ch->cookie, ch->cookie_len);
        o += ch->cookie_len;

        if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES) return -1;
        if (o + 2 + ch->cipher_suites_len > tmp_cap) return -1;
        tmp[o++] = (u8)(ch->cipher_suites_len >> 8);
        tmp[o++] = (u8)(ch->cipher_suites_len & 0xff);
        memcpy(tmp + o, ch->cipher_suites, ch->cipher_suites_len);
        o += ch->cipher_suites_len;

        if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN) return -1;
        if (o + 1 + ch->compression_methods_len > tmp_cap) return -1;
        tmp[o++] = ch->compression_methods_len;
        memcpy(tmp + o, ch->compression_methods, ch->compression_methods_len);
        o += ch->compression_methods_len;

        if (ch->extensions.present) {
            if (ch->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
            if (o + 2 + ch->extensions.total_len > tmp_cap) return -1;
            tmp[o++] = (u8)(ch->extensions.total_len >> 8);
            tmp[o++] = (u8)(ch->extensions.total_len & 0xff);
            memcpy(tmp + o, ch->extensions.raw, ch->extensions.total_len);
            o += ch->extensions.total_len;
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
        if (o + 1 + sh->session_id.len > tmp_cap) return -1;
        tmp[o++] = sh->session_id.len;
        memcpy(tmp + o, sh->session_id.id, sh->session_id.len);
        o += sh->session_id.len;

        if (o + 2 + 1 > tmp_cap) return -1;
        tmp[o++] = (u8)(sh->cipher_suite >> 8);
        tmp[o++] = (u8)(sh->cipher_suite & 0xff);
        tmp[o++] = sh->compression_method;

        if (sh->extensions.present) {
            if (sh->extensions.total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;
            if (o + 2 + sh->extensions.total_len > tmp_cap) return -1;
            tmp[o++] = (u8)(sh->extensions.total_len >> 8);
            tmp[o++] = (u8)(sh->extensions.total_len & 0xff);
            memcpy(tmp + o, sh->extensions.raw, sh->extensions.total_len);
            o += sh->extensions.total_len;
        }

        break;
    }
    case 3: { /* HelloVerifyRequest */
        const dtls_hello_verify_request_t *hv = &pkt->payload.handshake.body.hello_verify_request;

        if (o + 2 + 1 > tmp_cap) return -1;
        tmp[o++] = hv->server_version.major;
        tmp[o++] = hv->server_version.minor;

        if (hv->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
        tmp[o++] = hv->cookie_len;
        if (o + hv->cookie_len > tmp_cap) return -1;
        memcpy(tmp + o, hv->cookie, hv->cookie_len);
        o += hv->cookie_len;

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
    case 12: { /* ServerKeyExchange */
        const dtls_server_key_exchange_ecdhe_t *ske = &pkt->payload.handshake.body.server_key_exchange;
        if (o + 1 + 2 + 1 > tmp_cap) return -1;

        tmp[o++] = ske->curve_type;
        tmp[o++] = (u8)(ske->named_curve >> 8);
        tmp[o++] = (u8)(ske->named_curve & 0xff);

        if (ske->ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
        if (o + 1 + ske->ec_point_len + 2 + 2 > tmp_cap) return -1;

        tmp[o++] = ske->ec_point_len;
        memcpy(tmp + o, ske->ec_point, ske->ec_point_len);
        o += ske->ec_point_len;

        tmp[o++] = ske->hash_algorithm;
        tmp[o++] = ske->signature_algorithm;

        if (ske->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
        tmp[o++] = (u8)(ske->signature_len >> 8);
        tmp[o++] = (u8)(ske->signature_len & 0xff);

        if (o + ske->signature_len > tmp_cap) return -1;
        memcpy(tmp + o, ske->signature, ske->signature_len);
        o += ske->signature_len;

        break;
    }
    case 16: { /* ClientKeyExchange */
        const dtls_client_key_exchange_body_t *cke = &pkt->payload.handshake.body.client_key_exchange;

        if (cke->kx_type == 1) {
            if (cke->u.psk.identity_len > DTLS_MAX_PSK_IDENTITY_LEN) return -1;
            if (o + 2 + cke->u.psk.identity_len > tmp_cap) return -1;
            tmp[o++] = (u8)(cke->u.psk.identity_len >> 8);
            tmp[o++] = (u8)(cke->u.psk.identity_len & 0xff);
            memcpy(tmp + o, cke->u.psk.identity, cke->u.psk.identity_len);
            o += cke->u.psk.identity_len;
        } else {
            if (cke->u.ecdh.ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
            if (o + 1 + cke->u.ecdh.ec_point_len > tmp_cap) return -1;
            tmp[o++] = cke->u.ecdh.ec_point_len;
            memcpy(tmp + o, cke->u.ecdh.ec_point, cke->u.ecdh.ec_point_len);
            o += cke->u.ecdh.ec_point_len;
        }
        break;
    }
    case 15: { /* CertificateVerify */
        const dtls_certificate_verify_body_t *cv = &pkt->payload.handshake.body.certificate_verify;
        if (o + 2 + 2 > tmp_cap) return -1;

        tmp[o++] = cv->alg.hash_algorithm;
        tmp[o++] = cv->alg.signature_algorithm;

        if (cv->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
        tmp[o++] = (u8)(cv->signature_len >> 8);
        tmp[o++] = (u8)(cv->signature_len & 0xff);

        if (o + cv->signature_len > tmp_cap) return -1;
        memcpy(tmp + o, cv->signature, cv->signature_len);
        o += cv->signature_len;

        break;
    }
    case 20: { /* Finished (plaintext) */
        if (o + DTLS_VERIFY_DATA_LEN > tmp_cap) return -1;
        memcpy(tmp + o, pkt->payload.handshake.body.finished.verify_data, DTLS_VERIFY_DATA_LEN);
        o += DTLS_VERIFY_DATA_LEN;
        break;
    }
    case 14: { /* ServerHelloDone*/
        *body_len_out = 0;
        return 0;
    }

    default: {
        u32 l = pkt->payload.handshake.raw_body_len; 
        if (l > tmp_cap) return -1;
        if (l) memcpy(tmp, pkt->payload.handshake.raw_body, l);
        *body_len_out = l;
        return 0;
    }
    }

    *body_len_out = o;
    return 0;
}

/* ---------------- reassembler ---------------- */

int reassemble_dtls_msgs(const dtls_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len)
{
    if (!out_len || !output_buf) return -1;

    /* MR harness usually provides capacity in *out_len */
    u32 cap = 1024*1024;
    u32 off = 0;

    for (u32 i = 0; i < num_packets; i++) {
        const dtls_packet_t *pkt = &packets[i];

        if (pkt->kind == DTLS_PKT_HANDSHAKE) {
            /* serialize body into temporary buffer */
            u8 body_tmp[DTLS_MAX_HANDSHAKE_RAW];
            u32 body_len = 0;

            if (serialize_handshake_body(pkt, body_tmp, sizeof(body_tmp), &body_len) != 0)
                continue;

            const dtls_handshake_header_t *hh = &pkt->payload.handshake.handshake_header;

            /* record payload length = handshake header (12) + body */
            u16 rec_len = (u16)(12u + body_len);

            /* write record header with recomputed length */
            if (append_record_header(output_buf, cap, &off, &pkt->record_header, rec_len) != 0)
                continue;

            /* write handshake header (length/frag_len recomputed to body_len; frag_off=0) */
            if (append_u8(output_buf, cap, &off, hh->msg_type) != 0) continue;
            if (append_u24(output_buf, cap, &off, body_len) != 0) continue;
            if (append_u16(output_buf, cap, &off, hh->message_seq) != 0) continue;
            if (append_u24(output_buf, cap, &off, 0) != 0) continue;
            if (append_u24(output_buf, cap, &off, body_len) != 0) continue;

            /* write body */
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