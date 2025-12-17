/* dtls parser
 *
 * Implements:
 *   size_t parse_dtls_msg(const u8 *buf, u32 buf_len, dtls_packet_t *out_packets, u32 max_count);
 *
 * Notes:
 *  - Does NOT decrypt. epoch>0 handshake/application_data are treated as DTLS_PKT_ENCRYPTED (opaque bytes).
 *  - For plaintext handshake epoch==0:
 *      * Known msg_type: parse into typed union fields.
 *      * Unknown msg_type: store raw_body[] so reassembly is byte-identical.
 */

#include "dtls.h"
#include <string.h>
#include <stddef.h>


/* ---------------- helpers ---------------- */

static u16 rd_u16(const u8 *p) { return (u16)(((u16)p[0] << 8) | (u16)p[1]); }
static u32 rd_u24(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2]; }

static void set_zero(void *p, size_t n) { if (p && n) memset(p, 0, n); }

/* ---------------- parsing: body-specific ---------------- */

static int parse_client_hello(const u8 *body, u32 body_len, dtls_client_hello_t *ch) {
    u32 o = 0;
    if (!body || !ch) return -1;

    if (body_len < 2 + 32 + 1 + 1 + 2 + 1 + 2) return -1; /* rough minimum */

    /* client_version */
    ch->client_version.major = body[o++];
    ch->client_version.minor = body[o++];

    /* random */
    memcpy(ch->random.bytes, body + o, 32); o += 32;

    /* session_id */
    ch->session_id.len = body[o++];
    if (ch->session_id.len > DTLS_MAX_SESSION_ID_LEN) return -1;
    if (o + ch->session_id.len > body_len) return -1;
    memcpy(ch->session_id.id, body + o, ch->session_id.len);
    o += ch->session_id.len;

    /* cookie */
    ch->cookie_len = body[o++];
    if (ch->cookie_len > DTLS_MAX_COOKIE_LEN) return -1;
    if (o + ch->cookie_len > body_len) return -1;
    memcpy(ch->cookie, body + o, ch->cookie_len);
    o += ch->cookie_len;

    /* cipher_suites */
    if (o + 2 > body_len) return -1;
    ch->cipher_suites_len = rd_u16(body + o); o += 2;
    if (ch->cipher_suites_len > DTLS_MAX_CIPHER_SUITES_BYTES) return -1;
    if (o + ch->cipher_suites_len > body_len) return -1;
    memcpy(ch->cipher_suites, body + o, ch->cipher_suites_len);
    o += ch->cipher_suites_len;

    /* compression_methods */
    if (o + 1 > body_len) return -1;
    ch->compression_methods_len = body[o++];
    if (ch->compression_methods_len > DTLS_MAX_COMPRESSION_METHODS_LEN) return -1;
    if (o + ch->compression_methods_len > body_len) return -1;
    memcpy(ch->compression_methods, body + o, ch->compression_methods_len);
    o += ch->compression_methods_len;

    /* extensions (optional in TLS; but common) */
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

    /* extensions (optional in TLS; but common) */
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

static int parse_server_key_exchange_ecdhe(const u8 *body, u32 body_len, dtls_server_key_exchange_ecdhe_t *ske) {
    u32 o = 0;
    if (!body || !ske) return -1;
    if (body_len < 1 + 2 + 1) return -1;

    ske->curve_type = body[o++];
    ske->named_curve = rd_u16(body + o); o += 2;

    ske->ec_point_len = body[o++];
    if (ske->ec_point_len > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;
    if (o + ske->ec_point_len + 2 + 2 > body_len) return -1;

    memcpy(ske->ec_point, body + o, ske->ec_point_len);
    o += ske->ec_point_len;

    ske->hash_algorithm = body[o++];
    ske->signature_algorithm = body[o++];

    ske->signature_len = rd_u16(body + o); o += 2;
    if (ske->signature_len > DTLS_MAX_SIGNATURE_LEN) return -1;
    if (o + ske->signature_len != body_len) return -1;

    memcpy(ske->signature, body + o, ske->signature_len);
    return 0;
}

/* Heuristic dispatch: if body starts with uint16 and remaining equals that length => PSK identity */
static int parse_client_key_exchange(const u8 *body, u32 body_len, dtls_client_key_exchange_body_t *cke) {
    if (!body || !cke) return -1;
    if (body_len == 0) return -1;

    if (body_len >= 2) {
        u16 idlen = rd_u16(body);
        if ((u32)idlen + 2 == body_len && idlen <= DTLS_MAX_PSK_IDENTITY_LEN) {
            cke->kx_type = 1; /* PSK */
            cke->u.psk.identity_len = idlen;
            memcpy(cke->u.psk.identity, body + 2, idlen);
            return 0;
        }
    }

    /* ECDH: opaque ECPoint<1..2^8-1> */
    u8 ptlen = body[0];
    if ((u32)ptlen + 1 != body_len) return -1;
    if (ptlen > DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN) return -1;

    cke->kx_type = 0;
    cke->u.ecdh.ec_point_len = ptlen;
    memcpy(cke->u.ecdh.ec_point, body + 1, ptlen);
    return 0;
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

/* ---------------- main parser ---------------- */

size_t parse_dtls_msg(const u8 *buf, u32 buf_len, dtls_packet_t *out_packets, u32 max_count)
{
    if (!buf || !out_packets || max_count == 0) return 0;

    u32 off = 0;
    u32 count = 0;

    while (off + 13 <= buf_len && count < max_count) {
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

        /* ---- classify ---- */
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

            /* default raw */
            pkt->payload.handshake.raw_body_len = 0;

            int ok = -1;
            switch (H->msg_type) {
            case 1:  ok = parse_client_hello(body, h_body_len, &pkt->payload.handshake.body.client_hello); break;
            case 2:  ok = parse_server_hello(body, h_body_len, &pkt->payload.handshake.body.server_hello); break;
            case 3:  ok = parse_hello_verify_request(body, h_body_len, &pkt->payload.handshake.body.hello_verify_request); break;
            case 11: ok = parse_certificate_blob(body, h_body_len, &pkt->payload.handshake.body.certificate); break;
            case 12: ok = parse_server_key_exchange_ecdhe(body, h_body_len, &pkt->payload.handshake.body.server_key_exchange); break;
            case 16: ok = parse_client_key_exchange(body, h_body_len, &pkt->payload.handshake.body.client_key_exchange); break;
            case 15: ok = parse_certificate_verify(body, h_body_len, &pkt->payload.handshake.body.certificate_verify); break;
            case 20: ok = parse_finished_plain(body, h_body_len, &pkt->payload.handshake.body.finished); break;
            case 14: /* ServerHelloDone */
                ok = (h_body_len == 0) ? 0 : -1;
                break;
            default:
                ok = -1;
                break;
            }

            if (ok != 0) {
                /* store raw for unknown/unsupported/plaintext-unparsable handshake so MR can still pass */
                if (h_body_len > DTLS_MAX_HANDSHAKE_RAW) break;
                pkt->payload.handshake.raw_body_len = (u16)h_body_len;
                memcpy(pkt->payload.handshake.raw_body, body, h_body_len);
            } else {
                /* for known types: also store raw to guarantee byte-identical reassembly if desired
                   (optional; here we store only when needed to keep packet smaller) */
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
            /* encrypted / unknown: store opaque bytes */
            pkt->kind = DTLS_PKT_ENCRYPTED;
            if (plen > DTLS_MAX_CIPHERTEXT_LEN) break;
            pkt->payload.encrypted.ciphertext_len = plen;
            memcpy(pkt->payload.encrypted.ciphertext, payload, plen);
        }

        off += plen;
        count++;
    }

    return (size_t)count;
}


