/* ===== DTLS 1.2 packet definitions (RFC 6347 / RFC 5246)
 * Covers:
 *  - ECC (ECDHE_ECDSA)
 *  - PSK
 *  - ClientHello / ServerHello extensions
 *  - HelloVerifyRequest
 *  - Certificate (RPK / X.509-compatible blob)
 *  - ServerKeyExchange (ECDHE)
 *  - ClientKeyExchange (ECC / PSK variants)
 *  - CertificateVerify
 *  - Finished
 *  - ChangeCipherSpec
 */

#include <stdint.h>

/* ---------- common helpers ---------- */

typedef struct { uint8_t b[3]; } uint24_t;
typedef struct { uint8_t b[6]; } uint48_t;

/* ---------- limits ---------- */

#define DTLS_MAX_SESSION_ID_LEN            32
#define DTLS_MAX_COOKIE_LEN               255
#define DTLS_MAX_CIPHER_SUITES_BYTES     256
#define DTLS_MAX_COMPRESSION_METHODS_LEN   16
#define DTLS_MAX_EXTENSIONS_LEN          512

#define DTLS_MAX_CERT_BLOB_LEN          8192
#define DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN 512
#define DTLS_MAX_PSK_IDENTITY_LEN        256
#define DTLS_MAX_SIGNATURE_LEN          512
#define DTLS_VERIFY_DATA_LEN              12
#define DTLS_MAX_APPDATA_LEN     2048
#define DTLS_MAX_CIPHERTEXT_LEN  2048
#define DTLS_MAX_HANDSHAKE_RAW   2048   
#define DTLS_MAX_CERT_TYPES_LEN  32
#define DTLS_MAX_CA_DN_LEN       4096
#define DTLS_MAX_SIG_ALGS_LEN    256

#define DTLS_MAX_DH_P_LEN 512
#define DTLS_MAX_DH_G_LEN 512
#define DTLS_MAX_DH_Y_LEN 512
#define DTLS_MAX_RSA_ENC_PMS_LEN 512

/* ---------- Record Layer ---------- */

typedef struct {
    uint8_t  type;            /* ContentType */
    uint8_t  version_major;   /* 0xFE */
    uint8_t  version_minor;   /* 0xFD */
    uint16_t epoch;
    uint48_t sequence_number;
    uint16_t length;
} dtls_record_header_t;

/* ---------- Handshake Layer ---------- */

typedef struct {
    uint8_t  msg_type;        /* HandshakeType */
    uint24_t length;
    uint16_t message_seq;
    uint24_t fragment_offset;
    uint24_t fragment_length;
} dtls_handshake_header_t;

/* ---------- ClientHello / ServerHello ---------- */

typedef struct {
    uint8_t major;
    uint8_t minor;
} dtls_protocol_version_t;

typedef struct {
    uint8_t bytes[32];
} dtls_random_t;

typedef struct {
    uint8_t len;
    uint8_t id[DTLS_MAX_SESSION_ID_LEN];
} dtls_session_id_t;


typedef struct {
    uint16_t total_len;
    uint8_t  raw[DTLS_MAX_EXTENSIONS_LEN];
    uint8_t  present; 
} dtls_extensions_block_t;

/* ---- ClientHello ---- */

typedef struct {
    dtls_protocol_version_t client_version;
    dtls_random_t           random;
    dtls_session_id_t       session_id;

    uint8_t  cookie_len;
    uint8_t  cookie[DTLS_MAX_COOKIE_LEN];

    uint16_t cipher_suites_len;
    uint8_t  cipher_suites[DTLS_MAX_CIPHER_SUITES_BYTES];

    uint8_t  compression_methods_len;
    uint8_t  compression_methods[DTLS_MAX_COMPRESSION_METHODS_LEN];

    dtls_extensions_block_t extensions;
} dtls_client_hello_t;


/* ---- ServerHello ---- */

typedef struct {
    dtls_protocol_version_t server_version;
    dtls_random_t           random;
    dtls_session_id_t       session_id;

    uint16_t cipher_suite;
    uint8_t  compression_method;

    dtls_extensions_block_t extensions;
} dtls_server_hello_t;

/* ---------- HelloVerifyRequest ---------- */

typedef struct {
    dtls_protocol_version_t server_version;
    uint8_t cookie_len;
    uint8_t cookie[DTLS_MAX_COOKIE_LEN];
} dtls_hello_verify_request_t;

/* ---------- Certificate ---------- */
/* Supports both X.509 chains and RawPublicKey/SPKI blob */

typedef struct {
    uint24_t cert_blob_len;
    uint8_t  cert_blob[DTLS_MAX_CERT_BLOB_LEN];
} dtls_certificate_body_t;

/* ---------- ServerKeyExchange (ECDHE_ECDSA) ---------- */

// typedef struct {
//     uint8_t  curve_type;      /* named_curve = 3 */
//     uint16_t named_curve;     /* e.g. secp256r1 = 23 */

//     uint8_t  ec_point_len;
//     uint8_t  ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];

//     uint8_t  hash_algorithm;      /* e.g. SHA256 = 4 */
//     uint8_t  signature_algorithm; /* e.g. ECDSA = 3 */

//     uint16_t signature_len;
//     uint8_t  signature[DTLS_MAX_SIGNATURE_LEN];
// } dtls_server_key_exchange_ecdhe_t;

/* ---------- ClientKeyExchange ---------- */

// /* ECC variant */
// typedef struct {
//     uint8_t ec_point_len;
//     uint8_t ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];
// } dtls_client_key_exchange_ecdh_t;

// /* PSK variant */
// typedef struct {
//     uint16_t identity_len;
//     uint8_t  identity[DTLS_MAX_PSK_IDENTITY_LEN];
// } dtls_client_key_exchange_psk_t;


/* ---------- CertificateVerify ---------- */

typedef struct {
    uint8_t hash_algorithm;
    uint8_t signature_algorithm;
} dtls_signature_and_hash_t;

typedef struct {
    dtls_signature_and_hash_t alg;
    uint16_t signature_len;
    uint8_t  signature[DTLS_MAX_SIGNATURE_LEN];
} dtls_certificate_verify_body_t;

/* ---------- Finished ---------- */

typedef struct {
    uint8_t verify_data[DTLS_VERIFY_DATA_LEN];
} dtls_finished_body_t;

/* ---------- ChangeCipherSpec ---------- */

typedef struct {
    uint8_t value; /* always 0x01 */
} dtls_change_cipher_spec_t;

/* ---------- CertificateRequest (TLS 1.2 / DTLS 1.2) ---------- */
typedef struct {
    uint8_t  cert_types_len;                         /* 1..255 */
    uint8_t  cert_types[DTLS_MAX_CERT_TYPES_LEN];     /* client_certificate_type values */

    uint16_t sig_algs_len;                            /* bytes, even number (pairs) */
    uint8_t  sig_algs[DTLS_MAX_SIG_ALGS_LEN];         /* (hash, sig) pairs */

    uint16_t ca_dn_len;                               /* bytes */
    uint8_t  ca_dn_blob[DTLS_MAX_CA_DN_LEN];          /* raw DistinguishedName list encoding */
} dtls_certificate_request_t;


typedef struct {
    uint8_t _dummy; /* unused; keep non-empty to avoid some compilers warning on empty struct */
} dtls_server_hello_done_t;

/* ---------- HelloRequest ----------
 * TLS 1.2 / DTLS 1.2: body is empty.
 * Keep a non-empty struct for portability.
 */
typedef struct {
    uint8_t _dummy; /* unused */
} dtls_hello_request_t;





/* ===================== Enums ===================== */

typedef enum {
    KX_UNKNOWN = 0,

    /* Classic DH family */
    KX_DH_ANON,
    KX_DHE_DSS,
    KX_DHE_RSA,
    KX_DH_DSS,
    KX_DH_RSA,

    /* RSA key exchange */
    KX_RSA,

    /* Static ECDH (cert-based) */
    KX_ECDH_ECDSA,
    KX_ECDH_RSA,
    KX_ECDH_ANON,

    /* Ephemeral ECDHE (signed) */
    KX_ECDHE_ECDSA,
    KX_ECDHE_RSA,

    /* PSK family */
    KX_PSK,
    KX_DHE_PSK,
    KX_RSA_PSK,
    KX_ECDHE_PSK
} dtls_kx_alg_t;

typedef enum {
    SIG_ANON  = 0,
    SIG_RSA   = 1,
    SIG_DSA   = 2,
    SIG_ECDSA = 3
} dtls_sig_alg_t;

typedef enum {
    HASH_NONE   = 0,
    HASH_MD5    = 1,
    HASH_SHA1   = 2,
    HASH_SHA224 = 3,
    HASH_SHA256 = 4,
    HASH_SHA384 = 5,
    HASH_SHA512 = 6
} dtls_hash_alg_t;


/* DigitallySigned (TLS 1.2) */
typedef struct {
    dtls_signature_and_hash_t alg;
    uint16_t signature_len;
    uint8_t  signature[DTLS_MAX_SIGNATURE_LEN];
} dtls_digitally_signed_t;

/* ===================== DH (RFC 5246) ===================== */

typedef struct {
    uint16_t dh_p_len;
    uint8_t  dh_p[DTLS_MAX_DH_P_LEN];

    uint16_t dh_g_len;
    uint8_t  dh_g[DTLS_MAX_DH_G_LEN];

    uint16_t dh_Ys_len;
    uint8_t  dh_Ys[DTLS_MAX_DH_Y_LEN];
} dtls_server_dh_params_t;

typedef struct {
    uint16_t dh_Yc_len;
    uint8_t  dh_Yc[DTLS_MAX_DH_Y_LEN];
} dtls_client_dh_public_t;

/* ===================== ECDH/ECDHE (TLSECC-style) ===================== */
/*
 * ECParameters (we model named_curve only) + ECPoint.
 * This supports:
 *  - ServerKeyExchange for ECDHE_* (params + signature)
 *  - (Optional) ServerKeyExchange for ECDH_* if an implementation sends it
 *  - ClientKeyExchange for ECDH/ECDHE (client ECPoint only)
 */
typedef struct {
    uint8_t  curve_type;   /* named_curve = 3 */
    uint16_t named_curve;  /* e.g., secp256r1 = 23 */

    uint8_t  ec_point_len; /* Server's ephemeral/static ECDH public */
    uint8_t  ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];
} dtls_ecdh_server_params_t;

typedef struct {
    uint8_t  ec_point_len; /* ClientECDiffieHellmanPublic */
    uint8_t  ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];
} dtls_ecdh_client_public_t;

/* ===================== PSK ===================== */

typedef struct {
    uint16_t identity_hint_len;
    uint8_t  identity_hint[DTLS_MAX_PSK_IDENTITY_LEN];
} dtls_psk_identity_hint_t;

typedef struct {
    uint16_t identity_len;
    uint8_t  identity[DTLS_MAX_PSK_IDENTITY_LEN];
} dtls_psk_identity_t;

/* ===================== RSA ===================== */

typedef struct {
    uint16_t enc_pms_len;
    uint8_t  enc_pms[DTLS_MAX_RSA_ENC_PMS_LEN];
} dtls_encrypted_premaster_secret_t;

/* ===================== ServerKeyExchange (all KX) ===================== */

typedef struct {
    dtls_server_dh_params_t params; /* only params */
} dtls_ske_dh_anon_t;

typedef struct {
    dtls_server_dh_params_t params;
    dtls_digitally_signed_t sig;    /* covers client_random||server_random||params */
} dtls_ske_dhe_signed_t;

typedef struct {
    dtls_ecdh_server_params_t params;
    dtls_digitally_signed_t   sig;  /* covers client_random||server_random||params */
} dtls_ske_ecdhe_signed_t;

/* ECDH_* is usually "omitted" in classic TLS, but some stacks may emit params.
 * Keep both shapes: omitted and explicit params.
 */
typedef struct { uint8_t _dummy; } dtls_ske_omitted_t;

typedef struct {
    dtls_ecdh_server_params_t params; /* explicit ECDH params if present */
} dtls_ske_ecdh_params_only_t;

typedef struct {
    dtls_psk_identity_hint_t hint;
} dtls_ske_psk_t;

typedef struct {
    dtls_psk_identity_hint_t hint;
    dtls_server_dh_params_t  params; /* no signature */
} dtls_ske_dhe_psk_t;

typedef struct {
    dtls_psk_identity_hint_t hint;
} dtls_ske_rsa_psk_t;

typedef struct {
    dtls_psk_identity_hint_t hint;
    dtls_ecdh_server_params_t params; /* no signature */
} dtls_ske_ecdhe_psk_t;

typedef struct {
    dtls_kx_alg_t kx_alg;
    union {
        dtls_ske_dh_anon_t            dh_anon;        /* KX_DH_ANON */
        dtls_ske_dhe_signed_t         dhe_signed;     /* KX_DHE_DSS, KX_DHE_RSA */
        dtls_ske_ecdhe_signed_t       ecdhe_signed;   /* KX_ECDHE_ECDSA, KX_ECDHE_RSA */

        dtls_ske_ecdh_params_only_t   ecdh_params;    /* KX_ECDH_* if present */
        dtls_ske_omitted_t            omitted;        /* KX_RSA, KX_DH_DSS, KX_DH_RSA, or ECDH if omitted */

        dtls_ske_psk_t                psk;            /* KX_PSK */
        dtls_ske_dhe_psk_t            dhe_psk;        /* KX_DHE_PSK */
        dtls_ske_rsa_psk_t            rsa_psk;        /* KX_RSA_PSK */
        dtls_ske_ecdhe_psk_t          ecdhe_psk;      /* KX_ECDHE_PSK */
    } u;
} dtls_server_key_exchange_body_t;

/* ===================== ClientKeyExchange (all KX) ===================== */

typedef struct {
    dtls_encrypted_premaster_secret_t enc_pms; /* EncryptedPreMasterSecret */
} dtls_cke_rsa_t;

typedef struct {
    dtls_client_dh_public_t dh_pub; /* ClientDiffieHellmanPublic */
} dtls_cke_dh_t;

typedef struct {
    dtls_ecdh_client_public_t ecdh_pub; /* ClientECDiffieHellmanPublic */
} dtls_cke_ecdh_t;

typedef struct {
    dtls_psk_identity_t psk;
} dtls_cke_psk_t;

typedef struct {
    dtls_psk_identity_t      psk;
    dtls_client_dh_public_t  dh_pub;
} dtls_cke_dhe_psk_t;

typedef struct {
    dtls_psk_identity_t                 psk;
    dtls_encrypted_premaster_secret_t   enc_pms;
} dtls_cke_rsa_psk_t;

typedef struct {
    dtls_psk_identity_t        psk;
    dtls_ecdh_client_public_t  ecdh_pub;
} dtls_cke_ecdhe_psk_t;

typedef struct {
    dtls_kx_alg_t kx_alg;
    union {
        dtls_cke_rsa_t        rsa;        /* KX_RSA */
        dtls_cke_dh_t         dh;         /* KX_DH_ANON, KX_DHE_*, KX_DH_* */
        dtls_cke_ecdh_t       ecdh;       /* KX_ECDH_*, KX_ECDHE_* */
        dtls_cke_psk_t        psk;        /* KX_PSK */
        dtls_cke_dhe_psk_t    dhe_psk;    /* KX_DHE_PSK */
        dtls_cke_rsa_psk_t    rsa_psk;    /* KX_RSA_PSK */
        dtls_cke_ecdhe_psk_t  ecdhe_psk;  /* KX_ECDHE_PSK */
    } u;
} dtls_client_key_exchange_body_t;



/* ---------- Generic DTLS packet (all message types) ---------- */

typedef enum {
    DTLS_PKT_HANDSHAKE,
    DTLS_PKT_CHANGE_CIPHER_SPEC,
    DTLS_PKT_ALERT,
    DTLS_PKT_APPLICATION_DATA,
    DTLS_PKT_ENCRYPTED
} dtls_packet_kind_t;

/* Handshake message bodies (union) */
typedef union {
    dtls_hello_request_t                hello_request; //verified
    dtls_client_hello_t                 client_hello; //verified
    dtls_server_hello_t                 server_hello; //verified
    dtls_hello_verify_request_t         hello_verify_request; //verified

    dtls_certificate_body_t             certificate; //verified
    dtls_certificate_request_t          certificate_request;   //verified
    dtls_server_key_exchange_body_t    server_key_exchange;  //verified
    dtls_server_hello_done_t            server_hello_done;     //verified

    dtls_client_key_exchange_body_t     client_key_exchange; //verified
    dtls_certificate_verify_body_t      certificate_verify; //verified
    dtls_finished_body_t                finished;  //verified
} dtls_handshake_body_u;

/* Unified DTLS packet */
typedef struct {
    dtls_record_header_t record_header; //verified
    dtls_packet_kind_t   kind;

    union {
        struct {
            dtls_handshake_header_t handshake_header;
            dtls_handshake_body_u   body;

            uint16_t raw_body_len;
            uint8_t  raw_body[DTLS_MAX_HANDSHAKE_RAW];
        } handshake;

        dtls_change_cipher_spec_t change_cipher_spec;

        struct {
            uint8_t level;
            uint8_t description;
        } alert;

        struct {
            uint16_t data_len;
            uint8_t  data[DTLS_MAX_APPDATA_LEN];
        } application_data;

        struct {
            uint16_t ciphertext_len;
            uint8_t  ciphertext[DTLS_MAX_CIPHERTEXT_LEN];
        } encrypted;
    } payload;
} dtls_packet_t;

