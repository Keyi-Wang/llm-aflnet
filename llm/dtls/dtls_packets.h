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

/* generic extension container */
typedef struct {
    uint16_t ext_type;
    uint16_t ext_len;
    uint8_t  ext_data[DTLS_MAX_EXTENSIONS_LEN];
} dtls_extension_t;

typedef struct {
    uint16_t total_len;
    uint8_t  raw[DTLS_MAX_EXTENSIONS_LEN];
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

typedef struct {
    dtls_record_header_t    record;
    dtls_handshake_header_t handshake;
    dtls_client_hello_t     body;
} dtls_client_hello_packet_t;

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

typedef struct {
    uint8_t  curve_type;      /* named_curve = 3 */
    uint16_t named_curve;     /* e.g. secp256r1 = 23 */

    uint8_t  ec_point_len;
    uint8_t  ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];

    uint8_t  hash_algorithm;      /* e.g. SHA256 = 4 */
    uint8_t  signature_algorithm; /* e.g. ECDSA = 3 */

    uint16_t signature_len;
    uint8_t  signature[DTLS_MAX_SIGNATURE_LEN];
} dtls_server_key_exchange_ecdhe_t;

/* ---------- ClientKeyExchange ---------- */

/* ECC variant */
typedef struct {
    uint8_t ec_point_len;
    uint8_t ec_point[DTLS_MAX_CLIENT_KEY_EXCHANGE_LEN];
} dtls_client_key_exchange_ecdh_t;

/* PSK variant */
typedef struct {
    uint16_t identity_len;
    uint8_t  identity[DTLS_MAX_PSK_IDENTITY_LEN];
} dtls_client_key_exchange_psk_t;

/* union wrapper */
typedef struct {
    uint8_t kx_type; /* internal discriminator */
    union {
        dtls_client_key_exchange_ecdh_t ecdh;
        dtls_client_key_exchange_psk_t  psk;
    } u;
} dtls_client_key_exchange_body_t;

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

/* ---------- Generic handshake packet wrapper ---------- */

typedef struct {
    dtls_record_header_t    record;
    dtls_handshake_header_t handshake;
    uint8_t                 body[];
} dtls_handshake_packet_t;

/* ---------- Encrypted handshake / application data ---------- */

typedef struct {
    dtls_record_header_t record;
    uint8_t             ciphertext[];
} dtls_encrypted_record_t;


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
    dtls_client_hello_t                 client_hello;
    dtls_server_hello_t                 server_hello;
    dtls_hello_verify_request_t         hello_verify_request;
    dtls_certificate_body_t             certificate;
    dtls_server_key_exchange_ecdhe_t    server_key_exchange;
    dtls_client_key_exchange_body_t     client_key_exchange;
    dtls_certificate_verify_body_t      certificate_verify;
    dtls_finished_body_t                finished;
} dtls_handshake_body_u;

/* Unified DTLS packet */
typedef struct {
    dtls_record_header_t record_header;
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

