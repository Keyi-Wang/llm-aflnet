/* dtls mutators source file */
#include "dtls.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* -------- minimal RNG -------- */
/* ===================== dtls_mutators_helpers.h (inline) =====================
 * Fix undefined references by providing local implementations.
 * Put this near the top of dtls_mutators.c (after includes).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* If your project already defines these, you can guard with #ifndef ... */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* ---- clamp helpers ---- */
static inline u32 clamp_u32(u32 v, u32 lo, u32 hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
// static inline u16 clamp_u16(u16 v, u16 lo, u16 hi) {
//     if (v < lo) return lo;
//     if (v > hi) return hi;
//     return v;
// }
// static inline u8 clamp_u8(u8 v, u8 lo, u8 hi) {
//     if (v < lo) return lo;
//     if (v > hi) return hi;
//     return v;
// }

/* ---- swap helpers ---- */
static inline void swap_u8(u8 *a, u8 *b) {
    if (!a || !b) return;
    u8 t = *a; *a = *b; *b = t;
}
static inline void swap_u16(u16 *a, u16 *b) {
    if (!a || !b) return;
    u16 t = *a; *a = *b; *b = t;
}
static inline void swap_u32(u32 *a, u32 *b) {
    if (!a || !b) return;
    u32 t = *a; *a = *b; *b = t;
}

/* ---- endian read/write ---- */
static inline u16 rd_u16(const u8 *p) {
    return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}
static inline void wr_u16(u8 *p, u16 v) {
    p[0] = (u8)(v >> 8);
    p[1] = (u8)(v & 0xff);
}
static inline u32 rd_u24(const u8 *p) {
    return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2];
}
static inline void wr_u24(u8 *p, u32 v) {
    p[0] = (u8)((v >> 16) & 0xff);
    p[1] = (u8)((v >> 8) & 0xff);
    p[2] = (u8)(v & 0xff);
}


static inline u32 xorshift32_state(u32 *state) {
    u32 x = (state && *state) ? *state : 0xA3C59AC3u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if (state) *state = x;
    return x;
}
/* ---------------- RNG core ---------------- */
static u32 g_dtls_rng_state = 0xA3C59AC3u; /* non-zero default */
/* old-style: xorshift32() */
static inline u32 xorshift32(void) {
    return xorshift32_state(&g_dtls_rng_state);
}

static inline u32 rnd_u32(u32 max_exclusive) {
    if (max_exclusive == 0) return 0;
    return xorshift32() % max_exclusive;
}

static inline u32 rnd_u32_state(u32 *state, u32 lo, u32 hi) {
    if (hi < lo) { u32 t = lo; lo = hi; hi = t; }
    u32 span = hi - lo + 1u;
    u32 r = xorshift32_state(state);
    /* avoid div-by-zero if span wraps (shouldn't happen for sane args) */
    if (span == 0) return lo;
    return lo + (r % span);
}

/* ---- memory rotate left (byte-wise) ---- */
static inline void mem_rotl(u8 *buf, size_t n, size_t k) {
    if (!buf || n == 0) return;
    k %= n;
    if (k == 0) return;

    /* O(n) rotation using temp up to small n; for large n use malloc? keep safe */
    u8 tmp[256];
    if (n <= sizeof(tmp)) {
        memcpy(tmp, buf, k);
        memmove(buf, buf + k, n - k);
        memcpy(buf + (n - k), tmp, k);
        return;
    }

    /* fallback: rotate by repeated swaps in chunks (still O(n)) */
    u8 *t = (u8 *)malloc(k);
    if (!t) return;
    memcpy(t, buf, k);
    memmove(buf, buf + k, n - k);
    memcpy(buf + (n - k), t, k);
    free(t);
}

/* ---- shuffle bytes ---- */
// static inline void shuffle(u8 *buf, size_t n, u32 *state) {
//     if (!buf || n < 2) return;
//     for (size_t i = n - 1; i > 0; i--) {
//         size_t j = (size_t)(rnd_u32_state(state, 0, (u32)i));
//         u8 t = buf[i];
//         buf[i] = buf[j];
//         buf[j] = t;
//     }
// }

static u32 g_seed_epoch = 0xA51CE0E1u;
static u32 xorshift32_epoch(void) {
    u32 x = g_seed_epoch;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_epoch = x;
    return x;
}
static u32 urand_epoch(u32 n) { return n ? (xorshift32_epoch() % n) : 0; }

/* -------- helpers -------- */
static int is_handshake_pkt(const dtls_packet_t *p) {
    return p && p->kind == DTLS_PKT_HANDSHAKE;
}
static u16 clamp_u16(u32 v) { return (u16)(v & 0xFFFFu); }

/* Field is NOT optional and NOT repeatable in the DTLS record header, so no add/delete/repeat. */

/* Semantic-aware mutator for record_header.epoch (DTLS record header, 16-bit) */
void mutate_record_header_epoch(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Precompute a plausible "current epoch" from existing traffic (most frequent non-zero). */
    u16 hint_epoch = 0;
    {
        u32 freq[4] = {0, 0, 0, 0}; /* epochs 0..3 */
        for (size_t i = 0; i < n; i++) {
            if (!is_handshake_pkt(&pkts[i])) continue;
            u16 e = pkts[i].record_header.epoch;
            if (e <= 3) freq[e]++;
        }
        /* prefer 1 if seen, else 0, else any */
        if (freq[1]) hint_epoch = 1;
        else if (freq[0]) hint_epoch = 0;
        else {
            for (u16 e = 2; e <= 3; e++) {
                if (freq[e]) { hint_epoch = e; break; }
            }
        }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_handshake_pkt(p)) continue;

        u16 cur = p->record_header.epoch;

        /* Pick a semantic category (A-H) with some randomized perturbations. */
        u32 cat = urand_epoch(100);

        if (cat < 18) {
            /* A. Canonical form:
               - Initial plaintext handshake records commonly use epoch=0. */
            p->record_header.epoch = 0;
        } else if (cat < 33) {
            /* B. Boundaries (still valid u16):
               - 0 (lowest) and 0xFFFF (highest, rare but in-range). */
            p->record_header.epoch = (urand_epoch(2) == 0) ? (u16)0 : (u16)0xFFFFu;
        } else if (cat < 48) {
            /* C. Equivalence-class alternatives:
               - 0: pre-CCS handshake
               - 1: post-CCS epoch (common for established session)
               - hint_epoch: inferred from nearby traffic patterns
               - cur: keep as-is (stability) */
            u32 pick = urand_epoch(4);
            if (pick == 0) p->record_header.epoch = 0;
            else if (pick == 1) p->record_header.epoch = 1;
            else if (pick == 2) p->record_header.epoch = hint_epoch;
            else p->record_header.epoch = cur;
        } else if (cat < 63) {
            /* D. Allowed enum/range:
               - Any u16 is allowed by the field definition; select "low, plausible" epochs. */
            static const u16 allowed_small[] = {0, 1, 2, 3, 4, 5, 8, 16, 32, 64};
            p->record_header.epoch = allowed_small[urand_epoch((u32)(sizeof(allowed_small)/sizeof(allowed_small[0])))];
        } else if (cat < 70) {
            /* E. Encoding-shape variant:
               - Not applicable (fixed-width integer in the model). Use "shape-preserving" toggle:
                 flip a single bit but keep within u16. */
            u16 bit = (u16)(1u << (urand_epoch(16)));
            p->record_header.epoch = (u16)(cur ^ bit);
        } else if (cat < 76) {
            /* F. Padding/alignment:
               - Not applicable (no padding field on wire for epoch).
                 Use a no-op safe normalization to avoid structural side-effects. */
            p->record_header.epoch = (u16)(cur); /* keep */
        } else if (cat < 90) {
            /* G. In-range sweep:
               - Sweep epochs in a small window around current/hint to explore state handling. */
            u16 base = (cur != 0) ? cur : hint_epoch;
            u16 delta = (u16)(urand_epoch(7));      /* 0..6 */
            int dir = (urand_epoch(2) == 0) ? -1 : 1;
            u32 v = (u32)base + (u32)(dir * (int)delta);
            p->record_header.epoch = clamp_u16(v);
        } else {
            /* H. Random valid mix:
               - Mix shallow (set to common values) and deep (random u16) to maintain diversity. */
            u32 mode = urand_epoch(4);
            if (mode == 0) p->record_header.epoch = 0;
            else if (mode == 1) p->record_header.epoch = 1;
            else if (mode == 2) p->record_header.epoch = hint_epoch;
            else p->record_header.epoch = (u16)(xorshift32_epoch() & 0xFFFFu);
        }

        /* Randomized perturbations (shallow+deep) while staying in-range (u16):
           - Occasionally correlate with nearby packets to prevent collapse into a single epoch. */
        if (urand_epoch(100) < 20) {
            /* shallow: snap to neighbor epoch if exists */
            if (i > 0 && is_handshake_pkt(&pkts[i - 1])) {
                if (urand_epoch(2) == 0) p->record_header.epoch = pkts[i - 1].record_header.epoch;
            }
            if (i + 1 < n && is_handshake_pkt(&pkts[i + 1])) {
                if (urand_epoch(2) == 0) p->record_header.epoch = pkts[i + 1].record_header.epoch;
            }
        }
        if (urand_epoch(100) < 8) {
            /* deep: multi-bit perturbation */
            u16 mask = (u16)(xorshift32_epoch() & 0xFFFFu);
            p->record_header.epoch = (u16)(p->record_header.epoch ^ mask);
        }
    }
}


/* -------- minimal RNG -------- */
static u32 g_seed_seq = 0x51A5C0DEu;
static u32 xorshift32_seq(void) {
    u32 x = g_seed_seq;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_seq = x;
    return x;
}
static u32 urand_seq(u32 n) { return n ? (xorshift32_seq() % n) : 0; }

/* -------- sequence_number helpers (48-bit, big-endian byte array) -------- */
static u64 rd_u48_be(const uint48_t *v) {
    const u8 *b = (const u8 *)v->b;
    return ((u64)b[0] << 40) | ((u64)b[1] << 32) | ((u64)b[2] << 24) |
           ((u64)b[3] << 16) | ((u64)b[4] << 8)  |  (u64)b[5];
}
static void wr_u48_be(uint48_t *v, u64 x) {
    u8 *b = (u8 *)v->b;
    b[0] = (u8)((x >> 40) & 0xFFu);
    b[1] = (u8)((x >> 32) & 0xFFu);
    b[2] = (u8)((x >> 24) & 0xFFu);
    b[3] = (u8)((x >> 16) & 0xFFu);
    b[4] = (u8)((x >> 8)  & 0xFFu);
    b[5] = (u8)( x        & 0xFFu);
}
static u64 clamp_u48(u64 x) { return x & 0xFFFFFFFFFFFFULL; }


/* Field is NOT optional and NOT repeatable in the DTLS record header, so no add/delete/repeat. */

void mutate_record_header_sequence_number(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Infer a plausible base and step (common case: monotonic +1 within an epoch). */
    u64 min_seen = 0xFFFFFFFFFFFFULL;
    u64 max_seen = 0;
    u32 seen = 0;

    for (size_t i = 0; i < n; i++) {
        if (!is_handshake_pkt(&pkts[i])) continue;
        u64 s = rd_u48_be(&pkts[i].record_header.sequence_number);
        if (s < min_seen) min_seen = s;
        if (s > max_seen) max_seen = s;
        seen++;
    }
    if (seen == 0) { min_seen = 0; max_seen = 0; }

    u64 base = (seen ? min_seen : 0);
    u64 span = (seen ? (max_seen - min_seen) : 0);
    if (span > 0xFFFFULL) span = 0xFFFFULL; /* keep "plausible window" bounded */

    /* Occasionally rewrite an entire run to a clean monotonic sequence (helps MR stability). */
    if (urand_seq(100) < 10) {
        u16 epoch_hint = 0;
        for (size_t i = 0; i < n; i++) {
            if (is_handshake_pkt(&pkts[i])) { epoch_hint = pkts[i].record_header.epoch; break; }
        }

        u64 s = 0;
        for (size_t i = 0; i < n; i++) {
            if (!is_handshake_pkt(&pkts[i])) continue;
            /* reset per epoch boundary (rough heuristic) */
            if (pkts[i].record_header.epoch != epoch_hint) {
                epoch_hint = pkts[i].record_header.epoch;
                s = 0;
            }
            wr_u48_be(&pkts[i].record_header.sequence_number, clamp_u48(s++));
        }
        /* continue with per-packet perturbations below */
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_handshake_pkt(p)) continue;

        u64 cur = rd_u48_be(&p->record_header.sequence_number);

        /* pick semantic category (A-H) */
        u32 cat = urand_seq(100);

        if (cat < 16) {
            /* A. Canonical form: monotonic increasing small numbers starting near base. */
            u64 v = base + (u64)(i % 32);
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
        } else if (cat < 28) {
            /* B. Boundaries: 0 and max 48-bit. */
            u64 v = (urand_seq(2) == 0) ? 0ULL : 0xFFFFFFFFFFFFULL;
            wr_u48_be(&p->record_header.sequence_number, v);
        } else if (cat < 44) {
            /* C. Equivalence-class alternatives:
               - keep current
               - neighbor copy
               - base
               - base+offset */
            u32 pick = urand_seq(4);
            u64 v = cur;
            if (pick == 1 && i > 0 && is_handshake_pkt(&pkts[i - 1])) {
                v = rd_u48_be(&pkts[i - 1].record_header.sequence_number);
            } else if (pick == 2) {
                v = base;
            } else if (pick == 3) {
                v = base + (u64)urand_seq((u32)(span + 1));
            }
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
        } else if (cat < 60) {
            /* D. Allowed range (48-bit):
               - choose "plausible" in-range values in a small window. */
            u64 v = base + (u64)urand_seq((u32)(span + 1));
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
        } else if (cat < 70) {
            /* E. Encoding-shape variant:
               - fixed-width in model; emulate shape-preserving perturbation by byte-swapping a nibble. */
            u8 tmp[6];
            for (int k = 0; k < 6; k++) tmp[k] = p->record_header.sequence_number.b[k];
            /* swap two random bytes */
            u32 a = urand_seq(6), b = urand_seq(6);
            u8 t = tmp[a]; tmp[a] = tmp[b]; tmp[b] = t;
            for (int k = 0; k < 6; k++) p->record_header.sequence_number.b[k] = tmp[k];
        } else if (cat < 76) {
            /* F. Padding/alignment:
               - not applicable; keep stable to avoid structural side-effects. */
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(cur));
        } else if (cat < 90) {
            /* G. In-range sweep:
               - walk around current by small deltas to explore anti-replay windows. */
            u64 delta = (u64)(urand_seq(33)); /* 0..32 */
            int dir = (urand_seq(2) == 0) ? -1 : 1;
            u64 v = (dir < 0) ? (cur - delta) : (cur + delta);
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
        } else {
            /* H. Random valid mix:
               - mix shallow (near base/current) and deep (random 48-bit) */
            u32 mode = urand_seq(4);
            u64 v;
            if (mode == 0) v = base + (u64)(i & 0xFFu);
            else if (mode == 1) v = cur;
            else if (mode == 2) v = base + (u64)urand_seq((u32)(span + 1));
            else v = (((u64)xorshift32_seq() << 16) ^ (u64)xorshift32_seq()) & 0xFFFFFFFFFFFFULL;
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
        }

        /* randomized perturbations (shallow + deep) to keep diversity */
        if (urand_seq(100) < 22) {
            /* shallow: enforce weak monotonic relation within same epoch */
            if (i > 0 && is_handshake_pkt(&pkts[i - 1]) &&
                pkts[i - 1].record_header.epoch == p->record_header.epoch) {
                u64 prev = rd_u48_be(&pkts[i - 1].record_header.sequence_number);
                u64 v = prev + (u64)(1 + urand_seq(3)); /* +1..+3 */
                wr_u48_be(&p->record_header.sequence_number, clamp_u48(v));
            }
        }
        if (urand_seq(100) < 7) {
            /* deep: flip multiple bits but keep within 48-bit */
            u64 v = rd_u48_be(&p->record_header.sequence_number);
            u64 mask = (((u64)xorshift32_seq() << 16) ^ (u64)xorshift32_seq()) & 0xFFFFFFFFFFFFULL;
            wr_u48_be(&p->record_header.sequence_number, clamp_u48(v ^ mask));
        }
    }
}




/* -------- minimal RNG -------- */
static u32 g_seed_len = 0x1EAFB00Du;
static u32 xorshift32_len(void) {
    u32 x = g_seed_len;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_len = x;
    return x;
}
static u32 urand_len(u32 n) { return n ? (xorshift32_len() % n) : 0; }



/* Compute the canonical DTLS record payload length for a handshake record from the in-struct model.
 * Canonical record payload for handshake records is:
 *   12-byte handshake header + handshake_body_length
 *
 * We prefer payload.handshake.raw_body_len when present (already parsed),
 * else fall back to handshake_header.length (24-bit).
 */
static u16 canonical_handshake_record_len(const dtls_packet_t *p) {
    if (!p) return 0;
    if (!is_handshake_pkt(p)) return p->record_header.length;

    u32 body_len = 0;
    if (p->payload.handshake.raw_body_len != 0) {
        body_len = (u32)p->payload.handshake.raw_body_len;
    } else {
        const u8 *b = p->payload.handshake.handshake_header.length.b;
        body_len = ((u32)b[0] << 16) | ((u32)b[1] << 8) | (u32)b[2];
    }

    /* 12-byte handshake header + body, clamp to u16 (record_header.length is u16) */
    u32 total = 12u + body_len;
    if (total > 0xFFFFu) total = 0xFFFFu;
    return (u16)total;
}

void mutate_record_header_length(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Collect a plausible min/max window from existing handshake packets. */
    u16 min_seen = 0xFFFFu;
    u16 max_seen = 0;
    u32 seen = 0;

    for (size_t i = 0; i < n; i++) {
        if (!is_handshake_pkt(&pkts[i])) continue;
        u16 L = pkts[i].record_header.length;
        if (L < min_seen) min_seen = L;
        if (L > max_seen) max_seen = L;
        seen++;
    }
    if (seen == 0) { min_seen = 0; max_seen = 0; }
    u16 span = (u16)(max_seen - min_seen);

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_handshake_pkt(p)) continue;

        u16 cur = p->record_header.length;
        u16 canon = canonical_handshake_record_len(p);

        u32 cat = urand_len(100);

        if (cat < 22) {
            /* A. Canonical form: exactly match computed payload length. */
            p->record_header.length = canon;
        } else if (cat < 34) {
            /* B. Boundaries (still within u16; note: may be rejected by strict peers):
               - 0 (empty record payload)
               - 13 (minimum record header payload for handshake header(12)+1)
               - 0xFFFF (max) */
            static const u16 bnd[] = {0u, 13u, 12u, 0xFFFFu};
            p->record_header.length = bnd[urand_len((u32)(sizeof(bnd)/sizeof(bnd[0])))];
        } else if (cat < 49) {
            /* C. Equivalence-class alternatives:
               - exact canonical
               - canonical +/- small delta (off-by-one / truncation-ish)
               - keep current
               - neighbor's length */
            u32 pick = urand_len(5);
            if (pick == 0) p->record_header.length = canon;
            else if (pick == 1) p->record_header.length = (u16)(canon + 1u);
            else if (pick == 2) p->record_header.length = (u16)(canon - (canon ? 1u : 0u));
            else if (pick == 3) p->record_header.length = cur;
            else {
                if (i > 0 && is_handshake_pkt(&pkts[i - 1])) p->record_header.length = pkts[i - 1].record_header.length;
                else if (i + 1 < n && is_handshake_pkt(&pkts[i + 1])) p->record_header.length = pkts[i + 1].record_header.length;
                else p->record_header.length = canon;
            }
        } else if (cat < 64) {
            /* D. Allowed range:
               - Any u16 is representable; choose "plausible" range around observed or canonical. */
            u16 base = (seen ? min_seen : canon);
            u16 v = (u16)(base + (span ? (u16)urand_len((u32)span + 1u) : 0u));
            p->record_header.length = v;
        } else if (cat < 72) {
            /* E. Encoding-shape variant:
               - fixed-width u16; emulate shape perturbation by endian-like swap of bytes. */
            u16 v = cur;
            u16 swapped = (u16)((v >> 8) | (v << 8));
            /* keep within some plausibility by snapping near canonical occasionally */
            p->record_header.length = (urand_len(2) == 0) ? swapped : (u16)(canon ^ swapped);
        } else if (cat < 78) {
            /* F. Padding/alignment:
               - not applicable; use "alignment-like" rounding to 2/4/8 boundaries. */
            u16 v = canon;
            u16 m = (u16)(1u << (1u + urand_len(3))); /* 2,4,8 */
            p->record_header.length = (u16)((v + (m - 1u)) & (u16)~(m - 1u));
        } else if (cat < 92) {
            /* G. In-range sweep:
               - walk around canonical by small deltas */
            u16 delta = (u16)urand_len(33); /* 0..32 */
            int dir = (urand_len(2) == 0) ? -1 : 1;
            u32 vv = (u32)canon + (u32)(dir * (int)delta);
            if (vv > 0xFFFFu) vv = 0xFFFFu;
            p->record_header.length = (u16)vv;
        } else {
            /* H. Random valid mix:
               - mix canonical, observed window, and random u16 */
            u32 mode = urand_len(4);
            if (mode == 0) p->record_header.length = canon;
            else if (mode == 1) {
                u16 base = (seen ? min_seen : 0);
                p->record_header.length = (u16)(base + (u16)urand_len((u32)(span ? span : 64u) + 1u));
            } else if (mode == 2) {
                /* shallow random near canonical */
                u16 jitter = (u16)urand_len(16);
                p->record_header.length = (u16)(canon ^ jitter);
            } else {
                /* deep random */
                p->record_header.length = (u16)(xorshift32_len() & 0xFFFFu);
            }
        }

        /* Randomized perturbations to preserve diversity:
           - occasionally "repair" back to canonical to prevent collapse into invalid lengths only. */
        if (urand_len(100) < 18) {
            if (urand_len(2) == 0) {
                p->record_header.length = canon;
            } else {
                /* slight mismatch but close */
                u16 d = (u16)(1u + urand_len(3)); /* 1..3 */
                p->record_header.length = (urand_len(2) == 0) ? (u16)(canon + d)
                                                             : (u16)(canon - (canon > d ? d : canon));
            }
        }
        if (urand_len(100) < 6) {
            /* deep: flip multiple bits but keep u16 */
            p->record_header.length ^= (u16)(xorshift32_len() & 0xFFFFu);
        }
    }
}



/* -------- minimal RNG -------- */
static u32 g_seed_hmt = 0xC0FFEE11u;
static u32 xorshift32_hmt(void) {
    u32 x = g_seed_hmt;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_hmt = x;
    return x;
}
static u32 urand_hmt(u32 n) { return n ? (xorshift32_hmt() % n) : 0; }


/* Handshake.msg_type is NOT optional and NOT repeatable. */

/* Common DTLS/TLS 1.2 HandshakeType values (RFC 5246 + DTLS delta):
 * 0 is hello_request (rare), 1 client_hello, 2 server_hello, 3 hello_verify_request (DTLS),
 * 11 certificate, 12 server_key_exchange, 13 certificate_request, 14 server_hello_done,
 * 15 certificate_verify, 16 client_key_exchange, 20 finished.
 */
static const u8 k_hs_types_common[] = {
    0, 1, 2, 3, 11, 12, 13, 14, 15, 16, 20
};

static u8 pick_common_hs_type(void) {
    return k_hs_types_common[urand_hmt((u32)(sizeof(k_hs_types_common) / sizeof(k_hs_types_common[0])))];
}

/* Infer a canonical handshake msg_type from the union body presence and/or known raw body expectations.
 * Since the struct union doesn't carry an explicit discriminator, we use heuristics:
 * - If raw_body_len != 0, keep current as canonical (parser likely set it).
 * - Otherwise, keep current (safe) but allow a few "structure-guided" selections:
 *   client_hello is most common in seeds, so treat 1 as the canonical default.
 */
static u8 canonical_hs_msg_type(const dtls_packet_t *p) {
    if (!p || !is_handshake_pkt(p)) return 1;
    if (p->payload.handshake.raw_body_len != 0) {
        return p->payload.handshake.handshake_header.msg_type;
    }
    return 1; /* default canonical */
}

void mutate_handshake_header_msg_type(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Gather seen types to build equivalence classes from the input sequence */
    u8 seen_types[256] = {0};
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n; i++) {
        if (!is_handshake_pkt(&pkts[i])) continue;
        u8 t = pkts[i].payload.handshake.handshake_header.msg_type;
        if (!seen_types[t]) { seen_types[t] = 1; seen_cnt++; }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_handshake_pkt(p)) continue;

        u8 cur = p->payload.handshake.handshake_header.msg_type;
        u8 canon = canonical_hs_msg_type(p);

        u32 cat = urand_hmt(100);

        if (cat < 18) {
            /* A. Canonical form */
            p->payload.handshake.handshake_header.msg_type = canon;
        } else if (cat < 30) {
            /* B. Boundaries */
            static const u8 bnd[] = { 0, 1, 20, 255 };
            p->payload.handshake.handshake_header.msg_type =
                bnd[urand_hmt((u32)(sizeof(bnd)/sizeof(bnd[0])))];
        } else if (cat < 46) {
            /* C. Equivalence-class alternatives:
             * - keep current
             * - use another type seen in this trace
             * - neighbor's type
             * - a common handshake type
             */
            u32 pick = urand_hmt(4);
            if (pick == 0) {
                p->payload.handshake.handshake_header.msg_type = cur;
            } else if (pick == 1 && seen_cnt > 1) {
                /* pick any seen type (uniform scan) */
                u32 k = urand_hmt(seen_cnt);
                u32 j = 0;
                for (u32 t = 0; t < 256; t++) {
                    if (!seen_types[t]) continue;
                    if (j++ == k) { p->payload.handshake.handshake_header.msg_type = (u8)t; break; }
                }
            } else if (pick == 2) {
                if (i > 0 && is_handshake_pkt(&pkts[i - 1]))
                    p->payload.handshake.handshake_header.msg_type =
                        pkts[i - 1].payload.handshake.handshake_header.msg_type;
                else if (i + 1 < n && is_handshake_pkt(&pkts[i + 1]))
                    p->payload.handshake.handshake_header.msg_type =
                        pkts[i + 1].payload.handshake.handshake_header.msg_type;
                else
                    p->payload.handshake.handshake_header.msg_type = canon;
            } else {
                p->payload.handshake.handshake_header.msg_type = pick_common_hs_type();
            }
        } else if (cat < 66) {
            /* D. Allowed enum/range:
             * choose from well-known valid handshake types (keeps "valid-ish"). */
            p->payload.handshake.handshake_header.msg_type = pick_common_hs_type();
        } else if (cat < 74) {
            /* E. Encoding-shape variant:
             * fixed-width u8; emulate shape perturbation by bit permutation/masks. */
            u8 v = cur;
            u8 rot = (u8)((v << (urand_hmt(7) + 1)) | (v >> (8 - (urand_hmt(7) + 1))));
            /* snap back into known set half the time */
            p->payload.handshake.handshake_header.msg_type = (urand_hmt(2) == 0) ? rot : pick_common_hs_type();
        } else if (cat < 80) {
            /* F. Padding/alignment: not applicable (single byte); keep stable */
            p->payload.handshake.handshake_header.msg_type = cur;
        } else if (cat < 92) {
            /* G. In-range sweep:
             * sweep through nearby values but bias toward valid ones. */
            u8 delta = (u8)(1 + urand_hmt(5)); /* 1..5 */
            u8 v = (urand_hmt(2) == 0) ? (u8)(cur + delta) : (u8)(cur - delta);
            /* if not seen/common, snap */
            if (!seen_types[v] && urand_hmt(3) != 0) v = pick_common_hs_type();
            p->payload.handshake.handshake_header.msg_type = v;
        } else {
            /* H. Random valid mix:
             * blend canonical, seen, common, and rare-but-valid handshake types. */
            u32 mode = urand_hmt(5);
            if (mode == 0) p->payload.handshake.handshake_header.msg_type = canon;
            else if (mode == 1 && seen_cnt) {
                u32 k = urand_hmt(seen_cnt);
                u32 j = 0;
                for (u32 t = 0; t < 256; t++) {
                    if (!seen_types[t]) continue;
                    if (j++ == k) { p->payload.handshake.handshake_header.msg_type = (u8)t; break; }
                }
            } else if (mode == 2) p->payload.handshake.handshake_header.msg_type = pick_common_hs_type();
            else if (mode == 3) {
                /* rare valid: server_hello_done(14) or certificate_request(13) */
                p->payload.handshake.handshake_header.msg_type = (urand_hmt(2) == 0) ? 14 : 13;
            } else {
                /* deep random but often snap to valid */
                u8 v = (u8)(xorshift32_hmt() & 0xFFu);
                if (urand_hmt(4) != 0) v = pick_common_hs_type();
                p->payload.handshake.handshake_header.msg_type = v;
            }
        }

        /* Randomized perturbations (shallow+deep) to avoid collapse */
        if (urand_hmt(100) < 20) {
            /* shallow: ensure the first handshake in a typical flow stays client_hello */
            if (i == 0) p->payload.handshake.handshake_header.msg_type = 1;
        }
        if (urand_hmt(100) < 6) {
            /* deep: xor with non-zero mask, then snap sometimes */
            u8 v = p->payload.handshake.handshake_header.msg_type;
            v ^= (u8)(1u + (xorshift32_hmt() & 0x7Fu));
            if (urand_hmt(3) != 0) v = pick_common_hs_type();
            p->payload.handshake.handshake_header.msg_type = v;
        }
    }
}




/* ---------------- minimal helpers ---------------- */

static u32 g_seed_hl = 0xA5A5F00Du;
static u32 xs32_hl(void) {
    u32 x = g_seed_hl;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_hl = x;
    return x;
}
static u32 urand_hl(u32 n) { return n ? (xs32_hl() % n) : 0; }

static int is_hs(const dtls_packet_t *p) { return p && p->kind == DTLS_PKT_HANDSHAKE; }

static u32 rd_u24_be(const u8 b[3]) { return ((u32)b[0] << 16) | ((u32)b[1] << 8) | (u32)b[2]; }
static void wr_u24_be(u8 b[3], u32 v) {
    b[0] = (u8)((v >> 16) & 0xFF);
    b[1] = (u8)((v >> 8) & 0xFF);
    b[2] = (u8)(v & 0xFF);
}


/* Handshake.length is REQUIRED on-wire and NOT repeatable. */

/* Canonical: for our struct, we can reliably set handshake.length to raw_body_len
 * (bounded by DTLS_MAX_HANDSHAKE_RAW), and keep fragment_length consistent too.
 */
static u32 canonical_body_len(const dtls_packet_t *p) {
    if (!p || !is_hs(p)) return 0;
    /* Prefer raw_body_len; fall back to existing header length if raw is empty */
    u32 rb = (u32)p->payload.handshake.raw_body_len;
    if (rb != 0) return clamp_u32(rb, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
    return clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
                     0, (u32)DTLS_MAX_HANDSHAKE_RAW);
}

static void set_len_consistent(dtls_packet_t *p, u32 body_len) {
    if (!p || !is_hs(p)) return;

    body_len = clamp_u32(body_len, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);

    /* handshake_header.length = body_len */
    wr_u24_be(p->payload.handshake.handshake_header.length.b, body_len);

    /* For non-fragmented messages, fragment_offset=0 and fragment_length=length */
    /* We won't force offset=0 always (could be fragmented in captures), but we
       often keep fragment_length within [0..length] for "valid-ish" shapes. */
    u32 frag_off = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
    u32 frag_len = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b);

    /* If currently looks non-fragmented, keep it non-fragmented */
    if (frag_off == 0 && (frag_len == 0 || frag_len == body_len)) {
        wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, body_len);
        return;
    }

    /* Otherwise: ensure frag_off <= body_len and frag_len <= body_len - frag_off */
    if (frag_off > body_len) frag_off = body_len;
    u32 max_frag = body_len - frag_off;
    if (frag_len > max_frag) frag_len = max_frag;

    wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, frag_off);
    wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, frag_len);
}

/* Equivalence-class alternatives for length, but still within our struct constraints */
static u32 equiv_len(u32 canon) {
    /* common alternatives: same; small non-zero; powers of two-ish; near max; */
    static const u32 alts[] = { 0, 1, 12, 24, 32, 48, 64, 128, 256, 512, 1024, (u32)DTLS_MAX_HANDSHAKE_RAW };
    u32 pick = urand_hl((u32)(sizeof(alts)/sizeof(alts[0])));
    u32 v = alts[pick];
    /* bias toward canon */
    if (urand_hl(3) == 0) v = canon;
    return clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
}

/* In-range sweep around canonical length */
static u32 sweep_len(u32 canon) {
    if (canon == 0) return (u32)urand_hl(33); /* 0..32 */
    u32 span = (canon < 64) ? 16 : (canon < 256) ? 64 : 128;
    u32 delta = 1 + urand_hl(span);
    u32 dir = urand_hl(2);
    u32 v = dir ? (canon + delta) : (canon - (delta > canon ? canon : delta));
    return clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
}

void mutate_handshake_header_length(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Build a small set of seen lengths in this message sequence */
    u32 seen[64];
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n && seen_cnt < 64; i++) {
        if (!is_hs(&pkts[i])) continue;
        u32 v = rd_u24_be(pkts[i].payload.handshake.handshake_header.length.b);
        /* de-dup */
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) if (seen[j] == v) { ok = 0; break; }
        if (ok) seen[seen_cnt++] = v;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hs(p)) continue;

        u32 cur   = rd_u24_be(p->payload.handshake.handshake_header.length.b);
        u32 canon = canonical_body_len(p);

        u32 cat = urand_hl(100);
        u32 v = cur;

        if (cat < 20) {
            /* A. Canonical form */
            v = canon;
        } else if (cat < 34) {
            /* B. Boundaries */
            static const u32 bnd[] = { 0, 1, 2, 3, 11, 12, 13, 255, 256, 257, (u32)DTLS_MAX_HANDSHAKE_RAW - 1,
                                       (u32)DTLS_MAX_HANDSHAKE_RAW };
            v = bnd[urand_hl((u32)(sizeof(bnd)/sizeof(bnd[0])))];
        } else if (cat < 50) {
            /* C. Equivalence-class alternatives */
            if (seen_cnt && urand_hl(2) == 0) {
                v = seen[urand_hl(seen_cnt)];
            } else {
                v = equiv_len(canon);
            }
        } else if (cat < 70) {
            /* D. Allowed range (vector length for handshake body):
             * 0..2^24-1 on wire, but our struct caps by DTLS_MAX_HANDSHAKE_RAW.
             */
            /* pick a valid in-range value, biased toward canon and current */
            u32 mode = urand_hl(4);
            if (mode == 0) v = canon;
            else if (mode == 1) v = cur;
            else if (mode == 2) v = (u32)urand_hl((u32)DTLS_MAX_HANDSHAKE_RAW + 1u);
            else v = sweep_len(canon);
        } else if (cat < 78) {
            /* E. Encoding-shape variant:
             * still a 24-bit big-endian; emulate shape by "bytewise" edits while clamped.
             */
            u8 b[3];
            b[0] = (u8)((cur >> 16) & 0xFF);
            b[1] = (u8)((cur >> 8) & 0xFF);
            b[2] = (u8)(cur & 0xFF);

            u32 which = urand_hl(3);
            if (which == 0) b[0] ^= (u8)(1u + (xs32_hl() & 0x7Fu));
            else if (which == 1) b[1] ^= (u8)(1u + (xs32_hl() & 0x7Fu));
            else b[2] ^= (u8)(1u + (xs32_hl() & 0x7Fu));

            v = rd_u24_be(b);
            v = clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        } else if (cat < 84) {
            /* F. Padding/alignment:
             * choose lengths that align common structures (4/8/16).
             */
            u32 base = canon ? canon : cur;
            u32 align = (urand_hl(3) == 0) ? 4u : (urand_hl(2) == 0) ? 8u : 16u;
            v = (base + (align - 1u)) & ~(align - 1u);
            v = clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        } else if (cat < 94) {
            /* G. In-range sweep */
            v = sweep_len(canon);
        } else {
            /* H. Random valid mix */
            u32 mode = urand_hl(6);
            if (mode == 0) v = canon;
            else if (mode == 1) v = equiv_len(canon);
            else if (mode == 2) v = sweep_len(canon);
            else if (mode == 3 && seen_cnt) v = seen[urand_hl(seen_cnt)];
            else if (mode == 4) v = (u32)urand_hl((u32)DTLS_MAX_HANDSHAKE_RAW + 1u);
            else v = (u32)DTLS_MAX_HANDSHAKE_RAW;
        }

        /* Randomized perturbations: shallow+deep, but stay within struct bounds */
        if (urand_hl(100) < 20) {
            /* shallow: small +/- 1..3 tweak */
            u32 d = 1u + urand_hl(3);
            if (urand_hl(2) == 0) v = (v + d);
            else v = (v >= d) ? (v - d) : 0;
            v = clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        }
        if (urand_hl(100) < 8) {
            /* deep: jump near max or near zero */
            if (urand_hl(2) == 0) v = (u32)DTLS_MAX_HANDSHAKE_RAW - urand_hl(64);
            else v = urand_hl(64);
            v = clamp_u32(v, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        }

        /* Apply and keep fragment_length coherent "enough" */
        set_len_consistent(p, v);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_hfo = 0xC0FFEE11u;
static u32 xs32_hfo(void) {
    u32 x = g_seed_hfo;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_hfo = x;
    return x;
}
static u32 urand_hfo(u32 n) { return n ? (xs32_hfo() % n) : 0; }



/* canonical body length (bounded to our struct cap) */
static u32 body_len_cap(const dtls_packet_t *p) {
    if (!p || !is_hs(p)) return 0;
    u32 rb = (u32)p->payload.handshake.raw_body_len;
    if (rb != 0) return clamp_u32(rb, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
    return clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
                     0, (u32)DTLS_MAX_HANDSHAKE_RAW);
}

/* Keep invariants "valid-ish":
 *  - fragment_offset <= handshake.length
 *  - fragment_length <= handshake.length - fragment_offset
 *  - if message looks non-fragmented, keep offset=0 and frag_len=length
 */
static void normalize_frag(dtls_packet_t *p) {
    if (!p || !is_hs(p)) return;

    u32 L = clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
                      0, (u32)DTLS_MAX_HANDSHAKE_RAW);
    u32 off = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
    u32 fl  = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b);

    /* Prefer non-fragmented form if possible */
    if (off == 0 && (fl == 0 || fl == L)) {
        wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, 0);
        wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, L);
        return;
    }

    if (off > L) off = L;
    u32 max_fl = L - off;
    if (fl > max_fl) fl = max_fl;

    wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, off);
    wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, fl);
}

/* Handshake.fragment_offset is REQUIRED on-wire and NOT repeatable. */


/* ---------------- mutator ---------------- */

static u32 choose_boundary(u32 L) {
    /* boundary cases relative to length L */
    u32 near = (L > 0) ? (L - 1) : 0;
    u32 mid  = (L > 1) ? (L / 2) : 0;
    u32 vals[10];
    vals[0] = 0;
    vals[1] = 1;
    vals[2] = 2;
    vals[3] = 3;
    vals[4] = mid;
    vals[5] = near;
    vals[6] = L;
    vals[7] = (L > 4) ? (L - 4) : 0;
    vals[8] = (L > 8) ? (L - 8) : 0;
    vals[9] = (L > 16) ? (L - 16) : 0;
    return vals[urand_hfo(10)];
}

static u32 sweep_offset(u32 cur, u32 L) {
    if (L == 0) return 0;
    u32 span = (L < 64) ? 8 : (L < 256) ? 32 : 64;
    u32 d = 1u + urand_hfo(span);
    u32 dir = urand_hfo(2);
    u32 v = dir ? (cur + d) : (cur >= d ? (cur - d) : 0u);
    return clamp_u32(v, 0, L);
}

static u32 align_offset(u32 base, u32 L) {
    u32 a = (urand_hfo(3) == 0) ? 2u : (urand_hfo(2) == 0) ? 4u : 8u;
    u32 v = base & ~(a - 1u);
    return clamp_u32(v, 0, L);
}

void mutate_handshake_header_fragment_offset(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Collect seen offsets to enable equivalence-class reuse */
    u32 seen[64];
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n && seen_cnt < 64; i++) {
        if (!is_hs(&pkts[i])) continue;
        u32 v = rd_u24_be(pkts[i].payload.handshake.handshake_header.fragment_offset.b);
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) if (seen[j] == v) { ok = 0; break; }
        if (ok) seen[seen_cnt++] = v;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hs(p)) continue;

        u32 L = clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
                          0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        /* If length looks unset, fall back to raw_body_len/capped */
        if (L == 0) {
            L = body_len_cap(p);
            wr_u24_be(p->payload.handshake.handshake_header.length.b, L);
        }

        u32 cur = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
        u32 v = cur;

        u32 cat = urand_hfo(100);

        if (cat < 20) {
            /* A. Canonical form: non-fragmented => offset = 0 */
            v = 0;
        } else if (cat < 34) {
            /* B. Boundaries */
            v = choose_boundary(L);
        } else if (cat < 50) {
            /* C. Equivalence-class alternatives */
            if (seen_cnt && urand_hfo(2) == 0) v = seen[urand_hfo(seen_cnt)];
            else v = choose_boundary(L);
        } else if (cat < 70) {
            /* D. Allowed range: 0..length */
            u32 mode = urand_hfo(4);
            if (mode == 0) v = 0;
            else if (mode == 1) v = L;
            else if (mode == 2) v = (u32)urand_hfo(L + 1u);
            else v = sweep_offset(cur, L);
        } else if (cat < 78) {
            /* E. Encoding-shape variant: bytewise perturb in 24-bit, then clamp */
            u8 b[3];
            b[0] = (u8)((cur >> 16) & 0xFF);
            b[1] = (u8)((cur >> 8) & 0xFF);
            b[2] = (u8)(cur & 0xFF);

            u32 which = urand_hfo(3);
            if (which == 0) b[0] ^= (u8)(1u + (xs32_hfo() & 0x7Fu));
            else if (which == 1) b[1] ^= (u8)(1u + (xs32_hfo() & 0x7Fu));
            else b[2] ^= (u8)(1u + (xs32_hfo() & 0x7Fu));

            v = rd_u24_be(b);
            v = clamp_u32(v, 0, L);
        } else if (cat < 84) {
            /* F. Padding/alignment */
            u32 base = (urand_hfo(2) == 0) ? cur : choose_boundary(L);
            v = align_offset(base, L);
        } else if (cat < 94) {
            /* G. In-range sweep */
            v = sweep_offset(cur, L);
        } else {
            /* H. Random valid mix */
            u32 mode = urand_hfo(6);
            if (mode == 0) v = 0;
            else if (mode == 1) v = choose_boundary(L);
            else if (mode == 2) v = (u32)urand_hfo(L + 1u);
            else if (mode == 3) v = align_offset(cur, L);
            else if (mode == 4) v = sweep_offset(cur, L);
            else if (seen_cnt) v = seen[urand_hfo(seen_cnt)];
            else v = (u32)urand_hfo(L + 1u);
        }

        /* randomized perturbations (still valid) */
        if (urand_hfo(100) < 18) {
            /* shallow +/- 1..3 */
            u32 d = 1u + urand_hfo(3);
            if (urand_hfo(2) == 0) v = clamp_u32(v + d, 0, L);
            else v = (v >= d) ? (v - d) : 0u;
        }
        if (urand_hfo(100) < 8) {
            /* deep jump: near end or near start */
            if (urand_hfo(2) == 0) v = (L > 0) ? (L - urand_hfo((L < 32) ? (L + 1u) : 32u)) : 0u;
            else v = urand_hfo((L < 32) ? (L + 1u) : 32u);
            v = clamp_u32(v, 0, L);
        }

        /* apply and keep fragment_length consistent */
        wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, v);

        /* If it now looks non-fragmented, force frag_len = length; else clamp */
        {
            u32 off = v;
            u32 fl  = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b);
            if (off == 0 && (fl == 0 || fl == L)) {
                wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, L);
            } else {
                u32 max_fl = (off <= L) ? (L - off) : 0u;
                if (fl > max_fl) fl = max_fl;
                wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, fl);
            }
        }

        normalize_frag(p);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_hms = 0xA5D1E11Du;
static u32 xs32_hms(void) {
    u32 x = g_seed_hms;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_hms = x;
    return x;
}
static u32 urand_hms(u32 n) { return n ? (xs32_hms() % n) : 0; }




static u16 bswap16(u16 v) { return (u16)((v << 8) | (v >> 8)); }

// static u32 body_len_cap(const dtls_packet_t *p) {
//     if (!p || !is_hs(p)) return 0;
//     u32 rb = (u32)p->payload.handshake.raw_body_len;
//     if (rb != 0) return clamp_u32(rb, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
//     return clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
//                      0, (u32)DTLS_MAX_HANDSHAKE_RAW);
// }

/* normalize fragment fields so message_seq stays coherent with "valid-ish" DTLS:
 * - ensure frag_offset/frag_len are within handshake.length
 * - if looks non-fragmented, force offset=0 and frag_len=length
 */
// static void normalize_frag(dtls_packet_t *p) {
//     if (!p || !is_hs(p)) return;

//     u32 L = clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
//                       0, (u32)DTLS_MAX_HANDSHAKE_RAW);
//     if (L == 0) {
//         L = body_len_cap(p);
//         wr_u24_be(p->payload.handshake.handshake_header.length.b, L);
//     }

//     u32 off = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
//     u32 fl  = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b);

//     if (off == 0 && (fl == 0 || fl == L)) {
//         wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, 0);
//         wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, L);
//         return;
//     }

//     if (off > L) off = L;
//     u32 max_fl = L - off;
//     if (fl > max_fl) fl = max_fl;

//     wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, off);
//     wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, fl);
// }

/* message_seq is REQUIRED on-wire and NOT repeatable. */

/* ---------------- mutator ---------------- */

static u16 choose_boundary_u16(void) {
    static const u16 vals[] = {
        0x0000u, 0x0001u, 0x0002u, 0x0003u,
        0x000Fu, 0x0010u, 0x001Fu, 0x0020u,
        0x007Fu, 0x0080u, 0x00FFu, 0x0100u,
        0x03FFu, 0x0400u, 0x07FFu, 0x0800u,
        0x0FFFu, 0x1000u, 0x3FFFu, 0x4000u,
        0x7FFFu, 0x8000u, 0xFFFEu, 0xFFFFu
    };
    return vals[urand_hms((u32)(sizeof(vals) / sizeof(vals[0])))];
}

static u16 sweep_u16(u16 cur) {
    u32 span = 1u + urand_hms(64); /* small walk */
    if (urand_hms(2) == 0) {
        u32 v = (u32)cur + span;
        return (u16)(v & 0xFFFFu);
    } else {
        return (u16)((cur >= span) ? (cur - (u16)span) : 0u);
    }
}

static u16 align_u16(u16 v) {
    /* treat sequence as a "counter", sometimes align to 2/4/8 */
    u16 a = (urand_hms(3) == 0) ? 2u : (urand_hms(2) == 0) ? 4u : 8u;
    return (u16)(v & (u16)~(a - 1u));
}

void mutate_handshake_header_message_seq(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect seen seq values to enable equivalence-class reuse */
    u16 seen[64];
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n && seen_cnt < 64; i++) {
        if (!is_hs(&pkts[i])) continue;
        u16 v = pkts[i].payload.handshake.handshake_header.message_seq;
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) if (seen[j] == v) { ok = 0; break; }
        if (ok) seen[seen_cnt++] = v;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hs(p)) continue;

        /* ensure length/fragment fields are sane-ish around mutations */
        normalize_frag(p);

        u16 cur = p->payload.handshake.handshake_header.message_seq;
        u16 v = cur;

        u32 cat = urand_hms(100);

        if (cat < 16) {
            /* A. Canonical form: monotonic-ish small numbers (often start at 0/1) */
            v = (urand_hms(2) == 0) ? 0u : 1u;
        } else if (cat < 30) {
            /* B. Boundaries */
            v = choose_boundary_u16();
        } else if (cat < 46) {
            /* C. Equivalence-class alternatives:
               - reuse a seen seq
               - or mirror current around a nearby boundary */
            if (seen_cnt && urand_hms(2) == 0) v = seen[urand_hms(seen_cnt)];
            else {
                u16 b = choose_boundary_u16();
                v = (u16)(b ^ (cur & 0x00FFu));
            }
        } else if (cat < 66) {
            /* D. Allowed range: u16, typically counter.
               Keep "reasonable" most of the time, but still valid u16. */
            u32 mode = urand_hms(5);
            if (mode == 0) v = 0u;
            else if (mode == 1) v = 1u;
            else if (mode == 2) v = (u16)urand_hms(256);          /* small */
            else if (mode == 3) v = (u16)urand_hms(4096);         /* medium */
            else v = (u16)urand_hms(65536u);                      /* full u16 */
        } else if (cat < 76) {
            /* E. Encoding-shape variant:
               simulate endian confusion by swapping bytes (still u16 in struct). */
            v = bswap16(cur);
            if (urand_hms(100) < 30) v ^= (u16)(1u << urand_hms(16));
        } else if (cat < 82) {
            /* F. Padding/alignment */
            v = align_u16((urand_hms(2) == 0) ? cur : choose_boundary_u16());
        } else if (cat < 92) {
            /* G. In-range sweep: local walk */
            v = sweep_u16(cur);
        } else {
            /* H. Random valid mix */
            u32 mode = urand_hms(7);
            if (mode == 0) v = (u16)urand_hms(256);
            else if (mode == 1) v = (u16)urand_hms(4096);
            else if (mode == 2) v = choose_boundary_u16();
            else if (mode == 3) v = align_u16(cur);
            else if (mode == 4) v = sweep_u16(cur);
            else if (mode == 5 && seen_cnt) v = seen[urand_hms(seen_cnt)];
            else v = (u16)urand_hms(65536u);
        }

        /* randomized perturbations: shallow + deep, still u16 */
        if (urand_hms(100) < 20) {
            u16 d = (u16)(1u + urand_hms(3));
            v = (urand_hms(2) == 0) ? (u16)(v + d) : (u16)(v - d);
        }
        if (urand_hms(100) < 10) {
            /* deep: jump near current +/- large, or flip a high bit */
            if (urand_hms(2) == 0) v = (u16)(v ^ (u16)(1u << (8u + urand_hms(8))));
            else v = (u16)(v + (u16)(0x0100u * (1u + urand_hms(16))));
        }

        p->payload.handshake.handshake_header.message_seq = v;

        /* keep related fragmentation fields sane-ish */
        normalize_frag(p);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_hfl = 0xC0FFEE11u;
static u32 xs32_hfl(void) {
    u32 x = g_seed_hfl;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_hfl = x;
    return x;
}
static u32 urand_hfl(u32 n) { return n ? (xs32_hfl() % n) : 0; }

// static u32 body_len_cap(const dtls_packet_t *p) {
//     if (!p || !is_hs(p)) return 0;
//     u32 rb = (u32)p->payload.handshake.raw_body_len;
//     if (rb != 0) return clamp_u32(rb, 0, (u32)DTLS_MAX_HANDSHAKE_RAW);
//     return clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
//                      0, (u32)DTLS_MAX_HANDSHAKE_RAW);
// }

// /* normalize frag_offset/frag_len w.r.t handshake.length; keep within bounds */
// static void normalize_frag(dtls_packet_t *p) {
//     if (!p || !is_hs(p)) return;

//     u32 L = clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
//                       0, (u32)DTLS_MAX_HANDSHAKE_RAW);
//     if (L == 0) {
//         L = body_len_cap(p);
//         wr_u24_be(p->payload.handshake.handshake_header.length.b, L);
//     }

//     u32 off = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
//     u32 fl  = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b);

//     if (off > L) off = L;
//     u32 max_fl = (L >= off) ? (L - off) : 0;
//     if (fl > max_fl) fl = max_fl;

//     /* if looks like unfragmented, standardize */
//     if (off == 0 && (fl == 0 || fl == L)) fl = L;

//     wr_u24_be(p->payload.handshake.handshake_header.fragment_offset.b, off);
//     wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, fl);
// }

/* fragment_length is REQUIRED on-wire and NOT repeatable. */

/* ---------------- mutator ---------------- */

static u32 choose_boundary_u24(u32 cap /* inclusive upper bound */) {
    /* boundaries around 0, 1, cap, cap-1, small powers */
    u32 c = cap;
    u32 vals[20];
    u32 k = 0;
    vals[k++] = 0;
    vals[k++] = 1;
    vals[k++] = 2;
    vals[k++] = 3;
    vals[k++] = 7;
    vals[k++] = 8;
    vals[k++] = 15;
    vals[k++] = 16;
    vals[k++] = 31;
    vals[k++] = 32;
    vals[k++] = 63;
    vals[k++] = 64;
    vals[k++] = 127;
    vals[k++] = 128;
    if (c > 0) vals[k++] = c;
    if (c > 0) vals[k++] = c - 1;
    if (c > 1) vals[k++] = c - 2;
    if (c > 3) vals[k++] = c - 3;
    return vals[urand_hfl(k)];
}

static u32 sweep_u24(u32 cur, u32 cap) {
    u32 step = 1u + urand_hfl(64);
    if (urand_hfl(2) == 0) {
        u32 v = cur + step;
        return (v > cap) ? cap : v;
    } else {
        return (cur > step) ? (cur - step) : 0u;
    }
}

static u32 align_u24(u32 v) {
    /* sometimes align to 2/4/8/16 bytes */
    u32 a = (urand_hfl(4) == 0) ? 16u : (urand_hfl(3) == 0) ? 8u : (urand_hfl(2) == 0) ? 4u : 2u;
    return v & ~(a - 1u);
}

static u32 bswap24(u32 v) {
    v &= 0xFFFFFFu;
    return ((v & 0xFFu) << 16) | (v & 0xFF00u) | ((v >> 16) & 0xFFu);
}

void mutate_handshake_header_fragment_length(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect some seen fragment_length values for equivalence reuse */
    u32 seen[64];
    u32 seen_cnt = 0;

    for (size_t i = 0; i < n && seen_cnt < 64; i++) {
        if (!is_hs(&pkts[i])) continue;
        u32 fl = rd_u24_be(pkts[i].payload.handshake.handshake_header.fragment_length.b);
        fl &= 0xFFFFFFu;
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) if (seen[j] == fl) { ok = 0; break; }
        if (ok) seen[seen_cnt++] = fl;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hs(p)) continue;

        /* start from a consistent baseline */
        normalize_frag(p);

        u32 L = clamp_u32(rd_u24_be(p->payload.handshake.handshake_header.length.b),
                          0, (u32)DTLS_MAX_HANDSHAKE_RAW);
        if (L == 0) {
            L = body_len_cap(p);
            wr_u24_be(p->payload.handshake.handshake_header.length.b, L);
        }

        u32 off = rd_u24_be(p->payload.handshake.handshake_header.fragment_offset.b);
        if (off > L) off = L;
        u32 cap = (L >= off) ? (L - off) : 0;

        u32 cur = rd_u24_be(p->payload.handshake.handshake_header.fragment_length.b) & 0xFFFFFFu;
        u32 v = cur;

        u32 cat = urand_hfl(100);

        if (cat < 16) {
            /* A. Canonical: unfragmented => fragment_length = handshake.length - offset */
            v = cap;
        } else if (cat < 30) {
            /* B. Boundaries */
            v = choose_boundary_u24(cap);
        } else if (cat < 46) {
            /* C. Equivalence-class alternatives:
               - reuse a seen fl
               - or use "half fragment", "quarter fragment" style */
            if (seen_cnt && urand_hfl(2) == 0) {
                v = seen[urand_hfl(seen_cnt)];
                if (v > cap) v = cap;
            } else {
                u32 mode = urand_hfl(4);
                if (mode == 0) v = cap;
                else if (mode == 1) v = cap / 2;
                else if (mode == 2) v = cap / 4;
                else v = (cap >= 1) ? 1u : 0u;
            }
        } else if (cat < 66) {
            /* D. Allowed range: 0..(length-offset) */
            u32 mode = urand_hfl(5);
            if (mode == 0) v = cap;                         /* full */
            else if (mode == 1) v = (cap ? 1u : 0u);         /* tiny */
            else if (mode == 2) v = (cap >= 2) ? 2u : cap;
            else if (mode == 3) v = (cap ? urand_hfl(cap + 1u) : 0u);
            else v = (cap >= 16) ? (cap - urand_hfl(16)) : cap;
        } else if (cat < 76) {
            /* E. Encoding-shape variant: byte-swap-ish within 24 bits, then clamp */
            v = bswap24(cur);
            if (v > cap) v = cap;
            if (urand_hfl(100) < 30 && cap) v = (v ^ (1u << urand_hfl(24))) % (cap + 1u);
        } else if (cat < 82) {
            /* F. Padding/alignment */
            v = align_u24((urand_hfl(2) == 0) ? cap : (cap ? urand_hfl(cap + 1u) : 0u));
            if (v > cap) v = cap;
        } else if (cat < 92) {
            /* G. In-range sweep */
            v = sweep_u24(cur, cap);
        } else {
            /* H. Random valid mix */
            u32 mode = urand_hfl(7);
            if (mode == 0) v = cap;
            else if (mode == 1) v = choose_boundary_u24(cap);
            else if (mode == 2) v = (cap ? urand_hfl(cap + 1u) : 0u);
            else if (mode == 3) v = align_u24(cap);
            else if (mode == 4) v = sweep_u24(cur, cap);
            else if (mode == 5 && seen_cnt) { v = seen[urand_hfl(seen_cnt)]; if (v > cap) v = cap; }
            else v = (cap >= 8) ? (cap - urand_hfl(8)) : cap;
        }

        /* randomized perturbations: shallow + deep, keep within cap */
        if (cap) {
            if (urand_hfl(100) < 20) {
                u32 d = 1u + urand_hfl(7);
                v = (urand_hfl(2) == 0) ? ((v + d > cap) ? cap : (v + d)) : ((v > d) ? (v - d) : 0u);
            }
            if (urand_hfl(100) < 10) {
                /* deep: jump to a different "shape" but still in range */
                u32 pick = urand_hfl(4);
                if (pick == 0) v = cap;
                else if (pick == 1) v = 0;
                else if (pick == 2) v = (cap / 2);
                else v = (cap ? urand_hfl(cap + 1u) : 0u);
            }
        } else {
            v = 0;
        }

        /* write back */
        wr_u24_be(p->payload.handshake.handshake_header.fragment_length.b, v & 0xFFFFFFu);

        /* keep consistent */
        normalize_frag(p);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_chv = 0xA1B2C3D4u;
static u32 xs32_chv(void) {
    u32 x = g_seed_chv;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_chv = x;
    return x;
}
static u32 urand_chv(u32 n) { return n ? (xs32_chv() % n) : 0; }

/* Heuristic: treat as ClientHello when handshake msg_type == 1 */
static int is_client_hello(const dtls_packet_t *p) {
    if (!is_hs(p)) return 0;
    return p->payload.handshake.handshake_header.msg_type == 1; /* client_hello */
}

/* DTLS record version for DTLS 1.2 is 0xFEFD; DTLS 1.0 is 0xFEFF */
#define DTLS_VMAJ 0xFEu
#define DTLS_VMIN_12 0xFDu
#define DTLS_VMIN_10 0xFFu

/* ClientHello.client_version typically matches record version */
static void canonicalize_client_version(dtls_packet_t *p) {
    if (!p || !is_client_hello(p)) return;
    /* default to DTLS 1.2 */
    p->payload.handshake.body.client_hello.client_version.major = (u8)DTLS_VMAJ;
    p->payload.handshake.body.client_hello.client_version.minor = (u8)DTLS_VMIN_12;
}

/* client_version is REQUIRED on-wire and NOT repeatable. */

/* ---------------- mutator ---------------- */

static void set_ver(dtls_packet_t *p, u8 maj, u8 min) {
    p->payload.handshake.body.client_hello.client_version.major = maj;
    p->payload.handshake.body.client_hello.client_version.minor = min;
}

/* Some widely-seen TLS/DTLS legacy encodings (kept as in-range byte pairs). */
static void pick_equiv_version(u8 *maj, u8 *min, u32 idx) {
    /* idx selects a pair; keep small list */
    switch (idx % 8u) {
        case 0: *maj = (u8)DTLS_VMAJ; *min = (u8)DTLS_VMIN_12; break; /* DTLS 1.2 */
        case 1: *maj = (u8)DTLS_VMAJ; *min = (u8)DTLS_VMIN_10; break; /* DTLS 1.0 */
        case 2: *maj = (u8)0x03u;     *min = (u8)0x03u;       break; /* TLS 1.2 (common mis-set) */
        case 3: *maj = (u8)0x03u;     *min = (u8)0x01u;       break; /* TLS 1.0 */
        case 4: *maj = (u8)0x03u;     *min = (u8)0x00u;       break; /* SSL 3.0 */
        case 5: *maj = (u8)DTLS_VMAJ; *min = (u8)0xFEu;       break; /* near DTLS space */
        case 6: *maj = (u8)0x7Fu;     *min = (u8)0x17u;       break; /* arbitrary but byte-valid */
        default:*maj = (u8)0x01u;     *min = (u8)0x00u;       break; /* very low legacy-like */
    }
}

void mutate_client_hello_client_version(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* Gather a couple of observed versions in the input sequence for reuse. */
    u16 seen[16];
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n && seen_cnt < 16; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        u8 mj = p->payload.handshake.body.client_hello.client_version.major;
        u8 mn = p->payload.handshake.body.client_hello.client_version.minor;
        u16 v = (u16)(((u16)mj << 8) | (u16)mn);
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) if (seen[j] == v) { ok = 0; break; }
        if (ok) seen[seen_cnt++] = v;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 cur_maj = p->payload.handshake.body.client_hello.client_version.major;
        u8 cur_min = p->payload.handshake.body.client_hello.client_version.minor;

        u8 maj = cur_maj, min = cur_min;

        u32 cat = urand_chv(100);

        if (cat < 18) {
            /* A. Canonical form */
            maj = (u8)DTLS_VMAJ;
            min = (u8)DTLS_VMIN_12;

        } else if (cat < 32) {
            /* B. Boundaries */
            /* push extremes while keeping byte-valid */
            switch (urand_chv(6)) {
                case 0: maj = 0x00; min = 0x00; break;
                case 1: maj = 0xFF; min = 0xFF; break;
                case 2: maj = (u8)DTLS_VMAJ; min = 0x00; break;
                case 3: maj = (u8)DTLS_VMAJ; min = 0xFF; break;
                case 4: maj = 0x01; min = 0x00; break;
                default:maj = 0x03; min = 0x03; break;
            }

        } else if (cat < 48) {
            /* C. Equivalence-class alternatives */
            if (seen_cnt && urand_chv(2) == 0) {
                u16 v = seen[urand_chv(seen_cnt)];
                maj = (u8)(v >> 8);
                min = (u8)(v & 0xFF);
            } else {
                pick_equiv_version(&maj, &min, urand_chv(1024));
            }

        } else if (cat < 68) {
            /* D. Allowed enum/range (DTLS family) */
            /* Keep major=0xFE, vary minor among known DTLS minors and close neighbors */
            maj = (u8)DTLS_VMAJ;
            switch (urand_chv(8)) {
                case 0: min = (u8)DTLS_VMIN_12; break; /* FE FD */
                case 1: min = (u8)DTLS_VMIN_10; break; /* FE FF */
                case 2: min = (u8)0xFC; break;
                case 3: min = (u8)0xFE; break;
                case 4: min = (u8)0x00; break;
                case 5: min = (u8)0x01; break;
                case 6: min = (u8)0x7F; break;
                default:min = (u8)(0xF0u + (u8)urand_chv(16)); break;
            }

        } else if (cat < 78) {
            /* E. Encoding-shape variant */
            /* Swap bytes or correlate with record-layer version fields */
            if (urand_chv(2) == 0) {
                u8 t = maj; maj = min; min = t;
            } else {
                maj = p->record_header.version_major;
                min = p->record_header.version_minor;
            }

        } else if (cat < 84) {
            /* F. Padding/alignment (not meaningful for 2 bytes): emulate "alignment" via masking */
            /* Align minor to even / multiple of 4 */
            maj = (urand_chv(2) == 0) ? (u8)DTLS_VMAJ : cur_maj;
            min = (u8)(cur_min & (urand_chv(2) ? (u8)~1u : (u8)~3u));

        } else if (cat < 92) {
            /* G. In-range sweep */
            /* Walk minor around canonical DTLS 1.2; keep major stable */
            maj = (u8)DTLS_VMAJ;
            {
                int dir = (urand_chv(2) == 0) ? 1 : -1;
                u8 step = (u8)(1u + urand_chv(8));
                u8 base = (u8)DTLS_VMIN_12;
                min = (u8)(base + (u8)(dir * (int)step));
            }

        } else {
            /* H. Random valid mix */
            u32 mode = urand_chv(6);
            if (mode == 0) { maj = (u8)DTLS_VMAJ; min = (u8)DTLS_VMIN_12; }
            else if (mode == 1) { maj = (u8)DTLS_VMAJ; min = (u8)DTLS_VMIN_10; }
            else if (mode == 2) { pick_equiv_version(&maj, &min, urand_chv(4096)); }
            else if (mode == 3) { maj = p->record_header.version_major; min = p->record_header.version_minor; }
            else if (mode == 4) { maj = (u8)DTLS_VMAJ; min = (u8)urand_chv(256); }
            else { maj = (u8)urand_chv(256); min = (u8)urand_chv(256); }
        }

        /* randomized perturbations: shallow + deep */
        if (urand_chv(100) < 18) {
            /* shallow: tweak one byte slightly */
            if (urand_chv(2) == 0) maj = (u8)(maj + (u8)(1u + urand_chv(3)));
            else min = (u8)(min + (u8)(1u + urand_chv(7)));
        }
        if (urand_chv(100) < 10) {
            /* deep: snap back to canonical DTLS or record-layer */
            if (urand_chv(2) == 0) { maj = (u8)DTLS_VMAJ; min = (u8)DTLS_VMIN_12; }
            else { maj = p->record_header.version_major; min = p->record_header.version_minor; }
        }

        set_ver(p, maj, min);

        /* keep long-term stability: occasionally canonicalize after mutation */
        if (urand_chv(100) < 15) {
            canonicalize_client_version(p);
        }
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_chr = 0xC0FFEE11u;
static u32 xs32_chr(void) {
    u32 x = g_seed_chr;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_chr = x;
    return x;
}
static u32 urand_chr(u32 n) { return n ? (xs32_chr() % n) : 0; }


static void fill_bytes(u8 *dst, size_t len) {
    if (!dst || len == 0) return;
    for (size_t i = 0; i < len; i++) dst[i] = (u8)urand_chr(256);
}

static void xor_bytes(u8 *dst, size_t len, u8 mask) {
    if (!dst || len == 0) return;
    for (size_t i = 0; i < len; i++) dst[i] ^= mask;
}

static void rotl_bytes_1(u8 *dst, size_t len) {
    if (!dst || len < 2) return;
    u8 first = dst[0];
    memmove(&dst[0], &dst[1], len - 1);
    dst[len - 1] = first;
}

static void swap_halves(u8 *dst, size_t len) {
    if (!dst || len < 2) return;
    size_t h = len / 2;
    for (size_t i = 0; i < h; i++) {
        u8 t = dst[i];
        dst[i] = dst[i + h];
        dst[i + h] = t;
    }
}

static void set_client_hello_random(dtls_packet_t *p, const u8 *src32) {
    if (!p || !src32) return;
    if (!is_client_hello(p)) return;
    memcpy(p->payload.handshake.body.client_hello.random.bytes, src32, 32);
}

static void get_client_hello_random(const dtls_packet_t *p, u8 *dst32) {
    if (!p || !dst32) return;
    if (!is_client_hello(p)) { memset(dst32, 0, 32); return; }
    memcpy(dst32, p->payload.handshake.body.client_hello.random.bytes, 32);
}

/* client_random is REQUIRED on-wire and NOT repeatable. */

/* ---------------- mutator ---------------- */

void mutate_client_hello_random(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect some observed randoms to enable "equivalence-class alternatives" */
    u8 seen[8][32];
    u32 seen_cnt = 0;
    for (size_t i = 0; i < n && seen_cnt < 8; i++) {
        if (!is_client_hello(&pkts[i])) continue;
        get_client_hello_random(&pkts[i], seen[seen_cnt]);
        /* de-dup by simple memcmp */
        int ok = 1;
        for (u32 j = 0; j < seen_cnt; j++) {
            if (memcmp(seen[j], seen[seen_cnt], 32) == 0) { ok = 0; break; }
        }
        if (ok) seen_cnt++;
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 cur[32];
        get_client_hello_random(p, cur);

        u8 out[32];
        memcpy(out, cur, 32);

        u32 cat = urand_chr(100);

        if (cat < 10) {
            /* A. Canonical form: time-like prefix (4 bytes) + randomness (rest) */
            u32 t = xs32_chr();
            out[0] = (u8)(t >> 24);
            out[1] = (u8)(t >> 16);
            out[2] = (u8)(t >> 8);
            out[3] = (u8)(t);
            fill_bytes(out + 4, 28);

        } else if (cat < 22) {
            /* B. Boundaries: all-0, all-FF, alternating patterns */
            switch (urand_chr(4)) {
                case 0: memset(out, 0x00, 32); break;
                case 1: memset(out, 0xFF, 32); break;
                case 2:
                    for (u32 k = 0; k < 32; k++) out[k] = (u8)((k & 1) ? 0x00 : 0xFF);
                    break;
                default:
                    for (u32 k = 0; k < 32; k++) out[k] = (u8)((k & 1) ? 0xAA : 0x55);
                    break;
            }

        } else if (cat < 34) {
            /* C. Equivalence-class alternatives: reuse from another seed/packet */
            if (seen_cnt) {
                memcpy(out, seen[urand_chr(seen_cnt)], 32);
            } else {
                fill_bytes(out, 32);
            }

        } else if (cat < 52) {
            /* D. Allowed range: any 32 bytes; bias to "mostly random" with a few fixed bytes */
            fill_bytes(out, 32);
            /* keep some bytes stable to model partial invariants */
            if (urand_chr(2) == 0) { out[0] = cur[0]; out[1] = cur[1]; }
            if (urand_chr(3) == 0) { out[31] = cur[31]; }

        } else if (cat < 66) {
            /* E. Encoding-shape variant: reorder / mirrored / rotate (still 32 bytes) */
            switch (urand_chr(4)) {
                case 0: rotl_bytes_1(out, 32); break;
                case 1:
                    for (u32 k = 0; k < 16; k++) {
                        u8 t = out[k];
                        out[k] = out[31 - k];
                        out[31 - k] = t;
                    }
                    break;
                case 2: swap_halves(out, 32); break;
                default:
                    /* interleave halves */
                    {
                        u8 tmp[32];
                        for (u32 k = 0; k < 16; k++) {
                            tmp[2 * k]     = out[k];
                            tmp[2 * k + 1] = out[16 + k];
                        }
                        memcpy(out, tmp, 32);
                    }
                    break;
            }

        } else if (cat < 74) {
            /* F. Padding/alignment: not meaningful; simulate by forcing nibble alignment */
            for (u32 k = 0; k < 32; k++) {
                out[k] = (u8)(out[k] & (urand_chr(2) ? 0xF0u : 0x0Fu));
                if (urand_chr(3) == 0) out[k] |= (u8)(urand_chr(16));
            }

        } else if (cat < 86) {
            /* G. In-range sweep: tweak a contiguous window deterministically */
            u32 start = urand_chr(32);
            u32 win = 1u + urand_chr(8);
            if (start + win > 32) win = 32 - start;
            u8 base = (u8)urand_chr(256);
            for (u32 k = 0; k < win; k++) {
                out[start + k] = (u8)(base + (u8)k);
            }

        } else {
            /* H. Random valid mix */
            fill_bytes(out, 32);
            if (seen_cnt && urand_chr(3) == 0) {
                /* splice with an observed one */
                u8 *s = seen[urand_chr(seen_cnt)];
                u32 cut = urand_chr(33);
                memcpy(out, s, cut);
            }
            if (urand_chr(4) == 0) {
                /* sprinkle a small structured prefix */
                out[0] = 0xDE; out[1] = 0xAD; out[2] = 0xBE; out[3] = 0xEF;
            }
        }

        /* randomized perturbations: shallow + deep */
        if (urand_chr(100) < 22) {
            /* shallow: flip a few bytes */
            u32 flips = 1u + urand_chr(4);
            for (u32 f = 0; f < flips; f++) {
                u32 idx = urand_chr(32);
                out[idx] ^= (u8)(1u << urand_chr(8));
            }
        }
        if (urand_chr(100) < 10) {
            /* deep: xor-mask whole block or rotate */
            if (urand_chr(2) == 0) xor_bytes(out, 32, (u8)(1u + urand_chr(255)));
            else rotl_bytes_1(out, 32);
        }

        set_client_hello_random(p, out);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_sid = 0xA51D0F0Du;
static u32 xs32_sid(void) {
    u32 x = g_seed_sid;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_sid = x;
    return x;
}
static u32 urand_sid(u32 n) { return n ? (xs32_sid() % n) : 0; }


static void reverse_bytes(u8 *dst, size_t len) {
    if (!dst || len < 2) return;
    for (size_t i = 0; i < len / 2; i++) {
        u8 t = dst[i];
        dst[i] = dst[len - 1 - i];
        dst[len - 1 - i] = t;
    }
}


static u8 clamp_u8(u32 v) { return (v > 255u) ? 255u : (u8)v; }
static u8 sid_max_len(void) { return (u8)DTLS_MAX_SESSION_ID_LEN; }

static void get_session_id(const dtls_packet_t *p, u8 *len_out, u8 *id_out32) {
    if (!len_out || !id_out32) return;
    *len_out = 0;
    memset(id_out32, 0, DTLS_MAX_SESSION_ID_LEN);
    if (!is_client_hello(p)) return;
    u8 l = p->payload.handshake.body.client_hello.session_id.len;
    if (l > sid_max_len()) l = sid_max_len();
    *len_out = l;
    memcpy(id_out32, p->payload.handshake.body.client_hello.session_id.id, l);
}

static void set_session_id(dtls_packet_t *p, u8 len, const u8 *id32) {
    if (!p || !id32) return;
    if (!is_client_hello(p)) return;
    if (len > sid_max_len()) len = sid_max_len();
    p->payload.handshake.body.client_hello.session_id.len = len;
    /* user preference: uint8_t[] style arrays always have a max-sized backing buffer */
    memset(p->payload.handshake.body.client_hello.session_id.id, 0, DTLS_MAX_SESSION_ID_LEN);
    memcpy(p->payload.handshake.body.client_hello.session_id.id, id32, len);
}

/* Session ID is present as a length-prefixed vector; "optional" is modeled by len==0.
 * It is not repeatable on-wire.
 */
void add_client_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        u8 l = p->payload.handshake.body.client_hello.session_id.len;
        if (l != 0) continue; /* already present */
        u8 buf[DTLS_MAX_SESSION_ID_LEN];
        fill_bytes(buf, DTLS_MAX_SESSION_ID_LEN);
        /* canonical non-empty length often 32, but keep some variety */
        u8 newl = (urand_sid(100) < 60) ? (u8)DTLS_MAX_SESSION_ID_LEN : (u8)(1u + urand_sid(DTLS_MAX_SESSION_ID_LEN));
        set_session_id(p, newl, buf);
    }
}

void delete_client_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        /* delete == set length 0 (leave backing buffer max-sized zeroed) */
        u8 z[DTLS_MAX_SESSION_ID_LEN];
        memset(z, 0, sizeof(z));
        set_session_id(p, 0, z);
    }
}


/* ---------------- mutator ---------------- */

void mutate_client_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect observed session_id values for equivalence-class alternatives */
    u8  seen_len[8];
    u8  seen_id[8][DTLS_MAX_SESSION_ID_LEN];
    u32 seen_cnt = 0;

    for (size_t i = 0; i < n && seen_cnt < 8; i++) {
        if (!is_client_hello(&pkts[i])) continue;
        u8 l;
        u8 idbuf[DTLS_MAX_SESSION_ID_LEN];
        get_session_id(&pkts[i], &l, idbuf);

        /* accept both empty and non-empty (empty models "no session") */
        int dup = 0;
        for (u32 j = 0; j < seen_cnt; j++) {
            if (seen_len[j] == l && memcmp(seen_id[j], idbuf, DTLS_MAX_SESSION_ID_LEN) == 0) { dup = 1; break; }
        }
        if (!dup) {
            seen_len[seen_cnt] = l;
            memcpy(seen_id[seen_cnt], idbuf, DTLS_MAX_SESSION_ID_LEN);
            seen_cnt++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 cur_len;
        u8 cur_id[DTLS_MAX_SESSION_ID_LEN];
        get_session_id(p, &cur_len, cur_id);

        u8 out_len = cur_len;
        u8 out_id[DTLS_MAX_SESSION_ID_LEN];
        memcpy(out_id, cur_id, DTLS_MAX_SESSION_ID_LEN);

        u32 cat = urand_sid(100);

        if (cat < 12) {
            /* A. Canonical form: either empty (no resumption) or full 32-byte ID */
            if (urand_sid(2) == 0) {
                out_len = 0;
                memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            } else {
                out_len = (u8)DTLS_MAX_SESSION_ID_LEN;
                fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
            }

        } else if (cat < 26) {
            /* B. Boundaries: lengths at 0/1/31/32 with simple patterns */
            static const u8 lens[] = {0, 1, 31, 32};
            out_len = lens[urand_sid(4)];
            memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            if (out_len) {
                switch (urand_sid(4)) {
                    case 0: memset(out_id, 0x00, out_len); break;
                    case 1: memset(out_id, 0xFF, out_len); break;
                    case 2:
                        for (u32 k = 0; k < out_len; k++) out_id[k] = (u8)((k & 1) ? 0xAA : 0x55);
                        break;
                    default:
                        /* small counter prefix then random tail */
                        for (u32 k = 0; k < out_len; k++) out_id[k] = (u8)k;
                        break;
                }
            }

        } else if (cat < 38) {
            /* C. Equivalence-class alternatives: reuse another observed session id */
            if (seen_cnt) {
                u32 pick = urand_sid(seen_cnt);
                out_len = seen_len[pick];
                memcpy(out_id, seen_id[pick], DTLS_MAX_SESSION_ID_LEN);
            } else {
                out_len = (u8)(urand_sid(2) ? 0 : 32);
                if (out_len) fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
                else memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            }

        } else if (cat < 56) {
            /* D. Allowed range: 0..32 length, arbitrary bytes; bias toward non-empty */
            out_len = (urand_sid(100) < 75) ? (u8)(1u + urand_sid(DTLS_MAX_SESSION_ID_LEN)) : 0;
            if (out_len) {
                fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
                /* keep a few original bytes sometimes */
                if (cur_len && urand_sid(3) == 0) {
                    u32 keep = 1u + urand_sid((cur_len < 8) ? cur_len : 8);
                    memcpy(out_id, cur_id, keep);
                }
            } else {
                memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            }

        } else if (cat < 70) {
            /* E. Encoding-shape variant: reorder bytes while keeping length */
            if (out_len == 0) {
                /* if currently empty, materialize then reorder */
                out_len = (u8)(1u + urand_sid(DTLS_MAX_SESSION_ID_LEN));
                fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
            }
            switch (urand_sid(4)) {
                case 0: rotl_bytes_1(out_id, out_len); break;
                case 1: reverse_bytes(out_id, out_len); break;
                case 2:
                    if (out_len >= 4) swap_halves(out_id, out_len & ~1u);
                    break;
                default:
                    /* pairwise swap */
                    for (u32 k = 0; k + 1 < out_len; k += 2) {
                        u8 t = out_id[k]; out_id[k] = out_id[k + 1]; out_id[k + 1] = t;
                    }
                    break;
            }

        } else if (cat < 78) {
            /* F. Padding/alignment: not meaningful here; emulate "aligned prefixes" */
            if (out_len == 0) {
                out_len = (u8)(1u + urand_sid(DTLS_MAX_SESSION_ID_LEN));
                fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
            }
            /* force some bytes to 0x00 to resemble padding-like segments */
            u32 pad = 1u + urand_sid(8);
            if (pad > out_len) pad = out_len;
            memset(out_id + (out_len - pad), 0x00, pad);

        } else if (cat < 90) {
            /* G. In-range sweep: sweep length and embed a counter pattern */
            u8 newl = clamp_u8(urand_sid(DTLS_MAX_SESSION_ID_LEN + 1u));
            if (newl > (u8)DTLS_MAX_SESSION_ID_LEN) newl = (u8)DTLS_MAX_SESSION_ID_LEN;
            out_len = newl;
            memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            for (u32 k = 0; k < out_len; k++) out_id[k] = (u8)(k + (u8)urand_sid(16));

        } else {
            /* H. Random valid mix: splice, then perturb */
            out_len = (urand_sid(100) < 85) ? (u8)(1u + urand_sid(DTLS_MAX_SESSION_ID_LEN)) : 0;
            if (out_len == 0) {
                memset(out_id, 0, DTLS_MAX_SESSION_ID_LEN);
            } else {
                fill_bytes(out_id, DTLS_MAX_SESSION_ID_LEN);
                if (seen_cnt && urand_sid(3) == 0) {
                    u32 pick = urand_sid(seen_cnt);
                    u32 cut = urand_sid(out_len + 1u);
                    memcpy(out_id, seen_id[pick], cut);
                }
                if (urand_sid(4) == 0) {
                    /* small structured prefix */
                    out_id[0] = 0x53; /* 'S' */
                    if (out_len > 1) out_id[1] = 0x49; /* 'I' */
                    if (out_len > 2) out_id[2] = 0x44; /* 'D' */
                }
            }
        }

        /* randomized perturbations: shallow + deep */
        if (urand_sid(100) < 25 && out_len) {
            u32 flips = 1u + urand_sid(4);
            for (u32 f = 0; f < flips; f++) {
                u32 idx = urand_sid(out_len);
                out_id[idx] ^= (u8)(1u << urand_sid(8));
            }
        }
        if (urand_sid(100) < 10 && out_len) {
            if (urand_sid(2) == 0) xor_bytes(out_id, out_len, (u8)(1u + urand_sid(255)));
            else rotl_bytes_1(out_id, out_len);
        }

        set_session_id(p, out_len, out_id);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_cookie = 0xC00C1E01u;
static u32 xs32_cookie(void) {
    u32 x = g_seed_cookie;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_cookie = x;
    return x;
}
static u32 urand_cookie(u32 n) { return n ? (xs32_cookie() % n) : 0; }


static u8 cookie_max_len(void) { return (u8)DTLS_MAX_COOKIE_LEN; }


/* Cookie in ClientHello is a length-prefixed opaque vector.
 * Optionality in this struct is modeled by cookie_len==0.
 */
static void get_cookie(const dtls_packet_t *p, u8 *len_out, u8 *buf255) {
    if (!len_out || !buf255) return;
    *len_out = 0;
    memset(buf255, 0, DTLS_MAX_COOKIE_LEN);
    if (!is_client_hello(p)) return;

    u8 l = p->payload.handshake.body.client_hello.cookie_len;
    if (l > cookie_max_len()) l = cookie_max_len();
    *len_out = l;
    memcpy(buf255, p->payload.handshake.body.client_hello.cookie, l);
}

static void set_cookie(dtls_packet_t *p, u8 len, const u8 *buf255) {
    if (!p || !buf255) return;
    if (!is_client_hello(p)) return;

    if (len > cookie_max_len()) len = cookie_max_len();
    p->payload.handshake.body.client_hello.cookie_len = len;
    /* backing buffer always max-sized */
    memset(p->payload.handshake.body.client_hello.cookie, 0, DTLS_MAX_COOKIE_LEN);
    memcpy(p->payload.handshake.body.client_hello.cookie, buf255, len);
}

/* Cookie may be empty in the first ClientHello; typically non-empty after HelloVerifyRequest.
 * Not repeatable on-wire.
 */
void add_client_hello_cookie(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        if (p->payload.handshake.body.client_hello.cookie_len != 0) continue;

        u8 buf[DTLS_MAX_COOKIE_LEN];
        fill_bytes(buf, DTLS_MAX_COOKIE_LEN);

        /* canonical-ish cookie lengths seen in practice often small-ish; keep variety */
        u8 newl;
        u32 r = urand_cookie(100);
        if (r < 40) newl = (u8)(8u + urand_cookie(25));        /* 8..32 */
        else if (r < 80) newl = (u8)(1u + urand_cookie(64));   /* 1..64 */
        else newl = (u8)(1u + urand_cookie(DTLS_MAX_COOKIE_LEN)); /* 1..255 */
        set_cookie(p, newl, buf);
    }
}

void delete_client_hello_cookie(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    u8 z[DTLS_MAX_COOKIE_LEN];
    memset(z, 0, sizeof(z));
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        set_cookie(p, 0, z);
    }
}


/* ---------------- mutator ---------------- */

void mutate_client_hello_cookie(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect observed cookies for equivalence-class alternatives */
    u8  seen_len[8];
    u8  seen_cookie[8][DTLS_MAX_COOKIE_LEN];
    u32 seen_cnt = 0;

    for (size_t i = 0; i < n && seen_cnt < 8; i++) {
        if (!is_client_hello(&pkts[i])) continue;
        u8 l;
        u8 buf[DTLS_MAX_COOKIE_LEN];
        get_cookie(&pkts[i], &l, buf);

        int dup = 0;
        for (u32 j = 0; j < seen_cnt; j++) {
            if (seen_len[j] == l && memcmp(seen_cookie[j], buf, DTLS_MAX_COOKIE_LEN) == 0) { dup = 1; break; }
        }
        if (!dup) {
            seen_len[seen_cnt] = l;
            memcpy(seen_cookie[seen_cnt], buf, DTLS_MAX_COOKIE_LEN);
            seen_cnt++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 cur_len;
        u8 cur_buf[DTLS_MAX_COOKIE_LEN];
        get_cookie(p, &cur_len, cur_buf);

        u8 out_len = cur_len;
        u8 out_buf[DTLS_MAX_COOKIE_LEN];
        memcpy(out_buf, cur_buf, DTLS_MAX_COOKIE_LEN);

        u32 cat = urand_cookie(100);

        if (cat < 10) {
            /* A. Canonical form: either empty (first flight) or reasonable cookie (post-HVR) */
            if (urand_cookie(2) == 0) {
                out_len = 0;
                memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            } else {
                out_len = (u8)(16u + urand_cookie(17)); /* 16..32 */
                fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
            }

        } else if (cat < 25) {
            /* B. Boundaries: 0/1/2/32/64/255 with simple patterns */
            static const u8 lens[] = {0, 1, 2, 32, 64, 255};
            out_len = lens[urand_cookie(sizeof(lens) / sizeof(lens[0]))];
            memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            if (out_len) {
                switch (urand_cookie(5)) {
                    case 0: memset(out_buf, 0x00, out_len); break;
                    case 1: memset(out_buf, 0xFF, out_len); break;
                    case 2:
                        for (u32 k = 0; k < out_len; k++) out_buf[k] = (u8)((k & 1) ? 0xAA : 0x55);
                        break;
                    case 3:
                        for (u32 k = 0; k < out_len; k++) out_buf[k] = (u8)k;
                        break;
                    default:
                        fill_bytes(out_buf, out_len);
                        break;
                }
            }

        } else if (cat < 37) {
            /* C. Equivalence-class alternatives: reuse another observed cookie */
            if (seen_cnt) {
                u32 pick = urand_cookie(seen_cnt);
                out_len = seen_len[pick];
                memcpy(out_buf, seen_cookie[pick], DTLS_MAX_COOKIE_LEN);
            } else {
                out_len = (urand_cookie(100) < 30) ? 0 : (u8)(8u + urand_cookie(25));
                if (out_len) fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
                else memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            }

        } else if (cat < 57) {
            /* D. Allowed range: 0..255 length, arbitrary bytes; bias toward 0 and small-ish */
            u32 r = urand_cookie(100);
            if (r < 25) out_len = 0;
            else if (r < 75) out_len = (u8)(1u + urand_cookie(64));   /* 1..64 */
            else out_len = (u8)(1u + urand_cookie(DTLS_MAX_COOKIE_LEN)); /* 1..255 */

            if (out_len) {
                fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
                /* optionally preserve a prefix from current cookie */
                if (cur_len && urand_cookie(3) == 0) {
                    u32 keep = 1u + urand_cookie((cur_len < 16) ? cur_len : 16);
                    memcpy(out_buf, cur_buf, keep);
                }
            } else {
                memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            }

        } else if (cat < 70) {
            /* E. Encoding-shape variant: reorder/scramble bytes while keeping length */
            if (out_len == 0) {
                out_len = (u8)(1u + urand_cookie(64));
                fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
            }
            switch (urand_cookie(4)) {
                case 0: rotl_bytes_1(out_buf, out_len); break;
                case 1: reverse_bytes(out_buf, out_len); break;
                case 2:
                    if (out_len >= 4) swap_halves(out_buf, out_len & ~1u);
                    break;
                default:
                    /* block swap of 4-byte chunks */
                    for (u32 k = 0; k + 7 < out_len; k += 8) {
                        for (u32 t = 0; t < 4; t++) {
                            u8 tmp = out_buf[k + t];
                            out_buf[k + t] = out_buf[k + 4 + t];
                            out_buf[k + 4 + t] = tmp;
                        }
                    }
                    break;
            }

        } else if (cat < 79) {
            /* F. Padding/alignment: emulate pad-like suffix of zeros */
            if (out_len == 0) {
                out_len = (u8)(8u + urand_cookie(25)); /* 8..32 */
                fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
            }
            u32 pad = 1u + urand_cookie(16);
            if (pad > out_len) pad = out_len;
            memset(out_buf + (out_len - pad), 0x00, pad);

        } else if (cat < 90) {
            /* G. In-range sweep: sweep length across range; fill with structured counter */
            out_len = (u8)urand_cookie(DTLS_MAX_COOKIE_LEN + 1u); /* 0..255 */
            memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            for (u32 k = 0; k < out_len; k++) out_buf[k] = (u8)(k + (u8)urand_cookie(16));

        } else {
            /* H. Random valid mix: splice observed prefix + random tail */
            u32 r = urand_cookie(100);
            if (r < 20) out_len = 0;
            else if (r < 80) out_len = (u8)(1u + urand_cookie(64));
            else out_len = (u8)(1u + urand_cookie(DTLS_MAX_COOKIE_LEN));

            if (out_len == 0) {
                memset(out_buf, 0, DTLS_MAX_COOKIE_LEN);
            } else {
                fill_bytes(out_buf, DTLS_MAX_COOKIE_LEN);
                if (seen_cnt && urand_cookie(2) == 0) {
                    u32 pick = urand_cookie(seen_cnt);
                    u32 cut = urand_cookie(out_len + 1u);
                    memcpy(out_buf, seen_cookie[pick], cut);
                }
                /* embed a small marker sometimes (not required by spec, but stays in-range) */
                if (urand_cookie(5) == 0) {
                    out_buf[0] = 0x43; /* 'C' */
                    if (out_len > 1) out_buf[1] = 0x4B; /* 'K' */
                }
            }
        }

        /* randomized perturbations: shallow + deep */
        if (urand_cookie(100) < 30 && out_len) {
            u32 flips = 1u + urand_cookie(6);
            for (u32 f = 0; f < flips; f++) {
                u32 idx = urand_cookie(out_len);
                out_buf[idx] ^= (u8)(1u << urand_cookie(8));
            }
        }
        if (urand_cookie(100) < 12 && out_len) {
            if (urand_cookie(2) == 0) xor_bytes(out_buf, out_len, (u8)(1u + urand_cookie(255)));
            else reverse_bytes(out_buf, out_len);
        }

        set_cookie(p, out_len, out_buf);
    }
}



/* ---------------- minimal helpers ---------------- */

static u32 g_seed_cs = 0xA11CE5u;
static u32 xs32_cs(void) {
    u32 x = g_seed_cs;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_cs = x;
    return x;
}
static u32 urand_cs(u32 n) { return n ? (xs32_cs() % n) : 0; }

static u16 rd_be16(const u8 *p) { return (u16)(((u16)p[0] << 8) | (u16)p[1]); }
static void wr_be16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)(v & 0xFF); }



static u16 max_cs_bytes(void) { return (u16)DTLS_MAX_CIPHER_SUITES_BYTES; }
static u16 even_down(u16 v) { return (u16)(v & (u16)~1u); }
static u16 even_up_clamped(u16 v, u16 cap) {
    u16 r = (u16)((v + 1u) & (u16)~1u);
    return (r > cap) ? cap : r;
}

/* A small curated list of commonly seen DTLS/TLS 1.2 cipher suites.
 * (Values are TLS CipherSuite IDs, used in ClientHello.cipher_suites list)
 */
static const u16 k_cs_common[] = {
    0xC02B, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    0xC02C, /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    0xC02F, /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    0xC030, /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    0xC00A, /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    0xC009, /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    0xC013, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    0xC014, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    0x00A8, /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    0x00A9, /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    0x008C, /* TLS_PSK_WITH_AES_128_CBC_SHA */
    0x008D, /* TLS_PSK_WITH_AES_256_CBC_SHA */
    0x00FF, /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
    0x5600  /* TLS_FALLBACK_SCSV */
};

static u16 pick_common_suite(void) {
    return k_cs_common[urand_cs((u32)(sizeof(k_cs_common) / sizeof(k_cs_common[0])))];
}

static void fill_rand(u8 *dst, size_t n) {
    if (!dst || n == 0) return;
    for (size_t i = 0; i < n; i++) dst[i] = (u8)urand_cs(256);
}

static void zero_tail(u8 *buf, u16 from, u16 total) {
    if (!buf) return;
    if (from >= total) return;
    memset(buf + from, 0, (size_t)(total - from));
}

static void cs_get(const dtls_packet_t *p, u16 *len_out, u8 *buf256) {
    if (!len_out || !buf256) return;
    *len_out = 0;
    memset(buf256, 0, DTLS_MAX_CIPHER_SUITES_BYTES);
    if (!is_client_hello(p)) return;

    u16 l = p->payload.handshake.body.client_hello.cipher_suites_len;
    if (l > max_cs_bytes()) l = max_cs_bytes();
    *len_out = l;
    memcpy(buf256, p->payload.handshake.body.client_hello.cipher_suites, l);
}

static void cs_set(dtls_packet_t *p, u16 len, const u8 *buf256) {
    if (!p || !buf256) return;
    if (!is_client_hello(p)) return;

    if (len > max_cs_bytes()) len = max_cs_bytes();
    /* The list is a vector of uint16, so canonical length is even; keep within buffer. */
    len = even_down(len);

    p->payload.handshake.body.client_hello.cipher_suites_len = len;
    memset(p->payload.handshake.body.client_hello.cipher_suites, 0, DTLS_MAX_CIPHER_SUITES_BYTES);
    memcpy(p->payload.handshake.body.client_hello.cipher_suites, buf256, len);
}

/* list helpers working on a temp buffer */
static u16 cs_count(u16 bytes_len) { return (u16)(bytes_len / 2u); }

static void cs_write_at(u8 *buf, u16 idx, u16 suite) {
    u16 off = (u16)(idx * 2u);
    wr_be16(&buf[off], suite);
}
static u16 cs_read_at(const u8 *buf, u16 idx) {
    u16 off = (u16)(idx * 2u);
    return rd_be16(&buf[off]);
}

static u16 cs_find(const u8 *buf, u16 cnt, u16 suite) {
    for (u16 i = 0; i < cnt; i++) if (cs_read_at(buf, i) == suite) return i;
    return (u16)0xFFFFu;
}

static void cs_shuffle(u8 *buf, u16 cnt) {
    if (!buf || cnt < 2) return;
    for (u16 i = cnt - 1; i > 0; i--) {
        u16 j = (u16)urand_cs((u32)(i + 1u));
        u16 a = cs_read_at(buf, i);
        u16 b = cs_read_at(buf, j);
        cs_write_at(buf, i, b);
        cs_write_at(buf, j, a);
    }
}

static void cs_reverse(u8 *buf, u16 cnt) {
    if (!buf || cnt < 2) return;
    for (u16 i = 0; i < (u16)(cnt / 2u); i++) {
        u16 j = (u16)(cnt - 1u - i);
        u16 a = cs_read_at(buf, i);
        u16 b = cs_read_at(buf, j);
        cs_write_at(buf, i, b);
        cs_write_at(buf, j, a);
    }
}

/* not optional in spec, but tolerate "empty list" as a modeled deletion */
void add_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u16 l;
        u8  buf[DTLS_MAX_CIPHER_SUITES_BYTES];
        cs_get(p, &l, buf);

        if (l != 0) continue;

        /* canonical-ish: a few suites + SCSV sometimes */
        u16 cnt = (u16)(2u + urand_cs(6)); /* 2..7 */
        u16 bytes = (u16)(cnt * 2u);
        if (bytes > max_cs_bytes()) bytes = max_cs_bytes();
        cnt = cs_count(bytes);

        for (u16 k = 0; k < cnt; k++) cs_write_at(buf, k, pick_common_suite());

        /* de-dup lightly */
        for (u16 k = 0; k < cnt; k++) {
            u16 s = cs_read_at(buf, k);
            for (u16 t = (u16)(k + 1u); t < cnt; t++) {
                if (cs_read_at(buf, t) == s) cs_write_at(buf, t, pick_common_suite());
            }
        }

        cs_set(p, bytes, buf);
    }
}

void delete_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    u8 z[DTLS_MAX_CIPHER_SUITES_BYTES];
    memset(z, 0, sizeof(z));
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        cs_set(p, 0, z);
    }
}

/* ---------------- mutator ---------------- */

void mutate_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect observed suite lists (equivalence class alternatives) */
    u16 seen_len[6];
    u8  seen_buf[6][DTLS_MAX_CIPHER_SUITES_BYTES];
    u32 seen_cnt = 0;

    for (size_t i = 0; i < n && seen_cnt < 6; i++) {
        if (!is_client_hello(&pkts[i])) continue;
        u16 l;
        u8  b[DTLS_MAX_CIPHER_SUITES_BYTES];
        cs_get(&pkts[i], &l, b);

        int dup = 0;
        for (u32 j = 0; j < seen_cnt; j++) {
            if (seen_len[j] == l && memcmp(seen_buf[j], b, DTLS_MAX_CIPHER_SUITES_BYTES) == 0) { dup = 1; break; }
        }
        if (!dup) {
            seen_len[seen_cnt] = l;
            memcpy(seen_buf[seen_cnt], b, DTLS_MAX_CIPHER_SUITES_BYTES);
            seen_cnt++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u16 cur_len;
        u8  cur_buf[DTLS_MAX_CIPHER_SUITES_BYTES];
        cs_get(p, &cur_len, cur_buf);

        u16 out_len = cur_len;
        u8  out_buf[DTLS_MAX_CIPHER_SUITES_BYTES];
        memcpy(out_buf, cur_buf, DTLS_MAX_CIPHER_SUITES_BYTES);

        u32 cat = urand_cs(100);

        if (cat < 12) {
            /* A. Canonical form: common set, ordered, include SCSV sometimes */
            u16 cnt = (u16)(4u + urand_cs(6)); /* 4..9 */
            u16 bytes = (u16)(cnt * 2u);
            if (bytes > max_cs_bytes()) bytes = max_cs_bytes();
            cnt = cs_count(bytes);

            for (u16 k = 0; k < cnt; k++) cs_write_at(out_buf, k, pick_common_suite());

            /* ensure one GCM/ECDHE-ish near the front */
            if (cnt) cs_write_at(out_buf, 0, 0xC02B);

            /* maybe ensure SCSV present near end */
            if (cnt >= 2 && urand_cs(2) == 0) cs_write_at(out_buf, (u16)(cnt - 1u), 0x00FF);

            /* remove duplicates by re-rolling */
            for (u16 k = 0; k < cnt; k++) {
                u16 s = cs_read_at(out_buf, k);
                for (u16 t = (u16)(k + 1u); t < cnt; t++) {
                    if (cs_read_at(out_buf, t) == s) cs_write_at(out_buf, t, pick_common_suite());
                }
            }

            out_len = bytes;
            zero_tail(out_buf, out_len, max_cs_bytes());

        } else if (cat < 27) {
            /* B. Boundaries: 0, 2, 4, 32, 64, 256 bytes (even, clamped) */
            static const u16 lens[] = {0, 2, 4, 32, 64, 256};
            out_len = lens[urand_cs((u32)(sizeof(lens) / sizeof(lens[0])))];
            out_len = even_up_clamped(out_len, max_cs_bytes());
            u16 cnt = cs_count(out_len);

            memset(out_buf, 0, DTLS_MAX_CIPHER_SUITES_BYTES);
            for (u16 k = 0; k < cnt; k++) {
                u32 r = urand_cs(100);
                if (r < 70) cs_write_at(out_buf, k, pick_common_suite());
                else cs_write_at(out_buf, k, (u16)urand_cs(0x10000u));
            }

        } else if (cat < 38) {
            /* C. Equivalence-class alternatives: reuse another observed list, maybe permute */
            if (seen_cnt) {
                u32 pick = urand_cs(seen_cnt);
                out_len = seen_len[pick];
                memcpy(out_buf, seen_buf[pick], DTLS_MAX_CIPHER_SUITES_BYTES);
                out_len = even_down(clamp_u16(out_len));
                if (urand_cs(2) == 0) cs_shuffle(out_buf, cs_count(out_len));
            } else {
                /* fallback to a small common list */
                u16 cnt = (u16)(2u + urand_cs(6));
                u16 bytes = (u16)(cnt * 2u);
                if (bytes > max_cs_bytes()) bytes = max_cs_bytes();
                cnt = cs_count(bytes);
                for (u16 k = 0; k < cnt; k++) cs_write_at(out_buf, k, pick_common_suite());
                out_len = bytes;
            }
            zero_tail(out_buf, out_len, max_cs_bytes());

        } else if (cat < 60) {
            /* D. Allowed range: any even length 0..256, each suite is uint16 */
            u32 r = urand_cs(100);
            if (r < 15) out_len = 0;
            else if (r < 70) out_len = (u16)(2u * (1u + urand_cs(16)));  /* 2..32 */
            else if (r < 90) out_len = (u16)(2u * (1u + urand_cs(64)));  /* 2..128 */
            else out_len = (u16)(2u * (1u + urand_cs(128)));             /* 2..256 */
            out_len = even_up_clamped(out_len, max_cs_bytes());

            u16 cnt = cs_count(out_len);
            memset(out_buf, 0, DTLS_MAX_CIPHER_SUITES_BYTES);

            for (u16 k = 0; k < cnt; k++) {
                u32 pcommon = (k < 6) ? 85u : 55u;
                if (urand_cs(100) < pcommon) cs_write_at(out_buf, k, pick_common_suite());
                else cs_write_at(out_buf, k, (u16)urand_cs(0x10000u));
            }

            /* ensure at least one non-zero suite if non-empty */
            if (cnt && cs_read_at(out_buf, 0) == 0x0000) cs_write_at(out_buf, 0, 0xC02B);

        } else if (cat < 73) {
            /* E. Encoding-shape variant: reorder within list; duplicate marker suites; place SCSV at ends */
            if (out_len == 0) {
                u16 cnt = (u16)(4u + urand_cs(6));
                u16 bytes = (u16)(cnt * 2u);
                if (bytes > max_cs_bytes()) bytes = max_cs_bytes();
                cnt = cs_count(bytes);
                for (u16 k = 0; k < cnt; k++) cs_write_at(out_buf, k, pick_common_suite());
                out_len = bytes;
            }
            u16 cnt = cs_count(out_len);
            switch (urand_cs(4)) {
                case 0: cs_shuffle(out_buf, cnt); break;
                case 1: cs_reverse(out_buf, cnt); break;
                case 2:
                    /* move a random element to front */
                    if (cnt >= 2) {
                        u16 j = (u16)urand_cs(cnt);
                        u16 v = cs_read_at(out_buf, j);
                        for (u16 k = j; k > 0; k--) cs_write_at(out_buf, k, cs_read_at(out_buf, (u16)(k - 1u)));
                        cs_write_at(out_buf, 0, v);
                    }
                    break;
                default:
                    /* ensure SCSV exists and positioned */
                    if (cnt >= 1) {
                        if (cs_find(out_buf, cnt, 0x00FF) == 0xFFFFu) cs_write_at(out_buf, (u16)(cnt - 1u), 0x00FF);
                        if (cnt >= 2 && cs_find(out_buf, cnt, 0x5600) == 0xFFFFu) cs_write_at(out_buf, (u16)(cnt - 2u), 0x5600);
                    }
                    break;
            }

        } else if (cat < 82) {
            /* F. Padding/alignment: keep even length; emphasize "aligned tail" of zeros (still bytes within vector) */
            if (out_len == 0) {
                out_len = (u16)(2u * (4u + urand_cs(8))); /* 8..22 suites */
                out_len = even_up_clamped(out_len, max_cs_bytes());
                u16 cnt = cs_count(out_len);
                for (u16 k = 0; k < cnt; k++) cs_write_at(out_buf, k, pick_common_suite());
            }
            u16 cnt = cs_count(out_len);
            /* zero out last 1..4 suites */
            u16 z = (u16)(1u + urand_cs(4));
            if (z > cnt) z = cnt;
            for (u16 k = 0; k < z; k++) cs_write_at(out_buf, (u16)(cnt - 1u - k), 0x0000);

        } else if (cat < 92) {
            /* G. In-range sweep: sweep suite IDs over a narrow band (valid uint16 space), keep even len */
            u16 cnt = (u16)(2u + urand_cs(24)); /* 2..25 */
            u16 bytes = (u16)(cnt * 2u);
            if (bytes > max_cs_bytes()) bytes = max_cs_bytes();
            cnt = cs_count(bytes);

            u16 base = (u16)urand_cs(0x10000u);
            for (u16 k = 0; k < cnt; k++) cs_write_at(out_buf, k, (u16)(base + k));
            out_len = (u16)(cnt * 2u);
            zero_tail(out_buf, out_len, max_cs_bytes());

        } else {
            /* H. Random valid mix: splice prefix from observed + tail random/common, then perturb */
            u16 cnt;
            if (cur_len) {
                out_len = cur_len;
            } else {
                out_len = (u16)(2u * (2u + urand_cs(32))); /* 4..68 suites */
                out_len = even_up_clamped(out_len, max_cs_bytes());
            }
            cnt = cs_count(out_len);

            /* start with random/common */
            for (u16 k = 0; k < cnt; k++) {
                if (urand_cs(100) < 70) cs_write_at(out_buf, k, pick_common_suite());
                else cs_write_at(out_buf, k, (u16)urand_cs(0x10000u));
            }

            if (seen_cnt && urand_cs(2) == 0) {
                u32 pick = urand_cs(seen_cnt);
                u16 slen = even_down(clamp_u16(seen_len[pick]));
                u16 scnt = cs_count(slen);
                u16 cut = (u16)urand_cs((u32)((scnt < cnt) ? scnt : cnt) + 1u);
                memcpy(out_buf, seen_buf[pick], (size_t)(cut * 2u));
            }

            /* ensure at least one strong suite somewhere */
            if (cnt) {
                u16 pos = (u16)urand_cs(cnt);
                cs_write_at(out_buf, pos, 0xC02B);
            }
        }

        /* randomized perturbations: shallow + deep diversity */
        if (urand_cs(100) < 28 && out_len) {
            /* flip a few bits in random bytes inside the list */
            u32 flips = 1u + urand_cs(8);
            for (u32 f = 0; f < flips; f++) {
                u16 idx = (u16)urand_cs(out_len);
                out_buf[idx] ^= (u8)(1u << urand_cs(8));
            }
        }
        if (urand_cs(100) < 14 && out_len >= 2) {
            /* deep: swap two suites */
            u16 cnt = cs_count(out_len);
            if (cnt >= 2) {
                u16 a = (u16)urand_cs(cnt);
                u16 b = (u16)urand_cs(cnt);
                u16 va = cs_read_at(out_buf, a);
                u16 vb = cs_read_at(out_buf, b);
                cs_write_at(out_buf, a, vb);
                cs_write_at(out_buf, b, va);
            }
        }
        if (urand_cs(100) < 10) {
            /* occasionally adjust length slightly but keep even+clamped */
            if (urand_cs(2) == 0) {
                out_len = (out_len >= 2) ? (u16)(out_len - 2u) : 0;
            } else {
                out_len = (out_len + 2u <= max_cs_bytes()) ? (u16)(out_len + 2u) : out_len;
            }
            out_len = even_down(out_len);
        }

        cs_set(p, out_len, out_buf);
    }
}


#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* ---------------- minimal helpers ---------------- */

static u32 g_seed_cm = 0xA11CE5u;
static u32 xs32_cm(void) {
    u32 x = g_seed_cm;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed_cm = x;
    return x;
}
static u32 urand_cm(u32 n) { return n ? (xs32_cm() % n) : 0; }



static u8 max_cm_len(void) { return (u8)DTLS_MAX_COMPRESSION_METHODS_LEN; }

/* TLS/DTLS compression methods (historically):
 * 0 = null, 1 = DEFLATE; others are reserved/unknown.
 */
static u8 pick_known_method(void) {
    return (urand_cm(4) == 0) ? (u8)1 : (u8)0; /* bias to null */
}

static void cm_get(const dtls_packet_t *p, u8 *len_out, u8 *buf16) {
    if (!len_out || !buf16) return;
    *len_out = 0;
    memset(buf16, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
    if (!is_client_hello(p)) return;

    u8 l = p->payload.handshake.body.client_hello.compression_methods_len;
    if (l > max_cm_len()) l = max_cm_len();
    *len_out = l;
    memcpy(buf16, p->payload.handshake.body.client_hello.compression_methods, l);
}

static void cm_set(dtls_packet_t *p, u8 len, const u8 *buf16) {
    if (!p || !buf16) return;
    if (!is_client_hello(p)) return;

    if (len > max_cm_len()) len = max_cm_len();

    p->payload.handshake.body.client_hello.compression_methods_len = len;
    memset(p->payload.handshake.body.client_hello.compression_methods, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
    memcpy(p->payload.handshake.body.client_hello.compression_methods, buf16, len);
}

static int cm_has(const u8 *buf, u8 len, u8 v) {
    for (u8 i = 0; i < len; i++) if (buf[i] == v) return 1;
    return 0;
}

static void cm_shuffle(u8 *buf, u8 len) {
    if (!buf || len < 2) return;
    for (u8 i = (u8)(len - 1u); i > 0; i--) {
        u8 j = (u8)urand_cm((u32)(i + 1u));
        u8 t = buf[i];
        buf[i] = buf[j];
        buf[j] = t;
    }
}

static void cm_reverse(u8 *buf, u8 len) {
    if (!buf || len < 2) return;
    for (u8 i = 0; i < (u8)(len / 2u); i++) {
        u8 j = (u8)(len - 1u - i);
        u8 t = buf[i];
        buf[i] = buf[j];
        buf[j] = t;
    }
}

/* Modeled optionality helpers (field isn't optional in spec, but we allow empty list) */
void add_client_hello_compression_methods(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 l;
        u8 b[DTLS_MAX_COMPRESSION_METHODS_LEN];
        cm_get(p, &l, b);

        if (l != 0) continue;

        /* canonical: length 1, method 0 (null) */
        b[0] = 0;
        cm_set(p, 1, b);
    }
}

void delete_client_hello_compression_methods(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    u8 z[DTLS_MAX_COMPRESSION_METHODS_LEN];
    memset(z, 0, sizeof(z));
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;
        cm_set(p, 0, z);
    }
}


/* ---------------- mutator ---------------- */

void mutate_client_hello_compression_methods(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* collect observed vectors for equivalence-class alternatives */
    u8 seen_len[6];
    u8 seen_buf[6][DTLS_MAX_COMPRESSION_METHODS_LEN];
    u32 seen_cnt = 0;

    for (size_t i = 0; i < n && seen_cnt < 6; i++) {
        if (!is_client_hello(&pkts[i])) continue;
        u8 l;
        u8 b[DTLS_MAX_COMPRESSION_METHODS_LEN];
        cm_get(&pkts[i], &l, b);

        int dup = 0;
        for (u32 j = 0; j < seen_cnt; j++) {
            if (seen_len[j] == l && memcmp(seen_buf[j], b, DTLS_MAX_COMPRESSION_METHODS_LEN) == 0) { dup = 1; break; }
        }
        if (!dup) {
            seen_len[seen_cnt] = l;
            memcpy(seen_buf[seen_cnt], b, DTLS_MAX_COMPRESSION_METHODS_LEN);
            seen_cnt++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_client_hello(p)) continue;

        u8 cur_len;
        u8 cur_buf[DTLS_MAX_COMPRESSION_METHODS_LEN];
        cm_get(p, &cur_len, cur_buf);

        u8 out_len = cur_len;
        u8 out_buf[DTLS_MAX_COMPRESSION_METHODS_LEN];
        memcpy(out_buf, cur_buf, DTLS_MAX_COMPRESSION_METHODS_LEN);

        u32 cat = urand_cm(100);

        if (cat < 18) {
            /* A. Canonical form: [0] only */
            memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
            out_buf[0] = 0;
            out_len = 1;

        } else if (cat < 33) {
            /* B. Boundaries: 0,1,2,16 (clamped); keep 0 often */
            static const u8 lens[] = {0, 1, 2, 16};
            out_len = lens[urand_cm((u32)(sizeof(lens) / sizeof(lens[0])))];
            out_len = clamp_u8(out_len);

            memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
            for (u8 k = 0; k < out_len; k++) {
                u32 r = urand_cm(100);
                if (r < 80) out_buf[k] = pick_known_method();
                else out_buf[k] = (u8)urand_cm(256);
            }
            if (out_len && urand_cm(100) < 85) out_buf[0] = 0; /* bias include null */

        } else if (cat < 45) {
            /* C. Equivalence-class alternatives: reuse another observed vector, maybe permute */
            if (seen_cnt) {
                u32 pick = urand_cm(seen_cnt);
                out_len = seen_len[pick];
                memcpy(out_buf, seen_buf[pick], DTLS_MAX_COMPRESSION_METHODS_LEN);
                out_len = clamp_u8(out_len);
                if (urand_cm(2) == 0) cm_shuffle(out_buf, out_len);
            } else {
                memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
                out_buf[0] = 0;
                out_len = 1;
            }

        } else if (cat < 62) {
            /* D. Allowed enum/range: method bytes are u8; prefer {0,1} with some reserved */
            out_len = (u8)(1u + urand_cm(max_cm_len())); /* 1..16 */
            memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);

            for (u8 k = 0; k < out_len; k++) {
                u32 r = urand_cm(100);
                if (r < 75) out_buf[k] = pick_known_method();
                else if (r < 90) out_buf[k] = (u8)(2u + urand_cm(10)); /* small reserved band */
                else out_buf[k] = (u8)urand_cm(256);
            }
            /* ensure at least one 0 most of the time */
            if (urand_cm(100) < 85) out_buf[urand_cm(out_len)] = 0;

        } else if (cat < 74) {
            /* E. Encoding-shape variant: reorder, duplicate, move null to end/start */
            if (out_len == 0) {
                out_len = 1;
                memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
                out_buf[0] = 0;
            }
            switch (urand_cm(4)) {
                case 0: cm_shuffle(out_buf, out_len); break;
                case 1: cm_reverse(out_buf, out_len); break;
                case 2:
                    /* duplicate a random element (shape change within fixed buffer/len) */
                    if (out_len < max_cm_len()) {
                        u8 src = (u8)urand_cm(out_len);
                        out_buf[out_len] = out_buf[src];
                        out_len++;
                    } else {
                        out_buf[(u8)urand_cm(out_len)] = out_buf[(u8)urand_cm(out_len)];
                    }
                    break;
                default:
                    /* force null to front or end */
                    if (cm_has(out_buf, out_len, 0)) {
                        if (urand_cm(2) == 0) {
                            /* move first found 0 to front */
                            u8 pos = 0;
                            for (u8 k = 0; k < out_len; k++) { if (out_buf[k] == 0) { pos = k; break; } }
                            for (u8 k = pos; k > 0; k--) out_buf[k] = out_buf[(u8)(k - 1u)];
                            out_buf[0] = 0;
                        } else {
                            /* move first found 0 to end */
                            u8 pos = 0;
                            for (u8 k = 0; k < out_len; k++) { if (out_buf[k] == 0) { pos = k; break; } }
                            for (u8 k = pos; k + 1u < out_len; k++) out_buf[k] = out_buf[(u8)(k + 1u)];
                            out_buf[(u8)(out_len - 1u)] = 0;
                        }
                    } else {
                        out_buf[(u8)urand_cm(out_len)] = 0;
                    }
                    break;
            }

        } else if (cat < 82) {
            /* F. Padding/alignment: keep len, but force tail to 0; also sometimes extend len with zeros */
            if (out_len == 0) {
                out_len = (u8)(1u + urand_cm(4)); /* 1..4 */
                memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);
                out_buf[0] = 0;
            }
            /* zero last 1..4 bytes */
            {
                u8 z = (u8)(1u + urand_cm(4));
                if (z > out_len) z = out_len;
                for (u8 k = 0; k < z; k++) out_buf[(u8)(out_len - 1u - k)] = 0;
            }
            /* optionally extend by 1..3 zeros */
            if (urand_cm(3) == 0 && out_len < max_cm_len()) {
                u8 add = (u8)(1u + urand_cm(3));
                if ((u8)(out_len + add) > max_cm_len()) add = (u8)(max_cm_len() - out_len);
                for (u8 k = 0; k < add; k++) out_buf[(u8)(out_len + k)] = 0;
                out_len = (u8)(out_len + add);
            }

        } else if (cat < 92) {
            /* G. In-range sweep: sweep small band, ensure 0 included */
            out_len = (u8)(1u + urand_cm(max_cm_len())); /* 1..16 */
            memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);

            u8 base = (u8)urand_cm(32);
            for (u8 k = 0; k < out_len; k++) out_buf[k] = (u8)(base + k);

            /* inject 0 and maybe 1 */
            out_buf[(u8)urand_cm(out_len)] = 0;
            if (out_len >= 2 && urand_cm(2) == 0) out_buf[(u8)urand_cm(out_len)] = 1;

        } else {
            /* H. Random valid mix: splice observed prefix + random tail, perturb */
            out_len = (cur_len == 0) ? (u8)(1u + urand_cm(max_cm_len())) : cur_len;
            out_len = clamp_u8(out_len);
            memset(out_buf, 0, DTLS_MAX_COMPRESSION_METHODS_LEN);

            for (u8 k = 0; k < out_len; k++) {
                if (urand_cm(100) < 78) out_buf[k] = pick_known_method();
                else out_buf[k] = (u8)urand_cm(256);
            }

            if (seen_cnt && urand_cm(2) == 0) {
                u32 pick = urand_cm(seen_cnt);
                u8 sl = seen_len[pick];
                if (sl > max_cm_len()) sl = max_cm_len();
                u8 cut = (u8)urand_cm((u32)((sl < out_len) ? sl : out_len) + 1u);
                memcpy(out_buf, seen_buf[pick], cut);
            }

            /* keep null present most of the time */
            if (urand_cm(100) < 85) out_buf[(u8)urand_cm(out_len)] = 0;
        }

        /* randomized perturbations: shallow + deep diversity */
        if (urand_cm(100) < 30 && out_len) {
            /* flip a few bits in random elements */
            u32 flips = 1u + urand_cm(6);
            for (u32 f = 0; f < flips; f++) {
                u8 idx = (u8)urand_cm(out_len);
                out_buf[idx] ^= (u8)(1u << urand_cm(8));
            }
        }
        if (urand_cm(100) < 14 && out_len >= 2) {
            /* deep: swap two positions */
            u8 a = (u8)urand_cm(out_len);
            u8 b = (u8)urand_cm(out_len);
            u8 t = out_buf[a];
            out_buf[a] = out_buf[b];
            out_buf[b] = t;
        }
        if (urand_cm(100) < 10) {
            /* occasionally adjust length slightly within range */
            if (urand_cm(2) == 0) {
                out_len = (out_len > 0) ? (u8)(out_len - 1u) : 0;
            } else {
                out_len = (out_len < max_cm_len()) ? (u8)(out_len + 1u) : out_len;
            }
        }

        /* keep buffer clean beyond len */
        for (u8 k = out_len; k < max_cm_len(); k++) out_buf[k] = 0;

        cm_set(p, out_len, out_buf);
    }
}



/* ===== minimal helpers (PRNG, bounds, extension list builder) ===== */

static uint32_t g_rng_state = 0xC0FFEE01u;

static uint32_t rng32(void) {
    /* xorshift32 */
    uint32_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x ? x : 0xA341316Cu;
    return g_rng_state;
}

static uint32_t rand_bounded(uint32_t n) {
    if (n == 0) return 0;
    return rng32() % n;
}

static void rand_bytes(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dst[i] = (uint8_t)(rng32() & 0xFFu);
    }
}

static uint16_t rd_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void wr_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void ext_clear(dtls_extensions_block_t *ext) {
    if (!ext) return;
    ext->present = 0;
    ext->total_len = 0;
    memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);
}

/* Append one TLS extension entry: type(2) + len(2) + data(len) */
static int ext_append(dtls_extensions_block_t *ext, uint16_t typ,
                      const uint8_t *data, uint16_t len) {
    if (!ext) return -1;
    if (!ext->present) {
        ext->present = 1;
        ext->total_len = 0;
    }
    if (len > DTLS_MAX_EXTENSIONS_LEN) return -1;
    if (ext->total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;

    uint32_t need = (uint32_t)ext->total_len + 4u + (uint32_t)len;
    if (need > DTLS_MAX_EXTENSIONS_LEN) return -1;

    uint8_t *p = ext->raw + ext->total_len;
    wr_u16_be(p + 0, typ);
    wr_u16_be(p + 2, len);
    if (len && data) memcpy(p + 4, data, len);
    ext->total_len = (uint16_t)need;
    return 0;
}

typedef struct {
    uint16_t typ;
    uint16_t len;
    const uint8_t *data;  /* points into original raw */
    uint32_t off;         /* offset in raw */
} ext_entry_t;

static int ext_parse_entries(const dtls_extensions_block_t *ext, ext_entry_t *ents, uint32_t *cnt_io) {
    if (!ext || !ents || !cnt_io) return -1;
    uint32_t cap = *cnt_io;
    uint32_t cnt = 0;

    if (!ext->present) { *cnt_io = 0; return 0; }
    if (ext->total_len > DTLS_MAX_EXTENSIONS_LEN) return -1;

    uint32_t o = 0;
    while (o < ext->total_len) {
        if (ext->total_len - o < 4) return -1;
        if (cnt >= cap) return -1;

        const uint8_t *p = ext->raw + o;
        uint16_t typ = rd_u16_be(p + 0);
        uint16_t len = rd_u16_be(p + 2);
        o += 4;

        if (o + (uint32_t)len > ext->total_len) return -1;
        ents[cnt].typ = typ;
        ents[cnt].len = len;
        ents[cnt].data = ext->raw + o;
        ents[cnt].off = o - 4;
        cnt++;

        o += (uint32_t)len;
    }

    *cnt_io = cnt;
    return 0;
}

static void ext_rebuild_shuffled(dtls_extensions_block_t *ext) {
    if (!ext || !ext->present) return;

    ext_entry_t ents[32];
    uint32_t cnt = 32;
    if (ext_parse_entries(ext, ents, &cnt) != 0) return;
    if (cnt <= 1) return;

    /* Fisher-Yates shuffle order by swapping indices */
    uint32_t idx[32];
    for (uint32_t i = 0; i < cnt; i++) idx[i] = i;
    for (uint32_t i = cnt - 1; i > 0; i--) {
        uint32_t j = rand_bounded(i + 1);
        uint32_t t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }

    uint8_t tmp[DTLS_MAX_EXTENSIONS_LEN];
    uint32_t o = 0;
    for (uint32_t k = 0; k < cnt; k++) {
        ext_entry_t e = ents[idx[k]];
        if (o + 4u + (uint32_t)e.len > DTLS_MAX_EXTENSIONS_LEN) break;
        wr_u16_be(tmp + o + 0, e.typ);
        wr_u16_be(tmp + o + 2, e.len);
        if (e.len) memcpy(tmp + o + 4, e.data, e.len);
        o += 4u + (uint32_t)e.len;
    }

    ext->total_len = (uint16_t)o;
    memcpy(ext->raw, tmp, o);
    if (o < DTLS_MAX_EXTENSIONS_LEN) memset(ext->raw + o, 0, DTLS_MAX_EXTENSIONS_LEN - o);
}

static void ext_add_padding_to_align(dtls_extensions_block_t *ext, uint32_t align) {
    if (!ext || !ext->present) return;
    if (align == 0) return;

    uint32_t cur = ext->total_len;
    uint32_t want = (cur + (align - 1)) & ~(align - 1);
    if (want > DTLS_MAX_EXTENSIONS_LEN) want = DTLS_MAX_EXTENSIONS_LEN;

    if (want <= cur) return;

    /* TLS padding extension type is commonly 21 (0x0015). */
    uint32_t max_pad = DTLS_MAX_EXTENSIONS_LEN - cur;
    if (max_pad < 4) return;

    uint32_t pad_data_len = want - cur;
    if (pad_data_len < 4) pad_data_len = 4; /* ensure room for header+some */
    if (pad_data_len > max_pad) pad_data_len = max_pad;

    /* Our append adds 4 bytes header; data is pad_data_len-4 bytes. */
    uint16_t dlen = (pad_data_len >= 4) ? (uint16_t)(pad_data_len - 4) : 0;
    uint8_t pad[256];
    uint16_t use = dlen;
    if (use > sizeof(pad)) use = (uint16_t)sizeof(pad);
    rand_bytes(pad, use);

    /* If too big, append in chunks */
    uint16_t remain = dlen;
    while (remain) {
        uint16_t chunk = remain;
        if (chunk > sizeof(pad)) chunk = (uint16_t)sizeof(pad);
        if (ext_append(ext, 0x0015u, pad, chunk) != 0) break;
        remain = (uint16_t)(remain - chunk);
    }

    /* If we couldn't reach 'want', that's fine; ext_append kept bounds. */
}

/* Build a few common, well-formed extension templates */
static void ext_build_minimal(dtls_extensions_block_t *ext) {
    if (!ext) return;
    ext->present = 1;
    ext->total_len = 0;
    memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);

    /* renegotiation_info (0xFF01) with len=1 and data {0} is common */
    {
        uint8_t ri[1] = { 0x00 };
        (void)ext_append(ext, 0xFF01u, ri, 1);
    }
}

static void ext_build_ecdhe_like(dtls_extensions_block_t *ext) {
    if (!ext) return;
    ext->present = 1;
    ext->total_len = 0;
    memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);

    /* supported_groups (named curves) (0x000A) */
    {
        uint8_t sg[2 + 4];
        /* list length = 4, two groups: secp256r1 (23), secp384r1 (24) */
        sg[0] = 0x00; sg[1] = 0x04;
        sg[2] = 0x00; sg[3] = 0x17;
        sg[4] = 0x00; sg[5] = 0x18;
        (void)ext_append(ext, 0x000Au, sg, (uint16_t)sizeof(sg));
    }

    /* ec_point_formats (0x000B): len=2, {1, 0} */
    {
        uint8_t epf[2] = { 0x01, 0x00 };
        (void)ext_append(ext, 0x000Bu, epf, (uint16_t)sizeof(epf));
    }

    /* signature_algorithms (0x000D) */
    {
        uint8_t sa[2 + 6];
        /* list len=6, pairs: (sha256, ecdsa), (sha1, rsa), (sha256, rsa) */
        sa[0] = 0x00; sa[1] = 0x06;
        sa[2] = 0x04; sa[3] = 0x03;
        sa[4] = 0x02; sa[5] = 0x01;
        sa[6] = 0x04; sa[7] = 0x01;
        (void)ext_append(ext, 0x000Du, sa, (uint16_t)sizeof(sa));
    }

    /* extended_master_secret (0x0017) length=0 */
    (void)ext_append(ext, 0x0017u, NULL, 0);

    /* renegotiation_info */
    {
        uint8_t ri[1] = { 0x00 };
        (void)ext_append(ext, 0xFF01u, ri, 1);
    }
}

static void ext_build_grease_mix(dtls_extensions_block_t *ext) {
    if (!ext) return;
    ext->present = 1;
    ext->total_len = 0;
    memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);

    /* Start with a plausible base set */
    if (rand_bounded(2) == 0) ext_build_minimal(ext);
    else ext_build_ecdhe_like(ext);

    /* Add 0..3 "GREASE-like" unknown extensions with small lengths */
    uint32_t k = rand_bounded(4);
    for (uint32_t i = 0; i < k; i++) {
        uint16_t typ = (uint16_t)(0x0A0Au + (uint16_t)(rand_bounded(0xF0F0u))); /* arbitrary */
        uint16_t len = (uint16_t)rand_bounded(12);
        uint8_t buf[12];
        rand_bytes(buf, len);
        (void)ext_append(ext, typ, buf, len);
    }

    /* Maybe add padding to a boundary */
    if (rand_bounded(2) == 0) {
        uint32_t align = (rand_bounded(2) == 0) ? 8u : 16u;
        ext_add_padding_to_align(ext, align);
    }

    /* Maybe shuffle */
    if (rand_bounded(2) == 0) ext_rebuild_shuffled(ext);
}

static void ext_shallow_perturb(dtls_extensions_block_t *ext) {
    if (!ext || !ext->present) return;
    if (ext->total_len < 5) return;

    /* Try to flip bytes mostly in data areas, avoid breaking type/len too often */
    ext_entry_t ents[32];
    uint32_t cnt = 32;
    if (ext_parse_entries(ext, ents, &cnt) != 0 || cnt == 0) {
        /* fallback: flip some bytes in raw */
        uint32_t flips = 1 + rand_bounded(3);
        for (uint32_t i = 0; i < flips; i++) {
            uint32_t pos = rand_bounded(ext->total_len);
            ext->raw[pos] ^= (uint8_t)(1u << (rand_bounded(8)));
        }
        return;
    }

    uint32_t flips = 1 + rand_bounded(4);
    for (uint32_t i = 0; i < flips; i++) {
        ext_entry_t *e = &ents[rand_bounded(cnt)];
        if (e->len == 0) continue;
        uint32_t j = rand_bounded(e->len);
        uint32_t pos = (e->off + 4u) + j;
        if (pos < ext->total_len) {
            ext->raw[pos] ^= (uint8_t)(rng32() & 0xFFu);
        }
    }
}

/* ===== requested API ===== */

void add_client_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* light re-seed */
    g_rng_state ^= (uint32_t)(uintptr_t)pkts;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 1) continue; /* ClientHello */

        dtls_extensions_block_t *ext = &p->payload.handshake.body.client_hello.extensions;
        if (ext->present) continue; /* already present */

        if (rand_bounded(2) == 0) {
            ext_build_minimal(ext);          /* present=1, small valid list */
        } else {
            ext->present = 1;               /* present with empty vector */
            ext->total_len = 0;
            memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);
        }
    }
}

void delete_client_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    g_rng_state ^= (uint32_t)((uintptr_t)pkts >> 4);

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 1) continue; /* ClientHello */

        dtls_extensions_block_t *ext = &p->payload.handshake.body.client_hello.extensions;
        ext_clear(ext);
    }
}

/* The extensions block itself appears once in ClientHello; no repeat_* needed. */

void mutate_client_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* re-seed per call to avoid collapse across runs */
    g_rng_state ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 1) continue; /* ClientHello */

        dtls_extensions_block_t *ext = &p->payload.handshake.body.client_hello.extensions;

        /* Randomly choose category A..H */
        uint32_t cat = rand_bounded(8);

        switch (cat) {
        case 0: /* A. Canonical form */
            if (rand_bounded(3) == 0) {
                /* canonical minimal: absent */
                ext_clear(ext);
            } else if (rand_bounded(2) == 0) {
                /* present but empty */
                ext->present = 1;
                ext->total_len = 0;
                memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);
            } else {
                /* minimal common extension */
                ext_build_minimal(ext);
            }
            break;

        case 1: { /* B. Boundaries */
            ext->present = 1;
            ext->total_len = 0;
            memset(ext->raw, 0, DTLS_MAX_EXTENSIONS_LEN);

            /* Build a base, then pad to a boundary */
            if (rand_bounded(2) == 0) ext_build_minimal(ext);
            else ext_build_ecdhe_like(ext);

            /* target boundary set */
            static const uint16_t targets[] = { 0, 4, 8, 16, 32, 64, 128, 255, 256, 384, 511, 512 };
            uint16_t t = targets[rand_bounded((uint32_t)(sizeof(targets)/sizeof(targets[0])))];
            if (t == 0) {
                ext->total_len = 0;
            } else if (t <= DTLS_MAX_EXTENSIONS_LEN) {
                /* extend using padding to reach >= t (best-effort) */
                ext_add_padding_to_align(ext, 16u);
                /* If still short, add one padding extension of exact remaining (if possible) */
                if (ext->total_len < t && (uint32_t)t - ext->total_len >= 4u) {
                    uint16_t remain = (uint16_t)(t - ext->total_len);
                    uint16_t dlen = (remain >= 4) ? (uint16_t)(remain - 4) : 0;
                    uint8_t buf[256];
                    uint16_t use = dlen;
                    if (use > sizeof(buf)) use = (uint16_t)sizeof(buf);
                    rand_bytes(buf, use);
                    (void)ext_append(ext, 0x0015u, buf, use);
                }
                if (ext->total_len > t && ext->total_len <= DTLS_MAX_EXTENSIONS_LEN) {
                    /* keep as-is; boundary stress can be >= target */
                }
            }
            break;
        }

        case 2: /* C. Equivalence-class alternatives */
            if (!ext->present || ext->total_len == 0) {
                /* switch between two plausible “classes” */
                if (rand_bounded(2) == 0) ext_build_minimal(ext);
                else ext_build_ecdhe_like(ext);
            } else {
                /* reorder and optionally duplicate an entry */
                ext_rebuild_shuffled(ext);

                /* duplicate first entry (best-effort) */
                ext_entry_t ents[32];
                uint32_t cnt = 32;
                if (ext_parse_entries(ext, ents, &cnt) == 0 && cnt > 0) {
                    ext_entry_t e0 = ents[0];
                    /* capture data */
                    uint8_t tmp[64];
                    uint16_t l = e0.len;
                    if (l > sizeof(tmp)) l = (uint16_t)sizeof(tmp);
                    if (l) memcpy(tmp, e0.data, l);
                    (void)ext_append(ext, e0.typ, tmp, l);
                }
            }
            break;

        case 3: { /* D. Allowed bitfield/enum/range */
            /* Keep structure well-formed and tweak known fields within their domains */
            if (!ext->present || ext->total_len == 0) ext_build_ecdhe_like(ext);

            ext_entry_t ents[32];
            uint32_t cnt = 32;
            if (ext_parse_entries(ext, ents, &cnt) != 0 || cnt == 0) break;

            for (uint32_t k = 0; k < cnt; k++) {
                ext_entry_t *e = &ents[k];
                /* signature_algorithms (0x000D): data starts with uint16 list_len then pairs */
                if (e->typ == 0x000Du && e->len >= 4) {
                    uint32_t base = e->off + 4u;
                    uint16_t list_len = rd_u16_be(ext->raw + base);
                    /* clamp to even and within buffer */
                    if (list_len > (uint16_t)(e->len - 2)) list_len = (uint16_t)(e->len - 2);
                    list_len = (uint16_t)(list_len & ~1u);
                    wr_u16_be(ext->raw + base, list_len);

                    /* tweak a few pairs */
                    uint32_t pairs = (uint32_t)list_len / 2u;
                    if (pairs) {
                        uint32_t tweak = 1 + rand_bounded(3);
                        for (uint32_t t = 0; t < tweak; t++) {
                            uint32_t pi = rand_bounded(pairs);
                            uint32_t pos = base + 2u + pi*2u;
                            if (pos + 1u < e->off + 4u + e->len) {
                                /* hash: 1..6 (common), sig: 1..3 (rsa/dsa/ecdsa) */
                                ext->raw[pos + 0] = (uint8_t)(1u + rand_bounded(6));
                                ext->raw[pos + 1] = (uint8_t)(1u + rand_bounded(3));
                            }
                        }
                    }
                }

                /* ec_point_formats (0x000B): first byte is list length */
                if (e->typ == 0x000Bu && e->len >= 1) {
                    uint32_t base = e->off + 4u;
                    uint8_t l = ext->raw[base];
                    if (l > (uint8_t)(e->len - 1)) l = (uint8_t)(e->len - 1);
                    ext->raw[base] = l;
                    if (l) {
                        /* formats typically 0..2; random in that range */
                        uint32_t flips = 1 + rand_bounded(2);
                        for (uint32_t t = 0; t < flips; t++) {
                            uint32_t pos = base + 1u + rand_bounded(l);
                            if (pos < e->off + 4u + e->len) {
                                ext->raw[pos] = (uint8_t)rand_bounded(3);
                            }
                        }
                    }
                }

                /* supported_groups (0x000A): starts with uint16 list_len then uint16 groups */
                if (e->typ == 0x000Au && e->len >= 4) {
                    uint32_t base = e->off + 4u;
                    uint16_t list_len = rd_u16_be(ext->raw + base);
                    if (list_len > (uint16_t)(e->len - 2)) list_len = (uint16_t)(e->len - 2);
                    list_len = (uint16_t)(list_len & ~1u);
                    wr_u16_be(ext->raw + base, list_len);
                    uint32_t ng = (uint32_t)list_len / 2u;
                    if (ng) {
                        uint32_t gidx = rand_bounded(ng);
                        uint32_t pos = base + 2u + gidx*2u;
                        if (pos + 1u < e->off + 4u + e->len) {
                            /* choose common named groups 23..25 */
                            uint16_t grp = (uint16_t)(23u + rand_bounded(3));
                            wr_u16_be(ext->raw + pos, grp);
                        }
                    }
                }
            }
            break;
        }

        case 4: /* E. Encoding-shape variant */
            /* Add/replace with mixture including zero-length and unknown extensions, keep well-formed */
            ext_build_grease_mix(ext);
            break;

        case 5: { /* F. Padding/alignment */
            if (!ext->present) ext_build_minimal(ext);

            /* Ensure we have at least one padding extension, then align total length */
            uint32_t align = (rand_bounded(2) == 0) ? 8u : 16u;
            ext_add_padding_to_align(ext, align);

            /* Also sometimes insert a tiny zero-length extension (shape variant but still well-formed) */
            if (rand_bounded(2) == 0) {
                uint16_t typ = (uint16_t)rand_bounded(0xFFFFu);
                (void)ext_append(ext, typ, NULL, 0);
            }

            /* Maybe shuffle */
            if (rand_bounded(2) == 0) ext_rebuild_shuffled(ext);
            break;
        }

        case 6: { /* G. In-range sweep */
            if (!ext->present || ext->total_len == 0) ext_build_ecdhe_like(ext);

            /* Sweep by adjusting padding length or appending small entries while staying in-range */
            uint32_t steps = 1 + rand_bounded(4);
            for (uint32_t s = 0; s < steps; s++) {
                uint32_t action = rand_bounded(3);
                if (action == 0) {
                    /* append small unknown ext */
                    uint16_t typ = (uint16_t)(0x7F00u + (uint16_t)rand_bounded(0x0100u));
                    uint16_t len = (uint16_t)rand_bounded(8);
                    uint8_t buf[8];
                    rand_bytes(buf, len);
                    (void)ext_append(ext, typ, buf, len);
                } else if (action == 1) {
                    /* align to a larger boundary */
                    ext_add_padding_to_align(ext, 16u);
                } else {
                    /* shuffle order */
                    ext_rebuild_shuffled(ext);
                }
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default:
            if (rand_bounded(2) == 0) ext_build_ecdhe_like(ext);
            else ext_build_grease_mix(ext);
            break;
        }

        /* Randomized perturbations: mix shallow and deep to avoid collapse */
        {
            uint32_t p1 = rand_bounded(100);
            if (p1 < 35) {
                /* shallow: tweak inside entries */
                ext_shallow_perturb(ext);
            } else if (p1 < 50) {
                /* toggle present occasionally */
                if (ext->present && rand_bounded(3) == 0) {
                    ext_clear(ext);
                } else if (!ext->present) {
                    ext_build_minimal(ext);
                }
            } else if (p1 < 60) {
                /* deep: rebuild and shuffle */
                ext_build_grease_mix(ext);
                ext_rebuild_shuffled(ext);
            }

            /* Always clamp */
            if (ext->total_len > DTLS_MAX_EXTENSIONS_LEN) {
                ext->total_len = DTLS_MAX_EXTENSIONS_LEN;
            }
        }
    }
}



/* ===== minimal helpers ===== */

static uint32_t g_rng_state_sv = 0x6D736E56u;

static uint32_t rng32_sv(void) {
    uint32_t x = g_rng_state_sv;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_sv = x ? x : 0xA341316Cu;
    return g_rng_state_sv;
}

static uint32_t rand_bounded_sv(uint32_t n) {
    if (n == 0) return 0;
    return rng32_sv() % n;
}

static uint8_t pick_u8(const uint8_t *vals, uint32_t cnt) {
    if (!vals || cnt == 0) return 0;
    return vals[rand_bounded_sv(cnt)];
}

static void set_version(dtls_protocol_version_t *v, uint8_t maj, uint8_t min) {
    if (!v) return;
    v->major = maj;
    v->minor = min;
}

/* ===== field: server_hello_server_version =====
 * In DTLS, the ServerHello.server_version is not a fixed constant across all valid handshakes.
 * It is negotiable and may vary among supported DTLS versions. So: mutable.
 *
 * Not optional in ServerHello and appears once => no add/delete/repeat helpers required.
 */

void mutate_server_hello_server_version(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* reseed lightly */
    g_rng_state_sv ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_sv ^= (uint32_t)n * 0x9E3779B9u;

    /* Common DTLS version bytes:
     * DTLS 1.0 = {0xFE, 0xFF}
     * DTLS 1.2 = {0xFE, 0xFD}
     * (Minor values count down in DTLS: 0xFF, 0xFE, 0xFD, ...)
     */
    static const uint8_t canon_maj = 0xFE;
    static const uint8_t canon_min = 0xFD; /* DTLS 1.2 canonical here */

    static const uint8_t dtls_minors[] = { 0xFF, 0xFE, 0xFD }; /* DTLS1.0, 1.1, 1.2 */
    static const uint8_t plausible_minors_more[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0x00, 0x01 };

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        /* ServerHello handshake msg_type = 2 */
        if (p->payload.handshake.handshake_header.msg_type != 2) continue;

        dtls_protocol_version_t *v = &p->payload.handshake.body.server_hello.server_version;

        uint32_t cat = rand_bounded_sv(8);

        switch (cat) {
        case 0: /* A. Canonical form */
            set_version(v, canon_maj, canon_min);
            break;

        case 1: { /* B. Boundaries */
            /* boundary-like minors around DTLS minors, and extreme bytes */
            static const uint8_t mins[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01 };
            uint8_t min = pick_u8(mins, (uint32_t)(sizeof(mins) / sizeof(mins[0])));
            uint8_t maj = (rand_bounded_sv(4) == 0) ? (uint8_t)pick_u8((const uint8_t[]){0x00,0x01,0x7F,0xFF}, 4) : canon_maj;
            set_version(v, maj, min);
            break;
        }

        case 2: /* C. Equivalence-class alternatives */
            /* Other valid/negotiable DTLS versions */
            set_version(v, canon_maj, pick_u8(dtls_minors, (uint32_t)(sizeof(dtls_minors)/sizeof(dtls_minors[0]))));
            break;

        case 3: { /* D. Allowed bitfield/enum/range */
            /* Keep it within the DTLS "family": major 0xFE, minor among a plausible set */
            uint8_t min = pick_u8(plausible_minors_more, (uint32_t)(sizeof(plausible_minors_more)/sizeof(plausible_minors_more[0])));
            set_version(v, canon_maj, min);
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            /* ProtocolVersion is 2 bytes; shape-variant here means controlled byte-wise perturbation. */
            uint8_t maj = canon_maj;
            uint8_t min = canon_min;

            /* flip 1 bit in minor, rarely in major */
            if (rand_bounded_sv(5) == 0) {
                maj ^= (uint8_t)(1u << rand_bounded_sv(8));
            }
            min ^= (uint8_t)(1u << rand_bounded_sv(8));
            set_version(v, maj, min);
            break;
        }

        case 5: /* F. Padding/alignment */
            /* No padding/alignment for fixed 2-byte version; use a stable "alignment-safe" choice. */
            set_version(v, canon_maj, canon_min);
            break;

        case 6: { /* G. In-range sweep */
            /* Sweep within DTLS minor countdown space near known values */
            uint8_t base = 0xFF; /* start at DTLS 1.0 */
            uint8_t step = (uint8_t)rand_bounded_sv(6); /* 0..5 */
            uint8_t min = (uint8_t)(base - step); /* wraps naturally in u8; still byte-range */
            /* Keep major DTLS-like */
            set_version(v, canon_maj, min);
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            /* Randomly choose among canonical DTLS minors, with occasional shallow perturbation */
            uint8_t maj = canon_maj;
            uint8_t min = pick_u8(dtls_minors, (uint32_t)(sizeof(dtls_minors)/sizeof(dtls_minors[0])));

            if (rand_bounded_sv(10) == 0) {
                /* deep-ish: pick from broader plausible set */
                min = pick_u8(plausible_minors_more, (uint32_t)(sizeof(plausible_minors_more)/sizeof(plausible_minors_more[0])));
            }
            if (rand_bounded_sv(6) == 0) {
                /* shallow: tweak one bit */
                min ^= (uint8_t)(1u << rand_bounded_sv(8));
            }
            set_version(v, maj, min);
            break;
        }
        }

        /* randomized perturbations: shallow+deep mix to preserve diversity */
        {
            uint32_t r = rand_bounded_sv(100);
            if (r < 20) {
                /* shallow: flip a bit in minor */
                v->minor ^= (uint8_t)(1u << rand_bounded_sv(8));
            } else if (r < 30) {
                /* deep: swap to another DTLS minor */
                v->major = canon_maj;
                v->minor = pick_u8(dtls_minors, (uint32_t)(sizeof(dtls_minors)/sizeof(dtls_minors[0])));
            } else if (r < 33) {
                /* rare: extreme boundary in both bytes */
                v->major = (uint8_t)pick_u8((const uint8_t[]){0x00,0x01,0x7F,0xFE,0xFF}, 5);
                v->minor = (uint8_t)pick_u8((const uint8_t[]){0x00,0x01,0xFB,0xFC,0xFD,0xFE,0xFF}, 7);
            }
        }
    }
}


/* ===== minimal helpers ===== */

static uint32_t g_rng_state_shr = 0x1A2B3C4Du;

static uint32_t rng32_shr(void) {
    uint32_t x = g_rng_state_shr;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_shr = x ? x : 0xC0FFEE11u;
    return g_rng_state_shr;
}

static uint32_t rand_bounded_shr(uint32_t n) {
    if (n == 0) return 0;
    return rng32_shr() % n;
}

static void memswap_u8(uint8_t *a, uint8_t *b) {
    uint8_t t = *a;
    *a = *b;
    *b = t;
}


static void fill_bytes_pattern(uint8_t *dst, size_t n, uint8_t pat) {
    if (!dst) return;
    for (size_t i = 0; i < n; i++) dst[i] = pat;
}

static void flip_one_bit(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;
    size_t idx = (size_t)rand_bounded_shr((uint32_t)n);
    uint8_t bit = (uint8_t)(1u << rand_bounded_shr(8));
    dst[idx] ^= bit;
}

static void rotate_left(uint8_t *dst, size_t n, size_t k) {
    if (!dst || n == 0) return;
    k %= n;
    if (k == 0) return;

    /* simple in-place rotation using swaps (O(n*k) but n=32 small) */
    for (size_t r = 0; r < k; r++) {
        uint8_t first = dst[0];
        for (size_t i = 0; i + 1 < n; i++) dst[i] = dst[i + 1];
        dst[n - 1] = first;
    }
}

static void sprinkle_small_edits(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;

    uint32_t edits = 1u + rand_bounded_shr(4); /* 1..4 */
    for (uint32_t e = 0; e < edits; e++) {
        uint32_t kind = rand_bounded_shr(5);
        switch (kind) {
        case 0: flip_one_bit(dst, n); break;
        case 1: {
            size_t i = (size_t)rand_bounded_shr((uint32_t)n);
            dst[i] = (uint8_t)(dst[i] + (uint8_t)(1u + rand_bounded_shr(7)));
            break;
        }
        case 2: {
            size_t i = (size_t)rand_bounded_shr((uint32_t)n);
            dst[i] = (uint8_t)(dst[i] - (uint8_t)(1u + rand_bounded_shr(7)));
            break;
        }
        case 3: {
            size_t i = (size_t)rand_bounded_shr((uint32_t)n);
            size_t j = (size_t)rand_bounded_shr((uint32_t)n);
            memswap_u8(&dst[i], &dst[j]);
            break;
        }
        default: {
            size_t i = (size_t)rand_bounded_shr((uint32_t)n);
            dst[i] ^= (uint8_t)rng32_shr();
            break;
        }
        }
    }
}

/* ===== field: server_hello_random =====
 * ServerHello.random is a 32-byte Random (TLS/DTLS), not a fixed constant => mutable.
 * Not optional in ServerHello and appears once => no add/delete/repeat helpers required.
 */

void mutate_server_hello_random(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* reseed lightly */
    g_rng_state_shr ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_shr ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        /* ServerHello handshake msg_type = 2 */
        if (p->payload.handshake.handshake_header.msg_type != 2) continue;

        uint8_t *r = p->payload.handshake.body.server_hello.random.bytes;
        const size_t RLEN = 32;

        uint32_t cat = rand_bounded_shr(8); /* A..H */

        switch (cat) {
        case 0: { /* A. Canonical form */
            /* leave as-is most of the time; sometimes refresh with high-entropy bytes */
            if (rand_bounded_shr(4) == 0) fill_bytes(r, RLEN);
            break;
        }

        case 1: { /* B. Boundaries */
            /* boundary-like patterns: all-00, all-FF, alternating, and low-entropy blocks */
            uint32_t b = rand_bounded_shr(5);
            if (b == 0) fill_bytes_pattern(r, RLEN, 0x00);
            else if (b == 1) fill_bytes_pattern(r, RLEN, 0xFF);
            else if (b == 2) {
                for (size_t k = 0; k < RLEN; k++) r[k] = (uint8_t)((k & 1u) ? 0xAA : 0x55);
            } else if (b == 3) {
                /* half zeros, half random */
                fill_bytes_pattern(r, RLEN / 2, 0x00);
                fill_bytes(r + RLEN / 2, RLEN - RLEN / 2);
            } else {
                /* repeated byte */
                uint8_t pat = (uint8_t)rng32_shr();
                fill_bytes_pattern(r, RLEN, pat);
            }
            break;
        }

        case 2: { /* C. Equivalence-class alternatives */
            /* Different valid randomness classes: time-ish prefix vs fully random */
            uint32_t c = rand_bounded_shr(3);
            if (c == 0) {
                /* "gmt_unix_time"-like 4-byte prefix, rest random */
                uint32_t t = rng32_shr();
                r[0] = (uint8_t)(t >> 24);
                r[1] = (uint8_t)(t >> 16);
                r[2] = (uint8_t)(t >> 8);
                r[3] = (uint8_t)(t);
                fill_bytes(r + 4, RLEN - 4);
            } else if (c == 1) {
                /* counter-ish prefix */
                uint32_t ctr = (uint32_t)i ^ rng32_shr();
                r[0] = (uint8_t)(ctr >> 24);
                r[1] = (uint8_t)(ctr >> 16);
                r[2] = (uint8_t)(ctr >> 8);
                r[3] = (uint8_t)(ctr);
                for (size_t k = 4; k < RLEN; k++) r[k] = (uint8_t)(k + (uint8_t)ctr);
            } else {
                /* fully random */
                fill_bytes(r, RLEN);
            }
            break;
        }

        case 3: { /* D. Allowed bitfield/enum/range */
            /* Any 32 bytes are allowed. Keep it "DTLS-safe": don't force invalid lengths. */
            /* Choose between high entropy or mild edits */
            if (rand_bounded_shr(2) == 0) fill_bytes(r, RLEN);
            else sprinkle_small_edits(r, RLEN);
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            /* Shape is fixed 32 bytes; apply controlled byte-wise transforms */
            uint32_t e = rand_bounded_shr(4);
            if (e == 0) {
                /* reverse */
                for (size_t a = 0, b = RLEN - 1; a < b; a++, b--) memswap_u8(&r[a], &r[b]);
            } else if (e == 1) {
                /* rotate */
                rotate_left(r, RLEN, (size_t)(1 + rand_bounded_shr(7)));
            } else if (e == 2) {
                /* XOR with short repeating mask */
                uint8_t m[4];
                fill_bytes(m, 4);
                for (size_t k = 0; k < RLEN; k++) r[k] ^= m[k & 3u];
            } else {
                /* byte swap pairs */
                for (size_t k = 0; k + 1 < RLEN; k += 2) memswap_u8(&r[k], &r[k + 1]);
            }
            break;
        }

        case 5: { /* F. Padding/alignment */
            /* No padding/alignment in Random; emulate "aligned blocks" by blocky patterns */
            uint32_t f = rand_bounded_shr(3);
            if (f == 0) {
                /* 4-byte aligned repeating words */
                uint32_t w = rng32_shr();
                for (size_t k = 0; k < RLEN; k += 4) {
                    r[k + 0] = (uint8_t)(w >> 24);
                    r[k + 1] = (uint8_t)(w >> 16);
                    r[k + 2] = (uint8_t)(w >> 8);
                    r[k + 3] = (uint8_t)(w);
                    w = w * 1103515245u + 12345u;
                }
            } else if (f == 1) {
                /* 8-byte blocks: each block constant but different */
                for (size_t k = 0; k < RLEN; k += 8) {
                    uint8_t pat = (uint8_t)rng32_shr();
                    for (size_t j = 0; j < 8; j++) r[k + j] = pat;
                }
            } else {
                /* mostly zeros, with aligned "islands" of random */
                fill_bytes_pattern(r, RLEN, 0x00);
                for (uint32_t t = 0; t < 4; t++) {
                    size_t base = (size_t)(rand_bounded_shr(4) * 8); /* 0,8,16,24 */
                    for (size_t j = 0; j < 4; j++) r[base + j] = (uint8_t)rng32_shr();
                }
            }
            break;
        }

        case 6: { /* G. In-range sweep */
            /* Sweep within byte range: create gradients/ramps */
            uint32_t g = rand_bounded_shr(3);
            if (g == 0) {
                uint8_t start = (uint8_t)rng32_shr();
                for (size_t k = 0; k < RLEN; k++) r[k] = (uint8_t)(start + (uint8_t)k);
            } else if (g == 1) {
                uint8_t start = (uint8_t)rng32_shr();
                uint8_t step  = (uint8_t)(1u + rand_bounded_shr(7));
                for (size_t k = 0; k < RLEN; k++) r[k] = (uint8_t)(start + (uint8_t)(k * step));
            } else {
                /* two-phase ramp */
                uint8_t a = (uint8_t)rng32_shr();
                uint8_t b = (uint8_t)rng32_shr();
                for (size_t k = 0; k < RLEN / 2; k++) r[k] = (uint8_t)(a + (uint8_t)k);
                for (size_t k = RLEN / 2; k < RLEN; k++) r[k] = (uint8_t)(b - (uint8_t)(k - RLEN / 2));
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            /* Mix of patterns and entropy */
            uint32_t h = rand_bounded_shr(4);
            if (h == 0) {
                fill_bytes(r, RLEN);
                sprinkle_small_edits(r, RLEN);
            } else if (h == 1) {
                /* time-ish prefix + perturb */
                uint32_t t = rng32_shr();
                r[0] = (uint8_t)(t >> 24);
                r[1] = (uint8_t)(t >> 16);
                r[2] = (uint8_t)(t >> 8);
                r[3] = (uint8_t)(t);
                fill_bytes(r + 4, RLEN - 4);
                if (rand_bounded_shr(2) == 0) flip_one_bit(r, RLEN);
            } else if (h == 2) {
                /* alternating + random islands */
                for (size_t k = 0; k < RLEN; k++) r[k] = (uint8_t)((k & 1u) ? 0xAA : 0x55);
                for (uint32_t t = 0; t < 6; t++) {
                    size_t idx = (size_t)rand_bounded_shr((uint32_t)RLEN);
                    r[idx] = (uint8_t)rng32_shr();
                }
            } else {
                /* keep existing but apply a few transforms */
                if (rand_bounded_shr(2) == 0) rotate_left(r, RLEN, (size_t)(1 + rand_bounded_shr(7)));
                sprinkle_small_edits(r, RLEN);
            }
            break;
        }
        }

        /* randomized perturbations: shallow + deep */
        {
            uint32_t rsel = rand_bounded_shr(100);
            if (rsel < 18) {
                /* shallow */
                flip_one_bit(r, RLEN);
            } else if (rsel < 26) {
                /* shallow: 1..4 small edits */
                sprinkle_small_edits(r, RLEN);
            } else if (rsel < 32) {
                /* deep: regenerate fully */
                fill_bytes(r, RLEN);
            } else if (rsel < 36) {
                /* deep-ish: boundary pattern */
                fill_bytes_pattern(r, RLEN, (rsel & 1u) ? 0x00 : 0xFF);
            }
        }
    }
}



/* ===== minimal helpers ===== */

static uint32_t g_rng_state_shr_sid = 0x7B9D13A5u;

static uint32_t rng32_sid(void) {
    uint32_t x = g_rng_state_shr_sid;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_shr_sid = x ? x : 0xA5A5A5A5u;
    return g_rng_state_shr_sid;
}

static uint32_t rand_bounded_sid(uint32_t n) {
    if (n == 0) return 0;
    return rng32_sid() % n;
}

static void fill_bytes_sid(uint8_t *dst, size_t n) {
    if (!dst) return;
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)rng32_sid();
}

static void fill_pat_sid(uint8_t *dst, size_t n, uint8_t pat) {
    if (!dst) return;
    for (size_t i = 0; i < n; i++) dst[i] = pat;
}

static void memswap_u8_sid(uint8_t *a, uint8_t *b) {
    uint8_t t = *a;
    *a = *b;
    *b = t;
}

static void reverse_bytes_sid(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;
    for (size_t i = 0, j = n - 1; i < j; i++, j--) memswap_u8_sid(&dst[i], &dst[j]);
}

static void rotate_left_sid(uint8_t *dst, size_t n, size_t k) {
    if (!dst || n == 0) return;
    k %= n;
    if (k == 0) return;
    for (size_t r = 0; r < k; r++) {
        uint8_t first = dst[0];
        for (size_t i = 0; i + 1 < n; i++) dst[i] = dst[i + 1];
        dst[n - 1] = first;
    }
}

static void flip_one_bit_sid(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;
    size_t idx = (size_t)rand_bounded_sid((uint32_t)n);
    uint8_t bit = (uint8_t)(1u << rand_bounded_sid(8));
    dst[idx] ^= bit;
}

static void sprinkle_edits_sid(uint8_t *dst, size_t n) {
    if (!dst || n == 0) return;
    uint32_t edits = 1u + rand_bounded_sid(4); /* 1..4 */
    for (uint32_t e = 0; e < edits; e++) {
        uint32_t kind = rand_bounded_sid(5);
        switch (kind) {
        case 0: flip_one_bit_sid(dst, n); break;
        case 1: {
            size_t i = (size_t)rand_bounded_sid((uint32_t)n);
            dst[i] = (uint8_t)(dst[i] + (uint8_t)(1u + rand_bounded_sid(7)));
            break;
        }
        case 2: {
            size_t i = (size_t)rand_bounded_sid((uint32_t)n);
            dst[i] = (uint8_t)(dst[i] - (uint8_t)(1u + rand_bounded_sid(7)));
            break;
        }
        case 3: {
            size_t i = (size_t)rand_bounded_sid((uint32_t)n);
            size_t j = (size_t)rand_bounded_sid((uint32_t)n);
            memswap_u8_sid(&dst[i], &dst[j]);
            break;
        }
        default: {
            size_t i = (size_t)rand_bounded_sid((uint32_t)n);
            dst[i] ^= (uint8_t)rng32_sid();
            break;
        }
        }
    }
}

/* ===== optional helpers requested by template =====
 * In ServerHello, session_id is present as a vector with a length byte.
 * "Optional" can be modeled as len==0 (empty) vs non-empty.
 * It does not appear multiple times in a single ServerHello.
 */

void add_server_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    g_rng_state_shr_sid ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 2) continue; /* ServerHello */

        dtls_session_id_t *sid = &p->payload.handshake.body.server_hello.session_id;
        if (sid->len != 0) continue;

        uint8_t new_len = (uint8_t)(1u + rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN));
        sid->len = new_len;
        fill_bytes_sid(sid->id, new_len);
    }
}

void delete_server_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 2) continue; /* ServerHello */

        dtls_session_id_t *sid = &p->payload.handshake.body.server_hello.session_id;
        sid->len = 0;
        /* keep bytes unchanged to preserve potential later recovery/mix strategies */
    }
}



/* ===== main mutator ===== */

void mutate_server_hello_session_id(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shr_sid ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_shr_sid ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 2) continue; /* ServerHello */

        dtls_session_id_t *sid = &p->payload.handshake.body.server_hello.session_id;
        uint8_t *buf = sid->id;
        uint8_t len = sid->len;

        /* ensure length is in-range; if not, clamp to a safe value */
        if (len > DTLS_MAX_SESSION_ID_LEN) len = (uint8_t)DTLS_MAX_SESSION_ID_LEN;

        uint32_t cat = rand_bounded_sid(8); /* A..H */

        switch (cat) {
        case 0: { /* A. Canonical form */
            /* keep existing; if empty, create a small stable id */
            if (len == 0) {
                uint8_t nl = (uint8_t)(8u + rand_bounded_sid(9)); /* 8..16 */
                sid->len = nl;
                fill_bytes_sid(buf, nl);
            } else {
                /* occasionally refresh while preserving length */
                if (rand_bounded_sid(5) == 0) fill_bytes_sid(buf, len);
            }
            break;
        }

        case 1: { /* B. Boundaries */
            uint32_t b = rand_bounded_sid(6);
            if (b == 0) { /* empty */
                sid->len = 0;
            } else if (b == 1) { /* min non-empty */
                sid->len = 1;
                buf[0] = (uint8_t)rng32_sid();
            } else if (b == 2) { /* max */
                sid->len = (uint8_t)DTLS_MAX_SESSION_ID_LEN;
                fill_bytes_sid(buf, sid->len);
            } else if (b == 3) { /* all zeros */
                if (len == 0) { sid->len = 8; len = 8; }
                fill_pat_sid(buf, len, 0x00);
                sid->len = len;
            } else if (b == 4) { /* all FF */
                if (len == 0) { sid->len = 8; len = 8; }
                fill_pat_sid(buf, len, 0xFF);
                sid->len = len;
            } else { /* alternating */
                if (len == 0) { sid->len = 16; len = 16; }
                for (uint8_t k = 0; k < len; k++) buf[k] = (uint8_t)((k & 1u) ? 0xAA : 0x55);
                sid->len = len;
            }
            break;
        }

        case 2: { /* C. Equivalence-class alternatives */
            /* valid classes: empty (no resumption) vs non-empty; also "sticky" same value across packets */
            uint32_t c = rand_bounded_sid(4);
            if (c == 0) {
                sid->len = 0;
            } else if (c == 1) {
                uint8_t nl = (uint8_t)(8u + rand_bounded_sid(9)); /* 8..16 */
                sid->len = nl;
                fill_bytes_sid(buf, nl);
            } else if (c == 2) {
                /* low-entropy token style */
                uint8_t nl = (uint8_t)(4u + rand_bounded_sid(5)); /* 4..8 */
                sid->len = nl;
                for (uint8_t k = 0; k < nl; k++) buf[k] = (uint8_t)(k + (uint8_t)rng32_sid());
            } else {
                /* keep length, scramble lightly */
                if (len == 0) { sid->len = 12; len = 12; fill_bytes_sid(buf, len); }
                sprinkle_edits_sid(buf, len);
                sid->len = len;
            }
            break;
        }

        case 3: { /* D. Allowed bitfield/enum/range */
            /* allowed range: 0..32; keep within range and tweak length and/or content */
            uint32_t d = rand_bounded_sid(4);
            if (d == 0) {
                sid->len = (uint8_t)rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN + 1u); /* 0..32 */
                if (sid->len) fill_bytes_sid(buf, sid->len);
            } else if (d == 1) {
                /* keep length but mutate bytes */
                if (len == 0) { sid->len = 8; len = 8; fill_bytes_sid(buf, len); }
                sprinkle_edits_sid(buf, len);
                sid->len = len;
            } else if (d == 2) {
                /* set to a common small length */
                sid->len = 32 ? (uint8_t)(16u + rand_bounded_sid(9)) : 16;
                if (sid->len > DTLS_MAX_SESSION_ID_LEN) sid->len = DTLS_MAX_SESSION_ID_LEN;
                fill_bytes_sid(buf, sid->len);
            } else {
                /* truncate */
                if (len > 0) {
                    uint8_t nl = (uint8_t)rand_bounded_sid((uint32_t)len + 1u);
                    sid->len = nl;
                } else {
                    sid->len = 0;
                }
            }
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            /* shape is len-prefixed opaque bytes; vary internal ordering/masks */
            if (len == 0) { sid->len = 12; len = 12; fill_bytes_sid(buf, len); }
            uint32_t e = rand_bounded_sid(4);
            if (e == 0) reverse_bytes_sid(buf, len);
            else if (e == 1) rotate_left_sid(buf, len, (size_t)(1u + rand_bounded_sid(7)));
            else if (e == 2) {
                uint8_t m = (uint8_t)rng32_sid();
                for (uint8_t k = 0; k < len; k++) buf[k] ^= (uint8_t)(m + k);
            } else {
                /* swap pairs */
                for (uint8_t k = 0; k + 1 < len; k += 2) memswap_u8_sid(&buf[k], &buf[k + 1]);
            }
            sid->len = len;
            break;
        }

        case 5: { /* F. Padding/alignment */
            /* no explicit padding, but emulate aligned blocks (2/4/8) inside the id */
            uint32_t f = rand_bounded_sid(3);
            if (len == 0) { sid->len = 16; len = 16; fill_bytes_sid(buf, len); }

            if (f == 0) {
                /* 4-byte aligned repeating words */
                uint32_t w = rng32_sid();
                for (uint8_t k = 0; k + 3 < len; k += 4) {
                    buf[k + 0] = (uint8_t)(w >> 24);
                    buf[k + 1] = (uint8_t)(w >> 16);
                    buf[k + 2] = (uint8_t)(w >> 8);
                    buf[k + 3] = (uint8_t)(w);
                    w = w * 1103515245u + 12345u;
                }
            } else if (f == 1) {
                /* 8-byte constant blocks */
                for (uint8_t k = 0; k < len; k += 8) {
                    uint8_t pat = (uint8_t)rng32_sid();
                    uint8_t end = (uint8_t)((k + 8u <= len) ? (k + 8u) : len);
                    for (uint8_t j = k; j < end; j++) buf[j] = pat;
                }
            } else {
                /* prefix zeros, suffix random */
                uint8_t z = (uint8_t)rand_bounded_sid((uint32_t)len + 1u);
                fill_pat_sid(buf, z, 0x00);
                fill_bytes_sid(buf + z, (size_t)(len - z));
            }
            sid->len = len;
            break;
        }

        case 6: { /* G. In-range sweep */
            /* sweep lengths and values within valid range */
            uint32_t g = rand_bounded_sid(3);
            if (g == 0) {
                /* length sweep tied to packet index */
                uint8_t nl = (uint8_t)((i % (DTLS_MAX_SESSION_ID_LEN + 1u)));
                sid->len = nl;
                if (nl) {
                    uint8_t start = (uint8_t)rng32_sid();
                    for (uint8_t k = 0; k < nl; k++) buf[k] = (uint8_t)(start + k);
                }
            } else if (g == 1) {
                /* ramp bytes keep length */
                if (len == 0) { sid->len = 12; len = 12; }
                uint8_t start = (uint8_t)rng32_sid();
                uint8_t step  = (uint8_t)(1u + rand_bounded_sid(7));
                for (uint8_t k = 0; k < len; k++) buf[k] = (uint8_t)(start + (uint8_t)(k * step));
                sid->len = len;
            } else {
                /* sweep a window inside existing */
                if (len == 0) { sid->len = 16; len = 16; fill_bytes_sid(buf, len); }
                uint8_t base = (uint8_t)rng32_sid();
                uint8_t win  = (uint8_t)(1u + rand_bounded_sid((uint32_t)len));
                uint8_t pos  = (uint8_t)rand_bounded_sid((uint32_t)(len - win + 1u));
                for (uint8_t k = 0; k < win; k++) buf[pos + k] = (uint8_t)(base + k);
                sid->len = len;
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            uint32_t h = rand_bounded_sid(5);
            if (h == 0) {
                sid->len = (uint8_t)rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN + 1u);
                if (sid->len) fill_bytes_sid(buf, sid->len);
            } else if (h == 1) {
                if (len == 0) { sid->len = 8; len = 8; }
                fill_bytes_sid(buf, len);
                sprinkle_edits_sid(buf, len);
                sid->len = len;
            } else if (h == 2) {
                /* keep bytes, adjust length slightly */
                if (len == 0) { sid->len = 12; len = 12; fill_bytes_sid(buf, len); }
                int8_t delta = (int8_t)((int)rand_bounded_sid(7) - 3); /* -3..+3 */
                int nl = (int)len + (int)delta;
                if (nl < 0) nl = 0;
                if (nl > (int)DTLS_MAX_SESSION_ID_LEN) nl = (int)DTLS_MAX_SESSION_ID_LEN;
                sid->len = (uint8_t)nl;
                if (sid->len > len) fill_bytes_sid(buf + len, (size_t)(sid->len - len));
            } else if (h == 3) {
                /* boundary + islands */
                uint8_t nl = (uint8_t)(1u + rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN));
                sid->len = nl;
                fill_pat_sid(buf, nl, (uint8_t)((rng32_sid() & 1u) ? 0x00 : 0xFF));
                for (uint32_t t = 0; t < 4; t++) {
                    uint8_t idx = (uint8_t)rand_bounded_sid(nl);
                    buf[idx] = (uint8_t)rng32_sid();
                }
            } else {
                /* leave as-is; if empty, add */
                if (len == 0) {
                    sid->len = 16;
                    fill_bytes_sid(buf, sid->len);
                } else {
                    sprinkle_edits_sid(buf, len);
                    sid->len = len;
                }
            }
            break;
        }
        }

        /* randomized perturbations: shallow + deep */
        {
            uint32_t rsel = rand_bounded_sid(100);
            if (sid->len > DTLS_MAX_SESSION_ID_LEN) sid->len = DTLS_MAX_SESSION_ID_LEN;

            if (rsel < 16) {
                /* shallow: one bit flip if non-empty */
                if (sid->len) flip_one_bit_sid(sid->id, sid->len);
            } else if (rsel < 24) {
                /* shallow: small edits */
                if (sid->len) sprinkle_edits_sid(sid->id, sid->len);
            } else if (rsel < 30) {
                /* deep: regenerate with random length */
                sid->len = (uint8_t)rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN + 1u);
                if (sid->len) fill_bytes_sid(sid->id, sid->len);
            } else if (rsel < 34) {
                /* deep-ish: force empty/non-empty toggle */
                if (sid->len == 0) {
                    sid->len = (uint8_t)(1u + rand_bounded_sid(DTLS_MAX_SESSION_ID_LEN));
                    fill_bytes_sid(sid->id, sid->len);
                } else {
                    sid->len = 0;
                }
            }
        }
    }
}



/* ===== minimal helpers ===== */

static uint32_t g_rng_state_shr_cs = 0xC1F3A9D7u;

static uint32_t rng32_cs(void) {
    uint32_t x = g_rng_state_shr_cs;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_shr_cs = x ? x : 0x9E3779B9u;
    return g_rng_state_shr_cs;
}

static uint32_t rand_bounded_cs(uint32_t n) {
    if (n == 0) return 0;
    return rng32_cs() % n;
}

static uint16_t bswap16_cs(uint16_t v) {
    return (uint16_t)((uint16_t)(v << 8) | (uint16_t)(v >> 8));
}

static uint16_t clamp_u16_cs(uint32_t v) {
    if (v > 0xFFFFu) return 0xFFFFu;
    return (uint16_t)v;
}

static uint16_t rand_u16_cs(void) {
    return (uint16_t)rng32_cs();
}

static void tiny_shuffle_pairs_cs(uint16_t *arr, size_t n) {
    if (!arr || n < 2) return;
    size_t i = (size_t)rand_bounded_cs((uint32_t)n);
    size_t j = (size_t)rand_bounded_cs((uint32_t)n);
    uint16_t t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
}

static void perturb_u16_cs(uint16_t *v) {
    if (!v) return;
    uint32_t sel = rand_bounded_cs(6);
    switch (sel) {
    case 0: *v ^= (uint16_t)(1u << rand_bounded_cs(16)); break;                 /* flip 1 bit */
    case 1: *v = (uint16_t)(*v + (uint16_t)(1u + rand_bounded_cs(7))); break;   /* small + */
    case 2: *v = (uint16_t)(*v - (uint16_t)(1u + rand_bounded_cs(7))); break;   /* small - */
    case 3: *v ^= (uint16_t)rand_u16_cs(); break;                               /* xor */
    case 4: *v = bswap16_cs(*v); break;                                         /* endian flip */
    default: /* leave */ break;
    }
}

/* A small curated set of common TLS 1.2 cipher suites (16-bit IDs). */
static const uint16_t k_common_tls12_suites_cs[] = {
    0x0035, /* TLS_RSA_WITH_AES_256_CBC_SHA */
    0x002F, /* TLS_RSA_WITH_AES_128_CBC_SHA */
    0x000A, /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    0x009C, /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    0x009D, /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    0xC02F, /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    0xC030, /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    0xC02B, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    0xC02C, /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    0xC013, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    0xC014, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    0xC009, /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    0xC00A, /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    0x00FF  /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
};

static uint16_t pick_common_suite_cs(void) {
    uint32_t n = (uint32_t)(sizeof(k_common_tls12_suites_cs) / sizeof(k_common_tls12_suites_cs[0]));
    return k_common_tls12_suites_cs[rand_bounded_cs(n)];
}

/* ===== optional helpers requested by template =====
 * ServerHello.cipher_suite is mandatory in ServerHello.
 * Model optional add/delete as no-ops.
 * It does not appear multiple times in a single ServerHello.
 */


/* ===== main mutator ===== */

void mutate_server_hello_cipher_suite(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shr_cs ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_shr_cs ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 2) continue; /* ServerHello */

        dtls_server_hello_t *sh = &p->payload.handshake.body.server_hello;
        uint16_t cs = sh->cipher_suite;

        uint32_t cat = rand_bounded_cs(8); /* A..H */
        switch (cat) {
        case 0: { /* A. Canonical form */
            /* keep as-is; if looks unset, pick a common one */
            if (cs == 0x0000u) cs = pick_common_suite_cs();
            break;
        }

        case 1: { /* B. Boundaries */
            uint32_t b = rand_bounded_cs(6);
            if (b == 0) cs = 0x0000u;
            else if (b == 1) cs = 0x0001u;
            else if (b == 2) cs = 0x00FFu;   /* SCSV */
            else if (b == 3) cs = 0xFFFFu;
            else if (b == 4) cs = 0xC000u;
            else cs = 0x00A0u;
            break;
        }

        case 2: { /* C. Equivalence-class alternatives */
            /* Choose from “families”: RSA, ECDHE_RSA, ECDHE_ECDSA, GCM vs CBC, etc. */
            uint32_t c = rand_bounded_cs(5);
            if (c == 0) cs = 0x002Fu;        /* RSA AES128-CBC-SHA */
            else if (c == 1) cs = 0x0035u;   /* RSA AES256-CBC-SHA */
            else if (c == 2) cs = 0x009Cu;   /* RSA AES128-GCM-SHA256 */
            else if (c == 3) cs = 0xC02Fu;   /* ECDHE_RSA AES128-GCM-SHA256 */
            else cs = 0xC02Bu;               /* ECDHE_ECDSA AES128-GCM-SHA256 */
            break;
        }

        case 3: { /* D. Allowed bitfield/enum/range */
            /* This is a 16-bit code point. Stay in 0..0xFFFF, optionally keep within common list. */
            uint32_t d = rand_bounded_cs(4);
            if (d == 0) {
                cs = pick_common_suite_cs();
            } else if (d == 1) {
                /* choose within legacy (0x0000..0x00FF) */
                cs = (uint16_t)rand_bounded_cs(0x0100u);
            } else if (d == 2) {
                /* choose within ECDHE-ish private range band (0xC000..0xC0FF) */
                cs = (uint16_t)(0xC000u + rand_bounded_cs(0x0100u));
            } else {
                cs = rand_u16_cs();
            }
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            /* Byte order/bit twiddles that remain a 16-bit value. */
            uint32_t e = rand_bounded_cs(4);
            if (e == 0) cs = bswap16_cs(cs);
            else if (e == 1) cs ^= 0x00FFu;
            else if (e == 2) cs ^= 0xFF00u;
            else cs = (uint16_t)((cs << 1) | (cs >> 15));
            break;
        }

        case 5: { /* F. Padding/alignment */
            /* No padding here; emulate aligned “high-byte fixed” patterns. */
            uint32_t f = rand_bounded_cs(4);
            if (f == 0) cs = (uint16_t)((cs & 0xFF00u) | 0x00FFu);
            else if (f == 1) cs = (uint16_t)((cs & 0x00FFu) | 0xC000u);
            else if (f == 2) cs = (uint16_t)((cs & 0xFFF0u) | (uint16_t)rand_bounded_cs(16));
            else cs = (uint16_t)((cs & 0x0FFFu) | 0xC000u);
            break;
        }

        case 6: { /* G. In-range sweep */
            /* Sweep through nearby suite IDs (wrap in 16-bit space). */
            uint32_t g = rand_bounded_cs(3);
            if (g == 0) {
                cs = (uint16_t)(cs + (uint16_t)(i & 0x3Fu));
            } else if (g == 1) {
                cs = (uint16_t)(cs - (uint16_t)(i & 0x3Fu));
            } else {
                /* stride sweep */
                uint16_t stride = (uint16_t)(1u + rand_bounded_cs(31));
                cs = (uint16_t)(cs + (uint16_t)(stride * (uint16_t)(i & 0x0Fu)));
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            uint32_t h = rand_bounded_cs(6);
            if (h == 0) cs = pick_common_suite_cs();
            else if (h == 1) cs = (uint16_t)(0xC02Fu + (uint16_t)rand_bounded_cs(8)); /* near common ECDHE */
            else if (h == 2) cs = (uint16_t)rand_bounded_cs(0x0100u);
            else if (h == 3) cs = (uint16_t)(0x009Cu + (uint16_t)rand_bounded_cs(8)); /* near GCM RSA */
            else if (h == 4) cs = rand_u16_cs();
            else {
                /* keep, but perturb */
                perturb_u16_cs(&cs);
            }
            break;
        }
        }

        /* randomized perturbations: mix shallow and deep */
        {
            uint32_t rsel = rand_bounded_cs(100);
            if (rsel < 18) {
                /* shallow: one-bit flip */
                cs ^= (uint16_t)(1u << rand_bounded_cs(16));
            } else if (rsel < 26) {
                /* shallow: small arithmetic */
                cs = (uint16_t)(cs + (uint16_t)(1u + rand_bounded_cs(7)));
            } else if (rsel < 32) {
                /* deep: jump to curated common list */
                cs = pick_common_suite_cs();
            } else if (rsel < 36) {
                /* deep: swap endianness then perturb */
                cs = bswap16_cs(cs);
                perturb_u16_cs(&cs);
            } else if (rsel < 40) {
                /* deep-ish: force into ECDHE band */
                cs = (uint16_t)(0xC000u + rand_bounded_cs(0x0100u));
            }
        }

        /* commit */
        sh->cipher_suite = cs;
    }
}



/* ===== minimal helpers ===== */

static uint32_t g_rng_state_shr_cm = 0xA54D3B21u;

static uint32_t rng32_cm(void) {
    uint32_t x = g_rng_state_shr_cm;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_shr_cm = x ? x : 0x6D2B79F5u;
    return g_rng_state_shr_cm;
}

static uint32_t rand_bounded_cm(uint32_t n) {
    if (n == 0) return 0;
    return rng32_cm() % n;
}

static uint8_t rand_u8_cm(void) {
    return (uint8_t)rng32_cm();
}

static uint8_t rotl8_cm(uint8_t v, uint32_t r) {
    r &= 7u;
    return (uint8_t)((uint8_t)(v << r) | (uint8_t)(v >> ((8u - r) & 7u)));
}

static void perturb_u8_cm(uint8_t *v) {
    if (!v) return;
    uint32_t sel = rand_bounded_cm(6);
    switch (sel) {
    case 0: *v ^= (uint8_t)(1u << rand_bounded_cm(8)); break;                 /* flip 1 bit */
    case 1: *v = (uint8_t)(*v + (uint8_t)(1u + rand_bounded_cm(7))); break;   /* small + */
    case 2: *v = (uint8_t)(*v - (uint8_t)(1u + rand_bounded_cm(7))); break;   /* small - */
    case 3: *v ^= rand_u8_cm(); break;                                        /* xor random */
    case 4: *v = rotl8_cm(*v, 1u + rand_bounded_cm(7)); break;                /* rotate */
    default: /* leave */ break;
    }
}

/* Common TLS compression method IDs.
 *  - 0: null (the only widely used one in TLS 1.2)
 *  - 1: DEFLATE (historical/rare)
 */
static uint8_t pick_common_compression_cm(void) {
    return (rand_bounded_cm(10) < 8) ? 0u : 1u;
}

/* ===== optional helpers requested by template =====
 * ServerHello.compression_method is mandatory in ServerHello.
 * It does not appear multiple times in a single ServerHello.
 */



/* ===== main mutator ===== */

void mutate_server_hello_compression_method(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shr_cm ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_shr_cm ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;
        if (p->payload.handshake.handshake_header.msg_type != 2) continue; /* ServerHello */

        dtls_server_hello_t *sh = &p->payload.handshake.body.server_hello;
        uint8_t cm = sh->compression_method;

        uint32_t cat = rand_bounded_cm(8); /* A..H */
        switch (cat) {
        case 0: { /* A. Canonical form */
            /* Prefer null compression. */
            cm = 0u;
            break;
        }

        case 1: { /* B. Boundaries */
            uint32_t b = rand_bounded_cm(6);
            if (b == 0) cm = 0u;
            else if (b == 1) cm = 1u;
            else if (b == 2) cm = 0xFFu;
            else if (b == 3) cm = 0x7Fu;
            else if (b == 4) cm = 0x80u;
            else cm = 0x02u;
            break;
        }

        case 2: { /* C. Equivalence-class alternatives */
            /* Two reasonable classes: null vs "other"/legacy. */
            uint32_t c = rand_bounded_cm(4);
            if (c == 0) cm = 0u;        /* null */
            else if (c == 1) cm = 1u;   /* DEFLATE */
            else if (c == 2) cm = 0u;   /* null again (bias) */
            else cm = (uint8_t)(2u + rand_bounded_cm(6)); /* small other */
            break;
        }

        case 3: { /* D. Allowed bitfield/enum/range */
            /* It is an 8-bit code point; keep within 0..255. Prefer 0 or 1 often. */
            uint32_t d = rand_bounded_cm(5);
            if (d == 0) cm = 0u;
            else if (d == 1) cm = 1u;
            else if (d == 2) cm = pick_common_compression_cm();
            else if (d == 3) cm = (uint8_t)rand_bounded_cm(4); /* small range 0..3 */
            else cm = rand_u8_cm();
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            /* Byte-level transforms that remain one byte. */
            uint32_t e = rand_bounded_cm(4);
            if (e == 0) cm = (uint8_t)~cm;
            else if (e == 1) cm = (uint8_t)(cm ^ 0x55u);
            else if (e == 2) cm = (uint8_t)(cm ^ 0xAAu);
            else cm = rotl8_cm(cm, 1u + rand_bounded_cm(7));
            break;
        }

        case 5: { /* F. Padding/alignment */
            /* No padding here; emulate aligned patterns (low bits / high bits). */
            uint32_t f = rand_bounded_cm(4);
            if (f == 0) cm = (uint8_t)(cm & 0x0Fu);
            else if (f == 1) cm = (uint8_t)(cm & 0xF0u);
            else if (f == 2) cm = (uint8_t)((cm & 0xF0u) | 0x01u);
            else cm = (uint8_t)((cm & 0x0Fu) | 0x80u);
            break;
        }

        case 6: { /* G. In-range sweep */
            /* Sweep within a small neighborhood; wrap naturally in uint8_t. */
            uint32_t g = rand_bounded_cm(3);
            if (g == 0) cm = (uint8_t)(cm + (uint8_t)(i & 0x0Fu));
            else if (g == 1) cm = (uint8_t)(cm - (uint8_t)(i & 0x0Fu));
            else {
                uint8_t stride = (uint8_t)(1u + rand_bounded_cm(7));
                cm = (uint8_t)(cm + (uint8_t)(stride * (uint8_t)(i & 0x07u)));
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            uint32_t h = rand_bounded_cm(7);
            if (h == 0) cm = 0u;
            else if (h == 1) cm = 1u;
            else if (h == 2) cm = pick_common_compression_cm();
            else if (h == 3) cm = (uint8_t)rand_bounded_cm(8);     /* small */
            else if (h == 4) cm = (uint8_t)(0xF0u | (uint8_t)rand_bounded_cm(16));
            else if (h == 5) cm = rand_u8_cm();
            else perturb_u8_cm(&cm);
            break;
        }
        }

        /* randomized perturbations: mix shallow and deep */
        {
            uint32_t rsel = rand_bounded_cm(100);
            if (rsel < 20) {
                /* shallow: flip 1 bit */
                cm ^= (uint8_t)(1u << rand_bounded_cm(8));
            } else if (rsel < 28) {
                /* shallow: small +/- */
                cm = (uint8_t)(cm + (uint8_t)(1u + rand_bounded_cm(3)));
            } else if (rsel < 34) {
                /* deep: snap back to canonical or legacy-known */
                cm = (rand_bounded_cm(10) < 8) ? 0u : 1u;
            } else if (rsel < 38) {
                /* deep-ish: force into "other" bucket but still small */
                cm = (uint8_t)(2u + rand_bounded_cm(10));
            }
        }

        /* commit */
        sh->compression_method = cm;
    }
}



/* ===== minimal helpers ===== */

static uint32_t g_rng_state_shext = 0xC8E1C3A1u;

static uint32_t rng32_shext(void) {
    uint32_t x = g_rng_state_shext;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state_shext = x ? x : 0x9E3779B9u;
    return g_rng_state_shext;
}

static uint32_t rand_bounded_shext(uint32_t n) {
    if (n == 0) return 0;
    return rng32_shext() % n;
}

static uint8_t rand_u8_shext(void) {
    return (uint8_t)rng32_shext();
}

static uint16_t rand_u16_shext(void) {
    return (uint16_t)rng32_shext();
}

static void memmove_safe_shext(uint8_t *dst, const uint8_t *src, uint32_t n) {
    if (!dst || !src || n == 0) return;
    memmove(dst, src, n);
}

static uint32_t clamp_u32_shext(uint32_t v, uint32_t lo, uint32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int is_server_hello_pkt(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 2; /* ServerHello */
}

/* TLS extension vector helpers:
 * raw[] layout: { ext_type(2) ext_len(2) ext_data(ext_len) }...
 */
static uint32_t extvec_min_len(void) { return 0u; }

static uint32_t extvec_total_len_from_pairs(const uint8_t *raw, uint32_t total) {
    uint32_t o = 0;
    while (o + 4 <= total) {
        uint16_t el = (uint16_t)(((uint16_t)raw[o + 2] << 8) | (uint16_t)raw[o + 3]);
        o += 4u;
        if (o + (uint32_t)el > total) return total; /* stop at first inconsistency */
        o += (uint32_t)el;
    }
    return o;
}

static int extvec_is_well_formed(const uint8_t *raw, uint32_t total) {
    if (!raw && total) return 0;
    return extvec_total_len_from_pairs(raw, total) == total;
}

static uint32_t extvec_count(const uint8_t *raw, uint32_t total) {
    uint32_t o = 0, c = 0;
    while (o + 4 <= total) {
        uint16_t el = (uint16_t)(((uint16_t)raw[o + 2] << 8) | (uint16_t)raw[o + 3]);
        o += 4u;
        if (o + (uint32_t)el > total) break;
        o += (uint32_t)el;
        c++;
    }
    return c;
}

static uint32_t extvec_nth_offset(const uint8_t *raw, uint32_t total, uint32_t idx) {
    uint32_t o = 0, c = 0;
    while (o + 4 <= total) {
        uint16_t el = (uint16_t)(((uint16_t)raw[o + 2] << 8) | (uint16_t)raw[o + 3]);
        if (c == idx) return o;
        o += 4u;
        if (o + (uint32_t)el > total) return total;
        o += (uint32_t)el;
        c++;
    }
    return total;
}

static uint32_t extvec_nth_span(const uint8_t *raw, uint32_t total, uint32_t idx) {
    uint32_t off = extvec_nth_offset(raw, total, idx);
    if (off + 4 > total) return 0;
    uint16_t el = (uint16_t)(((uint16_t)raw[off + 2] << 8) | (uint16_t)raw[off + 3]);
    if (off + 4u + (uint32_t)el > total) return 0;
    return 4u + (uint32_t)el;
}

static void extvec_write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void extvec_overwrite_hdr(uint8_t *raw, uint32_t off, uint16_t typ, uint16_t len) {
    extvec_write_u16(raw + off + 0, typ);
    extvec_write_u16(raw + off + 2, len);
}

static int extvec_append_one(dtls_extensions_block_t *b, uint16_t typ, const uint8_t *data, uint16_t len) {
    if (!b) return -1;
    uint32_t cur = b->total_len;
    uint32_t need = 4u + (uint32_t)len;
    if (cur + need > DTLS_MAX_EXTENSIONS_LEN) return -1;
    extvec_write_u16(b->raw + cur + 0, typ);
    extvec_write_u16(b->raw + cur + 2, len);
    if (len && data) memcpy(b->raw + cur + 4, data, len);
    b->total_len = (uint16_t)(cur + need);
    b->present = 1;
    return 0;
}

static int extvec_delete_nth(dtls_extensions_block_t *b, uint32_t idx) {
    if (!b || b->present == 0) return -1;
    uint32_t total = b->total_len;
    if (!extvec_is_well_formed(b->raw, total)) return -1;

    uint32_t cnt = extvec_count(b->raw, total);
    if (cnt == 0 || idx >= cnt) return -1;

    uint32_t off = extvec_nth_offset(b->raw, total, idx);
    uint32_t span = extvec_nth_span(b->raw, total, idx);
    if (span == 0 || off + span > total) return -1;

    uint32_t tail = total - (off + span);
    if (tail) memmove_safe_shext(b->raw + off, b->raw + off + span, tail);
    b->total_len = (uint16_t)(total - span);

    if (b->total_len == 0) b->present = 0;
    return 0;
}

static int extvec_repeat_nth(dtls_extensions_block_t *b, uint32_t idx) {
    if (!b || b->present == 0) return -1;
    uint32_t total = b->total_len;
    if (!extvec_is_well_formed(b->raw, total)) return -1;

    uint32_t cnt = extvec_count(b->raw, total);
    if (cnt == 0 || idx >= cnt) return -1;

    uint32_t off = extvec_nth_offset(b->raw, total, idx);
    uint32_t span = extvec_nth_span(b->raw, total, idx);
    if (span == 0 || off + span > total) return -1;

    if (total + span > DTLS_MAX_EXTENSIONS_LEN) return -1;

    /* insert duplicate right after original */
    uint32_t insert_at = off + span;
    uint32_t tail = total - insert_at;
    if (tail) memmove_safe_shext(b->raw + insert_at + span, b->raw + insert_at, tail);
    memcpy(b->raw + insert_at, b->raw + off, span);
    b->total_len = (uint16_t)(total + span);
    b->present = 1;
    return 0;
}

/* Some common TLS extension types (not exhaustive). */
enum {
    EXT_SERVER_NAME            = 0,
    EXT_SUPPORTED_GROUPS       = 10,
    EXT_EC_POINT_FORMATS       = 11,
    EXT_SIGNATURE_ALGORITHMS   = 13,
    EXT_ALPN                   = 16,
    EXT_EXTENDED_MASTER_SECRET = 23,
    EXT_SESSION_TICKET         = 35,
    EXT_RENEGOTIATION_INFO     = 0xFF01
};

static uint16_t pick_common_ext_type(void) {
    static const uint16_t t[] = {
        EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS, EXT_EC_POINT_FORMATS,
        EXT_SIGNATURE_ALGORITHMS, EXT_ALPN, EXT_EXTENDED_MASTER_SECRET,
        EXT_SESSION_TICKET, EXT_RENEGOTIATION_INFO
    };
    return t[rand_bounded_shext((uint32_t)(sizeof(t) / sizeof(t[0])))];
}

static void random_fill(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i < n; i++) p[i] = rand_u8_shext();
}

static void shallow_byte_perturb(uint8_t *p, uint32_t n) {
    if (!p || n == 0) return;
    uint32_t flips = 1u + rand_bounded_shext(3);
    for (uint32_t k = 0; k < flips; k++) {
        uint32_t idx = rand_bounded_shext(n);
        uint8_t  bit = (uint8_t)(1u << rand_bounded_shext(8));
        p[idx] ^= bit;
    }
}

static void deep_shuffle_pairs(dtls_extensions_block_t *b) {
    if (!b || b->present == 0) return;
    uint32_t total = b->total_len;
    if (!extvec_is_well_formed(b->raw, total)) return;

    uint32_t cnt = extvec_count(b->raw, total);
    if (cnt < 2) return;

    uint32_t a = rand_bounded_shext(cnt);
    uint32_t c = rand_bounded_shext(cnt);
    if (a == c) return;

    uint32_t oa = extvec_nth_offset(b->raw, total, a);
    uint32_t sa = extvec_nth_span(b->raw, total, a);
    uint32_t oc = extvec_nth_offset(b->raw, total, c);
    uint32_t sc = extvec_nth_span(b->raw, total, c);
    if (sa == 0 || sc == 0) return;

    /* Swap blocks by copying into temp; handle ordering */
    uint8_t tmp[DTLS_MAX_EXTENSIONS_LEN];
    if (total > sizeof(tmp)) return;
    memcpy(tmp, b->raw, total);

    if (oa < oc) {
        /* [ ... A ... ][ ... C ... ] */
        uint32_t a_end = oa + sa;
        uint32_t c_end = oc + sc;
        uint32_t mid_len = oc - a_end;

        /* write: prefix, C, mid, A, suffix */
        uint32_t w = 0;
        memcpy(b->raw + w, tmp + 0, oa); w += oa;
        memcpy(b->raw + w, tmp + oc, sc); w += sc;
        memcpy(b->raw + w, tmp + a_end, mid_len); w += mid_len;
        memcpy(b->raw + w, tmp + oa, sa); w += sa;
        memcpy(b->raw + w, tmp + c_end, total - c_end); w += (total - c_end);
    } else {
        /* [ ... C ... ][ ... A ... ] */
        uint32_t c_end = oc + sc;
        uint32_t a_end = oa + sa;
        uint32_t mid_len = oa - c_end;

        uint32_t w = 0;
        memcpy(b->raw + w, tmp + 0, oc); w += oc;
        memcpy(b->raw + w, tmp + oa, sa); w += sa;
        memcpy(b->raw + w, tmp + c_end, mid_len); w += mid_len;
        memcpy(b->raw + w, tmp + oc, sc); w += sc;
        memcpy(b->raw + w, tmp + a_end, total - a_end); w += (total - a_end);
    }
}

/* ===== optionality / multiplicity hooks ===== */

void add_server_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shext ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_server_hello_pkt(p)) continue;

        dtls_extensions_block_t *b = &p->payload.handshake.body.server_hello.extensions;

        if (b->present && b->total_len > 0) continue;

        b->present = 1;
        b->total_len = 0;

        /* canonical-ish minimal extension: extended_master_secret with empty data */
        (void)extvec_append_one(b, (uint16_t)EXT_EXTENDED_MASTER_SECRET, NULL, 0);

        /* plus (maybe) one more small common extension */
        if (rand_bounded_shext(100) < 35) {
            uint16_t typ = pick_common_ext_type();
            if (typ == EXT_EC_POINT_FORMATS) {
                uint8_t data[2] = { 1u, 0u }; /* list_len=1, uncompressed=0 */
                (void)extvec_append_one(b, typ, data, (uint16_t)sizeof(data));
            } else if (typ == EXT_RENEGOTIATION_INFO) {
                uint8_t data[1] = { 0u }; /* renegotiated_connection length = 0 */
                (void)extvec_append_one(b, typ, data, (uint16_t)sizeof(data));
            } else {
                (void)extvec_append_one(b, typ, NULL, 0);
            }
        }
    }
}

void delete_server_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_server_hello_pkt(p)) continue;

        dtls_extensions_block_t *b = &p->payload.handshake.body.server_hello.extensions;
        b->present = 0;
        b->total_len = 0;
        /* raw remains don't-care */
    }
}

void repeat_server_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shext ^= (uint32_t)(uintptr_t)pkts ^ 0x13579BDFu;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_server_hello_pkt(p)) continue;

        dtls_extensions_block_t *b = &p->payload.handshake.body.server_hello.extensions;
        if (!b->present || b->total_len == 0) continue;
        if (!extvec_is_well_formed(b->raw, b->total_len)) continue;

        uint32_t cnt = extvec_count(b->raw, b->total_len);
        if (cnt == 0) continue;
        uint32_t idx = rand_bounded_shext(cnt);
        (void)extvec_repeat_nth(b, idx);
    }
}

/* ===== mutator ===== */

void mutate_server_hello_extensions(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_state_shext ^= (uint32_t)(uintptr_t)pkts;
    g_rng_state_shext ^= (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_server_hello_pkt(p)) continue;

        dtls_extensions_block_t *b = &p->payload.handshake.body.server_hello.extensions;

        /* ensure present sometimes to avoid collapse into always-empty */
        if (!b->present && rand_bounded_shext(100) < 55) {
            add_server_hello_extensions(p, 1);
        }

        uint32_t cat = rand_bounded_shext(8); /* A..H */
        switch (cat) {
        case 0: { /* A. Canonical form */
            /* canonical-ish: EMS + optionally reneg_info */
            b->present = 1;
            b->total_len = 0;
            (void)extvec_append_one(b, (uint16_t)EXT_EXTENDED_MASTER_SECRET, NULL, 0);
            if (rand_bounded_shext(100) < 35) {
                uint8_t ri[1] = { 0u };
                (void)extvec_append_one(b, (uint16_t)EXT_RENEGOTIATION_INFO, ri, 1);
            }
            break;
        }

        case 1: { /* B. Boundaries */
            b->present = 1;
            {
                uint32_t choice = rand_bounded_shext(6);
                if (choice == 0) {
                    b->total_len = 0; /* empty but present */
                } else if (choice == 1) {
                    /* smallest one extension: type+len only */
                    b->total_len = 4;
                    extvec_overwrite_hdr(b->raw, 0, pick_common_ext_type(), 0);
                } else if (choice == 2) {
                    /* near max: fill with repeated empty headers */
                    uint32_t max = DTLS_MAX_EXTENSIONS_LEN;
                    uint32_t headers = max / 4u;
                    uint32_t use = headers * 4u;
                    b->total_len = (uint16_t)use;
                    for (uint32_t k = 0; k < headers; k++) {
                        extvec_overwrite_hdr(b->raw, k * 4u, pick_common_ext_type(), 0);
                    }
                } else if (choice == 3) {
                    /* make it just under max with a tail payload */
                    uint32_t use = DTLS_MAX_EXTENSIONS_LEN;
                    use = (use > 8u) ? (use - (uint32_t)rand_bounded_shext(8)) : use;
                    b->total_len = (uint16_t)use;
                    random_fill(b->raw, use);
                    /* try to keep first one well-formed */
                    if (use >= 4u) {
                        uint16_t t = pick_common_ext_type();
                        uint16_t l = (uint16_t)clamp_u32_shext(use - 4u, 0u, 0xFFFFu);
                        extvec_overwrite_hdr(b->raw, 0, t, l);
                    }
                } else {
                    /* minimal: two extensions */
                    b->total_len = 0;
                    (void)extvec_append_one(b, pick_common_ext_type(), NULL, 0);
                    (void)extvec_append_one(b, pick_common_ext_type(), NULL, 0);
                }
            }
            break;
        }

        case 2: { /* C. Equivalence-class alternatives */
            /* Classes: empty, single-known, multi-known, random-opaque */
            uint32_t c = rand_bounded_shext(4);
            if (c == 0) {
                b->present = 0;
                b->total_len = 0;
            } else if (c == 1) {
                b->present = 1;
                b->total_len = 0;
                (void)extvec_append_one(b, pick_common_ext_type(), NULL, 0);
            } else if (c == 2) {
                b->present = 1;
                b->total_len = 0;
                for (uint32_t k = 0; k < 1u + rand_bounded_shext(4); k++) {
                    uint16_t typ = pick_common_ext_type();
                    if (typ == EXT_EC_POINT_FORMATS) {
                        uint8_t data[2] = { 1u, 0u };
                        (void)extvec_append_one(b, typ, data, 2);
                    } else {
                        (void)extvec_append_one(b, typ, NULL, 0);
                    }
                }
            } else {
                b->present = 1;
                b->total_len = (uint16_t)rand_bounded_shext(DTLS_MAX_EXTENSIONS_LEN + 1u);
                random_fill(b->raw, b->total_len);
            }
            break;
        }

        case 3: { /* D. Allowed bitfield/enum/range */
            /* total_len is 0..DTLS_MAX_EXTENSIONS_LEN; keep within range,
               and prefer well-formed vectors when possible. */
            if (!b->present) {
                if (rand_bounded_shext(100) < 60) add_server_hello_extensions(p, 1);
                break;
            }
            if (b->total_len > DTLS_MAX_EXTENSIONS_LEN) b->total_len = DTLS_MAX_EXTENSIONS_LEN;

            if (extvec_is_well_formed(b->raw, b->total_len) && b->total_len >= 4 && rand_bounded_shext(100) < 60) {
                uint32_t cnt = extvec_count(b->raw, b->total_len);
                if (cnt) {
                    uint32_t idx = rand_bounded_shext(cnt);
                    uint32_t off = extvec_nth_offset(b->raw, b->total_len, idx);
                    uint32_t span = extvec_nth_span(b->raw, b->total_len, idx);
                    if (span >= 4) {
                        /* tweak type within 16-bit space, keep length stable */
                        uint16_t len = (uint16_t)(((uint16_t)b->raw[off + 2] << 8) | b->raw[off + 3]);
                        uint16_t typ = pick_common_ext_type();
                        if (rand_bounded_shext(100) < 25) typ = rand_u16_shext();
                        extvec_overwrite_hdr(b->raw, off, typ, len);
                    }
                }
            } else {
                /* set to a sane random size and optionally build headers */
                uint32_t newlen = rand_bounded_shext(DTLS_MAX_EXTENSIONS_LEN + 1u);
                b->total_len = (uint16_t)newlen;
                if (newlen) random_fill(b->raw, newlen);
                if (newlen >= 4u && rand_bounded_shext(100) < 50) {
                    uint16_t typ = pick_common_ext_type();
                    uint16_t len = (uint16_t)clamp_u32_shext(newlen - 4u, 0u, 0xFFFFu);
                    extvec_overwrite_hdr(b->raw, 0, typ, len);
                }
            }
            break;
        }

        case 4: { /* E. Encoding-shape variant */
            if (!b->present || b->total_len == 0) break;

            uint32_t e = rand_bounded_shext(4);
            if (e == 0) {
                /* bytewise invert */
                for (uint32_t k = 0; k < b->total_len; k++) b->raw[k] = (uint8_t)~b->raw[k];
            } else if (e == 1) {
                /* xor mask pattern */
                uint8_t m = (rand_bounded_shext(2) == 0) ? 0x55u : 0xAAu;
                for (uint32_t k = 0; k < b->total_len; k++) b->raw[k] ^= m;
            } else if (e == 2) {
                /* swap endianness of every 16-bit word where possible */
                uint32_t words = b->total_len / 2u;
                for (uint32_t w = 0; w < words; w++) {
                    uint8_t a = b->raw[2u * w + 0];
                    b->raw[2u * w + 0] = b->raw[2u * w + 1];
                    b->raw[2u * w + 1] = a;
                }
            } else {
                /* rotate bytes */
                if (b->total_len > 1) {
                    uint32_t shift = 1u + rand_bounded_shext(b->total_len - 1u);
                    uint8_t tmp[DTLS_MAX_EXTENSIONS_LEN];
                    uint32_t L = b->total_len;
                    memcpy(tmp, b->raw, L);
                    memcpy(b->raw, tmp + shift, L - shift);
                    memcpy(b->raw + (L - shift), tmp, shift);
                }
            }
            break;
        }

        case 5: { /* F. Padding/alignment */
            if (!b->present) break;

            /* aim for 4-byte aligned total_len by adding/removing empty headers if possible */
            uint32_t f = rand_bounded_shext(3);
            if (f == 0) {
                /* pad up to next multiple of 4 using empty headers */
                uint32_t L = b->total_len;
                uint32_t rem = L % 4u;
                if (rem != 0) {
                    uint32_t need = 4u - rem;
                    if (L + need <= DTLS_MAX_EXTENSIONS_LEN) {
                        /* if need==1..3, easiest is to rebuild to a multiple of 4 with a new empty ext */
                        /* add one empty ext header if room (adds 4 bytes) */
                        if (L + 4u <= DTLS_MAX_EXTENSIONS_LEN) {
                            (void)extvec_append_one(b, pick_common_ext_type(), NULL, 0);
                        }
                    }
                }
            } else if (f == 1) {
                /* shrink by deleting one extension to reach smaller aligned size */
                if (extvec_is_well_formed(b->raw, b->total_len)) {
                    uint32_t cnt = extvec_count(b->raw, b->total_len);
                    if (cnt) (void)extvec_delete_nth(b, rand_bounded_shext(cnt));
                } else {
                    /* best-effort align down */
                    b->total_len = (uint16_t)(b->total_len & ~3u);
                }
            } else {
                /* insert an explicit "padding-like" extension: type=random, len=0..small */
                uint16_t typ = (uint16_t)(0x0015u + (uint16_t)rand_bounded_shext(32)); /* small type range */
                uint16_t len = (uint16_t)rand_bounded_shext(8);
                uint8_t data[8];
                random_fill(data, len);
                (void)extvec_append_one(b, typ, data, len);
            }
            break;
        }

        case 6: { /* G. In-range sweep */
            /* Systematically vary number of extensions / lengths but keep within bounds. */
            if (!b->present) {
                if (rand_bounded_shext(100) < 70) add_server_hello_extensions(p, 1);
                break;
            }

            if (extvec_is_well_formed(b->raw, b->total_len) && b->total_len > 0) {
                uint32_t cnt = extvec_count(b->raw, b->total_len);
                if (cnt) {
                    uint32_t idx = (uint32_t)(i % cnt);
                    uint32_t off = extvec_nth_offset(b->raw, b->total_len, idx);
                    uint32_t span = extvec_nth_span(b->raw, b->total_len, idx);
                    if (span >= 4u) {
                        uint16_t typ = (uint16_t)(((uint16_t)b->raw[off] << 8) | b->raw[off + 1]);
                        uint16_t len = (uint16_t)(((uint16_t)b->raw[off + 2] << 8) | b->raw[off + 3]);

                        /* sweep length within current span's payload size (keeps overall vector consistent if we also adjust bytes) */
                        uint16_t newlen = len;
                        if (rand_bounded_shext(2) == 0) {
                            newlen = (uint16_t)((len + 1u) & 0x00FFu);
                        } else {
                            newlen = (uint16_t)((len - 1u) & 0x00FFu);
                        }
                        /* keep within available payload bytes of this ext */
                        uint32_t payload_cap = span - 4u;
                        if ((uint32_t)newlen > payload_cap) newlen = (uint16_t)payload_cap;

                        extvec_overwrite_hdr(b->raw, off, typ, newlen);
                        /* if we reduced len, leave tail bytes as-is; if increased within cap, ensure new bytes randomized */
                        if (newlen > len) {
                            uint32_t delta = (uint32_t)newlen - (uint32_t)len;
                            random_fill(b->raw + off + 4u + (uint32_t)len, delta);
                        }
                    }
                }
            } else {
                /* sweep total_len through small steps */
                uint32_t L = b->total_len;
                uint32_t step = 4u * (1u + (uint32_t)(i & 3u));
                if (rand_bounded_shext(2) == 0) {
                    uint32_t nl = (L + step <= DTLS_MAX_EXTENSIONS_LEN) ? (L + step) : DTLS_MAX_EXTENSIONS_LEN;
                    b->total_len = (uint16_t)nl;
                    random_fill(b->raw, b->total_len);
                } else {
                    uint32_t nl = (L >= step) ? (L - step) : 0u;
                    b->total_len = (uint16_t)nl;
                    if (b->total_len == 0) b->present = 0;
                }
            }
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            uint32_t h = rand_bounded_shext(8);
            if (h == 0) {
                /* delete */
                delete_server_hello_extensions(p, 1);
            } else if (h == 1) {
                /* add canonical */
                add_server_hello_extensions(p, 1);
            } else if (h == 2) {
                /* repeat one */
                repeat_server_hello_extensions(p, 1);
            } else if (h == 3) {
                /* shuffle */
                deep_shuffle_pairs(b);
            } else if (h == 4) {
                /* append random small ext */
                b->present = 1;
                {
                    uint16_t typ = pick_common_ext_type();
                    uint16_t len = (uint16_t)rand_bounded_shext(16);
                    uint8_t data[16];
                    random_fill(data, len);
                    (void)extvec_append_one(b, typ, data, len);
                }
            } else if (h == 5) {
                /* shallow byte perturb */
                if (b->present && b->total_len) shallow_byte_perturb(b->raw, b->total_len);
            } else if (h == 6) {
                /* rebuild as a random well-formed vector with a few entries */
                b->present = 1;
                b->total_len = 0;
                {
                    uint32_t kmax = 1u + rand_bounded_shext(6);
                    for (uint32_t k = 0; k < kmax; k++) {
                        uint16_t typ = pick_common_ext_type();
                        uint16_t len = (uint16_t)rand_bounded_shext(12);
                        uint8_t data[12];
                        random_fill(data, len);
                        if (typ == EXT_EXTENDED_MASTER_SECRET) len = 0;
                        if (typ == EXT_RENEGOTIATION_INFO) { uint8_t z = 0; (void)extvec_append_one(b, typ, &z, 1); }
                        else (void)extvec_append_one(b, typ, data, len);
                    }
                }
            } else {
                /* random opaque (still in-range) */
                b->present = 1;
                b->total_len = (uint16_t)rand_bounded_shext(DTLS_MAX_EXTENSIONS_LEN + 1u);
                if (b->total_len) random_fill(b->raw, b->total_len);
            }
            break;
        }
        }

        /* randomized perturbations: shallow + deep to preserve diversity */
        {
            uint32_t r = rand_bounded_shext(100);

            if (r < 18) {
                /* shallow: flip a few bits in raw */
                if (b->present && b->total_len) shallow_byte_perturb(b->raw, b->total_len);
            } else if (r < 26) {
                /* deep: shuffle order if possible */
                deep_shuffle_pairs(b);
            } else if (r < 32) {
                /* deep: duplicate or delete one entry if well-formed */
                if (b->present && extvec_is_well_formed(b->raw, b->total_len)) {
                    uint32_t cnt = extvec_count(b->raw, b->total_len);
                    if (cnt) {
                        if (rand_bounded_shext(2) == 0) (void)extvec_repeat_nth(b, rand_bounded_shext(cnt));
                        else (void)extvec_delete_nth(b, rand_bounded_shext(cnt));
                    }
                }
            } else if (r < 36) {
                /* snap to canonical sometimes */
                add_server_hello_extensions(p, 1);
            }
        }

        /* keep invariants: cap lengths, keep present consistent */
        if (b->total_len > DTLS_MAX_EXTENSIONS_LEN) b->total_len = DTLS_MAX_EXTENSIONS_LEN;
        if (b->total_len == 0) {
            if (rand_bounded_shext(100) < 40) b->present = 0; /* sometimes truly absent */
        } else {
            b->present = 1;
        }
    }
}



/* minimal RNG/helpers */
static uint32_t g_rng_hvsv = 0xA1B2C3D4u;

static uint32_t rng32_hvsv(void) {
    uint32_t x = g_rng_hvsv;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_hvsv = x ? x : 0x9E3779B9u;
    return g_rng_hvsv;
}

static uint32_t rand_bounded_hvsv(uint32_t n) {
    if (n == 0) return 0;
    return rng32_hvsv() % n;
}

static uint8_t rand_u8_hvsv(void) {
    return (uint8_t)rng32_hvsv();
}



static int is_hvr_pkt(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 3; /* HelloVerifyRequest */
}

// static void set_ver(dtls_protocol_version_t *v, uint8_t maj, uint8_t min) {
//     if (!v) return;
//     v->major = maj;
//     v->minor = min;
// }

/* HelloVerifyRequest.server_version is mandatory in DTLS 1.2.*/


void mutate_hello_verify_request_server_version(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_hvsv ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hvr_pkt(p)) continue;

        dtls_protocol_version_t *v = &p->payload.handshake.body.hello_verify_request.server_version;

        /* pick semantic category A..H */
        uint32_t cat = rand_bounded_hvsv(8);

        switch (cat) {
        case 0: /* A. Canonical form */
            /* DTLS 1.2 record uses {0xFE,0xFD}; keep canonical here too */
            set_ver(v, 0xFEu, 0xFDu);
            break;

        case 1: /* B. Boundaries */
            /* edge values for each byte */
            if (rand_bounded_hvsv(2) == 0) set_ver(v, 0x00u, 0x00u);
            else set_ver(v, 0xFFu, 0xFFu);
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* plausible family values that still "look like" TLS/DTLS */
            switch (rand_bounded_hvsv(5)) {
            case 0: set_ver(v, 0xFEu, 0xFDu); break; /* DTLS 1.2 */
            case 1: set_ver(v, 0xFEu, 0xFFu); break; /* DTLS 1.0 (common older) */
            case 2: set_ver(v, 0x03u, 0x03u); break; /* TLS 1.2 (stream TLS) */
            case 3: set_ver(v, 0x03u, 0x01u); break; /* TLS 1.0 */
            default:set_ver(v, 0x03u, 0x04u); break; /* TLS 1.3 marker */
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* For DTLS, major often 0xFE; keep major fixed and vary minor within a small valid-looking set. */
            v->major = 0xFEu;
            switch (rand_bounded_hvsv(4)) {
            case 0: v->minor = 0xFDu; break; /* DTLS 1.2 */
            case 1: v->minor = 0xFFu; break; /* DTLS 1.0 */
            case 2: v->minor = 0xFCu; break; /* near-neighbor */
            default:v->minor = 0xFEu; break; /* near-neighbor */
            }
            break;

        case 4: /* E. Encoding-shape variant */
            /* endianness/swap-like perturbation on bytes */
            if (rand_bounded_hvsv(2) == 0) {
                swap_u8(&v->major, &v->minor);
            } else {
                /* XOR mask that preserves "shape" but changes bits */
                uint8_t m = (rand_bounded_hvsv(2) == 0) ? 0x55u : 0xAAu;
                v->major ^= m;
                v->minor ^= m;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* no padding in this field; emulate alignment-like rounding by snapping low bits */
            v->major = (uint8_t)(v->major & 0xF0u);
            v->minor = (uint8_t)(v->minor & 0xF0u);
            break;

        case 6: { /* G. In-range sweep */
            /* sweep minors around canonical while keeping DTLS major */
            static const uint8_t sweep[] = { 0xFFu, 0xFEu, 0xFDu, 0xFCu };
            v->major = 0xFEu;
            v->minor = sweep[(uint32_t)(i % (sizeof(sweep) / sizeof(sweep[0])))];
            break;
        }

        case 7: /* H. Random valid mix */
        default: {
            /* mix: usually DTLS-like, sometimes TLS-like, rarely fully random */
            uint32_t r = rand_bounded_hvsv(100);
            if (r < 60) {
                /* DTLS-like */
                v->major = 0xFEu;
                v->minor = (rand_bounded_hvsv(2) == 0) ? 0xFDu : 0xFFu;
            } else if (r < 90) {
                /* TLS-like */
                v->major = 0x03u;
                v->minor = (uint8_t)(1u + rand_bounded_hvsv(4)); /* 0x01..0x04 */
            } else {
                /* fully random bytes */
                v->major = rand_u8_hvsv();
                v->minor = rand_u8_hvsv();
            }
            break;
        }
        }

        /* randomized perturbations: shallow + "deep" mix to avoid collapse */
        {
            uint32_t r = rand_bounded_hvsv(100);

            if (r < 18) {
                /* shallow: flip a bit in either byte */
                uint8_t bit = (uint8_t)(1u << rand_bounded_hvsv(8));
                if (rand_bounded_hvsv(2) == 0) v->major ^= bit;
                else v->minor ^= bit;
            } else if (r < 28) {
                /* snap back to canonical occasionally */
                set_ver(v, 0xFEu, 0xFDu);
            } else if (r < 35) {
                /* alternate DTLS 1.0 vs 1.2 toggle */
                v->major = 0xFEu;
                v->minor = (v->minor == 0xFDu) ? 0xFFu : 0xFDu;
            }
        }
    }
}



/* minimal RNG/helpers */
static uint32_t g_rng_hvc = 0xC001D00Du;

static uint32_t rng32_hvc(void) {
    uint32_t x = g_rng_hvc;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_hvc = x ? x : 0x9E3779B9u;
    return g_rng_hvc;
}

static uint32_t rand_bounded_hvc(uint32_t n) {
    if (n == 0) return 0;
    return rng32_hvc() % n;
}

static uint8_t rand_u8_hvc(void) {
    return (uint8_t)rng32_hvc();
}

// static void fill_rand(uint8_t *p, uint32_t n) {
//     if (!p) return;
//     for (uint32_t i = 0; i < n; i++) p[i] = rand_u8_hvc();
// }

static void mem_xor(uint8_t *p, uint32_t n, uint8_t m) {
    if (!p) return;
    for (uint32_t i = 0; i < n; i++) p[i] ^= m;
}

static void mem_rev(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }
}

static void mem_rotl1(uint8_t *p, uint32_t n) {
    if (!p || n == 0) return;
    uint8_t first = p[0];
    memmove(p, p + 1, (size_t)(n - 1));
    p[n - 1] = first;
}


static void clamp_cookie_len(dtls_hello_verify_request_t *hv) {
    if (!hv) return;
    if (hv->cookie_len > DTLS_MAX_COOKIE_LEN) hv->cookie_len = DTLS_MAX_COOKIE_LEN;
}

/* HelloVerifyRequest.cookie is mandatory in the handshake body (cookie_len + cookie bytes).
 * In this struct representation, presence is encoded by cookie_len (0 means empty cookie, still present).
 * "add/delete/repeat" are no-ops to keep interfaces consistent.
 */


void mutate_hello_verify_request_cookie(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_hvc ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x85EBCA6Bu;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_hvr_pkt(p)) continue;

        dtls_hello_verify_request_t *hv = &p->payload.handshake.body.hello_verify_request;
        clamp_cookie_len(hv);

        uint8_t *cookie = hv->cookie;
        uint32_t len = (uint32_t)hv->cookie_len;

        /* pick semantic category A..H */
        uint32_t cat = rand_bounded_hvc(8);

        switch (cat) {
        case 0: /* A. Canonical form */
            /* keep as-is; if empty, synthesize a small, stable-looking cookie */
            if (len == 0) {
                hv->cookie_len = 8;
                len = 8;
                for (uint32_t k = 0; k < len; k++) cookie[k] = (uint8_t)(0xA0u + (uint8_t)k);
            }
            break;

        case 1: /* B. Boundaries */
            /* 0, 1, max-1, max */
            switch (rand_bounded_hvc(4)) {
            case 0: hv->cookie_len = 0; len = 0; break;
            case 1: hv->cookie_len = 1; len = 1; cookie[0] = rand_u8_hvc(); break;
            case 2: hv->cookie_len = (uint8_t)(DTLS_MAX_COOKIE_LEN - 1); len = DTLS_MAX_COOKIE_LEN - 1; fill_rand(cookie, len); break;
            default: hv->cookie_len = (uint8_t)DTLS_MAX_COOKIE_LEN; len = DTLS_MAX_COOKIE_LEN; fill_rand(cookie, len); break;
            }
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* classes: all-zero, all-0xFF, printable-ish, structured prefix */
            if (rand_bounded_hvc(3) == 0) { hv->cookie_len = 16; len = 16; }
            else if (rand_bounded_hvc(3) == 1) { hv->cookie_len = 24; len = 24; }
            else { hv->cookie_len = 8; len = 8; }
            if (len > DTLS_MAX_COOKIE_LEN) len = DTLS_MAX_COOKIE_LEN;
            hv->cookie_len = (uint8_t)len;

            switch (rand_bounded_hvc(4)) {
            case 0:
                memset(cookie, 0x00, len);
                break;
            case 1:
                memset(cookie, 0xFF, len);
                break;
            case 2:
                for (uint32_t k = 0; k < len; k++) cookie[k] = (uint8_t)('A' + (rand_bounded_hvc(26)));
                break;
            default:
                /* "HVR" + random tail */
                if (len >= 3) { cookie[0] = 'H'; cookie[1] = 'V'; cookie[2] = 'R'; }
                if (len > 3) fill_rand(cookie + 3, len - 3);
                break;
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* cookie_len allowed range 0..255; keep within a small typical DTLS cookie size */
            hv->cookie_len = (uint8_t)(8u + rand_bounded_hvc(25u)); /* 8..32 */
            len = hv->cookie_len;
            if (len > DTLS_MAX_COOKIE_LEN) { len = DTLS_MAX_COOKIE_LEN; hv->cookie_len = (uint8_t)len; }
            fill_rand(cookie, len);
            break;

        case 4: /* E. Encoding-shape variant */
            /* transformations that preserve length but change "shape" */
            if (len == 0) {
                hv->cookie_len = 12;
                len = 12;
                fill_rand(cookie, len);
            }
            switch (rand_bounded_hvc(3)) {
            case 0: mem_rev(cookie, len); break;
            case 1: mem_xor(cookie, len, 0x5Au); break;
            default: mem_rotl1(cookie, len); break;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* pad length up to a multiple of 4 (or trim down), using a repeated pad byte */
            {
                uint32_t target = len;
                if (target == 0) target = 4;
                if (rand_bounded_hvc(2) == 0) {
                    /* round up */
                    uint32_t r = target % 4u;
                    if (r != 0) target += (4u - r);
                    if (target > DTLS_MAX_COOKIE_LEN) target = DTLS_MAX_COOKIE_LEN;
                } else {
                    /* round down */
                    target -= (target % 4u);
                    if (target == 0) target = 4;
                }
                hv->cookie_len = (uint8_t)target;
                if (target > len) {
                    /* keep prefix; pad rest */
                    uint8_t pad = (len ? cookie[len - 1] : 0x00u);
                    for (uint32_t k = len; k < target; k++) cookie[k] = pad;
                } else if (target < len) {
                    /* trim by just lowering len (bytes beyond len are ignored by reassembler) */
                } else {
                    /* same length: ensure last byte is a "pad marker" */
                    cookie[target - 1] ^= 0x01u;
                }
                len = target;
            }
            break;

        case 6: /* G. In-range sweep */
            /* sweep lengths across a typical range; content derived from index */
            {
                static const uint8_t sweep_lens[] = { 0, 1, 4, 8, 12, 16, 24, 32 };
                uint32_t idx = (uint32_t)(i % (sizeof(sweep_lens) / sizeof(sweep_lens[0])));
                uint32_t target = sweep_lens[idx];
                if (target > DTLS_MAX_COOKIE_LEN) target = DTLS_MAX_COOKIE_LEN;
                hv->cookie_len = (uint8_t)target;
                len = target;
                for (uint32_t k = 0; k < len; k++) cookie[k] = (uint8_t)(k + (uint8_t)(i * 7u));
            }
            break;

        case 7: /* H. Random valid mix */
        default:
            /* mix shallow+deep: often small cookie, sometimes max, sometimes zero */
            {
                uint32_t r = rand_bounded_hvc(100);
                if (r < 10) {
                    hv->cookie_len = 0;
                    len = 0;
                } else if (r < 70) {
                    hv->cookie_len = (uint8_t)(8u + rand_bounded_hvc(25u)); /* 8..32 */
                    len = hv->cookie_len;
                    fill_rand(cookie, len);
                } else if (r < 90) {
                    hv->cookie_len = (uint8_t)(32u + rand_bounded_hvc(64u)); /* 32..95 */
                    len = hv->cookie_len;
                    if (len > DTLS_MAX_COOKIE_LEN) { len = DTLS_MAX_COOKIE_LEN; hv->cookie_len = (uint8_t)len; }
                    fill_rand(cookie, len);
                } else {
                    hv->cookie_len = (uint8_t)DTLS_MAX_COOKIE_LEN;
                    len = DTLS_MAX_COOKIE_LEN;
                    fill_rand(cookie, len);
                }
            }
            break;
        }

        /* randomized perturbations: shallow + deep */
        clamp_cookie_len(hv);
        len = (uint32_t)hv->cookie_len;

        {
            uint32_t r = rand_bounded_hvc(100);

            if (r < 20) {
                /* shallow: flip one random bit in one random byte (if any) */
                if (len != 0) {
                    uint32_t pos = rand_bounded_hvc(len);
                    uint8_t bit = (uint8_t)(1u << rand_bounded_hvc(8));
                    cookie[pos] ^= bit;
                }
            } else if (r < 30) {
                /* shallow: swap two bytes */
                if (len > 1) {
                    uint32_t a = rand_bounded_hvc(len);
                    uint32_t b = rand_bounded_hvc(len);
                    uint8_t t = cookie[a];
                    cookie[a] = cookie[b];
                    cookie[b] = t;
                }
            } else if (r < 38) {
                /* deep: re-sample length and regenerate content */
                uint32_t target = rand_bounded_hvc(DTLS_MAX_COOKIE_LEN + 1u);
                hv->cookie_len = (uint8_t)target;
                len = target;
                if (len) fill_rand(cookie, len);
            } else if (r < 45) {
                /* deep: "canonical-ish" fallback */
                hv->cookie_len = 16;
                len = 16;
                for (uint32_t k = 0; k < len; k++) cookie[k] = (uint8_t)(0xC0u ^ (uint8_t)k);
            }
        }
    }
}


/* ===== minimal helpers / RNG ===== */
static uint32_t g_rng_cert = 0xA5A5F00Du;

static uint32_t rng32_cert(void) {
    uint32_t x = g_rng_cert;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_cert = x ? x : 0x9E3779B9u;
    return g_rng_cert;
}

static uint32_t rand_bounded_cert(uint32_t n) {
    if (n == 0) return 0;
    return rng32_cert() % n;
}

static uint8_t rand_u8_cert(void) { return (uint8_t)rng32_cert(); }



static int is_cert_pkt(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 11; /* Certificate */
}

static void clamp_cert_len(dtls_certificate_body_t *c) {
    if (!c) return;
    uint32_t l = rd_u24(c->cert_blob_len.b);
    if (l > DTLS_MAX_CERT_BLOB_LEN) {
        l = DTLS_MAX_CERT_BLOB_LEN;
        wr_u24(&c->cert_blob_len, l);
    }
}

/* Certificate.cert_blob is mandatory in Certificate handshake body (3-byte length + blob).
 * In this struct representation, presence is encoded by cert_blob_len (0 means empty).
 * "add/delete/repeat" are no-ops to keep interfaces consistent.
 */

void mutate_certificate_cert_blob(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_cert ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x85EBCA6Bu;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_cert_pkt(p)) continue;

        dtls_certificate_body_t *c = &p->payload.handshake.body.certificate;
        clamp_cert_len(c);

        uint8_t *blob = c->cert_blob;
        uint32_t len = rd_u24(c->cert_blob_len.b);

        /* pick semantic category A..H */
        uint32_t cat = rand_bounded_cert(8);

        switch (cat) {
        case 0: /* A. Canonical form */
            /* keep as-is; if empty, synthesize a minimal DER-like prefix */
            if (len == 0) {
                uint32_t target = 8;
                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                /* 0x30 SEQUENCE, length, then some bytes */
                blob[0] = 0x30;
                blob[1] = (uint8_t)(target - 2);
                for (uint32_t k = 2; k < target; k++) blob[k] = (uint8_t)(0xA0u + (uint8_t)k);
            }
            break;

        case 1: /* B. Boundaries */
            /* 0, 1, small, max-1, max */
            switch (rand_bounded_cert(5)) {
            case 0:
                wr_u24(&c->cert_blob_len, 0);
                len = 0;
                break;
            case 1:
                wr_u24(&c->cert_blob_len, 1);
                len = 1;
                blob[0] = rand_u8_cert();
                break;
            case 2: {
                uint32_t target = 32;
                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                fill_rand(blob, len);
                break;
            }
            case 3: {
                uint32_t target = (DTLS_MAX_CERT_BLOB_LEN > 0) ? (DTLS_MAX_CERT_BLOB_LEN - 1u) : 0u;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                fill_rand(blob, len);
                break;
            }
            default:
                wr_u24(&c->cert_blob_len, DTLS_MAX_CERT_BLOB_LEN);
                len = DTLS_MAX_CERT_BLOB_LEN;
                fill_rand(blob, len);
                break;
            }
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* classes: all-zero, all-0xFF, ASCII PEM-like, DER-like header + random */
            {
                uint32_t target;
                switch (rand_bounded_cert(4)) {
                case 0: target = 64; break;
                case 1: target = 128; break;
                case 2: target = 256; break;
                default: target = 96; break;
                }
                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;

                switch (rand_bounded_cert(4)) {
                case 0:
                    memset(blob, 0x00, len);
                    break;
                case 1:
                    memset(blob, 0xFF, len);
                    break;
                case 2: {
                    /* "-----BEGIN" style (not a full PEM, just class) */
                    const char *hdr = "-----BEGIN CERT-----\n";
                    uint32_t hlen = (uint32_t)strlen(hdr);
                    uint32_t off = 0;
                    while (off < len) {
                        uint32_t take = (hlen <= (len - off)) ? hlen : (len - off);
                        memcpy(blob + off, hdr, take);
                        off += take;
                    }
                    break;
                }
                default:
                    /* DER-ish: 0x30 len ... */
                    fill_rand(blob, len);
                    if (len >= 2) {
                        blob[0] = 0x30;
                        blob[1] = (uint8_t)(len - 2);
                    }
                    break;
                }
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* legal range: 0..DTLS_MAX_CERT_BLOB_LEN */
            {
                uint32_t target = rand_bounded_cert(DTLS_MAX_CERT_BLOB_LEN + 1u);
                /* bias toward typical sizes */
                if (rand_bounded_cert(100) < 60) {
                    target = 256u + rand_bounded_cert(1024u); /* 256..1279 */
                    if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                }
                wr_u24(&c->cert_blob_len, target);
                len = target;
                if (len) fill_rand(blob, len);
            }
            break;

        case 4: /* E. Encoding-shape variant */
            /* keep length, transform bytes to alter "shape" */
            if (len == 0) {
                uint32_t target = 64;
                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                fill_rand(blob, len);
            }
            switch (rand_bounded_cert(4)) {
            case 0: mem_rev(blob, len); break;
            case 1: mem_xor(blob, len, 0x5Au); break;
            case 2: mem_rotl(blob, len, 1u + rand_bounded_cert(7u)); break;
            default:
                /* nibble swap */
                for (uint32_t k = 0; k < len; k++) blob[k] = (uint8_t)((blob[k] << 4) | (blob[k] >> 4));
                break;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* pad/trim to 4 or 16 alignment; pad with last byte */
            {
                uint32_t target = len;
                if (target == 0) target = 16;
                uint32_t align = (rand_bounded_cert(2) == 0) ? 4u : 16u;

                if (rand_bounded_cert(2) == 0) {
                    /* round up */
                    uint32_t r = target % align;
                    if (r) target += (align - r);
                    if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                } else {
                    /* round down */
                    target -= (target % align);
                    if (target == 0) target = align;
                }

                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;

                if (target > len) {
                    uint8_t pad = (len ? blob[len - 1] : 0x00u);
                    /* keep prefix, pad tail */
                    for (uint32_t k = len; k < target; k++) blob[k] = pad;
                } else if (target < len) {
                    /* trim by lowering len */
                } else {
                    /* same length: tweak pad marker */
                    if (target) blob[target - 1] ^= 0x01u;
                }

                wr_u24(&c->cert_blob_len, target);
                len = target;
            }
            break;

        case 6: /* G. In-range sweep */
            /* deterministic-ish sweep over sizes */
            {
                static const uint32_t sweep[] = { 0u, 1u, 8u, 32u, 128u, 256u, 512u, 1024u, 2048u };
                uint32_t idx = (uint32_t)(i % (sizeof(sweep) / sizeof(sweep[0])));
                uint32_t target = sweep[idx];
                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                for (uint32_t k = 0; k < len; k++) blob[k] = (uint8_t)(k + (uint8_t)(i * 13u));
                /* keep a DER-ish start when length permits */
                if (len >= 2) { blob[0] = 0x30; blob[1] = (uint8_t)(len - 2); }
            }
            break;

        case 7: /* H. Random valid mix */
        default:
            {
                uint32_t r = rand_bounded_cert(100);
                uint32_t target;
                if (r < 10) target = 0;
                else if (r < 55) target = 128u + rand_bounded_cert(512u);      /* 128..639 */
                else if (r < 85) target = 512u + rand_bounded_cert(2048u);     /* 512..2559 */
                else target = DTLS_MAX_CERT_BLOB_LEN;

                if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                wr_u24(&c->cert_blob_len, target);
                len = target;
                if (len) fill_rand(blob, len);

                /* sometimes impose DER-like header */
                if (len >= 2 && rand_bounded_cert(100) < 50) {
                    blob[0] = 0x30;
                    blob[1] = (uint8_t)((len > 2) ? (len - 2) : 0);
                }
            }
            break;
        }

        /* randomized perturbations: mix shallow and deep */
        clamp_cert_len(c);
        len = rd_u24(c->cert_blob_len.b);

        {
            uint32_t r = rand_bounded_cert(100);

            if (r < 18) {
                /* shallow: flip one bit in one byte */
                if (len) {
                    uint32_t pos = rand_bounded_cert(len);
                    uint8_t bit = (uint8_t)(1u << rand_bounded_cert(8));
                    blob[pos] ^= bit;
                }
            } else if (r < 28) {
                /* shallow: swap two bytes */
                if (len > 1) {
                    uint32_t a = rand_bounded_cert(len);
                    uint32_t b = rand_bounded_cert(len);
                    uint8_t t = blob[a];
                    blob[a] = blob[b];
                    blob[b] = t;
                }
            } else if (r < 36) {
                /* deep: regenerate content with same length */
                if (len) fill_rand(blob, len);
            } else if (r < 44) {
                /* deep: change length to another valid value and fill */
                uint32_t target = rand_bounded_cert(DTLS_MAX_CERT_BLOB_LEN + 1u);
                wr_u24(&c->cert_blob_len, target);
                len = target;
                if (len) fill_rand(blob, len);
            } else if (r < 50) {
                /* deep: force a consistent-looking prefix (DER-ish) */
                if (len < 16) {
                    uint32_t target = 64;
                    if (target > DTLS_MAX_CERT_BLOB_LEN) target = DTLS_MAX_CERT_BLOB_LEN;
                    wr_u24(&c->cert_blob_len, target);
                    len = target;
                    fill_rand(blob, len);
                }
                if (len >= 2) { blob[0] = 0x30; blob[1] = (uint8_t)((len > 2) ? (len - 2) : 0); }
            }
        }
    }
}


#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ===== minimal helpers / RNG ===== */
static uint32_t g_rng_crt = 0xC0FFEE11u;

static uint32_t rng32_crt(void) {
    uint32_t x = g_rng_crt;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_crt = x ? x : 0x9E3779B9u;
    return g_rng_crt;
}

static uint32_t rand_bounded_crt(uint32_t n) {
    if (n == 0) return 0;
    return rng32_crt() % n;
}

static uint8_t rand_u8_crt(void) { return (uint8_t)rng32_crt(); }

// static void fill_rand(uint8_t *p, uint32_t n) {
//     if (!p) return;
//     for (uint32_t i = 0; i < n; i++) p[i] = rand_u8_crt();
// }

// static void mem_rev(uint8_t *p, uint32_t n) {
//     if (!p) return;
//     for (uint32_t i = 0; i < n / 2; i++) {
//         uint8_t t = p[i];
//         p[i] = p[n - 1 - i];
//         p[n - 1 - i] = t;
//     }
// }

// static void mem_rotl(uint8_t *p, uint32_t n, uint32_t k) {
//     if (!p || n == 0) return;
//     k %= n;
//     if (k == 0) return;
//     uint8_t tmp[64];
//     if (k <= sizeof(tmp)) {
//         memcpy(tmp, p, k);
//         memmove(p, p + k, n - k);
//         memcpy(p + (n - k), tmp, k);
//     } else {
//         for (uint32_t t = 0; t < k; t++) {
//             uint8_t first = p[0];
//             memmove(p, p + 1, n - 1);
//             p[n - 1] = first;
//         }
//     }
// }

static void shuffle(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i + 1 < n; i++) {
        uint32_t j = i + rand_bounded_crt(n - i);
        uint8_t t = p[i];
        p[i] = p[j];
        p[j] = t;
    }
}

static int is_certreq_pkt(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 13; /* CertificateRequest */
}

static void clamp_cert_types_len(dtls_certificate_request_t *cr) {
    if (!cr) return;
    if (cr->cert_types_len > DTLS_MAX_CERT_TYPES_LEN) cr->cert_types_len = DTLS_MAX_CERT_TYPES_LEN;
}

/* CertificateRequest.cert_types is mandatory in the message format, but can be empty (len=0).
 * In this struct representation, presence is encoded by cert_types_len.
 * "add/delete/repeat" are no-ops to keep interfaces consistent.
 */
void add_certificate_request_cert_types(dtls_packet_t *pkts, size_t n) {
    (void)pkts; (void)n;
}

void delete_certificate_request_cert_types(dtls_packet_t *pkts, size_t n) {
    (void)pkts; (void)n;
}

void repeat_certificate_request_cert_types(dtls_packet_t *pkts, size_t n) {
    (void)pkts; (void)n;
}

void mutate_certificate_request_cert_types(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_crt ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x27D4EB2Du;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        clamp_cert_types_len(cr);

        uint8_t *types = cr->cert_types;
        uint32_t len = cr->cert_types_len;

        /* known TLS client_certificate_type values (RFC 5246 / TLS 1.2) */
        static const uint8_t known_types[] = {
            1,  /* rsa_sign */
            2,  /* dss_sign */
            3,  /* rsa_fixed_dh */
            4,  /* dss_fixed_dh */
            5,  /* rsa_ephemeral_dh */
            6,  /* dss_ephemeral_dh */
            20, /* tls_sign */
            64, /* ecdsa_sign */
            65, /* rsa_fixed_ecdh */
            66  /* ecdsa_fixed_ecdh */
        };

        uint32_t cat = rand_bounded_crt(8); /* A..H */

        switch (cat) {
        case 0: /* A. Canonical form */
            /* typical modern: only ecdsa_sign (64) or rsa_sign (1) */
            if (rand_bounded_crt(2) == 0) {
                cr->cert_types_len = 1;
                types[0] = 64;
            } else {
                cr->cert_types_len = 1;
                types[0] = 1;
            }
            len = cr->cert_types_len;
            break;

        case 1: /* B. Boundaries */
            switch (rand_bounded_crt(5)) {
            case 0: /* empty */
                cr->cert_types_len = 0;
                len = 0;
                break;
            case 1: /* 1 */
                cr->cert_types_len = 1;
                len = 1;
                types[0] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                break;
            case 2: /* 2 */
                cr->cert_types_len = 2;
                len = 2;
                types[0] = 1;
                types[1] = 64;
                break;
            case 3: /* max-1 */
                cr->cert_types_len = (DTLS_MAX_CERT_TYPES_LEN > 0) ? (uint8_t)(DTLS_MAX_CERT_TYPES_LEN - 1) : 0;
                len = cr->cert_types_len;
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }
                break;
            default: /* max */
                cr->cert_types_len = (uint8_t)DTLS_MAX_CERT_TYPES_LEN;
                len = cr->cert_types_len;
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }
                break;
            }
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* classes: all-known, only-legacy, only-ecdsa family, duplicates-heavy */
            {
                uint32_t mode = rand_bounded_crt(4);
                uint32_t target = 1u + rand_bounded_crt((DTLS_MAX_CERT_TYPES_LEN >= 6) ? 6u : (uint32_t)DTLS_MAX_CERT_TYPES_LEN);
                if (target > DTLS_MAX_CERT_TYPES_LEN) target = DTLS_MAX_CERT_TYPES_LEN;
                cr->cert_types_len = (uint8_t)target;
                len = target;

                if (mode == 0) {
                    for (uint32_t k = 0; k < len; k++) {
                        types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                    }
                } else if (mode == 1) {
                    /* legacy-ish: rsa_sign/dss_sign (1/2/3/4/5/6) */
                    static const uint8_t legacy[] = {1,2,3,4,5,6};
                    for (uint32_t k = 0; k < len; k++) {
                        types[k] = legacy[rand_bounded_crt((uint32_t)(sizeof(legacy) / sizeof(legacy[0])))];
                    }
                } else if (mode == 2) {
                    /* ecdsa-centric: 64 + fixed ecdh variants */
                    static const uint8_t ecdsa_set[] = {64,65,66};
                    for (uint32_t k = 0; k < len; k++) {
                        types[k] = ecdsa_set[rand_bounded_crt((uint32_t)(sizeof(ecdsa_set) / sizeof(ecdsa_set[0])))];
                    }
                } else {
                    /* duplicates-heavy: repeat one or two values */
                    uint8_t a = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                    uint8_t b = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                    for (uint32_t k = 0; k < len; k++) types[k] = (k & 1u) ? a : b;
                }
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* choose only enumerated known values (range is uint8) */
            {
                uint32_t target = rand_bounded_crt(DTLS_MAX_CERT_TYPES_LEN + 1u);
                cr->cert_types_len = (uint8_t)target;
                len = target;
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }
                /* optionally ensure includes a common one */
                if (len && rand_bounded_crt(100) < 60) {
                    types[rand_bounded_crt(len)] = (rand_bounded_crt(2) == 0) ? 1 : 64;
                }
            }
            break;

        case 4: /* E. Encoding-shape variant */
            /* keep len but change order/shape: reverse, rotate, shuffle, nibble swap */
            if (len == 0) {
                cr->cert_types_len = 4;
                len = 4;
                types[0] = 1; types[1] = 64; types[2] = 2; types[3] = 66;
            }
            switch (rand_bounded_crt(4)) {
            case 0: mem_rev(types, len); break;
            case 1: mem_rotl(types, len, 1u + rand_bounded_crt((len > 1) ? (len - 1) : 1)); break;
            case 2: shuffle(types, len); break;
            default:
                for (uint32_t k = 0; k < len; k++) types[k] = (uint8_t)((types[k] << 4) | (types[k] >> 4));
                break;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* align length to 2/4/8 within bounds; pad with a repeated last value */
            {
                if (len == 0) {
                    cr->cert_types_len = 1;
                    len = 1;
                    types[0] = 64;
                }
                uint32_t align = (rand_bounded_crt(3) == 0) ? 2u : ((rand_bounded_crt(2) == 0) ? 4u : 8u);
                uint32_t target = len;

                if (rand_bounded_crt(2) == 0) {
                    uint32_t r = target % align;
                    if (r) target += (align - r);
                } else {
                    target -= (target % align);
                    if (target == 0) target = align;
                }

                if (target > DTLS_MAX_CERT_TYPES_LEN) target = DTLS_MAX_CERT_TYPES_LEN;
                if (target < len) {
                    cr->cert_types_len = (uint8_t)target;
                    len = target;
                } else if (target > len) {
                    uint8_t pad = types[len - 1];
                    for (uint32_t k = len; k < target; k++) types[k] = pad;
                    cr->cert_types_len = (uint8_t)target;
                    len = target;
                } else {
                    /* same: tweak last */
                    types[len - 1] ^= 0x01u;
                }
            }
            break;

        case 6: /* G. In-range sweep */
            /* sweep over known_types deterministically based on packet index */
            {
                uint32_t target = 1u + (uint32_t)(i % DTLS_MAX_CERT_TYPES_LEN);
                if (target > DTLS_MAX_CERT_TYPES_LEN) target = DTLS_MAX_CERT_TYPES_LEN;
                cr->cert_types_len = (uint8_t)target;
                len = target;
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[(k + (uint32_t)i) % (uint32_t)(sizeof(known_types) / sizeof(known_types[0]))];
                }
            }
            break;

        case 7: /* H. Random valid mix */
        default:
            {
                uint32_t r = rand_bounded_crt(100);
                uint32_t target;
                if (r < 10) target = 0;
                else if (r < 50) target = 1u + rand_bounded_crt(4u);
                else if (r < 85) target = 4u + rand_bounded_crt(8u);
                else target = DTLS_MAX_CERT_TYPES_LEN;

                if (target > DTLS_MAX_CERT_TYPES_LEN) target = DTLS_MAX_CERT_TYPES_LEN;
                cr->cert_types_len = (uint8_t)target;
                len = target;

                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }

                if (len && rand_bounded_crt(100) < 40) {
                    /* make first element a common anchor */
                    types[0] = (rand_bounded_crt(2) == 0) ? 1 : 64;
                }
            }
            break;
        }

        /* randomized perturbations: shallow + deep */
        clamp_cert_types_len(cr);
        len = cr->cert_types_len;

        {
            uint32_t r = rand_bounded_crt(100);

            if (r < 18) {
                /* shallow: flip a bit in one entry */
                if (len) {
                    uint32_t pos = rand_bounded_crt(len);
                    types[pos] ^= (uint8_t)(1u << rand_bounded_crt(8));
                }
            } else if (r < 28) {
                /* shallow: swap two entries */
                if (len > 1) {
                    uint32_t a = rand_bounded_crt(len);
                    uint32_t b = rand_bounded_crt(len);
                    uint8_t t = types[a];
                    types[a] = types[b];
                    types[b] = t;
                }
            } else if (r < 38) {
                /* deep: regenerate values (still within known set) */
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }
            } else if (r < 46) {
                /* deep: change length to another valid size and fill */
                uint32_t target = rand_bounded_crt(DTLS_MAX_CERT_TYPES_LEN + 1u);
                cr->cert_types_len = (uint8_t)target;
                len = target;
                for (uint32_t k = 0; k < len; k++) {
                    types[k] = known_types[rand_bounded_crt((uint32_t)(sizeof(known_types) / sizeof(known_types[0])))];
                }
            } else if (r < 52) {
                /* deep: force a compact canonical set but keep diversity in tail */
                if (DTLS_MAX_CERT_TYPES_LEN >= 3) {
                    cr->cert_types_len = 3;
                    len = 3;
                    types[0] = 1;
                    types[1] = 64;
                    types[2] = 66;
                } else if (DTLS_MAX_CERT_TYPES_LEN >= 2) {
                    cr->cert_types_len = 2;
                    len = 2;
                    types[0] = 1;
                    types[1] = 64;
                } else {
                    cr->cert_types_len = 1;
                    len = 1;
                    types[0] = 64;
                }
            }
        }
    }
}


/* ===== minimal helpers / RNG ===== */
static uint32_t g_rng_sig = 0xA5A5A5A5u;

static uint32_t rng32_sig(void) {
    uint32_t x = g_rng_sig;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_sig = x ? x : 0x9E3779B9u;
    return g_rng_sig;
}

static uint32_t rand_bounded_sig(uint32_t n) {
    if (n == 0) return 0;
    return rng32_sig() % n;
}

static uint8_t rand_u8_sig(void) { return (uint8_t)rng32_sig(); }

static void mem_rev_sig(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }
}

static void shuffle_sig(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i + 1 < n; i++) {
        uint32_t j = i + rand_bounded_sig(n - i);
        uint8_t t = p[i];
        p[i] = p[j];
        p[j] = t;
    }
}

static void rotate_pairs_left(uint8_t *p, uint32_t n_bytes, uint32_t pairs_k) {
    if (!p || n_bytes < 2) return;
    uint32_t pairs = n_bytes / 2;
    if (pairs == 0) return;
    pairs_k %= pairs;
    if (pairs_k == 0) return;

    /* rotate by pairs (2 bytes each) */
    uint8_t tmp[64];
    uint32_t kbytes = pairs_k * 2;
    if (kbytes <= sizeof(tmp)) {
        memcpy(tmp, p, kbytes);
        memmove(p, p + kbytes, n_bytes - kbytes);
        memcpy(p + (n_bytes - kbytes), tmp, kbytes);
    } else {
        for (uint32_t t = 0; t < pairs_k; t++) {
            uint8_t a0 = p[0], a1 = p[1];
            memmove(p, p + 2, n_bytes - 2);
            p[n_bytes - 2] = a0;
            p[n_bytes - 1] = a1;
        }
    }
}

static int is_certreq_pkt_sig(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 13; /* CertificateRequest */
}

static void clamp_sig_algs_len(dtls_certificate_request_t *cr) {
    if (!cr) return;
    if (cr->sig_algs_len > DTLS_MAX_SIG_ALGS_LEN) cr->sig_algs_len = DTLS_MAX_SIG_ALGS_LEN;
    /* must be even number of bytes (pairs) */
    cr->sig_algs_len &= (uint16_t)~1u;
}

/* ----- SignatureAndHashAlgorithm pairs (TLS 1.2) ----- */
/* HashAlgorithm (1 byte): 1=md5,2=sha1,3=sha224,4=sha256,5=sha384,6=sha512
 * SignatureAlgorithm (1 byte): 1=rsa,2=dsa,3=ecdsa
 */
static const uint8_t k_pairs_all[][2] = {
    {4, 1}, /* sha256,rsa */
    {4, 3}, /* sha256,ecdsa */
    {5, 1}, /* sha384,rsa */
    {5, 3}, /* sha384,ecdsa */
    {6, 1}, /* sha512,rsa */
    {6, 3}, /* sha512,ecdsa */
    {2, 1}, /* sha1,rsa */
    {2, 3}, /* sha1,ecdsa */
    {3, 1}, /* sha224,rsa */
    {3, 3}, /* sha224,ecdsa */
    {4, 2}, /* sha256,dsa */
    {2, 2}, /* sha1,dsa */
};

static const uint8_t k_pairs_modern[][2] = {
    {4, 1}, /* sha256,rsa */
    {4, 3}, /* sha256,ecdsa */
    {5, 1}, /* sha384,rsa */
    {5, 3}, /* sha384,ecdsa */
    {6, 1}, /* sha512,rsa */
    {6, 3}, /* sha512,ecdsa */
};

static const uint8_t k_pairs_legacy[][2] = {
    {2, 1}, /* sha1,rsa */
    {2, 3}, /* sha1,ecdsa */
    {2, 2}, /* sha1,dsa */
};

static void write_pair(uint8_t *dst, uint8_t h, uint8_t s) {
    dst[0] = h;
    dst[1] = s;
}

static void fill_pairs_from_set(uint8_t *dst, uint32_t pairs,
                                const uint8_t (*set)[2], uint32_t set_n) {
    for (uint32_t i = 0; i < pairs; i++) {
        uint32_t idx = rand_bounded_sig(set_n);
        write_pair(dst + 2 * i, set[idx][0], set[idx][1]);
    }
}

static void ensure_even_nonzero(dtls_certificate_request_t *cr, uint32_t min_pairs) {
    if (!cr) return;
    uint32_t min_bytes = min_pairs * 2;
    if (min_bytes > DTLS_MAX_SIG_ALGS_LEN) min_bytes = DTLS_MAX_SIG_ALGS_LEN & ~1u;
    if (cr->sig_algs_len < min_bytes) cr->sig_algs_len = (uint16_t)min_bytes;
    clamp_sig_algs_len(cr);
}

/* SignatureAlgorithms extension field is part of CertificateRequest in TLS 1.2 and is mandatory in the syntax.
 * In this struct representation, presence is encoded by sig_algs_len. Keep add/delete/repeat as no-ops.
 */


void mutate_certificate_request_sig_algs(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_sig ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x85EBCA6Bu;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt_sig(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        clamp_sig_algs_len(cr);

        uint8_t *buf = cr->sig_algs;
        uint32_t len = cr->sig_algs_len;     /* bytes, even */
        uint32_t pairs = len / 2;

        uint32_t cat = rand_bounded_sig(8); /* A..H */

        switch (cat) {
        case 0: /* A. Canonical form */
            /* common minimal set: (sha256,rsa) + (sha256,ecdsa) */
            cr->sig_algs_len = 4;
            write_pair(buf + 0, 4, 1);
            write_pair(buf + 2, 4, 3);
            break;

        case 1: /* B. Boundaries */
            switch (rand_bounded_sig(5)) {
            case 0: /* empty list allowed by length=0 in some stacks */
                cr->sig_algs_len = 0;
                break;
            case 1: /* 1 pair */
                cr->sig_algs_len = 2;
                fill_pairs_from_set(buf, 1, k_pairs_modern, (uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])));
                break;
            case 2: /* 2 pairs */
                cr->sig_algs_len = 4;
                fill_pairs_from_set(buf, 2, k_pairs_modern, (uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])));
                break;
            case 3: /* max-2 bytes */
                cr->sig_algs_len = (uint16_t)((DTLS_MAX_SIG_ALGS_LEN >= 2) ? (DTLS_MAX_SIG_ALGS_LEN - 2) : 0);
                clamp_sig_algs_len(cr);
                fill_pairs_from_set(buf, (uint32_t)cr->sig_algs_len / 2, k_pairs_all,
                                    (uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])));
                break;
            default: /* max */
                cr->sig_algs_len = (uint16_t)(DTLS_MAX_SIG_ALGS_LEN & ~1u);
                clamp_sig_algs_len(cr);
                fill_pairs_from_set(buf, (uint32_t)cr->sig_algs_len / 2, k_pairs_all,
                                    (uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])));
                break;
            }
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* classes: modern-only, legacy-only, RSA-heavy, ECDSA-heavy, duplicates-heavy */
            {
                uint32_t mode = rand_bounded_sig(5);
                uint32_t target_pairs = 1u + rand_bounded_sig((DTLS_MAX_SIG_ALGS_LEN / 2u) ? (DTLS_MAX_SIG_ALGS_LEN / 2u) : 1u);
                if (target_pairs * 2u > DTLS_MAX_SIG_ALGS_LEN) target_pairs = DTLS_MAX_SIG_ALGS_LEN / 2u;

                cr->sig_algs_len = (uint16_t)(target_pairs * 2u);
                clamp_sig_algs_len(cr);

                if (mode == 0) {
                    fill_pairs_from_set(buf, target_pairs, k_pairs_modern,
                                        (uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])));
                } else if (mode == 1) {
                    fill_pairs_from_set(buf, target_pairs, k_pairs_legacy,
                                        (uint32_t)(sizeof(k_pairs_legacy)/sizeof(k_pairs_legacy[0])));
                } else if (mode == 2) {
                    /* RSA-heavy */
                    for (uint32_t k = 0; k < target_pairs; k++) {
                        uint8_t h = k_pairs_modern[rand_bounded_sig((uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])))][0];
                        write_pair(buf + 2 * k, h, 1);
                    }
                } else if (mode == 3) {
                    /* ECDSA-heavy */
                    for (uint32_t k = 0; k < target_pairs; k++) {
                        uint8_t h = k_pairs_modern[rand_bounded_sig((uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])))][0];
                        write_pair(buf + 2 * k, h, 3);
                    }
                } else {
                    /* duplicates-heavy */
                    uint8_t h = k_pairs_all[rand_bounded_sig((uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])))][0];
                    uint8_t s = k_pairs_all[rand_bounded_sig((uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])))][1];
                    for (uint32_t k = 0; k < target_pairs; k++) write_pair(buf + 2 * k, h, s);
                }
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* keep within defined ranges for TLS 1.2 (hash 1..6, sig 1..3) */
            {
                uint32_t target_pairs = rand_bounded_sig((DTLS_MAX_SIG_ALGS_LEN / 2u) + 1u);
                cr->sig_algs_len = (uint16_t)(target_pairs * 2u);
                clamp_sig_algs_len(cr);
                target_pairs = (uint32_t)cr->sig_algs_len / 2u;

                for (uint32_t k = 0; k < target_pairs; k++) {
                    uint8_t hash = (uint8_t)(1u + rand_bounded_sig(6u)); /* 1..6 */
                    uint8_t sig  = (uint8_t)(1u + rand_bounded_sig(3u)); /* 1..3 */
                    write_pair(buf + 2 * k, hash, sig);
                }

                /* optionally pin a common pair */
                if (target_pairs && rand_bounded_sig(100) < 55) {
                    uint32_t pos = rand_bounded_sig(target_pairs);
                    write_pair(buf + 2 * pos, 4, (rand_bounded_sig(2) == 0) ? 1 : 3);
                }
            }
            break;

        case 4: /* E. Encoding-shape variant */
            /* preserve content but alter ordering/shape: reverse bytes, rotate pairs, shuffle pairs */
            if (len == 0) {
                cr->sig_algs_len = 6;
                write_pair(buf + 0, 4, 1);
                write_pair(buf + 2, 4, 3);
                write_pair(buf + 4, 5, 1);
            }
            clamp_sig_algs_len(cr);
            len = cr->sig_algs_len;
            pairs = len / 2;

            switch (rand_bounded_sig(4)) {
            case 0:
                mem_rev_sig(buf, len); /* byte-level reverse */
                break;
            case 1:
                rotate_pairs_left(buf, len, 1u + rand_bounded_sig((pairs > 1) ? (pairs - 1) : 1u));
                break;
            case 2:
                /* shuffle by pairs */
                for (uint32_t k = 0; k + 1 < pairs; k++) {
                    uint32_t j = k + rand_bounded_sig(pairs - k);
                    uint8_t a0 = buf[2 * k + 0], a1 = buf[2 * k + 1];
                    buf[2 * k + 0] = buf[2 * j + 0];
                    buf[2 * k + 1] = buf[2 * j + 1];
                    buf[2 * j + 0] = a0;
                    buf[2 * j + 1] = a1;
                }
                break;
            default:
                /* nibble swap each byte (still in-range sometimes) */
                for (uint32_t b = 0; b < len; b++) buf[b] = (uint8_t)((buf[b] << 4) | (buf[b] >> 4));
                break;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* force length aligned to 4/8/16 bytes within max; pad by repeating last pair */
            {
                ensure_even_nonzero(cr, 1);
                clamp_sig_algs_len(cr);
                len = cr->sig_algs_len;

                uint32_t align = (rand_bounded_sig(3) == 0) ? 4u : ((rand_bounded_sig(2) == 0) ? 8u : 16u);
                uint32_t target = len;

                if (rand_bounded_sig(2) == 0) {
                    uint32_t r = target % align;
                    if (r) target += (align - r);
                } else {
                    target -= (target % align);
                    if (target == 0) target = align;
                }

                if (target > (uint32_t)(DTLS_MAX_SIG_ALGS_LEN & ~1u)) target = (uint32_t)(DTLS_MAX_SIG_ALGS_LEN & ~1u);
                target &= ~1u;

                if (target < len) {
                    cr->sig_algs_len = (uint16_t)target;
                } else if (target > len) {
                    uint8_t last_h = buf[len - 2];
                    uint8_t last_s = buf[len - 1];
                    for (uint32_t off = len; off + 1 < target; off += 2) {
                        buf[off + 0] = last_h;
                        buf[off + 1] = last_s;
                    }
                    cr->sig_algs_len = (uint16_t)target;
                } else {
                    /* same: tweak last hash within range */
                    uint8_t h = buf[len - 2];
                    h = (uint8_t)(1u + ((uint32_t)h % 6u)); /* normalize */
                    buf[len - 2] = (uint8_t)((h % 6u) + 1u);
                }
                clamp_sig_algs_len(cr);
            }
            break;

        case 6: /* G. In-range sweep */
            /* sweep over (hash 1..6) x (sig 1..3) pairs in deterministic progression */
            {
                uint32_t max_pairs = DTLS_MAX_SIG_ALGS_LEN / 2u;
                uint32_t target_pairs = 1u + (uint32_t)(i % (max_pairs ? max_pairs : 1u));
                if (target_pairs * 2u > DTLS_MAX_SIG_ALGS_LEN) target_pairs = DTLS_MAX_SIG_ALGS_LEN / 2u;
                cr->sig_algs_len = (uint16_t)(target_pairs * 2u);
                clamp_sig_algs_len(cr);
                target_pairs = (uint32_t)cr->sig_algs_len / 2u;

                uint32_t base = (uint32_t)i;
                for (uint32_t k = 0; k < target_pairs; k++) {
                    uint32_t t = base + k;
                    uint8_t hash = (uint8_t)(1u + (t % 6u));
                    uint8_t sig  = (uint8_t)(1u + ((t / 6u) % 3u));
                    write_pair(buf + 2 * k, hash, sig);
                }
            }
            break;

        case 7: /* H. Random valid mix */
        default:
            {
                uint32_t r = rand_bounded_sig(100);
                uint32_t target_pairs;
                if (r < 10) target_pairs = 0;
                else if (r < 55) target_pairs = 1u + rand_bounded_sig(4u);
                else if (r < 85) target_pairs = 3u + rand_bounded_sig(10u);
                else target_pairs = DTLS_MAX_SIG_ALGS_LEN / 2u;

                if (target_pairs * 2u > DTLS_MAX_SIG_ALGS_LEN) target_pairs = DTLS_MAX_SIG_ALGS_LEN / 2u;
                cr->sig_algs_len = (uint16_t)(target_pairs * 2u);
                clamp_sig_algs_len(cr);
                target_pairs = (uint32_t)cr->sig_algs_len / 2u;

                /* mix modern + legacy + full set */
                for (uint32_t k = 0; k < target_pairs; k++) {
                    uint32_t sel = rand_bounded_sig(100);
                    if (sel < 60) {
                        uint32_t idx = rand_bounded_sig((uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])));
                        write_pair(buf + 2 * k, k_pairs_modern[idx][0], k_pairs_modern[idx][1]);
                    } else if (sel < 80) {
                        uint32_t idx = rand_bounded_sig((uint32_t)(sizeof(k_pairs_legacy)/sizeof(k_pairs_legacy[0])));
                        write_pair(buf + 2 * k, k_pairs_legacy[idx][0], k_pairs_legacy[idx][1]);
                    } else {
                        uint32_t idx = rand_bounded_sig((uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])));
                        write_pair(buf + 2 * k, k_pairs_all[idx][0], k_pairs_all[idx][1]);
                    }
                }

                if (target_pairs && rand_bounded_sig(100) < 35) {
                    /* anchor first as sha256,rsa */
                    write_pair(buf + 0, 4, 1);
                }
            }
            break;
        }

        /* randomized perturbations: shallow + deep (try to remain plausible) */
        clamp_sig_algs_len(cr);
        len = cr->sig_algs_len;
        pairs = len / 2;

        {
            uint32_t rr = rand_bounded_sig(100);

            if (rr < 18) {
                /* shallow: tweak one pair's hash within 1..6 */
                if (pairs) {
                    uint32_t pos = rand_bounded_sig(pairs);
                    uint8_t h = buf[2 * pos + 0];
                    h = (uint8_t)(1u + ((uint32_t)h % 6u));
                    buf[2 * pos + 0] = (uint8_t)(1u + ((uint32_t)h + rand_bounded_sig(6u)) % 6u);
                }
            } else if (rr < 28) {
                /* shallow: swap two pairs */
                if (pairs > 1) {
                    uint32_t a = rand_bounded_sig(pairs);
                    uint32_t b = rand_bounded_sig(pairs);
                    uint8_t a0 = buf[2 * a + 0], a1 = buf[2 * a + 1];
                    buf[2 * a + 0] = buf[2 * b + 0];
                    buf[2 * a + 1] = buf[2 * b + 1];
                    buf[2 * b + 0] = a0;
                    buf[2 * b + 1] = a1;
                }
            } else if (rr < 40) {
                /* deep: regenerate all from full set */
                for (uint32_t k = 0; k < pairs; k++) {
                    uint32_t idx = rand_bounded_sig((uint32_t)(sizeof(k_pairs_all)/sizeof(k_pairs_all[0])));
                    write_pair(buf + 2 * k, k_pairs_all[idx][0], k_pairs_all[idx][1]);
                }
            } else if (rr < 48) {
                /* deep: change length and fill */
                uint32_t target_pairs = rand_bounded_sig((DTLS_MAX_SIG_ALGS_LEN / 2u) + 1u);
                cr->sig_algs_len = (uint16_t)(target_pairs * 2u);
                clamp_sig_algs_len(cr);
                pairs = (uint32_t)cr->sig_algs_len / 2u;
                for (uint32_t k = 0; k < pairs; k++) {
                    uint32_t idx = rand_bounded_sig((uint32_t)(sizeof(k_pairs_modern)/sizeof(k_pairs_modern[0])));
                    write_pair(buf + 2 * k, k_pairs_modern[idx][0], k_pairs_modern[idx][1]);
                }
            } else if (rr < 55) {
                /* deep: force a compact canonical triple */
                if (DTLS_MAX_SIG_ALGS_LEN >= 6) {
                    cr->sig_algs_len = 6;
                    write_pair(buf + 0, 4, 1); /* sha256,rsa */
                    write_pair(buf + 2, 4, 3); /* sha256,ecdsa */
                    write_pair(buf + 4, 5, 1); /* sha384,rsa */
                } else {
                    cr->sig_algs_len = 4;
                    write_pair(buf + 0, 4, 1);
                    write_pair(buf + 2, 4, 3);
                }
                clamp_sig_algs_len(cr);
            } else if (rr < 60) {
                /* shallow: flip a random bit in a random byte */
                if (len) {
                    uint32_t b = rand_bounded_sig(len);
                    buf[b] ^= (uint8_t)(1u << rand_bounded_sig(8));
                }
            }
        }
    }
}



/* ===== minimal helpers / RNG ===== */
static uint32_t g_rng_dn = 0xC0FFEE01u;

static uint32_t rng32_dn(void) {
    uint32_t x = g_rng_dn;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_dn = x ? x : 0x9E3779B9u;
    return g_rng_dn;
}

static uint32_t rand_bounded_dn(uint32_t n) {
    if (n == 0) return 0;
    return rng32_dn() % n;
}

static uint8_t rand_u8_dn(void) { return (uint8_t)rng32_dn(); }

static uint16_t rd_be16_dn(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void wr_be16_dn(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void mem_rev_dn(uint8_t *p, uint32_t n) {
    if (!p) return;
    for (uint32_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }
}

static void xor_range_dn(uint8_t *p, uint32_t n, uint8_t m) {
    if (!p) return;
    for (uint32_t i = 0; i < n; i++) p[i] ^= m;
}

static int is_certreq_pkt_dn(const dtls_packet_t *p) {
    return p &&
           p->kind == DTLS_PKT_HANDSHAKE &&
           p->payload.handshake.handshake_header.msg_type == 13; /* CertificateRequest */
}

static void clamp_ca_dn_len(dtls_certificate_request_t *cr) {
    if (!cr) return;
    if (cr->ca_dn_len > DTLS_MAX_CA_DN_LEN) cr->ca_dn_len = DTLS_MAX_CA_DN_LEN;
}

/* DN list encoding: opaque DistinguishedName<0..2^16-1> and
 * DistinguishedName is opaque<1..2^16-1>, in a length-prefixed list:
 *   2 bytes: dn_list_length
 *   repeated:
 *     2 bytes: dn_length
 *     dn_bytes[dn_length]
 *
 * In this struct, ca_dn_len is the dn_list_length and ca_dn_blob holds the list bytes.
 */

/* ===== canonical DN entries (DER-ish blobs, but treated as opaque) ===== */
static const uint8_t k_dn_empty[] = { /* empty list */ };

static const uint8_t k_dn_der_like_1[] = {
    0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03
}; /* not necessarily valid DER; opaque seed */

static const uint8_t k_dn_der_like_2[] = {
    0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x04, 'T', 'E'
};

static const uint8_t k_dn_ascii_1[] = "CN=Test CA";
static const uint8_t k_dn_ascii_2[] = "O=Example Org, CN=Root";

/* build a single DN entry into out (prefix len + bytes), return bytes written, 0 on fail */
static uint32_t emit_one_dn(uint8_t *out, uint32_t out_cap, const uint8_t *dn, uint16_t dn_len) {
    if (!out || out_cap < (uint32_t)dn_len + 2u) return 0;
    wr_be16_dn(out, dn_len);
    if (dn_len) memcpy(out + 2, dn, dn_len);
    return (uint32_t)dn_len + 2u;
}

/* parse dn_list (cr->ca_dn_blob with length cr->ca_dn_len) and return count of entries
 * (best-effort; stops on inconsistent length). */
static uint32_t count_dn_entries(const uint8_t *list, uint32_t list_len) {
    uint32_t off = 0, cnt = 0;
    while (off + 2 <= list_len) {
        uint16_t l = rd_be16_dn(list + off);
        off += 2;
        if (l == 0) break; /* 0-length DN is nonsensical; treat as terminator */
        if (off + l > list_len) break;
        off += l;
        cnt++;
    }
    return cnt;
}

/* write a list of DNs from an array of (ptr,len) into cr, respecting DTLS_MAX_CA_DN_LEN */
typedef struct { const uint8_t *p; uint16_t n; } dn_ref_t;

static void write_dn_list(dtls_certificate_request_t *cr, const dn_ref_t *dns, uint32_t dn_cnt) {
    if (!cr) return;
    uint8_t *dst = cr->ca_dn_blob;
    uint32_t cap = DTLS_MAX_CA_DN_LEN;
    uint32_t off = 0;

    for (uint32_t i = 0; i < dn_cnt; i++) {
        uint32_t w = emit_one_dn(dst + off, cap - off, dns[i].p, dns[i].n);
        if (w == 0) break;
        off += w;
    }
    cr->ca_dn_len = (uint16_t)off;
    clamp_ca_dn_len(cr);
}

/* optionality: in the syntax, ca_dn_len can be 0 (empty DN list), so implement add/delete as toggles */
void add_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    g_rng_dn ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x27D4EB2Du;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt_dn(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        if (cr->ca_dn_len != 0) continue;

        dn_ref_t dns[2];
        dns[0].p = k_dn_ascii_1; dns[0].n = (uint16_t)(sizeof(k_dn_ascii_1) - 1);
        dns[1].p = k_dn_der_like_1; dns[1].n = (uint16_t)sizeof(k_dn_der_like_1);
        write_dn_list(cr, dns, 2);
    }
}

void delete_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt_dn(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        cr->ca_dn_len = 0;
        /* keep blob bytes as-is; length controls presence */
    }
}

void repeat_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;
    g_rng_dn ^= 0xBADC0DEu ^ (uint32_t)n;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt_dn(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        clamp_ca_dn_len(cr);
        uint32_t len = cr->ca_dn_len;
        if (len == 0) continue;

        /* If there is room, duplicate the whole list once (concatenate list with itself)
           while keeping inner encoding intact (length-prefixed DNs). */
        uint32_t room = DTLS_MAX_CA_DN_LEN - len;
        if (room < len) continue;

        memcpy(cr->ca_dn_blob + len, cr->ca_dn_blob, len);
        cr->ca_dn_len = (uint16_t)(len * 2u);
        clamp_ca_dn_len(cr);
    }
}

void mutate_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    g_rng_dn ^= (uint32_t)(uintptr_t)pkts ^ (uint32_t)n * 0x9E3779B9u;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (!is_certreq_pkt_dn(p)) continue;

        dtls_certificate_request_t *cr = &p->payload.handshake.body.certificate_request;
        clamp_ca_dn_len(cr);

        uint8_t *buf = cr->ca_dn_blob;
        uint32_t len = cr->ca_dn_len; /* bytes of dn_list */
        uint32_t cat = rand_bounded_dn(8); /* A..H */

        switch (cat) {
        case 0: /* A. Canonical form */
            /* empty list is canonical-simple for many stacks */
            cr->ca_dn_len = 0;
            break;

        case 1: /* B. Boundaries */
            {
                uint32_t mode = rand_bounded_dn(5);
                if (mode == 0) {
                    cr->ca_dn_len = 0;
                } else if (mode == 1) {
                    dn_ref_t dns[1] = {{ k_dn_ascii_1, (uint16_t)(sizeof(k_dn_ascii_1) - 1) }};
                    write_dn_list(cr, dns, 1);
                } else if (mode == 2) {
                    dn_ref_t dns[1] = {{ k_dn_der_like_2, (uint16_t)sizeof(k_dn_der_like_2) }};
                    write_dn_list(cr, dns, 1);
                } else if (mode == 3) {
                    /* near-max: fill with many small DNs */
                    uint32_t off = 0;
                    while (off + 4 <= DTLS_MAX_CA_DN_LEN) { /* need at least 2+2 bytes */
                        uint16_t dn_l = (uint16_t)(1u + rand_bounded_dn(12u)); /* 1..12 */
                        if (off + 2u + dn_l > DTLS_MAX_CA_DN_LEN) break;
                        wr_be16_dn(buf + off, dn_l);
                        for (uint16_t k = 0; k < dn_l; k++) buf[off + 2 + k] = (uint8_t)('A' + (k % 26));
                        off += 2u + dn_l;
                    }
                    cr->ca_dn_len = (uint16_t)off;
                    clamp_ca_dn_len(cr);
                } else {
                    /* exact max: random bytes with self-consistent lengths using 1-byte DNs */
                    uint32_t off = 0;
                    while (off + 3u <= DTLS_MAX_CA_DN_LEN) {
                        uint16_t dn_l = 1;
                        if (off + 2u + dn_l > DTLS_MAX_CA_DN_LEN) break;
                        wr_be16_dn(buf + off, dn_l);
                        buf[off + 2] = rand_u8_dn();
                        off += 3u;
                    }
                    cr->ca_dn_len = (uint16_t)off;
                    clamp_ca_dn_len(cr);
                }
            }
            break;

        case 2: /* C. Equivalence-class alternatives */
            /* same meaning class: empty vs single ascii vs single der-like vs mixed */
            {
                uint32_t mode = rand_bounded_dn(4);
                if (mode == 0) {
                    cr->ca_dn_len = 0;
                } else if (mode == 1) {
                    dn_ref_t dns[1] = {{ k_dn_ascii_2, (uint16_t)(sizeof(k_dn_ascii_2) - 1) }};
                    write_dn_list(cr, dns, 1);
                } else if (mode == 2) {
                    dn_ref_t dns[1] = {{ k_dn_der_like_1, (uint16_t)sizeof(k_dn_der_like_1) }};
                    write_dn_list(cr, dns, 1);
                } else {
                    dn_ref_t dns[3];
                    dns[0].p = k_dn_ascii_1;    dns[0].n = (uint16_t)(sizeof(k_dn_ascii_1) - 1);
                    dns[1].p = k_dn_der_like_2; dns[1].n = (uint16_t)sizeof(k_dn_der_like_2);
                    dns[2].p = k_dn_ascii_2;    dns[2].n = (uint16_t)(sizeof(k_dn_ascii_2) - 1);
                    write_dn_list(cr, dns, 3);
                }
            }
            break;

        case 3: /* D. Allowed bitfield/enum/range */
            /* For this field, the main constraints are: ca_dn_len is 0..2^16-1 and inner dn_length are 1..2^16-1.
               Keep lengths consistent and within buffer bounds. */
            {
                uint32_t target_entries = rand_bounded_dn(8); /* 0..7 entries */
                uint32_t off = 0;

                for (uint32_t e = 0; e < target_entries; e++) {
                    uint16_t dn_l;
                    if (rand_bounded_dn(100) < 70) dn_l = (uint16_t)(1u + rand_bounded_dn(32u)); /* 1..32 */
                    else dn_l = (uint16_t)(1u + rand_bounded_dn(128u)); /* 1..128 */
                    if (off + 2u + dn_l > DTLS_MAX_CA_DN_LEN) break;
                    wr_be16_dn(buf + off, dn_l);
                    for (uint16_t k = 0; k < dn_l; k++) buf[off + 2 + k] = rand_u8_dn();
                    off += 2u + dn_l;
                }

                cr->ca_dn_len = (uint16_t)off;
                clamp_ca_dn_len(cr);
            }
            break;

        case 4: /* E. Encoding-shape variant */
            /* keep content but transform shape: reorder DNs, reverse list bytes, flip endianness on some len fields */
            if (len == 0) {
                dn_ref_t dns[2] = {
                    { k_dn_ascii_1, (uint16_t)(sizeof(k_dn_ascii_1) - 1) },
                    { k_dn_ascii_2, (uint16_t)(sizeof(k_dn_ascii_2) - 1) },
                };
                write_dn_list(cr, dns, 2);
                len = cr->ca_dn_len;
            }
            clamp_ca_dn_len(cr);
            buf = cr->ca_dn_blob;
            len = cr->ca_dn_len;

            switch (rand_bounded_dn(4)) {
            case 0:
                mem_rev_dn(buf, len);
                break;
            case 1:
                /* XOR mask (keeps structure size but changes bytes) */
                xor_range_dn(buf, len, (uint8_t)(1u << rand_bounded_dn(8)));
                break;
            case 2:
                /* swap a couple of dn_length fields' byte order (shape variant) */
                {
                    uint32_t off = 0;
                    uint32_t swaps = 1u + rand_bounded_dn(3u);
                    while (off + 2 <= len && swaps) {
                        uint16_t l = rd_be16_dn(buf + off);
                        /* flip endianness in-place */
                        uint8_t t = buf[off];
                        buf[off] = buf[off + 1];
                        buf[off + 1] = t;
                        off += 2;
                        if (off + l > len) break;
                        off += l;
                        swaps--;
                    }
                }
                break;
            default:
                /* reorder by moving first DN to end (if parseable) */
                {
                    uint32_t off = 0;
                    if (off + 2 <= len) {
                        uint16_t l = rd_be16_dn(buf + off);
                        uint32_t dn_bytes = 2u + (uint32_t)l;
                        if (l != 0 && dn_bytes <= len) {
                            uint8_t tmp[512];
                            if (dn_bytes <= sizeof(tmp)) {
                                memcpy(tmp, buf, dn_bytes);
                                memmove(buf, buf + dn_bytes, len - dn_bytes);
                                memcpy(buf + (len - dn_bytes), tmp, dn_bytes);
                            }
                        }
                    }
                }
                break;
            }
            break;

        case 5: /* F. Padding/alignment */
            /* Align total ca_dn_len to 4/8/16 by appending a DN with repeated bytes. */
            {
                uint32_t align = (rand_bounded_dn(3) == 0) ? 4u : ((rand_bounded_dn(2) == 0) ? 8u : 16u);

                if (len == 0) {
                    dn_ref_t dns[1] = {{ k_dn_ascii_1, (uint16_t)(sizeof(k_dn_ascii_1) - 1) }};
                    write_dn_list(cr, dns, 1);
                    len = cr->ca_dn_len;
                }

                uint32_t target = len;
                uint32_t r = target % align;
                if (r) target += (align - r);

                if (target > DTLS_MAX_CA_DN_LEN) target = DTLS_MAX_CA_DN_LEN;
                if (target < len) target = len;

                if (target > len) {
                    uint32_t pad = target - len;
                    /* append one DN whose length exactly fits (needs 2-byte header) */
                    if (pad >= 3u) {
                        uint16_t dn_l = (uint16_t)(pad - 2u);
                        if (dn_l == 0) dn_l = 1;
                        if (len + 2u + (uint32_t)dn_l <= DTLS_MAX_CA_DN_LEN) {
                            wr_be16_dn(buf + len, dn_l);
                            for (uint16_t k = 0; k < dn_l; k++) buf[len + 2 + k] = (uint8_t)0x50; /* 'P' */
                            cr->ca_dn_len = (uint16_t)(len + 2u + (uint32_t)dn_l);
                        }
                    }
                }
                clamp_ca_dn_len(cr);
            }
            break;

        case 6: /* G. In-range sweep */
            /* deterministically sweep: generate entries with increasing length 1..64 wrapping */
            {
                uint32_t target_entries = 1u + (uint32_t)(i % 16u);
                uint32_t off = 0;
                for (uint32_t e = 0; e < target_entries; e++) {
                    uint16_t dn_l = (uint16_t)(1u + ((uint32_t)(i + e) % 64u)); /* 1..64 */
                    if (off + 2u + dn_l > DTLS_MAX_CA_DN_LEN) break;
                    wr_be16_dn(buf + off, dn_l);
                    for (uint16_t k = 0; k < dn_l; k++) buf[off + 2 + k] = (uint8_t)(k + (uint8_t)e);
                    off += 2u + dn_l;
                }
                cr->ca_dn_len = (uint16_t)off;
                clamp_ca_dn_len(cr);
            }
            break;

        case 7: /* H. Random valid mix */
        default:
            {
                uint32_t r = rand_bounded_dn(100);
                uint32_t entries;
                if (r < 15) entries = 0;
                else if (r < 55) entries = 1u + rand_bounded_dn(3u);
                else if (r < 85) entries = 3u + rand_bounded_dn(12u);
                else entries = 16u + rand_bounded_dn(32u);

                uint32_t off = 0;
                for (uint32_t e = 0; e < entries; e++) {
                    uint16_t dn_l;
                    uint32_t m = rand_bounded_dn(100);
                    if (m < 35) dn_l = (uint16_t)(sizeof(k_dn_der_like_1));
                    else if (m < 55) dn_l = (uint16_t)(sizeof(k_dn_der_like_2));
                    else if (m < 75) dn_l = (uint16_t)(sizeof(k_dn_ascii_1) - 1);
                    else if (m < 90) dn_l = (uint16_t)(sizeof(k_dn_ascii_2) - 1);
                    else dn_l = (uint16_t)(1u + rand_bounded_dn(80u));

                    if (off + 2u + dn_l > DTLS_MAX_CA_DN_LEN) break;
                    wr_be16_dn(buf + off, dn_l);

                    /* pick payload */
                    if (dn_l == (uint16_t)(sizeof(k_dn_der_like_1))) {
                        memcpy(buf + off + 2, k_dn_der_like_1, sizeof(k_dn_der_like_1));
                    } else if (dn_l == (uint16_t)(sizeof(k_dn_der_like_2))) {
                        memcpy(buf + off + 2, k_dn_der_like_2, sizeof(k_dn_der_like_2));
                    } else if (dn_l == (uint16_t)(sizeof(k_dn_ascii_1) - 1)) {
                        memcpy(buf + off + 2, k_dn_ascii_1, sizeof(k_dn_ascii_1) - 1);
                    } else if (dn_l == (uint16_t)(sizeof(k_dn_ascii_2) - 1)) {
                        memcpy(buf + off + 2, k_dn_ascii_2, sizeof(k_dn_ascii_2) - 1);
                    } else {
                        for (uint16_t k = 0; k < dn_l; k++) buf[off + 2 + k] = rand_u8_dn();
                    }

                    off += 2u + dn_l;
                }

                cr->ca_dn_len = (uint16_t)off;
                clamp_ca_dn_len(cr);
            }
            break;
        }

        /* randomized perturbations: mix shallow/deep */
        clamp_ca_dn_len(cr);
        buf = cr->ca_dn_blob;
        len = cr->ca_dn_len;

        {
            uint32_t rr = rand_bounded_dn(100);
            if (rr < 18) {
                /* shallow: flip a bit in a random byte */
                if (len) {
                    uint32_t pos = rand_bounded_dn(len);
                    buf[pos] ^= (uint8_t)(1u << rand_bounded_dn(8));
                }
            } else if (rr < 30) {
                /* shallow: tweak one dn_length within bounds, keeping list parsable best-effort */
                if (len >= 2) {
                    uint32_t off = 0;
                    if (off + 2 <= len) {
                        uint16_t l = rd_be16_dn(buf + off);
                        if (l > 0 && off + 2u + l <= len) {
                            /* increase/decrease slightly but clamp to remaining bytes */
                            int32_t delta = (int32_t)rand_bounded_dn(7) - 3; /* -3..+3 */
                            int32_t nl = (int32_t)l + delta;
                            if (nl < 1) nl = 1;
                            uint32_t maxl = (len - 2u);
                            if ((uint32_t)nl > maxl) nl = (int32_t)maxl;
                            wr_be16_dn(buf + off, (uint16_t)nl);
                        }
                    }
                }
            } else if (rr < 45) {
                /* deep: reverse whole list */
                mem_rev_dn(buf, len);
            } else if (rr < 55) {
                /* deep: append a tiny DN if room */
                if (len + 3u <= DTLS_MAX_CA_DN_LEN) {
                    wr_be16_dn(buf + len, 1);
                    buf[len + 2] = (uint8_t)'Z';
                    cr->ca_dn_len = (uint16_t)(len + 3u);
                    clamp_ca_dn_len(cr);
                }
            } else if (rr < 62) {
                /* deep: compact to empty */
                cr->ca_dn_len = 0;
            } else if (rr < 70) {
                /* shallow: XOR mask over a small window */
                if (len) {
                    uint32_t start = rand_bounded_dn(len);
                    uint32_t span = 1u + rand_bounded_dn((len - start) ? (len - start) : 1u);
                    if (span > 64u) span = 64u;
                    uint8_t m = (uint8_t)(1u << rand_bounded_dn(8));
                    for (uint32_t k = 0; k < span && start + k < len; k++) buf[start + k] ^= m;
                }
            }
        }
    }
}


/* =========================
 * minimal helpers (PRNG, bytes)
 * ========================= */
#ifndef DTLS_MEMCPY
#define DTLS_MEMCPY(dst, src, n) do { \
    uint8_t *_d=(uint8_t*)(dst); const uint8_t *_s=(const uint8_t*)(src); \
    for (size_t _i=0; _i<(size_t)(n); _i++) _d[_i]=_s[_i]; \
} while(0)
#endif

#ifndef DTLS_MEMSET
#define DTLS_MEMSET(dst, v, n) do { \
    uint8_t *_d=(uint8_t*)(dst); \
    for (size_t _i=0; _i<(size_t)(n); _i++) _d[_i]=(uint8_t)(v); \
} while(0)
#endif

static uint32_t dtls_rnd_u32(void) {
    /* xorshift32 */
    static uint32_t s = 0xC0FFEE01u;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}
static uint8_t dtls_rnd_u8(void) { return (uint8_t)(dtls_rnd_u32() & 0xFFu); }
static uint16_t dtls_rnd_u16(void) { return (uint16_t)(dtls_rnd_u32() & 0xFFFFu); }
static uint32_t dtls_rnd_bounded(uint32_t n) { return n ? (dtls_rnd_u32() % n) : 0; }

static void dtls_fill_random(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = dtls_rnd_u8();
}

static void dtls_mix_shallow_deep(uint8_t *p, size_t n) {
    if (n == 0) return;
    /* shallow: flip 1..3 bytes */
    uint32_t flips = 1u + dtls_rnd_bounded(3u);
    for (uint32_t i = 0; i < flips; i++) {
        size_t idx = (size_t)dtls_rnd_bounded((uint32_t)n);
        p[idx] ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
    }
    /* deep: rewrite a random slice sometimes */
    if ((dtls_rnd_u8() & 1u) && n >= 4) {
        size_t off = (size_t)dtls_rnd_bounded((uint32_t)(n - 1));
        size_t len = 1u + (size_t)dtls_rnd_bounded((uint32_t)(n - off));
        dtls_fill_random(p + off, len);
    }
}

/* clamp helper */
static uint16_t dtls_clamp_u16(uint32_t v, uint16_t lo, uint16_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return (uint16_t)v;
}
static uint8_t dtls_clamp_u8(uint32_t v, uint8_t lo, uint8_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return (uint8_t)v;
}

/* =========================
 * Base field mutators (A~H)
 * ========================= */

/* ---- A/B/C/D/E/F/G/H for uint16 length that bounds an array ---- */
static void mutate_len_u16(uint16_t *len,
                           uint16_t max_cap,
                           uint16_t min_cap,
                           uint8_t prefer_even /* for sig_algs_len etc */) {
    if (!len) return;
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u); /* 0..7 => A..H */
    uint32_t v;

    switch (cat) {
    /* A Canonical form */
    case 0:
        v = (uint32_t)(*len);
        if (v < min_cap) v = min_cap;
        if (v > max_cap) v = max_cap;
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* B Boundaries */
    case 1: {
        static const uint16_t b[] = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512};
        uint16_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
        v = pick;
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;
    }

    /* C Equivalence-class alternatives */
    case 2:
        /* keep same "class": small/medium/large */
        if (*len <= 8) v = (uint32_t)(dtls_rnd_bounded(9u));                 /* 0..8 */
        else if (*len <= 64) v = 9u + dtls_rnd_bounded(56u);                /* 9..64 */
        else v = 65u + dtls_rnd_bounded((uint32_t)(max_cap - 64u));         /* 65..max */
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* D Allowed bitfield/enum/range */
    case 3:
        v = (uint32_t)dtls_rnd_bounded((uint32_t)(max_cap + 1u));
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* E Encoding-shape variant */
    case 4:
        /* choose values that stress parsers: odd/even toggles, near powers of two */
        v = (uint32_t)(1u << (dtls_rnd_bounded(9u))); /* 1..256 */
        if ((dtls_rnd_u8() & 1u) && v > 0) v -= 1u;
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* F Padding/alignment */
    case 5:
        /* align to 2/4/8 if possible */
        v = (uint32_t)(*len);
        switch (dtls_rnd_bounded(3u)) {
        case 0: v = (v + 1u) & ~1u; break;
        case 1: v = (v + 3u) & ~3u; break;
        default:v = (v + 7u) & ~7u; break;
        }
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* G In-range sweep */
    case 6:
        v = (uint32_t)(*len);
        if (dtls_rnd_u8() & 1u) v = v + (1u + dtls_rnd_bounded(8u));
        else v = (v >= 8u) ? (v - (1u + dtls_rnd_bounded(8u))) : 0u;
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;

    /* H Random valid mix */
    default:
        v = (uint32_t)dtls_rnd_bounded((uint32_t)(max_cap + 1u));
        v = dtls_clamp_u16(v, min_cap, max_cap);
        if (prefer_even) v &= ~1u;
        *len = (uint16_t)v;
        break;
    }
}

/* uint8 length */
static void mutate_len_u8(uint8_t *len, uint8_t max_cap, uint8_t min_cap) {
    if (!len) return;
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    uint32_t v;

    switch (cat) {
    case 0: /* A */
        v = *len;
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    case 1: { /* B */
        static const uint8_t b[] = {0,1,2,3,4,7,8,15,16,31,32,63,64,127,128,254,255};
        uint8_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
        v = dtls_clamp_u8(pick, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    }
    case 2: /* C */
        if (*len <= 8) v = dtls_rnd_bounded(9u);
        else if (*len <= 64) v = 9u + dtls_rnd_bounded(56u);
        else v = 65u + dtls_rnd_bounded((uint32_t)(max_cap - 64u));
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    case 3: /* D */
        v = dtls_rnd_bounded((uint32_t)(max_cap + 1u));
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    case 4: /* E */
        v = (uint32_t)(1u << (dtls_rnd_bounded(8u))); /* 1..128 */
        if ((dtls_rnd_u8() & 1u) && v) v -= 1u;
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    case 5: /* F */
        v = *len;
        switch (dtls_rnd_bounded(3u)) {
        case 0: v = (v + 1u) & ~1u; break;
        case 1: v = (v + 3u) & ~3u; break;
        default:v = (v + 7u) & ~7u; break;
        }
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    case 6: /* G */
        v = *len;
        if (dtls_rnd_u8() & 1u) v += 1u + dtls_rnd_bounded(8u);
        else v = (v >= 8u) ? (v - (1u + dtls_rnd_bounded(8u))) : 0u;
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    default: /* H */
        v = dtls_rnd_bounded((uint32_t)(max_cap + 1u));
        v = dtls_clamp_u8(v, min_cap, max_cap);
        *len = (uint8_t)v;
        break;
    }
}

/* mutate opaque byte blob with known capacity and current length */
static void mutate_opaque_blob(uint8_t *buf, uint16_t len, uint16_t cap) {
    if (!buf || cap == 0) return;
    if (len > cap) len = cap;

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    switch (cat) {
    case 0: /* A Canonical: keep as-is but add tiny entropy */
        if (len) dtls_mix_shallow_deep(buf, (size_t)len);
        break;

    case 1: /* B Boundaries: all zeros / all FF / ascending / alternating */
        if (len == 0) break;
        switch (dtls_rnd_bounded(4u)) {
        case 0: DTLS_MEMSET(buf, 0x00, len); break;
        case 1: DTLS_MEMSET(buf, 0xFF, len); break;
        case 2: for (uint16_t i=0;i<len;i++) buf[i]=(uint8_t)i; break;
        default: for (uint16_t i=0;i<len;i++) buf[i]=(uint8_t)((i&1)?0xAA:0x55); break;
        }
        dtls_mix_shallow_deep(buf, (size_t)len);
        break;

    case 2: /* C Equivalence-class: preserve "shape" (mostly same) */
        if (len) {
            /* tweak a few positions only */
            uint32_t k = 1u + dtls_rnd_bounded(6u);
            for (uint32_t i=0;i<k;i++) {
                size_t idx = (size_t)dtls_rnd_bounded((uint32_t)len);
                buf[idx] = (uint8_t)(buf[idx] + (uint8_t)(1u + dtls_rnd_bounded(7u)));
            }
        }
        break;

    case 3: /* D Allowed range: bytes are 0..255 anyway -> just randomize some */
        if (len) {
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)len);
            size_t l = 1u + (size_t)dtls_rnd_bounded((uint32_t)(len - off));
            dtls_fill_random(buf + off, l);
        }
        break;

    case 4: /* E Encoding-shape: inject common encodings (DER-ish headers) into prefix */
        if (len >= 2) {
            /* 0x30 len (SEQUENCE) or 0x02 len (INTEGER) like */
            buf[0] = (dtls_rnd_u8() & 1u) ? 0x30 : 0x02;
            buf[1] = (uint8_t)((len > 2) ? (len - 2) : 0);
            if (len > 2) dtls_mix_shallow_deep(buf + 2, (size_t)(len - 2));
        } else if (len == 1) {
            buf[0] = 0x30;
        }
        break;

    case 5: /* F Padding/alignment: add padding patterns inside */
        if (len) {
            uint8_t pad = (uint8_t)(dtls_rnd_bounded(16u));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)len);
            size_t l = (size_t)dtls_rnd_bounded((uint32_t)(len - off + 1u));
            for (size_t i=0;i<l;i++) buf[off+i] = pad;
            dtls_mix_shallow_deep(buf, (size_t)len);
        }
        break;

    case 6: /* G In-range sweep: gradient / sliding window overwrite */
        if (len) {
            size_t win = 1u + (size_t)dtls_rnd_bounded((uint32_t)((len < 32)?len:32));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)(len - win + 1u));
            for (size_t i=0;i<win;i++) buf[off+i] = (uint8_t)((off+i) & 0xFFu);
        }
        break;

    default: /* H Random valid mix */
        if (len) {
            if (dtls_rnd_u8() & 1u) dtls_fill_random(buf, (size_t)len);
            else dtls_mix_shallow_deep(buf, (size_t)len);
        }
        break;
    }
}

/* mutate (hash,sig) pair list for TLS 1.2 SignatureAndHashAlgorithm */
static void mutate_sig_alg_pairs(uint8_t *pairs, uint16_t len_bytes, uint16_t cap_bytes) {
    if (!pairs || cap_bytes < 2) return;
    if (len_bytes > cap_bytes) len_bytes = cap_bytes;
    len_bytes &= ~1u; /* must be even bytes */
    if (len_bytes == 0) return;

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    uint16_t n = (uint16_t)(len_bytes / 2u);

    /* known-ish sets (TLS 1.2) */
    static const uint8_t hashes[] = {1,2,3,4,5,6}; /* MD5..SHA512 (HASH_NONE excluded here) */
    static const uint8_t sigs[]   = {1,2,3};       /* RSA,DSA,ECDSA */
    static const uint8_t canon_pairs[][2] = {
        {4,3}, /* sha256, ecdsa */
        {4,1}, /* sha256, rsa   */
        {2,1}, /* sha1, rsa     */
        {2,3}, /* sha1, ecdsa   */
        {5,1}, /* sha384, rsa   */
        {5,3}  /* sha384, ecdsa */
    };

    switch (cat) {
    case 0: /* A Canonical */
        for (uint16_t i=0;i<n;i++) {
            const uint8_t *p = canon_pairs[dtls_rnd_bounded((uint32_t)(sizeof(canon_pairs)/sizeof(canon_pairs[0])))];
            pairs[2u*i]   = p[0];
            pairs[2u*i+1] = p[1];
        }
        break;

    case 1: /* B Boundaries */
        /* extremes + repeats */
        for (uint16_t i=0;i<n;i++) {
            pairs[2u*i]   = (i&1)?1:6; /* MD5 vs SHA512 */
            pairs[2u*i+1] = (i&1)?1:3; /* RSA vs ECDSA  */
        }
        dtls_mix_shallow_deep(pairs, len_bytes);
        break;

    case 2: /* C Equivalence-class alternatives */
        /* preserve distribution: mostly same, tweak few entries */
        {
            uint16_t tweaks = 1u + (uint16_t)dtls_rnd_bounded((n < 8) ? n : 8u);
            for (uint16_t t=0;t<tweaks;t++) {
                uint16_t idx = (uint16_t)dtls_rnd_bounded(n);
                pairs[2u*idx]   = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
                pairs[2u*idx+1] = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
            }
        }
        break;

    case 3: /* D Allowed enums */
        for (uint16_t i=0;i<n;i++) {
            pairs[2u*i]   = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
            pairs[2u*i+1] = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        }
        break;

    case 4: /* E Encoding-shape variant */
        /* create blocks of same pair */
        {
            const uint8_t *p = canon_pairs[dtls_rnd_bounded((uint32_t)(sizeof(canon_pairs)/sizeof(canon_pairs[0])))];
            uint16_t block = 1u + (uint16_t)dtls_rnd_bounded((n < 8)?n:8u);
            for (uint16_t i=0;i<n;i++) {
                if ((i % block) == 0) p = canon_pairs[dtls_rnd_bounded((uint32_t)(sizeof(canon_pairs)/sizeof(canon_pairs[0])))];
                pairs[2u*i]   = p[0];
                pairs[2u*i+1] = p[1];
            }
        }
        break;

    case 5: /* F Padding/alignment */
        /* alignment already even; stress with repeated zero-ish patterns but keep in allowed sets */
        for (uint16_t i=0;i<n;i++) {
            pairs[2u*i]   = (i&1)?2:4; /* sha1/sha256 */
            pairs[2u*i+1] = (i&1)?1:3; /* rsa/ecdsa   */
        }
        break;

    case 6: /* G In-range sweep */
        for (uint16_t i=0;i<n;i++) {
            pairs[2u*i]   = hashes[(i % (uint16_t)sizeof(hashes))];
            pairs[2u*i+1] = sigs[(i % (uint16_t)sizeof(sigs))];
        }
        break;

    default: /* H Random valid mix */
        for (uint16_t i=0;i<n;i++) {
            if (dtls_rnd_u8() & 1u) {
                const uint8_t *p = canon_pairs[dtls_rnd_bounded((uint32_t)(sizeof(canon_pairs)/sizeof(canon_pairs[0])))];
                pairs[2u*i]   = p[0];
                pairs[2u*i+1] = p[1];
            } else {
                pairs[2u*i]   = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
                pairs[2u*i+1] = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
            }
        }
        dtls_mix_shallow_deep(pairs, len_bytes);
        break;
    }
}

/* mutate a single (hash,sig) struct */
static void mutate_signature_and_hash(struct { uint8_t hash_algorithm; uint8_t signature_algorithm; } *alg) {
    if (!alg) return;
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    static const uint8_t hashes[] = {1,2,3,4,5,6};
    static const uint8_t sigs[]   = {1,2,3};

    switch (cat) {
    case 0: /* A canonical */
        alg->hash_algorithm = 4;      /* SHA256 */
        alg->signature_algorithm = 3; /* ECDSA */
        break;
    case 1: /* B boundaries */
        alg->hash_algorithm = (dtls_rnd_u8() & 1u) ? 1 : 6;
        alg->signature_algorithm = (dtls_rnd_u8() & 1u) ? 1 : 3;
        break;
    case 2: /* C equivalence */
        /* switch within common set */
        alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
        alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        break;
    case 3: /* D allowed enum */
        alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
        alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        break;
    case 4: /* E encoding-shape (not much) -> pick sha1/rsa classic */
        alg->hash_algorithm = 2;
        alg->signature_algorithm = 1;
        break;
    case 5: /* F padding/alignment N/A -> perturb gently */
        alg->hash_algorithm = (uint8_t)(alg->hash_algorithm ^ (1u << (dtls_rnd_u8() & 2u)));
        alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        break;
    case 6: /* G sweep */
        alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
        alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        break;
    default: /* H random valid mix */
        if (dtls_rnd_u8() & 1u) {
            alg->hash_algorithm = 4;
            alg->signature_algorithm = 1;
        } else {
            alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)sizeof(hashes))];
            alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)sizeof(sigs))];
        }
        break;
    }
}

/* mutate EC named_curve + curve_type (named_curve=3) */
static void mutate_ec_params_header(uint8_t *curve_type, uint16_t *named_curve) {
    if (!curve_type || !named_curve) return;
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    /* common NamedCurve ids (TLS ECC): 23 secp256r1, 24 secp384r1, 25 secp521r1,
       29 x25519 (TLS1.2 extensions; some stacks use), 30 x448 */
    static const uint16_t curves[] = {23,24,25,29,30};

    switch (cat) {
    case 0: /* A canonical */
        *curve_type = 3;
        *named_curve = 23;
        break;
    case 1: /* B boundaries */
        *curve_type = 3;
        *named_curve = (dtls_rnd_u8() & 1u) ? 23 : 30;
        break;
    case 2: /* C equivalence */
        *curve_type = 3;
        *named_curve = curves[dtls_rnd_bounded((uint32_t)(sizeof(curves)/sizeof(curves[0])))];
        break;
    case 3: /* D allowed range/enum */
        *curve_type = 3;
        *named_curve = curves[dtls_rnd_bounded((uint32_t)(sizeof(curves)/sizeof(curves[0])))];
        break;
    case 4: /* E encoding-shape variant */
        /* keep curve_type=3 but choose less common curve */
        *curve_type = 3;
        *named_curve = (dtls_rnd_u8() & 1u) ? 24 : 25;
        break;
    case 5: /* F padding/alignment N/A -> small perturb */
        *curve_type = 3;
        *named_curve = (uint16_t)(*named_curve + (uint16_t)(dtls_rnd_bounded(3u)));
        if (*named_curve < 23 || *named_curve > 30) *named_curve = 23;
        break;
    case 6: /* G sweep */
        *curve_type = 3;
        *named_curve = curves[dtls_rnd_bounded((uint32_t)(sizeof(curves)/sizeof(curves[0])))];
        break;
    default: /* H random valid mix */
        *curve_type = 3;
        *named_curve = curves[dtls_rnd_bounded((uint32_t)(sizeof(curves)/sizeof(curves[0])))];
        break;
    }
}

/* =========================
 * Reusable struct-level mutators (compose base field mutators)
 * ========================= */

/* -- dtls_server_dh_params_t:
 *   uint16_t dh_p_len; uint8_t dh_p[CAP];
 *   uint16_t dh_g_len; uint8_t dh_g[CAP];
 *   uint16_t dh_Ys_len;uint8_t dh_Ys[CAP];
 */
static void mutate_server_dh_params(struct {
    uint16_t dh_p_len; uint8_t dh_p[512];
    uint16_t dh_g_len; uint8_t dh_g[512];
    uint16_t dh_Ys_len;uint8_t dh_Ys[512];
} *p) {
    if (!p) return;

    /* length fields (A~H) */
    mutate_len_u16(&p->dh_p_len, 512, 0, 0);
    mutate_len_u16(&p->dh_g_len, 512, 0, 0);
    mutate_len_u16(&p->dh_Ys_len,512, 0, 0);

    /* opaque blobs */
    mutate_opaque_blob(p->dh_p,  p->dh_p_len,  512);
    mutate_opaque_blob(p->dh_g,  p->dh_g_len,  512);
    mutate_opaque_blob(p->dh_Ys, p->dh_Ys_len, 512);

    /* extra randomized perturbation */
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->dh_p,  (size_t)p->dh_p_len);
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->dh_g,  (size_t)p->dh_g_len);
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->dh_Ys, (size_t)p->dh_Ys_len);
}

/* -- dtls_ecdh_server_params_t:
 *   uint8_t curve_type; uint16_t named_curve;
 *   uint8_t ec_point_len; uint8_t ec_point[CAP];
 */
static void mutate_ecdh_server_params(struct {
    uint8_t  curve_type;
    uint16_t named_curve;
    uint8_t  ec_point_len;
    uint8_t  ec_point[512];
} *p) {
    if (!p) return;

    mutate_ec_params_header(&p->curve_type, &p->named_curve);

    /* ec_point_len is uint8, cap 512 -> clamp to 255 because uint8 */
    mutate_len_u8(&p->ec_point_len, 255, 0);
    mutate_opaque_blob(p->ec_point, (uint16_t)p->ec_point_len, 512);

    /* keep first byte 0x04 for uncompressed sometimes (common ECPoint) */
    if (p->ec_point_len >= 1 && (dtls_rnd_u8() & 1u)) p->ec_point[0] = 0x04;

    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->ec_point, (size_t)p->ec_point_len);
}

/* -- dtls_digitally_signed_t:
 *   alg (hash,sig), signature_len, signature[]
 */
static void mutate_digitally_signed(struct {
    struct { uint8_t hash_algorithm; uint8_t signature_algorithm; } alg;
    uint16_t signature_len;
    uint8_t  signature[512];
} *s) {
    if (!s) return;

    mutate_signature_and_hash(&s->alg);
    mutate_len_u16(&s->signature_len, 512, 0, 0);
    mutate_opaque_blob(s->signature, s->signature_len, 512);

    /* sometimes set signature as DER-ish prefix for ECDSA/RSA */
    if (s->signature_len >= 2 && (dtls_rnd_u8() & 1u)) {
        s->signature[0] = 0x30;
        s->signature[1] = (uint8_t)((s->signature_len > 2) ? (s->signature_len - 2) : 0);
    }
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(s->signature, (size_t)s->signature_len);
}

/* -- dtls_psk_identity_hint_t:
 *   uint16_t identity_hint_len; uint8_t identity_hint[]
 */
static void mutate_psk_identity_hint(struct {
    uint16_t identity_hint_len;
    uint8_t  identity_hint[256];
} *h) {
    if (!h) return;
    mutate_len_u16(&h->identity_hint_len, 256, 0, 0);
    mutate_opaque_blob(h->identity_hint, h->identity_hint_len, 256);

    /* canonical ASCII-ish sometimes */
    if (h->identity_hint_len && (dtls_rnd_u8() & 1u)) {
        for (uint16_t i=0;i<h->identity_hint_len;i++) {
            uint8_t c = (uint8_t)('a' + (dtls_rnd_u8() % 26));
            if (dtls_rnd_u8() & 1u) c = (uint8_t)('0' + (dtls_rnd_u8() % 10));
            h->identity_hint[i] = c;
        }
    }
}

/* -- dtls_encrypted_premaster_secret_t:
 *   uint16_t enc_pms_len; uint8_t enc_pms[]
 */
static void mutate_encrypted_pms(struct {
    uint16_t enc_pms_len;
    uint8_t  enc_pms[512];
} *pms) {
    if (!pms) return;
    mutate_len_u16(&pms->enc_pms_len, 512, 0, 0);
    mutate_opaque_blob(pms->enc_pms, pms->enc_pms_len, 512);

    /* RSA ciphertext often random-looking -> enforce high entropy sometimes */
    if (pms->enc_pms_len && (dtls_rnd_u8() & 1u)) dtls_fill_random(pms->enc_pms, pms->enc_pms_len);
}

/* -- signature algorithm pairs list (certificate_request.sig_algs) */
static void mutate_certreq_sig_algs(struct {
    uint16_t sig_algs_len;
    uint8_t  sig_algs[256];
} *sa) {
    if (!sa) return;
    mutate_len_u16(&sa->sig_algs_len, 256, 0, 1 /* even */);
    mutate_sig_alg_pairs(sa->sig_algs, sa->sig_algs_len, 256);
}

/* -- certificate_request cert_types list */
static void mutate_certreq_cert_types(struct {
    uint8_t  cert_types_len;
    uint8_t  cert_types[32];
} *ct) {
    if (!ct) return;
    mutate_len_u8(&ct->cert_types_len, 32, 0);
    mutate_opaque_blob(ct->cert_types, ct->cert_types_len, 32);
}

/* -- CA DN blob */
static void mutate_ca_dn_blob(struct {
    uint16_t ca_dn_len;
    uint8_t  ca_dn_blob[4096];
} *dn) {
    if (!dn) return;
    mutate_len_u16(&dn->ca_dn_len, 4096, 0, 0);
    mutate_opaque_blob(dn->ca_dn_blob, dn->ca_dn_len, 4096);

    /* DER-ish DistinguishedName list: start with SEQUENCE */
    if (dn->ca_dn_len >= 2 && (dtls_rnd_u8() & 1u)) {
        dn->ca_dn_blob[0] = 0x30;
        dn->ca_dn_blob[1] = (uint8_t)((dn->ca_dn_len > 2) ? (dn->ca_dn_len - 2) : 0);
    }
}

/* =========================
 * Top-level: reuse in higher layers
 * The upper layer mutator just calls these for repeated structures.
 * ========================= */

/* Example: mutate a ServerKeyExchange body by dispatching on kx_alg and reusing base mutators.
 * (You can call this from your packet-level mutator.)
 *
 * NOTE: This expects your dtls_server_key_exchange_body_t layout exactly as you posted.
 */

/* forward declare enums from your code */
// typedef enum {
//     KX_UNKNOWN = 0,
//     KX_DH_ANON, KX_DHE_DSS, KX_DHE_RSA, KX_DH_DSS, KX_DH_RSA, KX_RSA,
//     KX_ECDH_ECDSA, KX_ECDH_RSA, KX_ECDH_ANON,
//     KX_ECDHE_ECDSA, KX_ECDHE_RSA,
//     KX_PSK, KX_DHE_PSK, KX_RSA_PSK, KX_ECDHE_PSK
// } dtls_kx_alg_t;

// typedef struct {
//     dtls_kx_alg_t kx_alg;
//     union {
//         struct { struct { uint16_t dh_p_len; uint8_t dh_p[512]; uint16_t dh_g_len; uint8_t dh_g[512]; uint16_t dh_Ys_len; uint8_t dh_Ys[512]; } params; } dh_anon;
//         struct { struct { uint16_t dh_p_len; uint8_t dh_p[512]; uint16_t dh_g_len; uint8_t dh_g[512]; uint16_t dh_Ys_len; uint8_t dh_Ys[512]; } params;
//                  struct { struct { uint8_t hash_algorithm; uint8_t signature_algorithm; } alg; uint16_t signature_len; uint8_t signature[512]; } sig; } dhe_signed;
//         struct { struct { uint8_t curve_type; uint16_t named_curve; uint8_t ec_point_len; uint8_t ec_point[512]; } params;
//                  struct { struct { uint8_t hash_algorithm; uint8_t signature_algorithm; } alg; uint16_t signature_len; uint8_t signature[512]; } sig; } ecdhe_signed;

//         struct { struct { uint8_t curve_type; uint16_t named_curve; uint8_t ec_point_len; uint8_t ec_point[512]; } params; } ecdh_params;
//         struct { uint8_t _dummy; } omitted;

//         struct { struct { uint16_t identity_hint_len; uint8_t identity_hint[256]; } hint; } psk;
//         struct { struct { uint16_t identity_hint_len; uint8_t identity_hint[256]; } hint;
//                  struct { uint16_t dh_p_len; uint8_t dh_p[512]; uint16_t dh_g_len; uint8_t dh_g[512]; uint16_t dh_Ys_len; uint8_t dh_Ys[512]; } params; } dhe_psk;
//         struct { struct { uint16_t identity_hint_len; uint8_t identity_hint[256]; } hint; } rsa_psk;
//         struct { struct { uint16_t identity_hint_len; uint8_t identity_hint[256]; } hint;
//                  struct { uint8_t curve_type; uint16_t named_curve; uint8_t ec_point_len; uint8_t ec_point[512]; } params; } ecdhe_psk;
//     } u;
// } dtls_server_key_exchange_body_t;

void mutate_server_key_exchange_body(dtls_server_key_exchange_body_t *ske) {
    if (!ske) return;

    /* optional: mutate kx_alg itself sometimes (upper layer choice) */
    if (dtls_rnd_u8() & 1u) {
        static const dtls_kx_alg_t kxs[] = {
            KX_DH_ANON, KX_DHE_DSS, KX_DHE_RSA, KX_RSA,
            KX_ECDHE_ECDSA, KX_ECDHE_RSA,
            KX_ECDH_ECDSA, KX_ECDH_RSA, KX_ECDH_ANON,
            KX_PSK, KX_DHE_PSK, KX_RSA_PSK, KX_ECDHE_PSK
        };
        ske->kx_alg = kxs[dtls_rnd_bounded((uint32_t)(sizeof(kxs)/sizeof(kxs[0])))];
    }

    /* reuse bottom mutators for repeated base structures */
    switch (ske->kx_alg) {
    case KX_DH_ANON:
        mutate_server_dh_params(&ske->u.dh_anon.params);
        break;

    case KX_DHE_DSS:
    case KX_DHE_RSA:
        mutate_server_dh_params(&ske->u.dhe_signed.params);
        mutate_digitally_signed(&ske->u.dhe_signed.sig);
        break;

    case KX_ECDHE_ECDSA:
    case KX_ECDHE_RSA:
        mutate_ecdh_server_params(&ske->u.ecdhe_signed.params);
        mutate_digitally_signed(&ske->u.ecdhe_signed.sig);
        break;

    case KX_ECDH_ECDSA:
    case KX_ECDH_RSA:
    case KX_ECDH_ANON:
        /* either omitted or explicit params; keep both shapes by sometimes switching */
        if (dtls_rnd_u8() & 1u) {
            mutate_ecdh_server_params(&ske->u.ecdh_params.params);
        } else {
            ske->u.omitted._dummy ^= dtls_rnd_u8();
        }
        break;

    case KX_RSA:
    case KX_DH_DSS:
    case KX_DH_RSA:
        ske->u.omitted._dummy ^= dtls_rnd_u8();
        break;

    case KX_PSK:
        mutate_psk_identity_hint(&ske->u.psk.hint);
        break;

    case KX_DHE_PSK:
        mutate_psk_identity_hint(&ske->u.dhe_psk.hint);
        mutate_server_dh_params(&ske->u.dhe_psk.params);
        break;

    case KX_RSA_PSK:
        mutate_psk_identity_hint(&ske->u.rsa_psk.hint);
        break;

    case KX_ECDHE_PSK:
        mutate_psk_identity_hint(&ske->u.ecdhe_psk.hint);
        mutate_ecdh_server_params(&ske->u.ecdhe_psk.params);
        break;

    default:
        /* unknown -> perturb dummy */
        ske->u.omitted._dummy ^= dtls_rnd_u8();
        break;
    }
}


void mutate_server_key_exchange(dtls_packet_t *pkts, size_t n){
    for (size_t i = 0; i < n; i++)
    {
        if(&pkts[i].payload.handshake.body.server_key_exchange){
            mutate_server_key_exchange_body(&pkts[i].payload.handshake.body.server_key_exchange);
        }
    }
}



/* =========================
 * Enums + minimal structs (must match your posted layout)
 * ========================= */

// typedef enum {
//     KX_UNKNOWN = 0,

//     KX_DH_ANON,
//     KX_DHE_DSS,
//     KX_DHE_RSA,
//     KX_DH_DSS,
//     KX_DH_RSA,

//     KX_RSA,

//     KX_ECDH_ECDSA,
//     KX_ECDH_RSA,
//     KX_ECDH_ANON,

//     KX_ECDHE_ECDSA,
//     KX_ECDHE_RSA,

//     KX_PSK,
//     KX_DHE_PSK,
//     KX_RSA_PSK,
//     KX_ECDHE_PSK
// } dtls_kx_alg_t;

// /* ---- base structs for CKE ---- */
// typedef struct {
//     uint16_t dh_Yc_len;
//     uint8_t  dh_Yc[512];
// } dtls_client_dh_public_t;

// typedef struct {
//     uint8_t  ec_point_len;
//     uint8_t  ec_point[512];
// } dtls_ecdh_client_public_t;

// typedef struct {
//     uint16_t identity_len;
//     uint8_t  identity[256];
// } dtls_psk_identity_t;

// typedef struct {
//     uint16_t enc_pms_len;
//     uint8_t  enc_pms[512];
// } dtls_encrypted_premaster_secret_t;

// /* ---- CKE variants ---- */
// typedef struct { dtls_encrypted_premaster_secret_t enc_pms; } dtls_cke_rsa_t;
// typedef struct { dtls_client_dh_public_t           dh_pub;  } dtls_cke_dh_t;
// typedef struct { dtls_ecdh_client_public_t         ecdh_pub;} dtls_cke_ecdh_t;
// typedef struct { dtls_psk_identity_t               psk;     } dtls_cke_psk_t;

// typedef struct {
//     dtls_psk_identity_t      psk;
//     dtls_client_dh_public_t  dh_pub;
// } dtls_cke_dhe_psk_t;

// typedef struct {
//     dtls_psk_identity_t               psk;
//     dtls_encrypted_premaster_secret_t enc_pms;
// } dtls_cke_rsa_psk_t;

// typedef struct {
//     dtls_psk_identity_t        psk;
//     dtls_ecdh_client_public_t  ecdh_pub;
// } dtls_cke_ecdhe_psk_t;

// /* union wrapper */
// typedef struct {
//     dtls_kx_alg_t kx_alg;
//     union {
//         dtls_cke_rsa_t        rsa;        /* KX_RSA */
//         dtls_cke_dh_t         dh;         /* KX_DH_ANON, KX_DHE_*, KX_DH_* */
//         dtls_cke_ecdh_t       ecdh;       /* KX_ECDH_*, KX_ECDHE_* */
//         dtls_cke_psk_t        psk;        /* KX_PSK */
//         dtls_cke_dhe_psk_t    dhe_psk;    /* KX_DHE_PSK */
//         dtls_cke_rsa_psk_t    rsa_psk;    /* KX_RSA_PSK */
//         dtls_cke_ecdhe_psk_t  ecdhe_psk;  /* KX_ECDHE_PSK */
//     } u;
// } dtls_client_key_exchange_body_t;

/* =========================
 * Struct-level mutators (reuse base field mutators)
 * ========================= */
/* Overwrite: A-H aligned base-struct mutators */

static void mutate_client_dh_public(dtls_client_dh_public_t *p) {
    if (!p) return;

    /* A-H on length (dh_Yc_len), then content */
    mutate_len_u16(&p->dh_Yc_len, (uint16_t)DTLS_MAX_DH_Y_LEN, 0, 0);

    /* Choose category explicitly so the struct mutator itself is A-H complete */
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    uint16_t L = p->dh_Yc_len;
    if (L > (uint16_t)DTLS_MAX_DH_Y_LEN) L = (uint16_t)DTLS_MAX_DH_Y_LEN;

    switch (cat) {
    case 0: /* A. Canonical form */
        /* Typical DH public length is non-zero and often "big-ish"; keep existing but normalize. */
        if (L == 0) {
            p->dh_Yc_len = 64;
            L = p->dh_Yc_len;
        }
        /* Canonical: big-endian-like blob, no strict rule; keep mostly stable, small perturb. */
        mutate_opaque_blob(p->dh_Yc, L, (uint16_t)DTLS_MAX_DH_Y_LEN);
        dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
        break;

    case 1: /* B. Boundaries */
        /* boundary lengths: 0,1,2, (cap-1), cap */
        {
            static const uint16_t b[] = {0,1,2,3,7,8,15,16,31,32,63,64,127,128,
                                         (uint16_t)(DTLS_MAX_DH_Y_LEN-1), (uint16_t)DTLS_MAX_DH_Y_LEN};
            uint16_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
            if (pick > (uint16_t)DTLS_MAX_DH_Y_LEN) pick = (uint16_t)DTLS_MAX_DH_Y_LEN;
            p->dh_Yc_len = pick;
            L = pick;
            if (L) {
                /* boundary patterns */
                switch (dtls_rnd_bounded(4u)) {
                case 0: DTLS_MEMSET(p->dh_Yc, 0x00, L); break;
                case 1: DTLS_MEMSET(p->dh_Yc, 0xFF, L); break;
                case 2: for (uint16_t i=0;i<L;i++) p->dh_Yc[i]=(uint8_t)i; break;
                default: for (uint16_t i=0;i<L;i++) p->dh_Yc[i]=(uint8_t)((i&1)?0xAA:0x55); break;
                }
                dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
            }
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* Different "classes": short/medium/long DH public */
        {
            uint16_t pick;
            uint8_t cls = (uint8_t)dtls_rnd_bounded(3u);
            if (cls == 0) pick = (uint16_t)(16u + dtls_rnd_bounded(49u));        /* 16..64 */
            else if (cls == 1) pick = (uint16_t)(65u + dtls_rnd_bounded(192u));  /* 65..256 */
            else pick = (uint16_t)(257u + dtls_rnd_bounded((uint32_t)(DTLS_MAX_DH_Y_LEN-256u))); /* 257..cap */
            if (pick > (uint16_t)DTLS_MAX_DH_Y_LEN) pick = (uint16_t)DTLS_MAX_DH_Y_LEN;
            p->dh_Yc_len = pick;
            L = pick;

            /* content class: random / monotonic / sparse flips */
            if (L) {
                if (dtls_rnd_u8() & 1u) dtls_fill_random(p->dh_Yc, L);
                else {
                    DTLS_MEMSET(p->dh_Yc, 0, L);
                    for (uint16_t i=0;i<L;i += (uint16_t)(1u + dtls_rnd_bounded(13u)))
                        p->dh_Yc[i] = (uint8_t)(1u + (dtls_rnd_u8() % 0xFEu));
                }
                dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
            }
        }
        break;

    case 3: /* D. Allowed bitfield/enum/range */
        /* Range: length is [0..cap], bytes are [0..255]. Keep in-range but structured. */
        if (L) {
            mutate_opaque_blob(p->dh_Yc, L, (uint16_t)DTLS_MAX_DH_Y_LEN);
            /* enforce in-range already; add tiny nibble-level changes */
            uint32_t k = 1u + dtls_rnd_bounded(6u);
            for (uint32_t i=0;i<k;i++) {
                size_t idx = (size_t)dtls_rnd_bounded((uint32_t)L);
                p->dh_Yc[idx] = (uint8_t)((p->dh_Yc[idx] & 0xF0u) | (dtls_rnd_u8() & 0x0Fu));
            }
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* Not a formal encoding, but we can emulate "big-int" shapes:
           - leading 0x00 padding (positive)
           - leading 0xFF padding
           - strip/extend leading zeros within cap
        */
        if (L) {
            mutate_opaque_blob(p->dh_Yc, L, (uint16_t)DTLS_MAX_DH_Y_LEN);
            uint8_t shape = (uint8_t)dtls_rnd_bounded(3u);
            if (shape == 0) p->dh_Yc[0] = 0x00;
            else if (shape == 1) p->dh_Yc[0] = 0xFF;
            else if (L >= 2) { p->dh_Yc[0] = 0x00; p->dh_Yc[1] = 0x01; }
            dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
        }
        break;

    case 5: /* F. Padding/alignment */
        /* Align length to 2/4/8 while staying <= cap; pad tail with a chosen byte */
        {
            uint16_t base = L;
            uint16_t aligned = base;
            switch (dtls_rnd_bounded(3u)) {
            case 0: aligned = (uint16_t)((base + 1u) & ~1u); break;
            case 1: aligned = (uint16_t)((base + 3u) & ~3u); break;
            default:aligned = (uint16_t)((base + 7u) & ~7u); break;
            }
            if (aligned > (uint16_t)DTLS_MAX_DH_Y_LEN) aligned = (uint16_t)DTLS_MAX_DH_Y_LEN;
            p->dh_Yc_len = aligned;
            L = aligned;
            if (L) {
                uint8_t pad = (uint8_t)dtls_rnd_bounded(16u);
                /* fill all, then perturb a window */
                DTLS_MEMSET(p->dh_Yc, pad, L);
                dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
            }
        }
        break;

    case 6: /* G. In-range sweep */
        /* Sweep a small window with incremental bytes (in-range) */
        if (L) {
            size_t win = 1u + (size_t)dtls_rnd_bounded((uint32_t)((L < 64u) ? L : 64u));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)(L - win + 1u));
            for (size_t i=0;i<win;i++) p->dh_Yc[off+i] = (uint8_t)((off+i) & 0xFFu);
            dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
        }
        break;

    default: /* H. Random valid mix */
        /* Mix length tweak + blob tweak */
        mutate_len_u16(&p->dh_Yc_len, (uint16_t)DTLS_MAX_DH_Y_LEN, 0, 0);
        L = p->dh_Yc_len;
        if (L > (uint16_t)DTLS_MAX_DH_Y_LEN) L = (uint16_t)DTLS_MAX_DH_Y_LEN;
        if (L) {
            if (dtls_rnd_u8() & 1u) dtls_fill_random(p->dh_Yc, L);
            mutate_opaque_blob(p->dh_Yc, L, (uint16_t)DTLS_MAX_DH_Y_LEN);
            dtls_mix_shallow_deep(p->dh_Yc, (size_t)L);
        }
        break;
    }
}

static void mutate_ecdh_client_public(dtls_ecdh_client_public_t *p) {
    if (!p) return;

    /* Note: ec_point_len is uint8_t (0..255), but buffer cap is 512.
       We keep length in-range (0..255) per struct field. */
    mutate_len_u8(&p->ec_point_len, 255, 0);

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    uint16_t L = (uint16_t)p->ec_point_len;
    if (L > 255u) L = 255u;

    switch (cat) {
    case 0: /* A. Canonical form */
        /* Uncompressed EC point is 0x04 || X || Y; make it look like that */
        if (L < 1) { p->ec_point_len = 65; L = 65; }
        if (L > 1) {
            p->ec_point[0] = 0x04;
            dtls_fill_random(p->ec_point + 1, (size_t)(L - 1));
        } else {
            p->ec_point[0] = 0x04;
        }
        /* keep stable with shallow perturbations */
        dtls_mix_shallow_deep(p->ec_point, (size_t)L);
        break;

    case 1: /* B. Boundaries */
        {
            static const uint8_t b[] = {0,1,2,3,5,7,8,15,16,31,32,33,64,65,97,129,255};
            uint8_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
            p->ec_point_len = pick;
            L = (uint16_t)pick;
            if (L) {
                /* boundary patterns; also sometimes set first tag */
                switch (dtls_rnd_bounded(4u)) {
                case 0: DTLS_MEMSET(p->ec_point, 0x00, L); break;
                case 1: DTLS_MEMSET(p->ec_point, 0xFF, L); break;
                case 2: for (uint16_t i=0;i<L;i++) p->ec_point[i]=(uint8_t)i; break;
                default: for (uint16_t i=0;i<L;i++) p->ec_point[i]=(uint8_t)((i&1)?0xAA:0x55); break;
                }
                if (L >= 1 && (dtls_rnd_u8() & 1u)) p->ec_point[0] = 0x04;
                dtls_mix_shallow_deep(p->ec_point, (size_t)L);
            }
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* Classes: compressed(0x02/0x03), uncompressed(0x04), hybrid(0x06/0x07) */
        if (L < 1) { p->ec_point_len = 33; L = 33; }
        {
            static const uint8_t tags[] = {0x02,0x03,0x04,0x06,0x07};
            uint8_t tag = tags[dtls_rnd_bounded((uint32_t)(sizeof(tags)/sizeof(tags[0])))];
            p->ec_point[0] = tag;
            if (L > 1) dtls_fill_random(p->ec_point + 1, (size_t)(L - 1));
            dtls_mix_shallow_deep(p->ec_point, (size_t)L);
        }
        break;

    case 3: /* D. Allowed bitfield/enum/range */
        /* In-range: tag is one byte, rest any bytes. Keep tag from allowed set sometimes. */
        if (L) {
            mutate_opaque_blob(p->ec_point, L, 512);
            if (L >= 1 && (dtls_rnd_u8() & 1u)) {
                static const uint8_t tags[] = {0x02,0x03,0x04,0x06,0x07};
                p->ec_point[0] = tags[dtls_rnd_bounded((uint32_t)(sizeof(tags)/sizeof(tags[0])))];
            }
            /* nibble-level constraint-like tweak */
            uint32_t k = 1u + dtls_rnd_bounded(6u);
            for (uint32_t i=0;i<k;i++) {
                size_t idx = (size_t)dtls_rnd_bounded((uint32_t)L);
                p->ec_point[idx] = (uint8_t)((p->ec_point[idx] & 0xF0u) | (dtls_rnd_u8() & 0x0Fu));
            }
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* Shape: ensure first byte looks like ECPoint tag; rest resembles coordinate halves */
        if (L < 1) { p->ec_point_len = 65; L = 65; }
        {
            uint8_t tag = (dtls_rnd_u8() & 1u) ? 0x04 : (uint8_t)((dtls_rnd_u8() & 1u) ? 0x02 : 0x03);
            p->ec_point[0] = tag;
            if (L > 1) {
                /* put "X" as increasing, "Y" as random (still valid bytes) */
                size_t body = (size_t)(L - 1);
                size_t half = body / 2;
                for (size_t i=0;i<half;i++) p->ec_point[1+i] = (uint8_t)i;
                if (body > half) dtls_fill_random(p->ec_point + 1 + half, body - half);
            }
            dtls_mix_shallow_deep(p->ec_point, (size_t)L);
        }
        break;

    case 5: /* F. Padding/alignment */
        /* Align length to common ECPoint sizes: 33, 65, 97, 129, 161, 193, 225, 255 */
        {
            static const uint8_t sizes[] = {33,65,97,129,161,193,225,255};
            uint8_t pick = sizes[dtls_rnd_bounded((uint32_t)(sizeof(sizes)/sizeof(sizes[0])))];
            p->ec_point_len = pick;
            L = (uint16_t)pick;
            /* pad with a fixed value then perturb */
            if (L) {
                uint8_t pad = (uint8_t)(dtls_rnd_bounded(16u));
                DTLS_MEMSET(p->ec_point, pad, L);
                if (L >= 1) p->ec_point[0] = 0x04;
                dtls_mix_shallow_deep(p->ec_point, (size_t)L);
            }
        }
        break;

    case 6: /* G. In-range sweep */
        if (L) {
            size_t win = 1u + (size_t)dtls_rnd_bounded((uint32_t)((L < 64u) ? L : 64u));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)(L - win + 1u));
            for (size_t i=0;i<win;i++) p->ec_point[off+i] = (uint8_t)((off+i) & 0xFFu);
            if (L >= 1 && (dtls_rnd_u8() & 1u)) p->ec_point[0] = 0x04;
            dtls_mix_shallow_deep(p->ec_point, (size_t)L);
        }
        break;

    default: /* H. Random valid mix */
        mutate_len_u8(&p->ec_point_len, 255, 0);
        L = (uint16_t)p->ec_point_len;
        if (L) {
            if (dtls_rnd_u8() & 1u) dtls_fill_random(p->ec_point, (size_t)L);
            mutate_opaque_blob(p->ec_point, L, 512);
            if (L >= 1 && (dtls_rnd_u8() & 1u)) {
                static const uint8_t tags[] = {0x02,0x03,0x04,0x06,0x07};
                p->ec_point[0] = tags[dtls_rnd_bounded((uint32_t)(sizeof(tags)/sizeof(tags[0])))];
            }
            dtls_mix_shallow_deep(p->ec_point, (size_t)L);
        }
        break;
    }
}

static void mutate_psk_identity(dtls_psk_identity_t *p) {
    if (!p) return;

    mutate_len_u16(&p->identity_len, (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN, 0, 0);

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    uint16_t L = p->identity_len;
    if (L > (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN) L = (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN;

    switch (cat) {
    case 0: /* A. Canonical form */
        /* Canonical: printable ASCII identity */
        if (L == 0) { p->identity_len = 8; L = 8; }
        for (uint16_t i=0;i<L;i++) {
            uint8_t c = (uint8_t)('a' + (dtls_rnd_u8() % 26));
            if (dtls_rnd_u8() & 1u) c = (uint8_t)('0' + (dtls_rnd_u8() % 10));
            p->identity[i] = c;
        }
        dtls_mix_shallow_deep(p->identity, (size_t)L);
        break;

    case 1: /* B. Boundaries */
        {
            static const uint16_t b[] = {0,1,2,3,4,7,8,15,16,31,32,63,64,127,128,255,256};
            uint16_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
            if (pick > (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN) pick = (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN;
            p->identity_len = pick;
            L = pick;
            if (L) {
                /* boundary strings */
                switch (dtls_rnd_bounded(4u)) {
                case 0: DTLS_MEMSET(p->identity, 'A', L); break;
                case 1: DTLS_MEMSET(p->identity, '0', L); break;
                case 2: for (uint16_t i=0;i<L;i++) p->identity[i] = (uint8_t)('a' + (i % 26)); break;
                default: for (uint16_t i=0;i<L;i++) p->identity[i] = (uint8_t)((i&1)?'_':'-'); break;
                }
                dtls_mix_shallow_deep(p->identity, (size_t)L);
            }
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* Classes: ascii-printable / raw-bytes / mostly-zero */
        if (L) {
            uint8_t cls = (uint8_t)dtls_rnd_bounded(3u);
            if (cls == 0) {
                for (uint16_t i=0;i<L;i++) p->identity[i] = (uint8_t)(32u + (dtls_rnd_u8() % 95u));
            } else if (cls == 1) {
                dtls_fill_random(p->identity, L);
            } else {
                DTLS_MEMSET(p->identity, 0x00, L);
                for (uint16_t i=0;i<L;i += (uint16_t)(1u + dtls_rnd_bounded(17u)))
                    p->identity[i] = (uint8_t)(1u + (dtls_rnd_u8() % 0xFEu));
            }
            dtls_mix_shallow_deep(p->identity, (size_t)L);
        }
        break;

    case 3: /* D. Allowed bitfield/enum/range */
        /* Range: bytes 0..255, length 0..cap. Keep "safe printable" set sometimes. */
        if (L) {
            mutate_opaque_blob(p->identity, L, (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN);
            if (dtls_rnd_u8() & 1u) {
                for (uint16_t i=0;i<L;i++) {
                    uint8_t c = p->identity[i];
                    /* map into a conservative allowed range: [0-9A-Za-z_-] */
                    if (c < '0') c = '0';
                    if (c > 'z') c = 'z';
                    if ((c > '9' && c < 'A')) c = 'A';
                    if ((c > 'Z' && c < 'a')) c = 'a';
                    p->identity[i] = c;
                }
            }
            dtls_mix_shallow_deep(p->identity, (size_t)L);
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* Shape: prefix-like forms "id=", "user:", "psk/" while staying bytes */
        if (L == 0) { p->identity_len = 6; L = 6; }
        {
            static const char *pref[] = {"id=", "user:", "psk/", "dev-", "cli_"};
            const char *s = pref[dtls_rnd_bounded((uint32_t)(sizeof(pref)/sizeof(pref[0])))];
            uint16_t si = 0;
            while (s[si] && si < L) { p->identity[si] = (uint8_t)s[si]; si++; }
            for (uint16_t i=si;i<L;i++) p->identity[i] = (uint8_t)(32u + (dtls_rnd_u8() % 95u));
            dtls_mix_shallow_deep(p->identity, (size_t)L);
        }
        break;

    case 5: /* F. Padding/alignment */
        /* Align length to 4/8/16 and pad tail with a chosen byte */
        {
            uint16_t base = L;
            uint16_t aligned = base;
            switch (dtls_rnd_bounded(3u)) {
            case 0: aligned = (uint16_t)((base + 3u) & ~3u); break;
            case 1: aligned = (uint16_t)((base + 7u) & ~7u); break;
            default:aligned = (uint16_t)((base + 15u) & ~15u); break;
            }
            if (aligned > (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN) aligned = (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN;
            p->identity_len = aligned;
            L = aligned;
            if (L) {
                uint8_t pad = (uint8_t)dtls_rnd_bounded(16u);
                DTLS_MEMSET(p->identity, pad, L);
                dtls_mix_shallow_deep(p->identity, (size_t)L);
            }
        }
        break;

    case 6: /* G. In-range sweep */
        if (L) {
            size_t win = 1u + (size_t)dtls_rnd_bounded((uint32_t)((L < 64u) ? L : 64u));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)(L - win + 1u));
            for (size_t i=0;i<win;i++) p->identity[off+i] = (uint8_t)('a' + ((off+i) % 26u));
            dtls_mix_shallow_deep(p->identity, (size_t)L);
        }
        break;

    default: /* H. Random valid mix */
        mutate_len_u16(&p->identity_len, (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN, 0, 0);
        L = p->identity_len;
        if (L > (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN) L = (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN;
        if (L) {
            if (dtls_rnd_u8() & 1u) dtls_fill_random(p->identity, L);
            mutate_opaque_blob(p->identity, L, (uint16_t)DTLS_MAX_PSK_IDENTITY_LEN);
            if (dtls_rnd_u8() & 1u) {
                for (uint16_t i=0;i<L;i++) p->identity[i] = (uint8_t)(32u + (dtls_rnd_u8() % 95u));
            }
            dtls_mix_shallow_deep(p->identity, (size_t)L);
        }
        break;
    }
}


static void mutate_encrypted_premaster_secret(dtls_encrypted_premaster_secret_t *pms) {
    if (!pms) return;

    /* length is the main local semantic knob; keep strictly in-range */
    mutate_len_u16(&pms->enc_pms_len, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN, 0, 0);

    uint8_t  cat = (uint8_t)dtls_rnd_bounded(8u);
    uint16_t L   = pms->enc_pms_len;
    if (L > (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN) L = (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN;

    switch (cat) {
    case 0: /* A. Canonical form */
        /* Make it look like a typical RSA ciphertext blob: non-zero-ish, high entropy */
        if (L == 0) { pms->enc_pms_len = 128; L = 128; }
        dtls_fill_random(pms->enc_pms, L);
        /* light normalization then mix */
        mutate_opaque_blob(pms->enc_pms, L, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN);
        dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
        break;

    case 1: /* B. Boundaries */
        {
            static const uint16_t b[] = {0,1,2,3,7,8,15,16,31,32,47,48,63,64,
                                         95,96,127,128,191,192,255,256,
                                         (uint16_t)(DTLS_MAX_RSA_ENC_PMS_LEN-1),
                                         (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN};
            uint16_t pick = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
            if (pick > (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN) pick = (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN;
            pms->enc_pms_len = pick;
            L = pick;

            if (L) {
                switch (dtls_rnd_bounded(4u)) {
                case 0: DTLS_MEMSET(pms->enc_pms, 0x00, L); break;
                case 1: DTLS_MEMSET(pms->enc_pms, 0xFF, L); break;
                case 2: for (uint16_t i=0;i<L;i++) pms->enc_pms[i] = (uint8_t)i; break;
                default: for (uint16_t i=0;i<L;i++) pms->enc_pms[i] = (uint8_t)((i&1)?0xAA:0x55); break;
                }
                dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
            }
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* Classes: small/medium/large ciphertext sizes + different entropy profiles */
        {
            uint16_t pick;
            uint8_t cls = (uint8_t)dtls_rnd_bounded(3u);
            if (cls == 0) pick = (uint16_t)(32u + dtls_rnd_bounded(97u));        /* 32..128 */
            else if (cls == 1) pick = (uint16_t)(129u + dtls_rnd_bounded(128u)); /* 129..256 */
            else pick = (uint16_t)(257u + dtls_rnd_bounded((uint32_t)(DTLS_MAX_RSA_ENC_PMS_LEN-256u))); /* 257..cap */
            if (pick > (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN) pick = (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN;
            pms->enc_pms_len = pick;
            L = pick;

            if (L) {
                uint8_t prof = (uint8_t)dtls_rnd_bounded(3u);
                if (prof == 0) {
                    dtls_fill_random(pms->enc_pms, L);
                } else if (prof == 1) {
                    /* sparse non-zeros */
                    DTLS_MEMSET(pms->enc_pms, 0x00, L);
                    for (uint16_t i=0;i<L;i += (uint16_t)(1u + dtls_rnd_bounded(17u)))
                        pms->enc_pms[i] = (uint8_t)(1u + (dtls_rnd_u8() % 0xFEu));
                } else {
                    /* structured ramp with jitter */
                    for (uint16_t i=0;i<L;i++) pms->enc_pms[i] = (uint8_t)(i ^ dtls_rnd_u8());
                }
                dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
            }
        }
        break;

    case 3: /* D. Allowed bitfield/enum/range */
        /* Only constraints here are: length in-range, bytes are 0..255. Keep in-range but do nibble edits. */
        if (L) {
            mutate_opaque_blob(pms->enc_pms, L, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN);
            uint32_t k = 1u + dtls_rnd_bounded(10u);
            for (uint32_t i=0;i<k;i++) {
                size_t idx = (size_t)dtls_rnd_bounded((uint32_t)L);
                uint8_t b = pms->enc_pms[idx];
                if (dtls_rnd_u8() & 1u) b = (uint8_t)((b & 0xF0u) | (dtls_rnd_u8() & 0x0Fu));
                else b = (uint8_t)(((dtls_rnd_u8() & 0x0Fu) << 4) | (b & 0x0Fu));
                pms->enc_pms[idx] = b;
            }
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* Emulate RSA ciphertext "shape" knobs: leading 0x00, leading 0xFF, or high-bit set. */
        if (L == 0) { pms->enc_pms_len = 128; L = 128; }
        dtls_fill_random(pms->enc_pms, L);
        {
            uint8_t shape = (uint8_t)dtls_rnd_bounded(3u);
            if (shape == 0) pms->enc_pms[0] = 0x00;
            else if (shape == 1) pms->enc_pms[0] = 0xFF;
            else pms->enc_pms[0] = (uint8_t)(pms->enc_pms[0] | 0x80u);
        }
        mutate_opaque_blob(pms->enc_pms, L, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN);
        dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
        break;

    case 5: /* F. Padding/alignment */
        /* Align to 8/16 boundaries (common for RSA sizes), pad tail with a constant, then perturb */
        {
            uint16_t base = L;
            uint16_t aligned = base;
            if (dtls_rnd_u8() & 1u) aligned = (uint16_t)((base + 7u)  & ~7u);
            else                    aligned = (uint16_t)((base + 15u) & ~15u);
            if (aligned > (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN) aligned = (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN;
            pms->enc_pms_len = aligned;
            L = aligned;

            if (L) {
                uint8_t pad = (uint8_t)dtls_rnd_bounded(256u);
                DTLS_MEMSET(pms->enc_pms, pad, L);
                /* perturb a window so it doesn't collapse */
                mutate_opaque_blob(pms->enc_pms, L, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN);
                dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
            }
        }
        break;

    case 6: /* G. In-range sweep */
        /* Sweep a small window with incrementing bytes (still valid ciphertext bytes) */
        if (L) {
            size_t win = 1u + (size_t)dtls_rnd_bounded((uint32_t)((L < 128u) ? L : 128u));
            size_t off = (size_t)dtls_rnd_bounded((uint32_t)(L - win + 1u));
            for (size_t i=0;i<win;i++) pms->enc_pms[off+i] = (uint8_t)((off+i) & 0xFFu);
            dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
        }
        break;

    default: /* H. Random valid mix */
        /* Mix length tweak + random fill + blob mutations */
        mutate_len_u16(&pms->enc_pms_len, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN, 0, 0);
        L = pms->enc_pms_len;
        if (L > (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN) L = (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN;
        if (L) {
            if (dtls_rnd_u8() & 1u) dtls_fill_random(pms->enc_pms, L);
            mutate_opaque_blob(pms->enc_pms, L, (uint16_t)DTLS_MAX_RSA_ENC_PMS_LEN);
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(pms->enc_pms, (size_t)L);
        }
        break;
    }
}


/* =========================
 * Top-level mutator: ClientKeyExchange body
 * ========================= */

void mutate_client_key_exchange_body(dtls_client_key_exchange_body_t *cke) {
    if (!cke) return;

    /* upper-layer choice: sometimes switch kx_alg (diversity) */
    if (dtls_rnd_u8() & 1u) {
        static const dtls_kx_alg_t kxs[] = {
            KX_RSA,
            KX_DH_ANON, KX_DHE_DSS, KX_DHE_RSA, KX_DH_DSS, KX_DH_RSA,
            KX_ECDH_ECDSA, KX_ECDH_RSA, KX_ECDH_ANON,
            KX_ECDHE_ECDSA, KX_ECDHE_RSA,
            KX_PSK, KX_DHE_PSK, KX_RSA_PSK, KX_ECDHE_PSK
        };
        cke->kx_alg = kxs[dtls_rnd_bounded((uint32_t)(sizeof(kxs)/sizeof(kxs[0])))];
    }

    /* dispatch: reuse base mutators for repeated components */
    switch (cke->kx_alg) {
    case KX_RSA:
        mutate_encrypted_premaster_secret(&cke->u.rsa.enc_pms);
        break;

    case KX_DH_ANON:
    case KX_DHE_DSS:
    case KX_DHE_RSA:
    case KX_DH_DSS:
    case KX_DH_RSA:
        mutate_client_dh_public(&cke->u.dh.dh_pub);
        break;

    case KX_ECDH_ECDSA:
    case KX_ECDH_RSA:
    case KX_ECDH_ANON:
    case KX_ECDHE_ECDSA:
    case KX_ECDHE_RSA:
        mutate_ecdh_client_public(&cke->u.ecdh.ecdh_pub);
        break;

    case KX_PSK:
        mutate_psk_identity(&cke->u.psk.psk);
        break;

    case KX_DHE_PSK:
        mutate_psk_identity(&cke->u.dhe_psk.psk);
        mutate_client_dh_public(&cke->u.dhe_psk.dh_pub);
        break;

    case KX_RSA_PSK:
        mutate_psk_identity(&cke->u.rsa_psk.psk);
        mutate_encrypted_premaster_secret(&cke->u.rsa_psk.enc_pms);
        break;

    case KX_ECDHE_PSK:
        mutate_psk_identity(&cke->u.ecdhe_psk.psk);
        mutate_ecdh_client_public(&cke->u.ecdhe_psk.ecdh_pub);
        break;

    default:
        /* unknown: perturb whichever union arm is "safe" — use psk identity as generic blob */
        mutate_psk_identity(&cke->u.psk.psk);
        break;
    }

    /* global randomized perturbation to avoid pattern collapse */
    if (dtls_rnd_u8() & 1u) {
        /* light touch across one representative buffer depending on kx */
        switch (cke->kx_alg) {
        case KX_RSA:
            dtls_mix_shallow_deep(cke->u.rsa.enc_pms.enc_pms, (size_t)cke->u.rsa.enc_pms.enc_pms_len);
            break;
        case KX_PSK:
            dtls_mix_shallow_deep(cke->u.psk.psk.identity, (size_t)cke->u.psk.psk.identity_len);
            break;
        default:
            break;
        }
    }
}


void mutate_client_key_exchange(dtls_packet_t *pkts, size_t n){
    for (size_t i = 0; i < n; i++)
    {
        if(&pkts[i].payload.handshake.body.client_key_exchange){
            mutate_client_key_exchange_body(&pkts[i].payload.handshake.body.client_key_exchange);
        }
    }
    
    
}


/* Finished.verify_data is fixed-length (DTLS_VERIFY_DATA_LEN = 12) but value is not fixed.
 * It depends on the handshake transcript, so it is mutable for fuzzing.
 */

static void mutate_finished_verify_data_bytes(uint8_t vd[DTLS_VERIFY_DATA_LEN]) {
    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    switch (cat) {
    case 0: /* A. Canonical form: high-entropy PRF output-like */
        dtls_fill_random(vd, DTLS_VERIFY_DATA_LEN);
        if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        break;

    case 1: /* B. Boundaries: all-zeros/all-ones/alternating/near-uniform */
        switch (dtls_rnd_bounded(5u)) {
        case 0: DTLS_MEMSET(vd, 0x00, DTLS_VERIFY_DATA_LEN); break;
        case 1: DTLS_MEMSET(vd, 0xFF, DTLS_VERIFY_DATA_LEN); break;
        case 2:
            for (uint8_t i = 0; i < DTLS_VERIFY_DATA_LEN; i++) vd[i] = (uint8_t)((i & 1u) ? 0xAAu : 0x55u);
            break;
        case 3: {
            uint8_t b = dtls_rnd_u8();
            DTLS_MEMSET(vd, b, DTLS_VERIFY_DATA_LEN);
            if (dtls_rnd_u8() & 1u) vd[dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN)] ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
        } break;
        default:
            for (uint8_t i = 0; i < DTLS_VERIFY_DATA_LEN; i++) vd[i] = (uint8_t)i;
            break;
        }
        if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        break;

    case 2: /* C. Equivalence-class alternatives: reverse/rotate/xor masks */
        if (dtls_rnd_u8() & 1u) {
            for (uint8_t i = 0; i < (DTLS_VERIFY_DATA_LEN / 2u); i++) {
                uint8_t t = vd[i];
                vd[i] = vd[DTLS_VERIFY_DATA_LEN - 1u - i];
                vd[DTLS_VERIFY_DATA_LEN - 1u - i] = t;
            }
        }
        if (dtls_rnd_u8() & 1u) {
            uint8_t tmp[DTLS_VERIFY_DATA_LEN];
            uint8_t r = (uint8_t)dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN);
            for (uint8_t i = 0; i < DTLS_VERIFY_DATA_LEN; i++) tmp[i] = vd[(uint8_t)((i + r) % DTLS_VERIFY_DATA_LEN)];
            DTLS_MEMCPY(vd, tmp, DTLS_VERIFY_DATA_LEN);
        }
        if (dtls_rnd_u8() & 1u) {
            static const uint8_t masks[] = {0x00u,0xFFu,0x55u,0xAAu,0x0Fu,0xF0u};
            uint8_t m = masks[dtls_rnd_bounded((uint32_t)(sizeof(masks)/sizeof(masks[0])))];
            for (uint8_t i = 0; i < DTLS_VERIFY_DATA_LEN; i++) vd[i] ^= m;
        }
        if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        break;

    case 3: /* D. Allowed range: bytes are 0..255; do bit-local edits */
        {
            uint8_t k = (uint8_t)(1u + dtls_rnd_bounded(8u));
            for (uint8_t i = 0; i < k; i++) {
                uint8_t idx = (uint8_t)dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN);
                uint8_t b = vd[idx];
                if (dtls_rnd_u8() & 1u) b ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
                else b = (uint8_t)((b & 0xF0u) | (dtls_rnd_u8() & 0x0Fu));
                vd[idx] = b;
            }
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        }
        break;

    case 4: /* E. Encoding-shape variant: treat as 3x u32-ish blocks and perturb */
        {
            /* Without assuming alignment, mutate by 4-byte stripes */
            for (uint8_t off = 0; off < DTLS_VERIFY_DATA_LEN; off = (uint8_t)(off + 4u)) {
                if (dtls_rnd_u8() & 1u) {
                    /* endian-ish swap within the 4-byte stripe */
                    uint8_t a = vd[off + 0u], b = vd[off + 1u], c = vd[off + 2u], d = vd[off + 3u];
                    if (dtls_rnd_u8() & 1u) { vd[off+0u]=d; vd[off+1u]=c; vd[off+2u]=b; vd[off+3u]=a; }
                    else { vd[off+0u]=b; vd[off+1u]=a; vd[off+2u]=d; vd[off+3u]=c; }
                } else {
                    /* arithmetic-ish tweak */
                    vd[off + (dtls_rnd_u8() & 3u)] = (uint8_t)(vd[off + (dtls_rnd_u8() & 3u)] + (uint8_t)(1u + (dtls_rnd_u8() & 31u)));
                }
            }
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        }
        break;

    case 5: /* F. Padding/alignment: enforce repeated 4-byte pattern then perturb */
        {
            uint8_t pat[4];
            dtls_fill_random(pat, 4);
            for (uint8_t i = 0; i < DTLS_VERIFY_DATA_LEN; i++) vd[i] = pat[i & 3u];
            /* Small perturb so it doesn't collapse */
            {
                uint8_t flips = (uint8_t)(1u + dtls_rnd_bounded(6u));
                for (uint8_t j = 0; j < flips; j++) {
                    uint8_t idx = (uint8_t)dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN);
                    vd[idx] ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
                }
            }
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        }
        break;

    case 6: /* G. In-range sweep: sweep a window with incrementing bytes */
        {
            uint8_t win = (uint8_t)(1u + dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN));
            uint8_t off = (uint8_t)dtls_rnd_bounded((uint32_t)(DTLS_VERIFY_DATA_LEN - win + 1u));
            for (uint8_t i = 0; i < win; i++) vd[off + i] = (uint8_t)((off + i + (dtls_rnd_u8() & 15u)) & 0xFFu);
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        }
        break;

    default: /* H. Random valid mix: combine shallow + deep edits */
        if (dtls_rnd_u8() & 1u) dtls_fill_random(vd, DTLS_VERIFY_DATA_LEN);
        {
            /* shallow edits */
            uint8_t k = (uint8_t)(1u + dtls_rnd_bounded(10u));
            for (uint8_t i = 0; i < k; i++) {
                uint8_t idx = (uint8_t)dtls_rnd_bounded(DTLS_VERIFY_DATA_LEN);
                vd[idx] = (uint8_t)(vd[idx] ^ dtls_rnd_u8());
            }
        }
        /* deep mix */
        dtls_mix_shallow_deep(vd, DTLS_VERIFY_DATA_LEN);
        break;
    }
}

void mutate_finished_verify_data(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;

        /* TLS/DTLS HandshakeType: Finished = 20 */
        if (p->payload.handshake.handshake_header.msg_type != 20u) continue;

        mutate_finished_verify_data_bytes(p->payload.handshake.body.finished.verify_data);
    }
}


/* CertificateVerify.alg is not fixed: it depends on the signing cert/key and chosen scheme.
 * It is always present in TLS/DTLS 1.2 CertificateVerify, so no add/delete/repeat helpers.
 */

static uint8_t dtls_is_known_hash(uint8_t h) {
    return (h == HASH_NONE || h == HASH_MD5 || h == HASH_SHA1 || h == HASH_SHA224 ||
            h == HASH_SHA256 || h == HASH_SHA384 || h == HASH_SHA512);
}

static uint8_t dtls_is_known_sig(uint8_t s) {
    return (s == SIG_ANON || s == SIG_RSA || s == SIG_DSA || s == SIG_ECDSA);
}

static void dtls_pick_hash_sig_pair(uint8_t *out_hash, uint8_t *out_sig) {
    /* Common TLS 1.2 hash/signature pairs.
     * (We keep them broad to support many stacks; not all are acceptable in every context.)
     */
    static const uint8_t pairs[][2] = {
        { HASH_SHA256, SIG_RSA   },
        { HASH_SHA384, SIG_RSA   },
        { HASH_SHA1,   SIG_RSA   },
        { HASH_SHA256, SIG_ECDSA },
        { HASH_SHA384, SIG_ECDSA },
        { HASH_SHA1,   SIG_ECDSA },
        { HASH_SHA256, SIG_DSA   },
        { HASH_SHA1,   SIG_DSA   },
    };
    uint32_t idx = dtls_rnd_bounded((uint32_t)(sizeof(pairs) / sizeof(pairs[0])));
    *out_hash = pairs[idx][0];
    *out_sig  = pairs[idx][1];
}

static void mutate_certificate_verify_alg_pair(dtls_signature_and_hash_t *alg) {
    if (!alg) return;

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    switch (cat) {
    case 0: /* A. Canonical form: choose a common pair */
        dtls_pick_hash_sig_pair(&alg->hash_algorithm, &alg->signature_algorithm);
        break;

    case 1: /* B. Boundaries: lowest/highest-ish known enums; plus edge nudges */
        if (dtls_rnd_u8() & 1u) alg->hash_algorithm = HASH_NONE;
        else alg->hash_algorithm = HASH_SHA512;

        if (dtls_rnd_u8() & 1u) alg->signature_algorithm = SIG_ANON;
        else alg->signature_algorithm = SIG_ECDSA;

        if (dtls_rnd_u8() & 1u) {
            /* small in-enum bump */
            if (dtls_is_known_hash(alg->hash_algorithm) && (dtls_rnd_u8() & 1u)) {
                alg->hash_algorithm = (uint8_t)((alg->hash_algorithm + 1u) & 0xFFu);
                if (!dtls_is_known_hash(alg->hash_algorithm)) alg->hash_algorithm = HASH_SHA256;
            }
            if (dtls_is_known_sig(alg->signature_algorithm) && (dtls_rnd_u8() & 1u)) {
                alg->signature_algorithm = (uint8_t)((alg->signature_algorithm + 1u) & 0xFFu);
                if (!dtls_is_known_sig(alg->signature_algorithm)) alg->signature_algorithm = SIG_RSA;
            }
        }
        break;

    case 2: /* C. Equivalence-class alternatives: keep sig, swap hash-family; or keep hash, swap sig-family */
        if (dtls_rnd_u8() & 1u) {
            /* preserve signature, swap among common hashes */
            switch (dtls_rnd_bounded(5u)) {
            case 0: alg->hash_algorithm = HASH_SHA1; break;
            case 1: alg->hash_algorithm = HASH_SHA224; break;
            case 2: alg->hash_algorithm = HASH_SHA256; break;
            case 3: alg->hash_algorithm = HASH_SHA384; break;
            default: alg->hash_algorithm = HASH_SHA512; break;
            }
            if (!dtls_is_known_sig(alg->signature_algorithm)) alg->signature_algorithm = SIG_RSA;
        } else {
            /* preserve hash, swap signature among typical ones */
            switch (dtls_rnd_bounded(3u)) {
            case 0: alg->signature_algorithm = SIG_RSA; break;
            case 1: alg->signature_algorithm = SIG_ECDSA; break;
            default: alg->signature_algorithm = SIG_DSA; break;
            }
            if (!dtls_is_known_hash(alg->hash_algorithm)) alg->hash_algorithm = HASH_SHA256;
        }
        break;

    case 3: /* D. Allowed enum/range: choose from known enums only, but vary widely */
        {
            static const uint8_t hashes[] = {HASH_SHA1,HASH_SHA224,HASH_SHA256,HASH_SHA384,HASH_SHA512};
            static const uint8_t sigs[]   = {SIG_RSA,SIG_DSA,SIG_ECDSA};
            alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)(sizeof(hashes)/sizeof(hashes[0])))];
            alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)(sizeof(sigs)/sizeof(sigs[0])))];
        }
        break;

    case 4: /* E. Encoding-shape variant: treat as 2 bytes; swap/order and bit-twiddle then clamp back */
        {
            uint8_t h = alg->hash_algorithm;
            uint8_t s = alg->signature_algorithm;

            if (dtls_rnd_u8() & 1u) { uint8_t t = h; h = s; s = t; } /* swap bytes */
            if (dtls_rnd_u8() & 1u) h ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
            if (dtls_rnd_u8() & 1u) s ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));

            /* clamp to known where possible to stay "valid-ish" */
            if (!dtls_is_known_hash(h)) {
                uint8_t nh, ns;
                dtls_pick_hash_sig_pair(&nh, &ns);
                h = nh;
            }
            if (!dtls_is_known_sig(s)) {
                uint8_t nh, ns;
                dtls_pick_hash_sig_pair(&nh, &ns);
                s = ns;
            }

            alg->hash_algorithm = h;
            alg->signature_algorithm = s;
        }
        break;

    case 5: /* F. Padding/alignment: align-ish to preferred pairs, then minor perturb */
        dtls_pick_hash_sig_pair(&alg->hash_algorithm, &alg->signature_algorithm);
        if (dtls_rnd_u8() & 1u) {
            /* minor perturb but keep within known enums */
            static const uint8_t hashes[] = {HASH_SHA1,HASH_SHA224,HASH_SHA256,HASH_SHA384,HASH_SHA512};
            alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)(sizeof(hashes)/sizeof(hashes[0])))];
        }
        break;

    case 6: /* G. In-range sweep: sweep through hash choices; keep signature stable (or vice versa) */
        if (dtls_rnd_u8() & 1u) {
            static const uint8_t hashes[] = {HASH_SHA1,HASH_SHA224,HASH_SHA256,HASH_SHA384,HASH_SHA512};
            uint32_t cur = 0;
            for (uint32_t i = 0; i < (uint32_t)(sizeof(hashes)/sizeof(hashes[0])); i++) {
                if (alg->hash_algorithm == hashes[i]) { cur = i; break; }
            }
            alg->hash_algorithm = hashes[(cur + 1u + dtls_rnd_bounded(2u)) % (uint32_t)(sizeof(hashes)/sizeof(hashes[0]))];
            if (!dtls_is_known_sig(alg->signature_algorithm)) alg->signature_algorithm = SIG_RSA;
        } else {
            static const uint8_t sigs[] = {SIG_RSA,SIG_DSA,SIG_ECDSA};
            uint32_t cur = 0;
            for (uint32_t i = 0; i < (uint32_t)(sizeof(sigs)/sizeof(sigs[0])); i++) {
                if (alg->signature_algorithm == sigs[i]) { cur = i; break; }
            }
            alg->signature_algorithm = sigs[(cur + 1u + dtls_rnd_bounded(2u)) % (uint32_t)(sizeof(sigs)/sizeof(sigs[0]))];
            if (!dtls_is_known_hash(alg->hash_algorithm)) alg->hash_algorithm = HASH_SHA256;
        }
        break;

    default: /* H. Random valid mix: combine shallow flips + re-canonicalize */
        {
            uint8_t h = alg->hash_algorithm;
            uint8_t s = alg->signature_algorithm;

            /* shallow */
            if (dtls_rnd_u8() & 1u) h = (uint8_t)(h + (dtls_rnd_u8() & 7u));
            if (dtls_rnd_u8() & 1u) s = (uint8_t)(s ^ (dtls_rnd_u8() & 3u));

            /* deep: occasionally jump to canonical */
            if (dtls_rnd_u8() & 1u) {
                dtls_pick_hash_sig_pair(&h, &s);
            } else {
                if (!dtls_is_known_hash(h)) h = HASH_SHA256;
                if (!dtls_is_known_sig(s))  s = SIG_RSA;
            }

            alg->hash_algorithm = h;
            alg->signature_algorithm = s;
        }
        break;
    }

    /* Extra randomized perturbation to avoid collapse, while keeping "known" space */
    if (dtls_rnd_u8() & 1u) {
        if (dtls_rnd_u8() & 1u) {
            /* nudge hash among known set */
            static const uint8_t hashes[] = {HASH_SHA1,HASH_SHA224,HASH_SHA256,HASH_SHA384,HASH_SHA512};
            alg->hash_algorithm = hashes[dtls_rnd_bounded((uint32_t)(sizeof(hashes)/sizeof(hashes[0])))];
        }
        if (dtls_rnd_u8() & 1u) {
            /* nudge sig among known set */
            static const uint8_t sigs[] = {SIG_RSA,SIG_DSA,SIG_ECDSA};
            alg->signature_algorithm = sigs[dtls_rnd_bounded((uint32_t)(sizeof(sigs)/sizeof(sigs[0])))];
        }
    }
}

void mutate_certificate_verify_alg(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;

        /* TLS/DTLS HandshakeType: CertificateVerify = 15 */
        if (p->payload.handshake.handshake_header.msg_type != 15u) continue;

        mutate_certificate_verify_alg_pair(&p->payload.handshake.body.certificate_verify.alg);
    }
}



/* CertificateVerify.signature is not fixed: it is computed over the handshake transcript.
 * It is always present in TLS/DTLS 1.2 CertificateVerify, so no add/delete/repeat helpers.
 */

static void mutate_certificate_verify_signature_body(dtls_certificate_verify_body_t *cv) {
    if (!cv) return;

    /* Keep length within struct capacity (DTLS_MAX_SIGNATURE_LEN == 512) */
    uint16_t *lenp = &cv->signature_len;
    uint8_t  *buf  = cv->signature;

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);

    switch (cat) {
    case 0: /* A. Canonical form: keep typical DER-ish shape when possible */
        /* typical ECDSA/RSA signatures are non-empty */
        if (*lenp == 0) *lenp = (uint16_t)(16u + dtls_rnd_bounded(96u));
        if (*lenp > DTLS_MAX_SIGNATURE_LEN) *lenp = DTLS_MAX_SIGNATURE_LEN;

        /* If ECDSA: sometimes craft a DER SEQUENCE header (0x30) */
        if ((dtls_rnd_u8() & 1u) && cv->alg.signature_algorithm == SIG_ECDSA && *lenp >= 8) {
            buf[0] = 0x30;
            buf[1] = (uint8_t)((*lenp - 2) & 0xFFu);
            /* two INTEGERs (very rough but keeps "canonical-ish" bytes) */
            buf[2] = 0x02;
            buf[3] = (uint8_t)(((*lenp - 6) / 2) & 0xFFu);
            buf[4] = (buf[4] ? buf[4] : 0x01);
            buf[4] |= 0x01; /* non-zero */
            /* rest random-ish */
            mutate_opaque_blob(&buf[5], (uint16_t)(*lenp - 5), (uint16_t)(*lenp - 5));
        } else {
            /* Otherwise keep content but diversify */
            mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
        }

        if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        break;

    case 1: /* B. Boundaries: 0, 1, small, typical, max */
        {
            static const uint16_t lens[] = {0u, 1u, 2u, 8u, 16u, 32u, 64u, 128u, 256u, 512u};
            *lenp = lens[dtls_rnd_bounded((uint32_t)(sizeof(lens)/sizeof(lens[0])))];
            if (*lenp > DTLS_MAX_SIGNATURE_LEN) *lenp = DTLS_MAX_SIGNATURE_LEN;

            if (*lenp == 0) {
                /* nothing to fill */
            } else if (*lenp <= 8) {
                /* short: deterministic-ish pattern */
                for (uint16_t i = 0; i < *lenp; i++) buf[i] = (uint8_t)(i ^ 0xA5u);
            } else if (*lenp == DTLS_MAX_SIGNATURE_LEN) {
                dtls_fill_random(buf, *lenp);
            } else {
                mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
            }

            if (*lenp && (dtls_rnd_u8() & 1u)) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        }
        break;

    case 2: /* C. Equivalence-class alternatives: RSA-like vs ECDSA-like shapes */
        /* Decide target "shape" based on alg, but allow toggling to explore parser paths */
        if (dtls_rnd_u8() & 1u) {
            /* ECDSA-like DER: 0x30 ... 0x02 ... 0x02 ... */
            uint16_t L = (uint16_t)(8u + dtls_rnd_bounded(120u));
            if (L > DTLS_MAX_SIGNATURE_LEN) L = DTLS_MAX_SIGNATURE_LEN;
            *lenp = L;
            if (*lenp >= 8) {
                buf[0] = 0x30;
                buf[1] = (uint8_t)((*lenp - 2) & 0xFFu);
                buf[2] = 0x02;
                buf[3] = (uint8_t)(((*lenp - 6) / 2) & 0xFFu);
                buf[4] = (uint8_t)(1u + (dtls_rnd_u8() & 0x7Fu));
                buf[5] = 0x02;
                buf[6] = (uint8_t)((*lenp - 7) & 0xFFu);
                mutate_opaque_blob(&buf[7], (uint16_t)(*lenp - 7), (uint16_t)(*lenp - 7));
            } else if (*lenp) {
                dtls_fill_random(buf, *lenp);
            }
        } else {
            /* RSA-like: opaque random of common sizes (128/256) */
            uint16_t L = (dtls_rnd_u8() & 1u) ? 128u : 256u;
            if (dtls_rnd_u8() & 1u) L = (uint16_t)(32u + dtls_rnd_bounded(256u));
            if (L > DTLS_MAX_SIGNATURE_LEN) L = DTLS_MAX_SIGNATURE_LEN;
            *lenp = L;
            dtls_fill_random(buf, *lenp);
            if (*lenp && (dtls_rnd_u8() & 1u)) mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
        }
        if (*lenp && (dtls_rnd_u8() & 1u)) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        break;

    case 3: /* D. Allowed range: keep length in 1..512 and keep "reasonable" content */
        if (*lenp == 0) *lenp = (uint16_t)(8u + dtls_rnd_bounded(120u));
        if (*lenp > DTLS_MAX_SIGNATURE_LEN) *lenp = DTLS_MAX_SIGNATURE_LEN;

        /* Keep within "known-good" byte space occasionally: avoid all-zeros */
        mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
        if (*lenp && (dtls_rnd_u8() & 1u)) {
            /* ensure not all zeros */
            uint16_t pos = (uint16_t)dtls_rnd_bounded(*lenp);
            buf[pos] ^= 0x01u;
        }
        if (*lenp && (dtls_rnd_u8() & 1u)) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        break;

    case 4: /* E. Encoding-shape variant: endianness-like / block reordering / prefixing */
        if (*lenp == 0) *lenp = (uint16_t)(16u + dtls_rnd_bounded(96u));
        if (*lenp > DTLS_MAX_SIGNATURE_LEN) *lenp = DTLS_MAX_SIGNATURE_LEN;

        /* Variant 1: reverse */
        if ((dtls_rnd_u8() & 1u) && *lenp >= 2) {
            for (uint16_t i = 0; i < (uint16_t)(*lenp / 2); i++) {
                uint8_t t = buf[i];
                buf[i] = buf[*lenp - 1u - i];
                buf[*lenp - 1u - i] = t;
            }
        }
        /* Variant 2: rotate */
        if ((dtls_rnd_u8() & 1u) && *lenp >= 4) {
            uint16_t k = (uint16_t)(1u + dtls_rnd_bounded((uint32_t)(*lenp - 1u)));
            /* simple in-place rotate using swaps */
            for (uint16_t r = 0; r < k; r++) {
                uint8_t last = buf[*lenp - 1u];
                for (uint16_t j = (uint16_t)(*lenp - 1u); j > 0; j--) buf[j] = buf[j - 1u];
                buf[0] = last;
            }
        }
        /* Variant 3: mutate then re-canonicalize header sometimes */
        mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
        if ((dtls_rnd_u8() & 1u) && cv->alg.signature_algorithm == SIG_ECDSA && *lenp >= 2) {
            buf[0] = 0x30;
            buf[1] = (uint8_t)((*lenp - 2) & 0xFFu);
        }
        if (*lenp && (dtls_rnd_u8() & 1u)) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        break;

    case 5: /* F. Padding/alignment: add or strip trailing zeros / 0xFF within bounds */
        {
            uint16_t L = *lenp;
            if (L == 0) L = (uint16_t)(16u + dtls_rnd_bounded(96u));
            if (L > DTLS_MAX_SIGNATURE_LEN) L = DTLS_MAX_SIGNATURE_LEN;

            /* adjust length slightly to simulate padding effects */
            if (dtls_rnd_u8() & 1u) {
                uint16_t delta = (uint16_t)dtls_rnd_bounded(16u);
                if ((dtls_rnd_u8() & 1u) && (L + delta) <= DTLS_MAX_SIGNATURE_LEN) L = (uint16_t)(L + delta);
                else if (L > delta) L = (uint16_t)(L - delta);
                if (L == 0) L = 1;
            }
            *lenp = L;

            /* fill base, then pad tail */
            mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);
            if (*lenp) {
                uint16_t pad_n = (uint16_t)dtls_rnd_bounded(16u);
                if (pad_n > *lenp) pad_n = *lenp;
                uint8_t pad_byte = (dtls_rnd_u8() & 1u) ? 0x00u : 0xFFu;
                for (uint16_t i = 0; i < pad_n; i++) buf[*lenp - 1u - i] = pad_byte;
            }

            if (*lenp && (dtls_rnd_u8() & 1u)) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
        }
        break;

    case 6: /* G. In-range sweep: walk length across a band; mutate a sliding window */
        {
            uint16_t base = *lenp;
            if (base == 0) base = 64u;
            if (base > DTLS_MAX_SIGNATURE_LEN) base = DTLS_MAX_SIGNATURE_LEN;

            /* sweep within [8..512] */
            uint16_t next = base;
            uint16_t step = (uint16_t)(1u + dtls_rnd_bounded(31u));
            if (dtls_rnd_u8() & 1u) {
                if (next + step <= DTLS_MAX_SIGNATURE_LEN) next = (uint16_t)(next + step);
            } else {
                if (next > step) next = (uint16_t)(next - step);
            }
            if (next < 8u) next = 8u;
            *lenp = next;

            /* mutate only a slice to preserve some structure */
            if (*lenp) {
                dtls_fill_random(buf, *lenp);
                uint16_t win = (uint16_t)(4u + dtls_rnd_bounded(32u));
                if (win > *lenp) win = *lenp;
                uint16_t off = (uint16_t)dtls_rnd_bounded((uint32_t)(*lenp - win + 1u));
                mutate_opaque_blob(&buf[off], win, win);
                if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(&buf[off], (size_t)win);
            }
        }
        break;

    default: /* H. Random valid mix: combine length tweak + random fill + localized edits */
        {
            uint16_t L = *lenp;
            if (L == 0) L = (uint16_t)(8u + dtls_rnd_bounded(192u));
            if (dtls_rnd_u8() & 1u) {
                /* shallow length jitter */
                int16_t j = (int16_t)((int8_t)dtls_rnd_u8());
                int32_t tmp = (int32_t)L + (int32_t)(j & 31);
                if (dtls_rnd_u8() & 1u) tmp -= (int32_t)((j >> 1) & 15);
                if (tmp < 1) tmp = 1;
                if (tmp > DTLS_MAX_SIGNATURE_LEN) tmp = DTLS_MAX_SIGNATURE_LEN;
                L = (uint16_t)tmp;
            }
            *lenp = L;

            /* deep: sometimes full random, sometimes mutate existing */
            if (dtls_rnd_u8() & 1u) dtls_fill_random(buf, *lenp);
            else mutate_opaque_blob(buf, *lenp, DTLS_MAX_SIGNATURE_LEN);

            /* localized edits */
            if (*lenp) {
                uint16_t flips = (uint16_t)(1u + dtls_rnd_bounded(8u));
                for (uint16_t k = 0; k < flips; k++) {
                    uint16_t pos = (uint16_t)dtls_rnd_bounded(*lenp);
                    buf[pos] ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
                }
                if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(buf, (size_t)(*lenp));
            }
        }
        break;
    }

    /* extra perturbations (shallow+deep) to avoid converging */
    if (*lenp && (dtls_rnd_u8() & 1u)) {
        /* shallow: flip a couple bits */
        uint16_t k = (uint16_t)(1u + dtls_rnd_bounded(4u));
        for (uint16_t i = 0; i < k; i++) {
            uint16_t pos = (uint16_t)dtls_rnd_bounded(*lenp);
            buf[pos] ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
        }
    }
    if (*lenp && (dtls_rnd_u8() & 1u)) {
        /* deep: occasionally re-randomize a chunk */
        uint16_t win = (uint16_t)(1u + dtls_rnd_bounded(32u));
        if (win > *lenp) win = *lenp;
        uint16_t off = (uint16_t)dtls_rnd_bounded((uint32_t)(*lenp - win + 1u));
        dtls_fill_random(&buf[off], win);
    }
}

void mutate_certificate_verify_signature(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];
        if (p->kind != DTLS_PKT_HANDSHAKE) continue;

        /* TLS/DTLS HandshakeType: CertificateVerify = 15 */
        if (p->payload.handshake.handshake_header.msg_type != 15u) continue;

        mutate_certificate_verify_signature_body(&p->payload.handshake.body.certificate_verify);
    }
}


/* alert_level is not fixed; it is a 1-byte enum (typically warning(1) or fatal(2)).
 * It is part of DTLS_PKT_ALERT (not handshake body). Always present in our struct, so
 * no add/delete/repeat helpers.
 */

static void mutate_alert_level_u8(uint8_t *lvl) {
    if (!lvl) return;

    /* Common TLS AlertLevel values */
    static const uint8_t canonical[] = { 1u, 2u }; /* warning, fatal */

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    switch (cat) {
    case 0: /* A. Canonical form */
        *lvl = canonical[dtls_rnd_bounded((uint32_t)(sizeof(canonical)/sizeof(canonical[0])))];
        break;

    case 1: /* B. Boundaries */
        /* explore edges around typical small enums */
        {
            static const uint8_t b[] = { 0u, 1u, 2u, 3u, 0x7Fu, 0x80u, 0xFEu, 0xFFu };
            *lvl = b[dtls_rnd_bounded((uint32_t)(sizeof(b)/sizeof(b[0])))];
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* map to "classes": canonical, reserved-low, reserved-high */
        if (dtls_rnd_u8() & 1u) {
            *lvl = (dtls_rnd_u8() & 1u) ? 1u : 2u;
        } else if (dtls_rnd_u8() & 1u) {
            *lvl = (uint8_t)(3u + dtls_rnd_bounded(8u)); /* small reserved */
        } else {
            *lvl = (uint8_t)(240u + dtls_rnd_bounded(16u)); /* high reserved */
        }
        break;

    case 3: /* D. Allowed enum/range (stay in known-valid set more often) */
        /* bias toward valid {1,2} but still allow rare 0 */
        {
            uint8_t r = dtls_rnd_u8();
            if ((r % 10u) == 0u) *lvl = 0u;
            else *lvl = (r & 1u) ? 1u : 2u;
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* 1-byte field: simulate "encoded via bit patterns" */
        {
            uint8_t v = *lvl;
            if (dtls_rnd_u8() & 1u) v ^= 0x01u;     /* toggle LSB */
            if (dtls_rnd_u8() & 1u) v ^= 0x80u;     /* toggle MSB */
            if (dtls_rnd_u8() & 1u) v = (uint8_t)((v << 1) | (v >> 7)); /* rotate */
            *lvl = v;
        }
        break;

    case 5: /* F. Padding/alignment */
        /* n/a for single byte; emulate by snapping to aligned small ints */
        {
            uint8_t v = (uint8_t)(dtls_rnd_bounded(16u) & 0xFCu); /* multiples of 4 */
            /* sometimes pull back to canonical */
            if (dtls_rnd_u8() & 1u) v = (dtls_rnd_u8() & 1u) ? 1u : 2u;
            *lvl = v;
        }
        break;

    case 6: /* G. In-range sweep */
        /* sweep through small neighborhood around 1..2 */
        {
            uint8_t base = (*lvl == 0u) ? 1u : *lvl;
            int8_t step = (int8_t)((dtls_rnd_u8() & 1u) ? 1 : -1);
            int16_t tmp = (int16_t)base + (int16_t)step;
            if (tmp < 0) tmp = 0;
            if (tmp > 255) tmp = 255;
            *lvl = (uint8_t)tmp;
        }
        break;

    default: /* H. Random valid mix */
        {
            uint8_t r = dtls_rnd_u8();
            /* mix shallow and deep: choose canonical then perturb */
            *lvl = (r & 1u) ? 1u : 2u;
            if (dtls_rnd_u8() & 1u) *lvl ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
            if (dtls_rnd_u8() & 1u) *lvl = (uint8_t)(*lvl + (dtls_rnd_u8() % 7u));
        }
        break;
    }

    /* extra randomized perturbations (shallow+deep) to avoid collapse */
    if (dtls_rnd_u8() & 1u) {
        /* shallow */
        *lvl ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
    }
    if (dtls_rnd_u8() & 1u) {
        /* deep: occasionally re-snap to canonical after chaos */
        if (dtls_rnd_u8() & 1u) *lvl = 1u;
        else *lvl = 2u;
    }
}

void mutate_alert_level(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];

        /* alert_level is in DTLS_PKT_ALERT, not DTLS_PKT_HANDSHAKE */
        if (p->kind != DTLS_PKT_ALERT) continue;

        mutate_alert_level_u8(&p->payload.alert.level);
    }
}


/* alert_description is not fixed; it is a 1-byte enum (AlertDescription).
 * It is in DTLS_PKT_ALERT (not handshake). Always present in our struct, so
 * no add/delete/repeat helpers.
 */

static uint8_t dtls_pick_from_u8(const uint8_t *arr, uint32_t n) {
    if (!arr || n == 0) return 0;
    return arr[dtls_rnd_bounded(n)];
}

static void mutate_alert_description_u8(uint8_t *desc) {
    if (!desc) return;

    /* Representative TLS/DTLS 1.2 AlertDescription values (not exhaustive). */
    static const uint8_t canonical[] = {
        0u,   /* close_notify */
        10u,  /* unexpected_message */
        20u,  /* bad_record_mac */
        21u,  /* decryption_failed (historical) */
        22u,  /* record_overflow */
        30u,  /* decompression_failure */
        40u,  /* handshake_failure */
        42u,  /* bad_certificate */
        43u,  /* unsupported_certificate */
        44u,  /* certificate_revoked */
        45u,  /* certificate_expired */
        46u,  /* certificate_unknown */
        47u,  /* illegal_parameter */
        48u,  /* unknown_ca */
        49u,  /* access_denied */
        50u,  /* decode_error */
        51u,  /* decrypt_error */
        60u,  /* export_restriction (historical) */
        70u,  /* protocol_version */
        71u,  /* insufficient_security */
        80u,  /* internal_error */
        90u,  /* user_canceled */
        100u, /* no_renegotiation */
        109u, /* missing_extension */
        110u, /* unsupported_extension */
        112u, /* unrecognized_name */
        113u, /* bad_certificate_status_response */
        115u  /* unknown_psk_identity */
    };

    uint8_t cat = (uint8_t)dtls_rnd_bounded(8u);
    switch (cat) {
    case 0: /* A. Canonical form */
        *desc = dtls_pick_from_u8(canonical, (uint32_t)(sizeof(canonical)/sizeof(canonical[0])));
        break;

    case 1: /* B. Boundaries */
        {
            static const uint8_t b[] = { 0u, 1u, 2u, 9u, 10u, 11u, 19u, 20u, 21u, 22u,
                                         47u, 50u, 51u, 69u, 70u, 71u, 79u, 80u,
                                         99u, 100u, 101u, 109u, 110u, 111u, 112u,
                                         254u, 255u };
            *desc = dtls_pick_from_u8(b, (uint32_t)(sizeof(b)/sizeof(b[0])));
        }
        break;

    case 2: /* C. Equivalence-class alternatives */
        /* cluster by likely subsystem: record/handshake/cert/app/other */
        {
            uint8_t r = dtls_rnd_u8();
            if ((r % 5u) == 0u) {
                /* record-layer-ish */
                static const uint8_t rec[] = { 20u, 21u, 22u, 50u };
                *desc = dtls_pick_from_u8(rec, (uint32_t)(sizeof(rec)/sizeof(rec[0])));
            } else if ((r % 5u) == 1u) {
                /* handshake-ish */
                static const uint8_t hs[] = { 10u, 40u, 47u, 70u, 109u, 110u };
                *desc = dtls_pick_from_u8(hs, (uint32_t)(sizeof(hs)/sizeof(hs[0])));
            } else if ((r % 5u) == 2u) {
                /* certificate-ish */
                static const uint8_t cert[] = { 42u, 43u, 44u, 45u, 46u, 48u };
                *desc = dtls_pick_from_u8(cert, (uint32_t)(sizeof(cert)/sizeof(cert[0])));
            } else if ((r % 5u) == 3u) {
                /* application/user-ish */
                static const uint8_t app[] = { 0u, 90u, 100u };
                *desc = dtls_pick_from_u8(app, (uint32_t)(sizeof(app)/sizeof(app[0])));
            } else {
                /* other/edge */
                static const uint8_t oth[] = { 71u, 80u, 112u, 113u, 115u };
                *desc = dtls_pick_from_u8(oth, (uint32_t)(sizeof(oth)/sizeof(oth[0])));
            }
        }
        break;

    case 3: /* D. Allowed enum/range (bias to widely-implemented alerts) */
        {
            /* keep it mostly in common set; occasionally nudge to neighbors */
            static const uint8_t common[] = { 0u, 10u, 20u, 22u, 40u, 47u, 50u, 70u, 80u, 100u };
            uint8_t v = dtls_pick_from_u8(common, (uint32_t)(sizeof(common)/sizeof(common[0])));
            if (dtls_rnd_u8() & 1u) {
                int16_t t = (int16_t)v + (int16_t)((dtls_rnd_u8() & 1u) ? 1 : -1);
                if (t < 0) t = 0;
                if (t > 255) t = 255;
                v = (uint8_t)t;
            }
            *desc = v;
        }
        break;

    case 4: /* E. Encoding-shape variant */
        /* 1-byte field: apply bit/byte transforms as "shape" perturbations */
        {
            uint8_t v = *desc;
            if (dtls_rnd_u8() & 1u) v ^= 0x01u;
            if (dtls_rnd_u8() & 1u) v ^= 0x80u;
            if (dtls_rnd_u8() & 1u) v = (uint8_t)((v << 1) | (v >> 7)); /* rotate */
            if (dtls_rnd_u8() & 1u) v = (uint8_t)(v ^ (uint8_t)(1u << (dtls_rnd_u8() & 7u)));
            *desc = v;
        }
        break;

    case 5: /* F. Padding/alignment */
        /* n/a for single byte; emulate by snapping to "round" values / multiples */
        {
            uint8_t v;
            if (dtls_rnd_u8() & 1u) {
                /* multiples of 5/10 common in registry-like enums */
                v = (uint8_t)((dtls_rnd_bounded(26u)) * 10u); /* 0..250 step 10 */
            } else {
                v = (uint8_t)((dtls_rnd_bounded(52u)) * 5u);  /* 0..255 step 5 (wrap ok) */
            }
            /* sometimes keep canonical after alignment */
            if (dtls_rnd_u8() & 1u) v = dtls_pick_from_u8(canonical, (uint32_t)(sizeof(canonical)/sizeof(canonical[0])));
            *desc = v;
        }
        break;

    case 6: /* G. In-range sweep */
        /* sweep within a "typical" alert band (0..115-ish) */
        {
            uint8_t base = *desc;
            if (base > 200u) base = (uint8_t)(dtls_pick_from_u8(canonical, (uint32_t)(sizeof(canonical)/sizeof(canonical[0]))));
            {
                int16_t t = (int16_t)base + (int16_t)((dtls_rnd_u8() % 7u) - 3); /* -3..+3 */
                if (t < 0) t = 0;
                if (t > 115) t = 115;
                *desc = (uint8_t)t;
            }
        }
        break;

    default: /* H. Random valid mix */
        {
            /* Mix: start from canonical, then perform a couple of controlled perturbations */
            uint8_t v = dtls_pick_from_u8(canonical, (uint32_t)(sizeof(canonical)/sizeof(canonical[0])));
            if (dtls_rnd_u8() & 1u) v = (uint8_t)(v + (dtls_rnd_u8() % 5u)); /* small drift */
            if (dtls_rnd_u8() & 1u) v ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
            if (dtls_rnd_u8() & 1u) {
                /* occasionally jump to a boundary/reserved */
                static const uint8_t j[] = { 0u, 255u, 254u, 1u, 2u, 200u };
                v = dtls_pick_from_u8(j, (uint32_t)(sizeof(j)/sizeof(j[0])));
            }
            *desc = v;
        }
        break;
    }

    /* extra randomized perturbations (shallow + deep) to preserve diversity */
    if (dtls_rnd_u8() & 1u) {
        /* shallow: flip one bit */
        *desc ^= (uint8_t)(1u << (dtls_rnd_u8() & 7u));
    }
    if (dtls_rnd_u8() & 1u) {
        /* deep: re-anchor to a semantically meaningful value class */
        if (dtls_rnd_u8() & 1u) {
            *desc = dtls_pick_from_u8(canonical, (uint32_t)(sizeof(canonical)/sizeof(canonical[0])));
        } else {
            /* push to high/rare space */
            *desc = (uint8_t)(200u + dtls_rnd_bounded(56u));
        }
    }
}

void mutate_alert_description(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        dtls_packet_t *p = &pkts[i];

        /* alert_description is in DTLS_PKT_ALERT, not DTLS_PKT_HANDSHAKE */
        if (p->kind != DTLS_PKT_ALERT) continue;

        mutate_alert_description_u8(&p->payload.alert.description);
    }
}


/* ===== local tiny helpers ===== */
static uint16_t dtls_min_u16(uint16_t a, uint16_t b) { return (a < b) ? a : b; }
static uint16_t dtls_max_u16(uint16_t a, uint16_t b) { return (a > b) ? a : b; }

static uint16_t clamp_u16_2(uint16_t v, uint16_t lo, uint16_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void fill_repeat(uint8_t *p, uint16_t n, uint8_t byte) {
    if (!p || !n) return;
    for (uint16_t i = 0; i < n; i++) p[i] = byte;
}

static void fill_pattern_2(uint8_t *p, uint16_t n, uint8_t a, uint8_t b) {
    if (!p || !n) return;
    for (uint16_t i = 0; i < n; i++) p[i] = (i & 1u) ? b : a;
}

static void fill_ascii_printable(uint8_t *p, uint16_t n) {
    if (!p || !n) return;
    for (uint16_t i = 0; i < n; i++) {
        uint8_t r = dtls_rnd_u8();
        uint8_t c = (uint8_t)(32u + (r % 95u)); /* [0x20..0x7E] */
        p[i] = c;
    }
}

static void fill_ascii_alnum(uint8_t *p, uint16_t n) {
    if (!p || !n) return;
    for (uint16_t i = 0; i < n; i++) {
        uint8_t r = dtls_rnd_u8();
        uint8_t c;
        if ((r % 3u) == 0u) c = (uint8_t)('0' + (r % 10u));
        else if ((r % 3u) == 1u) c = (uint8_t)('a' + (r % 26u));
        else c = (uint8_t)('A' + (r % 26u));
        p[i] = c;
    }
}

static void xor_sparse(uint8_t *p, uint16_t n) {
    if (!p || n == 0) return;
    /* shallow: flip a few bytes */
    uint8_t flips = (uint8_t)(1u + (dtls_rnd_u8() % 6u));
    for (uint8_t k = 0; k < flips; k++) {
        uint16_t idx = (uint16_t)(dtls_rnd_u16() % n);
        uint8_t  m   = (uint8_t)(1u << (dtls_rnd_u8() & 7u));
        p[idx] ^= m;
    }
}

static void mutate_len_app(uint16_t *len) {
    if (!len) return;
    /* keep in valid range [0..DTLS_MAX_APPDATA_LEN] */
    uint16_t v = *len;
    uint8_t  m = dtls_rnd_u8();

    /* A/H: keep as-is sometimes */
    if ((m & 7u) == 0u) return;

    /* B: boundaries / near-boundaries */
    if ((m & 7u) == 1u) {
        static const uint16_t bnd[] = {0,1,2,3,7,8,15,16,31,32,63,64,127,128,255,256,511,512,1023,1024,1536,2047,2048};
        uint16_t pick = bnd[dtls_rnd_u8() % (uint8_t)(sizeof(bnd)/sizeof(bnd[0]))];
        *len = clamp_u16_2(pick, 0, DTLS_MAX_APPDATA_LEN);
        return;
    }

    /* G: in-range sweep (small step) */
    if ((m & 7u) == 2u) {
        int16_t step = (int16_t)((int8_t)dtls_rnd_u8());
        int32_t nv = (int32_t)v + (int32_t)(step / 4); /* gentle */
        if (nv < 0) nv = 0;
        if (nv > (int32_t)DTLS_MAX_APPDATA_LEN) nv = DTLS_MAX_APPDATA_LEN;
        *len = (uint16_t)nv;
        return;
    }

    /* C/D: common equivalence-class lengths */
    if ((m & 7u) == 3u) {
        static const uint16_t cls[] = {0, 16, 32, 48, 64, 128, 256, 512, 1024};
        uint16_t pick = cls[dtls_rnd_u8() % (uint8_t)(sizeof(cls)/sizeof(cls[0]))];
        *len = clamp_u16_2(pick, 0, DTLS_MAX_APPDATA_LEN);
        return;
    }

    /* H: random valid */
    *len = (uint16_t)(dtls_rnd_u16() % (DTLS_MAX_APPDATA_LEN + 1u));
}

/* ===== target mutators =====
 * Field: application_data.data (and its length) in dtls_packet_t::payload.application_data
 *
 * Not fixed by spec (application data is arbitrary). Mutable.
 * "Optional": model as allowed to be empty (data_len==0).
 * "May appear multiple times": across packet sequences, yes (multiple DTLS_PKT_APPLICATION_DATA packets).
 */

void add_application_data_data(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        if (pkts[i].kind != DTLS_PKT_APPLICATION_DATA) continue;

        /* if empty, make it non-empty; otherwise maybe append/refresh */
        uint16_t len = pkts[i].payload.application_data.data_len;
        if (len == 0) {
            /* A: canonical small payload */
            uint16_t new_len = 16;
            if (dtls_rnd_u8() & 1u) new_len = 32;
            if (dtls_rnd_u8() & 1u) new_len = (uint16_t)(1u + (dtls_rnd_u16() % 128u));
            new_len = clamp_u16_2(new_len, 1, DTLS_MAX_APPDATA_LEN);

            pkts[i].payload.application_data.data_len = new_len;
            fill_ascii_printable(pkts[i].payload.application_data.data, new_len);
            if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(pkts[i].payload.application_data.data, (size_t)new_len);
        } else if (dtls_rnd_u8() & 1u) {
            /* opportunistic: append some bytes if room */
            uint16_t add = (uint16_t)(1u + (dtls_rnd_u16() % 64u));
            uint16_t room = (uint16_t)(DTLS_MAX_APPDATA_LEN - len);
            add = dtls_min_u16(add, room);
            if (add) {
                uint8_t *dst = &pkts[i].payload.application_data.data[len];
                fill_ascii_alnum(dst, add);
                pkts[i].payload.application_data.data_len = (uint16_t)(len + add);
            }
        }
        return; /* add at most one packet per call */
    }
}

void delete_application_data_data(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    for (size_t i = 0; i < n; i++) {
        if (pkts[i].kind != DTLS_PKT_APPLICATION_DATA) continue;

        /* make empty; keep buffer untouched for diversity */
        pkts[i].payload.application_data.data_len = 0;
        return;
    }
}

void repeat_application_data_data(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* find a source appdata packet with non-empty data */
    size_t src = (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].kind == DTLS_PKT_APPLICATION_DATA &&
            pkts[i].payload.application_data.data_len > 0) {
            src = i;
            break;
        }
    }
    if (src == (size_t)-1) return;

    /* copy into another appdata packet (or itself) */
    size_t dst = (size_t)(dtls_rnd_u16() % (uint16_t)n);
    if (pkts[dst].kind != DTLS_PKT_APPLICATION_DATA) return;

    uint16_t slen = pkts[src].payload.application_data.data_len;
    slen = dtls_min_u16(slen, DTLS_MAX_APPDATA_LEN);

    pkts[dst].payload.application_data.data_len = slen;
    if (slen) {
        memcpy(pkts[dst].payload.application_data.data,
               pkts[src].payload.application_data.data,
               (size_t)slen);
        if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(pkts[dst].payload.application_data.data, (size_t)slen);
    }
}

static void apply_A_canonical(dtls_packet_t *p) {
    /* Canonical: short printable / request-like tokens */
    uint16_t len = p->payload.application_data.data_len;
    if (len == 0) {
        len = (dtls_rnd_u8() & 1u) ? 16u : 32u;
        p->payload.application_data.data_len = len;
    }
    len = dtls_min_u16(len, DTLS_MAX_APPDATA_LEN);

    /* simple canonical phrases */
    static const char *msgs[] = {
        "ping", "hello", "GET /", "POST /", "status", "OK", "data", "test"
    };
    const char *m = msgs[dtls_rnd_u8() % (uint8_t)(sizeof(msgs)/sizeof(msgs[0]))];
    size_t ml = strlen(m);
    uint16_t copy = (uint16_t)dtls_min_u16((uint16_t)ml, len);
    if (copy) memcpy(p->payload.application_data.data, m, copy);
    if (len > copy) fill_ascii_printable(&p->payload.application_data.data[copy], (uint16_t)(len - copy));

    /* light shallow tweak */
    if (dtls_rnd_u8() & 1u) xor_sparse(p->payload.application_data.data, len);
}

static void apply_B_boundaries(dtls_packet_t *p) {
    /* Boundary lengths + edge-content */
    uint16_t len;
    static const uint16_t bnd[] = {0,1,2,3,7,8,15,16,31,32,63,64,127,128,255,256,511,512,1023,1024,2047,2048};
    len = bnd[dtls_rnd_u8() % (uint8_t)(sizeof(bnd)/sizeof(bnd[0]))];
    len = clamp_u16_2(len, 0, DTLS_MAX_APPDATA_LEN);
    p->payload.application_data.data_len = len;

    if (len == 0) return;

    /* boundary content: all-0x00 / all-0xFF / 0xAA55 pattern */
    switch (dtls_rnd_u8() % 3u) {
        case 0: fill_repeat(p->payload.application_data.data, len, 0x00); break;
        case 1: fill_repeat(p->payload.application_data.data, len, 0xFF); break;
        default: fill_pattern_2(p->payload.application_data.data, len, 0xAA, 0x55); break;
    }
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->payload.application_data.data, (size_t)len);
}

static void apply_C_equiv(dtls_packet_t *p) {
    /* Equivalence classes: printable, binary, structured-ish */
    uint16_t len = p->payload.application_data.data_len;
    if (len == 0) {
        len = (uint16_t)(1u + (dtls_rnd_u16() % 256u));
        p->payload.application_data.data_len = len;
    }
    len = dtls_min_u16(len, DTLS_MAX_APPDATA_LEN);

    uint8_t cls = (uint8_t)(dtls_rnd_u8() % 4u);
    if (cls == 0) {
        fill_ascii_printable(p->payload.application_data.data, len);
    } else if (cls == 1) {
        dtls_fill_random(p->payload.application_data.data, len);
    } else if (cls == 2) {
        /* repeated small token */
        static const char *tok[] = {"A", "0", "xyz", "ABCD", "0000", "FFFF"};
        const char *t = tok[dtls_rnd_u8() % (uint8_t)(sizeof(tok)/sizeof(tok[0]))];
        size_t tl = strlen(t);
        if (tl == 0) tl = 1;
        for (uint16_t i = 0; i < len; i++) p->payload.application_data.data[i] = (uint8_t)t[i % tl];
    } else {
        /* "record-like" header then random */
        if (len >= 4) {
            p->payload.application_data.data[0] = (uint8_t)(dtls_rnd_u8()); /* type-ish */
            p->payload.application_data.data[1] = (uint8_t)(dtls_rnd_u8());
            p->payload.application_data.data[2] = (uint8_t)(len >> 8);
            p->payload.application_data.data[3] = (uint8_t)(len & 0xFF);
            dtls_fill_random(&p->payload.application_data.data[4], (uint16_t)(len - 4));
        } else {
            dtls_fill_random(p->payload.application_data.data, len);
        }
    }

    if (dtls_rnd_u8() & 1u) xor_sparse(p->payload.application_data.data, len);
}

static void apply_D_allowed_range(dtls_packet_t *p) {
    /* For appdata, "allowed range" is any bytes; enforce only length in [0..max]. */
    uint16_t len = p->payload.application_data.data_len;
    len = clamp_u16_2(len, 0, DTLS_MAX_APPDATA_LEN);
    p->payload.application_data.data_len = len;
    if (len == 0) return;

    /* keep within range but alter content deterministically-ish */
    if (dtls_rnd_u8() & 1u) {
        /* keep mostly same, flip a few bits (shallow) */
        xor_sparse(p->payload.application_data.data, len);
    } else {
        /* moderate random refresh (still valid) */
        uint16_t n = (uint16_t)(1u + (dtls_rnd_u16() % dtls_max_u16(1u, (uint16_t)(len / 2u))));
        for (uint16_t k = 0; k < n; k++) {
            uint16_t idx = (uint16_t)(dtls_rnd_u16() % len);
            p->payload.application_data.data[idx] = dtls_rnd_u8();
        }
    }
}

static void apply_E_encoding_shape(dtls_packet_t *p) {
    /* Shape variants: TLV-ish / varint-ish / base64-ish, still just bytes */
    uint16_t len = p->payload.application_data.data_len;
    if (len < 8) {
        len = 32;
        p->payload.application_data.data_len = len;
    }
    len = dtls_min_u16(len, DTLS_MAX_APPDATA_LEN);

    uint8_t mode = (uint8_t)(dtls_rnd_u8() % 3u);
    if (mode == 0) {
        /* TLV: [T][L][V...] repeated */
        uint16_t i = 0;
        while (i + 2 <= len) {
            uint8_t T = dtls_rnd_u8();
            uint8_t L = (uint8_t)(dtls_rnd_u8() % 32u);
            p->payload.application_data.data[i++] = T;
            p->payload.application_data.data[i++] = L;
            uint16_t remain = (uint16_t)(len - i);
            uint16_t take = dtls_min_u16((uint16_t)L, remain);
            if (take) dtls_fill_random(&p->payload.application_data.data[i], take);
            i = (uint16_t)(i + take);
            if (take < (uint16_t)L) break;
        }
        if (i < len) dtls_fill_random(&p->payload.application_data.data[i], (uint16_t)(len - i));
    } else if (mode == 1) {
        /* length-prefixed chunk: [len_hi][len_lo][payload...] */
        p->payload.application_data.data[0] = (uint8_t)((len - 2) >> 8);
        p->payload.application_data.data[1] = (uint8_t)((len - 2) & 0xFF);
        dtls_fill_random(&p->payload.application_data.data[2], (uint16_t)(len - 2));
    } else {
        /* base64-ish alphabet */
        static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (uint16_t i = 0; i < len; i++) {
            p->payload.application_data.data[i] = (uint8_t)b64[dtls_rnd_u8() & 63u];
        }
        /* sprinkle '=' padding markers */
        if (len >= 2 && (dtls_rnd_u8() & 1u)) {
            p->payload.application_data.data[len - 1] = '=';
            if (dtls_rnd_u8() & 1u) p->payload.application_data.data[len - 2] = '=';
        }
    }

    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->payload.application_data.data, (size_t)len);
}

static void apply_F_padding_alignment(dtls_packet_t *p) {
    /* Pad to 16/32 boundary with 0x00 or PKCS#7-like padding bytes */
    uint16_t len = p->payload.application_data.data_len;
    if (len == 0) {
        len = 1;
        p->payload.application_data.data_len = len;
        p->payload.application_data.data[0] = dtls_rnd_u8();
    }
    len = dtls_min_u16(len, DTLS_MAX_APPDATA_LEN);

    uint16_t align = (dtls_rnd_u8() & 1u) ? 16u : 32u;
    uint16_t new_len = (uint16_t)(((len + align - 1u) / align) * align);
    new_len = dtls_min_u16(new_len, DTLS_MAX_APPDATA_LEN);

    /* if growing, fill appended part */
    if (new_len > len) {
        uint16_t pad = (uint16_t)(new_len - len);
        if (dtls_rnd_u8() & 1u) {
            /* zero padding */
            fill_repeat(&p->payload.application_data.data[len], pad, 0x00);
        } else {
            /* PKCS#7-like */
            fill_repeat(&p->payload.application_data.data[len], pad, (uint8_t)pad);
        }
        p->payload.application_data.data_len = new_len;
        len = new_len;
    } else {
        /* if already aligned, maybe rewrite tail padding-like region */
        uint16_t tail = (uint16_t)dtls_min_u16(align, len);
        uint16_t start = (uint16_t)(len - tail);
        if (dtls_rnd_u8() & 1u) fill_repeat(&p->payload.application_data.data[start], tail, 0x00);
        else fill_repeat(&p->payload.application_data.data[start], tail, (uint8_t)tail);
    }

    if (dtls_rnd_u8() & 1u) xor_sparse(p->payload.application_data.data, len);
}

static void apply_G_inrange_sweep(dtls_packet_t *p) {
    /* Sweep: slide a window and increment/decrement within valid bytes */
    uint16_t len = p->payload.application_data.data_len;
    if (len == 0) return;
    len = dtls_min_u16(len, DTLS_MAX_APPDATA_LEN);

    uint16_t win = (uint16_t)(1u + (dtls_rnd_u16() % dtls_max_u16(1u, (uint16_t)(len / 4u))));
    uint16_t off = (uint16_t)(dtls_rnd_u16() % len);
    if (off + win > len) win = (uint16_t)(len - off);

    int8_t delta = (int8_t)((dtls_rnd_u8() & 1u) ? 1 : -1);
    for (uint16_t i = 0; i < win; i++) {
        p->payload.application_data.data[off + i] = (uint8_t)(p->payload.application_data.data[off + i] + (uint8_t)delta);
    }

    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(&p->payload.application_data.data[off], (size_t)win);
}

static void apply_H_random_mix(dtls_packet_t *p) {
    uint16_t len = p->payload.application_data.data_len;
    mutate_len_app(&len);
    p->payload.application_data.data_len = len;

    if (len == 0) return;

    /* blend: some printable, some random, some patterns */
    uint8_t m = dtls_rnd_u8() % 4u;
    if (m == 0) {
        fill_ascii_printable(p->payload.application_data.data, len);
    } else if (m == 1) {
        dtls_fill_random(p->payload.application_data.data, len);
    } else if (m == 2) {
        fill_pattern_2(p->payload.application_data.data, len, (uint8_t)dtls_rnd_u8(), (uint8_t)dtls_rnd_u8());
    } else {
        fill_ascii_alnum(p->payload.application_data.data, len);
        xor_sparse(p->payload.application_data.data, len);
    }

    /* randomized perturbations: shallow + deep */
    if (dtls_rnd_u8() & 1u) xor_sparse(p->payload.application_data.data, len);
    if (dtls_rnd_u8() & 1u) dtls_mix_shallow_deep(p->payload.application_data.data, (size_t)len);
}

void mutate_application_data_data(dtls_packet_t *pkts, size_t n) {
    if (!pkts || n == 0) return;

    /* pick one application-data packet to mutate */
    size_t idx = (size_t)-1;
    for (size_t tries = 0; tries < 8 && idx == (size_t)-1; tries++) {
        size_t i = (size_t)(dtls_rnd_u16() % (uint16_t)n);
        if (pkts[i].kind == DTLS_PKT_APPLICATION_DATA) idx = i;
    }
    if (idx == (size_t)-1) {
        for (size_t i = 0; i < n; i++) {
            if (pkts[i].kind == DTLS_PKT_APPLICATION_DATA) { idx = i; break; }
        }
    }
    if (idx == (size_t)-1) return;

    dtls_packet_t *p = &pkts[idx];

    /* sometimes mutate length first (kept valid) */
    if (dtls_rnd_u8() & 1u) {
        uint16_t len = p->payload.application_data.data_len;
        mutate_len_app(&len);
        p->payload.application_data.data_len = len;
        if (len && (dtls_rnd_u8() & 1u)) dtls_fill_random(p->payload.application_data.data, len);
    }

    /* choose semantic category A-H */
    uint8_t cat = (uint8_t)(dtls_rnd_u8() % 8u);
    switch (cat) {
        case 0: apply_A_canonical(p); break;          /* A */
        case 1: apply_B_boundaries(p); break;         /* B */
        case 2: apply_C_equiv(p); break;              /* C */
        case 3: apply_D_allowed_range(p); break;      /* D */
        case 4: apply_E_encoding_shape(p); break;     /* E */
        case 5: apply_F_padding_alignment(p); break;  /* F */
        case 6: apply_G_inrange_sweep(p); break;      /* G */
        default: apply_H_random_mix(p); break;        /* H */
    }

    /* extra diversity: occasional cross-packet repeat/perturb */
    if ((dtls_rnd_u8() & 7u) == 0u) repeat_application_data_data(pkts, n);
}



/* add */
void add_application_data_data(dtls_packet_t *pkts, size_t n);
void add_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n);
void add_certificate_request_cert_types(dtls_packet_t *pkts, size_t n);
void add_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n);
void add_client_hello_compression_methods(dtls_packet_t *pkts, size_t n);
void add_client_hello_cookie(dtls_packet_t *pkts, size_t n);
void add_client_hello_extensions(dtls_packet_t *pkts, size_t n);
void add_client_hello_session_id(dtls_packet_t *pkts, size_t n);
void add_server_hello_extensions(dtls_packet_t *pkts, size_t n);
void add_server_hello_session_id(dtls_packet_t *pkts, size_t n);

/* delete */
void delete_application_data_data(dtls_packet_t *pkts, size_t n);
void delete_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n);
void delete_certificate_request_cert_types(dtls_packet_t *pkts, size_t n);
void delete_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n);
void delete_client_hello_compression_methods(dtls_packet_t *pkts, size_t n);
void delete_client_hello_cookie(dtls_packet_t *pkts, size_t n);
void delete_client_hello_extensions(dtls_packet_t *pkts, size_t n);
void delete_client_hello_session_id(dtls_packet_t *pkts, size_t n);
void delete_server_hello_extensions(dtls_packet_t *pkts, size_t n);
void delete_server_hello_session_id(dtls_packet_t *pkts, size_t n);

/* repeat */
void repeat_application_data_data(dtls_packet_t *pkts, size_t n);
void repeat_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n);
void repeat_certificate_request_cert_types(dtls_packet_t *pkts, size_t n);
void repeat_server_hello_extensions(dtls_packet_t *pkts, size_t n);

/* mutate (packet-level) */
void mutate_alert_description(dtls_packet_t *pkts, size_t n);
void mutate_alert_level(dtls_packet_t *pkts, size_t n);
void mutate_application_data_data(dtls_packet_t *pkts, size_t n);
void mutate_certificate_cert_blob(dtls_packet_t *pkts, size_t n);
void mutate_certificate_request_ca_dn_blob(dtls_packet_t *pkts, size_t n);
void mutate_certificate_request_cert_types(dtls_packet_t *pkts, size_t n);
void mutate_certificate_request_sig_algs(dtls_packet_t *pkts, size_t n);
void mutate_certificate_verify_alg(dtls_packet_t *pkts, size_t n);
void mutate_certificate_verify_signature(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_cipher_suites(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_client_version(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_compression_methods(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_cookie(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_extensions(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_random(dtls_packet_t *pkts, size_t n);
void mutate_client_hello_session_id(dtls_packet_t *pkts, size_t n);
void mutate_client_key_exchange(dtls_packet_t *pkts, size_t n);
void mutate_finished_verify_data(dtls_packet_t *pkts, size_t n);
void mutate_handshake_header_fragment_length(dtls_packet_t *pkts, size_t n);
void mutate_handshake_header_fragment_offset(dtls_packet_t *pkts, size_t n);
void mutate_handshake_header_length(dtls_packet_t *pkts, size_t n);
void mutate_handshake_header_message_seq(dtls_packet_t *pkts, size_t n);
void mutate_handshake_header_msg_type(dtls_packet_t *pkts, size_t n);
void mutate_hello_verify_request_cookie(dtls_packet_t *pkts, size_t n);
void mutate_hello_verify_request_server_version(dtls_packet_t *pkts, size_t n);
void mutate_record_header_epoch(dtls_packet_t *pkts, size_t n);
void mutate_record_header_length(dtls_packet_t *pkts, size_t n);
void mutate_record_header_sequence_number(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_cipher_suite(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_compression_method(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_extensions(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_random(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_server_version(dtls_packet_t *pkts, size_t n);
void mutate_server_hello_session_id(dtls_packet_t *pkts, size_t n);
void mutate_server_key_exchange(dtls_packet_t *pkts, size_t n);



/* ---- RNG ---- */
static uint32_t g_dtls_rng = 0xC001D00Du;


typedef void (*dtls_mut_fn)(dtls_packet_t *, size_t);

static void call_one(dtls_mut_fn const *fns, size_t cnt, dtls_packet_t *pkts, size_t n) {
    if (!fns || cnt == 0 || !pkts || n == 0) return;
    size_t idx = (size_t)rnd_u32((uint32_t)cnt);
    fns[idx](pkts, n);
}

static void call_some(dtls_mut_fn const *fns, size_t cnt, dtls_packet_t *pkts, size_t n,
                      uint32_t min_k, uint32_t max_k) {
    if (!fns || cnt == 0 || !pkts || n == 0) return;
    if (max_k < min_k) { uint32_t t = min_k; min_k = max_k; max_k = t; }
    uint32_t k = min_k + rnd_u32(max_k - min_k + 1u);
    for (uint32_t i = 0; i < k; i++) call_one(fns, cnt, pkts, n);
}

/* ---- per-message-type dispatch tables ---- */
static const dtls_mut_fn g_record_hdr_muts[] = {
    mutate_record_header_epoch,
    mutate_record_header_length,
    mutate_record_header_sequence_number
};

static const dtls_mut_fn g_handshake_hdr_muts[] = {
    mutate_handshake_header_msg_type,
    mutate_handshake_header_length,
    mutate_handshake_header_message_seq,
    mutate_handshake_header_fragment_offset,
    mutate_handshake_header_fragment_length
};

static const dtls_mut_fn g_alert_muts[] = {
    mutate_alert_level,
    mutate_alert_description
};

static const dtls_mut_fn g_appdata_muts[] = {
    add_application_data_data,
    delete_application_data_data,
    repeat_application_data_data,
    mutate_application_data_data
};

static const dtls_mut_fn g_hv_muts[] = {
    mutate_hello_verify_request_server_version,
    mutate_hello_verify_request_cookie
};

static const dtls_mut_fn g_client_hello_muts[] = {
    add_client_hello_session_id,
    delete_client_hello_session_id,
    mutate_client_hello_session_id,

    add_client_hello_cookie,
    delete_client_hello_cookie,
    mutate_client_hello_cookie,

    add_client_hello_cipher_suites,
    delete_client_hello_cipher_suites,
    mutate_client_hello_cipher_suites,

    add_client_hello_compression_methods,
    delete_client_hello_compression_methods,
    mutate_client_hello_compression_methods,

    add_client_hello_extensions,
    delete_client_hello_extensions,
    mutate_client_hello_extensions,

    mutate_client_hello_client_version,
    mutate_client_hello_random
};

static const dtls_mut_fn g_server_hello_muts[] = {
    add_server_hello_session_id,
    delete_server_hello_session_id,
    mutate_server_hello_session_id,

    add_server_hello_extensions,
    delete_server_hello_extensions,
    repeat_server_hello_extensions,
    mutate_server_hello_extensions,

    mutate_server_hello_server_version,
    mutate_server_hello_random,
    mutate_server_hello_cipher_suite,
    mutate_server_hello_compression_method
};

static const dtls_mut_fn g_cert_muts[] = {
    mutate_certificate_cert_blob
};

static const dtls_mut_fn g_cert_req_muts[] = {
    add_certificate_request_cert_types,
    delete_certificate_request_cert_types,
    repeat_certificate_request_cert_types,
    mutate_certificate_request_cert_types,

    add_certificate_request_ca_dn_blob,
    delete_certificate_request_ca_dn_blob,
    repeat_certificate_request_ca_dn_blob,
    mutate_certificate_request_ca_dn_blob,

    mutate_certificate_request_sig_algs
};

static const dtls_mut_fn g_ske_muts[] = {
    mutate_server_key_exchange
};

static const dtls_mut_fn g_cke_muts[] = {
    mutate_client_key_exchange
};

static const dtls_mut_fn g_cv_muts[] = {
    mutate_certificate_verify_alg,
    mutate_certificate_verify_signature
};

static const dtls_mut_fn g_finished_muts[] = {
    mutate_finished_verify_data
};

/* ---- public dispatcher ----
 * NOTE: your message had ftp_packet_t*; for DTLS this should be dtls_packet_t*.
 */
void dispatch_dtls_multiple_mutations(dtls_packet_t *pkts, int num_packets, int rounds)
{
    if (!pkts || num_packets <= 0 || rounds <= 0) return;

    size_t n = (size_t)num_packets;

    /* diversify seed a bit using address + counts (no time() dependency) */
    g_dtls_rng ^= (uint32_t)(uintptr_t)pkts;
    g_dtls_rng ^= (uint32_t)num_packets * 0x9E3779B1u;
    g_dtls_rng ^= (uint32_t)rounds * 0x85EBCA6Bu;

    for (int r = 0; r < rounds; r++) {
        /* shallow vs deep mixing: vary how many ops each round */
        uint32_t deep = (xorshift32() & 3u) == 0u; /* ~25% deep */
        uint32_t k_global = deep ? (2u + rnd_u32(3u)) : 1u;
        uint32_t k_local  = deep ? (2u + rnd_u32(5u)) : (1u + rnd_u32(2u));

        /* global-ish: record header always eligible; handshake header only if any handshake exists */
        call_some(g_record_hdr_muts, sizeof(g_record_hdr_muts)/sizeof(g_record_hdr_muts[0]),
                  pkts, n, 1u, k_global);

        /* pick a packet to guide local dispatch */
        dtls_packet_t *p = &pkts[rnd_u32((uint32_t)n)];

        if (p->kind == DTLS_PKT_HANDSHAKE) {
            /* mutate handshake header sometimes */
            if ((xorshift32() & 1u) == 0u) {
                call_some(g_handshake_hdr_muts, sizeof(g_handshake_hdr_muts)/sizeof(g_handshake_hdr_muts[0]),
                          pkts, n, 1u, deep ? 3u : 2u);
            }

            uint8_t mt = p->payload.handshake.handshake_header.msg_type;

            switch (mt) {
            case 0: /* HelloRequest: header-only mutations already cover this */
                /* occasionally also perturb record header again to mix */
                if (deep) call_one(g_record_hdr_muts, sizeof(g_record_hdr_muts)/sizeof(g_record_hdr_muts[0]), pkts, n);
                break;

            case 1: /* ClientHello */
                call_some(g_client_hello_muts, sizeof(g_client_hello_muts)/sizeof(g_client_hello_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 2: /* ServerHello */
                call_some(g_server_hello_muts, sizeof(g_server_hello_muts)/sizeof(g_server_hello_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 3: /* HelloVerifyRequest */
                call_some(g_hv_muts, sizeof(g_hv_muts)/sizeof(g_hv_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 11: /* Certificate */
                call_some(g_cert_muts, sizeof(g_cert_muts)/sizeof(g_cert_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 12: /* ServerKeyExchange */
                call_some(g_ske_muts, sizeof(g_ske_muts)/sizeof(g_ske_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 13: /* CertificateRequest */
                call_some(g_cert_req_muts, sizeof(g_cert_req_muts)/sizeof(g_cert_req_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 15: /* CertificateVerify */
                call_some(g_cv_muts, sizeof(g_cv_muts)/sizeof(g_cv_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 16: /* ClientKeyExchange */
                call_some(g_cke_muts, sizeof(g_cke_muts)/sizeof(g_cke_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            case 20: /* Finished */
                call_some(g_finished_muts, sizeof(g_finished_muts)/sizeof(g_finished_muts[0]),
                          pkts, n, 1u, k_local);
                break;

            default:
                /* unknown handshake: rely on header + record header mutations for diversity */
                if (deep) {
                    call_some(g_handshake_hdr_muts, sizeof(g_handshake_hdr_muts)/sizeof(g_handshake_hdr_muts[0]),
                              pkts, n, 1u, 2u);
                }
                break;
            }

        } else if (p->kind == DTLS_PKT_ALERT) {
            call_some(g_alert_muts, sizeof(g_alert_muts)/sizeof(g_alert_muts[0]),
                      pkts, n, 1u, k_local);

        } else if (p->kind == DTLS_PKT_APPLICATION_DATA) {
            call_some(g_appdata_muts, sizeof(g_appdata_muts)/sizeof(g_appdata_muts[0]),
                      pkts, n, 1u, k_local);

        } else if (p->kind == DTLS_PKT_CHANGE_CIPHER_SPEC) {
            /* no (dtls_packet_t*,size_t) mutator in your list for CCS value; keep it header/record based */
            if (deep) {
                call_some(g_record_hdr_muts, sizeof(g_record_hdr_muts)/sizeof(g_record_hdr_muts[0]),
                          pkts, n, 1u, 2u);
            }

        } else { /* DTLS_PKT_ENCRYPTED or unknown */
            /* treat as opaque: only record header mutations apply */
            if (deep) {
                call_some(g_record_hdr_muts, sizeof(g_record_hdr_muts)/sizeof(g_record_hdr_muts[0]),
                          pkts, n, 1u, 2u);
            }
        }

        /* extra random mix-in to avoid collapsing into one pattern */
        if ((xorshift32() & 7u) == 0u) { /* ~12.5% */
            /* choose one “orthogonal” area */
            uint32_t pick = xorshift32() % 5u;
            if (pick == 0) call_one(g_record_hdr_muts, sizeof(g_record_hdr_muts)/sizeof(g_record_hdr_muts[0]), pkts, n);
            else if (pick == 1) call_one(g_handshake_hdr_muts, sizeof(g_handshake_hdr_muts)/sizeof(g_handshake_hdr_muts[0]), pkts, n);
            else if (pick == 2) call_one(g_alert_muts, sizeof(g_alert_muts)/sizeof(g_alert_muts[0]), pkts, n);
            else if (pick == 3) call_one(g_appdata_muts, sizeof(g_appdata_muts)/sizeof(g_appdata_muts[0]), pkts, n);
            else call_one(g_client_hello_muts, sizeof(g_client_hello_muts)/sizeof(g_client_hello_muts[0]), pkts, n);
        }
    }
}
