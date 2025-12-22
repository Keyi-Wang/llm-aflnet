#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <PROTO> <SEED_DIR>"
  exit 2
fi

PROTO_RAW="$1"
SEED_DIR="$2"
PROTO="$(echo "$PROTO_RAW" | tr '[:upper:]' '[:lower:]')"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---- locate per-proto files (support llm/$PROTO/$PROTO_*.c and llm/$PROTO_*.c) ----
PROTO_DIR="${ROOT_DIR}/llm/${PROTO}"

if [ -d "$PROTO_DIR" ]; then
  MUT_C="${PROTO_DIR}/${PROTO}_mutators.c"
  PARSER_C="${PROTO_DIR}/${PROTO}_parser.c"
  REASM_C="${PROTO_DIR}/${PROTO}_reassembler.c"
  PKTS_H="${PROTO_DIR}/${PROTO}.h"
else
  MUT_C="${ROOT_DIR}/llm/${PROTO}_mutators.c"
  PARSER_C="${ROOT_DIR}/llm/${PROTO}_parser.c"
  REASM_C="${ROOT_DIR}/llm/${PROTO}_reassembler.c"
  PKTS_H="${ROOT_DIR}/llm/${PROTO}.h"
fi

for f in "$MUT_C" "$PARSER_C" "$REASM_C" "$PKTS_H"; do
  if [ ! -f "$f" ]; then
    echo "[!] Missing required file: $f" >&2
    exit 2
  fi
done

if [ ! -d "$SEED_DIR" ]; then
  echo "[!] SEED_DIR not found: $SEED_DIR" >&2
  exit 2
fi

# ---- tunables ----
ROUNDS="${ROUNDS:-500}"
MAX_PKTS="${MAX_PKTS:-256}"
OUT_CAP="${OUT_CAP:-1048576}"   # 1MB
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/tests/mutator_sanity/out_mutator_sanity_${PROTO}}"
NAME_REGEX="${NAME_REGEX:-^(add_|mutate_|delete_|repeat_)}"
EXCLUDE_REGEX="${EXCLUDE_REGEX:-}"
VERBOSE="${VERBOSE:-0}"
NO_FORK="${NO_FORK:-0}"

BUILD_DIR="${SCRIPT_DIR}/build_${PROTO}"
mkdir -p "$BUILD_DIR"

# ---- generate adapter_gen.h into BUILD_DIR ----
# adapter.h (shim) lives in tests/mutator_sanity/, and includes "adapter_gen.h".
# Since we compile with -I BUILD_DIR, it will resolve to BUILD_DIR/adapter_gen.h.
cat > "${BUILD_DIR}/adapter_gen.h" <<EOF
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "${PROTO}.h"

typedef ${PROTO}_packet_t proto_packet_t;

/* parser / reassembler prototypes */
extern size_t parse_${PROTO}_msg(const uint8_t *buf, uint32_t buf_len,
                                 proto_packet_t *out_packets, uint32_t max_count);

extern int reassemble_${PROTO}_msgs(const proto_packet_t *packets, uint32_t num_packets,
                                    uint8_t *output_buf, uint32_t *out_len);

/*
 * Optional cleanup hook (weak):
 * If you implement this symbol somewhere, the sanity test will call it each round.
 */
extern void free_${PROTO}_packets(proto_packet_t *packets, uint32_t num_packets) __attribute__((weak));

static inline size_t proto_parse(const uint8_t *buf, uint32_t len,
                                 proto_packet_t *out_packets, uint32_t max_count) {
  return parse_${PROTO}_msg(buf, len, out_packets, max_count);
}

static inline int proto_reassemble(const proto_packet_t *packets, uint32_t num_packets,
                                   uint8_t *output_buf, uint32_t *out_len_out) {
  return reassemble_${PROTO}_msgs(packets, num_packets, output_buf, out_len_out);
}

static inline void proto_packets_reset(proto_packet_t *packets, uint32_t max_count) {
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}

static inline void proto_packets_cleanup(proto_packet_t *packets, uint32_t num_packets, uint32_t max_count) {
  (void)max_count;
  if (free_${PROTO}_packets) free_${PROTO}_packets(packets, num_packets);
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}
EOF

# ---- generate mutator_registry.c ----
python3 "${SCRIPT_DIR}/gen_mutator_registry.py" \
  --mutators "$MUT_C" \
  --out "${BUILD_DIR}/mutator_registry.c" \
  --pkt-type "${PROTO}_packet_t" \


# ---- compile ----
BIN="${BUILD_DIR}/mutator_sanity_${PROTO}"

CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O2 -g -Wall -Wextra -Wno-unused-function}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"
LDFLAGS="${LDFLAGS:-}"
EXTRA_LDFLAGS="${EXTRA_LDFLAGS:-}"

# include paths:
#  - BUILD_DIR: adapter_gen.h + generated mutator_registry.c
#  - SCRIPT_DIR: mutator_registry.h + adapter.h shim + mutator_sanity.c
#  - PROTO_DIR (if exists): so "#include mqtt.h" resolves
#  - ROOT_DIR/llm: fallback
INCLUDES="-I${BUILD_DIR} -I${SCRIPT_DIR}"
if [ -d "$PROTO_DIR" ]; then
  INCLUDES="${INCLUDES} -I${PROTO_DIR}"
fi
INCLUDES="${INCLUDES} -I${ROOT_DIR}/llm -I${ROOT_DIR}"

$CC $CFLAGS $EXTRA_CFLAGS $INCLUDES \
  -o "$BIN" \
  "${SCRIPT_DIR}/mutator_sanity.c" \
  "${BUILD_DIR}/mutator_registry.c" \
  "$PARSER_C" \
  "$REASM_C" \
  $LDFLAGS $EXTRA_LDFLAGS

echo "[*] Built: $BIN" >&2

RUN_ARGS=(--seeds "$SEED_DIR" --rounds "$ROUNDS" --max-pkts "$MAX_PKTS" --out-cap "$OUT_CAP" --out "$OUT_DIR")
if [ "$VERBOSE" = "1" ]; then RUN_ARGS+=(--verbose); fi
if [ "$NO_FORK" = "1" ]; then RUN_ARGS+=(--no-fork); fi

echo "[*] Run: $BIN ${RUN_ARGS[*]}" >&2
"$BIN" "${RUN_ARGS[@]}"
