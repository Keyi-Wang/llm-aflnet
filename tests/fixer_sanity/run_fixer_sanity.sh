#!/usr/bin/env bash
set -euo pipefail

# Generic fixer sanity runner.
# Usage:
#   tests/fixer_sanity/run_fixer_sanity.sh <PROTO> [--verbose ...]
#
# Examples:
#   tests/fixer_sanity/run_fixer_sanity.sh dtls --verbose
#   tests/fixer_sanity/run_fixer_sanity.sh mqtt
#
# Env:
#   CC=clang|gcc
#   SAN=1 (default 1)
#   CFLAGS="..."
#   TEST_FILE=".../xxx_tests.c"  (override)
#   BUILD_DIR="..." OUT_DIR="..." BIN="..." (override)
#
# It will:
#   - compile <proto>_fixer_sanity_tests.c
#   - run it (passes --out <OUT_DIR> if supported)
#   - print where illegal_fixers.txt would be (if produced)

if [ $# -lt 1 ]; then
  echo "Usage: $0 <PROTO> [args...]" >&2
  exit 2
fi

PROTO_RAW="$1"
shift
PROTO="$(echo "$PROTO_RAW" | tr '[:upper:]' '[:lower:]')"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEST_FILE="${TEST_FILE:-${SCRIPT_DIR}/${PROTO}_fixer_sanity_tests.c}"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build_${PROTO}_fixer_sanity}"
BIN="${BIN:-${BUILD_DIR}/${PROTO}_fixer_sanity}"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out_fixer_sanity_${PROTO}}"

mkdir -p "$BUILD_DIR" "$OUT_DIR"

if [ ! -f "$TEST_FILE" ]; then
  echo "[!] TEST_FILE not found: $TEST_FILE" >&2
  exit 2
fi

# Choose compiler
CC="${CC:-}"
if [ -z "$CC" ]; then
  if command -v clang >/dev/null 2>&1; then
    CC=clang
  else
    CC=gcc
  fi
fi

SAN="${SAN:-1}"
SAN_FLAGS=()
if [ "$SAN" = "1" ]; then
  SAN_FLAGS=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi

# Default flags (you can override via env CFLAGS)
# Note: keep as a string so user can override easily.
CFLAGS_STR="${CFLAGS:- -std=c11 -O0 -g -Wall -Wextra -Wno-unused-function -Wno-unused-parameter}"

# Include paths:
# Always include ROOT; plus llm and llm/<proto> if present.
INCLUDES=("-I${ROOT_DIR}")
if [ -d "${ROOT_DIR}/llm" ]; then
  INCLUDES+=("-I${ROOT_DIR}/llm")
fi
if [ -d "${ROOT_DIR}/llm/${PROTO}" ]; then
  INCLUDES+=("-I${ROOT_DIR}/llm/${PROTO}")
fi
# Backward compatible: some repos use llm/mqtt style headers even if proto dir doesn't exist
# (already covered by llm/<proto> above).

echo "[*] ROOT_DIR  = $ROOT_DIR"
echo "[*] PROTO     = $PROTO"
echo "[*] TEST_FILE = $TEST_FILE"
echo "[*] BUILD_DIR = $BUILD_DIR"
echo "[*] BIN       = $BIN"
echo "[*] OUT_DIR   = $OUT_DIR"
echo "[*] CC        = $CC"
echo "[*] SAN       = $SAN"

# Build
set -x
"$CC" $CFLAGS_STR "${SAN_FLAGS[@]}" "${INCLUDES[@]}" -o "$BIN" "$TEST_FILE"
set +x
echo "[*] built: $BIN"

# Run
RUN_ARGS=("$@")

# Pass sanitizer opts for stability (same as your mqtt script)
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"

# Try to detect whether the binary supports --out. If not, skip it.
# (This keeps dtls behavior while not breaking mqtt tests that don't parse --out.)
SUPPORTS_OUT=0
if "$BIN" --help 2>&1 | grep -q -- '--out'; then
  SUPPORTS_OUT=1
fi

echo "[*] run..."
if [ "$SUPPORTS_OUT" = "1" ]; then
  echo "[*] passing: --out $OUT_DIR"
  "$BIN" --out "$OUT_DIR" "${RUN_ARGS[@]}"
else
  "$BIN" "${RUN_ARGS[@]}"
fi

echo "[*] done."
echo "[*] (if produced) illegal list: $OUT_DIR/illegal_fixers.txt"
