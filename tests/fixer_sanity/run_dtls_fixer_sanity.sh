#!/usr/bin/env bash
set -euo pipefail

# run_dtls_fixer_sanity.sh
# Place this script at: tests/fixer_sanity/run_dtls_fixer_sanity.sh
# Then run (from repo root or anywhere):
#   tests/fixer_sanity/run_dtls_fixer_sanity.sh [--verbose]
#
# It will:
#   - compile tests/fixer_sanity/dtls_fixer_sanity_tests.c
#   - run it
#   - write out_fixer_sanity_dtls/illegal_fixers.txt

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$THIS_DIR/../.." && pwd)"

TEST_C="$THIS_DIR/dtls_fixer_sanity_tests.c"
BUILD_DIR="$THIS_DIR/build_dtls"
OUT_DIR="${ROOT_DIR}/tests/fixer_sanity/out_fixer_sanity_dtls"

mkdir -p "$BUILD_DIR" "$OUT_DIR"

CC="${CC:-clang}"
CFLAGS=(
  -std=c11 -O0 -g
  -Wall -Wextra
  -Wno-unused-function
)

# Optional sanitizers (set SAN=1 to enable)
if [[ "${SAN:-0}" == "1" ]]; then
  CFLAGS+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi

BIN="$BUILD_DIR/dtls_fixer_sanity"

echo "[*] build: $BIN"
"$CC" "${CFLAGS[@]}" \
  -I"$ROOT_DIR" \
  -o "$BIN" \
  "$TEST_C"

echo "[*] run..."
"$BIN" --out "$OUT_DIR" ${1:-}

echo "[*] done."
echo "[*] illegal list: $OUT_DIR/illegal_fixers.txt"
