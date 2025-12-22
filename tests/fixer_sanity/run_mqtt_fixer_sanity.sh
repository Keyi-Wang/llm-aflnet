#!/usr/bin/env bash
set -euo pipefail

# MQTT fixer sanity runner.
# Expected layout:
#   <ROOT>/llm/mqtt/mqtt_fixers.c
#   <ROOT>/tests/fixer_sanity/mqtt_fixer_sanity_tests.c  (this test file)
#   <ROOT>/tests/fixer_sanity/run_mqtt_fixer_sanity.sh   (this script)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEST_FILE="${TEST_FILE:-${SCRIPT_DIR}/mqtt_fixer_sanity_tests.c}"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build_mqtt_fixer_sanity}"
BIN="${BUILD_DIR}/mqtt_fixer_sanity"

mkdir -p "${BUILD_DIR}"

# Choose compiler
CC="${CC:-}"
if [ -z "${CC}" ]; then
  if command -v clang >/dev/null 2>&1; then
    CC=clang
  else
    CC=gcc
  fi
fi

SAN="${SAN:-1}"
SAN_FLAGS=""
if [ "${SAN}" = "1" ]; then
  SAN_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
fi

CFLAGS="${CFLAGS:- -std=c11 -O0 -g -Wall -Wextra -Wno-unused-function -Wno-unused-parameter}"
INCLUDES="-I${ROOT_DIR}/llm/mqtt -I${ROOT_DIR}/llm -I${ROOT_DIR}"

echo "[*] ROOT_DIR = ${ROOT_DIR}"
echo "[*] TEST_FILE = ${TEST_FILE}"
echo "[*] CC = ${CC}"
echo "[*] SAN = ${SAN}"
echo "[*] BUILD_DIR = ${BUILD_DIR}"

set -x
"${CC}" ${CFLAGS} ${SAN_FLAGS} ${INCLUDES} -o "${BIN}" "${TEST_FILE}"
set +x

echo "[*] Running: ${BIN}"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" "${BIN}"
