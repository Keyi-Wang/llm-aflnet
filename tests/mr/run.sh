#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <PROTO> <SEED_DIR> [JOBS]"
  exit 2
fi

PROTO="$1"
SEED_DIR="$2"
JOBS="${3:-$(nproc)}"

cd "$(dirname "$0")"   # into tests/mr
make clean >/dev/null 2>&1 || true
make PROTO="$PROTO"

OUT="out/${PROTO}-$(date +%F-%H%M%S)"
mkdir -p "$OUT"
export MR_OUTDIR="$OUT"



echo "[*] Running MR test: PROTO=$PROTO, SEEDS=$SEED_DIR, OUT=$OUT, JOBS=$JOBS"
find "$SEED_DIR" -type f -print0 | xargs -0 -n1 -P"$JOBS" -I{} bash -c '
  f="{}"
  if ./mr_test "$f"; then
    echo "[PASS] $f"
  else
    echo "[FAIL] $f"
  fi
' | tee "$OUT/run.log"

PASS=$(grep -c "^\[PASS\]" "$OUT/run.log" || true)
FAIL=$(grep -c "^\[FAIL\]" "$OUT/run.log" || true)
echo "==== SUMMARY ===="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "Failures saved under: $OUT/"
