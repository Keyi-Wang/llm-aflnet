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

# 1) 清理旧的可执行文件 & 覆盖率数据
make clean >/dev/null 2>&1 || true
# 建议把上一次残留的 *.gcda 删掉，避免污染统计
find .. -name '*.gcda' -delete >/dev/null 2>&1 || true

# 2) 带覆盖率编译 mr_test（会给 mr_test + llm/$PROTO/*.c 加上 --coverage）
make PROTO="$PROTO" COVERAGE=1

OUT="out/${PROTO}-$(date +%F-%H%M%S)"
mkdir -p "$OUT"
export MR_OUTDIR="$OUT"

echo "[*] Running MR test: PROTO=$PROTO, SEEDS=$SEED_DIR, OUT=$OUT, JOBS=$JOBS"

# 3) 跑 MR 测试
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

# 4) 收集覆盖率：根据 PROTO 自动聚焦 llm/$PROTO 下的源码
echo "[*] Collecting coverage for PROTO=$PROTO ..."

# 项目根目录：tests/mr/ 的上上级（和 Makefile 里的 ROOT := ../.. 对齐）
ROOT_DIR="$(cd ../.. && pwd)"
PROTO_DIR="$ROOT_DIR/llm/$PROTO"

echo "    ROOT_DIR = $ROOT_DIR"
echo "    PROTO_DIR = $PROTO_DIR"

# 4.1 纯文本总览（标准输出重定向到 txt）
gcovr -r "$ROOT_DIR" \
  --filter "$PROTO_DIR" \
  --branches \
  > "$OUT/coverage.txt" || true

# 4.2 XML 报告（比如给 CI / 其它工具用）
gcovr -r "$ROOT_DIR" \
  --filter "$PROTO_DIR" \
  --branches \
  --xml \
  -o "$OUT/coverage.xml" || true

# 4.3 HTML 报告（带明细行）
gcovr -r "$ROOT_DIR" \
  --filter "$PROTO_DIR" \
  --branches \
  --html --html-details \
  -o "$OUT/coverage.html" || true

echo "[*] Coverage reports written to:"
echo "    $OUT/coverage.txt"
echo "    $OUT/coverage.xml"
echo "    $OUT/coverage.html"
