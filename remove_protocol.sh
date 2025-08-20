#!/bin/bash
set -e

if [ $# -ne 1 ]; then
    echo "用法: $0 <protocol_name>"
    exit 1
fi

PROTO="$1"
AFLNET="$PWD"  # 假设脚本在AFLNET目录执行
PROTO_DIR="$AFLNET/llm/$PROTO"
MAKEFILE="$AFLNET/Makefile"

# 1️⃣ 删除协议目录
if [ -d "$PROTO_DIR" ]; then
    rm -rf "$PROTO_DIR"
    echo "已删除目录: $PROTO_DIR"
else
    echo "目录 $PROTO_DIR 不存在，跳过删除"
fi

# 2️⃣ 删除 Makefile 中的 SRC/OBJ 定义
if grep -q "${PROTO}_SRC" "$MAKEFILE"; then
    # 删除 SRC 和 OBJ 定义
    sed -i "/^${PROTO}_SRC =/,/llm\/${PROTO}\/${PROTO}_reassembler.c/d" "$MAKEFILE"
    sed -i "/^${PROTO}_OBJ =.*${PROTO}_SRC:.c=.o/d" "$MAKEFILE"
    echo "已删除 ${PROTO}_SRC 和 ${PROTO}_OBJ 定义"
fi

# 3️⃣ 删除 afl-fuzz 编译规则中的 $(PROTO_OBJ)
if grep -q "\$(${PROTO}_OBJ)" "$MAKEFILE"; then
    sed -i "s/ \$(\(${PROTO}_OBJ\))//g" "$MAKEFILE"
    echo "已从 afl-fuzz 规则中移除 $( ${PROTO}_OBJ )"
fi

echo "✅ 协议 $PROTO 清理完成"
