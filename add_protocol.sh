#!/bin/bash
set -e

if [ $# -ne 1 ]; then
    echo "用法: $0 <protocol_name>"
    exit 1
fi

PROTO="$1"
AFLNET="$PWD"  # 假设脚本在AFLNET目录执行
PROTO_DIR="$AFLNET/llm/$PROTO"

# 1️ 创建目录
mkdir -p "$PROTO_DIR"

# 2 创建头文件
PROTO_H="$PROTO_DIR/${PROTO}.h"
PROTO_PACKETS_H="$PROTO_DIR/${PROTO}_packets.h"

if [ ! -f "$PROTO_PACKETS_H" ]; then
    echo "/* $PROTO packet definitions */" > "$PROTO_PACKETS_H"
fi

if [ ! -f "$PROTO_H" ]; then
    echo "#ifndef ${PROTO^^}_H" > "$PROTO_H"
    echo "#define ${PROTO^^}_H" >> "$PROTO_H"
    echo "" >> "$PROTO_H"
    echo "#include \"${PROTO}_packets.h\"" >> "$PROTO_H"
    echo "#include \"../../types.h\"" >> "$PROTO_H"
    echo "#include \"../../config.h\"" >> "$PROTO_H"
    echo "" >> "$PROTO_H"
    echo "#endif /* ${PROTO^^}_H */" >> "$PROTO_H"
fi

# 3 创建空的源文件
for f in init parser mutators fixers reassembler; do
    FILE="$PROTO_DIR/${PROTO}_${f}.c"
    if [ ! -f "$FILE" ]; then
        echo "/* $PROTO $f source file */" > "$FILE"
        echo "#include \"${PROTO}.h\"" >> "$FILE"
        echo "" >> "$FILE"
    fi
done

# 4 在Makefile添加SRC和OBJ定义
MAKEFILE="$AFLNET/Makefile"

# 检查是否已存在
if ! grep -q "${PROTO}_SRC" "$MAKEFILE"; then
    echo "" >> "$MAKEFILE"
    echo "${PROTO}_SRC = llm/${PROTO}/${PROTO}_init.c \\" >> "$MAKEFILE"
    echo "              llm/${PROTO}/${PROTO}_parser.c \\" >> "$MAKEFILE"
    echo "              llm/${PROTO}/${PROTO}_mutators.c \\" >> "$MAKEFILE"
    echo "              llm/${PROTO}/${PROTO}_fixers.c \\" >> "$MAKEFILE"
    echo "              llm/${PROTO}/${PROTO}_reassembler.c" >> "$MAKEFILE"
    echo "${PROTO}_OBJ = \$(${PROTO}_SRC:.c=.o)" >> "$MAKEFILE"
    echo "已添加 ${PROTO}_SRC 和 ${PROTO}_OBJ 到 Makefile"
fi

# 5 修改afl-fuzz目标的依赖和链接
if ! grep -q "\$(${PROTO}_OBJ)" "$MAKEFILE"; then
    sed -i "/^afl-fuzz:/ s/\$/ \$(${PROTO}_OBJ)/" "$MAKEFILE"
    sed -i "/\$(CC) \$(CFLAGS) .*aflnet.o \$(MQTT_OBJ) \$(RTSP_OBJ)/ s/\$/ \$(${PROTO}_OBJ)/" "$MAKEFILE"
    echo "已将 ${PROTO}_OBJ 添加到 afl-fuzz 编译规则"
fi

echo "✅ 协议 $PROTO 添加完成"
