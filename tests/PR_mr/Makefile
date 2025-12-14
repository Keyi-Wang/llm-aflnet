# Usage:
#   make PROTO=ftp
# Optionally specify symbol names:
#   make PROTO=ftp PARSE_SYM=ftp_parse REASM_SYM=ftp_reassemble
# If adapters/ftp_adapter.c exists, it takes precedence (no need to set PARSE/REASM_SYM).


ROOT := ../..
PROTOSRC := $(ROOT)/llm/$(PROTO)

CC ?= clang
SAN ?= 1
CFLAGS_BASE := -O0 -g -Wall -Wextra -I. -I$(PROTOSRC)
LDFLAGS_BASE :=

# ---- 覆盖率开关：make PROTO=ftp COVERAGE=1 ----
ifeq ($(COVERAGE),1)
  CFLAGS_BASE  += --coverage
  LDFLAGS_BASE += --coverage
endif

ifeq ($(SAN),1)
  CFLAGS_BASE += -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS_BASE += -fsanitize=address,undefined
endif

OBJS := mr_test.o

ifeq ($(wildcard adapters/$(PROTO)_adapter.c),)

  ifeq ($(PARSE_SYM),)
    PARSE_SYM := $(PROTO)_parse
  endif
  ifeq ($(REASM_SYM),)
    REASM_SYM := $(PROTO)_reassemble
  endif
  CFLAGS := $(CFLAGS_BASE) -DPARSE_SYM=$(PARSE_SYM) -DREASM_SYM=$(REASM_SYM)
  OBJS += generic_adapter.o
else
  CFLAGS := $(CFLAGS_BASE)
  OBJS += adapters/$(PROTO)_adapter.o
endif

# 链接时使用带好 SAN / COVERAGE 的 LDFLAGS_BASE
LDFLAGS := $(LDFLAGS_BASE)

# 协议源码列表（保持原来写法）
PROTO_SRCS := $(wildcard $(PROTOSRC)/*_parser.c) $(wildcard $(PROTOSRC)/*_reassembler.c)

# 不再生成 PROTO_OBJS，直接在链接时编译这些 .c
all: check-proto mr_test

check-proto:
	@if [ -z "$(PROTO)" ]; then echo "Please set PROTO=<name>, e.g. make PROTO=ftp"; exit 1; fi
	@if [ ! -d "$(PROTOSRC)" ]; then echo "Protocol dir not found: $(PROTOSRC)"; exit 1; fi

mr_test: $(OBJS) $(PROTO_SRCS)
	$(CC) $(CFLAGS) $(OBJS) $(PROTO_SRCS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f mr_test $(OBJS)
