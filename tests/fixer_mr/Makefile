# tests/mr/Makefile

ROOT       := ../..
LLM_DIR    := $(ROOT)/llm

CC         ?= gcc
CFLAGS     ?= -std=c11 -Wall -Wextra -O2
LDFLAGS    ?=
PROTO      ?= ftp        # 默认协议
COVERAGE   ?= 0

# 覆盖率开关
ifeq ($(COVERAGE),1)
  CFLAGS  += --coverage
  LDFLAGS += --coverage
endif

# ===== 根据 PROTO 选择具体类型/函数名 =====
# 这些要和你各协议的头文件 / 函数命名保持一致

ifeq ($(PROTO),ftp)
  PROTO_HEADER      := ftp.h
  PACKET_TYPE       := ftp_packet_t
  PARSE_FUNC        := parse_ftp_msg
  REASSEMBLE_FUNC   := reassemble_ftp_msgs
  MUTATE_FUNC       := dispatch_ftp_multiple_mutations
  FIX_FUNC          := fix_ftp
  PROTO_SRCS        := $(LLM_DIR)/ftp/ftp_parser.c \
                       $(LLM_DIR)/ftp/ftp_mutators.c \
                       $(LLM_DIR)/ftp/ftp_fixers.c \
					   $(LLM_DIR)/ftp/ftp_reassembler.c
else ifeq ($(PROTO),sip)
  PROTO_HEADER      := sip.h
  PACKET_TYPE       := sip_packet_t
  PARSE_FUNC        := parse_sip_msg
  REASSEMBLE_FUNC   := reassemble_sip_msgs
  MUTATE_FUNC       := dispatch_sip_multiple_mutations
  FIX_FUNC          := fix_sip
  PROTO_SRCS        := $(LLM_DIR)/sip/sip_parser.c \
                       $(LLM_DIR)/sip/sip_mutators.c \
                       $(LLM_DIR)/sip/sip_fixers.c \
					   $(LLM_DIR)/sip/sip_reassembler.c
# 在这里继续加其它协议，例如 mqtt / rtsp / smtp 等
else ifeq ($(PROTO),mqtt)
 PROTO_HEADER      := mqtt.h
 PACKET_TYPE       := mqtt_packet_t
 PARSE_FUNC        := parse_mqtt_msg
 REASSEMBLE_FUNC   := reassemble_mqtt_msgs
 MUTATE_FUNC       := dispatch_mqtt_multiple_mutations
 FIX_FUNC          := fix_mqtt
 PROTO_SRCS        := $(LLM_DIR)/mqtt/mqtt_parser.c \
                      $(LLM_DIR)/mqtt/mqtt_mutators.c \
                      $(LLM_DIR)/mqtt/mqtt_fixers.c \
					  $(LLM_DIR)/mqtt/mqtt_reassembler.c
endif

# === 通用宏注入 ===
CFLAGS += \
  -DPROTO_HEADER=$(PROTO_HEADER) \
  -DPACKET_TYPE=$(PACKET_TYPE) \
  -DPARSE_FUNC=$(PARSE_FUNC) \
  -DREASSEMBLE_FUNC=$(REASSEMBLE_FUNC) \
  -DMUTATE_FUNC=$(MUTATE_FUNC) \
  -DFIX_FUNC=$(FIX_FUNC)
CFLAGS += -I$(LLM_DIR)/$(PROTO)
MR_SRCS := mr_test.c $(PROTO_SRCS)

all: mr_test

mr_test: $(MR_SRCS)
	$(CC) $(CFLAGS) -o $@ $(MR_SRCS) $(LDFLAGS)

clean:
	rm -f mr_test *.o *.gcno *.gcda
