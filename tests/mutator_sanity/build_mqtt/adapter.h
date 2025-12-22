#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* packets type */
#include "mqtt_packets.h"

typedef mqtt_packet_t proto_packet_t;

/* parser/reassembler prototypes (use stdint types; compatible with u8/u32 typedefs) */
extern size_t parse_mqtt_msg(const uint8_t *buf, uint32_t buf_len,
                                 proto_packet_t *out_packets, uint32_t max_count);

extern int reassemble_mqtt_msgs(const proto_packet_t *packets, uint32_t num_packets,
                                    uint8_t *output_buf, uint32_t *out_len);

/*
 * 可选：如果你项目里有释放函数，建议按这个名字实现：
 *   void free_mqtt_packets(proto_packet_t *packets, uint32_t num_packets);
 * 这样测试不会因为重复多轮而内存暴涨。
 */
extern void free_mqtt_packets(proto_packet_t *packets, uint32_t num_packets) __attribute__((weak));

static inline size_t proto_parse(const uint8_t *buf, uint32_t len,
                                 proto_packet_t *out_packets, uint32_t max_count) {
  return parse_mqtt_msg(buf, len, out_packets, max_count);
}

static inline int proto_reassemble(const proto_packet_t *packets, uint32_t num_packets,
                                   uint8_t *output_buf, uint32_t *out_len_inout) {
  return reassemble_mqtt_msgs(packets, num_packets, output_buf, out_len_inout);
}

/* 每次 parse 前建议 reset，避免上轮残留影响 */
static inline void proto_packets_reset(proto_packet_t *packets, uint32_t max_count) {
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}

/* 每轮结束后清理（若 free_mqtt_packets 存在则调用） */
static inline void proto_packets_cleanup(proto_packet_t *packets, uint32_t num_packets, uint32_t max_count) {
  (void)max_count;
  if (free_mqtt_packets) free_mqtt_packets(packets, num_packets);
  /* 清零避免悬挂指针被下轮误用 */
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}
