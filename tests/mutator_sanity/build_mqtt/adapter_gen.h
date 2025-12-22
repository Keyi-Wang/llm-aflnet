#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mqtt.h"

typedef mqtt_packet_t proto_packet_t;

/* parser / reassembler prototypes */
extern size_t parse_mqtt_msg(const uint8_t *buf, uint32_t buf_len,
                                 proto_packet_t *out_packets, uint32_t max_count);

extern int reassemble_mqtt_msgs(const proto_packet_t *packets, uint32_t num_packets,
                                    uint8_t *output_buf, uint32_t *out_len);

/*
 * Optional cleanup hook (weak):
 * If you implement this symbol somewhere, the sanity test will call it each round.
 */
extern void free_mqtt_packets(proto_packet_t *packets, uint32_t num_packets) __attribute__((weak));

static inline size_t proto_parse(const uint8_t *buf, uint32_t len,
                                 proto_packet_t *out_packets, uint32_t max_count) {
  return parse_mqtt_msg(buf, len, out_packets, max_count);
}

static inline int proto_reassemble(const proto_packet_t *packets, uint32_t num_packets,
                                   uint8_t *output_buf, uint32_t *out_len_out) {
  return reassemble_mqtt_msgs(packets, num_packets, output_buf, out_len_out);
}

static inline void proto_packets_reset(proto_packet_t *packets, uint32_t max_count) {
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}

static inline void proto_packets_cleanup(proto_packet_t *packets, uint32_t num_packets, uint32_t max_count) {
  (void)max_count;
  if (free_mqtt_packets) free_mqtt_packets(packets, num_packets);
  memset(packets, 0, (size_t)max_count * sizeof(proto_packet_t));
}
