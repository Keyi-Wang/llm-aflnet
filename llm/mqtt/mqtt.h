#ifndef MQTT_H
#define MQTT_H

#include <stdint.h>
#include <stddef.h>
#include "mqtt_packets.h"   // 这里包含所有 MQTT 数据结构定义
#include "../../types.h"          // 包含自定义类型定义
#include "../../config.h"         // 包含配置相关定义
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// mqtt_init.c
mqtt_packet_t* generate_mqtt_packets(int count);

//mqtt_parser.c
size_t parse_mqtt_msg(const uint8_t *buf, size_t buf_len,
                      mqtt_packet_t *out_packets, size_t max_count);

void print_mqtt_packets(const mqtt_packet_t *pkt, size_t index);

// mqtt_mutators.c
void dispatch_mqtt_multiple_mutations(mqtt_packet_t *pkt, int num_packets, int rounds);

//mqtt_fixers.c
void fix_mqtt(mqtt_packet_t *pkt, int num_packets);

//mqtt_reassembler.c
int reassemble_mqtt_msgs(const mqtt_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);


#ifdef __cplusplus
}
#endif

#endif /* MQTT_H */
