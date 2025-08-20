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
int decode_remaining_length(const uint8_t *buf, size_t max_len,
                            uint32_t *value, int *bytes_used);
int parse_connect_packet(const uint8_t *buf, size_t len, mqtt_connect_packet_t *pkt);
int parse_subscribe_packet(const uint8_t *buf, size_t len, mqtt_subscribe_packet_t *pkt);
int parse_publish_packet(const uint8_t *buf, size_t len, mqtt_publish_packet_t *pkt, uint8_t header_flags);
int parse_unsubscribe_packet(const uint8_t *buf, size_t len, mqtt_unsubscribe_packet_t *pkt);
int parse_auth_packet(const uint8_t *buf, size_t len, mqtt_auth_packet_t *pkt);
size_t parse_mqtt_msg(const uint8_t *buf, size_t buf_len,
                      mqtt_packet_t *out_packets, size_t max_count);

void print_mqtt_packets(const mqtt_packet_t *pkt, size_t index);

// mqtt_mutators.c
void mutate_connect_flags(mqtt_connect_packet_t *pkts, int num_pkts);
void mutate_connect_keep_alive(mqtt_connect_packet_t *pkts, int num_pkts);

void add_connect_property_len(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_property_len(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_property_len(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_properties(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_properties(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_properties(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_client_id(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_client_id(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_client_id(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_user_name(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_user_name(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_user_name(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_password(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_password(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_password(mqtt_connect_packet_t *packets, int num_packets);

void add_connect_password_len(mqtt_connect_packet_t *packets, int num_packets);
void delete_connect_password_len(mqtt_connect_packet_t *packets, int num_packets);
void mutate_connect_password_len(mqtt_connect_packet_t *packets, int num_packets);

void mutate_subscribe_packet_identifier(mqtt_subscribe_packet_t *subs, size_t num_subs);

void mutate_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs);
void add_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs);
void delete_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs);
void repeat_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs);

void mutate_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs);
void repeat_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs);

void mutate_subscribe_qos(mqtt_subscribe_packet_t *subs, size_t num_subs);
void mutate_subscribe_topic_count(mqtt_subscribe_packet_t *subs, size_t num_subs);

void mutate_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num);
void add_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num);
void delete_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num);

void mutate_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num);
void add_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num);
void delete_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num);

void mutate_publish_properties(mqtt_publish_packet_t *pkts, size_t num);
void add_publish_properties(mqtt_publish_packet_t *pkts, size_t num);
void delete_publish_properties(mqtt_publish_packet_t *pkts, size_t num);
void repeat_publish_properties(mqtt_publish_packet_t *pkts, size_t num);

void mutate_publish_payload(mqtt_publish_packet_t *pkts, size_t num);
void add_publish_payload(mqtt_publish_packet_t *pkts, size_t num);
void delete_publish_payload(mqtt_publish_packet_t *pkts, size_t num);

void mutate_publish_qos(mqtt_publish_packet_t *pkts, size_t num);
void mutate_publish_dup(mqtt_publish_packet_t *pkts, size_t num);
void mutate_publish_retain(mqtt_publish_packet_t *pkts, size_t num);

void mutate_unsubscribe_packet_identifier(mqtt_unsubscribe_packet_t *pkts, int num);

void add_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num);
void delete_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num);
void repeat_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num);
void mutate_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num);

void repeat_unsubscribe_topic_filters(mqtt_unsubscribe_packet_t *pkts, int num);
void mutate_unsubscribe_topic_filters(mqtt_unsubscribe_packet_t *pkts, int num);

void mutate_auth_reason_code(mqtt_auth_packet_t *pkts, int num);
void add_auth_reason_code(mqtt_auth_packet_t *pkts, int num);
void delete_auth_reason_code(mqtt_auth_packet_t *pkts, int num);

void mutate_auth_properties(mqtt_auth_packet_t *pkts, int num);
void add_auth_properties(mqtt_auth_packet_t *pkts, int num);
void repeat_auth_properties(mqtt_auth_packet_t *pkts, int num);

void dispatch_connect_mutation(mqtt_connect_packet_t *pkt, int num_packets);
void dispatch_subscribe_mutation(mqtt_subscribe_packet_t *pkt, int num_packets);
void dispatch_publish_mutation(mqtt_publish_packet_t *pkt, int num_packets);
void dispatch_unsubscribe_mutation(mqtt_unsubscribe_packet_t *pkt, int num_packets);
void dispatch_auth_mutation(mqtt_auth_packet_t *pkt, int num_packets);

void dispatch_mqtt_multiple_mutations(mqtt_packet_t *pkt, int num_packets, int rounds);

//mqtt_fixers.c
// CONNECT fixers
void fix_connect_packet_will_rules(mqtt_connect_packet_t *packets, int num_packets);
void fix_user_name_flag(mqtt_connect_packet_t *packets, int num_packets);
void fix_password_flag(mqtt_connect_packet_t *packets, int num_packets);
void fix_connect_all_length(mqtt_connect_packet_t *packets, int num_packets);

// PUBLISH fixers
void fix_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_packet_identifier_unique(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_dup_flag(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_qos_bits(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_topic_alias(mqtt_publish_packet_t *pkts, size_t num_pkts, uint16_t connack_alias_max);
void fix_publish_response_topic(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_subscription_identifier(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_delivery_protocol(mqtt_publish_packet_t *pkts, size_t num_pkts);
void fix_publish_all_length(mqtt_publish_packet_t *packets, int num_packets);

// SUBSCRIBE fixers
void fix_subscribe_no_local(mqtt_subscribe_packet_t *pkts, size_t num_pkts);
void fix_subscribe_packet_identifier(mqtt_subscribe_packet_t *pkts, size_t num_pkts);
void fix_subscribe_packet_identifier_unique(mqtt_subscribe_packet_t *pkts, size_t num_pkts);
void fix_subscribe_all_length(mqtt_subscribe_packet_t *packets, int num_packets);

// UNSUBSCRIBE fixers
void fix_unsubscribe_packet_identifier(mqtt_unsubscribe_packet_t *packets, int num_packets);
void fix_unsubscribe_all_length(mqtt_unsubscribe_packet_t *packets, int num_packets);

// AUTH fixers
void fix_auth_all_length(mqtt_auth_packet_t *packets, int num_packets);

// Grouped fixers
void fix_connect(mqtt_connect_packet_t *packets, int num_packets);
void fix_subscribe(mqtt_subscribe_packet_t *packets, int num_packets);
void fix_publish(mqtt_publish_packet_t *packets, int num_packets);
void fix_unsubscribe(mqtt_unsubscribe_packet_t *packets, int num_packets);
void fix_auth(mqtt_auth_packet_t *packets, int num_packets);
void fix_mqtt(mqtt_packet_t *pkt, int num_packets);

//mqtt_reassembler.c

size_t write_utf8_str(uint8_t *buf, const char *str);
size_t write_remaining_length(uint8_t *buf, uint32_t len);
void write_uint16(uint8_t *buf, uint16_t val);

int reassemble_single_msg(const mqtt_packet_t *pkt, u8 *output_buf, u32 *out_len);
int reassemble_mqtt_msgs(const mqtt_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);


#ifdef __cplusplus
}
#endif

#endif /* MQTT_H */
