#include "mqtt.h"
#include <stdio.h>
static uint16_t read_uint16(const uint8_t *data) {
    return (data[0] << 8) | data[1];
}

// 解析 MQTT Remaining Length (可变长编码)
int decode_remaining_length(const uint8_t *buf, size_t max_len, uint32_t *value, int *bytes_used) {
    uint32_t multiplier = 1;
    *value = 0;
    *bytes_used = 0;
    for (int i = 0; i < 4 && i < max_len; i++) {
        uint8_t byte = buf[i];
        *value += (byte & 127) * multiplier;
        multiplier *= 128;
        (*bytes_used)++;
        if ((byte & 0x80) == 0)
            return 0;
    }
    return -1;  // 编码错误
}

// 解析 CONNECT 报文
int parse_connect_packet(const uint8_t *buf, size_t len, mqtt_connect_packet_t *pkt) {
    size_t offset = 0;

    // Variable Header
    uint16_t proto_len = read_uint16(buf + offset); offset += 2;
    if (proto_len >= MAX_PROTOCOL_NAME_LEN) return -1;
    memcpy(pkt->variable_header.protocol_name, buf + offset, proto_len);
    pkt->variable_header.protocol_name[proto_len] = '\0';
    offset += proto_len;

    pkt->variable_header.protocol_level = buf[offset++];
    pkt->variable_header.connect_flags = buf[offset++];
    pkt->variable_header.keep_alive = read_uint16(buf + offset); offset += 2;

    // Property Length (VarInt)
    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0) return -1;
    pkt->variable_header.property_len = prop_len;
    offset += prop_len_bytes;

    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    // Payload: Client ID
    uint16_t client_id_len = read_uint16(buf + offset); offset += 2;
    if (client_id_len >= MAX_CLIENT_ID_LEN) return -1;
    memcpy(pkt->payload.client_id, buf + offset, client_id_len);
    pkt->payload.client_id[client_id_len] = '\0';
    offset += client_id_len;

    // 可选字段未解析（如 will、username、password）

    return 0;
}

// 解析 SUBSCRIBE 报文
int parse_subscribe_packet(const uint8_t *buf, size_t len, mqtt_subscribe_packet_t *pkt) {
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0) return -1;
    pkt->variable_header.property_len = prop_len;
    offset += prop_len_bytes;

    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    pkt->payload.topic_count = 0;
    while (offset + 2 <= len && pkt->payload.topic_count < MAX_TOPIC_FILTERS) {
        uint16_t topic_len = read_uint16(buf + offset); offset += 2;
        if (offset + topic_len + 1 > len) break;

        memcpy(pkt->payload.topic_filters[pkt->payload.topic_count].topic_filter, buf + offset, topic_len);
        pkt->payload.topic_filters[pkt->payload.topic_count].topic_filter[topic_len] = '\0';
        offset += topic_len;

        pkt->payload.topic_filters[pkt->payload.topic_count].qos = buf[offset++];
        pkt->payload.topic_count++;
    }

    return 0;
}

int parse_publish_packet(const uint8_t *buf, size_t len, mqtt_publish_packet_t *pkt, uint8_t header_flags) {
    size_t offset = 0;

    pkt->qos    = (header_flags & 0x06) >> 1;
    pkt->dup    = (header_flags & 0x08) >> 3;
    pkt->retain = (header_flags & 0x01);

    // Topic Name
    uint16_t topic_len = read_uint16(buf + offset); offset += 2;
    if (topic_len >= MAX_TOPIC_LEN || offset + topic_len > len) return -1;
    memcpy(pkt->variable_header.topic_name, buf + offset, topic_len);
    pkt->variable_header.topic_name[topic_len] = '\0';
    offset += topic_len;

    // Packet Identifier (only if QoS > 0)
    if (pkt->qos > 0) {
        if (offset + 2 > len) return -1;
        pkt->variable_header.packet_identifier = read_uint16(buf + offset);
        offset += 2;
    } else {
        pkt->variable_header.packet_identifier = 0;
    }

    // Properties
    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0) return -1;
    pkt->variable_header.property_len = prop_len;
    offset += prop_len_bytes;
    if (offset + prop_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    // Payload
    pkt->payload.payload_len = len - offset;
    if (pkt->payload.payload_len > MAX_PAYLOAD_LEN) return -1;
    memcpy(pkt->payload.payload, buf + offset, pkt->payload.payload_len);

    return 0;
}

int parse_unsubscribe_packet(const uint8_t *buf, size_t len, mqtt_unsubscribe_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;

    size_t offset = 0;

    // 固定头部
    pkt->fixed_header.packet_type = buf[offset++];
    size_t rem_len_bytes = 0;
    uint32_t rem_len = 0;

    int ret = decode_remaining_length(buf + offset, len - offset, &rem_len, &rem_len_bytes);
    if (ret != 0) {
        // 解码失败
        return -1;
    }

    pkt->fixed_header.remaining_length = rem_len;
    offset += rem_len_bytes;

    if (offset + 2 > len) return -1;

    // 可变头部：packet identifier
    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    // 属性长度（Variable Byte Integer）
    
    uint32_t prop_len = 0;
    u32 prop_len_bytes = 0;

    ret = decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes);
    if (ret != 0) {
        return -1; // 解码失败，返回错误
    }

    pkt->variable_header.property_len = prop_len;
    offset += prop_len_bytes;
    offset += prop_len_bytes;

    if (pkt->variable_header.property_len > MAX_PROPERTIES_LEN || offset + pkt->variable_header.property_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, pkt->variable_header.property_len);
    offset += pkt->variable_header.property_len;

    // 有效载荷：读取 topic filters
    uint8_t topic_count = 0;
    while (offset + 2 <= len && topic_count < MAX_TOPIC_FILTERS) {
        uint16_t topic_len = read_uint16(buf + offset);
        offset += 2;

        if (offset + topic_len > len || topic_len >= MAX_TOPIC_LEN) return -1;

        memcpy(pkt->payload.topic_filters[topic_count], buf + offset, topic_len);
        pkt->payload.topic_filters[topic_count][topic_len] = '\0';  // Null-terminate
        offset += topic_len;
        topic_count++;
    }

    pkt->payload.topic_count = topic_count;

    return 0;
}

int parse_auth_packet(const uint8_t *buf, size_t len, mqtt_auth_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;

    size_t offset = 0;

    // 固定头部：packet_type (1 byte)
    pkt->fixed_header.packet_type = buf[offset++];

    // 解析 remaining_length
    uint32_t remaining_len = 0;
    int rem_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &remaining_len, &rem_len_bytes) != 0)
        return -1;
    pkt->fixed_header.remaining_length = remaining_len;
    offset += rem_len_bytes;

    if (offset >= len) return -1;

    // 可变头部：reason_code (1 byte)
    pkt->variable_header.reason_code = buf[offset++];

    // 解析属性长度（Property Length）
    uint32_t property_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &property_len, &prop_len_bytes) != 0)
        return -1;
    pkt->variable_header.property_len = property_len;
    offset += prop_len_bytes;

    if (property_len > MAX_PROPERTIES_LEN) return -1;
    if (offset + property_len > len) return -1;

    memcpy(pkt->variable_header.properties, buf + offset, property_len);
    offset += property_len;

    // 校验实际读取的数据长度与 remaining_length 是否一致
    if ((offset - (1 + rem_len_bytes)) != pkt->fixed_header.remaining_length) {
        return -1;
    }

    return 0;
}


// 解析所有 MQTT 报文
size_t parse_mqtt_msg(const uint8_t *buf, size_t buf_len, mqtt_packet_t *out_packets, size_t max_count) {
  // printf("Parsing MQTT messages from buffer of length %zu\n", buf_len);
    size_t offset = 0;
    size_t count = 0;
    // printf("pointer address(parser): %p\n", (void*)out_packets);
    while (offset < buf_len && count < max_count) {
        uint8_t packet_type = buf[offset] >> 4;
        // printf("Parsing packet type: 0x%02X at offset %zu\n", packet_type, offset);
        out_packets[count].type = TYPE_UNKNOWN;
        out_packets[count].connect.fixed_header.packet_type = packet_type;

        uint32_t remaining_length = 0;
        int rl_bytes = 0;
        if (decode_remaining_length(buf + offset + 1, buf_len - offset - 1, &remaining_length, &rl_bytes) != 0)
            break;

        size_t total_length = 1 + rl_bytes + remaining_length;
        if (offset + total_length > buf_len)
            break;

        // 设置 fixed_header
        out_packets[count].connect.fixed_header.packet_type = packet_type;
        out_packets[count].connect.fixed_header.remaining_length = remaining_length;

        const uint8_t *payload_buf = buf + offset + 1 + rl_bytes;
        size_t payload_len = remaining_length;

        if (packet_type == MQTT_CONNECT) {
            out_packets[count].type = TYPE_CONNECT;
            if (parse_connect_packet(payload_buf, payload_len, &out_packets[count].connect) != 0) break;
        } else if (packet_type == MQTT_SUBSCRIBE) {
            out_packets[count].type = TYPE_SUBSCRIBE;
            if (parse_subscribe_packet(payload_buf, payload_len, &out_packets[count].subscribe) != 0) break;
        } else if (packet_type == MQTT_PUBLISH) {
            out_packets[count].type = TYPE_PUBLISH;
            if (parse_publish_packet(payload_buf, payload_len, &out_packets[count].publish, buf[offset] & 0x0F) != 0) break;
        } else if( packet_type == MQTT_UNSUBSCRIBE) {
            out_packets[count].type = TYPE_UNSUBSCRIBE;
            if (parse_unsubscribe_packet(payload_buf, payload_len, &out_packets[count].unsubscribe) != 0) break;
        } else if( packet_type == MQTT_AUTH) {
            out_packets[count].type = TYPE_AUTH;
            if (parse_auth_packet(payload_buf, payload_len, &out_packets[count].auth) != 0) break;
        } 



        count++;
        offset += total_length;
        // printf("offset updated to %zu, count is now %zu\n", offset, count);
    }

    return count;
}


void print_mqtt_packets(const mqtt_packet_t *pkt, size_t count) {
    for(int index = 0; index < count; index++){
        printf("======= MQTT Packet #%zu =======\n", index + 1);
        printf("Packet Type: ");

        switch (pkt->type) {
            case TYPE_CONNECT: {
                printf("CONNECT (0x%02X)\n", pkt->connect.fixed_header.packet_type);
                printf("Remaining Length: %u\n", pkt->connect.fixed_header.remaining_length);
                printf("  Protocol Name : %s\n", pkt->connect.variable_header.protocol_name);
                printf("  Protocol Level: %u\n", pkt->connect.variable_header.protocol_level);
                printf("  Connect Flags : 0x%02X\n", pkt->connect.variable_header.connect_flags);
                printf("  Keep Alive    : %u\n", pkt->connect.variable_header.keep_alive);
                printf("  Property Len  : %u\n", pkt->connect.variable_header.property_len);
                printf("  Properties    : ");
                for (size_t i = 0; i < pkt->connect.variable_header.property_len; ++i) {
                    printf("%02X ", pkt->connect.variable_header.properties[i]);
                }
                printf("\n");
                printf("  Client ID     : %s\n", pkt->connect.payload.client_id);
                // 如有需要，可继续打印 will、username、password 等
                break;
            }

            case TYPE_SUBSCRIBE: {
                printf("SUBSCRIBE (0x%02X)\n", pkt->subscribe.fixed_header.packet_type);
                printf("Remaining Length: %u\n", pkt->subscribe.fixed_header.remaining_length);
                printf("  Packet ID     : %u\n", pkt->subscribe.variable_header.packet_identifier);
                printf("  Property Len  : %u\n", pkt->subscribe.variable_header.property_len);
                for (size_t i = 0; i < pkt->subscribe.variable_header.property_len; ++i) {
                    printf("%02X ", pkt->subscribe.variable_header.properties[i]);
                }
                printf("\n");
                printf("  Topic Count   : %u\n", pkt->subscribe.payload.topic_count);

                for (int i = 0; i < pkt->subscribe.payload.topic_count; ++i) {
                    printf("    Topic Filter[%d]: %s (QoS=%u)\n", i,
                        pkt->subscribe.payload.topic_filters[i].topic_filter,
                        pkt->subscribe.payload.topic_filters[i].qos);
                }
                break;
            }
            case TYPE_PUBLISH: {
                printf("PUBLISH (0x%02X)\n", pkt->publish.fixed_header.packet_type);
                printf("Remaining Length: %u\n", pkt->publish.fixed_header.remaining_length);
                printf("  Topic Name    : %s\n", pkt->publish.variable_header.topic_name);
                if (pkt->publish.qos > 0) {
                    printf("  Packet ID     : %u\n", pkt->publish.variable_header.packet_identifier);
                }
                printf("  Property Len  : %u\n", pkt->publish.variable_header.property_len);
                printf("  Payload Length: %u\n", pkt->publish.payload.payload_len);
                // 可打印 payload 内容
                break;
            }
            case TYPE_UNSUBSCRIBE: {
                printf("UNSUBSCRIBE (0x%02X)\n", pkt->unsubscribe.fixed_header.packet_type);
                printf("Remaining Length: %u\n", pkt->unsubscribe.fixed_header.remaining_length);
                printf("  Packet ID     : %u\n", pkt->unsubscribe.variable_header.packet_identifier);
                printf("  Property Len  : %u\n", pkt->unsubscribe.variable_header.property_len);
                printf("  Topic Count   : %u\n", pkt->unsubscribe.payload.topic_count);

                for (int i = 0; i < pkt->unsubscribe.payload.topic_count; ++i) {
                    printf("    Topic Filter[%d]: %s\n", i, pkt->unsubscribe.payload.topic_filters[i]);
                }
                break;
            }
            case TYPE_AUTH: {
                printf("AUTH (0x%02X)\n", pkt->auth.fixed_header.packet_type);
                printf("Remaining Length: %u\n", pkt->auth.fixed_header.remaining_length);
                printf("  Reason Code   : %u\n", pkt->auth.variable_header.reason_code);
                printf("  Property Len  : %u\n", pkt->auth.variable_header.property_len);
                // 可打印 properties 内容
                break;
            }
            case TYPE_UNKNOWN:
            default:
                printf("UNKNOWN TYPE\n");
                break;
        }

        printf("=================================\n\n");
    }
}