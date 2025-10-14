#include "mqtt.h"

// 写 2 字节长度前缀字符串
size_t write_utf8_str(uint8_t *buf, const char *str) {
    size_t len = strlen(str);
    buf[0] = (len >> 8) & 0xFF;
    buf[1] = len & 0xFF;
    memcpy(buf + 2, str, len);
    return len + 2;
}

// 写 MQTT 剩余长度（Variable Byte Integer 编码）
size_t write_remaining_length(uint8_t *buf, uint32_t len) {
    size_t i = 0;
    do {
        uint8_t byte = len % 128;
        len /= 128;
        if (len > 0) byte |= 0x80;
        buf[i++] = byte;
    } while (len > 0);
    return i;
}

// 写 2 字节整数
void write_uint16(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

int reassemble_a_mqtt_msg(const mqtt_packet_t *pkt, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;
    u8 header_buf[10];
    u32 header_len = 0;

    u8 payload_buf[1024 * 1024];
    u32 payload_len = 0;

    switch (pkt->type) {
        case TYPE_CONNECT: {
            const mqtt_connect_packet_t *con = &pkt->connect;

            if (con->variable_header.protocol_name)
                payload_len += write_utf8_str(payload_buf + payload_len, con->variable_header.protocol_name);

            payload_buf[payload_len++] = con->variable_header.protocol_level;
            payload_buf[payload_len++] = con->variable_header.connect_flags;

            write_uint16(payload_buf + payload_len, con->variable_header.keep_alive);
            payload_len += 2;

            if (con->variable_header.property_len > 0 && con->variable_header.properties) {
                // u32 len = strlen((char *)con->variable_header.properties);
                u32 len = con->variable_header.property_len;
                // printf("(reassemble)Properties length: %u\n", len);
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, con->variable_header.properties, len);
                payload_len += len;
            } else {
                payload_len += write_remaining_length(payload_buf + payload_len, 0);
            }

            if (con->payload.client_id)
                payload_len += write_utf8_str(payload_buf + payload_len, con->payload.client_id);

            if (con->payload.will_property_len > 0 && con->payload.will_properties[0]) {
                // printf("(reassemble)Will Properties: %s\n", con->payload.will_properties);
                u32 len = con->payload.will_property_len;
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, con->payload.will_properties, len);
                payload_len += len;
            }

            if (con->payload.will_topic[0])
                payload_len += write_utf8_str(payload_buf + payload_len, con->payload.will_topic);

            if (con->payload.will_payload[0]) {
                u32 len = con->payload.will_payload_len;
                write_uint16(payload_buf + payload_len, len);
                payload_len += 2;
                memcpy(payload_buf + payload_len, con->payload.will_payload, len);
                payload_len += len;
            }

            if (con->payload.user_name[0])
                payload_len += write_utf8_str(payload_buf + payload_len, con->payload.user_name);

            if (con->payload.password[0]) {
                u32 len = con->payload.password_len;
                write_uint16(payload_buf + payload_len, len);
                payload_len += 2;
                memcpy(payload_buf + payload_len, con->payload.password, len);
                payload_len += len;
            }

            break;
        }

        case TYPE_SUBSCRIBE: {
            const mqtt_subscribe_packet_t *sub = &pkt->subscribe;

            write_uint16(payload_buf + payload_len, sub->variable_header.packet_identifier);
            payload_len += 2;

            if (sub->variable_header.property_len > 0 && sub->variable_header.properties) {
                u32 len = sub->variable_header.property_len;
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, sub->variable_header.properties, len);
                payload_len += len;
            } else {
                payload_len += write_remaining_length(payload_buf + payload_len, 0);
            }

            for (int i = 0; i < sub->payload.topic_count; ++i) {
                if (sub->payload.topic_filters[i].topic_filter) {
                    payload_len += write_utf8_str(payload_buf + payload_len,
                                                  sub->payload.topic_filters[i].topic_filter);
                    payload_buf[payload_len++] = sub->payload.topic_filters[i].qos;
                }
            }

            break;
        }

        case TYPE_PUBLISH: {
            const mqtt_publish_packet_t *pub = &pkt->publish;
            payload_len += write_utf8_str(payload_buf + payload_len, pub->variable_header.topic_name);
            if(pub->qos!=0){
                write_uint16(payload_buf + payload_len, pub->variable_header.packet_identifier);
                payload_len += 2;
            }
            

            if (pub->variable_header.property_len>0 && pub->variable_header.properties[0]) {
                u32 len = pub->variable_header.property_len;
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, pub->variable_header.properties, len);
                payload_len += len;
            } else {
                payload_len += write_remaining_length(payload_buf + payload_len, 0);
            }

            if (pub->payload.payload[0]) {
                u32 len = pub->payload.payload_len;
                memcpy(payload_buf + payload_len, pub->payload.payload, len);
                payload_len += len;
            }

            break;
        }

        case TYPE_UNSUBSCRIBE: {
            const mqtt_unsubscribe_packet_t *unsub = &pkt->unsubscribe;

            write_uint16(payload_buf + payload_len, unsub->variable_header.packet_identifier);
            payload_len += 2;

            if (unsub->variable_header.property_len > 0 && unsub->variable_header.properties) {
                u32 len = unsub->variable_header.property_len;
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, unsub->variable_header.properties, len);
                payload_len += len;
            } else {
                payload_len += write_remaining_length(payload_buf + payload_len, 0);
            }

            for (int i = 0; i < unsub->payload.topic_count; ++i) {
                if (unsub->payload.topic_filters[i])
                    payload_len += write_utf8_str(payload_buf + payload_len, unsub->payload.topic_filters[i]);
            }

            break;
        }

        case TYPE_AUTH: {
            const mqtt_auth_packet_t *auth = &pkt->auth;

            payload_buf[payload_len++] = auth->variable_header.reason_code;

            if (auth->variable_header.property_len > 0 && auth->variable_header.properties) {
                u32 len = auth->variable_header.property_len;
                payload_len += write_remaining_length(payload_buf + payload_len, len);
                memcpy(payload_buf + payload_len, auth->variable_header.properties, len);
                payload_len += len;
            } else {
                payload_len += write_remaining_length(payload_buf + payload_len, 0);
            }

            break;
        }

        default:
            return -1;
    }

    // Fixed header
    uint8_t first_byte = 0;
    switch (pkt->type) {
    case TYPE_CONNECT:     first_byte = 0x10; break;
    case TYPE_SUBSCRIBE:   first_byte = 0x82; break;
    case TYPE_PUBLISH: {
        /* PUBLISH 固定头：
           bits 7..4 = 0x3 (PUBLISH)
           bit 3     = DUP
           bits 2..1 = QoS (00/01/10)
           bit 0     = RETAIN
        */
        uint8_t qos    = pkt->publish.qos & 0x03;          /* 只保留低两位，裁剪到 0..2 */
        uint8_t dup    = pkt->publish.dup ? 1 : 0;
        uint8_t retain = pkt->publish.retain ? 1 : 0;

        /* 规范上 QoS 0 时 DUP 不应置 1，出于兼容性将其清零 */
        if (qos == 0) dup = 0;

        first_byte = (uint8_t)(0x30 | (dup << 3) | (qos << 1) | retain);
        break;
    }
    case TYPE_UNSUBSCRIBE: first_byte = 0xA2; break;
    case TYPE_AUTH:        first_byte = 0xF0; break;
    default:               return -1;
}


    output_buf[offset++] = first_byte;
    header_len = write_remaining_length(header_buf, payload_len);
    memcpy(output_buf + offset, header_buf, header_len);
    offset += header_len;

    memcpy(output_buf + offset, payload_buf, payload_len);
    offset += payload_len;

    *out_len = offset;
    return 0;
}




int reassemble_mqtt_msgs(const mqtt_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
    u32 offset = 0;
    *out_len = 0;

    for (u32 j = 0; j < num_packets; ++j) {
        u8 temp_buf[1024 * 1024]; // 临时缓冲区
        u32 temp_len = 0;

        if (reassemble_a_mqtt_msg(&packets[j], temp_buf, &temp_len) != 0) {
            // printf("❌ 第 %zu 条消息重组失败，跳过\n", j);
            continue;
        }

        if (offset + temp_len >= MAX_FILE) {
            // printf("⚠️ 消息序列长度超过限制，截断\n");
            break;
        }

        memcpy(output_buf + offset, temp_buf, temp_len);
        offset += temp_len;
    }

    *out_len = offset;
    return 0;
}