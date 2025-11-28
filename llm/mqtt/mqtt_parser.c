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

// 解析 CONNECT 报文（MQTT v5）
// buf/len 是 Remaining Length 对应的 payload（即 parse_mqtt_msg 已剥掉 fixed header）
// 返回 0 成功，-1 失败
int parse_connect_packet(const uint8_t *buf, size_t len, mqtt_connect_packet_t *pkt) {
    size_t offset = 0;
    if (!buf || !pkt) return -1;

    /* ---- 先清零可选字段，防止残留 ---- */
    pkt->payload.will_property_len = 0;
    pkt->payload.will_properties[0] = 0;  /* 二进制raw，但清首字节即可避免旧值干扰 */
    pkt->payload.will_topic[0] = '\0';
    pkt->payload.will_payload_len = 0;
    if (sizeof(pkt->payload.will_payload) > 0) pkt->payload.will_payload[0] = 0;

    pkt->payload.user_name[0] = '\0';
    pkt->payload.password_len = 0;
    if (sizeof(pkt->payload.password) > 0) pkt->payload.password[0] = 0;

    /* ---------------- Variable Header ---------------- */
    if (offset + 2 > len) return -1;
    uint16_t proto_len = read_uint16(buf + offset); offset += 2;
    if (proto_len == 0 || proto_len >= MAX_PROTOCOL_NAME_LEN) return -1;
    if (offset + proto_len > len) return -1;
    memcpy(pkt->variable_header.protocol_name, buf + offset, proto_len);
    pkt->variable_header.protocol_name[proto_len] = '\0';
    offset += proto_len;

    if (offset + 1 > len) return -1;
    pkt->variable_header.protocol_level = buf[offset++];

    if (offset + 1 > len) return -1;
    pkt->variable_header.connect_flags = buf[offset++];

    if (offset + 2 > len) return -1;
    pkt->variable_header.keep_alive = read_uint16(buf + offset); offset += 2;

    /* ---- CONNECT Flags 语义解析/合法性 ---- */
    uint8_t flags = pkt->variable_header.connect_flags;
    uint8_t username_flag = (flags >> 7) & 1;
    uint8_t password_flag = (flags >> 6) & 1;
    uint8_t will_retain   = (flags >> 5) & 1;
    uint8_t will_qos      = (flags >> 3) & 0x3;
    uint8_t will_flag     = (flags >> 2) & 1;

    /* bit0 保留必须为 0（合法筛选） */
    if (flags & 0x01) return -1;
    /* will_flag=0 时 will_qos/retain 必须为 0 */
    if (!will_flag && (will_qos != 0 || will_retain != 0)) return -1;
    /* will_qos=3 非法 */
    if (will_qos == 3) return -1;
    /* password_flag=1 时 username_flag 必须为 1（规范约束） */
    if (password_flag && !username_flag) return -1;

    /* ---- Properties (VarInt length + bytes) ---- */
    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0) return -1;
    offset += (size_t)prop_len_bytes;
    pkt->variable_header.property_len = prop_len;

    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    /* ---------------- Payload ---------------- */

    /* 1) Client ID (UTF-8 string; 允许 0 长度) */
    if (offset + 2 > len) return -1;
    uint16_t client_id_len = read_uint16(buf + offset); offset += 2;
    if (client_id_len >= MAX_CLIENT_ID_LEN) return -1;
    if (offset + client_id_len > len) return -1;
    memcpy(pkt->payload.client_id, buf + offset, client_id_len);
    pkt->payload.client_id[client_id_len] = '\0';
    offset += client_id_len;

    /* 2) Will（可选：由 Will Flag 控制） */
    if (will_flag) {
        /* 2.1 Will Properties */
        uint32_t will_prop_len = 0;
        int will_prop_len_bytes = 0;
        if (decode_remaining_length(buf + offset, len - offset,
                                    &will_prop_len, &will_prop_len_bytes) != 0) return -1;
        offset += (size_t)will_prop_len_bytes;

        if (will_prop_len > MAX_PROPERTIES_LEN || offset + will_prop_len > len) return -1;
        pkt->payload.will_property_len = will_prop_len;
        memcpy(pkt->payload.will_properties, buf + offset, will_prop_len);
        offset += will_prop_len;

        /* 2.2 Will Topic (UTF-8 string) */
        if (offset + 2 > len) return -1;
        uint16_t will_topic_len = read_uint16(buf + offset); offset += 2;
        /* 这里用 MAX_TOPIC_LEN（与你的结构一致） */
        if (will_topic_len == 0 || will_topic_len >= MAX_TOPIC_LEN) return -1;
        if (offset + will_topic_len > len) return -1;
        memcpy(pkt->payload.will_topic, buf + offset, will_topic_len);
        pkt->payload.will_topic[will_topic_len] = '\0';
        offset += will_topic_len;

        /* 2.3 Will Payload (Binary data) */
        if (offset + 2 > len) return -1;
        uint16_t will_payload_len = read_uint16(buf + offset); offset += 2;
        if (will_payload_len > MAX_PAYLOAD_LEN) return -1;
        if (offset + will_payload_len > len) return -1;
        pkt->payload.will_payload_len = will_payload_len;
        memcpy(pkt->payload.will_payload, buf + offset, will_payload_len);
        offset += will_payload_len;
    }

    /* 3) User Name（可选 UTF-8 string，允许 0 长度） */
    if (username_flag) {
        if (offset + 2 > len) return -1;
        uint16_t user_len = read_uint16(buf + offset); offset += 2;
        if (user_len >= MAX_USERNAME_LEN) return -1;
        if (offset + user_len > len) return -1;
        memcpy(pkt->payload.user_name, buf + offset, user_len);
        pkt->payload.user_name[user_len] = '\0';
        offset += user_len;
    }

    /* 4) Password（可选 binary data，允许 0 长度） */
    if (password_flag) {
        if (offset + 2 > len) return -1;
        uint16_t pass_len = read_uint16(buf + offset); offset += 2;
        if (pass_len > MAX_PASSWORD_LEN) return -1;
        if (offset + pass_len > len) return -1;
        pkt->payload.password_len = pass_len;
        memcpy(pkt->payload.password, buf + offset, pass_len);
        offset += pass_len;
    }

    /* ---- 最后必须精确消费完 Remaining Length ---- */
    if (offset != len) return -1;

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

    /* 注意：这里的 buf/len 是“payload”（remaining_length 指向的那段），
       所以不要再读取固定头和 remaining_length */

    /* 可变头：packet identifier */
    if (offset + 2 > len) return -1;
    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    /* 属性长度（Variable Byte Integer） */
    uint32_t prop_len = 0;
    size_t   prop_len_bytes = 0;   /* 建议 size_t，统一类型 */
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, (int*)&prop_len_bytes) != 0) {
        return -1;
    }
    offset += prop_len_bytes;

    if (prop_len > MAX_PROPERTIES_LEN) return -1;
    if (offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    /* 载荷：topic filters（至少 1 个） */
    uint8_t topic_count = 0;
    while (offset + 2 <= len && topic_count < MAX_TOPIC_FILTERS) {
        uint16_t topic_len = read_uint16(buf + offset);
        offset += 2;

        if (topic_len == 0) {           /* 空过滤器非法 */
            return -1;
        }
        if (topic_len >= MAX_TOPIC_LEN) { /* 需要留 '\0'，严格可用 > MAX_TOPIC_LEN-1 */
            return -1;
        }
        if (offset + topic_len > len) {
            return -1;
        }

        memcpy(pkt->payload.topic_filters[topic_count], buf + offset, topic_len);
        pkt->payload.topic_filters[topic_count][topic_len] = '\0';
        offset += topic_len;
        topic_count++;
    }

    if (topic_count == 0) {
        /* MQTT 规范要求至少一个 topic filter */
        return -1;
    }

    pkt->payload.topic_count = topic_count;

    /* fixed_header 的 packet_type / remaining_length 已在 parse_mqtt_msg() 里写入
       （通过 union 的同址特性）。这里无需再设置。 */
    return 0;
}

int parse_disconnect_packet(const uint8_t *buf, size_t len, mqtt_disconnect_packet_t *pkt) {
    if (!buf || !pkt) return -1;

    size_t offset = 0;

    /* remaining_length==0：无 reason / 无属性 */
    if (len == 0) {
        pkt->variable_header.reason_code = 0x00;
        pkt->variable_header.property_len = 0;
        return 0;
    }

    /* 有 1 字节 reason_code */
    pkt->variable_header.reason_code = buf[offset++];
    if (offset == len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

    /* 有属性：Property Length (varint) + Properties */
    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0)
        return -1;
    offset += prop_len_bytes;

    if (prop_len > MAX_PROPERTIES_LEN) return -1;
    if (offset + prop_len > len) return -1;

    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    return 0;
}

int parse_pingreq_packet(const uint8_t *buf, size_t len, mqtt_pingreq_packet_t *pkt) {
    (void)buf; (void)pkt;
    return (len == 0) ? 0 : -1;
}

int parse_auth_packet(const uint8_t *buf, size_t len, mqtt_auth_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;

    size_t offset = 0;

    // // 固定头部：packet_type (1 byte)
    // pkt->fixed_header.packet_type = buf[offset++];

    // // 解析 remaining_length
    // uint32_t remaining_len = 0;
    // int rem_len_bytes = 0;
    // if (decode_remaining_length(buf + offset, len - offset, &remaining_len, &rem_len_bytes) != 0)
    //     return -1;
    // pkt->fixed_header.remaining_length = remaining_len;
    // offset += rem_len_bytes;

    // if (offset >= len) return -1;

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
    // if ((offset - (1 + rem_len_bytes)) != pkt->fixed_header.remaining_length) {
    //     return -1;
    // }

    return 0;
}

/* ---- PUBLISH 响应类公共模式：PID(2) [ReasonCode(1)] [PropertyLen(varint) Properties...] ---- */

/* PUBACK */
int parse_puback_packet(const uint8_t *buf, size_t len, mqtt_puback_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    /* MQTT 3.1.1: 只有 Packet Identifier；MQTT 5: 后续可能有 Reason Code + Properties */
    if (offset >= len) {
        pkt->variable_header.reason_code = 0x00;  // Success (默认)
        pkt->variable_header.property_len = 0;
        return 0;
    }

    /* 有 Reason Code */
    pkt->variable_header.reason_code = buf[offset++];
    if (offset >= len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

    /* 有 Properties */
    uint32_t prop_len = 0; int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0)
        return -1;
    offset += prop_len_bytes;
    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    return 0;
}

/* PUBREC */
int parse_pubrec_packet(const uint8_t *buf, size_t len, mqtt_pubrec_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    if (offset >= len) {
        pkt->variable_header.reason_code = 0x00;
        pkt->variable_header.property_len = 0;
        return 0;
    }

    pkt->variable_header.reason_code = buf[offset++];
    if (offset >= len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

    uint32_t prop_len = 0; int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0)
        return -1;
    offset += prop_len_bytes;
    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    return 0;
}

/* PUBREL（注意：固定头低 4 bit 必须为 0x2，但这里在 parse_mqtt_msg 检/忽略均可） */
int parse_pubrel_packet(const uint8_t *buf, size_t len, mqtt_pubrel_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    if (offset >= len) {
        pkt->variable_header.reason_code = 0x00;
        pkt->variable_header.property_len = 0;
        return 0;
    }

    pkt->variable_header.reason_code = buf[offset++];
    if (offset >= len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

    uint32_t prop_len = 0; int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0)
        return -1;
    offset += prop_len_bytes;
    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    return 0;
}

/* PUBCOMP */
int parse_pubcomp_packet(const uint8_t *buf, size_t len, mqtt_pubcomp_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    if (offset >= len) {
        pkt->variable_header.reason_code = 0x00;
        pkt->variable_header.property_len = 0;
        return 0;
    }

    pkt->variable_header.reason_code = buf[offset++];
    if (offset >= len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

    uint32_t prop_len = 0; int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0)
        return -1;
    offset += prop_len_bytes;
    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

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
        } else if (packet_type == MQTT_PUBACK) {
            out_packets[count].type = TYPE_PUBACK;
            if (parse_puback_packet(payload_buf, payload_len, &out_packets[count].puback) != 0) break;
        } else if (packet_type == MQTT_PUBREC) {
            out_packets[count].type = TYPE_PUBREC;
            if (parse_pubrec_packet(payload_buf, payload_len, &out_packets[count].pubrec) != 0) break;
        } else if (packet_type == MQTT_PUBREL) {
            out_packets[count].type = TYPE_PUBREL;
            if (parse_pubrel_packet(payload_buf, payload_len, &out_packets[count].pubrel) != 0) break;
        } else if (packet_type == MQTT_PUBCOMP) {
            out_packets[count].type = TYPE_PUBCOMP;
            if (parse_pubcomp_packet(payload_buf, payload_len, &out_packets[count].pubcomp) != 0) break;
        } else if (packet_type == MQTT_PINGREQ) {
            out_packets[count].type = TYPE_PINGREQ;
            if (parse_pingreq_packet(payload_buf, payload_len, &out_packets[count].pingreq) != 0) break;

        } else if (packet_type == MQTT_DISCONNECT) {
            out_packets[count].type = TYPE_DISCONNECT;
            if (parse_disconnect_packet(payload_buf, payload_len, &out_packets[count].disconnect) != 0) break;
        }




        count++;
        offset += total_length;
        // printf("offset updated to %zu, count is now %zu\n", offset, count);
    }

    return count;
}


// void print_mqtt_packets(const mqtt_packet_t *pkt, size_t count) {
//     for(int index = 0; index < count; index++){
//         printf("======= MQTT Packet #%zu =======\n", index + 1);
//         printf("Packet Type: ");

//         switch (pkt->type) {
//             case TYPE_CONNECT: {
//                 printf("CONNECT (0x%02X)\n", pkt->connect.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->connect.fixed_header.remaining_length);
//                 printf("  Protocol Name : %s\n", pkt->connect.variable_header.protocol_name);
//                 printf("  Protocol Level: %u\n", pkt->connect.variable_header.protocol_level);
//                 printf("  Connect Flags : 0x%02X\n", pkt->connect.variable_header.connect_flags);
//                 printf("  Keep Alive    : %u\n", pkt->connect.variable_header.keep_alive);
//                 printf("  Property Len  : %u\n", pkt->connect.variable_header.property_len);
//                 printf("  Properties    : ");
//                 for (size_t i = 0; i < pkt->connect.variable_header.property_len; ++i) {
//                     printf("%02X ", pkt->connect.variable_header.properties[i]);
//                 }
//                 printf("\n");
//                 printf("  Client ID     : %s\n", pkt->connect.payload.client_id);
//                 // 如有需要，可继续打印 will、username、password 等
//                 break;
//             }

//             case TYPE_SUBSCRIBE: {
//                 printf("SUBSCRIBE (0x%02X)\n", pkt->subscribe.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->subscribe.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->subscribe.variable_header.packet_identifier);
//                 printf("  Property Len  : %u\n", pkt->subscribe.variable_header.property_len);
//                 for (size_t i = 0; i < pkt->subscribe.variable_header.property_len; ++i) {
//                     printf("%02X ", pkt->subscribe.variable_header.properties[i]);
//                 }
//                 printf("\n");
//                 printf("  Topic Count   : %u\n", pkt->subscribe.payload.topic_count);

//                 for (int i = 0; i < pkt->subscribe.payload.topic_count; ++i) {
//                     printf("    Topic Filter[%d]: %s (QoS=%u)\n", i,
//                         pkt->subscribe.payload.topic_filters[i].topic_filter,
//                         pkt->subscribe.payload.topic_filters[i].qos);
//                 }
//                 break;
//             }
//             case TYPE_PUBLISH: {
//                 printf("PUBLISH (0x%02X)\n", pkt->publish.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->publish.fixed_header.remaining_length);
//                 printf("  Topic Name    : %s\n", pkt->publish.variable_header.topic_name);
//                 if (pkt->publish.qos > 0) {
//                     printf("  Packet ID     : %u\n", pkt->publish.variable_header.packet_identifier);
//                 }
//                 printf("  Property Len  : %u\n", pkt->publish.variable_header.property_len);
//                 printf("  Payload Length: %u\n", pkt->publish.payload.payload_len);
//                 // 可打印 payload 内容
//                 break;
//             }
//             case TYPE_UNSUBSCRIBE: {
//                 printf("UNSUBSCRIBE (0x%02X)\n", pkt->unsubscribe.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->unsubscribe.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->unsubscribe.variable_header.packet_identifier);
//                 printf("  Property Len  : %u\n", pkt->unsubscribe.variable_header.property_len);
//                 printf("  Topic Count   : %u\n", pkt->unsubscribe.payload.topic_count);

//                 for (int i = 0; i < pkt->unsubscribe.payload.topic_count; ++i) {
//                     printf("    Topic Filter[%d]: %s\n", i, pkt->unsubscribe.payload.topic_filters[i]);
//                 }
//                 break;
//             }
//             case TYPE_AUTH: {
//                 printf("AUTH (0x%02X)\n", pkt->auth.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->auth.fixed_header.remaining_length);
//                 printf("  Reason Code   : %u\n", pkt->auth.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->auth.variable_header.property_len);
//                 // 可打印 properties 内容
//                 break;
//             }
//                         case TYPE_PUBACK: {
//                 printf("PUBACK (0x%02X)\n", pkt->puback.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->puback.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->puback.variable_header.packet_identifier);
//                 printf("  Reason Code   : %u\n", pkt->puback.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->puback.variable_header.property_len);
//                 if (pkt->puback.variable_header.property_len) {
//                     printf("  Properties    : ");
//                     for (size_t i = 0; i < pkt->puback.variable_header.property_len; ++i)
//                         printf("%02X ", pkt->puback.variable_header.properties[i]);
//                     printf("\n");
//                 }
//                 break;
//             }
//             case TYPE_PUBREC: {
//                 printf("PUBREC (0x%02X)\n", pkt->pubrec.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->pubrec.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->pubrec.variable_header.packet_identifier);
//                 printf("  Reason Code   : %u\n", pkt->pubrec.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->pubrec.variable_header.property_len);
//                 if (pkt->pubrec.variable_header.property_len) {
//                     printf("  Properties    : ");
//                     for (size_t i = 0; i < pkt->pubrec.variable_header.property_len; ++i)
//                         printf("%02X ", pkt->pubrec.variable_header.properties[i]);
//                     printf("\n");
//                 }
//                 break;
//             }
//             case TYPE_PUBREL: {
//                 printf("PUBREL (0x%02X)\n", pkt->pubrel.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->pubrel.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->pubrel.variable_header.packet_identifier);
//                 printf("  Reason Code   : %u\n", pkt->pubrel.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->pubrel.variable_header.property_len);
//                 if (pkt->pubrel.variable_header.property_len) {
//                     printf("  Properties    : ");
//                     for (size_t i = 0; i < pkt->pubrel.variable_header.property_len; ++i)
//                         printf("%02X ", pkt->pubrel.variable_header.properties[i]);
//                     printf("\n");
//                 }
//                 break;
//             }
//             case TYPE_PUBCOMP: {
//                 printf("PUBCOMP (0x%02X)\n", pkt->pubcomp.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->pubcomp.fixed_header.remaining_length);
//                 printf("  Packet ID     : %u\n", pkt->pubcomp.variable_header.packet_identifier);
//                 printf("  Reason Code   : %u\n", pkt->pubcomp.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->pubcomp.variable_header.property_len);
//                 if (pkt->pubcomp.variable_header.property_len) {
//                     printf("  Properties    : ");
//                     for (size_t i = 0; i < pkt->pubcomp.variable_header.property_len; ++i)
//                         printf("%02X ", pkt->pubcomp.variable_header.properties[i]);
//                     printf("\n");
//                 }
//                 break;
//             }
//             case TYPE_PINGREQ: {
//                 printf("PINGREQ (0x%02X)\n", pkt->pingreq.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->pingreq.fixed_header.remaining_length);
//                 break;
//             }
//             case TYPE_DISCONNECT: {
//                 printf("DISCONNECT (0x%02X)\n", pkt->disconnect.fixed_header.packet_type);
//                 printf("Remaining Length: %u\n", pkt->disconnect.fixed_header.remaining_length);
//                 printf("  Reason Code   : %u\n", pkt->disconnect.variable_header.reason_code);
//                 printf("  Property Len  : %u\n", pkt->disconnect.variable_header.property_len);
//                 if (pkt->disconnect.variable_header.property_len) {
//                     printf("  Properties    : ");
//                     for (size_t i = 0; i < pkt->disconnect.variable_header.property_len; ++i)
//                         printf("%02X ", pkt->disconnect.variable_header.properties[i]);
//                     printf("\n");
//                 }
//                 break;
//             }

//             case TYPE_UNKNOWN:
//             default:
//                 printf("UNKNOWN TYPE\n");
//                 break;
//         }

//         printf("=================================\n\n");
//     }
// }