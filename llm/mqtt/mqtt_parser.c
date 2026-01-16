#include "mqtt.h"
#include <stdio.h>
static uint16_t read_uint16(const uint8_t *data) {
    return (data[0] << 8) | data[1];
}


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
    return -1;  
}


int parse_connect_packet(const uint8_t *buf, size_t len, mqtt_connect_packet_t *pkt) {
    size_t offset = 0;
    if (!buf || !pkt) return -1;

    pkt->payload.will_property_len = 0;
    pkt->payload.will_properties[0] = 0;  
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

    uint8_t flags = pkt->variable_header.connect_flags;
    uint8_t username_flag = (flags >> 7) & 1;
    uint8_t password_flag = (flags >> 6) & 1;
    uint8_t will_retain   = (flags >> 5) & 1;
    uint8_t will_qos      = (flags >> 3) & 0x3;
    uint8_t will_flag     = (flags >> 2) & 1;

    if (flags & 0x01) return -1;
    if (!will_flag && (will_qos != 0 || will_retain != 0)) return -1;
    if (will_qos == 3) return -1;
    if (password_flag && !username_flag) return -1;

    uint32_t prop_len = 0;
    int prop_len_bytes = 0;
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, &prop_len_bytes) != 0) return -1;
    offset += (size_t)prop_len_bytes;
    pkt->variable_header.property_len = prop_len;

    if (prop_len > MAX_PROPERTIES_LEN || offset + prop_len > len) return -1;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    /* ---------------- Payload ---------------- */
    if (offset + 2 > len) return -1;
    uint16_t client_id_len = read_uint16(buf + offset); offset += 2;
    if (client_id_len >= MAX_CLIENT_ID_LEN) return -1;
    if (offset + client_id_len > len) return -1;
    memcpy(pkt->payload.client_id, buf + offset, client_id_len);
    pkt->payload.client_id[client_id_len] = '\0';
    offset += client_id_len;

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

    if (username_flag) {
        if (offset + 2 > len) return -1;
        uint16_t user_len = read_uint16(buf + offset); offset += 2;
        if (user_len >= MAX_USERNAME_LEN) return -1;
        if (offset + user_len > len) return -1;
        memcpy(pkt->payload.user_name, buf + offset, user_len);
        pkt->payload.user_name[user_len] = '\0';
        offset += user_len;
    }

    if (password_flag) {
        if (offset + 2 > len) return -1;
        uint16_t pass_len = read_uint16(buf + offset); offset += 2;
        if (pass_len > MAX_PASSWORD_LEN) return -1;
        if (offset + pass_len > len) return -1;
        pkt->payload.password_len = pass_len;
        memcpy(pkt->payload.password, buf + offset, pass_len);
        offset += pass_len;
    }

    if (offset != len) return -1;

    return 0;
}



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

    if (offset + 2 > len) return -1;
    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    uint32_t prop_len = 0;
    size_t   prop_len_bytes = 0;   
    if (decode_remaining_length(buf + offset, len - offset, &prop_len, (int*)&prop_len_bytes) != 0) {
        return -1;
    }
    offset += prop_len_bytes;

    if (prop_len > MAX_PROPERTIES_LEN) return -1;
    if (offset + prop_len > len) return -1;
    pkt->variable_header.property_len = prop_len;
    memcpy(pkt->variable_header.properties, buf + offset, prop_len);
    offset += prop_len;

    uint8_t topic_count = 0;
    while (offset + 2 <= len && topic_count < MAX_TOPIC_FILTERS) {
        uint16_t topic_len = read_uint16(buf + offset);
        offset += 2;

        if (topic_len == 0) {         
            return -1;
        }
        if (topic_len >= MAX_TOPIC_LEN) { 
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

        return -1;
    }

    pkt->payload.topic_count = topic_count;

    return 0;
}

int parse_disconnect_packet(const uint8_t *buf, size_t len, mqtt_disconnect_packet_t *pkt) {
    if (!buf || !pkt) return -1;

    size_t offset = 0;

    if (len == 0) {
        pkt->variable_header.reason_code = 0x00;
        pkt->variable_header.property_len = 0;
        return 0;
    }

    pkt->variable_header.reason_code = buf[offset++];
    if (offset == len) {
        pkt->variable_header.property_len = 0;
        return 0;
    }

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

    pkt->variable_header.reason_code = buf[offset++];

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


    return 0;
}


/* PUBACK */
int parse_puback_packet(const uint8_t *buf, size_t len, mqtt_puback_packet_t *pkt) {
    if (!buf || !pkt || len < 2) return -1;
    size_t offset = 0;

    pkt->variable_header.packet_identifier = read_uint16(buf + offset);
    offset += 2;

    if (offset >= len) {
        pkt->variable_header.reason_code = 0x00;  // Success
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

/* PUBREL */
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


size_t parse_mqtt_msg(const uint8_t *buf, size_t buf_len, mqtt_packet_t *out_packets, size_t max_count) {
    size_t offset = 0;
    size_t count = 0;

    while (offset < buf_len && count < max_count) {
        uint8_t packet_type = buf[offset] >> 4;

        out_packets[count].type = TYPE_UNKNOWN;
        out_packets[count].connect.fixed_header.packet_type = packet_type;

        uint32_t remaining_length = 0;
        int rl_bytes = 0;
        if (decode_remaining_length(buf + offset + 1, buf_len - offset - 1, &remaining_length, &rl_bytes) != 0)
            break;

        size_t total_length = 1 + rl_bytes + remaining_length;
        if (offset + total_length > buf_len)
            break;

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
    }

    return count;
}

