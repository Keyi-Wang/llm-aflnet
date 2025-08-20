#include "mqtt.h"

extern u32 fixed_count;
void fix_connect_packet_will_rules(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets) return;

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        // 提取 Will Flag, Will QoS, Will Retain（来自 connect_flags）
        uint8_t connect_flags = pkt->variable_header.connect_flags;
        uint8_t will_flag   = (connect_flags >> 2) & 0x01;
        uint8_t will_qos    = (connect_flags >> 3) & 0x03;
        uint8_t will_retain = (connect_flags >> 5) & 0x01;

        // [MQTT-3.1.2-11] If Will Flag == 0, Will QoS must be 0
        // [MQTT-3.1.2-13] If Will Flag == 0, Will Retain must be 0
        if (will_flag == 0) {
            pkt->variable_header.connect_flags &= ~(0x03 << 3); // clear Will QoS (bit 3-4)
            pkt->variable_header.connect_flags &= ~(1 << 5);    // clear Will Retain (bit 5)
        } else {
            // [MQTT-3.1.2-12] If Will Flag == 1, Will QoS must ∈ {0,1,2}
            if (will_qos > 2) {
                pkt->variable_header.connect_flags &= ~(0x03 << 3); // clear Will QoS
                pkt->variable_header.connect_flags |= (0x00 << 3);  // set Will QoS to 0
            }

            // [MQTT-3.1.2-9] If Will Flag == 1, Will fields must be present
            if (pkt->payload.will_topic[0] == '\0') {
                strncpy(pkt->payload.will_topic, "default/topic", MAX_TOPIC_LEN);
            }

            if (pkt->payload.will_payload_len == 0) {
                const char *default_payload = "default_payload";
                size_t len = strlen(default_payload);
                memcpy(pkt->payload.will_payload, default_payload, len);
                pkt->payload.will_payload_len = len;
            }

            if (pkt->payload.will_property_len == 0) {
                // 添加一个默认 Will Property（例如会话过期时间 ID: 0x18）
                pkt->payload.will_properties[0] = 0x18;
                pkt->payload.will_properties[1] = 0x00;
                pkt->payload.will_property_len = 2;
            }
        }

        // （注意：3.1.2-14 和 15 是对 Server 行为的要求，不需要在 Client 端修复）
    }
}


void fix_user_name_flag(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets) return;

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        uint8_t *flags = &pkt->variable_header.connect_flags;

        uint8_t user_name_flag = (*flags >> 7) & 0x01;

        if (user_name_flag == 0) {
            // [MQTT-3.1.2-16] User Name must NOT be present
            memset(pkt->payload.user_name, 0, MAX_CLIENT_ID_LEN);
        } else {
            // [MQTT-3.1.2-17] User Name must be present
            if (pkt->payload.user_name[0] == '\0') {
                strncpy(pkt->payload.user_name, "default_user", MAX_CLIENT_ID_LEN);
            }
        }
    }
}



void fix_password_flag(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets) return;

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        uint8_t *flags = &pkt->variable_header.connect_flags;

        uint8_t password_flag = (*flags >> 6) & 0x01;

        if (password_flag == 0) {
            // [MQTT-3.1.2-18] Password MUST NOT be present
            memset(pkt->payload.password, 0, MAX_CLIENT_ID_LEN);
            pkt->payload.password_len = 0;
        } else {
            // [MQTT-3.1.2-19] Password MUST be present
            if (pkt->payload.password_len == 0) {
                const char *default_password = "default_pass";
                size_t len = strlen(default_password);
                if (len > MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN;
                memcpy(pkt->payload.password, default_password, len);
                pkt->payload.password_len = len;
            }
        }
    }
}


void fix_connect_all_length(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 will_property_len
        pkt->payload.will_property_len = strlen((char *)pkt->payload.will_properties);

        // 修复 will_payload_len
        for (int j = MAX_PAYLOAD_LEN - 1; j >= 0; --j) {
            if (pkt->payload.will_payload[j] != 0) {
                pkt->payload.will_payload_len = j + 1;
                break;
            }
        }

        // 修复 password_len
        for (int j = MAX_CLIENT_ID_LEN - 1; j >= 0; --j) {
            if (pkt->payload.password[j] != 0) {
                pkt->payload.password_len = j + 1;
                break;
            }
        }

        // 修复 remaining_length
        size_t variable_header_len = 0;
        variable_header_len += 2 + strlen(pkt->variable_header.protocol_name); // protocol_name with 2-byte length
        variable_header_len += 1; // protocol_level
        variable_header_len += 1; // connect_flags
        variable_header_len += 2; // keep_alive
        variable_header_len += pkt->variable_header.property_len;

        size_t payload_len = 0;
        payload_len += 2 + strlen(pkt->payload.client_id);
        if (((pkt->variable_header.connect_flags >> 2) & 0x01)) { // Will Flag
            payload_len += pkt->payload.will_property_len;
            payload_len += 2 + strlen(pkt->payload.will_topic);
            payload_len += 2 + pkt->payload.will_payload_len;
        }
        if (((pkt->variable_header.connect_flags >> 7) & 0x01)) { // Username Flag
            payload_len += 2 + strlen(pkt->payload.user_name);
        }
        if (((pkt->variable_header.connect_flags >> 6) & 0x01)) { // Password Flag
            payload_len += 2 + pkt->payload.password_len;
        }

        pkt->fixed_header.remaining_length = variable_header_len + payload_len;
    }
}

void fix_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        if (pkt->qos == 0) {
            pkt->variable_header.packet_identifier = 0; // 清除不应出现的 Packet Identifier
        }
    }
}


#define MAX_PACKET_ID 65535

// 简单位图记录是否使用（仅用于 fuzz 环境简单避免重复）
static uint8_t packet_id_used[MAX_PACKET_ID + 1] = {0};

// 寻找下一个未使用且非零的 packet identifier
static uint16_t get_next_packet_id() {
    static uint16_t next_id = 1;
    for (int i = 0; i < MAX_PACKET_ID; ++i) {
        uint16_t id = next_id++;
        if (next_id > MAX_PACKET_ID) next_id = 1; // wrap around
        if (!packet_id_used[id]) {
            packet_id_used[id] = 1;
            return id;
        }
    }
    return 1; // fallback，理论上不会发生
}

void fix_publish_packet_identifier_unique(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        // 仅 QoS > 0 的 PUBLISH 报文需要 Packet Identifier
        if (pkt->qos > 0) {
            if (pkt->variable_header.packet_identifier == 0 ||
                packet_id_used[pkt->variable_header.packet_identifier]) {
                pkt->variable_header.packet_identifier = get_next_packet_id();
            } else {
                packet_id_used[pkt->variable_header.packet_identifier] = 1;
            }
        } else {
            // qos == 0 时不应有 packet_id（由 MQTT-2.2.1-2 规则负责）
            pkt->variable_header.packet_identifier = 0;
        }
    }
}


void fix_publish_dup_flag(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        if (pkt->qos == 0) {
            // [MQTT-3.3.1-2] QoS 0 MUST NOT have DUP set
            pkt->dup = 0;
        } else {
            // [MQTT-3.3.1-1/3] QoS > 0, randomly choose DUP = 0 or 1
            pkt->dup = rand() % 2;
        }
    }
}

void fix_publish_qos_bits(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        if (pkt->qos > 2) {
            // QoS值非法，修复为合法值（0、1或2）
            pkt->qos = rand() % 3;
        }
    }
}
#define PROP_ID_TOPIC_ALIAS 0x23 

void fix_publish_topic_alias(mqtt_publish_packet_t *pkts, size_t num_pkts, uint16_t connack_alias_max) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t len = pkt->variable_header.property_len;

        uint8_t new_props[MAX_PROPERTIES_LEN];
        uint32_t new_len = 0;

        for (uint32_t j = 0; j < len;) {
            uint8_t id = props[j++];

            if (id == PROP_ID_TOPIC_ALIAS) {
                if (j + 1 >= len) break; // 不合法
                uint16_t alias = (props[j] << 8) | props[j + 1];

                // 若值非法，则修复
                if (alias == 0 || alias > connack_alias_max) {
                    // 修复：设为随机合法值（不为0，且 ≤ connack_alias_max）
                    alias = 1 + (rand() % connack_alias_max);
                }

                // 保留合法 alias 到新属性中
                new_props[new_len++] = PROP_ID_TOPIC_ALIAS;
                new_props[new_len++] = (alias >> 8) & 0xFF;
                new_props[new_len++] = alias & 0xFF;

                j += 2; // 跳过原始alias值
            } else {
                // 非 alias 属性，直接复制
                new_props[new_len++] = id;

                // TODO: 按 MQTT 属性格式解析后复制完整值。
                // 简化起见我们跳过这一部分，可以结合 property parser 实现更精细修复。
                // 当前实现保守处理 alias，其它属性不拷贝。
                break;
            }
        }

        // 更新属性缓冲区
        memcpy(pkt->variable_header.properties, new_props, new_len);
        pkt->variable_header.property_len = new_len;
    }
}

#define PROP_ID_RESPONSE_TOPIC 0x08
#define MAX_PROPERTIES_LEN 256

bool contains_wildcard(const char *str, uint16_t len) {
    for (uint16_t i = 0; i < len; ++i) {
        if (str[i] == '+' || str[i] == '#') return true;
    }
    return false;
}

void fix_publish_response_topic(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t len = pkt->variable_header.property_len;

        uint8_t new_props[MAX_PROPERTIES_LEN];
        uint32_t new_len = 0;

        for (uint32_t j = 0; j < len;) {
            uint8_t id = props[j++];

            if (id == PROP_ID_RESPONSE_TOPIC) {
                if (j + 2 > len) break;  // 长度不足
                uint16_t topic_len = (props[j] << 8) | props[j + 1];
                j += 2;

                if (j + topic_len > len) break;  // 越界

                char *topic = (char *)&props[j];

                if (contains_wildcard(topic, topic_len)) {
                    // 删除该属性（不复制）
                    j += topic_len;
                    continue;
                }

                // ✅ 合法，保留该属性
                new_props[new_len++] = PROP_ID_RESPONSE_TOPIC;
                new_props[new_len++] = (topic_len >> 8) & 0xFF;
                new_props[new_len++] = topic_len & 0xFF;
                memcpy(&new_props[new_len], topic, topic_len);
                new_len += topic_len;
                j += topic_len;
            } else {
                // 非 Response Topic 属性，简化起见直接丢弃（也可以保留）
                break;
            }
        }

        memcpy(pkt->variable_header.properties, new_props, new_len);
        pkt->variable_header.property_len = new_len;
    }
}

#define MAX_PROPERTIES_LEN 256
#define SUBSCRIPTION_IDENTIFIER_ID 0x0B

// 解析 Variable Byte Integer，返回长度（字节数）
size_t parse_varint_len(const uint8_t *buf, size_t max_len) {
    size_t len = 0;
    for (; len < max_len && len < 4; ++len) {
        if ((buf[len] & 0x80) == 0)
            return len + 1;
    }
    return 0;  // 错误
}

void fix_publish_subscription_identifier(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        const uint8_t *in = pkt->variable_header.properties;
        uint32_t in_len = pkt->variable_header.property_len;

        uint8_t out[MAX_PROPERTIES_LEN];
        uint32_t out_len = 0;

        for (uint32_t j = 0; j < in_len;) {
            uint8_t id = in[j++];

            if (id == SUBSCRIPTION_IDENTIFIER_ID) {
                // 跳过 Variable Byte Integer
                size_t skip = parse_varint_len(&in[j], in_len - j);
                if (skip == 0 || (j + skip > in_len)) break;
                j += skip;  // 不拷贝，跳过
            } else {
                // 保留其它属性（简化版：只保留第一个非订阅ID属性）
                // 为完整保留，请解析所有字段（或使用 MQTT 属性解析器）
                out[out_len++] = id;
                if (j < in_len) {
                    // 简单起见，假设其后是 length + value，直接拷贝剩余内容
                    size_t remain = in_len - j;
                    memcpy(&out[out_len], &in[j], remain);
                    out_len += remain;
                    break;
                }
            }
        }

        memcpy(pkt->variable_header.properties, out, out_len);
        pkt->variable_header.property_len = out_len;
    }
}

// Fixer：修复 QoS / DUP / Packet Identifier
void fix_publish_delivery_protocol(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        // QoS 0: DUP 必须是 0，不能含 packet identifier
        if (pkt->qos == 0) {
            pkt->dup = 0;
            pkt->variable_header.packet_identifier = 0;
        }

        // QoS 1: 必须有未使用的 packet id，DUP = 0
        else if (pkt->qos == 1) {
            if (pkt->variable_header.packet_identifier == 0 ||
                packet_id_used[pkt->variable_header.packet_identifier]) {
                pkt->variable_header.packet_identifier = get_next_packet_id();
            } else {
                packet_id_used[pkt->variable_header.packet_identifier] = 1;
            }
            pkt->dup = 0;  // 新消息必须 dup = 0
        }

        // QoS 2: 同样需要未使用的 packet id，DUP = 0
        else if (pkt->qos == 2) {
            if (pkt->variable_header.packet_identifier == 0 ||
                packet_id_used[pkt->variable_header.packet_identifier]) {
                pkt->variable_header.packet_identifier = get_next_packet_id();
            } else {
                packet_id_used[pkt->variable_header.packet_identifier] = 1;
            }
            pkt->dup = 0;
        }

        // 如果 qos 是非法值（例如 >2），强制改为 0
        else {
            pkt->qos = 0;
            pkt->dup = 0;
            pkt->variable_header.packet_identifier = 0;
        }
    }
}

void fix_subscribe_no_local(mqtt_subscribe_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_subscribe_packet_t *pkt = &pkts[i];
        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            // 清除 Subscription Options 的 bit 2（No Local 位）
            pkt->payload.topic_filters[j].qos &= ~(1 << 2);
        }
    }
}

void fix_subscribe_packet_identifier(mqtt_subscribe_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_subscribe_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.packet_identifier == 0) {
            pkt->variable_header.packet_identifier = get_next_packet_id();
        }
    }
}

void fix_subscribe_packet_identifier_unique(mqtt_subscribe_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_subscribe_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.packet_identifier == 0 ||
            packet_id_used[pkt->variable_header.packet_identifier]) {
            pkt->variable_header.packet_identifier = get_next_packet_id();
        } else {
            packet_id_used[pkt->variable_header.packet_identifier] = 1;
        }
    }
}

void fix_subscribe_all_length(mqtt_subscribe_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_subscribe_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 remaining_length
        size_t variable_header_len = 2 + pkt->variable_header.property_len; // packet_identifier + properties
        size_t payload_len = 0;

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            payload_len += strlen(pkt->payload.topic_filters[j].topic_filter) + 1; // topic_filter + qos byte
        }

        pkt->fixed_header.remaining_length = variable_header_len + payload_len;
    }
}

void fix_publish_all_length(mqtt_publish_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_publish_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 payload_len，如果原始值为0，尝试计算真实长度
        if (pkt->payload.payload_len == 0 && pkt->payload.payload[0] != '\0') {
            pkt->payload.payload_len = strlen((char *)pkt->payload.payload);
        }

        // 计算 variable header 长度
        size_t variable_header_len = 2 + strlen(pkt->variable_header.topic_name); // topic name
        if (pkt->qos > 0) {
            variable_header_len += 2; // packet identifier
        }
        variable_header_len += 1 + pkt->variable_header.property_len; // 1 byte for property length encoding (approx.)

        // 计算 total remaining length
        pkt->fixed_header.remaining_length = variable_header_len + pkt->payload.payload_len;
    }
}
void fix_unsubscribe_packet_identifier(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &packets[i];
        if (pkt->variable_header.packet_identifier == 0 ||
            packet_id_used[pkt->variable_header.packet_identifier]) {
            pkt->variable_header.packet_identifier = get_next_packet_id();
        } else {
            packet_id_used[pkt->variable_header.packet_identifier] = 1;
        }
    }
}

void fix_unsubscribe_all_length(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 remaining_length
        size_t variable_header_len = 2 + pkt->variable_header.property_len; // packet_identifier + properties
        size_t payload_len = 0;

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            payload_len += strlen(pkt->payload.topic_filters[j]) + 2; // topic_filter + length byte
        }

        pkt->fixed_header.remaining_length = variable_header_len + payload_len;
    }
}

void fix_auth_all_length(mqtt_auth_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_auth_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 remaining_length
        size_t variable_header_len = 1 + pkt->variable_header.property_len; // reason_code + properties
        pkt->fixed_header.remaining_length = variable_header_len;
    }
}


void fix_connect(mqtt_connect_packet_t *packets, int num_packets) {
  //fix in order to make sure that the packets are valid
  fix_connect_packet_will_rules(packets, num_packets);
  fix_user_name_flag(packets, num_packets);
  fix_password_flag(packets, num_packets);
  fix_connect_all_length(packets, num_packets);
}
void fix_subscribe(mqtt_subscribe_packet_t *packets, int num_packets) {
  fix_subscribe_no_local(packets, num_packets);
  fix_subscribe_packet_identifier(packets, num_packets);
  fix_subscribe_packet_identifier_unique(packets, num_packets);
  fix_subscribe_all_length(packets, num_packets);
}

void fix_publish(mqtt_publish_packet_t *packets, int num_packets){
  //fix in order to make sure that the packets are valid
  fix_publish_packet_identifier(packets, num_packets);
  fix_publish_packet_identifier_unique(packets, num_packets);
  fix_publish_dup_flag(packets, num_packets);
  fix_publish_qos_bits(packets, num_packets);
  fix_publish_topic_alias(packets, num_packets, 65535); // 假设 connack_alias_max 为 65535
  fix_publish_response_topic(packets, num_packets);
  fix_publish_subscription_identifier(packets, num_packets);
  fix_publish_delivery_protocol(packets, num_packets);
  fix_publish_all_length(packets, num_packets);
}

void fix_unsubscribe(mqtt_unsubscribe_packet_t *packets, int num_packets) {
  fix_unsubscribe_packet_identifier(packets, num_packets);
  fix_unsubscribe_all_length(packets, num_packets);
    // 目前不需要修复 UNSUBSCRIBE 包
}
void fix_auth(mqtt_auth_packet_t *packets, int num_packets) {
  fix_auth_all_length(packets, num_packets);
    // 目前不需要修复 AUTH 包
}

void fix_mqtt(mqtt_packet_t *pkt, int num_packets) {
    if (pkt == NULL) return;

    for (int i = 0; i < num_packets; ++i) {
        if (pkt[i].type == TYPE_CONNECT) {
          fixed_count++; // 统计修复的 CONNECT 包数量
          fix_connect(&pkt[i].connect, 1);  // 修复 CONNECT 包
        } else if (pkt[i].type == TYPE_SUBSCRIBE) {
          fixed_count++;
          fix_subscribe(&pkt[i].subscribe, 1);  // 修复 SUBSCRIBE 包
        } else if (pkt[i].type == TYPE_PUBLISH) {
          fixed_count++;
          fix_publish(&pkt[i].publish, 1);  // 修复 PUBLISH 包
        } else if (pkt[i].type == TYPE_UNSUBSCRIBE) {
          fixed_count++;
          fix_unsubscribe(&pkt[i].unsubscribe, 1);  // 修复 UNSUB
        } else if (pkt[i].type == TYPE_AUTH) {
          fixed_count++;
          fix_auth(&pkt[i].auth, 1);  // 修复 AUTH 包
        }
    }
}