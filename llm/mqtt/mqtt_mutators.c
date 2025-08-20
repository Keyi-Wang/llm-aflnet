#include "mqtt.h"
#define USERNAME_FLAG   0x80
#define PASSWORD_FLAG   0x40
#define WILL_RETAIN     0x20
#define WILL_QOS_MASK   0x18
#define WILL_QOS_SHIFT  3
#define WILL_FLAG       0x04
#define CLEAN_START     0x02
#define RESERVED        0x01


void mutate_connect_flags(mqtt_connect_packet_t* pkts, int num_pkts) {
    int total_mutations = 0;

    for (int i = 0; i < num_pkts; i++) {
        uint8_t original = pkts[i].variable_header.connect_flags;
        uint8_t mutated = original;

        int mut_type = rand() % 7;

        switch (mut_type) {
            case 0:  // 合法组合：随机合法构造
                {
                    uint8_t clean = rand() % 2;
                    uint8_t will = rand() % 2;
                    uint8_t qos = rand() % 3;
                    uint8_t retain = will ? (rand() % 2) : 0;
                    uint8_t user = rand() % 2;
                    uint8_t pass = rand() % 2;

                    mutated = 0;
                    mutated |= (user << 7);
                    mutated |= (pass << 6);
                    mutated |= (retain << 5);
                    mutated |= ((qos & 0x03) << 3);
                    mutated |= (will << 2);
                    mutated |= (clean << 1);
                    mutated |= 0x00;  // reserved bit
                }
                break;
            case 1:  // 设置非法 QoS = 3
                mutated = (original & ~WILL_QOS_MASK) | (3 << WILL_QOS_SHIFT);
                break;
            case 2:  // 设置 Retain/QoS 但未设置 WillFlag
                mutated = (1 << 5) | (2 << 3);  // retain + qos
                mutated &= ~WILL_FLAG;
                break;
            case 3:  // 设置保留位（非法）
                mutated = original | RESERVED;
                break;
            case 4:  // bitflip
                mutated = original ^ (1 << (rand() % 8));
                break;
            case 5:  // rotate left
                mutated = ((original << 1) | (original >> 7)) & 0xFF;
                break;
            case 6:  // rotate right
                mutated = ((original >> 1) | (original << 7)) & 0xFF;
                break;
        }

        pkts[i].variable_header.connect_flags = mutated;
        total_mutations++;
    }

}


#define MAX_KEEP_ALIVE 65535  // uint16_t 最大值

void mutate_connect_keep_alive(mqtt_connect_packet_t* pkts, int num_pkts) {
    int total = 0;

    for (int i = 0; i < num_pkts; i++) {
        uint16_t orig = pkts[i].variable_header.keep_alive;
        uint16_t mutated = orig;

        int strategy = rand() % 7;

        switch (strategy) {
            case 0:
                mutated = 0;  // 关闭 keep_alive
                break;
            case 1:
                mutated = 60; // 常见的设置（1 分钟）
                break;
            case 2:
                mutated = 65535;  // 最大合法值
                break;
            case 3:
                mutated = rand() % 10000;  // 合法范围内随机值
                break;
            case 4:
                mutated = orig + (rand() % 1000);  // 正向扰动
                if (mutated > MAX_KEEP_ALIVE) mutated = MAX_KEEP_ALIVE;
                break;
            case 5:
                mutated = orig - (rand() % 1000);  // 负向扰动
                // uint16 下溢自动变大：非法扰动也可保留
                break;
            case 6:
                mutated = rand();  // 全随机，可能合法也可能非法（模拟误操作）
                break;
        }

        pkts[i].variable_header.keep_alive = mutated;
        total++;
    }

}


void add_connect_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5)
            continue;

        // 增加属性字段：设定非零长度并填充内容
        pkt->variable_header.property_len = 10;
        for (int j = 0; j < 10; j++) {
            pkt->variable_header.properties[j] = (uint8_t)(rand() % 256);
        }
    }
}

void delete_connect_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5)
            continue;

        // 删除属性字段
        pkt->variable_header.property_len = 0;
        memset(pkt->variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}


void mutate_connect_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    srand(time(NULL));

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5) {
            // 非 MQTT 5.0，不含该字段
            pkt->variable_header.property_len = 0;
            continue;
        }

        int mode = rand() % 4;

        switch (mode) {
            case 0:
                // 合法: 无属性
                pkt->variable_header.property_len = 0;
                break;

            case 1:
                // 合法: 添加随机属性
                pkt->variable_header.property_len = rand() % MAX_PROPERTIES_LEN;
                for (uint32_t j = 0; j < pkt->variable_header.property_len; j++) {
                    pkt->variable_header.properties[j] = rand() % 256;
                }
                break;

            case 2:
                // 非法: 声称属性长度远大于实际
                pkt->variable_header.property_len = MAX_PROPERTIES_LEN + 50;
                break;

            case 3:
                // 非法: 超大属性长度（溢出测试）
                pkt->variable_header.property_len = 0xFFFFFFFF;
                break;
        }
    }
}

void add_connect_properties(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5)
            continue;

        // 如果原来没有属性，则添加一些属性
        if (pkt->variable_header.property_len == 0) {
            pkt->variable_header.property_len = 3;
            pkt->variable_header.properties[0] = 0x11; // Session Expiry Interval (1-byte ID)
            pkt->variable_header.properties[1] = 0x00;
            pkt->variable_header.properties[2] = 0x0A; // Value = 10
        }
    }
}

void delete_connect_properties(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5)
            continue;

        pkt->variable_header.property_len = 0;
        memset(pkt->variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

void mutate_connect_properties(mqtt_connect_packet_t *packets, int num_packets) {
    // 常见合法属性 ID
    uint8_t legal_ids[] = {
        0x11, // Session Expiry Interval
        0x12, // Receive Maximum
        0x13, // Maximum Packet Size
        0x15, // Topic Alias Maximum
        0x17, // Request Response Information
        0x19, // Request Problem Information
        0x21, // User Property (repeatable)
        0x22, // Authentication Method
        0x23  // Authentication Data
    };
    int legal_id_count = sizeof(legal_ids) / sizeof(legal_ids[0]);

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (pkt->variable_header.protocol_level != 5) continue;

        uint32_t prop_len = 0;
        uint32_t pos = 0;

        // 每次属性项数量 1 ~ 10 个
        int num_props = 1 + rand() % 10;

        for (int j = 0; j < num_props && pos < MAX_PROPERTIES_LEN - 5; ++j) {
            uint8_t id;
            if (rand() % 2) {
                id = legal_ids[rand() % legal_id_count]; // 从合法表挑
            } else {
                id = (uint8_t)(rand() & 0xFF); // 随机非法
            }

            pkt->variable_header.properties[pos++] = id;

            // 随机值长度：1, 2 或 4
            int val_len = 1 << (rand() % 3);

            // 边界：有时声明长度与实际值不符
            if (rand() % 10 == 0) val_len += rand() % 2;

            for (int k = 0; k < val_len && pos < MAX_PROPERTIES_LEN; ++k) {
                pkt->variable_header.properties[pos++] = (uint8_t)(rand() & 0xFF);
            }
        }

        // 最终声明长度可以错配或准确
        if (rand() % 5 == 0 && pos + 5 < MAX_PROPERTIES_LEN) {
            // 声明大于实际填充
            pkt->variable_header.property_len = pos + rand() % 5;
        } else {
            pkt->variable_header.property_len = pos;
        }
    }
}


void add_connect_client_id(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        if (strlen(packets[i].payload.client_id) == 0) {
            snprintf(packets[i].payload.client_id, MAX_CLIENT_ID_LEN, "client%d", rand() % 10000);
        }
    }
}

void delete_connect_client_id(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        memset(packets[i].payload.client_id, 0, MAX_CLIENT_ID_LEN);
    }
}


const char valid_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char bad_chars[] = " \t\r\n#@$%^&*()[]{}<>?!|~";

void mutate_connect_client_id(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        char *cid = packets[i].payload.client_id;
        int orig_len = strlen(cid);
        int mut_type = rand() % 8;

        switch (mut_type) {
            case 0: // 空 ID
                cid[0] = '\0';
                break;

            case 1: { // 合法随机 ID（长度 1-23）
                int len = 1 + rand() % 23;
                for (int j = 0; j < len; ++j) {
                    cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                cid[len] = '\0';
                break;
            }

            case 2: { // 超长 ID
                int len = 24 + rand() % 40; // 随机更长
                if (len >= MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN - 1;
                for (int j = 0; j < len; ++j) {
                    cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                cid[len] = '\0';
                break;
            }

            case 3: { // 插入非法字符混合
                int len = 5 + rand() % 30;
                if (len >= MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN - 1;
                for (int j = 0; j < len; ++j) {
                    if (rand() % 3 == 0)
                        cid[j] = bad_chars[rand() % (sizeof(bad_chars) - 1)];
                    else
                        cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                cid[len] = '\0';
                break;
            }

            case 4: { // 全数字 ID
                int len = 3 + rand() % 20;
                if (len >= MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN - 1;
                for (int j = 0; j < len; ++j) {
                    cid[j] = '0' + rand() % 10;
                }
                cid[len] = '\0';
                break;
            }

            case 5: { // bit-flip 原 ID 若非空
                if (orig_len > 0) {
                    int flips = 1 + rand() % 3; // 连续翻几位
                    for (int f = 0; f < flips; ++f) {
                        int pos = rand() % orig_len;
                        cid[pos] ^= (1 << (rand() % 8));
                    }
                }
                break;
            }

            case 6: { // 拼接合法段 + 非法段
                int len1 = 3 + rand() % 10;
                int len2 = 3 + rand() % 10;
                if (len1 + len2 >= MAX_CLIENT_ID_LEN) len2 = MAX_CLIENT_ID_LEN - len1 - 1;
                for (int j = 0; j < len1; ++j) {
                    cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                for (int j = 0; j < len2; ++j) {
                    cid[len1 + j] = bad_chars[rand() % (sizeof(bad_chars) - 1)];
                }
                cid[len1 + len2] = '\0';
                break;
            }

            case 7: { // 截断 ID（部分丢失）
                if (orig_len > 2) {
                    int new_len = 1 + rand() % (orig_len - 1);
                    cid[new_len] = '\0';
                }
                break;
            }

            default:
                break;
        }
    }
}

void add_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        // 仅在设置了 Will Flag 的情况下添加
        if ((packets[i].variable_header.connect_flags & 0x04) &&
            packets[i].payload.will_property_len == 0) {
            
            packets[i].payload.will_property_len = rand() % 10 + 1;
            for (uint32_t j = 0; j < packets[i].payload.will_property_len; j++) {
                packets[i].payload.will_properties[j] = rand() % 256;
            }
        }
    }
}

void delete_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        packets[i].payload.will_property_len = 0;
        memset(packets[i].payload.will_properties, 0, MAX_PROPERTIES_LEN);
    }
}

void mutate_connect_will_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        int strategy = rand() % 5;

        switch (strategy) {
            case 0: // 合法长度 + 合法属性
                packets[i].payload.will_property_len = rand() % MAX_PROPERTIES_LEN;
                for (uint32_t j = 0; j < packets[i].payload.will_property_len; ++j) {
                    packets[i].payload.will_properties[j] = rand() % 256;
                }
                break;

            case 1: // 超出最大长度（非法）
                packets[i].payload.will_property_len = MAX_PROPERTIES_LEN + rand() % 128;
                break;

            case 2: // 与 WillFlag 不一致：未设置 WillFlag 却有 Will Properties
                packets[i].variable_header.connect_flags &= ~(1 << 2); // 清除 Will Flag
                packets[i].payload.will_property_len = rand() % 10 + 1;
                for (uint32_t j = 0; j < packets[i].payload.will_property_len; ++j) {
                    packets[i].payload.will_properties[j] = rand() % 256;
                }
                break;

            case 3: // 长度与实际属性数量不符
                packets[i].payload.will_property_len = 2;
                for (uint32_t j = 0; j < 10; ++j) {
                    packets[i].payload.will_properties[j] = 0xEE;
                }
                break;

            case 4: // 清空字段（合法）
                packets[i].payload.will_property_len = 0;
                memset(packets[i].payload.will_properties, 0, MAX_PROPERTIES_LEN);
                break;
        }
    }
}

void add_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        if ((packets[i].variable_header.connect_flags & 0x04) && packets[i].payload.will_property_len == 0) {
            packets[i].payload.will_property_len = rand() % 10 + 1;
            for (uint32_t j = 0; j < packets[i].payload.will_property_len; j++) {
                packets[i].payload.will_properties[j] = rand() % 256;
            }
        }
    }
}

void delete_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; i++) {
        packets[i].payload.will_property_len = 0;
        memset(packets[i].payload.will_properties, 0, MAX_PROPERTIES_LEN);
    }
}

#define LEGAL_WILL_PROP_IDS_LEN 8

const uint8_t legal_will_prop_ids[LEGAL_WILL_PROP_IDS_LEN] = {
    0x01, // Payload Format Indicator
    0x02, // Message Expiry Interval
    0x03, // Content Type
    0x08, // Response Topic
    0x09, // Correlation Data
    0x26, // User Property
    0x27, // User Property
    0x28  // Will Delay Interval
};

void mutate_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        uint8_t *props = pkt->payload.will_properties;

        int strategy = rand() % 8;

        switch (strategy) {

            case 0: { // 合法单个属性
                pkt->payload.will_property_len = 3;
                props[0] = legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                props[1] = 0x00;
                props[2] = rand() % 256;
                break;
            }

            case 1: { // 合法多个属性混合
                int count = 2 + rand() % 4; // 2~5 个属性
                int pos = 0;
                for (int j = 0; j < count; ++j) {
                    if (pos + 3 >= MAX_PROPERTIES_LEN) break;
                    props[pos++] = legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                    props[pos++] = 0x00;
                    props[pos++] = rand() % 256;
                }
                pkt->payload.will_property_len = pos;
                break;
            }

            case 2: { // 非法属性 ID混入
                int len = 3 + rand() % 5;
                for (int j = 0; j < len; ++j) {
                    props[j] = (rand() % 2) ? 0xFF : legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                }
                pkt->payload.will_property_len = len;
                break;
            }

            case 3: { // 超长属性随机填充
                pkt->payload.will_property_len = MAX_PROPERTIES_LEN;
                for (int j = 0; j < MAX_PROPERTIES_LEN; ++j) {
                    props[j] = rand() % 256;
                }
                break;
            }

            case 4: { // 重复属性段
                uint8_t id = legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                int repeat = 1 + rand() % 5;
                int pos = 0;
                for (int j = 0; j < repeat; ++j) {
                    if (pos + 3 >= MAX_PROPERTIES_LEN) break;
                    props[pos++] = id;
                    props[pos++] = 0x00;
                    props[pos++] = rand() % 256;
                }
                pkt->payload.will_property_len = pos;
                break;
            }

            case 5: { // 全 0x00
                int len = 2 + rand() % 10;
                memset(props, 0x00, len);
                pkt->payload.will_property_len = len;
                break;
            }

            case 6: { // 全 0xFF
                int len = 2 + rand() % 10;
                memset(props, 0xFF, len);
                pkt->payload.will_property_len = len;
                break;
            }

            case 7: { // bitflip + 插入垃圾尾部
                int len = 5 + rand() % 10;
                for (int j = 0; j < len; ++j) {
                    props[j] = rand() % 256;
                    if (rand() % 3 == 0) {
                        props[j] ^= (1 << (rand() % 8));
                    }
                }
                // 垃圾尾
                if (len + 5 < MAX_PROPERTIES_LEN) {
                    for (int j = len; j < len + 5; ++j) {
                        props[j] = rand() % 256;
                    }
                    len += 5;
                }
                pkt->payload.will_property_len = len;
                break;
            }

            default:
                break;
        }
    }
}

void add_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets) {
    const char *sample_topics[] = {
        "sensor/temp",
        "a/b/c",
        "device/+/status",
        "home/+/light/#",
        "你好/测试"
    };
    int topic_count = sizeof(sample_topics) / sizeof(sample_topics[0]);

    for (int i = 0; i < num_packets; ++i) {
        if ((packets[i].variable_header.connect_flags & 0x04) && strlen(packets[i].payload.will_topic) == 0) {
            strncpy(packets[i].payload.will_topic,
                    sample_topics[rand() % topic_count],
                    MAX_TOPIC_LEN - 1);
            packets[i].payload.will_topic[MAX_TOPIC_LEN - 1] = '\0';
        }
    }
}

void delete_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        memset(packets[i].payload.will_topic, 0, MAX_TOPIC_LEN);
    }
}


void mutate_connect_will_topic(mqtt_connect_packet_t *packets, int num_packets) {
    const char *base_topics[] = {
        "",               // 空 topic
        "/",              // 根
        "home/sensor",    // 正常
        "+/#",            // 通配符组合
        "#/invalid",      // 非法 # 用法
        "topic\x00mid",   // 带 NULL
        "\xC3\x28",       // 非法 UTF-8
        "\xFF\xFF\xFF",   // 垃圾 UTF-8
    };
    int total_base = sizeof(base_topics) / sizeof(base_topics[0]);

    const char valid_chars[] = "abcdefghijklmnopqrstuvwxyz/+-_0123456789";

    for (int i = 0; i < num_packets; ++i) {

        if (!(packets[i].variable_header.connect_flags & 0x04)) continue;  // WillFlag=1

        int strategy = rand() % 6;
        char *topic = packets[i].payload.will_topic;

        switch (strategy) {

            case 0: {
                // 使用预设 topic
                const char *mutation = base_topics[rand() % total_base];
                strncpy(topic, mutation, MAX_TOPIC_LEN - 1);
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            }

            case 1: {
                // 生成合法随机 topic：用有效字符构造
                int len = 1 + rand() % (MAX_TOPIC_LEN - 2);
                for (int j = 0; j < len; ++j) {
                    topic[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                topic[len] = '\0';
                break;
            }

            case 2: {
                // 生成超长 topic（非法）
                int len = MAX_TOPIC_LEN - 1 + rand() % 20;
                for (int j = 0; j < len && j < MAX_TOPIC_LEN - 1; ++j) {
                    topic[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            }

            case 3: {
                // 拼接合法 + 非法片段
                int len = 0;
                const char *prefix = base_topics[rand() % total_base];
                strncpy(topic, prefix, MAX_TOPIC_LEN - 1);
                len = strlen(topic);
                if (len < MAX_TOPIC_LEN - 1) {
                    int remain = (MAX_TOPIC_LEN - 1) - len;
                    for (int j = 0; j < remain; ++j) {
                        topic[len + j] = '\xFF'; // 非 UTF-8
                    }
                    topic[MAX_TOPIC_LEN - 1] = '\0';
                }
                break;
            }

            case 4: {
                // 插入特殊符号 & bitflip
                int len = 1 + rand() % (MAX_TOPIC_LEN - 2);
                for (int j = 0; j < len; ++j) {
                    if (rand() % 4 == 0) {
                        topic[j] = '#';  // 通配符非法位置
                    } else {
                        topic[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                        if (rand() % 3 == 0) {
                            topic[j] ^= (1 << (rand() % 8));  // bitflip
                        }
                    }
                }
                topic[len] = '\0';
                break;
            }

            case 5: {
                // 全 NULL 字节填充（测试 MQTT 字符串解析）
                memset(topic, '\0', MAX_TOPIC_LEN);
                break;
            }

            default:
                break;
        }
    }
}

void add_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets) {
    const char *samples[] = {
        "device offline",
        "error: timeout",
        "{\"status\": \"dead\"}",
        "MQTT last will",
        "\xDE\xAD\xBE\xEF"
    };
    int sample_count = sizeof(samples) / sizeof(samples[0]);

    for (int i = 0; i < num_packets; ++i) {
        if ((packets[i].variable_header.connect_flags & 0x04) && packets[i].payload.will_payload_len == 0) {
            const char *data = samples[rand() % sample_count];
            size_t len = strlen(data);
            if (len > MAX_PAYLOAD_LEN) len = MAX_PAYLOAD_LEN;
            memcpy(packets[i].payload.will_payload, data, len);
            packets[i].payload.will_payload_len = len;
        }
    }
}

void delete_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        memset(packets[i].payload.will_payload, 0, MAX_PAYLOAD_LEN);
        packets[i].payload.will_payload_len = 0;
    }
}

void mutate_connect_will_payload(mqtt_connect_packet_t *packets, int num_packets) {
    const char valid_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~";

    for (int i = 0; i < num_packets; ++i) {

        if (!(packets[i].variable_header.connect_flags & 0x04)) continue; // 仅在 WillFlag=1 时生效

        uint8_t strategy = rand() % 7;
        uint8_t *payload = packets[i].payload.will_payload;
        uint16_t *len = &packets[i].payload.will_payload_len;

        switch (strategy) {

            case 0: { // 合法 UTF-8 文本（随机长度）
                int l = 5 + rand() % 20;
                for (int j = 0; j < l; ++j) {
                    payload[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                *len = l;
                break;
            }

            case 1: { // 二进制模式（随机长度）
                int l = 1 + rand() % 64;
                for (int j = 0; j < l; ++j) {
                    payload[j] = rand() % 256;
                }
                *len = l;
                break;
            }

            case 2: { // 空 payload
                *len = 0;
                break;
            }

            case 3: { // 超长 payload
                int l = MAX_PAYLOAD_LEN;
                for (int j = 0; j < l; ++j) {
                    payload[j] = rand() % 256;
                }
                *len = l;
                break;
            }

            case 4: { // 插入 NULL 字节 + 随机尾随数据
                int l = 5 + rand() % 10;
                for (int j = 0; j < l; ++j) {
                    payload[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                int pos = rand() % l;
                payload[pos] = '\0';  // 强行插入 NULL
                *len = l;
                break;
            }

            case 5: { // 非法 UTF-8 序列
                uint8_t invalid_utf8[] = {0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x28, 0xA1};
                int l = sizeof(invalid_utf8);
                memcpy(payload, invalid_utf8, l);
                *len = l;
                break;
            }

            case 6: { // 混合合法文本 + 垃圾二进制
                int l = 10 + rand() % 30;
                int split = rand() % l;
                for (int j = 0; j < split; ++j) {
                    payload[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                for (int j = split; j < l; ++j) {
                    payload[j] = rand() % 256;
                }
                *len = l;
                break;
            }

            default:
                break;
        }

    }
}

void add_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        if ((packets[i].variable_header.connect_flags & 0x04) && packets[i].payload.will_payload_len == 0) {
            uint16_t len = rand() % MAX_PAYLOAD_LEN;
            for (int j = 0; j < len; ++j) {
                packets[i].payload.will_payload[j] = rand() % 256;
            }
            packets[i].payload.will_payload_len = len;
        }
    }
}

void delete_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        packets[i].payload.will_payload_len = 0;
    }
}

void mutate_connect_will_payload_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (!(pkt->variable_header.connect_flags & 0x04)) continue;

        uint8_t strategy = rand() % 5;
        switch (strategy) {
            case 0:  // 设置为实际 payload 长度（合法）
                pkt->payload.will_payload_len = strlen((char *)pkt->payload.will_payload);
                break;
            case 1:  // 过长（非法）
                pkt->payload.will_payload_len = MAX_PAYLOAD_LEN + rand() % 100;
                break;
            case 2:  // 过短（非法）
                if (strlen((char *)pkt->payload.will_payload) > 2)
                    pkt->payload.will_payload_len = rand() % 2;
                else
                    pkt->payload.will_payload_len = 0;
                break;
            case 3:  // 设置为 0（可合法或非法）
                pkt->payload.will_payload_len = 0;
                break;
            case 4:  // 极端随机值
                pkt->payload.will_payload_len = rand() % 0xFFFF;
                break;
        }
    }
}

void add_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (!(pkt->variable_header.connect_flags & 0x80)) {
            pkt->variable_header.connect_flags |= 0x80;  // 设置 User Name Flag
            snprintf(pkt->payload.user_name, MAX_CLIENT_ID_LEN, "user_%d", rand());
        }
    }
}

void delete_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        pkt->variable_header.connect_flags &= ~(0x80);  // 清除 User Name Flag
        memset(pkt->payload.user_name, 0, MAX_CLIENT_ID_LEN);
    }
}

void mutate_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    static const char *special_cases[] = {
        "",                              // 空字符串
        "admin",                         // 常用用户名
        "root",                          // 经典 root
        "user!@#$%^&*()",                // 含特殊字符
        "A_very_very_long_username_string_that_may_overflow_the_buffer_lol",
        "\xFF\xFE\xFD",                  // 非 ASCII 字节
        NULL
    };

    static const char valid_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#";

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        // 如果未启用 User Name Flag，则跳过
        if (!(pkt->variable_header.connect_flags & 0x80)) continue;

        int strategy = rand() % 7;

        switch (strategy) {

            case 0: {  // 合法随机用户名
                int len = 5 + rand() % 20;
                for (int j = 0; j < len; ++j) {
                    pkt->payload.user_name[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                pkt->payload.user_name[len] = '\0';
                break;
            }

            case 1: {  // 使用特殊测试用例
                const char *src = special_cases[rand() % 5];
                strncpy(pkt->payload.user_name, src, MAX_CLIENT_ID_LEN - 1);
                pkt->payload.user_name[MAX_CLIENT_ID_LEN - 1] = '\0';
                break;
            }

            case 2: {  // 非法非 ASCII 序列 + UTF-8 序列污染
                uint8_t garbage[] = { 0xC3, 0x28, 0xA0, 0xA1, 0xFF, 0xFE };
                int l = sizeof(garbage);
                memcpy(pkt->payload.user_name, garbage, l);
                pkt->payload.user_name[l] = '\0';
                break;
            }

            case 3: {  // 缓冲区溢出模拟：填满 + 不写 \0
                memset(pkt->payload.user_name, 'A', MAX_CLIENT_ID_LEN);
                // 故意不写 \0
                break;
            }

            case 4: {  // 清空用户名
                pkt->payload.user_name[0] = '\0';
                break;
            }

            case 5: {  // NULL 字节注入 + 随机后缀
                int l = 5 + rand() % 10;
                for (int j = 0; j < l; ++j) {
                    pkt->payload.user_name[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                int pos = rand() % l;
                pkt->payload.user_name[pos] = '\0'; // 中间注入 NULL
                break;
            }

            case 6: {  // 随机 bit-flip
                int l = strlen(pkt->payload.user_name);
                if (l == 0) l = 5;
                for (int j = 0; j < l; ++j) {
                    pkt->payload.user_name[j] ^= (rand() % 2) ? (1 << (rand() % 8)) : 0;
                }
                break;
            }

            default:
                break;
        }
    }
}


void add_connect_password(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (!(pkt->variable_header.connect_flags & 0x40)) {
            pkt->variable_header.connect_flags |= 0x40;  // 打开 password 标志
            const char *sample = "secret_pass";
            memcpy(pkt->payload.password, sample, strlen(sample));
            pkt->payload.password_len = strlen(sample);
        }
    }
}

void delete_connect_password(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        pkt->variable_header.connect_flags &= ~(0x40);  // 清除 password 标志
        memset(pkt->payload.password, 0, MAX_CLIENT_ID_LEN);
        pkt->payload.password_len = 0;
    }
}

void mutate_connect_password(mqtt_connect_packet_t *packets, int num_packets) {

    static const char *common_passwords[] = {
        "",                    // 空密码
        "123456",              // 弱口令
        "password",            // 弱口令
        "pass!@#$_",           // 特殊字符
        "admin123",            // 常见组合
        "\x00\x01\xFF\xFE",    // 非 ASCII 字节
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 超长串
        NULL
    };

    for (int i = 0; i < num_packets; ++i) {

        mqtt_connect_packet_t *pkt = &packets[i];

        // 若未启用 Password Flag，则跳过
        if (!(pkt->variable_header.connect_flags & 0x40)) continue;

        int strategy = rand() % 8;

        switch (strategy) {

            case 0: { // 使用预置常见密码
                const char *src = common_passwords[rand() % 5];
                pkt->payload.password_len = strlen(src);
                memcpy(pkt->payload.password, src, pkt->payload.password_len);
                break;
            }

            case 1: { // 空密码
                pkt->payload.password_len = 0;
                break;
            }

            case 2: { // 固定二进制垃圾
                uint8_t garbage[] = { 0x00, 0xFF, 0xAA, 0x55 };
                memcpy(pkt->payload.password, garbage, sizeof(garbage));
                pkt->payload.password_len = sizeof(garbage);
                break;
            }

            case 3: { // 随机二进制串
                pkt->payload.password_len = rand() % (MAX_CLIENT_ID_LEN);
                for (int j = 0; j < pkt->payload.password_len; ++j) {
                    pkt->payload.password[j] = rand() % 256;
                }
                break;
            }

            case 4: { // 超长填充（全'A'）
                pkt->payload.password_len = MAX_CLIENT_ID_LEN;
                memset(pkt->payload.password, 'A', pkt->payload.password_len);
                break;
            }

            case 5: { // 非法 UTF-8 序列
                uint8_t bad_utf8[] = { 0xC3, 0x28, 0xA0, 0xA1 };
                memcpy(pkt->payload.password, bad_utf8, sizeof(bad_utf8));
                pkt->payload.password_len = sizeof(bad_utf8);
                break;
            }

            case 6: { // NULL 字节混入 + 后缀
                int len = 5 + rand() % 10;
                for (int j = 0; j < len; ++j) {
                    pkt->payload.password[j] = 'a' + (rand() % 26);
                }
                int pos = rand() % len;
                pkt->payload.password[pos] = '\0'; // 注入 NULL
                pkt->payload.password_len = len;
                break;
            }

            case 7: { // Bit-flip 当前值或随机生成
                if (pkt->payload.password_len == 0) {
                    pkt->payload.password_len = 5 + rand() % 10;
                    for (int j = 0; j < pkt->payload.password_len; ++j) {
                        pkt->payload.password[j] = 'a' + (rand() % 26);
                    }
                }
                int flip_pos = rand() % pkt->payload.password_len;
                pkt->payload.password[flip_pos] ^= 1 << (rand() % 8);
                break;
            }

            default:
                break;
        }
    }
}


void add_connect_password_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (!(pkt->variable_header.connect_flags & 0x40)) {
            pkt->variable_header.connect_flags |= 0x40;
            pkt->payload.password_len = 5;
            memcpy(pkt->payload.password, "12345", 5);
        }
    }
}

void delete_connect_password_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        pkt->variable_header.connect_flags &= ~0x40;
        pkt->payload.password_len = 0;
        memset(pkt->payload.password, 0, MAX_CLIENT_ID_LEN);
    }
}

void mutate_connect_password_len(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (!(pkt->variable_header.connect_flags & 0x40)) continue;

        int strategy = rand() % 6;
        switch (strategy) {
            case 0:  // 设置为实际密码长度（合法）
                pkt->payload.password_len = strlen((char *)pkt->payload.password);
                break;
            case 1:  // 越界长度
                pkt->payload.password_len = MAX_CLIENT_ID_LEN + 10;
                break;
            case 2:  // 设置为 0（空密码）
                pkt->payload.password_len = 0;
                break;
            case 3:  // 随机较小长度
                pkt->payload.password_len = rand() % 5;
                break;
            case 4:  // 随机非法值
                pkt->payload.password_len = rand() % 70000;  // 超过 uint16_t 合法范围
                break;
            case 5:  // 正确长度 ±1（可能截断或越界）
                {
                    int len = strlen((char *)pkt->payload.password);
                    pkt->payload.password_len = len + ((rand() % 3) - 1); // len-1, len, len+1
                }
                break;
        }
    }
}

void mutate_subscribe_packet_identifier(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint16_t original = pkt->variable_header.packet_identifier;
        uint16_t mutated = original;

        switch (rand() % 10) {
            case 0: // 设置为0（非法，MQTT规定Packet ID不能为0）
                mutated = 0;
                break;
            case 1: // 设置为最大合法值
                mutated = 65535;
                break;
            case 2: // 设置为最小合法值
                mutated = 1;
                break;
            case 3: // 生成完全随机值
                mutated = (uint16_t)(rand() % 65536);
                break;
            case 4: // 高位全1，低位随机
                mutated = 0xFF00 | (rand() & 0x00FF);
                break;
            case 5: // 翻转一位
                mutated = original ^ (1 << (rand() % 16));
                break;
            case 6: // 加1（模拟顺序 ID）
                mutated = original + 1;
                break;
            case 7: // 减1（模拟 wraparound）
                mutated = original - 1;
                break;
            case 8: // 设置为前一个包的 ID（模拟 ID 重复）
                if (i > 0)
                    mutated = subs[i - 1].variable_header.packet_identifier;
                break;
            case 9: // 设置为常见边界值（0x8000）
                mutated = 0x8000;
                break;
        }

        pkt->variable_header.packet_identifier = mutated;
    }
}

void mutate_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t *plen = &pkt->variable_header.property_len;

        if (*plen > MAX_PROPERTIES_LEN) continue;

        switch (rand() % 10) {
            case 0: // 清空属性
                *plen = 0;
                break;
            case 1: // 重复属性
                if (*plen * 2 < MAX_PROPERTIES_LEN) {
                    memcpy(props + *plen, props, *plen);
                    *plen *= 2;
                }
                break;
            case 2: // 插入无效属性 ID
                if (*plen < MAX_PROPERTIES_LEN - 1)
                    props[(*plen)++] = 0xFF; // 未定义属性
                break;
            case 3: // bit flip
                if (*plen > 0)
                    props[rand() % *plen] ^= 0xFF;
                break;
            case 4: // 增加乱序 User Property
                if (*plen < MAX_PROPERTIES_LEN - 10) {
                    uint8_t tmp[] = {0x26, 0x00, 0x01, 'X', 0x00, 0x01, 'Y'};
                    memcpy(props + *plen, tmp, sizeof(tmp));
                    *plen += sizeof(tmp);
                }
                break;
            case 5: // 裁剪一半
                *plen /= 2;
                break;
            case 6: // 扩展 property_len 超实际长度
                *plen += 5;  // 让 property_len > 实际字节，测试 parser
                break;
            case 7: // 插入 Subscription Identifier (0x0B)
                if (*plen < MAX_PROPERTIES_LEN - 2) {
                    props[(*plen)++] = 0x0B;
                    props[(*plen)++] = rand() % 128;
                }
                break;
            case 8: // 随机覆盖属性区
                for (int j = 0; j < 10 && *plen + j < MAX_PROPERTIES_LEN; j++) {
                    props[*plen + j] = rand() % 256;
                }
                *plen += 10;
                break;
            case 9: // 设置为全0
                memset(props, 0, *plen);
                break;
        }
    }
}

void add_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];

        if (pkt->variable_header.property_len >= MAX_PROPERTIES_LEN - 5) continue;

        // 添加一个简单的 User Property（Identifier = 0x26）
        uint8_t *p = pkt->variable_header.properties + pkt->variable_header.property_len;
        size_t offset = 0;

        p[offset++] = 0x26; // User Property identifier

        // Key = "foo"
        p[offset++] = 0;
        p[offset++] = 3;
        p[offset++] = 'f';
        p[offset++] = 'o';
        p[offset++] = 'o';

        // Value = "bar"
        p[offset++] = 0;
        p[offset++] = 3;
        p[offset++] = 'b';
        p[offset++] = 'a';
        p[offset++] = 'r';

        pkt->variable_header.property_len += offset;
    }
}

void delete_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        subs[i].variable_header.property_len = 0;
        memset(subs[i].variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

void repeat_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        size_t len = pkt->variable_header.property_len;

        if (len > 0 && len * 2 < MAX_PROPERTIES_LEN) {
            memcpy(pkt->variable_header.properties + len, pkt->variable_header.properties, len);
            pkt->variable_header.property_len *= 2;
        }
    }
}


void mutate_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    const char *wildcards[] = {"#", "+", "/#", "a/#/b", "+/+"};
    const char *bad_topics[] = {"", " ", "///", "#/#", "#+", "invalid\x01topic"};
    const char *valid_topics[] = {"sensor/temperature", "device/+/status", "home/+/light/#", "foo", "a/b/c/d"};

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            char *filter = pkt->payload.topic_filters[j].topic_filter;

            switch (rand() % 10) {
                case 0: // 替换为通配符
                    strncpy(filter, wildcards[rand() % 5], MAX_TOPIC_LEN);
                    break;
                case 1: // 替换为非法主题（空串、包含控制字符）
                    strncpy(filter, bad_topics[rand() % 6], MAX_TOPIC_LEN);
                    break;
                case 2: // 添加无效字符
                    snprintf(filter, MAX_TOPIC_LEN, "topic/invalid/%c", rand() % 32);  // 控制字符
                    break;
                case 3: // Bit flip 第一个字符
                    if (strlen(filter) > 0) filter[0] ^= 0xFF;
                    break;
                case 4: // 变成随机 ASCII 串
                    for (int k = 0; k < 10; ++k) {
                        filter[k] = (char)(33 + rand() % 94); // 可打印 ASCII
                    }
                    filter[10] = '\0';
                    break;
                case 5: // 合法但复杂 filter
                    strncpy(filter, valid_topics[rand() % 5], MAX_TOPIC_LEN);
                    break;
                case 6: // 插入多个斜杠
                    strncpy(filter, "///a///b///", MAX_TOPIC_LEN);
                    break;
                case 7: // 长度扩展至最大
                    memset(filter, 'a', MAX_TOPIC_LEN - 1);
                    filter[MAX_TOPIC_LEN - 1] = '\0';
                    break;
                case 8: // 清空
                    filter[0] = '\0';
                    break;
                case 9: // 拷贝前一个 filter（模拟重复）
                    if (j > 0) strncpy(filter, pkt->payload.topic_filters[j - 1].topic_filter, MAX_TOPIC_LEN);
                    break;
            }
        }
    }
}



void repeat_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];

        if (pkt->payload.topic_count == 0 || pkt->payload.topic_count >= MAX_TOPIC_FILTERS)
            continue;

        // 随机选一个已有的 topic_filter 来重复
        int repeat_index = rand() % pkt->payload.topic_count;
        int new_index = pkt->payload.topic_count;

        // 执行复制（包括 topic + qos）
        memcpy(&pkt->payload.topic_filters[new_index],
               &pkt->payload.topic_filters[repeat_index],
               sizeof(pkt->payload.topic_filters[0]));

        // 可选：对复制后的 qos 进行微调（如随机变异）
        if (rand() % 2 == 0) {  // 50% 概率随机改动 qos
            pkt->payload.topic_filters[new_index].qos = rand() % 4;  // 可包含非法值测试解析器
        }

        pkt->payload.topic_count++;
    }
}

void mutate_subscribe_qos(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            uint8_t *qos = &pkt->payload.topic_filters[j].qos;
            switch (rand() % 10) {
                case 0: // 设置为合法值0
                    *qos = 0;
                    break;
                case 1: // 设置为合法值1
                    *qos = 1;
                    break;
                case 2: // 设置为合法值2
                    *qos = 2;
                    break;
                case 3: // 设置为非法值3（仅0/1/2合法）
                    *qos = 3;
                    break;
                case 4: // 设置为255（最大无符号）
                    *qos = 255;
                    break;
                case 5: // 设置为随机合法值（0-2）
                    *qos = rand() % 3;
                    break;
                case 6: // 设置为随机非法值（3~254）
                    *qos = 3 + rand() % 252;
                    break;
                case 7: // bit flip（破坏现有值）
                    *qos ^= (1 << (rand() % 3));
                    break;
                case 8: // 复制前一个 topic 的 qos
                    if (j > 0) *qos = pkt->payload.topic_filters[j - 1].qos;
                    break;
                case 9: // 全0（合法，但所有都是0）
                    *qos = 0;
                    break;
            }
        }
    }
}

void mutate_subscribe_topic_count(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *count = &pkt->payload.topic_count;

        switch (rand() % 10) {
            case 0: // 设置为 0（非法，必须至少有一个 topic）
                *count = 0;
                break;
            case 1: // 设置为 MAX_TOPIC_FILTERS（边界值）
                *count = MAX_TOPIC_FILTERS;
                break;
            case 2: // 设置为 MAX_TOPIC_FILTERS + 1（非法，超出）
                *count = MAX_TOPIC_FILTERS + 1;
                break;
            case 3: // 设置为 1（最小合法值）
                *count = 1;
                break;
            case 4: // 设置为随机合法值 [1, MAX_TOPIC_FILTERS]
                *count = 1 + rand() % MAX_TOPIC_FILTERS;
                break;
            case 5: // 设置为随机非法值 [MAX+2, 255]
                *count = MAX_TOPIC_FILTERS + 2 + rand() % (255 - MAX_TOPIC_FILTERS - 2);
                break;
            case 6: // 将 count 设置为原值翻倍（可能溢出）
                *count = (*count) * 2;
                break;
            case 7: // 取反：bitwise NOT
                *count = ~(*count);
                break;
            case 8: // 位翻转最低位
                *count ^= 0x01;
                break;
            case 9: // 拷贝前一个 packet 的 topic_count
                if (i > 0) *count = subs[i - 1].payload.topic_count;
                break;
        }

        // 为避免结构不一致，可清空多余的 topic_filter
        if (*count > MAX_TOPIC_FILTERS)
            *count = MAX_TOPIC_FILTERS;

        // 如果设置过少，可复制已有的 topic filter 填满
        for (int j = 1; j < *count; ++j) {
            memcpy(&pkt->payload.topic_filters[j],
                   &pkt->payload.topic_filters[0],
                   sizeof(pkt->payload.topic_filters[0]));
        }
    }
}


void add_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        if (strlen(pkts[i].variable_header.topic_name) == 0) {
            strcpy(pkts[i].variable_header.topic_name, "test/topic/added");
        }
    }
}

void delete_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        pkts[i].variable_header.topic_name[0] = '\0';
    }
}

void mutate_publish_topic_name(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        char *topic = pkts[i].variable_header.topic_name;

        switch (rand() % 10) {
            case 0:  // 设置为空串（非法，除非使用 Topic Alias）
                topic[0] = '\0';
                break;
            case 1:  // 设置为单级通配符： "+"
                strcpy(topic, "+");
                break;
            case 2:  // 设置为多级通配符： "#"
                strcpy(topic, "#");
                break;
            case 3:  // 非法主题（包含多个 #）
                strcpy(topic, "invalid/#/test#");
                break;
            case 4:  // 超长主题（超过 MAX_TOPIC_LEN）
                memset(topic, 'A', MAX_TOPIC_LEN + 10);
                topic[MAX_TOPIC_LEN + 9] = '\0';
                break;
            case 5:  // 合法嵌套主题
                strcpy(topic, "sensor/+/temperature");
                break;
            case 6:  // 随机字节填充（可能非 UTF-8）
                for (int j = 0; j < MAX_TOPIC_LEN - 1; j++)
                    topic[j] = (char)(rand() % 256);
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            case 7:  // 合法静态主题
                strcpy(topic, "home/kitchen/light");
                break;
            case 8:  // 特殊字符
                strcpy(topic, "topic/!@#$%^&*()");
                break;
            case 9:  // 添加前缀/后缀
                snprintf(topic, MAX_TOPIC_LEN, "prefix_%s_suffix", topic);
                break;
        }
    }
}

void add_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        if (pkts[i].qos > 0 && pkts[i].variable_header.packet_identifier == 0) {
            pkts[i].variable_header.packet_identifier = rand() % 0xFFFF + 1;
        }
    }
}

void delete_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        if (pkts[i].qos == 0) {
            pkts[i].variable_header.packet_identifier = 0; // 合法
        } else {
            // 非法行为：故意清空
            pkts[i].variable_header.packet_identifier = 0;
        }
    }
}

void mutate_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        // 若 QoS == 0，该字段无意义；我们故意做边界测试
        uint16_t *id = &pkt->variable_header.packet_identifier;

        switch (rand() % 10) {
            case 0: *id = 0; break;                     // 非法值（当 QoS > 0）
            case 1: *id = 1; break;                     // 最小有效值
            case 2: *id = 0xFFFF; break;                // 最大值
            case 3: *id = rand() % 0xFFFF; break;       // 随机有效值
            case 4: *id = rand(); break;                // 随机 32 位截断
            case 5: *id = 0x7FFF; break;                // 中间值
            case 6: *id = 0x8000; break;                // 边界测试
            case 7: *id ^= 0xAAAA; break;               // 位翻转测试
            case 8: *id = (uint16_t)(~(*id)); break;    // 全反转
            case 9: *id = *id + 1; break;               // 增加1造成碰撞
        }
    }
}

void add_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        if (pkt->variable_header.property_len == 0) {
            // 构造一个简单属性，例如 Payload Format Indicator (ID: 0x01, value: 0x01)
            pkt->variable_header.properties[0] = 0x01;  // ID
            pkt->variable_header.properties[1] = 0x01;  // value
            pkt->variable_header.property_len = 2;
        }
    }
}

void delete_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i]; 
        pkt->variable_header.property_len = 0;  
    }
}


void repeat_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint32_t len = pkt->variable_header.property_len;

        // 只复制一次已有字段（简单复制前两个字节）
        if (len + 2 < MAX_PROPERTIES_LEN && len >= 2) {
            pkt->variable_header.properties[len]     = pkt->variable_header.properties[0];
            pkt->variable_header.properties[len + 1] = pkt->variable_header.properties[1];
            pkt->variable_header.property_len += 2;
        }
    }
}

void mutate_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t *len = &pkt->variable_header.property_len;

        switch (rand() % 10) {
            case 0: // 清空
                *len = 0;
                break;
            case 1: // 设置非法属性 ID
                props[0] = 0xFF;
                props[1] = 0x00;
                *len = 2;
                break;
            case 2: // 填入最大长度属性
                memset(props, 0x01, MAX_PROPERTIES_LEN);
                *len = MAX_PROPERTIES_LEN;
                break;
            case 3: // 添加多个合法属性
                props[0] = 0x01; props[1] = 0x01; // Payload Format Indicator
                props[2] = 0x23; props[3] = 0x00; props[4] = 0x00; props[5] = 0x00; props[6] = 0x64; // Message Expiry
                *len = 7;
                break;
            case 4: // 非法长度（声明比实际短）
                *len = 1;
                props[0] = 0x01;
                break;
            case 5: // 非法长度（声明比实际长）
                *len = 5;
                props[0] = 0x01; props[1] = 0x01;
                break;
            case 6: // 填充乱码
                for (int j = 0; j < 10; j++) props[j] = rand() % 256;
                *len = 10;
                break;
            case 7: // 添加非法重复属性（例如两个 Payload Format）
                props[0] = 0x01; props[1] = 0x00;
                props[2] = 0x01; props[3] = 0x01;
                *len = 4;
                break;
            case 8: // 添加合法 user property (ID 0x26, UTF8-pair)
                props[0] = 0x26;
                props[1] = 0x00; props[2] = 0x03; props[3] = 'k'; props[4] = 'e'; props[5] = 'y';
                props[6] = 0x00; props[7] = 0x05; props[8] = 'v'; props[9] = 'a'; props[10] = 'l'; props[11] = 'u'; props[12] = 'e';
                *len = 13;
                break;
            case 9: // 前缀注入
                if (*len + 2 > MAX_PROPERTIES_LEN) {
                  continue;
                }
                memmove(props + 2, props, *len);
                props[0] = 0x02; props[1] = 0x02;  // Content Type = 0x02
                *len += 2;
                break;
        }
    }
}

void add_publish_payload(mqtt_publish_packet_t *pkts, size_t num) {
    const char *default_payload = "hello";
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        if (pkt->payload.payload_len == 0) {
            size_t len = strlen(default_payload);
            memcpy(pkt->payload.payload, default_payload, len);
            pkt->payload.payload_len = len;
        }
    }
}

void delete_publish_payload(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        pkt->payload.payload_len = 0;
    }
}


void mutate_publish_payload(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->payload.payload;
        uint32_t *len = &pkt->payload.payload_len;

        switch (rand() % 10) {
            case 0: // 清空
                *len = 0;
                break;
            case 1: // 设置最大长度
                for (int j = 0; j < MAX_PAYLOAD_LEN; ++j) p[j] = 'A';
                *len = MAX_PAYLOAD_LEN;
                break;
            case 2: // 填入随机字节
                *len = rand() % MAX_PAYLOAD_LEN;
                for (uint32_t j = 0; j < *len; ++j) p[j] = rand() % 256;
                break;
            case 3: // UTF-8 字符串
                *len = snprintf((char *)p, MAX_PAYLOAD_LEN, "msg_%d", rand() % 1000);
                break;
            case 4: // 二进制爆破
                *len = 16;
                for (int j = 0; j < 16; ++j) p[j] = 0xFF;
                break;
            case 5: // 逻辑数据（如 JSON 片段）
                *len = snprintf((char *)p, MAX_PAYLOAD_LEN, "{\"key\":\"val%d\"}", rand() % 100);
                break;
            case 6: // 溢出长度
                *len = MAX_PAYLOAD_LEN + 100;
                break;
            case 7: // 编码错误（如 UTF-8 非法序列）
                p[0] = 0xC0; p[1] = 0x00;
                *len = 2;
                break;
            case 8: // 拷贝 topic_name 作为 payload
                *len = strlen(pkt->variable_header.topic_name);
                memcpy(p, pkt->variable_header.topic_name, *len);
                break;
            case 9: // 重复填充已有内容
                if (*len > 0 && *len * 2 < MAX_PAYLOAD_LEN) {
                    memcpy(p + *len, p, *len);
                    *len *= 2;
                }
                break;
        }
    }
}

void mutate_publish_qos(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *qos = &pkt->qos;

        switch (rand() % 10) {
            case 0: *qos = 0; break;               // 合法值
            case 1: *qos = 1; break;               // 合法值
            case 2: *qos = 2; break;               // 合法值
            case 3: *qos = 3; break;               // ⚠️非法值（超过最大合法 QoS）
            case 4: *qos = 255; break;             // 极端非法值
            case 5: *qos = rand() % 256; break;    // 随机字节
            case 6: *qos = (*qos + 1) % 4; break;  // 环形自增
            case 7: *qos = 0xFF & ~(*qos); break;  // 位反转
            case 8: *qos = (rand() % 10 == 0) ? 4 : 2; break; // 极小概率越界
            case 9: *qos = 0xAA; break;            // 特殊模式字节（模拟位错乱）
        }
    }
}


void mutate_publish_dup(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *dup = &pkt->dup;

        switch (rand() % 10) {
            case 0: *dup = 0; break;                 // 合法值: 0 = 非重复
            case 1: *dup = 1; break;                 // 合法值: 1 = 重复消息
            case 2: *dup = (*dup == 0) ? 1 : 0; break; // 切换原始值
            case 3: *dup = 2; break;                 // ⚠️ 非法值
            case 4: *dup = 255; break;               // ⚠️ 极端非法值
            case 5: *dup = rand() % 256; break;      // 随机 byte
            case 6: *dup ^= 0x01; break;             // 位翻转
            case 7: *dup = 0xAA; break;              // 非法模式字节
            case 8: *dup = (rand() % 2) ? 0x00 : 0x01; break; // 伪随机合法变异
            case 9: *dup = (*dup + rand() % 3) & 0xFF; break; // 增量扰动
        }
    }
}

void mutate_publish_retain(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *retain = &pkt->retain;

        switch (rand() % 10) {
            case 0: *retain = 0; break;                 // 合法值：清除 retain
            case 1: *retain = 1; break;                 // 合法值：设置 retain
            case 2: *retain ^= 0x01; break;             // 位翻转
            case 3: *retain = 2; break;                 // ⚠️ 非法值
            case 4: *retain = 255; break;               // ⚠️ 非法边界值
            case 5: *retain = rand() % 256; break;      // 随机 byte
            case 6: *retain = 0xFF; break;              // 非法填充值
            case 7: *retain = (pkt->qos == 0) ? 1 : 0; break; // 合法/非法组合
            case 8: *retain = (*retain + 1) & 0xFF; break;     // 增量扰动
            case 9: *retain = (rand() % 2) * 3; break;   // 合法位移非法组合（0 or 3）
        }
    }
}

#define NUM_MUTATIONS 10

void mutate_unsubscribe_packet_identifier(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint16_t *id = &pkt->variable_header.packet_identifier;

        switch (rand() % NUM_MUTATIONS) {
            case 0: *id = 0x0001; break;                          // 最小合法值
            case 1: *id = 0xFFFF; break;                          // 最大合法值
            case 2: *id = 0x0000; break;                          // 非法值（规范要求不能为 0）
            case 3: *id ^= 0xFFFF; break;                         // 全位翻转
            case 4: *id = ((*id & 0xFF) << 8) | (*id >> 8); break; // 字节序翻转
            case 5: *id = rand() % 0xFFFF; break;                 // 合法随机值
            case 6: *id = 0x1234; break;                          // 固定中间值
            case 7: *id = *id; break;                             // 不变（模拟重发）
            case 8: *id = 0xABCD; break;                          // 特殊测试值
            case 9: *id = 0xFFFF + rand() % 100; break;           // 越界非法值（模拟解析器溢出）
        }


    }
}

// 增加properties字段（添加一个伪随机属性）
void add_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t pkt = pkts[i];
        if (pkt.variable_header.property_len == 0) {
            pkt.variable_header.properties[0] = 0x26;  // User Property 标识符
            pkt.variable_header.properties[1] = 0x00; pkt.variable_header.properties[2] = 0x03;  // key 长度 = 3
            memcpy(&pkt.variable_header.properties[3], "key", 3);
            pkt.variable_header.properties[6] = 0x00; pkt.variable_header.properties[7] = 0x05;  // value 长度 = 5
            memcpy(&pkt.variable_header.properties[8], "value", 5);
            pkt.variable_header.property_len = 13;
        }
    }
}

// 删除properties字段
void delete_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        pkts[i].variable_header.property_len = 0;
        memset(pkts[i].variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

void repeat_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        // 插入两个相同 User Property
        uint8_t entry[] = {
            0x26, 0x00, 0x03, 'k', 'e', 'y',
            0x00, 0x05, 'v', 'a', 'l', 'u', 'e'
        };

        if (sizeof(entry) * 2 < MAX_PROPERTIES_LEN) {
            memcpy(pkt->variable_header.properties, entry, sizeof(entry));
            memcpy(pkt->variable_header.properties + sizeof(entry), entry, sizeof(entry));
            pkt->variable_header.property_len = sizeof(entry) * 2;
        }
    }
}

void mutate_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t *len = &pkt->variable_header.property_len;

        switch (rand() % 10) {
            case 0:  // 清空属性
                *len = 0;
                memset(props, 0, MAX_PROPERTIES_LEN);
                break;
            case 1:  // 插入随机属性字节
                *len = rand() % 20 + 1;
                for (uint32_t j = 0; j < *len; ++j)
                    props[j] = rand() % 256;
                break;
            case 2:  // 插入最大长度属性
                *len = MAX_PROPERTIES_LEN;
                memset(props, 0x41, MAX_PROPERTIES_LEN);  // 全'A'
                break;
            case 3:  // 插入重复 user property
                repeat_unsubscribe_properties(&pkts[i], 1);
                break;
            case 4:  // 插入非法属性标识符
                props[0] = 0xFF;  // 未定义
                *len = 1;
                break;
            case 5:  // 修改 length，但不写入属性内容
                *len = 10;
                break;
            case 6:  // 写入合法 user property
                add_unsubscribe_properties(&pkts[i], 1);
                break;
            case 7:  // 写入乱码属性内容
                *len = 8;
                for (int j = 0; j < 8; ++j)
                    props[j] = 0x80 + rand() % 128;  // 非 UTF-8 编码字符
                break;
            case 8:  // 增加随机填充在尾部
                if (*len + 4 < MAX_PROPERTIES_LEN) {
                    memset(props + *len, 0xCC, 4);
                    *len += 4;
                }
                break;
            case 9:  // 整个字段溢出写入
                *len = MAX_PROPERTIES_LEN + 10;
                memset(props, 0xFF, MAX_PROPERTIES_LEN);  // 实际数据长度仍安全
                break;
        }
    }
}

void repeat_unsubscribe_topic_filters(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        if (pkt->payload.topic_count < MAX_TOPIC_FILTERS) {
            strcpy(pkt->payload.topic_filters[pkt->payload.topic_count],
                   pkt->payload.topic_filters[0]);  // 复制第一个 filter
            pkt->payload.topic_count += 1;
        }
    }
}


void mutate_unsubscribe_topic_filters(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t count = pkt->payload.topic_count;

        int op = rand() % 10;
        switch (op) {
            case 0:  // 清空所有 topic filter（非法）
                pkt->payload.topic_count = 0;
                break;
            case 1:  // 插入空字符串（非法 filter）
                if (count < MAX_TOPIC_FILTERS) {
                    pkt->payload.topic_filters[count][0] = '\0';
                    pkt->payload.topic_count++;
                }
                break;
            case 2:  // 插入过长字符串
                if (count < MAX_TOPIC_FILTERS) {
                    memset(pkt->payload.topic_filters[count], 'A', MAX_TOPIC_LEN - 1);
                    pkt->payload.topic_filters[count][MAX_TOPIC_LEN - 1] = '\0';
                    pkt->payload.topic_count++;
                }
                break;
            case 3:  // 插入非法字符（如控制符）
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "\x01\x02#");
                    pkt->payload.topic_count++;
                }
                break;
            case 4:  // 插入合法 filter（如通配符）
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "sensor/#");
                    pkt->payload.topic_count++;
                }
                break;
            case 5:  // 插入重复 filter
                repeat_unsubscribe_topic_filters(&pkts[i], 1);
                break;
            case 6:  // 替换已有 filter 为乱码
                if (count > 0) {
                    int idx = rand() % count;
                    for (int j = 0; j < 10; ++j)
                        pkt->payload.topic_filters[idx][j] = rand() % 256;
                    pkt->payload.topic_filters[idx][10] = '\0';
                }
                break;
            case 7:  // 设置 topic_count 超出实际个数（非法）
                pkt->payload.topic_count = MAX_TOPIC_FILTERS + 10;
                break;
            case 8:  // 插入 UTF-8 非法字符串
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "\xC0\xC0");
                    pkt->payload.topic_count++;
                }
                break;
            case 9:  // 插入 filter 含有非法通配符组合
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "foo/#/bar");  // 非法组合
                    pkt->payload.topic_count++;
                }
                break;
        }
    }
}




void add_auth_reason_code(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        if (pkt->fixed_header.remaining_length == 0) {
            pkt->variable_header.reason_code = 0x00;  // 默认合法值
            pkt->fixed_header.remaining_length += 1;
        }
    }
}

void delete_auth_reason_code(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        if (pkt->fixed_header.remaining_length >= 1) {
            pkt->variable_header.reason_code = 0;  // 清除值
            pkt->fixed_header.remaining_length -= 1;
        }
    }
}


void mutate_auth_reason_code(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];

        // 只有当 reason_code 字段存在时才变异
        if (pkt->fixed_header.remaining_length < 1) continue;

        uint8_t *rc = &pkt->variable_header.reason_code;
        uint8_t mutation_type = rand() % 10;

        switch (mutation_type) {
            case 0: *rc = 0x00; break;                  // 合法值：Success
            case 1: *rc = 0x18; break;                  // 合法值：Continue authentication
            case 2: *rc = 0x19; break;                  // 合法值：Re-authenticate
            case 3: *rc = 0xFF; break;                  // 非法最大值
            case 4: *rc = 0x7F; break;                  // 边界值
            case 5: *rc = 0x80; break;                  // 错误起始边界
            case 6: *rc = rand() % 256; break;          // 随机 byte
            case 7: *rc = 0x01; break;                  // 非 AUTH 合法 reason code
            case 8: *rc = 0xFE; break;                  // 接近最大值
            case 9: *rc = 0x10; break;                  // 无实际含义的合法值
        }
    }
}

void add_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];

        if (pkt->variable_header.property_len == 0) {
            pkt->variable_header.properties[0] = 0x15;  // Authentication Method identifier
            pkt->variable_header.properties[1] = 0x00;  // Empty string length MSB
            pkt->variable_header.properties[2] = 0x00;  // Empty string length LSB
            pkt->variable_header.property_len = 3;

            pkt->fixed_header.remaining_length += 3;
        }
    }
}


void repeat_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];

        if (pkt->variable_header.property_len + 10 >= MAX_PROPERTIES_LEN) continue;

        // User Property: Identifier 0x26, Key=“x”, Value=“y”
        uint8_t *p = pkt->variable_header.properties + pkt->variable_header.property_len;
        *p++ = 0x26;
        *p++ = 0x00; *p++ = 0x01; *p++ = 'x';  // key
        *p++ = 0x00; *p++ = 0x01; *p++ = 'y';  // value

        pkt->variable_header.property_len += 7;
        pkt->fixed_header.remaining_length += 7;
    }
}

void mutate_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        uint32_t *len = &pkt->variable_header.property_len;
        uint8_t *p = pkt->variable_header.properties;

        uint8_t choice = rand() % 10;
        switch (choice) {
            case 0: // 插入 Authentication Method 空字符串
                p[0] = 0x15; p[1] = 0x00; p[2] = 0x00; *len = 3; break;
            case 1: // 插入 Authentication Method "PLAIN"
                p[0] = 0x15; p[1] = 0x00; p[2] = 0x05; memcpy(p+3, "PLAIN", 5); *len = 8; break;
            case 2: // 插入 Authentication Data 空数据
                p[0] = 0x16; p[1] = 0x00; p[2] = 0x00; *len = 3; break;
            case 3: // 插入非法属性 ID（超出 MQTT 定义）
                p[0] = 0xFF; p[1] = 0x00; p[2] = 0x00; *len = 3; break;
            case 4: // 属性长度设为 MAX_PROPERTIES_LEN，填满随机
                *len = MAX_PROPERTIES_LEN; for (int j = 0; j < MAX_PROPERTIES_LEN; j++) p[j] = rand() % 256; break;
            case 5: // 插入 User Property (“x”,"y")
                p[0] = 0x26; p[1] = 0x00; p[2] = 0x01; p[3] = 'x'; p[4] = 0x00; p[5] = 0x01; p[6] = 'y'; *len = 7; break;
            case 6: // 插入多个合法字段（Method + Data）
                p[0] = 0x15; p[1] = 0x00; p[2] = 0x02; p[3] = 'A'; p[4] = 'B';
                p[5] = 0x16; p[6] = 0x00; p[7] = 0x03; p[8] = 1; p[9] = 2; p[10] = 3;
                *len = 11; break;
            case 7: // 超长长度字段（声明长度超出实际）
                p[0] = 0x15; p[1] = 0xFF; p[2] = 0xFF; *len = 3; break;
            case 8: // 空内容但声明长度 > 0
                *len = 5; memset(p, 0, 5); break;
            case 9: // 插入 UTF-8 不合法字符
                p[0] = 0x15; p[1] = 0x00; p[2] = 0x01; p[3] = 0xFF; *len = 4; break;
        }

        // 更新 fixed_header 长度
        pkt->fixed_header.remaining_length = 1 + *len;  // +1 for reason_code
    }
}


// mutator 函数指针类型
typedef void (*connect_mutator_fn)(mqtt_connect_packet_t *pkt, int num_packets);
typedef void (*subscribe_mutator_fn)(mqtt_subscribe_packet_t *pkt, int num_packets);
typedef void (*publish_mutator_fn)(mqtt_publish_packet_t *pkt, int num_packets);
typedef void (*auth_mutator_fn)(mqtt_auth_packet_t *pkt, int num_packets);
typedef void (*unsubscribe_mutator_fn)(mqtt_unsubscribe_packet_t *pkt, int num_packets);

// mutator dispatch 列表 23
connect_mutator_fn connect_mutators[] = {
    mutate_connect_flags,
    mutate_connect_keep_alive,
    // mutate_property_len,
    mutate_connect_properties,
    mutate_connect_client_id,
    // mutate_will_property_len,
    mutate_connect_will_properties,
    mutate_connect_will_topic,
    mutate_connect_will_payload,
    // mutate_will_payload_len,
    mutate_connect_user_name,
    mutate_connect_password,
    // mutate_password_len,
    // add_property_len,
    add_connect_properties,
    add_connect_client_id,
    // add_will_property_len,
    add_connect_will_properties,
    add_connect_will_topic,
    add_connect_will_payload,
    // add_will_payload_len,
    add_connect_user_name,
    add_connect_password,
    // add_password_len,
    // delete_property_len,
    delete_connect_properties,
    delete_connect_client_id,
    // delete_will_property_len,
    delete_connect_will_properties,
    delete_connect_will_topic,
    delete_connect_will_payload,
    // delete_will_payload_len,
    delete_connect_user_name,
    delete_connect_password,
    // delete_password_len
};
// subscribe mutator 列表 9
subscribe_mutator_fn subscribe_mutators[] = {
    mutate_subscribe_packet_identifier,
    mutate_subscribe_properties,
    add_subscribe_properties,
    delete_subscribe_properties,
    repeat_subscribe_properties,
    mutate_subscribe_topic_filter,
    repeat_subscribe_topic_filter,
    mutate_subscribe_qos,
    mutate_subscribe_topic_count
};
// publish mutator 列表 15
publish_mutator_fn publish_mutators[] = {
    mutate_publish_packet_identifier,
    add_publish_packet_identifier,
    delete_publish_packet_identifier,
    mutate_publish_topic_name,
    add_publish_topic_name,
    delete_publish_topic_name,
    mutate_publish_properties,
    add_publish_properties,
    delete_publish_properties,
    repeat_publish_properties,
    mutate_publish_payload,
    add_publish_payload,
    delete_publish_payload,
    mutate_publish_qos,
    mutate_publish_dup,
    mutate_publish_retain
    
};
// unsubscribe mutator 列表 7
unsubscribe_mutator_fn unsubscribe_mutators[] = {
    mutate_unsubscribe_packet_identifier,
    add_unsubscribe_properties,
    delete_unsubscribe_properties,
    mutate_unsubscribe_properties,
    repeat_unsubscribe_properties,
    mutate_unsubscribe_topic_filters,
    repeat_unsubscribe_topic_filters
};
// auth mutator 列表 6
auth_mutator_fn auth_mutators[] = {
    mutate_auth_reason_code,
    add_auth_reason_code,
    delete_auth_reason_code,
    mutate_auth_properties,
    add_auth_properties,
    // delete_auth_properties,
    repeat_auth_properties
};

#define CONNECT_MUTATOR_COUNT (sizeof(connect_mutators) / sizeof(connect_mutator_fn))
#define SUBSCRIBE_MUTATOR_COUNT (sizeof(subscribe_mutators) / sizeof(subscribe_mutator_fn))
#define PUBLISH_MUTATOR_COUNT (sizeof(publish_mutators) / sizeof(publish_mutator_fn))
#define UNSUBSCRIBE_MUTATOR_COUNT (sizeof(unsubscribe_mutators) / sizeof(unsubscribe_mutator_fn))
#define AUTH_MUTATOR_COUNT (sizeof(auth_mutators) / sizeof(auth_mutator_fn))

// 主调度函数：从 mutators 中随机选择一个进行变异
void dispatch_connect_mutation(mqtt_connect_packet_t *pkt, int num_packets) {
    if (pkt == NULL) return;
    int index = rand() % CONNECT_MUTATOR_COUNT;
    // printf("[DISPATCH] Applying mutator #%d\n", index);
    connect_mutators[index](pkt, 1); 
}

void dispatch_subscribe_mutation(mqtt_subscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = rand() % SUBSCRIBE_MUTATOR_COUNT;
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  subscribe_mutators[index](pkt, 1);
}

void dispatch_publish_mutation(mqtt_publish_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = rand() % PUBLISH_MUTATOR_COUNT;
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  publish_mutators[index](pkt, 1);
}

void dispatch_unsubscribe_mutation(mqtt_unsubscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = rand() % UNSUBSCRIBE_MUTATOR_COUNT;
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  unsubscribe_mutators[index](pkt, 1);
}
void dispatch_auth_mutation(mqtt_auth_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = rand() % AUTH_MUTATOR_COUNT;
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  auth_mutators[index](pkt, 1);
}

// 可选：多轮调度以提高多样性
void dispatch_mqtt_multiple_mutations(mqtt_packet_t *pkt, int num_packets, int rounds) {
    for (int i = 0; i < rounds; ++i) {
      // printf("[DISPATCH] Applying mutator #%d\n", index);
      int mutate_index = rand() % num_packets;

      //connect类型mutator
      if(pkt[mutate_index].type == TYPE_CONNECT){
        dispatch_connect_mutation(&pkt[mutate_index].connect, 1);
      }else if(pkt[mutate_index].type == TYPE_SUBSCRIBE){
        // subscribe类型mutator
        dispatch_subscribe_mutation(&pkt[mutate_index].subscribe, 1);
      }else if(pkt[mutate_index].type == TYPE_PUBLISH){
        // publish类型mutator
        // printf("[PUBLISH]mutating packet #%d\n", mutate_index);
        dispatch_publish_mutation(&pkt[mutate_index].publish, 1);
      }else if(pkt[mutate_index].type == TYPE_UNSUBSCRIBE){
        // unsubscribe类型mutator
        dispatch_unsubscribe_mutation(&pkt[mutate_index].unsubscribe, 1);
      }else if(pkt[mutate_index].type == TYPE_AUTH){
        // auth类型mutator
        dispatch_auth_mutation(&pkt[mutate_index].auth, 1); 
      }
    }
}
