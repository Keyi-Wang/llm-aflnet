#include "mqtt.h"
#define USERNAME_FLAG   0x80
#define PASSWORD_FLAG   0x40
#define WILL_RETAIN     0x20
#define WILL_QOS_MASK   0x18
#define WILL_QOS_SHIFT  3
#define WILL_FLAG       0x04
#define CLEAN_START     0x02
#define RESERVED        0x01

static int pick_weighted(const int *w, int n) {
    int sum = 0;
    for (int i = 0; i < n; ++i) sum += w[i];
    if (sum <= 0) return 0;
    int r = rand() % sum;
    for (int i = 0; i < n; ++i) {
        if (r < w[i]) return i;
        r -= w[i];
    }
    return n - 1;
}

void mutate_connect_flags(mqtt_connect_packet_t* pkts, int num_pkts) {
    int total_mutations = 0;

    for (int i = 0; i < num_pkts; i++) {
        uint8_t original = pkts[i].variable_header.connect_flags;
        uint8_t mutated = original;

        int weights[7] = {70, 0, 0, 0, 0, 0, 0}; 
        int mut_type = pick_weighted(weights, 7);

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

        int weights[7] = {20, 20, 20, 20, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);

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
    if (!packets) return;

    // 规范里的标识码（请按你项目的常量替换）
    #define PID_SES_EXP   0x11  // Session Expiry Interval (4B)
    #define PID_RCV_MAX   0x12  // Receive Maximum (2B)
    #define PID_MAX_PKT   0x13  // Maximum Packet Size (4B)
    #define PID_TA_MAX    0x22  // Topic Alias Maximum (2B)  // 有些代码里写 0x15，请确认
    #define PID_REQ_RESP  0x17  // Request Response Information (1B)
    #define PID_REQ_PROB  0x19  // Request Problem Information (1B)
    #define PID_USER_PROP 0x26  // User Property (UTF-8 pair)
    #define PID_AUTH_METH 0x15  // Authentication Method (UTF-8 string)
    #define PID_AUTH_DATA 0x16  // Authentication Data (Binary Data)

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (pkt->variable_header.protocol_level != 5) {
            pkt->variable_header.property_len = 0;
            continue;
        }

        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

        // 工具宏：边界 & 写入
        #define ENSURE(n) do { if (pos + (uint32_t)(n) > (uint32_t)MAX_PROPERTIES_LEN) goto done; } while (0)
        #define PUT8(v)   do { ENSURE(1); buf[pos++] = (uint8_t)(v); } while (0)
        #define PUT16(v)  do { ENSURE(2); buf[pos++] = (uint8_t)(((v)>>8)&0xFF); buf[pos++] = (uint8_t)((v)&0xFF); } while (0)
        #define PUT32(v)  do { ENSURE(4); buf[pos++] = (uint8_t)(((v)>>24)&0xFF); buf[pos++] = (uint8_t)(((v)>>16)&0xFF); buf[pos++] = (uint8_t)(((v)>>8)&0xFF); buf[pos++] = (uint8_t)((v)&0xFF); } while (0)
        #define PUT_UTF8(s, maxs) do { \
            const char *S__ = (s); size_t N__ = S__ ? strnlen(S__, (maxs)) : 0; \
            if (N__ > 65535) N__ = 65535; ENSURE(2 + N__); PUT16((uint16_t)N__); \
            if (N__) { memcpy(buf + pos, S__, N__); pos += (uint32_t)N__; } \
        } while (0)
        #define PUT_BIN(p, n) do { \
            uint32_t L__ = (uint32_t)(n); if (L__ > 65535) L__ = 65535; ENSURE(2 + L__); \
            PUT16((uint16_t)L__); if (L__) { memcpy(buf + pos, (p), L__); pos += L__; } \
        } while (0)

        // “只出现一次”的属性使用防重标记
        int used_ses=0, used_rcv=0, used_max=0, used_ta=0, used_rr=0, used_rp=0, used_am=0, used_ad=0;

        // 生成 1~6 个属性
        int num_props = 1 + rand() % 6;
        for (int n = 0; n < num_props; ++n) {
            int pick = rand() % 9;
            switch (pick) {
                case 0: if (!used_ses) { PUT8(PID_SES_EXP); PUT32((uint32_t)(rand()%86400)); used_ses=1; } break;
                case 1: if (!used_rcv) { PUT8(PID_RCV_MAX); PUT16((uint16_t)(1 + rand()%1024)); used_rcv=1; } break;
                case 2: if (!used_max) { PUT8(PID_MAX_PKT); PUT32((uint32_t)(512 + rand()%65536)); used_max=1; } break;
                case 3: if (!used_ta ) { PUT8(PID_TA_MAX ); PUT16((uint16_t)(1 + rand()%100)); used_ta =1; } break;
                case 4: if (!used_rr ) { PUT8(PID_REQ_RESP); PUT8((uint8_t)(rand()%2)); used_rr=1; } break;
                case 5: if (!used_rp ) { PUT8(PID_REQ_PROB); PUT8((uint8_t)(rand()%2)); used_rp=1; } break;
                case 6: { // User Property (可重复)
                    PUT8(PID_USER_PROP);
                    PUT_UTF8("key", 32);
                    PUT_UTF8("val", 32);
                    break;
                }
                case 7: if (!used_am) { // Authentication Method (UTF-8)
                    PUT8(PID_AUTH_METH);
                    PUT_UTF8("PLAIN", 64);
                    used_am=1;
                    break;
                }
                case 8: if (!used_ad) { // Authentication Data (Binary)
                    uint8_t tmp[16]; int L = 4 + rand()%8;
                    for (int t=0;t<L;++t) tmp[t]=(uint8_t)rand();
                    PUT8(PID_AUTH_DATA);
                    PUT_BIN(tmp, L);
                    used_ad=1;
                    break;
                }
            }
        }

    done:
        pkt->variable_header.property_len = pos;

        #undef ENSURE
        #undef PUT8
        #undef PUT16
        #undef PUT32
        #undef PUT_UTF8
        #undef PUT_BIN
    }

    #undef PID_SES_EXP
    #undef PID_RCV_MAX
    #undef PID_MAX_PKT
    #undef PID_TA_MAX
    #undef PID_REQ_RESP
    #undef PID_REQ_PROB
    #undef PID_USER_PROP
    #undef PID_AUTH_METH
    #undef PID_AUTH_DATA
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
        int weights[8] = {0, 70, 0, 0, 0, 0, 0, 0}; 
        int mut_type = pick_weighted(weights, 8);

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
    /* Will Properties 标识符 */
    #define PID_PFI     0x01  /* Payload Format Indicator: 1 byte (0 or 1) */
    #define PID_MEI     0x02  /* Message Expiry Interval: 4 bytes (uint32) */
    #define PID_CT      0x03  /* Content Type: UTF-8 string */
    #define PID_RT      0x08  /* Response Topic: UTF-8 string */
    #define PID_CD      0x09  /* Correlation Data: Binary Data */
    #define PID_WDI     0x18  /* Will Delay Interval: 4 bytes (uint32) */
    #define PID_UP      0x26  /* User Property: UTF-8 string pair (Key, Value) */

    for (int i = 0; i < num_packets; i++) {
        mqtt_connect_packet_t *pkt = &packets[i];

        uint8_t *buf = pkt->payload.will_properties;
        uint32_t pos = 0;

        /* 安全写入工具 */
        #define ENSURE(n) do { if (pos + (uint32_t)(n) > (uint32_t)MAX_PROPERTIES_LEN) goto finish; } while (0)
        #define PUT8(v)   do { ENSURE(1); buf[pos++] = (uint8_t)(v); } while (0)
        #define PUT16(v)  do { ENSURE(2); buf[pos++] = (uint8_t)(((v)>>8)&0xFF); buf[pos++] = (uint8_t)((v)&0xFF); } while (0)
        #define PUT32(v)  do { ENSURE(4); buf[pos++] = (uint8_t)(((v)>>24)&0xFF); buf[pos++] = (uint8_t)(((v)>>16)&0xFF); buf[pos++] = (uint8_t)(((v)>>8)&0xFF); buf[pos++] = (uint8_t)((v)&0xFF); } while (0)
        #define PUT_UTF8_LIT(s) do { \
            const char *S__ = (s); size_t N__ = S__ ? strlen(S__) : 0; \
            if (N__ > 65535) N__ = 65535; ENSURE(2 + N__); \
            PUT16((uint16_t)N__); if (N__) { memcpy(buf + pos, S__, N__); pos += (uint32_t)N__; } \
        } while (0)
        #define PUT_BIN_RAND(minLen, maxLen) do { \
            int L__ = (minLen) + rand() % ((maxLen) - (minLen) + 1); \
            if (L__ > 65535) L__ = 65535; ENSURE(2 + L__); \
            PUT16((uint16_t)L__); \
            for (int __k = 0; __k < L__; ++__k) buf[pos + __k] = (uint8_t)rand(); \
            pos += (uint32_t)L__; \
        } while (0)

        int strategy = rand() % 6;
        switch (strategy) {
            case 0: /* 仅 PFI=1（UTF-8 文本 Will Payload） */
                PUT8(PID_PFI); PUT8(1);
                break;
            case 1: /* 仅 Message Expiry Interval（0~3600 秒） */
                PUT8(PID_MEI); PUT32((uint32_t)(rand() % 3601));
                break;
            case 2: /* 仅 Will Delay Interval（0~600 秒） */
                PUT8(PID_WDI); PUT32((uint32_t)(rand() % 601));
                break;
            case 3: /* Content Type: text/plain */
                PUT8(PID_CT); PUT_UTF8_LIT("text/plain");
                break;
            case 4: /* Response Topic: reply/topic */
                PUT8(PID_RT); PUT_UTF8_LIT("reply/topic");
                break;
            case 5: /* Correlation Data: 8~24 随机字节 */
                PUT8(PID_CD); PUT_BIN_RAND(8, 24);
                break;
        }

        /* 追加 0~2 个 User Property（可重复） */
        {
            static const char *keys[] = {"source", "priority", "note", "device"};
            static const char *vals[] = {"sensor1", "high", "ok", "edge"};
            int upn = rand() % 3; /* 0..2 */
            for (int t = 0; t < upn; ++t) {
                PUT8(PID_UP);
                PUT_UTF8_LIT(keys[rand() % 4]);
                PUT_UTF8_LIT(vals[rand() % 4]);
            }
        }

finish:
        /* 兜底：若因为边界等原因未能写入任何属性，保证至少有 PFI=0 */
        if (pos == 0) {
            ENSURE(2);
            PUT8(PID_PFI); PUT8(0);
        }

        pkt->payload.will_property_len = pos;

        #undef ENSURE
        #undef PUT8
        #undef PUT16
        #undef PUT32
        #undef PUT_UTF8_LIT
        #undef PUT_BIN_RAND
    }

    #undef PID_PFI
    #undef PID_MEI
    #undef PID_CT
    #undef PID_RT
    #undef PID_CD
    #undef PID_WDI
    #undef PID_UP
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

        int weights[8] = {40, 40, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 8);

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

        int weights[6] = {0, 50, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 6);
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

        int weights[7] = {70, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);
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

        int weights[7] = {70, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);

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

        int weights[8] = {70, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 8);

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
        int weights[10] = {0, 40, 40, 0, 0, 0, 40, 40, 40, 40}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
/* ===== 工具：VarInt 编码、UTF-8/边界写入 ===== */
static inline size_t write_varint(uint8_t *dst, uint32_t v) {
    size_t n = 0;
    do {
        uint8_t byte = v % 128;
        v /= 128;
        if (v > 0) byte |= 0x80;
        dst[n++] = byte;
    } while (v > 0 && n < 4);
    return n; /* 1..4 */
}

static inline int ensure_space(uint32_t pos, uint32_t need, uint32_t limit) {
    return (pos + need <= limit);
}

static inline void put16(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)((v >> 8) & 0xFF);
    b[1] = (uint8_t)(v & 0xFF);
}

/* 计算一条已编码的 User Property 从 props[pos] 开始的总字节数；非法返回 0 */
static uint32_t peek_user_property_len(const uint8_t *props, uint32_t plen, uint32_t pos) {
    if (pos >= plen || props[pos] != 0x26) return 0;
    uint32_t r = pos + 1;
    if (r + 2 > plen) return 0;
    uint16_t klen = (props[r] << 8) | props[r+1]; r += 2;
    if (r + klen + 2 > plen) return 0;
    r += klen;
    uint16_t vlen = (props[r] << 8) | props[r+1]; r += 2;
    if (r + vlen > plen) return 0;
    r += vlen;
    return r - pos; /* 总长度 */
}

/* ===== 仅生成合法变异：SUBSCRIBE Properties ===== */

void mutate_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 策略：重建一个新的、合法的属性区 */
        /* 50% 是否带 Subscription Identifier（值范围 1..16383，足够且短编码） */
        if (rand() % 2) {
            uint8_t tmp[4];
            uint32_t sid = 1u + (rand() % 16383u);
            if (!ensure_space(pos, 1, MAX_PROPERTIES_LEN)) goto done;
            props[pos++] = 0x0B; /* Subscription Identifier */
            size_t vn = write_varint(tmp, sid);
            if (!ensure_space(pos, (uint32_t)vn, MAX_PROPERTIES_LEN)) goto done;
            memcpy(props + pos, tmp, vn); pos += (uint32_t)vn;
        }

        /* 追加 0..3 个 User Property（Key/Value 为合法 UTF-8） */
        static const char *keys[] = {"source", "priority", "note", "device"};
        static const char *vals[] = {"sensor1", "high", "ok", "edge"};
        int upn = rand() % 4; /* 0..3 */
        for (int t = 0; t < upn; ++t) {
            const char *k = keys[rand() % 4];
            const char *v = vals[rand() % 4];
            uint16_t klen = (uint16_t)strlen(k);
            uint16_t vlen = (uint16_t)strlen(v);

            uint32_t need = 1 + 2 + klen + 2 + vlen;
            if (!ensure_space(pos, need, MAX_PROPERTIES_LEN)) break;

            props[pos++] = 0x26;                /* User Property */
            put16(props + pos, klen); pos += 2; memcpy(props + pos, k, klen); pos += klen;
            put16(props + pos, vlen); pos += 2; memcpy(props + pos, v, vlen); pos += vlen;
        }

    done:
        pkt->variable_header.property_len = pos; /* 字节长度 */
    }
}

void add_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        /* 优先：若尚无 Subscription Identifier，则添加一个（合法 VarInt，短编码） */
        int has_sid = 0;
        for (uint32_t j = 0; j < plen; ) {
            if (p[j] == 0x0B) { has_sid = 1; break; }
            else if (p[j] == 0x26) {
                uint32_t step = peek_user_property_len(p, plen, j);
                if (step == 0) { has_sid = 1; break; } /* 结构异常时不再操作 */
                j += step;
            } else {
                has_sid = 1; break; /* 非法/未知结构，避免再写导致不一致 */
            }
        }

        if (!has_sid) {
            uint8_t tmp[4]; uint32_t sid = 1u + (rand() % 16383u);
            size_t vn = write_varint(tmp, sid);
            if (ensure_space(plen, 1 + (uint32_t)vn, MAX_PROPERTIES_LEN)) {
                p[plen++] = 0x0B;
                memcpy(p + plen, tmp, vn); plen += (uint32_t)vn;
                pkt->variable_header.property_len = plen;
                continue;
            }
        }

        /* 其次：追加一条合法 User Property（不破坏现有结构） */
        {
            const char *k = "foo";
            const char *v = "bar";
            uint16_t klen = (uint16_t)strlen(k), vlen = (uint16_t)strlen(v);
            uint32_t need = 1 + 2 + klen + 2 + vlen;

            if (ensure_space(plen, need, MAX_PROPERTIES_LEN)) {
                p[plen++] = 0x26;
                put16(p + plen, klen); plen += 2; memcpy(p + plen, k, klen); plen += klen;
                put16(p + plen, vlen); plen += 2; memcpy(p + plen, v, vlen); plen += vlen;
                pkt->variable_header.property_len = plen;
            }
        }
    }
}

void delete_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;
    for (size_t i = 0; i < num_subs; ++i) {
        subs[i].variable_header.property_len = 0;
        memset(subs[i].variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

/* 合法“重复”：只复制一条现有的 User Property（若存在），不复制 Subscription Identifier */
void repeat_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        /* 找到第一条可完整解析的 User Property */
        uint32_t up_pos = 0, up_len = 0, j = 0;
        while (j < plen) {
            if (p[j] == 0x26) {
                uint32_t step = peek_user_property_len(p, plen, j);
                if (step == 0) break; /* 结构异常，停止 */
                up_pos = j; up_len = step; break;
            } else if (p[j] == 0x0B) {
                /* 跳过 Subscription Identifier（VarInt） */
                uint32_t k = j + 1, mul = 1, count = 0;
                /* 解析 VarInt 长度以便跳过（最多 4 字节） */
                while (k < plen && count < 4) {
                    uint8_t b = p[k++]; count++;
                    if (!(b & 0x80)) break;
                }
                j = k;
            } else {
                /* 遇到未知/异常，放弃重复以避免破坏结构 */
                up_len = 0; break;
            }
        }

        if (up_len == 0) continue; /* 没有可重复的 UP */

        /* 追加一份相同的 User Property */
        if (ensure_space(plen, up_len, MAX_PROPERTIES_LEN)) {
            memcpy(p + plen, p + up_pos, up_len);
            pkt->variable_header.property_len = plen + up_len;
        }
    }
}


void mutate_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    // 一些“确定合法”的模板
    static const char *legal_wildcards[] = {
        "#",                 // 匹配所有主题
        "+",                 // 单层通配
        "+/+",               // 两层单层通配
        "devices/+/status",  // 中间层使用 '+'
        "sensor/#"           // 末尾使用 '#'
    };
    enum { LEGAL_WC_COUNT = (int)(sizeof(legal_wildcards)/sizeof(legal_wildcards[0])) };

    // 合法的主题字符（不含通配符；通配符由策略控制加入）
    static const char legal_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            char *filter = pkt->payload.topic_filters[j].topic_filter;

            // 6 种“保证合法”的策略
            int weights[6] = {20, 20, 20, 20, 10, 10};
            int strategy = pick_weighted(weights, 6);

            // 小工具：安全追加字符/字符串（保证不越界、不丢 '\0'）
            int pos = 0;
            #define APPEND_CHAR(ch) do { \
                if (pos < MAX_TOPIC_LEN - 1) { filter[pos++] = (char)(ch); filter[pos] = '\0'; } \
            } while (0)
            #define APPEND_STR(sz) do { \
                const char *___s = (sz); \
                while (*___s && pos < MAX_TOPIC_LEN - 1) { filter[pos++] = *___s++; } \
                filter[pos] = '\0'; \
            } while (0)
            #define APPEND_LEVEL_FROM_SET() do { \
                int lvl_len = 1 + rand() % 8; \
                for (int __t = 0; __t < lvl_len && pos < MAX_TOPIC_LEN - 1; ++__t) { \
                    APPEND_CHAR( legal_chars[rand() % (int)(sizeof(legal_chars) - 1)] ); \
                } \
            } while (0)
            #define APPEND_SLASH_IF_NEEDED() do { \
                if (pos > 0 && filter[pos-1] != '/' && pos < MAX_TOPIC_LEN - 1) { APPEND_CHAR('/'); } \
            } while (0)

            filter[0] = '\0'; // 先清空

            switch (strategy) {
                case 0: { // 直接使用一条“已知合法”的模板
                    APPEND_STR(legal_wildcards[rand() % LEGAL_WC_COUNT]);
                    break;
                }

                case 1: { // 纯静态合法路径：1~4 层，每层由合法字符组成
                    int levels = 1 + rand() % 4;
                    for (int l = 0; l < levels; ++l) {
                        if (l) APPEND_CHAR('/');
                        APPEND_LEVEL_FROM_SET();
                    }
                    if (pos == 0) { APPEND_CHAR('a'); } // 保证非空
                    break;
                }

                case 2: { // 含 '+' 的合法过滤器：2~4 层，随机 1~2 层使用 '+'
                    int levels = 2 + rand() % 3;           // 2..4 层
                    int plus_cnt = 1 + rand() % 2;         // 1..2 个 '+'
                    // 随机选择放置 '+' 的层索引（不重复）
                    int plus_at[2] = {-1, -1};
                    for (int p = 0; p < plus_cnt; ++p) {
                        int idx;
                        do { idx = rand() % levels; } while ((p == 1 && idx == plus_at[0]));
                        plus_at[p] = idx;
                    }
                    for (int l = 0; l < levels; ++l) {
                        if (l) APPEND_CHAR('/');
                        if (l == plus_at[0] || l == plus_at[1]) {
                            APPEND_CHAR('+');           // 单层通配符
                        } else {
                            APPEND_LEVEL_FROM_SET();
                        }
                    }
                    break;
                }

                case 3: { // 末尾 '#': 0~3 个静态层 + "/#" 或仅 "#"
                    int levels = rand() % 4; // 0..3
                    if (levels == 0) {
                        APPEND_CHAR('#');               // 单独一个 '#'
                    } else {
                        for (int l = 0; l < levels; ++l) {
                            if (l) APPEND_CHAR('/');
                            APPEND_LEVEL_FROM_SET();
                        }
                        APPEND_CHAR('/'); APPEND_CHAR('#'); // 末尾 "#"
                    }
                    break;
                }

                case 4: { // 构造“比较长但合法”的过滤器（接近上限）
                    // 用 "aaaa/aaaa/..." 直到接近 MAX_TOPIC_LEN
                    while (pos < MAX_TOPIC_LEN - 1) {
                        int left = (MAX_TOPIC_LEN - 1) - pos;
                        if (left <= 5) { // 留点空间，避免最后一个字符是 '/'
                            break;
                        }
                        if (pos) APPEND_CHAR('/');
                        int seg = 4 + rand() % 8; // 每段 4..11 个字母
                        for (int s = 0; s < seg && pos < MAX_TOPIC_LEN - 1; ++s) APPEND_CHAR('a' + (rand() % 26));
                    }
                    // 如果末尾是 '/'，删掉它
                    if (pos > 0 && filter[pos-1] == '/') { filter[--pos] = '\0'; }
                    if (pos == 0) { APPEND_CHAR('a'); }     // 保底
                    break;
                }

                case 5: { // 拷贝前一个合法 filter（若 j==0 则退化为 "sensor/#"）
                    if (j > 0) {
                        strncpy(filter, pkt->payload.topic_filters[j - 1].topic_filter, MAX_TOPIC_LEN - 1);
                        filter[MAX_TOPIC_LEN - 1] = '\0';
                    } else {
                        APPEND_STR("sensor/#");
                    }
                    break;
                }
            }

            // 双重保险：不允许空、也不允许超长
            if (filter[0] == '\0') { strncpy(filter, "a", MAX_TOPIC_LEN - 1); filter[MAX_TOPIC_LEN - 1] = '\0'; }
            filter[MAX_TOPIC_LEN - 1] = '\0';
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
            pkt->payload.topic_filters[new_index].qos = rand() % 3;  // 可包含非法值测试解析器
        }

        pkt->payload.topic_count++;
    }
}

void mutate_subscribe_qos(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            uint8_t *qos = &pkt->payload.topic_filters[j].qos;
            int weights[10] = {40, 40, 40, 0, 0, 0, 0, 0, 0, 40}; 
            int strategy = pick_weighted(weights, 10);
            switch (strategy) {
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
        int weights[10] = {0, 40, 0, 40, 40, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = { 0, 0, 0, 0, 0, 0, 0, 50, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = {0, 40, 40, 40, 0, 40, 40, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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

/* ===== PUBLISH Properties: helpers ===== */
static inline int pp_ensure(uint32_t pos, uint32_t need, uint32_t limit) {
    return (pos + need <= limit);
}
static inline void pp_put16(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)((v >> 8) & 0xFF);
    b[1] = (uint8_t)(v & 0xFF);
}
static inline void pp_put32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)((v >> 24) & 0xFF);
    b[1] = (uint8_t)((v >> 16) & 0xFF);
    b[2] = (uint8_t)((v >> 8) & 0xFF);
    b[3] = (uint8_t)(v & 0xFF);
}

/* 计算从 props[pos] 开始的一条 User Property 的总长度；非法返回 0 */
static uint32_t peek_publish_user_property_len(const uint8_t *props, uint32_t plen, uint32_t pos) {
    if (pos >= plen || props[pos] != 0x26) return 0;
    uint32_t r = pos + 1;
    if (r + 2 > plen) return 0;
    uint16_t klen = (uint16_t)((props[r] << 8) | props[r+1]); r += 2;
    if (r + klen + 2 > plen) return 0;
    r += klen;
    uint16_t vlen = (uint16_t)((props[r] << 8) | props[r+1]); r += 2;
    if (r + vlen > plen) return 0;
    r += vlen;
    return r - pos;
}

/* ===== add_publish_properties: 若为空则补一组合法属性 ===== */
void add_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.property_len != 0) continue;

        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 随机选择一种最小合法集合 */
        int strategy = rand() % 5;
        switch (strategy) {
            case 0: { /* PFI=1 */
                if (!pp_ensure(pos, 2, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x01;        /* PFI */
                buf[pos++] = 0x01;        /* 值=1，UTF-8 文本 */
                break;
            }
            case 1: { /* Message Expiry Interval (0..3600) */
                if (!pp_ensure(pos, 1+4, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x02;
                pp_put32(buf+pos, (uint32_t)(rand()%3601)); pos += 4;
                break;
            }
            case 2: { /* Content Type = text/plain */
                const char *ct = "text/plain";
                uint16_t n = (uint16_t)strlen(ct);
                if (!pp_ensure(pos, 1+2+n, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x03;
                pp_put16(buf+pos, n); pos += 2;
                memcpy(buf+pos, ct, n); pos += n;
                break;
            }
            case 3: { /* Topic Alias = 1..100 */
                if (!pp_ensure(pos, 1+2, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x23;
                pp_put16(buf+pos, (uint16_t)(1 + rand()%100)); pos += 2;
                break;
            }
            case 4: { /* 一条 User Property: key=key, value=value */
                const char *k="key", *v="value";
                uint16_t klen=(uint16_t)strlen(k), vlen=(uint16_t)strlen(v);
                if (!pp_ensure(pos, 1+2+klen+2+vlen, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x26;
                pp_put16(buf+pos, klen); pos += 2; memcpy(buf+pos, k, klen); pos += klen;
                pp_put16(buf+pos, vlen); pos += 2; memcpy(buf+pos, v, vlen); pos += vlen;
                break;
            }
        }

        pkt->variable_header.property_len = pos; /* 可能为 0（空间不足时），也合法 */
    }
}

/* ===== delete_publish_properties: 清空并可选清零缓冲区 ===== */
void delete_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        pkt->variable_header.property_len = 0;
        memset(pkt->variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

/* ===== repeat_publish_properties: 只重复一条 User Property（可重复的属性） ===== */
void repeat_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        /* 找到第一条可完整解析的 User Property */
        uint32_t up_pos = 0, up_len = 0;
        for (uint32_t j = 0; j < plen; ) {
            uint8_t id = p[j];
            if (id == 0x26) {
                uint32_t L = peek_publish_user_property_len(p, plen, j);
                if (L == 0) break;
                up_pos = j; up_len = L; break;
            }
            /* 跳过非 UP 的属性（按照类型长度跳） */
            if (id == 0x01) {                 /* PFI: 1B */
                if (j + 2 > plen) break; j += 2;
            } else if (id == 0x02) {          /* MEI: 4B */
                if (j + 1 + 4 > plen) break; j += 1 + 4;
            } else if (id == 0x03) {          /* CT: UTF-8 */
                if (j + 1 + 2 > plen) break;
                uint16_t n = (uint16_t)((p[j+1] << 8) | p[j+2]);
                if (j + 1 + 2 + n > plen) break;
                j += 1 + 2 + n;
            } else if (id == 0x08) {          /* RT: UTF-8 */
                if (j + 1 + 2 > plen) break;
                uint16_t n = (uint16_t)((p[j+1] << 8) | p[j+2]);
                if (j + 1 + 2 + n > plen) break;
                j += 1 + 2 + n;
            } else if (id == 0x09) {          /* CD: Binary */
                if (j + 1 + 2 > plen) break;
                uint16_t n = (uint16_t)((p[j+1] << 8) | p[j+2]);
                if (j + 1 + 2 + n > plen) break;
                j += 1 + 2 + n;
            } else if (id == 0x23) {          /* Topic Alias: 2B */
                if (j + 1 + 2 > plen) break; j += 1 + 2;
            } else {
                /* 未知/异常，停止保护 */
                up_len = 0; break;
            }
        }

        if (up_len == 0) continue;                 /* 没有可重复的 UP */
        if (!pp_ensure(plen, up_len, MAX_PROPERTIES_LEN)) continue;

        memcpy(p + plen, p + up_pos, up_len);
        pkt->variable_header.property_len = plen + up_len;
    }
}

/* ===== mutate_publish_properties: 重建为一组“合法组合”的属性 ===== */
void mutate_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 标记只出现一次的属性是否已写入 */
        int used_pfi=0, used_mei=0, used_ct=0, used_rt=0, used_cd=0, used_ta=0;

        /* 选择几种合法策略，全部“重建”属性区 */
        int strategy = rand() % 6;

        /* 工具宏 */
        #define ENSURE(n) do { if (!pp_ensure(pos, (n), MAX_PROPERTIES_LEN)) goto done; } while (0)
        #define PUT8(v)   do { ENSURE(1); buf[pos++] = (uint8_t)(v); } while (0)
        #define PUT16(v)  do { ENSURE(2); pp_put16(buf+pos, (uint16_t)(v)); pos += 2; } while (0)
        #define PUT32(v)  do { ENSURE(4); pp_put32(buf+pos, (uint32_t)(v)); pos += 4; } while (0)
        #define PUT_UTF8(s) do { \
            const char *S__ = (s); uint16_t N__ = (uint16_t)(S__ ? strlen(S__) : 0); \
            ENSURE(1+2+N__); buf[pos++] = cur_id; PUT16(N__); if (N__) { memcpy(buf+pos, S__, N__); pos += N__; } \
        } while (0)
        #define PUT_BIN(ptr,len) do { \
            uint16_t L__ = (uint16_t)(len); ENSURE(1+2+L__); buf[pos++] = 0x09; PUT16(L__); memcpy(buf+pos, (ptr), L__); pos += L__; \
        } while (0)

        switch (strategy) {
            case 0: /* 清空（合法） */
                break;

            case 1: /* PFI=1 + 可选 CT */
            {
                if (!used_pfi) { PUT8(0x01); PUT8(1); used_pfi=1; }
                if ((rand()%2) && !used_ct) {
                    uint8_t cur_id = 0x03; (void)cur_id;
                    PUT_UTF8("text/plain"); used_ct=1;
                }
                break;
            }

            case 2: /* Message Expiry + 可选 PFI */
            {
                if (!used_mei) { PUT8(0x02); PUT32((uint32_t)(rand()%7200)); used_mei=1; }
                if ((rand()%2) && !used_pfi) { PUT8(0x01); PUT8(rand()%2); used_pfi=1; }
                break;
            }

            case 3: /* Topic Alias（1..100）+ 可选 Response Topic */
            {
                if (!used_ta) { PUT8(0x23); PUT16((uint16_t)(1 + rand()%100)); used_ta=1; }
                if ((rand()%2) && !used_rt) {
                    uint8_t cur_id = 0x08; (void)cur_id;
                    PUT_UTF8("reply/topic"); used_rt=1;
                }
                break;
            }

            case 4: /* Correlation Data + Response Topic（常用于请求-响应） */
            {
                if (!used_rt) { uint8_t cur_id = 0x08; (void)cur_id; PUT_UTF8("reply/topic"); used_rt=1; }
                if (!used_cd) {
                    uint8_t tmp[24]; int L = 8 + rand()%17;
                    for (int k=0;k<L;k++) tmp[k]=(uint8_t)rand();
                    PUT_BIN(tmp, L); used_cd=1;
                }
                break;
            }

            case 5: /* 混合：随机挑若干“仅一次”属性 + 0..3 个 User Property */
            {
                if (!used_pfi && (rand()%2)) { PUT8(0x01); PUT8(rand()%2); used_pfi=1; }
                if (!used_mei && (rand()%2)) { PUT8(0x02); PUT32((uint32_t)(rand()%7200)); used_mei=1; }
                if (!used_ct  && (rand()%2)) { uint8_t cur_id=0x03; (void)cur_id; PUT_UTF8("application/json"); used_ct=1; }
                if (!used_rt  && (rand()%2)) { uint8_t cur_id=0x08; (void)cur_id; PUT_UTF8("resp/alpha"); used_rt=1; }
                if (!used_cd  && (rand()%2)) {
                    uint8_t tmp[16]; int L = 6 + rand()%9;
                    for (int k=0;k<L;k++) tmp[k]=(uint8_t)rand();
                    PUT_BIN(tmp, L); used_cd=1;
                }
                if (!used_ta  && (rand()%2)) { PUT8(0x23); PUT16((uint16_t)(1 + rand()%100)); used_ta=1; }

                /* 0..3 个 User Property */
                int upn = rand()%4;
                for (int t=0; t<upn; ++t) {
                    const char *k = (t%2)? "source":"note";
                    const char *v = (t%2)? "edge":"ok";
                    uint16_t klen=(uint16_t)strlen(k), vlen=(uint16_t)strlen(v);
                    ENSURE(1+2+klen+2+vlen);
                    buf[pos++] = 0x26;
                    pp_put16(buf+pos, klen); pos += 2; memcpy(buf+pos, k, klen); pos += klen;
                    pp_put16(buf+pos, vlen); pos += 2; memcpy(buf+pos, v, vlen); pos += vlen;
                }
                break;
            }
        }

    done:
        pkt->variable_header.property_len = pos;

        #undef ENSURE
        #undef PUT8
        #undef PUT16
        #undef PUT32
        #undef PUT_UTF8
        #undef PUT_BIN
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
        int weights[10] = {40, 40, 0, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = {40, 40, 40, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = {40, 40, 40, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = {40, 40, 0, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = {40, 40, 0, 0, 0, 0, 40, 40, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
/* ===== Helpers for UNSUBSCRIBE properties (User Property only) ===== */
static inline int uprop_ensure(uint32_t pos, uint32_t need) {
    return pos + need <= (uint32_t)MAX_PROPERTIES_LEN;
}
static inline void uprop_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}
/* 计算从 props[pos] 开始的一条 User Property 的总长度；不完整/非法返回 0 */
static uint32_t peek_unsub_user_property_len(const uint8_t *props, uint32_t plen, uint32_t pos) {
    if (pos >= plen || props[pos] != 0x26) return 0;
    uint32_t r = pos + 1;
    if (r + 2 > plen) return 0;
    uint16_t klen = (uint16_t)((props[r] << 8) | props[r+1]); r += 2;
    if (r + klen + 2 > plen) return 0;
    r += klen;
    uint16_t vlen = (uint16_t)((props[r] << 8) | props[r+1]); r += 2;
    if (r + vlen > plen) return 0;
    r += vlen;
    return r - pos; /* 总长度（字节） */
}

/* 增加 properties 字段（添加一条合法 User Property） */
void add_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    static const char *def_key = "key";
    static const char *def_val = "value";

    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];  /* 注意：使用指针，直接修改原对象 */

        if (pkt->variable_header.property_len != 0) continue;   /* 已有属性则跳过 */

        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;
        uint16_t klen = (uint16_t)strlen(def_key);
        uint16_t vlen = (uint16_t)strlen(def_val);

        if (!uprop_ensure(pos, 1 + 2 + klen + 2 + vlen)) {
            pkt->variable_header.property_len = 0;  /* 空属性也合法 */
            continue;
        }

        p[pos++] = 0x26;                               /* User Property */
        uprop_put16(p + pos, klen); pos += 2; memcpy(p + pos, def_key, klen); pos += klen;
        uprop_put16(p + pos, vlen); pos += 2; memcpy(p + pos, def_val, vlen); pos += vlen;

        pkt->variable_header.property_len = pos;
    }
}

/* 删除 properties 字段（清空即可） */
void delete_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        pkts[i].variable_header.property_len = 0;
        memset(pkts[i].variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

/* 复制一条已存在的 User Property 并追加（仅当解析到完整 UP 时进行） */
void repeat_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        /* 找第一条完整的 User Property */
        uint32_t up_pos = 0, up_len = 0;
        for (uint32_t j = 0; j < plen; ) {
            if (p[j] == 0x26) {
                uint32_t L = peek_unsub_user_property_len(p, plen, j);
                if (L == 0) break;          /* 结构异常则不处理 */
                up_pos = j; up_len = L;
                break;
            } else {
                /* UNSUBSCRIBE 不允许其他属性，遇到未知字节则放弃重复 */
                up_len = 0; break;
            }
        }
        if (up_len == 0) continue;
        if (!uprop_ensure(plen, up_len)) continue;

        memcpy(p + plen, p + up_pos, up_len);
        pkt->variable_header.property_len = plen + up_len;
    }
}

/* 只做“合法变异”：重建为 0..N 条合法 User Property（不写入其他 ID） */
void mutate_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    static const char *keys[] = {"source","priority","note","device","region"};
    static const char *vals[] = {"sensor1","high","ok","edge","cn-north"};

    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 选择合法策略：0=清空，1=写1条，2=写2条，3=写3条（全部合法 UP） */
        int strategy = rand() % 4;
        int count = 0;
        switch (strategy) {
            case 0: count = 0; break;
            case 1: count = 1; break;
            case 2: count = 2; break;
            case 3: count = 3; break;
        }

        for (int t = 0; t < count; ++t) {
            const char *k = keys[rand() % (int)(sizeof(keys)/sizeof(keys[0]))];
            const char *v = vals[rand() % (int)(sizeof(vals)/sizeof(vals[0]))];
            uint16_t klen = (uint16_t)strlen(k);
            uint16_t vlen = (uint16_t)strlen(v);

            uint32_t need = 1 + 2 + klen + 2 + vlen;
            if (!uprop_ensure(pos, need)) break;

            p[pos++] = 0x26;
            uprop_put16(p + pos, klen); pos += 2; memcpy(p + pos, k, klen); pos += klen;
            uprop_put16(p + pos, vlen); pos += 2; memcpy(p + pos, v, vlen); pos += vlen;
        }

        pkt->variable_header.property_len = pos;  /* 字节长度（合法） */
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
        int weights[10] = {0, 0, 0, 0, 40, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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
        int weights[10] = { 50, 50, 50, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
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

/* ===== Helpers ===== */
static inline int a_ensure(uint32_t pos, uint32_t need) {
    return pos + need <= (uint32_t)MAX_PROPERTIES_LEN;
}
static inline void a_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}
static inline void a_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}
/* MQTT VarInt 字节数 */
static inline uint32_t varint_size(uint32_t v) {
    if (v < 128u) return 1;
    if (v < 16384u) return 2;
    if (v < 2097152u) return 3;
    return 4;
}
/* 重新计算 AUTH 剩余长度：1 (reason_code) + varint(prop_len) + prop_len */
static inline void auth_recalc_remaining_length(mqtt_auth_packet_t *pkt) {
    uint32_t L = pkt->variable_header.property_len;
    pkt->fixed_header.remaining_length = 1u + varint_size(L) + L;
}

/* ===== add_auth_properties：若为空则追加一组最小且合法的属性 ===== */
void add_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.property_len != 0) { 
            auth_recalc_remaining_length(pkt);
            continue;
        }

        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 选择一个最小合规集合：默认写入 Authentication Method="PLAIN" */
        const char *method = "PLAIN";
        uint16_t mlen = (uint16_t)strlen(method);

        if (!a_ensure(pos, 1 + 2 + mlen)) { /* 0x15 + len + data */
            pkt->variable_header.property_len = 0;
            auth_recalc_remaining_length(pkt);
            continue;
        }

        p[pos++] = 0x15;                     /* Authentication Method */
        a_put16(p + pos, mlen); pos += 2;
        memcpy(p + pos, method, mlen); pos += mlen;

        pkt->variable_header.property_len = pos;
        auth_recalc_remaining_length(pkt);
    }
}

/* ===== repeat_auth_properties：仅复制一条完整的 User Property (0x26) ===== */
void repeat_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        /* 解析并找到第一条完整的 User Property */
        uint32_t up_pos = 0, up_len = 0;
        for (uint32_t j = 0; j < plen; ) {
            uint8_t id = p[j];
            if (id == 0x26) { /* User Property */
                if (j + 1 + 2 > plen) break;
                uint32_t r = j + 1;
                uint16_t klen = (uint16_t)((p[r] << 8) | p[r+1]); r += 2;
                if (r + klen + 2 > plen) break;
                r += klen;
                uint16_t vlen = (uint16_t)((p[r] << 8) | p[r+1]); r += 2;
                if (r + vlen > plen) break;
                r += vlen;
                up_pos = j; up_len = r - j;
                break;
            }
            /* 跳过单次属性：0x15/0x16/0x1F */
            else if (id == 0x15 || id == 0x1F) { /* UTF-8 */
                if (j + 1 + 2 > plen) break;
                uint16_t n = (uint16_t)((p[j+1] << 8) | p[j+2]);
                if (j + 1 + 2 + n > plen) break;
                j += 1 + 2 + n;
            } else if (id == 0x16) { /* Binary */
                if (j + 1 + 2 > plen) break;
                uint16_t n = (uint16_t)((p[j+1] << 8) | p[j+2]);
                if (j + 1 + 2 + n > plen) break;
                j += 1 + 2 + n;
            } else {
                /* 未知/异常，停止保护 */
                up_len = 0; break;
            }
        }
        if (up_len == 0) { auth_recalc_remaining_length(pkt); continue; }
        if (!a_ensure(plen, up_len)) { auth_recalc_remaining_length(pkt); continue; }

        memcpy(p + plen, p + up_pos, up_len);
        pkt->variable_header.property_len = plen + up_len;
        auth_recalc_remaining_length(pkt);
    }
}

/* ===== mutate_auth_properties：重建为一组“合法组合”的属性 ===== */
void mutate_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    static const char *methods[] = {"PLAIN", "SCRAM-SHA-256"};
    static const char *reasons[] = {"ok", "continue", "reauth"};
    static const char *keys[]    = {"source","priority","note","device"};
    static const char *vals[]    = {"client","high","ok","edge"};

    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        uint8_t *p  = pkt->variable_header.properties;
        uint32_t pos = 0;

        /* 标识“仅允许出现一次”的属性是否已写 */
        int used_method = 0, used_data = 0, used_reason = 0;

        /* 选择一个合法策略重建属性区 */
        int strategy = rand() % 6;
        switch (strategy) {
            case 0: /* 清空属性（合法） */
                break;

            case 1: /* 仅 Method */
            {
                const char *m = methods[rand() % 2];
                uint16_t ml = (uint16_t)strlen(m);
                if (a_ensure(pos, 1 + 2 + ml)) {
                    p[pos++] = 0x15; a_put16(p + pos, ml); pos += 2; memcpy(p + pos, m, ml); pos += ml;
                    used_method = 1;
                }
                break;
            }

            case 2: /* Method + Data */
            {
                const char *m = methods[rand() % 2];
                uint16_t ml = (uint16_t)strlen(m);
                uint16_t dl = (uint16_t)(8 + rand() % 9); /* 8..16 字节 */
                if (a_ensure(pos, 1 + 2 + ml + 1 + 2 + dl)) {
                    /* Method */
                    p[pos++] = 0x15; a_put16(p + pos, ml); pos += 2; memcpy(p + pos, m, ml); pos += ml; used_method=1;
                    /* Data */
                    p[pos++] = 0x16; a_put16(p + pos, dl); pos += 2;
                    for (uint16_t k = 0; k < dl; ++k) p[pos + k] = (uint8_t)rand();
                    pos += dl; used_data=1;
                }
                break;
            }

            case 3: /* Reason String */
            {
                const char *rs = reasons[rand() % 3];
                uint16_t rl = (uint16_t)strlen(rs);
                if (a_ensure(pos, 1 + 2 + rl)) {
                    p[pos++] = 0x1F; a_put16(p + pos, rl); pos += 2; memcpy(p + pos, rs, rl); pos += rl;
                    used_reason = 1;
                }
                break;
            }

            case 4: /* 若干 User Property（1..3） */
            {
                int upn = 1 + rand() % 3;
                for (int t = 0; t < upn; ++t) {
                    const char *k = keys[rand() % 4];
                    const char *v = vals[rand() % 4];
                    uint16_t kl = (uint16_t)strlen(k), vl = (uint16_t)strlen(v);
                    if (!a_ensure(pos, 1 + 2 + kl + 2 + vl)) break;
                    p[pos++] = 0x26;
                    a_put16(p + pos, kl); pos += 2; memcpy(p + pos, k, kl); pos += kl;
                    a_put16(p + pos, vl); pos += 2; memcpy(p + pos, v, vl); pos += vl;
                }
                break;
            }

            case 5: /* 混合：Method (+Data) + 0..2 个 User Property + 可选 Reason String */
            {
                /* Method */
                if (!used_method) {
                    const char *m = methods[rand() % 2];
                    uint16_t ml = (uint16_t)strlen(m);
                    if (a_ensure(pos, 1 + 2 + ml)) {
                        p[pos++] = 0x15; a_put16(p + pos, ml); pos += 2; memcpy(p + pos, m, ml); pos += ml;
                        used_method = 1;
                    }
                }
                /* 可选 Data（仅当 Method 已写入） */
                if (used_method && (rand() % 2) && !used_data) {
                    uint16_t dl = (uint16_t)(6 + rand() % 11); /* 6..16 */
                    if (a_ensure(pos, 1 + 2 + dl)) {
                        p[pos++] = 0x16; a_put16(p + pos, dl); pos += 2;
                        for (uint16_t k = 0; k < dl; ++k) p[pos + k] = (uint8_t)rand();
                        pos += dl; used_data = 1;
                    }
                }
                /* 0..2 个 User Property */
                {
                    int upn = rand() % 3;
                    for (int t = 0; t < upn; ++t) {
                        const char *k = keys[rand() % 4];
                        const char *v = vals[rand() % 4];
                        uint16_t kl = (uint16_t)strlen(k), vl = (uint16_t)strlen(v);
                        if (!a_ensure(pos, 1 + 2 + kl + 2 + vl)) break;
                        p[pos++] = 0x26;
                        a_put16(p + pos, kl); pos += 2; memcpy(p + pos, k, kl); pos += kl;
                        a_put16(p + pos, vl); pos += 2; memcpy(p + pos, v, vl); pos += vl;
                    }
                }
                /* 可选 Reason String（若未写过） */
                if (!used_reason && (rand() % 2)) {
                    const char *rs = "ok";
                    uint16_t rl = (uint16_t)strlen(rs);
                    if (a_ensure(pos, 1 + 2 + rl)) {
                        p[pos++] = 0x1F; a_put16(p + pos, rl); pos += 2; memcpy(p + pos, rs, rl); pos += rl;
                        used_reason = 1;
                    }
                }
                break;
            }
        }

        pkt->variable_header.property_len = pos;
        auth_recalc_remaining_length(pkt);
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
static int connect_mutators_weights[] = {
    8, // mutate_connect_flags
    8, // mutate_connect_keep_alive
    0, // mutate_connect_properties            <-- 禁用
    6, // mutate_connect_client_id
    6, // mutate_connect_will_properties
    6, // mutate_connect_will_topic
    6, // mutate_connect_will_payload
    6, // mutate_connect_user_name
    6, // mutate_connect_password
    0, // add_connect_properties               <-- 禁用
    8, // add_connect_client_id
    0, // add_connect_will_properties          <-- 禁用
    0, // add_connect_will_topic               <-- 禁用
    8, // add_connect_will_payload
    8, // add_connect_user_name
    8, // add_connect_password
    8, // delete_connect_properties
    0, // delete_connect_client_id             <-- 禁用（或修函数后再放开）
    0, // delete_connect_will_properties
    0, // delete_connect_will_topic
    0, // delete_connect_will_payload
    8, // delete_connect_user_name
    8, // delete_connect_password
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
static int subscribe_mutators_weights[] = {
    8, // mutate_subscribe_packet_identifier
    6, // mutate_subscribe_properties
    8, // add_subscribe_properties
    8, // delete_subscribe_properties
    6, // repeat_subscribe_properties
    6, // mutate_subscribe_topic_filter
    6, // repeat_subscribe_topic_filter
    8, // mutate_subscribe_qos
    8, // mutate_subscribe_topic_count
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
static int publish_mutators_weights[] = {
    0, // mutate_publish_packet_identifier
    8, // add_publish_packet_identifier
    0, // delete_publish_packet_identifier
    6, // mutate_publish_topic_name
    8, // add_publish_topic_name
    0, // delete_publish_topic_name
    6, // mutate_publish_properties
    8, // add_publish_properties
    8, // delete_publish_properties
    0, // repeat_publish_properties
    6, // mutate_publish_payload
    8, // add_publish_payload
    8, // delete_publish_payload
    8, // mutate_publish_qos
    8, // mutate_publish_dup
    8, // mutate_publish_retain
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
static int unsubscribe_mutators_weights[] = {
    6, // mutate_unsubscribe_packet_identifier
    8, // add_unsubscribe_properties
    8, // delete_unsubscribe_properties
    6, // mutate_unsubscribe_properties
    6, // repeat_unsubscribe_properties
    6, // mutate_unsubscribe_topic_filters
    6, // repeat_unsubscribe_topic_filters
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
static int auth_mutators_weights[] = {
    6, // mutate_auth_reason_code
    8, // add_auth_reason_code
    8, // delete_auth_reason_code
    6, // mutate_auth_properties
    8, // add_auth_properties
    6, // repeat_auth_properties
};

#define CONNECT_MUTATOR_COUNT (sizeof(connect_mutators) / sizeof(connect_mutator_fn))
#define SUBSCRIBE_MUTATOR_COUNT (sizeof(subscribe_mutators) / sizeof(subscribe_mutator_fn))
#define PUBLISH_MUTATOR_COUNT (sizeof(publish_mutators) / sizeof(publish_mutator_fn))
#define UNSUBSCRIBE_MUTATOR_COUNT (sizeof(unsubscribe_mutators) / sizeof(unsubscribe_mutator_fn))
#define AUTH_MUTATOR_COUNT (sizeof(auth_mutators) / sizeof(auth_mutator_fn))

// 主调度函数：从 mutators 中随机选择一个进行变异
void dispatch_connect_mutation(mqtt_connect_packet_t *pkt, int num_packets) {
    if (pkt == NULL) return;
    int index = pick_weighted(connect_mutators_weights, (int)CONNECT_MUTATOR_COUNT);
    // printf("[DISPATCH] Applying mutator #%d\n", index);
    connect_mutators[index](pkt, 1); 
}

void dispatch_subscribe_mutation(mqtt_subscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(subscribe_mutators_weights, (int)SUBSCRIBE_MUTATOR_COUNT);
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  subscribe_mutators[index](pkt, 1);
}

void dispatch_publish_mutation(mqtt_publish_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(publish_mutators_weights, (int)PUBLISH_MUTATOR_COUNT);
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  publish_mutators[index](pkt, 1);
}

void dispatch_unsubscribe_mutation(mqtt_unsubscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(unsubscribe_mutators_weights, (int)UNSUBSCRIBE_MUTATOR_COUNT);
  // printf("[DISPATCH] Applying mutator #%d\n", index);
  unsubscribe_mutators[index](pkt, 1);
}
void dispatch_auth_mutation(mqtt_auth_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(auth_mutators_weights, (int)AUTH_MUTATOR_COUNT);
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
