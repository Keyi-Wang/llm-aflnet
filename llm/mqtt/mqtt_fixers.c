#include "mqtt.h"

static void sanitize_utf8_topic_filter(char *s, size_t max_len) {
    if (!s || max_len == 0) {
        return;
    }

    size_t i;
    int has_nul = 0;

    /* 遍历并将内容约束为 7-bit ASCII（ASCII 本身是合法 UTF-8） */
    for (i = 0; i < max_len; ++i) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\0') {
            has_nul = 1;
            break;
        }

        /* 控制字符（除 TAB）与 DEL 统一替换为空格 */
        if ((c < 0x20 && c != '\t') || c == 0x7F) {
            s[i] = ' ';
        }
        /* 非 ASCII 字节替换为下划线，保证结果全是 7-bit ASCII */
        else if (c >= 0x80) {
            s[i] = '_';
        }
        /* 其他可打印 ASCII 保持不变 */
    }

    /* 确保以 '\0' 结尾，若原来没有终止符则截断 */
    if (!has_nul) {
        s[max_len - 1] = '\0';
    }
}

/* Common helpers for MQTT fixers */

static void sanitize_utf8_string_basic(char *s, size_t max_len) {
    if (!s || max_len == 0) {
        return;
    }

    size_t i;
    int found_nul = 0;

    for (i = 0; i < max_len; ++i) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\0') {
            found_nul = 1;
            break;
        }

        /* 控制字符（除 TAB）与 DEL 统一替换为空格 */
        if ((c < 0x20 && c != '\t') || c == 0x7F) {
            s[i] = ' ';
        }
        /* 非 ASCII 字节统一替换为 '_'，保证结果为 7-bit ASCII（合法 UTF-8 子集） */
        else if (c >= 0x80) {
            s[i] = '_';
        }
        /* 其他可打印 ASCII 直接保留 */
    }

    /* 若未遇到 '\0'，强制末尾终止 */
    if (!found_nul) {
        s[max_len - 1] = '\0';
    } else {
        /* 清理第一个 '\0' 之后的尾部，避免“包含 U+0000”歧义 */
        size_t j;
        for (j = i + 1; j < max_len; ++j) {
            s[j] = '\0';
        }
    }
}

static void ensure_non_empty_string(char *s, size_t max_len, const char *fallback) {
    if (!s || max_len == 0) {
        return;
    }
    if (!fallback || fallback[0] == '\0') {
        fallback = "t";
    }
    if (s[0] == '\0') {
        (void)snprintf(s, max_len, "%s", fallback);
    }
}

/* 去除 Topic Name 中的通配符（仅用于 Topic Name，不用于 Topic Filter） */
static void strip_wildcards_from_topic_name(char *s, size_t max_len) {
    if (!s || max_len == 0) {
        return;
    }
    size_t i;
    for (i = 0; i < max_len && s[i] != '\0'; ++i) {
        if (s[i] == '+' || s[i] == '#') {
            s[i] = '_';
        }
    }
}

/* -------------------------------------------------------------
 * 1 & 12. UNSUBSCRIBE Payload MUST contain at least one Topic Filter
 *    [MQTT-3.10.3-2]
 * ------------------------------------------------------------- */
void fix_unsubscribe_payload_has_topic_filter(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        mqtt_unsubscribe_packet_t *p = &packets[i];

        if (p->payload.topic_count == 0) {
            p->payload.topic_count = 1;
            (void)snprintf(p->payload.topic_filters[0], MAX_TOPIC_LEN, "fixed/topic");
        } else if (p->payload.topic_count > MAX_TOPIC_FILTERS) {
            p->payload.topic_count = MAX_TOPIC_FILTERS;
        }

        for (uint8_t j = 0; j < p->payload.topic_count && j < MAX_TOPIC_FILTERS; ++j) {
            sanitize_utf8_string_basic(p->payload.topic_filters[j], MAX_TOPIC_LEN);
            ensure_non_empty_string(p->payload.topic_filters[j], MAX_TOPIC_LEN, "fixed/topic");
        }
    }
}

/* 方便按照规范编号再调用一次（等价实现） */
void fix_unsubscribe_payload_has_topic_filter_mqtt_3_10_3_2(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    fix_unsubscribe_payload_has_topic_filter(packets, num_packets);
}

/* -------------------------------------------------------------
 * 2. CONNECT: protocol name MUST be the UTF-8 String "MQTT"
 * ------------------------------------------------------------- */
void fix_connect_protocol_name_mqtt(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        (void)snprintf(packets[i].variable_header.protocol_name, MAX_PROTOCOL_NAME_LEN, "MQTT");
    }
}

/* -------------------------------------------------------------
 * 3. PUBLISH: Topic Name MUST be present and a UTF-8 Encoded String
 * ------------------------------------------------------------- */
void fix_publish_topic_name_utf8(mqtt_publish_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        sanitize_utf8_string_basic(packets[i].variable_header.topic_name, MAX_TOPIC_LEN);
        ensure_non_empty_string(packets[i].variable_header.topic_name, MAX_TOPIC_LEN, "topic/name");
    }
}

/* -------------------------------------------------------------
 * 4 & 16. PUBLISH Topic Name MUST NOT contain wildcard characters
 *         (wildcards only for Topic Filters, not Topic Names)
 * ------------------------------------------------------------- */
void fix_publish_topic_name_no_wildcards(mqtt_publish_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        strip_wildcards_from_topic_name(packets[i].variable_header.topic_name, MAX_TOPIC_LEN);
        ensure_non_empty_string(packets[i].variable_header.topic_name, MAX_TOPIC_LEN, "topic/name");
    }
}

/* 提供一个带规范号的别名，方便按规则调用 */
void fix_publish_topic_name_no_wildcards_mqtt_4_7_0_1(mqtt_publish_packet_t *packets, int num_packets) {
    fix_publish_topic_name_no_wildcards(packets, num_packets);
}

/* -------------------------------------------------------------
 * 5. PUBLISH Topic Name MUST match Subscription’s Topic Filter
 *    （需要订阅上下文，这里仅提供占位实现）
 * ------------------------------------------------------------- */
void fix_publish_match_subscription_filter(mqtt_publish_packet_t *packets, int num_packets) {
    /* 无订阅列表上下文，无法在本地修正。
     * 这里预留空实现，以便将来扩展为：
     *   fix_publish_match_subscription_filter(packets, num_packets,
     *                                         const mqtt_subscribe_packet_t *subs, int num_subs);
     */
    (void)packets;
    (void)num_packets;
}

/* -------------------------------------------------------------
 * 6. PUBREL Fixed Header bits 3..0 MUST be 0010 (0x2)
 * ------------------------------------------------------------- */
void fix_pubrel_reserved_flags(mqtt_pubrel_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t hdr = packets[i].fixed_header.packet_type;
        if ((hdr >> 4) == MQTT_PUBREL) {
            hdr = (uint8_t)((hdr & 0xF0u) | 0x02u);
            packets[i].fixed_header.packet_type = hdr;
        }
    }
}

/* -------------------------------------------------------------
 * 7. PUBREL Reason Code MUST be one of PUBREL Reason Codes
 *    （简单策略：只允许 0x00 和 0x92，否则归一为 0x00）
 * ------------------------------------------------------------- */
void fix_pubrel_reason_code_valid(mqtt_pubrel_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t rc = packets[i].variable_header.reason_code;
        if (rc != 0x00u && rc != 0x92u) {
            packets[i].variable_header.reason_code = 0x00u; /* Success */
        }
    }
}

/* -------------------------------------------------------------
 * 8. PUBACK Reason Code MUST be one of PUBACK Reason Codes
 *    （简单策略：允许 {0x00, 0x10, 0x80}，否则归一为 0x00）
 * ------------------------------------------------------------- */
void fix_puback_reason_code_valid(mqtt_puback_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t rc = packets[i].variable_header.reason_code;
        if (rc != 0x00u && rc != 0x10u && rc != 0x80u) {
            packets[i].variable_header.reason_code = 0x00u; /* Success */
        }
    }
}

/* -------------------------------------------------------------
 * 9. SUBSCRIBE Fixed Header bits 3..0 MUST be 0010 (0x2)
 * ------------------------------------------------------------- */
void fix_subscribe_reserved_flags(mqtt_subscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t hdr = packets[i].fixed_header.packet_type;
        if ((hdr >> 4) == MQTT_SUBSCRIBE) {
            hdr = (uint8_t)((hdr & 0xF0u) | 0x02u);
            packets[i].fixed_header.packet_type = hdr;
        }
    }
}

/* -------------------------------------------------------------
 * 10. SUBSCRIBE Topic Filters MUST be UTF-8 Encoded Strings
 * ------------------------------------------------------------- */
void fix_subscribe_topic_filters_utf8(mqtt_subscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        mqtt_subscribe_packet_t *p = &packets[i];
        uint8_t count = p->payload.topic_count;

        if (count > MAX_TOPIC_FILTERS) {
            count = MAX_TOPIC_FILTERS;
            p->payload.topic_count = count;
        }

        for (uint8_t j = 0; j < count; ++j) {
            sanitize_utf8_string_basic(p->payload.topic_filters[j].topic_filter, MAX_TOPIC_LEN);
            ensure_non_empty_string(p->payload.topic_filters[j].topic_filter,
                                    MAX_TOPIC_LEN, "fixed/topic");
        }
    }
}

/* -------------------------------------------------------------
 * 11. SUBSCRIBE Payload MUST contain at least one Topic Filter
 *     and Subscription Options pair
 * ------------------------------------------------------------- */
void fix_subscribe_payload_has_topic_pair(mqtt_subscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        mqtt_subscribe_packet_t *p = &packets[i];

        if (p->payload.topic_count == 0) {
            p->payload.topic_count = 1;
            (void)snprintf(p->payload.topic_filters[0].topic_filter, MAX_TOPIC_LEN, "fixed/topic");
            p->payload.topic_filters[0].qos = 0; /* QoS 0 as safe default */
        } else if (p->payload.topic_count > MAX_TOPIC_FILTERS) {
            p->payload.topic_count = MAX_TOPIC_FILTERS;
        }

        uint8_t count = p->payload.topic_count;
        for (uint8_t j = 0; j < count; ++j) {
            sanitize_utf8_string_basic(p->payload.topic_filters[j].topic_filter, MAX_TOPIC_LEN);
            ensure_non_empty_string(p->payload.topic_filters[j].topic_filter,
                                    MAX_TOPIC_LEN, "fixed/topic");
        }
    }
}

/* -------------------------------------------------------------
 * 13. DISCONNECT Reason Code MUST be one of DISCONNECT Reason Codes
 *      （简单策略：允许 {0x00, 0x04, 0x80}，否则归一为 0x00）
 * ------------------------------------------------------------- */
void fix_disconnect_reason_code_valid(mqtt_disconnect_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t rc = packets[i].variable_header.reason_code;
        if (rc != 0x00u && rc != 0x04u && rc != 0x80u) {
            packets[i].variable_header.reason_code = 0x00u; /* Normal disconnection */
        }
    }
}

/* -------------------------------------------------------------
 * 14. AUTH Fixed Header bits 3..0 MUST all be 0
 * ------------------------------------------------------------- */
void fix_auth_reserved_flags(mqtt_auth_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t hdr = packets[i].fixed_header.packet_type;
        if ((hdr >> 4) == MQTT_AUTH) {
            hdr = (uint8_t)(hdr & 0xF0u); /* 低 4 位清零 */
            packets[i].fixed_header.packet_type = hdr;
        }
    }
}

/* -------------------------------------------------------------
 * 15. AUTH Reason Code MUST be one of Authenticate Reason Codes
 *      （简单策略：若不在 {0x00, 0x18} 内，则归一为 0x00）
 * ------------------------------------------------------------- */
void fix_auth_reason_code_valid(mqtt_auth_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t rc = packets[i].variable_header.reason_code;
        if (rc != 0x00u && rc != 0x18u) {
            packets[i].variable_header.reason_code = 0x00u; /* Success / Continue */
        }
    }
}

/* -------------------------------------------------------------
 * 17. All Topic Names and Topic Filters MUST be at least one char
 * 18. MUST NOT include null character U+0000 (内部借助 C 字符串 + 清尾实现)
 * 19. MUST NOT encode to more than 65535 bytes
 *     （本实现中 MAX_TOPIC_LEN << 65535，天然满足；这里只保证非空 + UTF-8/ASCII）
 * ------------------------------------------------------------- */

/* 针对 PUBLISH Topic Name */
void fix_publish_topic_name_length_and_nul(mqtt_publish_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }
    for (int i = 0; i < num_packets; ++i) {
        sanitize_utf8_string_basic(packets[i].variable_header.topic_name, MAX_TOPIC_LEN);
        ensure_non_empty_string(packets[i].variable_header.topic_name, MAX_TOPIC_LEN, "topic/name");
    }
}

/* 针对 SUBSCRIBE / UNSUBSCRIBE 的 Topic Filters */
void fix_sub_unsub_topic_filters_length_and_nul(mqtt_subscribe_packet_t *subs, int num_subs,
                                                mqtt_unsubscribe_packet_t *unsubs, int num_unsubs) {
    int i;

    if (subs && num_subs > 0) {
        for (i = 0; i < num_subs; ++i) {
            mqtt_subscribe_packet_t *p = &subs[i];
            if (p->payload.topic_count > MAX_TOPIC_FILTERS) {
                p->payload.topic_count = MAX_TOPIC_FILTERS;
            }
            for (uint8_t j = 0; j < p->payload.topic_count; ++j) {
                sanitize_utf8_string_basic(p->payload.topic_filters[j].topic_filter, MAX_TOPIC_LEN);
                ensure_non_empty_string(p->payload.topic_filters[j].topic_filter,
                                        MAX_TOPIC_LEN, "fixed/topic");
            }
        }
    }

    if (unsubs && num_unsubs > 0) {
        for (i = 0; i < num_unsubs; ++i) {
            mqtt_unsubscribe_packet_t *p = &unsubs[i];
            if (p->payload.topic_count > MAX_TOPIC_FILTERS) {
                p->payload.topic_count = MAX_TOPIC_FILTERS;
            }
            for (uint8_t j = 0; j < p->payload.topic_count; ++j) {
                sanitize_utf8_string_basic(p->payload.topic_filters[j], MAX_TOPIC_LEN);
                ensure_non_empty_string(p->payload.topic_filters[j],
                                        MAX_TOPIC_LEN, "fixed/topic");
            }
        }
    }
}

/* -------------------------------------------------------------
 * 20 & 21. Shared Subscription Topic Filter:
 *   - MUST start with "$share/"
 *   - ShareName at least one char, MUST NOT contain "/", "+" or "#"
 *   - MUST be followed by "/" and a Topic Filter
 *   简化策略：所有以 "$share" 开头的过滤器重写为 "$share/group/topic"
 * ------------------------------------------------------------- */
void fix_subscribe_shared_subscription_filters(mqtt_subscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        mqtt_subscribe_packet_t *p = &packets[i];
        if (p->payload.topic_count > MAX_TOPIC_FILTERS) {
            p->payload.topic_count = MAX_TOPIC_FILTERS;
        }

        for (uint8_t j = 0; j < p->payload.topic_count; ++j) {
            char *tf = p->payload.topic_filters[j].topic_filter;

            if (!tf || tf[0] == '\0') {
                continue;
            }

            if (strncmp(tf, "$share", 6) == 0) {
                /* 重写为规范形式：$share/group/topic */
                char tmp[MAX_TOPIC_LEN];
                (void)snprintf(tmp, sizeof(tmp), "$share/group/topic");
                (void)snprintf(tf, MAX_TOPIC_LEN, "%s", tmp);
            }

            sanitize_utf8_string_basic(tf, MAX_TOPIC_LEN);
            ensure_non_empty_string(tf, MAX_TOPIC_LEN, "fixed/topic");
        }
    }
}

// extern u32 fixed_count;
void fix_connect_packet_will_rules(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets) return;

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        /* 0) 清保留位 bit0（必须为 0） */
        pkt->variable_header.connect_flags &= ~0x01;

        uint8_t flags       = pkt->variable_header.connect_flags;
        uint8_t will_flag   = (flags >> 2) & 0x01;
        uint8_t will_qos    = (flags >> 3) & 0x03;
        uint8_t will_retain = (flags >> 5) & 0x01;

        /* 如果是 MQTT v3.1.1 及以下，根本没有 Will Properties（仅 v5 有） */
        if (pkt->variable_header.protocol_level < 5) {
            pkt->payload.will_property_len = 0;
        }

        if (will_flag == 0) {
            /* 1) Will=0 则 QoS=0、Retain=0，且禁止携带任何 Will 字段 */
            pkt->variable_header.connect_flags &= ~(0x03 << 3); /* QoS -> 0 */
            pkt->variable_header.connect_flags &= ~(1 << 5);    /* Retain -> 0 */

            pkt->payload.will_property_len = 0;
            pkt->payload.will_payload_len  = 0;
            if (sizeof(pkt->payload.will_topic) > 0)
                pkt->payload.will_topic[0] = '\0';

        } else {
            /* 2) Will=1 时 QoS ∈ {0,1,2} */
            if (will_qos > 2) {
                pkt->variable_header.connect_flags &= ~(0x03 << 3);
                pkt->variable_header.connect_flags |=  (0x00 << 3); /* QoS=0 */
            }

            /* 3) 必须有 topic 和 payload（至少非空） */
            if (pkt->payload.will_topic[0] == '\0') {
                /* 确保留出 \0 结尾 */
                snprintf(pkt->payload.will_topic, MAX_TOPIC_LEN, "%s", "default/topic");
            }
            if (pkt->payload.will_payload_len == 0) {
                const char *def = "default_payload";
                size_t len = strlen(def);
                if (len > MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN;
                memcpy(pkt->payload.will_payload, def, len);
                pkt->payload.will_payload_len = (uint16_t)len;
            }

            /* 4) v5 的 Will Properties 必须是合法编码 */
            if (pkt->variable_header.protocol_level >= 5) {
                if (pkt->payload.will_property_len == 0) {
                    /* 选一个最短且合法的属性：Payload Format Indicator (0x01) + 1字节值 */
                    pkt->payload.will_properties[0] = 0x01;  /* PFI */
                    pkt->payload.will_properties[1] = 0x00;  /* value=0 (unspecified) */
                    pkt->payload.will_property_len  = 2;

                }
            } else {
                pkt->payload.will_property_len = 0;
            }
        }

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
            pkt->payload.password_len = 0;
            pkt->variable_header.connect_flags &= ~(1 << 6); // Clear Password Flag
            memset(pkt->payload.password, 0, MAX_CLIENT_ID_LEN);
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

/* ===================== fixer_sanity helpers ===================== */
/* NOTE: CONNECT will properties are a raw byte array; it may legitimately end with 0x00.
 * Never infer length via "last non-zero byte". Use best-effort property framing instead.
 */
static size_t u8_strnlen0(const uint8_t *p, size_t cap) {
    if (!p) return 0;
    for (size_t i = 0; i < cap; i++) {
        if (p[i] == 0) return i;
    }
    return cap;
}

static int rd_u16_be_ok_local(const uint8_t *p, uint32_t j, uint32_t cap, uint16_t *out) {
    if (!p || !out) return 0;
    if (j + 2 > cap) return 0;
    *out = (uint16_t)(((uint16_t)p[j] << 8) | (uint16_t)p[j + 1]);
    return 1;
}

/* Best-effort parser for MQTT v5 Will Properties (subset sufficient for our fixers/tests).
 * Returns a derived length within [0, cap]. Stops on unknown/truncated property or 0 padding.
 */
static uint32_t best_effort_will_props_len(const uint8_t *p, uint32_t cap) {
    if (!p || cap == 0) return 0;
    uint32_t j = 0;
    while (j < cap) {
        uint8_t id = p[j];
        if (id == 0) break; /* treat zero padding as end */
        j++;

        switch (id) {
            case 0x01: /* Payload Format Indicator: 1 byte */
                if (j + 1 > cap) return (j - 1);
                j += 1;
                break;
            case 0x02: /* Message Expiry Interval: 4 bytes */
            case 0x18: /* Will Delay Interval: 4 bytes */
                if (j + 4 > cap) return (j - 1);
                j += 4;
                break;
            case 0x03: /* Content Type: UTF-8 (2B len + data) */
            case 0x08: { /* Response Topic: UTF-8 (2B len + data) */
                uint16_t n = 0;
                if (!rd_u16_be_ok_local(p, j, cap, &n)) return (j - 1);
                j += 2;
                if (j + (uint32_t)n > cap) return (j - 3);
                j += (uint32_t)n;
                break;
            }
            case 0x09: { /* Correlation Data: binary (2B len + data) */
                uint16_t n = 0;
                if (!rd_u16_be_ok_local(p, j, cap, &n)) return (j - 1);
                j += 2;
                if (j + (uint32_t)n > cap) return (j - 3);
                j += (uint32_t)n;
                break;
            }
            case 0x26: { /* User Property: UTF-8 pair */
                uint16_t k = 0, v = 0;
                if (!rd_u16_be_ok_local(p, j, cap, &k)) return (j - 1);
                j += 2;
                if (j + (uint32_t)k > cap) return (j - 3);
                j += (uint32_t)k;

                if (!rd_u16_be_ok_local(p, j, cap, &v)) return (j - 1);
                j += 2;
                if (j + (uint32_t)v > cap) return (j - 3);
                j += (uint32_t)v;
                break;
            }
            default:
                /* unknown property id -> stop before this property */
                return (j - 1);
        }
    }
    return j;
}
/* =============================================================== */


void fix_connect_all_length(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) return;

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        /* Flags are a packed byte in this codebase (not a bitfield struct). */
        const uint8_t flags = (uint8_t)pkt->variable_header.connect_flags;
        const uint8_t will_flag     = (uint8_t)((flags >> 2) & 0x01u);
        const uint8_t username_flag = (uint8_t)((flags >> 7) & 0x01u);
        const uint8_t password_flag = (uint8_t)((flags >> 6) & 0x01u);

        /* ---- derive binary lengths (best-effort) ----
         * IMPORTANT:
         *  - Will properties/payload may legitimately end with 0x00, so don't use "last non-zero".
         *  - If Will Flag is 0, do NOT try to infer will lengths from stale bytes.
         */
        if (!will_flag) {
            pkt->payload.will_property_len = 0;
            pkt->payload.will_payload_len  = 0;
        } else {
            if (pkt->payload.will_property_len == 0 && pkt->payload.will_properties[0] != 0) {
                pkt->payload.will_property_len =
                    best_effort_will_props_len(pkt->payload.will_properties, (uint32_t)MAX_PROPERTIES_LEN);
            }
            if (pkt->payload.will_payload_len == 0 && pkt->payload.will_payload[0] != 0) {
                pkt->payload.will_payload_len =
                    (uint16_t)u8_strnlen0(pkt->payload.will_payload, (size_t)MAX_PAYLOAD_LEN);
            }
        }

        if (!password_flag) {
            pkt->payload.password_len = 0;
        } else {
            if (pkt->payload.password_len == 0 && pkt->payload.password[0] != 0) {
                pkt->payload.password_len =
                    (uint16_t)u8_strnlen0(pkt->payload.password, (size_t)MAX_PASSWORD_LEN);
            }
        }

        /* ---- compute remaining_length (as this fixer intended) ---- */
        size_t variable_header_len = 0;
        variable_header_len += 2 + strlen(pkt->variable_header.protocol_name); /* protocol_name with 2-byte length */
        variable_header_len += 1; /* protocol_level */
        variable_header_len += 1; /* connect_flags */
        variable_header_len += 2; /* keep_alive */
        variable_header_len += pkt->variable_header.property_len;

        size_t payload_len = 0;
        payload_len += 2 + strlen(pkt->payload.client_id);

        if (will_flag) {
            payload_len += pkt->payload.will_property_len;
            payload_len += 2 + strlen(pkt->payload.will_topic);
            payload_len += 2 + pkt->payload.will_payload_len;
        }
        if (username_flag) {
            payload_len += 2 + strlen(pkt->payload.user_name);
        }
        if (password_flag) {
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

#define PROP_ID_PFI            0x01
#define PROP_ID_MEI            0x02
#define PROP_ID_CONTENT_TYPE   0x03
#define PROP_ID_RESPONSE_TOPIC 0x08
#define PROP_ID_CORR_DATA      0x09
#define PROP_ID_SUB_ID         0x0B
#define PROP_ID_TOPIC_ALIAS    0x23
#define PROP_ID_USER_PROP      0x26

static inline int read_u16_be_ok(const uint8_t *p, uint32_t j, uint32_t len, uint16_t *out) {
    if (j + 2 > len) return 0;
    *out = (uint16_t)((p[j] << 8) | p[j+1]);
    return 1;
}

/* 解 VarInt，只需要字节数即可；value 可选 */
static inline int read_varint_ok(const uint8_t *p, uint32_t len, uint32_t j, uint32_t *value, uint32_t *used) {
    uint32_t mul = 1, v = 0, u = 0;
    while (u < 4 && j + u < len) {
        uint8_t b = p[j + u];
        v += (uint32_t)(b & 0x7F) * mul;
        u++;
        if ((b & 0x80) == 0) { if (value) *value = v; if (used) *used = u; return 1; }
        mul *= 128;
    }
    return 0;
}

void fix_publish_topic_alias(mqtt_publish_packet_t *pkts, size_t num_pkts, uint16_t connack_alias_max) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t  *props = pkt->variable_header.properties;
        uint32_t  len   = pkt->variable_header.property_len;

        uint8_t  new_props[MAX_PROPERTIES_LEN];
        uint32_t new_len = 0;

        int allow_alias = (connack_alias_max > 0);
        int seen_alias  = 0;
        int topic_empty = (pkt->variable_header.topic_name[0] == '\0');

        for (uint32_t j = 0; j < len; ) {
            if (new_len >= MAX_PROPERTIES_LEN) break; /* 防溢出 */

            uint8_t id = props[j++];
            switch (id) {
                case PROP_ID_PFI: { /* 1B 值，必须 0/1 */
                    if (j + 1 > len) { j = len; break; }
                    uint8_t v = props[j++];
                    v = (v ? 1 : 0);
                    if (new_len + 2 > MAX_PROPERTIES_LEN) break;
                    new_props[new_len++] = PROP_ID_PFI;
                    new_props[new_len++] = v;
                    break;
                }

                case PROP_ID_MEI: { /* 4B */
                    if (j + 4 > len) { j = len; break; }
                    if (new_len + 5 > MAX_PROPERTIES_LEN) break;
                    new_props[new_len++] = PROP_ID_MEI;
                    memcpy(new_props + new_len, props + j, 4);
                    new_len += 4; j += 4;
                    break;
                }

                case PROP_ID_CONTENT_TYPE: /* UTF-8: 2B len + data */
                case PROP_ID_RESPONSE_TOPIC: {
                    uint16_t n;
                    if (!read_u16_be_ok(props, j, len, &n)) { j = len; break; }
                    if (j + 2 + n > len) { j = len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = id;
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, n);
                    new_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_CORR_DATA: { /* Binary: 2B len + data */
                    uint16_t n;
                    if (!read_u16_be_ok(props, j, len, &n)) { j = len; break; }
                    if (j + 2 + n > len) { j = len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_CORR_DATA;
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, n);
                    new_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_SUB_ID: { /* VarInt（保留原值与编码） */
                    uint32_t v=0, used=0;
                    if (!read_varint_ok(props, len, j, &v, &used)) { j = len; break; }
                    if (new_len + 1 + used > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_SUB_ID;
                    memcpy(new_props + new_len, props + j, used);
                    new_len += used; j += used;
                    break;
                }

                case PROP_ID_TOPIC_ALIAS: { /* 2B */
                    if (j + 2 > len) { j = len; break; }
                    uint16_t alias = (uint16_t)((props[j] << 8) | props[j+1]);
                    j += 2;

                    if (seen_alias) {
                        /* 只保留第一条，后续丢弃 */
                        break;
                    }

                    if (!allow_alias) {
                        /* 服务器禁止别名 */
                        if (topic_empty) {
                            /* 主题为空：保留并修正到 1，避免消息整体不合法（若想严格遵守服务器限制，可选择丢弃并在上层补主题名） */
                            alias = 1;
                            if (new_len + 3 > MAX_PROPERTIES_LEN) break;
                            new_props[new_len++] = PROP_ID_TOPIC_ALIAS;
                            new_props[new_len++] = (uint8_t)(alias >> 8);
                            new_props[new_len++] = (uint8_t)(alias & 0xFF);
                            seen_alias = 1;
                        } else {
                            /* 主题非空：删除该属性 */
                        }
                        break;
                    }

                    /* 允许别名：修正到 [1, connack_alias_max] */
                    if (alias == 0) alias = 1;
                    if (alias > connack_alias_max) alias = connack_alias_max;

                    if (new_len + 3 > MAX_PROPERTIES_LEN) break;
                    new_props[new_len++] = PROP_ID_TOPIC_ALIAS;
                    new_props[new_len++] = (uint8_t)(alias >> 8);
                    new_props[new_len++] = (uint8_t)(alias & 0xFF);
                    seen_alias = 1;
                    break;
                }

                case PROP_ID_USER_PROP: { /* 0x26: key UTF-8, value UTF-8 */
                    uint16_t klen, vlen;
                    if (!read_u16_be_ok(props, j, len, &klen)) { j = len; break; }
                    if (j + 2 + klen + 2 > len) { j = len; break; }
                    if (!read_u16_be_ok(props, j + 2 + klen, len, &vlen)) { j = len; break; }
                    if (j + 2 + klen + 2 + vlen > len) { j = len; break; }

                    uint32_t need = 1 + 2 + klen + 2 + vlen;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }

                    new_props[new_len++] = PROP_ID_USER_PROP;
                    /* key */
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, klen);
                    new_len += klen;
                    /* value */
                    new_props[new_len++] = props[j + 2 + klen];
                    new_props[new_len++] = props[j + 2 + klen + 1];
                    memcpy(new_props + new_len, props + j + 2 + klen + 2, vlen);
                    new_len += vlen;

                    j += 2 + klen + 2 + vlen;
                    break;
                }

                default: {
                    /* 未知属性：保守处理 —— 直接把剩余全部原样拷贝，避免破坏 */
                    uint32_t rem = len - (j - 1); /* 包括刚读出的 id 字节 */
                    if (new_len + rem > MAX_PROPERTIES_LEN) rem = (uint32_t)(MAX_PROPERTIES_LEN - new_len);
                    if (rem > 0) {
                        memcpy(new_props + new_len, props + (j - 1), rem);
                        new_len += rem;
                    }
                    j = len; /* 结束 */
                    break;
                }
            }
        }

        /* 更新属性缓冲区与长度 */
        memcpy(pkt->variable_header.properties, new_props, new_len);
        pkt->variable_header.property_len = new_len;
    }
}


#define PROP_ID_PFI            0x01 /* Payload Format Indicator: 1B */
#define PROP_ID_MEI            0x02 /* Message Expiry Interval: 4B */
#define PROP_ID_CONTENT_TYPE   0x03 /* Content Type: UTF-8 */
#define PROP_ID_RESPONSE_TOPIC 0x08 /* Response Topic: UTF-8 */
#define PROP_ID_CORR_DATA      0x09 /* Correlation Data: Binary */
#define PROP_ID_SUB_ID         0x0B /* Subscription Identifier: VarInt */
#define PROP_ID_TOPIC_ALIAS    0x23 /* Topic Alias: 2B */
#define PROP_ID_USER_PROP      0x26 /* User Property: UTF-8 pair */

static inline int rd_u16_ok(const uint8_t *p, uint32_t j, uint32_t len, uint16_t *out) {
    if (j + 2 > len) return 0;
    *out = (uint16_t)((p[j] << 8) | p[j+1]);
    return 1;
}
static inline int rd_varint_ok(const uint8_t *p, uint32_t len, uint32_t j, uint32_t *value, uint32_t *used) {
    uint32_t mul = 1, v = 0, u = 0;
    while (u < 4 && j + u < len) {
        uint8_t b = p[j + u];
        v += (uint32_t)(b & 0x7F) * mul;
        u++;
        if ((b & 0x80) == 0) { if (value) *value = v; if (used) *used = u; return 1; }
        mul *= 128;
    }
    return 0;
}

bool contains_wildcard(const char *str, uint16_t len) { 
    for (uint16_t i = 0; i < len; ++i) 
    { 
        if (str[i] == '+' || str[i] == '#') 
            return true; 
    } 
    return false; 
}
void fix_publish_response_topic(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        const uint8_t *props = pkt->variable_header.properties;
        uint32_t len = pkt->variable_header.property_len;

        uint8_t new_props[MAX_PROPERTIES_LEN];
        uint32_t new_len = 0;

        int seen_resp_topic = 0;

        for (uint32_t j = 0; j < len; ) {
            if (new_len >= MAX_PROPERTIES_LEN) break; /* 防溢出 */

            uint8_t id = props[j++];

            switch (id) {
                case PROP_ID_PFI: { /* 1字节，值只能是0或1（宽容剪裁） */
                    if (j + 1 > len) { j = len; break; }
                    uint8_t v = props[j++];
                    v = (v ? 1 : 0);
                    if (new_len + 2 > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_PFI;
                    new_props[new_len++] = v;
                    break;
                }

                case PROP_ID_MEI: { /* 4字节 */
                    if (j + 4 > len) { j = len; break; }
                    if (new_len + 5 > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_MEI;
                    memcpy(new_props + new_len, props + j, 4);
                    new_len += 4; j += 4;
                    break;
                }

                case PROP_ID_CONTENT_TYPE: /* UTF-8: 2字节长度 + 数据 */
                {
                    uint16_t n;
                    if (!rd_u16_ok(props, j, len, &n)) { j = len; break; }
                    if (j + 2 + n > len) { j = len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_CONTENT_TYPE;
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, n);
                    new_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_RESPONSE_TOPIC: /* UTF-8: 2字节长度 + 数据 */
                {
                    uint16_t n;
                    if (!rd_u16_ok(props, j, len, &n)) { j = len; break; }
                    if (j + 2 + n > len) { j = len; break; }

                    const char *topic = (const char *)(props + j + 2);
                    int drop = 0;

                    /* 规则：不得包含通配符；若重复出现，仅保留第一条有效的 */
                    if (contains_wildcard(topic, n)) drop = 1;
                    if (seen_resp_topic) drop = 1;

                    if (!drop) {
                        uint32_t need = 1 + 2 + n;
                        if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }
                        new_props[new_len++] = PROP_ID_RESPONSE_TOPIC;
                        new_props[new_len++] = props[j];
                        new_props[new_len++] = props[j+1];
                        memcpy(new_props + new_len, topic, n);
                        new_len += n;
                        seen_resp_topic = 1;
                    }
                    j += 2 + n; /* 跳过当前 Response Topic（无论保留或删除） */
                    break;
                }

                case PROP_ID_CORR_DATA: { /* Binary: 2字节长度 + 数据 */
                    uint16_t n;
                    if (!rd_u16_ok(props, j, len, &n)) { j = len; break; }
                    if (j + 2 + n > len) { j = len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_CORR_DATA;
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, n);
                    new_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_SUB_ID: { /* VarInt：保留原始编码 */
                    uint32_t v = 0, used = 0;
                    if (!rd_varint_ok(props, len, j, &v, &used)) { j = len; break; }
                    if (new_len + 1 + used > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_SUB_ID;
                    memcpy(new_props + new_len, props + j, used);
                    new_len += used; j += used;
                    break;
                }

                case PROP_ID_TOPIC_ALIAS: { /* 2字节 */
                    if (j + 2 > len) { j = len; break; }
                    if (new_len + 3 > MAX_PROPERTIES_LEN) { j = len; break; }
                    new_props[new_len++] = PROP_ID_TOPIC_ALIAS;
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    j += 2;
                    break;
                }

                case PROP_ID_USER_PROP: { /* 0x26: key UTF-8, value UTF-8 */
                    uint16_t klen, vlen;
                    if (!rd_u16_ok(props, j, len, &klen)) { j = len; break; }
                    if (j + 2 + klen + 2 > len) { j = len; break; }
                    if (!rd_u16_ok(props, j + 2 + klen, len, &vlen)) { j = len; break; }
                    if (j + 2 + klen + 2 + vlen > len) { j = len; break; }

                    uint32_t need = 1 + 2 + klen + 2 + vlen;
                    if (new_len + need > MAX_PROPERTIES_LEN) { j = len; break; }

                    new_props[new_len++] = PROP_ID_USER_PROP;
                    /* key */
                    new_props[new_len++] = props[j];
                    new_props[new_len++] = props[j+1];
                    memcpy(new_props + new_len, props + j + 2, klen);
                    new_len += klen;
                    /* value */
                    new_props[new_len++] = props[j + 2 + klen];
                    new_props[new_len++] = props[j + 2 + klen + 1];
                    memcpy(new_props + new_len, props + j + 2 + klen + 2, vlen);
                    new_len += vlen;

                    j += 2 + klen + 2 + vlen;
                    break;
                }

                default: {
                    /* 未知属性：保守做法——把剩余原样拷贝，避免破坏 */
                    uint32_t rem = len - (j - 1);
                    if (rem > (uint32_t)(MAX_PROPERTIES_LEN - new_len))
                        rem = (uint32_t)(MAX_PROPERTIES_LEN - new_len);
                    if (rem > 0) {
                        memcpy(new_props + new_len, props + (j - 1), rem);
                        new_len += rem;
                    }
                    j = len; /* 结束循环 */
                    break;
                }
            }
        }

        /* 写回 */
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

#define PROP_ID_PFI            0x01 /* Payload Format Indicator: 1B */
#define PROP_ID_MEI            0x02 /* Message Expiry Interval: 4B */
#define PROP_ID_CONTENT_TYPE   0x03 /* Content Type: UTF-8 (2B len + data) */
#define PROP_ID_RESPONSE_TOPIC 0x08 /* Response Topic: UTF-8 (2B len + data) */
#define PROP_ID_CORR_DATA      0x09 /* Correlation Data: Binary (2B len + data) */
#define PROP_ID_SUB_ID         0x0B /* Subscription Identifier: VarInt (要删除) */
#define PROP_ID_TOPIC_ALIAS    0x23 /* Topic Alias: 2B BE */
#define PROP_ID_USER_PROP      0x26 /* User Property: UTF-8 pair (key,val) */


void fix_publish_subscription_identifier(mqtt_publish_packet_t *pkts, size_t num_pkts) {
    for (size_t i = 0; i < num_pkts; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        const uint8_t *in  = pkt->variable_header.properties;
        uint32_t in_len    = pkt->variable_header.property_len;

        uint8_t out[MAX_PROPERTIES_LEN];
        uint32_t out_len = 0;

        for (uint32_t j = 0; j < in_len; ) {
            if (out_len >= MAX_PROPERTIES_LEN) break; /* 防溢出 */
            uint8_t id = in[j++];

            switch (id) {
                case PROP_ID_PFI: { /* 1 字节，只允许 0/1，宽容剪裁 */
                    if (j + 1 > in_len) { j = in_len; break; }
                    uint8_t v = in[j++];
                    v = (v ? 1 : 0);
                    if (out_len + 2 > MAX_PROPERTIES_LEN) { j = in_len; break; }
                    out[out_len++] = PROP_ID_PFI;
                    out[out_len++] = v;
                    break;
                }

                case PROP_ID_MEI: { /* 4 字节 */
                    if (j + 4 > in_len) { j = in_len; break; }
                    if (out_len + 5 > MAX_PROPERTIES_LEN) { j = in_len; break; }
                    out[out_len++] = PROP_ID_MEI;
                    memcpy(out + out_len, in + j, 4);
                    out_len += 4; j += 4;
                    break;
                }

                case PROP_ID_CONTENT_TYPE: /* UTF-8: 2B 长度 + 数据 */
                case PROP_ID_RESPONSE_TOPIC: {
                    uint16_t n;
                    if (!rd_u16_ok(in, j, in_len, &n)) { j = in_len; break; }
                    if (j + 2 + n > in_len) { j = in_len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (out_len + need > MAX_PROPERTIES_LEN) { j = in_len; break; }
                    out[out_len++] = id;
                    out[out_len++] = in[j];
                    out[out_len++] = in[j+1];
                    memcpy(out + out_len, in + j + 2, n);
                    out_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_CORR_DATA: { /* Binary: 2B 长度 + 数据 */
                    uint16_t n;
                    if (!rd_u16_ok(in, j, in_len, &n)) { j = in_len; break; }
                    if (j + 2 + n > in_len) { j = in_len; break; }
                    uint32_t need = 1 + 2 + n;
                    if (out_len + need > MAX_PROPERTIES_LEN) { j = in_len; break; }
                    out[out_len++] = PROP_ID_CORR_DATA;
                    out[out_len++] = in[j];
                    out[out_len++] = in[j+1];
                    memcpy(out + out_len, in + j + 2, n);
                    out_len += n; j += 2 + n;
                    break;
                }

                case PROP_ID_SUB_ID: { /* 只删除，不拷贝 */
                    uint32_t v = 0, used = 0;
                    if (!rd_varint_ok(in, in_len, j, &v, &used)) { j = in_len; break; }
                    j += used; /* 跳过该属性 */
                    break;
                }

                case PROP_ID_TOPIC_ALIAS: { /* 2 字节 */
                    if (j + 2 > in_len) { j = in_len; break; }
                    if (out_len + 3 > MAX_PROPERTIES_LEN) { j = in_len; break; }
                    out[out_len++] = PROP_ID_TOPIC_ALIAS;
                    out[out_len++] = in[j];
                    out[out_len++] = in[j+1];
                    j += 2;
                    break;
                }

                case PROP_ID_USER_PROP: { /* key & value 都是 UTF-8: 2B+data, 2B+data */
                    uint16_t klen, vlen;
                    if (!rd_u16_ok(in, j, in_len, &klen)) { j = in_len; break; }
                    if (j + 2 + klen + 2 > in_len) { j = in_len; break; }
                    if (!rd_u16_ok(in, j + 2 + klen, in_len, &vlen)) { j = in_len; break; }
                    if (j + 2 + klen + 2 + vlen > in_len) { j = in_len; break; }

                    uint32_t need = 1 + 2 + klen + 2 + vlen;
                    if (out_len + need > MAX_PROPERTIES_LEN) { j = in_len; break; }

                    out[out_len++] = PROP_ID_USER_PROP;
                    /* key */
                    out[out_len++] = in[j];
                    out[out_len++] = in[j+1];
                    memcpy(out + out_len, in + j + 2, klen);
                    out_len += klen;
                    /* value */
                    out[out_len++] = in[j + 2 + klen];
                    out[out_len++] = in[j + 2 + klen + 1];
                    memcpy(out + out_len, in + j + 2 + klen + 2, vlen);
                    out_len += vlen;

                    j += 2 + klen + 2 + vlen;
                    break;
                }

                default: {
                    /* 未知属性：保守策略——把剩余原样拷贝，避免破坏 */
                    uint32_t rem = in_len - (j - 1); /* 包含 id 字节 */
                    if (rem > (uint32_t)(MAX_PROPERTIES_LEN - out_len))
                        rem = (uint32_t)(MAX_PROPERTIES_LEN - out_len);
                    if (rem > 0) {
                        memcpy(out + out_len, in + (j - 1), rem);
                        out_len += rem;
                    }
                    j = in_len; /* 结束解析 */
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

        /* 修复 remaining_length */
        size_t variable_header_len = 2 + pkt->variable_header.property_len; /* packet_identifier + properties */
        size_t payload_len = 0;

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            /* Each Topic Filter is encoded as: 2B length + bytes + 1B subscription options */
            payload_len += 2 + strlen(pkt->payload.topic_filters[j].topic_filter) + 1;
        }

        pkt->fixed_header.remaining_length = variable_header_len + payload_len;
    }
}


void fix_publish_all_length(mqtt_publish_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_publish_packet_t *pkt = &packets[i];

        // 修复 variable header 的 property_len（属性实际长度）
        // pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

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

void fix_unsubscribe_reserved_flags(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        uint8_t hdr = packets[i].fixed_header.packet_type;

        if ((hdr >> 4) == MQTT_UNSUBSCRIBE) {
            hdr = (hdr & 0xF0) | 0x02; 
            packets[i].fixed_header.packet_type = hdr;
        }
    }
}



void fix_unsubscribe_utf8_topic_filters(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        mqtt_unsubscribe_packet_t *p = &packets[i];

        uint8_t count = p->payload.topic_count;
        if (count > MAX_TOPIC_FILTERS) {
            count = MAX_TOPIC_FILTERS;
        }

        for (uint8_t j = 0; j < count; ++j) {
            sanitize_utf8_topic_filter(p->payload.topic_filters[j], MAX_TOPIC_LEN);
        }
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
        // pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

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
        // pkt->variable_header.property_len = strlen((char *)pkt->variable_header.properties);

        // 修复 remaining_length
        size_t variable_header_len = 1 + pkt->variable_header.property_len; // reason_code + properties
        pkt->fixed_header.remaining_length = variable_header_len;
    }
}


void fix_connect(mqtt_connect_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    /* MQTT-3.1.2-1: 协议名必须是 "MQTT" */
    fix_connect_protocol_name_mqtt(packets, num_packets);

    /* 原有规则：用户名 / 密码标志一致性、Will 相关规则等 */
    fix_user_name_flag(packets, num_packets);
    fix_password_flag(packets, num_packets);
    fix_connect_packet_will_rules(packets, num_packets);

    /* 最后修复长度字段，确保 remaining_length 等正确 */
    fix_connect_all_length(packets, num_packets);
}

void fix_subscribe(mqtt_subscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    /* MQTT-3.8.1-1: SUBSCRIBE 固定头低 4 bit 必须为 0x2 */
    fix_subscribe_reserved_flags(packets, num_packets);

    /* MQTT-3.8.3-2: 载荷中必须至少有一个 Topic Filter + Subscription Options 对 */
    fix_subscribe_payload_has_topic_pair(packets, num_packets);

    /* 原有：修复 no-local 等订阅选项 */
    fix_subscribe_no_local(packets, num_packets);

    /* MQTT-3.8.3-1 & MQTT-4.7.3-1/2/3: Topic Filter 为 UTF-8 字符串、非空、无 U+0000 等 */
    fix_subscribe_topic_filters_utf8(packets, num_packets);
    fix_sub_unsub_topic_filters_length_and_nul(packets, num_packets, NULL, 0);

    /* MQTT-4.8.2-1/2: 共享订阅的 Topic Filter 形如 "$share/<ShareName>/<Filter>" */
    fix_subscribe_shared_subscription_filters(packets, num_packets);

    /* 原有：修复报文标识符（唯一性等） */
    // fix_subscribe_packet_identifier(packets, num_packets);
    fix_subscribe_packet_identifier_unique(packets, num_packets);

    /* 最后统一修复长度字段 */
    fix_subscribe_all_length(packets, num_packets);
}

void fix_publish(mqtt_publish_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    /* MQTT-3.3.2-1/2 & MQTT-4.7.0-1 & MQTT-4.7.3-1/2/3:
     * - Topic Name 必须存在且为 UTF-8 字符串
     * - Topic Name 中不能包含通配符 '+' / '#'
     * - Topic Name 至少 1 字节，不含 U+0000，长度不超过实现上限
     */
    fix_publish_topic_name_utf8(packets, num_packets);
    fix_publish_topic_name_no_wildcards(packets, num_packets);
    fix_publish_topic_name_length_and_nul(packets, num_packets);

    /* 原有：修复 PUBLISH 的 packet identifier 等 */
    // fix_publish_packet_identifier(packets, num_packets);
    fix_publish_packet_identifier_unique(packets, num_packets);
    // fix_publish_dup_flag(packets, num_packets);
    // fix_publish_qos_bits(packets, num_packets);

    /* 原有：属性相关修复 Topic Alias / Response Topic / Subscription Identifier 等 */
    fix_publish_topic_alias(packets, num_packets, 65535);  // 假定 connack_alias_max = 65535
    fix_publish_response_topic(packets, num_packets);
    fix_publish_subscription_identifier(packets, num_packets);
    fix_publish_delivery_protocol(packets, num_packets);

    /* 最后修复长度字段 */
    fix_publish_all_length(packets, num_packets);

}

void fix_unsubscribe(mqtt_unsubscribe_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    /* 之前的规则：UNSUBSCRIBE 固定头低 4 bit 必须为 0x2 */
    fix_unsubscribe_reserved_flags(packets, num_packets);

    /* MQTT-3.10.3-2 / MQTT-3.10.3-1 / MQTT-4.7.3-1/2/3:
     * - 载荷中至少包含一个 Topic Filter
     * - Topic Filter 为 UTF-8 字符串、非空、无 U+0000
     */
    fix_unsubscribe_payload_has_topic_filter(packets, num_packets);
    fix_unsubscribe_utf8_topic_filters(packets, num_packets);
    fix_sub_unsub_topic_filters_length_and_nul(NULL, 0, packets, num_packets);

    /* 原有：报文标识符 + 长度字段修复 */
    fix_unsubscribe_packet_identifier(packets, num_packets);
    fix_unsubscribe_all_length(packets, num_packets);
}

void fix_auth(mqtt_auth_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

    /* MQTT-3.15.1-1: AUTH 固定头低 4 bit 必须全为 0 */
    fix_auth_reserved_flags(packets, num_packets);

    /* MQTT-3.15.2-1: Reason Code 必须是合法的 Authenticate Reason Code */
    fix_auth_reason_code_valid(packets, num_packets);

    /* 原有：修复长度字段 */
    fix_auth_all_length(packets, num_packets);
}

void fix_pubrel(mqtt_pubrel_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }
    fix_pubrel_reserved_flags(packets, num_packets);
    fix_pubrel_reason_code_valid(packets, num_packets);
}

void fix_puback(mqtt_puback_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }
    /* MQTT-3.4.2-1: PUBACK Reason Code 必须合法 */
    fix_puback_reason_code_valid(packets, num_packets);
}

void fix_pubrec(mqtt_pubrec_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

}

void fix_pubcomp(mqtt_pubcomp_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

}

void fix_pingreq(mqtt_pingreq_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }

}

void fix_disconnect(mqtt_disconnect_packet_t *packets, int num_packets) {
    if (!packets || num_packets <= 0) {
        return;
    }
    /* MQTT-3.14.2-1: DISCONNECT Reason Code 必须合法 */
    fix_disconnect_reason_code_valid(packets, num_packets);
}

void fix_mqtt(mqtt_packet_t *pkt, int num_packets) {
    if (!pkt || num_packets <= 0) {
        return;
    }

    for (int i = 0; i < num_packets; ++i) {
        switch (pkt[i].type) {
        case TYPE_CONNECT:
            // fixed_count++; // 统计修复的 CONNECT 包数量（若需要）
            fix_connect(&pkt[i].connect, 1);
            break;

        case TYPE_SUBSCRIBE:
            // fixed_count++;
            fix_subscribe(&pkt[i].subscribe, 1);
            break;

        case TYPE_PUBLISH:
            // fixed_count++;
            fix_publish(&pkt[i].publish, 1);
            break;

        case TYPE_UNSUBSCRIBE:
            // fixed_count++;
            fix_unsubscribe(&pkt[i].unsubscribe, 1);
            break;

        case TYPE_AUTH:
            // fixed_count++;
            fix_auth(&pkt[i].auth, 1);
            break;

        case TYPE_PUBREL:
            fix_pubrel(&pkt[i].pubrel, 1);
            break;

        case TYPE_PUBACK:
            fix_puback(&pkt[i].puback, 1);
            break;

        case TYPE_DISCONNECT:
            fix_disconnect(&pkt[i].disconnect, 1);
            break;

        default:

            break;
        }
    }
}
