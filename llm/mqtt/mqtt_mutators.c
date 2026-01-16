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
            case 0:  
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
            case 1:  
                mutated = (original & ~WILL_QOS_MASK) | (3 << WILL_QOS_SHIFT);
                break;
            case 2: 
                mutated = (1 << 5) | (2 << 3);  
                mutated &= ~WILL_FLAG;
                break;
            case 3: 
                mutated = original | RESERVED;
                break;
            case 4:  
                mutated = original ^ (1 << (rand() % 8));
                break;
            case 5:  
                mutated = ((original << 1) | (original >> 7)) & 0xFF;
                break;
            case 6:  
                mutated = ((original >> 1) | (original << 7)) & 0xFF;
                break;
        }

        pkts[i].variable_header.connect_flags = mutated;
        total_mutations++;
    }

}


#define MAX_KEEP_ALIVE 65535  

void mutate_connect_keep_alive(mqtt_connect_packet_t* pkts, int num_pkts) {
    int total = 0;

    for (int i = 0; i < num_pkts; i++) {
        uint16_t orig = pkts[i].variable_header.keep_alive;
        uint16_t mutated = orig;

        int weights[7] = {20, 20, 20, 20, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);

        switch (strategy) {
            case 0:
                mutated = 0;  
                break;
            case 1:
                mutated = 60; 
                break;
            case 2:
                mutated = 65535; 
                break;
            case 3:
                mutated = rand() % 10000; 
                break;
            case 4:
                mutated = orig + (rand() % 1000);  
                if (mutated > MAX_KEEP_ALIVE) mutated = MAX_KEEP_ALIVE;
                break;
            case 5:
                mutated = orig - (rand() % 1000);  
                break;
            case 6:
                mutated = rand();  
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

        pkt->variable_header.property_len = 0;
        memset(pkt->variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}


void mutate_connect_property_len(mqtt_connect_packet_t *packets, int num_packets) {
    srand(time(NULL));

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];

        if (pkt->variable_header.protocol_level != 5) {
            pkt->variable_header.property_len = 0;
            continue;
        }

        int mode = rand() % 4;

        switch (mode) {
            case 0:
                pkt->variable_header.property_len = 0;
                break;

            case 1:
                pkt->variable_header.property_len = rand() % MAX_PROPERTIES_LEN;
                for (uint32_t j = 0; j < pkt->variable_header.property_len; j++) {
                    pkt->variable_header.properties[j] = rand() % 256;
                }
                break;

            case 2:
                pkt->variable_header.property_len = MAX_PROPERTIES_LEN + 50;
                break;

            case 3:
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

    #define PID_SES_EXP   0x11  
    #define PID_RCV_MAX   0x12  
    #define PID_MAX_PKT   0x13  
    #define PID_TA_MAX    0x22  
    #define PID_REQ_RESP  0x17  
    #define PID_REQ_PROB  0x19  
    #define PID_USER_PROP 0x26  
    #define PID_AUTH_METH 0x15  
    #define PID_AUTH_DATA 0x16  

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (pkt->variable_header.protocol_level != 5) {
            pkt->variable_header.property_len = 0;
            continue;
        }

        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

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

        int used_ses=0, used_rcv=0, used_max=0, used_ta=0, used_rr=0, used_rp=0, used_am=0, used_ad=0;

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
                case 6: { // User Property 
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
            case 0: 
                cid[0] = '\0';
                break;

            case 1: {
                int len = 1 + rand() % 23;
                for (int j = 0; j < len; ++j) {
                    cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                cid[len] = '\0';
                break;
            }

            case 2: { 
                int len = 24 + rand() % 40; 
                if (len >= MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN - 1;
                for (int j = 0; j < len; ++j) {
                    cid[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                cid[len] = '\0';
                break;
            }

            case 3: { 
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

            case 4: { 
                int len = 3 + rand() % 20;
                if (len >= MAX_CLIENT_ID_LEN) len = MAX_CLIENT_ID_LEN - 1;
                for (int j = 0; j < len; ++j) {
                    cid[j] = '0' + rand() % 10;
                }
                cid[len] = '\0';
                break;
            }

            case 5: { 
                if (orig_len > 0) {
                    int flips = 1 + rand() % 3;
                    for (int f = 0; f < flips; ++f) {
                        int pos = rand() % orig_len;
                        cid[pos] ^= (1 << (rand() % 8));
                    }
                }
                break;
            }

            case 6: { 
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

            case 7: { 
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
            case 0: 
                packets[i].payload.will_property_len = rand() % MAX_PROPERTIES_LEN;
                for (uint32_t j = 0; j < packets[i].payload.will_property_len; ++j) {
                    packets[i].payload.will_properties[j] = rand() % 256;
                }
                break;

            case 1:
                packets[i].payload.will_property_len = MAX_PROPERTIES_LEN + rand() % 128;
                break;

            case 2: 
                packets[i].variable_header.connect_flags &= ~(1 << 2); 
                packets[i].payload.will_property_len = rand() % 10 + 1;
                for (uint32_t j = 0; j < packets[i].payload.will_property_len; ++j) {
                    packets[i].payload.will_properties[j] = rand() % 256;
                }
                break;

            case 3: 
                packets[i].payload.will_property_len = 2;
                for (uint32_t j = 0; j < 10; ++j) {
                    packets[i].payload.will_properties[j] = 0xEE;
                }
                break;

            case 4:
                packets[i].payload.will_property_len = 0;
                memset(packets[i].payload.will_properties, 0, MAX_PROPERTIES_LEN);
                break;
        }
    }
}

void add_connect_will_properties(mqtt_connect_packet_t *packets, int num_packets) {

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
            case 0: 
                PUT8(PID_PFI); PUT8(1);
                break;
            case 1: 
                PUT8(PID_MEI); PUT32((uint32_t)(rand() % 3601));
                break;
            case 2: 
                PUT8(PID_WDI); PUT32((uint32_t)(rand() % 601));
                break;
            case 3: 
                PUT8(PID_CT); PUT_UTF8_LIT("text/plain");
                break;
            case 4:
                PUT8(PID_RT); PUT_UTF8_LIT("reply/topic");
                break;
            case 5: 
                PUT8(PID_CD); PUT_BIN_RAND(8, 24);
                break;
        }

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

            case 0: { 
                pkt->payload.will_property_len = 3;
                props[0] = legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                props[1] = 0x00;
                props[2] = rand() % 256;
                break;
            }

            case 1: {
                int count = 2 + rand() % 4; 
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

            case 2: { 
                int len = 3 + rand() % 5;
                for (int j = 0; j < len; ++j) {
                    props[j] = (rand() % 2) ? 0xFF : legal_will_prop_ids[rand() % LEGAL_WILL_PROP_IDS_LEN];
                }
                pkt->payload.will_property_len = len;
                break;
            }

            case 3: { 
                pkt->payload.will_property_len = MAX_PROPERTIES_LEN;
                for (int j = 0; j < MAX_PROPERTIES_LEN; ++j) {
                    props[j] = rand() % 256;
                }
                break;
            }

            case 4: {
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

            case 5: { 
                int len = 2 + rand() % 10;
                memset(props, 0x00, len);
                pkt->payload.will_property_len = len;
                break;
            }

            case 6: {
                int len = 2 + rand() % 10;
                memset(props, 0xFF, len);
                pkt->payload.will_property_len = len;
                break;
            }

            case 7: { 
                int len = 5 + rand() % 10;
                for (int j = 0; j < len; ++j) {
                    props[j] = rand() % 256;
                    if (rand() % 3 == 0) {
                        props[j] ^= (1 << (rand() % 8));
                    }
                }
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
        "",               
        "/",              
        "home/sensor",    
        "+/#",            
        "#/invalid",      
        "topic\x00mid",   
        "\xC3\x28",       
        "\xFF\xFF\xFF",   
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

                const char *mutation = base_topics[rand() % total_base];
                strncpy(topic, mutation, MAX_TOPIC_LEN - 1);
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            }

            case 1: {
                int len = 1 + rand() % (MAX_TOPIC_LEN - 2);
                for (int j = 0; j < len; ++j) {
                    topic[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                topic[len] = '\0';
                break;
            }

            case 2: {
                int len = MAX_TOPIC_LEN - 1 + rand() % 20;
                for (int j = 0; j < len && j < MAX_TOPIC_LEN - 1; ++j) {
                    topic[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            }

            case 3: {
                int len = 0;
                const char *prefix = base_topics[rand() % total_base];
                strncpy(topic, prefix, MAX_TOPIC_LEN - 1);
                len = strlen(topic);
                if (len < MAX_TOPIC_LEN - 1) {
                    int remain = (MAX_TOPIC_LEN - 1) - len;
                    for (int j = 0; j < remain; ++j) {
                        topic[len + j] = '\xFF'; 
                    }
                    topic[MAX_TOPIC_LEN - 1] = '\0';
                }
                break;
            }

            case 4: {
                int len = 1 + rand() % (MAX_TOPIC_LEN - 2);
                for (int j = 0; j < len; ++j) {
                    if (rand() % 4 == 0) {
                        topic[j] = '#';  
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

        if (!(packets[i].variable_header.connect_flags & 0x04)) continue; 

        int weights[7] = {70, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);
        uint8_t *payload = packets[i].payload.will_payload;
        uint16_t *len = &packets[i].payload.will_payload_len;

        switch (strategy) {

            case 0: { 
                int l = 5 + rand() % 20;
                for (int j = 0; j < l; ++j) {
                    payload[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                *len = l;
                break;
            }

            case 1: {
                int l = 1 + rand() % 64;
                for (int j = 0; j < l; ++j) {
                    payload[j] = rand() % 256;
                }
                *len = l;
                break;
            }

            case 2: { 
                *len = 0;
                break;
            }

            case 3: { 
                int l = MAX_PAYLOAD_LEN;
                for (int j = 0; j < l; ++j) {
                    payload[j] = rand() % 256;
                }
                *len = l;
                break;
            }

            case 4: { 
                int l = 5 + rand() % 10;
                for (int j = 0; j < l; ++j) {
                    payload[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                int pos = rand() % l;
                payload[pos] = '\0'; 
                *len = l;
                break;
            }

            case 5: { 
                uint8_t invalid_utf8[] = {0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x28, 0xA1};
                int l = sizeof(invalid_utf8);
                memcpy(payload, invalid_utf8, l);
                *len = l;
                break;
            }

            case 6: { 
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
            case 0: 
                pkt->payload.will_payload_len = strlen((char *)pkt->payload.will_payload);
                break;
            case 1:  
                pkt->payload.will_payload_len = MAX_PAYLOAD_LEN + rand() % 100;
                break;
            case 2:  
                if (strlen((char *)pkt->payload.will_payload) > 2)
                    pkt->payload.will_payload_len = rand() % 2;
                else
                    pkt->payload.will_payload_len = 0;
                break;
            case 3: 
                pkt->payload.will_payload_len = 0;
                break;
            case 4: 
                pkt->payload.will_payload_len = rand() % 0xFFFF;
                break;
        }
    }
}

void add_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        if (!(pkt->variable_header.connect_flags & 0x80)) {
            pkt->variable_header.connect_flags |= 0x80; 
            snprintf(pkt->payload.user_name, MAX_CLIENT_ID_LEN, "user_%d", rand());
        }
    }
}

void delete_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        pkt->variable_header.connect_flags &= ~(0x80);  
        memset(pkt->payload.user_name, 0, MAX_CLIENT_ID_LEN);
    }
}

void mutate_connect_user_name(mqtt_connect_packet_t *packets, int num_packets) {
    static const char *special_cases[] = {
        "",                              
        "admin",                         
        "root",                          
        "user!@#$%^&*()",                
        "A_very_very_long_username_string_that_may_overflow_the_buffer_lol",
        "\xFF\xFE\xFD",                 
        NULL
    };

    static const char valid_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#";

    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];


        if (!(pkt->variable_header.connect_flags & 0x80)) continue;

        int weights[7] = {70, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 7);

        switch (strategy) {

            case 0: {  
                int len = 5 + rand() % 20;
                for (int j = 0; j < len; ++j) {
                    pkt->payload.user_name[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                pkt->payload.user_name[len] = '\0';
                break;
            }

            case 1: {  
                const char *src = special_cases[rand() % 5];
                strncpy(pkt->payload.user_name, src, MAX_CLIENT_ID_LEN - 1);
                pkt->payload.user_name[MAX_CLIENT_ID_LEN - 1] = '\0';
                break;
            }

            case 2: {  
                uint8_t garbage[] = { 0xC3, 0x28, 0xA0, 0xA1, 0xFF, 0xFE };
                int l = sizeof(garbage);
                memcpy(pkt->payload.user_name, garbage, l);
                pkt->payload.user_name[l] = '\0';
                break;
            }

            case 3: {  
                memset(pkt->payload.user_name, 'A', MAX_CLIENT_ID_LEN);
                break;
            }

            case 4: {  
                pkt->payload.user_name[0] = '\0';
                break;
            }

            case 5: { 
                int l = 5 + rand() % 10;
                for (int j = 0; j < l; ++j) {
                    pkt->payload.user_name[j] = valid_chars[rand() % (sizeof(valid_chars) - 1)];
                }
                int pos = rand() % l;
                pkt->payload.user_name[pos] = '\0'; 
                break;
            }

            case 6: {  
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
            pkt->variable_header.connect_flags |= 0x40;  
            const char *sample = "secret_pass";
            memcpy(pkt->payload.password, sample, strlen(sample));
            pkt->payload.password_len = strlen(sample);
        }
    }
}

void delete_connect_password(mqtt_connect_packet_t *packets, int num_packets) {
    for (int i = 0; i < num_packets; ++i) {
        mqtt_connect_packet_t *pkt = &packets[i];
        pkt->variable_header.connect_flags &= ~(0x40); 
        memset(pkt->payload.password, 0, MAX_CLIENT_ID_LEN);
        pkt->payload.password_len = 0;
    }
}

void mutate_connect_password(mqtt_connect_packet_t *packets, int num_packets) {

    static const char *common_passwords[] = {
        "",                    
        "123456",              
        "password",            
        "pass!@#$_",           
        "admin123",            
        "\x00\x01\xFF\xFE",    
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        NULL
    };

    for (int i = 0; i < num_packets; ++i) {

        mqtt_connect_packet_t *pkt = &packets[i];

        if (!(pkt->variable_header.connect_flags & 0x40)) continue;

        int weights[8] = {70, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 8);

        switch (strategy) {

            case 0: { 
                const char *src = common_passwords[rand() % 5];
                pkt->payload.password_len = strlen(src);
                memcpy(pkt->payload.password, src, pkt->payload.password_len);
                break;
            }

            case 1: { 
                pkt->payload.password_len = 0;
                break;
            }

            case 2: { 
                uint8_t garbage[] = { 0x00, 0xFF, 0xAA, 0x55 };
                memcpy(pkt->payload.password, garbage, sizeof(garbage));
                pkt->payload.password_len = sizeof(garbage);
                break;
            }

            case 3: { 
                pkt->payload.password_len = rand() % (MAX_CLIENT_ID_LEN);
                for (int j = 0; j < pkt->payload.password_len; ++j) {
                    pkt->payload.password[j] = rand() % 256;
                }
                break;
            }

            case 4: {
                pkt->payload.password_len = MAX_CLIENT_ID_LEN;
                memset(pkt->payload.password, 'A', pkt->payload.password_len);
                break;
            }

            case 5: { 
                uint8_t bad_utf8[] = { 0xC3, 0x28, 0xA0, 0xA1 };
                memcpy(pkt->payload.password, bad_utf8, sizeof(bad_utf8));
                pkt->payload.password_len = sizeof(bad_utf8);
                break;
            }

            case 6: { 
                int len = 5 + rand() % 10;
                for (int j = 0; j < len; ++j) {
                    pkt->payload.password[j] = 'a' + (rand() % 26);
                }
                int pos = rand() % len;
                pkt->payload.password[pos] = '\0'; 
                pkt->payload.password_len = len;
                break;
            }

            case 7: { 
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
            case 0:  
                pkt->payload.password_len = strlen((char *)pkt->payload.password);
                break;
            case 1:  
                pkt->payload.password_len = MAX_CLIENT_ID_LEN + 10;
                break;
            case 2:  
                pkt->payload.password_len = 0;
                break;
            case 3:  
                pkt->payload.password_len = rand() % 5;
                break;
            case 4:  
                pkt->payload.password_len = rand() % 70000;  
                break;
            case 5:  
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
            case 0: 
                mutated = 0;
                break;
            case 1: 
                mutated = 65535;
                break;
            case 2: 
                mutated = 1;
                break;
            case 3: 
                mutated = (uint16_t)(rand() % 65536);
                break;
            case 4: 
                mutated = 0xFF00 | (rand() & 0x00FF);
                break;
            case 5: 
                mutated = original ^ (1 << (rand() % 16));
                break;
            case 6: 
                mutated = original + 1;
                break;
            case 7: 
                mutated = original - 1;
                break;
            case 8: 
                if (i > 0)
                    mutated = subs[i - 1].variable_header.packet_identifier;
                break;
            case 9: 
                mutated = 0x8000;
                break;
        }

        pkt->variable_header.packet_identifier = mutated;
    }
}

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
    return r - pos; 
}


void mutate_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *props = pkt->variable_header.properties;
        uint32_t pos = 0;

        if (rand() % 2) {
            uint8_t tmp[4];
            uint32_t sid = 1u + (rand() % 16383u);
            if (!ensure_space(pos, 1, MAX_PROPERTIES_LEN)) goto done;
            props[pos++] = 0x0B; /* Subscription Identifier */
            size_t vn = write_varint(tmp, sid);
            if (!ensure_space(pos, (uint32_t)vn, MAX_PROPERTIES_LEN)) goto done;
            memcpy(props + pos, tmp, vn); pos += (uint32_t)vn;
        }

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
        pkt->variable_header.property_len = pos; 
    }
}

void add_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        int has_sid = 0;
        for (uint32_t j = 0; j < plen; ) {
            if (p[j] == 0x0B) { has_sid = 1; break; }
            else if (p[j] == 0x26) {
                uint32_t step = peek_user_property_len(p, plen, j);
                if (step == 0) { has_sid = 1; break; }
                j += step;
            } else {
                has_sid = 1; break; 
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


void repeat_subscribe_properties(mqtt_subscribe_packet_t *subs, size_t num_subs) {
    if (!subs) return;

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        uint32_t up_pos = 0, up_len = 0, j = 0;
        while (j < plen) {
            if (p[j] == 0x26) {
                uint32_t step = peek_user_property_len(p, plen, j);
                if (step == 0) break; 
                up_pos = j; up_len = step; break;
            } else if (p[j] == 0x0B) {
                uint32_t k = j + 1, mul = 1, count = 0;
                while (k < plen && count < 4) {
                    uint8_t b = p[k++]; count++;
                    if (!(b & 0x80)) break;
                }
                j = k;
            } else {
                up_len = 0; break;
            }
        }

        if (up_len == 0) continue; 

        if (ensure_space(plen, up_len, MAX_PROPERTIES_LEN)) {
            memcpy(p + plen, p + up_pos, up_len);
            pkt->variable_header.property_len = plen + up_len;
        }
    }
}


void mutate_subscribe_topic_filter(mqtt_subscribe_packet_t *subs, size_t num_subs) {

    static const char *legal_wildcards[] = {
        "#",                 
        "+",                 
        "+/+",               
        "devices/+/status",  
        "sensor/#"           
    };
    enum { LEGAL_WC_COUNT = (int)(sizeof(legal_wildcards)/sizeof(legal_wildcards[0])) };

    static const char legal_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

    for (size_t i = 0; i < num_subs; ++i) {
        mqtt_subscribe_packet_t *pkt = &subs[i];

        for (int j = 0; j < pkt->payload.topic_count; ++j) {
            char *filter = pkt->payload.topic_filters[j].topic_filter;

            int weights[6] = {20, 20, 20, 20, 10, 10};
            int strategy = pick_weighted(weights, 6);

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

            filter[0] = '\0'; 

            switch (strategy) {
                case 0: { 
                    APPEND_STR(legal_wildcards[rand() % LEGAL_WC_COUNT]);
                    break;
                }

                case 1: { 
                    int levels = 1 + rand() % 4;
                    for (int l = 0; l < levels; ++l) {
                        if (l) APPEND_CHAR('/');
                        APPEND_LEVEL_FROM_SET();
                    }
                    if (pos == 0) { APPEND_CHAR('a'); } 
                    break;
                }

                case 2: { 
                    int levels = 2 + rand() % 3;           
                    int plus_cnt = 1 + rand() % 2;         
                    int plus_at[2] = {-1, -1};
                    for (int p = 0; p < plus_cnt; ++p) {
                        int idx;
                        do { idx = rand() % levels; } while ((p == 1 && idx == plus_at[0]));
                        plus_at[p] = idx;
                    }
                    for (int l = 0; l < levels; ++l) {
                        if (l) APPEND_CHAR('/');
                        if (l == plus_at[0] || l == plus_at[1]) {
                            APPEND_CHAR('+');         
                        } else {
                            APPEND_LEVEL_FROM_SET();
                        }
                    }
                    break;
                }

                case 3: { 
                    int levels = rand() % 4; // 0..3
                    if (levels == 0) {
                        APPEND_CHAR('#');              
                    } else {
                        for (int l = 0; l < levels; ++l) {
                            if (l) APPEND_CHAR('/');
                            APPEND_LEVEL_FROM_SET();
                        }
                        APPEND_CHAR('/'); APPEND_CHAR('#'); 
                    }
                    break;
                }

                case 4: { 
                    while (pos < MAX_TOPIC_LEN - 1) {
                        int left = (MAX_TOPIC_LEN - 1) - pos;
                        if (left <= 5) { 
                            break;
                        }
                        if (pos) APPEND_CHAR('/');
                        int seg = 4 + rand() % 8; 
                        for (int s = 0; s < seg && pos < MAX_TOPIC_LEN - 1; ++s) APPEND_CHAR('a' + (rand() % 26));
                    }
                    if (pos > 0 && filter[pos-1] == '/') { filter[--pos] = '\0'; }
                    if (pos == 0) { APPEND_CHAR('a'); }    
                }

                case 5: { 
                    if (j > 0) {
                        strncpy(filter, pkt->payload.topic_filters[j - 1].topic_filter, MAX_TOPIC_LEN - 1);
                        filter[MAX_TOPIC_LEN - 1] = '\0';
                    } else {
                        APPEND_STR("sensor/#");
                    }
                    break;
                }
            }


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

        int repeat_index = rand() % pkt->payload.topic_count;
        int new_index = pkt->payload.topic_count;

        memcpy(&pkt->payload.topic_filters[new_index],
               &pkt->payload.topic_filters[repeat_index],
               sizeof(pkt->payload.topic_filters[0]));

        if (rand() % 2 == 0) {  
            pkt->payload.topic_filters[new_index].qos = rand() % 3; 
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
                case 0: 
                    *qos = 0;
                    break;
                case 1: 
                    *qos = 1;
                    break;
                case 2: 
                    *qos = 2;
                    break;
                case 3: 
                    *qos = 3;
                    break;
                case 4: 
                    *qos = 255;
                    break;
                case 5: 
                    *qos = rand() % 3;
                    break;
                case 6:
                    *qos = 3 + rand() % 252;
                    break;
                case 7: 
                    *qos ^= (1 << (rand() % 3));
                    break;
                case 8: 
                    if (j > 0) *qos = pkt->payload.topic_filters[j - 1].qos;
                    break;
                case 9: 
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
            case 0: 
                *count = 0;
                break;
            case 1: 
                *count = MAX_TOPIC_FILTERS;
                break;
            case 2: 
                *count = MAX_TOPIC_FILTERS + 1;
                break;
            case 3: 
                *count = 1;
                break;
            case 4: 
                *count = 1 + rand() % MAX_TOPIC_FILTERS;
                break;
            case 5: 
                *count = MAX_TOPIC_FILTERS + 2 + rand() % (255 - MAX_TOPIC_FILTERS - 2);
                break;
            case 6: 
                *count = (*count) * 2;
                break;
            case 7: 
                *count = ~(*count);
                break;
            case 8:
                *count ^= 0x01;
                break;
            case 9:
                if (i > 0) *count = subs[i - 1].payload.topic_count;
                break;
        }

        if (*count > MAX_TOPIC_FILTERS)
            *count = MAX_TOPIC_FILTERS;

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
            case 0:  
                topic[0] = '\0';
                break;
            case 1:  
                strcpy(topic, "+");
                break;
            case 2:  
                strcpy(topic, "#");
                break;
            case 3:  
                strcpy(topic, "invalid/#/test#");
                break;
            case 4:  
                memset(topic, 'A', MAX_TOPIC_LEN + 10);
                topic[MAX_TOPIC_LEN + 9] = '\0';
                break;
            case 5: 
                strcpy(topic, "sensor/+/temperature");
                break;
            case 6:  
                for (int j = 0; j < MAX_TOPIC_LEN - 1; j++)
                    topic[j] = (char)(rand() % 256);
                topic[MAX_TOPIC_LEN - 1] = '\0';
                break;
            case 7: 
                strcpy(topic, "home/kitchen/light");
                break;
            case 8: 
                strcpy(topic, "topic/!@#$%^&*()");
                break;
            case 9: 
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
            pkts[i].variable_header.packet_identifier = 0;
        }
    }
}

void mutate_publish_packet_identifier(mqtt_publish_packet_t *pkts, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];

        uint16_t *id = &pkt->variable_header.packet_identifier;
        int weights[10] = {0, 40, 40, 40, 0, 40, 40, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
            case 0: *id = 0; break;                     
            case 1: *id = 1; break;                     
            case 2: *id = 0xFFFF; break;                
            case 3: *id = rand() % 0xFFFF; break;       
            case 4: *id = rand(); break;                
            case 5: *id = 0x7FFF; break;                
            case 6: *id = 0x8000; break;                
            case 7: *id ^= 0xAAAA; break;               
            case 8: *id = (uint16_t)(~(*id)); break;    
            case 9: *id = *id + 1; break;               
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

void add_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.property_len != 0) continue;

        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

        int strategy = rand() % 5;
        switch (strategy) {
            case 0: { /* PFI=1 */
                if (!pp_ensure(pos, 2, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x01;        /* PFI */
                buf[pos++] = 0x01;       
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
            case 4: { 
                const char *k="key", *v="value";
                uint16_t klen=(uint16_t)strlen(k), vlen=(uint16_t)strlen(v);
                if (!pp_ensure(pos, 1+2+klen+2+vlen, MAX_PROPERTIES_LEN)) break;
                buf[pos++] = 0x26;
                pp_put16(buf+pos, klen); pos += 2; memcpy(buf+pos, k, klen); pos += klen;
                pp_put16(buf+pos, vlen); pos += 2; memcpy(buf+pos, v, vlen); pos += vlen;
                break;
            }
        }

        pkt->variable_header.property_len = pos; 
    }
}

void delete_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;
    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        pkt->variable_header.property_len = 0;
        memset(pkt->variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

void repeat_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

        uint32_t up_pos = 0, up_len = 0;
        for (uint32_t j = 0; j < plen; ) {
            uint8_t id = p[j];
            if (id == 0x26) {
                uint32_t L = peek_publish_user_property_len(p, plen, j);
                if (L == 0) break;
                up_pos = j; up_len = L; break;
            }
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
                up_len = 0; break;
            }
        }

        if (up_len == 0) continue;              
        if (!pp_ensure(plen, up_len, MAX_PROPERTIES_LEN)) continue;

        memcpy(p + plen, p + up_pos, up_len);
        pkt->variable_header.property_len = plen + up_len;
    }
}

void mutate_publish_properties(mqtt_publish_packet_t *pkts, size_t num) {
    if (!pkts) return;

    for (size_t i = 0; i < num; ++i) {
        mqtt_publish_packet_t *pkt = &pkts[i];
        uint8_t *buf = pkt->variable_header.properties;
        uint32_t pos = 0;

        int used_pfi=0, used_mei=0, used_ct=0, used_rt=0, used_cd=0, used_ta=0;

        int strategy = rand() % 6;

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
            case 0:
                break;

            case 1: 
            {
                if (!used_pfi) { PUT8(0x01); PUT8(1); used_pfi=1; }
                if ((rand()%2) && !used_ct) {
                    uint8_t cur_id = 0x03; (void)cur_id;
                    PUT_UTF8("text/plain"); used_ct=1;
                }
                break;
            }

            case 2: 
            {
                if (!used_mei) { PUT8(0x02); PUT32((uint32_t)(rand()%7200)); used_mei=1; }
                if ((rand()%2) && !used_pfi) { PUT8(0x01); PUT8(rand()%2); used_pfi=1; }
                break;
            }

            case 3: 
            {
                if (!used_ta) { PUT8(0x23); PUT16((uint16_t)(1 + rand()%100)); used_ta=1; }
                if ((rand()%2) && !used_rt) {
                    uint8_t cur_id = 0x08; (void)cur_id;
                    PUT_UTF8("reply/topic"); used_rt=1;
                }
                break;
            }

            case 4: 
            {
                if (!used_rt) { uint8_t cur_id = 0x08; (void)cur_id; PUT_UTF8("reply/topic"); used_rt=1; }
                if (!used_cd) {
                    uint8_t tmp[24]; int L = 8 + rand()%17;
                    for (int k=0;k<L;k++) tmp[k]=(uint8_t)rand();
                    PUT_BIN(tmp, L); used_cd=1;
                }
                break;
            }

            case 5: 
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
            case 0:
                *len = 0;
                break;
            case 1: 
                for (int j = 0; j < MAX_PAYLOAD_LEN; ++j) p[j] = 'A';
                *len = MAX_PAYLOAD_LEN;
                break;
            case 2: 
                *len = rand() % MAX_PAYLOAD_LEN;
                for (uint32_t j = 0; j < *len; ++j) p[j] = rand() % 256;
                break;
            case 3: 
                *len = snprintf((char *)p, MAX_PAYLOAD_LEN, "msg_%d", rand() % 1000);
                break;
            case 4:
                *len = 16;
                for (int j = 0; j < 16; ++j) p[j] = 0xFF;
                break;
            case 5: 
                *len = snprintf((char *)p, MAX_PAYLOAD_LEN, "{\"key\":\"val%d\"}", rand() % 100);
                break;
            case 6:
                *len = MAX_PAYLOAD_LEN + 100;
                break;
            case 7:
                p[0] = 0xC0; p[1] = 0x00;
                *len = 2;
                break;
            case 8: 
                *len = strlen(pkt->variable_header.topic_name);
                memcpy(p, pkt->variable_header.topic_name, *len);
                break;
            case 9: 
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
            case 0: *qos = 0; break;              
            case 1: *qos = 1; break;              
            case 2: *qos = 2; break;              
            case 3: *qos = 3; break;             
            case 4: *qos = 255; break;            
            case 5: *qos = rand() % 256; break;   
            case 6: *qos = (*qos + 1) % 4; break; 
            case 7: *qos = 0xFF & ~(*qos); break; 
            case 8: *qos = (rand() % 10 == 0) ? 4 : 2; break; 
            case 9: *qos = 0xAA; break;          
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
            case 0: *dup = 0; break;                 
            case 1: *dup = 1; break;                 
            case 2: *dup = (*dup == 0) ? 1 : 0; break; 
            case 3: *dup = 2; break;                
            case 4: *dup = 255; break;              
            case 5: *dup = rand() % 256; break;     
            case 6: *dup ^= 0x01; break;            
            case 7: *dup = 0xAA; break;             
            case 8: *dup = (rand() % 2) ? 0x00 : 0x01; break; 
            case 9: *dup = (*dup + rand() % 3) & 0xFF; break; 
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
            case 0: *retain = 0; break;                
            case 1: *retain = 1; break;                
            case 2: *retain ^= 0x01; break;            
            case 3: *retain = 2; break;                
            case 4: *retain = 255; break;              
            case 5: *retain = rand() % 256; break;     
            case 6: *retain = 0xFF; break;             
            case 7: *retain = (pkt->qos == 0) ? 1 : 0; break; 
            case 8: *retain = (*retain + 1) & 0xFF; break;     
            case 9: *retain = (rand() % 2) * 3; break;  
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
            case 0: *id = 0x0001; break;                         
            case 1: *id = 0xFFFF; break;                         
            case 2: *id = 0x0000; break;                         
            case 3: *id ^= 0xFFFF; break;                        
            case 4: *id = ((*id & 0xFF) << 8) | (*id >> 8); break; 
            case 5: *id = rand() % 0xFFFF; break;                
            case 6: *id = 0x1234; break;                         
            case 7: *id = *id; break;                            
            case 8: *id = 0xABCD; break;                         
            case 9: *id = 0xFFFF + rand() % 100; break;          
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
    return r - pos; 
}


void add_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    static const char *def_key = "key";
    static const char *def_val = "value";

    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i]; 

        if (pkt->variable_header.property_len != 0) continue;   

        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;
        uint16_t klen = (uint16_t)strlen(def_key);
        uint16_t vlen = (uint16_t)strlen(def_val);

        if (!uprop_ensure(pos, 1 + 2 + klen + 2 + vlen)) {
            pkt->variable_header.property_len = 0; 
            continue;
        }

        p[pos++] = 0x26;                               /* User Property */
        uprop_put16(p + pos, klen); pos += 2; memcpy(p + pos, def_key, klen); pos += klen;
        uprop_put16(p + pos, vlen); pos += 2; memcpy(p + pos, def_val, vlen); pos += vlen;

        pkt->variable_header.property_len = pos;
    }
}


void delete_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        pkts[i].variable_header.property_len = 0;
        memset(pkts[i].variable_header.properties, 0, MAX_PROPERTIES_LEN);
    }
}

void repeat_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;


        uint32_t up_pos = 0, up_len = 0;
        for (uint32_t j = 0; j < plen; ) {
            if (p[j] == 0x26) {
                uint32_t L = peek_unsub_user_property_len(p, plen, j);
                if (L == 0) break;        
                up_pos = j; up_len = L;
                break;
            } else {
                up_len = 0; break;
            }
        }
        if (up_len == 0) continue;
        if (!uprop_ensure(plen, up_len)) continue;

        memcpy(p + plen, p + up_pos, up_len);
        pkt->variable_header.property_len = plen + up_len;
    }
}

void mutate_unsubscribe_properties(mqtt_unsubscribe_packet_t *pkts, int num) {
    static const char *keys[] = {"source","priority","note","device","region"};
    static const char *vals[] = {"sensor1","high","ok","edge","cn-north"};

    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;

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

        pkt->variable_header.property_len = pos;  
    }
}


void repeat_unsubscribe_topic_filters(mqtt_unsubscribe_packet_t *pkts, int num) {
    for (int i = 0; i < num; ++i) {
        mqtt_unsubscribe_packet_t *pkt = &pkts[i];
        if (pkt->payload.topic_count < MAX_TOPIC_FILTERS) {
            strcpy(pkt->payload.topic_filters[pkt->payload.topic_count],
                   pkt->payload.topic_filters[0]); 
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
            case 0:  
                pkt->payload.topic_count = 0;
                break;
            case 1:  
                if (count < MAX_TOPIC_FILTERS) {
                    pkt->payload.topic_filters[count][0] = '\0';
                    pkt->payload.topic_count++;
                }
                break;
            case 2:  
                if (count < MAX_TOPIC_FILTERS) {
                    memset(pkt->payload.topic_filters[count], 'A', MAX_TOPIC_LEN - 1);
                    pkt->payload.topic_filters[count][MAX_TOPIC_LEN - 1] = '\0';
                    pkt->payload.topic_count++;
                }
                break;
            case 3:  
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "\x01\x02#");
                    pkt->payload.topic_count++;
                }
                break;
            case 4: 
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "sensor/#");
                    pkt->payload.topic_count++;
                }
                break;
            case 5: 
                repeat_unsubscribe_topic_filters(&pkts[i], 1);
                break;
            case 6:  
                if (count > 0) {
                    int idx = rand() % count;
                    for (int j = 0; j < 10; ++j)
                        pkt->payload.topic_filters[idx][j] = rand() % 256;
                    pkt->payload.topic_filters[idx][10] = '\0';
                }
                break;
            case 7: 
                pkt->payload.topic_count = MAX_TOPIC_FILTERS + 10;
                break;
            case 8: 
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "\xC0\xC0");
                    pkt->payload.topic_count++;
                }
                break;
            case 9:  
                if (count < MAX_TOPIC_FILTERS) {
                    strcpy(pkt->payload.topic_filters[count], "foo/#/bar"); 
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
            pkt->variable_header.reason_code = 0x00;  
            pkt->fixed_header.remaining_length += 1;
        }
    }
}

void delete_auth_reason_code(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        if (pkt->fixed_header.remaining_length >= 1) {
            pkt->variable_header.reason_code = 0;  
            pkt->fixed_header.remaining_length -= 1;
        }
    }
}


void mutate_auth_reason_code(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];

        if (pkt->fixed_header.remaining_length < 1) continue;

        uint8_t *rc = &pkt->variable_header.reason_code;
        int weights[10] = { 50, 50, 50, 0, 0, 0, 0, 0, 0, 0}; 
        int strategy = pick_weighted(weights, 10);
        switch (strategy) {
            case 0: *rc = 0x00; break;                  
            case 1: *rc = 0x18; break;                  
            case 2: *rc = 0x19; break;                  
            case 3: *rc = 0xFF; break;                  
            case 4: *rc = 0x7F; break;                  
            case 5: *rc = 0x80; break;                  
            case 6: *rc = rand() % 256; break;          
            case 7: *rc = 0x01; break;                  
            case 8: *rc = 0xFE; break;                  
            case 9: *rc = 0x10; break;                  
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

static inline uint32_t varint_size(uint32_t v) {
    if (v < 128u) return 1;
    if (v < 16384u) return 2;
    if (v < 2097152u) return 3;
    return 4;
}

static inline void auth_recalc_remaining_length(mqtt_auth_packet_t *pkt) {
    uint32_t L = pkt->variable_header.property_len;
    pkt->fixed_header.remaining_length = 1u + varint_size(L) + L;
}


void add_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        if (pkt->variable_header.property_len != 0) { 
            auth_recalc_remaining_length(pkt);
            continue;
        }

        uint8_t *p = pkt->variable_header.properties;
        uint32_t pos = 0;

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

void repeat_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        uint8_t *p = pkt->variable_header.properties;
        uint32_t plen = pkt->variable_header.property_len;

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


void mutate_auth_properties(mqtt_auth_packet_t *pkts, int num) {
    static const char *methods[] = {"PLAIN", "SCRAM-SHA-256"};
    static const char *reasons[] = {"ok", "continue", "reauth"};
    static const char *keys[]    = {"source","priority","note","device"};
    static const char *vals[]    = {"client","high","ok","edge"};

    for (int i = 0; i < num; i++) {
        mqtt_auth_packet_t *pkt = &pkts[i];
        uint8_t *p  = pkt->variable_header.properties;
        uint32_t pos = 0;

        int used_method = 0, used_data = 0, used_reason = 0;

        int strategy = rand() % 6;
        switch (strategy) {
            case 0:
                break;

            case 1: 
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
                uint16_t dl = (uint16_t)(8 + rand() % 9); 
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

            case 4: 
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

            case 5: 
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

                if (used_method && (rand() % 2) && !used_data) {
                    uint16_t dl = (uint16_t)(6 + rand() % 11); /* 6..16 */
                    if (a_ensure(pos, 1 + 2 + dl)) {
                        p[pos++] = 0x16; a_put16(p + pos, dl); pos += 2;
                        for (uint16_t k = 0; k < dl; ++k) p[pos + k] = (uint8_t)rand();
                        pos += dl; used_data = 1;
                    }
                }
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



typedef void (*connect_mutator_fn)(mqtt_connect_packet_t *pkt, int num_packets);
typedef void (*subscribe_mutator_fn)(mqtt_subscribe_packet_t *pkt, int num_packets);
typedef void (*publish_mutator_fn)(mqtt_publish_packet_t *pkt, int num_packets);
typedef void (*auth_mutator_fn)(mqtt_auth_packet_t *pkt, int num_packets);
typedef void (*unsubscribe_mutator_fn)(mqtt_unsubscribe_packet_t *pkt, int num_packets);

connect_mutator_fn connect_mutators[] = {
    mutate_connect_flags,
    mutate_connect_keep_alive,
    mutate_connect_properties,
    mutate_connect_client_id,
    mutate_connect_will_properties,
    mutate_connect_will_topic,
    mutate_connect_will_payload,
    mutate_connect_user_name,
    mutate_connect_password,
    add_connect_properties,
    add_connect_client_id,
    add_connect_will_properties,
    add_connect_will_topic,
    add_connect_will_payload,
    add_connect_user_name,
    add_connect_password,
    delete_connect_properties,
    delete_connect_client_id,
    delete_connect_will_properties,
    delete_connect_will_topic,
    delete_connect_will_payload,
    delete_connect_user_name,
    delete_connect_password,
};
static int connect_mutators_weights[] = {
    8, // mutate_connect_flags
    8, // mutate_connect_keep_alive
    0, // mutate_connect_properties         
    6, // mutate_connect_client_id
    6, // mutate_connect_will_properties
    6, // mutate_connect_will_topic
    6, // mutate_connect_will_payload
    6, // mutate_connect_user_name
    6, // mutate_connect_password
    0, // add_connect_properties        
    8, // add_connect_client_id
    0, // add_connect_will_properties       
    0, // add_connect_will_topic              
    8, // add_connect_will_payload
    8, // add_connect_user_name
    8, // add_connect_password
    8, // delete_connect_properties
    0, // delete_connect_client_id            
    0, // delete_connect_will_properties
    0, // delete_connect_will_topic
    0, // delete_connect_will_payload
    8, // delete_connect_user_name
    8, // delete_connect_password
};

// subscribe mutator  9
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
// publish mutator 15
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
// unsubscribe mutator 7
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
// auth mutator 6
auth_mutator_fn auth_mutators[] = {
    mutate_auth_reason_code,
    add_auth_reason_code,
    delete_auth_reason_code,
    mutate_auth_properties,
    add_auth_properties,
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


void dispatch_connect_mutation(mqtt_connect_packet_t *pkt, int num_packets) {
    if (pkt == NULL) return;
    int index = pick_weighted(connect_mutators_weights, (int)CONNECT_MUTATOR_COUNT);
    connect_mutators[index](pkt, 1); 
}

void dispatch_subscribe_mutation(mqtt_subscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(subscribe_mutators_weights, (int)SUBSCRIBE_MUTATOR_COUNT);
  subscribe_mutators[index](pkt, 1);
}

void dispatch_publish_mutation(mqtt_publish_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(publish_mutators_weights, (int)PUBLISH_MUTATOR_COUNT);
  publish_mutators[index](pkt, 1);
}

void dispatch_unsubscribe_mutation(mqtt_unsubscribe_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(unsubscribe_mutators_weights, (int)UNSUBSCRIBE_MUTATOR_COUNT);
  unsubscribe_mutators[index](pkt, 1);
}
void dispatch_auth_mutation(mqtt_auth_packet_t *pkt, int num_packets) {
  if (pkt == NULL) return;
  int index = pick_weighted(auth_mutators_weights, (int)AUTH_MUTATOR_COUNT);
  auth_mutators[index](pkt, 1);
}

void dispatch_mqtt_multiple_mutations(mqtt_packet_t *pkt, int num_packets, int rounds) {
    for (int i = 0; i < rounds; ++i) {
      int mutate_index = rand() % num_packets;

      if(pkt[mutate_index].type == TYPE_CONNECT){
        dispatch_connect_mutation(&pkt[mutate_index].connect, 1);
      }else if(pkt[mutate_index].type == TYPE_SUBSCRIBE){
        dispatch_subscribe_mutation(&pkt[mutate_index].subscribe, 1);
      }else if(pkt[mutate_index].type == TYPE_PUBLISH){
        dispatch_publish_mutation(&pkt[mutate_index].publish, 1);
      }else if(pkt[mutate_index].type == TYPE_UNSUBSCRIBE){
        dispatch_unsubscribe_mutation(&pkt[mutate_index].unsubscribe, 1);
      }else if(pkt[mutate_index].type == TYPE_AUTH){
        dispatch_auth_mutation(&pkt[mutate_index].auth, 1); 
      }
    }
}
