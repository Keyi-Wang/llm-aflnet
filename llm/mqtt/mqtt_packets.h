#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_WILL_TOPIC_LEN  128
#define MAX_WILL_MSG_LEN    256
#define MAX_PROPERTIES      16
#define MAX_PROP_VALUE_LEN  256
#define MAX_PROTOCOL_NAME_LEN 10
#define MAX_CLIENT_ID_LEN 64
#define MAX_PROPERTIES_LEN 128
#define MAX_TOPIC_LEN 128
#define MAX_PAYLOAD_LEN 256
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_TOPIC_FILTERS 10
#define MQTT_CONNECT     1
#define MQTT_SUBSCRIBE   8
#define MQTT_PUBLISH     3
#define MQTT_UNSUBSCRIBE  10
#define MQTT_AUTH        15

typedef struct {
    uint8_t packet_type;
    uint32_t remaining_length;
} mqtt_fixed_header_t;

typedef struct {
    char protocol_name[MAX_PROTOCOL_NAME_LEN];
    uint8_t protocol_level;
    uint8_t connect_flags;
    uint16_t keep_alive;
    uint32_t property_len;
    uint8_t properties[MAX_PROPERTIES_LEN];  // 原始属性字节流
} mqtt_connect_variable_header_t;

typedef struct {
    char client_id[MAX_CLIENT_ID_LEN];
    uint32_t will_property_len;
    uint8_t will_properties[MAX_PROPERTIES_LEN];
    char will_topic[MAX_TOPIC_LEN];
    uint8_t will_payload[MAX_PAYLOAD_LEN];
    uint16_t will_payload_len;
    char user_name[MAX_USERNAME_LEN];
    uint8_t password[MAX_PASSWORD_LEN];
    uint16_t password_len;
} mqtt_connect_payload_t;

typedef struct {
    mqtt_fixed_header_t fixed_header;
    mqtt_connect_variable_header_t variable_header;
    mqtt_connect_payload_t payload;
} mqtt_connect_packet_t;

typedef struct {
    uint16_t packet_identifier;
    uint32_t property_len;
    uint8_t properties[MAX_PROPERTIES_LEN];  // 原始属性字节流
} mqtt_subscribe_variable_header_t;

typedef struct {
    struct {
        char topic_filter[MAX_TOPIC_LEN];
        uint8_t qos;
    } topic_filters[MAX_TOPIC_FILTERS];
    uint8_t topic_count;
} mqtt_subscribe_payload_t;

typedef struct {
    mqtt_fixed_header_t fixed_header;
    mqtt_subscribe_variable_header_t variable_header;
    mqtt_subscribe_payload_t payload;
} mqtt_subscribe_packet_t;

typedef struct {
    char topic_name[MAX_TOPIC_LEN];
    uint16_t packet_identifier; // 如果 QoS > 0 才使用
    uint32_t property_len;
    uint8_t properties[MAX_PROPERTIES_LEN];
} mqtt_publish_variable_header_t;

typedef struct {
    uint8_t payload[MAX_PAYLOAD_LEN];
    uint32_t payload_len;
} mqtt_publish_payload_t;

typedef struct {
    mqtt_fixed_header_t fixed_header;
    mqtt_publish_variable_header_t variable_header;
    mqtt_publish_payload_t payload;
    uint8_t qos;   // 从 fixed header flags 解析
    uint8_t dup;
    uint8_t retain;
} mqtt_publish_packet_t;

typedef struct {
    uint16_t packet_identifier;   // 报文标识符
    uint32_t property_len;        // 属性字段长度
    uint8_t properties[MAX_PROPERTIES_LEN];  // 属性字节流
} mqtt_unsubscribe_variable_header_t;

typedef struct {
    char topic_filters[MAX_TOPIC_FILTERS][MAX_TOPIC_LEN];  // 退订的主题过滤器列表
    uint8_t topic_count;                                   // 主题数量
} mqtt_unsubscribe_payload_t;

typedef struct {
    mqtt_fixed_header_t fixed_header;                      // 固定头部
    mqtt_unsubscribe_variable_header_t variable_header;    // 可变头部
    mqtt_unsubscribe_payload_t payload;                    // 有效载荷
} mqtt_unsubscribe_packet_t;

typedef struct {
    uint8_t reason_code;                // 原因码（Reason Code）
    uint32_t property_len;              // 属性长度
    uint8_t properties[MAX_PROPERTIES_LEN];  // 属性字节流
} mqtt_auth_variable_header_t;

typedef struct {
    mqtt_fixed_header_t fixed_header;                   // 固定头部
    mqtt_auth_variable_header_t variable_header;        // 可变头部
} mqtt_auth_packet_t;

typedef enum {
    TYPE_CONNECT,
    TYPE_SUBSCRIBE,
    TYPE_PUBLISH,
    TYPE_UNSUBSCRIBE,
    TYPE_AUTH,
    TYPE_UNKNOWN
} mqtt_type_t;

typedef struct {
    mqtt_type_t type;
    union {
        mqtt_connect_packet_t connect;
        mqtt_subscribe_packet_t subscribe;
        mqtt_publish_packet_t publish;
        mqtt_unsubscribe_packet_t unsubscribe;
        mqtt_auth_packet_t auth;
    };
} mqtt_packet_t;