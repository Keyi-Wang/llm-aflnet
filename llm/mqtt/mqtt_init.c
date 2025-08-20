#include "mqtt.h"
#include <stdio.h>

// 初始化 mqtt_packet_t 数组，返回指针
mqtt_packet_t* generate_mqtt_packets(int count) {
    mqtt_packet_t *packets = (mqtt_packet_t *)malloc(sizeof(mqtt_packet_t) * count);
    if (packets == NULL) {
        return NULL;  // 内存分配失败
    }
    memset(packets, 0, sizeof(mqtt_packet_t) * count);  // 初始化为0
    printf("Generated %d MQTT packets.\n", count);
    printf("pointer address: %p\n", (void*)packets);
    return packets;
}