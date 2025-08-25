#include "mqtt.h"
#include <stdio.h>

mqtt_packet_t* generate_mqtt_packets(int count) {
    mqtt_packet_t *packets = (mqtt_packet_t *)malloc(sizeof(mqtt_packet_t) * count);
    if (packets == NULL) {
        return NULL;  
    }
    memset(packets, 0, sizeof(mqtt_packet_t) * count);  
    return packets;
}