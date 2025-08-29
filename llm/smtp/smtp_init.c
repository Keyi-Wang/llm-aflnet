/* smtp init source file */
#include "smtp.h"
#include <stdio.h>

smtp_packet_t* generate_smtp_packets(int count) {
    smtp_packet_t *packets = (smtp_packet_t *)malloc(sizeof(smtp_packet_t) * count);
    if (packets == NULL) {
        return NULL; 
    }
    memset(packets, 0, sizeof(smtp_packet_t) * count); 
    return packets;
}