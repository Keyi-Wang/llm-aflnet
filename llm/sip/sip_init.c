/* sip init source file */
#include "sip.h"

sip_packet_t* generate_sip_packets(int count) {
    sip_packet_t *packets = (sip_packet_t *)malloc(sizeof(sip_packet_t) * count);
    if (packets == NULL) {
        return NULL; 
    }
    memset(packets, 0, sizeof(sip_packet_t) * count); 
    return packets;
}