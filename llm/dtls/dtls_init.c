/* dtls init source file */
#include "dtls.h"
#include <stdio.h>

dtls_packet_t* generate_dtls_packets(int count) {
    dtls_packet_t *packets = (dtls_packet_t *)malloc(sizeof(dtls_packet_t) * count);
    if (packets == NULL) {
        return NULL; 
    }
    memset(packets, 0, sizeof(dtls_packet_t) * count); 
    return packets;
}

