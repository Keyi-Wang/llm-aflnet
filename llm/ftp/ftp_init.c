/* ftp init source file */
#include "ftp.h"
#include <stdio.h>

ftp_packet_t* generate_ftp_packets(int count) {
    ftp_packet_t *packets = (ftp_packet_t *)malloc(sizeof(ftp_packet_t) * count);
    if (packets == NULL) {
        return NULL; 
    }
    memset(packets, 0, sizeof(ftp_packet_t) * count); 
    return packets;
}
