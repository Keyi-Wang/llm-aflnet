#include <stdlib.h>
#include "rtsp.h"
rtsp_packet_t* generate_rtsp_packets(int count) {
    rtsp_packet_t *packets = (rtsp_packet_t *)malloc(sizeof(rtsp_packet_t) * count);
    if (packets == NULL) {
        return NULL; // 内存分配失败
    }
    memset(packets, 0, sizeof(rtsp_packet_t) * count);  // 初始化为0
    return packets;
}