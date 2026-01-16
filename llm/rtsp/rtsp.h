#ifndef RTSP_H
#define RTSP_H

#include <stdint.h>
#include <stddef.h>
#include "rtsp_packets.h"  
#include "../../types.h"       
#include "../../config.h"        
#ifdef __cplusplus
extern "C" {
#endif

//rtsp_init.c
rtsp_packet_t* generate_rtsp_packets(int count);

size_t parse_rtsp_msg(const uint8_t *buf, size_t buf_len,
                           rtsp_packet_t *out_packets, size_t max_count);
void print_rtsp_packets(const rtsp_packet_t *packets, size_t count) ;

//rtsp_mutators.c
void dispatch_rtsp_multiple_mutations(rtsp_packet_t *arr, size_t num_packets, int rounds);

//rtsp_fixers.c
void fix_rtsp(rtsp_packet_t *packets, int num);

//rtsp_reassembler.c
int reassemble_rtsp_msgs(const rtsp_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);
#ifdef __cplusplus
}
#endif

#endif /* RTSP_H */
