#ifndef SIP_H
#define SIP_H

#include "sip_packets.h"
#include "../../types.h"
#include "../../config.h"

#endif /* SIP_H */

sip_packet_t* generate_sip_packets(int count);

size_t parse_sip_msg(const uint8_t *buf, size_t buf_len, sip_packet_t *out_packets, size_t max_count);

int reassemble_sip_msgs(const sip_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);

void dispatch_sip_multiple_mutations(sip_packet_t *pkt, int num_packets, int rounds);

void fix_sip(sip_packet_t *pkts, size_t count);
