#ifndef SMTP_H
#define SMTP_H

#include "smtp_packets.h"
#include "../../types.h"
#include "../../config.h"

#endif /* SMTP_H */

smtp_packet_t* generate_smtp_packets(int count);

size_t parse_smtp_msg(const uint8_t *buf, size_t buf_len, smtp_packet_t *out_packets, size_t max_count);

int reassemble_smtp_msgs(const smtp_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);

void dispatch_smtp_multiple_mutations(smtp_packet_t *pkt, int num_packets, int rounds);

void fix_smtp(smtp_packet_t *pkts, size_t count);

void print_smtp_packets(const smtp_packet_t *packets, size_t pkt_num);