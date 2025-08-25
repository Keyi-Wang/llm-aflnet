#ifndef FTP_H
#define FTP_H

#include "ftp_packets.h"
#include "../../types.h"
#include "../../config.h"

#endif /* FTP_H */

ftp_packet_t* generate_ftp_packets(int count);

size_t parse_ftp_msg(const uint8_t *buf, size_t buf_len,
                     ftp_packet_t *out_packets, size_t max_count);

int reassemble_ftp_msgs(const ftp_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len);

void dispatch_ftp_multiple_mutations(ftp_packet_t *pkt, int num_packets, int rounds);

void fix_ftp(ftp_packet_t *pkts, size_t count);

void print_ftp_packets(const ftp_packet_t *packets, size_t pkt_num);