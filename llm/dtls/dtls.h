#ifndef DTLS_H
#define DTLS_H

#include "dtls_packets.h"
#include "../../types.h"
#include "../../config.h"


#endif /* DTLS_H */

size_t parse_dtls_msg(const u8 *buf, u32 buf_len,
                      dtls_packet_t *out_packets,
                      u32 max_count);

int reassemble_dtls_msgs(const dtls_packet_t *packets,
                          u32 num_packets,
                          u8 *output_buf,
                          u32 *out_len);
