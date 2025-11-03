#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t* data;
  size_t   len;
} msg_t;

typedef struct {
  msg_t*  v;
  size_t  n;
} msg_array_t;


int  dut_parse(const uint8_t* buf, size_t len, msg_array_t* out);                   // 0=OK
int  dut_reassemble(const msg_array_t* in, uint8_t** out_buf, size_t* out_len);    // 0=OK
void dut_free_msg_array(msg_array_t* arr);
void dut_free_buffer(uint8_t* buf);

__attribute__((weak))
size_t dut_normalize(const uint8_t* in, size_t in_len, uint8_t** out_norm);

#ifdef __cplusplus
}
#endif
