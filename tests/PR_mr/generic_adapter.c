#include "dut.h"
#include <stdlib.h>


#ifndef PARSE_SYM
# error "Please define PARSE_SYM (e.g., -DPARSE_SYM=ftp_parse)"
#endif
#ifndef REASM_SYM
# error "Please define REASM_SYM (e.g., -DREASM_SYM=ftp_reassemble)"
#endif


int PARSE_SYM(const uint8_t*, size_t, msg_array_t*);
int REASM_SYM(const msg_array_t*, uint8_t**, size_t*);


int  dut_parse(const uint8_t* buf, size_t len, msg_array_t* out) {
  return PARSE_SYM(buf, len, out);
}
int  dut_reassemble(const msg_array_t* in, uint8_t** out_buf, size_t* out_len) {
  return REASM_SYM(in, out_buf, out_len);
}
void dut_free_msg_array(msg_array_t* arr) {
  if (!arr || !arr->v) return;
  for (size_t i = 0; i < arr->n; ++i) free(arr->v[i].data);
  free(arr->v);
  arr->v = NULL; arr->n = 0;
}
void dut_free_buffer(uint8_t* buf) { free(buf); }


