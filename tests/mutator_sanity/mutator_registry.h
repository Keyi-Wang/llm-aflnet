#pragma once
#include <stddef.h>
#include "adapter.h"

/* mutator: void f(proto_packet_t *pkts, int/u32 num) */
typedef void (*mutator_fn_t)(proto_packet_t *pkts, int num);

typedef struct {
  const char *name;
  mutator_fn_t fn;
} mutator_desc_t;

extern const mutator_desc_t g_mutators[];
extern const size_t g_mutators_count;
