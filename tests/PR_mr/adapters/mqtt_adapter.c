// tests/mr/adapters/mqtt_adapter.c
#include "dut.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* 请按实际工程调整：需要能提供 mqtt_packet_t 的定义 */
#include "../../../llm/mqtt/mqtt_packets.h"

/* 若你的项目已有这两个声明且头文件已包含，可以删除下面的 extern 声明 */
extern size_t parse_mqtt_msg(const uint8_t *buf, size_t buf_len,
                             mqtt_packet_t *out_packets, size_t max_count);
extern int reassemble_mqtt_msgs(const mqtt_packet_t *packets, uint32_t num_packets,
                                uint8_t *output_buf, uint32_t *out_len);

/* ---------- 可调参数 ---------- */
#ifndef MQTT_MAX_MSGS_INIT
#define MQTT_MAX_MSGS_INIT 128
#endif
#ifndef MQTT_MAX_MSGS_CAP
#define MQTT_MAX_MSGS_CAP  8192
#endif
#ifndef MQTT_REASM_INIT_CAP
#define MQTT_REASM_INIT_CAP (4*1024*1024)   /* 4MB */
#endif
#ifndef MQTT_REASM_MAX_CAP
#define MQTT_REASM_MAX_CAP  (64*1024*1024)  /* 64MB */
#endif
/* 如果 reassembler 支持 output_buf==NULL 只回填 out_len，则可启用探测长度模式 */
// #define MQTT_REASM_SUPPORTS_QUERY_LEN 1

/* 解析产物的持有者；通过 msg_array_t 传递（把指针塞进 v[0].data） */
typedef struct {
  mqtt_packet_t *pkts;
  size_t         n;
  size_t         cap;
  size_t         orig_len;
} mqtt_holder_t;

static void free_holder(mqtt_holder_t *h) {
  if (!h) return;
  /* 如 mqtt_packet_t 内部含堆指针并需专门释放，请在此处逐个释放 */
  free(h->pkts);
  free(h);
}

/* ========== dut_* 实现 ========== */

int dut_parse(const uint8_t *buf, size_t len, msg_array_t *out) {
  if (!out) return -1;

  mqtt_holder_t *holder = (mqtt_holder_t*)calloc(1, sizeof(*holder));
  if (!holder) return -ENOMEM;
  holder->orig_len = len;

  size_t cap = MQTT_MAX_MSGS_INIT;
  holder->pkts = (mqtt_packet_t*)malloc(cap * sizeof(mqtt_packet_t));
  memset(holder->pkts, 0, sizeof(mqtt_packet_t) * cap);  
  if (!holder->pkts) { free(holder); return -ENOMEM; }

  for (;;) {
    size_t n = parse_mqtt_msg(buf, len, holder->pkts, cap);
    if (n > cap) { free_holder(holder); return -1; } // 契约防御
    holder->n = n;

    holder->n = n;
    holder->cap = cap;

    if (n < cap) break;               /* 未打满 -> 认为完整解析 */
    if (cap >= MQTT_MAX_MSGS_CAP) break;

    cap <<= 1;
    if (cap > MQTT_MAX_MSGS_CAP) cap = MQTT_MAX_MSGS_CAP;
    mqtt_packet_t *np = (mqtt_packet_t*)realloc(holder->pkts, cap * sizeof(mqtt_packet_t));
    if (!np) { free_holder(holder); return -ENOMEM; }
    holder->pkts = np;
  }

  /* 将 holder 指针通过 msg_array_t 传递给 reassembler 适配函数 */
  out->v = (msg_t*)calloc(1, sizeof(msg_t));
  if (!out->v) { free_holder(holder); return -ENOMEM; }
  out->n = holder->n;                 /* 用于测试报告显示“消息条数” */
  out->v[0].data = (uint8_t*)holder;  /* 存放 holder 指针 */
  out->v[0].len  = 0;
  return 0;
}

int dut_reassemble(const msg_array_t *in, uint8_t **out_buf, size_t *out_len) {
  if (!in || !out_buf || !out_len) return -1;

  if (!in->v || in->n == 0) {
    /* 允许空消息序列：返回空串 */
    *out_buf = (uint8_t*)malloc(1);
    if (!*out_buf) return -ENOMEM;
    *out_len = 0;
    return 0;
  }

  mqtt_holder_t *holder = (mqtt_holder_t*)in->v[0].data;
  if (!holder) return -1;

#ifdef MQTT_REASM_SUPPORTS_QUERY_LEN
  /* 优先：探测所需长度（如果你的 reassembler 支持） */
  uint32_t need = 0;
  if (reassemble_mqtt_msgs(holder->pkts, (uint32_t)holder->n, NULL, &need) == 0 && need > 0) {
    uint8_t *buf = (uint8_t*)malloc(need);
    if (!buf) return -ENOMEM;
    uint32_t outn = 0;
    int rc = reassemble_mqtt_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc != 0) { free(buf); return rc; }
    *out_buf = buf; *out_len = (size_t)outn; return 0;
  }
#endif

  /* 回退：启发式容量，多次尝试并按需扩容 */
  size_t cap = holder->orig_len ? (holder->orig_len * 2 + holder->n * 16 + 1024)
                                : MQTT_REASM_INIT_CAP;
  if (cap > MQTT_REASM_MAX_CAP) cap = MQTT_REASM_MAX_CAP;
  if (cap < 1024) cap = 1024;

  for (int attempt = 0; attempt < 6; ++attempt) {
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) return -ENOMEM;

    uint32_t outn = 0;
    int rc = reassemble_mqtt_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc == 0) {
      *out_buf = buf;
      *out_len = (size_t)outn;
      return 0;
    }

    /* 失败时尝试扩大缓冲区：优先信任 outn 的建议值，否则翻倍 */
    free(buf);
    if (outn > cap && outn <= MQTT_REASM_MAX_CAP) {
      cap = outn;
    } else {
      cap <<= 1;
    }
    if (cap > MQTT_REASM_MAX_CAP) break;
  }

  return -ENOMEM; /* 或者返回上一次 rc，看你的重组实现更适配哪种错误码 */
}

void dut_free_msg_array(msg_array_t *arr) {
  if (!arr || !arr->v) return;
  mqtt_holder_t *holder = (mqtt_holder_t*)arr->v[0].data;
  free_holder(holder);
  free(arr->v);
  arr->v = NULL; arr->n = 0;
}

void dut_free_buffer(uint8_t *buf) {
  free(buf);
}
