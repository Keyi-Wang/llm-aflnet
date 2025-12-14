// tests/mr/adapters/sip_adapter.c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "dut.h"   // msg_array_t / dut_* 原型
#include "sip.h"   // sip_packet_t / parse_sip_msg / reassemble_sip_msgs

#ifndef u8
typedef uint8_t  u8;
#endif
#ifndef u32
typedef uint32_t u32;
#endif

#ifndef MR_MAX_OUTPUT
#define MR_MAX_OUTPUT (32u * 1024u * 1024u)  // 32MB 上限：重组输出缓冲
#endif

// -------- 内部 holder，保存 parser 输出的包数组 --------
typedef struct {
    sip_packet_t *pkts;
    size_t        cap;
} sip_holder_t;

// -------- 将 msg_array_t* 映射到 holder 的简易表 --------
typedef struct map_node_s {
    const msg_array_t *key;
    sip_holder_t      *val;
    struct map_node_s *next;
} map_node_t;

static map_node_t *g_map = NULL;

static void map_set(const msg_array_t *k, sip_holder_t *v) {
    map_node_t *p = malloc(sizeof(*p));      // <-- 修复点：不使用 map_node_s* 强转
    if (!p) return;
    p->key = k;
    p->val = v;
    p->next = g_map;
    g_map = p;
}
static sip_holder_t* map_get(const msg_array_t *k) {
    for (map_node_t *p = g_map; p; p = p->next) if (p->key == k) return p->val;
    return NULL;
}
static void map_del(const msg_array_t *k) {
    map_node_t **pp = &g_map, *p = g_map;
    while (p) {
        if (p->key == k) {
            *pp = p->next;
            free(p);
            return;
        }
        pp = &p->next;
        p = p->next;
    }
}

// ---------------- DUT 接口实现 ----------------

// 解析：buf -> sip_packet_t[]
int dut_parse(const uint8_t *buf, size_t len, msg_array_t *out_arr) {
    if (!out_arr) return -1;
    out_arr->n = 0;

    // 估算容量：SIP 文本报文通常 >128B，这里 len/128 + 4，至少 8
    size_t cap = len / 128 + 4;
    if (cap < 8) cap = 8;

    sip_holder_t *holder = (sip_holder_t*)calloc(1, sizeof(sip_holder_t));
    if (!holder) return -1;

    holder->pkts = (sip_packet_t*)calloc(cap, sizeof(sip_packet_t));
    if (!holder->pkts) { free(holder); return -1; }
    holder->cap = cap;

    size_t n = parse_sip_msg(buf, len, holder->pkts, holder->cap);

    // 若输入非空却没有解析到任何消息，视作失败
    if (n == 0 && len > 0) {
        free(holder->pkts);
        free(holder);
        return -1;
    }

    out_arr->n = n;
    map_set(out_arr, holder);
    return 0;
}

// 重组：sip_packet_t[] -> 字节流（返回 malloc 的缓冲）
int dut_reassemble(const msg_array_t *arr, uint8_t **out_buf, size_t *out_len) {
    if (!arr || !out_buf || !out_len) return -1;

    sip_holder_t *holder = map_get(arr);
    if (!holder) return -1;

    u8 *buf = (u8*)malloc(MR_MAX_OUTPUT);
    if (!buf) return -1;

    u32 len32 = 0;
    int rc = reassemble_sip_msgs(holder->pkts, (u32)arr->n, buf, &len32);
    if (rc != 0) {
        free(buf);
        return -1;
    }
    if (len32 > MR_MAX_OUTPUT) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = (size_t)len32;
    return 0;
}

// 释放解析阶段的消息数组
void dut_free_msg_array(msg_array_t *arr) {
    if (!arr) return;
    sip_holder_t *holder = map_get(arr);
    if (holder) {
        free(holder->pkts);
        free(holder);
        map_del(arr);
    }
    arr->n = 0;
}

// 释放由 dut_reassemble 返回的缓冲
void dut_free_buffer(uint8_t *p) {
    free(p);
}
