// tests/mr/adapters/smtp_adapter.c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "dut.h"    // msg_array_t / dut_* 原型
#include "smtp.h"   // smtp_packet_t / parse_smtp_msg / reassemble_smtp_msgs

#ifndef u8
typedef uint8_t  u8;
#endif
#ifndef u32
typedef uint32_t u32;
#endif

#ifndef MR_MAX_OUTPUT
#define MR_MAX_OUTPUT (32u * 1024u * 1024u)  // 32MB：重组输出上限
#endif

// -------- 内部 holder：保存 parser 输出的包数组 --------
typedef struct {
    smtp_packet_t *pkts;
    size_t         cap;
} smtp_holder_t;

// -------- 将 msg_array_t* 映射到 holder 的简易表 --------
typedef struct map_node_s {
    const msg_array_t *key;
    smtp_holder_t     *val;
    struct map_node_s *next;
} map_node_t;

static map_node_t *g_map = NULL;

static void map_set(const msg_array_t *k, smtp_holder_t *v) {
    map_node_t *p = (map_node_t*)malloc(sizeof(*p));
    if (!p) return;
    p->key = k;
    p->val = v;
    p->next = g_map;
    g_map = p;
}
static smtp_holder_t* map_get(const msg_array_t *k) {
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

// 解析：buf -> smtp_packet_t[]
int dut_parse(const uint8_t *buf, size_t len, msg_array_t *out_arr) {
    if (!out_arr) return -1;
    out_arr->n = 0;

    // 估算容量：SMTP 文本行较长，取 len/128 + 4，至少 8
    size_t cap = len / 128 + 4;
    if (cap < 8) cap = 8;

    smtp_holder_t *holder = (smtp_holder_t*)calloc(1, sizeof(smtp_holder_t));
    if (!holder) return -1;

    holder->pkts = (smtp_packet_t*)calloc(cap, sizeof(smtp_packet_t));
    if (!holder->pkts) { free(holder); return -1; }
    holder->cap = cap;

    size_t n = parse_smtp_msg(buf, len, holder->pkts, holder->cap);

    // 若可能被容量截断，放大一次重试（parse_smtp_msg 若不会截断，可忽略该分支）
    if (n >= holder->cap) {
        size_t new_cap = holder->cap * 2;
        smtp_packet_t *np = (smtp_packet_t*)realloc(holder->pkts, new_cap * sizeof(smtp_packet_t));
        if (np) {
            holder->pkts = np;
            holder->cap = new_cap;
            n = parse_smtp_msg(buf, len, holder->pkts, holder->cap);
        }
    }

    // 输入非空却 0 包，视作失败（保持与其他协议一致）
    if (n == 0 && len > 0) {
        free(holder->pkts);
        free(holder);
        return -1;
    }

    out_arr->n = n;
    map_set(out_arr, holder);
    return 0;
}

// 重组：smtp_packet_t[] -> 字节流（返回 malloc 的缓冲）
int dut_reassemble(const msg_array_t *arr, uint8_t **out_buf, size_t *out_len) {
    if (!arr || !out_buf || !out_len) return -1;

    smtp_holder_t *holder = map_get(arr);
    if (!holder) return -1;

    u8 *buf = (u8*)malloc(MR_MAX_OUTPUT);
    if (!buf) return -1;

    u32 len32 = 0;
    int rc = reassemble_smtp_msgs(holder->pkts, (u32)arr->n, buf, &len32);
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
    smtp_holder_t *holder = map_get(arr);
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
