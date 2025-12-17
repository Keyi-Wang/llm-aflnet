// tests/mr/adapters/dtls_adapter.c
#include "dut.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* === 必须：包含定义 dtls_packet_t 的头文件（请按你的项目名修改路径） === */
// 例如：#include "../../../llm/dtls/dtls_common.h"
// 或者：#include "../../../llm/dtls/dtls.h"
// 或者：#include "../../../llm/dtls/dtls_parser.h"
#include "../../../llm/dtls/dtls_packets.h"  // <- 按需改名

/* === 声明被测函数（若已在上面的头文件声明，可删掉这两行 extern） === */
extern size_t parse_dtls_msg(const uint8_t *buf, size_t buf_len,
                            dtls_packet_t *out_packets, size_t max_count);
extern int reassemble_dtls_msgs(const dtls_packet_t *packets, uint32_t num_packets,
                               uint8_t *output_buf, uint32_t *out_len);

/* ---------- 适配参数，可按需调整 ---------- */
#ifndef dtls_MAX_MSGS_INIT
#define dtls_MAX_MSGS_INIT 128       /* 初始申请的 packet 容量 */
#endif
#ifndef dtls_MAX_MSGS_CAP
#define dtls_MAX_MSGS_CAP  8192      /* packet 上限（防止异常膨胀） */
#endif
#ifndef dtls_REASM_INIT_CAP
#define dtls_REASM_INIT_CAP (4*1024*1024)  /* 初始重组缓冲区 4MB */
#endif
#ifndef dtls_REASM_MAX_CAP
#define dtls_REASM_MAX_CAP  (64*1024*1024) /* 重组缓冲区最大 64MB */
#endif
/* 若你的 reassembler 支持 output_buf == NULL 仅返回 out_len，可打开此宏走“探测长度再分配”的路径 */
// #define dtls_REASM_SUPPORTS_QUERY_LEN 1

/* 我们把解析结果放在一个 holder 里，通过 msg_array_t 传递给重组函数 */
typedef struct {
  dtls_packet_t *pkts;
  size_t        n;         /* 解析得到的 packet 个数 */
  size_t        cap;       /* pkts 容量 */
  size_t        orig_len;  /* 原始输入长度，用于估算输出缓冲区大小 */
} dtls_holder_t;

/* 工具：安全释放 holder */
static void free_holder(dtls_holder_t *h) {
  if (!h) return;
  /* 如果 dtls_packet_t 内部没有堆内存，这里只需 free(h->pkts)。
     如果你的实现里 dtls_packet_t 内部持有堆指针，且 parse_dtls_msg 分配了内存，
     请在这里改为调用相应的释放函数。*/
  free(h->pkts);
  free(h);
}

/* ========== dut_* 实现 ========== */

int dut_parse(const uint8_t *buf, size_t len, msg_array_t *out) {
  if (!out) return -1;

  dtls_holder_t *holder = (dtls_holder_t*)calloc(1, sizeof(*holder));
  if (!holder) return -ENOMEM;
  holder->orig_len = len;

  /* 逐步扩容解析缓存，直到不再“打满”容量为止 */
  size_t cap = dtls_MAX_MSGS_INIT;
  holder->pkts = (dtls_packet_t*)malloc(cap * sizeof(dtls_packet_t));
  if (!holder->pkts) { free(holder); return -ENOMEM; }

  for (;;) {
    size_t n = parse_dtls_msg(buf, len, holder->pkts, cap);
    holder->n = n;
    holder->cap = cap;

    if (n < cap) break;           /* 认为没有被截断，解析完成 */
    if (cap >= dtls_MAX_MSGS_CAP)  /* 防止无限扩容 */
      break;

    /* 扩容并重试解析（假设 parse_dtls_msg 是幂等可重入的） */
    cap = cap * 2;
    if (cap > dtls_MAX_MSGS_CAP) cap = dtls_MAX_MSGS_CAP;
    dtls_packet_t *np = (dtls_packet_t*)realloc(holder->pkts, cap * sizeof(dtls_packet_t));
    memset(np,0,sizeof(dtls_packet_t)*cap);
    if (!np) { free_holder(holder); return -ENOMEM; }
    holder->pkts = np;
  }

  /* 将 holder 打包到 msg_array_t 里传递（我们只用 v[0].data 存指针，n 用来统计数量） */
  out->v = (msg_t*)calloc(1, sizeof(msg_t));
  if (!out->v) { free_holder(holder); return -ENOMEM; }
  out->n = holder->n;               /* 让测试报告显示“消息条数” */
  out->v[0].data = (uint8_t*)holder;
  out->v[0].len  = 0;               /* 未用 */

  return 0;
}

int dut_reassemble(const msg_array_t *in, uint8_t **out_buf, size_t *out_len) {
  if (!in || !out_buf || !out_len) return -1;
  if (!in->v || in->n == 0) {      /* 允许 0 消息的情况，返回空串 */
    *out_buf = (uint8_t*)malloc(1);
    if (!*out_buf) return -ENOMEM;
    *out_len = 0;
    return 0;
  }

  dtls_holder_t *holder = (dtls_holder_t*)in->v[0].data;
  if (!holder) return -1;

#ifdef dtls_REASM_SUPPORTS_QUERY_LEN
  /* 如果你的 reassembler 支持“只填 out_len、不写数据”的探测模式（例如 output_buf==NULL），建议优先用这条分支 */
  uint32_t need = 0;
  if (reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, NULL, &need) != 0 || need == 0) {
    /* 若不支持/探测失败，则走下方“猜测缓冲+按需扩容”流程 */
  } else {
    uint8_t *buf = (uint8_t*)malloc(need);
    if (!buf) return -ENOMEM;
    uint32_t outn = 0;
    int rc = reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc != 0) { free(buf); return rc; }
    *out_buf = buf; *out_len = (size_t)outn; return 0;
  }
#endif

  /* 一般回退路径：用启发式容量尝试，失败则倍增 */
  size_t cap = holder->orig_len ? (holder->orig_len * 2 + holder->n * 8 + 1024)
                                : dtls_REASM_INIT_CAP;
  if (cap > dtls_REASM_MAX_CAP) cap = dtls_REASM_MAX_CAP;
  if (cap < 1024) cap = 1024;

  for (int attempt = 0; attempt < 6; ++attempt) {
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) return -ENOMEM;

    uint32_t outn = 0;
    int rc = reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc == 0) {
      *out_buf = buf;
      *out_len = (size_t)outn;
      return 0;
    }

    /* 如果返回非 0，尽量依据 outn 判断是否“缓冲区不够” */
    free(buf);
    if (outn > cap && outn <= dtls_REASM_MAX_CAP) {
      cap = outn;                 /* 如果 reassembler 告知需要长度，就按需扩大 */
    } else {
      cap = cap << 1;             /* 否则简单倍增 */
    }
    if (cap > dtls_REASM_MAX_CAP) break;
  }
  return -ENOMEM;  /* 视情况改成更合适的错误码 */
}

void dut_free_msg_array(msg_array_t *arr) {
  if (!arr || !arr->v) return;
  dtls_holder_t *holder = (dtls_holder_t*)arr->v[0].data;
  free_holder(holder);
  free(arr->v);
  arr->v = NULL; arr->n = 0;
}

void dut_free_buffer(uint8_t *buf) {
  free(buf);
}
