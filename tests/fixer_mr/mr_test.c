// tests/fixer_mr/mr_test.c
// 通用 fixer 蜕变测试：
//
//   MSG = mutator(VALID_MSG)
//   M1  = fixer(MSG)
//   M2  = fixer(M1)
//
//   MR1: reassemble(M1) == reassemble(M2)           // fixer 幂等
//   MR2: M1_wire == reassemble(parse(M1_wire))      // parser/reassembler 蜕变
//
// 额外：输出 MSG vs M1 的简单相似度，辅助观察 fixer 是否退化成“常量输出”。
// 如有环境变量 MR_OUTDIR，当 MR 失败时会把 seed / MSG / M1 / M2 等 dump 到该目录下。

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

// ============ 必须由编译时 -D 注入的宏 ============

#ifndef PROTO_HEADER
# error "You must define PROTO_HEADER, e.g. -DPROTO_HEADER=ftp.h"
#endif

#ifndef PACKET_TYPE
# error "You must define PACKET_TYPE, e.g. -DPACKET_TYPE=ftp_packet_t"
#endif

#ifndef PARSE_FUNC
# error "You must define PARSE_FUNC, e.g. -DPARSE_FUNC=parse_ftp_msg"
#endif

#ifndef REASSEMBLE_FUNC
# error "You must define REASSEMBLE_FUNC, e.g. -DREASSEMBLE_FUNC=reassemble_ftp_msgs"
#endif

#ifndef MUTATE_FUNC
# error "You must define MUTATE_FUNC, e.g. -DMUTATE_FUNC=dispatch_ftp_multiple_mutations"
#endif

#ifndef FIX_FUNC
# error "You must define FIX_FUNC, e.g. -DFIX_FUNC=fix_ftp"
#endif

// 可以在编译时用 -DMAX_PKTS=xx 等覆盖
#ifndef MAX_PKTS
# define MAX_PKTS 64
#endif

#ifndef MAX_WIRE_BUF
# define MAX_WIRE_BUF 65536
#endif

#ifndef MUTATION_ROUNDS
# define MUTATION_ROUNDS 10
#endif

// 字符串化宏，把 PROTO_HEADER 展开为 "#include \"xxx.h\""
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#include STR(PROTO_HEADER)

// ============ 小工具函数 ============

static int read_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "fopen('%s') failed: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "fseek(SEEK_END) failed on '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fprintf(stderr, "ftell() failed on '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "fseek(SEEK_SET) failed on '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fprintf(stderr, "malloc(%ld) failed\n", sz);
        fclose(fp);
        return -1;
    }

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        fprintf(stderr, "fread short: %zu/%ld on '%s'\n", n, sz, path);
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = n;
    return 0;
}

// 简单“相似度”：按字节比较相同的数量 / 最小长度，仅用于观察，不做硬约束
static double simple_similarity(const uint8_t *a, size_t len_a,
                                const uint8_t *b, size_t len_b) {
    size_t min_len = len_a < len_b ? len_a : len_b;
    if (min_len == 0) return 0.0;
    size_t same = 0;
    for (size_t i = 0; i < min_len; i++) {
        if (a[i] == b[i]) same++;
    }
    return (double)same / (double)min_len;
}


// 失败时把一些中间结果 dump 到 MR_OUTDIR 里
static void dump_failure_artifacts(
    const char *seed_path,
    const uint8_t *seed_buf, size_t seed_len,
    const uint8_t *msg_wire, size_t msg_wire_len,
    const uint8_t *m1_wire, size_t m1_wire_len,
    const uint8_t *m2_wire, size_t m2_wire_len,
    int mr1_ok, int mr2_ok
) {
    const char *outdir = getenv("MR_OUTDIR");
    if (!outdir || !*outdir) {
        return; // 用户没设置就不 dump
    }

    // 取 basename：例如 /path/to/seed1.raw -> seed1.raw
    const char *base = strrchr(seed_path, '/');
    base = base ? base + 1 : seed_path;

    char dirbuf[4096];
    char pathbuf[4096];
    FILE *fp;

    // 子目录：<MR_OUTDIR>/<basename>
    // 例如：out/mqtt-2025-.../seed1.raw/
    if (snprintf(dirbuf, sizeof(dirbuf), "%s/%s", outdir, base) >= (int)sizeof(dirbuf)) {
        // 路径太长，安全起见直接放弃 dump
        return;
    }

    // 创建子目录（如果已存在则忽略错误）
    if (mkdir(dirbuf, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir('%s') failed: %s\n", dirbuf, strerror(errno));
        return;
    }

    // 下面所有文件都写到这个子目录里：
    //   seed.raw
    //   msg.raw
    //   m1.raw
    //   m2.raw
    //   info.txt

    // seed
    snprintf(pathbuf, sizeof(pathbuf), "%s/seed.raw", dirbuf);
    fp = fopen(pathbuf, "wb");
    if (fp) {
        (void)fwrite(seed_buf, 1, seed_len, fp);
        fclose(fp);
    }

    // MSG (变异后但未修复)
    snprintf(pathbuf, sizeof(pathbuf), "%s/msg.raw", dirbuf);
    fp = fopen(pathbuf, "wb");
    if (fp) {
        (void)fwrite(msg_wire, 1, msg_wire_len, fp);
        fclose(fp);
    }

    // M1
    snprintf(pathbuf, sizeof(pathbuf), "%s/m1.raw", dirbuf);
    fp = fopen(pathbuf, "wb");
    if (fp) {
        (void)fwrite(m1_wire, 1, m1_wire_len, fp);
        fclose(fp);
    }

    // M2
    snprintf(pathbuf, sizeof(pathbuf), "%s/m2.raw", dirbuf);
    fp = fopen(pathbuf, "wb");
    if (fp) {
        (void)fwrite(m2_wire, 1, m2_wire_len, fp);
        fclose(fp);
    }

    // info
    snprintf(pathbuf, sizeof(pathbuf), "%s/info.txt", dirbuf);
    fp = fopen(pathbuf, "w");
    if (fp) {
        fprintf(fp, "seed_path=%s\n", seed_path);
        fprintf(fp, "mr1_ok=%d\n", mr1_ok);
        fprintf(fp, "mr2_ok=%d\n", mr2_ok);
        fclose(fp);
    }
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <msg.raw>\n", argv[0]);
        return 2;
    }

    const char *path = argv[1];
    uint8_t *seed_buf = NULL;
    size_t seed_len = 0;

    if (read_file(path, &seed_buf, &seed_len) != 0) {
        fprintf(stderr, "[%s] read_file failed\n", path);
        return 1;
    }

    // 1) 解析种子：保证 VALID_MSG 可解析
    PACKET_TYPE seed_pkts[MAX_PKTS];
    memset(seed_pkts, 0, sizeof(seed_pkts));

    size_t num_seed = PARSE_FUNC(seed_buf, seed_len,
                                 seed_pkts, MAX_PKTS);
    if (num_seed == 0 || num_seed > MAX_PKTS) {
        fprintf(stderr, "[%s] PARSE_FUNC on seed failed (num_seed=%zu)\n",
                path, num_seed);
        free(seed_buf);
        return 1;
    }

    // 2) mutator：得到 MSG（变异后的 AST）
    PACKET_TYPE mut_pkts[MAX_PKTS];
    memcpy(mut_pkts, seed_pkts, num_seed * sizeof(PACKET_TYPE));

    MUTATE_FUNC(mut_pkts, (int)num_seed, MUTATION_ROUNDS);

    uint8_t msg_wire[MAX_WIRE_BUF];
    uint32_t msg_wire_len = 0;
    if (REASSEMBLE_FUNC(mut_pkts, (uint32_t)num_seed,
                        msg_wire, &msg_wire_len) != 0) {
        fprintf(stderr, "[%s] REASSEMBLE_FUNC on mutated pkts failed\n", path);
        free(seed_buf);
        return 1;
    }

    // 3) 第一轮 fixer：M1 = fixer(MSG)
    PACKET_TYPE m1_pkts[MAX_PKTS];
    memcpy(m1_pkts, mut_pkts, num_seed * sizeof(PACKET_TYPE));

    FIX_FUNC(m1_pkts, num_seed);  // in-place 修复

    uint8_t m1_wire[MAX_WIRE_BUF];
    uint32_t m1_wire_len = 0;
    if (REASSEMBLE_FUNC(m1_pkts, (uint32_t)num_seed,
                        m1_wire, &m1_wire_len) != 0) {
        fprintf(stderr, "[%s] REASSEMBLE_FUNC on M1 failed\n", path);
        free(seed_buf);
        return 1;
    }

    // 4) 第二轮 fixer：M2 = fixer(M1)
    PACKET_TYPE m2_pkts[MAX_PKTS];
    memcpy(m2_pkts, m1_pkts, num_seed * sizeof(PACKET_TYPE));

    FIX_FUNC(m2_pkts, num_seed);  // 再修一次

    uint8_t m2_wire[MAX_WIRE_BUF];
    uint32_t m2_wire_len = 0;
    if (REASSEMBLE_FUNC(m2_pkts, (uint32_t)num_seed,
                        m2_wire, &m2_wire_len) != 0) {
        fprintf(stderr, "[%s] REASSEMBLE_FUNC on M2 failed\n", path);
        free(seed_buf);
        return 1;
    }

    // === MR1: reassemble(M1) == reassemble(M2)（fixer 幂等） ===
    int mr1_ok = 0;
    if (m1_wire_len == m2_wire_len &&
        memcmp(m1_wire, m2_wire, m1_wire_len) == 0) {
        mr1_ok = 1;
    }

    // === MR2: M1_wire == reassemble(parse(M1_wire)) ===
    int mr2_ok = 0;
    {
        PACKET_TYPE round_pkts[MAX_PKTS];
        memset(round_pkts, 0, sizeof(round_pkts));

        size_t num_round = PARSE_FUNC(m1_wire, m1_wire_len,
                                      round_pkts, MAX_PKTS);
        if (num_round == 0 || num_round > MAX_PKTS) {
            fprintf(stderr, "[%s] PARSE_FUNC(M1) failed (num_round=%zu)\n",
                    path, num_round);
            mr2_ok = 0;
        } else {
            uint8_t round_wire[MAX_WIRE_BUF];
            uint32_t round_wire_len = 0;
            if (REASSEMBLE_FUNC(round_pkts, (uint32_t)num_round,
                                round_wire, &round_wire_len) != 0) {
                fprintf(stderr, "[%s] REASSEMBLE_FUNC(parse(M1)) failed\n", path);
                mr2_ok = 0;
            } else if (round_wire_len == m1_wire_len &&
                       memcmp(round_wire, m1_wire, m1_wire_len) == 0) {
                mr2_ok = 1;
            } else {
                mr2_ok = 0;
            }
        }
    }

    // MSG vs M1 相似度（退化检测辅助，不影响返回码）
    double sim_msg_m1 = simple_similarity(msg_wire, msg_wire_len,
                                          m1_wire, m1_wire_len);

    printf("FILE=%s MR1=%s MR2=%s SIM(MSG,M1)=%.3f\n",
           path,
           mr1_ok ? "OK" : "FAIL",
           mr2_ok ? "OK" : "FAIL",
           sim_msg_m1);

    // 如果有失败，dump 调试文件
    if (!(mr1_ok && mr2_ok)) {
        dump_failure_artifacts(
            path,
            seed_buf, seed_len,
            msg_wire, msg_wire_len,
            m1_wire, m1_wire_len,
            m2_wire, m2_wire_len,
            mr1_ok, mr2_ok
        );
    }

    free(seed_buf);

    // 返回值：两个 MR 都通过才算整体通过
    return (mr1_ok && mr2_ok) ? 0 : 1;
}
