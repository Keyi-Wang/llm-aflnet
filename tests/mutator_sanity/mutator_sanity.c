#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "adapter.h"
#include "mutator_registry.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
  char **items;
  size_t n;
  size_t cap;
} str_list_t;

static void sl_push(str_list_t *sl, const char *s) {
  if (sl->n + 1 > sl->cap) {
    size_t nc = sl->cap ? sl->cap * 2 : 128;
    char **ni = (char **)realloc(sl->items, nc * sizeof(char*));
    if (!ni) { perror("realloc"); exit(1); }
    sl->items = ni;
    sl->cap = nc;
  }
  sl->items[sl->n++] = strdup(s);
}

static void sl_free(str_list_t *sl) {
  for (size_t i = 0; i < sl->n; i++) free(sl->items[i]);
  free(sl->items);
  memset(sl, 0, sizeof(*sl));
}

static void walk_dir_recursive(const char *dir, str_list_t *out_files) {
  DIR *dp = opendir(dir);
  if (!dp) {
    fprintf(stderr, "[!] opendir failed: %s: %s\n", dir, strerror(errno));
    return;
  }
  struct dirent *de;
  while ((de = readdir(dp)) != NULL) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

    struct stat st;
    if (lstat(path, &st) != 0) continue;

    if (S_ISDIR(st.st_mode)) walk_dir_recursive(path, out_files);
    else if (S_ISREG(st.st_mode)) sl_push(out_files, path);
  }
  closedir(dp);
}

static uint8_t *read_file_all(const char *path, uint32_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return NULL;
  if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
  long sz = ftell(fp);
  if (sz < 0) { fclose(fp); return NULL; }
  rewind(fp);

  uint8_t *buf = (uint8_t *)malloc((size_t)sz);
  if (!buf) { fclose(fp); return NULL; }

  size_t nread = fread(buf, 1, (size_t)sz, fp);
  fclose(fp);
  if (nread != (size_t)sz) { free(buf); return NULL; }
  *out_len = (uint32_t)sz;
  return buf;
}

static void mkdir_p(const char *dir) {
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s", dir);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      (void)mkdir(tmp, 0755);
      *p = '/';
    }
  }
  (void)mkdir(tmp, 0755);
}

static const char *base_name(const char *path) {
  const char *p = strrchr(path, '/');
  return p ? p + 1 : path;
}

static int write_bin(const char *path, const uint8_t *buf, uint32_t len) {
  FILE *fp = fopen(path, "wb");
  if (!fp) return -1;
  size_t w = fwrite(buf, 1, len, fp);
  fclose(fp);
  return (w == len) ? 0 : -1;
}

static int test_one_mutator(const mutator_desc_t *m,
                            const str_list_t *seeds,
                            int rounds,
                            uint32_t max_pkts,
                            uint32_t out_cap,
                            const char *out_dir,
                            int verbose) {
  uint8_t *out_buf = (uint8_t *)malloc(out_cap);
  if (!out_buf) { perror("malloc out_buf"); return 1; }

  proto_packet_t *pkts = (proto_packet_t *)calloc((size_t)max_pkts, sizeof(proto_packet_t));
  if (!pkts) { perror("calloc pkts"); free(out_buf); return 1; }

  for (size_t i = 0; i < seeds->n; i++) {
    const char *seed_path = seeds->items[i];
    uint32_t seed_len = 0;
    uint8_t *seed_bytes = read_file_all(seed_path, &seed_len);
    if (!seed_bytes) {
      if (verbose) fprintf(stderr, "[W] cannot read seed: %s\n", seed_path);
      continue;
    }

    // 先验证 seed 本身能 parse（你的流程要求先 parser）
    proto_packets_reset(pkts, max_pkts);
    size_t n0 = proto_parse(seed_bytes, seed_len, pkts, max_pkts);
    proto_packets_cleanup(pkts, (uint32_t)n0, max_pkts);

    if (n0 == 0) {
      if (verbose) fprintf(stderr, "[W] seed not parsable, skip: %s\n", seed_path);
      free(seed_bytes);
      continue;
    }

    for (int r = 0; r < rounds; r++) {
      // 每一轮都从原 seed 重新 parse，避免累计污染
      proto_packets_reset(pkts, max_pkts);
      size_t n = proto_parse(seed_bytes, seed_len, pkts, max_pkts);
      if (n == 0) {
        if (verbose) fprintf(stderr, "[W] seed parse failed unexpectedly: %s\n", seed_path);
        continue;
      }
      if ((uint32_t)n > max_pkts) {
        if (verbose) fprintf(stderr, "[FAIL] parse returned too many packets: %zu > %u\n", n, max_pkts);
        proto_packets_cleanup(pkts, (uint32_t)n, max_pkts);
        free(seed_bytes);
        free(pkts);
        free(out_buf);
        return 1;
      }

      // mutator（void）
      m->fn(pkts, (int)n);

      // reassemble：out_len 作为“容量/返回长度”的 inout（按常见约定）
      uint32_t out_len = 0;
      int rc = proto_reassemble(pkts, (uint32_t)n, out_buf, &out_len);
      if (rc != 0 || out_len == 0 || out_len > out_cap) {
        if (verbose) fprintf(stderr, "[FAIL] reassemble failed: %s seed=%s round=%d rc=%d out_len=%u\n",
                             m->name, seed_path, r, rc, out_len);

        if (out_dir) {
          char dir1[PATH_MAX];
          snprintf(dir1, sizeof(dir1), "%s/%s", out_dir, m->name);
          mkdir_p(dir1);
          char pseed[PATH_MAX];
          snprintf(pseed, sizeof(pseed), "%s/%s_seed.bin", dir1, base_name(seed_path));
          (void)write_bin(pseed, seed_bytes, seed_len);
        }

        proto_packets_cleanup(pkts, (uint32_t)n, max_pkts);
        free(seed_bytes);
        free(pkts);
        free(out_buf);
        return 1;
      }

      // 关键检查：parser(mutated_bytes) 必须成功
      proto_packets_reset(pkts, max_pkts);
      size_t n2 = proto_parse(out_buf, out_len, pkts, max_pkts);

      if (n2 == 0) {
        // 非法：只输出名称到 stdout（便于收集）
        printf("%s\n", m->name);
        fflush(stdout);

        if (verbose) {
          fprintf(stderr, "[ILLEGAL] %s seed=%s round=%d mutated_len=%u\n",
                  m->name, seed_path, r, out_len);
        }

        // 保存失败样例，便于复现
        if (out_dir) {
          char dir1[PATH_MAX];
          snprintf(dir1, sizeof(dir1), "%s/%s", out_dir, m->name);
          mkdir_p(dir1);

          char pseed[PATH_MAX], pmut[PATH_MAX];
          snprintf(pseed, sizeof(pseed), "%s/%s_seed.bin", dir1, base_name(seed_path));
          snprintf(pmut,  sizeof(pmut),  "%s/%s_round%d_mutated.bin", dir1, base_name(seed_path), r);

          (void)write_bin(pseed, seed_bytes, seed_len);
          (void)write_bin(pmut, out_buf, out_len);
        }

        proto_packets_cleanup(pkts, (uint32_t)n2, max_pkts);
        free(seed_bytes);
        free(pkts);
        free(out_buf);
        return 1;
      }

      proto_packets_cleanup(pkts, (uint32_t)n2, max_pkts);
      proto_packets_cleanup(pkts, (uint32_t)n, max_pkts);
    }

    free(seed_bytes);
  }

  free(pkts);
  free(out_buf);
  return 0;
}

static void usage(const char *argv0) {
  fprintf(stderr,
    "Usage: %s --seeds <dir> [--rounds N] [--max-pkts N] [--out-cap BYTES] [--out DIR] [--no-fork] [--verbose]\n",
    argv0
  );
}

int main(int argc, char **argv) {
  const char *seeds_dir = NULL;
  const char *out_dir = "/tests/mutator_sanity/out_mutator_sanity";
  int rounds = 500;
  uint32_t max_pkts = 256;
  uint32_t out_cap = 1024 * 1024;
  int do_fork = 1;
  int verbose = 0;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--seeds") && i + 1 < argc) seeds_dir = argv[++i];
    else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) rounds = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--max-pkts") && i + 1 < argc) max_pkts = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--out-cap") && i + 1 < argc) out_cap = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--out") && i + 1 < argc) out_dir = argv[++i];
    else if (!strcmp(argv[i], "--no-fork")) do_fork = 0;
    else if (!strcmp(argv[i], "--verbose")) verbose = 1;
    else { usage(argv[0]); return 2; }
  }
  if (!seeds_dir) { usage(argv[0]); return 2; }

  str_list_t seeds = {0};
  walk_dir_recursive(seeds_dir, &seeds);
  if (seeds.n == 0) {
    fprintf(stderr, "[!] No seed files found under: %s\n", seeds_dir);
    sl_free(&seeds);
    return 2;
  }

  fprintf(stderr, "[*] seeds=%zu mutators=%zu rounds=%d max_pkts=%u out_cap=%u\n",
          seeds.n, g_mutators_count, rounds, max_pkts, out_cap);

  int illegal_cnt = 0;

  for (size_t mi = 0; mi < g_mutators_count; mi++) {
    const mutator_desc_t *m = &g_mutators[mi];

    if (!do_fork) {
      int rc = test_one_mutator(m, &seeds, rounds, max_pkts, out_cap, out_dir, verbose);
      if (rc != 0) illegal_cnt++;
      continue;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); sl_free(&seeds); return 2; }

    if (pid == 0) {
      int rc = test_one_mutator(m, &seeds, rounds, max_pkts, out_cap, out_dir, verbose);
      _exit(rc == 0 ? 0 : 1);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
      // 崩溃也视为非法：输出名称到 stdout
      printf("%s\n", m->name);
      fflush(stdout);

      if (verbose) fprintf(stderr, "[ILLEGAL] %s crashed sig=%d\n", m->name, WTERMSIG(status));
      illegal_cnt++;
    } else if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      if (code != 0) illegal_cnt++;
    }
  }

  fprintf(stderr, "[*] done. illegal=%d / total=%zu\n", illegal_cnt, g_mutators_count);
  sl_free(&seeds);
  return (illegal_cnt == 0) ? 0 : 1;
}
