#define _GNU_SOURCE
#include "dut.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>   // basename

#ifndef MR_MAX_INPUT
#define MR_MAX_INPUT (32 * 1024 * 1024)
#endif

static int read_all(const char* path, uint8_t** buf, size_t* len) {
  *buf = NULL; *len = 0;
  FILE* f = strcmp(path, "-") ? fopen(path, "rb") : stdin;
  if (!f) { fprintf(stderr, "OPEN_FAIL %s: %s\n", path, strerror(errno)); return -1; }

  if (f != stdin && fseek(f, 0, SEEK_END) == 0) {
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    if (sz == 0) { fclose(f); return 0; }
    if ((size_t)sz > MR_MAX_INPUT) { fclose(f); fprintf(stderr,"TOO_BIG\n"); return -1; }
    *buf = (uint8_t*)malloc((size_t)sz);
    if (!*buf) { fclose(f); return -1; }
    if (fread(*buf,1,(size_t)sz,f)!=(size_t)sz){ free(*buf); fclose(f); return -1; }
    *len = (size_t)sz; fclose(f); return 0;
  }

  size_t cap = 1<<20, used = 0;
  *buf = (uint8_t*)malloc(cap);
  if (!*buf) { if (f!=stdin) fclose(f); return -1; }
  for (;;) {
    if (used == cap) {
      if (cap > MR_MAX_INPUT/2) { free(*buf); if (f!=stdin) fclose(f); return -1; }
      cap <<= 1;
      uint8_t* p = (uint8_t*)realloc(*buf, cap);
      if (!p) { free(*buf); if (f!=stdin) fclose(f); return -1; }
      *buf = p;
    }
    size_t r = fread(*buf + used, 1, cap - used, f);
    used += r;
    if (r == 0) break;
  }
  if (f != stdin) fclose(f);
  *len = used;
  return 0;
}

static void ensure_dir(const char* p) {
  struct stat st; if (stat(p,&st)==0 && S_ISDIR(st.st_mode)) return;
  mkdir(p,0755);
}

static void write_bin(const char* path, const uint8_t* buf, size_t len) {
  FILE* f = fopen(path,"wb"); if (!f) return; fwrite(buf,1,len,f); fclose(f);
}

/* 计算首个差异（1-based；若完全相同返回 -1） */
static long first_diff_1based(const uint8_t* A, size_t Al,
                              const uint8_t* B, size_t Bl) {
  size_t m = (Al < Bl) ? Al : Bl;
  for (size_t i=0;i<m;i++) if (A[i]!=B[i]) return (long)i+1;
  if (Al!=Bl) return (long)m+1;
  return -1;
}

/* 将逐字节差异写到文本文件（避免超长，最多写前 100k 个差异行） */
static void write_diff_txt(const char* path,
                           const uint8_t* A, size_t Al,
                           const uint8_t* B, size_t Bl) {
  FILE* f = fopen(path,"w"); if (!f) return;
  fprintf(f, "orig_len=%zu reasm_len=%zu\n", Al, Bl);
  fprintf(f, "OFFSET  A   B\n");
  size_t max = (Al > Bl) ? Al : Bl;
  size_t lines = 0, limit = 100000;
  for (size_t i=0; i<max; ++i) {
    int av = (i<Al) ? (int)A[i] : -1;
    int bv = (i<Bl) ? (int)B[i] : -1;
    if (av != bv) {
      if (av < 0) fprintf(f, "%06zu  --  %02X\n", i, bv & 0xFF);
      else if (bv < 0) fprintf(f, "%06zu  %02X  --\n", i, av & 0xFF);
      else fprintf(f, "%06zu  %02X  %02X\n", i, av & 0xFF, bv & 0xFF);
      if (++lines >= limit) { fprintf(f, "... truncated ...\n"); break; }
    }
  }
  fclose(f);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input-file|->\n", argv[0]);
    return 2;
  }

  const char* in_path = argv[1];
  int allow_parse_fail = getenv("MR_ALLOW_PARSE_FAIL") ? 1 : 0;
  const char* outdir = getenv("MR_OUTDIR");

  uint8_t *orig=NULL, *reasm=NULL;
  size_t orig_len=0, reasm_len=0;

  if (read_all(in_path, &orig, &orig_len) != 0) return 2;

  msg_array_t arr = {0};
  int pr = dut_parse(orig, orig_len, &arr);
  if (pr != 0) {
    fprintf(stderr, "PARSE_FAIL %s (len=%zu)\n", in_path, orig_len);
    if (outdir) {
      ensure_dir(outdir);
      char base[256]; strncpy(base, in_path, sizeof(base)-1); base[sizeof(base)-1]=0;
      char *bn = basename(base);
      char case_dir[640]; snprintf(case_dir,sizeof(case_dir),"%s/%s-%ld-%d", outdir, bn, (long)time(NULL), getpid());
      ensure_dir(case_dir);
      char p1[768]; snprintf(p1,sizeof(p1), "%s/input.bin", case_dir);
      write_bin(p1, orig, orig_len);
      fprintf(stderr, " saved: %s\n", case_dir);
    }
    free(orig);
    return allow_parse_fail ? 0 : 1;
  }

  int rr = dut_reassemble(&arr, &reasm, &reasm_len);
  if (rr != 0) {
    fprintf(stderr, "REASM_FAIL %s\n", in_path);
    dut_free_msg_array(&arr); free(orig);
    return 1;
  }

  uint8_t *na=NULL,*nb=NULL;
  size_t la=0, lb=0;
  const uint8_t* A = orig; size_t Al = orig_len;
  const uint8_t* B = reasm; size_t Bl = reasm_len;

  if (dut_normalize) {
    la = dut_normalize(orig, orig_len, &na);
    lb = dut_normalize(reasm, reasm_len, &nb);
    if (la>0) { A=na; Al=la; }
    if (lb>0) { B=nb; Bl=lb; }
  }

  int ok = (Al==Bl && memcmp(A,B,Al)==0);
  if (ok) {
    fprintf(stderr,"OK %s (len=%zu,msgs=%zu)\n", in_path, orig_len, arr.n);
  } else {
    long fdiff = first_diff_1based(A,Al,B,Bl);
    fprintf(stderr,"MR_FAIL %s (orig=%zu,reasm=%zu,msgs=%zu)\n", in_path, orig_len, reasm_len, arr.n);
    if (fdiff > 0) fprintf(stderr, " first-diff (1-based) = %ld\n", fdiff);

    if (outdir) {
      ensure_dir(outdir);
      char base[256]; strncpy(base, in_path, sizeof(base)-1); base[sizeof(base)-1]=0;
      char *bn = basename(base);
      char case_dir[640]; snprintf(case_dir,sizeof(case_dir),"%s/%s-%ld-%d", outdir, bn, (long)time(NULL), getpid());
      ensure_dir(case_dir);
      char p1[768],p2[768],p3[768];
      snprintf(p1,sizeof(p1), "%s/input.bin", case_dir);
      snprintf(p2,sizeof(p2), "%s/reasm.bin", case_dir);
      snprintf(p3,sizeof(p3), "%s/diff.txt",  case_dir);
      write_bin(p1, orig,  orig_len);
      write_bin(p2, reasm, reasm_len);
      write_diff_txt(p3, A, Al, B, Bl);
      fprintf(stderr, " saved: %s\n", case_dir);
    }
  }

  if (na) free(na);
  if (nb) free(nb);
  dut_free_msg_array(&arr);
  dut_free_buffer(reasm);
  free(orig);
  return ok ? 0 : 1;
}
