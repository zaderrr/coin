#include "util.h"
#include <stdint.h>
#include <stdio.h>
void print_public_key(unsigned char *public_key) {
  printf("0x");
  for (int i = 0; i < 32; i++) {
    printf("%02x", public_key[i]);
  }
  printf("\n");
}

uint64_t htonll(uint64_t val) {
  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {
    return __builtin_bswap64(val);
  }
  return val;
}

int write_bytes(Writer *w, void *in, size_t n) {
  if (w->ptr + n > w->end) {
    return 0;
  }

  memcpy(w->ptr, in, n);
  w->ptr += n;
  return 1;
}

int read_bytes(Reader *r, void *out, size_t n) {
  if (r->ptr + n > r->end) {
    return 0;
  }

  memcpy(out, r->ptr, n);
  r->ptr += n;
  return 1;
}
