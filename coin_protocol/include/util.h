#ifndef COIN_UTIL_H
#define COIN_UTIL_H
#include <stdint.h>
#include <string.h>

#define READ_FIELD(r, field, len)                                              \
  do {                                                                         \
    if (!read_bytes((r), &(field), len))                                       \
      return 1;                                                                \
  } while (0)

#define WRITE_FIELD(w, field, len)                                             \
  do {                                                                         \
    if (!write_bytes((w), &(field), len))                                      \
      return 1;                                                                \
  } while (0)

typedef struct {
  unsigned char *ptr;
  unsigned char *end;
} Reader;

typedef struct {
  unsigned char *ptr;
  unsigned char *end;
} Writer;

int write_bytes(Writer *r, void *in, size_t n);
int read_bytes(Reader *r, void *out, size_t n);
void print_public_key(unsigned char *public_key);
uint64_t htonll(uint64_t val);
#endif
