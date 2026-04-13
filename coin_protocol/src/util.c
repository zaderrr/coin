
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
