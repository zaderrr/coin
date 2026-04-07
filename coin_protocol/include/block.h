#include <stdint.h>
typedef struct {
  unsigned char from[32];
  unsigned char to[32];
  uint32_t amount;
  unsigned char *signature;
} transaction;

typedef struct {
  uint8_t public_key;
  uint64_t stake;
  uint64_t block_joined;
} validator;

typedef struct {
  uint32_t height;
  uint8_t prev_hash[32];
  uint8_t state_root[32];
  uint8_t tx_root[32];
  uint64_t timestamp;
  uint8_t proposer[32];
  uint8_t signature[64];
  uint32_t tx_count;
  transaction *transactions; // the actual tx data
} block;
