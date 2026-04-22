#include "block.h"
#include "genesis.h"
#include "transaction.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool make_test_chain(block *current_block, state *init_state) {
  init_chain(init_state, current_block);
  return 0;
}

bool test_block_size() {
  block genesis_test = {
      .height = 0,
      .prev_hash = {0},
      .timestamp = 233366400,
      .tx_count = 0,
      .transactions = NULL,
      .proposer = {0},
      .signature = {0},
      .tx_root = {0},
  };
  uint64_t size = get_block_size(&genesis_test);

  assert(size == 244);

  genesis_test.tx_count++;
  size = get_block_size(&genesis_test);

  assert(size == 244 + TX_SIZE);

  genesis_test.tx_count++;
  size = get_block_size(&genesis_test);

  assert(size == 244 + (genesis_test.tx_count * TX_SIZE));

  printf("Block size tests passed\n");
  return true;
}

bool test_block_hash() {
  block genesis_test = {
      .height = 0,
      .prev_hash = {0},
      .timestamp = 233366400,
      .tx_count = 0,
      .transactions = NULL,
      .proposer = {0},
      .signature = {0},
      .tx_root = {0},
  };
  unsigned char buff[32];
  hash_block(&genesis_test, buff);

  unsigned char hash[32] = {0xb1, 0x48, 0x47, 0xd2, 0xb7, 0x8a, 0x58, 0x07,
                            0xbd, 0x65, 0x6b, 0x60, 0x7a, 0x7c, 0x7a, 0x90,
                            0xa6, 0x8a, 0xc7, 0xb9, 0x98, 0x3b, 0x0b, 0x36,
                            0x02, 0xa5, 0xbd, 0x26, 0x7e, 0x2c, 0xb8, 0x02};
  assert(memcmp(buff, hash, 32) == 0);
  printf("Block hash correct \n");
  return true;
}

int main() {
  test_block_size();
  test_block_hash();
}
