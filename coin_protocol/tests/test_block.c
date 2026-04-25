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
  return 0;
}

bool test_block_hash() { return true; }

int main() {
  test_block_size();
  test_block_hash();
}
