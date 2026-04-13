#include "block.h"
#include <stddef.h>
#include <stdint.h>
int compute_merkle_root(uint8_t **leaves, uint32_t count, uint8_t *root,
                        size_t leaf_size);
uint8_t *state_to_leaf(unsigned char *state);
void free_leaves(unsigned char **leaves, size_t count);
int build_root(unsigned char *root, transaction *tx, int tx_count);
int build_root_hash(unsigned char *item, unsigned char *out_buf, int count);
