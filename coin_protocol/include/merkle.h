#include "state.h"
#include <stddef.h>
#include <stdint.h>
int compute_merkle_root(uint8_t **leaves, uint32_t count, uint8_t *root,
                        size_t leaf_size);

uint8_t *account_to_leaf(account *state);
uint8_t *validator_to_leaf(validator *state);
void free_leaves(unsigned char **leaves, size_t count);
int build_validators_hash(validator *validators, unsigned char *out_buf,
                          int count);
int build_accounts_hash(account *accounts, unsigned char *out_buf, int count);
int build_root(unsigned char *root, transaction *tx, int tx_count);
