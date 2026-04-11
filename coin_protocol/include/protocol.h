#include "block.h"
#include <stdint.h>
typedef struct {
  uint32_t IP;
  uint16_t PORT;
} Peer;

int min_validator_length();
int validate_funds(account *account, state *current_state, transaction *tx);
int can_wirthdraw_stake(account *account, validator *validator, transaction *tx,
                        state *current_state);
account *get_account(state *current_state, unsigned char public_key[32]);
validator *get_validator(state *current_state, unsigned char public_key[32]);
int get_next_validator(state *current_state);
