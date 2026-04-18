#include "block.h"
#include "state.h"
int validate_funds(account *account, state *current_state, transaction *tx);
int validate_tx(transaction *tx, state *state, account *from, block *block);
int verify_transaction(unsigned char *payload, transaction *tx);
int valid_nonce(account *account, transaction *tx);
int can_wirthdraw_stake(account *account, validator *val, transaction *tx,
                        state *current_state, block *block);
