#include "block.h"
#include "node.h"
int validate_funds(account *account, state *current_state, transaction *tx);
int validate_tx(transaction *tx, node_ctx *ctx);
int verify_transaction(unsigned char *payload, transaction *tx);

int can_wirthdraw_stake(account *account, validator *val, transaction *tx,
                        state *current_state);
