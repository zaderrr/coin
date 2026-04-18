#include "block.h"
#include "state.h"
block build_genesis(account *accounts, validator *validators);
int build_gen_state(state *current_state);
int init_chain(state *current_state, block *gen_block);
