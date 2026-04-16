#include "block.h"
#include "genesis.h"
#include "server.h"
#include "wallet.h"
#include <node.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SCHEDULE 10

int main(int argc, char **argv) {
  // Get config
  config cfg = {0};

  if (argc > 1) {
    if (read_args(argc, argv, &cfg) == 1) {
      return 1;
    }
  }

  // build chain
  block *gen_block = calloc(1, sizeof(block));
  node_ctx ctx = init_context();
  ctx.current_block = gen_block;
  if (cfg.is_validator) {
    if (init_validator(&ctx) == 1) {
      printf("Error initializing validator...");
      return 1;
    }
  }
  init_chain(ctx.current_state, gen_block);

  uint16_t port = 8080;
  if (cfg.port != 0) {
    port = cfg.port;
  }

  // Start node
  init_network(&ctx, port);
  int first = 0;
  while (1) {

    int new = accept_connections(&ctx);
    listen_for_message(&ctx);

    if (new > 0) {
      continue;
    }

    if (ctx.is_validator == true) {
      if (ctx.current_block->timestamp + BLOCK_SCHEDULE < time(NULL)) {
        int index = get_next_validator(ctx.current_state, ctx.current_block);
        validator t = ctx.current_state->validators[index];
        if (memcmp(t.public_key, ctx.wallet->public_key, 32) == 0) {
          block *new_block = malloc(sizeof(block));
          *new_block = build_next_block(ctx.current_block, &ctx);
          unsigned char prev_hash[32];
          hash_block(new_block, prev_hash);
          free(ctx.current_block->transactions);
          free(ctx.current_block);

          ctx.current_block = new_block;
        }
      }
    }
    display_state(&ctx);
  }
  return 0;
}
