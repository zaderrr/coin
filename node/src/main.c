#include "block.h"
#include "genesis.h"
#include "server.h"
#include "wallet.h"
#include <node.h>
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
  block gen_block = {0};
  node_ctx ctx = init_context();
  if (cfg.is_validator) {
    if (init_validator(&ctx) == 1) {
      printf("Error initializing validator...");
      return 1;
    }
  }
  init_chain(ctx.current_state, &gen_block);

  uint16_t port = 8080;
  if (cfg.port != 0) {
    port = cfg.port;
  }

  // Start node
  init_network(&ctx, port);
  while (1) {
    accept_connections(&ctx);
    listen_for_message(&ctx);
    if (ctx.is_validator == true) {
      if (gen_block.timestamp + BLOCK_SCHEDULE < time(NULL)) {
        int index = get_next_validator(ctx.current_state);
        validator t = ctx.current_state->validators[index];
        if (memcmp(t.public_key, ctx.wallet->public_key, 32) == 0) {
          gen_block = build_next_block(&gen_block, &ctx);
          display_state(ctx, gen_block);
        }
      }
    }
  }
  return 0;
}
