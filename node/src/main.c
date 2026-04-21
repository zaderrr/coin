#include "block.h"
#include "genesis.h"
#include "server.h"
#include "util.h"
#include "wallet.h"
#include <node.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SCHEDULE 5
#define QUIESCENCE_TIMEOUT 1

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
  ctx.chain = malloc(sizeof(chain));
  ctx.chain->start = malloc(sizeof(chain_node));
  ctx.chain->end = ctx.chain->start;
  ctx.chain->end->block = gen_block;
  ctx.chain->end->previous_node = NULL;
  ctx.chain->end->next_node = NULL;
  ctx.chain->count = 0;
  if (cfg.is_validator) {
    if (init_validator(&ctx, cfg.wallet_loc) == 1) {
      printf("Error initializing validator...\n");
      free(cfg.wallet_loc);
      return 1;
    }
  }

  uint16_t port = 8080;
  if (cfg.port != 0) {
    port = cfg.port;
  }

  // Start node
  init_chain(ctx.current_state, gen_block);
  init_network(&ctx, port);
  uint64_t response_start = 0;
  uint64_t last_progress = 0;
  int peers_responded = 0;
  uint64_t last_received_height = 0;

  while (1) {
    int new = accept_connections(&ctx);
    if (ctx.state == INIT) {
      ctx.sync = calloc(1, sizeof(sync_ctx));
      ctx.sync->confirming = false;
      ctx.sync->last_progress = (uint64_t)time(NULL);
      request_current_height(ctx.peer_manager);
      ctx.state = SYNCING;
      last_progress = (uint64_t)time(NULL);
      peers_responded = 0;
      continue;
    } else if (ctx.state == SYNCING) {
      uint64_t height_before = ctx.current_block->height;

      listen_for_message(&ctx);

      if (ctx.target_height > last_received_height) {
        peers_responded = 1;
        last_received_height = ctx.target_height;
      }

      if (ctx.target_height == ctx.current_block->height &&
          ctx.target_height != 0 && ctx.sync->confirming == false) {
        request_current_height(ctx.peer_manager);
        ctx.sync->confirming = true;
      }

      if (ctx.target_height == ctx.current_block->height &&
          ctx.target_height != 0 && ctx.sync->confirming == true &&
          ctx.sync->tip_confirmations >= 1) {
        ctx.state = READY;
        printf("Synced...\n");
      }

      uint64_t silence = (uint64_t)time(NULL) - last_progress;

      if (silence > QUIESCENCE_TIMEOUT) {
        if (peers_responded == 0) {
          ctx.state = READY;
          printf("No response from peers\n");
        } else {
          request_missing_blocks(&ctx);
          printf("Getting more\n");
          last_progress = (uint64_t)time(NULL);
        }
      }
      continue;
    }
    listen_for_message(&ctx);

    if (new > 0) {
      continue;
    }
    if (ctx.is_validator == true) {
      if (ctx.current_block->timestamp + BLOCK_SCHEDULE < time(NULL)) {
        validator *val =
            get_next_validator(ctx.current_state, ctx.current_block);
        if (memcmp(val->public_key, ctx.wallet->public_key, 32) == 0) {
          block *new_block = malloc(sizeof(block));
          *new_block = build_next_block(ctx.current_block, &ctx);
          add_node(&ctx, new_block);
          display_state(&ctx);
        }
      }
    }
  }
  return 0;
}
