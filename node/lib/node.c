#include "node.h"
#include "block.h"
#include "ed25519.h"
#include "genesis.h"
#include "merkle.h"
#include "message.h"
#include "server.h"
#include "time.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <netinet/in.h>
#include <sodium.h>
#include <string.h>

#define MAX_TX 256

int compare_tx(const void *a, const void *b) {
  transaction *ta = (transaction *)a;
  transaction *tb = (transaction *)b;

  int cmp = memcmp(ta->from, tb->from, 32);
  if (cmp != 0)
    return cmp;

  if (ta->nonce < tb->nonce)
    return -1;
  if (ta->nonce > tb->nonce)
    return 1;
  return 0;
}

int broadcast_block(unsigned char *block_buff, int size, PeerManager *pm) {
  unsigned char out_buff[size + HEADER_SIZE];
  create_message(BLOCK_PROPOSAL, size, block_buff, out_buff);
  broadcast_message(out_buff, size + HEADER_SIZE, pm);
  return 0;
}

block create_block_header(block *previous_block, node_ctx *ctx) {

  unsigned char prev_hash[32];
  hash_block(previous_block, prev_hash);
  block next_block = {0};
  next_block.height = previous_block->height + 1;
  next_block.timestamp = (uint64_t)time(NULL);

  memcpy(next_block.proposer, ctx->wallet->public_key, 32);
  memcpy(next_block.prev_hash, prev_hash, 32);
  return next_block;
}

int create_block_transactions(block *next_block, mempool *mempool,
                              state *current_state) {

  transaction *block_tx = malloc(sizeof(transaction) * mempool->tx_count);
  int tx_count = 0;

  // Sorts by account by nonce
  qsort(mempool->tx, mempool->tx_count, sizeof(transaction), compare_tx);

  for (int i = 0; i < mempool->tx_count; i++) {
    transaction tx = mempool->tx[i];
    account *account = get_account(current_state, tx.from);
    if (validate_tx(&tx, current_state, account, next_block) == 0) {
      if (valid_nonce(account, &tx) == 1) {
        continue;
      }
      block_tx[tx_count] = tx;
      tx_count++;
      update_state(current_state, &tx, next_block);
    }
  }
  next_block->transactions = block_tx;
  next_block->tx_count = tx_count;
  return 0;
}

int build_block_roots(block *next_block, state *current_state) {
  unsigned char root[32];
  build_root(root, next_block->transactions, next_block->tx_count);
  memcpy(next_block->tx_root, root, 32);

  unsigned char account_merkle[32];
  unsigned char val_merkle[32];
  build_accounts_hash(current_state->accounts, account_merkle,
                      current_state->accounts_count);
  build_validators_hash(current_state->validators, val_merkle,
                        current_state->validators_count);
  memcpy(next_block->state_root, account_merkle, 32);
  memcpy(next_block->validator_root, val_merkle, 32);
  return 0;
}

block build_next_block(block *previous_block, node_ctx *ctx) {
  block next_block = create_block_header(previous_block, ctx);
  create_block_transactions(&next_block, ctx->mempool, ctx->current_state);
  build_block_roots(&next_block, ctx->current_state);

  int size = get_block_size(&next_block);
  unsigned char serialized_block[size];
  serialize_block(&next_block, serialized_block, false);
  sign_block(&next_block, serialized_block, size, ctx->wallet);
  broadcast_block(serialized_block, size, ctx->peer_manager);

  ctx->mempool->tx_count = 0;
  return next_block;
}

int read_args(int count, char **args, config *out) {
  config cfg = {0};
  for (int i = 0; i < count; i++) {
    if (strcmp(args[i], "--validate") == 0) {
      cfg.is_validator = true;
    } else if (strcmp(args[i], "--wallet") == 0) {
      cfg.wallet_loc = (unsigned char *)args[i + 1];
    } else if (strcmp(args[i], "--port") == 0) {
      char *endptr = NULL;
      uint64_t arg_port = strtoul(args[i + 1], &endptr, 10);
      if (*endptr != '\0' || arg_port > UINT16_MAX) {
        printf("Invalid port\n");
        return 1;
      }

      cfg.port = (uint16_t)arg_port;
    }
  }
  *out = cfg;
  return 0;
}

void clear_term() { printf("\033[2J\n"); }

void format_pub(unsigned char public_key[32]) {
  unsigned char trunc[7];
  trunc[6] = '\0';
  memcpy(trunc, public_key, 6);
  printf("Account: 0x");
  for (int i = 0; i < 6; i++) {
    printf("%02x", trunc[i]);
  }
  printf("...");
}

node_ctx init_context() {
  state *current_state = malloc(sizeof(state));
  node_ctx ctx = {0};
  ctx.current_state = current_state;
  ctx.mempool = malloc(sizeof(mempool));
  ctx.mempool->tx = malloc(sizeof(transaction) * MAX_TX);
  ctx.state = INIT;
  ctx.target_height = 0;
  ctx.mempool->capacity = MAX_TX;
  ctx.peer_manager = init_pm();
  return ctx;
}

int add_node(node_ctx *ctx, block *next_block) {
  chain_node *next_node = malloc(sizeof(chain_node));

  next_node->next_node = NULL;
  next_node->block = next_block;
  next_node->previous_node = ctx->chain->end;
  ctx->chain->end->next_node = next_node;

  ctx->chain->end = next_node;
  ctx->current_block = next_block;
  ctx->chain->count++;
  return 0;
}

void display_state(node_ctx *ctx) {
  clear_term();
  printf("Accounts: %u\n", ctx->current_state->accounts_count);
  for (int i = 0; i < ctx->current_state->accounts_count; i++) {
    format_pub(ctx->current_state->accounts[i].public_key);
    printf(" Balance: %lu", ctx->current_state->accounts[i].balance);
    printf(" Nonce: %lu\n", ctx->current_state->accounts[i].nonce);
  }
  printf("Current block: %lu\n", ctx->current_block->height);
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int get_wallet(Wallet *wallet, unsigned char *wallet_loc) {
  if (wallet_loc == NULL) {
    char walletLoc[512];
    const char *home = getenv("HOME");
    if (!home) {
      fprintf(stderr, "HOME not set\n");
      return 1;
    }
    snprintf(walletLoc, sizeof walletLoc, "%s/Documents/keys/wallet.coin",
             home);
    wallet_loc = (unsigned char *)walletLoc;
  }

  FILE *fptr;
  fptr = fopen(wallet_loc, "rb");
  char password[128];
  get_password(password);
  if (fptr == NULL) {
    printf("No wallet, create one with the client first\n");
    return 1;
  } else {
    return decrypt_wallet(fptr, wallet, password);
  }
  return 0;
}
int init_validator(node_ctx *ctx, unsigned char *wallet_loc) {
  ctx->is_validator = true;
  // get validator key
  Wallet *wallet = malloc(sizeof(Wallet));
  ctx->wallet = wallet;
  return get_wallet(wallet, wallet_loc);
}

int build_chain(node_ctx *ctx) {
  block *gen_block = calloc(1, sizeof(block));
  ctx->current_block = gen_block;
  ctx->chain = malloc(sizeof(chain));
  ctx->chain->start = malloc(sizeof(chain_node));
  ctx->chain->end = ctx->chain->start;
  ctx->chain->end->block = gen_block;
  ctx->chain->end->previous_node = NULL;
  ctx->chain->end->next_node = NULL;
  ctx->chain->count = 0;
  init_chain(ctx->current_state, gen_block);
  return 0;
}
