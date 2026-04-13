#include "node.h"
#include "block.h"
#include "server.h"
#include "time.h"
#include "validation.h"
#include <sodium.h>
#include <string.h>

#define MAX_TX 256

// Creates new account with the new balance
int create_new_account(state *current_state, transaction *tx) {
  current_state->accounts_count++;
  int count = current_state->accounts_count;
  account *new_accounts =
      realloc(current_state->accounts, sizeof(account) * count);

  account new = {0};
  new.nonce = 0;
  memcpy(new.public_key, tx->to, 32);

  if (new_accounts == NULL) {
    printf("Failed to add account\n");
    return 1;
  }

  current_state->accounts = new_accounts;
  current_state->accounts[current_state->accounts_count - 1] = new;
  return 0;
}

int update_state(state *current_state, transaction *tx) {
  if (tx->type == TX_TRANSFER) {
    account *from = get_account(current_state, tx->from);
    account *to = get_account(current_state, tx->to);
    if (to == NULL) {
      if (create_new_account(current_state, tx) == 1) {
        return 1;
      }
      // Creating account, reallocates memory - Have to get pointers again
      from = get_account(current_state, tx->from);
      to = get_account(current_state, tx->to);
    }
    to->balance += tx->amount;
    from->balance -= tx->amount;
    from->nonce++;
  }
  return 0;
}

block build_next_block(block *previous_block, node_ctx *ctx) {
  unsigned char prev_hash[32];
  hash_block(previous_block, prev_hash);
  block next_block = {0};
  next_block.height = previous_block->height + 1;
  next_block.tx_count = ctx->mempool->tx_count;
  next_block.transactions = ctx->mempool->tx;
  next_block.timestamp = (uint64_t)time(NULL);

  memcpy(next_block.proposer, ctx->wallet->public_key, 32);
  memcpy(next_block.prev_hash, prev_hash, 32);

  transaction *block_tx = malloc(sizeof(transaction) * ctx->mempool->tx_count);
  int tx_count = 0;
  for (int i = 0; i < ctx->mempool->tx_count; i++) {
    transaction tx = ctx->mempool->tx[i];
    if (validate_tx(&tx, ctx) == 0) {
      block_tx[tx_count] = tx;
      tx_count++;
      update_state(ctx->current_state, &tx);
    }
  }
  next_block.transactions = block_tx;
  unsigned char root[32];
  build_root(root, ctx->mempool->tx, ctx->mempool->tx_count);
  memcpy(next_block.tx_root, root, 32);

  unsigned char account_merkle[32];
  unsigned char val_merkle[32];
  build_root_hash((unsigned char *)ctx->current_state->accounts, account_merkle,
                  ctx->current_state->accounts_count);
  build_root_hash((unsigned char *)ctx->current_state->validators, val_merkle,
                  ctx->current_state->validators_count);
  memcpy(next_block.state_root, account_merkle, 32);
  memcpy(next_block.validator_root, val_merkle, 32);
  ctx->mempool->tx_count = 0;
  free(previous_block->transactions);
  return next_block;
}

int read_args(int count, char **args, config *out) {
  config cfg = {0};
  for (int i = 0; i < count; i++) {
    if (strcmp(args[i], "--validate") == 0) {
      cfg.is_validator = true;
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
  ctx.mempool->capacity = MAX_TX;
  ctx.peer_manager = init_pm();
  return ctx;
}

void display_state(node_ctx ctx, block current_block) {
  clear_term();
  printf("Accounts: %u\n", ctx.current_state->accounts_count);
  for (int i = 0; i < ctx.current_state->accounts_count; i++) {
    format_pub(ctx.current_state->accounts[i].public_key);
    printf(" Balance: %lu", ctx.current_state->accounts[i].balance);
    printf(" Nonce: %lu\n", ctx.current_state->accounts[i].nonce);
  }
  printf("Current block: %lu\n", current_block.height);
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int get_wallet(Wallet *wallet) {
  char walletLoc[512];
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }
  snprintf(walletLoc, sizeof walletLoc, "%s/Documents/keys/wallet.coin", home);
  FILE *fptr;
  fptr = fopen(walletLoc, "rb");
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
int init_validator(node_ctx *ctx) {
  ctx->is_validator = true;
  // get validator key
  Wallet *wallet = malloc(sizeof(Wallet));
  ctx->wallet = wallet;
  return get_wallet(wallet);
}
