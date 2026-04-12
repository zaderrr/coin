#include "block.h"
#include "wallet.h"
#include <netinet/in.h>
#include <node.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_TX 256

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
    decrypt_wallet(fptr, wallet, password);
  }
  return 0;
}

int main(int argc, char const *argv[]) {
  // build chain
  block gen_block = {0};
  state *current_state = malloc(sizeof(state));
  node_ctx ctx = {0};
  ctx.current_state = current_state;
  ctx.mempool = malloc(sizeof(mempool));
  ctx.mempool->tx = malloc(sizeof(transaction) * MAX_TX);
  ctx.mempool->tx_count = 0;
  ctx.mempool->capacity = MAX_TX;
  init_chain(current_state, &gen_block);

  if (argc > 1 && strcmp(argv[1], "--validate") == 0) {
    ctx.is_validator = true;
    // get validator key
    Wallet *wallet = malloc(sizeof(Wallet));
    get_wallet(wallet);
    ctx.wallet = wallet;
    printf("Wallet loaded: ");
    print_public_key(wallet->public_key);
  }

  char buff[128];
  char *location = "text.txt";
  // read_friends(location, buff);
  //   Start node
  struct pollfd *fds = start_server();
  int nfds = 1;
  int block_schedule = 10;
  while (1) {
    accept_connections(fds, &nfds);
    listen_for_message(fds, &nfds, ctx);
    if (ctx.is_validator == true) {
      if (gen_block.timestamp + block_schedule < time(NULL)) {
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
